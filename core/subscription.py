import re
from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests
import yaml

from .parser import ProxyNode, parse_clash_proxy, parse_node_link, safe_b64decode

DEFAULT_USER_AGENT = "ClashMetaForAndroid/2.10.1 v2rayN/6.45 Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
SUPPORTED_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "socks://", "socks5://")
MAX_SUBSCRIPTION_BYTES = 16 * 1024 * 1024
_SHARE_LINK = re.compile(r"^[ \t]*([a-zA-Z][a-zA-Z0-9+.-]*)://", re.MULTILINE)
_CLASH_PROXIES = re.compile(r"""^[ \t]*(?:proxies|'proxies'|"proxies")[ \t]*:""", re.MULTILINE)


def _decode_response_bytes(raw: bytearray, encoding: str | None) -> str:
    for enc in ("utf-8-sig", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    try:
        return raw.decode(encoding or "utf-8", errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def discard_redirect_body(response: requests.Response, **kwargs: Any) -> None:
    # Requests otherwise buffers each redirect body while resolving the next URL.
    if response.is_redirect:
        response.close()


def parse_subscription_userinfo(header_val: str) -> Dict[str, Any]:
    """
    Parse Subscription-Userinfo header:
    e.g. 'upload=1234; download=5678; total=107374182400; expire=1798761600'
    """
    if not header_val:
        return {}
    info: Dict[str, int] = {}
    for part in header_val.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            try:
                info[k] = int(float(v))
            except (ValueError, OverflowError):
                pass
    if not info:
        return {}

    used = info.get("upload", 0) + info.get("download", 0)
    total = info.get("total", 0)
    expire = info.get("expire", 0)

    def _fmt_bytes(b: int) -> str:
        gb = b / (1024 ** 3)
        if gb >= 1.0:
            return f"{gb:.1f} GB"
        mb = b / (1024 ** 2)
        return f"{mb:.1f} MB"

    parts = []
    if total > 0:
        remain = max(0, total - used)
        parts.append(f"剩余 {_fmt_bytes(remain)}")
    elif used > 0:
        parts.append(f"已用 {_fmt_bytes(used)}")

    if expire > 0:
        try:
            dt = datetime.fromtimestamp(expire).strftime("%Y-%m-%d")
            parts.append(f"{dt} 到期")
        except Exception:
            pass

    return {
        "upload": info.get("upload", 0),
        "download": info.get("download", 0),
        "total": total,
        "expire": expire,
        "summary": " · ".join(parts),
    }


def fetch_subscription_with_meta(
    url: str,
    timeout: int = 15,
    user_agent: str = DEFAULT_USER_AGENT,
) -> Tuple[str, Dict[str, Any]]:
    """Fetch subscription text and parsed Subscription-Userinfo metadata."""
    clean_url = url.strip()
    parsed = urlparse(clean_url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise ValueError("订阅链接必须是以 http:// 或 https:// 开头的有效 URL")

    headers = {
        "User-Agent": user_agent,
        "Accept": "*/*",
    }

    # Try system environment first, fallback to direct connection if local system proxy is broken
    for trust_env in (True, False):
        try:
            with requests.Session() as sess:
                sess.trust_env = trust_env
                with sess.get(
                    clean_url, headers=headers, timeout=timeout, stream=True,
                    hooks={"response": discard_redirect_body},
                ) as resp:
                    resp.raise_for_status()
                    raw = bytearray()
                    for chunk in resp.iter_content(chunk_size=64 * 1024):
                        if len(raw) + len(chunk) > MAX_SUBSCRIPTION_BYTES:
                            raise ValueError(f"订阅响应体超过大小上限 ({MAX_SUBSCRIPTION_BYTES} 字节)")
                        raw.extend(chunk)
                    meta = parse_subscription_userinfo(resp.headers.get("Subscription-Userinfo", ""))
                    return _decode_response_bytes(raw, resp.encoding), meta
        except requests.exceptions.HTTPError as exc:
            response = exc.response
            if (trust_env and response is not None and response.status_code == 407
                    and requests.utils.select_proxy(response.url, requests.utils.get_environ_proxies(response.url))):
                continue
            raise
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            if not trust_env:
                raise


def fetch_subscription(url: str, timeout: int = 15, user_agent: str = DEFAULT_USER_AGENT) -> str:
    """Fetch raw content from subscription URL."""
    text, _ = fetch_subscription_with_meta(url, timeout=timeout, user_agent=user_agent)
    return text


def parse_subscription_content(content: str) -> Tuple[List[ProxyNode], List[str]]:
    """
    Parse subscription raw content (Clash YAML, Base64, or plain node links).
    Returns: (nodes_list, error_messages)
    """
    nodes: List[ProxyNode] = []
    errors: List[str] = []

    content = content.strip().lstrip("\ufeff").strip()
    if not content:
        return nodes, ["订阅内容为空"]

    # 1. Try Clash / Mihomo YAML format
    if _CLASH_PROXIES.search(content) or content.startswith("{"):
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            location = f"（第 {mark.line + 1} 行，第 {mark.column + 1} 列）" if mark else ""
            return nodes, [f"Clash YAML 语法错误{location}"]
        if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
            return nodes, ["Clash YAML 缺少有效的 proxies 列表"]
        for index, proxy in enumerate(data["proxies"], 1):
            if not isinstance(proxy, dict):
                errors.append(f"第 {index} 个 Clash 节点格式无效")
                continue
            try:
                nodes.append(parse_clash_proxy(proxy))
            except Exception as exc:
                errors.append(f"解析 Clash 节点失败 [{proxy.get('name', 'unknown')}]: {exc}")
        return nodes, errors

    # 2. Decode Base64 subscriptions, including ones with only unsupported links.
    if not _SHARE_LINK.search(content):
        try:
            decoded_text = safe_b64decode(content).lstrip("\ufeff").strip()
        except Exception:
            decoded_text = ""
        if _SHARE_LINK.search(decoded_text):
            content = decoded_text

    # 3. Parse each line
    for idx, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        match = _SHARE_LINK.match(line)
        if not match:
            continue
        scheme = match.group(1).lower()
        if scheme in ("http", "https"):
            continue
        if f"{scheme}://" not in SUPPORTED_SCHEMES:
            errors.append(f"第 {idx} 行不支持的节点协议: {scheme}")
            continue
        try:
            node = parse_node_link(line)
            nodes.append(node)
        except Exception as e:
            errors.append(f"第 {idx} 行节点解析失败: {e}")

    return nodes, errors
