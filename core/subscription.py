from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests
import yaml

from .parser import ProxyNode, parse_clash_proxy, parse_node_link, safe_b64decode

DEFAULT_USER_AGENT = "ClashMetaForAndroid/2.10.1 v2rayN/6.45 Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
SUPPORTED_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "socks://", "socks5://")


def _decode_response_bytes(resp: requests.Response) -> str:
    """Decode HTTP response bytes prioritizing UTF-8 (with BOM support) over chardet guesses."""
    raw = resp.content
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    fallback = resp.apparent_encoding or "utf-8"
    return raw.decode(fallback, errors="replace")


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
            except ValueError:
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

    resp = None
    last_err = None
    # Try system environment first, fallback to direct connection if local system proxy is broken
    for trust_env in (True, False):
        try:
            with requests.Session() as sess:
                sess.trust_env = trust_env
                resp = sess.get(clean_url, headers=headers, timeout=timeout, allow_redirects=True)
                resp.raise_for_status()
                break
        except requests.exceptions.HTTPError:
            raise
        except Exception as e:
            last_err = e
            resp = None

    if resp is None:
        raise last_err or RuntimeError("下载订阅失败")

    userinfo_raw = ""
    for hk, hv in resp.headers.items():
        if hk.lower() == "subscription-userinfo":
            userinfo_raw = hv
            break

    meta = parse_subscription_userinfo(userinfo_raw)
    return _decode_response_bytes(resp), meta


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

    content = content.strip()
    if not content:
        return nodes, ["订阅内容为空"]

    # 1. Try Clash / Mihomo YAML format
    if "proxies:" in content:
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                for p in data["proxies"]:
                    if not isinstance(p, dict):
                        continue
                    try:
                        node = parse_clash_proxy(p)
                        nodes.append(node)
                    except Exception as e:
                        errors.append(f"解析 Clash 节点失败 [{p.get('name', 'unknown')}]: {e}")
                if nodes:
                    return nodes, errors
        except Exception:
            pass

    # 2. Try Base64 decoding if not starting with plain protocol links
    decoded_text = ""
    first_lower = content[:16].lower()
    is_plain_links = any(first_lower.startswith(p) for p in SUPPORTED_SCHEMES)
    if not is_plain_links:
        try:
            decoded_text = safe_b64decode(content)
        except Exception:
            decoded_text = ""

    if decoded_text and any(p in decoded_text.lower() for p in SUPPORTED_SCHEMES):
        lines = [line.strip() for line in decoded_text.splitlines() if line.strip()]
    else:
        lines = [line.strip() for line in content.splitlines() if line.strip()]

    # 3. Parse each line
    for idx, line in enumerate(lines, 1):
        lower_line = line.lower()
        if not any(lower_line.startswith(p) for p in SUPPORTED_SCHEMES):
            continue
        try:
            node = parse_node_link(line)
            nodes.append(node)
        except Exception as e:
            errors.append(f"第 {idx} 行节点解析失败: {e}")

    return nodes, errors
