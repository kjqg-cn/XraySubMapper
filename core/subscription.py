import re
import threading
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .parser import ProxyNode, parse_clash_proxy, parse_node_link, safe_b64decode

if TYPE_CHECKING:
    import requests
    import yaml


def _get_requests():
    if "requests" not in globals():
        import requests as _requests
        globals()["requests"] = _requests
    return globals()["requests"]


def _get_yaml():
    if "yaml" not in globals():
        import yaml as _yaml
        globals()["yaml"] = _yaml
    return globals()["yaml"]


def __getattr__(name: str) -> Any:
    if name == "requests":
        return _get_requests()
    if name == "yaml":
        return _get_yaml()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

DEFAULT_USER_AGENT = "ClashMetaForAndroid/2.10.1 v2rayN/6.45 Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
SUPPORTED_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "socks://", "socks5://", "hysteria2://", "hy2://")
MAX_SUBSCRIPTION_BYTES = 16 * 1024 * 1024
MAX_YAML_NODES = 500_000
MAX_YAML_ALIASES = 2048
MAX_YAML_EXPANDED_ITEMS = 500_000
_SHARE_LINK = re.compile(r"^[ \t]*([a-zA-Z][a-zA-Z0-9+.-]*)://", re.MULTILINE)
_CLASH_PROXIES = re.compile(r"""^[ \t]*(?:proxies|'proxies'|"proxies")[ \t]*:""", re.MULTILINE)


def _has_proxy_share_links(text: str) -> bool:
    return any(m.group(1).lower() not in ("http", "https") for m in _SHARE_LINK.finditer(text))


def _safe_load_clash_yaml(content: str) -> Any:
    yaml_mod = _get_yaml()

    class _BoundedSafeLoader(yaml_mod.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self._node_count = 0
            self._alias_count = 0

        def compose_node(self, parent, index):
            self._node_count += 1
            if self._node_count > MAX_YAML_NODES:
                raise yaml_mod.YAMLError("Clash YAML 节点数量超过安全上限")
            if isinstance(self.peek_event(), yaml_mod.AliasEvent):
                self._alias_count += 1
                if self._alias_count > MAX_YAML_ALIASES:
                    raise yaml_mod.YAMLError("Clash YAML 别名引用次数超过安全上限")
            return super().compose_node(parent, index)

    loader = _BoundedSafeLoader(content)
    try:
        data = loader.get_single_data()
    finally:
        loader.dispose()

    # Defend against YAML alias expansion bombs (e.g., nested list/mapping references).
    stack = [data]
    remaining = MAX_YAML_EXPANDED_ITEMS
    while stack:
        item = stack.pop()
        remaining -= 1
        if remaining < 0:
            raise yaml_mod.YAMLError("Clash YAML 展开规模超过安全上限")
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return data


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


def discard_redirect_body(response: "requests.Response", **kwargs: Any) -> None:
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
    if expire >= 10**12:
        expire //= 1000

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
        except (OSError, OverflowError, ValueError):
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
    total_timeout: Optional[float] = None,
    cancel_event: Optional[threading.Event] = None,
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

    req = _get_requests()
    overall_limit = float(total_timeout) if total_timeout is not None else max(60.0, float(timeout) * 4.0)
    # Try system environment first, fallback to direct connection if local system proxy is broken
    for trust_env in (True, False):
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("订阅拉取已取消")
        try:
            deadline = time.monotonic() + overall_limit
            with req.Session() as sess:
                sess.trust_env = trust_env
                with sess.get(
                    clean_url, headers=headers, timeout=timeout, stream=True,
                    hooks={"response": discard_redirect_body},
                ) as resp:
                    if cancel_event is not None and cancel_event.is_set():
                        raise InterruptedError("订阅拉取已取消")
                    resp.raise_for_status()
                    raw = bytearray()
                    for chunk in resp.iter_content(chunk_size=64 * 1024):
                        if cancel_event is not None and cancel_event.is_set():
                            raise InterruptedError("订阅拉取已取消")
                        if time.monotonic() > deadline:
                            raise req.exceptions.ReadTimeout("订阅下载总耗时超时")
                        if len(raw) + len(chunk) > MAX_SUBSCRIPTION_BYTES:
                            raise ValueError(f"订阅响应体超过大小上限 ({MAX_SUBSCRIPTION_BYTES} 字节)")
                        raw.extend(chunk)
                    meta = parse_subscription_userinfo(resp.headers.get("Subscription-Userinfo", ""))
                    return _decode_response_bytes(raw, resp.encoding), meta
        except req.exceptions.HTTPError as exc:
            response = exc.response
            if (trust_env and response is not None and response.status_code == 407
                    and req.utils.select_proxy(response.url, req.utils.get_environ_proxies(response.url))):
                continue
            raise
        except req.exceptions.InvalidSchema as exc:
            if not trust_env or "socks" not in str(exc).lower():
                raise
        except (
            req.exceptions.ConnectionError, req.exceptions.Timeout,
            req.exceptions.InvalidURL,
        ):
            if not trust_env:
                raise
        except AttributeError as exc:
            # An incompatible socks module can satisfy urllib3's import without exposing PySocks APIs.
            if not trust_env or getattr(exc.obj, "__name__", "") != "socks":
                raise


def fetch_subscription(url: str, timeout: int = 15, user_agent: str = DEFAULT_USER_AGENT) -> str:
    """Fetch raw content from subscription URL."""
    text, _ = fetch_subscription_with_meta(url, timeout=timeout, user_agent=user_agent)
    return text


def _looks_like_clash_yaml(text: str) -> bool:
    return bool(_CLASH_PROXIES.search(text)) or (text.startswith("{") and "proxies" in text)


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

    # 1. Decode Base64 subscriptions (including Base64-wrapped Clash YAML or unsupported links).
    if not _SHARE_LINK.search(content) and not _looks_like_clash_yaml(content):
        try:
            decoded_text = safe_b64decode(content).lstrip("\ufeff").strip()
        except Exception:
            decoded_text = ""
        if _SHARE_LINK.search(decoded_text) or _looks_like_clash_yaml(decoded_text):
            content = decoded_text

    # 2. Try Clash / Mihomo YAML format (fall back to share links if present and YAML is not a Clash doc).
    has_share_links = _has_proxy_share_links(content)
    if _looks_like_clash_yaml(content):
        yaml_mod = _get_yaml()
        try:
            data = _safe_load_clash_yaml(content)
        except yaml_mod.YAMLError as exc:
            err_text = str(exc)
            if "超过安全上限" in err_text:
                return nodes, [err_text]
            if not has_share_links:
                mark = getattr(exc, "problem_mark", None)
                location = f"（第 {mark.line + 1} 行，第 {mark.column + 1} 列）" if mark else ""
                return nodes, [f"Clash YAML 语法错误{location}"]
            data = None
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            for index, proxy in enumerate(data["proxies"], 1):
                if not isinstance(proxy, dict):
                    errors.append(f"第 {index} 个 Clash 节点格式无效")
                    continue
                try:
                    nodes.append(parse_clash_proxy(proxy))
                except Exception as exc:
                    errors.append(f"解析 Clash 节点失败 [{proxy.get('name', 'unknown')}]: {exc}")
            return nodes, errors
        if not has_share_links:
            return nodes, ["Clash YAML 缺少有效的 proxies 列表"]

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
