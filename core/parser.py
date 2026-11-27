import base64
import json
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import ParseResult, parse_qsl, unquote, urlparse


DUMMY_SERVERS = {"", "127.0.0.1", "0.0.0.0", "localhost", "1.1.1.1", "8.8.8.8", "::1"}

KNOWN_SS_METHODS = (
    "2022-blake3-",
    "aes-",
    "chacha20-",
    "xchacha20-",
    "rc4-",
    "camellia-",
    "bf-cfb",
    "salsa20",
    "none",
    "plain",
)


def _safe_int(val: Any, default: int = 0) -> int:
    if val is None or val == "":
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_bool(val: Any, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "on", "tls"):
        return True
    if s in ("0", "false", "no", "off", "none", ""):
        return False
    return default


def safe_b64decode(s: str) -> str:
    """Safe Base64 decoding supporting URL encoding, whitespace, and missing padding."""
    s = unquote(s.strip())
    s = re.sub(r"\s+", "", s)
    if not s:
        return ""
    missing_padding = len(s) % 4
    if missing_padding:
        s += "=" * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(s.encode("utf-8")).decode("utf-8", errors="ignore")
    except Exception:
        return base64.b64decode(s.encode("utf-8")).decode("utf-8", errors="ignore")


def _authority_port(parsed: ParseResult, default_port: int) -> int:
    if parsed.netloc.endswith(":"):
        raise ValueError("Missing proxy port")
    port = parsed.port
    return default_port if port is None else port


def _parse_proxy_port(value: Any, protocol: str) -> int:
    message = f"{protocol} port 须为 0~65535 的整数"
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(message)
    try:
        port = int(value)
    except ValueError:
        raise ValueError(message) from None
    if not 0 <= port <= 65535:
        raise ValueError(message)
    return port


def _split_host_port(host_port: str, default_port: int = 443) -> Tuple[str, int]:
    """Safely split host:port including bracketed IPv6 like [2001:db8::1]:8388."""
    parsed = urlparse("//" + host_port.strip())
    if not parsed.hostname or any(c.isspace() for c in parsed.hostname) or parsed.path not in ("", "/"):
        raise ValueError("Invalid proxy host/port")
    port = _authority_port(parsed, default_port)
    if not 1 <= port <= 65535:
        raise ValueError("Proxy port must be in 1..65535")
    return parsed.hostname, port


_SINGLE_LINE_RE = re.compile(r"[\r\n\t\x00-\x1f\x7f]+")


def sanitize_single_line(text: Any) -> str:
    """Collapse control characters and newlines into single spaces to prevent line injection."""
    if text is None:
        return ""
    cleaned = _SINGLE_LINE_RE.sub(" ", str(text))
    return re.sub(r" {2,}", " ", cleaned).strip()


def _validate_transport(network: str) -> None:
    if network in ("h2", "http", "quic"):
        raise ValueError(f"Xray 已移除 {network} 传输，请向服务端获取 XHTTP 节点配置")
    if network not in ("tcp", "raw", "ws", "websocket", "grpc", "xhttp", "splithttp", "httpupgrade"):
        raise ValueError(f"不支持的传输方式: {network}")


def _validate_stream_security(security: str, allow_insecure: bool, public_key: str = "") -> None:
    if security not in ("none", "tls", "reality"):
        raise ValueError(f"不支持的传输安全配置: {security}")
    if security == "reality" and not public_key.strip():
        raise ValueError("REALITY 缺少公钥 (pbk / public-key)")
    if security != "none" and allow_insecure:
        raise ValueError("Xray 26.11.9+ 不支持 allowInsecure / skip-cert-verify；请使用有效证书的节点")


_HY2_SPEED_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(bps|kbps|mbps|gbps|tbps|b|k|m|g|t)?\s*$", re.IGNORECASE)
_HY2_UNIT_CANONICAL = {
    "b": "bps",
    "k": "kbps",
    "m": "mbps",
    "g": "gbps",
    "t": "tbps",
    "bps": "bps",
    "kbps": "kbps",
    "mbps": "mbps",
    "gbps": "gbps",
    "tbps": "tbps",
}
_HY2_UNIT_BYTES = {
    "bps": 1 / 8,
    "kbps": 1_000 / 8,
    "mbps": 1_000_000 / 8,
    "gbps": 1_000_000_000 / 8,
    "tbps": 1_000_000_000_000 / 8,
}


def _normalize_hysteria2_pin_sha256(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    lower = raw.lower()
    if lower.startswith(("sha256:", "sha256/")):
        lower = lower[7:]
    cleaned = lower.replace(":", "").replace(" ", "")
    if not re.fullmatch(r"[0-9a-f]{64}", cleaned):
        raise ValueError("Hysteria2 pinSHA256 证书指纹格式无效，须为 64 位十六进制 SHA-256")
    return cleaned


def _normalize_hysteria2_ports(value: str) -> Tuple[str, int]:
    raw = str(value or "").strip().replace("/", ",")
    if not raw:
        return "", 0
    normalized_parts = []
    first_port = 0
    for item in raw.split(","):
        part = item.strip()
        if not part:
            raise ValueError(f"Hysteria2 端口跳跃范围无效: {value}")
        if "-" in part:
            bounds = [b.strip() for b in part.split("-")]
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                raise ValueError(f"Hysteria2 端口跳跃范围无效: {value}")
            start, end = int(bounds[0]), int(bounds[1])
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Hysteria2 端口跳跃范围越界: {value}")
            if first_port == 0:
                first_port = start
            normalized_parts.append(f"{start}-{end}")
        else:
            if not part.isdigit():
                raise ValueError(f"Hysteria2 端口跳跃范围无效: {value}")
            port_num = int(part)
            if not (1 <= port_num <= 65535):
                raise ValueError(f"Hysteria2 端口跳跃范围越界: {value}")
            if first_port == 0:
                first_port = port_num
            normalized_parts.append(str(port_num))
    return ",".join(normalized_parts), first_port


def _normalize_hysteria2_hop_interval(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, bool):
        raise ValueError("Hysteria2 端口跳跃间隔须为 >= 5 的整数或范围")
    raw = str(value).strip().lower()
    if not raw or raw in ("0", "0s"):
        return ""
    if "-" in raw:
        bounds = [part.strip().removesuffix("s") for part in raw.split("-")]
        if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
            raise ValueError(f"Hysteria2 端口跳跃间隔格式无效: {value}")
        lo, hi = int(bounds[0]), int(bounds[1])
        if lo < 5 or lo > hi:
            raise ValueError("Hysteria2 端口跳跃间隔须 >= 5 秒且下限不大于上限")
        return f"{lo}-{hi}"
    sec_str = raw.removesuffix("s")
    if not sec_str.isdigit():
        raise ValueError(f"Hysteria2 端口跳跃间隔格式无效: {value}")
    sec = int(sec_str)
    if sec < 5:
        raise ValueError("Hysteria2 端口跳跃间隔须 >= 5 秒")
    return str(sec)


def _normalize_hysteria2_bandwidth(value: Any, field: str) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, bool):
        raise ValueError(f"Hysteria2 {field} 带宽格式无效")
    m = _HY2_SPEED_RE.match(str(value))
    if not m:
        raise ValueError(f"Hysteria2 {field} 带宽格式无效: {value}")
    num = float(m.group(1))
    unit = _HY2_UNIT_CANONICAL[(m.group(2) or "mbps").lower()]
    if num == 0:
        return ""
    if num * _HY2_UNIT_BYTES[unit] < 65536:
        raise ValueError(f"Hysteria2 {field} Brutal 带宽须至少 525 kbps (65536 B/s)")
    num_text = str(int(num)) if num.is_integer() else f"{num:.6f}".rstrip("0").rstrip(".")
    return f"{num_text} {unit}"


def _apply_transport_settings(
    stream: Dict[str, Any],
    network: str,
    host: str = "",
    path: str = "",
    header_type: str = "none",
    mode: str = "",
) -> None:
    """Populate Xray 26.x compatible streamSettings transport fields without raising on disabled placeholders."""
    net = (network or "tcp").lower()
    if net in ("splithttp", "xhttp"):
        stream["network"] = "xhttp"
        xhttp_settings: Dict[str, Any] = {"path": path or "/"}
        if host:
            xhttp_settings["host"] = host
        if mode:
            xhttp_settings["mode"] = mode
        stream["xhttpSettings"] = xhttp_settings
    elif net == "httpupgrade":
        stream["network"] = "httpupgrade"
        hu_settings: Dict[str, Any] = {"path": path or "/"}
        if host:
            hu_settings["host"] = host
        stream["httpupgradeSettings"] = hu_settings
    elif net in ("ws", "websocket"):
        stream["network"] = "ws"
        ws_settings: Dict[str, Any] = {}
        if path:
            ws_settings["path"] = path
        if host:
            # Xray 26.x uses top-level host; headers.Host is deprecated
            ws_settings["host"] = host
        stream["wsSettings"] = ws_settings
    elif net == "grpc":
        stream["network"] = "grpc"
        grpc_settings: Dict[str, Any] = {"serviceName": path or ""}
        if mode == "multi":
            grpc_settings["multiMode"] = True
        stream["grpcSettings"] = grpc_settings
    elif net in ("tcp", "raw"):
        stream["network"] = "tcp"
        if header_type == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [path] if path else ["/"],
                        "headers": {"Host": [host]} if host else {},
                    },
                }
            }
    else:
        stream["network"] = net


def _build_tls_settings(
    server_name: str,
    fp: str = "",
    alpn: str = "",
) -> Dict[str, Any]:
    tls_settings: Dict[str, Any] = {}
    if server_name:
        tls_settings["serverName"] = server_name
    if fp:
        tls_settings["fingerprint"] = fp
    if alpn:
        alpn_list = [x.strip() for x in alpn.split(",") if x.strip()]
        if alpn_list:
            tls_settings["alpn"] = alpn_list
    return tls_settings


_NON_KEY_ATTRS = frozenset({
    "local_port", "port_pinned", "enabled", "latency_ms",
    "last_error", "exit_ip", "probe_state", "name", "raw_link", "_cached_connection_key",
})


class ProxyNode:
    def __init__(self, name: str, protocol: str, server: str, port: int, raw_link: str = ""):
        object.__setattr__(self, "_cached_connection_key", None)
        self.server = (server or "").strip("[] ")
        self.port = _safe_int(port, 443)
        self.protocol = protocol.lower()
        clean_name = sanitize_single_line(name)
        self.name = clean_name or f"{self.protocol}-{self.server}:{self.port}"
        self.raw_link = raw_link
        self.local_port: int = 0
        self.port_pinned: bool = False
        # Auto-disable placeholder info nodes (e.g. 127.0.0.1 / port <= 1)
        self.enabled: bool = not self.is_placeholder_node()
        self.latency_ms: Optional[int] = None
        self.last_error: str = ""
        self.exit_ip: str = ""
        self.probe_state: str = ""

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, value)
        if name not in _NON_KEY_ATTRS:
            object.__setattr__(self, "_cached_connection_key", None)

    def is_placeholder_node(self) -> bool:
        return self.server.lower() in DUMMY_SERVERS or self.port <= 1 or self.port > 65535

    def validate_runtime(self) -> None:
        if not self.server:
            raise ValueError("节点缺少服务器地址 (server)")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"节点端口无效 ({self.port})，须在 1~65535 之间")

    def _build_outbound(self, tag: str) -> Dict[str, Any]:
        raise NotImplementedError

    def to_outbound(self, tag: str) -> Dict[str, Any]:
        if self.enabled:
            self.validate_runtime()
        return self._build_outbound(tag)

    def connection_key(self) -> str:
        """Stable identity excluding display name, port assignment and probe results."""
        cached = getattr(self, "_cached_connection_key", None)
        if cached is None:
            cached = json.dumps(self._build_outbound("node"), sort_keys=True, ensure_ascii=False)
            object.__setattr__(self, "_cached_connection_key", cached)
        return cached

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "protocol": self.protocol,
            "server": self.server,
            "port": self.port,
            "local_port": self.local_port,
            "port_pinned": self.port_pinned,
            "enabled": self.enabled,
            "latency": self.latency_ms,
            "last_error": self.last_error,
            "exit_ip": self.exit_ip,
            "raw_link": self.raw_link,
        }


class VMessNode(ProxyNode):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        uuid: str,
        alter_id: int = 0,
        security: str = "auto",
        network: str = "tcp",
        header_type: str = "none",
        host: str = "",
        path: str = "",
        tls: str = "",
        sni: str = "",
        alpn: str = "",
        fp: str = "",
        allow_insecure: bool = False,
        mode: str = "",
        raw_link: str = "",
    ):
        super().__init__(name, "vmess", server, port, raw_link)
        self.uuid = uuid
        self.alter_id = _safe_int(alter_id, 0)
        self.security = security or "auto"
        self.network = (network or "tcp").lower()
        self.header_type = header_type or "none"
        self.host = host or ""
        self.path = path or ""
        self.tls = "tls" if _safe_bool(tls) or str(tls).lower() == "tls" else ""
        self.sni = sni or ""
        self.alpn = alpn or ""
        self.fp = fp or ""
        self.allow_insecure = bool(allow_insecure)
        self.mode = mode or ""
        if self.enabled:
            self.validate_runtime()

    def validate_runtime(self) -> None:
        super().validate_runtime()
        if not str(self.uuid or "").strip():
            raise ValueError("VMess 缺少 UUID")
        _validate_transport(self.network)
        _validate_stream_security(self.tls or "none", self.allow_insecure)

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "uuid": self.uuid,
                "alter_id": self.alter_id,
                "security": self.security,
                "network": self.network,
                "header_type": self.header_type,
                "host": self.host,
                "path": self.path,
                "tls": self.tls,
                "sni": self.sni,
                "alpn": self.alpn,
                "fp": self.fp,
                "allow_insecure": self.allow_insecure,
                "mode": self.mode,
            }
        )
        return d

    def _build_outbound(self, tag: str) -> Dict[str, Any]:
        stream: Dict[str, Any] = {}
        if self.tls == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = _build_tls_settings(
                server_name=self.sni or self.host,
                fp=self.fp,
                alpn=self.alpn,
            )
        else:
            stream["security"] = "none"

        _apply_transport_settings(
            stream,
            network=self.network,
            host=self.host,
            path=self.path,
            header_type=self.header_type,
            mode=self.mode,
        )

        return {
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": self.server,
                        "port": self.port,
                        "users": [
                            {
                                "id": self.uuid,
                                "alterId": self.alter_id,
                                "security": self.security,
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream,
        }


class VLESSNode(ProxyNode):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        uuid: str,
        flow: str = "",
        encryption: str = "none",
        network: str = "tcp",
        header_type: str = "none",
        host: str = "",
        path: str = "",
        security: str = "none",
        sni: str = "",
        alpn: str = "",
        fp: str = "",
        pbk: str = "",
        sid: str = "",
        spx: str = "",
        allow_insecure: bool = False,
        mode: str = "",
        raw_link: str = "",
    ):
        super().__init__(name, "vless", server, port, raw_link)
        self.uuid = uuid
        self.flow = flow or ""
        self.encryption = encryption or "none"
        self.network = (network or "tcp").lower()
        self.header_type = header_type or "none"
        self.host = host or ""
        self.path = path or ""
        self.security = (security or "none").lower()
        self.sni = sni or ""
        self.alpn = alpn or ""
        self.fp = fp or ""
        self.pbk = pbk or ""
        self.sid = sid or ""
        self.spx = spx or ""
        self.allow_insecure = bool(allow_insecure)
        self.mode = mode or ""
        if self.enabled:
            self.validate_runtime()

    def validate_runtime(self) -> None:
        super().validate_runtime()
        if not str(self.uuid or "").strip():
            raise ValueError("VLESS 缺少 UUID")
        _validate_transport(self.network)
        _validate_stream_security(self.security, self.allow_insecure, self.pbk)

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "uuid": self.uuid,
                "flow": self.flow,
                "encryption": self.encryption,
                "network": self.network,
                "header_type": self.header_type,
                "host": self.host,
                "path": self.path,
                "security": self.security,
                "sni": self.sni,
                "alpn": self.alpn,
                "fp": self.fp,
                "pbk": self.pbk,
                "sid": self.sid,
                "spx": self.spx,
                "allow_insecure": self.allow_insecure,
                "mode": self.mode,
            }
        )
        return d

    def _build_outbound(self, tag: str) -> Dict[str, Any]:
        user_info: Dict[str, Any] = {
            "id": self.uuid,
            "encryption": self.encryption,
        }
        if self.flow:
            user_info["flow"] = self.flow

        stream: Dict[str, Any] = {"security": self.security}
        server_name = self.sni or self.host

        if self.security == "reality":
            stream["realitySettings"] = {
                "show": False,
                "fingerprint": self.fp or "chrome",
                "serverName": server_name,
                "publicKey": self.pbk,
                "shortId": self.sid,
                "spiderX": self.spx,
            }
        elif self.security == "tls":
            stream["tlsSettings"] = _build_tls_settings(
                server_name=server_name,
                fp=self.fp,
                alpn=self.alpn,
            )

        _apply_transport_settings(
            stream,
            network=self.network,
            host=self.host,
            path=self.path,
            header_type=self.header_type,
            mode=self.mode,
        )

        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": self.server,
                        "port": self.port,
                        "users": [user_info],
                    }
                ]
            },
            "streamSettings": stream,
        }


class TrojanNode(ProxyNode):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        password: str,
        network: str = "tcp",
        header_type: str = "none",
        security: str = "tls",
        sni: str = "",
        alpn: str = "",
        fp: str = "",
        host: str = "",
        path: str = "",
        pbk: str = "",
        sid: str = "",
        spx: str = "",
        allow_insecure: bool = False,
        mode: str = "",
        raw_link: str = "",
    ):
        super().__init__(name, "trojan", server, port, raw_link)
        self.password = password
        self.network = (network or "tcp").lower()
        self.header_type = header_type or "none"
        self.security = (security or "tls").lower()
        self.sni = sni or ""
        self.alpn = alpn or ""
        self.fp = fp or ""
        self.host = host or ""
        self.path = path or ""
        self.pbk = pbk or ""
        self.sid = sid or ""
        self.spx = spx or ""
        self.allow_insecure = bool(allow_insecure)
        self.mode = mode or ""
        if self.enabled:
            self.validate_runtime()

    def validate_runtime(self) -> None:
        super().validate_runtime()
        if not self.password:
            raise ValueError("Trojan 缺少密码")
        _validate_transport(self.network)
        _validate_stream_security(self.security, self.allow_insecure, self.pbk)

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "password": self.password,
                "network": self.network,
                "header_type": self.header_type,
                "security": self.security,
                "sni": self.sni,
                "alpn": self.alpn,
                "fp": self.fp,
                "host": self.host,
                "path": self.path,
                "pbk": self.pbk,
                "sid": self.sid,
                "spx": self.spx,
                "allow_insecure": self.allow_insecure,
                "mode": self.mode,
            }
        )
        return d

    def _build_outbound(self, tag: str) -> Dict[str, Any]:
        stream: Dict[str, Any] = {"security": self.security}
        server_name = self.sni or self.host or self.server

        if self.security == "reality":
            stream["realitySettings"] = {
                "show": False,
                "fingerprint": self.fp or "chrome",
                "serverName": server_name,
                "publicKey": self.pbk,
                "shortId": self.sid,
                "spiderX": self.spx,
            }
        elif self.security == "tls":
            stream["tlsSettings"] = _build_tls_settings(
                server_name=server_name,
                fp=self.fp,
                alpn=self.alpn,
            )

        _apply_transport_settings(
            stream,
            network=self.network,
            host=self.host,
            path=self.path,
            header_type=self.header_type,
            mode=self.mode,
        )

        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": self.server,
                        "port": self.port,
                        "password": self.password,
                    }
                ]
            },
            "streamSettings": stream,
        }


class ShadowsocksNode(ProxyNode):
    def __init__(self, name: str, server: str, port: int, method: str, password: str, raw_link: str = ""):
        super().__init__(name, "shadowsocks", server, port, raw_link)
        self.method = str(method or "").strip()
        self.password = password
        if self.enabled:
            self.validate_runtime()

    def validate_runtime(self) -> None:
        super().validate_runtime()
        if not self.method:
            raise ValueError("Shadowsocks 缺少加密方式 (method / cipher)")
        if not self.password:
            raise ValueError("Shadowsocks 缺少密码")

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"method": self.method, "password": self.password})
        return d

    def _build_outbound(self, tag: str) -> Dict[str, Any]:
        return {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": self.server,
                        "port": self.port,
                        "method": self.method,
                        "password": self.password,
                    }
                ]
            },
        }


class SocksNode(ProxyNode):
    def __init__(self, name: str, server: str, port: int, user: str = "", password: str = "", raw_link: str = ""):
        super().__init__(name, "socks", server, port, raw_link)
        self.user = user
        self.password = password

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"user": self.user, "password": self.password})
        return d

    def _build_outbound(self, tag: str) -> Dict[str, Any]:
        server_obj: Dict[str, Any] = {
            "address": self.server,
            "port": self.port,
        }
        if self.user:
            server_obj["users"] = [{"user": self.user, "pass": self.password}]
        return {
            "tag": tag,
            "protocol": "socks",
            "settings": {"servers": [server_obj]},
        }


class Hysteria2Node(ProxyNode):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        password: str,
        sni: str = "",
        alpn: str = "",
        fp: str = "",
        pin_sha256: str = "",
        allow_insecure: bool = False,
        obfs: str = "",
        obfs_password: str = "",
        mport: str = "",
        hop_interval: str = "",
        up: Any = "",
        down: Any = "",
        raw_link: str = "",
    ):
        super().__init__(name, "hysteria2", server, port, raw_link)
        self.password = password
        self.sni = (sni or "").strip()
        self.alpn = (alpn or "").strip()
        self.fp = (fp or "").strip()
        self.pin_sha256 = _normalize_hysteria2_pin_sha256(pin_sha256)
        self.allow_insecure = bool(allow_insecure)
        obfs_norm = (obfs or "").strip().lower()
        if obfs_norm in ("", "none"):
            self.obfs = ""
            self.obfs_password = ""
        elif obfs_norm == "salamander":
            self.obfs = "salamander"
            self.obfs_password = str(obfs_password or "")
        else:
            raise ValueError(f"不支持的 Hysteria2 混淆方式: {obfs}")
        self.mport, _ = _normalize_hysteria2_ports(mport)
        self.hop_interval = _normalize_hysteria2_hop_interval(hop_interval)
        self.up = _normalize_hysteria2_bandwidth(up, "up")
        self.down = _normalize_hysteria2_bandwidth(down, "down")
        if self.enabled:
            self.validate_runtime()

    def validate_runtime(self) -> None:
        super().validate_runtime()
        if not self.password:
            raise ValueError("Hysteria2 缺少密码 (auth / password)")
        if self.allow_insecure and not self.pin_sha256:
            raise ValueError(
                "Xray 26.11.9+ 不支持 allowInsecure / skip-cert-verify；请使用有效证书或配置 pinSHA256"
            )
        if self.obfs == "salamander" and not self.obfs_password:
            raise ValueError("Hysteria2 Salamander 混淆缺少 obfs-password")

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "password": self.password,
                "sni": self.sni,
                "alpn": self.alpn,
                "fp": self.fp,
                "pin_sha256": self.pin_sha256,
                "allow_insecure": self.allow_insecure,
                "obfs": self.obfs,
                "obfs_password": self.obfs_password,
                "mport": self.mport,
                "hop_interval": self.hop_interval,
                "up": self.up,
                "down": self.down,
            }
        )
        return d

    def _build_outbound(self, tag: str) -> Dict[str, Any]:
        tls_settings = _build_tls_settings(
            server_name=self.sni or self.server,
            fp=self.fp,
            alpn=self.alpn,
        )
        if self.pin_sha256:
            tls_settings["pinnedPeerCertSha256"] = self.pin_sha256

        stream: Dict[str, Any] = {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": tls_settings,
            "hysteriaSettings": {
                "version": 2,
                "auth": self.password,
            },
        }

        finalmask: Dict[str, Any] = {}
        udp_masks: list[Dict[str, Any]] = []
        if self.obfs == "salamander" and self.obfs_password:
            udp_masks.append({"type": "salamander", "settings": {"password": self.obfs_password}})
        if self.mport:
            # Xray 26.11+ requires udphop as the final UDP mask element when combined with salamander.
            udp_masks.append(
                {
                    "type": "udphop",
                    "settings": {
                        "mode": "intervalremote",
                        "remotePorts": self.mport,
                        "interval": self.hop_interval or "30",
                    },
                }
            )
        if udp_masks:
            finalmask["udp"] = udp_masks

        if self.up or self.down:
            quic_params: Dict[str, Any] = {"congestion": "brutal"}
            if self.up:
                quic_params["brutalUp"] = self.up
            if self.down:
                quic_params["brutalDown"] = self.down
            finalmask["quicParams"] = quic_params

        if finalmask:
            stream["finalmask"] = finalmask

        return {
            "tag": tag,
            "protocol": "hysteria",
            "settings": {
                "version": 2,
                "address": self.server,
                "port": self.port,
            },
            "streamSettings": stream,
        }


def node_from_dict(d: Dict[str, Any]) -> Optional[ProxyNode]:
    """Reconstruct a ProxyNode subclass instance from a saved dict."""
    if not isinstance(d, dict):
        return None
    proto = str(d.get("protocol", "")).lower()
    name = str(d.get("name", ""))
    server = str(d.get("server", ""))
    port = _safe_int(d.get("port"), 443)
    raw_link = str(d.get("raw_link", ""))

    node: Optional[ProxyNode] = None

    if proto == "vmess":
        node = VMessNode(
            name=name,
            server=server,
            port=port,
            uuid=d.get("uuid", ""),
            alter_id=_safe_int(d.get("alter_id"), 0),
            security=d.get("security", "auto"),
            network=d.get("network", "tcp"),
            header_type=d.get("header_type", "none"),
            host=d.get("host", ""),
            path=d.get("path", ""),
            tls=d.get("tls", ""),
            sni=d.get("sni", ""),
            alpn=d.get("alpn", ""),
            fp=d.get("fp", ""),
            allow_insecure=bool(d.get("allow_insecure", False)),
            mode=d.get("mode", ""),
            raw_link=raw_link,
        )
    elif proto == "vless":
        node = VLESSNode(
            name=name,
            server=server,
            port=port,
            uuid=d.get("uuid", ""),
            flow=d.get("flow", ""),
            encryption=d.get("encryption", "none"),
            network=d.get("network", "tcp"),
            header_type=d.get("header_type", "none"),
            host=d.get("host", ""),
            path=d.get("path", ""),
            security=d.get("security", "none"),
            sni=d.get("sni", ""),
            alpn=d.get("alpn", ""),
            fp=d.get("fp", ""),
            pbk=d.get("pbk", ""),
            sid=d.get("sid", ""),
            spx=d.get("spx", ""),
            allow_insecure=bool(d.get("allow_insecure", False)),
            mode=d.get("mode", ""),
            raw_link=raw_link,
        )
    elif proto == "trojan":
        node = TrojanNode(
            name=name,
            server=server,
            port=port,
            password=d.get("password", ""),
            network=d.get("network", "tcp"),
            header_type=d.get("header_type", "none"),
            security=d.get("security", "tls"),
            sni=d.get("sni", ""),
            alpn=d.get("alpn", ""),
            fp=d.get("fp", ""),
            host=d.get("host", ""),
            path=d.get("path", ""),
            pbk=d.get("pbk", ""),
            sid=d.get("sid", ""),
            spx=d.get("spx", ""),
            allow_insecure=bool(d.get("allow_insecure", False)),
            mode=d.get("mode", ""),
            raw_link=raw_link,
        )
    elif proto in ("ss", "shadowsocks"):
        node = ShadowsocksNode(
            name=name,
            server=server,
            port=port,
            method=d.get("method", ""),
            password=d.get("password", ""),
            raw_link=raw_link,
        )
    elif proto in ("socks", "socks5"):
        node = SocksNode(
            name=name,
            server=server,
            port=port,
            user=d.get("user", ""),
            password=d.get("password", ""),
            raw_link=raw_link,
        )
    elif proto in ("hysteria2", "hy2"):
        node = Hysteria2Node(
            name=name,
            server=server,
            port=port,
            password=d.get("password", ""),
            sni=d.get("sni", ""),
            alpn=d.get("alpn", ""),
            fp=d.get("fp", ""),
            pin_sha256=d.get("pin_sha256", ""),
            allow_insecure=bool(d.get("allow_insecure", False)),
            obfs=d.get("obfs", ""),
            obfs_password=d.get("obfs_password", ""),
            mport=d.get("mport", ""),
            hop_interval=d.get("hop_interval", ""),
            up=d.get("up", ""),
            down=d.get("down", ""),
            raw_link=raw_link,
        )

    if node:
        node.local_port = _safe_int(d.get("local_port"), 0)
        node.port_pinned = bool(d.get("port_pinned", False))
        node.enabled = bool(d.get("enabled", True))
        lat = d.get("latency")
        node.latency_ms = _safe_int(lat, -1) if lat is not None else None
        node.last_error = str(d.get("last_error", ""))
        node.exit_ip = str(d.get("exit_ip", ""))

    return node


def parse_vmess(link: str) -> VMessNode:
    b64, _, fragment = link[8:].partition("#")
    decoded = safe_b64decode(b64)
    data = json.loads(decoded)
    if not isinstance(data, dict):
        raise ValueError("Invalid VMess JSON payload")

    net = str(data.get("net") or "tcp").strip().lower()
    path = str(data.get("path") or "").strip()
    mode = str(data.get("mode") or "").strip()
    if not mode and net == "grpc" and data.get("type") == "multi":
        mode = "multi"

    return VMessNode(
        name=str(data.get("ps") or unquote(fragment)).strip(),
        server=str(data.get("add") or "").strip(),
        port=_parse_proxy_port(data.get("port", 443), "VMess"),
        uuid=str(data.get("id") or "").strip(),
        alter_id=_safe_int(data.get("aid"), 0),
        security=str(data.get("scy") or "auto").strip(),
        network=net,
        header_type=str(data.get("type") or "none").strip(),
        host=str(data.get("host") or "").strip(),
        path=path,
        tls=str(data.get("tls") or "").strip(),
        sni=str(data.get("sni") or "").strip(),
        alpn=str(data.get("alpn") or "").strip(),
        fp=str(data.get("fp") or "").strip(),
        allow_insecure=any(_safe_bool(value) for key, value in data.items()
                           if key.lower() in ("allowinsecure", "insecure")),
        mode=mode,
        raw_link=link,
    )


def _parse_share_query(query: str) -> Dict[str, list[str]]:
    # Share links use percent encoding. A literal plus is part of the value.
    params: Dict[str, list[str]] = {}
    for key, value in parse_qsl(query.replace("+", "%2B")):
        params.setdefault(key.lower(), []).append(value)
    return params


def _query_allows_insecure(params: Dict[str, list[str]]) -> bool:
    return any(_safe_bool(value) for key in ("allowinsecure", "insecure") for value in params.get(key, ()))


def parse_vless(link: str) -> VLESSNode:
    u = urlparse(link)
    uuid = unquote(u.username or "")
    server = u.hostname or ""
    port = _authority_port(u, 443)
    name = unquote(u.fragment) if u.fragment else f"vless-{server}:{port}"
    params = _parse_share_query(u.query)

    def get_p(key: str, default: str = "") -> str:
        return params.get(key.lower(), [default])[0]

    net = get_p("type", "tcp").lower()
    raw_path = get_p("serviceName") if net == "grpc" and get_p("serviceName") else get_p("path")

    return VLESSNode(
        name=name.strip(),
        server=server,
        port=port,
        uuid=uuid,
        flow=get_p("flow"),
        encryption=get_p("encryption", "none"),
        network=net,
        header_type=get_p("headerType", "none"),
        host=get_p("host"),
        path=raw_path,
        security=get_p("security", "none"),
        sni=get_p("sni") or get_p("peer"),
        alpn=get_p("alpn"),
        fp=get_p("fp"),
        pbk=get_p("pbk"),
        sid=get_p("sid"),
        spx=get_p("spx"),
        allow_insecure=_query_allows_insecure(params),
        mode=get_p("mode"),
        raw_link=link,
    )


def parse_trojan(link: str) -> TrojanNode:
    u = urlparse(link)
    userinfo, separator, _ = u.netloc.rpartition("@")
    password = unquote(userinfo) if separator else ""
    server = u.hostname or ""
    port = _authority_port(u, 443)
    name = unquote(u.fragment) if u.fragment else f"trojan-{server}:{port}"
    params = _parse_share_query(u.query)

    def get_p(key: str, default: str = "") -> str:
        return params.get(key.lower(), [default])[0]

    net = get_p("type", "tcp").lower()
    raw_path = get_p("serviceName") if net == "grpc" and get_p("serviceName") else get_p("path")

    return TrojanNode(
        name=name.strip(),
        server=server,
        port=port,
        password=password,
        network=net,
        header_type=get_p("headerType", "none"),
        security=get_p("security", "tls"),
        sni=get_p("sni") or get_p("peer"),
        alpn=get_p("alpn"),
        fp=get_p("fp"),
        host=get_p("host"),
        path=raw_path,
        pbk=get_p("pbk"),
        sid=get_p("sid"),
        spx=get_p("spx"),
        allow_insecure=_query_allows_insecure(params),
        mode=get_p("mode"),
        raw_link=link,
    )


def parse_ss(link: str) -> ShadowsocksNode:
    name = ""
    if "#" in link:
        main_part, frag = link.split("#", 1)
        name = unquote(frag).strip()
    else:
        main_part = link

    body = main_part[5:].strip()
    at_idx = body.rfind("@")
    q_idx = body.find("?", at_idx + 1)
    if q_idx != -1:
        query = body[q_idx + 1 :]
        body = body[:q_idx]
        if any(key.lower() == "plugin" for key, _ in parse_qsl(query, keep_blank_values=True)):
            raise ValueError("不支持 Shadowsocks 插件节点 (plugin)")

    if "@" in body:
        user_info, host_port = body.rsplit("@", 1)
        unquoted_user = unquote(user_info)
        # Support SIP002 plain method:password (including SS2022) as well as Base64 userinfo
        if ":" in unquoted_user and unquoted_user.lower().startswith(KNOWN_SS_METHODS):
            method, password = unquoted_user.split(":", 1)
        else:
            decoded_user = safe_b64decode(user_info)
            if ":" in decoded_user:
                method, password = decoded_user.split(":", 1)
            elif ":" in unquoted_user:
                method, password = unquoted_user.split(":", 1)
            else:
                raise ValueError("Invalid Shadowsocks userinfo")
        server, port = _split_host_port(host_port, 8388)
    else:
        decoded = safe_b64decode(body)
        if "@" not in decoded:
            raise ValueError("Unrecognized Shadowsocks link format")
        method_pass, server_port = decoded.rsplit("@", 1)
        if ":" not in method_pass:
            raise ValueError("Missing cipher/password in Shadowsocks link")
        method, password = method_pass.split(":", 1)
        server, port = _split_host_port(server_port, 8388)

    return ShadowsocksNode(
        name=name or f"ss-{server}:{port}",
        server=server,
        port=port,
        method=method.strip(),
        password=password,
        raw_link=link,
    )


def parse_socks(link: str) -> SocksNode:
    scheme_sep = link.find("://")
    rest = link[scheme_sep + 3 :]
    name = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = unquote(frag).strip()
    at_idx = rest.rfind("@")
    q_idx = rest.find("?", at_idx + 1)
    if q_idx != -1:
        query = rest[q_idx + 1 :]
        rest = rest[:q_idx]
        q_params = _parse_share_query(query)
        sec = q_params.get("security", [""])[0].lower()
        if any(_safe_bool(v) for v in q_params.get("tls", ())) or sec in ("tls", "reality"):
            raise ValueError("暂不支持带 TLS 或 REALITY 的 SOCKS5 节点")

    user = ""
    password = ""

    if "@" in rest:
        raw_auth, host_port = rest.rsplit("@", 1)
        if ":" in raw_auth:
            raw_user, raw_pass = raw_auth.split(":", 1)
            user, password = unquote(raw_user), unquote(raw_pass)
        else:
            decoded_auth = safe_b64decode(raw_auth)
            if ":" in decoded_auth:
                user, password = decoded_auth.split(":", 1)
            else:
                unquoted_auth = unquote(raw_auth)
                if ":" in unquoted_auth:
                    user, password = unquoted_auth.split(":", 1)
                else:
                    user = unquoted_auth
        server, port = _split_host_port(host_port, 1080)
    else:
        # Handle full Base64 socks://BASE64(user:pass@host:port) or plain host[:port]
        if ":" in rest:
            server, port = _split_host_port(rest, 1080)
        else:
            decoded = safe_b64decode(rest) if re.fullmatch(r"[A-Za-z0-9+/=_-]+", rest) else ""
            if "@" in decoded:
                auth_part, hp_part = decoded.rsplit("@", 1)
                if ":" in auth_part:
                    user, password = auth_part.split(":", 1)
                server, port = _split_host_port(hp_part, 1080)
            elif ":" in decoded:
                server, port = _split_host_port(decoded, 1080)
            else:
                server, port = _split_host_port(rest, 1080)

    return SocksNode(
        name=name or f"socks-{server}:{port}",
        server=server,
        port=port,
        user=user,
        password=password,
        raw_link=link,
    )


_HY2_SLASH_PORT_TAIL_RE = re.compile(r"^(\d+(?:\s*-\s*\d+)?(?:[,/]\d+(?:\s*-\s*\d+)?)*)(?=/|$)")


def _extract_hysteria2_authority(rest: str) -> str:
    at_idx = rest.rfind("@")
    slash_idx = rest.find("/", at_idx + 1)
    if slash_idx == -1:
        return rest
    head = rest[:slash_idx]
    tail = rest[slash_idx + 1 :]
    host_part = head[at_idx + 1 :] if at_idx != -1 else head
    has_port_sep = ("]:" in host_part) if host_part.startswith("[") else (":" in host_part)
    if has_port_sep and tail:
        m = _HY2_SLASH_PORT_TAIL_RE.match(tail)
        if m:
            return f"{head}/{m.group(1)}"
    return head


def _split_hysteria2_host_port(host_port: str) -> Tuple[str, int, str]:
    """Split Hysteria2 host[:port|port-range], supporting IPv6 brackets and multi-port ranges."""
    hp = host_port.strip()
    if not hp:
        raise ValueError("Invalid Hysteria2 host/port")
    if hp.startswith("["):
        end_bracket = hp.find("]")
        if end_bracket == -1:
            raise ValueError("Invalid IPv6 host in Hysteria2 link")
        server = hp[1:end_bracket].strip()
        rest = hp[end_bracket + 1 :]
        if rest and not rest.startswith(":"):
            raise ValueError("Invalid Hysteria2 host/port")
        port_part = rest[1:] if rest.startswith(":") else ""
        if rest == ":":
            raise ValueError("Missing proxy port")
    else:
        if ":" in hp:
            if hp.count(":") > 1:
                raise ValueError("IPv6 地址须使用 [...] 包裹")
            server, port_part = hp.rsplit(":", 1)
            if not port_part:
                raise ValueError("Missing proxy port")
        else:
            server, port_part = hp, ""
    server = server.strip()
    if not server:
        raise ValueError("Invalid Hysteria2 host/port")
    if not port_part:
        return server, 443, ""
    if "-" in port_part or "," in port_part or "/" in port_part:
        mport, first_port = _normalize_hysteria2_ports(port_part)
        return server, first_port, mport
    port = _parse_proxy_port(port_part, "Hysteria2")
    return server, port, ""


def parse_hysteria2(link: str) -> Hysteria2Node:
    scheme_sep = link.find("://")
    rest = link[scheme_sep + 3 :]
    name = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = unquote(frag).strip()
    query = ""
    at_idx = rest.rfind("@")
    q_idx = rest.find("?", at_idx + 1)
    if q_idx != -1:
        query = rest[q_idx + 1 :]
        rest = rest[:q_idx]
    authority = _extract_hysteria2_authority(rest)
    userinfo, separator, host_port = authority.rpartition("@")
    password = unquote(userinfo) if separator else ""
    server, port, authority_mport = _split_hysteria2_host_port(host_port)
    params = _parse_share_query(query)

    def get_p(key: str, default: str = "") -> str:
        return params.get(key.lower(), [default])[0]

    mport = get_p("mport") or get_p("ports") or authority_mport
    hop_interval = get_p("hop-interval") or get_p("hop_interval") or get_p("interval")

    return Hysteria2Node(
        name=name or f"hy2-{server}:{port}",
        server=server,
        port=port,
        password=password,
        sni=get_p("sni") or get_p("peer"),
        alpn=get_p("alpn"),
        fp=get_p("fp"),
        pin_sha256=get_p("pinsha256") or get_p("pin-sha256"),
        allow_insecure=_query_allows_insecure(params),
        obfs=get_p("obfs"),
        obfs_password=get_p("obfs-password") or get_p("obfs_password"),
        mport=mport,
        hop_interval=hop_interval,
        up=get_p("up") or get_p("upmbps"),
        down=get_p("down") or get_p("downmbps"),
        raw_link=link,
    )


def parse_node_link(link: str) -> ProxyNode:
    link = link.strip()
    lower = link.lower()
    if lower.startswith("vmess://"):
        return parse_vmess(link)
    if lower.startswith("vless://"):
        return parse_vless(link)
    if lower.startswith("trojan://"):
        return parse_trojan(link)
    if lower.startswith("ss://"):
        return parse_ss(link)
    if lower.startswith("socks://") or lower.startswith("socks5://"):
        return parse_socks(link)
    if lower.startswith("hysteria2://") or lower.startswith("hy2://"):
        return parse_hysteria2(link)
    raise ValueError(f"Unsupported protocol: {link[:12]}")


def _extract_clash_transport(p: Dict[str, Any]) -> Dict[str, Any]:
    """Extract unified transport & TLS fields from a Clash / Mihomo proxy dict."""
    network = str(p.get("network") or "tcp").lower()
    host = ""
    path = ""
    header_type = "none"
    mode = ""

    if network in ("ws", "websocket", "httpupgrade"):
        ws_opts = p.get("ws-opts")
        ws_opts = ws_opts if isinstance(ws_opts, dict) else {}
        path = str(ws_opts.get("path") or p.get("ws-path") or "")
        headers = ws_opts.get("headers") or p.get("ws-headers")
        if isinstance(headers, dict):
            host = str(headers.get("Host") or headers.get("host") or "")
        if _safe_bool(ws_opts.get("v2ray-http-upgrade")):
            network = "httpupgrade"
        if network == "httpupgrade" and _safe_bool(ws_opts.get("v2ray-http-upgrade-fast-open")):
            raise ValueError("不支持 Mihomo HTTPUpgrade Fast Open")

    grpc_opts = p.get("grpc-opts")
    if network == "grpc" and isinstance(grpc_opts, dict):
        path = str(grpc_opts.get("grpc-service-name") or path)

    xhttp_opts = p.get("xhttp-opts")
    if isinstance(xhttp_opts, dict) and network in ("xhttp", "splithttp"):
        unsupported = set(xhttp_opts) - {"path", "host", "mode"}
        if unsupported:
            raise ValueError(f"不支持的 XHTTP 参数: {', '.join(sorted(unsupported))}")
        path = str(xhttp_opts.get("path") or "/")
        host = str(xhttp_opts.get("host") or "")
        mode = str(xhttp_opts.get("mode") or "")

    http_opts = p.get("http-opts")
    if network in ("tcp", "raw") and isinstance(http_opts, dict) and http_opts:
        header_type = "http"
        paths = http_opts.get("path")
        if isinstance(paths, list) and paths:
            path = str(paths[0])
        elif isinstance(paths, str):
            path = paths
        headers = http_opts.get("headers")
        if isinstance(headers, dict):
            h_list = headers.get("Host") or headers.get("host")
            if isinstance(h_list, list) and h_list:
                host = str(h_list[0])
            elif isinstance(h_list, str):
                host = h_list

    sni = str(p.get("servername") or p.get("sni") or "").strip()
    if p.get("fingerprint"):
        raise ValueError("暂不支持 Clash TLS 证书指纹锁定 (fingerprint)")
    fp = str(p.get("client-fingerprint") or "").strip()
    raw_alpn = p.get("alpn")
    if isinstance(raw_alpn, list):
        alpn = ",".join(str(x) for x in raw_alpn if x)
    else:
        alpn = str(raw_alpn or "")

    allow_insecure = _safe_bool(p.get("skip-cert-verify", False))

    reality_opts = p.get("reality-opts")
    if reality_opts is not None and not isinstance(reality_opts, dict):
        raise ValueError("Clash reality-opts 必须为映射")
    pbk = ""
    sid = ""
    spx = ""
    if isinstance(reality_opts, dict):
        pbk = str(reality_opts.get("public-key") or "")
        sid = str(reality_opts.get("short-id") or "")
        spx = str(reality_opts.get("spider-x") or "")

    return {
        "network": network,
        "host": host,
        "path": path,
        "mode": mode,
        "header_type": header_type,
        "sni": sni,
        "fp": fp,
        "alpn": alpn,
        "allow_insecure": allow_insecure,
        "has_reality": isinstance(reality_opts, dict) and bool(reality_opts),
        "pbk": pbk,
        "sid": sid,
        "spx": spx,
    }


def _clash_tls_enabled(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "tls"):
        return True
    if text in ("0", "false", "no", "off", "none", ""):
        return False
    raise ValueError("Clash tls 配置无效，请使用布尔值")


def _clash_str(value: Any) -> str:
    return "" if value is None else str(value)


def parse_clash_proxy(p: Dict[str, Any]) -> ProxyNode:
    ptype = _clash_str(p.get("type")).lower()
    name = _clash_str(p.get("name")).strip()
    server = _clash_str(p.get("server")).strip()
    if ptype in ("hysteria2", "hy2"):
        if p.get("ca") or p.get("ca-str"):
            raise ValueError("暂不支持 Clash Hysteria2 自定义 CA 证书 (ca / ca-str)")
        raw_ports = _clash_str(p.get("ports")).strip() or _clash_str(p.get("mport")).strip()
        mport, first_hop_port = _normalize_hysteria2_ports(raw_ports)
        raw_port = p.get("port")
        if first_hop_port and (
            raw_port is None
            or raw_port == ""
            or (not isinstance(raw_port, bool) and raw_port in (0, "0"))
        ):
            port = first_hop_port
        else:
            port = _parse_proxy_port(443 if raw_port is None else raw_port, "Clash")
        raw_pw = p.get("password") if p.get("password") is not None else p.get("auth")
        raw_alpn = p.get("alpn")
        if isinstance(raw_alpn, list):
            alpn = ",".join(str(x) for x in raw_alpn if x)
        else:
            alpn = _clash_str(raw_alpn)
        return Hysteria2Node(
            name=name,
            server=server,
            port=port,
            password=_clash_str(raw_pw),
            sni=_clash_str(p.get("sni") or p.get("servername")).strip(),
            alpn=alpn,
            fp=_clash_str(p.get("client-fingerprint")).strip(),
            pin_sha256=_clash_str(p.get("fingerprint") or p.get("pinSHA256") or p.get("pin-sha256")).strip(),
            allow_insecure=_safe_bool(p.get("skip-cert-verify", False)),
            obfs=_clash_str(p.get("obfs")).strip(),
            obfs_password=_clash_str(p.get("obfs-password")),
            mport=mport,
            hop_interval=p.get("hop-interval"),
            up=p.get("up"),
            down=p.get("down"),
        )
    port = _parse_proxy_port(p.get("port", 443), "Clash")
    password = _clash_str(p.get("password"))
    if ptype in ("vmess", "vless", "trojan"):
        tr = _extract_clash_transport(p)

    if ptype == "vmess":
        if tr["has_reality"]:
            raise ValueError("不支持 Clash VMess 的 REALITY 配置")
        return VMessNode(
            name=name,
            server=server,
            port=port,
            uuid=str(p.get("uuid") or ""),
            alter_id=_safe_int(p.get("alterId"), 0),
            security=str(p.get("cipher") or "auto"),
            network=tr["network"],
            header_type=tr["header_type"],
            host=tr["host"],
            path=tr["path"],
            tls="tls" if _clash_tls_enabled(p.get("tls")) else "",
            sni=tr["sni"],
            alpn=tr["alpn"],
            fp=tr["fp"],
            allow_insecure=tr["allow_insecure"],
            mode=tr["mode"],
        )
    if ptype == "vless":
        security = "reality" if tr["has_reality"] else ("tls" if _clash_tls_enabled(p.get("tls")) else "none")
        return VLESSNode(
            name=name,
            server=server,
            port=port,
            uuid=str(p.get("uuid") or ""),
            flow=str(p.get("flow") or ""),
            encryption=str(p.get("encryption") or "none"),
            network=tr["network"],
            header_type=tr["header_type"],
            host=tr["host"],
            path=tr["path"],
            security=security,
            sni=tr["sni"],
            alpn=tr["alpn"],
            fp=tr["fp"],
            pbk=tr["pbk"],
            sid=tr["sid"],
            spx=tr["spx"],
            allow_insecure=tr["allow_insecure"],
            mode=tr["mode"],
        )
    if ptype == "trojan":
        security = "reality" if tr["has_reality"] else ("tls" if _clash_tls_enabled(p.get("tls", True)) else "none")
        return TrojanNode(
            name=name,
            server=server,
            port=port,
            password=password,
            network=tr["network"],
            header_type=tr["header_type"],
            security=security,
            sni=tr["sni"],
            alpn=tr["alpn"],
            fp=tr["fp"],
            host=tr["host"],
            path=tr["path"],
            pbk=tr["pbk"],
            sid=tr["sid"],
            spx=tr["spx"],
            allow_insecure=tr["allow_insecure"],
            mode=tr["mode"],
        )
    if ptype in ("ss", "shadowsocks"):
        if p.get("plugin") or p.get("plugin-opts"):
            raise ValueError("不支持 Shadowsocks 插件节点 (plugin / plugin-opts)")
        return ShadowsocksNode(
            name=name,
            server=server,
            port=port,
            method=str(p.get("cipher") or ""),
            password=password,
        )
    if ptype in ("socks", "socks5"):
        if _clash_tls_enabled(p.get("tls")) or p.get("fingerprint"):
            raise ValueError("暂不支持带 TLS 或证书指纹锁定的 Clash SOCKS5 节点")
        return SocksNode(
            name=name,
            server=server,
            port=port,
            user=_clash_str(p.get("username")),
            password=password,
        )
    raise ValueError(f"Unsupported clash proxy type: {ptype}")
