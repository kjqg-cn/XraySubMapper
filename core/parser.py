import base64
import json
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, parse_qsl, unquote, urlparse


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


def _split_host_port(host_port: str, default_port: int = 443) -> Tuple[str, int]:
    """Safely split host:port including bracketed IPv6 like [2001:db8::1]:8388."""
    parsed = urlparse("//" + host_port.strip())
    if not parsed.hostname or parsed.path not in ("", "/"):
        raise ValueError("Invalid proxy host/port")
    if parsed.netloc.endswith(":"):
        raise ValueError("Missing proxy port")
    port = parsed.port if parsed.port is not None else default_port
    if not 1 <= port <= 65535:
        raise ValueError("Proxy port must be in 1..65535")
    return parsed.hostname, port


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


def _apply_transport_settings(
    stream: Dict[str, Any],
    network: str,
    host: str = "",
    path: str = "",
    header_type: str = "none",
    mode: str = "",
) -> None:
    """Populate Xray 26.x compatible streamSettings transport fields."""
    net = (network or "tcp").lower()
    _validate_transport(net)
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
    else:
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


class ProxyNode:
    def __init__(self, name: str, protocol: str, server: str, port: int, raw_link: str = ""):
        self.server = (server or "").strip("[] ")
        self.port = _safe_int(port, 443)
        self.protocol = protocol.lower()
        self.name = (name or "").strip() or f"{self.protocol}-{self.server}:{self.port}"
        self.raw_link = raw_link
        self.local_port: int = 0
        self.port_pinned: bool = False
        # Auto-disable placeholder info nodes (e.g. 127.0.0.1 / port <= 1)
        self.enabled: bool = not self.is_placeholder_node()
        self.latency_ms: Optional[int] = None
        self.last_error: str = ""
        self.exit_ip: str = ""

    def is_placeholder_node(self) -> bool:
        return self.server.lower() in DUMMY_SERVERS or self.port <= 1 or self.port > 65535

    def to_outbound(self, tag: str) -> Dict[str, Any]:
        raise NotImplementedError

    def connection_key(self) -> str:
        """Stable identity excluding display name, port assignment and probe results."""
        return json.dumps(self.to_outbound("node"), sort_keys=True, ensure_ascii=False)

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

    def to_outbound(self, tag: str) -> Dict[str, Any]:
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

    def to_outbound(self, tag: str) -> Dict[str, Any]:
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

    def to_outbound(self, tag: str) -> Dict[str, Any]:
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
        self.method = method
        self.password = password

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"method": self.method, "password": self.password})
        return d

    def to_outbound(self, tag: str) -> Dict[str, Any]:
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

    def to_outbound(self, tag: str) -> Dict[str, Any]:
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
    mode = ""
    if net == "grpc" and data.get("type") == "multi":
        mode = "multi"

    return VMessNode(
        name=str(data.get("ps") or unquote(fragment)).strip(),
        server=str(data.get("add") or "").strip(),
        port=_safe_int(data.get("port"), 443),
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
    port = 443 if u.port is None else u.port
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
    port = 443 if u.port is None else u.port
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
    if "?" in body:
        body, query = body.split("?", 1)
        if "plugin" in parse_qs(query, keep_blank_values=True):
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
    if "?" in rest:
        rest = rest.split("?", 1)[0]

    user = ""
    password = ""

    if "@" in rest:
        raw_auth, host_port = rest.rsplit("@", 1)
        unquoted_auth = unquote(raw_auth)
        if ":" in unquoted_auth:
            user, password = unquoted_auth.split(":", 1)
        else:
            decoded_auth = safe_b64decode(raw_auth)
            if ":" in decoded_auth:
                user, password = decoded_auth.split(":", 1)
            else:
                user = unquoted_auth
        server, port = _split_host_port(host_port, 1080)
    else:
        # Handle full Base64 socks://BASE64(user:pass@host:port) or plain host:port
        if ":" in rest:
            server, port = _split_host_port(rest, 1080)
        else:
            decoded = safe_b64decode(rest)
            if "@" in decoded:
                auth_part, hp_part = decoded.rsplit("@", 1)
                if ":" in auth_part:
                    user, password = auth_part.split(":", 1)
                server, port = _split_host_port(hp_part, 1080)
            elif ":" in decoded:
                server, port = _split_host_port(decoded, 1080)
            else:
                raise ValueError("Invalid socks link")

    return SocksNode(
        name=name or f"socks-{server}:{port}",
        server=server,
        port=port,
        user=user,
        password=password,
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

    h2_opts = p.get("h2-opts")
    if isinstance(h2_opts, dict):
        path = str(h2_opts.get("path") or path)
        h2_hosts = h2_opts.get("host")
        if isinstance(h2_hosts, list) and h2_hosts:
            host = str(h2_hosts[0])
        elif isinstance(h2_hosts, str):
            host = h2_hosts

    http_opts = p.get("http-opts")
    if isinstance(http_opts, dict):
        header_type = "http"
        paths = http_opts.get("path")
        if isinstance(paths, list) and paths:
            path = str(paths[0])
        headers = http_opts.get("headers")
        if isinstance(headers, dict):
            h_list = headers.get("Host") or headers.get("host")
            if isinstance(h_list, list) and h_list:
                host = str(h_list[0])

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
    if isinstance(reality_opts, dict):
        pbk = str(reality_opts.get("public-key") or "")
        sid = str(reality_opts.get("short-id") or "")

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


def parse_clash_proxy(p: Dict[str, Any]) -> ProxyNode:
    ptype = str(p.get("type", "")).lower()
    name = str(p.get("name", "")).strip()
    server = str(p.get("server", "")).strip()
    port = _safe_int(p.get("port"), 443)
    if ptype in ("vmess", "vless", "trojan"):
        tr = _extract_clash_transport(p)

    if ptype == "vmess":
        if tr["has_reality"]:
            raise ValueError("不支持 Clash VMess 的 REALITY 配置")
        return VMessNode(
            name=name,
            server=server,
            port=port,
            uuid=str(p.get("uuid", "")),
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
            uuid=str(p.get("uuid", "")),
            flow=str(p.get("flow") or ""),
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
            allow_insecure=tr["allow_insecure"],
            mode=tr["mode"],
        )
    if ptype == "trojan":
        security = "reality" if tr["has_reality"] else ("tls" if _clash_tls_enabled(p.get("tls", True)) else "none")
        return TrojanNode(
            name=name,
            server=server,
            port=port,
            password=str(p.get("password", "")),
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
            method=str(p.get("cipher", "")),
            password=str(p.get("password", "")),
        )
    if ptype in ("socks", "socks5"):
        if _clash_tls_enabled(p.get("tls")) or p.get("fingerprint"):
            raise ValueError("暂不支持带 TLS 或证书指纹锁定的 Clash SOCKS5 节点")
        return SocksNode(
            name=name,
            server=server,
            port=port,
            user=str(p.get("username", "")),
            password=str(p.get("password", "")),
        )
    raise ValueError(f"Unsupported clash proxy type: {ptype}")
