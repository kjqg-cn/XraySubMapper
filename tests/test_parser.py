import base64
import json

import pytest

from core.parser import node_from_dict, parse_clash_proxy, parse_node_link
from core.subscription import parse_subscription_content

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


@pytest.mark.parametrize("authority", ["example.com:9443", "[2001:db8::1]:9443"])
@pytest.mark.parametrize("suffix", ["", "/", "/#tag"])
def test_ss_authority_port_with_optional_slash(authority, suffix):
    node = parse_node_link(f"ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@{authority}{suffix}")
    assert node.port == 9443
    assert node.server == ("2001:db8::1" if authority.startswith("[") else "example.com")


@pytest.mark.parametrize("port", ["bad", "0", "65536", ""])
def test_ss_rejects_explicit_invalid_port(port):
    with pytest.raises(ValueError):
        parse_node_link(f"ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:{port}/")


@pytest.mark.parametrize("protocol,auth", [("vless", UUID), ("trojan", "p%40ss%3Aword")])
def test_query_values_are_decoded_once(protocol, auth):
    node = parse_node_link(f"{protocol}://{auth}@example.com:443?type=ws&security=tls&path=%2Fws%2F%252F")
    assert node.path == "/ws/%2F"
    assert node.to_outbound("test")["streamSettings"]["wsSettings"]["path"] == "/ws/%2F"
    if protocol == "trojan":
        assert node.password == "p@ss:word"


@pytest.mark.parametrize("protocol,auth", [("vless", UUID), ("trojan", "my:pass:word")])
def test_literal_plus_and_case_insensitive_query(protocol, auth):
    node = parse_node_link(f"{protocol}://{auth}@example.com?Type=grpc&servicename=svc+a%2Bb")
    assert node.port == 443
    assert node.to_outbound("test")["streamSettings"]["grpcSettings"]["serviceName"] == "svc+a+b"
    if protocol == "trojan":
        assert node.password == "my:pass:word"


@pytest.mark.parametrize("prefix", [f"vless://{UUID}", "trojan://password"])
def test_explicit_zero_port_keeps_placeholder_disabled(prefix):
    node = parse_node_link(f"{prefix}@example.com:0")
    assert node.port == 0 and not node.enabled


@pytest.mark.parametrize("network", ["kcp", "quic", "h2", "http", "unknown"])
def test_unsupported_transports_report_node_error(network):
    valid = "trojan://password@example.com:443#valid"
    bad = f"vless://{UUID}@example.com:443?type={network}&security=tls"
    nodes, errors = parse_subscription_content(valid + "\n" + bad)
    assert len(nodes) == 1 and nodes[0].name == "valid"
    assert len(errors) == 1 and network in errors[0]


@pytest.mark.parametrize("text", [
    f"vless://{UUID}@example.com:443?security=tls&allowInsecure=1",
    f"vless://{UUID}@example.com:443?security=tls&allowInsecure=0&allowinsecure=1",
    "trojan://password@example.com?SECURITY=TLS&insecure=false&AllowInsecure=YES",
    "proxies:\n  - {name: insecure, type: trojan, server: example.com, port: 443, password: test, skip-cert-verify: true}",
])
def test_removed_tls_option_is_rejected_at_import(text):
    nodes, errors = parse_subscription_content(text)
    assert not nodes
    assert any("skip-cert-verify" in error for error in errors)


@pytest.mark.parametrize("text", [
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:9443/?plugin=v2ray-plugin%3Bmode%3Dwebsocket",
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:9443/?%50lugin=v2ray-plugin",
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:9443/?PLUGIN=",
    "proxies:\n  - {name: plugin, type: ss, server: example.com, port: 9443, cipher: aes-128-gcm, password: test, plugin: v2ray-plugin}",
])
def test_unsupported_ss_plugins_are_not_silently_accepted(text):
    nodes, errors = parse_subscription_content(text)
    assert not nodes and any("plugin" in error for error in errors)


@pytest.mark.parametrize("text", [
    f"vless://{UUID}@example.com:",
    "trojan://password@example.com:",
    "vless://@example.com:443",
    "proxies: [{type: ss, server: example.com, port: 8388, cipher: null}]",
    "proxies: [{type: trojan, server: example.com, port: bad, password: testing}]",
    "proxies: [{type: trojan, server: example.com, port: 1.5, password: testing}]",
])
def test_invalid_ports_and_required_fields_are_reported_at_import(text):
    nodes, errors = parse_subscription_content(text)
    assert not nodes and len(errors) == 1


@pytest.mark.parametrize("bad", [
    "trojan://@example.com:443",
    "proxies: [{type: trojan, server: example.com, port: 443, password: null}]",
    "proxies: [{type: vmess, server: example.com, port: 443, uuid: null}]",
    "proxies: [{type: vmess, server: example.com, port: 443, uuid: ' '}]",
    "vmess://" + base64.b64encode(json.dumps({"add": "example.com", "port": 443}).encode()).decode(),
])
def test_missing_vmess_and_trojan_credentials_do_not_break_valid_subscription(bad):
    if bad.startswith("proxies:"):
        content = bad.replace("proxies: [", "proxies: [{type: trojan, name: good, server: example.net, port: 443, password: valid}, ", 1)
    else:
        content = "trojan://valid@example.net:443#good\n" + bad
    nodes, errors = parse_subscription_content(content)
    assert [node.name for node in nodes] == ["good"]
    assert len(errors) == 1


@pytest.mark.parametrize("port", ["bad", "", None, True, 1.5, -1, 65536])
def test_vmess_rejects_malformed_explicit_port(port):
    payload = base64.b64encode(json.dumps({"add": "example.com", "id": UUID, "port": port}).encode()).decode()
    nodes, errors = parse_subscription_content("vmess://" + payload)
    assert not nodes and len(errors) == 1


@pytest.mark.parametrize("protocol", ["vmess", "trojan"])
def test_placeholder_nodes_can_omit_credentials(protocol):
    node = parse_clash_proxy({"type": protocol, "name": "remaining quota", "server": "127.0.0.1", "port": 1})
    assert not node.enabled


@pytest.mark.parametrize("method", ["aes-256-gcm", "2022-blake3-aes-128-gcm", "none"])
@pytest.mark.parametrize("source", ["share", "clash_null", "clash_empty"])
def test_empty_shadowsocks_password_is_rejected_without_losing_valid_nodes(method, source):
    if source == "share":
        content = f"trojan://valid@example.net:443#good\nss://{method}:@example.com:8388"
    else:
        password = "null" if source == "clash_null" else "''"
        content = ("proxies: [{type: trojan, name: good, server: example.net, password: valid}, "
                   f"{{type: ss, server: example.com, port: 8388, cipher: {method}, password: {password}}}]")
    nodes, errors = parse_subscription_content(content)
    assert [node.name for node in nodes] == ["good"]
    assert len(errors) == 1 and "Shadowsocks 缺少密码" in errors[0]


@pytest.mark.parametrize("username,password", [(None, None), ("", None), ("user", None), (0, 0), ("None", "None")])
def test_clash_socks_credentials_distinguish_null_from_literal_values(username, password):
    proxy = {"type": "socks5", "server": "example.com", "port": 1080,
             "username": username, "password": password}
    node = parse_clash_proxy(proxy)
    server = node.to_outbound("test")["settings"]["servers"][0]
    if username is None or username == "":
        assert "users" not in server
    else:
        assert server["users"] == [{"user": str(username), "pass": "" if password is None else str(password)}]
    assert node_from_dict(node.to_dict()).to_outbound("test") == node.to_outbound("test")


@pytest.mark.parametrize("password", [0, "None", " pass "])
def test_clash_shadowsocks_preserves_nonempty_passwords(password):
    node = parse_clash_proxy({"type": "ss", "server": "example.com", "port": 8388,
                              "cipher": "aes-256-gcm", "password": password})
    assert node.password == str(password)


def test_shadowsocks_placeholder_can_omit_password():
    node = parse_clash_proxy({"type": "ss", "server": "127.0.0.1", "port": 1,
                              "cipher": "aes-256-gcm", "password": None})
    assert not node.enabled and node.password == ""


def test_clash_null_server_is_disabled_and_null_name_uses_default():
    placeholder = parse_clash_proxy({"type": "socks5", "name": None, "server": None, "port": 1080})
    assert placeholder.server == "" and not placeholder.enabled
    node = parse_clash_proxy({"type": "socks5", "name": None, "server": "example.com", "port": 1080})
    assert node.name == "socks-example.com:1080" and node.enabled
    numeric = parse_clash_proxy({"type": "socks5", "name": 0, "server": "example.com", "port": 1080})
    assert numeric.name == "0"


def test_empty_clash_http_opts_leaves_plain_tcp():
    proxy = {"type": "vless", "server": "example.com", "uuid": UUID, "network": "tcp", "http-opts": {}}
    stream = parse_clash_proxy(proxy).to_outbound("t")["streamSettings"]
    assert stream["network"] == "tcp" and "tcpSettings" not in stream


@pytest.mark.parametrize("single_value", [False, True])
def test_clash_http_path_and_host_preserve_single_and_list_values(single_value):
    path = "/custom" if single_value else ["/custom"]
    host = "cdn.example.com" if single_value else ["cdn.example.com"]
    proxy = {"type": "vless", "server": "example.com", "uuid": UUID, "network": "tcp",
             "http-opts": {"path": path, "headers": {"Host": host}}}
    request = parse_clash_proxy(proxy).to_outbound("t")["streamSettings"]["tcpSettings"]["header"]["request"]
    assert request == {"path": ["/custom"], "headers": {"Host": ["cdn.example.com"]}}


def test_clash_xhttp_fields_survive_cache_roundtrip():
    node = parse_clash_proxy({
        "type": "vless", "name": "xhttp", "server": "example.com", "port": 443,
        "uuid": UUID, "tls": True, "network": "xhttp",
        "xhttp-opts": {"path": "/custom", "host": "cdn.example.com", "mode": "stream-one"},
    })
    restored = node_from_dict(node.to_dict())
    assert restored.to_outbound("test")["streamSettings"]["xhttpSettings"] == {
        "path": "/custom", "host": "cdn.example.com", "mode": "stream-one",
    }


def test_unknown_xhttp_options_raise_instead_of_being_dropped():
    with pytest.raises(ValueError, match="XHTTP"):
        parse_clash_proxy({"type": "vless", "network": "xhttp", "xhttp-opts": {"extra": {"test": True}}})


def test_clash_legacy_websocket_and_mihomo_httpupgrade():
    proxy = {"type": "vless", "server": "example.com", "uuid": UUID, "network": "ws",
             "ws-path": "/legacy", "ws-headers": {"Host": "cdn.example.com"}}
    stream = parse_clash_proxy(proxy).to_outbound("t")["streamSettings"]
    assert stream["wsSettings"] == {"path": "/legacy", "host": "cdn.example.com"}
    proxy["ws-opts"] = {"v2ray-http-upgrade": True, "path": "/upgrade"}
    stream = parse_clash_proxy(proxy).to_outbound("t")["streamSettings"]
    assert stream["network"] == "httpupgrade"
    assert stream["httpupgradeSettings"] == {"path": "/upgrade", "host": "cdn.example.com"}


def test_clash_rejects_certificate_pin_and_encrypted_socks():
    tls_proxy = {"type": "vless", "server": "example.com", "uuid": UUID, "tls": True,
                 "client-fingerprint": "chrome", "fingerprint": "ab" * 32}
    with pytest.raises(ValueError, match="证书指纹锁定"):
        parse_clash_proxy(tls_proxy)
    with pytest.raises(ValueError, match="TLS"):
        parse_clash_proxy({"type": "socks5", "server": "example.com", "tls": True, "skip-cert-verify": True})
    with pytest.raises(ValueError, match="tls 配置无效"):
        parse_clash_proxy({"type": "socks5", "server": "example.com", "tls": "unexpected"})


def test_plain_node_accepts_irrelevant_certificate_option_and_invalid_security_is_reported():
    proxy = {"type": "vless", "server": "example.com", "uuid": UUID, "tls": False, "skip-cert-verify": True}
    assert parse_clash_proxy(proxy).to_outbound("t")["streamSettings"]["security"] == "none"
    with pytest.raises(ValueError, match="缺少公钥"):
        parse_clash_proxy(dict(proxy, **{"reality-opts": {"short-id": "ab"}}))
    with pytest.raises(ValueError, match="安全配置"):
        parse_node_link("trojan://password@example.com?security=xtls")


def test_vmess_unpadded_payload_with_fragment():
    encoded = base64.urlsafe_b64encode(json.dumps({"add": "example.com", "id": UUID}).encode()).decode().rstrip("=")
    assert parse_node_link(f"vmess://{encoded}#My%20Node").name == "My Node"


@pytest.mark.parametrize("encoded", [False, True])
@pytest.mark.parametrize("inner_bom", [False, True])
def test_bom_single_and_multiline_subscriptions(encoded, inner_bom):
    content = "trojan://password@example.com:443#first\ntrojan://password@example.net:443#second"
    if inner_bom:
        content = "\ufeff" + content
    if encoded:
        content = base64.b64encode(content.encode()).decode()
    nodes, errors = parse_subscription_content("\ufeff" + content)
    assert [n.name for n in nodes] == ["first", "second"]
    assert not errors


def test_hysteria2_share_links_outbound_and_cache_roundtrip():
    pin = "ab" * 32
    formatted_pin = "sha256:" + ":".join(pin[i : i + 2].upper() for i in range(0, 64, 2))
    full_link = (
        f"hy2://user%3Apass%2F1@[2001:db8::1]:8443"
        f"?sni=hy2.example.com&alpn=h3&fp=chrome&insecure=1&pinSHA256={formatted_pin}"
        f"&obfs=salamander&obfs-password=obfs%2Bpw&mport=20000-30000,40000"
        f"&hop-interval=15s&upmbps=50&downmbps=200#HK-HY2"
    )
    node = parse_node_link(full_link)
    assert node.protocol == "hysteria2"
    assert node.name == "HK-HY2"
    assert node.server == "2001:db8::1" and node.port == 8443
    assert node.password == "user:pass/1"
    out = node.to_outbound("tag0")
    assert out["protocol"] == "hysteria"
    assert out["settings"] == {"version": 2, "address": "2001:db8::1", "port": 8443}
    stream = out["streamSettings"]
    assert stream["network"] == "hysteria" and stream["security"] == "tls"
    assert stream["hysteriaSettings"] == {"version": 2, "auth": "user:pass/1"}
    assert stream["tlsSettings"] == {
        "serverName": "hy2.example.com",
        "fingerprint": "chrome",
        "alpn": ["h3"],
        "pinnedPeerCertSha256": pin,
    }
    assert "allowInsecure" not in stream["tlsSettings"]
    assert stream["finalmask"]["udp"] == [
        {"type": "salamander", "settings": {"password": "obfs+pw"}},
        {"type": "udphop", "settings": {"mode": "intervalremote", "remotePorts": "20000-30000,40000", "interval": "15"}},
    ]
    assert stream["finalmask"]["quicParams"] == {
        "congestion": "brutal",
        "brutalUp": "50 mbps",
        "brutalDown": "200 mbps",
    }
    assert node_from_dict(node.to_dict()).to_outbound("tag0") == out

    # Authority multi-port range & default port 443
    hop_auth = parse_node_link("hysteria2://secret@example.com:20000-20010,20020/?peer=sni.example.com#HopAuth")
    assert hop_auth.port == 20000 and hop_auth.mport == "20000-20010,20020"
    assert hop_auth.to_outbound("t")["streamSettings"]["tlsSettings"]["serverName"] == "sni.example.com"
    assert "finalmask" not in parse_node_link("hysteria2://secret@example.com#Plain").to_outbound("t")["streamSettings"]


def test_hysteria2_clash_yaml_and_placeholders():
    pin = "cd" * 32
    node = parse_clash_proxy({
        "name": "Clash-HY2",
        "type": "hysteria2",
        "server": "hy2.example.net",
        "ports": "30000-30100/30200",
        "hop-interval": "10s-20s",
        "password": 0,
        "sni": "sni.example.net",
        "alpn": ["h3"],
        "client-fingerprint": "firefox",
        "fingerprint": pin,
        "skip-cert-verify": True,
        "obfs": "salamander",
        "obfs-password": 0,
        "up": 50,
        "down": "1.5 gbps",
    })
    assert node.port == 30000 and node.password == "0" and node.obfs_password == "0"
    stream = node.to_outbound("t")["streamSettings"]
    assert stream["tlsSettings"]["pinnedPeerCertSha256"] == pin
    assert stream["finalmask"]["udp"][0]["type"] == "salamander"
    assert stream["finalmask"]["udp"][1] == {
        "type": "udphop",
        "settings": {"mode": "intervalremote", "remotePorts": "30000-30100,30200", "interval": "10-20"},
    }
    assert stream["finalmask"]["quicParams"] == {
        "congestion": "brutal",
        "brutalUp": "50 mbps",
        "brutalDown": "1.5 gbps",
    }
    assert node_from_dict(node.to_dict()).to_outbound("t") == node.to_outbound("t")

    zero_bw = parse_clash_proxy({"type": "hy2", "server": "example.com", "port": 443, "auth": "pw", "up": 0, "down": "0"})
    assert "finalmask" not in zero_bw.to_outbound("t")["streamSettings"]

    placeholder_clash = parse_clash_proxy({"type": "hysteria2", "server": "127.0.0.1", "port": 1, "skip-cert-verify": True})
    assert not placeholder_clash.enabled
    placeholder_link = parse_node_link("hy2://@example.com:0#剩余流量")
    assert placeholder_link.port == 0 and not placeholder_link.enabled


@pytest.mark.parametrize("text,match", [
    ("hy2://@example.com:443#no-pw", "缺少密码"),
    ("hy2://pw@example.com:443?insecure=1#no-pin", "pinSHA256"),
    ("hy2://pw@example.com:443?pinSHA256=deadbeef#bad-pin", "pinSHA256"),
    ("hy2://pw@example.com:443?obfs=salamander#no-obfs-pw", "obfs-password"),
    ("hy2://pw@example.com:443?obfs=gecko&obfs-password=1#bad-obfs", "混淆"),
    ("hy2://pw@example.com:443?mport=30000-20000#bad-mport", "端口跳跃"),
    ("hy2://pw@example.com:443?mport=20000-20010&hop-interval=4#bad-interval", ">= 5"),
    ("hy2://pw@example.com:443?mport=20000-20010&hop-interval=20-10#bad-range", "下限"),
    ("hy2://pw@example.com:443?up=500kbps#too-slow", "525 kbps"),
    ("hy2://pw@2001:db8::1#unbracketed-v6", "IPv6"),
    ("proxies:\n  - {type: hysteria2, server: example.com, port: 443, password: pw, ca-str: pem}", "自定义 CA"),
    ("proxies:\n  - {type: hysteria2, server: example.com, port: 443, password: null}", "缺少密码"),
])
def test_hysteria2_rejects_invalid_configs_without_breaking_subscription(text, match):
    if text.startswith("proxies:"):
        content = text + "\n  - {name: ok, type: hysteria2, server: ok.example.com, port: 443, password: pw}"
    else:
        content = "hy2://pw@ok.example.com:443#ok\n" + text
    nodes, errors = parse_subscription_content(content)
    assert [n.name for n in nodes] == ["ok"]
    assert len(errors) == 1 and match in errors[0]


def test_clash_stale_h2_opts_does_not_overwrite_active_transport():
    proxy = {
        "name": "ws-with-stale-h2",
        "type": "vless",
        "server": "example.com",
        "port": 443,
        "uuid": UUID,
        "tls": True,
        "network": "ws",
        "ws-opts": {"path": "/real-ws", "headers": {"Host": "real.example.com"}},
        "h2-opts": {"path": "/stale-h2", "host": ["wrong.example.com"]},
    }
    ws = parse_clash_proxy(proxy).to_outbound("t")["streamSettings"]["wsSettings"]
    assert ws == {"path": "/real-ws", "host": "real.example.com"}


def test_node_name_sanitizes_newlines_and_control_chars():
    node = parse_node_link("trojan://pw@example.com:443#HK%0Ahttp://attacker:8080%0D%0Aextra")
    assert "\n" not in node.name and "\r" not in node.name
    assert node.name == "HK http://attacker:8080 extra"


def test_hysteria2_slash_authority_shorthand_bandwidth_and_clash_fallbacks():
    slash_node = parse_node_link("hy2://pw@example.com:20000-20010/20020/?up=50M&down=1G#slash-hop")
    assert slash_node.port == 20000
    assert slash_node.mport == "20000-20010,20020"
    quic = slash_node.to_outbound("t")["streamSettings"]["finalmask"]["quicParams"]
    assert quic == {"congestion": "brutal", "brutalUp": "50 mbps", "brutalDown": "1 gbps"}

    clash_node = parse_clash_proxy({
        "name": "hy2-fallback",
        "type": "hysteria2",
        "server": "example.com",
        "port": 0,
        "ports": "",
        "mport": "20000 - 20010",
        "password": "pw",
        "up": "525K",
        "down": "100m",
    })
    assert clash_node.enabled and clash_node.port == 20000 and clash_node.mport == "20000-20010"
    assert clash_node.up == "525 kbps" and clash_node.down == "100 mbps"


def test_placeholder_nodes_unified_import_and_runtime_revalidation():
    for proto in ("vmess", "vless", "trojan", "hysteria2"):
        ph = parse_clash_proxy({
            "type": proto, "name": "quota", "server": "127.0.0.1", "port": 1, "skip-cert-verify": True,
        })
        assert not ph.enabled
        assert ph.connection_key()
        ph.enabled = True
        with pytest.raises(ValueError):
            ph.to_outbound("t")


def test_clash_vless_encryption_spiderx_and_vmess_xhttp_mode():
    vless = parse_clash_proxy({
        "type": "vless", "server": "example.com", "port": 443, "uuid": UUID,
        "encryption": "mlkem768x25519plus.native.0rtt.test",
        "reality-opts": {"public-key": "pk", "short-id": "12", "spider-x": "/spx"},
    })
    out = vless.to_outbound("t")
    assert out["settings"]["vnext"][0]["users"][0]["encryption"] == "mlkem768x25519plus.native.0rtt.test"
    assert out["streamSettings"]["realitySettings"]["spiderX"] == "/spx"

    payload = base64.b64encode(json.dumps({
        "add": "example.com", "port": 443, "id": UUID, "net": "xhttp", "path": "/xh", "mode": "stream-one",
    }).encode()).decode()
    vmess = parse_node_link("vmess://" + payload)
    assert vmess.to_outbound("t")["streamSettings"]["xhttpSettings"]["mode"] == "stream-one"


def test_socks_and_ss_edge_cases_and_connection_key_cache_invalidation():
    socks_enc = parse_node_link("socks5://user%3A1:pass%402@example.com:1080#s1")
    assert socks_enc.user == "user:1" and socks_enc.password == "pass@2"

    socks_default_port = parse_node_link("socks5://example.com#s2")
    assert socks_default_port.server == "example.com" and socks_default_port.port == 1080

    with pytest.raises(ValueError, match="TLS"):
        parse_node_link("socks5://u:p@example.com:1080?tls=1#s-tls")

    ss_q = parse_node_link("ss://aes-256-gcm:abc?def@example.com:8388#ss-q")
    assert ss_q.password == "abc?def" and ss_q.server == "example.com" and ss_q.port == 8388

    before = ss_q.connection_key()
    ss_q.server = "other.example.com"
    assert ss_q.connection_key() != before


def test_r2_placeholder_removed_transport_hysteria2_raw_pw_and_raw_link_cache():
    ph_h2 = parse_clash_proxy({"type": "vless", "name": "quota-h2", "server": "127.0.0.1", "port": 1, "uuid": UUID, "network": "h2"})
    ph_quic = parse_clash_proxy({"type": "vless", "name": "quota-q", "server": "127.0.0.1", "port": 1, "uuid": UUID, "network": "quic"})
    assert not ph_h2.enabled and not ph_quic.enabled
    assert ph_h2.connection_key() != ph_quic.connection_key()
    ph_h2.enabled = True
    with pytest.raises(ValueError, match="h2"):
        ph_h2.to_outbound("t")

    q_pw = parse_node_link("hy2://pass?word@example.com:443#q-pw")
    assert q_pw.password == "pass?word" and q_pw.server == "example.com" and q_pw.port == 443

    slash_pw = parse_node_link("hy2://abc/def@example.com:443#slash-pw")
    assert slash_pw.password == "abc/def" and slash_pw.server == "example.com" and slash_pw.port == 443

    both = parse_node_link("hy2://abc/def@example.com:20000-20010/20020/?sni=s.example.com#both")
    assert both.password == "abc/def" and both.mport == "20000-20010,20020" and both.sni == "s.example.com"

    cached = both.connection_key()
    both.raw_link = "hy2://changed-link-metadata"
    assert both._cached_connection_key == cached
