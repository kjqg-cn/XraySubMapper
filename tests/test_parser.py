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
