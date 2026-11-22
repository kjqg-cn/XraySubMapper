import base64

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


@pytest.mark.parametrize("network", ["kcp", "quic", "h2", "http", "unknown"])
def test_unsupported_transports_report_node_error(network):
    valid = "trojan://password@example.com:443#valid"
    bad = f"vless://{UUID}@example.com:443?type={network}&security=tls"
    nodes, errors = parse_subscription_content(valid + "\n" + bad)
    assert len(nodes) == 1 and nodes[0].name == "valid"
    assert len(errors) == 1 and network in errors[0]


@pytest.mark.parametrize("text", [
    f"vless://{UUID}@example.com:443?security=tls&allowInsecure=1",
    "proxies:\n  - {name: insecure, type: trojan, server: example.com, port: 443, password: test, skip-cert-verify: true}",
])
def test_removed_tls_option_is_rejected_at_import(text):
    nodes, errors = parse_subscription_content(text)
    assert not nodes
    assert any("skip-cert-verify" in error for error in errors)


@pytest.mark.parametrize("text", [
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:9443/?plugin=v2ray-plugin%3Bmode%3Dwebsocket",
    "proxies:\n  - {name: plugin, type: ss, server: example.com, port: 9443, cipher: aes-128-gcm, password: test, plugin: v2ray-plugin}",
])
def test_unsupported_ss_plugins_are_not_silently_accepted(text):
    nodes, errors = parse_subscription_content(text)
    assert not nodes and any("plugin" in error for error in errors)


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
