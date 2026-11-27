import base64
import gzip
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import ModuleType
from unittest.mock import Mock

import pytest
import requests

from core import subscription


@pytest.mark.parametrize("proxy_error", ["missing-socks", "bad-socks", "invalid-proxy-url"])
def test_broken_system_proxy_retries_without_proxy(monkeypatch, proxy_error):
    attempts = []
    socks = ModuleType("socks")
    errors = {
        "missing-socks": requests.exceptions.InvalidSchema("Missing dependencies for SOCKS support."),
        "bad-socks": AttributeError("PySocks API unavailable", name="PROXY_TYPE_SOCKS5", obj=socks),
        "invalid-proxy-url": requests.exceptions.InvalidProxyURL("Missing proxy host"),
    }

    def send(self, request, **kwargs):
        attempts.append(self.trust_env)
        if self.trust_env:
            raise errors[proxy_error]
        response = requests.Response()
        response.status_code = 200
        response._content = b"trojan://fake@example.com:443"
        response._content_consumed = True
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    content, _ = subscription.fetch_subscription_with_meta("http://example.com/sub")
    assert content == "trojan://fake@example.com:443" and attempts == [True, False]


def test_millisecond_and_second_subscription_expiries_are_equivalent():
    seconds = 1798761600
    expected = subscription.parse_subscription_userinfo(f"expire={seconds}")
    assert expected["summary"] == f"{datetime.fromtimestamp(seconds):%Y-%m-%d} 到期"
    assert subscription.parse_subscription_userinfo(f"expire={seconds * 1000 + 123}") == expected


@pytest.mark.parametrize("encoded", [False, True])
def test_unsupported_links_are_reported_without_credentials(encoded):
    text = "https://example.com/about\n\nhysteria://secret@example.com:443\ntuic://password@example.net:443"
    if encoded:
        text = base64.b64encode(text.encode()).decode()
    nodes, errors = subscription.parse_subscription_content(text)
    assert not nodes
    assert errors == ["第 3 行不支持的节点协议: hysteria", "第 4 行不支持的节点协议: tuic"]


def test_invalid_clash_yaml_reports_location_without_payload():
    nodes, errors = subscription.parse_subscription_content("proxies:\n  - name: [synthetic-secret")
    assert not nodes and len(errors) == 1
    assert "语法错误" in errors[0] and "行" in errors[0]
    assert "synthetic-secret" not in errors[0]


def test_fetch_handles_redirects_and_limits_decompressed_body(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setattr(subscription, "MAX_SUBSCRIPTION_BYTES", 128)
    visited = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            visited.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/nodes")
                self.send_header("Content-Length", "100000000")
                self.end_headers()
                return
            if self.path == "/bad-gateway":
                self.send_response(502)
                self.end_headers()
                return
            content = b"x" * 256 if self.path == "/oversize" else b"trojan://fake@example.com:443"
            body = gzip.compress(content)
            assert len(body) < 128
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Subscription-Userinfo", "total=1024")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = f"http://127.0.0.1:{server.server_port}"
        try:
            content, meta = subscription.fetch_subscription_with_meta(f"{url}/redirect", timeout=2)
            assert content == "trojan://fake@example.com:443" and meta["total"] == 1024
            with pytest.raises(ValueError, match="大小上限"):
                subscription.fetch_subscription_with_meta(f"{url}/oversize", timeout=2)
            with pytest.raises(requests.HTTPError):
                subscription.fetch_subscription_with_meta(f"{url}/bad-gateway", timeout=2)
        finally:
            server.shutdown()
            worker.join(5)
    assert visited == ["/redirect", "/nodes", "/oversize", "/bad-gateway"]


def test_base64_clash_yaml_and_mixed_text_fallback():
    clash_yaml = "proxies:\n  - {name: b64-clash, type: trojan, server: example.com, port: 443, password: pw}\n"
    encoded = base64.b64encode(clash_yaml.encode("utf-8")).decode("ascii")
    nodes, errors = subscription.parse_subscription_content(encoded)
    assert [n.name for n in nodes] == ["b64-clash"] and not errors

    mixed = '{"meta": true}\ntrojan://pw@example.com:443#from-mixed\n'
    nodes, errors = subscription.parse_subscription_content(mixed)
    assert [n.name for n in nodes] == ["from-mixed"] and not errors

    comment_like = "proxies: header-note\ntrojan://pw@example.com:443#from-lines\n"
    nodes, errors = subscription.parse_subscription_content(comment_like)
    assert [n.name for n in nodes] == ["from-lines"] and not errors


def test_yaml_alias_bomb_is_rejected_safely():
    lines = ["a: &a [x, x, x, x]"]
    prev = "a"
    for idx in range(1, 14):
        cur = f"k{idx}"
        lines.append(f"{cur}: &{cur} [*{prev}, *{prev}, *{prev}, *{prev}]")
        prev = cur
    lines.append(f"proxies: [*{prev}]")
    nodes, errors = subscription.parse_subscription_content("\n".join(lines))
    assert not nodes and len(errors) == 1 and "安全上限" in errors[0]


def test_invalid_non_socks_redirect_scheme_does_not_retry(monkeypatch):
    attempts = []

    def send(self, request, **kwargs):
        attempts.append(self.trust_env)
        raise requests.exceptions.InvalidSchema("No connection adapters were found for 'ftp://example.com/sub'")

    monkeypatch.setattr(requests.Session, "send", send)
    with pytest.raises(requests.exceptions.InvalidSchema):
        subscription.fetch_subscription_with_meta("http://example.com/sub")
    assert attempts == [True]


def test_fetch_subscription_respects_cancel_event(monkeypatch):
    cancel = threading.Event()
    cancel.set()
    send = Mock()
    monkeypatch.setattr(requests.Session, "send", send)
    with pytest.raises(InterruptedError, match="取消"):
        subscription.fetch_subscription_with_meta("http://example.com/sub", cancel_event=cancel)
    send.assert_not_called()


def test_r2_large_clash_anchors_rules_allowed_and_alias_bomb_with_https_not_swallowed():
    # 300 nodes reusing YAML anchor must succeed
    anchor_lines = ["base: &base", "  type: trojan", "  server: example.com", "  port: 443", "  password: pw", "proxies:"]
    for i in range(300):
        anchor_lines.append(f"  - {{<<: *base, name: node-{i}}}")
    nodes, errors = subscription.parse_subscription_content("\n".join(anchor_lines))
    assert len(nodes) == 300 and not errors

    # Alias bomb with valid YAML block containing https:// (which matches _SHARE_LINK) must still report security limit
    bomb = ["a: &a [x, x, x, x]"]
    prev = "a"
    for idx in range(1, 14):
        cur = f"k{idx}"
        bomb.append(f"{cur}: &{cur} [*{prev}, *{prev}, *{prev}, *{prev}]")
        prev = cur
    bomb.append("note: |")
    bomb.append("  https://example.com/decoy")
    bomb.append(f"proxies: [*{prev}]")
    nodes, errors = subscription.parse_subscription_content("\n".join(bomb))
    assert not nodes and len(errors) == 1 and "安全上限" in errors[0]

    # Alias bomb accompanied by a real proxy link line must ALSO report security limit rather than falling back
    bomb_with_proxy = list(bomb)
    bomb_with_proxy.insert(-1, "  trojan://pw@example.com:443#decoy")
    nodes, errors = subscription.parse_subscription_content("\n".join(bomb_with_proxy))
    assert not nodes and len(errors) == 1 and "安全上限" in errors[0]
