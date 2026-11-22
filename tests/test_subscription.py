import base64
import gzip
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import ModuleType

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
    text = "https://example.com/about\n\nhy2://secret@example.com:443\ntuic://password@example.net:443"
    if encoded:
        text = base64.b64encode(text.encode()).decode()
    nodes, errors = subscription.parse_subscription_content(text)
    assert not nodes
    assert errors == ["第 3 行不支持的节点协议: hy2", "第 4 行不支持的节点协议: tuic"]


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
