import base64
import gzip
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from core import subscription


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
