import base64
import json
import os
import shutil
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser import parse_node_link
from core.subscription import parse_subscription_content, parse_subscription_userinfo
from core.xray_manager import XrayManager


def test_full_flow() -> None:
    print("[*] 1. 测试 Clash YAML 全参数解析 (含 VLESS+WS+TLS, Trojan+gRPC, 假节点自动禁用)...")
    clash_yaml = """
proxies:
  - name: "Clash-VLESS-WS"
    type: vless
    server: hk.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: sni.example.com
    client-fingerprint: chrome
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless-ws
      headers:
        Host: ws.example.com
  - name: "Clash-Trojan-gRPC"
    type: trojan
    server: jp.example.com
    port: 443
    password: "my_pass_123"
    sni: jp.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: "trojan-grpc-svc"
  - name: "剩余流量：100GB"
    type: ss
    server: 127.0.0.1
    port: 1
    cipher: aes-256-gcm
    password: dummy
"""
    c_nodes, c_errors = parse_subscription_content(clash_yaml)
    assert len(c_nodes) == 3, f"期望 3 个 Clash 节点，实际得到 {len(c_nodes)} ({c_errors})"
    vless_ws = c_nodes[0].to_outbound("t0")
    assert vless_ws["streamSettings"]["wsSettings"]["path"] == "/vless-ws"
    assert vless_ws["streamSettings"]["wsSettings"]["host"] == "ws.example.com"
    assert "headers" not in vless_ws["streamSettings"]["wsSettings"]
    assert vless_ws["streamSettings"]["tlsSettings"]["allowInsecure"] is True

    trojan_grpc = c_nodes[1].to_outbound("t1")
    assert trojan_grpc["streamSettings"]["grpcSettings"]["serviceName"] == "trojan-grpc-svc"
    assert c_nodes[2].enabled is False, "127.0.0.1:1 提示假节点应当自动禁用"
    print("[+] Clash YAML 解析断言全部通过！")

    print("[*] 2. 测试特殊节点链接 (SS2022明文、IPv6、URL编码密码、XHTTP、VMess空aid)...")
    ss2022 = parse_node_link(
        "ss://2022-blake3-aes-128-gcm:Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ%3D%3D@[2001:db8::1]:8388#SS2022-IPv6"
    )
    assert ss2022.method == "2022-blake3-aes-128-gcm"
    assert ss2022.password == "Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ=="
    assert ss2022.server == "2001:db8::1" and ss2022.port == 8388

    trojan_enc = parse_node_link("trojan://p%40ss%3Aword%231@example.com:443?type=xhttp&path=%2Fxhttp&sni=example.com#Trojan-XHTTP")
    assert trojan_enc.password == "p@ss:word#1"
    assert trojan_enc.to_outbound("tx")["streamSettings"]["network"] == "xhttp"

    vmess_empty_aid = {
        "v": "2", "ps": "HK-VMess", "add": "example.com", "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "", "scy": "auto",
        "net": "ws", "type": "none", "host": "hk.example.com", "path": "/ws", "tls": "1"
    }
    vmess_url = "vmess://" + base64.b64encode(json.dumps(vmess_empty_aid).encode()).decode()

    vless_reality_url = (
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com"
        "&fp=chrome&pbk=fgG1NbySPniaSpg0HezhCbPUOQQW62U-xpsDfCBKFSo&sid=12345678&type=tcp#US-Reality"
    )
    ss_b64 = "ss://" + base64.b64encode(b"aes-256-gcm:mypassword@example.com:8388").decode() + "#SG-SS"

    raw_sub = "\n".join([vmess_url, vless_reality_url, ss_b64])
    b64_sub = base64.b64encode(raw_sub.encode()).decode()
    nodes, errors = parse_subscription_content(b64_sub)
    assert len(nodes) == 3 and not errors

    meta = parse_subscription_userinfo("upload=1073741824; download=4294967296; total=107374182400; expire=1893456000")
    assert "95.0 GB" in meta["summary"]
    print("[+] 协议边界用例与 Userinfo 解析全部通过！")

    print("[*] 3. 测试端口重复冲突拦截与 Xray stdin 无落盘启动...")
    mgr = XrayManager()
    nodes[0].local_port = 19810
    nodes[1].local_port = 19810
    nodes[2].local_port = 19812
    dup_ok, dup_msg = mgr.validate_node_ports(nodes, "127.0.0.1")
    assert not dup_ok and "重复冲突" in dup_msg, f"未拦截重复端口: {dup_msg}"

    has_xray = os.path.isfile(mgr.xray_path) or (shutil.which(mgr.xray_path) is not None)
    if not has_xray:
        print("[*] 未在当前目录或 PATH 检测到 xray.exe，跳过内核进程监听测试（纯逻辑单测已全部通过）！")
        return

    for i, n in enumerate(nodes):
        n.local_port = 19810 + i

    ok, msg = mgr.start(nodes, "127.0.0.1", auth_user="admin", auth_pass="secret123")
    assert ok, f"启动失败: {msg}"
    assert mgr.is_running(), "Xray 进程未运行"

    time.sleep(0.5)
    for i in range(3):
        test_p = 19810 + i
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            assert s.connect_ex(("127.0.0.1", test_p)) == 0, f"端口 {test_p} 未监听"

    # Test hot reload with new ports (no auth) and verify Mixed HTTP + SOCKS5 on the same port
    for i, n in enumerate(nodes):
        n.local_port = 19820 + i
    r_ok, r_msg = mgr.reload(nodes, "127.0.0.1")
    assert r_ok, f"热重载失败: {r_msg}"
    time.sleep(0.4)

    # Verify SOCKS5 handshake on port 19820
    with socket.create_connection(("127.0.0.1", 19820), timeout=2.0) as s:
        s.sendall(b"\x05\x01\x00")
        s5_resp = s.recv(2)
        assert s5_resp == b"\x05\x00", f"同端口 SOCKS5 握手失败: {s5_resp}"

    # Verify HTTP proxy protocol on the exact same port 19820
    with socket.create_connection(("127.0.0.1", 19820), timeout=2.0) as s:
        s.sendall(b"CONNECT 127.0.0.1:19821 HTTP/1.1\r\nHost: 127.0.0.1:19821\r\n\r\n")
        http_resp = s.recv(64)
        assert b"200 Connection established" in http_resp, f"同端口 HTTP CONNECT 失败: {http_resp}"

    stop_ok, _ = mgr.stop()
    assert stop_ok and not mgr.is_running(), "停止后进程仍未退出"
    print("[+] Xray stdin 启动、鉴权配置、热重载与干净退出全部验证通过！")


if __name__ == "__main__":
    test_full_flow()
