import argparse
import ipaddress
import os
import signal
import sys
import threading
import time
from urllib.parse import quote

from core.subscription import fetch_subscription_with_meta, parse_subscription_content
from core.xray_manager import XrayManager, format_proxy_host


def run_cli(args: argparse.Namespace) -> None:
    auth_user = getattr(args, "auth_user", None)
    auth_pass = getattr(args, "auth_pass", None)
    if auth_user and auth_pass is None:
        auth_pass = os.environ.get("XRAY_AUTH_PASS")
    if (auth_user is not None or auth_pass is not None) and not (auth_user and auth_pass):
        print("[-] 请提供 --auth-user 和 --auth-pass（也可通过 XRAY_AUTH_PASS 设置密码）")
        sys.exit(1)

    content = ""
    if args.sub:
        print(f"[*] 正在下载订阅链接: {args.sub}")
        try:
            content, meta = fetch_subscription_with_meta(args.sub)
            summary = meta.get("summary", "")
            print(f"[+] 订阅下载成功！{(' (' + summary + ')') if summary else ''}")
        except Exception as e:
            print(f"[-] 下载订阅失败: {e}")
            sys.exit(1)
    elif args.file:
        print(f"[*] 正在读取文件: {args.file}")
        try:
            with open(args.file, "r", encoding="utf-8-sig", errors="ignore") as f:
                content = f.read()
            print("[+] 文件读取成功！")
        except Exception as e:
            print(f"[-] 读取文件失败: {e}")
            sys.exit(1)
    else:
        print("[-] 错误: 请指定 --sub 订阅链接 或 --file 文件路径")
        sys.exit(1)

    nodes, errors = parse_subscription_content(content)
    active_nodes = [n for n in nodes if n.enabled]
    if not active_nodes:
        print("[-] 未能解析出任何有效节点！")
        for err in errors[:5]:
            print(f"    {err}")
        sys.exit(1)

    print(f"[+] 成功解析出 {len(active_nodes)} 个有效节点。")
    if errors:
        print(f"[*] 忽略 {len(errors)} 个异常节点。")

    if args.max_nodes and args.max_nodes > 0:
        active_nodes = active_nodes[: args.max_nodes]
        print(f"[*] 限制映射前 {len(active_nodes)} 个节点。")

    start_p = args.start_port
    if start_p < 1 or start_p + len(active_nodes) - 1 > 65535:
        print(f"[-] 错误: 端口区间越界 ({start_p} ~ {start_p + len(active_nodes) - 1})，须在 1~65535 之间。")
        sys.exit(1)

    listen_ip = args.listen
    export_host = format_proxy_host(listen_ip)
    try:
        loopback = ipaddress.ip_address(listen_ip).is_loopback
    except ValueError:
        loopback = listen_ip.lower() == "localhost"
    if not loopback and not auth_user:
        print("[!] 当前监听地址可供其他设备访问，建议启用代理鉴权。")

    print("\n" + "=" * 72)
    print(f"{'序号':<4} {'协议':<10} {'本地混合代理 (HTTP / SOCKS5)':<28} {'节点名称'}")
    print("-" * 72)
    for idx, node in enumerate(active_nodes):
        node.local_port = start_p + idx
        proxy_addr = f"{export_host}:{node.local_port}"
        print(f"{idx + 1:<4} {node.protocol.upper():<10} {proxy_addr:<28} {node.name}")
    print("=" * 72 + "\n")

    stopping = threading.Event()
    mgr = XrayManager(cancel_event=stopping)
    interrupted = False

    def _sig_handler(sig, frame):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            stopping.set()

    handlers = {}
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, _sig_handler)
        ok, msg = mgr.start(active_nodes, listen_ip, auth_user=auth_user or "", auth_pass=auth_pass or "")
        if stopping.is_set():
            return
        if not ok:
            print(f"[-] 启动 Xray 失败: {msg}")
            sys.exit(1)

        print(f"[+] Xray 混合代理已启动 (监听 {listen_ip}，端口 {start_p} ~ {start_p + len(active_nodes) - 1})")

        export_candidates = active_nodes
        if args.test:
            print("\n[*] 正在并发测试各节点 HTTPS 连通性与延时...")
            results = mgr.test_all_proxies(active_nodes, cancel_event=stopping)
            if stopping.is_set():
                return
            export_candidates = []
            for node in active_nodes:
                t_ok, lat, err = results.get(node.local_port, (False, None, "未知"))
                status_str = f"{lat} ms" if t_ok else f"失败 ({err})"
                print(f"端口 {node.local_port} ({node.name}): {status_str}")
                if t_ok:
                    export_candidates.append(node)
            print(f"[*] 测速完成: {len(export_candidates)}/{len(active_nodes)} 个节点可用。\n")

        if args.export and not stopping.is_set():
            auth_prefix = f"{quote(auth_user, safe='')}:{quote(auth_pass, safe='')}@" if auth_user else ""
            try:
                with open(args.export, "w", encoding="utf-8") as f:
                    for node in export_candidates:
                        latency = node.latency_ms
                        suffix = f" [{latency}ms]" if latency is not None and latency >= 0 else ""
                        f.write(f"http://{auth_prefix}{export_host}:{node.local_port} # {node.name}{suffix}\n")
                print(f"[+] 代理映射列表 ({len(export_candidates)} 条) 已保存至: {args.export}")
            except OSError as exc:
                print(f"[-] 导出文件失败: {exc}")

        print("[*] 服务运行中... 按 Ctrl+C 停止退出。")
        while not stopping.is_set() and mgr.is_running():
            time.sleep(0.2)
        if not stopping.is_set():
            print("[-] 检测到 Xray 进程意外退出！")
            sys.exit(1)
    except KeyboardInterrupt:
        stopping.set()
    finally:
        try:
            ok, msg = mgr.close()
            if stopping.is_set():
                print(f"\n{'[+]' if ok else '[-]'} {msg}")
        finally:
            for sig, handler in handlers.items():
                if handler is not None:
                    signal.signal(sig, handler)
