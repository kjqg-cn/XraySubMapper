import argparse
import signal
import sys
import time

from core.subscription import fetch_subscription_with_meta, parse_subscription_content
from core.xray_manager import XrayManager


def run_cli(args: argparse.Namespace) -> None:
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
    export_host = "127.0.0.1" if listen_ip == "0.0.0.0" else listen_ip

    print("\n" + "=" * 72)
    print(f"{'序号':<4} {'协议':<10} {'本地混合代理 (HTTP / SOCKS5)':<28} {'节点名称'}")
    print("-" * 72)
    for idx, node in enumerate(active_nodes):
        node.local_port = start_p + idx
        proxy_addr = f"{export_host}:{node.local_port}"
        print(f"{idx + 1:<4} {node.protocol.upper():<10} {proxy_addr:<28} {node.name}")
    print("=" * 72 + "\n")

    mgr = XrayManager()
    ok, msg = mgr.start(active_nodes, listen_ip)
    if not ok:
        print(f"[-] 启动 Xray 失败: {msg}")
        sys.exit(1)

    print(f"[+] Xray 多端口混合代理 (HTTP + SOCKS5) 已成功启动！(监听 IP: {listen_ip})")
    print(f"[*] 端口范围: {start_p} ~ {start_p + len(active_nodes) - 1} (每个端口均同时支持 http:// 与 socks5://)")

    export_candidates = active_nodes
    if args.test:
        print("\n[*] 正在并发测试各节点 HTTPS 连通性与延时...")
        results = mgr.test_all_proxies(active_nodes)
        print("-" * 60)
        passed = []
        for node in active_nodes:
            t_ok, lat, err = results.get(node.local_port, (False, None, "未知"))
            status_str = f"{lat} ms" if t_ok else f"失败 ({err})"
            print(f"端口 {node.local_port} ({node.name}): {status_str}")
            if t_ok:
                passed.append(node)
        print("-" * 60)
        print(f"[*] 测速完成: {len(passed)}/{len(active_nodes)} 个节点可用。\n")
        export_candidates = passed

    if args.export:
        try:
            with open(args.export, "w", encoding="utf-8") as f:
                for node in export_candidates:
                    lat_suffix = f" [{node.latency_ms}ms]" if node.latency_ms and node.latency_ms > 0 else ""
                    f.write(f"http://{export_host}:{node.local_port} # {node.name}{lat_suffix}\n")
            print(f"[+] 代理映射列表 ({len(export_candidates)} 条) 已保存至: {args.export}")
        except Exception as e:
            print(f"[-] 导出文件失败: {e}")

    stopping = [False]

    def _sig_handler(sig, frame):
        stopping[0] = True
        print("\n[*] 正在停止 Xray 代理服务...")
        mgr.stop()
        print("[+] 服务已停止，程序退出。")
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    print("[*] 服务运行中... 按 Ctrl+C 停止退出。\n")
    try:
        while mgr.is_running():
            time.sleep(1)
        if not stopping[0]:
            print("[-] 检测到 Xray 进程意外退出！")
            sys.exit(1)
    except KeyboardInterrupt:
        _sig_handler(None, None)
