import argparse
import os
import sys

# Detect --noconsole / pythonw mode before replacing None streams with os.devnull
_NO_CONSOLE = sys.stdout is None
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")


def _enable_windows_dpi_awareness() -> None:
    from core.config import enable_windows_dpi_awareness

    enable_windows_dpi_awareness()


def _show_startup_error(title: str, message: str) -> None:
    """Display native Windows MessageBox if GUI launch fails (even under pythonw.exe)."""
    if sys.platform == "win32":
        _enable_windows_dpi_awareness()
        try:
            import ctypes
            from ctypes.wintypes import HWND, UINT

            show_message = ctypes.windll.user32.MessageBoxW
            show_message.argtypes = [HWND, ctypes.c_wchar_p, ctypes.c_wchar_p, UINT]
            show_message.restype = ctypes.c_int
            show_message(None, message, title, 0x10)
            return
        except Exception:
            pass
    sys.stderr.write(f"[{title}] {message}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Xray 多节点多端口混合代理工具 (HTTP + SOCKS5)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例用法:
  直接双击或执行 python main.py 启动桌面图形界面 (GUI)
  命令行启动 (CLI):
    python main.py --sub "https://example.com/sub" --start-port 10800
    python main.py --file nodes.txt --start-port 10800 --test
    python main.py --file nodes.txt --listen 0.0.0.0 --auth-user proxyuser --auth-pass YOUR_PASSWORD
""",
    )
    parser.add_argument("--sub", type=str, help="订阅链接 URL")
    parser.add_argument("--file", type=str, help="包含节点链接或订阅内容的本地文件路径")
    parser.add_argument("--start-port", type=int, default=10800, help="本地混合代理起始端口 (1024~65535，默认: 10800)")
    parser.add_argument("--listen", type=str, default="127.0.0.1", help="本地监听 IP (默认: 127.0.0.1，局域网共享可用 0.0.0.0)")
    parser.add_argument("--max-nodes", type=int, default=0, help="最大映射节点数量 (0 表示不限制)")
    parser.add_argument("--auth-user", help="本地代理鉴权用户名，与 --auth-pass 一起使用")
    parser.add_argument("--auth-pass", help="本地代理鉴权密码，省略时读取 XRAY_AUTH_PASS")
    parser.add_argument("--test", action="store_true", help="启动后自动进行连通性与延时测速")
    parser.add_argument("--export", type=str, help="将生成的代理列表导出为文本文件")
    parser.add_argument("--gui", action="store_true", help="强制启动图形界面")

    if getattr(sys, "frozen", False) and _NO_CONSOLE and len(sys.argv) > 1 and "--gui" not in sys.argv:
        _show_startup_error(
            "便携版仅支持桌面模式 - XraySubMapper",
            "当前单文件便携版为无控制台窗口应用，暂不支持直接传参运行 CLI 模式。\n\n"
            "请直接双击启动桌面工作台，或在源码目录使用命令行运行：\n"
            "python main.py --sub \"...\" --start-port 10800",
        )
        sys.exit(1)

    args = parser.parse_args()
    if len(sys.argv) == 1 or args.gui:
        _enable_windows_dpi_awareness()
        try:
            from gui.app import run_gui
        except ImportError as exc:
            _show_startup_error(
                "缺少运行依赖 - XraySubMapper",
                f"无法启动图形界面，缺少必要的 Python 依赖库 ({exc})。\n\n"
                "请在项目目录下执行以下命令安装依赖：\n"
                "pip install -r requirements.txt",
            )
            sys.exit(1)
        try:
            run_gui()
        except Exception as exc:
            _show_startup_error(
                "启动失败 - XraySubMapper",
                f"图形界面启动或初始化时发生异常：\n{exc}",
            )
            sys.exit(1)
    else:
        from cli import run_cli
        run_cli(args)


if __name__ == "__main__":
    main()
