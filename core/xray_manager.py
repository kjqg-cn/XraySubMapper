import atexit
import copy
import ctypes
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

from .config import get_app_dir
from .parser import ProxyNode


def _create_kill_on_close_job() -> Optional[int]:
    """Create a Windows Job Object configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE."""
    if sys.platform != "win32":
        return None
    try:
        kernel32 = ctypes.windll.kernel32

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", ctypes.c_ulong),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_ulong),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_ulong),
                ("SchedulingClass", ctypes.c_ulong),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        kernel32.SetInformationJobObject.restype = ctypes.c_int

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = kernel32.SetInformationJobObject(
            job,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            return None
        return int(job)
    except Exception:
        return None


def _assign_process_to_job(job_handle: Optional[int], proc: subprocess.Popen) -> None:
    if sys.platform != "win32" or not job_handle:
        return
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        proc_handle = int(proc._handle)  # type: ignore[attr-defined]
        kernel32.AssignProcessToJobObject(ctypes.c_void_p(job_handle), ctypes.c_void_p(proc_handle))
    except Exception:
        pass


class XrayManager:
    def __init__(self, xray_path: Optional[str] = None):
        self.xray_path = xray_path or self._find_xray_executable()
        self.process: Optional[subprocess.Popen] = None
        self.log_callback: Optional[Callable[[str], None]] = None
        self._log_thread: Optional[threading.Thread] = None
        self._running = False
        self._job_handle: Optional[int] = _create_kill_on_close_job()
        self.active_mappings: List[Dict[str, Any]] = []
        self.listen_ip: str = "127.0.0.1"
        self.auth_credentials: Optional[Tuple[str, str]] = None
        self._lifecycle_lock = threading.RLock()
        self._stop_requested = threading.Event()
        self._active_nodes: List[ProxyNode] = []
        self._active_config: Optional[Dict[str, Any]] = None
        self.generation = 0
        atexit.register(self.stop)

    def _find_xray_executable(self) -> str:
        app_dir = get_app_dir()
        current_dir = os.getcwd()
        exe_name = "xray.exe" if sys.platform == "win32" else "xray"
        candidates = [
            # 1. External xray.exe next to the portable .exe / project root (allows easy kernel upgrade)
            os.path.join(app_dir, exe_name),
        ]
        # 2. Bundled xray.exe inside PyInstaller single-file runtime (_MEIPASS)
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(os.path.join(meipass, exe_name))
        candidates.extend([
            os.path.join(current_dir, exe_name),
            exe_name,
        ])
        for p in candidates:
            if os.path.isfile(p):
                return os.path.abspath(p)
        return exe_name

    def set_log_callback(self, callback: Callable[[str], None]) -> None:
        self.log_callback = callback

    def _log(self, msg: str) -> None:
        if self.log_callback:
            try:
                self.log_callback(msg)
            except Exception:
                pass
        else:
            print(f"[XrayManager] {msg}")

    @staticmethod
    def check_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
        """Return True if port is already bound by another process."""
        probe_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
        # 1. Active TCP connect probe catches non-exclusive binds on Windows
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.15)
            if sock.connect_ex((probe_host, port)) == 0:
                return True

        # 2. Exclusive bind test on target listen address
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                except OSError:
                    pass
            try:
                sock.bind((host, port))
                return False
            except OSError:
                return True

    @staticmethod
    def validate_node_ports(
        nodes: List[ProxyNode], listen_ip: str = "127.0.0.1", owned_ports: Optional[set] = None,
    ) -> Tuple[bool, str]:
        """Validate port range, internal duplicates, and external port conflicts."""
        active_nodes = [n for n in nodes if n.enabled]
        if not active_nodes:
            return False, "没有已启用的节点，请至少勾选一个节点。"

        seen_ports: Dict[int, str] = {}
        for n in active_nodes:
            if not (1 <= n.local_port <= 65535):
                return False, f"节点 [{n.name}] 的本地端口 ({n.local_port}) 无效，须在 1~65535 之间。"
            if n.local_port in seen_ports:
                prev_name = seen_ports[n.local_port]
                return (
                    False,
                    f"本地端口重复冲突：端口 {n.local_port} 同时分配给了 [{prev_name}] 与 [{n.name}]。",
                )
            seen_ports[n.local_port] = n.name

        conflict_ports = []
        for n in active_nodes:
            if owned_ports and n.local_port in owned_ports:
                continue
            if XrayManager.check_port_in_use(n.local_port, listen_ip):
                conflict_ports.append(f"{n.local_port} ({n.name})")

        if conflict_ports:
            joined = "\n".join(conflict_ports[:6])
            more = f"\n...等共 {len(conflict_ports)} 个端口" if len(conflict_ports) > 6 else ""
            return False, f"以下本地端口已被其他程序占用，请更换起始端口后重试：\n{joined}{more}"

        return True, "OK"

    def generate_config(
        self,
        nodes: List[ProxyNode],
        listen_ip: str = "127.0.0.1",
        auth_user: str = "",
        auth_pass: str = "",
    ) -> Dict[str, Any]:
        """Generate Xray JSON configuration with 1-to-1 Mixed (HTTP + SOCKS5) inbound to outbound mapping."""
        inbounds = []
        outbounds = []
        routing_rules = []

        use_auth = bool(auth_user and auth_pass)

        for idx, node in enumerate(nodes):
            if not node.enabled:
                continue

            in_tag = f"mixed-in-{idx}"
            out_tag = f"node-out-{idx}"

            inbound_settings: Dict[str, Any] = {
                "udp": True,
                "timeout": 300,
            }
            if use_auth:
                inbound_settings["auth"] = "password"
                inbound_settings["accounts"] = [{"user": auth_user, "pass": auth_pass}]

            inbound = {
                "tag": in_tag,
                "port": node.local_port,
                "listen": listen_ip,
                "protocol": "mixed",
                "settings": inbound_settings,
            }
            inbounds.append(inbound)

            try:
                outbound = node.to_outbound(out_tag)
            except Exception as exc:
                raise ValueError(f"节点 [{node.name}] 配置无效: {exc}") from exc
            outbounds.append(outbound)

            routing_rules.append(
                {
                    "type": "field",
                    "inboundTag": [in_tag],
                    "outboundTag": out_tag,
                }
            )

        outbounds.append({"tag": "direct", "protocol": "freedom"})
        outbounds.append({"tag": "block", "protocol": "blackhole"})

        return {
            "log": {"loglevel": "warning"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {
                "domainStrategy": "AsIs",
                "rules": routing_rules,
            },
        }

    def validate_config(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate config in-memory via `xray run -test -c stdin:` without writing plaintext credentials to disk."""
        if not os.path.isfile(self.xray_path) and os.path.sep in self.xray_path:
            return False, f"未找到 Xray 内核可执行文件: {self.xray_path}"

        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        payload = json.dumps(config, ensure_ascii=False)

        try:
            version = subprocess.run(
                [self.xray_path, "version"], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=10, creationflags=creationflags,
            )
            match = re.search(r"Xray (\d+)\.(\d+)\.(\d+)", version.stdout)
            if version.returncode != 0 or not match:
                return False, "无法识别 Xray 版本，请使用官方 Xray 26.11.9 或更高版本"
            if tuple(int(v) for v in match.groups()) < (26, 11, 9):
                return False, "需要 Xray 26.11.9 或更高版本，请升级内核"
            proc = subprocess.run(
                [self.xray_path, "run", "-test", "-c", "stdin:"],
                input=payload,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=10,
                creationflags=creationflags,
            )
            if proc.returncode == 0:
                return True, "Configuration OK"
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            return False, err_msg
        except Exception as e:
            return False, str(e)

    def start(
        self,
        nodes: List[ProxyNode],
        listen_ip: str = "127.0.0.1",
        auth_user: str = "",
        auth_pass: str = "",
    ) -> Tuple[bool, str]:
        """Start Xray process mapping enabled nodes to local HTTP ports."""
        with self._lifecycle_lock:
            if self.is_running():
                return False, "代理服务已在运行中。"
            self._stop_requested.clear()
            active_nodes = copy.deepcopy([n for n in nodes if n.enabled])
            ok, msg, config = self._prepare_config(active_nodes, listen_ip, auth_user, auth_pass)
            if not ok:
                return False, msg
            return self._launch(config, active_nodes, listen_ip, auth_user, auth_pass)

    def _prepare_config(
        self, nodes: List[ProxyNode], listen_ip: str, auth_user: str, auth_pass: str,
        owned_ports: Optional[set] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        ok, err = self.validate_node_ports(nodes, listen_ip, owned_ports)
        if not ok:
            return False, err, {}
        try:
            config = self.generate_config(nodes, listen_ip, auth_user=auth_user, auth_pass=auth_pass)
        except Exception as exc:
            return False, str(exc), {}
        ok, msg = self.validate_config(config)
        if not ok:
            return False, f"Xray 配置校验未通过:\n{msg}", {}
        return True, "OK", config

    def _launch(
        self, config: Dict[str, Any], active_nodes: List[ProxyNode],
        listen_ip: str, auth_user: str, auth_pass: str,
    ) -> Tuple[bool, str]:
        if self._stop_requested.is_set():
            return False, "启动已取消"
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        payload = json.dumps(config, ensure_ascii=False)
        proc = None
        try:
            proc = subprocess.Popen(
                [self.xray_path, "run", "-c", "stdin:"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="ignore",
                bufsize=1,
                creationflags=creationflags,
            )
            _assign_process_to_job(self._job_handle, proc)
            self.process = proc
            self._running = True

            def _reader(target_proc: subprocess.Popen) -> None:
                stream = target_proc.stdout
                if stream is not None:
                    try:
                        for line in stream:
                            if line:
                                self._log(line.rstrip())
                    except (OSError, ValueError):
                        pass
                    finally:
                        stream.close()
                self._log("Xray 进程已退出。")

            self._log_thread = threading.Thread(target=_reader, args=(proc,), daemon=True)
            self._log_thread.start()

            if proc.stdin:
                proc.stdin.write(payload)
                proc.stdin.close()

            time.sleep(0.25)
            if proc.poll() is not None:
                self._stop_process()
                return False, f"Xray 启动后立即异常退出 (code={proc.returncode})"
            if self._stop_requested.is_set():
                self._stop_process()
                return False, "启动已取消"

            self.listen_ip = listen_ip
            self.auth_credentials = (auth_user, auth_pass) if (auth_user and auth_pass) else None
            self._active_nodes = copy.deepcopy(active_nodes)
            self._active_config = copy.deepcopy(config)
            self.active_mappings = [
                {"name": n.name, "protocol": n.protocol, "server": n.server,
                 "target_port": n.port, "local_port": n.local_port,
                 "in_tag": f"mixed-in-{i}", "out_tag": f"node-out-{i}"}
                for i, n in enumerate(active_nodes)
            ]
            self.generation += 1

            self._log(f"Xray 已启动 · 监听 {listen_ip} · 映射 {len(active_nodes)} 个混合端口 (HTTP + SOCKS5)")
            return True, f"已启动并映射 {len(active_nodes)} 个本地端口 (同端口支持 HTTP 与 SOCKS5)"
        except Exception as e:
            if proc is not None:
                self._stop_process()
            return False, f"启动 Xray 进程异常: {e}"

    def reload(
        self,
        nodes: List[ProxyNode],
        listen_ip: str = "127.0.0.1",
        auth_user: str = "",
        auth_pass: str = "",
    ) -> Tuple[bool, str]:
        """Validate first, restart, and restore the previous service if switching fails."""
        with self._lifecycle_lock:
            self._stop_requested.clear()
            active_nodes = copy.deepcopy([n for n in nodes if n.enabled])
            was_running = self.is_running()
            owned_ports = set()
            if was_running and (listen_ip == self.listen_ip or "0.0.0.0" in (listen_ip, self.listen_ip)):
                owned_ports = {n.local_port for n in self._active_nodes}
            ok, msg, config = self._prepare_config(active_nodes, listen_ip, auth_user, auth_pass, owned_ports)
            if not ok:
                return False, msg
            if self._stop_requested.is_set():
                return False, "重载已取消"

            previous = (self._active_config, self._active_nodes, self.listen_ip, self.auth_credentials)
            if was_running:
                ok, msg = self._stop_process()
                if not ok:
                    return False, msg
            ok, msg = self._launch(config, active_nodes, listen_ip, auth_user, auth_pass)
            if ok or not was_running or self._stop_requested.is_set():
                return ok, msg
            old_config, old_nodes, old_ip, old_auth = previous
            restored, restore_msg = self._launch(old_config, old_nodes, old_ip, *(old_auth or ("", "")))
            if restored:
                return False, f"重载失败，已恢复原配置：\n{msg}"
            return False, f"重载失败：{msg}\n恢复原配置也失败：{restore_msg}"

    def stop(self) -> Tuple[bool, str]:
        """Stop Xray process cleanly."""
        self._stop_requested.set()
        with self._lifecycle_lock:
            return self._stop_process()

    def _stop_process(self) -> Tuple[bool, str]:
        self._running = False
        proc = self.process
        if not proc:
            return True, "服务未运行"

        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1.0)
            self.process = None
            self.active_mappings = []
            self._active_config = None
            self._active_nodes = []
            self.generation += 1
            self._log("Xray 服务已停止。")
            return True, "代理服务已停止"
        except Exception as e:
            return False, f"停止服务时出错: {e}"

    def is_running(self) -> bool:
        proc = self.process
        return proc is not None and proc.poll() is None

    def _build_proxy_url(self, local_port: int, host: Optional[str] = None) -> str:
        target_host = host or self.listen_ip or "127.0.0.1"
        if target_host in ("0.0.0.0", "::", ""):
            target_host = "127.0.0.1"
        if self.auth_credentials:
            u, p = self.auth_credentials
            return f"http://{quote(u, safe='')}:{quote(p, safe='')}@{target_host}:{local_port}"
        return f"http://{target_host}:{local_port}"

    def test_single_proxy(
        self,
        local_port: int,
        test_url: str = "https://cp.cloudflare.com/generate_204",
        timeout: float = 5.0,
        host: Optional[str] = None,
        session: Optional[requests.Session] = None,
        proxy_url: Optional[str] = None,
    ) -> Tuple[bool, Optional[int], str]:
        """Test a local HTTP proxy port over HTTPS CONNECT tunnel."""
        proxy_url = proxy_url or self._build_proxy_url(local_port, host=host)
        proxies = {"http": proxy_url, "https": proxy_url}
        start_t = time.perf_counter()

        own_session = session is None
        sess = session or requests.Session()
        sess.trust_env = False

        try:
            resp = sess.get(test_url, proxies=proxies, timeout=timeout, allow_redirects=False)
            if 200 <= resp.status_code < 400:
                cost_ms = max(1, int((time.perf_counter() - start_t) * 1000))
                return True, cost_ms, "OK"
            return False, None, f"HTTP {resp.status_code}"
        except requests.exceptions.Timeout:
            return False, None, "连接超时"
        except requests.exceptions.SSLError:
            return False, None, "TLS 握手失败"
        except Exception as e:
            err_str = str(e)
            if "Connection refused" in err_str or "10061" in err_str:
                return False, None, "本地端口未监听"
            if "407" in err_str:
                return False, None, "代理鉴权失败 (407)"
            return False, None, "连接失败"
        finally:
            if own_session:
                sess.close()

    def test_all_proxies(
        self,
        nodes: List[ProxyNode],
        test_url: str = "https://cp.cloudflare.com/generate_204",
        timeout: float = 5.0,
        progress_cb: Optional[Callable[[int, int, ProxyNode], None]] = None,
    ) -> Dict[int, Tuple[bool, Optional[int], str]]:
        """Concurrently test latency for all enabled nodes."""
        results: Dict[int, Tuple[bool, Optional[int], str]] = {}
        generation = self.generation
        active_nodes = [(n, n.local_port, n.connection_key(), self._build_proxy_url(n.local_port))
                        for n in nodes if n.enabled and n.local_port > 0]
        total = len(active_nodes)
        if total == 0:
            return results

        lock = threading.Lock()
        done_counter = [0]

        def _worker(item) -> None:
            node, port, key, proxy_url = item
            ok, lat, msg = self.test_single_proxy(port, test_url=test_url, timeout=timeout, proxy_url=proxy_url)
            current = (generation == self.generation and node.enabled
                       and node.local_port == port and node.connection_key() == key)
            if current:
                node.latency_ms = lat if ok else -1
                node.last_error = "" if ok else msg
            with lock:
                done_counter[0] += 1
                done_now = done_counter[0]
                results[port] = (ok, lat, msg)
            if progress_cb:
                progress_cb(done_now, total, node)

        with ThreadPoolExecutor(max_workers=min(16, total)) as pool:
            list(pool.map(_worker, active_nodes))

        return results

    def probe_exit_ip(
        self, local_port: int, timeout: float = 6.0, proxy_url: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Query outbound exit IP and country code through the mapped local HTTP proxy."""
        proxy_url = proxy_url or self._build_proxy_url(local_port)
        proxies = {"http": proxy_url, "https": proxy_url}
        with requests.Session() as sess:
            sess.trust_env = False
            # Primary: Cloudflare trace (fast, returns both IP and 2-letter country code)
            try:
                resp = sess.get("https://cp.cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=timeout)
                if resp.status_code == 200 and "ip=" in resp.text:
                    kv = {}
                    for line in resp.text.splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            kv[k.strip()] = v.strip()
                    ip = kv.get("ip", "")
                    loc = kv.get("loc", "")
                    if ip:
                        return True, f"{ip} ({loc})" if loc else ip
            except Exception:
                pass

            # Fallback: ipify
            try:
                resp = sess.get("https://api.ipify.org?format=json", proxies=proxies, timeout=timeout)
                if resp.status_code == 200:
                    ip = str(resp.json().get("ip", "")).strip()
                    if ip:
                        return True, ip
            except Exception:
                pass

        return False, ""

    def probe_all_exit_ips(
        self,
        nodes: List[ProxyNode],
        progress_cb: Optional[Callable[[int, int, ProxyNode], None]] = None,
    ) -> None:
        generation = self.generation
        active_nodes = [(n, n.local_port, n.connection_key(), self._build_proxy_url(n.local_port))
                        for n in nodes if n.enabled and n.local_port > 0]
        total = len(active_nodes)
        if total == 0:
            return

        lock = threading.Lock()
        done_counter = [0]

        def _worker(item) -> None:
            node, port, key, proxy_url = item
            ok, ip_info = self.probe_exit_ip(port, proxy_url=proxy_url)
            if (generation == self.generation and node.enabled
                    and node.local_port == port and node.connection_key() == key):
                node.exit_ip = ip_info if ok else ""
            with lock:
                done_counter[0] += 1
                done_now = done_counter[0]
            if progress_cb:
                progress_cb(done_now, total, node)

        with ThreadPoolExecutor(max_workers=min(12, total)) as pool:
            list(pool.map(_worker, active_nodes))
