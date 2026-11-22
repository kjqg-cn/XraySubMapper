import copy
import ctypes
import errno
import json
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import weakref
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

from .config import get_app_dir
from .parser import ProxyNode
from .subscription import discard_redirect_body


MIN_XRAY_VERSION = (26, 11, 9)
_MIN_VERSION_TEXT = ".".join(map(str, MIN_XRAY_VERSION))
_CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
_POLL_INTERVAL = 0.025
_LISTENER_PROBE_BATCH = 256  # Winsock select() limits the number of sockets per set.
_ERROR_INSUFFICIENT_BUFFER = 122
_TCP_TABLE_OWNER_PID_LISTENER = 3
_UDP_TABLE_OWNER_PID = 1
_CONNECT_PENDING = {
    errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR,
    getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK),
}


def _close_job(job: int) -> None:
    close_handle = ctypes.windll.kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    close_handle(job)


def _create_kill_on_close_job() -> Optional[int]:
    """Create a Windows Job Object configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE."""
    if sys.platform != "win32":
        return None
    job = None
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
            _close_job(job)
            return None
        return int(job)
    except Exception:
        if job:
            _close_job(job)
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


def _terminate_process(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1.0)


def _connect_host(listen_ip: str) -> str:
    return {"": "127.0.0.1", "0.0.0.0": "127.0.0.1", "::": "::1"}.get(listen_ip, listen_ip)


def format_proxy_host(listen_ip: str) -> str:
    host = _connect_host(listen_ip)
    return f"[{host}]" if ":" in host else host


def _ready_tcp_ports(host: str, ports: List[int], timeout: float) -> set[int]:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    ready = set()
    with ExitStack() as sockets:
        connecting = {}
        for port in ports:
            try:
                sock = sockets.enter_context(socket.socket(family, socket.SOCK_STREAM))
                sock.setblocking(False)
                status = sock.connect_ex((host, port))
                if status == 0:
                    ready.add(port)
                elif status in _CONNECT_PENDING:
                    connecting[sock] = port
            except OSError:
                continue

        deadline = time.monotonic() + timeout
        while connecting:
            try:
                _, writable, failed = select.select([], connecting, connecting, max(0.0, deadline - time.monotonic()))
            except OSError:
                break
            if not writable and not failed:
                break
            for sock in failed:
                connecting.pop(sock, None)
            for sock in writable:
                port = connecting.pop(sock, None)
                try:
                    if port is not None and sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                        ready.add(port)
                except OSError:
                    continue
            if time.monotonic() >= deadline:
                break
    return ready


def _windows_foreign_listener_ports(exclude_pid: int) -> set[int]:
    ip_helper = ctypes.windll.iphlpapi
    # MIB_*ROW_OWNER_PID layouts, retaining dwLocalPort and dwOwningPid.
    tables = (
        (ip_helper.GetExtendedTcpTable, _TCP_TABLE_OWNER_PID_LISTENER, socket.AF_INET, "8xI8xI"),
        (ip_helper.GetExtendedTcpTable, _TCP_TABLE_OWNER_PID_LISTENER, socket.AF_INET6, "20xI28xI"),
        (ip_helper.GetExtendedUdpTable, _UDP_TABLE_OWNER_PID, socket.AF_INET, "4xII"),
        (ip_helper.GetExtendedUdpTable, _UDP_TABLE_OWNER_PID, socket.AF_INET6, "20xII"),
    )
    dword = ctypes.c_uint32
    ports = set()
    for get_table, table_class, family, row_format in tables:
        get_table.argtypes = [ctypes.c_void_p, ctypes.POINTER(dword), ctypes.c_int, dword, ctypes.c_int, dword]
        get_table.restype = dword
        size = dword()
        data = None
        for _ in range(4):  # A socket may open between reading the size and filling the buffer.
            error = get_table(data, ctypes.byref(size), False, family, table_class, 0)
            if error != _ERROR_INSUFFICIENT_BUFFER:
                break
            data = ctypes.create_string_buffer(size.value)
        if error:
            raise ctypes.WinError(error)
        if data is None:
            continue
        row = struct.Struct("=" + row_format)
        count, = struct.unpack_from("=I", data)
        end = ctypes.sizeof(dword) + count * row.size
        for port, pid in row.iter_unpack(memoryview(data)[ctypes.sizeof(dword):end]):
            if pid != exclude_pid:
                ports.add(socket.ntohs(port & 0xFFFF))
    return ports


def _local_proxy_error(exc: Exception) -> str:
    message = str(exc).lower()
    if "connection refused" in message or "10061" in message:
        return "本地端口未监听"
    if "407 proxy" in message:
        return "代理鉴权失败 (407)"
    return ""


class XrayManager:
    def __init__(self, xray_path: Optional[str] = None, *, cancel_event: Optional[threading.Event] = None):
        self.xray_path = xray_path or self._find_xray_executable()
        self.process: Optional[subprocess.Popen] = None
        self.log_callback: Optional[Callable[[str], None]] = None
        self._job_handle: Optional[int] = _create_kill_on_close_job()
        self._job_cleanup = weakref.finalize(self, _close_job, self._job_handle) if self._job_handle else None
        self._process_cleanup: Optional[weakref.finalize] = None
        self.active_mappings: List[Dict[str, Any]] = []
        self.listen_ip: str = "127.0.0.1"
        self.auth_credentials: Optional[Tuple[str, str]] = None
        self._lifecycle_lock = threading.RLock()
        self._stop_lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._cancel_event = cancel_event
        self._closed = False
        self._version_cache = None
        self._active_nodes: List[ProxyNode] = []
        self._active_config: Optional[Dict[str, Any]] = None
        self.generation = 0

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
        """Check the TCP and UDP sockets required by a mixed inbound."""
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        for sock_type in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            try:
                with socket.socket(family, sock_type) as sock:
                    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    sock.bind((host, port))
            except OSError:
                return True
        return False

    @staticmethod
    def validate_node_ports(
        nodes: List[ProxyNode], listen_ip: str = "127.0.0.1", owned_ports: Optional[set] = None,
        cancelled: Optional[Callable[[], bool]] = None,
    ) -> Tuple[bool, str]:
        """Validate port range, internal duplicates, and external port conflicts."""
        active_nodes = [n for n in nodes if n.enabled]
        if not active_nodes:
            return False, "没有已启用的节点，请至少勾选一个节点。"

        seen_ports: Dict[int, str] = {}
        for n in active_nodes:
            if cancelled is not None and cancelled():
                return False, "端口校验已取消"
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
            if cancelled is not None and cancelled():
                return False, "端口校验已取消"
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

        if bool(auth_user) != bool(auth_pass):
            raise ValueError("启用代理鉴权时必须同时提供用户名和密码")
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

    def _resolved_xray_path(self) -> str:
        path = self.xray_path if os.path.isfile(self.xray_path) else shutil.which(self.xray_path)
        if not path:
            raise FileNotFoundError(f"未找到 Xray 内核可执行文件: {self.xray_path}")
        return os.path.realpath(path)

    def _is_cancelled(self) -> bool:
        return self._stop_requested.is_set() or (self._cancel_event is not None and self._cancel_event.is_set())

    def _run_preflight(self, command: List[str], payload: Optional[str] = None) -> Tuple[int, str]:
        if self._is_cancelled():
            raise InterruptedError("Xray 校验已取消")
        proc = subprocess.Popen(
            command, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", creationflags=_CREATE_NO_WINDOW,
        )
        _assign_process_to_job(self._job_handle, proc)
        done = threading.Event()
        result = []
        errors = []

        def communicate() -> None:
            try:
                with proc:
                    output, _ = proc.communicate(payload)
                result.append((proc.returncode, output))
            except Exception as exc:
                errors.append(exc)
            finally:
                done.set()

        # Windows pipe writes may block before communicate() reaches its timeout.
        worker = threading.Thread(target=communicate, daemon=True)
        try:
            worker.start()
        except RuntimeError:
            with proc:
                proc.kill()
            raise
        try:
            deadline = time.monotonic() + 10
            while not done.wait(_POLL_INTERVAL):
                if self._is_cancelled():
                    raise InterruptedError("Xray 校验已取消")
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, 10)
        finally:
            try:
                if not done.is_set():
                    proc.kill()
            finally:
                worker.join(timeout=2.0)
        if errors:
            raise errors[0]
        return result[0]

    def check_version(self) -> Tuple[bool, str]:
        """Apply the same Xray version requirement to runtime and portable builds."""
        try:
            path = self._resolved_xray_path()
            stat = os.stat(path)
            key = (path, stat.st_mtime_ns, stat.st_size, stat.st_ino)
            if self._version_cache and self._version_cache[0] == key:
                version = self._version_cache[1]
            else:
                code, output = self._run_preflight([path, "version"])
                match = re.search(r"^Xray (\d+)\.(\d+)\.(\d+)\b", output, re.MULTILINE)
                if code != 0 or not match:
                    return False, f"无法识别 Xray 版本，请使用官方 Xray {_MIN_VERSION_TEXT} 或更高版本"
                version = tuple(int(component) for component in match.groups())
                self._version_cache = (key, version)
            detected = ".".join(map(str, version))
            if version < MIN_XRAY_VERSION:
                return False, f"需要 Xray {_MIN_VERSION_TEXT} 或更高版本，当前为 {detected}，请升级内核"
            return True, detected
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)

    def validate_config(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate through Xray's stdin without writing credentials to disk."""
        ok, msg = self.check_version()
        if not ok:
            return False, msg
        try:
            command = [self._resolved_xray_path(), "run", "-test", "-c", "stdin:"]
            code, output = self._run_preflight(command, json.dumps(config, ensure_ascii=False))
            return (True, "Configuration OK") if code == 0 else (False, output.strip() or f"Xray 退出码 {code}")
        except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
            return False, str(exc)

    def start(
        self,
        nodes: List[ProxyNode],
        listen_ip: str = "127.0.0.1",
        auth_user: str = "",
        auth_pass: str = "",
    ) -> Tuple[bool, str]:
        """Start Xray and wait until the mapped ports accept connections."""
        with self._lifecycle_lock:
            if self._is_cancelled():
                return False, "启动已取消"
            if self.is_running():
                return False, "代理服务已在运行中。"
            if self.process is not None:
                self._stop_process()
            active_nodes = copy.deepcopy([n for n in nodes if n.enabled])
            ok, msg, config = self._prepare_config(active_nodes, listen_ip, auth_user, auth_pass)
            if not ok:
                return False, msg
            return self._launch(config, active_nodes, listen_ip, auth_user, auth_pass)

    def _prepare_config(
        self, nodes: List[ProxyNode], listen_ip: str, auth_user: str, auth_pass: str,
        owned_ports: Optional[set] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        ok, err = self.validate_node_ports(nodes, listen_ip, owned_ports, self._is_cancelled)
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
        if self._is_cancelled():
            return False, "启动已取消"
        payload = json.dumps(config, ensure_ascii=False)
        proc = None
        reader = None
        recent_logs = deque(maxlen=8)
        log_method = weakref.WeakMethod(self._log)
        written = threading.Event()
        write_errors = []

        def log_output(message: str) -> None:
            log = log_method()
            if log is not None:
                log(message)

        def read_output(stream) -> None:
            try:
                with stream:
                    for line in stream:
                        message = line.rstrip()
                        recent_logs.append(message[-512:])
                        log_output(message)
            except (OSError, ValueError):
                pass
            log_output("Xray 进程已退出。")

        def write_config(stream) -> None:
            try:
                with stream:
                    stream.write(payload)
            except OSError as exc:
                write_errors.append(exc)
            finally:
                written.set()

        try:
            proc = subprocess.Popen(
                [self._resolved_xray_path(), "run", "-c", "stdin:"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=_CREATE_NO_WINDOW,
            )
            _assign_process_to_job(self._job_handle, proc)
            reader = threading.Thread(target=read_output, args=(proc.stdout,), daemon=True)
            reader.start()
            threading.Thread(target=write_config, args=(proc.stdin,), daemon=True).start()

            host = _connect_host(listen_ip)
            pending = deque(node.local_port for node in active_nodes)
            deadline = time.monotonic() + 5
            while pending:
                if self._is_cancelled():
                    raise InterruptedError("启动已取消")
                if write_errors:
                    raise write_errors[0]
                if proc.poll() is not None:
                    raise RuntimeError(f"Xray 启动后退出 (code={proc.returncode})")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    ports = ", ".join(str(port) for port in sorted(pending)[:6])
                    raise TimeoutError(f"等待 Xray 监听超时，仍有 {len(pending)} 个端口未就绪（{ports}）")
                if not written.is_set():
                    self._stop_requested.wait(_POLL_INTERVAL)
                    continue
                batch = [pending.popleft() for _ in range(min(len(pending), _LISTENER_PROBE_BATCH))]
                ready = _ready_tcp_ports(host, batch, min(remaining, _POLL_INTERVAL))
                pending.extend(port for port in batch if port not in ready)
                if pending and not ready and len(pending) == len(batch):
                    self._stop_requested.wait(_POLL_INTERVAL)

            if proc.poll() is not None:
                raise RuntimeError(f"Xray 启动后退出 (code={proc.returncode})")
            if self._is_cancelled():
                raise InterruptedError("启动已取消")

            mappings = [
                {"name": n.name, "protocol": n.protocol, "server": n.server,
                 "target_port": n.port, "local_port": n.local_port,
                 "in_tag": f"mixed-in-{i}", "out_tag": f"node-out-{i}"}
                for i, n in enumerate(active_nodes)
            ]
            self.listen_ip = listen_ip
            self.auth_credentials = (auth_user, auth_pass) if (auth_user and auth_pass) else None
            self._active_nodes = active_nodes
            self._active_config = config
            self.active_mappings = mappings
            self._process_cleanup = weakref.finalize(self, _terminate_process, proc)
            self.generation += 1
            self.process = proc

            self._log(f"Xray 已启动 · 监听 {listen_ip} · 映射 {len(active_nodes)} 个混合端口 (HTTP + SOCKS5)")
            return True, f"已启动并映射 {len(active_nodes)} 个本地端口 (同端口支持 HTTP 与 SOCKS5)"
        except (Exception, KeyboardInterrupt) as exc:
            if proc is not None:
                _terminate_process(proc)
            if reader is not None and reader.ident is not None:
                reader.join(timeout=0.1)
            if isinstance(exc, KeyboardInterrupt):
                raise
            output = "\n".join(recent_logs.copy())
            detail = f"\n{output}" if output else ""
            return False, f"启动 Xray 进程异常: {exc}{detail}"

    def reload(
        self,
        nodes: List[ProxyNode],
        listen_ip: str = "127.0.0.1",
        auth_user: str = "",
        auth_pass: str = "",
    ) -> Tuple[bool, str]:
        """Validate first, restart, and restore the previous service if switching fails."""
        with self._lifecycle_lock:
            if self._is_cancelled():
                return False, "重载已取消"
            active_nodes = copy.deepcopy([n for n in nodes if n.enabled])
            was_running = self.is_running()
            owned_ports = set()
            addresses = (listen_ip, self.listen_ip)
            shared_bind = (
                listen_ip == self.listen_ip or "::" in addresses
                or ("0.0.0.0" in addresses and all(":" not in ip for ip in addresses))
            )
            if was_running and shared_bind:
                owned_ports = {n.local_port for n in self._active_nodes}
            reused = owned_ports.intersection(n.local_port for n in active_nodes)
            if sys.platform == "win32" and reused and listen_ip in ("0.0.0.0", "::") and listen_ip != self.listen_ip:
                try:
                    conflicts = reused & _windows_foreign_listener_ports(self.process.pid)
                except OSError as exc:
                    return False, f"无法核对通配监听地址的端口占用: {exc}"
                if conflicts:
                    ports = ", ".join(map(str, sorted(conflicts)[:6]))
                    return False, f"其他程序已占用 {len(conflicts)} 个待复用端口（{ports}）"
            ok, msg, config = self._prepare_config(active_nodes, listen_ip, auth_user, auth_pass, owned_ports)
            if not ok:
                return False, msg
            if self._is_cancelled():
                return False, "重载已取消"

            previous = (self._active_config, self._active_nodes, self.listen_ip, self.auth_credentials)
            if self.process is not None:
                ok, msg = self._stop_process()
                if not ok:
                    return False, msg
            ok, msg = self._launch(config, active_nodes, listen_ip, auth_user, auth_pass)
            if ok or not was_running or self._is_cancelled():
                return ok, msg
            old_config, old_nodes, old_ip, old_auth = previous
            restored, restore_msg = self._launch(old_config, old_nodes, old_ip, *(old_auth or ("", "")))
            if restored:
                return False, f"重载失败，已恢复原配置：\n{msg}"
            return False, f"重载失败：{msg}\n恢复原配置也失败：{restore_msg}"

    def stop(self) -> Tuple[bool, str]:
        """Stop Xray process cleanly."""
        with self._stop_lock:
            self._stop_requested.set()
            with self._lifecycle_lock:
                try:
                    return self._stop_process()
                finally:
                    if not self._closed:
                        self._stop_requested.clear()

    def close(self) -> Tuple[bool, str]:
        """Stop this manager and reject any start queued during shutdown."""
        self._closed = True
        result = self.stop()
        if result[0] and self._job_cleanup is not None:
            self._job_cleanup()
            self._job_handle = None
        return result

    def _stop_process(self) -> Tuple[bool, str]:
        proc = self.process
        if not proc:
            return True, "服务未运行"

        try:
            _terminate_process(proc)
            if self._process_cleanup is not None:
                self._process_cleanup.detach()
                self._process_cleanup = None
            self.process = None
            self.active_mappings = []
            self._active_config = None
            self._active_nodes = []
            self.auth_credentials = None
            self.generation += 1
            self._log("Xray 服务已停止。")
            return True, "代理服务已停止"
        except Exception as e:
            return False, f"停止服务时出错: {e}"

    def is_running(self) -> bool:
        proc = self.process
        return proc is not None and proc.poll() is None

    def _build_proxy_url(self, local_port: int, host: Optional[str] = None) -> str:
        target_host = format_proxy_host(host or self.listen_ip)
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
            with sess.get(
                test_url, proxies=proxies, timeout=timeout, allow_redirects=False, stream=True,
                hooks={"response": discard_redirect_body},
            ) as resp:
                if 200 <= resp.status_code < 400:
                    cost_ms = max(1, int((time.perf_counter() - start_t) * 1000))
                    return True, cost_ms, "OK"
                return False, None, f"HTTP {resp.status_code}"
        except requests.exceptions.Timeout:
            return False, None, "连接超时"
        except requests.exceptions.SSLError:
            return False, None, "TLS 握手失败"
        except Exception as e:
            return False, None, _local_proxy_error(e) or "连接失败"
        finally:
            if own_session:
                sess.close()

    def test_all_proxies(
        self,
        nodes: List[ProxyNode],
        test_url: str = "https://cp.cloudflare.com/generate_204",
        timeout: float = 5.0,
        progress_cb: Optional[Callable[[int, int, ProxyNode], None]] = None,
        cancel_event: Optional[threading.Event] = None,
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
            if cancel_event is not None and cancel_event.is_set():
                return
            node, port, key, proxy_url = item
            ok, lat, msg = self.test_single_proxy(port, test_url=test_url, timeout=timeout, proxy_url=proxy_url)
            current = (generation == self.generation and node.enabled
                       and node.local_port == port and node.connection_key() == key)
            if current:
                node.latency_ms = lat if ok else -1
                node.last_error = "" if ok else msg
            with lock:
                done_counter[0] += 1
                results[port] = (ok, lat, msg)
                if progress_cb:
                    progress_cb(done_counter[0], total, node)

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
                if resp.status_code == 407:
                    return False, ""
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
            except requests.RequestException as exc:
                if _local_proxy_error(exc):
                    return False, ""

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
        cancel_event: Optional[threading.Event] = None,
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
            if cancel_event is not None and cancel_event.is_set():
                return
            node, port, key, proxy_url = item
            ok, ip_info = self.probe_exit_ip(port, proxy_url=proxy_url)
            if (generation == self.generation and node.enabled
                    and node.local_port == port and node.connection_key() == key):
                node.exit_ip = ip_info if ok else ""
            with lock:
                done_counter[0] += 1
                if progress_cb:
                    progress_cb(done_counter[0], total, node)

        with ThreadPoolExecutor(max_workers=min(12, total)) as pool:
            list(pool.map(_worker, active_nodes))
