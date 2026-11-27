import copy
import ctypes
import socket
import struct
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

import build_portable
import core.xray_manager as manager_module
from core.parser import parse_node_link
from core.xray_manager import XrayManager


def test_stop_cancels_start_waiting_for_validation(manager, make_node, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    started, stopped = [], []
    launched = []

    def validate(config):
        entered.set()
        assert release.wait(5)
        return True, "OK"

    monkeypatch.setattr(manager, "validate_config", validate)
    monkeypatch.setattr(manager, "validate_node_ports", lambda *args: (True, "OK"))
    monkeypatch.setattr("core.xray_manager.subprocess.Popen", lambda *args, **kwargs: launched.append(True))
    starter = threading.Thread(target=lambda: started.append(manager.start([make_node(port=19880)])))
    stopper = threading.Thread(target=lambda: stopped.append(manager.stop()))
    try:
        starter.start()
        assert entered.wait(5)
        stopper.start()
        assert manager._stop_requested.wait(5)
        release.set()
        starter.join(5)
        stopper.join(5)
        assert not starter.is_alive() and not stopper.is_alive()
        assert not started[0][0] and stopped[0][0]
        assert not launched and not manager.is_running()
    finally:
        release.set()
        starter.join(5)
        if stopper.ident is not None:
            stopper.join(5)


def test_reload_rejects_busy_port_without_stopping_old_service(kernel_manager, make_node, free_port):
    manager = kernel_manager
    old = make_node("old", free_port())
    assert manager.start([old])[0]
    process = manager.process
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        ok, error = manager.reload([make_node("new", busy.getsockname()[1])])
    assert not ok and "占用" in error
    assert manager.process is process and manager.is_running()
    assert manager.active_mappings[0]["name"] == "old"


def test_reload_bad_config_preserves_old_service(kernel_manager, make_node, free_port, monkeypatch):
    manager = kernel_manager
    assert manager.start([make_node("old", free_port())])[0]
    process = manager.process
    monkeypatch.setattr(manager, "validate_config", lambda config: (False, "invalid config"))
    ok, error = manager.reload([make_node("new", free_port())])
    assert not ok and "invalid config" in error
    assert manager.process is process and manager.is_running()


def test_reload_launch_failure_restores_previous_config(kernel_manager, make_node, free_port, monkeypatch):
    manager = kernel_manager
    old = make_node("old", free_port())
    assert manager.start([old], auth_user="user", auth_pass="password")[0]
    original_launch = manager._launch
    calls = []

    def fail_once(*args):
        calls.append(args)
        if len(calls) == 1:
            return False, "simulated process failure"
        return original_launch(*args)

    monkeypatch.setattr(manager, "_launch", fail_once)
    ok, error = manager.reload([make_node("new", free_port())])
    assert not ok and "已恢复原配置" in error
    assert manager.is_running() and manager.auth_credentials == ("user", "password")
    assert manager.active_mappings[0]["local_port"] == old.local_port


def test_reload_can_reuse_own_ports(kernel_manager, make_node, free_port):
    manager = kernel_manager
    node = make_node(port=free_port())
    assert manager.start([node])[0]
    assert manager.reload([node], auth_user="user", auth_pass="password")[0]
    with socket.create_connection(("127.0.0.1", node.local_port), timeout=2) as sock:
        sock.sendall(b"\x05\x01\x00")
        assert sock.recv(2) == b"\x05\xff"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows wildcard binding semantics")
@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
@pytest.mark.parametrize("sock_type", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_start_rejects_existing_wildcard_listener(kernel_manager, make_node, family, sock_type):
    with socket.socket(family, sock_type) as busy:
        if family == socket.AF_INET6:
            busy.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        busy.bind(("0.0.0.0" if family == socket.AF_INET else "::", 0))
        if sock_type == socket.SOCK_STREAM:
            busy.listen()
        port = busy.getsockname()[1]
        reported_busy = kernel_manager.check_port_in_use(port, "127.0.0.1")
        ok, message = kernel_manager.start([make_node(port=port)], "127.0.0.1")
        assert reported_busy and not ok, message
        assert "占用" in message and str(port) in message
        assert kernel_manager.process is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows IP Helper port tables")
@pytest.mark.parametrize("address", ["::1", "::"])
@pytest.mark.parametrize("sock_type", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_ipv4_reload_ignores_ipv6_only_listener(kernel_manager, make_node, address, sock_type):
    with socket.socket(socket.AF_INET6, sock_type) as busy:
        busy.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            busy.bind((address, 0))
        except OSError:
            pytest.skip("IPv6 is unavailable")
        if sock_type == socket.SOCK_STREAM:
            busy.listen()
        node = make_node(port=busy.getsockname()[1])
        ok, message = kernel_manager.start([node], "127.0.0.1")
        assert ok, message
        ok, message = kernel_manager.reload([node], "0.0.0.0")
        assert ok, message
        assert kernel_manager.is_running() and kernel_manager.listen_ip == "0.0.0.0"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows IP Helper port tables")
@pytest.mark.parametrize("sock_type", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_reload_to_wildcard_rejects_a_conflicting_interface(kernel_manager, make_node, sock_type):
    addresses = socket.gethostbyname_ex(socket.gethostname())[2]
    with socket.socket(socket.AF_INET, sock_type) as busy:
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        for address in addresses:
            if address.startswith("127."):
                continue
            try:
                busy.bind((address, 0))
            except OSError:
                continue
            break
        else:
            pytest.skip("A bindable non-loopback IPv4 address is required")
        if sock_type == socket.SOCK_STREAM:
            busy.listen()
        port = busy.getsockname()[1]
        node = make_node(port=port)
        manager = kernel_manager
        ok, message = manager.start([node], "127.0.0.1")
        assert ok, message
        original = manager.process
        ok, message = manager.reload([node], "0.0.0.0")
        assert not ok and "占用" in message and str(port) in message
        assert manager.process is original and manager.is_running() and manager.listen_ip == "127.0.0.1"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows IP Helper port tables")
@pytest.mark.parametrize("truncated", [False, True])
def test_ipv4_port_validation_handles_disabled_ipv6_and_truncated_tables(
    manager, make_node, free_port, monkeypatch, truncated,
):
    families = []

    def get_table(data, size, ordered, family, table_class, reserved):
        families.append(family)
        if family == socket.AF_INET6:
            return 50  # ERROR_NOT_SUPPORTED, as on a system without IPv6.
        payload = struct.pack("=I", 1 if truncated else 0)
        ctypes.cast(size, ctypes.POINTER(ctypes.c_uint32)).contents.value = len(payload)
        if data is None:
            return 122
        ctypes.memmove(data, payload, len(payload))
        return 0

    helper = SimpleNamespace(GetExtendedTcpTable=get_table, GetExtendedUdpTable=get_table)
    monkeypatch.setattr(manager_module.ctypes.windll, "iphlpapi", helper)
    ok, message = manager.validate_node_ports([make_node(port=free_port())], "127.0.0.1")
    assert ok is not truncated
    assert set(families) == {socket.AF_INET}
    if truncated:
        assert "端口表" in message


def test_reject_old_kernel_before_submitting_config(manager, monkeypatch, tmp_path):
    kernel = tmp_path / "xray.exe"
    kernel.write_bytes(b"old")
    kernel.chmod(0o700)
    manager.xray_path = str(kernel)
    versions = iter(("26.10.31", "26.11.9"))
    commands = []

    def preflight(command, payload=None):
        commands.append(command[1:])
        return (0, f"Xray {next(versions)}") if command[1] == "version" else (0, "OK")

    monkeypatch.setattr(manager, "_run_preflight", preflight)
    ok, error = manager.validate_config({})
    assert not ok and "26.11.9" in error and "26.10.31" in error
    assert not manager.validate_config({})[0]
    assert commands == [["version"]]
    kernel.write_bytes(b"upgraded")
    assert manager.validate_config({})[0]
    assert manager.validate_config({})[0]
    assert commands == [
        ["version"], ["version"], ["run", "-test", "-c", "stdin:"], ["run", "-test", "-c", "stdin:"],
    ]


def test_portable_build_rejects_incompatible_kernel(tmp_path, monkeypatch):
    binary = tmp_path / "xray.exe"
    binary.touch(mode=0o700)
    monkeypatch.setattr(build_portable, "ROOT_DIR", str(tmp_path))
    monkeypatch.setattr(XrayManager, "_run_preflight", lambda self, command: (0, "Xray 26.10.31"))
    with pytest.raises(SystemExit, match="26.11.9"):
        build_portable.build()
    assert not (tmp_path / "build").exists()
    assert not (tmp_path / "release").exists()


def test_stop_interrupts_preflight_process(manager, make_node, monkeypatch, free_port):
    manager.xray_path = sys.executable
    monkeypatch.setattr(manager, "check_version", lambda: (True, "26.11.9"))
    real_popen = subprocess.Popen
    entered = threading.Event()
    children = []
    wait_threads = set()
    results = []

    def popen(command, **kwargs):
        assert command[1:3] == ["run", "-test"]
        child = real_popen([sys.executable, "-c", "import time; time.sleep(20)"], **kwargs)
        wait = child.wait

        def record_wait(*args, **kwargs):
            wait_threads.add(threading.get_ident())
            return wait(*args, **kwargs)

        child.wait = record_wait
        children.append(child)
        entered.set()
        return child

    monkeypatch.setattr(subprocess, "Popen", popen)
    node = make_node(port=free_port())
    node.password = "x" * 65536
    starter = threading.Thread(target=lambda: results.append(manager.start([node])))
    starter.start()
    try:
        assert entered.wait(5)
        start = time.monotonic()
        assert manager.stop()[0]
        assert time.monotonic() - start < 2
        assert children[0].poll() is not None
    finally:
        starter.join(5)
    assert not results[0][0] and "取消" in results[0][1]
    assert wait_threads and len(wait_threads) == 1
    assert starter.ident not in wait_threads and threading.get_ident() not in wait_threads
    assert children[0].stdin.closed and children[0].stdout.closed


@pytest.mark.parametrize("reason", ["cancel", "timeout"])
def test_preflight_preserves_original_error_when_kill_races_with_exit(manager, monkeypatch, reason):
    real_popen = subprocess.Popen
    children = []

    def popen(command, **kwargs):
        child = real_popen([sys.executable, "-c", "import time; time.sleep(20)"], **kwargs)
        communicate, kill = child.communicate, child.kill

        def communicate_and_cancel(payload):
            if reason == "cancel":
                manager._stop_requested.set()
            return communicate(payload)

        def kill_and_raise():
            kill()
            raise PermissionError("Process exited during TerminateProcess")

        child.communicate = communicate_and_cancel
        child.kill = kill_and_raise
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", popen)
    if reason == "timeout":
        ticks = iter((0.0, 11.0))
        monkeypatch.setattr(manager_module.time, "monotonic", lambda: next(ticks))
    expected = InterruptedError if reason == "cancel" else subprocess.TimeoutExpired
    with pytest.raises(expected):
        manager._run_preflight([sys.executable])
    assert children[0].poll() is not None and children[0].stdout.closed


def test_start_checks_all_ports_before_publishing(kernel_manager, make_node, free_port, monkeypatch):
    manager = kernel_manager
    ports = {free_port(), free_port()}
    while len(ports) < 2:
        ports.add(free_port())
    first_port, last_port = sorted(ports)
    defer_last = threading.Event()
    checking = threading.Event()
    results = []
    ready_tcp_ports = manager_module._ready_tcp_ports

    def probe(host, ports, timeout):
        if last_port in ports and not defer_last.is_set():
            checking.set()
            ports = [port for port in ports if port != last_port]
        return ready_tcp_ports(host, ports, timeout)

    monkeypatch.setattr(manager_module, "_ready_tcp_ports", probe)
    nodes = [make_node(port=first_port), make_node(port=last_port)]
    starter = threading.Thread(target=lambda: results.append(manager.start(nodes)))
    starter.start()
    try:
        assert checking.wait(5)
        assert not manager.is_running() and not manager.active_mappings
    finally:
        defer_last.set()
        starter.join(5)
    assert results[0][0] and manager.is_running()
    assert {item["local_port"] for item in manager.active_mappings} == ports


def test_many_ports_start_without_per_port_waits(kernel_manager, make_node, monkeypatch):
    snapshots = Mock(wraps=manager_module._windows_foreign_listener_ports)
    monkeypatch.setattr(manager_module, "_windows_foreign_listener_ports", snapshots)
    with ExitStack() as reservations:
        ports = []
        for _ in range(270):
            sock = reservations.enter_context(socket.socket())
            sock.bind(("127.0.0.1", 0))
            ports.append(sock.getsockname()[1])
    nodes = [make_node(port=port) for port in ports]
    ok, message = kernel_manager.start(nodes)
    assert ok, message
    assert set(ports) == {mapping["local_port"] for mapping in kernel_manager.active_mappings}
    if sys.platform == "win32":
        assert snapshots.call_count == 1


def test_listener_probe_ignores_transient_socket_errors(monkeypatch):
    real_socket = socket.socket
    with real_socket() as listener, real_socket() as idle:
        for sock in (listener, idle):
            sock.bind(("127.0.0.1", 0))
        listener.listen()
        ready_port, idle_port = [sock.getsockname()[1] for sock in (listener, idle)]

        class FlakySocket(real_socket):
            def connect_ex(self, address):
                if address[1] == idle_port:
                    raise OSError("transient error")
                return super().connect_ex(address)

        monkeypatch.setattr(manager_module.socket, "socket", FlakySocket)
        assert manager_module._ready_tcp_ports("127.0.0.1", [idle_port, ready_port], 0.1) == {ready_port}


def test_explicit_kernel_path_does_not_require_pathext(manager, tmp_path, monkeypatch):
    kernel = tmp_path / "custom-kernel.bin"
    kernel.touch()
    manager.xray_path = str(kernel)
    monkeypatch.setattr(manager_module.shutil, "which", lambda path: None)
    assert manager._resolved_xray_path() == str(kernel.resolve())


def test_ipv6_listen_and_ipv6_proxy_url(kernel_manager, make_node):
    with socket.socket(socket.AF_INET6) as sock:
        try:
            sock.bind(("::1", 0))
        except OSError:
            pytest.skip("IPv6 loopback is unavailable")
        port = sock.getsockname()[1]
    manager = kernel_manager
    assert not manager.check_port_in_use(port, "::1")
    ok, error = manager.start([make_node(port=port)], "::1")
    assert ok, error
    assert manager.check_port_in_use(port, "::1")
    assert manager._build_proxy_url(port) == f"http://[::1]:{port}"


def test_preflight_detects_udp_conflict(manager, make_node):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        ok, msg = manager.validate_node_ports([make_node(port=sock.getsockname()[1])])
        assert not ok and "占用" in msg


def test_preflight_detects_reusable_tcp_listener(manager):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        assert manager.check_port_in_use(sock.getsockname()[1])


def test_launch_reports_child_output_on_early_exit(manager, make_node, monkeypatch, free_port):
    manager.xray_path = sys.executable
    real_popen = subprocess.Popen

    def popen(command, **kwargs):
        return real_popen([sys.executable, "-c", 'print("synthetic bind failure"); raise SystemExit(1)'], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", popen)
    node = make_node(port=free_port())
    node.password = "x" * 65536
    config = manager.generate_config([node])
    ok, error = manager._launch(config, [node], "127.0.0.1", "", "")
    assert not ok and "synthetic bind failure" in error
    assert manager.process is None and not manager.active_mappings


@pytest.mark.parametrize("transport", ["tcp", "ws", "grpc", "xhttp", "httpupgrade"])
def test_supported_transports_pass_real_kernel_validation(kernel_manager, transport, free_port):
    node = parse_node_link(
        f"vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type={transport}&path=%2Fcustom"
    )
    node.local_port = free_port()
    ok, error = kernel_manager.validate_config(kernel_manager.generate_config([node]))
    assert ok, error


@pytest.mark.parametrize("result", ["primary", "fallback", "407", "bad_json"])
def test_exit_ip_responses_close_on_success_and_failure(manager, monkeypatch, result):
    primary = manager_module.requests.Response()
    primary.status_code = 407 if result == "407" else 200
    primary._content = b"ip=192.0.2.1\nloc=US" if result == "primary" else b"not a trace"
    primary.close = Mock()
    fallback = manager_module.requests.Response()
    fallback.status_code = 200
    fallback._content = b"invalid json" if result == "bad_json" else b'{"ip": "192.0.2.2"}'
    fallback.close = Mock()
    session = MagicMock()
    session.__enter__.return_value = session
    session.get.side_effect = [primary, fallback]
    monkeypatch.setattr(manager_module.requests, "Session", lambda: session)

    ok, value = manager.probe_exit_ip(19880)
    assert ok == (result in ("primary", "fallback"))
    assert value == {"primary": "192.0.2.1 (US)", "fallback": "192.0.2.2"}.get(result, "")
    primary.close.assert_called_once()
    if result in ("fallback", "bad_json"):
        fallback.close.assert_called_once()
    else:
        assert session.get.call_count == 1


@pytest.mark.parametrize("message", ["Tunnel connection failed: 407", "Tunnel connection failed: 407 Unauthorized"])
def test_bare_proxy_auth_error_stops_exit_ip_fallback(manager, monkeypatch, message):
    session = MagicMock()
    session.__enter__.return_value = session
    session.get.side_effect = manager_module.requests.exceptions.ProxyError(message)
    monkeypatch.setattr(manager_module.requests, "Session", lambda: session)
    assert manager.probe_exit_ip(19880) == (False, "")
    assert session.get.call_count == 1
    assert manager.test_single_proxy(19880, session=session)[2] == "代理鉴权失败 (407)"


@pytest.mark.parametrize("probe", ["speed", "exit"])
@pytest.mark.parametrize("change", ["port", "generation"])
def test_probe_results_cannot_overwrite_changed_mapping(manager, make_node, monkeypatch, probe, change):
    node = make_node(port=19880)
    original = copy.deepcopy(node)
    entered, release = threading.Event(), threading.Event()
    results = []
    sampled = []

    def delayed(port, **kwargs):
        sampled.append((port, kwargs["proxy_url"]))
        entered.set()
        assert release.wait(5)
        return (True, 42, "OK") if probe == "speed" else (True, "192.0.2.1 (US)")

    method = "test_single_proxy" if probe == "speed" else "probe_exit_ip"
    monkeypatch.setattr(manager, method, delayed)
    operation = manager.test_all_proxies if probe == "speed" else manager.probe_all_exit_ips
    thread = threading.Thread(target=lambda: results.append(operation([node])))
    try:
        thread.start()
        assert entered.wait(5)
        if change == "port":
            node.local_port = 19881
        else:
            manager.generation += 1
        release.set()
        thread.join(5)
        assert not thread.is_alive()
        assert sampled == [(19880, "http://127.0.0.1:19880")]
        assert node.latency_ms == original.latency_ms and node.exit_ip == original.exit_ip
        if probe == "speed":
            assert results[0] == {19880: (True, 42, "OK")}
    finally:
        release.set()
        thread.join(5)


def test_terminate_process_tolerates_windows_access_denied_on_exit():
    proc = Mock()
    exited = False

    def poll():
        return 0 if exited else None

    def terminate():
        nonlocal exited
        exited = True
        raise PermissionError(5, "Access is denied")

    proc.poll.side_effect = poll
    proc.terminate.side_effect = terminate
    proc.wait.return_value = 0

    manager_module._terminate_process(proc)
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once_with(timeout=2.0)


def test_probe_exit_ip_enforces_response_size_limit_and_cancellation(manager, monkeypatch):
    oversized = manager_module.requests.Response()
    oversized.status_code = 200
    oversized._content = b"x" * (manager_module.MAX_PROBE_RESPONSE_BYTES + 1)
    oversized.close = Mock()
    session = MagicMock()
    session.__enter__.return_value = session
    session.get.return_value = oversized
    monkeypatch.setattr(manager_module.requests, "Session", lambda: session)
    assert manager.probe_exit_ip(19880) == (False, "")

    cancelled = threading.Event()
    cancelled.set()
    session.get.reset_mock()
    assert manager.probe_exit_ip(19880, cancel_event=cancelled) == (False, "")
    session.get.assert_not_called()


def test_find_xray_executable_ignores_untrusted_cwd(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    cwd_dir = tmp_path / "downloads"
    app_dir.mkdir()
    cwd_dir.mkdir()
    exe_name = "xray.exe" if sys.platform == "win32" else "xray"
    (cwd_dir / exe_name).write_bytes(b"fake")
    monkeypatch.setattr(manager_module, "get_app_dir", lambda: str(app_dir))
    monkeypatch.chdir(cwd_dir)
    mgr = manager_module.XrayManager()
    assert mgr.xray_path == exe_name


def test_test_all_proxies_invokes_start_cb_before_probe(manager, make_node, monkeypatch):
    node = make_node(port=19880)
    events = []

    def fake_probe(port, **kwargs):
        events.append(("probe", port))
        return True, 25, "OK"

    monkeypatch.setattr(manager, "test_single_proxy", fake_probe)
    manager.test_all_proxies([node], start_cb=lambda n: events.append(("start", n.local_port)))
    assert events == [("start", 19880), ("probe", 19880)]


def test_https_speedtest_measures_second_keepalive_request_and_falls_back_cleanly(manager, monkeypatch):
    # Verify warmup + timed 2nd request on Keep-Alive HTTPS and fallback on Connection: close / 2nd failure
    r1 = manager_module.requests.Response()
    r1.status_code = 204
    r1.headers["Connection"] = "keep-alive"
    r1._content = b""
    r1.close = Mock()

    r2 = manager_module.requests.Response()
    r2.status_code = 204
    r2.headers["Connection"] = "keep-alive"
    r2._content = b""
    r2.close = Mock()

    ticks = iter([10.0, 10.300, 10.305, 10.365])  # warmup=300ms, 2nd=60ms
    monkeypatch.setattr(manager_module.time, "perf_counter", lambda: next(ticks))

    session = MagicMock()
    session.get.side_effect = [r1, r2]
    ok, lat, msg = manager.test_single_proxy(19880, test_url="https://cp.cloudflare.com/generate_204", session=session)
    assert ok and lat == 60 and msg == "OK"
    assert session.get.call_count == 2

    # When 2nd request fails (e.g. server closed idle socket), fall back to verified 1st measurement
    r_ok = manager_module.requests.Response()
    r_ok.status_code = 204
    r_ok._content = b""
    r_ok.close = Mock()
    ticks2 = iter([20.0, 20.180, 20.185])
    monkeypatch.setattr(manager_module.time, "perf_counter", lambda: next(ticks2))
    session2 = MagicMock()
    session2.get.side_effect = [r_ok, manager_module.requests.exceptions.ConnectionError("closed")]
    ok2, lat2, msg2 = manager.test_single_proxy(19880, test_url="https://cp.cloudflare.com/generate_204", session=session2)
    assert ok2 and lat2 == 180 and msg2 == "OK"

    # Plain HTTP skips 2nd request (single request only)
    r_http = manager_module.requests.Response()
    r_http.status_code = 204
    r_http._content = b""
    r_http.close = Mock()
    ticks3 = iter([30.0, 30.120])
    monkeypatch.setattr(manager_module.time, "perf_counter", lambda: next(ticks3))
    session3 = MagicMock()
    session3.get.side_effect = [r_http]
    ok3, lat3, msg3 = manager.test_single_proxy(19880, test_url="http://cp.cloudflare.com/generate_204", session=session3)
    assert ok3 and lat3 == 120 and msg3 == "OK"
    assert session3.get.call_count == 1


def test_r2_shared_ssl_adapter_clears_ca_certs_and_speedtest_respects_budget_and_cancel(manager, monkeypatch):
    from types import SimpleNamespace

    # R2-H2: cert_verify must clear conn.ca_certs so urllib3 never reloads certifi onto shared SSLContext
    sess = manager_module.requests.Session()
    try:
        manager_module._mount_shared_ssl_adapter(sess, manager_module.requests)
        adapter = sess.get_adapter("https://cp.cloudflare.com/generate_204")
        conn = SimpleNamespace(cert_reqs=None, ca_certs="stale.pem", ca_cert_dir="dir", ca_cert_data="data")
        adapter.cert_verify(conn, "https://cp.cloudflare.com/generate_204", True, None)
        assert conn.cert_reqs == "CERT_REQUIRED"
        assert conn.ca_certs is None and conn.ca_cert_dir is None and conn.ca_cert_data is None
    finally:
        sess.close()

    # R2-M2: cancelled before entry skips all requests
    cancelled = threading.Event()
    cancelled.set()
    session_c = MagicMock()
    assert manager.test_single_proxy(19880, session=session_c, cancel_event=cancelled) == (False, None, "测速已取消")
    session_c.get.assert_not_called()

    # R2-M2: warmup exhausting timeout budget skips 2nd request instead of doubling total wait
    r_slow = manager_module.requests.Response()
    r_slow.status_code = 204
    r_slow._content = b""
    r_slow.close = Mock()
    ticks = iter([100.0, 104.9])  # remaining = 0.1s <= 0.2s
    monkeypatch.setattr(manager_module.time, "perf_counter", lambda: next(ticks))
    session_s = MagicMock()
    session_s.get.side_effect = [r_slow]
    ok, lat, msg = manager.test_single_proxy(19880, test_url="https://cp.cloudflare.com/generate_204", timeout=5.0, session=session_s)
    assert ok and lat == 4900 and msg == "OK"
    assert session_s.get.call_count == 1
