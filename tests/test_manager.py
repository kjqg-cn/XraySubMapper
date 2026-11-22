import copy
import socket
import subprocess
import sys
import threading
import time
from contextlib import ExitStack

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
        assert not ok and "已占用" in message and str(port) in message
        assert manager.process is original and manager.is_running() and manager.listen_ip == "127.0.0.1"


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


def test_many_ports_start_without_per_port_waits(kernel_manager, make_node):
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
