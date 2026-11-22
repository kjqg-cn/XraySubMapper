import copy
import socket
import threading
from types import SimpleNamespace

import pytest

from core.parser import parse_node_link


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


def test_reject_old_kernel_before_submitting_config(manager, monkeypatch):
    monkeypatch.setattr("core.xray_manager.subprocess.run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout="Xray 25.1.1", stderr=""))
    ok, error = manager.validate_config({})
    assert not ok and "26.11.9" in error


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
