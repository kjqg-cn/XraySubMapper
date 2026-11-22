import argparse
from unittest.mock import Mock

import pytest

import cli


@pytest.mark.parametrize("passed", [False, True])
def test_export_contains_only_successful_probes(tmp_path, make_node, monkeypatch, passed):
    node = make_node()
    node.latency_ms = 0 if passed else -1
    target = tmp_path / "proxies.txt"
    manager = Mock()
    manager.start.return_value = (True, "OK")
    manager.close.return_value = (True, "OK")
    manager.test_all_proxies.return_value = {19890: (passed, 0 if passed else None, "OK" if passed else "timeout")}
    manager.is_running.return_value = False
    monkeypatch.setattr(cli, "XrayManager", lambda **kwargs: manager)
    monkeypatch.setattr(cli, "parse_subscription_content", lambda text: ([node], []))
    monkeypatch.setattr(cli, "fetch_subscription_with_meta", lambda url: ("synthetic", {}))
    monkeypatch.setattr(cli.signal, "signal", lambda *args: None)
    args = argparse.Namespace(sub="https://example.com/sub", file=None, start_port=19890,
                              listen="::1", max_nodes=0, test=True, export=str(target),
                              auth_user="test", auth_pass="a+b")
    with pytest.raises(SystemExit):
        cli.run_cli(args)
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == int(passed)
    if passed:
        assert "http://test:a%2Bb@[::1]:19890" in lines[0]
        assert "[0ms]" in lines[0]
    manager.start.assert_called_once_with([node], "::1", auth_user="test", auth_pass="a+b")
    manager.close.assert_called_once()


def test_cli_interrupt_during_probes_reaches_cleanup(tmp_path, make_node, monkeypatch):
    manager = Mock()
    manager.start.return_value = manager.close.return_value = (True, "OK")
    handlers = {}
    monkeypatch.setattr(cli, "XrayManager", lambda **kwargs: manager)
    monkeypatch.setattr(cli, "fetch_subscription_with_meta", lambda url: (make_node().raw_link, {}))
    def register_handler(sig, handler):
        handlers[sig] = handler

    monkeypatch.setattr(cli.signal, "signal", register_handler)

    def probe(nodes, *, cancel_event):
        handlers[cli.signal.SIGINT](cli.signal.SIGINT, None)
        assert cancel_event.is_set()
        manager.close.assert_not_called()
        return {}

    manager.test_all_proxies.side_effect = probe
    target = tmp_path / "proxies.txt"
    args = argparse.Namespace(sub="https://example.com/sub", file=None, start_port=19890,
                              listen="127.0.0.1", max_nodes=0, test=True, export=str(target))
    cli.run_cli(args)
    manager.close.assert_called_once()
    assert not target.exists()


def test_cli_cancels_during_start_and_loads_auth_from_environment(make_node, monkeypatch):
    manager = Mock()
    manager.close.return_value = True, "OK"
    handlers = {}
    monkeypatch.setenv("XRAY_AUTH_PASS", "mock-secret")
    monkeypatch.setattr(cli, "fetch_subscription_with_meta", lambda url: (make_node().raw_link, {}))
    monkeypatch.setattr(cli.signal, "signal", lambda sig, handler: handlers.update({sig: handler}))

    def create_manager(*, cancel_event):
        def start(*args, **kwargs):
            handlers[cli.signal.SIGINT](cli.signal.SIGINT, None)
            assert cancel_event.is_set()
            assert kwargs["auth_pass"] == "mock-secret"
            return False, "cancelled"

        manager.start.side_effect = start
        return manager

    monkeypatch.setattr(cli, "XrayManager", create_manager)
    args = argparse.Namespace(sub="https://example.com/sub", file=None, start_port=19890,
                              listen="127.0.0.1", max_nodes=0, test=True, export=None,
                              auth_user="test", auth_pass=None)
    cli.run_cli(args)
    manager.close.assert_called_once()
    manager.test_all_proxies.assert_not_called()
