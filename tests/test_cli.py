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
    manager.stop.return_value = (True, "OK")
    manager.test_all_proxies.return_value = {19890: (passed, 0 if passed else None, "OK" if passed else "timeout")}
    manager.is_running.return_value = False
    monkeypatch.setattr(cli, "XrayManager", lambda: manager)
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
    manager.stop.assert_called_once()


def test_cli_interrupt_during_probes_reaches_cleanup(tmp_path, make_node, monkeypatch):
    manager = Mock()
    manager.start.return_value = manager.stop.return_value = (True, "OK")
    handlers = {}
    monkeypatch.setattr(cli, "XrayManager", lambda: manager)
    monkeypatch.setattr(cli, "fetch_subscription_with_meta", lambda url: (make_node().raw_link, {}))
    def register_handler(sig, handler):
        handlers[sig] = handler

    monkeypatch.setattr(cli.signal, "signal", register_handler)

    def probe(nodes, *, cancel_event):
        handlers[cli.signal.SIGINT](cli.signal.SIGINT, None)
        assert cancel_event.is_set()
        manager.stop.assert_not_called()
        return {}

    manager.test_all_proxies.side_effect = probe
    target = tmp_path / "proxies.txt"
    args = argparse.Namespace(sub="https://example.com/sub", file=None, start_port=19890,
                              listen="127.0.0.1", max_nodes=0, test=True, export=str(target))
    cli.run_cli(args)
    manager.stop.assert_called_once()
    assert not target.exists()
