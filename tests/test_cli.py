import argparse
from unittest.mock import Mock

import pytest

import cli


@pytest.mark.parametrize("passed", [False, True])
def test_export_contains_only_successful_probes(tmp_path, make_node, monkeypatch, passed):
    node = make_node()
    node.latency_ms = 10 if passed else -1
    target = tmp_path / "proxies.txt"
    manager = Mock()
    manager.start.return_value = (True, "OK")
    manager.test_all_proxies.return_value = {19890: (passed, 10 if passed else None, "OK" if passed else "timeout")}
    manager.is_running.return_value = False
    monkeypatch.setattr(cli, "XrayManager", lambda: manager)
    monkeypatch.setattr(cli, "parse_subscription_content", lambda text: ([node], []))
    monkeypatch.setattr(cli, "fetch_subscription_with_meta", lambda url: ("synthetic", {}))
    monkeypatch.setattr(cli.signal, "signal", lambda *args: None)
    args = argparse.Namespace(sub="https://example.com/sub", file=None, start_port=19890,
                              listen="127.0.0.1", max_nodes=0, test=True, export=str(target))
    with pytest.raises(SystemExit):
        cli.run_cli(args)
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == int(passed)
    if passed:
        assert "19890" in lines[0]
