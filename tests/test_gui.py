import copy
import os
import threading
import time
import warnings
from unittest.mock import Mock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication

from core.config import DEFAULT_SETTINGS
from gui.app import MainWindow


@pytest.fixture(scope="module")
def application():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(application, monkeypatch):
    monkeypatch.setattr("gui.app.load_settings", lambda: copy.deepcopy(DEFAULT_SETTINGS))
    monkeypatch.setattr("gui.app.load_cached_nodes", lambda: [])
    monkeypatch.setattr("gui.app.save_settings", lambda *args: None)
    monkeypatch.setattr("gui.app.save_cached_nodes", lambda *args: None)
    monkeypatch.setattr(MainWindow, "_setup_tray", lambda self: setattr(self, "tray", None))
    window = MainWindow()
    window._watchdog.stop()
    window._notify = Mock()
    yield window
    window.xray_mgr.stop()
    window.xray_mgr.set_log_callback(lambda message: None)
    window._force_quit = True
    window.close()
    application.processEvents()


def spin(application, predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        application.processEvents()
        if predicate():
            return
        time.sleep(0.005)
    pytest.fail("GUI worker did not finish")


@pytest.mark.parametrize("edit", ["port", "auth", "listen"])
def test_edits_during_start_remain_unapplied(window, application, make_node, monkeypatch, edit):
    node = make_node(port=19880)
    window.nodes = [node]
    window.table_model.set_nodes(window.nodes)
    entered, release = threading.Event(), threading.Event()
    submitted = []

    def start(nodes, **kwargs):
        submitted.append((nodes, kwargs))
        entered.set()
        assert release.wait(5)
        return True, "OK"

    monkeypatch.setattr(window.xray_mgr, "start", start)
    monkeypatch.setattr(window.xray_mgr, "is_running", lambda: True)
    try:
        window._start_service()
        assert entered.wait(5)
        assert not window.btn_service.isEnabled()
        if edit == "port":
            window._on_inline_port_edited(0, 19881)
        elif edit == "auth":
            window.settings.update(auth_enabled=True, auth_user="new", auth_pass="secret")
        else:
            window.combo_listen.setValue("0.0.0.0")
        release.set()
        spin(application, lambda: not window._service_busy)
        assert window._has_unapplied_changes()
        assert not window.btn_reload_dirty.isHidden()
        assert submitted[0][0][0].local_port == 19880
        assert submitted[0][1]["listen_ip"] == "127.0.0.1"
        assert submitted[0][1]["auth_user"] == ""
    finally:
        release.set()
        spin(application, lambda: not window._service_busy)


def test_filtering_passed_nodes_blocks_wrong_proxy_export(window, application, make_node, monkeypatch):
    a, b = make_node("failed", 19880), make_node("passed", 19881)
    a.latency_ms, b.latency_ms = -1, 20
    window.nodes = [a, b]
    window.table_model.set_nodes(window.nodes)
    window.inp_start_port.setText("19880")
    monkeypatch.setattr(window.xray_mgr, "is_running", lambda: True)
    window._applied_signature = window._calc_config_signature()
    window._keep_only_passed_nodes()
    assert b.local_port == 19880
    application.clipboard().setText("unchanged")
    window._copy_proxies_bulk()
    window._copy_node_proxy(b, "url")
    assert application.clipboard().text() == "unchanged"
    save_dialog = Mock()
    monkeypatch.setattr("gui.app.QFileDialog.getSaveFileName", save_dialog)
    window._export_proxies_to_file()
    save_dialog.assert_not_called()


def test_subscription_refresh_keeps_pins_and_enabled_state(window, make_node):
    pinned = make_node("old-name", 25000)
    pinned.port_pinned = True
    disabled = make_node("disabled", 0)
    disabled.server = "other.example.com"
    disabled.enabled = False
    window.nodes = [pinned, disabled]
    window.table_model.set_nodes(window.nodes)
    fresh = make_node("new-name")
    fresh_disabled = copy.deepcopy(disabled)
    fresh_disabled.enabled = True
    fresh_disabled.port_pinned = False
    window._load_new_nodes([fresh_disabled, fresh], preserve_state=True)
    assert fresh.port_pinned and fresh.local_port == 25000
    assert not fresh_disabled.enabled


@pytest.mark.parametrize("kind", ["speed", "exit"])
@pytest.mark.parametrize("change", ["port", "generation", "replace"])
def test_queued_probe_result_cannot_update_new_configuration(window, make_node, monkeypatch, kind, change):
    node = make_node(port=19880)
    window.nodes = [node]
    window.table_model.set_nodes(window.nodes)
    monkeypatch.setattr(window.xray_mgr, "is_running", lambda: True)
    signature = window._calc_config_signature()
    window._applied_signature = signature
    tested = copy.deepcopy(node)
    tested.latency_ms, tested.exit_ip = 42, "192.0.2.1"
    payload = (node, tested, signature, window.xray_mgr.generation)
    if change == "port":
        node.local_port = 19881
    elif change == "generation":
        window.xray_mgr.generation += 1
    else:
        window.nodes = [make_node(port=19880)]
        window.table_model.set_nodes(window.nodes)
    handler = window._on_speed_progress if kind == "speed" else window._on_exit_ip_progress
    handler(1, 1, payload)
    assert node.latency_ms is None and node.exit_ip == ""


def test_busy_service_blocks_window_and_tray_reentry(window, monkeypatch):
    window.tray = Mock()
    window.act_tray_toggle = Mock()
    window._set_service_busy(True)
    assert not window.btn_service.isEnabled() and not window.btn_reload_dirty.isEnabled()
    window.act_tray_toggle.setEnabled.assert_called_with(False)
    start, stop = Mock(), Mock()
    monkeypatch.setattr(window.xray_mgr, "start", start)
    monkeypatch.setattr(window.xray_mgr, "stop", stop)
    window._toggle_service()
    window._reload_service()
    window._start_service()
    window._stop_service()
    start.assert_not_called()
    stop.assert_not_called()
    window._set_service_busy(False)


def test_valid_probe_result_is_applied_on_gui_thread(window, make_node, monkeypatch):
    node = make_node(port=19880)
    window.nodes = [node]
    window.table_model.set_nodes(window.nodes)
    monkeypatch.setattr(window.xray_mgr, "is_running", lambda: True)
    signature = window._calc_config_signature()
    window._applied_signature = signature
    tested = copy.deepcopy(node)
    tested.latency_ms, tested.exit_ip = 42, "192.0.2.1"
    payload = (node, tested, signature, window.xray_mgr.generation)
    window._on_speed_progress(1, 1, payload)
    window._on_exit_ip_progress(1, 1, payload)
    assert node.latency_ms == 42 and node.exit_ip == "192.0.2.1"


def test_cache_read_failure_is_visible_in_gui(window, application, monkeypatch):
    def load_settings():
        warnings.warn("无法读取或保护设置缓存: cannot decrypt", RuntimeWarning)
        return copy.deepcopy(DEFAULT_SETTINGS)

    show_warning = Mock()
    monkeypatch.setattr("gui.app.load_settings", load_settings)
    monkeypatch.setattr("gui.app.QMessageBox.warning", show_warning)
    other = MainWindow()
    other._watchdog.stop()
    try:
        spin(application, lambda: show_warning.called)
        assert "cannot decrypt" in show_warning.call_args.args[2]
        assert "原文件会保留" in show_warning.call_args.args[2]
    finally:
        other._force_quit = True
        other.close()
        application.processEvents()
