import base64
import copy
import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import uuid
import warnings
from unittest.mock import Mock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QSpinBox

from core import config
from core.config import CacheSaveResult, DEFAULT_SETTINGS
from gui.app import MainWindow, ProbeTask
from gui.single_instance import GuiInstanceLock, activation_message_id
from gui.widgets import COL_ENABLED, ProxySettingsDialog, extract_region_and_clean_name


@pytest.fixture(scope="module")
def application():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(application, monkeypatch):
    monkeypatch.setattr("gui.app.load_settings", lambda: copy.deepcopy(DEFAULT_SETTINGS))
    monkeypatch.setattr("gui.app.load_cached_nodes", lambda: [])
    monkeypatch.setattr("gui.app.save_settings", lambda *args, **kwargs: CacheSaveResult())
    monkeypatch.setattr("gui.app.save_cached_nodes", lambda *args, **kwargs: CacheSaveResult())
    monkeypatch.setattr(MainWindow, "_setup_tray", lambda self: setattr(self, "tray", None))
    window = MainWindow()
    window._watchdog.stop()
    window._notify = Mock()
    yield window
    window.xray_mgr.stop()
    window.xray_mgr.set_log_callback(lambda message: None)
    window._force_quit = True
    window.close()
    spin(application, lambda: window._shutdown_complete)


def spin(application, predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        application.processEvents()
        if predicate():
            return
        time.sleep(0.005)
    pytest.fail("GUI worker did not finish")


@pytest.fixture
def protected_settings(window, tmp_path, monkeypatch):
    path = tmp_path / "app_settings.json"
    original = b'{"auth_pass": "legacy-fixture"'
    path.write_bytes(original)
    monkeypatch.setattr(config, "CONFIG_FILE", str(path))
    monkeypatch.setattr(config, "_UNREADABLE_FILES", set())
    monkeypatch.setattr("gui.app.save_settings", config.save_settings)
    with pytest.warns(RuntimeWarning, match="无法读取"):
        window.settings = config.load_settings()
    return path, original


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
@pytest.mark.parametrize("action", ["import", "subscription", "listen", "port", "rearrange", "clear", "history"])
def test_explicit_actions_recover_protected_settings(window, protected_settings, make_node, monkeypatch, action):
    path, original = protected_settings
    if action == "import":
        window._parse_and_load_raw_text(make_node().raw_link)
    elif action == "subscription":
        request = object()
        window._fetch_request = request
        window._on_fetch_finished(request, "https://example.com/new-sub", ([make_node()], [], {}), "")
    elif action == "listen":
        window.combo_listen.setValue("0.0.0.0", emit_signal=True)
    elif action in ("port", "rearrange"):
        window.inp_start_port.setText("19880")
        if action == "port":
            window._on_start_port_edited()
        else:
            window._rearrange_ports_clicked()
    elif action == "clear":
        window.nodes = [make_node()]
        window.table_model.set_nodes(window.nodes)
        from PySide6.QtWidgets import QMessageBox

        monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Yes)
        monkeypatch.setattr("gui.app.clear_cached_nodes", lambda **kwargs: CacheSaveResult())
        window._clear_all_nodes()
    else:
        window.settings["recent_urls"] = ["https://example.com/old-sub"]
        window._clear_recent_urls()

    assert path.read_bytes() != original
    backups = list(path.parent.glob("app_settings.json.*.bak"))
    assert len(backups) == 1
    envelope = json.loads(backups[0].read_text(encoding="utf-8"))
    assert config._crypt_data(base64.b64decode(envelope["data"]), protect=False) == original
    assert config.load_settings() == window.settings
    assert "原缓存已备份至:" in window.txt_console.toPlainText()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_window_autosave_keeps_unreadable_settings(window, protected_settings):
    path, original = protected_settings
    with pytest.warns(RuntimeWarning, match="阻止覆盖"):
        window._save_window_state()
    assert path.read_bytes() == original
    assert not list(path.parent.glob("*.bak"))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
@pytest.mark.parametrize("action", ["checkbox", "selected", "invert", "delete", "batch", "passed"])
def test_node_edits_preserve_protected_settings_and_save_nodes(
    window, application, protected_settings, make_node, monkeypatch, action,
):
    settings_path, original = protected_settings
    nodes_path = settings_path.parent / "cached_nodes.json"
    monkeypatch.setattr(config, "NODES_CACHE_FILE", str(nodes_path))
    monkeypatch.setattr("gui.app.save_cached_nodes", config.save_cached_nodes)
    window.nodes = [make_node("one", 10800), make_node("two", 10801)]
    window.nodes[0].latency_ms, window.nodes[1].latency_ms = 42, -1
    window.table_model.set_nodes(window.nodes)
    window.table_view.selectRow(0)
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always", RuntimeWarning)
        if action == "checkbox":
            window._on_table_clicked(window.proxy_model.index(0, COL_ENABLED))
        elif action == "selected":
            window._toggle_selected_rows()
        elif action == "invert":
            window._invert_selection()
        elif action == "delete":
            window._delete_selected_rows()
        elif action == "batch":
            window._batch_set_enabled(False)
        else:
            window._keep_only_passed_nodes()
        application.processEvents()
    assert not recorded
    assert settings_path.read_bytes() == original
    assert not list(settings_path.parent.glob("app_settings.json.*.bak"))
    assert [node.to_dict() for node in config.load_cached_nodes()] == [node.to_dict() for node in window.nodes]
    assert all(call.args[1] != "error" for call in window._notify.call_args_list)


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


def test_equivalent_subscription_refresh_does_not_require_reload(window, make_node, monkeypatch):
    node = make_node("before", 10800)
    window._load_new_nodes([node])
    window._applied_signature = window._calc_config_signature()
    monkeypatch.setattr(window.xray_mgr, "is_running", lambda: True)
    window._load_new_nodes([make_node("after")], preserve_state=True)
    window.settings.update(auth_user="unused", auth_pass="unused")
    assert not window._has_unapplied_changes()


def test_overflow_does_not_reuse_the_last_pinned_port(window, make_node, monkeypatch):
    locked = make_node("locked", 65535)
    locked.port_pinned = True
    window.nodes = [locked, make_node("auto"), make_node("overflow")]
    window.table_model.set_nodes(window.nodes)
    monkeypatch.setattr(window, "_get_start_port", lambda: 65534)
    window._assign_ports()
    assert [n.local_port for n in window.nodes] == [65535, 65534, 0]
    assert "1 个节点未分配端口" in window.lbl_stats.text()


def test_repeated_enter_and_late_fetch_after_manual_import(window, application, make_node, monkeypatch):
    url = "https://example.com/sub"
    entered, release = threading.Event(), threading.Event()
    requests, completed = [], []

    def fetch(request_url):
        requests.append(request_url)
        entered.set()
        assert release.wait(5)
        return make_node("remote").raw_link, {"summary": "old"}

    monkeypatch.setattr("gui.app.fetch_subscription_with_meta", fetch)
    window.bridge.fetchFinished.connect(lambda *args: completed.append(args))
    window.settings.update(subscription_url=url, sub_userinfo={"summary": "old"}, recent_urls=[url])
    window.inp_url.setText(url)
    window.inp_url.returnPressed.emit()
    try:
        assert entered.wait(5)
        window.inp_url.returnPressed.emit()
        window._parse_and_load_raw_text(make_node("manual").raw_link)
        release.set()
        spin(application, lambda: bool(completed))
        assert requests == [url]
        assert [node.name for node in window.nodes] == ["manual"]
        assert not window.settings["subscription_url"] and not window.settings["sub_userinfo"]
        assert window.settings["recent_urls"] == [url]
    finally:
        release.set()


def test_fetch_finishes_for_submitted_url_while_user_edits_next_url(window, make_node):
    submitted = "https://example.com/sub"
    draft = "https://example.com/next"
    request = object()
    window._fetch_request = request
    window.inp_url.setText(draft)
    window._on_fetch_finished(request, submitted, ([make_node("downloaded")], [], {}), "")
    assert window.nodes[0].name == "downloaded"
    assert window.inp_url.text() == draft
    assert window.settings["subscription_url"] == submitted


def test_explicit_import_reports_cache_failure(window, application, make_node, monkeypatch):
    save = Mock(return_value=CacheSaveResult(error="模拟节点缓存写入失败"))
    monkeypatch.setattr("gui.app.save_cached_nodes", save)
    window._parse_and_load_raw_text(make_node("manual").raw_link)
    save.assert_called_once_with(window.nodes, replace_unreadable=True)
    spin(application, lambda: window._notify.call_args.args[1] == "error")
    assert "模拟节点缓存写入失败" in window.txt_console.toPlainText()


def test_clear_empty_view_can_recover_protected_cache(window, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr("gui.app.nodes_cache_protected", lambda: True)
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Yes)
    clear = Mock(return_value=CacheSaveResult(backup_path="cached_nodes.json.test.bak"))
    monkeypatch.setattr("gui.app.clear_cached_nodes", clear)
    window._clear_all_nodes()
    clear.assert_called_once_with(replace_unreadable=True)
    assert not window.nodes


def test_clear_nodes_resets_search_before_next_import(window, make_node, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    window._load_new_nodes([make_node("old")])
    window.inp_search.setText("old")
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr("gui.app.clear_cached_nodes", lambda **kwargs: CacheSaveResult())
    window._clear_all_nodes()
    assert not window.inp_search.text()
    window._load_new_nodes([make_node("new")])
    assert window.proxy_model.rowCount() == 1


@pytest.mark.parametrize("kind", ["speed", "exit"])
def test_single_and_batch_probes_share_a_task(window, application, make_node, monkeypatch, kind):
    window._load_new_nodes([make_node("first"), make_node("second")])
    window._applied_signature = window._calc_config_signature()
    monkeypatch.setattr(window.xray_mgr, "is_running", lambda: True)
    entered, release = threading.Event(), threading.Event()
    batches = []

    def operation(nodes, *, progress_cb, **kwargs):
        batches.append(len(nodes))
        entered.set()
        assert release.wait(5)
        for index, node in enumerate(nodes, 1):
            node.latency_ms, node.exit_ip = 0, "192.0.2.1"
            progress_cb(index, len(nodes), node)

    speed = kind == "speed"
    monkeypatch.setattr(window.xray_mgr, "test_all_proxies" if speed else "probe_all_exit_ips", operation)
    batch = window._test_all_speed_async if speed else window._probe_all_exit_ips_async
    single = window._test_single_row_async if speed else window._probe_single_exit_ip_async
    button = window.btn_speed if speed else window.btn_probe_ip
    batch()
    try:
        assert entered.wait(5)
        single(0)
        assert "0/2" in button.text()
        release.set()
        spin(application, button.isEnabled)
        assert batches == [2]
        if speed:
            assert window.nodes[0].latency_ms == 0
        else:
            assert window.nodes[0].exit_ip == "192.0.2.1"
    finally:
        release.set()


def test_no_enabled_nodes_does_not_stop_service_for_probe(window, make_node, monkeypatch):
    node = make_node()
    node.enabled = False
    window.nodes = [node]
    monkeypatch.setattr(window.xray_mgr, "is_running", lambda: True)
    reload_service = Mock()
    monkeypatch.setattr(window, "_reload_service", reload_service)
    window._test_all_speed_async()
    reload_service.assert_not_called()


def test_closing_with_service_transition_waits_off_gui_thread(window, application, monkeypatch):
    window._set_service_busy(True)
    entered, release = threading.Event(), threading.Event()
    caller = threading.get_ident()

    def close():
        assert threading.get_ident() != caller
        entered.set()
        assert release.wait(5)
        return True, "OK"

    monkeypatch.setattr(window.xray_mgr, "close", close)
    try:
        assert not window.close()
        assert entered.wait(5) and not window._shutdown_complete
        release.set()
        spin(application, lambda: window._shutdown_complete)
    finally:
        release.set()


@pytest.mark.parametrize("running", [False, True])
@pytest.mark.parametrize("force_quit", [False, True])
def test_run_gui_exits_after_hidden_window_closes(running, force_quit):
    # Run the production event loop in an isolated process.
    mutex_name = rf"Local\XraySubMapper.Test.{uuid.uuid4().hex}"
    code = f"""
from unittest.mock import Mock
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
import gui.app as gui

gui.GUI_MUTEX_NAME = {mutex_name!r}
gui.load_settings = lambda: {DEFAULT_SETTINGS!r}
gui.load_cached_nodes = list
gui.save_settings = Mock(return_value=gui.CacheSaveResult())
gui.save_cached_nodes = Mock(return_value=gui.CacheSaveResult())
gui._set_windows_app_user_model_id = lambda: None

class HiddenWindow(gui.MainWindow):
    def _setup_tray(self):
        self.tray = None

    def __init__(self):
        super().__init__()
        self.xray_mgr.is_running = lambda: {running!r}
        self.xray_mgr.close = Mock(return_value=(True, "closed"))
        QTimer.singleShot(0, self.quit_hidden)
        QTimer.singleShot(3000, lambda: QApplication.instance().exit(3))
        QApplication.instance().aboutToQuit.connect(self.check_cleanup)

    def quit_hidden(self):
        self.hide()
        self._quit_completely() if {force_quit!r} else self.close()

    def check_cleanup(self):
        print("manager closed", self.xray_mgr.close.call_count)

gui.MainWindow = HiddenWindow
gui.run_gui()
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert b"manager closed 1" in result.stdout


def test_close_prompt_reentry_and_tray_quit_cleanup_once():
    mutex_name = rf"Local\XraySubMapper.Test.{uuid.uuid4().hex}"
    code = f"""
from unittest.mock import Mock
from PySide6.QtCore import QCoreApplication, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QMessageBox
import gui.app as gui

gui.GUI_MUTEX_NAME = {mutex_name!r}
gui.load_settings = lambda: {DEFAULT_SETTINGS!r}
gui.load_cached_nodes = list
gui.save_settings = Mock(return_value=gui.CacheSaveResult())
gui.save_cached_nodes = Mock(return_value=gui.CacheSaveResult())
gui._set_windows_app_user_model_id = lambda: None
prompts = []
real_exec = QMessageBox.exec

def exec_prompt(box):
    prompts.append(box)
    return real_exec(box)

QMessageBox.exec = exec_prompt

def dismiss_prompts():
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, QMessageBox):
            widget.reject()

class PromptWindow(gui.MainWindow):
    def _setup_tray(self):
        self.tray = Mock()
        self.tray.isVisible.return_value = True

    def __init__(self):
        super().__init__()
        self._watchdog.stop()
        self.xray_mgr.is_running = lambda: True
        self.xray_mgr.close = Mock(return_value=(True, "closed"))
        QTimer.singleShot(0, self.begin_close)
        QTimer.singleShot(2000, lambda: QApplication.instance().exit(3))
        QApplication.instance().aboutToQuit.connect(self.check_cleanup)

    def begin_close(self):
        QTimer.singleShot(0, lambda: QCoreApplication.sendEvent(self, QCloseEvent()))
        QTimer.singleShot(30, self._quit_completely)
        QTimer.singleShot(150, dismiss_prompts)
        self.close()

    def check_cleanup(self):
        print("prompts", len(prompts), "closed", self.xray_mgr.close.call_count)

gui.MainWindow = PromptWindow
gui.run_gui()
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert b"prompts 1 closed 1" in result.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="Windows GUI singleton")
def test_gui_initialization_failure_releases_instance_lock(application, monkeypatch):
    import gui.app as gui

    name = rf"Local\XraySubMapper.Test.{uuid.uuid4().hex}"
    monkeypatch.setattr(gui, "GUI_MUTEX_NAME", name)
    monkeypatch.setattr(gui, "MainWindow", Mock(side_effect=RuntimeError("initialization failed")))
    with pytest.raises(RuntimeError, match="initialization failed"):
        gui.run_gui()
    replacement = GuiInstanceLock(name)
    try:
        assert replacement.acquire()
    finally:
        replacement.close()


def test_gui_mutex_failure_is_reported_before_window_initialization(application, monkeypatch):
    import gui.app as gui

    lock = Mock()
    lock.acquire.side_effect = OSError("mutex unavailable")
    critical, constructor = Mock(), Mock()
    monkeypatch.setattr(gui, "GuiInstanceLock", lambda name: lock)
    monkeypatch.setattr(gui, "MainWindow", constructor)
    monkeypatch.setattr(gui.QMessageBox, "critical", critical)
    with pytest.raises(SystemExit) as result:
        gui.run_gui()
    assert result.value.code == 1 and "mutex unavailable" in critical.call_args.args[2]
    constructor.assert_not_called()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native activation message")
@pytest.mark.parametrize("closing", [False, True])
def test_activation_restores_window_unless_shutdown_has_started(window, application, closing):
    from ctypes.wintypes import MSG

    message = MSG()
    message.message = activation_message_id()
    window.setWindowState(Qt.WindowState.WindowMinimized)
    window.hide()
    window._closing = closing
    try:
        assert window.nativeEvent(b"windows_generic_MSG", ctypes.addressof(message)) == (True, 0)
        application.processEvents()
        assert window.isVisible() is not closing
        if not closing:
            assert not window.windowState() & Qt.WindowState.WindowMinimized
    finally:
        window._closing = False


def test_paste_shortcut_protects_numeric_editor(window, application, make_node, monkeypatch):
    editor = QSpinBox(window)
    monkeypatch.setattr(QApplication, "focusWidget", lambda: editor)
    application.clipboard().setText(make_node().raw_link)
    window._smart_paste_shortcut()
    assert not window.nodes


def test_incomplete_auth_cannot_be_saved(window, monkeypatch):
    warning = Mock()
    monkeypatch.setattr("gui.widgets.QMessageBox.warning", warning)
    dialog = ProxySettingsDialog(True, "user", "", "", parent=window)
    dialog.accept()
    warning.assert_called_once()
    assert not dialog.result()
    dialog.inp_pass.setText("password")
    dialog.accept()
    assert dialog.get_values()[:3] == (True, "user", "password")
    assert dialog.result() == dialog.DialogCode.Accepted


@pytest.mark.parametrize("name", ["My-Network-Node", "Ukraine-01", "Fukuoka-01", "Jerusalem-01"])
def test_unrelated_english_names_do_not_match_region_abbreviations(name):
    assert extract_region_and_clean_name(name) == ("", name)


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
    task = ProbeTask(window.xray_mgr.generation, signature, (node,), False)
    setattr(window, "_speed_task" if kind == "speed" else "_exit_ip_task", task)
    payload = (task, node, tested)
    if change == "port":
        node.local_port = 19881
    elif change == "generation":
        window.xray_mgr.generation += 1
    else:
        window._load_new_nodes([make_node(port=19880)])
    notify = window._notify
    notify.reset_mock()
    persist = Mock()
    monkeypatch.setattr(window, "_persist_nodes", persist)
    handler = window._on_speed_progress if kind == "speed" else window._on_exit_ip_progress
    handler(1, 1, payload)
    finish = window._on_speed_finished if kind == "speed" else window._on_exit_ip_finished
    finish(task, "")
    assert node.latency_ms is None and node.exit_ip == ""
    notify.assert_not_called()
    persist.assert_not_called()


def test_busy_service_blocks_window_and_tray_reentry(window, monkeypatch):
    window.tray = Mock()
    window.act_tray_toggle = Mock()
    window._set_service_busy(True)
    assert not window.btn_service.isEnabled() and not window.btn_reload_dirty.isEnabled()
    window.act_tray_toggle.setEnabled.assert_called_with(False)
    start, stop = Mock(), Mock(return_value=(True, "OK"))
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
    tested.latency_ms, tested.exit_ip = 0, "192.0.2.1"
    task = ProbeTask(window.xray_mgr.generation, signature, (node,), True)
    window._speed_task = window._exit_ip_task = task
    payload = (task, node, tested)
    window._on_speed_progress(1, 1, payload)
    window._on_exit_ip_progress(1, 1, payload)
    window._on_speed_finished(task, "")
    assert node.latency_ms == 0 and node.exit_ip == "192.0.2.1"
    assert window._notify.call_args.args[1] == "success"


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
        spin(application, lambda: other._shutdown_complete)
