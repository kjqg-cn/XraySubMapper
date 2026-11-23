import os
import subprocess
import sys
import uuid
from unittest.mock import Mock

import pytest

from gui.single_instance import GuiInstanceLock, activate_existing_window


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows GUI singleton")


@pytest.fixture
def held_mutex():
    name = rf"Local\XraySubMapper.Test.{uuid.uuid4().hex}"
    code = f"""
import sys
from gui.single_instance import GuiInstanceLock
lock = GuiInstanceLock({name!r})
assert lock.acquire()
print("READY", flush=True)
sys.stdin.readline()
lock.close()
"""
    process = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        assert process.stdout.readline().strip() == "READY"
        yield name, process
    finally:
        if process.poll() is None:
            process.stdin.write("exit\n")
            process.stdin.flush()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def test_existing_instance_is_rejected_across_processes(held_mutex):
    name, _ = held_mutex
    duplicate = GuiInstanceLock(name)
    try:
        assert not duplicate.acquire()
    finally:
        duplicate.close()


def test_access_denied_mutex_is_treated_as_existing_instance(monkeypatch):
    import ctypes
    from types import SimpleNamespace
    import gui.single_instance as mod

    def create_denied(*args):
        ctypes.set_last_error(mod._ERROR_ACCESS_DENIED)
        return 0

    fake_kernel32 = SimpleNamespace(
        CreateMutexExW=create_denied,
        CloseHandle=lambda handle: 1,
    )
    monkeypatch.setattr(mod.ctypes, "WinDLL", lambda *args, **kwargs: fake_kernel32)
    lock = GuiInstanceLock(r"Local\XraySubMapper.Test.AccessDenied")
    assert lock.acquire() is False
    assert lock._handle is None


@pytest.mark.parametrize("termination", ["normal", "killed"])
def test_mutex_is_released_after_owner_exits(held_mutex, termination):
    name, process = held_mutex
    if termination == "normal":
        process.stdin.write("exit\n")
        process.stdin.flush()
    else:
        process.terminate()
    process.wait(timeout=5)
    replacement = GuiInstanceLock(name)
    try:
        assert replacement.acquire()
    finally:
        replacement.close()


def test_duplicate_gui_does_not_load_cache_or_construct_another_window(held_mutex):
    name, _ = held_mutex
    code = f"""
from unittest.mock import Mock
import gui.app as gui
gui.GUI_MUTEX_NAME = {name!r}
gui.MainWindow = Mock(side_effect=AssertionError("A duplicate window was constructed"))
gui.load_settings = Mock(side_effect=AssertionError("A duplicate read the settings"))
gui.activate_existing_window = Mock(return_value=True)
gui.run_gui()
gui.MainWindow.assert_not_called()
gui.load_settings.assert_not_called()
gui.activate_existing_window.assert_called_once_with(gui.GUI_WINDOW_TITLE)
print("DUPLICATE_REJECTED")
"""
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=10, env=env,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    assert b"DUPLICATE_REJECTED" in result.stdout


def test_cli_entry_can_run_while_gui_mutex_is_held(held_mutex, monkeypatch):
    import cli
    import gui.app as gui
    import main

    name, _ = held_mutex
    monkeypatch.setattr(gui, "GUI_MUTEX_NAME", name)
    run_cli = Mock()
    run_gui = Mock(side_effect=AssertionError("CLI must not launch the GUI"))
    monkeypatch.setattr(cli, "run_cli", run_cli)
    monkeypatch.setattr(gui, "run_gui", run_gui)
    monkeypatch.setattr(sys, "argv", ["main.py", "--file", "nodes.txt"])
    main.main()
    assert run_cli.call_args.args[0].file == "nodes.txt"
    run_gui.assert_not_called()


def test_native_activation_message_reaches_a_hidden_qt_window():
    title = f"XraySubMapper native activation test {uuid.uuid4().hex}"
    code = f"""
from unittest.mock import Mock
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
import gui.app as gui
from core.config import DEFAULT_SETTINGS, CacheSaveResult

gui.load_settings = lambda: dict(DEFAULT_SETTINGS)
gui.load_cached_nodes = list
gui.save_settings = Mock(return_value=CacheSaveResult())
gui.save_cached_nodes = Mock(return_value=CacheSaveResult())
gui.MainWindow._setup_tray = lambda self: setattr(self, "tray", None)
app = QApplication([])
app.aboutToQuit.connect(gui.clear_icon_caches)
window = gui.MainWindow()
window._watchdog.stop()
window.setWindowTitle({title!r})

def activated():
    print("ACTIVATED", flush=True)
    app.quit()

window._bring_to_front = activated
window.winId()
assert not window.isVisible()
print("READY", flush=True)
QTimer.singleShot(4000, lambda: app.exit(3))
result = app.exec()
window.xray_mgr.close()
raise SystemExit(result)
"""
    env = dict(os.environ, QT_QPA_PLATFORM="windows")
    startup = subprocess.STARTUPINFO()
    startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", env=env, startupinfo=startup,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        assert process.stdout.readline().strip() == "READY"
        assert activate_existing_window(title)
        output, error = process.communicate(timeout=10)
        assert process.returncode == 0, error
        assert "ACTIVATED" in output and "Traceback" not in error
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
