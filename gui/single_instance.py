import ctypes
import sys
from functools import lru_cache
from typing import Optional


GUI_MUTEX_NAME = r"Local\XraySubMapper.Desktop.Gui"
_ACTIVATION_MESSAGE = "XraySubMapper.Desktop.Activate"
_ERROR_ALREADY_EXISTS = 183
_SYNCHRONIZE = 0x00100000


class GuiInstanceLock:
    """Keep the Windows GUI's named mutex alive until the event loop exits."""

    def __init__(self, name: str = GUI_MUTEX_NAME):
        self.name = name
        self._handle: Optional[int] = None
        self._kernel32 = None

    def acquire(self) -> bool:
        if sys.platform != "win32" or self._handle is not None:
            return True
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create = self._kernel32.CreateMutexExW
        create.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        create.restype = ctypes.c_void_p
        close = self._kernel32.CloseHandle
        close.argtypes = [ctypes.c_void_p]
        close.restype = ctypes.c_int
        ctypes.set_last_error(0)
        # Object existence gates startup; no mutex ownership or write access is needed.
        handle = create(None, self.name, 0, _SYNCHRONIZE)
        error = ctypes.get_last_error()
        if not handle:
            raise ctypes.WinError(error)
        if error == _ERROR_ALREADY_EXISTS:
            close(handle)
            return False
        self._handle = handle
        return True

    def close(self) -> None:
        if self._handle is not None:
            handle, self._handle = self._handle, None
            self._kernel32.CloseHandle(handle)


@lru_cache(maxsize=1)
def activation_message_id() -> int:
    if sys.platform != "win32":
        return 0
    register = ctypes.windll.user32.RegisterWindowMessageW
    register.argtypes = [ctypes.c_wchar_p]
    register.restype = ctypes.c_uint32
    return register(_ACTIVATION_MESSAGE)


def activate_existing_window(title: str) -> bool:
    if sys.platform != "win32":
        return False
    user32 = ctypes.windll.user32
    find_window = user32.FindWindowW
    find_window.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    find_window.restype = ctypes.c_void_p
    hwnd = find_window(None, title)
    message = activation_message_id()
    if not hwnd or not message:
        return False
    process_id = ctypes.c_uint32()
    get_process = user32.GetWindowThreadProcessId
    get_process.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    get_process.restype = ctypes.c_uint32
    get_process(hwnd, ctypes.byref(process_id))
    allow_foreground = user32.AllowSetForegroundWindow
    allow_foreground.argtypes = [ctypes.c_uint32]
    allow_foreground.restype = ctypes.c_int
    allow_foreground(process_id.value)
    post_message = user32.PostMessageW
    post_message.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_size_t, ctypes.c_ssize_t]
    post_message.restype = ctypes.c_int
    return bool(post_message(hwnd, message, 0, 0))
