import base64
import ctypes
import json
import os
import sys
import tempfile
import threading
import warnings
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Dict, List, Set


def get_app_dir() -> str:
    """Return executable directory when packaged as portable .exe, or project root in source mode."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def enable_windows_dpi_awareness() -> None:
    """Request Windows PerMonitorV2 DPI awareness before any native dialog or GUI creation."""
    if sys.platform != "win32":
        return
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        set_ctx = user32.SetProcessDpiAwarenessContext
        set_ctx.argtypes = [ctypes.c_void_p]
        set_ctx.restype = ctypes.c_int
        ctypes.set_last_error(0)
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = (DPI_AWARENESS_CONTEXT)-4
        if set_ctx(ctypes.c_void_p(-4)) or ctypes.get_last_error() == 5:
            # 5 == ERROR_ACCESS_DENIED (already declared by application manifest / earlier call).
            return
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass


BASE_DIR = get_app_dir()
CONFIG_FILE = os.path.join(BASE_DIR, "app_settings.json")
NODES_CACHE_FILE = os.path.join(BASE_DIR, "cached_nodes.json")
_WRITE_LOCK = threading.Lock()
_UNREADABLE_FILES: Set[str] = set()


@dataclass(frozen=True)
class CacheSaveResult:
    error: str = ""
    backup_path: str = ""


def _crypt_data(data: bytes, protect: bool) -> bytes:
    """Protect portable caches for the current Windows account, without a stored key."""
    if sys.platform != "win32":
        raise OSError("敏感配置缓存需要 Windows DPAPI，当前平台不保存敏感数据")

    class DataBlob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_ulong), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    buffer = ctypes.create_string_buffer(data)
    source = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    operation = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    operation.argtypes = [ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.c_void_p,
                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(DataBlob)]
    operation.restype = ctypes.c_int
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel32.LocalFree(target.data)


def _read_json(file_path: str, expected_type: type) -> Any:
    key = os.path.normcase(os.path.abspath(file_path))
    try:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            payload = json.load(f)
        protected = isinstance(payload, dict) and payload.get("format") == "dpapi-v1"
        if protected:
            encrypted = base64.b64decode(payload["data"], validate=True)
            payload = json.loads(_crypt_data(encrypted, protect=False).decode("utf-8"))
        if not isinstance(payload, expected_type):
            raise ValueError("缓存格式无效")
        with _WRITE_LOCK:
            _UNREADABLE_FILES.discard(key)
        if not protected:
            # Migrate legacy plaintext before returning it to the application.
            _atomic_write_json(file_path, payload)
        return payload
    except Exception:
        with _WRITE_LOCK:
            _UNREADABLE_FILES.add(key)
        raise


DEFAULT_SETTINGS: Dict[str, Any] = {
    "subscription_url": "",
    "start_port": 10800,
    "listen_ip": "127.0.0.1",
    "recent_urls": [],
    "test_url": "https://cp.cloudflare.com/generate_204",
    "auth_enabled": False,
    "auth_user": "",
    "auth_pass": "",
    "sub_userinfo": {},
    "window_rect": None,
    "column_widths": None,
}


def _protect_bytes(raw: bytes) -> dict:
    encrypted = _crypt_data(raw, protect=True)
    return {"format": "dpapi-v1", "data": base64.b64encode(encrypted).decode("ascii")}


def _backup_cache(file_path: str) -> str:
    with open(file_path, "rb") as source:
        raw = source.read()
    try:
        envelope = json.loads(raw)
        protected = (
            isinstance(envelope, dict)
            and envelope.keys() == {"format", "data"}
            and envelope["format"] == "dpapi-v1"
            and bool(base64.b64decode(envelope["data"], validate=True))
        )
    except (ValueError, TypeError, RecursionError):
        protected = False
    if not protected:
        raw = json.dumps(_protect_bytes(raw)).encode("utf-8")

    parent = os.path.dirname(os.path.abspath(file_path))
    backup_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=parent, prefix=f"{os.path.basename(file_path)}.",
            suffix=".bak", delete=False,
        ) as backup:
            backup_path = backup.name
            backup.write(raw)
            backup.flush()
            os.fsync(backup.fileno())
        return backup_path
    except Exception:
        if backup_path is not None:
            with suppress(OSError):
                os.unlink(backup_path)
        raise


def _atomic_write_json(file_path: str, payload: Any, *, replace_unreadable: bool = False) -> str:
    abs_path = os.path.abspath(file_path)
    parent = os.path.dirname(abs_path)
    key = os.path.normcase(abs_path)
    with _WRITE_LOCK:
        protected = key in _UNREADABLE_FILES and os.path.exists(abs_path)
        if protected and not replace_unreadable:
            raise OSError("原缓存已受保护，已阻止覆盖。可通过主动导入、清空或保存设置替换")
        envelope = _protect_bytes(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        os.makedirs(parent, exist_ok=True)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=parent,
                prefix=f"{os.path.basename(abs_path)}.", suffix=".tmp", delete=False,
            ) as f:
                tmp_path = f.name
                json.dump(envelope, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            backup_path = _backup_cache(abs_path) if protected else ""
            os.replace(tmp_path, abs_path)
            _UNREADABLE_FILES.discard(key)
            return backup_path
        finally:
            if tmp_path is not None and os.path.exists(tmp_path):
                with suppress(OSError):
                    os.unlink(tmp_path)


def load_settings() -> Dict[str, Any]:
    res = DEFAULT_SETTINGS.copy()
    res["recent_urls"] = []
    res["sub_userinfo"] = {}
    if os.path.isfile(CONFIG_FILE):
        try:
            res.update(_read_json(CONFIG_FILE, dict))
        except Exception as exc:
            warnings.warn(f"无法读取或保护设置缓存: {exc}", RuntimeWarning)
    return res


def _save_cache(file_path: str, payload: Any, action: str, replace_unreadable: bool) -> CacheSaveResult:
    try:
        return CacheSaveResult(backup_path=_atomic_write_json(
            file_path, payload, replace_unreadable=replace_unreadable,
        ))
    except Exception as exc:
        message = f"{action}失败（未回退为明文）: {exc}"
        warnings.warn(message, RuntimeWarning)
        return CacheSaveResult(error=message)


def save_settings(settings: Dict[str, Any], *, replace_unreadable: bool = False) -> CacheSaveResult:
    return _save_cache(CONFIG_FILE, settings, "设置保存", replace_unreadable)


def save_cached_nodes(nodes: List[Any], *, replace_unreadable: bool = False) -> CacheSaveResult:
    """Save parsed/mapped nodes to cached_nodes.json."""
    try:
        data = [n.to_dict() for n in nodes if hasattr(n, "to_dict")]
    except Exception as exc:
        message = f"节点缓存序列化失败: {exc}"
        warnings.warn(message, RuntimeWarning)
        return CacheSaveResult(error=message)
    return _save_cache(NODES_CACHE_FILE, data, "节点缓存保存", replace_unreadable)


def load_cached_nodes() -> List[Any]:
    """Load and reconstruct saved nodes from cached_nodes.json."""
    from .parser import node_from_dict

    if not os.path.isfile(NODES_CACHE_FILE):
        return []
    try:
        raw_list = _read_json(NODES_CACHE_FILE, list)
        nodes = []
        for item in raw_list:
            try:
                node = node_from_dict(item)
            except (ValueError, TypeError, AttributeError):
                node = None
            if node is not None:
                nodes.append(node)
        skipped = len(raw_list) - len(nodes)
        if skipped:
            with _WRITE_LOCK:
                _UNREADABLE_FILES.add(os.path.normcase(os.path.abspath(NODES_CACHE_FILE)))
            warnings.warn(f"跳过 {skipped} 个不兼容的缓存节点，已阻止自动覆盖原缓存", RuntimeWarning)
        return nodes
    except Exception as exc:
        warnings.warn(f"无法读取或保护节点缓存: {exc}", RuntimeWarning)
    return []


def nodes_cache_protected() -> bool:
    with _WRITE_LOCK:
        return (os.path.normcase(os.path.abspath(NODES_CACHE_FILE)) in _UNREADABLE_FILES
                and os.path.exists(NODES_CACHE_FILE))


def clear_cached_nodes(*, replace_unreadable: bool = False) -> CacheSaveResult:
    """Clear the cached nodes by saving an empty list."""
    return _save_cache(NODES_CACHE_FILE, [], "节点缓存清空", replace_unreadable)
