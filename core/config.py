import base64
import ctypes
import json
import os
import sys
import tempfile
import threading
import warnings
from typing import Any, Dict, List, Set


def get_app_dir() -> str:
    """Return executable directory when packaged as portable .exe, or project root in source mode."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


BASE_DIR = get_app_dir()
CONFIG_FILE = os.path.join(BASE_DIR, "app_settings.json")
NODES_CACHE_FILE = os.path.join(BASE_DIR, "cached_nodes.json")
_WRITE_LOCK = threading.Lock()
_UNREADABLE_FILES: Set[str] = set()


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


def _atomic_write_json(file_path: str, payload: Any) -> None:
    key = os.path.normcase(os.path.abspath(file_path))
    with _WRITE_LOCK:
        if key in _UNREADABLE_FILES and os.path.exists(file_path):
            raise OSError("原缓存读取失败，已阻止覆盖；请先备份原文件并恢复原账户或缓存文件")
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        encrypted = _crypt_data(raw, protect=True)
        envelope = {"format": "dpapi-v1", "data": base64.b64encode(encrypted).decode("ascii")}
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=os.path.dirname(file_path),
                prefix=f"{os.path.basename(file_path)}.", suffix=".tmp", delete=False,
            ) as f:
                tmp_path = f.name
                json.dump(envelope, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, file_path)
        finally:
            if tmp_path is not None and os.path.exists(tmp_path):
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


def save_settings(settings: Dict[str, Any]) -> None:
    try:
        _atomic_write_json(CONFIG_FILE, settings)
    except Exception as exc:
        warnings.warn(f"设置保存失败（未回退为明文）: {exc}", RuntimeWarning)


def save_cached_nodes(nodes: List[Any]) -> None:
    """Save parsed/mapped nodes to cached_nodes.json."""
    try:
        data = [n.to_dict() for n in nodes if hasattr(n, "to_dict")]
        _atomic_write_json(NODES_CACHE_FILE, data)
    except Exception as exc:
        warnings.warn(f"节点缓存保存失败（未回退为明文）: {exc}", RuntimeWarning)


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


def clear_cached_nodes() -> None:
    """Clear the cached nodes by saving an empty list."""
    try:
        _atomic_write_json(NODES_CACHE_FILE, [])
    except Exception as exc:
        warnings.warn(f"节点缓存清空失败: {exc}", RuntimeWarning)
