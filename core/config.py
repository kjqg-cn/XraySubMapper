import json
import os
import sys
from typing import Any, Dict, List


def get_app_dir() -> str:
    """Return executable directory when packaged as portable .exe, or project root in source mode."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


BASE_DIR = get_app_dir()
CONFIG_FILE = os.path.join(BASE_DIR, "app_settings.json")
NODES_CACHE_FILE = os.path.join(BASE_DIR, "cached_nodes.json")

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
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    tmp_path = f"{file_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, file_path)


def load_settings() -> Dict[str, Any]:
    res = DEFAULT_SETTINGS.copy()
    res["recent_urls"] = []
    res["sub_userinfo"] = {}
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                res.update(data)
        except Exception:
            pass
    return res


def save_settings(settings: Dict[str, Any]) -> None:
    try:
        _atomic_write_json(CONFIG_FILE, settings)
    except Exception:
        pass


def save_cached_nodes(nodes: List[Any]) -> None:
    """Save parsed/mapped nodes to cached_nodes.json."""
    try:
        data = [n.to_dict() for n in nodes if hasattr(n, "to_dict")]
        _atomic_write_json(NODES_CACHE_FILE, data)
    except Exception:
        pass


def load_cached_nodes() -> List[Any]:
    """Load and reconstruct saved nodes from cached_nodes.json."""
    from .parser import node_from_dict

    if not os.path.isfile(NODES_CACHE_FILE):
        return []
    try:
        with open(NODES_CACHE_FILE, "r", encoding="utf-8") as f:
            raw_list = json.load(f)
        if isinstance(raw_list, list):
            nodes = []
            for item in raw_list:
                node = node_from_dict(item)
                if node:
                    nodes.append(node)
            return nodes
    except Exception:
        pass
    return []


def clear_cached_nodes() -> None:
    """Clear the cached nodes by saving an empty list."""
    try:
        _atomic_write_json(NODES_CACHE_FILE, [])
    except Exception:
        pass
