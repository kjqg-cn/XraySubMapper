import base64
import json
import sys
from pathlib import Path

import pytest

from core import config


@pytest.fixture
def cache_paths(tmp_path, monkeypatch):
    settings = tmp_path / "app_settings.json"
    nodes = tmp_path / "cached_nodes.json"
    monkeypatch.setattr(config, "CONFIG_FILE", str(settings))
    monkeypatch.setattr(config, "NODES_CACHE_FILE", str(nodes))
    return settings, nodes


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_sensitive_caches_are_encrypted_and_roundtrip(cache_paths, make_node):
    settings_path, nodes_path = cache_paths
    settings = dict(config.DEFAULT_SETTINGS, auth_pass="secret-credential", subscription_url="https://example.com/private-token")
    config.save_settings(settings)
    config.save_cached_nodes([make_node()])
    assert config.load_settings()["auth_pass"] == "secret-credential"
    assert config.load_cached_nodes()[0].password == "test-password"
    for path in cache_paths:
        raw = path.read_text(encoding="utf-8")
        assert "secret-credential" not in raw and "private-token" not in raw and "test-password" not in raw
        assert json.loads(raw)["format"] == "dpapi-v1"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_legacy_caches_are_migrated_without_losing_nodes(cache_paths, make_node):
    settings_path, nodes_path = cache_paths
    settings_path.write_text(json.dumps({"auth_pass": "old-password"}), encoding="utf-8")
    nodes_path.write_text(json.dumps([make_node().to_dict()]), encoding="utf-8")
    assert config.load_settings()["auth_pass"] == "old-password"
    assert len(config.load_cached_nodes()) == 1
    assert "old-password" not in settings_path.read_text(encoding="utf-8")
    assert "test-password" not in nodes_path.read_text(encoding="utf-8")


def test_encryption_failure_never_writes_plaintext(cache_paths, make_node, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("DPAPI unavailable")
    monkeypatch.setattr(config, "_crypt_data", fail)
    with pytest.warns(RuntimeWarning, match="未回退为明文"):
        config.save_cached_nodes([make_node()])
    assert not cache_paths[1].exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
@pytest.mark.parametrize("cache", ["settings", "nodes"])
def test_failed_decryption_preserves_original_on_autosave(cache_paths, make_node, monkeypatch, cache):
    settings_path, nodes_path = cache_paths
    settings = dict(config.DEFAULT_SETTINGS, auth_pass="original-password")
    config.save_settings(settings)
    config.save_cached_nodes([make_node()])
    path = settings_path if cache == "settings" else nodes_path
    original = path.read_bytes()
    crypt_data = config._crypt_data

    def fail_decryption(data, protect):
        if not protect:
            raise OSError("Cannot decrypt under this Windows account")
        return crypt_data(data, protect)

    monkeypatch.setattr(config, "_crypt_data", fail_decryption)
    with pytest.warns(RuntimeWarning, match="无法读取"):
        restored = config.load_settings() if cache == "settings" else config.load_cached_nodes()
    with pytest.warns(RuntimeWarning, match="保存失败"):
        if cache == "settings":
            config.save_settings(restored)
        else:
            config.save_cached_nodes([make_node("replacement")])
    assert path.read_bytes() == original
    if cache == "nodes":
        with pytest.warns(RuntimeWarning, match="清空失败"):
            config.clear_cached_nodes()
        assert path.read_bytes() == original

    # A successful read after restoring the account/file must re-enable persistence.
    monkeypatch.setattr(config, "_crypt_data", crypt_data)
    if cache == "settings":
        assert config.load_settings()["auth_pass"] == "original-password"
        config.save_settings(dict(settings, auth_pass="updated-password"))
        assert config.load_settings()["auth_pass"] == "updated-password"
    else:
        assert config.load_cached_nodes()[0].name == "node"
        config.save_cached_nodes([make_node("updated")])
        assert config.load_cached_nodes()[0].name == "updated"


def test_malformed_cache_cannot_be_overwritten_by_defaults(cache_paths):
    path = cache_paths[0]
    original = b'{"format": "dpapi-v1", "data": "unfinished'
    path.write_bytes(original)
    with pytest.warns(RuntimeWarning, match="无法读取"):
        restored = config.load_settings()
    with pytest.warns(RuntimeWarning, match="阻止覆盖"):
        config.save_settings(restored)
    assert path.read_bytes() == original


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_partially_unreadable_cache_preserves_incompatible_records(cache_paths, make_node):
    path = cache_paths[1]
    config._atomic_write_json(str(path), [make_node().to_dict(), {"protocol": "future"}])
    original = path.read_bytes()
    with pytest.warns(RuntimeWarning, match="不兼容的缓存节点"):
        assert len(config.load_cached_nodes()) == 1
    with pytest.warns(RuntimeWarning, match="阻止覆盖"):
        config.save_cached_nodes([make_node("new")])
    assert path.read_bytes() == original
    result = config.save_cached_nodes([make_node("new")], replace_unreadable=True)
    assert not result.error and Path(result.backup_path).read_bytes() == original
    assert config.save_cached_nodes([make_node("newer")]) == config.CacheSaveResult()
    assert config.load_cached_nodes()[0].name == "newer"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
@pytest.mark.parametrize("original", [
    b'[{"password": "legacy-fixture"',
    b'{"format":"dpapi-v1","data":"broken","password":"legacy-fixture"}',
])
def test_explicit_clear_preserves_unreadable_legacy_bytes_encrypted(cache_paths, original):
    path = cache_paths[1]
    path.write_bytes(original)
    with pytest.warns(RuntimeWarning, match="无法读取"):
        assert config.load_cached_nodes() == []
    assert config.nodes_cache_protected()
    result = config.clear_cached_nodes(replace_unreadable=True)
    assert not result.error
    backup = Path(result.backup_path).read_bytes()
    assert b"legacy-fixture" not in backup
    envelope = json.loads(backup)
    assert config._crypt_data(base64.b64decode(envelope["data"]), protect=False) == original
    assert not config.nodes_cache_protected()
    assert config.load_cached_nodes() == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_explicit_save_keeps_original_when_backup_fails(cache_paths, monkeypatch):
    path = cache_paths[0]
    original = b'{"auth_pass": "legacy-fixture"'
    path.write_bytes(original)
    with pytest.warns(RuntimeWarning, match="无法读取"):
        restored = config.load_settings()

    def fail_backup(file_path):
        raise OSError("backup failed")

    monkeypatch.setattr(config, "_backup_cache", fail_backup)
    with pytest.warns(RuntimeWarning, match="backup failed"):
        result = config.save_settings(restored, replace_unreadable=True)
    assert "backup failed" in result.error
    assert path.read_bytes() == original
    assert not list(path.parent.glob("*.tmp"))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_interrupted_replace_leaves_previous_cache(cache_paths, make_node, monkeypatch):
    path = cache_paths[1]
    config.save_cached_nodes([make_node("old")])
    original = path.read_bytes()
    attempted = []

    def fail_replace(source, dest):
        attempted.append(source)
        raise OSError("simulated replace failure")

    monkeypatch.setattr(config.os, "replace", fail_replace)
    for _ in range(2):
        with pytest.warns(RuntimeWarning, match="保存失败"):
            config.save_cached_nodes([make_node("new")])
    assert len(set(attempted)) == 2
    assert not list(path.parent.glob("*.tmp"))
    assert path.read_bytes() == original
