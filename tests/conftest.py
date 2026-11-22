import os
from pathlib import Path
import shutil
import socket
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.parser import parse_node_link
from core.xray_manager import XrayManager


@pytest.fixture
def make_node():
    def make(name="node", port=0):
        node = parse_node_link(f"trojan://test-password@example.com:443#{name}")
        node.local_port = port
        return node
    return make


@pytest.fixture
def free_port():
    def allocate():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
    return allocate


@pytest.fixture
def manager():
    manager = XrayManager()
    manager.set_log_callback(lambda message: None)
    yield manager
    manager.stop()


@pytest.fixture
def kernel_manager(manager):
    path = os.environ.get("XRAY_TEST_EXECUTABLE") or shutil.which(manager.xray_path)
    if not path:
        pytest.skip("Xray kernel not installed; set XRAY_TEST_EXECUTABLE to run integration tests")
    manager.xray_path = path
    return manager
