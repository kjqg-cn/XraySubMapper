import os
import shutil
import struct
import subprocess
import sys

from PySide6.QtCore import QBuffer, QByteArray, QIODevice
from PySide6.QtGui import QGuiApplication

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)

from gui.icons import _render_logo_pixmap  # noqa: E402


def generate_multi_size_ico(ico_path: str) -> None:
    """Generate a native multi-resolution Windows .ico file directly from vector SVG logo."""
    app = QGuiApplication.instance() or QGuiApplication([])
    sizes = [16, 24, 32, 48, 64, 128, 256]
    png_blobs = []

    for sz in sizes:
        pm = _render_logo_pixmap(sz, active=False)
        ba = QByteArray()
        buf = QBuffer(ba)
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        pm.save(buf, "PNG")
        buf.close()
        png_blobs.append((sz, bytes(ba)))

    os.makedirs(os.path.dirname(ico_path), exist_ok=True)
    header = struct.pack("<HHH", 0, 1, len(png_blobs))
    dir_entries = []
    offset = 6 + 16 * len(png_blobs)

    for sz, blob in png_blobs:
        w_byte = 0 if sz >= 256 else sz
        h_byte = 0 if sz >= 256 else sz
        entry = struct.pack("<BBBBHHII", w_byte, h_byte, 0, 0, 1, 32, len(blob), offset)
        dir_entries.append(entry)
        offset += len(blob)

    with open(ico_path, "wb") as f:
        f.write(header)
        for e in dir_entries:
            f.write(e)
        for _, blob in png_blobs:
            f.write(blob)
    _ = app


def build() -> None:
    build_work_dir = os.path.join(ROOT_DIR, "build")
    release_dir = os.path.join(ROOT_DIR, "release")
    ico_path = os.path.join(build_work_dir, "app_logo.ico")
    xray_bin = os.path.join(ROOT_DIR, "xray.exe")

    if not os.path.isfile(xray_bin):
        raise FileNotFoundError(f"Missing xray.exe at {xray_bin}")

    print("[1/3] Generating multi-resolution Windows icon (16..256px)...")
    generate_multi_size_ico(ico_path)

    excludes = [
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebEngineQuick",
        "PySide6.QtQml",
        "PySide6.QtQuick",
        "PySide6.QtQuickWidgets",
        "PySide6.QtPdf",
        "PySide6.QtPdfWidgets",
        "PySide6.Qt3DCore",
        "PySide6.Qt3DRender",
        "PySide6.QtMultimedia",
        "PySide6.QtSql",
        "PySide6.QtTest",
        "PySide6.QtDesigner",
        "PySide6.QtOpenGL",
        "PySide6.QtNetwork",
        "tkinter",
        "unittest",
        "pydoc",
    ]

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--noconsole",
        "--name",
        "XraySubMapper",
        "--icon",
        ico_path,
        "--add-binary",
        f"{xray_bin};.",
        "--distpath",
        release_dir,
        "--workpath",
        os.path.join(build_work_dir, "pyinstaller_work"),
        "--specpath",
        build_work_dir,
    ]
    for mod in excludes:
        cmd.extend(["--exclude-module", mod])
    cmd.append(os.path.join(ROOT_DIR, "main.py"))

    print("[2/3] Running PyInstaller single-file portable build...")
    os.makedirs(release_dir, exist_ok=True)
    subprocess.run(cmd, check=True)

    exe_out = os.path.join(release_dir, "XraySubMapper.exe")
    size_mb = os.path.getsize(exe_out) / (1024 * 1024)
    print(f"[3/3] Build complete! Portable EXE: {exe_out} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    build()
