import os
import struct
import subprocess
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)

from core.xray_manager import XrayManager  # noqa: E402


def generate_multi_size_ico(ico_path: str) -> None:
    """Generate a native multi-resolution Windows .ico file directly from vector SVG logo."""
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    from PySide6.QtGui import QGuiApplication

    from gui.icons import _render_logo_pixmap

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
    ok, version = XrayManager(xray_bin).check_version()
    if not ok:
        raise SystemExit(f"无法打包 {xray_bin}\n{version}")

    print(f"Bundling Xray {version}")
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
        "setuptools",
        "pkg_resources",
        "distutils",
        "_distutils_hack",
    ]

    # Build via a tailored .spec so unused Qt software OpenGL / extra image plugins / non-zh/en translations
    # are stripped before compression, reducing both EXE size and single-file startup extraction time.
    spec_path = os.path.join(build_work_dir, "XraySubMapper.spec")
    entry_script = os.path.join(ROOT_DIR, "main.py")
    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-

_DROP_BINARIES = {{
    "opengl32sw.dll",
    "qdirect2d.dll",
    "qtiff.dll",
    "qjpeg.dll",
    "qgif.dll",
    "qwebp.dll",
    "qwbmp.dll",
    "qtga.dll",
    "qicns.dll",
    "qpdf.dll",
    "qtvirtualkeyboardplugin.dll",
    "qt6pdf.dll",
    "qt6quick.dll",
    "qt6qml.dll",
    "qt6qmlmeta.dll",
    "qt6qmlmodels.dll",
    "qt6qmlworkerscript.dll",
    "qt6opengl.dll",
    "qt6virtualkeyboard.dll",
}}

def _keep_binary(entry):
    name = entry[0].replace("\\\\", "/").rsplit("/", 1)[-1].lower()
    return name not in _DROP_BINARIES

def _keep_data(entry):
    rel = entry[0].replace("\\\\", "/").lower()
    if "/translations/" in rel and rel.endswith(".qm"):
        base = rel.rsplit("/", 1)[-1]
        return base.startswith(("qtbase_zh", "qtbase_en"))
    return True

a = Analysis(
    [{entry_script!r}],
    pathex=[],
    binaries=[({xray_bin!r}, ".")],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes={excludes!r},
    noarchive=False,
    optimize=0,
)
a.binaries = [b for b in a.binaries if _keep_binary(b)]
a.datas = [d for d in a.datas if _keep_data(d)]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="XraySubMapper",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[{ico_path!r}],
)
"""
    os.makedirs(build_work_dir, exist_ok=True)
    with open(spec_path, "w", encoding="utf-8") as f:
        f.write(spec_content)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--distpath",
        release_dir,
        "--workpath",
        os.path.join(build_work_dir, "pyinstaller_work"),
        spec_path,
    ]

    print("[2/3] Running PyInstaller single-file portable build...")
    os.makedirs(release_dir, exist_ok=True)
    subprocess.run(cmd, check=True)

    exe_out = os.path.join(release_dir, "XraySubMapper.exe")
    size_mb = os.path.getsize(exe_out) / (1024 * 1024)
    print(f"[3/3] Build complete! Portable EXE: {exe_out} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    build()
