# Third-Party Notices

XraySubMapper itself is released under the [MIT License](LICENSE).
Binary distributions (such as the portable Windows `XraySubMapper.exe`) bundle or depend on the following third-party open-source components, each governed by its own license:

## Core Runtime & GUI Frameworks

### 1. Qt for Python / PySide6
- **License**: GNU Lesser General Public License v3.0 (LGPL-3.0-only) / GPL-3.0-only
- **Project**: <https://wiki.qt.io/Qt_for_Python>
- **LGPLv3 Compliance Notice**:
  - XraySubMapper uses unmodified Qt / PySide6 libraries.
  - Full Python source code, dependency specifications (`requirements.txt`), and the build script (`build_portable.py`) are published in this repository so users can run XraySubMapper directly against any compatible PySide6 / Qt version or rebuild the executable with modified/replaced LGPLv3 libraries.

### 2. Xray-core
- **License**: Mozilla Public License 2.0 (MPL-2.0)
- **Project**: <https://github.com/XTLS/Xray-core>
- **Notice**:
  - Official unmodified `xray.exe` binaries from `XTLS/Xray-core` are bundled for convenience in portable builds.
  - Placing an external `xray.exe` next to `XraySubMapper.exe` automatically takes precedence over the bundled binary, allowing independent upgrades or replacement.

## Python Dependencies & Packaging

| Component | License | Project URL |
| :--- | :--- | :--- |
| `requests` | Apache-2.0 | <https://github.com/psf/requests> |
| `PyYAML` | MIT | <https://github.com/yaml/pyyaml> |
| `urllib3` | MIT | <https://github.com/urllib3/urllib3> |
| `certifi` | MPL-2.0 | <https://github.com/certifi/python-certifi> |
| `charset-normalizer` | MIT | <https://github.com/jawah/charset_normalizer> |
| `idna` | BSD-3-Clause | <https://github.com/kjd/idna> |
| `PyInstaller` (build/bootloader) | GPL-2.0-or-later with Bootloader Exception | <https://github.com/pyinstaller/pyinstaller> |
