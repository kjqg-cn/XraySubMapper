from typing import Dict, Tuple

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

# Crisp 24x24 Lucide-style linear SVG paths (1.75px stroke, round caps/joins)
SVG_PATHS: Dict[str, str] = {
    "play": '<polygon points="6 3 20 12 6 21 6 3" fill="{color}" stroke="{color}" stroke-width="1.5" stroke-linejoin="round"/>',
    "stop": '<rect x="5" y="5" width="14" height="14" rx="2" fill="{color}" stroke="{color}" stroke-width="1.5"/>',
    "refresh": (
        '<path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>'
        '<path d="M3 3v5h5"/>'
        '<path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/>'
        '<path d="M16 16h5v5"/>'
    ),
    "download": (
        '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
        '<polyline points="7 10 12 15 17 10"/>'
        '<line x1="12" y1="15" x2="12" y2="3"/>'
    ),
    "clipboard": (
        '<rect width="8" height="4" x="8" y="2" rx="1" ry="1"/>'
        '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>'
    ),
    "folder": (
        '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>'
    ),
    "zap": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "globe": (
        '<circle cx="12" cy="12" r="10"/>'
        '<path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/>'
        '<path d="M2 12h20"/>'
    ),
    "copy": (
        '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>'
        '<path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>'
    ),
    "search": (
        '<circle cx="11" cy="11" r="8"/>'
        '<path d="m21 21-4.3-4.3"/>'
    ),
    "terminal": (
        '<polyline points="4 17 10 11 4 5"/>'
        '<line x1="12" x2="20" y1="19" y2="19"/>'
    ),
    "shield": (
        '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'
    ),
    "lock": (
        '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>'
        '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>'
    ),
    "trash": (
        '<path d="M3 6h18"/>'
        '<path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>'
        '<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>'
    ),
    "sliders": (
        '<line x1="4" x2="4" y1="21" y2="14"/><line x1="4" x2="4" y1="10" y2="3"/>'
        '<line x1="12" x2="12" y1="21" y2="12"/><line x1="12" x2="12" y1="8" y2="3"/>'
        '<line x1="20" x2="20" y1="21" y2="16"/><line x1="20" x2="20" y1="12" y2="3"/>'
        '<line x1="2" x2="6" y1="14" y2="14"/><line x1="10" x2="14" y1="8" y2="8"/>'
        '<line x1="18" x2="22" y1="16" y2="16"/>'
    ),
    "chevron_down": '<path d="m6 9 6 6 6-6"/>',
    "check": '<polyline points="20 6 9 17 4 12"/>',
    "pin": (
        '<line x1="12" x2="12" y1="17" y2="22"/>'
        '<path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/>'
    ),
    "route": (
        '<circle cx="6" cy="19" r="3"/>'
        '<path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/>'
        '<circle cx="18" cy="5" r="3"/>'
    ),
}

_ICON_CACHE: Dict[Tuple[str, str, int], QIcon] = {}


def svg_pixmap(name: str, color: str = "#334155", size: int = 16) -> QPixmap:
    app = QGuiApplication.instance()
    dpr = float(app.primaryScreen().devicePixelRatio()) if (app and app.primaryScreen()) else 1.0
    dpr = max(1.0, dpr)

    body = SVG_PATHS.get(name, SVG_PATHS["route"]).format(color=color)
    svg_xml = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 24 24" fill="none" stroke="{color}" '
        f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
        f"{body}</svg>"
    )

    px_size = max(1, int(round(size * dpr)))
    pixmap = QPixmap(px_size, px_size)
    pixmap.fill(Qt.GlobalColor.transparent)

    renderer = QSvgRenderer(QByteArray(svg_xml.encode("utf-8")))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    renderer.render(painter, QRectF(0, 0, px_size, px_size))
    painter.end()

    pixmap.setDevicePixelRatio(dpr)
    return pixmap


def icon(name: str, color: str = "#334155", size: int = 16) -> QIcon:
    key = (name, color, size)
    cached = _ICON_CACHE.get(key)
    if cached is not None:
        return cached
    ic = QIcon(svg_pixmap(name, color=color, size=size))
    _ICON_CACHE[key] = ic
    return ic


def _render_logo_pixmap(px: int, active: bool = False) -> QPixmap:
    pixmap = QPixmap(px, px)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    pad = max(1.0, px * 0.04)
    radius = px * 0.24
    bg_color = QColor("#059669") if active else QColor("#0F172A")
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(bg_color)
    painter.drawRoundedRect(QRectF(pad, pad, px - 2 * pad, px - 2 * pad), radius, radius)

    icon_sz = max(10, int(round(px * 0.56)))
    body = SVG_PATHS["route"].format(color="#FFFFFF")
    svg_xml = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{icon_sz}" height="{icon_sz}" '
        f'viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" '
        f'stroke-width="2.0" stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    )
    renderer = QSvgRenderer(QByteArray(svg_xml.encode("utf-8")))
    offset = (px - icon_sz) / 2.0
    renderer.render(painter, QRectF(offset, offset, icon_sz, icon_sz))
    painter.end()
    return pixmap


def build_app_logo_icon(active: bool = False) -> QIcon:
    """Build multi-resolution QIcon (16..256px) so Windows Taskbar, Alt-Tab, and Tray all render crisply."""
    ic = QIcon()
    for sz in (16, 20, 24, 32, 40, 48, 64, 128, 256):
        ic.addPixmap(_render_logo_pixmap(sz, active=active))
    return ic
