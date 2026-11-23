import re
from typing import Dict, List, Optional, Set, Tuple

from PySide6.QtCore import (
    QEasingCurve,
    QModelIndex,
    QPoint,
    QPropertyAnimation,
    QRect,
    QRectF,
    QSize,
    QSortFilterProxyModel,
    Qt,
    QTimer,
    Signal,
    QAbstractTableModel,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFormLayout,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStyledItemDelegate,
    QStyle,
    QStyleOptionViewItem,
    QTableView,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core.parser import ProxyNode
from .icons import icon, svg_pixmap

COL_ENABLED = 0
COL_INDEX = 1
COL_NAME = 2
COL_PROTO = 3
COL_REMOTE = 4
COL_LOCAL = 5
COL_LATENCY = 6

ROLE_NODE = Qt.ItemDataRole.UserRole + 1
ROLE_SORT = Qt.ItemDataRole.UserRole + 2
ROLE_CONFLICT = Qt.ItemDataRole.UserRole + 3
ROLE_LISTEN_IP = Qt.ItemDataRole.UserRole + 4

PROTO_STYLES: Dict[str, Tuple[str, str, str]] = {
    "vless": ("#EEF2FF", "#4338CA", "#E0E7FF"),
    "trojan": ("#FAF5FF", "#7E22CE", "#F3E8FF"),
    "vmess": ("#FFFBEB", "#B45309", "#FEF3C7"),
    "shadowsocks": ("#ECFEFF", "#0E7490", "#CFFAFE"),
    "ss": ("#ECFEFF", "#0E7490", "#CFFAFE"),
    "socks": ("#F1F5F9", "#475569", "#E2E8F0"),
}

REGION_KEYWORDS: List[Tuple[Tuple[str, ...], str]] = [
    (("香港", "hong kong", "hk"), "HK"),
    (("台湾", "台北", "taiwan", "tw"), "TW"),
    (("日本", "东京", "大阪", "japan", "tokyo", "tyo", "jp"), "JP"),
    (("新加坡", "狮城", "singapore", "sg"), "SG"),
    (("美国", "洛杉矶", "圣何塞", "西雅图", "芝加哥", "纽约", "usa", "united states"), "US"),
    (("韩国", "首尔", "korea", "kr"), "KR"),
    (("英国", "伦敦", "uk", "london"), "GB"),
    (("德国", "法兰克福", "germany", "frankfurt"), "DE"),
    (("法国", "巴黎", "france"), "FR"),
    (("加拿大", "canada"), "CA"),
    (("澳大利亚", "悉尼", "australia"), "AU"),
    (("俄罗斯", "莫斯科", "russia"), "RU"),
    (("印度", "孟买", "india"), "IN"),
    (("荷兰", "阿姆斯特丹", "netherlands"), "NL"),
]

_REGIONAL_RE = re.compile(r"([\U0001F1E6-\U0001F1FF]{2})")
_MISC_SYMBOL_RE = re.compile(r"[\U0001F300-\U0001FAFF\u23F0-\u23FF\u2600-\u27BF]+")
_REGION_PATTERNS = [
    (re.compile("|".join(
        rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])" if key.isascii() else re.escape(key)
        for key in keys
    )), iso)
    for keys, iso in REGION_KEYWORDS
]


def extract_region_and_clean_name(raw_name: str) -> Tuple[str, str]:
    """
    Convert Windows-broken Regional Indicator flags (e.g. 🇭🇰) into clean ISO code ('HK')
    and strip broken monochrome glyphs from the display label.
    """
    region = ""
    text = raw_name or ""

    m = _REGIONAL_RE.search(text)
    if m:
        pair = m.group(1)
        c1 = chr(ord(pair[0]) - 0x1F1E6 + ord("A"))
        c2 = chr(ord(pair[1]) - 0x1F1E6 + ord("A"))
        region = f"{c1}{c2}"
        text = _REGIONAL_RE.sub("", text)

    text = _MISC_SYMBOL_RE.sub(" ", text)
    text = re.sub(r"\s{2,}", " ", text).strip(" -|·")

    if not region:
        lower = text.lower()
        for pattern, iso in _REGION_PATTERNS:
            if pattern.search(lower):
                region = iso
                break

    return region, (text or raw_name)


def format_proto_badge_text(node: ProxyNode) -> str:
    base = "SS" if node.protocol == "shadowsocks" else node.protocol.upper()
    sec = getattr(node, "security", "").lower()
    net = getattr(node, "network", "").lower()
    if sec == "reality":
        return f"{base} · REALITY"
    if net and net != "tcp":
        return f"{base} · {net.upper()}"
    return base


class NodeTableModel(QAbstractTableModel):
    portEdited = Signal(int, int)  # (row_index, new_port)

    HEADERS = ["启用", "#", "节点名称", "协议 / 传输", "远程入口 / 落地出口", "本地端口 (HTTP/SOCKS5)", "延迟 / 状态"]

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.nodes: List[ProxyNode] = []
        self.listen_ip: str = "127.0.0.1"
        self._conflict_ports: Set[int] = set()

    def set_nodes(self, nodes: List[ProxyNode]) -> None:
        self.beginResetModel()
        self.nodes = nodes
        self._recalc_conflicts()
        self.endResetModel()

    def set_listen_ip(self, ip: str) -> None:
        self.listen_ip = ip or "127.0.0.1"
        if self.nodes:
            top = self.index(0, COL_LOCAL)
            bot = self.index(len(self.nodes) - 1, COL_LOCAL)
            self.dataChanged.emit(top, bot)

    def refresh_all(self) -> None:
        self._recalc_conflicts()
        if self.nodes:
            top = self.index(0, 0)
            bot = self.index(len(self.nodes) - 1, self.columnCount() - 1)
            self.dataChanged.emit(top, bot)

    def refresh_row(self, row: int) -> None:
        if 0 <= row < len(self.nodes):
            self._recalc_conflicts()
            self.dataChanged.emit(self.index(row, 0), self.index(row, self.columnCount() - 1))

    def _recalc_conflicts(self) -> None:
        counts: Dict[int, int] = {}
        for n in self.nodes:
            if n.enabled and n.local_port > 0:
                counts[n.local_port] = counts.get(n.local_port, 0) + 1
        self._conflict_ports = {p for p, c in counts.items() if c > 1}

    def has_port_conflicts(self) -> bool:
        return bool(self._conflict_ports)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.nodes)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.TextAlignmentRole:
            if section in (COL_ENABLED, COL_INDEX, COL_PROTO, COL_LATENCY):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == COL_LOCAL:
            return base | Qt.ItemFlag.ItemIsEditable
        return base

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self.nodes)):
            return None

        row = index.row()
        col = index.column()
        node = self.nodes[row]

        if role == ROLE_NODE:
            return node
        if role == ROLE_CONFLICT:
            return node.enabled and (node.local_port in self._conflict_ports)
        if role == ROLE_LISTEN_IP:
            return "127.0.0.1" if self.listen_ip == "0.0.0.0" else self.listen_ip

        if role == ROLE_SORT:
            if col == COL_ENABLED:
                return 0 if node.enabled else 1
            if col == COL_INDEX:
                return row + 1
            if col == COL_NAME:
                return node.name.lower()
            if col == COL_PROTO:
                return format_proto_badge_text(node)
            if col == COL_REMOTE:
                return f"{node.server}:{node.port}"
            if col == COL_LOCAL:
                return node.local_port if (node.enabled and node.local_port > 0) else 999999
            if col == COL_LATENCY:
                if node.latency_ms is None:
                    return 999998
                if node.latency_ms < 0:
                    return 999999
                return node.latency_ms

        if role == Qt.ItemDataRole.EditRole and col == COL_LOCAL:
            return node.local_port if node.local_port > 0 else 10800

        if role == Qt.ItemDataRole.ToolTipRole:
            if col == COL_NAME:
                return node.name
            if col == COL_LOCAL:
                host_disp = "127.0.0.1" if self.listen_ip == "0.0.0.0" else self.listen_ip
                if node.enabled and node.local_port in self._conflict_ports:
                    return f"端口 {node.local_port} 存在重复冲突！双击修改端口"
                pin_tip = "\n• 已手动锁定端口，顺延重排时自动保留" if node.port_pinned else ""
                if node.enabled and node.local_port > 0:
                    return (
                        f"同端口自适应支持 HTTP 与 SOCKS5：\n"
                        f"• HTTP:   http://{host_disp}:{node.local_port}\n"
                        f"• SOCKS5: socks5://{host_disp}:{node.local_port}"
                        f"{pin_tip}\n(双击单元格可直接修改端口)"
                    )
                return "启用后自动分配本地混合代理端口 (HTTP + SOCKS5)"
            if col == COL_LATENCY and node.latency_ms == -1 and node.last_error:
                return f"测速失败原因: {node.last_error}"
            if col == COL_PROTO:
                return f"协议与传输层: {format_proto_badge_text(node)}"
            if col == COL_REMOTE:
                if node.exit_ip:
                    return f"远程入口: {node.server}:{node.port}\n实测落地出口: {node.exit_ip}"
                return f"远程入口: {node.server}:{node.port}"

        if role == Qt.ItemDataRole.DisplayRole:
            if col == COL_INDEX:
                return str(row + 1)
            if col == COL_NAME:
                return node.name
            if col == COL_PROTO:
                return format_proto_badge_text(node)
            if col == COL_REMOTE:
                return f"{node.server}:{node.port}"
            if col == COL_LOCAL:
                host_disp = "127.0.0.1" if self.listen_ip == "0.0.0.0" else self.listen_ip
                return f"http://{host_disp}:{node.local_port}" if (node.enabled and node.local_port > 0) else "--"
            if col == COL_LATENCY:
                if node.latency_ms is None:
                    return "--"
                return f"{node.latency_ms} ms" if node.latency_ms >= 0 else (node.last_error or "失败")

        return None

    def setData(self, index: QModelIndex, value, role: int = Qt.ItemDataRole.EditRole) -> bool:
        if not index.isValid() or index.column() != COL_LOCAL or role != Qt.ItemDataRole.EditRole:
            return False
        try:
            new_port = int(value)
        except (ValueError, TypeError):
            return False
        if not (1024 <= new_port <= 65535):
            return False
        self.portEdited.emit(index.row(), new_port)
        return True


class NodeFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.search_query: str = ""
        self.proto_filter: str = "all"
        self.setSortRole(ROLE_SORT)
        self.setDynamicSortFilter(True)

    def _apply_filter_change(self, attr: str, value: str) -> None:
        if hasattr(self, "beginFilterChange") and hasattr(self, "endFilterChange"):
            self.beginFilterChange()
            setattr(self, attr, value)
            direction = getattr(QSortFilterProxyModel, "Direction", None)
            if direction is not None:
                self.endFilterChange(direction.Rows)
            else:
                self.endFilterChange()
        else:
            setattr(self, attr, value)
            self.invalidateFilter()

    def set_search_query(self, text: str) -> None:
        self._apply_filter_change("search_query", text.strip().lower())

    def set_proto_filter(self, proto: str) -> None:
        self._apply_filter_change("proto_filter", proto.lower())

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: NodeTableModel = self.sourceModel()  # type: ignore[assignment]
        if not model or not (0 <= source_row < len(model.nodes)):
            return False
        node = model.nodes[source_row]

        if self.proto_filter != "all":
            p = "ss" if node.protocol == "shadowsocks" else node.protocol
            if p != self.proto_filter:
                return False

        if self.search_query:
            region, clean_name = extract_region_and_clean_name(node.name)
            haystack = f"{node.name} {clean_name} {region} {node.server} {node.local_port} {node.exit_ip}".lower()
            if self.search_query not in haystack:
                return False

        return True


def _crisp_font(family: str, pt_size: float, bold: bool = False) -> QFont:
    f = QFont(family)
    f.setPointSizeF(pt_size)
    f.setWeight(QFont.Weight.Bold if bold else QFont.Weight.Normal)
    f.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    f.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    return f


class NodeTableDelegate(QStyledItemDelegate):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.font_ui = _crisp_font("Microsoft YaHei UI", 9.0, bold=False)
        self.font_ui_bold = _crisp_font("Microsoft YaHei UI", 9.0, bold=True)
        mono_fam = "Cascadia Mono" if QFontMetrics(QFont("Cascadia Mono", 9)).inFont("0") else "Consolas"
        self.font_mono = _crisp_font(mono_fam, 9.0, bold=False)
        self.font_mono_bold = _crisp_font(mono_fam, 9.0, bold=True)
        self.font_badge = _crisp_font(mono_fam, 8.0, bold=True)

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        node: Optional[ProxyNode] = index.data(ROLE_NODE)
        if node is None:
            s = super().sizeHint(option, index)
            return QSize(s.width(), 40)

        col = index.column()
        if col == COL_ENABLED:
            return QSize(50, 40)
        if col == COL_INDEX:
            return QSize(52, 40)
        if col == COL_NAME:
            region, clean_name = extract_region_and_clean_name(node.name)
            w = 24 + QFontMetrics(self.font_ui_bold).horizontalAdvance(clean_name)
            if region:
                w += max(24, QFontMetrics(self.font_badge).horizontalAdvance(region) + 10) + 8
            return QSize(min(720, max(160, w)), 40)
        if col == COL_PROTO:
            label = format_proto_badge_text(node)
            w = QFontMetrics(self.font_badge).horizontalAdvance(label) + 32
            return QSize(max(110, w), 40)
        if col == COL_REMOTE:
            entry = f"{node.server}:{node.port}"
            w = QFontMetrics(self.font_mono).horizontalAdvance(entry) + 24
            if node.exit_ip:
                w_exit = QFontMetrics(self.font_badge).horizontalAdvance(f"出口 {node.exit_ip}") + 24
                w = max(w, w_exit)
            return QSize(min(480, max(160, w)), 40)
        if col == COL_LOCAL:
            host_disp = str(index.data(ROLE_LISTEN_IP) or "127.0.0.1")
            w = QFontMetrics(self.font_mono_bold).horizontalAdvance(f"{host_disp}:{node.local_port}") + 44
            return QSize(max(165, w), 40)
        if col == COL_LATENCY:
            return QSize(118, 40)
        return QSize(120, 40)

    def createEditor(self, parent: QWidget, option: QStyleOptionViewItem, index: QModelIndex) -> QWidget:
        from PySide6.QtGui import QIntValidator
        ed = QLineEdit(parent)
        ed.setValidator(QIntValidator(1024, 65535, ed))
        ed.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ed.setFont(self.font_mono_bold)
        ed.setStyleSheet(
            "QLineEdit { background: #EFF6FF; color: #1E40AF; border: 1.5px solid #2563EB; "
            "border-radius: 5px; padding: 0 6px; selection-background-color: #2563EB; selection-color: #FFFFFF; }"
        )
        return ed

    def setEditorData(self, editor: QWidget, index: QModelIndex) -> None:
        if isinstance(editor, QLineEdit):
            val = index.model().data(index, Qt.ItemDataRole.EditRole)
            editor.setText(str(int(val) if val else 10800))
            editor.selectAll()

    def setModelData(self, editor: QWidget, model, index: QModelIndex) -> None:
        if isinstance(editor, QLineEdit):
            txt = editor.text().strip()
            if txt.isdigit():
                model.setData(index, int(txt), Qt.ItemDataRole.EditRole)

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        node: Optional[ProxyNode] = index.data(ROLE_NODE)
        if node is None:
            super().paint(painter, option, index)
            return

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = option.rect
        is_selected = bool(option.state & QStyle.StateFlag.State_Selected)
        is_hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)

        # Row background
        if is_selected:
            painter.fillRect(rect, QColor("#EFF6FF"))
        elif is_hovered:
            painter.fillRect(rect, QColor("#F8FAFC"))
        else:
            painter.fillRect(rect, QColor("#FFFFFF"))

        # Subtle bottom hairline divider
        painter.setPen(QPen(QColor("#F1F5F9"), 1))
        painter.drawLine(rect.bottomLeft(), rect.bottomRight())

        enabled = node.enabled
        col = index.column()

        if col == COL_ENABLED:
            self._paint_checkbox(painter, rect, enabled, is_hovered)
        elif col == COL_INDEX:
            painter.setFont(self.font_mono)
            painter.setPen(QColor("#64748B" if enabled else "#CBD5E1"))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(index.data(Qt.ItemDataRole.DisplayRole)))
        elif col == COL_NAME:
            self._paint_name(painter, rect, node, enabled)
        elif col == COL_PROTO:
            self._paint_protocol(painter, rect, node, enabled)
        elif col == COL_REMOTE:
            self._paint_remote(painter, rect, node, enabled)
        elif col == COL_LOCAL:
            is_conflict = bool(index.data(ROLE_CONFLICT))
            host_disp = str(index.data(ROLE_LISTEN_IP) or "127.0.0.1")
            self._paint_local_proxy(painter, rect, node, host_disp, enabled, is_conflict)
        elif col == COL_LATENCY:
            self._paint_latency(painter, rect, node, enabled)

        painter.restore()

    def _paint_checkbox(self, painter: QPainter, rect: QRect, checked: bool, hovered: bool) -> None:
        box_sz = 17
        x = rect.x() + (rect.width() - box_sz) / 2.0
        y = rect.y() + (rect.height() - box_sz) / 2.0
        box_rect = QRectF(x, y, box_sz, box_sz)

        if checked:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#1D4ED8" if hovered else "#2563EB"))
            painter.drawRoundedRect(box_rect, 4.5, 4.5)

            pen = QPen(QColor("#FFFFFF"), 1.9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            path = QPainterPath()
            path.moveTo(x + 4.2, y + 8.8)
            path.lineTo(x + 7.3, y + 12.0)
            path.lineTo(x + 13.0, y + 5.6)
            painter.drawPath(path)
        else:
            painter.setPen(QPen(QColor("#94A3B8" if hovered else "#CBD5E1"), 1.4))
            painter.setBrush(QColor("#FFFFFF"))
            painter.drawRoundedRect(box_rect, 4.5, 4.5)

    def _paint_name(self, painter: QPainter, rect: QRect, node: ProxyNode, enabled: bool) -> None:
        region, clean_name = extract_region_and_clean_name(node.name)
        cur_x = rect.x() + 10

        if region:
            painter.setFont(self.font_badge)
            fm_b = QFontMetrics(self.font_badge)
            bw = max(24, fm_b.horizontalAdvance(region) + 10)
            bh = 19
            by = rect.y() + (rect.height() - bh) / 2.0
            badge_rect = QRectF(cur_x, by, bw, bh)

            bg = QColor("#F1F5F9") if enabled else QColor("#F8FAFC")
            fg = QColor("#334155") if enabled else QColor("#CBD5E1")
            bd = QColor("#E2E8F0") if enabled else QColor("#F1F5F9")

            painter.setPen(QPen(bd, 1))
            painter.setBrush(bg)
            painter.drawRoundedRect(badge_rect, 4, 4)
            painter.setPen(fg)
            painter.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter, region)
            cur_x += bw + 8

        painter.setFont(self.font_ui_bold if enabled else self.font_ui)
        painter.setPen(QColor("#0F172A") if enabled else QColor("#94A3B8"))
        avail_w = max(20, rect.right() - cur_x - 8)
        fm = QFontMetrics(painter.font())
        elided = fm.elidedText(clean_name, Qt.TextElideMode.ElideRight, avail_w)
        text_rect = QRect(int(cur_x), rect.y(), int(avail_w), rect.height())
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elided)

    def _paint_protocol(self, painter: QPainter, rect: QRect, node: ProxyNode, enabled: bool) -> None:
        label = format_proto_badge_text(node)
        bg_hex, fg_hex, bd_hex = PROTO_STYLES.get(node.protocol, ("#F1F5F9", "#475569", "#E2E8F0"))
        if not enabled:
            bg_hex, fg_hex, bd_hex = "#F8FAFC", "#94A3B8", "#E2E8F0"

        painter.setFont(self.font_badge)
        fm = QFontMetrics(self.font_badge)
        pw = min(rect.width() - 12, fm.horizontalAdvance(label) + 16)
        ph = 21
        px = rect.x() + (rect.width() - pw) / 2.0
        py = rect.y() + (rect.height() - ph) / 2.0
        pill = QRectF(px, py, pw, ph)

        painter.setPen(QPen(QColor(bd_hex), 1))
        painter.setBrush(QColor(bg_hex))
        painter.drawRoundedRect(pill, 5, 5)
        painter.setPen(QColor(fg_hex))
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, label)

    def _paint_remote(self, painter: QPainter, rect: QRect, node: ProxyNode, enabled: bool) -> None:
        entry = f"{node.server}:{node.port}"
        inner = rect.adjusted(10, 0, -8, 0)
        painter.setFont(self.font_mono)
        fm = QFontMetrics(self.font_mono)

        if node.exit_ip and enabled:
            top_r = QRect(inner.x(), inner.y() + 4, inner.width(), inner.height() // 2 - 2)
            bot_r = QRect(inner.x(), inner.y() + inner.height() // 2, inner.width(), inner.height() // 2 - 4)
            painter.setPen(QColor("#334155"))
            painter.drawText(
                top_r,
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                fm.elidedText(entry, Qt.TextElideMode.ElideMiddle, inner.width()),
            )
            painter.setFont(self.font_badge)
            painter.setPen(QColor("#059669"))
            painter.drawText(
                bot_r,
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                f"出口 {node.exit_ip}",
            )
        else:
            painter.setPen(QColor("#475569") if enabled else QColor("#CBD5E1"))
            painter.drawText(
                inner,
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                fm.elidedText(entry, Qt.TextElideMode.ElideMiddle, inner.width()),
            )

    def _paint_local_proxy(
        self,
        painter: QPainter,
        rect: QRect,
        node: ProxyNode,
        host_disp: str,
        enabled: bool,
        is_conflict: bool,
    ) -> None:
        if not enabled or node.local_port <= 0:
            painter.setFont(self.font_mono)
            painter.setPen(QColor("#CBD5E1"))
            painter.drawText(rect.adjusted(10, 0, -10, 0), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "--")
            return

        chip_rect = QRectF(rect.x() + 8, rect.y() + 7, rect.width() - 16, rect.height() - 14)
        if is_conflict:
            painter.setPen(QPen(QColor("#EF4444"), 1.2))
            painter.setBrush(QColor("#FEF2F2"))
            painter.drawRoundedRect(chip_rect, 5, 5)
        elif node.port_pinned:
            painter.setPen(QPen(QColor("#BFDBFE"), 1))
            painter.setBrush(QColor("#F8FAFC"))
            painter.drawRoundedRect(chip_rect, 5, 5)

        prefix = f"{host_disp}:"
        port_str = str(node.local_port)

        painter.setFont(self.font_mono)
        fm_reg = QFontMetrics(self.font_mono)
        fm_bold = QFontMetrics(self.font_mono_bold)

        w_prefix = fm_reg.horizontalAdvance(prefix)
        w_port = fm_bold.horizontalAdvance(port_str)
        start_x = rect.x() + 14

        painter.setPen(QColor("#DC2626") if is_conflict else QColor("#64748B"))
        painter.drawText(
            QRect(start_x, rect.y(), w_prefix + 2, rect.height()),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            prefix,
        )

        painter.setFont(self.font_mono_bold)
        painter.setPen(QColor("#B91C1C") if is_conflict else QColor("#0F172A"))
        painter.drawText(
            QRect(start_x + w_prefix, rect.y(), w_port + 4, rect.height()),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            port_str,
        )

        if node.port_pinned:
            pin_px = svg_pixmap("pin", color="#2563EB", size=12)
            py = int(rect.y() + (rect.height() - 12) / 2)
            px = min(rect.right() - 20, start_x + w_prefix + w_port + 6)
            painter.drawPixmap(px, py, pin_px)

    def _paint_latency(self, painter: QPainter, rect: QRect, node: ProxyNode, enabled: bool) -> None:
        if not enabled or node.latency_ms is None:
            painter.setFont(self.font_mono)
            painter.setPen(QColor("#CBD5E1"))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "--")
            return

        lat = node.latency_ms
        if lat < 0:
            label = node.last_error or "超时"
            if len(label) > 6:
                label = label[:6]
            bg_hex, fg_hex, dot_hex = "#FEF2F2", "#DC2626", "#EF4444"
        elif lat < 180:
            label = f"{lat} ms"
            bg_hex, fg_hex, dot_hex = "#ECFDF5", "#047857", "#10B981"
        elif lat <= 450:
            label = f"{lat} ms"
            bg_hex, fg_hex, dot_hex = "#FFFBEB", "#B45309", "#F59E0B"
        else:
            label = f"{lat} ms"
            bg_hex, fg_hex, dot_hex = "#FFF1F2", "#BE123C", "#F43F5E"

        painter.setFont(self.font_badge)
        fm = QFontMetrics(self.font_badge)
        pw = min(rect.width() - 12, fm.horizontalAdvance(label) + 24)
        ph = 22
        px = rect.x() + (rect.width() - pw) / 2.0
        py = rect.y() + (rect.height() - ph) / 2.0
        pill = QRectF(px, py, pw, ph)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(bg_hex))
        painter.drawRoundedRect(pill, 11, 11)

        # Status dot
        dot_r = 5.5
        painter.setBrush(QColor(dot_hex))
        painter.drawEllipse(QRectF(px + 7.5, py + (ph - dot_r) / 2.0, dot_r, dot_r))

        painter.setPen(QColor(fg_hex))
        text_r = QRectF(px + 15, py, pw - 19, ph)
        painter.drawText(text_r, Qt.AlignmentFlag.AlignCenter, label)


class MenuSelectButton(QToolButton):
    """
    Modern unified selector button matching split-action buttons ('顺延重排', '复制代理'):
    Features leading SVG icon, right separator + chevron, and rounded checkmark popup menu.
    """

    valueChanged = Signal(str)

    def __init__(
        self,
        options: List[Tuple[str, str, str, str]],
        initial_value: str = "",
        compact: bool = False,
        parent: Optional[QWidget] = None,
    ):
        """
        options: list of (label, value, icon_name, icon_color)
        """
        super().__init__(parent)
        self._options = options
        self._current_value = initial_value or (options[0][1] if options else "")
        self._compact = compact

        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        if compact:
            self.setFixedHeight(28)
            self.setStyleSheet(
                "QToolButton { font-size: 12px; padding: 2px 26px 2px 9px; border-radius: 6px; } "
                "QToolButton::menu-button { width: 18px; border-top-right-radius: 6px; border-bottom-right-radius: 6px; }"
            )

        self._menu = QMenu(self)
        self.setMenu(self._menu)
        self.clicked.connect(self.showMenu)
        self._rebuild_menu_and_label()

    def currentData(self) -> str:
        return self._current_value

    def setValue(self, value: str, emit_signal: bool = False) -> None:
        if value == self._current_value:
            return
        self._current_value = value
        self._rebuild_menu_and_label()
        if emit_signal:
            self.valueChanged.emit(value)

    def _rebuild_menu_and_label(self) -> None:
        self._menu.clear()
        blank_px = svg_pixmap("check", color="transparent", size=14)
        from PySide6.QtGui import QIcon
        blank_icon = QIcon(blank_px)
        check_icon = icon("check", "#2563EB", 14)

        active_opt = self._options[0] if self._options else ("", "", "sliders", "#475569")
        for opt in self._options:
            if opt[1] == self._current_value:
                active_opt = opt

        lbl, val, ic_name, ic_color = active_opt
        ic_sz = 13 if self._compact else 15
        self.setText(f" {lbl}")
        self.setIcon(icon(ic_name, ic_color, ic_sz))
        self.setIconSize(QSize(ic_sz, ic_sz))

        for opt_lbl, opt_val, _, _ in self._options:
            is_sel = opt_val == self._current_value
            act = self._menu.addAction(check_icon if is_sel else blank_icon, opt_lbl)
            if is_sel:
                f = act.font()
                f.setWeight(QFont.Weight.Bold)
                act.setFont(f)
            act.triggered.connect(lambda checked=False, v=opt_val: self._on_item_triggered(v))

    def _on_item_triggered(self, val: str) -> None:
        if val != self._current_value:
            self._current_value = val
            self._rebuild_menu_and_label()
            self.valueChanged.emit(val)


class EmptyStateTableView(QTableView):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.empty_title = "暂无代理节点"
        self.empty_subtitle = "在顶部输入订阅链接下载，或按 Ctrl+V 直接粘贴节点链接 / 将配置文件拖入窗口"

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        model = self.model()
        if model is not None and model.rowCount() == 0:
            painter = QPainter(self.viewport())
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            vr = self.viewport().rect()
            cx = vr.center().x()
            cy = vr.center().y()

            # Soft icon circle
            circle_r = 26
            painter.setPen(QPen(QColor("#E2E8F0"), 1))
            painter.setBrush(QColor("#F8FAFC"))
            painter.drawEllipse(QPoint(cx, cy - 28), circle_r, circle_r)

            ic = svg_pixmap("route", color="#64748B", size=24)
            painter.drawPixmap(cx - 12, cy - 40, ic)

            f_title = _crisp_font("Microsoft YaHei UI", 10.0, bold=True)
            painter.setFont(f_title)
            painter.setPen(QColor("#334155"))
            painter.drawText(
                QRect(0, cy + 8, vr.width(), 24),
                Qt.AlignmentFlag.AlignCenter,
                self.empty_title,
            )

            f_sub = _crisp_font("Microsoft YaHei UI", 9.0, bold=False)
            painter.setFont(f_sub)
            painter.setPen(QColor("#94A3B8"))
            painter.drawText(
                QRect(20, cy + 32, vr.width() - 40, 24),
                Qt.AlignmentFlag.AlignCenter,
                self.empty_subtitle,
            )
            painter.end()


class ToastNotification(QWidget):
    """Lightweight non-blocking floating toast replacing disruptive modal messageboxes."""

    LEVEL_COLORS = {
        "success": "#10B981",
        "info": "#3B82F6",
        "warning": "#F59E0B",
        "error": "#EF4444",
    }

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.hide()

        self._dot_color = "#10B981"
        self._label = QLabel(self)
        self._label.setFont(_crisp_font("Microsoft YaHei UI", 9.0, bold=False))
        self._label.setStyleSheet("color: #F8FAFC; background: transparent;")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(28, 9, 16, 9)
        layout.addWidget(self._label)

        self._opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity)
        self._anim = QPropertyAnimation(self._opacity, b"opacity", self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._fade_out)
        self._fade_connected = False

    def show_toast(self, text: str, level: str = "success", duration_ms: int = 2400) -> None:
        self._dot_color = self.LEVEL_COLORS.get(level, "#10B981")
        self._label.setText(text)
        self.adjustSize()
        self.reposition()

        self._anim.stop()
        if self._fade_connected:
            try:
                self._anim.finished.disconnect(self.hide)
            except Exception:
                pass
            self._fade_connected = False

        self._opacity.setOpacity(0.0)
        self.show()
        self.raise_()
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.start()
        self._timer.start(duration_ms)

    def _fade_out(self) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._opacity.opacity())
        self._anim.setEndValue(0.0)
        if not self._fade_connected:
            self._anim.finished.connect(self.hide)
            self._fade_connected = True
        self._anim.start()

    def reposition(self) -> None:
        p = self.parentWidget()
        if p:
            x = max(16, (p.width() - self.width()) // 2)
            y = p.height() - self.height() - 28
            self.move(x, y)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        painter.setPen(QPen(QColor("#334155"), 1))
        painter.setBrush(QColor(15, 23, 42, 238))
        painter.drawRoundedRect(r, 18, 18)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self._dot_color))
        painter.drawEllipse(QRectF(13, (self.height() - 7) / 2.0, 7, 7))
        painter.end()


class PasteImportDialog(QDialog):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("粘贴订阅或节点内容")
        self.resize(580, 390)
        self.result_text: str = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        hint = QLabel("支持直接粘贴 Base64 订阅密文、Clash YAML 配置或多行节点分享链接 (vless/vmess/trojan/ss/socks)：")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #475569; font-size: 12px;")
        layout.addWidget(hint)

        self.editor = QPlainTextEdit()
        self.editor.setPlaceholderText("vless://...\ntrojan://...\n或粘贴完整 Clash proxies 配置...")
        self.editor.setFont(QFont("Consolas", 9))
        layout.addWidget(self.editor, 1)

        cb_text = QApplication.clipboard().text().strip()
        if any(s in cb_text.lower() for s in ("vmess://", "vless://", "trojan://", "ss://", "socks", "proxies:")):
            self.editor.setPlainText(cb_text)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("取消")
        btn_cancel.setProperty("role", "secondary")
        btn_cancel.clicked.connect(self.reject)

        btn_ok = QPushButton("解析并导入")
        btn_ok.setProperty("role", "primary")
        btn_ok.clicked.connect(self._on_accept)

        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

    def _on_accept(self) -> None:
        raw = self.editor.toPlainText().strip()
        if raw:
            self.result_text = raw
            self.accept()


class ProxySettingsDialog(QDialog):
    def __init__(
        self,
        auth_enabled: bool,
        auth_user: str,
        auth_pass: str,
        test_url: str,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("代理安全与测速参数设置")
        self.resize(440, 260)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        self.chk_auth = QCheckBox("启用本地混合代理账号密码鉴权")
        self.chk_auth.setChecked(auth_enabled)
        layout.addWidget(self.chk_auth)

        form = QFormLayout()
        form.setSpacing(10)
        self.inp_user = QLineEdit(auth_user)
        self.inp_user.setPlaceholderText("例如: proxyuser")
        self.inp_pass = QLineEdit(auth_pass)
        self.inp_pass.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.inp_pass.setPlaceholderText("输入访问密码")
        self.inp_test_url = QLineEdit(test_url or "https://cp.cloudflare.com/generate_204")

        form.addRow("鉴权用户名:", self.inp_user)
        form.addRow("鉴权密码:", self.inp_pass)
        form.addRow("HTTPS 测速地址:", self.inp_test_url)
        layout.addLayout(form)

        def _sync_state(checked: bool) -> None:
            self.inp_user.setEnabled(checked)
            self.inp_pass.setEnabled(checked)

        self.chk_auth.toggled.connect(_sync_state)
        _sync_state(auth_enabled)

        layout.addStretch()
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("取消")
        btn_cancel.setProperty("role", "secondary")
        btn_cancel.clicked.connect(self.reject)
        btn_save = QPushButton("保存设置")
        btn_save.setProperty("role", "primary")
        btn_save.clicked.connect(self.accept)
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_save)
        layout.addLayout(btn_row)

    def get_values(self) -> Tuple[bool, str, str, str]:
        u = self.inp_user.text().strip()
        p = self.inp_pass.text().strip()
        enabled = self.chk_auth.isChecked()
        t_url = self.inp_test_url.text().strip() or "https://cp.cloudflare.com/generate_204"
        return enabled, u, p, t_url

    def accept(self) -> None:
        enabled, user, password, _ = self.get_values()
        if enabled and (not user or not password):
            QMessageBox.warning(self, "鉴权配置不完整", "启用鉴权时，请同时填写用户名和密码。")
            (self.inp_user if not user else self.inp_pass).setFocus()
            return
        super().accept()
