import copy
import os
import sys
import threading
import warnings
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from PySide6.QtCore import QEvent, QObject, QPoint, QRect, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QCloseEvent,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QIntValidator,
    QKeySequence,
    QShortcut,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSystemTrayIcon,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core.config import (
    CacheSaveResult,
    clear_cached_nodes,
    load_cached_nodes,
    load_settings,
    nodes_cache_protected,
    save_cached_nodes,
    save_settings,
)
from core.parser import ProxyNode
from core.subscription import fetch_subscription_with_meta, parse_subscription_content
from core.xray_manager import XrayManager, format_proxy_host
from .icons import build_app_logo_icon, clear_icon_caches, icon
from .single_instance import GUI_MUTEX_NAME, GuiInstanceLock, activate_existing_window, activation_message_id
from .widgets import (
    COL_ENABLED,
    COL_INDEX,
    COL_LATENCY,
    COL_LOCAL,
    COL_NAME,
    COL_PROTO,
    COL_REMOTE,
    EmptyStateTableView,
    MenuSelectButton,
    NodeFilterProxyModel,
    NodeTableDelegate,
    NodeTableModel,
    PasteImportDialog,
    ProxySettingsDialog,
    ToastNotification,
)

GUI_WINDOW_TITLE = "XraySubMapper · 多节点多端口混合代理工作台 (HTTP + SOCKS5)"

GLOBAL_QSS = """
QMainWindow {
    background-color: #F8FAFC;
}
QWidget {
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    color: #0F172A;
}
QFrame#Card {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
}
QFrame#SubtleBar {
    background-color: #F8FAFC;
    border-bottom: 1px solid #E2E8F0;
    border-top-left-radius: 9px;
    border-top-right-radius: 9px;
}
QFrame#Divider {
    background-color: #F1F5F9;
    max-height: 1px;
    min-height: 1px;
}
QFrame#VDivider {
    background-color: #E2E8F0;
    max-width: 1px;
    min-width: 1px;
}

/* Inputs & Selects */
QLineEdit, QComboBox, QPlainTextEdit {
    background-color: #FFFFFF;
    border: 1px solid #CBD5E1;
    border-radius: 7px;
    padding: 5px 10px;
    font-size: 13px;
    color: #0F172A;
    selection-background-color: #DBEAFE;
    selection-color: #1E3A8A;
}
QComboBox {
    padding-right: 24px;
}
QSpinBox {
    background-color: #FFFFFF;
    border: 1px solid #CBD5E1;
    border-radius: 7px;
    padding: 4px 6px;
    font-size: 13px;
    color: #0F172A;
    selection-background-color: #DBEAFE;
    selection-color: #1E3A8A;
}
QSpinBox::up-button, QSpinBox::down-button {
    width: 0px;
    height: 0px;
    border: none;
}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover {
    border-color: #94A3B8;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {
    border: 1.5px solid #2563EB;
    background-color: #FFFFFF;
}
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 22px;
    border: none;
}
QComboBox QAbstractItemView {
    background-color: #FFFFFF;
    border: 1px solid #CBD5E1;
    border-radius: 6px;
    padding: 4px;
    selection-background-color: #EFF6FF;
    selection-color: #1D4ED8;
    outline: none;
}

/* Buttons: Use native 400 (normal) or 700 (bold) only to avoid blurry synthetic 500/600 weights on YaHei */
QPushButton, QToolButton {
    background-color: #FFFFFF;
    border: 1px solid #CBD5E1;
    border-radius: 7px;
    padding: 6px 13px;
    font-size: 13px;
    font-weight: normal;
    color: #0F172A;
}
QPushButton:hover, QToolButton:hover {
    background-color: #F8FAFC;
    border-color: #94A3B8;
}
QPushButton:pressed, QToolButton:pressed {
    background-color: #F1F5F9;
}
QPushButton:disabled, QToolButton:disabled {
    background-color: #F8FAFC;
    color: #94A3B8;
    border-color: #E2E8F0;
}

/* Primary Action Button (Sole solid focal point) */
QPushButton[role="primary"] {
    background-color: #0F172A;
    border: 1px solid #0F172A;
    color: #FFFFFF;
    font-weight: bold;
    padding: 7px 18px;
}
QPushButton[role="primary"]:hover {
    background-color: #1E293B;
    border-color: #1E293B;
}
QPushButton[role="primary"]:disabled {
    background-color: #94A3B8;
    border-color: #94A3B8;
    color: #F8FAFC;
}

/* Brand Accent Button (Fetch) */
QPushButton[role="accent"] {
    background-color: #2563EB;
    border: 1px solid #2563EB;
    color: #FFFFFF;
    font-weight: bold;
}
QPushButton[role="accent"]:hover {
    background-color: #1D4ED8;
    border-color: #1D4ED8;
}
QPushButton[role="accent"]:disabled {
    background-color: #93C5FD;
    border-color: #93C5FD;
}

/* Stop Service Button (Controlled rose outline/tint) */
QPushButton[role="danger"] {
    background-color: #FEF2F2;
    border: 1px solid #FECACA;
    color: #DC2626;
    font-weight: bold;
    padding: 7px 18px;
}
QPushButton[role="danger"]:hover {
    background-color: #FEE2E2;
    border-color: #FCA5A5;
}

/* Reload Dirty State Pill Button */
QPushButton[role="warning_pill"] {
    background-color: #FFFBEB;
    border: 1px solid #FDE68A;
    border-radius: 14px;
    color: #B45309;
    font-size: 12px;
    font-weight: bold;
    padding: 4px 12px;
}
QPushButton[role="warning_pill"]:hover {
    background-color: #FEF3C7;
    border-color: #FCD34D;
}

/* Subtle Ghost Micro Buttons */
QPushButton[role="ghost"] {
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 5px;
    padding: 3px 8px;
    font-size: 12px;
    color: #475569;
}
QPushButton[role="ghost"]:hover {
    background-color: #E2E8F0;
    color: #0F172A;
}

/* ToolButton with Menu */
QToolButton[popupMode="1"] {
    padding-right: 28px;
}
QToolButton::menu-button {
    border: none;
    border-left: 1px solid #E2E8F0;
    width: 20px;
    border-top-right-radius: 7px;
    border-bottom-right-radius: 7px;
}

/* Table & Header */
QTableView {
    background-color: #FFFFFF;
    border: none;
    gridline-color: transparent;
    selection-background-color: #EFF6FF;
    selection-color: #0F172A;
    outline: none;
}
QHeaderView {
    background-color: #FFFFFF;
    border: none;
}
QHeaderView::section {
    background-color: #FFFFFF;
    color: #475569;
    font-size: 12px;
    font-weight: bold;
    padding: 8px 10px;
    border: none;
    border-right: 1px solid #F1F5F9;
    border-bottom: 1px solid #E2E8F0;
}
QHeaderView::section:last {
    border-right: none;
}
QHeaderView::section:hover {
    background-color: #F8FAFC;
    color: #0F172A;
}

/* Sleek Thin Scrollbars */
QScrollBar:vertical {
    background: transparent;
    width: 8px;
    margin: 2px 1px 2px 1px;
}
QScrollBar::handle:vertical {
    background: #CBD5E1;
    min-height: 28px;
    border-radius: 3px;
}
QScrollBar::handle:vertical:hover {
    background: #94A3B8;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    height: 0px;
    background: none;
}
QScrollBar:horizontal {
    background: transparent;
    height: 8px;
    margin: 1px 2px 1px 2px;
}
QScrollBar::handle:horizontal {
    background: #CBD5E1;
    min-width: 28px;
    border-radius: 3px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    width: 0px;
    background: none;
}

/* Context Menu */
QMenu {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    padding: 5px;
}
QMenu::item {
    padding: 6px 24px 6px 12px;
    border-radius: 5px;
    font-size: 13px;
    color: #1E293B;
}
QMenu::item:selected {
    background-color: #EFF6FF;
    color: #1D4ED8;
}
QMenu::separator {
    height: 1px;
    background: #F1F5F9;
    margin: 4px 6px;
}
"""


class UiBridge(QObject):
    logReceived = Signal(str)
    fetchFinished = Signal(object, str, object, str)
    serviceTransitioned = Signal(bool, str, str)
    speedProgress = Signal(int, int, object)
    speedFinished = Signal(object, str)
    exitIpProgress = Signal(int, int, object)
    exitIpFinished = Signal(object, str)


@dataclass(frozen=True)
class ProbeTask:
    generation: int
    signature: Tuple
    nodes: Tuple[ProxyNode, ...]
    single: bool
    cancelled: threading.Event = field(default_factory=threading.Event)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(GUI_WINDOW_TITLE)
        self.setWindowIcon(build_app_logo_icon(active=False))
        self.setAcceptDrops(True)

        with warnings.catch_warnings(record=True) as cache_warnings:
            warnings.simplefilter("always", RuntimeWarning)
            self.settings: Dict[str, Any] = load_settings()
            self.nodes: List[ProxyNode] = load_cached_nodes()
        self.xray_mgr = XrayManager()
        self._fetch_request: Optional[object] = None
        self._speed_task: Optional[ProbeTask] = None
        self._exit_ip_task: Optional[ProbeTask] = None
        self._closing = False
        self._shutdown_complete = False
        self._force_quit = False
        self._close_prompt: Optional[QMessageBox] = None
        self._applied_signature: Optional[Tuple] = None
        self._pending_signature: Optional[Tuple] = None
        self._service_busy = False
        self._manual_name_width: Optional[int] = None
        self._resizing_columns_internally = False

        self.bridge = UiBridge(self)
        self.bridge.logReceived.connect(self._append_log)
        self.bridge.fetchFinished.connect(self._on_fetch_finished)
        self.bridge.serviceTransitioned.connect(self._on_service_transitioned)
        self.bridge.speedProgress.connect(self._on_speed_progress)
        self.bridge.speedFinished.connect(self._on_speed_finished)
        self.bridge.exitIpProgress.connect(self._on_exit_ip_progress)
        self.bridge.exitIpFinished.connect(self._on_exit_ip_finished)

        self.xray_mgr.set_log_callback(lambda msg: self._emit_worker_signal(self.bridge.logReceived, msg))

        self._build_ui()
        self._restore_window_bounds()
        self._setup_shortcuts()
        self._setup_tray()

        # Toast overlay
        self.toast = ToastNotification(self)

        # Populate initial cached state
        if self.nodes:
            # Ensure enabled nodes without valid port get assigned cleanly
            if any(n.enabled and n.local_port <= 0 for n in self.nodes):
                self._assign_ports(reset_pinned=False)
            self.table_model.set_nodes(self.nodes)
            self._update_summary_counters()

        self._refresh_sub_userinfo_badge()
        self._refresh_auth_button_style()

        # Watchdog timer to detect unexpected Xray exit
        self._watchdog = QTimer(self)
        self._watchdog.setInterval(1500)
        self._watchdog.timeout.connect(self._check_xray_alive)
        self._watchdog.start()
        if cache_warnings:
            details = "\n".join(str(warning.message) for warning in cache_warnings)
            QTimer.singleShot(0, lambda: QMessageBox.warning(
                self, "缓存读取提示",
                details + "\n\n读取失败的原文件会保留。主动导入、清空或保存设置时会先备份。",
            ))

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        # 1. HEADER CARD
        header_card = QFrame()
        header_card.setObjectName("Card")
        header_layout = QHBoxLayout(header_card)
        header_layout.setContentsMargins(16, 10, 16, 10)
        header_layout.setSpacing(12)

        self.lbl_logo = QLabel()
        self.lbl_logo.setPixmap(build_app_logo_icon(False).pixmap(QSize(32, 32)))
        header_layout.addWidget(self.lbl_logo)

        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        lbl_title = QLabel("XraySubMapper")
        lbl_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #0F172A;")
        lbl_sub = QLabel("多节点 1:1 独立本地代理池 (HTTP + SOCKS5)")
        lbl_sub.setStyleSheet("font-size: 11px; color: #64748B;")
        title_col.addWidget(lbl_title)
        title_col.addWidget(lbl_sub)
        header_layout.addLayout(title_col)

        header_layout.addSpacing(8)

        # Running Status Pill
        self.lbl_service_badge = QLabel("● 服务未启动")
        self._set_service_badge_style("stopped", "● 服务未启动")
        header_layout.addWidget(self.lbl_service_badge)

        # Dirty Config Reload Action Pill (Hidden until needed)
        self.btn_reload_dirty = QPushButton(" 应用变更")
        self.btn_reload_dirty.setIcon(icon("refresh", "#B45309", 13))
        self.btn_reload_dirty.setProperty("role", "warning_pill")
        self.btn_reload_dirty.setToolTip("验证新配置后重启 Xray；现有连接会断开，切换失败时尝试恢复原配置")
        self.btn_reload_dirty.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_reload_dirty.clicked.connect(self._reload_service)
        self.btn_reload_dirty.hide()
        header_layout.addWidget(self.btn_reload_dirty)

        header_layout.addStretch()

        # Right Header Controls: Settings, Console Drawer, Main Start/Stop
        self.btn_settings = QPushButton(" 鉴权与测速")
        self.btn_settings.setIcon(icon("lock", "#475569", 15))
        self.btn_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_settings.setToolTip("配置本地混合代理访问账号密码及 HTTPS 测速地址")
        self.btn_settings.clicked.connect(self._open_settings_dialog)
        header_layout.addWidget(self.btn_settings)

        self.btn_console = QPushButton(" 运行日志")
        self.btn_console.setIcon(icon("terminal", "#475569", 15))
        self.btn_console.setCheckable(True)
        self.btn_console.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_console.toggled.connect(self._toggle_console_drawer)
        header_layout.addWidget(self.btn_console)

        self.btn_service = QPushButton(" 启动映射服务")
        self.btn_service.setIcon(icon("play", "#FFFFFF", 14))
        self.btn_service.setProperty("role", "primary")
        self.btn_service.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_service.setMinimumWidth(142)
        self.btn_service.clicked.connect(self._toggle_service)
        header_layout.addWidget(self.btn_service)

        root.addWidget(header_card)

        # 2. WORKSPACE TOOLBAR CARD (2 Clean Rows)
        toolbar_card = QFrame()
        toolbar_card.setObjectName("Card")
        tb_vbox = QVBoxLayout(toolbar_card)
        tb_vbox.setContentsMargins(14, 10, 14, 10)
        tb_vbox.setSpacing(9)

        # Row A: Subscription & Import
        row_sub = QHBoxLayout()
        row_sub.setSpacing(8)

        lbl_url = QLabel("订阅源")
        lbl_url.setStyleSheet("font-size: 12px; font-weight: bold; color: #334155;")
        row_sub.addWidget(lbl_url)

        self.inp_url = QLineEdit(self.settings.get("subscription_url", ""))
        self.inp_url.setPlaceholderText("粘贴订阅 URL (自动识别 V2Ray Base64 / Clash YAML / 多协议分享链接)...")
        self.inp_url.setClearButtonEnabled(True)
        self.inp_url.returnPressed.connect(self._fetch_subscription_async)
        self._act_url_history = self.inp_url.addAction(
            icon("chevron_down", "#64748B", 15),
            QLineEdit.ActionPosition.TrailingPosition,
        )
        self._act_url_history.setToolTip("选择最近使用的历史订阅链接")
        self._act_url_history.triggered.connect(self._show_recent_urls_menu)
        row_sub.addWidget(self.inp_url, 1)

        self.btn_fetch = QPushButton(" 下载更新")
        self.btn_fetch.setIcon(icon("download", "#FFFFFF", 15))
        self.btn_fetch.setProperty("role", "accent")
        self.btn_fetch.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_fetch.clicked.connect(self._fetch_subscription_async)
        row_sub.addWidget(self.btn_fetch)

        btn_paste = QPushButton(" 粘贴导入")
        btn_paste.setIcon(icon("clipboard", "#334155", 15))
        btn_paste.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_paste.clicked.connect(self._open_paste_dialog)
        row_sub.addWidget(btn_paste)

        btn_file = QPushButton(" 导入文件")
        btn_file.setIcon(icon("folder", "#334155", 15))
        btn_file.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_file.clicked.connect(self._import_from_file)
        row_sub.addWidget(btn_file)

        tb_vbox.addLayout(row_sub)

        div = QFrame()
        div.setObjectName("Divider")
        tb_vbox.addWidget(div)

        # Row B: Port Orchestration (Left) + Speedtest & Export (Right)
        row_ctrl = QHBoxLayout()
        row_ctrl.setSpacing(8)

        lbl_listen = QLabel("监听地址")
        lbl_listen.setStyleSheet("font-size: 12px; font-weight: bold; color: #334155;")
        row_ctrl.addWidget(lbl_listen)

        cur_ip = "0.0.0.0" if self.settings.get("listen_ip") == "0.0.0.0" else "127.0.0.1"
        self.settings["listen_ip"] = cur_ip
        self.combo_listen = MenuSelectButton(
            options=[
                ("127.0.0.1 (仅本机)", "127.0.0.1", "shield", "#475569"),
                ("0.0.0.0 (局域网共享)", "0.0.0.0", "globe", "#059669"),
            ],
            initial_value=cur_ip,
            compact=False,
            parent=self,
        )
        self.combo_listen.setMinimumWidth(188)
        self.combo_listen.valueChanged.connect(self._on_listen_ip_changed)
        row_ctrl.addWidget(self.combo_listen)

        row_ctrl.addSpacing(6)

        lbl_port = QLabel("起始端口")
        lbl_port.setStyleSheet("font-size: 12px; font-weight: bold; color: #334155;")
        row_ctrl.addWidget(lbl_port)

        self.inp_start_port = QLineEdit(str(int(self.settings.get("start_port", 10800))))
        self.inp_start_port.setValidator(QIntValidator(1024, 65000, self))
        self.inp_start_port.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.inp_start_port.setFont(QFont("Cascadia Mono", 9, QFont.Weight.Bold))
        self.inp_start_port.setFixedWidth(78)
        self.inp_start_port.editingFinished.connect(self._on_start_port_edited)
        row_ctrl.addWidget(self.inp_start_port)

        btn_rearrange = QToolButton()
        btn_rearrange.setText(" 顺延重排")
        btn_rearrange.setIcon(icon("refresh", "#334155", 14))
        btn_rearrange.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        btn_rearrange.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        btn_rearrange.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_rearrange.clicked.connect(lambda: self._rearrange_ports_clicked(reset_pinned=False))

        rearrange_menu = QMenu(btn_rearrange)
        act_keep_pin = rearrange_menu.addAction("顺延重排 (保留手动锁定的端口)")
        act_keep_pin.triggered.connect(lambda: self._rearrange_ports_clicked(reset_pinned=False))
        act_reset_pin = rearrange_menu.addAction("强制重排全部 (解除所有端口锁定)")
        act_reset_pin.triggered.connect(lambda: self._rearrange_ports_clicked(reset_pinned=True))
        btn_rearrange.setMenu(rearrange_menu)
        row_ctrl.addWidget(btn_rearrange)

        row_ctrl.addStretch()

        # Speedtest, Exit IP Probe & Copy Split Button
        self.btn_speed = QPushButton(" 并发测速")
        self.btn_speed.setIcon(icon("zap", "#334155", 15))
        self.btn_speed.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_speed.clicked.connect(self._test_all_speed_async)
        row_ctrl.addWidget(self.btn_speed)

        self.btn_probe_ip = QPushButton(" 查出口 IP")
        self.btn_probe_ip.setIcon(icon("globe", "#334155", 15))
        self.btn_probe_ip.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_probe_ip.setToolTip("并发探测所有已启用本地端口的真实落地出口 IP 与国家代码")
        self.btn_probe_ip.clicked.connect(self._probe_all_exit_ips_async)
        row_ctrl.addWidget(self.btn_probe_ip)

        self.btn_export = QToolButton()
        self.btn_export.setText(" 复制代理 (0)")
        self.btn_export.setIcon(icon("copy", "#334155", 15))
        self.btn_export.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.btn_export.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export.clicked.connect(lambda: self._copy_proxies_bulk("url", only_passed=False))

        export_menu = QMenu(self.btn_export)
        export_menu.addAction("复制 HTTP 代理列表 (http://ip:port)", lambda: self._copy_proxies_bulk("url", False))
        export_menu.addAction("复制 SOCKS5 代理列表 (socks5://ip:port)", lambda: self._copy_proxies_bulk("socks5", False))
        export_menu.addAction("复制 IP:Port 列表", lambda: self._copy_proxies_bulk("hostport", False))
        export_menu.addAction("复制带节点备注格式 (http://... # 名称)", lambda: self._copy_proxies_bulk("comment", False))
        export_menu.addSeparator()
        export_menu.addAction("仅复制测速可用的 HTTP 列表", lambda: self._copy_proxies_bulk("url", True))
        export_menu.addAction("仅复制测速可用的 SOCKS5 列表", lambda: self._copy_proxies_bulk("socks5", True))
        export_menu.addAction("导出代理清单到 .txt 文件...", self._export_proxies_to_file)
        self.btn_export.setMenu(export_menu)
        row_ctrl.addWidget(self.btn_export)

        tb_vbox.addLayout(row_ctrl)
        root.addWidget(toolbar_card)

        # 3. MAIN DATA TABLE CARD
        table_card = QFrame()
        table_card.setObjectName("Card")
        table_vbox = QVBoxLayout(table_card)
        table_vbox.setContentsMargins(1, 1, 1, 1)
        table_vbox.setSpacing(0)

        # Filter, Batch Action & Stats Bar directly attached to Table Header
        micro_bar = QFrame()
        micro_bar.setObjectName("SubtleBar")
        micro_layout = QHBoxLayout(micro_bar)
        micro_layout.setContentsMargins(10, 6, 14, 6)
        micro_layout.setSpacing(6)

        self.inp_search = QLineEdit()
        self.inp_search.setPlaceholderText("搜索名称 / 地区 / 端口...")
        self.inp_search.setClearButtonEnabled(True)
        self.inp_search.addAction(icon("search", "#94A3B8", 14), QLineEdit.ActionPosition.LeadingPosition)
        self.inp_search.setMinimumWidth(165)
        self.inp_search.setMaximumWidth(205)
        self.inp_search.setFixedHeight(28)
        self.inp_search.setStyleSheet("QLineEdit { font-size: 12px; padding: 2px 8px; border-radius: 6px; }")
        self.inp_search.textChanged.connect(self._on_search_changed)
        micro_layout.addWidget(self.inp_search)

        self.combo_proto = MenuSelectButton(
            options=[
                ("全部协议", "all", "sliders", "#475569"),
                ("VLESS", "vless", "sliders", "#2563EB"),
                ("Trojan", "trojan", "sliders", "#7E22CE"),
                ("VMess", "vmess", "sliders", "#B45309"),
                ("Shadowsocks", "ss", "sliders", "#0E7490"),
                ("Socks5", "socks", "sliders", "#475569"),
            ],
            initial_value="all",
            compact=True,
            parent=self,
        )
        self.combo_proto.setMinimumWidth(116)
        self.combo_proto.valueChanged.connect(self._on_proto_filter_changed)
        micro_layout.addWidget(self.combo_proto)

        vdiv = QFrame()
        vdiv.setObjectName("VDivider")
        micro_layout.addWidget(vdiv)

        for label, cb in [
            ("全选", lambda: self._batch_set_enabled(True)),
            ("全不选", lambda: self._batch_set_enabled(False)),
            ("反选", self._invert_selection),
            ("仅保留可用", self._keep_only_passed_nodes),
            ("按延迟排序", lambda: self.table_view.sortByColumn(COL_LATENCY, Qt.SortOrder.AscendingOrder)),
        ]:
            b = QPushButton(label)
            b.setProperty("role", "ghost")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(cb)
            micro_layout.addWidget(b)

        btn_clear_all = QPushButton("清空")
        btn_clear_all.setProperty("role", "ghost")
        btn_clear_all.setStyleSheet("QPushButton[role='ghost']:hover { background: #FEE2E2; color: #DC2626; }")
        btn_clear_all.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_clear_all.clicked.connect(self._clear_all_nodes)
        micro_layout.addWidget(btn_clear_all)

        micro_layout.addStretch()

        self.lbl_userinfo = QLabel("")
        self.lbl_userinfo.setStyleSheet(
            "background-color: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; "
            "border-radius: 10px; padding: 2px 9px; font-size: 11px; font-weight: normal;"
        )
        self.lbl_userinfo.hide()
        micro_layout.addWidget(self.lbl_userinfo)

        self.lbl_stats = QLabel("共 0 节点 · 启用 0")
        self.lbl_stats.setStyleSheet("font-size: 12px; font-weight: bold; color: #334155;")
        micro_layout.addWidget(self.lbl_stats)

        table_vbox.addWidget(micro_bar)

        # Table View + Model + Proxy + Delegate
        self.table_model = NodeTableModel(self)
        self.table_model.set_listen_ip(cur_ip)
        self.table_model.portEdited.connect(self._on_inline_port_edited)

        self.proxy_model = NodeFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.table_model)

        self.table_view = EmptyStateTableView(self)
        self.table_view.setModel(self.proxy_model)
        self.table_view.setItemDelegate(NodeTableDelegate(self.table_view))
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table_view.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked)
        self.table_view.setSortingEnabled(True)
        self.table_view.setShowGrid(False)
        self.table_view.setMouseTracking(True)
        self.table_view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.table_view.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.verticalHeader().setDefaultSectionSize(40)
        self.table_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        hdr = self.table_view.horizontalHeader()
        hdr.setHighlightSections(False)
        hdr.setSortIndicatorShown(True)
        hdr.setSortIndicator(COL_INDEX, Qt.SortOrder.AscendingOrder)
        hdr.setMinimumSectionSize(44)
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(COL_ENABLED, QHeaderView.ResizeMode.Fixed)
        for col_idx in (COL_INDEX, COL_NAME, COL_PROTO, COL_REMOTE, COL_LOCAL, COL_LATENCY):
            hdr.setSectionResizeMode(col_idx, QHeaderView.ResizeMode.Interactive)

        default_widths = [50, 50, 310, 134, 224, 194, 118]
        saved_widths = self.settings.get("column_widths")
        name_col_manual = bool(self.settings.get("name_col_manual", False))
        self._resizing_columns_internally = True
        try:
            if isinstance(saved_widths, list) and len(saved_widths) == len(default_widths):
                for c_i, w_val in enumerate(saved_widths):
                    if c_i == COL_NAME and not name_col_manual:
                        self.table_view.setColumnWidth(c_i, default_widths[c_i])
                    else:
                        self.table_view.setColumnWidth(c_i, max(44, int(w_val)))
                if name_col_manual:
                    self._manual_name_width = max(140, int(saved_widths[COL_NAME]))
            else:
                for c_i, w_val in enumerate(default_widths):
                    self.table_view.setColumnWidth(c_i, w_val)
            self.table_view.setColumnWidth(COL_ENABLED, 50)
        finally:
            self._resizing_columns_internally = False

        hdr.sectionResized.connect(self._on_header_section_resized)

        self.table_view.clicked.connect(self._on_table_clicked)
        self.table_view.doubleClicked.connect(self._on_table_double_clicked)
        self.table_view.customContextMenuRequested.connect(self._show_table_context_menu)

        table_vbox.addWidget(self.table_view, 1)
        root.addWidget(table_card, 1)

        # 4. COLLAPSIBLE CONSOLE DRAWER (Hidden by default)
        self.console_card = QFrame()
        self.console_card.setStyleSheet(
            "QFrame { background-color: #0F172A; border: 1px solid #1E293B; border-radius: 10px; }"
        )
        self.console_card.setFixedHeight(165)
        con_vbox = QVBoxLayout(self.console_card)
        con_vbox.setContentsMargins(12, 8, 12, 8)
        con_vbox.setSpacing(6)

        con_hdr = QHBoxLayout()
        lbl_con = QLabel("Xray 内核实时运行日志")
        lbl_con.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: bold; border: none;")
        con_hdr.addWidget(lbl_con)
        con_hdr.addStretch()

        con_btn_qss = (
            "QPushButton { background: #1E293B; color: #CBD5E1; border: 1px solid #334155; "
            "border-radius: 4px; padding: 1px 9px; font-size: 11px; font-weight: normal; } "
            "QPushButton:hover { background: #334155; color: #FFFFFF; }"
        )

        btn_copy_log = QPushButton("复制")
        btn_copy_log.setFixedHeight(22)
        btn_copy_log.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_copy_log.setStyleSheet(con_btn_qss)
        btn_copy_log.clicked.connect(lambda: (
            QApplication.clipboard().setText(self.txt_console.toPlainText()),
            self._notify("日志内容已复制", "info"),
        ))
        con_hdr.addWidget(btn_copy_log)

        btn_clear_log = QPushButton("清空")
        btn_clear_log.setFixedHeight(22)
        btn_clear_log.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_clear_log.setStyleSheet(con_btn_qss)
        btn_clear_log.clicked.connect(self._clear_console)
        con_hdr.addWidget(btn_clear_log)

        btn_close_log = QPushButton("关闭")
        btn_close_log.setFixedHeight(22)
        btn_close_log.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_close_log.setStyleSheet(
            "QPushButton { background: #1E293B; color: #CBD5E1; border: 1px solid #334155; "
            "border-radius: 4px; padding: 1px 9px; font-size: 11px; font-weight: normal; } "
            "QPushButton:hover { background: #7F1D1D; border-color: #991B1B; color: #FECACA; }"
        )
        btn_close_log.clicked.connect(lambda: self.btn_console.setChecked(False))
        con_hdr.addWidget(btn_close_log)
        con_vbox.addLayout(con_hdr)

        self.txt_console = QPlainTextEdit()
        self.txt_console.setReadOnly(True)
        self.txt_console.setMaximumBlockCount(500)
        self.txt_console.setFont(QFont("Cascadia Mono", 9))
        self.txt_console.setStyleSheet(
            "QPlainTextEdit { background: #0F172A; color: #E2E8F0; border: none; padding: 2px; }"
        )
        self.txt_console.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.txt_console.customContextMenuRequested.connect(self._show_console_context_menu)
        con_vbox.addWidget(self.txt_console, 1)

        self.console_card.hide()
        root.addWidget(self.console_card)

    def _restore_window_bounds(self) -> None:
        self.setMinimumSize(880, 560)
        screen = QApplication.primaryScreen()
        avail = screen.availableGeometry() if screen else QRect(0, 0, 1920, 1080)

        default_w = min(1120, int(avail.width() * 0.85))
        default_h = min(720, int(avail.height() * 0.85))

        rect_cfg = self.settings.get("window_rect")
        if isinstance(rect_cfg, list) and len(rect_cfg) == 4:
            try:
                x, y, w, h = [int(v) for v in rect_cfg]
                w = max(880, min(w, avail.width()))
                h = max(560, min(h, avail.height()))
                x = max(avail.left(), min(x, avail.right() - w))
                y = max(avail.top(), min(y, avail.bottom() - h))
                self.setGeometry(x, y, w, h)
                return
            except Exception:
                pass

        cx = avail.left() + (avail.width() - default_w) // 2
        cy = avail.top() + (avail.height() - default_h) // 2
        self.setGeometry(cx, cy, default_w, default_h)

    def _setup_shortcuts(self) -> None:
        sc_space = QShortcut(QKeySequence(Qt.Key.Key_Space), self.table_view)
        sc_space.setContext(Qt.ShortcutContext.WidgetShortcut)
        sc_space.activated.connect(self._toggle_selected_rows)

        sc_del = QShortcut(QKeySequence(Qt.Key.Key_Delete), self.table_view)
        sc_del.setContext(Qt.ShortcutContext.WidgetShortcut)
        sc_del.activated.connect(self._delete_selected_rows)

        sc_paste = QShortcut(QKeySequence.StandardKey.Paste, self)
        sc_paste.activated.connect(self._smart_paste_shortcut)

        sc_find = QShortcut(QKeySequence.StandardKey.Find, self)
        sc_find.activated.connect(lambda: (self.inp_search.setFocus(), self.inp_search.selectAll()))

    def _setup_tray(self) -> None:
        self.tray: Optional[QSystemTrayIcon] = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        tray = QSystemTrayIcon(build_app_logo_icon(False), self)
        tray.setToolTip("XraySubMapper · 服务未启动")

        menu = QMenu(self)
        act_show = menu.addAction("显示主工作台")
        act_show.triggered.connect(self._bring_to_front)
        self.act_tray_toggle = menu.addAction("启动映射服务")
        self.act_tray_toggle.triggered.connect(self._toggle_service)
        act_copy = menu.addAction("复制已启用代理 (URL)")
        act_copy.triggered.connect(lambda: self._copy_proxies_bulk("url", False))
        menu.addSeparator()
        act_quit = menu.addAction("彻底退出")
        act_quit.triggered.connect(self._quit_completely)

        tray.setContextMenu(menu)
        tray.activated.connect(self._on_tray_activated)
        tray.show()
        self.tray = tray

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self._bring_to_front()

    def _bring_to_front(self) -> None:
        if self._closing:
            return
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized)
        self.show()
        self.activateWindow()
        self.raise_()

    def nativeEvent(self, eventType, message):
        if sys.platform == "win32" and eventType == b"windows_generic_MSG":
            from ctypes.wintypes import MSG

            activation = activation_message_id()
            if activation and MSG.from_address(int(message)).message == activation:
                QTimer.singleShot(0, self._bring_to_front)
                return True, 0
        return super().nativeEvent(eventType, message)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        QTimer.singleShot(0, self._sync_table_columns_to_viewport)

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            # Ensure viewport width is settled after maximize <-> restore transition
            QTimer.singleShot(0, self._sync_table_columns_to_viewport)
            QTimer.singleShot(60, self._sync_table_columns_to_viewport)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._sync_table_columns_to_viewport()
        if hasattr(self, "toast") and self.toast.isVisible():
            self.toast.reposition()

    def _on_header_section_resized(self, logical_idx: int, old_size: int, new_size: int) -> None:
        if self._resizing_columns_internally:
            return
        if logical_idx == COL_NAME:
            vp_w = self.table_view.viewport().width()
            col_count = self.table_model.columnCount()
            other_w = sum(self.table_view.columnWidth(c) for c in range(col_count) if c != COL_NAME)
            avail = max(180, vp_w - other_w - 2)
            # Only lock manual width when user explicitly drags wider than current viewport fit,
            # otherwise unlock back to responsive mode so maximize/restore stays fluid.
            if new_size > avail + 12:
                self._manual_name_width = new_size
            else:
                self._manual_name_width = None

    def _sync_table_columns_to_viewport(self) -> None:
        """Bidirectionally adapt Name column width on maximize & restore so right-side columns never get pushed off-screen."""
        vp_w = self.table_view.viewport().width()
        if vp_w <= 100:
            return
        col_count = self.table_model.columnCount()
        other_w = sum(self.table_view.columnWidth(c) for c in range(col_count) if c != COL_NAME)
        avail_for_name = vp_w - other_w - 2
        min_base = self._manual_name_width if self._manual_name_width is not None else 180
        target_name_w = max(min_base, avail_for_name)
        if self.table_view.columnWidth(COL_NAME) != target_name_w:
            self._resizing_columns_internally = True
            try:
                self.table_view.setColumnWidth(COL_NAME, target_name_w)
            finally:
                self._resizing_columns_internally = False

    # ------------------------------------------------------------------
    # Visual Helpers & State Sync
    # ------------------------------------------------------------------
    def _notify(self, text: str, level: str = "success", duration_ms: int = 2400) -> None:
        self.toast.show_toast(text, level=level, duration_ms=duration_ms)

    def _set_service_badge_style(self, state: str, text: str) -> None:
        self.lbl_service_badge.setText(text)
        styles = {
            "stopped": "background: #F1F5F9; color: #64748B; border: 1px solid #E2E8F0;",
            "starting": "background: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE;",
            "running": "background: #ECFDF5; color: #047857; border: 1px solid #A7F3D0;",
            "error": "background: #FEF2F2; color: #DC2626; border: 1px solid #FECACA;",
        }
        s = styles.get(state, styles["stopped"])
        self.lbl_service_badge.setStyleSheet(
            f"{s} border-radius: 12px; padding: 3px 11px; font-size: 12px; font-weight: bold;"
        )

    def _refresh_sub_userinfo_badge(self) -> None:
        info = self.settings.get("sub_userinfo") or {}
        summary = info.get("summary", "") if isinstance(info, dict) else ""
        if summary:
            self.lbl_userinfo.setText(summary)
            self.lbl_userinfo.show()
        else:
            self.lbl_userinfo.hide()

    def _refresh_auth_button_style(self) -> None:
        user, _ = self._get_auth_pair()
        if user:
            self.btn_settings.setText(f" 已设鉴权 ({user})")
            self.btn_settings.setIcon(icon("shield", "#059669", 15))
        else:
            self.btn_settings.setText(" 鉴权与测速")
            self.btn_settings.setIcon(icon("lock", "#475569", 15))

    def _calc_config_signature(self) -> Tuple:
        listen_ip = str(self.combo_listen.currentData() or "127.0.0.1")
        enabled_items = tuple(sorted((n.local_port, n.connection_key()) for n in self.nodes if n.enabled))
        return (listen_ip, self._get_auth_pair(), enabled_items)

    def _has_unapplied_changes(self) -> bool:
        return self.xray_mgr.is_running() and self._calc_config_signature() != self._applied_signature

    def _sync_dirty_banner(self) -> None:
        if self.xray_mgr.is_running() and self._applied_signature is not None:
            is_dirty = self._has_unapplied_changes()
            if is_dirty:
                self._cancel_probes()
            self.btn_reload_dirty.setVisible(is_dirty)
        else:
            self.btn_reload_dirty.hide()

    def _update_summary_counters(self) -> None:
        total = len(self.nodes)
        enabled = sum(1 for n in self.nodes if n.enabled)
        passed = sum(1 for n in self.nodes if n.enabled and n.latency_ms is not None and n.latency_ms >= 0)
        failed = sum(1 for n in self.nodes if n.enabled and n.latency_ms == -1)

        parts = [f"共 {total} 节点", f"启用 {enabled}"]
        if passed or failed:
            parts.append(f"可用 {passed}")
        if self.table_model.has_port_conflicts():
            parts.append("端口冲突!")
        unassigned = sum(1 for n in self.nodes if n.enabled and n.local_port == 0)
        if unassigned:
            parts.append(f"{unassigned} 个节点未分配端口")
        self.lbl_stats.setText(" · ".join(parts))
        self.btn_export.setText(f" 复制代理 ({enabled})")
        self._sync_dirty_banner()

    def _report_cache_save(self, result: CacheSaveResult) -> None:
        if result.error:
            message, level = result.error, "error"
            log_message = message
        elif result.backup_path:
            message, level = f"原缓存已备份至 {os.path.basename(result.backup_path)}", "info"
            log_message = f"原缓存已备份至: {result.backup_path}"
        else:
            return
        self._append_log(log_message)
        QTimer.singleShot(0, lambda: self._notify(message, level, 4200) if not self._closing else None)

    def _persist_nodes(self, *, replace_unreadable: bool = False) -> None:
        self._report_cache_save(save_cached_nodes(self.nodes, replace_unreadable=replace_unreadable))
        self._update_summary_counters()

    # ------------------------------------------------------------------
    # Port Assignment & Filtering
    # ------------------------------------------------------------------
    def _get_start_port(self) -> int:
        txt = self.inp_start_port.text().strip()
        val = int(txt) if txt.isdigit() else 10800
        val = max(1024, min(65000, val))
        if str(val) != txt:
            self.inp_start_port.setText(str(val))
        return val

    def _assign_ports(self, reset_pinned: bool = False, *, replace_unreadable: bool = False) -> None:
        start_p = self._get_start_port()
        if replace_unreadable or start_p != self.settings.get("start_port"):
            self.settings["start_port"] = start_p
            self._report_cache_save(save_settings(self.settings, replace_unreadable=replace_unreadable))

        if reset_pinned:
            for n in self.nodes:
                n.port_pinned = False

        pinned_ports = {n.local_port for n in self.nodes if n.enabled and n.port_pinned and n.local_port > 0}
        curr_port = start_p

        for node in self.nodes:
            if node.enabled:
                if node.port_pinned and node.local_port > 0:
                    continue
                while curr_port <= 65535 and curr_port in pinned_ports:
                    curr_port += 1
                node.local_port = curr_port if curr_port <= 65535 else 0
                curr_port += 1
            else:
                if not node.port_pinned:
                    node.local_port = 0

        self.table_model.refresh_all()
        self._persist_nodes(replace_unreadable=replace_unreadable)

    def _rearrange_ports_clicked(self, reset_pinned: bool = False) -> None:
        self._assign_ports(reset_pinned=reset_pinned, replace_unreadable=True)
        msg = "已解除锁定并重排全部端口" if reset_pinned else "已顺延编排端口 (手动锁定的端口已保留)"
        self._notify(msg, "info")

    def _on_start_port_edited(self) -> None:
        if self._get_start_port() != self.settings.get("start_port"):
            self._assign_ports(reset_pinned=False, replace_unreadable=True)

    def _on_listen_ip_changed(self) -> None:
        ip = str(self.combo_listen.currentData() or "127.0.0.1")
        self.settings["listen_ip"] = ip
        self._report_cache_save(save_settings(self.settings, replace_unreadable=True))
        self.table_model.set_listen_ip(ip)
        self._sync_dirty_banner()
        if ip == "0.0.0.0" and not all(self._get_auth_pair()):
            self._notify("已切换为 0.0.0.0 局域网共享，建议在右上角开启代理账号密码鉴权", "warning", 3500)

    def _on_search_changed(self, text: str) -> None:
        self.proxy_model.set_search_query(text)
        if self.nodes and self.proxy_model.rowCount() == 0:
            self.table_view.empty_title = "未找到匹配的节点"
            self.table_view.empty_subtitle = "请尝试更换搜索关键词或切换协议筛选条件"
        else:
            self.table_view.empty_title = "暂无代理节点"
            self.table_view.empty_subtitle = "在顶部输入订阅链接下载，或按 Ctrl+V 直接粘贴节点链接 / 将配置文件拖入窗口"
        self.table_view.viewport().update()

    def _on_proto_filter_changed(self) -> None:
        proto = str(self.combo_proto.currentData() or "all")
        self.proxy_model.set_proto_filter(proto)
        self._on_search_changed(self.inp_search.text())

    # ------------------------------------------------------------------
    # Subscription, Paste & Drag-and-Drop Import
    # ------------------------------------------------------------------
    def _show_recent_urls_menu(self) -> None:
        recent = self.settings.get("recent_urls", [])
        menu = QMenu(self)
        if not recent:
            act_empty = menu.addAction("暂无历史订阅记录")
            act_empty.setEnabled(False)
        else:
            cur = self.inp_url.text().strip()
            for u in recent:
                disp = u if len(u) <= 76 else (u[:42] + "..." + u[-28:])
                act = menu.addAction(icon("check", "#2563EB", 14) if u == cur else icon("check", "transparent", 14), disp)
                act.triggered.connect(lambda checked=False, val=u: self.inp_url.setText(val))
            menu.addSeparator()
            act_clr = menu.addAction("清空历史订阅记录")
            act_clr.triggered.connect(self._clear_recent_urls)
        pos = self.inp_url.mapToGlobal(QPoint(0, self.inp_url.height() + 2))
        menu.setMinimumWidth(min(520, self.inp_url.width()))
        menu.exec(pos)

    def _clear_recent_urls(self) -> None:
        self.settings["recent_urls"] = []
        self._report_cache_save(save_settings(self.settings, replace_unreadable=True))
        self._notify("已清空历史订阅记录", "info")

    def _fetch_subscription_async(self) -> None:
        if self._closing or self._fetch_request is not None:
            return
        url = self.inp_url.text().strip()
        if not url:
            self._notify("请先输入或选择订阅链接 URL", "warning")
            self.inp_url.setFocus()
            return

        request = object()
        self._fetch_request = request
        self.btn_fetch.setEnabled(False)
        self.btn_fetch.setText(" 正在拉取...")

        def _worker() -> None:
            try:
                content, meta = fetch_subscription_with_meta(url)
                nodes, errors = parse_subscription_content(content)
            except Exception as exc:
                self._emit_worker_signal(self.bridge.fetchFinished, request, url, None, str(exc))
            else:
                self._emit_worker_signal(self.bridge.fetchFinished, request, url, (nodes, errors, meta), "")

        threading.Thread(target=_worker, daemon=True).start()

    def _reset_fetch(self) -> None:
        self._fetch_request = None
        self.btn_fetch.setEnabled(True)
        self.btn_fetch.setText(" 下载更新")

    def _on_fetch_finished(self, request: object, url: str, result, error: str) -> None:
        if self._closing or request is not self._fetch_request:
            return
        self._reset_fetch()
        if result is None:
            QMessageBox.critical(self, "下载订阅失败", f"请求订阅链接时出错：\n{error}")
            return
        nodes, errors, meta = result
        if not nodes:
            detail = "\n".join(errors[:3]) if errors else "未识别到支持的节点格式"
            QMessageBox.warning(self, "解析订阅失败", f"未能从订阅中解析出有效节点：\n{detail}")
            return

        preserve_state = url == self.settings.get("subscription_url")
        recent = [u for u in self.settings.get("recent_urls", []) if u != url]
        recent.insert(0, url)
        self.settings["recent_urls"] = recent[:12]
        self.settings["subscription_url"] = url
        self.settings["sub_userinfo"] = meta
        self._refresh_sub_userinfo_badge()
        self._load_new_nodes(nodes, source_label=f"成功更新订阅 · 导入 {len(nodes)} 个节点", preserve_state=preserve_state)
        self._show_import_errors(errors)

    def _clear_subscription_source(self) -> None:
        self._reset_fetch()
        self.settings["subscription_url"] = ""
        self.settings["sub_userinfo"] = {}
        self.inp_url.clear()
        self._refresh_sub_userinfo_badge()

    def _show_import_errors(self, errors: List[str]) -> None:
        if errors:
            QMessageBox.warning(self, "部分节点未导入", "\n".join(errors[:8]))

    def _load_new_nodes(
        self, new_nodes: List[ProxyNode], source_label: str = "", preserve_state: bool = False,
    ) -> None:
        self._cancel_probes()
        if preserve_state:
            previous = defaultdict(deque)
            for node in self.nodes:
                previous[node.connection_key()].append(node)
            for node in new_nodes:
                matches = previous[node.connection_key()]
                if matches:
                    old = matches.popleft()
                    node.enabled = old.enabled
                    node.local_port = old.local_port
                    node.port_pinned = old.port_pinned
        self.nodes = new_nodes
        self.table_model.set_nodes(self.nodes)
        self._assign_ports(reset_pinned=not preserve_state, replace_unreadable=True)
        if source_label:
            self._notify(source_label, "success")

    def _open_paste_dialog(self) -> None:
        dlg = PasteImportDialog(self)
        if dlg.exec() == PasteImportDialog.DialogCode.Accepted and dlg.result_text:
            self._parse_and_load_raw_text(dlg.result_text)

    def _smart_paste_shortcut(self) -> None:
        fw = QApplication.focusWidget()
        if isinstance(fw, (QLineEdit, QPlainTextEdit, QSpinBox)):
            if isinstance(fw, QLineEdit):
                fw.paste()
            elif isinstance(fw, QPlainTextEdit):
                fw.paste()
            return

        cb = QApplication.clipboard().text().strip()
        if not cb:
            return
        if cb.startswith(("http://", "https://")) and "\n" not in cb:
            self.inp_url.setText(cb)
            self._notify("已粘贴订阅链接到地址栏，回车即可下载", "info")
            return

        nodes, errors = parse_subscription_content(cb)
        if nodes:
            self._clear_subscription_source()
            self._load_new_nodes(nodes, f"从剪贴板导入 {len(nodes)} 个节点")
            self._show_import_errors(errors)
        else:
            self._open_paste_dialog()

    def _parse_and_load_raw_text(self, text: str) -> None:
        nodes, errors = parse_subscription_content(text)
        if not nodes:
            detail = "\n".join(errors[:3]) if errors else "请确认输入为节点链接、Base64 或 Clash 配置"
            QMessageBox.warning(self, "未识别到有效节点", detail)
            return
        self._clear_subscription_source()
        self._load_new_nodes(nodes, f"成功导入 {len(nodes)} 个节点")
        self._show_import_errors(errors)

    def _import_from_file(self) -> None:
        fpath, _ = QFileDialog.getOpenFileName(
            self,
            "选择节点或订阅配置文件",
            "",
            "支持的配置文件 (*.txt *.yaml *.yml *.conf);;所有文件 (*.*)",
        )
        if fpath:
            self._load_file_path(fpath)

    def _load_file_path(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8-sig", errors="ignore") as f:
                content = f.read()
            nodes, errors = parse_subscription_content(content)
            if not nodes:
                if errors:
                    self._show_import_errors(errors)
                else:
                    self._notify("该文件中未发现有效代理节点", "error")
                return
            self._clear_subscription_source()
            self._load_new_nodes(nodes, f"已从 {os.path.basename(fpath)} 导入 {len(nodes)} 个节点")
            self._show_import_errors(errors)
        except Exception as exc:
            QMessageBox.critical(self, "读取文件失败", str(exc))

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls() or event.mimeData().hasText():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        md = event.mimeData()
        if md.hasUrls():
            for u in md.urls():
                local = u.toLocalFile()
                if local and os.path.isfile(local):
                    self._load_file_path(local)
                    return
        if md.hasText():
            self._parse_and_load_raw_text(md.text())

    # ------------------------------------------------------------------
    # Table Interactions & Batch Actions
    # ------------------------------------------------------------------
    def _source_rows_from_selection(self) -> List[int]:
        sel = self.table_view.selectionModel().selectedRows()
        return sorted({self.proxy_model.mapToSource(idx).row() for idx in sel if idx.isValid()})

    def _on_table_clicked(self, proxy_idx) -> None:
        if not proxy_idx.isValid():
            return
        if proxy_idx.column() == COL_ENABLED:
            src_row = self.proxy_model.mapToSource(proxy_idx).row()
            if 0 <= src_row < len(self.nodes):
                self.nodes[src_row].enabled = not self.nodes[src_row].enabled
                self._assign_ports(reset_pinned=False)

    def _on_table_double_clicked(self, proxy_idx) -> None:
        if not proxy_idx.isValid():
            return
        if proxy_idx.column() in (COL_LOCAL, COL_ENABLED):
            return
        src_row = self.proxy_model.mapToSource(proxy_idx).row()
        if 0 <= src_row < len(self.nodes):
            self.nodes[src_row].enabled = not self.nodes[src_row].enabled
            self._assign_ports(reset_pinned=False)

    def _on_inline_port_edited(self, src_row: int, new_port: int) -> None:
        if not (0 <= src_row < len(self.nodes)):
            return
        node = self.nodes[src_row]
        node.local_port = new_port
        node.port_pinned = True
        node.enabled = True
        self.table_model.refresh_all()
        self._persist_nodes()
        if self.table_model.has_port_conflicts():
            self._notify(f"端口 {new_port} 与其他启用节点重复，请检查标红行！", "warning", 3200)
        else:
            self._notify(f"已锁定节点端口为 {new_port}", "success")

    def _toggle_selected_rows(self) -> None:
        rows = self._source_rows_from_selection()
        if not rows:
            return
        for r in rows:
            self.nodes[r].enabled = not self.nodes[r].enabled
        self._assign_ports(reset_pinned=False)

    def _delete_selected_rows(self) -> None:
        rows = self._source_rows_from_selection()
        if not rows:
            return
        for r in reversed(rows):
            self.nodes.pop(r)
        self.table_model.set_nodes(self.nodes)
        self._assign_ports(reset_pinned=False)
        self._notify(f"已移除 {len(rows)} 个节点", "info")

    def _batch_set_enabled(self, state: bool) -> None:
        if not self.nodes:
            return
        # Apply to currently visible filtered rows for intuitive UX
        vis_count = self.proxy_model.rowCount()
        for pr in range(vis_count):
            sr = self.proxy_model.mapToSource(self.proxy_model.index(pr, 0)).row()
            self.nodes[sr].enabled = state
        self._assign_ports(reset_pinned=False)

    def _invert_selection(self) -> None:
        if not self.nodes:
            return
        vis_count = self.proxy_model.rowCount()
        for pr in range(vis_count):
            sr = self.proxy_model.mapToSource(self.proxy_model.index(pr, 0)).row()
            self.nodes[sr].enabled = not self.nodes[sr].enabled
        self._assign_ports(reset_pinned=False)

    def _keep_only_passed_nodes(self) -> None:
        tested = [n for n in self.nodes if n.latency_ms is not None]
        if not tested:
            self._notify("请先启动服务并执行一次并发测速", "warning")
            return
        kept = 0
        for n in self.nodes:
            if n.latency_ms is not None and n.latency_ms >= 0:
                n.enabled = True
                kept += 1
            else:
                n.enabled = False
        self._assign_ports(reset_pinned=False)
        self._notify(f"已自动筛除失效节点，保留 {kept} 个可用节点", "success")

    def _clear_all_nodes(self) -> None:
        if not self.nodes and not nodes_cache_protected():
            return
        if self.xray_mgr.is_running():
            self._notify("代理服务正在运行中，请先停止服务再清空列表", "warning")
            return
        ans = QMessageBox.question(
            self,
            "确认清空",
            f"确定要清空当前全部 {len(self.nodes)} 个节点吗？" if self.nodes else "确定备份无法读取的缓存并清空吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if ans == QMessageBox.StandardButton.Yes:
            result = clear_cached_nodes(replace_unreadable=True)
            self._report_cache_save(result)
            if result.error:
                return
            self._cancel_probes()
            self._clear_subscription_source()
            self.nodes = []
            self._report_cache_save(save_settings(self.settings, replace_unreadable=True))
            self.table_model.set_nodes(self.nodes)
            self.inp_search.clear()
            self._update_summary_counters()
            self._notify("节点列表已清空", "info")

    def _show_table_context_menu(self, pos: QPoint) -> None:
        idx = self.table_view.indexAt(pos)
        if not idx.isValid():
            return
        src_row = self.proxy_model.mapToSource(idx).row()
        if not (0 <= src_row < len(self.nodes)):
            return
        if not self.table_view.selectionModel().isRowSelected(idx.row(), idx.parent()):
            self.table_view.selectRow(idx.row())
        node = self.nodes[src_row]

        menu = QMenu(self)
        if node.enabled and node.local_port > 0 and not self._service_busy and not self._has_unapplied_changes():
            url_str = self._format_node_proxy_line(node, "url")
            socks_str = self._format_node_proxy_line(node, "socks5")
            hp_str = self._format_node_proxy_line(node, "hostport")
            menu.addAction(f"复制 HTTP 代理 ({url_str})", lambda: self._copy_node_proxy(node, "url"))
            menu.addAction(f"复制 SOCKS5 代理 ({socks_str})", lambda: self._copy_node_proxy(node, "socks5"))
            menu.addAction(f"复制 IP:Port ({hp_str})", lambda: self._copy_node_proxy(node, "hostport"))
        if node.raw_link:
            menu.addAction("复制原始节点分享链接", lambda: self._copy_text_toast(node.raw_link, "已复制原始分享链接"))

        menu.addSeparator()
        menu.addAction("单独测速此节点", lambda: self._test_single_row_async(src_row)).setEnabled(
            self._speed_task is None,
        )
        menu.addAction("检测此节点出口 IP", lambda: self._probe_single_exit_ip_async(src_row)).setEnabled(
            self._exit_ip_task is None,
        )
        menu.addAction("修改本地端口...", lambda: self._prompt_edit_port(src_row))
        if node.port_pinned:
            menu.addAction("解除端口锁定", lambda: self._unpin_row_port(src_row))

        menu.addSeparator()
        menu.addAction("切换 启用 / 禁用 (Space)", self._toggle_selected_rows)
        menu.addAction("移除选中节点 (Delete)", self._delete_selected_rows)
        menu.exec(self.table_view.viewport().mapToGlobal(pos))

    def _prompt_edit_port(self, src_row: int) -> None:
        node = self.nodes[src_row]
        val, ok = QInputDialog.getInt(
            self,
            "修改本地混合代理端口",
            f"节点：{node.name}\n设置独立监听端口 (1024 ~ 65535)：",
            node.local_port or self._get_start_port(),
            1024,
            65535,
        )
        if ok:
            self._on_inline_port_edited(src_row, val)

    def _unpin_row_port(self, src_row: int) -> None:
        self.nodes[src_row].port_pinned = False
        self._assign_ports(reset_pinned=False)
        self._notify("已解除端口锁定并重新顺延分配", "info")

    # ------------------------------------------------------------------
    # Copy & Export Helpers
    # ------------------------------------------------------------------
    def _ensure_ready_for_export(self) -> bool:
        if self._closing or self._service_busy or self._has_unapplied_changes():
            self._notify("请等待服务操作完成并应用配置变更后，再复制或导出代理", "warning")
            return False
        return True

    def _copy_node_proxy(self, node: ProxyNode, fmt: str) -> None:
        if self._ensure_ready_for_export() and node in self.nodes and node.enabled and node.local_port > 0:
            self._copy_text_toast(self._format_node_proxy_line(node, fmt), "已复制代理地址")

    def _format_node_proxy_line(self, node: ProxyNode, fmt: str = "url") -> str:
        raw_ip = str(self.combo_listen.currentData() or "127.0.0.1")
        host_disp = format_proxy_host(raw_ip)
        auth_prefix = ""
        user, password = self._get_auth_pair()
        if user and password:
            auth_prefix = f"{quote(user, safe='')}:{quote(password, safe='')}@"

        if fmt == "hostport":
            return f"{auth_prefix}{host_disp}:{node.local_port}"
        if fmt == "socks5":
            return f"socks5://{auth_prefix}{host_disp}:{node.local_port}"
        base_url = f"http://{auth_prefix}{host_disp}:{node.local_port}"
        if fmt == "comment":
            lat_part = f" [{node.latency_ms}ms]" if (node.latency_ms is not None and node.latency_ms >= 0) else ""
            ip_part = f" [{node.exit_ip}]" if node.exit_ip else ""
            return f"{base_url}  # {node.name}{lat_part}{ip_part}"
        return base_url

    def _copy_text_toast(self, text: str, msg: str) -> None:
        QApplication.clipboard().setText(text)
        self._notify(msg, "success")

    def _copy_proxies_bulk(self, fmt: str = "url", only_passed: bool = False) -> None:
        if not self._ensure_ready_for_export():
            return
        candidates = [n for n in self.nodes if n.enabled and n.local_port > 0]
        if only_passed:
            candidates = [n for n in candidates if n.latency_ms is not None and n.latency_ms >= 0]

        if not candidates:
            hint = "没有测速通过的节点，请先执行并发测速" if only_passed else "当前没有已启用的本地代理节点"
            self._notify(hint, "warning")
            return

        lines = [self._format_node_proxy_line(n, fmt) for n in candidates]
        QApplication.clipboard().setText("\n".join(lines))
        label_map = {"url": "HTTP URL", "socks5": "SOCKS5 URL", "hostport": "IP:Port", "comment": "带备注"}
        self._notify(f"已复制 {len(lines)} 条代理地址 ({label_map.get(fmt, 'URL')})", "success")

    def _export_proxies_to_file(self) -> None:
        if not self._ensure_ready_for_export():
            return
        candidates = [n for n in self.nodes if n.enabled and n.local_port > 0]
        if not candidates:
            self._notify("当前没有已启用的节点可导出", "warning")
            return
        fpath, _ = QFileDialog.getSaveFileName(self, "导出代理映射列表", "proxies.txt", "文本文件 (*.txt)")
        if not fpath:
            return
        if not self._ensure_ready_for_export():
            return
        candidates = [n for n in self.nodes if n.enabled and n.local_port > 0]
        if not candidates:
            self._notify("当前没有已启用的节点可导出", "warning")
            return
        try:
            lines = [self._format_node_proxy_line(n, "comment") for n in candidates]
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            self._notify(f"已导出 {len(lines)} 条代理至 {os.path.basename(fpath)}", "success")
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", str(exc))

    # ------------------------------------------------------------------
    # Xray Service Lifecycle (Start / Stop / Hot Reload)
    # ------------------------------------------------------------------
    def _get_auth_pair(self) -> Tuple[str, str]:
        if self.settings.get("auth_enabled"):
            u = str(self.settings.get("auth_user", "")).strip()
            p = str(self.settings.get("auth_pass", "")).strip()
            if u and p:
                return u, p
        return "", ""

    def _toggle_service(self) -> None:
        if self._closing or self._service_busy:
            return
        if self.xray_mgr.is_running():
            self._stop_service()
        else:
            self._start_service()

    def _start_service(self) -> None:
        if self._closing or self._service_busy:
            return
        active = [n for n in self.nodes if n.enabled]
        if not active:
            self._notify("请至少勾选一个需要映射的代理节点", "warning")
            return

        listen_ip = str(self.combo_listen.currentData() or "127.0.0.1")
        auth_u, auth_p = self._get_auth_pair()
        if self.settings.get("auth_enabled") and not (auth_u and auth_p):
            self._notify("请在鉴权设置中补齐用户名和密码", "warning")
            return

        self._set_service_busy(True)
        self.btn_service.setText(" 正在启动...")
        self._set_service_badge_style("starting", "● 正在启动内核...")

        self._pending_signature = self._calc_config_signature()
        nodes_snapshot = copy.deepcopy(self.nodes)

        def _worker() -> None:
            try:
                ok, msg = self.xray_mgr.start(nodes_snapshot, listen_ip=listen_ip, auth_user=auth_u, auth_pass=auth_p)
            except Exception as exc:
                ok, msg = False, str(exc)
            self._emit_worker_signal(self.bridge.serviceTransitioned, ok, msg, "start")

        threading.Thread(target=_worker, daemon=True).start()

    def _reload_service(self) -> None:
        if self._closing or self._service_busy:
            return
        active = [n for n in self.nodes if n.enabled]
        if not active:
            self._stop_service()
            return

        listen_ip = str(self.combo_listen.currentData() or "127.0.0.1")
        auth_u, auth_p = self._get_auth_pair()
        if self.settings.get("auth_enabled") and not (auth_u and auth_p):
            self._notify("请在鉴权设置中补齐用户名和密码", "warning")
            return

        self._set_service_busy(True)
        self.btn_reload_dirty.setText(" 正在重载...")
        self._pending_signature = self._calc_config_signature()
        nodes_snapshot = copy.deepcopy(self.nodes)

        def _worker() -> None:
            try:
                ok, msg = self.xray_mgr.reload(nodes_snapshot, listen_ip=listen_ip, auth_user=auth_u, auth_pass=auth_p)
            except Exception as exc:
                ok, msg = False, str(exc)
            self._emit_worker_signal(self.bridge.serviceTransitioned, ok, msg, "reload")

        threading.Thread(target=_worker, daemon=True).start()

    def _stop_service(self) -> None:
        if self._closing or self._service_busy:
            return
        self._set_service_busy(True)
        self.btn_service.setText(" 正在停止...")

        def _worker() -> None:
            ok, msg = self.xray_mgr.stop()
            self._emit_worker_signal(self.bridge.serviceTransitioned, ok, msg, "stop")

        threading.Thread(target=_worker, daemon=True).start()

    def _set_service_busy(self, busy: bool) -> None:
        self._service_busy = busy
        if busy:
            self._cancel_probes()
        self.btn_service.setEnabled(not busy)
        self.btn_reload_dirty.setEnabled(not busy)
        if self.tray:
            self.act_tray_toggle.setEnabled(not busy)

    def _on_service_transitioned(self, ok: bool, msg: str, action: str) -> None:
        if action == "close":
            self._shutdown_complete = True
            if not ok:
                QMessageBox.critical(self, "Xray 停止失败", msg)
            self.close()
            return
        if self._closing:
            return
        self._set_service_busy(False)
        self.btn_reload_dirty.setText(" 应用变更")

        if action in ("start", "reload"):
            if ok:
                self._applied_signature = self._pending_signature
                self._apply_running_ui_state(True)
                self._sync_dirty_banner()
                toast_txt = "新配置已生效（现有连接已重启）" if action == "reload" else msg
                self._notify(toast_txt, "success")
            else:
                self._apply_running_ui_state(self.xray_mgr.is_running())
                if not self.xray_mgr.is_running():
                    self._applied_signature = None
                    self._set_service_badge_style("error", "● 启动失败")
                self._sync_dirty_banner()
                QMessageBox.critical(self, "Xray 服务启动失败", msg)
        elif action == "stop":
            if ok:
                self._applied_signature = None
            self._apply_running_ui_state(self.xray_mgr.is_running())
            self._sync_dirty_banner()
            self._notify(msg, "info" if ok else "error")
        self._pending_signature = None

    def _apply_running_ui_state(self, running: bool) -> None:
        app_ic = build_app_logo_icon(active=running)
        app_inst = QApplication.instance()
        if isinstance(app_inst, QApplication):
            app_inst.setWindowIcon(app_ic)
        self.setWindowIcon(app_ic)
        self.lbl_logo.setPixmap(app_ic.pixmap(QSize(32, 32)))

        if running:
            ports = sorted(m["local_port"] for m in self.xray_mgr.active_mappings)
            p_range = f"{ports[0]}–{ports[-1]}" if len(ports) > 1 else (str(ports[0]) if ports else "")
            lan_tag = " [LAN]" if self.xray_mgr.listen_ip == "0.0.0.0" else ""
            badge = f"● 运行中 · {len(ports)} 端口 ({p_range}){lan_tag}"
            self._set_service_badge_style("running", badge)

            self.btn_service.setText(" 停止服务")
            self.btn_service.setIcon(icon("stop", "#DC2626", 13))
            self.btn_service.setProperty("role", "danger")
            if self.tray:
                self.tray.setIcon(app_ic)
                self.tray.setToolTip(f"XraySubMapper · {badge}")
                self.act_tray_toggle.setText("停止映射服务")
        else:
            self._set_service_badge_style("stopped", "● 服务未启动")
            self.btn_service.setText(" 启动映射服务")
            self.btn_service.setIcon(icon("play", "#FFFFFF", 14))
            self.btn_service.setProperty("role", "primary")
            if self.tray:
                self.tray.setIcon(app_ic)
                self.tray.setToolTip("XraySubMapper · 服务未启动")
                self.act_tray_toggle.setText("启动映射服务")

        self.btn_service.style().unpolish(self.btn_service)
        self.btn_service.style().polish(self.btn_service)

    def _check_xray_alive(self) -> None:
        if self._closing or self._service_busy:
            return
        if self._applied_signature is not None and not self.xray_mgr.is_running():
            self._applied_signature = None
            self._cancel_probes()
            self._apply_running_ui_state(False)
            self._set_service_badge_style("error", "● 内核意外退出")
            self._sync_dirty_banner()
            self._notify("检测到 Xray 进程已退出，请查看运行日志", "error", 3600)

    # ------------------------------------------------------------------
    # Latency Speedtest & Exit IP Probing
    # ------------------------------------------------------------------
    def _ensure_ready_for_probe(self) -> bool:
        if self._closing:
            return False
        if self._service_busy:
            self._notify("请等待服务操作完成后再进行测试", "warning")
            return False
        if not any(n.enabled for n in self.nodes):
            self._notify("请先启用要测试的节点", "warning")
            return False
        if not self.xray_mgr.is_running():
            self._notify("请先点击右上角【启动映射服务】后再进行测试", "warning", 2800)
            return False
        if self._has_unapplied_changes():
            self._notify("配置已变更，正在应用；完成后请再次点击测试", "info")
            self._reload_service()
            return False
        return True

    def _test_single_row_async(self, src_row: int) -> None:
        self._start_probe(speed=True, src_row=src_row)

    def _test_all_speed_async(self) -> None:
        self._start_probe(speed=True)

    def _probe_single_exit_ip_async(self, src_row: int) -> None:
        self._start_probe(speed=False, src_row=src_row)

    def _probe_all_exit_ips_async(self) -> None:
        self._start_probe(speed=False)

    def _start_probe(self, *, speed: bool, src_row: Optional[int] = None) -> None:
        current_task = self._speed_task if speed else self._exit_ip_task
        if current_task is not None or not self._ensure_ready_for_probe():
            return
        if src_row is not None and not 0 <= src_row < len(self.nodes):
            return
        candidates = self.nodes if src_row is None else [self.nodes[src_row]]
        nodes = tuple(node for node in candidates if node.enabled and node.local_port > 0)
        if not nodes:
            self._notify("没有已启用且已分配端口的节点可测试", "warning")
            return
        task = ProbeTask(self.xray_mgr.generation, self._calc_config_signature(), nodes, src_row is not None)
        snapshots = copy.deepcopy(nodes)
        originals = {id(snapshot): node for node, snapshot in zip(nodes, snapshots)}

        options = {}
        if speed:
            self._speed_task = task
            button, label = self.btn_speed, "测速"
            operation = self.xray_mgr.test_all_proxies
            progress, finished = self.bridge.speedProgress, self.bridge.speedFinished
            options["test_url"] = str(self.settings.get("test_url") or "https://cp.cloudflare.com/generate_204")
        else:
            self._exit_ip_task = task
            button, label = self.btn_probe_ip, "探测"
            operation = self.xray_mgr.probe_all_exit_ips
            progress, finished = self.bridge.exitIpProgress, self.bridge.exitIpFinished
        button.setEnabled(False)
        button.setText(f" {label} 0/{len(nodes)}")

        def _worker() -> None:
            error = ""
            try:
                operation(
                    list(snapshots), cancel_event=task.cancelled, **options,
                    progress_cb=lambda done, total, snapshot: self._emit_worker_signal(
                        progress, done, total, (task, originals[id(snapshot)], snapshot),
                    ),
                )
            except Exception as exc:
                error = f"{label}失败: {exc}"
            self._emit_worker_signal(finished, task, error)

        threading.Thread(target=_worker, daemon=True).start()

    def _reset_probe(self, *, speed: bool) -> None:
        task = self._speed_task if speed else self._exit_ip_task
        if task is None:
            return
        task.cancelled.set()
        if speed:
            self._speed_task = None
            self.btn_speed.setEnabled(True)
            self.btn_speed.setText(" 并发测速")
        else:
            self._exit_ip_task = None
            self.btn_probe_ip.setEnabled(True)
            self.btn_probe_ip.setText(" 查出口 IP")

    def _cancel_probes(self) -> None:
        self._reset_probe(speed=True)
        self._reset_probe(speed=False)

    def _probe_is_current(self, task: ProbeTask, *, speed: bool) -> bool:
        current = self._speed_task if speed else self._exit_ip_task
        return (not self._closing and not self._service_busy and task is current
                and self.xray_mgr.is_running() and task.generation == self.xray_mgr.generation
                and task.signature == self._applied_signature and task.signature == self._calc_config_signature())

    def _on_speed_progress(self, done: int, total: int, payload) -> None:
        task, node, snapshot = payload
        if self._probe_is_current(task, speed=True) and node in self.nodes:
            self.btn_speed.setText(f" 测速 {done}/{total}")
            node.latency_ms, node.last_error = snapshot.latency_ms, snapshot.last_error
            self.table_model.refresh_row(self.nodes.index(node))

    def _on_exit_ip_progress(self, done: int, total: int, payload) -> None:
        task, node, snapshot = payload
        if self._probe_is_current(task, speed=False) and node in self.nodes:
            self.btn_probe_ip.setText(f" 探测 {done}/{total}")
            node.exit_ip = snapshot.exit_ip
            self.table_model.refresh_row(self.nodes.index(node))

    def _finish_probe(self, task: ProbeTask, error: str, *, speed: bool) -> bool:
        if task is not (self._speed_task if speed else self._exit_ip_task):
            return False
        current = self._probe_is_current(task, speed=speed)
        self._reset_probe(speed=speed)
        if not current:
            return False
        self._persist_nodes()
        if error:
            self._append_log(error)
            self._notify(error, "error")
            return False
        return True

    def _on_speed_finished(self, task: ProbeTask, error: str) -> None:
        if not self._finish_probe(task, error, speed=True):
            return
        if task.single:
            node = task.nodes[0]
            if node.latency_ms is not None and node.latency_ms >= 0:
                self._notify(f"端口 {node.local_port} 连通正常 ({node.latency_ms} ms)", "success")
            else:
                self._notify(f"端口 {node.local_port} 测试失败: {node.last_error}", "error")
            return
        passed = sum(1 for node in task.nodes if node.latency_ms is not None and node.latency_ms >= 0)
        self._notify(f"测速完成 · {passed}/{len(task.nodes)} 个端口连通正常", "success" if passed else "warning")

    def _on_exit_ip_finished(self, task: ProbeTask, error: str) -> None:
        if not self._finish_probe(task, error, speed=False):
            return
        if task.single:
            node = task.nodes[0]
            if node.exit_ip:
                self._notify(f"端口 {node.local_port} 落地出口: {node.exit_ip}", "success")
            else:
                self._notify(f"端口 {node.local_port} 未能获取出口 IP", "error")
            return
        found = sum(1 for node in task.nodes if node.exit_ip)
        self._notify(f"出口探测完成 · 已识别 {found} 个端口的落地 IP", "success" if found else "warning")

    # ------------------------------------------------------------------
    # Settings, Console & Window Close
    # ------------------------------------------------------------------
    def _open_settings_dialog(self) -> None:
        dlg = ProxySettingsDialog(
            auth_enabled=bool(self.settings.get("auth_enabled", False)),
            auth_user=str(self.settings.get("auth_user", "")),
            auth_pass=str(self.settings.get("auth_pass", "")),
            test_url=str(self.settings.get("test_url", "https://cp.cloudflare.com/generate_204")),
            parent=self,
        )
        if dlg.exec() == ProxySettingsDialog.DialogCode.Accepted:
            en, u, p, t_url = dlg.get_values()
            settings = dict(self.settings, auth_enabled=en, auth_user=u, auth_pass=p, test_url=t_url)
            result = save_settings(settings, replace_unreadable=True)
            self._report_cache_save(result)
            if result.error:
                return
            self.settings = settings
            self._refresh_auth_button_style()
            self._sync_dirty_banner()
            self._notify("参数设置已保存", "success")

    def _toggle_console_drawer(self, checked: bool) -> None:
        self.console_card.setVisible(checked)

    def _emit_worker_signal(self, signal, *args, during_close: bool = False) -> None:
        if self._closing and not during_close:
            return
        try:
            signal.emit(*args)
        except RuntimeError:
            # Qt may have destroyed the bridge while the worker was running.
            pass

    def _append_log(self, msg: str) -> None:
        if not self._closing:
            self.txt_console.appendPlainText(msg)

    def _clear_console(self) -> None:
        self.txt_console.clear()

    def _show_console_context_menu(self, pos: QPoint) -> None:
        menu = QMenu(self)
        has_sel = self.txt_console.textCursor().hasSelection()
        has_text = bool(self.txt_console.toPlainText())

        act_copy = menu.addAction("复制")
        act_copy.setEnabled(has_sel)
        act_copy.triggered.connect(self.txt_console.copy)

        act_sel_all = menu.addAction("全选")
        act_sel_all.setEnabled(has_text)
        act_sel_all.triggered.connect(self.txt_console.selectAll)

        menu.addSeparator()
        act_clear = menu.addAction("清空")
        act_clear.setEnabled(has_text)
        act_clear.triggered.connect(self._clear_console)

        menu.exec(self.txt_console.viewport().mapToGlobal(pos))

    def _save_window_state(self) -> None:
        if not self.isMinimized() and not self.isMaximized():
            g = self.geometry()
            self.settings["window_rect"] = [g.x(), g.y(), g.width(), g.height()]
        col_count = self.table_model.columnCount()
        widths = [self.table_view.columnWidth(c) for c in range(col_count)]
        if self._manual_name_width is None:
            widths[COL_NAME] = 310
        self.settings["column_widths"] = widths
        self.settings["name_col_manual"] = self._manual_name_width is not None
        self._report_cache_save(save_settings(self.settings))
        if self.nodes:
            self._report_cache_save(save_cached_nodes(self.nodes))

    def _quit_completely(self) -> None:
        self._force_quit = True
        if self._close_prompt is not None:
            self._close_prompt.reject()
            return
        self.close()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._closing:
            if self._shutdown_complete:
                if self.tray:
                    self.tray.hide()
                event.accept()
                if self._force_quit or not self.isVisible():
                    QTimer.singleShot(0, QApplication.quit)
            else:
                event.ignore()
            return

        if self._close_prompt is not None:
            event.ignore()
            return

        if not self._force_quit and self.xray_mgr.is_running() and self.tray and self.tray.isVisible():
            box = QMessageBox(self)
            box.setWindowTitle("代理服务运行中")
            box.setText("Xray 多端口映射服务正在运行中，请选择关闭方式：")
            btn_tray = box.addButton("最小化到系统托盘 (继续运行)", QMessageBox.ButtonRole.AcceptRole)
            btn_exit = box.addButton("停止服务并退出", QMessageBox.ButtonRole.DestructiveRole)
            box.addButton("取消", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(btn_tray)
            self._close_prompt = box
            try:
                box.exec()
            finally:
                self._close_prompt = None

            if not self._force_quit:
                clicked = box.clickedButton()
                if clicked == btn_tray:
                    self._save_window_state()
                    event.ignore()
                    self.hide()
                    self.tray.showMessage(
                        "XraySubMapper 仍在后台运行",
                        "本地混合代理端口仍可用，双击托盘图标可恢复主窗口。",
                        QSystemTrayIcon.MessageIcon.Information,
                        2000,
                    )
                    return
                if clicked != btn_exit:
                    event.ignore()
                    return

        self._closing = True
        self._cancel_probes()
        self._save_window_state()

        event.ignore()
        self.setEnabled(False)
        self._set_service_badge_style("starting", "● 正在停止内核...")
        completed = self.bridge.serviceTransitioned

        def _worker() -> None:
            try:
                ok, msg = self.xray_mgr.close()
            except Exception as exc:
                ok, msg = False, str(exc)
            self._emit_worker_signal(completed, ok, msg, "close", during_close=True)

        threading.Thread(target=_worker, daemon=True).start()


ModernApp = MainWindow


def _set_windows_app_user_model_id() -> None:
    """Detach window taskbar grouping from python.exe/pythonw.exe so Windows Taskbar displays our custom icon."""
    if sys.platform == "win32":
        try:
            import ctypes
            set_app_id = ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID
            set_app_id.argtypes = [ctypes.c_wchar_p]
            set_app_id.restype = ctypes.c_long
            set_app_id("XraySubMapper.Desktop.App.1")
        except Exception:
            pass


def run_gui() -> None:
    _set_windows_app_user_model_id()
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication.instance() or QApplication(sys.argv)
    instance_lock = GuiInstanceLock(GUI_MUTEX_NAME)
    try:
        primary = instance_lock.acquire()
    except OSError as exc:
        QMessageBox.critical(None, "启动失败 - XraySubMapper", f"无法确认工作台运行状态，请稍后重试。\n{exc}")
        sys.exit(1)
    if not primary:
        if not activate_existing_window(GUI_WINDOW_TITLE):
            QMessageBox.information(None, "XraySubMapper 已在运行", "请从任务栏或系统托盘打开已有工作台；若正在启动，请稍候。")
        return

    try:
        app.aboutToQuit.connect(clear_icon_caches)
        app.setStyle("Fusion")
        base_font = QFont("Microsoft YaHei UI", 9)
        base_font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
        base_font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
        app.setFont(base_font)
        app.setStyleSheet(GLOBAL_QSS)
        app.setWindowIcon(build_app_logo_icon(active=False))
        win = MainWindow()
        win.show()
        # Guard against parent launchers passing STARTUPINFO.wShowWindow = SW_HIDE (0) on Windows
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes.wintypes import BOOL, HWND

                user32 = ctypes.windll.user32
                user32.IsWindowVisible.argtypes = [HWND]
                user32.IsWindowVisible.restype = BOOL
                user32.ShowWindow.argtypes = [HWND, ctypes.c_int]
                user32.ShowWindow.restype = BOOL
                user32.SetForegroundWindow.argtypes = [HWND]
                user32.SetForegroundWindow.restype = BOOL
                hwnd = int(win.winId())
                if not user32.IsWindowVisible(hwnd):
                    user32.ShowWindow(hwnd, 5)  # SW_SHOW
                user32.SetForegroundWindow(hwnd)
            except Exception:
                pass
        sys.exit(app.exec())
    finally:
        instance_lock.close()


if __name__ == "__main__":
    run_gui()
