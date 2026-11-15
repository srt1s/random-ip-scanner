import ctypes
import math
from collections import deque
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPointF,
    QRectF,
    QSortFilterProxyModel,
    Qt,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QVBoxLayout,
    QWidget,
)

# Renk Paleti (Obsidian Slate Telemetry)
COLORS = {
    "bg_canvas": "#0B0F17",
    "bg_sidebar": "#101623",
    "bg_surface": "#151E2E",
    "bg_surface_alt": "#1A2438",
    "bg_input": "#0D131F",
    "border": "#223047",
    "border_subtle": "#1A2436",
    "text_primary": "#F1F5F9",
    "text_secondary": "#94A3B8",
    "text_muted": "#64748B",
    "accent_blue": "#3B82F6",
    "accent_blue_hover": "#2563EB",
    "accent_cyan": "#06B6D4",
    "emerald": "#10B981",
    "emerald_dark": "#064E3B",
    "amber": "#F59E0B",
    "amber_dark": "#451A03",
    "violet": "#A855F7",
    "violet_dark": "#3B0764",
    "rose": "#EF4444",
    "rose_dark": "#450A0A",
    "tr_red": "#E11D48",
}

THEME_QSS = """
QMainWindow, QWidget#RootCanvas {
    background-color: #0B0F17;
    color: #F1F5F9;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}

QFrame#HeaderBar {
    background-color: #101623;
    border-bottom: 1px solid #1E293B;
}

QFrame#SidebarPanel {
    background-color: #101623;
    border-right: 1px solid #1E293B;
}

QWidget#SidebarScrollContent {
    background-color: transparent;
}

QFrame#SectionCard {
    background-color: #141C2B;
    border: 1px solid #1E293B;
    border-radius: 10px;
}

QFrame#StatCard {
    background-color: #141C2B;
    border: 1px solid #1F2B3E;
    border-radius: 10px;
}

QFrame#InspectorBar {
    background-color: #121A29;
    border: 1px solid #223047;
    border-radius: 8px;
}

QLabel#SectionTitle {
    color: #64748B;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.8px;
}

QLabel#MutedText {
    color: #94A3B8;
    font-size: 12px;
}

/* Primary Start/Stop CTA */
QPushButton#PrimaryStartBtn {
    background-color: #10B981;
    color: #042F2E;
    border: none;
    border-radius: 9px;
    font-size: 14px;
    font-weight: 700;
    padding: 11px 16px;
}
QPushButton#PrimaryStartBtn:hover {
    background-color: #34D399;
}
QPushButton#PrimaryStartBtn:pressed {
    background-color: #059669;
}

QPushButton#PrimaryStopBtn {
    background-color: #EF4444;
    color: #FFFFFF;
    border: none;
    border-radius: 9px;
    font-size: 14px;
    font-weight: 700;
    padding: 11px 16px;
}
QPushButton#PrimaryStopBtn:hover {
    background-color: #F87171;
}
QPushButton#PrimaryStopBtn:pressed {
    background-color: #DC2626;
}

/* Secondary & Action Buttons */
QPushButton#SecondaryBtn {
    background-color: #192336;
    color: #CBD5E1;
    border: 1px solid #26354D;
    border-radius: 7px;
    font-size: 12px;
    font-weight: 600;
    padding: 6px 12px;
}
QPushButton#SecondaryBtn:hover {
    background-color: #212E45;
    border-color: #334869;
    color: #F8FAFC;
}
QPushButton#SecondaryBtn:pressed {
    background-color: #151E2E;
}
QPushButton#SecondaryBtn:disabled {
    background-color: #111827;
    color: #475569;
    border-color: #1A2436;
}

QPushButton#AccentBtn {
    background-color: #2563EB;
    color: #FFFFFF;
    border: none;
    border-radius: 7px;
    font-size: 12px;
    font-weight: 600;
    padding: 6px 13px;
}
QPushButton#AccentBtn:hover {
    background-color: #3B82F6;
}
QPushButton#AccentBtn:disabled {
    background-color: #1E293B;
    color: #475569;
}

QPushButton#DangerGhostBtn {
    background-color: rgba(239, 68, 68, 0.10);
    color: #FCA5A5;
    border: 1px solid rgba(239, 68, 68, 0.28);
    border-radius: 7px;
    font-size: 12px;
    font-weight: 600;
    padding: 6px 12px;
}
QPushButton#DangerGhostBtn:hover {
    background-color: rgba(239, 68, 68, 0.20);
    border-color: rgba(239, 68, 68, 0.5);
    color: #FFFFFF;
}

/* Segmented Toggle */
QFrame#SegmentedTrack {
    background-color: #0B101B;
    border: 1px solid #1E293B;
    border-radius: 8px;
}
QPushButton#SegmentBtn {
    background-color: transparent;
    color: #94A3B8;
    border: none;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    padding: 6px 8px;
}
QPushButton#SegmentBtn:hover {
    color: #E2E8F0;
    background-color: rgba(255, 255, 255, 0.04);
}
QPushButton#SegmentBtn:checked {
    background-color: #1E2D47;
    color: #38BDF8;
    border: 1px solid #2E456B;
}

/* Filter Chip Buttons */
QPushButton#FilterChip {
    background-color: #111827;
    color: #94A3B8;
    border: 1px solid #223047;
    border-radius: 14px;
    font-size: 12px;
    font-weight: 600;
    padding: 4px 12px;
}
QPushButton#FilterChip:hover {
    color: #E2E8F0;
    border-color: #334869;
}
QPushButton#FilterChip:checked {
    background-color: rgba(56, 189, 248, 0.15);
    color: #38BDF8;
    border: 1px solid rgba(56, 189, 248, 0.45);
}

/* Search Input */
QLineEdit#SearchInput {
    background-color: #0D131F;
    color: #F1F5F9;
    border: 1px solid #223047;
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 13px;
    selection-background-color: #2563EB;
}
QLineEdit#SearchInput:focus {
    border-color: #3B82F6;
}

/* Sliders */
QSlider::groove:horizontal {
    border: none;
    height: 6px;
    background: #0B101B;
    border-radius: 3px;
}
QSlider::sub-page:horizontal {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563EB, stop:1 #06B6D4);
    border-radius: 3px;
}
QSlider::handle:horizontal {
    background: #F8FAFC;
    border: 2px solid #06B6D4;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 8px;
}
QSlider::handle:horizontal:hover {
    background: #38BDF8;
    border-color: #FFFFFF;
}

/* Checkboxes */
QCheckBox {
    color: #CBD5E1;
    spacing: 8px;
    font-size: 12.5px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #334155;
    background-color: #0D131F;
}
QCheckBox::indicator:hover {
    border-color: #38BDF8;
}
QCheckBox::indicator:checked {
    background-color: #2563EB;
    border-color: #3B82F6;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #1E293B;
    border-radius: 10px;
    background-color: #111827;
    top: -1px;
}
QTabBar::tab {
    background-color: #0E1420;
    color: #94A3B8;
    border: 1px solid #1E293B;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    padding: 9px 18px;
    margin-right: 4px;
    font-size: 13px;
    font-weight: 600;
}
QTabBar::tab:hover {
    color: #E2E8F0;
    background-color: #141D2E;
}
QTabBar::tab:selected {
    background-color: #111827;
    color: #38BDF8;
    border-color: #26354D;
    border-top: 2px solid #06B6D4;
}

/* Table View */
QTableView {
    background-color: #0D131F;
    alternate-background-color: #101726;
    color: #E2E8F0;
    gridline-color: #182234;
    border: 1px solid #1E293B;
    border-radius: 8px;
    selection-background-color: rgba(37, 99, 235, 0.25);
    selection-color: #FFFFFF;
    outline: none;
}
QTableView::item {
    padding: 6px 10px;
    border-bottom: 1px solid #151E2E;
}
QTableView::item:hover {
    background-color: rgba(56, 189, 248, 0.06);
}
QHeaderView::section {
    background-color: #141C2B;
    color: #94A3B8;
    padding: 8px 10px;
    border: none;
    border-right: 1px solid #1E293B;
    border-bottom: 1px solid #223047;
    font-size: 11.5px;
    font-weight: 700;
    text-transform: uppercase;
}
QHeaderView::section:hover {
    background-color: #1A2438;
    color: #F1F5F9;
}

/* PlainTextEdit (Realtime Log) */
QPlainTextEdit#LiveConsole {
    background-color: #090D16;
    color: #CBD5E1;
    border: 1px solid #1E293B;
    border-radius: 8px;
    padding: 8px;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
    selection-background-color: #2563EB;
}

/* Scrollbars */
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: #24324A;
    border-radius: 5px;
    min-height: 28px;
}
QScrollBar::handle:vertical:hover {
    background: #364B6E;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 2px;
}
QScrollBar::handle:horizontal {
    background: #24324A;
    border-radius: 5px;
    min-width: 28px;
}
QScrollBar::handle:horizontal:hover {
    background: #364B6E;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QMenu {
    background-color: #151E2E;
    color: #F1F5F9;
    border: 1px solid #2B3B57;
    border-radius: 8px;
    padding: 5px;
}
QMenu::item {
    padding: 7px 18px;
    border-radius: 5px;
}
QMenu::item:selected {
    background-color: #2563EB;
    color: #FFFFFF;
}
"""


def build_theme_qss(check_icon_path: str = "") -> str:
    """Opsiyonel tik ikonu yoluyla tam QSS temasini dondurur."""
    qss = THEME_QSS
    if check_icon_path:
        norm = check_icon_path.replace("\\", "/")
        qss += f"""
QCheckBox::indicator:checked {{
    background-color: #2563EB;
    border-color: #3B82F6;
    image: url("{norm}");
}}
"""
    return qss


def apply_windows_dark_titlebar(window_widget: QWidget) -> None:
    """Windows 10/11 yerel baslik cubugunu koyu tema ile uyumlu hale getirir."""
    try:
        hwnd = int(window_widget.winId())
        dwmapi = ctypes.windll.dwmapi
        dark_val = ctypes.c_int(1)
        # Windows 11 / Win10 20H1+: DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        res = dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(dark_val), ctypes.sizeof(dark_val))
        if res != 0:
            # Eski Win10 derlemeleri icin fallback: 19
            dwmapi.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(dark_val), ctypes.sizeof(dark_val))
        # Windows 11 ozel baslik cubugu rengi (#0B0F17 -> COLORREF 0x00170F0B)
        caption_color = ctypes.c_int(0x00170F0B)
        dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(caption_color), ctypes.sizeof(caption_color))
    except Exception:
        pass


class RadarLogoWidget(QWidget):
    """Baslikta canli donen ozel vektor radar logosu."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedSize(40, 40)
        self._angle = -45.0
        self._active = False
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._tick)

    def set_active(self, active: bool) -> None:
        self._active = active
        if active and not self._timer.isActive():
            self._timer.start()
        elif not active and self._timer.isActive():
            self._timer.stop()
        self.update()

    def _tick(self) -> None:
        self._angle = (self._angle + 5.0) % 360.0
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(2, 2, self.width() - 4, self.height() - 4)
        p.setBrush(QColor("#0F172A"))
        p.setPen(QPen(QColor("#1E3A5F" if not self._active else "#0891B2"), 1.5))
        p.drawRoundedRect(rect, 10, 10)

        cx, cy = self.width() / 2.0, self.height() / 2.0

        # Radar halkalari
        p.setBrush(Qt.BrushStyle.NoBrush)
        for rad, alpha in [(13.0, 90), (8.5, 130), (4.0, 160)]:
            p.setPen(QPen(QColor(56, 189, 248, alpha), 1.0))
            p.drawEllipse(QPointF(cx, cy), rad, rad)

        # Arti eksenleri
        p.setPen(QPen(QColor(56, 189, 248, 45), 1.0))
        p.drawLine(QPointF(cx - 14, cy), QPointF(cx + 14, cy))
        p.drawLine(QPointF(cx, cy - 14), QPointF(cx, cy + 14))

        # Tarama kolu + izi
        sweep_color = QColor("#10B981") if self._active else QColor("#38BDF8")
        if self._active:
            sweep_rect = QRectF(cx - 13, cy - 13, 26, 26)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(16, 185, 129, 55))
            p.drawPie(sweep_rect, int((-self._angle) * 16), int(48 * 16))

        rad_ang = math.radians(self._angle)
        ex = cx + 13.0 * math.cos(rad_ang)
        ey = cy + 13.0 * math.sin(rad_ang)
        p.setPen(QPen(sweep_color, 1.8))
        p.drawLine(QPointF(cx, cy), QPointF(ex, ey))

        # Merkez nokta
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(sweep_color)
        p.drawEllipse(QPointF(cx, cy), 2.3, 2.3)

        # Sabit hedef pingi
        p.setBrush(QColor("#10B981"))
        p.drawEllipse(QPointF(cx + 6.5, cy - 5.5), 2.2, 2.2)


class StatusBadgeWidget(QFrame):
    """Canli tarama durumunu gosteren hap rozet."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("StatusPill")
        self._state = "idle"
        self._pulse = False
        self._timer = QTimer(self)
        self._timer.setInterval(550)
        self._timer.timeout.connect(self._toggle_pulse)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 5, 12, 5)
        layout.setSpacing(7)

        self._dot = QFrame()
        self._dot.setFixedSize(8, 8)
        self._dot.setStyleSheet("background-color: #64748B; border-radius: 4px; border: none;")
        self._label = QLabel("HAZIR")
        self._label.setStyleSheet("font-size: 11.5px; font-weight: 700; letter-spacing: 0.6px; color: #94A3B8; background: transparent; border: none;")

        layout.addWidget(self._dot)
        layout.addWidget(self._label)
        self.set_status("idle")

    def _toggle_pulse(self) -> None:
        self._pulse = not self._pulse
        if self._state == "scanning":
            c = "#34D399" if self._pulse else "#059669"
            self._dot.setStyleSheet(f"background-color: {c}; border-radius: 4px; border: none;")

    def set_status(self, state: str) -> None:
        self._state = state
        if state == "scanning":
            self.setStyleSheet(
                "QFrame#StatusPill { background-color: rgba(16, 185, 129, 0.14); "
                "border: 1px solid rgba(16, 185, 129, 0.45); border-radius: 13px; }"
            )
            self._dot.setStyleSheet("background-color: #10B981; border-radius: 4px; border: none;")
            self._label.setText("AKTIF TARANIYOR")
            self._label.setStyleSheet("font-size: 11.5px; font-weight: 700; letter-spacing: 0.6px; color: #34D399; background: transparent; border: none;")
            if not self._timer.isActive():
                self._timer.start()
        elif state == "stopped":
            self._timer.stop()
            self.setStyleSheet(
                "QFrame#StatusPill { background-color: rgba(245, 158, 11, 0.12); "
                "border: 1px solid rgba(245, 158, 11, 0.35); border-radius: 13px; }"
            )
            self._dot.setStyleSheet("background-color: #F59E0B; border-radius: 4px; border: none;")
            self._label.setText("DURDURULDU")
            self._label.setStyleSheet("font-size: 11.5px; font-weight: 700; letter-spacing: 0.6px; color: #FBBF24; background: transparent; border: none;")
        else:
            self._timer.stop()
            self.setStyleSheet(
                "QFrame#StatusPill { background-color: rgba(100, 116, 139, 0.12); "
                "border: 1px solid rgba(100, 116, 139, 0.30); border-radius: 13px; }"
            )
            self._dot.setStyleSheet("background-color: #64748B; border-radius: 4px; border: none;")
            self._label.setText("HAZIR")
            self._label.setStyleSheet("font-size: 11.5px; font-weight: 700; letter-spacing: 0.6px; color: #94A3B8; background: transparent; border: none;")


class StatCard(QFrame):
    """Ust telemetri seridi icin KPI karti."""

    def __init__(self, title: str, accent_color: str, initial_value: str = "0", subtext: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        self._accent = accent_color

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 11, 14, 11)
        root.setSpacing(3)

        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(6)

        dot = QFrame()
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(f"background-color: {accent_color}; border-radius: 4px; border: none;")

        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setStyleSheet("color: #94A3B8; font-size: 10.5px; font-weight: 700; letter-spacing: 0.6px; border: none;")

        top_row.addWidget(dot)
        top_row.addWidget(self.lbl_title)
        top_row.addStretch()

        self.lbl_value = QLabel(initial_value)
        self.lbl_value.setStyleSheet(
            f"color: #F8FAFC; font-family: 'Consolas', 'Segoe UI', monospace; "
            f"font-size: 22px; font-weight: 700; border: none;"
        )

        self.lbl_sub = QLabel(subtext or " ")
        self.lbl_sub.setStyleSheet(f"color: {accent_color}; font-size: 11px; font-weight: 600; border: none;")

        root.addLayout(top_row)
        root.addWidget(self.lbl_value)
        root.addWidget(self.lbl_sub)

    def set_value(self, value_text: str, sub_text: Optional[str] = None) -> None:
        self.lbl_value.setText(value_text)
        if sub_text is not None:
            self.lbl_sub.setText(sub_text)


class SegmentedToggle(QFrame):
    """Modern segmentli secim kontrolu."""

    changed = pyqtSignal(str)

    def __init__(self, options: List[tuple], default_key: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("SegmentedTrack")
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons: Dict[str, QPushButton] = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

        for key, label in options:
            btn = QPushButton(label)
            btn.setObjectName("SegmentBtn")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if key == default_key:
                btn.setChecked(True)
            btn.clicked.connect(lambda checked, k=key: self._on_click(k))
            self._group.addButton(btn)
            self._buttons[key] = btn
            layout.addWidget(btn)

        self._current = default_key

    def _on_click(self, key: str) -> None:
        if key != self._current:
            self._current = key
            self.changed.emit(key)

    def value(self) -> str:
        return self._current

    def set_value(self, key: str) -> None:
        if key in self._buttons:
            self._buttons[key].setChecked(True)
            self._current = key


class SparklineChartWidget(QWidget):
    """Son 60 olcumdeki anlik tarama hizini (IP/sn) cizen gercek zamanli alan grafigi."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumHeight(96)
        self.setMaximumHeight(110)
        self._samples = deque([0.0] * 60, maxlen=60)
        self._peak = 0.0
        self._current = 0.0

    def push_value(self, val: float) -> None:
        v = max(0.0, float(val))
        self._samples.append(v)
        self._current = v
        self._peak = max(self._samples) if self._samples else 0.0
        self.update()

    def clear_values(self) -> None:
        self._samples = deque([0.0] * 60, maxlen=60)
        self._peak = 0.0
        self._current = 0.0
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = float(self.width()), float(self.height())
        card_rect = QRectF(0.5, 0.5, w - 1.0, h - 1.0)
        p.setBrush(QColor("#0B101B"))
        p.setPen(QPen(QColor("#1E293B"), 1.0))
        p.drawRoundedRect(card_rect, 8, 8)

        # Baslik & tepe hiz etiketleri
        p.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        p.setPen(QColor("#64748B"))
        p.drawText(QRectF(10, 6, w - 20, 16), Qt.AlignmentFlag.AlignLeft, "HIZ GRAFIGI")

        p.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
        p.setPen(QColor("#38BDF8"))
        p.drawText(QRectF(10, 6, w - 20, 16), Qt.AlignmentFlag.AlignRight, f"{self._current:.1f} IP/s  (Max {self._peak:.0f})")

        # Izgara cizgileri
        pad_l, pad_r, pad_t, pad_b = 8.0, 8.0, 26.0, 8.0
        plot_w = max(10.0, w - pad_l - pad_r)
        plot_h = max(10.0, h - pad_t - pad_b)

        p.setPen(QPen(QColor(30, 41, 59, 140), 1.0, Qt.PenStyle.DashLine))
        for ratio in (0.33, 0.66):
            yy = pad_t + plot_h * ratio
            p.drawLine(QPointF(pad_l, yy), QPointF(w - pad_r, yy))

        data = list(self._samples)
        max_val = max(max(data), 10.0) * 1.15
        n = len(data)
        if n < 2:
            return

        points: List[QPointF] = []
        for idx, val in enumerate(data):
            x = pad_l + (idx / (n - 1)) * plot_w
            y = pad_t + plot_h - (val / max_val) * plot_h
            points.append(QPointF(x, y))

        line_path = QPainterPath()
        line_path.moveTo(points[0])
        for pt in points[1:]:
            line_path.lineTo(pt)

        area_path = QPainterPath(line_path)
        area_path.lineTo(QPointF(points[-1].x(), pad_t + plot_h))
        area_path.lineTo(QPointF(points[0].x(), pad_t + plot_h))
        area_path.closeSubpath()

        grad = QLinearGradient(0, pad_t, 0, pad_t + plot_h)
        grad.setColorAt(0.0, QColor(6, 182, 212, 95))
        grad.setColorAt(1.0, QColor(6, 182, 212, 5))
        p.fillPath(area_path, QBrush(grad))

        p.setPen(QPen(QColor("#22D3EE"), 1.8))
        p.drawPath(line_path)

        # Son nokta vurgusu
        last_pt = points[-1]
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(34, 211, 238, 70))
        p.drawEllipse(last_pt, 5.0, 5.0)
        p.setBrush(QColor("#22D3EE"))
        p.drawEllipse(last_pt, 2.5, 2.5)


class HitsTableModel(QAbstractTableModel):
    """Yuksek performansli kesif sonuclari tablo modeli (on binlerce satir icin gecikmesiz)."""

    HEADERS = ["Zaman", "Bölge", "Durum", "URL", "Sayfa Başlığı", "Sunucu", "Süre"]

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._rows: List[Dict[str, Any]] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return row.get("timestamp", "")
            if col == 1:
                return "TR" if row.get("region") == "TR" else "GLOBAL"
            if col == 2:
                status = row.get("status", "")
                text = row.get("status_text", "")
                return f"{status} {text}".strip()
            if col == 3:
                return row.get("url", "")
            if col == 4:
                return row.get("title") or "—"
            if col == 5:
                return row.get("server") or "—"
            if col == 6:
                ms = row.get("elapsed_ms")
                return f"{ms} ms" if ms is not None and ms != "" else "—"

        elif role == Qt.ItemDataRole.UserRole:
            # Siralama ve filtreleme icin ham deger
            if col == 0:
                return row.get("full_timestamp") or row.get("timestamp", "")
            if col == 1:
                return row.get("region", "TR")
            if col == 2:
                return str(row.get("status", ""))
            if col == 6:
                ms = row.get("elapsed_ms")
                return int(ms) if isinstance(ms, (int, float)) else 999999
            return self.data(index, Qt.ItemDataRole.DisplayRole)

        elif role == Qt.ItemDataRole.UserRole + 1:
            return row

        elif role == Qt.ItemDataRole.ToolTipRole:
            if col == 0:
                return row.get("full_timestamp") or row.get("timestamp", "")
            if col in (3, 4, 5):
                return self.data(index, Qt.ItemDataRole.DisplayRole)

        elif role == Qt.ItemDataRole.FontRole:
            if col in (0, 3, 6):
                return QFont("Consolas", 10)

        elif role == Qt.ItemDataRole.ForegroundRole:
            if col == 3:
                return QColor("#60A5FA")
            if col == 0 or col == 6:
                return QColor("#94A3B8")
            if col == 4 and not row.get("title"):
                return QColor("#475569")
            if col == 5 and not row.get("server"):
                return QColor("#475569")

        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 1, 2, 6):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        return None

    def prepend_rows(self, items: List[Dict[str, Any]]) -> None:
        if not items:
            return
        self.beginInsertRows(QModelIndex(), 0, len(items) - 1)
        for item in reversed(items):
            self._rows.insert(0, item)
        self.endInsertRows()

    def set_all_rows(self, items: List[Dict[str, Any]]) -> None:
        self.beginResetModel()
        self._rows = list(items)
        self.endResetModel()

    def clear_rows(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def get_row(self, idx: int) -> Optional[Dict[str, Any]]:
        if 0 <= idx < len(self._rows):
            return self._rows[idx]
        return None


class HitsFilterProxyModel(QSortFilterProxyModel):
    """Anlik metin aramasi, durum kodu ve bolge filtresi saglar."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._search = ""
        self._status_filter = "ALL"
        self._region_filter = "ALL"
        self.setSortRole(Qt.ItemDataRole.UserRole)

    def set_search(self, text: str) -> None:
        self._search = text.strip().lower()
        self.invalidateFilter()

    def set_status_filter(self, status: str) -> None:
        self._status_filter = status
        self.invalidateFilter()

    def set_region_filter(self, region: str) -> None:
        self._region_filter = region
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: HitsTableModel = self.sourceModel()
        row = model.get_row(source_row)
        if not row:
            return False

        if self._status_filter != "ALL":
            if str(row.get("status", "")) != self._status_filter:
                return False

        if self._region_filter != "ALL":
            reg = "TR" if row.get("region") == "TR" else "GLOBAL"
            if reg != self._region_filter:
                return False

        if self._search:
            haystack = " ".join([
                str(row.get("ip", "")),
                str(row.get("url", "")),
                str(row.get("title", "")),
                str(row.get("server", "")),
                str(row.get("status", "")),
            ]).lower()
            if self._search not in haystack:
                return False

        return True


class StatusPillDelegate(QStyledItemDelegate):
    """Tablodaki Bolge ve Durum sutunlarini ozel hap rozet olarak cizer."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        col = index.column()
        if col not in (1, 2):
            super().paint(painter, option, index)
            return

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Secim / hover arkaplani
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor(37, 99, 235, 64))
        elif index.row() % 2 == 1:
            painter.fillRect(option.rect, QColor("#101726"))
        else:
            painter.fillRect(option.rect, QColor("#0D131F"))

        row_data = index.data(Qt.ItemDataRole.UserRole + 1) or {}

        if col == 1:
            is_tr = row_data.get("region") == "TR"
            text = "TR" if is_tr else "GLOBAL"
            bg = QColor(225, 29, 72, 42) if is_tr else QColor(59, 130, 246, 40)
            border = QColor(244, 63, 94, 140) if is_tr else QColor(96, 165, 250, 140)
            fg = QColor("#FDA4AF") if is_tr else QColor("#93C5FD")
            pill_w = 60
        else:
            status = str(row_data.get("status", ""))
            if status == "200":
                text = "200 OK"
                bg = QColor(16, 185, 129, 42)
                border = QColor(16, 185, 129, 160)
                fg = QColor("#34D399")
            elif status == "403":
                text = "403 FORBID"
                bg = QColor(245, 158, 11, 40)
                border = QColor(245, 158, 11, 160)
                fg = QColor("#FBBF24")
            elif status == "401":
                text = "401 AUTH"
                bg = QColor(168, 85, 247, 42)
                border = QColor(168, 85, 247, 160)
                fg = QColor("#D8B4FE")
            else:
                text = status
                bg = QColor(100, 116, 139, 40)
                border = QColor(100, 116, 139, 140)
                fg = QColor("#CBD5E1")
            pill_w = 88

        pill_h = 22
        cx = option.rect.center().x()
        cy = option.rect.center().y()
        pill_rect = QRectF(cx - pill_w / 2.0, cy - pill_h / 2.0, pill_w, pill_h)

        painter.setBrush(bg)
        painter.setPen(QPen(border, 1.0))
        painter.drawRoundedRect(pill_rect, 6, 6)

        painter.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        painter.setPen(fg)
        painter.drawText(pill_rect, Qt.AlignmentFlag.AlignCenter, text)

        painter.restore()


def configure_hits_table(table: QTableView) -> None:
    """Tablo gorunumunu modern tam satir secimli ve akici hale getirir."""
    table.setItemDelegate(StatusPillDelegate(table))
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setAlternatingRowColors(True)
    table.setSortingEnabled(True)
    table.setShowGrid(False)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(34)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    table.setWordWrap(False)

    hdr = table.horizontalHeader()
    hdr.setStretchLastSection(False)
    hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
    hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
    hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
    hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
    hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
    hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
    hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)

    table.setColumnWidth(0, 92)
    table.setColumnWidth(1, 78)
    table.setColumnWidth(2, 108)
    table.setColumnWidth(3, 230)
    table.setColumnWidth(5, 165)
    table.setColumnWidth(6, 76)


class ElidedLabel(QLabel):
    """Sigmayan uzun metinleri sonuna '...' koyarak duzgun kisaltan etiket."""

    def __init__(self, text: str = "", parent: Optional[QWidget] = None):
        super().__init__(text, parent)
        self._full_text = text

    def setText(self, text: str) -> None:
        self._full_text = text
        self._apply_elide()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._apply_elide()

    def _apply_elide(self) -> None:
        w = max(40, self.width() - 4)
        elided = self.fontMetrics().elidedText(self._full_text, Qt.TextElideMode.ElideRight, w)
        super().setText(elided)
