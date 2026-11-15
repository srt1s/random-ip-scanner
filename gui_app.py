import asyncio
import csv
import ctypes
import os
import queue
import sys
import threading
import time
import webbrowser
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QPoint, Qt, QTimer
from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QTabWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

try:
    from .paths import ensure_safe_stdio, get_app_dir, get_resource_path
    from .scanner_engine import IPScannerEngine, TurkeyIPPool
    from .ui_widgets import (
        COLORS,
        ElidedLabel,
        HitsFilterProxyModel,
        HitsTableModel,
        RadarLogoWidget,
        SegmentedToggle,
        SparklineChartWidget,
        StatCard,
        StatusBadgeWidget,
        apply_windows_dark_titlebar,
        build_theme_qss,
        configure_hits_table,
    )
except ImportError:
    from paths import ensure_safe_stdio, get_app_dir, get_resource_path
    from scanner_engine import IPScannerEngine, TurkeyIPPool
    from ui_widgets import (
        COLORS,
        ElidedLabel,
        HitsFilterProxyModel,
        HitsTableModel,
        RadarLogoWidget,
        SegmentedToggle,
        SparklineChartWidget,
        StatCard,
        StatusBadgeWidget,
        apply_windows_dark_titlebar,
        build_theme_qss,
        configure_hits_table,
    )


class IPScannerApp(QMainWindow):
    """PyQt6 tabanli modern Rastgele IP Web Tarayici masaustu arayuzu."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Rastgele IP Tarayıcı — Discovery Studio")
        self.resize(1300, 820)
        self.setMinimumSize(1020, 660)

        icon_path = get_resource_path(os.path.join("assets", "app_icon.ico"))
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # Calisma yolu ve dosya yollari (exe yanina kaydedilir)
        self.app_dir = get_app_dir()
        self.txt_path = os.path.join(self.app_dir, "bulunan_ipler.txt")
        self.csv_path = os.path.join(self.app_dir, "bulunan_ipler.csv")

        # TR IP Havuzunu acilista bir kez yukle
        self.tr_pool = TurkeyIPPool()

        # Tarama durum degiskenleri
        self.engine: Optional[IPScannerEngine] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.is_scanning = False
        self.session_id = 0
        self.msg_queue: queue.Queue = queue.Queue()
        self.last_browser_open_time = 0.0
        self.stream_paused = False
        self.stream_filter = "ALL"  # "ALL", "RESP", "HITS"
        self._live_hits_total = 0
        self._dark_titlebar_applied = False

        self._build_ui()
        self._load_csv_archive()

        # Kuyruk isleyici timer (50 ms -> akici 20 FPS toplu guncelleme)
        self.queue_timer = QTimer(self)
        self.queue_timer.setInterval(50)
        self.queue_timer.timeout.connect(self._process_queue)
        self.queue_timer.start()

        # Gecen sure sayaci
        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.setInterval(1000)
        self.elapsed_timer.timeout.connect(self._update_elapsed_clock)
        self._scan_started_mono = 0.0

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._dark_titlebar_applied:
            apply_windows_dark_titlebar(self)
            self._dark_titlebar_applied = True

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("RootCanvas")
        self.setCentralWidget(root)

        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Ust Komuta ve Durum Basligi
        root_layout.addWidget(self._build_header_bar())

        # 2. Govde: Sol Kontrol Paneli + Sag Calisma Alani
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        body_layout.addWidget(self._build_sidebar())
        body_layout.addWidget(self._build_workspace(), 1)

        root_layout.addWidget(body, 1)

    def _build_header_bar(self) -> QFrame:
        header = QFrame()
        header.setObjectName("HeaderBar")
        header.setFixedHeight(64)

        layout = QHBoxLayout(header)
        layout.setContentsMargins(18, 10, 18, 10)
        layout.setSpacing(14)

        self.radar_logo = RadarLogoWidget()
        layout.addWidget(self.radar_logo)

        title_col = QVBoxLayout()
        title_col.setContentsMargins(0, 0, 0, 0)
        title_col.setSpacing(1)

        lbl_app = QLabel("Rastgele IP Tarayıcı")
        lbl_app.setStyleSheet("font-size: 16px; font-weight: 700; color: #F8FAFC; background: transparent;")

        lbl_sub = QLabel("Asenkron IPv4 Web Keşif ve Analiz İstasyonu")
        lbl_sub.setStyleSheet("font-size: 11.5px; color: #64748B; background: transparent;")

        title_col.addWidget(lbl_app)
        title_col.addWidget(lbl_sub)
        layout.addLayout(title_col)

        layout.addStretch()

        # Hedef Havuz Rozeti
        self.lbl_pool_pill = QLabel(self._format_tr_pool_label())
        self.lbl_pool_pill.setStyleSheet(
            "background-color: #141C2B; color: #FDA4AF; border: 1px solid #332232; "
            "border-radius: 13px; padding: 5px 12px; font-size: 11.5px; font-weight: 700;"
        )
        layout.addWidget(self.lbl_pool_pill)

        # Sure sayaci
        self.lbl_clock = QLabel("00:00:00")
        self.lbl_clock.setStyleSheet(
            "background-color: #0D131F; color: #CBD5E1; border: 1px solid #1E293B; "
            "border-radius: 13px; padding: 5px 12px; font-family: 'Consolas', monospace; "
            "font-size: 12px; font-weight: 700;"
        )
        layout.addWidget(self.lbl_clock)

        # Durum Rozeti
        self.status_badge = StatusBadgeWidget()
        layout.addWidget(self.status_badge)

        # Dosya & Klasor Kisayollari
        sep = QFrame()
        sep.setFixedSize(1, 26)
        sep.setStyleSheet("background-color: #1E293B;")
        layout.addWidget(sep)

        btn_txt = QPushButton("TXT Aç")
        btn_txt.setObjectName("SecondaryBtn")
        btn_txt.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_txt.clicked.connect(self._open_txt_file)
        layout.addWidget(btn_txt)

        btn_csv = QPushButton("CSV Aç")
        btn_csv.setObjectName("SecondaryBtn")
        btn_csv.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_csv.clicked.connect(self._open_csv_file)
        layout.addWidget(btn_csv)

        btn_dir = QPushButton("Klasör")
        btn_dir.setObjectName("SecondaryBtn")
        btn_dir.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_dir.setToolTip("Kayıtların bulunduğu klasörü aç")
        btn_dir.clicked.connect(self._open_app_folder)
        layout.addWidget(btn_dir)

        return header

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("SidebarPanel")
        sidebar.setFixedWidth(306)

        outer_layout = QVBoxLayout(sidebar)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        content = QWidget()
        content.setObjectName("SidebarScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # Ana Aksiyon Butonlari
        self.btn_toggle = QPushButton("Taramayı Başlat")
        self.btn_toggle.setObjectName("PrimaryStartBtn")
        self.btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle.clicked.connect(self._toggle_scan)
        layout.addWidget(self.btn_toggle)

        btn_reset = QPushButton("Sayaçları ve Oturumu Sıfırla")
        btn_reset.setObjectName("SecondaryBtn")
        btn_reset.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_reset.clicked.connect(self._reset_session)
        layout.addWidget(btn_reset)

        # Hedef & Kapsam Karti
        scope_card = QFrame()
        scope_card.setObjectName("SectionCard")
        scope_lay = QVBoxLayout(scope_card)
        scope_lay.setContentsMargins(12, 12, 12, 12)
        scope_lay.setSpacing(10)

        lbl_scope = QLabel("HEDEF VE PROTOKOL")
        lbl_scope.setObjectName("SectionTitle")
        scope_lay.addWidget(lbl_scope)

        lbl_reg = QLabel("Hedef Bölge")
        lbl_reg.setObjectName("MutedText")
        scope_lay.addWidget(lbl_reg)

        self.seg_region = SegmentedToggle(
            [("TR", "Türkiye (TR)"), ("GLOBAL", "Tüm Dünya")],
            default_key="TR",
        )
        self.seg_region.changed.connect(self._on_region_changed)
        scope_lay.addWidget(self.seg_region)

        lbl_proto = QLabel("Tarama Protokolü")
        lbl_proto.setObjectName("MutedText")
        scope_lay.addWidget(lbl_proto)

        self.seg_proto = SegmentedToggle(
            [("http", "HTTP :80"), ("https", "HTTPS :443"), ("both", "Her İkisi")],
            default_key="http",
        )
        self.seg_proto.changed.connect(self._on_protocol_changed)
        scope_lay.addWidget(self.seg_proto)

        layout.addWidget(scope_card)

        # Kayit Filtreleri Karti
        filter_card = QFrame()
        filter_card.setObjectName("SectionCard")
        filter_lay = QVBoxLayout(filter_card)
        filter_lay.setContentsMargins(12, 12, 12, 12)
        filter_lay.setSpacing(8)

        lbl_flt = QLabel("KAYDEDİLECEK YANITLAR")
        lbl_flt.setObjectName("SectionTitle")
        filter_lay.addWidget(lbl_flt)

        self.chk_200 = QCheckBox("200 OK (Açık Web Siteleri)")
        self.chk_200.setChecked(True)
        self.chk_200.toggled.connect(self._sync_live_engine_flags)
        filter_lay.addWidget(self.chk_200)

        self.chk_403 = QCheckBox("403 Forbidden (Panel / Kısıtlı)")
        self.chk_403.setChecked(True)
        self.chk_403.toggled.connect(self._sync_live_engine_flags)
        filter_lay.addWidget(self.chk_403)

        self.chk_401 = QCheckBox("401 Unauthorized (Yetki İsteyen)")
        self.chk_401.setChecked(True)
        self.chk_401.toggled.connect(self._sync_live_engine_flags)
        filter_lay.addWidget(self.chk_401)

        layout.addWidget(filter_card)

        # Performans Karti
        perf_card = QFrame()
        perf_card.setObjectName("SectionCard")
        perf_lay = QVBoxLayout(perf_card)
        perf_lay.setContentsMargins(12, 12, 12, 12)
        perf_lay.setSpacing(10)

        lbl_perf = QLabel("MOTOR PERFORMANSI")
        lbl_perf.setObjectName("SectionTitle")
        perf_lay.addWidget(lbl_perf)

        # Eszamanlilik satiri
        conc_row = QHBoxLayout()
        conc_row.addWidget(QLabel("Eşzamanlı İşçi:"))
        conc_row.addStretch()
        self.lbl_conc_val = QLabel("50")
        self.lbl_conc_val.setStyleSheet("color: #38BDF8; font-family: 'Consolas', monospace; font-weight: 700;")
        conc_row.addWidget(self.lbl_conc_val)
        perf_lay.addLayout(conc_row)

        self.slider_conc = QSlider(Qt.Orientation.Horizontal)
        self.slider_conc.setRange(10, 250)
        self.slider_conc.setSingleStep(5)
        self.slider_conc.setPageStep(10)
        self.slider_conc.setValue(50)
        self.slider_conc.valueChanged.connect(lambda v: self.lbl_conc_val.setText(str(v)))
        perf_lay.addWidget(self.slider_conc)

        # Timeout satiri
        to_row = QHBoxLayout()
        to_row.addWidget(QLabel("Zaman Aşımı:"))
        to_row.addStretch()
        self.lbl_timeout_val = QLabel("1.5 sn")
        self.lbl_timeout_val.setStyleSheet("color: #38BDF8; font-family: 'Consolas', monospace; font-weight: 700;")
        to_row.addWidget(self.lbl_timeout_val)
        perf_lay.addLayout(to_row)

        self.slider_timeout = QSlider(Qt.Orientation.Horizontal)
        self.slider_timeout.setRange(5, 50)  # 0.5s .. 5.0s (* 0.1)
        self.slider_timeout.setSingleStep(1)
        self.slider_timeout.setValue(15)
        self.slider_timeout.valueChanged.connect(self._on_timeout_changed)
        perf_lay.addWidget(self.slider_timeout)

        # Otomatik tarayicida ac
        self.chk_auto_open = QCheckBox("200 OK bulunca tarayıcıda aç")
        self.chk_auto_open.setToolTip("Bilgisayarı sekmelerle boğmamak için en fazla 4 saniyede bir yeni sekme açar.")
        perf_lay.addWidget(self.chk_auto_open)

        layout.addWidget(perf_card)

        layout.addStretch()

        # Gercek Zamanli Hiz Grafigi
        self.sparkline = SparklineChartWidget()
        layout.addWidget(self.sparkline)

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)
        return sidebar

    def _build_workspace(self) -> QWidget:
        ws = QWidget()
        layout = QVBoxLayout(ws)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # 1. KPI Telemetri Seridi
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(10)

        self.card_scanned = StatCard("Taranan IP", COLORS["accent_blue"], "0", "Beklemede")
        self.card_200 = StatCard("200 OK", COLORS["emerald"], "0", "%0.00 oran")
        self.card_403 = StatCard("403 Forbidden", COLORS["amber"], "0", "Kısıtlı / Panel")
        self.card_401 = StatCard("401 Auth", COLORS["violet"], "0", "Yetki isteyen")
        self.card_skipped = StatCard("404 / Timeout", COLORS["text_muted"], "0", "T: 0 • 404: 0")
        self.card_speed = StatCard("Tarama Hızı", COLORS["accent_cyan"], "0.0 /s", "Ort: 0.0 IP/s")

        for card in (self.card_scanned, self.card_200, self.card_403, self.card_401, self.card_skipped, self.card_speed):
            kpi_row.addWidget(card, 1)

        layout.addLayout(kpi_row)

        # 2. Ana Sekmeli Calisma Alani
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_discoveries_tab(), "Keşfedilen Siteler (0)")
        self.tabs.addTab(self._build_live_stream_tab(), "Canlı Akış")
        self.tabs.addTab(self._build_archive_tab(), "Kayıt Arşivi (CSV)")
        self.tabs.currentChanged.connect(self._on_tab_changed)

        layout.addWidget(self.tabs, 1)
        return ws

    def _build_discoveries_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Filtre ve Arama Cubugu
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self.live_search = QLineEdit()
        self.live_search.setObjectName("SearchInput")
        self.live_search.setPlaceholderText("IP, URL, sayfa başlığı veya sunucu ara...")
        self.live_search.setClearButtonEnabled(True)
        bar.addWidget(self.live_search, 1)

        self.live_status_group = QButtonGroup(self)
        self.live_status_group.setExclusive(True)
        for key, label in [("ALL", "Tümü"), ("200", "200 OK"), ("403", "403"), ("401", "401")]:
            chip = QPushButton(label)
            chip.setObjectName("FilterChip")
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            if key == "ALL":
                chip.setChecked(True)
            chip.clicked.connect(lambda _, k=key: self.live_proxy.set_status_filter(k))
            self.live_status_group.addButton(chip)
            bar.addWidget(chip)

        sep = QFrame()
        sep.setFixedSize(1, 20)
        sep.setStyleSheet("background-color: #223047;")
        bar.addWidget(sep)

        self.live_region_group = QButtonGroup(self)
        self.live_region_group.setExclusive(True)
        for key, label in [("ALL", "Tüm Bölgeler"), ("TR", "TR"), ("GLOBAL", "Global")]:
            chip = QPushButton(label)
            chip.setObjectName("FilterChip")
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            if key == "ALL":
                chip.setChecked(True)
            chip.clicked.connect(lambda _, k=key: self.live_proxy.set_region_filter(k))
            self.live_region_group.addButton(chip)
            bar.addWidget(chip)

        btn_clear_hits = QPushButton("Listeyi Temizle")
        btn_clear_hits.setObjectName("DangerGhostBtn")
        btn_clear_hits.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_clear_hits.clicked.connect(self._clear_live_hits)
        bar.addWidget(btn_clear_hits)

        layout.addLayout(bar)

        # Tablo Model & View
        self.live_model = HitsTableModel(self)
        self.live_proxy = HitsFilterProxyModel(self)
        self.live_proxy.setSourceModel(self.live_model)
        self.live_search.textChanged.connect(self.live_proxy.set_search)

        self.live_table = QTableView()
        self.live_table.setModel(self.live_proxy)
        configure_hits_table(self.live_table)
        self.live_table.doubleClicked.connect(lambda idx: self._open_table_row(self.live_table, self.live_proxy, idx))
        self.live_table.customContextMenuRequested.connect(
            lambda pos: self._show_table_context_menu(self.live_table, self.live_proxy, pos)
        )
        layout.addWidget(self.live_table, 1)

        # Alt Secim Denetleyicisi (Inspector Bar)
        inspector, self.live_insp_labels, self.live_insp_btns = self._create_inspector_bar()
        self.live_table.selectionModel().selectionChanged.connect(
            lambda *_: self._update_inspector(self.live_table, self.live_proxy, self.live_insp_labels, self.live_insp_btns)
        )
        layout.addWidget(inspector)

        return tab

    def _build_live_stream_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        bar = QHBoxLayout()
        bar.setSpacing(8)

        lbl = QLabel("Akış Filtresi:")
        lbl.setObjectName("MutedText")
        bar.addWidget(lbl)

        self.stream_filter_group = QButtonGroup(self)
        self.stream_filter_group.setExclusive(True)
        for key, text in [("ALL", "Tümü"), ("RESP", "Sadece Yanıtlar"), ("HITS", "Sadece Bulunanlar")]:
            chip = QPushButton(text)
            chip.setObjectName("FilterChip")
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            if key == "ALL":
                chip.setChecked(True)
            chip.clicked.connect(lambda _, k=key: setattr(self, "stream_filter", k))
            self.stream_filter_group.addButton(chip)
            bar.addWidget(chip)

        bar.addStretch()

        self.chk_autoscroll = QCheckBox("Otomatik Kaydır")
        self.chk_autoscroll.setChecked(True)
        bar.addWidget(self.chk_autoscroll)

        self.btn_pause_stream = QPushButton("Akışı Duraklat")
        self.btn_pause_stream.setObjectName("SecondaryBtn")
        self.btn_pause_stream.setCheckable(True)
        self.btn_pause_stream.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_pause_stream.toggled.connect(self._on_stream_pause_toggled)
        bar.addWidget(self.btn_pause_stream)

        btn_clear_log = QPushButton("Ekranı Temizle")
        btn_clear_log.setObjectName("DangerGhostBtn")
        btn_clear_log.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_clear_log.clicked.connect(lambda: self.live_console.clear())
        bar.addWidget(btn_clear_log)

        layout.addLayout(bar)

        self.live_console = QPlainTextEdit()
        self.live_console.setObjectName("LiveConsole")
        self.live_console.setReadOnly(True)
        self.live_console.setMaximumBlockCount(1500)
        self.live_console.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.live_console, 1)

        return tab

    def _build_archive_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        bar = QHBoxLayout()
        bar.setSpacing(8)

        self.archive_search = QLineEdit()
        self.archive_search.setObjectName("SearchInput")
        self.archive_search.setPlaceholderText("Kayıtlı CSV geçmişinde IP, başlık veya sunucu ara...")
        self.archive_search.setClearButtonEnabled(True)
        bar.addWidget(self.archive_search, 1)

        self.arch_status_group = QButtonGroup(self)
        self.arch_status_group.setExclusive(True)
        for key, label in [("ALL", "Tümü"), ("200", "200 OK"), ("403", "403"), ("401", "401")]:
            chip = QPushButton(label)
            chip.setObjectName("FilterChip")
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            if key == "ALL":
                chip.setChecked(True)
            chip.clicked.connect(lambda _, k=key: self.archive_proxy.set_status_filter(k))
            self.arch_status_group.addButton(chip)
            bar.addWidget(chip)

        btn_reload = QPushButton("CSV Yenile")
        btn_reload.setObjectName("SecondaryBtn")
        btn_reload.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_reload.clicked.connect(self._load_csv_archive)
        bar.addWidget(btn_reload)

        layout.addLayout(bar)

        self.archive_model = HitsTableModel(self)
        self.archive_proxy = HitsFilterProxyModel(self)
        self.archive_proxy.setSourceModel(self.archive_model)
        self.archive_search.textChanged.connect(self.archive_proxy.set_search)

        self.archive_table = QTableView()
        self.archive_table.setModel(self.archive_proxy)
        configure_hits_table(self.archive_table)
        self.archive_table.setColumnWidth(0, 166)
        self.archive_table.setColumnWidth(3, 215)
        self.archive_table.setColumnWidth(5, 150)
        self.archive_table.setColumnHidden(6, True)
        self.archive_table.doubleClicked.connect(
            lambda idx: self._open_table_row(self.archive_table, self.archive_proxy, idx)
        )
        self.archive_table.customContextMenuRequested.connect(
            lambda pos: self._show_table_context_menu(self.archive_table, self.archive_proxy, pos)
        )
        layout.addWidget(self.archive_table, 1)

        inspector, self.arch_insp_labels, self.arch_insp_btns = self._create_inspector_bar()
        self.archive_table.selectionModel().selectionChanged.connect(
            lambda *_: self._update_inspector(self.archive_table, self.archive_proxy, self.arch_insp_labels, self.arch_insp_btns)
        )
        layout.addWidget(inspector)

        return tab

    def _create_inspector_bar(self):
        bar = QFrame()
        bar.setObjectName("InspectorBar")
        bar.setFixedHeight(52)

        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(10)

        lbl_info = ElidedLabel("Detay görmek için bir satır seçin veya açmak için çift tıklayın.")
        lbl_info.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        lbl_info.setStyleSheet("color: #94A3B8; font-size: 12.5px; background: transparent;")
        lay.addWidget(lbl_info, 1)

        btn_open = QPushButton("Tarayıcıda Aç")
        btn_open.setObjectName("AccentBtn")
        btn_open.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_open.setEnabled(False)

        btn_copy_url = QPushButton("URL Kopyala")
        btn_copy_url.setObjectName("SecondaryBtn")
        btn_copy_url.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_copy_url.setEnabled(False)

        btn_copy_ip = QPushButton("IP Kopyala")
        btn_copy_ip.setObjectName("SecondaryBtn")
        btn_copy_ip.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_copy_ip.setEnabled(False)

        lay.addWidget(btn_copy_ip)
        lay.addWidget(btn_copy_url)
        lay.addWidget(btn_open)

        btns = {"open": btn_open, "copy_url": btn_copy_url, "copy_ip": btn_copy_ip}
        labels = {"info": lbl_info}
        return bar, labels, btns

    def _update_inspector(self, table: QTableView, proxy: HitsFilterProxyModel, labels: dict, btns: dict) -> None:
        sel = table.selectionModel().selectedRows()
        if not sel:
            labels["info"].setText("Detay görmek için bir satır seçin veya açmak için çift tıklayın.")
            for b in btns.values():
                b.setEnabled(False)
            return

        row = self._get_row_from_proxy(proxy, sel[0])
        if not row:
            return

        url = row.get("url", "")
        ip = row.get("ip", "")
        title = row.get("title") or "Başlık yok"
        server = row.get("server") or "Bilinmeyen sunucu"
        labels["info"].setText(f"{url}   |   {title}   |   {server}")

        for b in btns.values():
            b.setEnabled(True)

        for key in ("open", "copy_url", "copy_ip"):
            try:
                btns[key].clicked.disconnect()
            except Exception:
                pass

        btns["open"].clicked.connect(lambda: webbrowser.open(url))
        btns["copy_url"].clicked.connect(lambda: QApplication.clipboard().setText(url))
        btns["copy_ip"].clicked.connect(lambda: QApplication.clipboard().setText(ip))

    def _get_row_from_proxy(self, proxy: HitsFilterProxyModel, proxy_index) -> Optional[Dict[str, Any]]:
        if not proxy_index.isValid():
            return None
        src_index = proxy.mapToSource(proxy_index)
        model: HitsTableModel = proxy.sourceModel()
        return model.get_row(src_index.row())

    def _open_table_row(self, table: QTableView, proxy: HitsFilterProxyModel, proxy_index) -> None:
        row = self._get_row_from_proxy(proxy, proxy_index)
        if row and row.get("url"):
            webbrowser.open(row["url"])

    def _show_table_context_menu(self, table: QTableView, proxy: HitsFilterProxyModel, pos: QPoint) -> None:
        idx = table.indexAt(pos)
        row = self._get_row_from_proxy(proxy, idx)
        if not row:
            return

        url = row.get("url", "")
        ip = row.get("ip", "")

        menu = QMenu(self)
        act_open = QAction("Tarayıcıda Aç", self)
        act_open.triggered.connect(lambda: webbrowser.open(url))

        act_http = QAction(f"HTTP olarak aç (http://{ip}/)", self)
        act_http.triggered.connect(lambda: webbrowser.open(f"http://{ip}/"))

        act_https = QAction(f"HTTPS olarak aç (https://{ip}/)", self)
        act_https.triggered.connect(lambda: webbrowser.open(f"https://{ip}/"))

        act_copy_url = QAction("URL Kopyala", self)
        act_copy_url.triggered.connect(lambda: QApplication.clipboard().setText(url))

        act_copy_ip = QAction("IP Adresini Kopyala", self)
        act_copy_ip.triggered.connect(lambda: QApplication.clipboard().setText(ip))

        menu.addAction(act_open)
        menu.addSeparator()
        menu.addAction(act_http)
        menu.addAction(act_https)
        menu.addSeparator()
        menu.addAction(act_copy_url)
        menu.addAction(act_copy_ip)
        menu.exec(table.viewport().mapToGlobal(pos))

    def _format_tr_pool_label(self) -> str:
        millions = self.tr_pool.total_ips / 1_000_000.0 if self.tr_pool.total_ips else 16.8
        return f"TR HAVUZU • {millions:.1f}M IP"

    def _on_region_changed(self, region: str) -> None:
        if region == "TR":
            self.lbl_pool_pill.setText(self._format_tr_pool_label())
            self.lbl_pool_pill.setStyleSheet(
                "background-color: #141C2B; color: #FDA4AF; border: 1px solid #332232; "
                "border-radius: 13px; padding: 5px 12px; font-size: 11.5px; font-weight: 700;"
            )
        else:
            self.lbl_pool_pill.setText("GLOBAL HAVUZ • 3.7B+ IP")
            self.lbl_pool_pill.setStyleSheet(
                "background-color: #141C2B; color: #93C5FD; border: 1px solid #1E3A5F; "
                "border-radius: 13px; padding: 5px 12px; font-size: 11.5px; font-weight: 700;"
            )
        if self.engine and self.is_scanning:
            self.engine.target_region = region

    def _on_protocol_changed(self, proto: str) -> None:
        if self.engine and self.is_scanning:
            self.engine.scan_mode = proto

    def _on_timeout_changed(self, raw_val: int) -> None:
        sec = raw_val / 10.0
        self.lbl_timeout_val.setText(f"{sec:.1f} sn")
        if self.engine and self.is_scanning:
            self.engine.timeout_sec = sec

    def _sync_live_engine_flags(self) -> None:
        if self.engine and self.is_scanning:
            self.engine.record_200 = self.chk_200.isChecked()
            self.engine.record_403 = self.chk_403.isChecked()
            self.engine.record_401 = self.chk_401.isChecked()

    def _on_stream_pause_toggled(self, paused: bool) -> None:
        self.stream_paused = paused
        self.btn_pause_stream.setText("Akışı Devam Ettir" if paused else "Akışı Duraklat")

    def _toggle_scan(self) -> None:
        if not self.is_scanning:
            self._start_scan()
        else:
            self._stop_scan()

    def _start_scan(self) -> None:
        self.is_scanning = True
        self.session_id += 1
        sid = self.session_id

        self.btn_toggle.setText("Taramayı Durdur")
        self.btn_toggle.setObjectName("PrimaryStopBtn")
        self.btn_toggle.style().unpolish(self.btn_toggle)
        self.btn_toggle.style().polish(self.btn_toggle)

        self.status_badge.set_status("scanning")
        self.radar_logo.set_active(True)
        self.slider_conc.setEnabled(False)

        self._scan_started_mono = time.perf_counter()
        self.elapsed_timer.start()

        engine = IPScannerEngine(
            txt_log_path=self.txt_path,
            csv_log_path=self.csv_path,
            on_result=lambda res, is_hit, s=sid: self.msg_queue.put(("RESULT", s, res, is_hit)),
            on_stat_update=lambda st, s=sid: self.msg_queue.put(("STATS", s, st)),
            tr_pool=self.tr_pool,
        )
        engine.concurrency = self.slider_conc.value()
        engine.timeout_sec = self.slider_timeout.value() / 10.0
        engine.scan_mode = self.seg_proto.value()
        engine.target_region = self.seg_region.value()
        engine.record_200 = self.chk_200.isChecked()
        engine.record_403 = self.chk_403.isChecked()
        engine.record_401 = self.chk_401.isChecked()
        self.engine = engine

        def run_worker_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(engine.run_async_scan())
            except Exception:
                pass
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

        self.scan_thread = threading.Thread(target=run_worker_loop, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self) -> None:
        self.is_scanning = False
        self.elapsed_timer.stop()
        self.radar_logo.set_active(False)
        self.status_badge.set_status("stopped")
        self.slider_conc.setEnabled(True)

        self.btn_toggle.setText("Taramayı Başlat")
        self.btn_toggle.setObjectName("PrimaryStartBtn")
        self.btn_toggle.style().unpolish(self.btn_toggle)
        self.btn_toggle.style().polish(self.btn_toggle)

        if self.engine:
            self.engine.stop()

    def _reset_session(self) -> None:
        was_running = self.is_scanning
        if was_running:
            self._stop_scan()

        self.session_id += 1
        while not self.msg_queue.empty():
            try:
                self.msg_queue.get_nowait()
            except queue.Empty:
                break

        self._live_hits_total = 0
        self.live_model.clear_rows()
        self.live_console.clear()
        self.sparkline.clear_values()
        self.lbl_clock.setText("00:00:00")
        self.status_badge.set_status("idle")
        self.tabs.setTabText(0, "Keşfedilen Siteler (0)")

        self.card_scanned.set_value("0", "Beklemede")
        self.card_200.set_value("0", "%0.00 oran")
        self.card_403.set_value("0", "Kısıtlı / Panel")
        self.card_401.set_value("0", "Yetki isteyen")
        self.card_skipped.set_value("0", "T: 0 • 404: 0")
        self.card_speed.set_value("0.0 /s", "Ort: 0.0 IP/s")

    def _update_elapsed_clock(self) -> None:
        if not self.is_scanning:
            return
        sec = max(0, int(time.perf_counter() - self._scan_started_mono))
        h, rem = divmod(sec, 3600)
        m, s = divmod(rem, 60)
        self.lbl_clock.setText(f"{h:02d}:{m:02d}:{s:02d}")

    def _process_queue(self) -> None:
        batch_limit = 120
        processed = 0
        new_hits: List[Dict[str, Any]] = []
        stream_items: List[tuple] = []
        latest_stats: Optional[Dict[str, Any]] = None

        while processed < batch_limit:
            try:
                msg = self.msg_queue.get_nowait()
            except queue.Empty:
                break

            kind = msg[0]
            sid = msg[1]
            if sid != self.session_id:
                processed += 1
                continue

            if kind == "STATS":
                latest_stats = msg[2]
            elif kind == "RESULT":
                result, is_hit = msg[2], msg[3]
                stream_items.append((result, is_hit))
                if is_hit:
                    new_hits.append(result)
            processed += 1

        if latest_stats:
            self._update_stats_ui(latest_stats)

        if new_hits:
            self.live_model.prepend_rows(new_hits)
            self._live_hits_total += len(new_hits)
            self.tabs.setTabText(0, f"Keşfedilen Siteler ({self._live_hits_total:,})")

            # 200 OK otomatik tarayicida acma
            if self.chk_auto_open.isChecked():
                for hit in new_hits:
                    if hit.get("status") == 200:
                        now = time.time()
                        if now - self.last_browser_open_time > 4.0:
                            self.last_browser_open_time = now
                            webbrowser.open(hit.get("url", ""))
                            break

        if stream_items and not self.stream_paused:
            self._append_stream_batch(stream_items)

    def _update_stats_ui(self, stats: Dict[str, Any]) -> None:
        scanned = stats.get("scanned", 0)
        h200 = stats.get("hits_200", 0)
        h403 = stats.get("hits_403", 0)
        h401 = stats.get("hits_401", 0)
        timeouts = stats.get("timeouts", 0)
        n404 = stats.get("not_found_404", 0)
        errs = stats.get("errors", 0)
        avg_spd = stats.get("speed", 0.0)
        inst_spd = stats.get("instant_speed", avg_spd)

        hit_pct = (h200 / scanned * 100.0) if scanned > 0 else 0.0
        reg_lbl = "Türkiye havuzu" if stats.get("region") == "TR" else "Global havuz"

        self.card_scanned.set_value(f"{scanned:,}", reg_lbl)
        self.card_200.set_value(f"{h200:,}", f"%{hit_pct:.2f} oran")
        self.card_403.set_value(f"{h403:,}", "Kısıtlı / Panel")
        self.card_401.set_value(f"{h401:,}", "Yetki isteyen")
        self.card_skipped.set_value(f"{timeouts + n404 + errs:,}", f"T:{timeouts:,} • 404:{n404:,}")
        self.card_speed.set_value(f"{inst_spd:.1f} /s", f"Ort: {avg_spd:.1f} IP/s")

        self.sparkline.push_value(inst_spd)

    def _append_stream_batch(self, items: List[tuple]) -> None:
        cursor = self.live_console.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        appended = False
        for res, is_hit in items:
            status = res.get("status")
            if self.stream_filter == "HITS" and not is_hit:
                continue
            if self.stream_filter == "RESP" and status in ("TIMEOUT", "CONN_REFUSED", "SSL_ERROR", "ERR"):
                continue

            ts = res.get("timestamp", "--:--:--")
            ip = res.get("ip", "")
            proto = res.get("proto", "http")
            reg = "TR " if res.get("region") == "TR" else "GLB"

            fmt = QTextCharFormat()
            if status == 200:
                fmt.setForeground(QColor("#34D399"))
                title = res.get("title") or "Başlık yok"
                line = f"[{ts}] [200 OK    ] [{reg}] {proto}://{ip:<15}  -> {title}\n"
            elif status == 403:
                fmt.setForeground(QColor("#FBBF24"))
                srv = res.get("server") or "Bilinmiyor"
                line = f"[{ts}] [403 FORBID] [{reg}] {proto}://{ip:<15}  -> Sunucu: {srv}\n"
            elif status == 401:
                fmt.setForeground(QColor("#C084FC"))
                line = f"[{ts}] [401 AUTH  ] [{reg}] {proto}://{ip:<15}  -> Kimlik doğrulama\n"
            elif status == 404:
                fmt.setForeground(QColor("#64748B"))
                line = f"[{ts}] [404 NOTFND] [{reg}] {proto}://{ip:<15}\n"
            elif status == "TIMEOUT":
                fmt.setForeground(QColor("#475569"))
                line = f"[{ts}] [TIMEOUT   ] [{reg}] {proto}://{ip:<15}\n"
            else:
                fmt.setForeground(QColor("#94A3B8"))
                line = f"[{ts}] [{str(status):<10}] [{reg}] {proto}://{ip:<15}\n"

            cursor.insertText(line, fmt)
            appended = True

        if appended and self.chk_autoscroll.isChecked():
            sb = self.live_console.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _on_tab_changed(self, index: int) -> None:
        if index == 2:
            self._load_csv_archive()

    def _clear_live_hits(self) -> None:
        self.live_model.clear_rows()
        self._live_hits_total = 0
        self.tabs.setTabText(0, "Keşfedilen Siteler (0)")

    def _load_csv_archive(self) -> None:
        rows: List[Dict[str, Any]] = []
        if os.path.exists(self.csv_path):
            try:
                with open(self.csv_path, mode="r", encoding="utf-8-sig", newline="") as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    for cols in reader:
                        if not cols:
                            continue
                        # Hem eski 9 sutunlu hem yeni 10 sutunlu formati destekle
                        if len(cols) >= 10:
                            ts_full, region, ip, port, proto, status, status_text, title, server, url = cols[:10]
                        elif len(cols) >= 9:
                            ts_full, ip, port, proto, status, status_text, title, server, url = cols[:9]
                            region = "GLOBAL"
                        else:
                            continue

                        ts_short = ts_full.split(" ")[1] if " " in ts_full else ts_full
                        try:
                            st_val: Any = int(status)
                        except ValueError:
                            st_val = status

                        rows.append({
                            "timestamp": ts_full,
                            "full_timestamp": ts_full,
                            "region": "TR" if region.upper() == "TR" else "GLOBAL",
                            "ip": ip,
                            "port": port,
                            "proto": proto.lower(),
                            "status": st_val,
                            "status_text": status_text,
                            "title": title,
                            "server": server,
                            "url": url,
                            "elapsed_ms": None,
                        })
            except Exception:
                pass

        rows.reverse()  # En son bulunanlar en ustte
        self.archive_model.set_all_rows(rows)
        self.tabs.setTabText(2, f"Kayıt Arşivi ({len(rows):,})")

    def _open_txt_file(self) -> None:
        if not os.path.exists(self.txt_path):
            with open(self.txt_path, "w", encoding="utf-8") as f:
                f.write("=== BULUNAN AKTIF IP LISTESI ===\n\n")
        os.startfile(self.txt_path)

    def _open_csv_file(self) -> None:
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Tarih", "Bolge", "IP", "Port", "Protokol",
                    "Durum Kodu", "Durum Aciklama", "Sayfa Basligi", "Web Sunucusu", "URL"
                ])
        os.startfile(self.csv_path)

    def _open_app_folder(self) -> None:
        os.startfile(self.app_dir)

    def closeEvent(self, event) -> None:
        if self.is_scanning:
            self._stop_scan()
        self.queue_timer.stop()
        self.elapsed_timer.stop()
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=0.35)
        event.accept()


def launch_gui() -> int:
    ensure_safe_stdio()

    # Windows gorev cubugu simge gruplamasi icin AppUserModelID
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("RandomIPScanner.DiscoveryStudio.v2")
    except Exception:
        pass

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    check_path = get_resource_path(os.path.join("assets", "check.png"))
    app.setStyleSheet(build_theme_qss(check_path if os.path.exists(check_path) else ""))

    icon_path = get_resource_path(os.path.join("assets", "app_icon.ico"))
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = IPScannerApp()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(launch_gui())
