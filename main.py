import sys
import os
import json
import time
import queue
import threading
import subprocess
import winreg
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

from ids_detector import IDSDetector
from risk_scoring import RiskScorer
from ids_logger import IDSLogger

from PySide6.QtCore import Qt, QThread, QTimer, Signal, QSize, QPointF
from PySide6.QtGui import QColor, QPainter, QPen, QBrush, QFont, QIcon, QPixmap, QPolygonF
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton,
    QComboBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QHBoxLayout,
    QGridLayout, QMessageBox, QFileDialog, QCheckBox, QSpinBox, QHeaderView,
    QAbstractItemView, QBoxLayout, QScrollArea, QSizePolicy
)

SCAPY_OK = False
try:
    from scapy.all import sniff, conf, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR
    SCAPY_OK = True
except Exception:
    sniff = conf = IP = IPv6 = TCP = UDP = ICMP = DNS = DNSQR = None

APP_NAME = "NetGuard"
APP_VERSION = "0.7"
MAX_QUEUE = 5000
MAX_TABLE_ROWS = 500
RADAR_MAX_POINTS = 120
RADAR_POINT_TTL = 6.0
UI_INTERVAL_MS = 300
RADAR_INTERVAL_MS = 50
LAYOUT_DIR = Path(__file__).resolve().parent / "layouts"
DEFAULT_LAYOUT = "events_left"
INTERFACE_LAYOUTS = (DEFAULT_LAYOUT, "radar_left", "events_bottom") + tuple(
    f"workspace_{index}" for index in range(1, 11)
)

PROTOCOLS = ["HTTP", "HTTPS", "DNS", "SSH", "FTP", "ICMP", "QUIC", "DHCP", "OTHER"]
PROTOCOL_ANGLE = {protocol: index * 360 / len(PROTOCOLS) for index, protocol in enumerate(PROTOCOLS)}
COLORS = {
    "navy": "#0B3D91",
    "blue": "#2563EB",
    "blue_light": "#EAF2FF",
    "white": "#FFFFFF",
    "text": "#10233F",
    "muted": "#64748B",
    "border": "#D7E2F0",
    "danger": "#DC2626",
    "warning": "#F59E0B",
    "success": "#16A34A",
    "radar": "#0B3D91",
    "radar_bg": "#F7FAFF",
}


def app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.scale(size / 64, size / 64)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(COLORS["navy"]))
        painter.drawPolygon(QPolygonF([
            QPointF(32, 2), QPointF(58, 12), QPointF(54, 40),
            QPointF(44, 53), QPointF(32, 62), QPointF(20, 53),
            QPointF(10, 40), QPointF(6, 12),
        ]))
        painter.setPen(QPen(QColor(COLORS["white"]), 6, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPolyline(QPolygonF([
            QPointF(22, 41), QPointF(22, 20),
            QPointF(42, 41), QPointF(42, 20),
        ]))
        painter.end()
        icon.addPixmap(pixmap)
    return icon


def app_data_dir() -> Path:
    p = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


def default_log_dir() -> Path:
    p = app_data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_settings() -> dict:
    path = app_data_dir() / "settings.json"
    defaults = {
        "language": "kk",
        "log_dir": str(default_log_dir()),
        "save_packets": True,
        "autostart": True,
        "auto_capture": True,
        "selected_iface": "",
        "interface_layout": DEFAULT_LAYOUT,
        "max_table_rows": MAX_TABLE_ROWS,
    }
    if not path.exists():
        save_settings(defaults)
        return defaults
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        defaults.update(data)
    except Exception:
        pass
    return defaults


def save_settings(data: dict):
    (app_data_dir() / "settings.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def set_windows_autostart(enabled: bool):
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

    if getattr(sys, "frozen", False):
        command = f'"{sys.executable}"'
    else:
        command = f'"{sys.executable}" "{Path(__file__).resolve()}"'

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            key_path,
            0,
            winreg.KEY_SET_VALUE
        ) as key:

            if enabled:
                winreg.SetValueEx(
                    key,
                    APP_NAME,
                    0,
                    winreg.REG_SZ,
                    command
                )
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass

    except Exception as e:
        print(f"Autostart error: {e}")


def protocol_for_packet(packet) -> str:
    if not SCAPY_OK:
        return "OTHER"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(TCP):
        ports = {int(packet[TCP].sport), int(packet[TCP].dport)}
        for port, protocol in ((443, "HTTPS"), (80, "HTTP"), (53, "DNS"),
                               (22, "SSH"), (21, "FTP"), (20, "FTP")):
            if port in ports:
                return protocol
    elif packet.haslayer(UDP):
        ports = {int(packet[UDP].sport), int(packet[UDP].dport)}
        if 53 in ports:
            return "DNS"
        if 443 in ports:
            return "QUIC"
        if ports <= {67, 68}:
            return "DHCP"
    return "OTHER"


def transport_for_packet(packet):
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def tcp_flags_for_packet(packet):
    return int(packet[TCP].flags) if packet.haslayer(TCP) else 0


def packet_ips(packet):
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return "", ""


def packet_ports(packet):
    if packet.haslayer(TCP):
        return int(packet[TCP].sport), int(packet[TCP].dport)
    if packet.haslayer(UDP):
        return int(packet[UDP].sport), int(packet[UDP].dport)
    return None, None


def tcp_flags(packet) -> str:
    if packet.haslayer(TCP):
        return str(packet[TCP].flags)
    return ""


def ftp_response_code(packet) -> str:
    """Read only the visible FTP control response code, if present."""
    try:
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
            if payload:
                text = payload.decode("latin-1", errors="ignore")
                for code in ("230", "530"):
                    if code in text:
                        return code
    except Exception:
        pass
    return ""


def packet_size(packet) -> int:
    try:
        return len(packet)
    except Exception:
        return 0


def packet_dns_query(packet) -> str:
    """DNS сұранысындағы домен атауын алу."""
    try:
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname
            if isinstance(qname, bytes):
                return qname.decode("utf-8", errors="ignore").rstrip(".")
            return str(qname).rstrip(".")
    except Exception:
        pass
    return ""

class CaptureWorker(QThread):
    packet_event = Signal(dict)
    status = Signal(str)
    failed = Signal(str)

    def __init__(self, iface: str, event_queue=None):
        super().__init__()
        self.iface = iface
        self.event_queue = event_queue
        self.stop_event = threading.Event()
        self.local_ips = set()
        try:
            obj = conf.ifaces[iface]
            self.local_ips.update(getattr(obj, "ips", []) or [])
        except Exception:
            pass

    def stop(self):
        self.stop_event.set()

    def run(self):
        if not SCAPY_OK:
            self.failed.emit("Scapy/Npcap қолжетімсіз.")
            return

        def callback(packet):
            if self.stop_event.is_set():
                return

            src, dst = packet_ips(packet)
            sport, dport = packet_ports(packet)
            protocol = protocol_for_packet(packet)

            direction = (
                "OUT" if src in self.local_ips
                else "IN" if dst in self.local_ips
                else "OTHER"
            )

            event = {
                "timestamp": time.time(),
                "monotonic_time": time.monotonic(),
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "protocol": protocol,
                "size": packet_size(packet),
                "dns_query": packet_dns_query(packet),
                "transport": transport_for_packet(packet),
                "tcp_flags": tcp_flags_for_packet(packet),
                "dns_is_query": bool(packet.haslayer(DNS) and int(packet[DNS].qr) == 0),
                "flags": tcp_flags(packet),
                "direction": direction,
                "ftp_code": ftp_response_code(packet)
                if protocol == "FTP" else "",
            }

            if self.event_queue is None:
                self.packet_event.emit(event)
            else:
                try:
                    self.event_queue.put_nowait(event)
                except queue.Full:
                    # Keep memory bounded when capture outruns GUI processing.
                    pass

        self.status.emit(f"Тыңдау басталды: {self.iface}")

        try:
            while not self.stop_event.is_set():

                sniff(
                    iface=self.iface,
                    prn=callback,
                    store=False,
                    timeout=1
                )

        except Exception as e:
            if not self.stop_event.is_set():
                self.failed.emit(str(e))

        finally:
            self.status.emit("Тыңдау тоқтатылды")


class RadarWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(380, 380)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.points = deque(maxlen=RADAR_MAX_POINTS)
        self.angle = 0.0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate)
        self.timer.start(RADAR_INTERVAL_MS)

    def add_event(self, protocol: str, status: str):
        self.points.append({
            "protocol": protocol,
            "status": status,
            "created": time.time(),
        })

    def animate(self):
        self.angle = (self.angle + 2.5) % 360
        now = time.time()
        while self.points and now - self.points[0]["created"] > RADAR_POINT_TTL:
            self.points.popleft()
        self.update()

    def sector_color(self, protocol):
        if protocol == "SSH":
            return QColor("#D97706")
        if protocol == "FTP":
            return QColor("#7C3AED")
        return QColor(COLORS["blue"])

    def status_color(self, status):

        if status == "green":
            return QColor(COLORS["success"])

        if status == "red":
            return QColor(COLORS["danger"])

        if status == "yellow":
            return QColor(COLORS["warning"])

        return QColor("#FFFFFF")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        # Радар мен протокол атауларына бос орын
        margin = 65

        size = min(w, h) - 2 * margin
        cx = w / 2
        cy = h / 2
        radius = size / 2

        painter.fillRect(self.rect(), QColor(COLORS["radar_bg"]))

        # -------------------------
        # Radar rings
        # -------------------------

        painter.setPen(QPen(QColor("#8FB3E8"), 1))

        for i in range(1, 6):
            r = radius * i / 5

            painter.drawEllipse(
                int(cx - r),
                int(cy - r),
                int(2 * r),
                int(2 * r)
            )

        # -------------------------
        # Crosshair
        # -------------------------

        painter.setPen(QPen(QColor("#B8CBE6"), 1))

        painter.drawLine(
            int(cx - radius),
            int(cy),
            int(cx + radius),
            int(cy)
        )

        painter.drawLine(
            int(cx),
            int(cy - radius),
            int(cx),
            int(cy + radius)
        )

        # -------------------------
        # Protocol sectors
        # -------------------------

        import math

        for protocol, center_angle in PROTOCOL_ANGLE.items():

            a = math.radians(center_angle)

            x1 = cx + radius * math.cos(a)
            y1 = cy - radius * math.sin(a)

            width = 2 if protocol in ("SSH", "FTP") else 1

            painter.setPen(
                QPen(
                    self.sector_color(protocol),
                    width
                )
            )

            painter.drawLine(
                int(cx),
                int(cy),
                int(x1),
                int(y1)
            )

        # -------------------------
        # Radar sweep
        # -------------------------

        sweep = math.radians(self.angle)

        sx = cx + radius * math.cos(sweep)
        sy = cy - radius * math.sin(sweep)

        painter.setPen(
            QPen(QColor(COLORS["blue"]), 3)
        )

        painter.drawLine(
            int(cx),
            int(cy),
            int(sx),
            int(sy)
        )

        # -------------------------
        # Traffic points
        # -------------------------

        for p in self.points:

            protocol = p["protocol"]

            center_angle = PROTOCOL_ANGLE.get(
                protocol,
                315
            )

            jitter = (
                hash(str(p["created"])) % 26
            ) - 13

            a = math.radians(
                center_angle + jitter
            )

            distance = radius * (
                0.25 +
                (
                    hash(
                        str(p["created"]) +
                        protocol
                    ) % 65
                ) / 100
            )

            px = cx + distance * math.cos(a)
            py = cy - distance * math.sin(a)

            age = time.time() - p["created"]

            alpha = max(
                60,
                int(
                    255 *
                    (
                        1 -
                        age /
                        RADAR_POINT_TTL
                    )
                )
            )

            color = self.status_color(
                p["status"]
            )

            color.setAlpha(alpha)

            painter.setBrush(
                QBrush(color)
            )

            painter.setPen(
                Qt.NoPen
            )

            painter.drawEllipse(
                int(px - 5),
                int(py - 5),
                10,
                10
            )

        # -------------------------
        # Protocol names
        # -------------------------

        # Атаулар шеңберден сәл сыртта,
        # бірақ widget шекарасынан қауіпсіз
        # қашықтықта орналасады.

        label_radius = radius + 20

        painter.setFont(
            QFont(
                "Segoe UI",
                9,
                QFont.Bold
            )
        )

        for protocol, center_angle in PROTOCOL_ANGLE.items():

            a = math.radians(
                center_angle
            )

            lx = (
                cx +
                label_radius *
                math.cos(a)
            )

            ly = (
                cy -
                label_radius *
                math.sin(a)
            )

            fm = painter.fontMetrics()

            text_width = fm.horizontalAdvance(
                protocol
            )

            text_height = fm.height()

            # Әр атауды экран шекарасынан шығармаймыз
            x = int(
                lx -
                text_width / 2
            )

            y = int(
                ly +
                text_height / 3
            )

            x = max(
                4,
                min(
                    x,
                    w - text_width - 4
                )
            )

            y = max(
                text_height,
                min(
                    y,
                    h - 4
                )
            )

            painter.setPen(
                QPen(
                    self.sector_color(
                        protocol
                    )
                )
            )

            painter.drawText(
                x,
                y,
                protocol
            )


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        set_windows_autostart(bool(self.settings.get("autostart", True)))

        self.events = queue.Queue(maxsize=MAX_QUEUE)
        self.worker = None
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_stats = Counter()
        self.source_stats = Counter()
        self.destination_stats = Counter()
        self.threats = deque(maxlen=300)
        self.recent_flows = {}

        self.ids = IDSDetector()
        self.risk_scorer = RiskScorer()
        self.ids_logger = IDSLogger(self.settings.get("log_dir") or default_log_dir())
        self.total_alerts = 0

        self.running = False

        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.setWindowIcon(app_icon())
        self.resize(1280, 820)
        self.sidebar_collapsed = False
        self.nav_icons = {
            "home": "⌂",
            "traffic": "⇄",
            "threats": "⚠️",
            "stats": "▥",
            "settings": "⚙️",
        }
        self.build_ui()
        self.apply_styles()
        self.refresh_adapters()
        self.retranslate()

        self.ui_timer = QTimer(self)
        self.ui_timer.timeout.connect(self.process_batch)
        self.ui_timer.start(UI_INTERVAL_MS)
        QTimer.singleShot(
            1500,
            self.start_automatic_capture
        )

        # Автоматический запуск мониторинга

    def start_automatic_capture(self):
        if not self.settings.get("auto_capture", True):
            return

        selected_iface = self.settings.get(
            "selected_iface", ""
        )

        if not selected_iface:
            self.status_label.setText(
                "Интерфейсті «Баптаулар» бөлімінен таңдаңыз."
            )
            return

        index = self.adapter.findData(selected_iface)

        if index < 0:

            self.status_label.setText(
                "Таңдалған желілік интерфейс табылмады."
            )

            return

        self.adapter.setCurrentIndex(index)

        self.start_capture()

    # ---------- UI ----------
    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        self.root_layout = QHBoxLayout(root)
        self.root_layout.setContentsMargins(0, 0, 0, 0)
        self.root_layout.setSpacing(0)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(235)
        sb = QVBoxLayout(self.sidebar)
        sb.setContentsMargins(14, 18, 14, 14)

        self.menu_button = QPushButton("☰")
        self.menu_button.setObjectName("menuToggle")
        self.menu_button.setFixedHeight(40)
        self.menu_button.clicked.connect(self.toggle_sidebar)
        sb.addWidget(self.menu_button)

        self.logo = QLabel(APP_NAME)
        self.logo.setObjectName("logo")
        sb.addWidget(self.logo)
        sb.addSpacing(20)

        self.nav_buttons = []
        for key in self.nav_icons:
            b = QPushButton()
            b.setObjectName("nav")
            b.setCheckable(True)
            b.setProperty("page", key)
            b.clicked.connect(lambda checked, k=key: self.show_page(k))
            self.nav_buttons.append(b)
            sb.addWidget(b)

        sb.addStretch()
        self.status_label = QLabel()
        self.status_label.setObjectName("sideStatus")
        self.status_label.setWordWrap(True)
        sb.addWidget(self.status_label)
        self.statusBar().setSizeGripEnabled(False)

        self.build_menu_bar()

        self.content = QFrame()
        self.content.setObjectName("content")
        cl = QVBoxLayout(self.content)
        cl.setContentsMargins(28, 24, 28, 24)

        self.page_title = QLabel()
        self.page_title.setObjectName("pageTitle")
        cl.addWidget(self.page_title)

        self.pages = {}
        self.stack_layout = QVBoxLayout()
        cl.addLayout(self.stack_layout)

        self.root_layout.addWidget(self.sidebar)
        self.root_layout.addWidget(self.content, 1)

        self.build_home()
        self.build_traffic()
        self.build_threats()
        self.build_stats()
        self.build_settings()
        self.apply_interface_layout()
        self.show_page("home")

    def build_menu_bar(self):
        bar = self.menuBar()
        self.file_menu = bar.addMenu("")
        self.view_menu = bar.addMenu("")
        self.page_actions = {}
        for key in self.nav_icons:
            menu = self.file_menu if key == "settings" else self.view_menu
            action = menu.addAction("")
            action.setCheckable(True)
            action.triggered.connect(lambda checked, page=key: self.show_page(page))
            self.page_actions[key] = action
        self.fullscreen_action = self.view_menu.addAction("Толық экран (F11)")
        self.fullscreen_action.setShortcut("F11")
        self.fullscreen_action.triggered.connect(
            lambda: self.showNormal() if self.isFullScreen() else self.showFullScreen()
        )
        self.addAction(self.fullscreen_action)
        self.file_menu.addSeparator()
        self.exit_action = self.file_menu.addAction("")
        self.exit_action.triggered.connect(self.close)

    def apply_interface_layout(self):
        preset = self.layout_combo.currentData()
        navigation = preset["navigation"]
        top_menu = navigation == "top"
        status_bar = self.statusBar()
        if top_menu and self.status_label.parentWidget() is self.sidebar:
            self.sidebar.layout().removeWidget(self.status_label)
            status_bar.addWidget(self.status_label, 1)
        elif not top_menu and self.status_label.parentWidget() is status_bar:
            status_bar.removeWidget(self.status_label)
            self.sidebar.layout().addWidget(self.status_label)
        self.status_label.setVisible(top_menu or not self.sidebar_collapsed)
        status_bar.setVisible(top_menu)
        self.menuBar().setVisible(top_menu)
        self.sidebar.setVisible(not top_menu)
        self.root_layout.setDirection(
            QBoxLayout.RightToLeft if navigation == "right"
            else QBoxLayout.LeftToRight
        )
        if "positions" in preset:
            positions = preset["positions"]
        else:
            controls_row = 0 if preset["controls"] == "top" else 3
            positions = {
                "controls": [controls_row, 0, 1, 2],
                "metrics": [1 if controls_row == 0 else 0, 0, 1, 2],
                "radar": [2 if controls_row == 0 else 1, 0, 1, 1],
                "events": [2 if controls_row == 0 else 1, 1, 1, 1],
            }
            if preset["radar"] == "right":
                positions["radar"], positions["events"] = positions["events"], positions["radar"]
            elif preset["radar"] == "top":
                positions["radar"] = [1, 0, 1, 2]
                positions["events"] = [2, 0, 1, 2]
        for widget in self.home_panels.values():
            self.home_layout.removeWidget(widget)
        for index in range(self.home_layout.rowCount()):
            self.home_layout.setRowStretch(index, 0)
        for index in range(self.home_layout.columnCount()):
            self.home_layout.setColumnStretch(index, 0)
        for name, position in positions.items():
            self.home_layout.addWidget(self.home_panels[name], *position)
            if name in ("radar", "events"):
                self.home_layout.setRowStretch(
                    position[0],
                    max(self.home_layout.rowStretch(position[0]), 2 if name == "radar" else 1),
                )
            self.home_layout.setColumnStretch(position[1], 1)

    def interface_layout_changed(self, index):
        self.apply_interface_layout()
        self.settings["interface_layout"] = self.layout_combo.itemData(index, Qt.UserRole + 1)
        save_settings(self.settings)

    def card(self):
        f = QFrame()
        f.setObjectName("card")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(18, 16, 18, 16)
        return f, lay

    def metric_card(self, title):
        f, lay = self.card()
        title_l = QLabel(title)
        title_l.setObjectName("metricTitle")
        value = QLabel("0")
        value.setObjectName("metric")
        lay.addWidget(title_l)
        lay.addWidget(value)
        return f, value

    def save_interface_settings(self, *_):
        self.settings["selected_iface"] = self.settings_adapter.currentData()
        self.settings["auto_capture"] = self.auto_capture_cb.isChecked()

        save_settings(self.settings)

        # Синхронизация интерфейса на главной странице
        if hasattr(self, "adapter"):
            index = self.adapter.findData(
                self.settings["selected_iface"]
            )

            if index >= 0:
                self.adapter.setCurrentIndex(index)

        if not self.running:
            self.status_label.setText("Баптаулар сақталды.")
    
    def build_home(self):
        page = QWidget()
        self.home_layout = QGridLayout(page)

        self.home_controls = QWidget()
        controls_layout = QVBoxLayout(self.home_controls)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        self.adapter = QComboBox()
        self.adapter.setMinimumWidth(180)
        top.addWidget(QLabel("Желілік адаптер:"))
        top.addWidget(self.adapter, 1)

        self.start_btn = QPushButton("Тыңдауды бастау")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self.toggle_capture)
        top.addWidget(self.start_btn)
        controls_layout.addLayout(top)

        self.interface_info = QLabel(
            "Автоматты тыңдалатын желілік интерфейсті "
            "«Баптаулар» бөлімінен таңдаңыз."
        )

        self.interface_info.setWordWrap(True)

        self.interface_info.setStyleSheet("""
            background: #EAF2FF;
            color: #0B3D91;
            padding: 12px;
            border-radius: 8px;
            font-weight: 600;
        """)

        controls_layout.addWidget(self.interface_info)

        metrics_panel = QWidget()
        metrics = QGridLayout(metrics_panel)
        self.m_packets, self.v_packets = self.metric_card("Қабылданған пакеттер")
        self.m_anom, self.v_anom = self.metric_card("Аномалиялар")
        self.m_threat, self.v_threat = self.metric_card("Қауіп белгілері")
        self.m_bytes, self.v_bytes = self.metric_card("Деректер көлемі")
        metrics.addWidget(self.m_packets, 0, 0)
        metrics.addWidget(self.m_anom, 0, 1)
        metrics.addWidget(self.m_threat, 0, 2)
        metrics.addWidget(self.m_bytes, 0, 3)

        radar_card, radar_lay = self.card()
        radar_title = QLabel("Протоколдық радар")
        radar_title.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        radar_lay.addWidget(radar_title, alignment=Qt.AlignLeft | Qt.AlignTop)
        self.radar = RadarWidget()
        radar_lay.addWidget(self.radar, 1)

        info_card, info_lay = self.card()
        info_lay.addWidget(QLabel("Соңғы анықталған оқиғалар"))
        self.home_threat_table = QTableWidget(0, 4)
        self.home_threat_table.setHorizontalHeaderLabels(["Уақыт", "Деңгей", "Протокол", "Белгі"])
        self.configure_table(self.home_threat_table)
        info_lay.addWidget(self.home_threat_table)
        self.home_panels = {
            "controls": self.home_controls, "metrics": metrics_panel,
            "radar": radar_card, "events": info_card,
        }

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(page)
        self.pages["home"] = scroll

    def build_traffic(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        self.traffic_table = QTableWidget(0, 8)
        self.traffic_table.setHorizontalHeaderLabels([
            "Уақыт", "Дереккөз", "Мақсат", "Протокол",
            "Src порт", "Dst порт", "Бағыт", "Өлшем"
        ])
        self.configure_table(self.traffic_table)
        lay.addWidget(self.traffic_table)
        self.pages["traffic"] = page

    def build_threats(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        self.threat_table = QTableWidget(0, 8)
        self.threat_table.setHorizontalHeaderLabels([
            "Уақыт", "Деңгей", "Протокол", "Дереккөз",
            "Мақсат", "Белгі", "Түсіндірме", "Қауіп баллы"
        ])
        self.configure_table(self.threat_table)
        lay.addWidget(self.threat_table)
        self.pages["threats"] = page

    def build_stats(self):
        page = QWidget()
        lay = QVBoxLayout(page)

        grid = QGridLayout()
        self.stats_labels = {}
        for i, key in enumerate(["protocol", "sources", "destinations", "bytes"]):
            f, fl = self.card()
            label = QLabel()
            label.setObjectName("statsText")
            fl.addWidget(label)
            self.stats_labels[key] = label
            grid.addWidget(f, i // 2, i % 2)
        lay.addLayout(grid)

        self.stats_table = QTableWidget(0, 3)
        self.stats_table.setHorizontalHeaderLabels(["Көз / бағыт", "Пакеттер", "Байт"])
        self.configure_table(self.stats_table)
        lay.addWidget(self.stats_table)
        self.pages["stats"] = page

    def build_settings(self):
        page = QWidget()
        lay = QVBoxLayout(page)

        layout_card, layout_lay = self.card()
        layout_lay.addWidget(QLabel("Интерфейс орналасуы"))
        self.layout_combo = QComboBox()
        layout_role = Qt.UserRole + 1
        for layout_id in INTERFACE_LAYOUTS:
            path = LAYOUT_DIR / f"{layout_id}.json"
            preset = json.loads(path.read_text(encoding="utf-8"))
            self.layout_combo.addItem(preset["name"], preset)
            self.layout_combo.setItemData(self.layout_combo.count() - 1, layout_id, layout_role)
        selected_layout = self.settings.get("interface_layout", DEFAULT_LAYOUT)
        index = self.layout_combo.findData(selected_layout, layout_role)
        if index < 0:
            index = self.layout_combo.findData(DEFAULT_LAYOUT, layout_role)
        self.layout_combo.setCurrentIndex(index)
        self.layout_combo.currentIndexChanged.connect(self.interface_layout_changed)
        layout_lay.addWidget(self.layout_combo)
        lay.addWidget(layout_card)

        lang_card, ll = self.card()
        ll.addWidget(QLabel("Интерфейс тілі"))
        self.language_combo = QComboBox()
        self.language_combo.addItem("Қазақша", "kk")
        self.language_combo.addItem("Русский", "ru")
        self.language_combo.addItem("English", "en")
        self.language_combo.setCurrentIndex(max(0, self.language_combo.findData(self.settings.get("language", "kk"))))
        self.language_combo.currentIndexChanged.connect(self.language_changed)
        ll.addWidget(self.language_combo)
        lay.addWidget(lang_card)

        # Выбор сетевого интерфейса

        interface_card, interface_lay = self.card()

        interface_lay.addWidget(
            QLabel("Желілік интерфейсті таңдау")
        )

        self.settings_adapter = QComboBox()
        self.settings_adapter.setMinimumWidth(400)

        interface_lay.addWidget(self.settings_adapter)

        self.auto_capture_cb = QCheckBox(
            "Бағдарлама іске қосылғанда трафикті автоматты тыңдау"
        )

        self.auto_capture_cb.setChecked(
            bool(self.settings.get("auto_capture", True))
        )

        self.auto_capture_cb.stateChanged.connect(
            self.save_interface_settings
        )

        interface_lay.addWidget(self.auto_capture_cb)

        save_interface_btn = QPushButton("Баптауларды сақтау")

        save_interface_btn.clicked.connect(
            self.save_interface_settings
        )

        self.settings_start_btn = QPushButton("Тыңдауды бастау")
        self.settings_start_btn.setObjectName("primary")
        self.settings_start_btn.clicked.connect(self.toggle_settings_capture)
        actions = QHBoxLayout()
        actions.addWidget(save_interface_btn)
        actions.addWidget(self.settings_start_btn)
        interface_lay.addLayout(actions)

        lay.addWidget(interface_card)

        log_card, log_lay = self.card()
        log_lay.addWidget(QLabel("Логтарды сақтау орны"))
        row = QHBoxLayout()
        self.log_path = QLabel(self.settings.get("log_dir", str(default_log_dir())))
        row.addWidget(self.log_path, 1)
        choose = QPushButton("Папканы таңдау")
        choose.clicked.connect(self.choose_log_dir)
        row.addWidget(choose)
        log_lay.addLayout(row)
        lay.addWidget(log_card)

        save_card, save_lay = self.card()
        self.save_packets_cb = QCheckBox("IDS ескертулерін JSONL журналына сақтау")
        self.save_packets_cb.setChecked(bool(self.settings.get("save_ids", self.settings.get("save_packets", True))))
        self.save_packets_cb.stateChanged.connect(self.settings_changed)
        save_lay.addWidget(self.save_packets_cb)

        self.autostart_cb = QCheckBox("Windows іске қосылғанда NetGuard автоматты іске қосылсын")
        self.autostart_cb.setChecked(bool(self.settings.get("autostart", True)))
        self.autostart_cb.stateChanged.connect(self.autostart_changed)
        save_lay.addWidget(self.autostart_cb)
        lay.addWidget(save_card)

        lay.addStretch()
        self.pages["settings"] = page

    def configure_table(self, table):
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

    def apply_styles(self):
        self.setStyleSheet(f"""
            QWidget {{
                background: {COLORS["white"]};
                color: {COLORS["text"]};
                font-family: "Segoe UI";
                font-size: 13px;
            }}
            QFrame#sidebar, QMenuBar, QStatusBar {{
                background: {COLORS["navy"]};
            }}
            QMenuBar {{
                color: {COLORS["white"]};
            }}
            QMenuBar::item:selected {{
                background: {COLORS["blue"]};
            }}
            QMenu {{
                background: {COLORS["white"]};
                color: {COLORS["text"]};
                border: 1px solid {COLORS["border"]};
            }}
            QMenu::item:selected {{
                background: {COLORS["blue_light"]};
            }}
            QLabel {{
                color: {COLORS["text"]};
                background: transparent;
            }}
            QLabel#logo {{
                color: white;
                font-size: 24px;
                font-weight: 800;
            }}
            QLabel#pageTitle {{
                color: {COLORS["navy"]};
                font-size: 25px;
                font-weight: 800;
            }}
            QLabel#sideStatus {{
                color: #D9E7FF;
            }}
            QLabel#metricTitle {{
                color: {COLORS["muted"]};
            }}
            QLabel#metric {{
                color: {COLORS["navy"]};
                font-size: 27px;
                font-weight: 800;
            }}
            QFrame#card {{
                background: #FFFFFF;
                border: 1px solid {COLORS["border"]};
                border-radius: 12px;
            }}
            QPushButton {{
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
                padding: 9px 13px;
                color: {COLORS["text"]};
                background: white;
            }}
            QPushButton:hover {{
                background: {COLORS["blue_light"]};
                border-color: {COLORS["blue"]};
            }}
            QPushButton#primary {{
                background: {COLORS["blue"]};
                color: white;
                border: none;
                font-weight: 700;
            }}
            QPushButton#primary:hover {{
                background: #1D4ED8;
            }}
            QPushButton#nav {{
                background: transparent;
                border: none;
                color: white;
                text-align: left;
                padding: 12px 14px;
                font-weight: 600;
            }}
            QPushButton#nav:hover {{
                background: rgba(255,255,255,0.13);
            }}
            QPushButton#nav:checked {{
                background: white;
                color: {COLORS["navy"]};
            }}
            QPushButton#menuToggle {{
                background: transparent;
                color: white;
                border: 1px solid rgba(255,255,255,0.35);
                font-size: 18px;
            }}
            QComboBox {{
                background: white;
                color: {COLORS["text"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
                padding: 9px 11px;
            }}
            QComboBox QAbstractItemView {{
                background: white;
                color: {COLORS["text"]};
                selection-background-color: {COLORS["blue"]};
                selection-color: white;
            }}
            QTableWidget {{
                background: white;
                alternate-background-color: {COLORS["white"]};
                color: {COLORS["text"]};
                border: 1px solid {COLORS["border"]};
                gridline-color: {COLORS["border"]};
                selection-background-color: {COLORS["blue_light"]};
                selection-color: {COLORS["text"]};
            }}
            QTableCornerButton::section {{
                background: {COLORS["white"]};
                border: 1px solid {COLORS["border"]};
            }}
            QHeaderView::section {{
                background: {COLORS["blue_light"]};
                color: {COLORS["navy"]};
                padding: 9px;
                border: none;
                font-weight: 700;
            }}
            QCheckBox {{
                color: {COLORS["text"]};
                spacing: 8px;
            }}
        """)

    # ---------- navigation ----------
    def toggle_sidebar(self):

        self.sidebar_collapsed = not self.sidebar_collapsed

        if self.sidebar_collapsed:
            self.sidebar.setFixedWidth(72)
            self.logo.hide()
            self.status_label.hide()

            for b in self.nav_buttons:
                key = b.property("page")

                b.setText(self.nav_icons[key])
                b.setToolTip(self.tr(key))
                b.setFixedWidth(44)
                b.setStyleSheet("text-align: center; font-size: 20px;")

        else:
            self.sidebar.setFixedWidth(235)
            self.logo.show()
            self.status_label.show()

            for b in self.nav_buttons:
                b.setFixedWidth(200)
                b.setStyleSheet("text-align: left;")

            self.retranslate()

    def show_page(self, key):
        while self.stack_layout.count():
            item = self.stack_layout.takeAt(0)
            if item.widget():
                item.widget().setParent(None)
        self.stack_layout.addWidget(self.pages[key])
        for b in self.nav_buttons:
            b.setChecked(b.property("page") == key)
        for page, action in self.page_actions.items():
            action.setChecked(page == key)
        self.page_title.setText(self.tr(key))

    # ---------- adapter ----------
    def refresh_adapters(self):

        selected_iface = self.settings.get(
            "selected_iface", ""
        )

        self.adapter.clear()
        self.settings_adapter.clear()

        if not SCAPY_OK:

            self.adapter.addItem(
                "Scapy/Npcap unavailable", ""
            )

            self.settings_adapter.addItem(
                "Scapy/Npcap unavailable", ""
            )

            return

        try:

            for iface in conf.ifaces.values():

                name = getattr(iface, "name", "")
                desc = getattr(iface, "description", "")

                display = desc or name

                if not name:
                    continue

                self.adapter.addItem(display, name)

                self.settings_adapter.addItem(
                    display, name
                )

            # Восстановление ранее выбранного интерфейса

            home_index = self.adapter.findData(selected_iface)

            settings_index = self.settings_adapter.findData(
                selected_iface
            )

            if home_index >= 0:
                self.adapter.setCurrentIndex(home_index)

            if settings_index >= 0:
                self.settings_adapter.setCurrentIndex(settings_index)

        except Exception as e:

            self.adapter.addItem(str(e), "")
            self.settings_adapter.addItem(str(e), "")

    # ---------- capture ----------
    def toggle_capture(self):
        if self.running:
            self.stop_capture()
        else:
            self.start_capture()

    def toggle_settings_capture(self):
        if self.running:
            self.stop_capture()
        else:
            self.start_capture(self.settings_adapter.currentData() or "")

    def start_capture(self, iface=None):
        if self.worker is not None:
            return
        if iface is None:
            iface = self.adapter.currentData()
        if not iface or not SCAPY_OK:
            QMessageBox.warning(self, APP_NAME, "Scapy/Npcap қолжетімсіз немесе адаптер таңдалмаған.")
            return

        self.worker = CaptureWorker(iface, self.events)
        self.worker.packet_event.connect(self.enqueue_event)
        self.worker.status.connect(self.status_label.setText)
        self.worker.failed.connect(self.capture_error)
        self.worker.finished.connect(self.capture_finished)
        self.running = True
        self.update_capture_buttons()
        self.worker.start()

    def stop_capture(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.start_btn.setEnabled(False)
            self.settings_start_btn.setEnabled(False)

    def update_capture_buttons(self):
        label = "Тыңдауды тоқтату" if self.running else "Тыңдауды бастау"
        style_name = "danger" if self.running else "primary"
        for button in (self.start_btn, self.settings_start_btn):
            button.setText(label)
            button.setObjectName(style_name)
            button.setEnabled(True)
            button.style().unpolish(button)
            button.style().polish(button)
            button.update()

    def capture_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.running = False
        self.update_capture_buttons()

    def capture_error(self, message):
        QMessageBox.warning(self, APP_NAME, f"Capture қатесі:\n{message}")

    def enqueue_event(self, event):
        try:
            self.events.put_nowait(event)
        except queue.Full:
            # Drop oldest data under extreme traffic instead of blocking capture.
            try:
                self.events.get_nowait()
                self.events.put_nowait(event)
            except Exception:
                pass

    def process_batch(self):
        processed = 0
        batch_limit = 300
        while processed < batch_limit:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            self.process_event(event)
            processed += 1

        if self.events.empty():
            self.ids.cleanup()
        self.risk_scorer.cleanup()
        if processed:
            self.update_dashboard()

    def process_event(self, e):
        self.total_packets += 1
        self.total_bytes += e["size"]
        p = e["protocol"]
        self.protocol_stats[p] += 1
        if e["src"]:
            self.source_stats[e["src"]] += 1
        if e["dst"]:
            self.destination_stats[e["dst"]] += 1

        status = self.connection_status(e)

        threats = [self.risk_scorer.evaluate(alert) for alert in self.detect_threat(e)]

        for threat in threats:
            self.threats.appendleft(threat)
            self.add_threat_row(threat)
            self.total_alerts += 1
            if self.settings.get("save_ids", self.settings.get("save_packets", True)):
                try:
                    self.ids_logger.write(threat)
                except OSError as error:
                    self.status_label.setText(f"IDS журналын сақтау қатесі: {error}")

        if threats:
            status = "red" if any(t["level"] == "HIGH" for t in threats) else "yellow"

        self.radar.add_event(p, status)

        self.add_traffic_row(e)
        self.update_flow_state(e)

    def connection_status(self, e):
        p = e["protocol"]
        flags = e["flags"]
        if p not in ("SSH", "FTP"):
            return "green"

        if "R" in flags:
            return "red"
        if "S" in flags and "A" not in flags:
            return "white"

        # For SSH, encryption prevents reliable password-result inspection.
        # Established bidirectional/application traffic is treated as active/green.
        if p == "SSH" and ("A" in flags or "P" in flags):
            return "green"

        # FTP control traffic is plaintext, so 230/530 can be recognized.
        if p == "FTP":
            if str(e.get("ftp_code")) == "530":
                return "red"
            if str(e.get("ftp_code")) == "230":
                return "green"
        return "white"


    def detect_threat(self, e):
        return self.ids.detect(e)

    def update_flow_state(self, e):
        if not e["src"] or not e["dst"]:
            return
        key = (e["src"], e["sport"], e["dst"], e["dport"], e["protocol"])
        self.recent_flows[key] = e["timestamp"]
        cutoff = e["timestamp"] - 60
        if len(self.recent_flows) > 5000:
            self.recent_flows = {
                k: v for k, v in self.recent_flows.items() if v >= cutoff
            }

    # ---------- tables ----------
    def add_traffic_row(self, e):
        table = self.traffic_table
        max_rows = int(self.settings.get("max_table_rows", MAX_TABLE_ROWS))
        if table.rowCount() >= max_rows:
            table.removeRow(table.rowCount() - 1)
        table.insertRow(0)
        values = [
            datetime.fromtimestamp(e["timestamp"]).strftime("%H:%M:%S"),
            e["src"],
            e["dst"],
            e["protocol"],
            str(e["sport"] or ""),
            str(e["dport"] or ""),
            e.get("direction", "OTHER"),
            str(e["size"]),
        ]
        for c, value in enumerate(values):
            table.setItem(0, c, QTableWidgetItem(value))

    def add_threat_row(self, t):
        table = self.threat_table
        if table.rowCount() >= 300:
            table.removeRow(table.rowCount() - 1)
        table.insertRow(0)
        values = [
            datetime.fromtimestamp(t["time"]).strftime("%H:%M:%S"),
            t["level"], t["protocol"], t["src"], t["dst"],
            t["indicator"], t["detail"], str(t.get("risk_score", ""))
        ]
        for c, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(t.get("risk_reason", t["detail"]))
            if c == 1:
                if t["level"] == "HIGH":
                    item.setForeground(QColor(COLORS["danger"]))
                elif t["level"] == "MEDIUM":
                    item.setForeground(QColor(COLORS["warning"]))
                else:
                    item.setForeground(QColor(COLORS["blue"]))
            table.setItem(0, c, item)

    def update_dashboard(self):
        self.v_packets.setText(f"{self.total_packets:,}")
        self.v_anom.setText(str(self.total_alerts))
        self.v_threat.setText(str(self.total_alerts))
        self.v_bytes.setText(self.format_bytes(self.total_bytes))

        self.home_threat_table.setRowCount(0)
        for t in list(self.threats)[:10]:
            r = self.home_threat_table.rowCount()
            self.home_threat_table.insertRow(r)
            vals = [
                datetime.fromtimestamp(t["time"]).strftime("%H:%M:%S"),
                t["level"], t["protocol"], t["indicator"]
            ]
            for c, value in enumerate(vals):
                self.home_threat_table.setItem(r, c, QTableWidgetItem(value))

        protocol_text = " | ".join(
            f"{p}: {self.protocol_stats[p]}" for p in PROTOCOLS
        )
        self.stats_labels["protocol"].setText("Протоколдар:\n" + protocol_text)

        top_sources = self.source_stats.most_common(5)
        self.stats_labels["sources"].setText(
            "Көбірек сұраныс жіберген көздер:\n" +
            "\n".join(f"{ip}: {n} пакет" for ip, n in top_sources)
        )

        top_dest = self.destination_stats.most_common(5)
        self.stats_labels["destinations"].setText(
            "Көбірек сұраныс түскен бағыттар:\n" +
            "\n".join(f"{ip}: {n} пакет" for ip, n in top_dest)
        )

        self.stats_labels["bytes"].setText(
            f"Барлық пакет: {self.total_packets:,}\n"
            f"Барлық дерек: {self.format_bytes(self.total_bytes)}"
        )

        self.update_stats_table()

    def update_stats_table(self):
        table = self.stats_table
        table.setRowCount(0)
        merged = Counter()
        for ip, n in self.source_stats.items():
            merged[ip] += n
        for ip, n in self.destination_stats.items():
            merged[ip] += n
        for ip, n in merged.most_common(20):
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(ip))
            table.setItem(r, 1, QTableWidgetItem(str(merged[ip])))
            table.setItem(r, 2, QTableWidgetItem("-"))

    @staticmethod
    def format_bytes(n):
        if n < 1024:
            return f"{n} B"
        if n < 1024**2:
            return f"{n/1024:.1f} KB"
        if n < 1024**3:
            return f"{n/1024**2:.1f} MB"
        return f"{n/1024**3:.2f} GB"

    # ---------- settings ----------
    def language_changed(self):
        self.settings["language"] = self.language_combo.currentData()
        save_settings(self.settings)
        self.retranslate()

    def settings_changed(self):
        self.settings["save_ids"] = self.save_packets_cb.isChecked()
        save_settings(self.settings)

    def autostart_changed(self):
        enabled = self.autostart_cb.isChecked()
        self.settings["autostart"] = enabled
        save_settings(self.settings)
        set_windows_autostart(enabled)

    def choose_log_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "Лог сақтау папкасын таңдаңыз")
        if folder:
            self.ids_logger = IDSLogger(folder)
            self.settings["log_dir"] = folder
            self.log_path.setText(folder)
            save_settings(self.settings)

    def tr(self, key):
        lang = self.settings.get("language", "kk")
        data = {
            "kk": {
                "home": "Басты бет", "traffic": "Желілік трафик",
                "threats": "Анықталған қауіптер", "stats": "Статистика",
                "settings": "Баптаулар",
                "file": "Файл", "view": "Көрініс", "exit": "Шығу",
            },
            "ru": {
                "home": "Главная", "traffic": "Сетевой трафик",
                "threats": "Обнаруженные угрозы", "stats": "Статистика",
                "settings": "Настройки",
                "file": "Файл", "view": "Вид", "exit": "Выход",
            },
            "en": {
                "home": "Dashboard", "traffic": "Network Traffic",
                "threats": "Detected Threats", "stats": "Statistics",
                "settings": "Settings",
                "file": "File", "view": "View", "exit": "Exit",
            },
        }
        return data.get(lang, data["kk"]).get(key, key)

    def retranslate(self):
        self.file_menu.setTitle(self.tr("file"))
        self.view_menu.setTitle(self.tr("view"))
        self.exit_action.setText(self.tr("exit"))
        for key, action in self.page_actions.items():
            action.setText(self.tr(key))

        for b in self.nav_buttons:
            key = b.property("page")

            if self.sidebar_collapsed:
                b.setText(self.nav_icons[key])
                b.setToolTip(self.tr(key))
            else:
                b.setText(self.tr(key))
                b.setToolTip("")

        current = None

        for b in self.nav_buttons:
            if b.isChecked():
                current = b.property("page")
                break

        if current:
            self.page_title.setText(self.tr(current))

    def closeEvent(self, event):
        self.stop_capture()
        if self.worker and self.worker.isRunning():
            self.worker.wait(1500)
        event.accept()



def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(app_icon())
    window = MainWindow()
    window.showFullScreen()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
