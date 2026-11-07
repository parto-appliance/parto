#!/usr/bin/env python3
"""The native OVERLAY welcome/setup flow for a fresh VM."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from PyQt5 import QtCore, QtGui, QtWidgets

# The shared customer portal theme. This launcher runs as the kiosk user; privileged
# operations live in immutable, fixed-purpose helpers.
APP = Path("/home/overlay/BootScript")
sys.path.insert(0, str(APP if APP.is_dir() else Path(__file__).resolve().parents[2] / "src"))
from gui_v2 import theme
from vm_console import error_text, status_text, validate_page, review_text, registration_code
from vm_import import read_settings as read_import_settings

HOLD = Path("/etc/parto/vm-identity-hold.json")
DEVICE = Path("/etc/parto/device.json")
STATUS = Path("/run/parto-vm/bootstrap-status.json")
ACCESS = Path("/etc/parto/vm-access-ready")
READY = Path("/etc/parto/vm-network-ready")
ASSETS = Path("/opt/splash")


def read_json(path):
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def snapshot():
    """Run probes on a worker, never the paint/input thread."""
    result = {"hold": HOLD.exists(), "status": read_json(STATUS),
              "device": read_json(DEVICE), "settings": read_json(READY),
              "access_ready": ACCESS.exists(), "adapters": [], "identity_ready": False, "network": "Checking the virtual adapters…"}
    if result["hold"]:
        return result
    if not result["settings"]:
        result["import_settings"] = read_import_settings()
    try:
        guard = subprocess.run(["systemctl", "is-active", "--quiet", "parto-vm-identity.service"],
                               capture_output=True, timeout=3)
        result["identity_ready"] = guard.returncode == 0
        adapters = json.loads(subprocess.check_output(["ip", "-j", "-4", "address", "show"], text=True, timeout=3))
        lines = []
        names = sorted(p.name for p in Path("/sys/class/net").iterdir() if (p / "device").exists() and (p / "type").read_text().strip() == "1")
        result["adapters"] = names
        roles = {row["name"]: row["role"] for row in result["settings"].get("interfaces", [])}
        for name in names:
            role = roles.get(name, "Not configured")
            adapter = next((item for item in adapters if item.get("ifname") == name), {})
            addresses = ["%s/%s" % (item["local"], item["prefixlen"]) for item in adapter.get("addr_info", []) if item.get("family") == "inet"]
            lines.append("%s · %s: %s" % (role, name, ", ".join(addresses) or "no IPv4 address"))
        result["network"] = "\n".join(lines)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        result["network"] = "Check that one to eight virtual Ethernet adapters are attached."
    return result


class Probe(QtCore.QThread):
    updated = QtCore.pyqtSignal(dict)

    def run(self):
        self.updated.emit(snapshot())


class Operation(QtCore.QThread):
    completed = QtCore.pyqtSignal(bool, str)

    def __init__(self, settings=None, parent=None):
        super().__init__(parent)
        self.settings = settings

    def run(self):
        try:
            if self.settings is not None:
                out = subprocess.run(["sudo", "-n", "/usr/bin/python3", "-I", "/usr/local/libexec/console-vm-network", "apply"],
                                     input=json.dumps(self.settings), capture_output=True, text=True, timeout=240)
                answer = json.loads(out.stdout)
                if out.returncode or not answer.get("ok"):
                    self.completed.emit(False, str(answer.get("error", "network_apply_failed")))
                    return
            out = subprocess.run(["sudo", "-n", "systemctl", "--no-block", "start", "parto-vm-bootstrap.service"],
                                 capture_output=True, text=True, timeout=15)
            self.completed.emit(out.returncode == 0, "" if out.returncode == 0 else "setup_failed")
        except (OSError, ValueError, subprocess.SubprocessError):
            self.completed.emit(False, "network_apply_failed" if self.settings is not None else "setup_failed")


class AccessOperation(QtCore.QThread):
    completed = QtCore.pyqtSignal(bool, str)
    def __init__(self, password, parent=None):
        super().__init__(parent)
        self.password = password
    def run(self):
        try:
            out = subprocess.run(["sudo", "-n", "/usr/bin/python3", "-I", "/usr/local/libexec/console-vm-access", "apply"],
                                 input=json.dumps({"password": self.password}), capture_output=True, text=True, timeout=65)
            answer = json.loads(out.stdout)
            self.completed.emit(out.returncode == 0 and bool(answer.get("ok")), "password_apply_failed")
        except (OSError, ValueError, subprocess.SubprocessError):
            self.completed.emit(False, "password_apply_failed")
        finally:
            self.password = None


def open_application():
    os.execv("/usr/bin/python3", ["python3", str(APP / "Boot-Menu.py")])


class Console(QtWidgets.QWidget):
    PAGES = ("Welcome", "Root password", "Network interfaces", "Review", "Setting up this unit")

    def __init__(self, *, live=True, launch=open_application, assets=ASSETS, splash_ms=1200):
        super().__init__()
        self.live, self.launch, self.assets = live, launch, Path(assets)
        self.page, self.busy, self.held, self.identity_ready = 0, False, False, False
        self.job = self.probe = None
        self.retry_settings = None
        self.operation_error = ""
        self.progress_failed = False
        self.launch_pending = False
        self.settings_loaded = False
        self.current_snapshot = {}
        self.access_ready = False
        self.adapter_names = []
        self.interface_rows = {}
        self.visible_adapters = set()
        self.counts_selected = False
        self.setWindowTitle("OVERLAY Virtual Appliance")
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.FramelessWindowHint)
        self.setCursor(QtCore.Qt.ArrowCursor)
        self.setStyleSheet(theme.WINDOW_QSS + f"""
            QLabel {{ font-size: 11pt; }}
            QLabel[role='section'] {{ font-size: 17pt; font-weight: 600; }}
            QPushButton, QLineEdit, QComboBox {{ font-size: 11pt; padding: 8px 12px; }}
            QFrame[role='card'] {{ background: {theme.CARD}; border: 1px solid {theme.LINE}; border-radius: 8px; }}
            QProgressBar {{ border: 1px solid {theme.LINE}; border-radius: 6px; background: {theme.CARD2}; height: 10px; }}
            QProgressBar::chunk {{ background: {theme.ACCENT2}; }}
        """)
        outer = QtWidgets.QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.stack = QtWidgets.QStackedWidget()
        outer.addWidget(self.stack)
        self._build_splash()
        self._build_wizard()
        self.stack.setCurrentIndex(0)
        self.splash_timer = QtCore.QTimer(self)
        self.splash_timer.setSingleShot(True)
        self.splash_timer.timeout.connect(self.show_wizard)
        self.splash_timer.start(splash_ms)
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh)
        if live:
            self.timer.start(2500)
            self.refresh()
        self.show_page(0)

    @staticmethod
    def label(text="", role=None):
        item = QtWidgets.QLabel(text)
        item.setWordWrap(True)
        if role:
            item.setProperty("role", role)
        return item

    def _build_splash(self):
        page = QtWidgets.QWidget()
        page.setStyleSheet("background: black;")
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.splash = QtWidgets.QLabel()
        # A pixmap's size hint must not pin the whole stacked window to the
        # previous console resolution when VMware changes its display size.
        self.splash.setSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Ignored)
        self.splash.setMinimumSize(0, 0)
        self.splash.setAlignment(QtCore.Qt.AlignCenter)
        self.splash_pixmap = QtGui.QPixmap(str(self.assets / "splash-quiet.png"))
        layout.addWidget(self.splash)
        self.stack.addWidget(page)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not self.splash_pixmap.isNull():
            self.splash.setPixmap(self.splash_pixmap.scaled(self.size(), QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation))

    def _build_wizard(self):
        screen = QtWidgets.QWidget()
        centered = QtWidgets.QVBoxLayout(screen)
        centered.setContentsMargins(24, 18, 24, 18)
        centered.addStretch(1)
        panel = QtWidgets.QWidget()
        self.panel = panel
        panel.setMaximumWidth(900)
        panel.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        panel_row = QtWidgets.QHBoxLayout()
        panel_row.addStretch(0)
        panel_row.addWidget(panel, 1)
        panel_row.addStretch(0)
        centered.addLayout(panel_row, 6)
        centered.addStretch(1)
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        head = QtWidgets.QHBoxLayout()
        logo = QtWidgets.QLabel()
        pix = QtGui.QPixmap(str(self.assets / "logo-badge.png"))
        if not pix.isNull():
            logo.setPixmap(pix.scaledToHeight(48, QtCore.Qt.SmoothTransformation))
        head.addWidget(logo)
        titles = QtWidgets.QVBoxLayout()
        brand = self.label("OVERLAY Virtual Appliance")
        brand.setStyleSheet("font-size: 20pt; font-weight: 600;")
        titles.addWidget(brand)
        titles.addWidget(self.label("OVERLAY virtual appliance", "muted"))
        head.addLayout(titles)
        head.addStretch()
        self.step = self.label("", "muted")
        head.addWidget(self.step)
        layout.addLayout(head)
        self.heading = self.label("Welcome", "section")
        layout.addWidget(self.heading)
        self.pages = QtWidgets.QStackedWidget()
        # Each page owns its scrolling; hidden interface cards cannot enlarge Welcome.
        self.scroll = self.pages
        layout.addWidget(self.pages, 1)
        self._welcome_page()
        self._access_page()
        self._interfaces_page()
        self._review_page()
        self._progress_page()
        self.notice = self.label("", "muted")
        self.notice.setMinimumHeight(36)
        layout.addWidget(self.notice)
        footer = QtWidgets.QHBoxLayout()
        self.back = QtWidgets.QPushButton("Back")
        self.back.clicked.connect(self.go_back)
        footer.addWidget(self.back)
        footer.addStretch()
        self.next = QtWidgets.QPushButton("Next")
        self.next.setProperty("variant", "primary")
        self.next.clicked.connect(self.go_next)
        footer.addWidget(self.next)
        layout.addLayout(footer)
        self.stack.addWidget(screen)

    def _page(self):
        page = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(12)
        if self.pages.count() == 0:
            self.pages.addWidget(page)
        else:
            scroll = QtWidgets.QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
            scroll.setWidget(page)
            self.pages.addWidget(scroll)
        return layout

    def _welcome_page(self):
        layout = self._page()
        layout.addWidget(self.label("Welcome to your OVERLAY Virtual Appliance."))
        layout.addWidget(self.label("Set your root password and choose the roles of up to eight virtual adapters, then this unit will prepare its own pre-stage code. Use that code in your customer portal to register this appliance.", "muted"))
        layout.addWidget(self.label("Assign each attached adapter as WAN, LAN or Unused. At least one WAN must reach the management service. LANs connect to your isolated lab networks.", "muted"))
        layout.addStretch()
        layout.addWidget(self.label("OVERLAY stays inactive until you configure and activate it in the application.", "muted"))

    def _access_page(self):
        layout = self._page()
        layout.addWidget(self.label("Choose the root password for this VM's console and SSH login.", "muted"))
        form = QtWidgets.QFormLayout()
        self.password, self.password_confirm = QtWidgets.QLineEdit(), QtWidgets.QLineEdit()
        for field in (self.password, self.password_confirm):
            field.setEchoMode(QtWidgets.QLineEdit.Password)
            field.setMaxLength(128)
        form.addRow("Root password", self.password)
        form.addRow("Confirm password", self.password_confirm)
        layout.addLayout(form)
        layout.addWidget(self.label("Use 12–128 characters. There is no default password. After setup, use root over SSH or press Ctrl+Alt+F2 for the console login; Ctrl+Alt+F7 returns to the application.", "muted"))
        layout.addStretch()

    def _interfaces_page(self):
        layout = self._page()
        layout.addWidget(self.label("Choose WAN or LAN for each adapter you want to use, up to eight in total. Leave spare adapters Unused. WAN and LAN support DHCP or static IPv4. LAN never installs a default route.", "muted"))
        self.interfaces_layout = QtWidgets.QVBoxLayout()
        layout.addLayout(self.interfaces_layout)
        self.add_interface = QtWidgets.QPushButton("Add interface")
        self.add_interface.hide()  # Compatibility attribute; hardware chosen before import.
        self.count_box = QtWidgets.QGroupBox("Choose your WAN and LAN counts")
        counts = QtWidgets.QFormLayout(self.count_box)
        self.wan_count, self.lan_count = QtWidgets.QSpinBox(), QtWidgets.QSpinBox()
        self.wan_count.setRange(1, 8)
        self.lan_count.setRange(0, 7)
        self.wan_count.setValue(1)
        self.lan_count.setValue(1)
        counts.addRow("WAN interfaces", self.wan_count)
        counts.addRow("LAN interfaces", self.lan_count)
        layout.insertWidget(1, self.count_box)
        self.adapter_hint = self.label("The pre-import configurator creates the requested adapters. Confirm the counts here, then enter DHCP or static addressing on the next page. Maximum: eight total.", "muted")
        layout.addWidget(self.adapter_hint)
        layout.addStretch()

    def populate_interfaces(self, names, settings=None):
        if not 1 <= len(names) <= 8 or any(not re.fullmatch(r"eth[0-7]", name) for name in names):
            self.notice.setText("Attach one to eight Ethernet adapters. Remove additional adapters before continuing.")
            self.adapter_names = names
            return
        if self.adapter_names == names and settings is None:
            return
        self.adapter_names = list(names)
        self.visible_adapters.intersection_update(names)
        self.visible_adapters.update(names[:2])
        while self.interfaces_layout.count():
            item = self.interfaces_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        self.interface_rows = {}
        saved = {r["name"]: r for r in (settings or {}).get("interfaces", [])}
        for index, name in enumerate(names):
            card = QtWidgets.QWidget()
            form = QtWidgets.QFormLayout(card)
            role, mode = QtWidgets.QComboBox(), QtWidgets.QComboBox()
            for label in ("WAN", "LAN", "Unused"): role.addItem(label, label)
            for label, value in (("DHCP", "dhcp"), ("Static IPv4", "static"), ("No address", "disabled")): mode.addItem(label, value)
            address, gateway, dns = QtWidgets.QLineEdit(), QtWidgets.QLineEdit(), QtWidgets.QLineEdit()
            address.setPlaceholderText("10.20.0.1/24")
            gateway.setPlaceholderText("192.168.1.1")
            dns.setPlaceholderText("192.168.1.1, 1.1.1.1")
            form.addRow("Adapter %d · %s" % (index + 1, name), role)
            form.addRow("Address mode", mode)
            for label, field in (("Address / prefix", address), ("WAN gateway", gateway), ("WAN DNS", dns)):
                form.addRow(label, field)
            self.interface_rows[name] = dict(card=card, role=role, mode=mode, address=address, gateway=gateway, dns=dns, form=form)
            row = saved.get(name, {"role": "WAN" if index == 0 else "LAN" if index == 1 else "Unused", "mode": "dhcp" if index == 0 else "disabled"})
            role.setCurrentIndex(role.findData(row["role"]))
            mode.setCurrentIndex(mode.findData(row["mode"]))
            for key, field in (("address", address), ("gateway", gateway), ("dns", dns)): field.setText(row.get(key, ""))
            role.currentIndexChanged.connect(self.mode_changed)
            mode.currentIndexChanged.connect(self.mode_changed)
            self.interfaces_layout.addWidget(card)
            if row["role"] != "Unused": self.visible_adapters.add(name)
            card.setVisible(name in self.visible_adapters)
        self.wan_count.setValue(sum(r["role"].currentData() == "WAN" for r in self.interface_rows.values()) or 1)
        self.lan_count.setValue(sum(r["role"].currentData() == "LAN" for r in self.interface_rows.values()))
        self.show_network_details(self.counts_selected)
        self.mode_changed()

    def show_network_details(self, details):
        self.count_box.setVisible(not details)
        for name, row in self.interface_rows.items():
            row["card"].setVisible(details and name in self.visible_adapters)
        if self.page == 2:
            self.heading.setText("Interface addressing" if details else "Interface counts")

    def select_counts(self):
        wan, lan = self.wan_count.value(), self.lan_count.value()
        if wan + lan > 8 or wan + lan > len(self.adapter_names):
            self.notice.setText("This VM has %d adapters. Generate an OVA with the requested counts using the pre-import configurator before creating the VM; maximum eight total." % len(self.adapter_names))
            return False
        selected = self.adapter_names[:wan + lan]
        self.visible_adapters = set(selected)
        for index, name in enumerate(self.adapter_names):
            row = self.interface_rows[name]
            row["role"].setCurrentIndex(0 if index < wan else 1 if index < wan + lan else 2)
        self.counts_selected = True
        self.show_network_details(True)
        self.notice.clear()
        return True

    def _review_page(self):
        layout = self._page()
        self.review = self.label()
        self.review.setStyleSheet(f"background: {theme.CARD}; border: 1px solid {theme.LINE}; border-radius: 8px; padding: 14px;")
        layout.addWidget(self.review)
        layout.addWidget(self.label("Next applies these settings and prepares this VM's pre-stage code. You will claim the unit yourself in the customer portal.", "muted"))
        layout.addStretch()

    def _progress_page(self):
        layout = self._page()
        self.progress_title = self.label("Preparing this unit")
        self.progress_title.setStyleSheet("font-size: 14pt; font-weight: 600;")
        layout.addWidget(self.progress_title)
        self.progress_detail = self.label("", "muted")
        layout.addWidget(self.progress_detail)
        self.code = self.label()
        self.code.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.code.setStyleSheet(f"font-family: '{theme.MONO}'; font-size: 22pt; color: {theme.TEXT};")
        layout.addWidget(self.code)
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)
        self.network = self.label("", "muted")
        layout.addWidget(self.network)
        layout.addStretch()
        self.progress_hint = self.label("Use the registration code in your Console Portal to claim this unit.", "muted")
        layout.addWidget(self.progress_hint)

    def mode_changed(self):
        for row in self.interface_rows.values():
            role, mode = row["role"].currentData(), row["mode"].currentData()
            allowed = {"WAN": ("dhcp", "static"), "LAN": ("dhcp", "static", "disabled"), "Unused": ("disabled",)}[role]
            for index in range(row["mode"].count()):
                row["mode"].model().item(index).setEnabled(row["mode"].itemData(index) in allowed)
            if mode not in allowed:
                row["mode"].setCurrentIndex(row["mode"].findData(allowed[0]))
                mode = allowed[0]
            for key in ("address", "gateway", "dns"):
                visible = mode == "static" and (key == "address" or role == "WAN")
                row[key].setVisible(visible)
                row["form"].labelForField(row[key]).setVisible(visible)

    def settings(self):
        rows = []
        for name, row in self.interface_rows.items():
            item = {"name": name, "role": row["role"].currentData(), "mode": row["mode"].currentData()}
            if item["mode"] == "static":
                item["address"] = row["address"].text().strip()
                if item["role"] == "WAN":
                    item.update(gateway=row["gateway"].text().strip(), dns=row["dns"].text().strip())
            rows.append(item)
        return {"interfaces": rows}

    def access_result(self, ok, code):
        self.busy = False
        self.password.clear()
        self.password_confirm.clear()
        if ok:
            self.access_ready = True
            self.show_page(2)
        else:
            self.notice.setText("The password could not be saved. Enter it again and retry.")
        self.controls()

    def show_wizard(self):
        self.splash_timer.stop()
        self.maybe_launch()
        if not self.launch_pending:
            self.stack.setCurrentIndex(1)

    def show_page(self, index):
        self.page = index
        self.pages.setCurrentIndex(index)
        self.heading.setText(self.PAGES[index])
        self.step.setText("" if index == 0 else "Step %d of 4" % index)
        self.notice.setText("")
        if index != 4:
            self.operation_error = ""
        if index == 2:
            self.show_network_details(self.counts_selected)
        if index == 3:
            self.review.setText(review_text(self.settings()))
        self.controls()

    def controls(self):
        enabled = self.identity_ready and not self.busy and not self.held
        self.add_interface.setEnabled(False)
        self.wan_count.setEnabled(enabled)
        self.lan_count.setEnabled(enabled)
        self.back.setVisible(self.page > 0 and not self.held)
        self.back.setEnabled(enabled)
        self.next.setVisible(not self.held)
        self.next.setEnabled(enabled and (self.page != 4 or self.progress_failed))
        self.next.setText("Retry" if self.page == 4 else "Next")
        self.password.setEnabled(enabled and not self.access_ready)
        self.password_confirm.setEnabled(enabled and not self.access_ready)
        for row in self.interface_rows.values():
            for key in ("role", "mode", "address", "gateway", "dns"):
                row[key].setEnabled(enabled)

    def go_back(self):
        if self.busy or self.held:
            return
        if self.page == 2 and self.counts_selected:
            self.counts_selected = False
            self.show_network_details(False)
            return
        self.show_page(2 if self.page == 4 else max(0, self.page - 1))

    def go_next(self):
        if self.busy or self.held or not self.identity_ready:
            return
        if self.page == 1:
            if self.access_ready:
                self.show_page(2)
                return
            password = self.password.text()
            if not 12 <= len(password) <= 128 or any(c in password for c in "\r\n\x00:"):
                self.notice.setText("Use a password of 12–128 characters without colon or line breaks.")
                return
            if password != self.password_confirm.text():
                self.notice.setText("The passwords do not match.")
                return
            self.busy = True
            self.job = AccessOperation(password, self)
            self.password.clear()
            self.password_confirm.clear()
            self.job.completed.connect(self.access_result)
            self.controls()
            self.job.start()
            return
        if self.page == 2 and not self.counts_selected:
            self.select_counts()
            return
        if self.page == 2:
            error = validate_page(self.settings(), "interfaces")
            if error or not 1 <= len(self.adapter_names) <= 8:
                self.notice.setText(error or "Attach one to eight Ethernet adapters.")
                return
        if self.page == 3:
            self.begin(self.settings())
        elif self.page == 4:
            self.begin(self.retry_settings)
        else:
            self.show_page(self.page + 1)

    def begin(self, settings):
        if self.job and self.job.isRunning():
            return
        self.show_page(4)
        self.operation_error = ""
        self.progress_failed = False
        self.retry_settings = settings
        self.busy = True
        self.progress.setRange(0, 0)
        self.progress_title.setText("Applying the network settings" if settings is not None else "Preparing this unit")
        self.progress_detail.setText("Keep your WAN adapters connected. Your existing VM identity is preserved.")
        self.controls()
        self.job = Operation(settings, self)
        self.job.completed.connect(self.result)
        self.job.start()

    def result(self, ok, code):
        self.busy = False
        if not ok:
            self.operation_error = code
            self.progress_failed = True
            title, detail = error_text(code)
            self.progress_title.setText(title)
            self.progress_detail.setText(detail)
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
        else:
            self.retry_settings = None
            self.progress_failed = False
            self.progress_title.setText("Preparing this unit")
            self.progress_detail.setText("Connecting securely and requesting this VM's pre-stage code…")
        self.controls()
        if self.live:
            self.refresh()

    def refresh(self):
        if self.probe and self.probe.isRunning():
            return
        if self.probe is None:
            self.probe = Probe(self)
            self.probe.updated.connect(self.on_snapshot)
        self.probe.start()

    def on_snapshot(self, value):
        self.current_snapshot = value
        self.access_ready = bool(value.get("access_ready", self.access_ready))
        names = value.get("adapters")
        if names is not None and not self.busy and not self.settings_loaded:
            self.populate_interfaces(names, value.get("settings") or value.get("import_settings"))
        self.identity_ready = bool(value.get("identity_ready"))
        self.held = bool(value.get("hold") or value.get("status", {}).get("state") == "hold")
        if self.held:
            self.show_page(4)
            title, detail = error_text("identity_hold")
            self.progress_title.setText(title)
            self.progress_detail.setText(detail)
            self.code.clear()
            self.progress_hint.hide()
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            self.controls()
            return
        self.progress_hint.show()
        self.code.setText(registration_code(value.get("status", {})))
        if not self.settings_loaded:
            settings = value.get("settings", {})
            self.settings_loaded = bool(value.get("adapters")) or bool(settings)
            if settings:
                if settings.get("interfaces"):
                    self.populate_interfaces([r["name"] for r in settings["interfaces"]], settings)
                self.show_page(4)
        if self.page == 4 and not self.busy:
            if self.operation_error:
                title, detail = error_text(self.operation_error)
                failed = True
            else:
                title, detail, failed = status_text(value.get("status", {}))
            self.progress_title.setText(title)
            self.progress_detail.setText(detail)
            self.progress_failed = failed
            self.progress.setRange(0, 1 if failed else 0)
            self.progress.setValue(0)
            self.network.setText(value.get("network", ""))
        if not self.identity_ready:
            self.notice.setText("Preparing this VM's unique identity. Please wait…")
        elif "unique identity" in self.notice.text():
            self.notice.clear()
        self.controls()
        self.maybe_launch()

    def maybe_launch(self):
        device = self.current_snapshot.get("device", {})
        if (self.held or self.busy or not self.identity_ready or self.splash_timer.isActive()
                or not re.fullmatch(r"[0-9a-f]{16}", str(device.get("serial", "")))
                or not re.fullmatch(r"[0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{12}", str(device.get("product_serial", "")))
                or device.get("model") != "vm" or not self.access_ready or self.launch_pending):
            return
        # Pre-stage owns the code. Do not flash a second code/review screen,
        # including on every subsequent registered boot.
        self.launch_pending = True
        QtCore.QTimer.singleShot(0, self.finish_launch)

    def finish_launch(self):
        if self.held or not self.identity_ready or self.busy:
            self.launch_pending = False
            return
        if self.probe and self.probe.isRunning():
            QtCore.QTimer.singleShot(200, self.finish_launch)
            return
        self.timer.stop()
        self.launch()

    def closeEvent(self, event):
        if self.job and self.job.isRunning():
            event.ignore()
            return
        self.timer.stop()
        if self.probe and self.probe.isRunning():
            self.probe.wait(7000)
        super().closeEvent(event)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setFont(theme.font(11))
    window = Console()
    window.showFullScreen()
    sys.exit(app.exec_())
