#!/usr/bin/python3
"""Native local-only setup and offline peer-file management."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from collections import deque
from PyQt5 import QtCore,QtGui,QtWidgets
sys.path.insert(0,'/home/overlay/BootScript')
import standalone_overlay as exchange
HERE=Path('/opt/parto-vm')
spec=importlib.util.spec_from_file_location('network_wizard',HERE/'console-launcher.py')
wizard=importlib.util.module_from_spec(spec);spec.loader.exec_module(wizard)
EXCHANGE_INBOX = Path('/var/lib/parto-inbox')
TLS_NG_LABEL = 'TLS + BGP (NG)'


def exchange_filename(label, suffix):
    site = re.sub(r'[<>:"/\\|?*\x00-\x1f\x7f]', '-', label).strip(' .')[:60]
    return f'{site or "site"}-{suffix}.json'


HELPER=['sudo','-n','/usr/bin/python3','-I','/usr/local/lib/parto-overlay/standalone-root.py']

PARTO_QSS = wizard.theme.WINDOW_QSS + """
QWidget { color: #e9f1fa; font-size: 11pt; }
QWidget#partoShell { background: #0b1422; }
QLabel[role='muted'] { color: #a7b7cb; }
QLabel[role='section'] { color: #e9f1fa; font-size: 19pt; font-weight: 600; }
QLineEdit, QComboBox, QPlainTextEdit, QTableWidget {
 background: #142238; border: 1px solid #30445e; border-radius: 8px; padding: 9px 12px;
 selection-background-color: #117f94;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #24c9d9; }
QPushButton { background: #20354e; border: 1px solid #3a516d; border-radius: 8px; padding: 10px 16px; }
QPushButton:hover { background: #2b4664; border-color: #24c9d9; }
QPushButton:disabled { color: #718197; background: #122033; border-color: #26374c; }
QPushButton#primary { background: #087d8c; border-color: #24c9d9; font-weight: 600; }
QPushButton#primary:disabled { color: #718197; background: #122033; border-color: #26374c; }
QCheckBox { spacing: 10px; padding: 4px 0px; }
QCheckBox::indicator { width: 20px; height: 20px; }
QGroupBox { border: 1px solid #30445e; border-radius: 10px; margin-top: 14px; padding: 16px; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; color: #83dce5; padding: 0 6px; }
QHeaderView::section { background: #1c3047; padding: 8px; border: 0; }
QProgressBar { border: 1px solid #30445e; border-radius: 6px; background: #142238; height: 10px; }
QProgressBar::chunk { background: #24c9d9; }
"""

def apply_brand(widget):
    widget.setObjectName('partoShell');widget.setStyleSheet(PARTO_QSS)


def style_placeholder(field):
    """Keep examples visibly different from entered values, including on focus."""
    if field.property('standalonePlaceholderStyled'):
        return
    field.setProperty('standalonePlaceholderStyled', True)
    palette = field.palette()
    palette.setColor(QtGui.QPalette.PlaceholderText, QtGui.QColor('#8793a5'))
    field.setPalette(palette)
    normal = QtGui.QFont(field.font())
    normal.setItalic(False)
    def update(text):
        font = QtGui.QFont(normal)
        font.setItalic(not bool(text))
        field.setFont(font)
    field.textChanged.connect(update)
    update(field.text())


def connection_lines(tunnels):
    return '\n'.join(str(t.get('peer_label') or t.get('peer') or 'Unknown site') +
                     ': ' + str(t.get('ipsec', t.get('tls', t.get('tunnel', 'unknown')))) +
                     ' · BGP ' + str(t.get('bgp', 'unknown')) for t in tunnels)


class TrafficGraph(QtWidgets.QWidget):
    def __init__(self,parent=None):
        super().__init__(parent);self.samples=deque(maxlen=60);self.setMinimumHeight(70)
    def add(self,download,upload):
        self.samples.append((download,upload));self.update()
    def paintEvent(self,event):
        p=QtGui.QPainter(self);p.fillRect(self.rect(),QtGui.QColor('#182433'))
        p.setPen(QtGui.QColor('#c5d2e0'));p.drawText(8,18,'Last 5 minutes · Download (blue) / Upload (green)')
        maximum=max([1.0]+[v for row in self.samples for v in row]);w=self.width()-16;h=self.height()-30
        for col,color in [(0,'#61afff'),(1,'#62dba6')]:
            points=[QtCore.QPointF(8+i*w/59,self.height()-5-row[col]/maximum*h) for i,row in enumerate(self.samples)]
            p.setPen(QtGui.QPen(QtGui.QColor(color),2))
            if len(points)>1:p.drawPolyline(QtGui.QPolygonF(points))
        p.end()


def rate_pair(previous,current,elapsed):
    if not previous or elapsed<=0 or previous.get('ifindex')!=current.get('ifindex'):return None
    if any(current[k]<previous[k] for k in ('rx','tx')):return None
    return tuple((current[k]-previous[k])*8/elapsed/1_000_000 for k in ('rx','tx'))


class Work(QtCore.QThread):
    done=QtCore.pyqtSignal(dict)
    def __init__(self,action,value=None,parent=None):
        super().__init__(parent);self.action,self.value=action,value
    def run(self):
        try:
            r=subprocess.run(HELPER+[self.action],input=json.dumps(self.value or {}),text=True,capture_output=True,timeout=180)
            self.done.emit(json.loads(r.stdout))
        except Exception:self.done.emit({'ok':False,'errors':['The local operation could not complete. Check the appliance console logs.']})

class TopologyDialog(QtWidgets.QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle('Parto · Topology')
        self.resize(1000, 620)
        apply_brand(self)
        layout = QtWidgets.QVBoxLayout(self)
        title = QtWidgets.QLabel('Network topology')
        title.setStyleSheet('font-size:24px; font-weight:600')
        layout.addWidget(title)
        self.caption = QtWidgets.QLabel()
        self.caption.setWordWrap(True)
        layout.addWidget(self.caption)
        self.scene = QtWidgets.QGraphicsScene(self)
        self.view = QtWidgets.QGraphicsView(self.scene)
        self.view.setRenderHint(QtGui.QPainter.Antialiasing)
        self.view.setBackgroundBrush(QtGui.QColor('#0b1422'))
        self.view.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        layout.addWidget(self.view)
        close = QtWidgets.QPushButton('Back')
        close.clicked.connect(self.accept)
        layout.addWidget(close)
        self.displayed = None

    def render(self, data, status):
        links = {link.get('peer'): (link.get('tunnel', 'unknown'), link.get('bgp', 'unknown'))
                 for link in status.get('tunnels', [])}
        policy = status.get('policy') or data['policy']
        view = (data, links, policy)
        if view == self.displayed:
            return
        self.displayed = view
        self.scene.clear()
        hub = next(site for site in data['sites'] if site['role'] == 'hub')
        local_hub = hub['id'] == data['local']
        egress = hub['egress'] or hub['wan']
        sharing = 'enabled' if policy['internet'] else 'disabled'
        reach = 'Current Hub policy' if local_hub else 'Policy in signed Hub file'
        spoke_access = 'allowed' if policy['spoke_access'] else 'isolated'
        self.caption.setText(f'{reach} · Internet sharing {sharing} · Spokes {spoke_access}')
        spokes = [site for site in data['sites'] if site['role'] == 'spoke']

        def local_addresses(site, iface):
            if site['id'] != data['local']:
                return ''
            return ', '.join(data['addresses'].get(iface, []))

        def card(x, y, width, title, detail, accent, muted=False):
            item = self.scene.addText('')
            item.setDefaultTextColor(QtGui.QColor('#a7b5c7' if muted else '#e9f1fa'))
            item.setFont(QtGui.QFont('Sans Serif', 10))
            item.setTextWidth(width - 24)
            item.setPlainText(title + '\n' + detail)
            item.setPos(x + 12, y + 10)
            height = max(74, item.boundingRect().height() + 20)
            box = self.scene.addRect(x, y, width, height, QtGui.QPen(QtGui.QColor(accent), 2),
                                     QtGui.QBrush(QtGui.QColor('#101a29' if muted else '#142238')))
            box.setZValue(-1)
            return height

        def line(x1, y1, x2, y2, color='#63849d'):
            edge = self.scene.addLine(x1, y1, x2, y2, QtGui.QPen(QtGui.QColor(color), 2))
            edge.setZValue(-2)

        def site_card(x, y, site, link='', muted=False):
            title = site['role'].title() + ' · ' + site['label']
            if site['id'] == data['local']:
                title += ' (this appliance)'
            wan = site['wan']
            endpoint = f"Endpoint {site['endpoint']}" if site['endpoint'] else 'Outbound / NAT'
            detail = '\n'.join(filter(None, [f'WAN {wan}', local_addresses(site, wan), endpoint, link]))
            return card(x, y, 225, title, detail, '#52667d' if muted else '#61afff', muted)

        def lan_card(x, y, site, muted=False):
            interfaces = [iface + ' ' + local_addresses(site, iface) for iface in site['lans']]
            prefixes = site['prefixes'] or ['No LAN advertised']
            return card(x, y, 208, 'LAN', '\n'.join([*interfaces, *prefixes]), '#52667d' if muted else '#62dba6', muted)

        def link_state(peer):
            tunnel, bgp = links.get(peer, ('unknown', 'unknown'))
            connected = tunnel == 'established' and bgp == 'Established'
            if connected:
                label, color = 'Connected', '#62dba6'
            elif tunnel == 'down':
                label, color = 'Disconnected', '#b48787'
            elif tunnel == 'unknown':
                label, color = 'Status unavailable', '#63849d'
            else:
                label, color = 'Connecting', '#d5af6a'
            return f'{label}\nTunnel {tunnel} · BGP {bgp}', color, not connected

        egress_detail = f"Hub {egress} · {'dedicated WAN' if hub['egress'] else 'shared WAN'}"
        egress_address = local_addresses(hub, egress)
        internet_height = card(20, 16, 225, 'Open internet',
                               '\n'.join(filter(None, [egress_detail, egress_address, f'Sharing {sharing}'])),
                               '#62dba6' if policy['internet'] else '#63849d')
        hub_y = 16 + internet_height + 38
        hub_height = site_card(20, hub_y, hub)
        hub_mid = hub_y + hub_height / 2
        line(132, 16 + internet_height, 132, hub_y)
        if hub['lans'] or hub['prefixes']:
            lan_y = hub_y + hub_height + 38
            line(132, hub_y + hub_height, 132, lan_y)
            lan_card(28, lan_y, hub)

        y = hub_y
        for spoke in spokes:
            peer = spoke.get('peer') if local_hub else hub.get('peer')
            status_text, color, muted = link_state(peer)
            height = site_card(335, y, spoke, status_text, muted)
            lan_height = lan_card(610, y, spoke, muted)
            mid = y + height / 2
            line(245, hub_mid, 290, hub_mid, color)
            line(290, hub_mid, 290, mid, color)
            line(290, mid, 335, mid, color)
            line(560, mid, 585, mid, color)
            line(585, mid, 585, y + lan_height / 2, color)
            line(585, y + lan_height / 2, 610, y + lan_height / 2, color)
            y += max(height, lan_height) + 28
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-14, -14, 14, 14))


class Manager(QtWidgets.QWidget):
    def __init__(self,role=None):
        super().__init__();self.job=None;self.initialized=False;self.hub=None;self.export_path=None;self.peers=[];self.own_role=None
        self.samples={};self.sample_time=None
        self.topology_data=None;self.topology_status={};self.topology_dialog=None
        self.setWindowTitle('Parto');apply_brand(self)
        layout=QtWidgets.QVBoxLayout(self);layout.setContentsMargins(32,24,32,24)
        header=QtWidgets.QHBoxLayout();logo=QtWidgets.QLabel();pix=QtGui.QPixmap(str(wizard.ASSETS/'logo-badge.png'));logo.setPixmap(pix.scaled(64,64,QtCore.Qt.KeepAspectRatio,QtCore.Qt.SmoothTransformation));header.addWidget(logo)
        titles=QtWidgets.QVBoxLayout();title=QtWidgets.QLabel('Parto');title.setStyleSheet('font-size:28px; font-weight:600');titles.addWidget(title);subtitle=QtWidgets.QLabel('A trusted path to the open Internet');subtitle.setStyleSheet('color:#a7b7cb');titles.addWidget(subtitle);header.addLayout(titles);header.addStretch();layout.addLayout(header)
        self.form=QtWidgets.QWidget();form=QtWidgets.QFormLayout(self.form);layout.addWidget(self.form)
        self.label=QtWidgets.QLineEdit('My Parto site');form.addRow('Node name',self.label)
        self.role=QtWidgets.QComboBox();self.role.addItem('Hub','hub');self.role.addItem('Spoke','spoke');form.addRow('Is this device the hub?',self.role)
        self.transport=QtWidgets.QComboBox();self.transport.addItem('IPsec + BGP','ipsec');self.transport.addItem('TLS + BGP','tls');self.transport.addItem(TLS_NG_LABEL,'obfs4');form.addRow('Transport',self.transport)
        self.endpoint=QtWidgets.QLineEdit();self.endpoint.setPlaceholderText('Reachable public or private IPv4 address');form.addRow('Hub reachable IPv4',self.endpoint);self.endpoint_label=form.labelForField(self.endpoint)
        self.gateway=QtWidgets.QCheckBox('Share the hub Internet connection with spokes');form.addRow('Internet Gateway',self.gateway)
        self.isolation=QtWidgets.QCheckBox('Isolate spokes (hub LAN and Internet only)');self.isolation.setChecked(True);form.addRow('Spoke isolation',self.isolation)
        self.fingerprint=QtWidgets.QLineEdit();self.fingerprint.setReadOnly(True);self.fingerprint.setPlaceholderText('Loaded from the signed hub file after approval');form.addRow('Hub file fingerprint',self.fingerprint);self.fingerprint_label=form.labelForField(self.fingerprint)
        self.hub_button=QtWidgets.QPushButton('Choose the hub JSON file (spoke setup)');form.addRow(self.hub_button);self.hub_button.clicked.connect(self.choose_hub)
        style_placeholder(self.endpoint);style_placeholder(self.fingerprint)
        self.reachability_hint=QtWidgets.QLabel('');self.reachability_hint.setWordWrap(True);form.addRow(self.reachability_hint)
        self.preselected_role=role
        if role in ('hub','spoke'):self.role.setCurrentIndex(self.role.findData(role));self.role.setEnabled(False)
        self.role.currentIndexChanged.connect(self.role_changed)
        self.create=QtWidgets.QPushButton('Create this node and its exchange file');self.create.setObjectName('primary');layout.addWidget(self.create);self.create.clicked.connect(self.initialize);self.role_changed()
        self.instructions=QtWidgets.QLabel('<b>Connect trusted sites</b><br>Hub invitation → Spoke request → Hub approval → Activate.<br>Import the hub invitation before creating a spoke. Each approval belongs to one spoke; fingerprints travel inside the files.');self.instructions.setWordWrap(True);layout.addWidget(self.instructions)
        self.lan_settings=None;self.lan_button=QtWidgets.QPushButton('Spoke LAN / DHCP settings');self.lan_button.clicked.connect(self.configure_lan);self.lan_button.hide();layout.addWidget(self.lan_button)
        self.info=QtWidgets.QPlainTextEdit();self.info.setReadOnly(True);layout.addWidget(self.info,1)
        row=QtWidgets.QHBoxLayout();layout.addLayout(row);self.buttons=[]
        for title,callback in [('Export file',self.export),('Import peer file',self.import_peer),('Activate',lambda:self.run('apply')),('Disable',lambda:self.run('disable')),('Check connections',lambda:self.run('status')),('Refresh hub file',lambda:self.run('refresh'))]:
            button=QtWidgets.QPushButton(title);button.clicked.connect(callback);row.addWidget(button);self.buttons.append(button)
        self.remove_button = QtWidgets.QPushButton('Remove spoke')
        self.remove_button.clicked.connect(self.remove)
        self.remove_button.hide()
        row.addWidget(self.remove_button)
        self.buttons.append(self.remove_button)
        self.topology_button = QtWidgets.QPushButton('View topology')
        self.topology_button.clicked.connect(self.show_topology)
        layout.addWidget(self.topology_button)
        self.topology_button.hide()
        self.policy_box=QtWidgets.QGroupBox('Hub sharing controls');policy_row=QtWidgets.QHBoxLayout(self.policy_box)
        self.live_internet=QtWidgets.QCheckBox('Share Internet with spokes');self.live_spokes=QtWidgets.QCheckBox('Allow spoke-to-spoke connectivity')
        self.policy_apply=QtWidgets.QPushButton('Apply sharing settings');self.policy_apply.clicked.connect(self.apply_policy)
        for widget in (self.live_internet,self.live_spokes,self.policy_apply):policy_row.addWidget(widget)
        layout.addWidget(self.policy_box);self.policy_box.hide()
        self.monitor=QtWidgets.QTableWidget(0,5);self.monitor.setHorizontalHeaderLabels(['Site','Tunnel','BGP','Download','Upload'])
        self.monitor.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers);self.monitor.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.monitor.setMaximumHeight(180);layout.addWidget(self.monitor)
        self.graph=TrafficGraph();layout.addWidget(self.graph)
        self.sample_label=QtWidgets.QLabel('Traffic: waiting for first sample · refresh every 5 seconds');layout.addWidget(self.sample_label)
        for widget in (self.monitor,self.graph,self.sample_label):widget.hide()
        self.timer=QtCore.QTimer(self);self.timer.setInterval(5000);self.timer.timeout.connect(self.poll);self.timer.start()
        self.notice=QtWidgets.QLabel();self.notice.setWordWrap(True);layout.addWidget(self.notice)
        self.run('info')

    def configure_lan(self):
        if self.own_role!='spoke' or not self.lan_settings:return
        value=self.lan_settings;dialog=QtWidgets.QDialog(self);dialog.setWindowTitle('Spoke LAN and DHCP');layout=QtWidgets.QVBoxLayout(dialog);form=QtWidgets.QFormLayout();layout.addLayout(form)
        address=QtWidgets.QLineEdit(value['address']);enabled=QtWidgets.QCheckBox('Serve DHCP on LAN eth1 only');enabled.setChecked(value['dhcp'])
        first=QtWidgets.QLineEdit(value.get('pool_start',''));last=QtWidgets.QLineEdit(value.get('pool_end',''));hours=QtWidgets.QSpinBox();hours.setRange(1,168);hours.setValue(value.get('lease_hours',12))
        first.setPlaceholderText('e.g. 172.30.212.100');last.setPlaceholderText('e.g. 172.30.212.199')
        for label,widget in [('LAN gateway / prefix',address),('DHCP server',enabled),('Pool start',first),('Pool end',last),('Lease hours',hours)]:form.addRow(label,widget)
        def toggle():
            for field in (first,last,hours):field.setEnabled(enabled.isChecked())
        enabled.toggled.connect(toggle);toggle()
        hint=QtWidgets.QLabel('Use a different LAN subnet at each site. For an access point: connect its LAN port, use AP/bridge mode, and disable its DHCP server. A subnet change stops this spoke until its new request is approved by the hub; an address change inside the same subnet needs no new peer file. Renew client leases after changes.');hint.setWordWrap(True);layout.addWidget(hint)
        buttons=QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Save|QtWidgets.QDialogButtonBox.Cancel);buttons.accepted.connect(dialog.accept);buttons.rejected.connect(dialog.reject);layout.addWidget(buttons)
        if dialog.exec_()==QtWidgets.QDialog.Accepted:self.run('lan',{'address':address.text().strip(),'dhcp':enabled.isChecked(),'pool_start':first.text().strip(),'pool_end':last.text().strip(),'lease_hours':hours.value()})

    def poll(self):
        if self.initialized and not (self.job and self.job.isRunning()):self.run('status',automatic=True)

    def apply_policy(self):
        self.run('policy',{'internet':self.live_internet.isChecked(),'spoke_access':self.live_spokes.isChecked()})

    def show_topology(self):
        if self.own_role != 'hub' or not self.topology_data:
            return
        if self.topology_dialog is None:
            self.topology_dialog = TopologyDialog(self)
        self.topology_dialog.render(self.topology_data, self.topology_status)
        self.topology_dialog.show()
        self.topology_dialog.raise_()

    def render_monitor(self,answer):
        self.topology_status = answer
        if self.topology_dialog and self.topology_dialog.isVisible():
            self.topology_dialog.render(self.topology_data, answer)
        now=time.monotonic();elapsed=now-self.sample_time if self.sample_time is not None else 0
        traffic=answer.get('traffic',{});rows=answer.get('tunnels',[]);self.monitor.setRowCount(len(rows));totals=[0.,0.];measured=False
        for n,row in enumerate(rows):
            counter=traffic.get(row['id']);rates=rate_pair(self.samples.get(row['id']),counter,elapsed) if counter else None
            if rates:
                measured=True;totals=[a+b for a,b in zip(totals,rates)]
            values=[row.get('peer_label',row.get('peer','Unknown')),row.get('tunnel','unknown'),row.get('bgp','unknown')]+([f'{v:.3f} Mbit/s' for v in rates] if rates else ['—','—'])
            for col,text in enumerate(values):self.monitor.setItem(n,col,QtWidgets.QTableWidgetItem(str(text)))
        self.samples=traffic;self.sample_time=now
        if measured:self.graph.add(*totals)
        download,upload=[f'{rate:.3f} Mbit/s' for rate in totals] if measured else ['—','—']
        self.sample_label.setText(f'Overlay total · Download {download} · Upload {upload} · refresh every 5 seconds')

    def role_changed(self):
        hub=self.role.currentData()=='hub';self.gateway.setEnabled(hub);self.isolation.setEnabled(hub);self.hub_button.setVisible(not hub);self.fingerprint.setVisible(not hub);self.fingerprint_label.setVisible(not hub)
        self.endpoint.setVisible(hub);self.endpoint_label.setVisible(hub)
        self.reachability_hint.setText('Hub: enter the tunnel-facing IPv4 address that every spoke can reach. Public and routed private addresses are supported. Internet uses the deployment selected on Welcome: same WAN or separate unfiltered WAN. Forward TCP 443 or UDP 500/4500 if behind your router.' if hub else 'Spoke: outbound-only, including behind NAT/CGNAT. No public IP or port forwarding required; the trusted Hub invitation supplies its address.')
        if not hub:self.gateway.setChecked(False);self.endpoint.clear()
        if hasattr(self,'create'):self.create.setEnabled(not self.initialized and (hub or self.hub is not None))

    def file(self):
        path,_=QtWidgets.QFileDialog.getOpenFileName(self,'Import public peer file',str(EXCHANGE_INBOX) if EXCHANGE_INBOX.is_dir() else str(Path.home()),'JSON peer files (*.json)')
        if not path:return None
        try:
            selected = Path(path)
            if selected.parent == EXCHANGE_INBOX:
                result = subprocess.run(
                    [*HELPER, 'read-inbox'], input=json.dumps({'name': selected.name}),
                    capture_output=True, text=True, timeout=10, check=True,
                )
                value = json.loads(result.stdout)['file']
            else:
                with selected.open('rb') as stream:
                    raw = stream.read(exchange.MAX_FILE * 2 + 1)
                value = exchange.parse(raw.decode('utf-8'))
            if value.get('format')=='sealed-exchange':
                passphrase,ok=QtWidgets.QInputDialog.getText(self,'Unlock exchange file','Exchange passphrase (not your root password):',QtWidgets.QLineEdit.Password)
                if not ok:return None
                value=exchange.unseal(value,passphrase)
            return value
        except PermissionError:
            self.notice.setText('Parto cannot read this file. Upload it as root to /var/lib/parto-inbox/ and select it there.')
            return None
        except Exception:self.notice.setText('Could not open the exchange file. Check its format and, if encrypted, its passphrase.');return None

    def confirm_peer(self, value, approval=False):
        try:
            peer = exchange.inspect_peer(value)
            message = QtWidgets.QMessageBox(self)
            message.setWindowTitle('Approve spoke request' if approval else 'Trust hub invitation')
            message.setIcon(QtWidgets.QMessageBox.Question)
            message.setTextFormat(QtCore.Qt.PlainText)
            message.setText(peer['label'] + ' (' + peer['role'] + ')\nEndpoint: ' + peer['endpoint'] +
                            '\nFingerprint: ' + peer['fingerprint'])
            message.setInformativeText('The file signature and embedded fingerprint were checked. A fingerprint in the same file does not prove its sender. Continue only if you obtained this file from the intended owner through a trusted channel; otherwise verify the fingerprint independently.')
            message.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            message.setDefaultButton(QtWidgets.QMessageBox.No)
            return peer if message.exec_() == QtWidgets.QMessageBox.Yes else None
        except Exception as exc:
            self.notice.setText('Peer file could not be verified: ' + str(exc))
            return None

    def choose_hub(self):
        value=self.file()
        if value is not None:
            try:
                if value.get('body', {}).get('kind') != 'standalone-hub' or value['body'].get('recipient') is not None:
                    raise ValueError('Choose the hub invitation, not a spoke-specific approval.')
                peer=self.confirm_peer(value)
                if peer is not None:
                    self.hub=value;self.fingerprint.setText(peer['fingerprint']);self.role_changed()
                    self.notice.setText('Hub invitation verified and explicitly trusted. Its fingerprint is loaded from the file.')
            except Exception as exc:
                self.notice.setText(str(exc))

    def initialize(self):
        try:
            ready=json.loads(Path('/etc/parto/vm-network-ready').read_text())
            rows=ready['interfaces'];wans=[r for r in rows if r['role']=='WAN'];lans=[r for r in rows if r['role']=='LAN' and r['mode']!='disabled']
            if not any(r['name']=='eth0' for r in wans) or any(r['name']!='eth1' for r in lans):raise ValueError('Use adapter 1 as transport WAN and adapter 2 as LAN.')
            if len(wans)>2 or (self.role.currentData()=='spoke' and len(wans)!=1):raise ValueError('Adapter roles do not match this deployment.')
            if ready.get('node_role') and ready['node_role']!=self.role.currentData():raise ValueError('Use the role selected before network setup.')
            if self.role.currentData()=='spoke' and not lans:raise ValueError('A spoke needs an active LAN to connect its clients.')
            if any(r['mode']!='static' for r in lans):raise ValueError('Configure static LAN addresses before creating this node.')
            settings={'label':self.label.text().strip(),'role':self.role.currentData(),'transport':'tls' if self.transport.currentData()=='obfs4' else self.transport.currentData(),
                      'endpoint':self.endpoint.text().strip() if self.role.currentData()=='hub' else '','wan':'eth0','lans':[r['name'] for r in lans],
                      'prefixes':[str(exchange.ipaddress.ip_interface(r['address']).network) for r in lans],
                      'internet_gateway':self.gateway.isChecked(),'isolate_spokes':self.role.currentData()=='hub' and self.isolation.isChecked()}
            if settings['role']=='hub' and len(wans)==2:settings['egress']=next(r['name'] for r in wans if r['name']!='eth0')
            if self.transport.currentData()=='obfs4':settings['obfuscated']=True
            # The immutable Hub helper creates the public bridge descriptor before signing.
            if not (settings.get('obfuscated') and settings['role']=='hub'):exchange.settings(settings)
            self.run('initialize',{'settings':settings,'hub_file':self.hub,'fingerprint':self.fingerprint.text().strip().lower()})
        except Exception as exc:self.notice.setText(str(exc))

    def import_peer(self):
        value=self.file()
        if value is None:return
        if self.own_role == 'hub':
            if value.get('body', {}).get('kind') != 'standalone-spoke':
                self.notice.setText('The hub imports a spoke request.');return
            peer=self.confirm_peer(value, approval=True)
            if peer is not None:self.run('import',{'file':value,'fingerprint':peer['fingerprint']})
        else:
            # Root validates against the saved CA pin and this spoke's identity.
            self.run('import',{'file':value,'fingerprint':''})

    def export_protection(self):
        choice=QtWidgets.QMessageBox.question(self,'Protect exchange file','Encrypt this file with an exchange passphrase? Recommended for storage or messaging. Send the passphrase separately; do not use your root password.',QtWidgets.QMessageBox.Yes|QtWidgets.QMessageBox.No|QtWidgets.QMessageBox.Cancel,QtWidgets.QMessageBox.Yes)
        if choice==QtWidgets.QMessageBox.Cancel:return False,None
        if choice==QtWidgets.QMessageBox.No:return True,None
        value,ok=QtWidgets.QInputDialog.getText(self,'Protect exchange file','Choose a 16–256 character exchange passphrase:',QtWidgets.QLineEdit.Password)
        if not ok:return False,None
        confirm,ok=QtWidgets.QInputDialog.getText(self,'Confirm exchange passphrase','Enter it again:',QtWidgets.QLineEdit.Password)
        if not ok:return False,None
        try:exchange._exchange_password(value)
        except ValueError as exc:self.notice.setText(str(exc));return False,None
        if value!=confirm:self.notice.setText('Exchange passphrases do not match.');return False,None
        return True,value

    def export(self):
        value={};suggested=exchange_filename(self.label.text(), 'request')
        if self.own_role == 'hub':
            spokes=[p for p in self.peers if p['role']=='spoke']
            options=['Hub invitation — for adding a new spoke'] + [p['label']+' · '+p['endpoint']+' · '+p['node'][:8] for p in spokes]
            selected,ok=QtWidgets.QInputDialog.getItem(self,'Export hub file','Choose invitation or approval recipient',options,0,False)
            if not ok:return
            index=options.index(selected)
            if index==0:
                value={'invitation':True};suggested=exchange_filename(self.label.text(), 'invitation')
            else:
                peer=spokes[index-1];value={'recipient':peer['node']};suggested=exchange_filename(peer['label'], 'approved')
        path,_=QtWidgets.QFileDialog.getSaveFileName(self,'Export public identity and configuration',str(EXCHANGE_INBOX / suggested),'JSON peer files (*.json)')
        if path:self.export_path=path;self.run('export',value)

    def remove(self):
        if self.own_role != 'hub':
            return
        spokes = [peer for peer in self.peers if peer['role'] == 'spoke']
        if not spokes:
            return
        options = [f"{index}. {peer['label']}" for index, peer in enumerate(spokes, 1)]
        selected, ok = QtWidgets.QInputDialog.getItem(
            self, 'Remove spoke', 'Choose an approved Spoke', options, 0, False)
        if not ok:
            return
        peer = spokes[options.index(selected)]
        answer = QtWidgets.QMessageBox.question(
            self, 'Revoke Spoke approval',
            f"Remove {peer['label']} and revoke its approval? "
            "The Hub may briefly reconnect the remaining Spokes.",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if answer == QtWidgets.QMessageBox.Yes:
            self.run('remove', {'node': peer['node']})

    def run(self,action,value=None,automatic=False):
        if self.job and self.job.isRunning():return
        self.last_action=action
        if not automatic:self.notice.setText('Working locally…')
        self.policy_box.setEnabled(False);self.lan_button.setEnabled(False)
        self.form.setEnabled(False);self.create.setEnabled(False)
        for button in self.buttons:button.setEnabled(False)
        self.job=Work(action,value,self);self.job.done.connect(self.result);self.job.finished.connect(self.finished);self.job.start()

    def result(self,answer):
        if not answer.get('ok'):
            if self.last_action=='status':self.sample_label.setText('Monitoring unavailable · retrying in 5 seconds')
            if self.last_action=='info' and 'setup is missing' in ' '.join(answer.get('errors',[])):
                self.notice.setText('Create this node to begin.');return
            self.notice.setText('; '.join(answer.get('errors',[])) or 'Operation did not complete.');return
        if self.last_action=='info':
            self.initialized=True;self.peers=answer['peers'];self.own_role=answer['role'];
            self.remove_button.setVisible(self.own_role == 'hub')
            self.topology_data=answer.get('topology') if self.own_role=='hub' else None
            self.topology_button.setVisible(bool(self.topology_data))
            if not self.topology_data and self.topology_dialog:
                self.topology_dialog.close()
            if 'label' in answer:self.label.setText(answer['label'])
            self.policy_box.setVisible(self.own_role=='hub');self.lan_settings=answer.get('lan');self.lan_button.setVisible(self.own_role=='spoke')
            if answer.get('lan_reapproval_required'):self.instructions.setText('LAN subnet changed: export a new spoke request. On the hub, Disable OVERLAY, remove the old spoke entry, import/approve the new request, and return its new approval. Then reactivate. Other spokes do not need new files.')
            if answer.get('policy'):
                self.live_internet.setChecked(answer['policy']['internet']);self.live_spokes.setChecked(answer['policy']['spoke_access'])
            self.info.setPlainText('Node ID: '+answer['node']+'\nRole: '+answer['role'].title()+'\nTransport: '+(TLS_NG_LABEL if answer.get('obfuscated') else answer['transport'].upper()+' + BGP')+'\nFingerprint (also included in exported JSON):\n'+answer['fingerprint']+'\n\nAccepted nodes:\n'+'\n'.join(r['label']+' ('+r['role']+') · '+r['node'] for r in answer['peers']));self.notice.setText('Each hub approval is addressed to one spoke. Invitations identify only the Hub; approvals identify the Hub and their recipient. Private keys stay on this VM.')
        elif self.last_action=='remove':
            self.notice.setText('Spoke removed and approval revoked.')
        elif self.last_action=='export':
            ok,passphrase=self.export_protection()
            if not ok:return
            try:
                value=exchange.seal(answer['file'],passphrase) if passphrase is not None else answer['file']
                selected = Path(self.export_path)
                if selected.parent == EXCHANGE_INBOX:
                    subprocess.run(
                        [*HELPER, 'write-inbox'],
                        input=json.dumps({'name': selected.name, 'file': value}, separators=(',', ':')),
                        capture_output=True, text=True, timeout=10, check=True,
                    )
                else:
                    output = QtCore.QSaveFile(self.export_path)
                    raw = json.dumps(value, indent=2).encode()
                    if not output.open(QtCore.QIODevice.WriteOnly):
                        raise ValueError()
                    if not output.setPermissions(QtCore.QFileDevice.ReadOwner | QtCore.QFileDevice.WriteOwner) or output.write(raw) != len(raw) or not output.commit():
                        raise ValueError()
                self.notice.setText('Saved '+self.export_path+'. '+('Encrypted: share its passphrase separately. ' if passphrase is not None else 'Unencrypted: use a trusted private channel. ')+'Verify the signed fingerprint against the intended sender.')
            except Exception:self.notice.setText('The exchange file could not be saved.')
        else:
            if self.last_action=='initialize':self.initialized=True
            if self.last_action=='status':self.render_monitor(answer)
            if self.last_action=='policy':self.notice.setText('Hub sharing settings applied. Existing tunnels remain connected.')
            self.info.setPlainText('State: '+str(answer.get('state','saved')).replace('_',' ')+'\nEstablished connections: '+str(answer.get('established_count',0))+'/'+str(answer.get('total_count',0))+'\n'+connection_lines(answer.get('tunnels',[])));self.notice.setText('Saved locally.' if self.last_action in ('initialize','import','remove','refresh') else 'Connection check complete. Activation is separate from established tunnel status.')

    def finished(self):
        self.policy_box.setEnabled(self.initialized and self.own_role=='hub');self.lan_button.setEnabled(self.initialized and self.own_role=='spoke')
        for widget in (self.monitor,self.graph,self.sample_label):widget.setVisible(self.initialized)
        self.form.setVisible(not self.initialized);self.form.setEnabled(True);self.create.setVisible(not self.initialized);self.create.setEnabled(not self.initialized and (self.role.currentData()=='hub' or self.hub is not None))
        for button in self.buttons:button.setEnabled(self.initialized)
        self.remove_button.setEnabled(self.own_role == 'hub' and any(p['role'] == 'spoke' for p in self.peers))
        if self.last_action in ('initialize','import','remove','refresh','policy','lan') and self.initialized:QtCore.QTimer.singleShot(0,lambda:self.run('info'))

    def closeEvent(self,event):
        if self.job and self.job.isRunning():event.ignore()
        else:super().closeEvent(event)

class NetworkWork(wizard.Operation):
    def run(self):
        try:
            r=subprocess.run(['sudo','-n','/usr/bin/python3','-I','/usr/local/libexec/console-vm-network','apply'],input=json.dumps(self.settings),capture_output=True,text=True,timeout=240)
            answer=json.loads(r.stdout);self.completed.emit(r.returncode==0 and answer.get('ok',False),answer.get('error',''))
        except Exception:self.completed.emit(False,'network_apply_failed')

class WebWelcome(QtWidgets.QWidget):
    """After local access/network setup, guide the operator to HTTPS management."""
    def __init__(self, role=None):
        super().__init__();self.setWindowTitle('Parto');apply_brand(self)
        layout=QtWidgets.QVBoxLayout(self);layout.setContentsMargins(60,40,60,40)
        logo=QtWidgets.QLabel();logo.setPixmap(QtGui.QPixmap(str(wizard.ASSETS/'logo-badge.png')).scaled(100,100,QtCore.Qt.KeepAspectRatio,QtCore.Qt.SmoothTransformation));layout.addWidget(logo)
        title=QtWidgets.QLabel('Parto · Manage in your browser');title.setStyleSheet('font-size:28px;font-weight:600');layout.addWidget(title)
        hint=QtWidgets.QLabel('Open one of these HTTPS addresses from a computer that can reach this appliance.\nSign in as admin with the root password you set here.\nThe certificate is generated locally for this VM; verify its fingerprint below before trusting it.');hint.setWordWrap(True);layout.addWidget(hint)
        self.role = role
        layout.addWidget(QtWidgets.QLabel('Physical interfaces'))
        self.addresses = QtWidgets.QLabel()
        layout.addWidget(self.addresses)
        layout.addWidget(QtWidgets.QLabel('HTTPS management · WAN only'))
        self.management = QtWidgets.QLabel()
        layout.addWidget(self.management)
        for block in (self.addresses, self.management):
            block.setTextFormat(QtCore.Qt.PlainText)
            block.setStyleSheet('font-size:18px;color:#83dce5;background:#142238;border:1px solid #30445e;border-radius:14px;padding:14px;')
            block.setWordWrap(True)
        self.cert=QtWidgets.QLabel();self.cert.setTextFormat(QtCore.Qt.PlainText);self.cert.setWordWrap(True);layout.addWidget(self.cert)
        layout.addStretch();layout.addWidget(QtWidgets.QLabel('All configuration, exchange-file upload/download, connection monitoring and topology are available in the browser.\nHTTPS management: port 8443 · Tunnel: port 443 or IPsec UDP 500/4500.\nKeep management access limited to trusted networks. Ctrl+Alt+F2 opens the Linux login console.'))
        self.timer=QtCore.QTimer(self);self.timer.setInterval(5000);self.timer.timeout.connect(self.refresh);self.timer.start();self.refresh()
    def refresh(self):
        try:
            rows=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','address','show'],timeout=3))
            ready = json.loads(Path('/etc/parto/vm-network-ready').read_text())
            wans = {row['name'] for row in ready['interfaces'] if row['role'] == 'WAN'}
            physical = {'eth0', 'eth1', 'eth2'} if self.role == 'hub' else {'eth0', 'eth1'}
            lines, urls = [], []
            for row in sorted(rows, key=lambda item: item['ifname']):
                name = row['ifname']
                if name not in physical:
                    continue
                addresses = [a['local'] for a in row.get('addr_info', [])
                             if a.get('scope') == 'global' and 'UP' in row.get('flags', [])]
                lines.append(name + ' — ' + (', '.join(addresses) or 'No address'))
                if name in wans:
                    for host in addresses:
                        urlhost = '[' + host + ']' if ':' in host else host
                        urls.append(name + ' — https://' + urlhost + ':8443')
            self.addresses.setText('\n'.join(lines) or 'Waiting for an interface address…')
            self.management.setText('\n'.join(urls) or 'Waiting for a WAN address…')
            result=subprocess.run(['openssl','x509','-in','/var/lib/parto-web/server.crt','-noout','-fingerprint','-sha256'],capture_output=True,text=True,timeout=3)
            self.cert.setText('HTTPS certificate '+result.stdout.strip() if result.returncode==0 else 'HTTPS certificate is being prepared…')
        except Exception:
            self.addresses.setText('Waiting for network information…')
            self.management.setText('Waiting for a WAN address…')


class Setup(wizard.Console):
    def __init__(self, **kwargs):
        super().__init__(**kwargs);self.setWindowTitle('Parto');apply_brand(self);self.next.setObjectName('primary');self.panel.setMaximumWidth(1000)
    def _interfaces_page(self):
        super()._interfaces_page()
        self.adapter_hint.setText('Adapter 1 / eth0: transport WAN. Adapter 2 / eth1: LAN. Hub adapter 3 / eth2: unfiltered Internet WAN; unused on Spokes.')
        self.counts_selected=True;self.count_box.hide()
        self.interfaces_layout.parentWidget().layout().itemAt(0).widget().setText('Adapter roles follow the Hub deployment selected on Welcome; map them in your hypervisor.')

    def populate_interfaces(self, names, settings=None):
        role=(settings or {}).get('node_role',self.node_role.currentData())
        mode=(settings or {}).get('hub_wan_mode',self.hub_wan_mode.currentData())
        self.hub_wan_mode.setVisible(role=='hub')
        self.hub_wan_mode.blockSignals(True);self.hub_wan_mode.setCurrentIndex(self.hub_wan_mode.findData(mode));self.hub_wan_mode.blockSignals(False)
        if role in ('hub','spoke') and self.node_role.currentData()!=role:
            self.node_role.blockSignals(True);self.node_role.setCurrentIndex(self.node_role.findData(role));self.node_role.blockSignals(False)
        if names not in (['eth0'],['eth0','eth1'],['eth0','eth1','eth2']) or (role=='spoke' and len(names)<2) or (role=='hub' and mode=='dual' and len(names)<3):
            self.adapter_names=list(names);self.notice.setText('Spokes need WAN and LAN. A one-WAN Hub needs at least one adapter; a two-WAN Hub needs three: eth0 transport WAN, eth1 optional LAN, eth2 Internet WAN. Power off and add the missing adapter in your hypervisor, then restart setup.');self.next.setEnabled(False);return
        super().populate_interfaces(names, settings)
        self.counts_selected=True;self.visible_adapters=set(names)
        for n,row in self.interface_rows.items():
            previous_role=row['role'].currentData()
            fixed='WAN' if n=='eth0' or (role=='hub' and mode=='dual' and n==('eth1' if len(names)==2 else 'eth2')) else 'LAN' if n=='eth1' else 'Unused';row['role'].blockSignals(True);row['role'].clear();row['role'].addItem(fixed,fixed);row['role'].setEnabled(False);row['role'].blockSignals(False)
            if previous_role!=fixed:
                for key in ('address','gateway','dns'):row[key].clear()
            if fixed=='LAN':
                old=row['mode'].currentData();row['mode'].blockSignals(True);row['mode'].clear();row['mode'].addItem('Static IPv4','static')
                if role=='hub':row['mode'].addItem('Unused — no hub LAN advertised','disabled')
                row['mode'].setCurrentIndex(max(0,row['mode'].findData(old)));row['mode'].blockSignals(False)
            if n!='eth0' and fixed!='LAN':
                old=row['mode'].currentData();row['mode'].blockSignals(True);row['mode'].clear()
                for label,value in ([('DHCP','dhcp'),('Static IPv4','static')] if fixed=='WAN' else [('Unused','disabled')]):row['mode'].addItem(label,value)
                row['mode'].setCurrentIndex(max(0,row['mode'].findData(old)));row['mode'].blockSignals(False)
            for key in ('address','gateway','dns'):style_placeholder(row[key])
        self.adapter_hint.setText('Spoke: eth0 WAN; eth1 required LAN; eth2 unused if present.' if role=='spoke' else 'One-WAN Hub: eth0 receives tunnels and shares Internet. eth1 LAN is optional; eth2 is unused.' if mode=='single' else 'Two-WAN Hub: eth0 receives tunnels; eth1 is unfiltered Internet. No LAN adapter.' if len(names)==2 else 'Two-WAN Hub: eth0 receives tunnels; eth2 is unfiltered Internet; eth1 LAN is optional.')
        self.show_network_details(True);self.mode_changed()

    def settings(self):
        value={**super().settings(),'node_role':self.node_role.currentData()}
        if self.node_role.currentData()=='hub':value['hub_wan_mode']=self.hub_wan_mode.currentData()
        return value

    def role_selected(self):
        if hasattr(self,'hub_wan_mode'):self.hub_wan_mode.setVisible(self.node_role.currentData()=='hub')
        if self.adapter_names:self.populate_interfaces(self.adapter_names,self.settings())

    def show_network_details(self,details):
        super().show_network_details(True);self.count_box.hide()
        if self.page==2:self.heading.setText('WAN and LAN addressing')

    def select_counts(self):
        self.counts_selected=True;return self.adapter_names==['eth0','eth1']

    def controls(self):
        super().controls();self.count_box.hide();self.wan_count.setEnabled(False);self.lan_count.setEnabled(False)
        for row in self.interface_rows.values():row['role'].setEnabled(False)
        if self.page==2 and (not 1<=len(self.adapter_names)<=3 or (self.node_role.currentData()=='spoke' and len(self.adapter_names)<2) or (self.node_role.currentData()=='hub' and self.hub_wan_mode.currentData()=='dual' and len(self.adapter_names)<3)):self.next.setEnabled(False)
        if self.page==2 and self.node_role.currentData()=='hub' and self.hub_wan_mode.currentData()=='dual' and len(self.adapter_names)<3:
            self.notice.setText('Two-WAN Hub requires three adapters: eth0 transport WAN, eth1 optional LAN, eth2 Internet WAN. Power off, add the third adapter in your hypervisor, then restart setup.')

    def go_back(self):
        if self.busy or self.held:return
        target=2 if self.page==4 else max(0,self.page-1)
        if target==1 and self.access_ready:target=0
        self.show_page(target)

    def go_next(self):
        if self.page==0 and self.access_ready and self.identity_ready and not self.busy and not self.held:
            self.show_page(2)
            self.notice.setText('Root password already configured. Your console and SSH password is unchanged; use passwd after login to change it.')
            return
        super().go_next()


    PAGES=('Welcome','Root password','Network adapters','Review','Parto')
    def _build_wizard(self):
        super()._build_wizard()
        for label in self.panel.findChildren(QtWidgets.QLabel):
            if label.text()=='OVERLAY Virtual Appliance':label.setText('Parto')
            elif label.text()=='OVERLAY virtual appliance':label.setText('A trusted path to the open Internet')

    def _welcome_page(self):
        layout=self._page();layout.addWidget(self.label('Share an open connection. Connect trusted sites.','section'))
        layout.addWidget(self.label('Parto creates a private overlay between one hub and your spokes. Setup and peer approval stay on your appliances — no management portal or registration.','muted'))
        box=QtWidgets.QGroupBox('Choose this appliance’s role');form=QtWidgets.QVBoxLayout(box)
        self.node_role=QtWidgets.QComboBox();self.node_role.addItem('Hub · share a connection with trusted spokes','hub');self.node_role.addItem('Spoke · connect local clients to the hub','spoke');self.node_role.currentIndexChanged.connect(self.role_selected);form.addWidget(self.node_role)
        self.hub_wan_mode=QtWidgets.QComboBox();self.hub_wan_mode.addItem('One WAN · receive tunnels and share Internet on the same connection','single');self.hub_wan_mode.addItem('Two WANs + optional LAN · requires three adapters','dual');self.hub_wan_mode.currentIndexChanged.connect(self.role_selected);form.addWidget(self.hub_wan_mode)
        form.addWidget(self.label('Hub: choose one shared WAN or two separate WANs. The tunnel-facing IPv4 must be reachable by the spokes (public or routed private); use port forwarding when needed; the second Internet WAN can be behind CGNAT. Hub LAN is optional. Spokes need WAN + LAN and initiate outbound.','muted'));layout.addWidget(box)
        layout.addWidget(self.label('Next: set your root password, configure WAN/LAN addressing, then open HTTPS management in your browser.','muted'));layout.addStretch()
    def _review_page(self):
        layout=self._page();self.review=self.label()
        self.review.setStyleSheet(f'background: {wizard.theme.CARD}; border: 1px solid {wizard.theme.LINE}; border-radius: 8px; padding: 14px;')
        layout.addWidget(self.review)
        layout.addWidget(self.label('Next applies these network settings. Open the HTTPS address shown next to select your transport and exchange peer files in your browser.','muted'))
        layout.addStretch()
    def maybe_launch(self):
        if getattr(self,'manager',None) is not None:return
        if self.held or self.busy or not self.identity_ready or not self.access_ready or self.splash_timer.isActive():return
        if not self.current_snapshot.get('settings'):return
        self.timer.stop();self.hide();self.manager=WebWelcome(role=self.current_snapshot['settings'].get('node_role'));self.manager.showFullScreen()
    def begin(self,settings):
        self.show_page(4);self.busy=True;self.progress.setRange(0,0);self.progress_title.setText('Applying local network settings')
        self.progress_detail.setText('The management portal is not used.');self.code.hide();self.progress_hint.hide();self.controls()
        self.job=NetworkWork(settings,self);self.job.completed.connect(self.result);self.job.start()
    def result(self,ok,code):
        self.busy=False
        if not ok:super().result(ok,code);return
        self.refresh()
    def on_snapshot(self,value):
        # The managed bootstrap status must never trigger enrollment/GUI launch.
        value=dict(value,status={})
        super().on_snapshot(value)
        self.code.hide();self.progress_hint.hide()
        if self.page==4 and not self.held and not self.manager_visible():
            self.progress_title.setText('Preparing local standalone setup');self.progress_detail.setText('Your root password and network settings stay on this VM.')
    def manager_visible(self):return getattr(self,'manager',None) is not None

if __name__=='__main__':
    app=QtWidgets.QApplication(sys.argv);app.setFont(wizard.theme.font(11));window=Setup();window.showFullScreen();sys.exit(app.exec_())
