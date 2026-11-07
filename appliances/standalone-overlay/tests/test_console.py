"""Native standalone wizard boundaries, without privileged guest operations."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
MANAGED = ROOT / 'appliances/parto-vm'
sys.path[:0] = [str(ROOT / 'src'), str(MANAGED)]
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
try:
    from PyQt5 import QtWidgets
except ImportError:
    QtWidgets = None


@unittest.skipIf(QtWidgets is None, 'PyQt5 required; run in the Debian build environment')
class StandaloneConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
        original = importlib.util.spec_from_file_location

        def local_wizard(name, location, *args, **kwargs):
            if str(location) == '/opt/parto-vm/console-launcher.py':
                location = MANAGED / 'console-launcher.py'
            return original(name, location, *args, **kwargs)

        exchange_spec=original('standalone_overlay',ROOT/'src/standalone_overlay.py')
        exchange=importlib.util.module_from_spec(exchange_spec);exchange_spec.loader.exec_module(exchange);sys.modules['standalone_overlay']=exchange
        spec = original('standalone_console_test', ROOT / 'appliances/standalone-overlay/standalone-console.py')
        cls.console = importlib.util.module_from_spec(spec)
        with mock.patch.object(importlib.util, 'spec_from_file_location', side_effect=local_wizard):
            spec.loader.exec_module(cls.console)

    def test_reachable_endpoint_form_has_no_private_wan_switch(self):
        with mock.patch.object(self.console.Work,'start'):
            window=self.console.Manager(role='hub')
        try:
            self.assertFalse(hasattr(window,'lab'))
            labels=[w.text().lower() for w in window.findChildren(QtWidgets.QCheckBox)]
            self.assertFalse(any('private wan' in label or 'lab' in label for label in labels))
            self.assertIn('private',window.endpoint.placeholderText())
            self.assertIn('reachable',window.endpoint_label.text().lower())
        finally:window.close()

    def test_network_review_has_no_managed_claim_instructions(self):
        window = self.console.Setup(live=False, splash_ms=60000)
        try:
            window.node_role.setCurrentIndex(window.node_role.findData('spoke'));window.populate_interfaces(['eth0', 'eth1'])
            window.show_page(3)
            page = window.pages.widget(3)
            text = '\n'.join(label.text() for label in page.findChildren(QtWidgets.QLabel))
            self.assertIn('eth0', text)
            self.assertIn('HTTPS', text)
            self.assertIn('peer files in your browser', text)
            for forbidden in ('pre-stage', 'claim', 'customer portal', 'registration code'):
                self.assertNotIn(forbidden, text.lower())
        finally:
            window.close()

    def test_staged_network_entrypoint_can_validate_the_real_next_transition(self):
        # Exercise the installed entrypoint, rather than the source-only fallback.
        import json
        import tempfile
        stage_spec = importlib.util.spec_from_file_location('standalone_stage_test', ROOT / 'appliances/standalone-overlay/stage.py')
        stage = importlib.util.module_from_spec(stage_spec)
        stage_spec.loader.exec_module(stage)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('opt/parto-vm', 'etc/systemd/system', 'etc/parto'):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / 'opt/parto-vm/build.json').write_text(json.dumps({'source_files': {},'architecture':'arm64'}))
            stage.stage(ROOT, root)
            entrypoint = root / 'usr/local/libexec/console-vm-network'
            window = self.console.Setup(live=False, splash_ms=60000)
            window.identity_ready = window.access_ready = True
            window.node_role.setCurrentIndex(window.node_role.findData('spoke'));window.populate_interfaces(['eth0', 'eth1'])
            wan = window.interface_rows['eth0']
            wan['mode'].setCurrentIndex(wan['mode'].findData('static'))
            wan['address'].setText('192.168.143.11/24')
            wan['gateway'].setText('192.168.143.2')
            wan['dns'].setText('192.168.143.2')
            window.interface_rows['eth1']['address'].setText('172.30.212.254/24')
            helper_spec=importlib.util.spec_from_file_location('parto_network_fixture',ROOT/'src/standalone_network.py')
            helper=importlib.util.module_from_spec(helper_spec);helper_spec.loader.exec_module(helper)
            original_path = type(Path('.'))
            def installed_path(value, *args, **kwargs):
                if str(value) == '/usr/local/libexec/console-vm-network':
                    return entrypoint
                return original_path(value, *args, **kwargs)
            try:
                window.show_page(2)
                # GUI validation must never invoke the privileged apply action.
                with mock.patch.dict(sys.modules,{'standalone_network':helper}), mock.patch('pathlib.Path', side_effect=installed_path), mock.patch('vm_network.main', side_effect=AssertionError('validation executed apply')):
                    window.go_next()
                    self.assertEqual(window.page, 3)
                    self.assertIn('192.168.143.11/24', window.review.text())
                    window.show_page(2)
                    wan['address'].setText('invalid')
                    window.go_next()
                    self.assertEqual(window.page, 2)
                    self.assertTrue(window.notice.text())
            finally:
                window.close()

    def test_only_hub_spoke_and_hub_gateway_are_offered(self):
        with mock.patch.object(self.console.Work, 'start'):
            window = self.console.Manager()
        try:
            self.assertEqual([window.role.itemData(i) for i in range(window.role.count())], ['hub', 'spoke'])
            self.assertTrue(window.isolation.isChecked())
            self.assertTrue(window.isolation.isEnabledTo(window.form))
            window.gateway.setChecked(True)
            window.role.setCurrentIndex(1)
            self.assertFalse(window.isolation.isEnabled())
            self.assertFalse(window.gateway.isEnabled())
            self.assertFalse(window.gateway.isChecked())
        finally:
            window.close()

    def test_placeholder_is_italic_only_while_empty(self):
        window = self.console.Setup(live=False, splash_ms=60000)
        try:
            window.node_role.setCurrentIndex(window.node_role.findData('spoke'));window.populate_interfaces(['eth0', 'eth1'])
            field=window.interface_rows['eth0']['address']
            self.assertTrue(field.font().italic())
            self.assertEqual(field.text(), '')
            field.setText('192.168.143.10/24')
            self.assertFalse(field.font().italic())
            self.assertEqual(field.text(), '192.168.143.10/24')
            field.clear();self.assertTrue(field.font().italic())
        finally:window.close()

    def test_connection_status_names_remote_sites(self):
        text=self.console.connection_lines([
            {'peer_label':'Tehran spoke','tls':'established','bgp':'Established'},
            {'peer_label':'Home hub','ipsec':'established','bgp':'Established'}])
        self.assertIn('Tehran spoke: established · BGP Established',text)
        self.assertIn('Home hub: established · BGP Established',text)
        self.assertNotIn('Peer 1',text)

    def test_hub_exports_selected_spoke_approval(self):
        with mock.patch.object(self.console.Work, 'start'):
            window=self.console.Manager()
        window.own_role='hub';window.peers=[{'node':'a'*32,'label':'Remote site','role':'spoke','endpoint':'192.168.143.11'}]
        try:
            with mock.patch.object(window,'export_protection',return_value=(True,None)), mock.patch.object(self.console.QtWidgets.QInputDialog,'getItem',return_value=('Remote site · 192.168.143.11 · aaaaaaaa',True)), mock.patch.object(self.console.QtWidgets.QFileDialog,'getSaveFileName',return_value=('/tmp/approval.json','')) as save, mock.patch.object(window,'run') as run:
                window.export()
                run.assert_called_once_with('export',{'recipient':'a'*32})
                self.assertEqual(Path(save.call_args.args[2]).name, 'Remote site-approved.json')
        finally:window.close()

    def test_local_exports_use_saved_site_name(self):
        with mock.patch.object(self.console.Work, 'start'):
            window = self.console.Manager()
        try:
            window.last_action = 'info'
            for role, suffix in [('hub', 'invitation'), ('spoke', 'request')]:
                with self.subTest(role=role):
                    window.result(dict(ok=True, node='n', role=role, label='Site / West',
                                       transport='tls', obfuscated=True, peers=[], fingerprint='f'))
                    with mock.patch.object(self.console.QtWidgets.QInputDialog, 'getItem',
                                           return_value=('Hub invitation — for adding a new spoke', True)), \
                         mock.patch.object(self.console.QtWidgets.QFileDialog, 'getSaveFileName',
                                           return_value=('', '')) as save:
                        window.export()
                    self.assertEqual(Path(save.call_args.args[2]).name, f'Site - West-{suffix}.json')
                    self.assertIn('TLS + BGP (NG)', window.info.toPlainText())
        finally:
            window.close()

    def test_encrypted_export_and_import_keep_passphrase_out_of_helper(self):
        import tempfile,json,stat
        with mock.patch.object(self.console.Work,'start'):w=self.console.Manager()
        try:
            with tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/'exchange.json';value={'body':{'test':'public fixture'},'signature':'fixture'}
                w.last_action='export';w.export_path=str(path)
                with mock.patch.object(w,'export_protection',return_value=(True,'fixture encryption passphrase only')):
                    w.result({'ok':True,'file':value})
                self.assertFalse(hasattr(w,'export_passphrase'))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                wrapper=json.loads(path.read_text());self.assertEqual(wrapper['format'],'sealed-exchange');self.assertNotIn('public fixture',path.read_text())
                with mock.patch.object(self.console.QtWidgets.QFileDialog,'getOpenFileName',return_value=(str(path),'')),mock.patch.object(self.console.QtWidgets.QInputDialog,'getText',return_value=('fixture encryption passphrase only',True)):
                    self.assertEqual(w.file(),value)
                with mock.patch.object(self.console.QtWidgets.QFileDialog,'getOpenFileName',return_value=(str(path),'')),mock.patch.object(self.console.QtWidgets.QInputDialog,'getText',return_value=('incorrect fixture passphrase',True)):
                    self.assertIsNone(w.file())
                w.result({'ok':False,'errors':['fixture failure']});self.assertFalse(hasattr(w,'export_passphrase'))
        finally:w.timer.stop();w.close()

    def test_obfuscated_transport_selection_is_explicit_and_helper_generates_descriptor(self):
        import json
        with mock.patch.object(self.console.Work,'start'):w=self.console.Manager('hub')
        try:
            w.transport.setCurrentIndex(w.transport.findData('obfs4'));w.endpoint.setText('198.51.100.10')
            ready={'node_role':'hub','interfaces':[{'name':'eth0','role':'WAN','mode':'dhcp'},{'name':'eth1','role':'LAN','mode':'static','address':'172.30.211.254/24'}]}
            with mock.patch.object(Path,'read_text',return_value=json.dumps(ready)),mock.patch.object(w,'run') as run:
                w.initialize();args=run.call_args.args;self.assertEqual(args[0],'initialize');settings=args[1]['settings'];self.assertTrue(settings['obfuscated']);self.assertEqual(settings['transport'],'tls');self.assertNotIn('obfs4_cert',settings)
        finally:w.timer.stop();w.close()

    def test_network_apply_never_starts_managed_bootstrap(self):
        worker = self.console.NetworkWork({'interfaces': []})
        result = mock.Mock(returncode=0, stdout='{"ok": true}')
        with mock.patch.object(self.console.subprocess, 'run', return_value=result) as run:
            worker.run()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][-2:], ['/usr/local/libexec/console-vm-network', 'apply'])



@unittest.skipIf(QtWidgets is None,'PyQt5 required')
class MonitoringTests(StandaloneConsoleTests):
    def test_counter_rates_reset_and_interface_recreation(self):
        old={'rx':100,'tx':200,'ifindex':8};new={'rx':1000100,'tx':2000200,'ifindex':8}
        self.assertEqual(self.console.rate_pair(old,new,5),(1.6,3.2))
        self.assertIsNone(self.console.rate_pair(old,dict(new,ifindex=9),5))
        self.assertIsNone(self.console.rate_pair(new,old,5))
        self.assertIsNone(self.console.rate_pair(None,new,5))
    def test_monitoring_timer_and_live_hub_controls(self):
        with mock.patch.object(self.console.Work,'start'):window=self.console.Manager()
        try:
            self.assertEqual(window.timer.interval(),5000)
            self.assertFalse(window.policy_box.isVisible())
            window.last_action='info';window.result(dict(ok=True,node='n',role='hub',transport='tls',peers=[],fingerprint='f',policy={'internet':True,'spoke_access':False}))
            self.assertTrue(window.live_internet.isChecked());self.assertFalse(window.live_spokes.isChecked())
            window.last_action='status';window.render_monitor({'tunnels':[{'id':'one','peer_label':'Tehran','tunnel':'established','bgp':'Established'}],'traffic':{'one':{'rx':10,'tx':20,'ifindex':3}}})
            self.assertEqual(window.monitor.item(0,0).text(),'Tehran');self.assertEqual(window.monitor.item(0,3).text(),'—')
            with mock.patch.object(self.console.time, 'monotonic', return_value=window.sample_time + 5):
                window.render_monitor({
                    'tunnels': [{'id': 'one'}],
                    'traffic': {'one': {'rx': 1_000_010, 'tx': 2_000_020, 'ifindex': 3}},
                })
            self.assertEqual(window.graph.samples[-1], (1.6, 3.2))
            self.assertIn('Download 1.600 Mbit/s · Upload 3.200 Mbit/s', window.sample_label.text())
        finally:window.timer.stop();window.close()

    def test_topology_shows_dual_wan_and_approved_spoke(self):
        dialog = self.console.TopologyDialog(None)
        try:
            hub = {'id': 'hub', 'role': 'hub', 'label': 'Lab Hub', 'wan': 'eth0',
                   'endpoint': '198.51.100.10', 'egress': 'eth2',
                   'lans': ['eth1'], 'prefixes': ['10.240.11.0/24']}
            spoke = {'id': 'spoke', 'peer': 'agent00002', 'role': 'spoke',
                     'label': 'Lab Spoke', 'wan': 'eth0', 'endpoint': '', 'egress': None,
                     'lans': ['eth1'], 'prefixes': ['10.240.12.0/24']}
            data = {'local': 'hub', 'sites': [hub, spoke],
                    'addresses': {'eth2': ['203.0.113.50/24'], 'eth1': ['10.240.11.254/24']},
                    'policy': {'internet': False, 'spoke_access': False}}
            status = {'policy': {'internet': True, 'spoke_access': True},
                      'tunnels': [{'peer': 'agent00002', 'tunnel': 'established', 'bgp': 'Established'}]}
            dialog.render(data, status)
            cards = [item.toPlainText() for item in dialog.scene.items()
                     if isinstance(item, self.console.QtWidgets.QGraphicsTextItem)]
            self.assertTrue(any('Open internet' in text and 'eth2 · dedicated WAN' in text for text in cards))
            self.assertTrue(any('203.0.113.50/24' in text and 'Sharing enabled' in text for text in cards))
            self.assertTrue(any('Lab Hub' in text and '198.51.100.10' in text for text in cards))
            self.assertTrue(any('Lab Spoke' in text and 'BGP Established' in text for text in cards))
            self.assertTrue(any('10.240.12.0/24' in text for text in cards))
            self.assertTrue(any(isinstance(item, self.console.QtWidgets.QGraphicsLineItem)
                                for item in dialog.scene.items()))
            def spoke_card():
                return next(item for item in dialog.scene.items()
                            if isinstance(item, self.console.QtWidgets.QGraphicsTextItem)
                            and 'Lab Spoke' in item.toPlainText())
            online_color = spoke_card().defaultTextColor()
            self.assertIn('Connected', spoke_card().toPlainText())
            status['tunnels'][0].update(tunnel='down', bgp='Connect')
            dialog.render(data, status)
            self.assertIn('Disconnected', spoke_card().toPlainText())
            self.assertNotEqual(online_color, spoke_card().defaultTextColor())
            status['tunnels'][0].update(tunnel='established', bgp='Established')
            dialog.render(data, status)
            self.assertIn('Connected', spoke_card().toPlainText())
            self.assertEqual(online_color, spoke_card().defaultTextColor())
        finally:
            dialog.close()

    def test_spoke_has_no_topology_even_if_info_contains_it(self):
        with mock.patch.object(self.console.Work, 'start'):
            window = self.console.Manager()
        try:
            window.last_action = 'info'
            window.result({'ok': True, 'role': 'spoke', 'node': 'spoke',
                           'transport': 'tls', 'fingerprint': '', 'peers': [],
                           'topology': {'sites': []}})
            self.assertTrue(window.topology_button.isHidden())
            self.assertIsNone(window.topology_data)
            window.show_topology()
            self.assertIsNone(window.topology_dialog)
        finally:
            window.timer.stop()
            window.close()

    def test_remove_spoke_uses_hub_picker_and_confirmation(self):
        with mock.patch.object(self.console.Work, 'start'):
            window = self.console.Manager()
        try:
            info = {'ok': True, 'role': 'spoke', 'node': 'local', 'transport': 'tls',
                    'fingerprint': '', 'peers': [
                        {'role': 'hub', 'node': 'local', 'label': 'Hub'},
                        {'role': 'spoke', 'node': 'a', 'label': 'Site'},
                        {'role': 'spoke', 'node': 'b', 'label': 'Site'}]}
            window.last_action = 'info'
            window.result(info)
            picker = self.console.QtWidgets.QInputDialog
            confirm = self.console.QtWidgets.QMessageBox
            with mock.patch.object(window, 'run') as run, \
                 mock.patch.object(picker, 'getItem', return_value=('2. Site', True)) as pick, \
                 mock.patch.object(confirm, 'question', return_value=confirm.No) as question:
                self.assertTrue(window.remove_button.isHidden())
                window.remove()
                pick.assert_not_called()
                window.result({**info, 'role': 'hub'})
                self.assertFalse(window.remove_button.isHidden())
                window.remove()
                run.assert_not_called()
                question.return_value = confirm.Yes
                window.remove()
                run.assert_called_once_with('remove', {'node': 'b'})
        finally:
            window.timer.stop()
            window.close()

    def test_spoke_create_is_disabled_without_invitation(self):
        with mock.patch.object(self.console.Work,'start'):w=self.console.Manager()
        try:
            w.role.setCurrentIndex(1);self.assertFalse(w.create.isEnabled());w.finished();self.assertFalse(w.create.isEnabled())
            w.hub={'verified':'invitation'};w.role_changed();self.assertTrue(w.create.isEnabled())
        finally:w.timer.stop();w.close()
    def test_fixed_two_adapter_roles_cannot_change(self):
        w=self.console.Setup(live=False,splash_ms=60000)
        try:
            w.node_role.setCurrentIndex(w.node_role.findData('spoke'));w.populate_interfaces(['eth0','eth1']);w.show_page(2)
            self.assertTrue(w.count_box.isHidden())
            self.assertEqual([r['role'].currentData() for r in w.interface_rows.values()],['WAN','LAN'])
            self.assertTrue(all(not r['role'].isEnabled() for r in w.interface_rows.values()))
            self.assertEqual(w.interface_rows['eth1']['mode'].count(),1)
            w.populate_interfaces(['eth0','eth1','eth2']);self.assertEqual(w.interface_rows['eth2']['role'].currentData(),'Unused')
        finally:w.close()

    def test_hub_requires_separate_internet_wan_and_can_leave_lan_unused(self):
        w=self.console.Setup(live=False,splash_ms=60000)
        try:
            w.identity_ready=True;w.hub_wan_mode.setCurrentIndex(w.hub_wan_mode.findData('dual'));w.populate_interfaces(['eth0','eth1','eth2']);w.show_page(2)
            mode=w.interface_rows['eth1']['mode'];self.assertNotEqual(mode.findData('disabled'),-1)
            mode.setCurrentIndex(mode.findData('disabled'));self.assertEqual(w.settings()['node_role'],'hub')
            self.assertEqual(w.settings()['interfaces'][1]['mode'],'disabled')
            self.assertEqual(w.interface_rows['eth2']['role'].currentData(),'WAN')
            w.populate_interfaces(['eth0']);w.show_page(2);self.assertFalse(w.next.isEnabled())
            w.node_role.setCurrentIndex(w.node_role.findData('spoke'));self.assertFalse(w.next.isEnabled())
        finally:w.close()

    def test_hub_deployment_choice_selects_roles_and_spokes_hide_endpoint(self):
        w=self.console.Setup(live=False,splash_ms=60000)
        try:
            w.populate_interfaces(['eth0','eth1','eth2'])
            self.assertEqual([r['role'].currentData() for r in w.interface_rows.values()],['WAN','LAN','Unused'])
            self.assertEqual(w.settings()['hub_wan_mode'],'single')
            w.hub_wan_mode.setCurrentIndex(w.hub_wan_mode.findData('dual'))
            self.assertEqual([r['role'].currentData() for r in w.interface_rows.values()],['WAN','LAN','WAN'])
            w.populate_interfaces(['eth0','eth1'])
            w.show_page(2);self.assertFalse(w.next.isEnabled());self.assertIn('three',w.notice.text())
            w.node_role.setCurrentIndex(w.node_role.findData('spoke'))
            self.assertTrue(w.hub_wan_mode.isHidden())
            self.assertEqual([r['role'].currentData() for r in w.interface_rows.values()],['WAN','LAN'])
            self.assertNotIn('hub_wan_mode',w.settings())
        finally:w.close()
        with mock.patch.object(self.console.Work,'start'):m=self.console.Manager('spoke')
        try:
            self.assertTrue(m.endpoint.isHidden());self.assertTrue(m.endpoint_label.isHidden())
            self.assertIn('NAT/CGNAT',m.reachability_hint.text())
        finally:m.timer.stop();m.close()

    def test_completed_password_is_skipped_in_both_directions(self):
        w=self.console.Setup(live=False,splash_ms=60000)
        try:
            w.identity_ready=True;w.populate_interfaces(['eth0','eth1'])
            w.show_page(2);w.access_ready=False;w.go_back();self.assertEqual(w.page,1)
            w.access_ready=True;w.show_page(2);w.go_back();self.assertEqual(w.page,0)
            with mock.patch.object(self.console.wizard.AccessOperation,'start') as start:
                w.go_next();self.assertEqual(w.page,2);start.assert_not_called()
            self.assertIn('already configured',w.notice.text())
            w.show_page(3);w.go_back();self.assertEqual(w.page,2)
        finally:w.close()

    def test_identity_hold_message_is_not_hidden_by_preparing_text(self):
        w=self.console.Setup(live=False,splash_ms=60000)
        try:
            w.on_snapshot({'hold':True,'identity_ready':False,'adapters':[]})
            self.assertIn('identity protection',w.progress_title.text())
            self.assertNotIn('Preparing local',w.progress_title.text())
        finally:w.close()

if __name__=='__main__':unittest.main()
