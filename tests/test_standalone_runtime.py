"""Prove local-only authority and certificate names in the shared transport engine."""
import importlib.util
from pathlib import Path
import sys
import unittest
from copy import deepcopy
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import standalone_overlay as s
spec=importlib.util.spec_from_file_location('standalone_root',Path(__file__).resolve().parents[1]/'appliances/standalone-overlay/standalone-root.py')
root=importlib.util.module_from_spec(spec)
# Loading the immutable standalone entry point intentionally changes its own
# runtime process binding; restore the global for other test modules afterward.
import overlay_runtime
original=overlay_runtime.DEVICE_DETAIL
spec.loader.exec_module(root)
overlay_runtime.DEVICE_DETAIL=original

class LocalAuthority(unittest.TestCase):
    def states(self,transport):
        cfg=lambda role,n:{'label':role,'role':role,'transport':transport,'endpoint':f'198.51.100.{n}','wan':'eth0','lans':['eth1'],'prefixes':[f'172.{20+n}.0.0/24'],'internet_gateway':role=='hub','lab_mode':True}
        hub=s.new(cfg('hub',1));ca=s.x509.load_pem_x509_certificate(hub['ca'].encode());fp=s.fingerprint(ca.public_bytes(s.serialization.Encoding.DER))
        spoke=s.new(cfg('spoke',2),s.hub_file(hub),fp);hub=s.approve(hub,s.request_file(spoke),s.fingerprint(s.public_bytes(s.load_key(spoke['key']).public_key())));spoke=s.accept(spoke,s.hub_file(hub,spoke['node']))
        for i,state in enumerate((hub,spoke)):state.update(instance_id=f'00000000-0000-4000-8000-{i+1:012d}',generation=1)
        return hub,spoke
    def test_no_estate_identity_required_and_certificate_names_match(self):
        for transport in ('ipsec','tls'):
            for state in self.states(transport):
                with patch.object(root,'read',return_value=state):
                    request=root.payload(state);_,local,plan,site=root.Engine()._compile(request)
                    self.assertEqual(local['board_serial'],state['instance_id']);self.assertEqual(request['tenant'],'standalone-'+state['network'])
                    self.assertEqual(site['identity'],s.identity(state['node'],state['network']))
                    for tunnel in site['tunnels']:
                        self.assertEqual(tunnel['peer_cert_cn'],tunnel['peer_identity'])
                    if transport=='tls':
                        configs=s.overlay.render_openvpn(site)
                        self.assertTrue(all('verify-x509-name '+site['tunnels'][0]['peer_identity']+' name' in config for config in configs.values()))
                    elif site['tunnels'][0]['initiator']:
                        config=s.overlay.render_swanctl(site)
                        self.assertIn('close_action = start',config)
                        self.assertIn('start_action = trap|start',config)
                        self.assertIn('keyingtries = 0',config)
    def test_standalone_vm_eligibility_does_not_relax_managed_policy(self):
        self.assertEqual(root.Engine()._model_errors({"lab_mode":False},{"model":"vm"}),[])
        self.assertTrue(overlay_runtime.Runtime()._model_errors({"lab_mode":False},{"model":"vm"}))

    def test_unapproved_spoke_cannot_activate(self):
        hub,spoke=self.states('ipsec');spoke['hub_file']['body']['roster']=spoke['hub_file']['body']['roster'][:1]
        # Alteration is rejected before runtime planning, even when local keys exist.
        with patch.object(root,'read',return_value=spoke):
            with self.assertRaises(ValueError):root.Engine()._identity()
    def test_restore_gate_uses_the_correct_family_unit(self):
        self.assertEqual(root.Engine().restore_unit,"console-standalone-restore.service")
        self.assertEqual(overlay_runtime.Runtime().restore_unit,"console-overlay-restore.service")
    def test_transport_capabilities_come_from_the_correct_family_manifest(self):
        def manifest(path):
            return {'transports':['ipsec','tls']} if path==root.INSTALL else {'transports':['ipsec']}
        with patch.object(root.runtime,'_json',side_effect=manifest):
            self.assertIn('tls',root.Engine()._supported_transports())
            self.assertNotIn('tls',overlay_runtime.Runtime()._supported_transports())

    def test_hub_renewal_preserves_peer_keys_and_returns_a_new_signed_roster(self):
        hub,spoke=self.states('tls');saved=[]
        with patch.object(root,'read',return_value=deepcopy(hub)),patch.object(root,'active',return_value=False),patch.object(root,'save',side_effect=lambda state:saved.append(state)):
            self.assertTrue(root.operate('refresh',{})['ok'])
        renewed=saved[0];self.assertEqual(renewed['revision'],hub['revision']+1)
        self.assertEqual(renewed['key'],hub['key']);self.assertEqual(renewed['ca_key'],hub['ca_key'])
        accepted=s.accept(spoke,s.hub_file(renewed,spoke['node']));self.assertEqual(accepted['key'],spoke['key'])
        self.assertNotEqual(renewed['roster'][1]['cert'],hub['roster'][1]['cert'])

    def test_engine_status_names_peers_for_apply_and_restore_too(self):
        hub,spoke=self.states('tls')
        for local,peer_id,expected in ((hub,'agent00002','spoke'),(spoke,'agent00001','hub')):
            answer={'ok':True,'tunnels':[{'peer':peer_id,'tls':'established','bgp':'Established'}]}
            with patch.object(root,'read',return_value=local),patch.object(root.runtime.Runtime,'status',return_value=answer):
                result=root.Engine().status(root.payload(local))
            self.assertEqual(result['tunnels'][0]['peer_label'],expected)

    def test_export_requires_recipient_or_explicit_invitation(self):
        hub,spoke=self.states('ipsec')
        with patch.object(root,'read',return_value=hub):
            with self.assertRaisesRegex(ValueError,'Choose an approved spoke'):root.operate('export',{})
            approval=root.operate('export',{'recipient':spoke['node']})['file']
            self.assertEqual(approval['body']['recipient'],spoke['node'])
            invitation=root.operate('export',{'invitation':True})['file']
            self.assertIsNone(invitation['body']['recipient'])

    def test_status_maps_peer_ids_to_remote_site_names(self):
        hub,spoke=self.states('tls')
        state={'ok':True,'tunnels':[{'peer':'agent00002','tls':'established','bgp':'Established'}]}
        with patch.object(root,'read',return_value=hub),patch.object(root.Engine,'status',return_value=state):
            answer=root.operate('status',{})
        self.assertEqual(answer['tunnels'][0]['peer_label'],'spoke')

    def test_installed_helper_and_complete_pins_required(self):
        with patch.object(root.runtime,'_root_file',return_value=False):
            self.assertIn('missing',root.Engine()._migration_errors()[0])
        with patch.object(root.runtime,'_root_file',return_value=True),patch.object(root.runtime,'_json',return_value={'helpers':{}}),patch.object(root.Engine,'_netlayer_lock_valid',return_value=True):
            self.assertIn('Standalone helper pins incomplete',root.Engine()._migration_errors())
    def test_only_hub_can_change_policy_and_saved_policy_is_local(self):
        hub,spoke=self.states('ipsec')
        with patch.object(root,'read',return_value=spoke):
            with self.assertRaisesRegex(ValueError,'Only the hub'):root.operate('policy',{'internet':False,'spoke_access':False})
        signed=s.hub_file(hub)
        with patch.object(root,'read',return_value=hub),patch.object(root,'active',return_value=False),patch.object(root,'save') as save:
            result=root.operate('policy',{'internet':False,'spoke_access':False})
            candidate=save.call_args.args[0]
            self.assertEqual(candidate['policy'],{'internet':False,'spoke_access':False})
            self.assertEqual(s.hub_file(candidate)['body'],signed['body'])
            self.assertEqual(result['state'],'policy_saved')

if __name__=='__main__':unittest.main()
