import json
from copy import deepcopy
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import standalone_overlay as s

class ExchangeTests(unittest.TestCase):
    def config(self,role='hub',transport='ipsec',n=1):
        return {'label':role,'role':role,'transport':transport,'endpoint':f'198.51.100.{n}','wan':'eth0','lans':['eth1'],
                'prefixes':[f'172.{20+n}.0.0/24'],'internet_gateway':role=='hub','lab_mode':True}
    def exchange(self,transport='ipsec'):
        hub=s.new(self.config(transport=transport));file=s.hub_file(hub)
        ca=s.x509.load_pem_x509_certificate(hub['ca'].encode());fp=s.fingerprint(ca.public_bytes(s.serialization.Encoding.DER))
        spoke=s.new(self.config('spoke',transport,2),file,fp);request=s.request_file(spoke)
        key_fp=s.fingerprint(s.public_bytes(s.load_key(spoke['key']).public_key()))
        hub=s.approve(hub,request,key_fp);spoke=s.accept(spoke,s.hub_file(hub,spoke['node']));return hub,spoke
    def test_reachable_endpoints_need_no_address_scope_setting(self):
        for transport in ('ipsec', 'tls'):
            for address in ('8.8.8.8', '10.20.30.40', '172.16.20.1', '192.168.143.10', '100.64.20.1'):
                with self.subTest(transport=transport, address=address):
                    config=self.config(transport=transport);config.pop('lab_mode');config['endpoint']=address
                    hub=s.new(config);invite=s.hub_file(hub)
                    peer=self.config('spoke',transport,2);peer.pop('lab_mode');peer['endpoint']=''
                    spoke=s.new(peer,invite,s.inspect_peer(invite)['fingerprint'])
                    request=s.request_file(spoke)
                    hub=s.approve(hub,request,s.inspect_peer(request)['fingerprint'])
                    spoke=s.accept(spoke,s.hub_file(hub,spoke['node']))
                    plan=s.overlay.compile_plan(s.desired(spoke['hub_file']['body']),hub['network'])
                    self.assertEqual(len(plan['links']),1)
                    self.assertEqual(s.desired(spoke['hub_file']['body'])['sites'][0]['uplinks'][0]['endpoint'],address)
                    for file in (invite,request,s.hub_file(hub,spoke['node'])):
                        self.assertNotIn('lab_mode',json.dumps(file))

    def test_legacy_scope_flag_no_longer_restricts_private_endpoints(self):
        config=self.config();config.update(endpoint='192.168.143.10',lab_mode=False)
        hub=s.new(config);self.assertNotIn('lab_mode',hub['settings'])
        invite=s.hub_file(hub);body=deepcopy(invite['body'])
        body['roster'][0]['settings']['lab_mode']=False
        legacy=s.sign(body,s.load_key(hub['ca_key']))
        peer=self.config('spoke',n=2);peer['lab_mode']=True
        spoke=s.new(peer,legacy,s.inspect_peer(legacy)['fingerprint'])
        self.assertEqual(spoke['network'],hub['network'])

    def test_unsafe_endpoints_still_rejected_and_managed_policy_unchanged(self):
        for address in ('0.0.0.0','127.0.0.1','169.254.1.2','224.0.0.1','255.255.255.255','not-an-ip'):
            config=self.config();config.pop('lab_mode');config['endpoint']=address
            with self.subTest(address=address),self.assertRaises(ValueError):s.settings(config)
        with self.assertRaisesRegex(ValueError,'public IPv4'):
            s.overlay._ipv4('192.168.143.10','endpoint',False)

    def test_ipsec_and_tls_exchange_identical_plans(self):
        for transport in ('ipsec','tls'):
            with self.subTest(transport=transport):
                hub,spoke=self.exchange(transport)
                self.assertEqual(s.desired(s.hub_file(hub)['body']),s.desired(spoke['hub_file']['body']))
                plan=s.overlay.compile_plan(s.desired(spoke['hub_file']['body']),hub['network'])
                self.assertEqual(len(plan['links']),1);self.assertEqual(s.desired(spoke['hub_file']['body'])['topology'],'hub_spoke')
    def test_exports_contain_no_private_key(self):
        hub,spoke=self.exchange()
        for file in (s.hub_file(hub),s.request_file(spoke)):
            raw=json.dumps(file);self.assertNotIn('PRIVATE KEY',raw);self.assertNotIn('ca_key',raw)
            self.assertNotIn('password',raw);self.assertNotIn('registration_id',raw)
    def test_revocation_list_identifies_certificate_authority(self):
        hub,spoke=self.exchange()
        ca=s.x509.load_pem_x509_certificate(hub['ca'].encode())
        issuer=ca.extensions.get_extension_for_class(s.x509.SubjectKeyIdentifier).value.digest
        cert=s.x509.load_pem_x509_certificate(spoke['hub_file']['body']['roster'][1]['cert'].encode())
        revocations=s.x509.load_pem_x509_crl(spoke['hub_file']['body']['crl'].encode())
        for signed in (ca,cert,revocations):
            self.assertEqual(signed.extensions.get_extension_for_class(s.x509.AuthorityKeyIdentifier).value.key_identifier,issuer)
    def test_embedded_fingerprints_are_signed_and_verified(self):
        hub,spoke=self.exchange()
        for envelope in (s.hub_file(hub,spoke['node']),s.request_file(spoke)):
            info=s.inspect_peer(envelope)
            self.assertEqual(envelope['body']['fingerprint'],info['fingerprint'])
            tampered=deepcopy(envelope);tampered['body']['fingerprint']='0'*64
            with self.assertRaises(ValueError):s.inspect_peer(tampered)

    def test_two_spokes_receive_distinct_bound_approvals(self):
        for transport in ('ipsec','tls'):
            hub,first=self.exchange(transport)
            invitation=s.hub_file(hub);fp=s.inspect_peer(invitation)['fingerprint']
            second=s.new(self.config('spoke',transport,3),invitation,fp)
            request=s.request_file(second);hub=s.approve(hub,request,s.inspect_peer(request)['fingerprint'])
            first_file=s.hub_file(hub,first['node']);second_file=s.hub_file(hub,second['node'])
            self.assertNotEqual(first_file,second_file)
            first=s.accept(first,first_file);second=s.accept(second,second_file)
            self.assertEqual(len(first['hub_file']['body']['roster']),2)
            self.assertEqual(len(second['hub_file']['body']['roster']),2)
            self.assertNotIn(second['node'],[r['node'] for r in first['hub_file']['body']['roster']])
            for state,wrong in ((first,second_file),(second,first_file),(first,s.hub_file(hub))):
                with self.assertRaisesRegex(ValueError,'addressed'):s.accept(state,wrong)
            with self.assertRaisesRegex(ValueError,'invitation'):s.new(self.config('spoke',transport,4),first_file,fp)
            with self.assertRaisesRegex(ValueError,'approved spoke'):s.hub_file(hub,'f'*32)
            for file in (first_file,second_file):self.assertNotIn('PRIVATE KEY',json.dumps(file))

    def test_legacy_signed_files_remain_readable_with_explicit_trust(self):
        hub,spoke=self.exchange();body=deepcopy(s.hub_file(hub)['body'])
        body['schema']=1;body.pop('recipient');body.pop('fingerprint')
        legacy=s.sign(body,s.load_key(hub['ca_key']))
        spoke['hub_file']=legacy  # State saved by the previous schema-1 release.
        accepted=s.accept(spoke,legacy)
        self.assertEqual(accepted['hub_file'],legacy)

    def test_wrong_hub_fingerprint(self):
        hub=s.new(self.config())
        with self.assertRaisesRegex(ValueError,'fingerprint'):s.new(self.config('spoke',n=2),s.hub_file(hub),'0'*64)
    def test_tampered_hub_and_spoke(self):
        hub,spoke=self.exchange();file=s.hub_file(hub,spoke['node']);file['body']['roster'][0]['settings']['endpoint']='198.51.100.200'
        with self.assertRaisesRegex(ValueError,'signature'):s.accept(spoke,file)
        request=s.request_file(spoke);request['body']['settings']['prefixes']=['172.28.0.0/24']
        with self.assertRaisesRegex(ValueError,'signature'):s.approve(hub,request,s.fingerprint(s.public_bytes(s.load_key(spoke['key']).public_key())))
    def test_other_network_and_duplicate_rejected(self):
        hub,spoke=self.exchange();other=s.new(self.config());request=s.request_file(spoke);fp=s.fingerprint(s.public_bytes(s.load_key(spoke['key']).public_key()))
        with self.assertRaisesRegex(ValueError,'another network'):s.approve(other,request,fp)
        with self.assertRaisesRegex(ValueError,'already approved'):s.approve(hub,request,fp)
    def test_overlap_rejected(self):
        hub=s.new(self.config());ca=s.x509.load_pem_x509_certificate(hub['ca'].encode());fp=s.fingerprint(ca.public_bytes(s.serialization.Encoding.DER))
        cfg=self.config('spoke',n=2);cfg['prefixes']=hub['settings']['prefixes'];spoke=s.new(cfg,s.hub_file(hub),fp)
        with self.assertRaisesRegex(ValueError,'overlap'):s.approve(hub,s.request_file(spoke),s.fingerprint(s.public_bytes(s.load_key(spoke['key']).public_key())))
    def test_transport_mismatch(self):
        hub=s.new(self.config());ca=s.x509.load_pem_x509_certificate(hub['ca'].encode());fp=s.fingerprint(ca.public_bytes(s.serialization.Encoding.DER))
        with self.assertRaisesRegex(ValueError,'transport'):s.new(self.config('spoke','tls',2),s.hub_file(hub),fp)
    def test_replay_and_removal(self):
        hub,spoke=self.exchange();old=deepcopy(spoke['hub_file']);removed=s.remove(hub,spoke['node'])
        cert=s.x509.load_pem_x509_certificate(hub['roster'][1]['cert'].encode())
        revoked=s.x509.load_pem_x509_crl(removed['crl'].encode())
        self.assertIsNotNone(revoked.get_revoked_certificate_by_serial_number(cert.serial_number))
        self.assertEqual([row['node'] for row in removed['roster']],[hub['node']])
        with self.assertRaisesRegex(ValueError,'addressed|removed'):s.accept(spoke,s.hub_file(removed))
        spoke['hub_file']['body']['revision']+=1
        with self.assertRaisesRegex(ValueError,'replayed'):s.accept(spoke,old)
    def test_unknown_fields_duplicate_json_and_size(self):
        for raw in ('{"x":1,"x":2}','x'*s.MAX_FILE+'a'):
            with self.assertRaises(ValueError):s.parse(raw)
        cfg=self.config();cfg['topology']='full_mesh'
        with self.assertRaises(ValueError):s.new(cfg)
    def test_spoke_cannot_share_gateway(self):
        cfg=self.config('spoke');cfg['internet_gateway']=True
        with self.assertRaisesRegex(ValueError,'Only the hub'):s.new(cfg)
    def test_approved_certificate_matches_own_key(self):
        hub,spoke=self.exchange();file=s.hub_file(hub,spoke['node'])
        # A hub cannot silently replace the spoke key/config even with a valid bundle signature.
        file['body']['roster'][1]['settings']['label']='altered';file['body']['revision']+=1;file=s.sign(file['body'],s.load_key(hub['ca_key']))
        with self.assertRaisesRegex(ValueError,'match this spoke'):s.accept(spoke,file)

if __name__=='__main__':unittest.main()
