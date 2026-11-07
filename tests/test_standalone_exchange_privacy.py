"""Exchange confidentiality, minimization and unbranded on-wire identities."""
import sys,unittest,json
from pathlib import Path
from copy import deepcopy
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import standalone_overlay as s
import standalone_live as live

class PrivacyTests(unittest.TestCase):
 def settings(self,role,n):return {'label':'site'+str(n),'role':role,'transport':'tls','endpoint':'198.51.100.10' if role=='hub' else '', 'wan':'eth0','lans':['eth1'],'prefixes':[f'172.30.{n}.0/24'],'internet_gateway':role=='hub','lab_mode':True}
 def network(self):
  hub=s.new(self.settings('hub',1));spokes=[]
  for n in (2,3):
   invitation=s.invitation_file(hub);fp=s.inspect_peer(invitation)['fingerprint'];spoke=s.new(self.settings('spoke',n),invitation,fp);request=s.request_file(spoke);hub=s.approve(hub,request,s.inspect_peer(request)['fingerprint']);spokes.append(spoke)
  return hub,spokes
 def test_minimized_files_remain_signed_and_bound(self):
  h,peers=self.network();invite=s.invitation_file(h)
  self.assertEqual(len(invite['body']['roster']),1);s.read_hub(invite,s.inspect_peer(invite)['fingerprint'])
  for own in peers:
   exported=s.hub_file(h,own['node']);self.assertEqual({r['node'] for r in exported['body']['roster']},{h['node'],own['node']});s.accept(own,exported)
   other=next(p for p in peers if p!=own)
   with self.assertRaises(ValueError):s.accept(other,exported)
  self.assertEqual(len(s.hub_file(h)['body']['roster']),3)
 def test_sealing_randomizes_and_authenticates_all_fields(self):
  h,peers=self.network();plain=s.hub_file(h,peers[0]['node']);password='test fixture only '+('x'*24)
  first=s.seal(plain,password);second=s.seal(plain,password);self.assertNotEqual(first,second);self.assertEqual(s.unseal(first,password),plain)
  self.assertNotIn(h['settings']['endpoint'],json.dumps(first));self.assertNotIn(peers[0]['node'],json.dumps(first))
  with self.assertRaises(ValueError):s.unseal(first,password+'wrong')
  for key in ('salt','nonce','ciphertext'):
   bad=deepcopy(first);raw=bytearray(s.base64.b64decode(bad[key]));raw[0]^=1;bad[key]=s.base64.b64encode(raw).decode()
   with self.assertRaises(ValueError):s.unseal(bad,password)
  bad=dict(first,kdf='scrypt-999999999-8-1')
  with self.assertRaises(ValueError):s.unseal(bad,password)
  with self.assertRaises(ValueError):s.seal(plain,'short')
  with self.assertRaises(ValueError):s.unseal(dict(first,extra=True),password)
 def test_decrypted_tampering_still_fails_signature_validation(self):
  h,peers=self.network();plain=s.hub_file(h,peers[0]['node']);plain['body']['revision']+=1
  unlocked=s.unseal(s.seal(plain,'fixture passphrase only!!!'),'fixture passphrase only!!!')
  with self.assertRaises(ValueError):s.accept(peers[0],unlocked)
 def test_no_product_name_in_new_certificates_or_sni(self):
  h,peers=self.network();body=s.hub_file(h)['body'];plan=live.plan(s.desired(body),h['network'],body)
  for site in plan['sites'].values():
   config=s.overlay.render_stunnel(site)
   for line in config.splitlines():
    if line.startswith(('sni =','checkHost =')):
     self.assertFalse(any(w in line.lower() for w in ('overlay','parto','parto','invalid')))
   self.assertIn('verifyChain = yes',config);self.assertIn('requireCert = yes',config)
  for row in body['roster']:
   cert=s.x509.load_pem_x509_certificate(row['cert'].encode());names=cert.subject.rfc4514_string()+cert.issuer.rfc4514_string()+str(cert.extensions.get_extension_for_class(s.x509.SubjectAlternativeName).value)
   self.assertFalse(any(w in names.lower() for w in ('overlay','parto','parto','invalid')))
  hub=plan['sites']['agent00001'];spoke=plan['sites']['agent00002'];self.assertEqual(hub['tunnels'][0]['transport_server_name'],spoke['tunnels'][0]['transport_server_name'])

if __name__=='__main__':unittest.main()
