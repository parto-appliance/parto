"""Signed profile selection and the fail-closed obfs4/TLS boundary."""
import unittest,sys,base64,os,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import standalone_overlay as s,standalone_live as live
class Obfs4Tests(unittest.TestCase):
 def config(self,role,n,obfuscated=True):
  value={'label':role,'role':role,'transport':'tls','endpoint':'198.51.100.10' if role=='hub' else '', 'wan':'eth0','lans':['eth1'],'prefixes':[f'172.30.{n}.0/24'],'internet_gateway':role=='hub','lab_mode':True}
  if obfuscated:
   value['obfuscated']=True
   if role=='hub':value['obfs4_cert']=base64.b64encode(os.urandom(52)).decode().rstrip('=')
  return value
 def states(self):
  hub=s.new(self.config('hub',1));invitation=s.invitation_file(hub);spoke=s.new(self.config('spoke',2),invitation,s.inspect_peer(invitation)['fingerprint']);request=s.request_file(spoke);hub=s.approve(hub,request,s.inspect_peer(request)['fingerprint']);spoke=s.accept(spoke,s.hub_file(hub,spoke['node']));return hub,spoke
 def test_signed_descriptor_and_mutual_selection(self):
  hub,spoke=self.states();invite=s.invitation_file(hub)
  self.assertEqual(invite['body']['roster'][0]['settings']['obfs4_cert'],hub['settings']['obfs4_cert'])
  from copy import deepcopy
  bad=deepcopy(invite);bad['body']['roster'][0]['settings']['obfs4_cert']=base64.b64encode(os.urandom(52)).decode().rstrip('=')
  with self.assertRaises(ValueError):s.read_hub(bad,s.inspect_peer(invite)['fingerprint'])
  with self.assertRaisesRegex(ValueError,'match'):s.new(self.config('spoke',3,False),invite,s.inspect_peer(invite)['fingerprint'])
  cfg=self.config('hub',1);cfg['transport']='ipsec'
  with self.assertRaises(ValueError):s.settings(cfg)
  cfg=self.config('hub',1);cfg['obfs4_cert']='invalid'
  with self.assertRaises(ValueError):s.settings(cfg)
 def test_tls_only_listens_on_loopback_inside_obfs4(self):
  hub,spoke=self.states();body=s.hub_file(hub)['body'];plan=live.plan(s.desired(body),hub['network'],body)
  h=plan['sites']['agent00001'];c=plan['sites']['agent00002']
  server=s.overlay.render_stunnel(h,{'eth0':'192.0.2.10'});client=s.overlay.render_stunnel(c,{'eth0':'192.0.2.11'})
  self.assertIn('accept = 127.0.0.1:4443',server);self.assertNotIn('accept = 192.0.2.10:443',server)
  self.assertIn('connect = 127.0.0.1:3443',client);self.assertNotIn('connect = 198.51.100.10:443',client)
  self.assertIn('local = 127.0.0.1',client);self.assertIn('socket = r:SO_BINDTODEVICE=lo',client)
  for text in (server,client):self.assertIn('verifyChain = yes',text);self.assertIn('requireCert = yes',text);self.assertIn('checkHost = ',text)
 def test_foreign_backend_port_blocks_initial_apply(self):
  from unittest.mock import patch
  site={'role':'hub','obfs4_cert':'fixture','tunnels':[{'if_id':1000,'local_uplink':'eth0','initiator':False}]}
  with patch.object(Path,'read_text',return_value='header\n0: 0100007F:115B 00000000:0000 0A\n'):
   self.assertIn('Private obfs4 bridge backend port is already in use',live.LiveRuntime._tls_port_errors(site,{'eth0':'192.0.2.10'}))
