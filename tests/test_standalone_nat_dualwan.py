"""Identity-bound dynamic Spokes and independent, fail-closed Hub egress."""
from copy import deepcopy
from pathlib import Path
import sys,unittest
from unittest import mock
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'src'),str(Path(__file__).resolve().parents[1]/'appliances/parto-vm/runtime')]
import standalone_overlay as ex
import standalone_live as live
import standalone_network as net
import overlay,overlay_runtime as runtime

class NatDualWan(unittest.TestCase):
 def topology(self,transport='ipsec'):
  hub=ex.new(dict(label='Hub',role='hub',transport=transport,endpoint='192.0.2.1',wan='eth0',lans=[],prefixes=[],internet_gateway=True,lab_mode=True,egress='eth2'))
  invite=ex.hub_file(hub)
  for n in (2,3):
   spoke=ex.new(dict(label='Spoke'+str(n),role='spoke',transport=transport,endpoint='',wan='eth0',lans=['eth1'],prefixes=[f'172.30.{200+n}.0/24'],internet_gateway=False,lab_mode=True),invite,ex.inspect_peer(invite)['fingerprint'])
   request=ex.request_file(spoke);hub=ex.approve(hub,request,ex.inspect_peer(request)['fingerprint']);ex.accept(spoke,ex.hub_file(hub,recipient=spoke['node']))
  body=ex.hub_file(hub)['body'];config=ex.desired(body);return body,config,live.plan(config,body['network'],body)
 def test_signed_requests_need_no_spoke_endpoint_and_keep_distinct_identities(self):
  body,config,plan=self.topology();self.assertEqual([r['settings']['endpoint'] for r in body['roster'][1:]],['',''])
  self.assertNotEqual(body['roster'][1]['node'],body['roster'][2]['node'])
  site=plan['sites'][config['hub']];text=overlay.render_swanctl(site,{'eth0':'10.200.0.2'})
  self.assertEqual(text.count('remote_addrs = %any'),2);self.assertEqual(text.count('auth = pubkey'),4)
  self.assertIn('revocation = strict',text);self.assertNotIn('id = %any',text)
  self.assertTrue(all(live.LiveRuntime()._passive_peer(t) for t in site['tunnels']))
  self.assertTrue(all(not runtime.Runtime()._passive_peer(t) for t in site['tunnels']))
  old=deepcopy(site)
  for t in old['tunnels']:t['dynamic_peer']=False
  with self.assertRaises(ValueError):overlay.render_swanctl(old,{'eth0':'10.200.0.2'})
 def test_both_transports_and_all_policies_keep_cleartext_off_underlay(self):
  for transport in ('ipsec','tls'):
   body,config,_=self.topology(transport)
   for internet in (True,False):
    for access in (True,False):
     plan=live.plan(config,body['network'],body,{'internet':internet,'spoke_access':access});site=plan['sites'][config['hub']]
     text=live.LiveRuntime._firewall(body['network'],plan,site,{'eth0':'10.200.0.2'})
     self.assertNotIn('ip saddr  ',text);self.assertNotIn('oifname { "eth0" } accept',text)
     self.assertEqual('masquerade' in text,internet)
     if internet:self.assertIn('oifname { "eth2" }',text)
     self.assertEqual('default-originate' in site['frr_config'],internet)
 def test_role_validation_and_local_egress_binding(self):
  wan={'name':'eth0','role':'WAN','mode':'dhcp'};lan={'name':'eth1','role':'LAN','mode':'static','address':'172.30.211.254/24'};egress={'name':'eth2','role':'WAN','mode':'dhcp'}
  ready=net.validate({'node_role':'hub','interfaces':[wan,lan,egress]})
  net.validate_node({'role':'hub','wan':'eth0','lans':['eth1'],'prefixes':['172.30.211.0/24'],'egress':'eth2'},ready)
  with self.assertRaises(ValueError):net.validate({'node_role':'spoke','interfaces':[wan,lan,egress]})
  net.validate({'node_role':'spoke','interfaces':[wan,lan,{'name':'eth2','role':'Unused','mode':'disabled'}]})
 def test_single_wan_hub_and_dual_wan_requires_three_nics(self):
  first={'name':'eth0','role':'WAN','mode':'dhcp'}
  ready=net.validate({'node_role':'hub','hub_wan_mode':'single','interfaces':[first]})
  net.validate_node({'role':'hub','wan':'eth0','lans':[],'prefixes':[]},ready)
  with self.assertRaises(ValueError):net.validate({'node_role':'hub','hub_wan_mode':'dual','interfaces':[first,{'name':'eth1','role':'WAN','mode':'dhcp'}]})
  ready=net.validate({'node_role':'hub','hub_wan_mode':'dual','interfaces':[first,{'name':'eth1','role':'LAN','mode':'disabled'},{'name':'eth2','role':'WAN','mode':'dhcp'}]})
  net.validate_node({'role':'hub','wan':'eth0','lans':[],'prefixes':[],'egress':'eth2'},ready)
  with self.assertRaises(ValueError):net.validate_node({'role':'hub','wan':'eth0','lans':[],'prefixes':[]},ready)
  with self.assertRaises(ValueError):net.validate({'node_role':'hub','hub_wan_mode':'single','interfaces':ready['interfaces']})
 def test_egress_policy_has_guard_default_and_owned_source_rules(self):
  body,config,plan=self.topology();site=plan['sites'][config['hub']];engine=live.LiveRuntime()
  inventory={'interfaces':{'eth2':{'flags':['UP'],'addr_info':[{'family':'inet','scope':'global','local':'10.204.0.2','prefixlen':30}]}},'routes':[{'dev':'eth2','dst':'default','gateway':'10.204.0.1'}]}
  with mock.patch.object(engine,'_inventory',return_value=inventory):
   ops=engine._commands(body['network'],plan,site,{'eth0':'10.203.0.2'},{'eth0':'10.203.0.1'},Path('/revision/test'))
  self.assertTrue(any(o['argv'][1:5]==['route','add','blackhole','default'] for o in ops))
  self.assertTrue(any('10.204.0.1' in o['argv'] and 'eth2' in o['argv'] for o in ops))
  rules=[o for o in ops if 'iif' in o['argv']]
  self.assertEqual(len(rules),2);self.assertTrue(all(o.get('owner_name') for o in rules))
  self.assertEqual(live.LiveRuntime._gateway_egress_errors(site,inventory),[])
  inventory['interfaces']['eth2']['flags']=[]
  self.assertTrue(live.LiveRuntime._gateway_egress_errors(site,inventory))

if __name__=='__main__':unittest.main()
