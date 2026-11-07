"""Parto's Internet-only hub has no fabricated LAN or advertised placeholder."""
from copy import deepcopy
from pathlib import Path
import sys,unittest
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'src'),str(Path(__file__).resolve().parents[1]/'appliances/parto-vm/runtime')]
import standalone_overlay as exchange
import standalone_live as live
import standalone_network as network
import overlay

class LanlessHubTests(unittest.TestCase):
    def topology(self,transport='ipsec'):
        def settings(role,n):
            return dict(label=role,role=role,transport=transport,endpoint=f'192.0.2.{n}',wan='eth0',lans=[] if role=='hub' else ['eth1'],prefixes=[] if role=='hub' else [f'172.30.{210+n}.0/24'],internet_gateway=role=='hub',lab_mode=True,isolate_spokes=role=='hub')
        hub=exchange.new(settings('hub',1));inv=exchange.hub_file(hub)
        for n in (2,3):
            spoke=exchange.new(settings('spoke',n),inv,exchange.inspect_peer(inv)['fingerprint']);req=exchange.request_file(spoke);hub=exchange.approve(hub,req,exchange.inspect_peer(req)['fingerprint']);approval=exchange.hub_file(hub,recipient=spoke['node']);exchange.accept(spoke,approval)
        return exchange.hub_file(hub)['body']
    def test_no_lan_hub_signed_exchange_and_managed_default_stay_strict(self):
        body=self.topology();config=exchange.desired(body)
        hub=next(s for s in config['sites'] if s['name']==config['hub'])
        self.assertEqual(hub['lan_interfaces'],[]);self.assertEqual(hub['prefixes'],[])
        with self.assertRaises(ValueError):overlay.validate_config(config,lab_mode=True)
        with self.assertRaises(ValueError):overlay.compile_plan(config,body['network'])
    def test_both_transports_have_no_hub_lan_rules_or_prefixes(self):
        for transport in ('ipsec','tls'):
            body=self.topology(transport);config=exchange.desired(body)
            for internet in (True,False):
                for access in (True,False):
                    plan=live.plan(config,body['network'],body,{'internet':internet,'spoke_access':access});hub=plan['sites'][config['hub']]
                    self.assertEqual(hub['prefixes'],[]);self.assertEqual(hub['lan_interfaces'],[])
                    self.assertNotIn('  network ',hub['frr_config'])
                    if not access:
                        self.assertEqual(set(hub['tunnels'][0]['exported_prefixes']),{'0.0.0.0/0'} if internet else set())
                    if not internet:self.assertNotIn(' default-originate ',hub['frr_config'])
                    text=live.LiveRuntime._firewall(body['network'],plan,hub,{'eth0':'192.0.2.1'})
                    self.assertNotIn('{  }',text);self.assertNotIn('"eth1"',text)
                    self.assertEqual('masquerade' in text,internet)
    def test_spoke_without_advertised_lan_is_rejected(self):
        row=self.topology()['roster'][1]['settings']
        for fields in ({'lans':[],'prefixes':[]},{'prefixes':[]},{'lans':[]}):
            with self.assertRaises(ValueError):exchange.settings({**row,**fields})
    def test_role_aware_one_nic_and_unused_validation(self):
        wan={'name':'eth0','role':'WAN','mode':'dhcp'};unused={'name':'eth1','role':'LAN','mode':'disabled'}
        for rows in ([wan],[wan,unused]):
            value=network.validate({'interfaces':rows,'node_role':'hub'});network.validate_node({'role':'hub','wan':'eth0','lans':[],'prefixes':[]},value)
            with self.assertRaises(ValueError):network.validate({'interfaces':rows,'node_role':'spoke'})
        with self.assertRaises(ValueError):network.validate_node({'role':'spoke','wan':'eth0','lans':['eth1'],'prefixes':['172.30.212.0/24']},{'interfaces':[wan,unused],'node_role':'hub'})
    def test_unused_hub_cannot_smuggle_an_advertised_prefix(self):
        row=self.topology()['roster'][0]['settings']
        with self.assertRaises(ValueError):exchange.settings({**row,'prefixes':['172.30.211.0/24']})

if __name__=='__main__':unittest.main()
