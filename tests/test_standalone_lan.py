import sys,tempfile,json,contextlib
from pathlib import Path
from unittest import TestCase,mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import standalone_lan as lan

class LanTests(TestCase):
 def config(self,**kw):return dict(address='172.30.212.254/24',dhcp=True,pool_start='172.30.212.100',pool_end='172.30.212.199',lease_hours=12,**kw)
 def test_scoped_dhcp_and_options(self):
  text=lan.config(self.config());self.assertIn('port=0',text);self.assertIn('interface=eth1',text);self.assertIn('except-interface=eth0',text);self.assertIn('option:router,172.30.212.254',text);self.assertIn('255.255.255.0,12h',text)
 def test_reject_bad_pools_and_overlaps(self):
  value=self.config()
  for patch in [{'pool_start':'172.30.212.254','pool_end':'172.30.212.254'},{'pool_start':'172.30.212.0'},{'pool_end':'172.30.213.2'},{'address':'10.254.0.1/24'},{'address':'8.8.8.1/24'},{'lease_hours':True},{'dhcp':'yes'}]:
   with self.assertRaises(ValueError):lan.validate({**value,**patch})
  for nets in [(['172.30.212.0/24'],[]),([],['172.30.212.0/23'])]:
   with self.assertRaises(ValueError):lan.validate(value,*nets)
 def test_hub_cannot_change_lan(self):
  with self.assertRaisesRegex(ValueError,'only on spokes'):lan.apply({'settings':{'role':'hub'}},self.config(),lambda x:None,lambda x:x,{'roster':[]})
 def test_failed_update_rolls_back_address_dhcp_and_ready(self):
  with tempfile.TemporaryDirectory() as directory,contextlib.ExitStack() as stack:
   root=Path(directory)
   for key in ['CONFIG','SETTINGS','READY','INTENT']:stack.enter_context(mock.patch.object(lan,key,root/(key+'.json')))
   stack.enter_context(mock.patch.object(lan.runtime,'_root_file',return_value=True))
   old={'interfaces':[{'name':'eth0','role':'WAN'},{'name':'eth1','role':'LAN','address':'172.30.212.254/24'}]};lan.runtime._atomic(lan.READY,old)
   state={'node':'x','settings':{'role':'spoke','prefixes':['172.30.212.0/24']},'generation':1}
   stack.enter_context(mock.patch.object(lan,'observed_wans',return_value=['192.168.143.0/24']));run=stack.enter_context(mock.patch.object(lan,'run'))
   address=stack.enter_context(mock.patch.object(lan,'change_address'));dhcp=stack.enter_context(mock.patch.object(lan,'dhcp',side_effect=[ValueError('failure'),None]))
   with self.assertRaisesRegex(ValueError,'failure'):lan.apply(state,self.config(),lambda x:None,lambda x:x,{'roster':[]})
   self.assertEqual(json.loads(lan.READY.read_text()),old);self.assertFalse(lan.INTENT.exists());self.assertEqual(address.call_count,2)

 def test_network_ready_remains_readable_by_console_after_lan_change(self):
  import stat
  with tempfile.TemporaryDirectory() as directory,contextlib.ExitStack() as stack:
   parent=Path(directory)/'parto';parent.mkdir(mode=0o755);private=parent/'standalone';private.mkdir(mode=0o700)
   for key,name in [('CONFIG','dhcp.conf'),('SETTINGS','settings.json'),('INTENT','intent.json')]:stack.enter_context(mock.patch.object(lan,key,private/name))
   stack.enter_context(mock.patch.object(lan,'READY',parent/'vm-network-ready'))
   ready={'interfaces':[{'name':'eth0','role':'WAN'},{'name':'eth1','role':'LAN','address':'172.30.212.254/24'}]};lan.READY.write_text(json.dumps(ready));lan.READY.chmod(0o644)
   stack.enter_context(mock.patch.object(lan,'observed_wans',return_value=['192.168.143.0/24']));stack.enter_context(mock.patch.object(lan,'run'));stack.enter_context(mock.patch.object(lan,'change_address'));stack.enter_context(mock.patch.object(lan,'dhcp'))
   state={'node':'x','settings':{'role':'spoke','prefixes':['172.30.212.0/24']},'generation':1};lan.apply(state,self.config(),lambda x:None,lambda x:x,{'roster':[]})
   self.assertEqual(stat.S_IMODE(parent.stat().st_mode),0o755)
   self.assertEqual(stat.S_IMODE(lan.READY.stat().st_mode),0o644)
   self.assertEqual(stat.S_IMODE(private.stat().st_mode),0o700)
