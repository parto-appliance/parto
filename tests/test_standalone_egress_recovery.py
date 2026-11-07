"""WAN carrier/DHCP recovery repairs owned routes without touching peers or policy."""
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from unittest import mock
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import standalone_live as live

class EgressRecovery(unittest.TestCase):
 def setup_engine(self,defaults=()):
  e=live.LiveRuntime();table='55208';src='10.204.0.2';gw='10.204.0.1'
  args=['/usr/sbin/ip','route','add','default','via',gw,'dev','eth2','src',src,'table',table,'proto',live.r.ROUTE_PROTOCOL,'metric','100']
  default={'argv':args,'undo':[('del' if x=='add' else x) for x in args],'kind':'command','purpose':'egress_default'}
  guard={'argv':[],'undo':[],'kind':'command','purpose':'egress_guard'}
  firewall={'kind':'firewall','argv':[],'undo':[]}
  selector={'kind':'gateway_rule','purpose':'egress_selector','argv':[],'undo':[]}
  state={'phase':'configured','payload_sha256':'h','operations':[default,guard,selector,firewall]}
  inventory={'interfaces':{'eth2':{'flags':['UP'],'addr_info':[{'family':'inet','scope':'global','local':src,'prefixlen':30}]}},'routes':[{'dev':'eth2','dst':'default','gateway':gw},*defaults]}
  site={'internet_egress':'eth2','uplinks':[{'iface':'eth0'}],'prefixes':[],'internet_gateway':{'spoke_prefixes':['172.30.202.0/24']}}
  e._compile=mock.Mock(return_value=({'network_id':'n'},None,None,site));e._lock=lambda:nullcontext();e._state=lambda n:state;e._inventory=lambda:inventory;e._payload_hash=lambda p:'h';e._owned_present=lambda o:True;e._boot_id=lambda:'boot';e.runner=mock.Mock()
  return e,state,inventory,default
 def test_missing_default_repaired_without_service_or_bgp_restart(self):
  e,state,inventory,default=self.setup_engine();writes=[]
  with mock.patch.object(live.r,'_atomic',side_effect=lambda p,v:writes.append(deepcopy(v))):r=e.reconcile_egress({})
  self.assertEqual(r['state'],'egress_restored');e.runner.run.assert_called_once_with(default['argv'])
  self.assertIn('egress_repair',writes[0]);self.assertNotIn('egress_repair',writes[-1])
  self.assertFalse(any('systemctl' in str(c) or 'vtysh' in str(c) for c in e.runner.run.call_args_list))
 def test_dhcp_source_and_gateway_update_paired_cleanup(self):
  e,state,inv,old=self.setup_engine();row={'dst':'default','dev':'eth2','gateway':'10.204.0.1','prefsrc':'10.204.0.2','table':'55208','protocol':live.r.ROUTE_PROTOCOL,'metric':100};inv['routes'].append(row)
  inv['interfaces']['eth2']['addr_info'][0]['local']='10.204.0.6';inv['routes'][0]['gateway']='10.204.0.5'
  with mock.patch.object(live.r,'_atomic'):e.reconcile_egress({})
  e.runner.run.assert_any_call(old['undo']);self.assertIn('10.204.0.6',state['operations'][0]['argv']);self.assertIn('10.204.0.5',state['operations'][0]['undo'])
 def test_carrier_down_preserves_guard_without_mutation(self):
  e,state,inv,op=self.setup_engine();inv['interfaces']['eth2']['flags']=[]
  with mock.patch.object(live.r,'_atomic') as write:r=e.reconcile_egress({})
  self.assertEqual(r['state'],'waiting_for_internet_wan');e.runner.run.assert_not_called();write.assert_not_called()
 def test_foreign_default_never_replaced(self):
  e,state,inv,op=self.setup_engine([{'dst':'default','dev':'eth2','gateway':'10.204.0.1','prefsrc':'10.204.0.2','table':'55208','protocol':'99','metric':100}])
  with mock.patch.object(live.r,'_atomic') as write:
   with self.assertRaises(live.r.RuntimeErrorSafe):e.reconcile_egress({})
  e.runner.run.assert_not_called();write.assert_not_called()
 def test_completed_route_with_crashed_commit_is_adopted_from_durable_intent(self):
  e,state,inv,old=self.setup_engine();new=deepcopy(old)
  for k in ('argv','undo'):new[k][new[k].index('src')+1]='10.204.0.6';new[k][new[k].index('via')+1]='10.204.0.5'
  state['egress_repair']={'old':old,'new':new,'boot_id':'boot'}
  inv['interfaces']['eth2']['addr_info'][0]['local']='10.204.0.6';inv['routes'][0]['gateway']='10.204.0.5';inv['routes'].append({'dst':'default','dev':'eth2','gateway':'10.204.0.5','prefsrc':'10.204.0.6','table':'55208','protocol':live.r.ROUTE_PROTOCOL,'metric':100})
  with mock.patch.object(live.r,'_atomic'):r=e.reconcile_egress({})
  self.assertEqual(r['state'],'healthy');self.assertEqual(state['operations'][0],new);self.assertNotIn('egress_repair',state);e.runner.run.assert_not_called()

if __name__=='__main__':unittest.main()
