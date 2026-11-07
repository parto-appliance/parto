"""Topology growth preserves existing peer contracts and isolation is enforced twice."""
import sys
from pathlib import Path
from copy import deepcopy
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import standalone_overlay as exchange
import standalone_live as live

class LivePolicy(unittest.TestCase):
    def topology(self,transport='ipsec',isolated=False):
        def settings(role,number):
            return dict(label=role+str(number),role=role,transport=transport,endpoint=f'192.0.2.{number}',wan='eth0',lans=['eth1'],prefixes=[f'172.30.{210+number}.0/24'],internet_gateway=role=='hub',lab_mode=True,isolate_spokes=isolated if role=='hub' else False)
        hub=exchange.new(settings('hub',1));invitation=exchange.hub_file(hub)
        def add(hub,number):
            spoke=exchange.new(settings('spoke',number),invitation,exchange.inspect_peer(invitation)['fingerprint'])
            request=exchange.request_file(spoke)
            return exchange.approve(hub,request,exchange.inspect_peer(request)['fingerprint']),spoke
        hub,first=add(hub,2);before=deepcopy(hub);hub,second=add(hub,3)
        return before,hub,first,second
    def compile(self,hub):
        body=exchange.hub_file(hub)['body']
        return live.plan(exchange.desired(body),body['network'],body)
    def test_existing_tunnels_and_spoke_bgp_unchanged_during_append(self):
        for transport in ('ipsec','tls'):
            for isolation in (True,False):
                old,new,_,_=self.topology(transport,isolation)
                a,b=self.compile(old),self.compile(new)
                self.assertEqual(a['sites']['agent00001']['tunnels'][0],b['sites']['agent00001']['tunnels'][0])
                self.assertEqual(a['sites']['agent00002']['frr_config'],b['sites']['agent00002']['frr_config'])
                self.assertEqual(a['sites']['agent00002']['tunnels'],b['sites']['agent00002']['tunnels'])
    def test_new_private_routes_fit_existing_policy_without_default_bypass(self):
        old,new,_,_=self.topology()
        import ipaddress
        accepted=self.compile(old)['sites']['agent00002']['tunnels'][0]['accepted_prefixes']
        self.assertTrue(any(ipaddress.ip_network('172.30.213.0/24').subnet_of(ipaddress.ip_network(p)) for p in accepted if p!='0.0.0.0/0'))
        for forbidden in ('172.30.212.0/24','10.254.0.0/16','192.168.4.0/24','192.168.50.0/23'):
            self.assertFalse(any(ipaddress.ip_network(forbidden).overlaps(ipaddress.ip_network(p)) for p in accepted if p!='0.0.0.0/0'))
        self.assertIn(' le 32',self.compile(old)['sites']['agent00002']['frr_config'])
        self.assertIn(' maximum-prefix 1024',self.compile(old)['sites']['agent00002']['frr_config'])
        self.assertIn(' neighbor 10.254.0.0 timers connect 5',self.compile(old)['sites']['agent00002']['frr_config'])
    def test_hub_isolation_suppresses_routes_and_drops_before_gateway_accept(self):
        _,hub,_,_=self.topology(isolated=True);compiled=self.compile(hub);site=compiled['sites']['agent00001']
        self.assertEqual(set(site['tunnels'][0]['exported_prefixes']),{'172.30.211.0/24','0.0.0.0/0'})
        firewall=live.LiveRuntime._firewall(hub['network'],compiled,site,{'eth0':'192.0.2.1'})
        xs='{ '+', '.join('"'+t['if_name']+'"' for t in site['tunnels'])+' }'
        deny=f'iifname {xs} oifname {xs} drop'
        self.assertIn(deny,firewall)
        self.assertLess(firewall.index('ct state { established, related } accept'),firewall.index('tcp dport 179 drop'))
        self.assertLess(firewall.index(deny),firewall.index('oifname { "eth0" } accept'))
        self.assertIn('masquerade',firewall)
    def test_delta_does_not_contain_old_neighbor_or_global_bgp_settings(self):
        _,hub,_,_=self.topology();site=deepcopy(self.compile(hub)['sites']['agent00001'])
        old=site['tunnels'].pop(0);delta=live.render_frr(site,delta=True)
        self.assertNotIn('neighbor '+old['peer_address'],delta)
        for forbidden in ('bgp router-id','bgp cluster-id','network 172.30.211','redistribute kernel','maximum-paths','hostname ','frr defaults'):
            self.assertNotIn(forbidden,delta)
        self.assertIn('neighbor '+site['tunnels'][0]['peer_address'],delta)
    def test_live_import_refuses_changed_existing_identity_or_policy(self):
        old,new,_,_=self.topology();a=exchange.hub_file(old)['body'];b=exchange.hub_file(new)['body']
        self.assertEqual(len(live.additive(a,b)),1)
        for key in ('cert','settings'):
            changed=deepcopy(b);changed['roster'][1][key]='altered'
            with self.assertRaises(ValueError):live.additive(a,changed)
    def test_off_link_private_endpoint_requires_a_verified_gateway(self):
        interface={'addr_info':[{'family':'inet','local':'10.203.0.2','prefixlen':30}]}
        route=[{'dev':'eth0'}]
        self.assertEqual(live.endpoint_gateway(route,'eth0','10.203.0.10',interface,lambda:'10.203.0.1'),'10.203.0.1')
        self.assertIsNone(live.endpoint_gateway(route,'eth0','10.203.0.1',interface,lambda:self.fail('On-link endpoint needs no gateway')))
        with self.assertRaises(live.r.RuntimeErrorSafe):live.endpoint_gateway(route,'eth0','10.203.0.10',interface,lambda:None)

    def test_stunnel_reload_path_stays_regular_while_revisions_remain_immutable(self):
        import tempfile,hashlib
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);network='example';runtime=live.LiveRuntime(state_root=root)
            for revision in ('old','new'):
                path=root/network/'revisions'/revision;path.mkdir(parents=True)
                (path/'stunnel.conf').write_text('configuration '+revision)
            runtime._current(network,'old');stable=root/network/'stunnel-live.conf'
            canonical=stable.resolve();self.assertFalse(stable.is_symlink())
            runtime._current(network,'new')
            self.assertEqual(stable.resolve(),canonical);self.assertEqual(stable.read_text(),'configuration new')
            self.assertEqual((root/network/'revisions'/'old'/'stunnel.conf').read_text(),'configuration old')
            runtime._current(network,'old');self.assertEqual(stable.read_text(),'configuration old')

    def test_standalone_staging_overrides_only_its_tls_reload_path(self):
        import tempfile,importlib.util,json
        source=Path(__file__).resolve().parents[1]
        spec=importlib.util.spec_from_file_location('standalone_stage_test',source/'appliances/standalone-overlay/stage.py')
        stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('opt/parto-vm','etc/systemd/system','etc/parto'):(root/name).mkdir(parents=True)
            (root/'opt/parto-vm/build.json').write_text(json.dumps({'source_files':{},'architecture':'arm64'}))
            stage.stage(source,root)
            drop=root/'etc/systemd/system/console-overlay-stunnel@.service.d/30-live-peers.conf'
            self.assertIn('ExecStart=\nExecStart=/usr/bin/stunnel4 /var/lib/parto-overlay/%i/stunnel-live.conf',drop.read_text())
            self.assertEqual((root/'etc/systemd/system/console-overlay-stunnel@.service').read_bytes(),(source/'configs/overlay/console-overlay-stunnel@.service').read_bytes())
            self.assertIn('standalone_live.py',json.loads((root/'etc/parto/standalone-install.json').read_text())['helpers'])

    def test_new_tls_backend_check_preserves_existing_listener_and_peer_port(self):
        from unittest.mock import patch
        probe={'tunnels':[{'if_id':1001,'local_uplink':'eth0','initiator':True}]}
        def sockets(new):
            return 'header\n0: 0100007F:8CA0 00000000:0000 0A\n1: 00000000:01BB 00000000:0000 0A\n'+('2: 0100007F:8CA1 00000000:0000 0A\n' if new else '')
        for occupied in (False,True):
            with patch.object(Path,'read_text',autospec=True,side_effect=lambda path:sockets(occupied) if str(path).endswith('/tcp') else 'header\n'):
                errors=live.LiveRuntime._tls_port_errors(probe,{'eth0':'192.0.2.1'})
            self.assertEqual(bool(errors),occupied)
            if occupied:self.assertEqual(errors,['a private TLS backend port is already in use'])

    def test_isolation_field_is_strict_and_hub_only(self):
        hub,_,spoke,_=self.topology()
        for bad in ('yes',1,None):
            settings=deepcopy(hub['settings']);settings['isolate_spokes']=bad
            with self.assertRaises(ValueError):exchange.settings(settings)
        settings=deepcopy(spoke['settings']);settings['isolate_spokes']=True
        with self.assertRaises(ValueError):exchange.settings(settings)


class LiveTransactions(unittest.TestCase):
    topology = LivePolicy.topology
    def exercise(self, failure=None, crash=False):
        import contextlib,json,tempfile
        old,new,_,_=self.topology()
        a=exchange.hub_file(old)['body'];b=exchange.hub_file(new)['body']
        network=a['network']
        payload=lambda hub,g:dict(network_id=network,config=exchange.desired(exchange.hub_file(hub)['body']),generation=g,tenant='standalone-'+network,registration_id='local-instance',lab_mode=True)
        before,after=payload(old,1),payload(new,2)
        class PowerLoss(BaseException):pass
        class PowerLoss(BaseException):pass
        class Runner:
            def __init__(self):self.calls=[];self.failed=False
            def run(self,args,check=True):
                self.calls.append(args)
                if failure and not self.failed and failure(args):
                    self.failed=True
                    if crash:raise PowerLoss()
                    raise live.r.RuntimeErrorSafe('Injected failure')
                return dict(returncode=0,stdout='')
        class Engine(live.LiveRuntime):
            def _lock(self):return contextlib.nullcontext()
            def _boot_id(self):return 'test-boot-before'
            def _state(self,n):return live.r._json(self.state_root/n/'state.json')
            def _identity(self):return dict(device='agent00001',board_serial='local-instance',model='vm')
            def _compile(self,p):
                p=live.r._request(p);compiled=live.plan(p['config'],network,b)
                return p,self._identity(),compiled,compiled['sites']['agent00001']
            def _owned_present(self,o):return True
            def _reservations(self,site):return []
            def _live_preflight(self,*args):return dict(sources={'eth0':'192.0.2.1'},gateways={'eth0':None},mtus={'eth0':1400},endpoint_routes={t['id']:dict(gateway=None) for t in self._compile(after)[3]['tunnels']})
            def _revision(self,*args):
                revision=self.state_root/network/'revisions'/'new';revision.mkdir(parents=True)
                (revision/'firewall.nft').write_text('table inet test {}\n')
                return revision
        with tempfile.TemporaryDirectory() as directory:
            runner=Runner();engine=Engine(runner=runner,state_root=directory)
            old_revision=Path(directory)/network/'revisions'/'old';old_revision.mkdir(parents=True)
            (old_revision/'firewall.nft').write_text('table inet test {}\n')
            firewall=dict(kind='firewall',name='owned',cookie='console-overlay:'+network,argv=[live.r.NFT,'-f',str(old_revision/'firewall.nft')],undo=[live.r.NFT,'delete','table','inet','owned'])
            previous=dict(phase='configured',pending=None,revision='old',generation=1,operations=[firewall],payload_sha256=engine._payload_hash(live.r._request(before)),device='agent00001',tenant=before['tenant'],registration_id='local-instance',board_serial='local-instance')
            live.r._atomic(Path(directory)/network/'state.json',previous)
            if crash:
                with self.assertRaises(PowerLoss):engine.add_peers(before,after,a,b)
                self.assertIn('live_add',engine._state(network))
                engine._boot_id=lambda:'different-boot'
                engine.recover_addition(network)
                self.assertEqual(engine._state(network),previous)
                self.assertFalse(any(c[0]==live.r.VTYSH for c in runner.calls))
            elif failure:
                with self.assertRaises(live.r.RuntimeErrorSafe):engine.add_peers(before,after,a,b)
                self.assertEqual(engine._state(network),previous)
            else:
                result=engine.add_peers(before,after,a,b);self.assertTrue(result['ok']);self.assertEqual(result['added'],1)
                self.assertNotIn('live_add',engine._state(network))
                self.assertEqual(engine._state(network)['standalone_commit'],b['revision'])
            self.assertFalse(any(c[0]==live.r.SYSTEMCTL and c[1] in ('stop','restart') for c in runner.calls))
            old_tunnel=live.plan(before['config'],network,a)['sites']['agent00001']['tunnels'][0]
            self.assertFalse(any(c[:3]==[live.r.IP,'link','delete'] and old_tunnel['if_name'] in c for c in runner.calls))
            return runner.calls
    def test_append_journals_new_resources_without_stopping_shared_services(self):self.exercise()
    def test_power_loss_recovers_the_previous_journal_without_requiring_dead_daemons(self):
        self.exercise(lambda c:c[:3]==[live.r.IP,'address','add'],crash=True)
    def test_failures_roll_back_only_new_resources(self):
        for match in (lambda c:c[:3]==[live.r.IP,'address','add'],lambda c:c[0]==live.r.NFT and c[-1].endswith('replace-firewall.nft') and '--check' not in c,lambda c:c[0]==live.r.SWANCTL and '--load-conns' in c,lambda c:c[0]==live.r.VTYSH and c[-1].endswith('add-neighbors.conf')):
            self.exercise(match)

if __name__=='__main__':unittest.main()

class HubControls(LivePolicy):
    def test_capability_stays_stable_across_all_hub_policies(self):
        hub,new,_,_=self.topology();body=exchange.hub_file(new)['body'];base=None
        for internet in (False,True):
            for access in (False,True):
                compiled=live.plan(exchange.desired(body),body['network'],body,{'internet':internet,'spoke_access':access})
                site=compiled['sites']['agent00001'];command=live.policy_commands(site)
                selectors=[(t['local_ts'],t['remote_ts'],t['id'],t['if_name']) for t in site['tunnels']]
                if base is None:base=selectors
                self.assertEqual(base,selectors)
                self.assertEqual(' default-originate route-map ' in site['frr_config'],internet)
                for t in site['tunnels']:
                    self.assertEqual('0.0.0.0/0' in t['exported_prefixes'],internet)
                    self.assertEqual(t['dynamic_out'],access)
                self.assertTrue(all('default-originate' in line for line in command.splitlines() if line.strip().startswith('no neighbor')))
                self.assertNotIn('remote-as',command)
                self.assertNotIn('shutdown',command)
                self.assertIn('prefix-list SD1000OUT',command)
                fw=live.LiveRuntime._firewall(body['network'],compiled,site,{'eth0':'192.0.2.1'})
                self.assertEqual('masquerade' in fw,internet)
                xs='{ '+', '.join(chr(34)+t['if_name']+chr(34) for t in site['tunnels'])+' }'
                self.assertEqual(f'iifname {xs} oifname {xs} drop' in fw,not access)
                spoke=compiled['sites']['agent00002']
                self.assertIn('0.0.0.0/0',spoke['tunnels'][0]['accepted_prefixes'])

    def test_hub_policy_is_strict(self):
        _,hub,_,_=self.topology();body=exchange.hub_file(hub)['body']
        for value in ({},{'internet':1,'spoke_access':True},{'internet':True,'spoke_access':True,'extra':True}):
            with self.assertRaises(ValueError):live.hub_policy(body,value)

class PolicyTransaction(unittest.TestCase):
    def test_policy_delta_rolls_back_without_transport_restart(self):
        self._policy_transaction()

    def test_interrupted_policy_is_recovered_through_root_reconciliation_path(self):
        self._policy_transaction(crash=True)

    def _policy_transaction(self,crash=False):
        import contextlib,tempfile
        fixture=LivePolicy();_,hub,_,_=fixture.topology();roster=exchange.hub_file(hub)['body'];network=roster['network']
        old={'network_id':network,'config':exchange.desired(roster),'generation':1,'tenant':'standalone','registration_id':'test'};new={**old,'generation':2}
        policy={'internet':False,'spoke_access':False}
        class PowerLoss(BaseException):pass
        class Runner:
            def __init__(self):self.calls=[];self.failed=False
            def run(self,args,check=True):
                self.calls.append(args)
                if args[-1].endswith('/live-policy.conf') and not self.failed:
                    self.failed=True
                    if crash:raise PowerLoss()
                    raise live.r.RuntimeErrorSafe('Injected FRR error')
                return {'returncode':0,'stdout':''}
        class Engine(live.LiveRuntime):
            def _lock(self):return contextlib.nullcontext()
            def _state(self,n):return live.r._json(self.state_root/n/'state.json')
            def _identity(self):return {'device':'agent00001','board_serial':'test'}
            def _boot_id(self):return 'test-boot'
            def _compile(self,p):
                compiled=live.plan(p['config'],network,roster,policy)
                return p,{'device':'agent00001'},compiled,compiled['sites']['agent00001']
            def _live_preflight(self,*args):return {'sources':{'eth0':'192.0.2.1'}}
            def _revision(self,*args):
                path=self.state_root/network/'revisions'/'new';path.mkdir();(path/'firewall.nft').write_text('new');return path
        with tempfile.TemporaryDirectory() as directory:
            runner=Runner();engine=Engine(runner=runner,state_root=directory)
            path=Path(directory)/network/'revisions'/'old';path.mkdir(parents=True);(path/'firewall.nft').write_text('old')
            previous={'phase':'configured','revision':'old','generation':1,'device':'agent00001','tenant':'standalone','registration_id':'test','payload_sha256':engine._payload_hash(old)}
            live.r._atomic(Path(directory)/network/'state.json',previous)
            if crash:
                with self.assertRaises(PowerLoss):engine.change_policy(old,new,roster,roster,{'internet':True,'spoke_access':True})
                self.assertIn('live_policy',engine._state(network))
                engine.recover_addition(network)
            else:
                with self.assertRaisesRegex(live.r.RuntimeErrorSafe,'Injected'):engine.change_policy(old,new,roster,roster,{'internet':True,'spoke_access':True})
            self.assertEqual(engine._state(network),previous)
            self.assertTrue(any(a[-1].endswith('rollback-policy.conf') for a in runner.calls))
            self.assertTrue(any('soft out' in a[-1] for a in runner.calls))
            self.assertFalse(any(a[0] in (live.r.SYSTEMCTL,live.r.SWANCTL) for a in runner.calls))
