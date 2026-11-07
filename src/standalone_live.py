"""Standalone-only route policy and additive live peer reconciliation.

Existing SAs/interfaces/BGP neighbors are never stopped for an append. Shared
managed compilation/runtime retain their original exact-roster behavior.
"""
from copy import deepcopy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import time
import overlay
import standalone_overlay as exchange
import overlay_runtime as r


def private_routes(own=()):
    blocks = list(overlay._PRIVATE)
    for excluded in [*overlay._PROTECTED, *(ipaddress.ip_network(p) for p in own)]:
        result = []
        for block in blocks:
            if block.subnet_of(excluded): continue
            result.extend(block.address_exclude(excluded) if excluded.subnet_of(block) else [block])
        blocks = result
    return sorted(map(str, blocks))


def endpoint_gateway(routes, iface, endpoint, interface, configured):
    """A device-only route result proves on-link reachability only on that subnet."""
    if len(routes)==1 and routes[0].get('dev')==iface and routes[0].get('type','unicast')=='unicast':
        if routes[0].get('gateway'):return routes[0]['gateway']
        address=ipaddress.ip_address(endpoint)
        if any(address in ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network
               for a in interface.get('addr_info',[]) if a.get('family')=='inet'):
            return None
    gateway=configured()
    if not gateway:raise r.RuntimeErrorSafe('New endpoint underlay route cannot be verified')
    return gateway


def render_frr(site, *, delta=False):
    text = overlay._render_frr(site, site['effective_asn'])
    dynamic = set()
    for t in site['tunnels']:
        for direction in ('IN', 'OUT'):
            if t.get('dynamic_' + direction.lower()): dynamic.add('SD'+str(t['if_id'])+direction)
    lines = []
    for line in text.splitlines():
        if delta and line.startswith('ip prefix-list CSGWDEFAULT '):break
        if delta and line.startswith(('frr defaults ', 'hostname ')):continue
        match = re.fullmatch(r'ip prefix-list (\S+) seq (\d+) permit (\S+)', line)
        if match and match[1] in dynamic and match[3] != '0.0.0.0/0': line += ' le 32'
        if site['role'] == 'spoke' and ' maximum-prefix ' in line:
            line = line.rsplit(' ', 1)[0] + ' 1024'
        if delta and (line.startswith((' bgp ', ' no bgp ')) or line.startswith(('  network ', '  redistribute ', '  maximum-paths '))):
            continue
        lines.append(line)
        connect=re.fullmatch(r' neighbor ([0-9.]+) timers 10 30',line)
        if connect:lines.append(f' neighbor {connect[1]} timers connect 5')
    return '\n'.join(lines)+'\n'


def hub_policy(roster, override=None):
    hub = next(x for x in roster['roster'] if x['node'] == roster['hub'])
    value = override if override is not None else {'internet':hub['settings']['internet_gateway'],
                                                 'spoke_access':not hub['settings'].get('isolate_spokes',False)}
    if not isinstance(value,dict) or set(value)!={'internet','spoke_access'} or any(type(v) is not bool for v in value.values()):
        raise ValueError('Choose boolean Internet sharing and spoke connectivity settings')
    return dict(value)


def policy_commands(site):
    """Replace only owned outbound filters; soft-out never resets a neighbor."""
    lines=[]
    for t in site['tunnels']:
        name='SD'+str(t['if_id'])+'OUT'
        lines.append('no ip prefix-list '+name)
        for n,p in enumerate(t['exported_prefixes'],1):
            lines.append(f'ip prefix-list {name} seq {n*5} permit {p}'+(' le 32' if t.get('dynamic_out') and p!='0.0.0.0/0' else ''))
    lines += [f'router bgp {site["effective_asn"]}',' address-family ipv4 unicast']
    for t in site['tunnels']:
        lines.append(('  ' if site['hub_policy']['internet'] else '  no ')+f'neighbor {t["peer_address"]} default-originate'+(' route-map CSGWORIGIN' if site['hub_policy']['internet'] else ''))
    return '\n'.join(lines+[' exit-address-family','exit'])+'\n'


def plan(config, network_id, roster, policy=None):
    # Stable transport capability is authorized at setup. Live hub policy only
    # narrows forwarding/advertisements, so no spoke file exchange or rekey occurs.
    capability = deepcopy(config);capability['internet_gateway']=True
    value = overlay.compile_plan(capability, network_id, allow_lanless_hub=True)
    rows = {f"agent{x['slot']:05d}": x for x in roster['roster']}
    hub = next(x for x in roster['roster'] if x['node'] == roster['hub'])
    controls = hub_policy(roster,policy)
    isolated = not controls['spoke_access']
    digest = hashlib.sha256(network_id.encode()).hexdigest()
    for name, site in value['sites'].items():
        site['isolate_spokes'] = isolated
        site['identity']=exchange.identity(rows[name]['node'],network_id)
        if hub['settings'].get('obfuscated'):site['obfs4_cert']=hub['settings']['obfs4_cert']
        if site['role']=='hub' and rows[name]['settings'].get('egress'):
            site['internet_egress']=rows[name]['settings']['egress']
        site['hub_policy'] = controls
        site['router_id'] = '10.254.255.'+str(rows[name]['slot'])
        for t in site['tunnels']:
            slot = rows[t['peer']]['slot'] if site['role']=='hub' else rows[name]['slot']
            ident = 1000+slot-2
            address = int(ipaddress.ip_address('10.254.0.0'))+2*(slot-2)
            left = str(ipaddress.ip_address(address));right = str(ipaddress.ip_address(address+1))
            t.update(id=f'sd{digest[:6]}{ident:04x}',if_name=f'cs{digest[:6]}{ident:04x}',
                     if_id=ident,table=40000+ident,mark=0xCA000000+ident,
                     local_address=(left if site['role']=='hub' else right)+'/31',
                     peer_address=right if site['role']=='hub' else left)
            peer = value['sites'][t['peer']]
            t['peer_identity']=exchange.identity(rows[t['peer']]['node'],network_id)
            t['peer_cert_cn']=t['peer_identity']
            t['obfs4']=bool(hub['settings'].get('obfuscated'))
            t['transport_server_name']=hashlib.sha256(('service:'+network_id+':'+t['id']).encode()).hexdigest()[:24]+'.'+hashlib.sha256(('domain:'+network_id).encode()).hexdigest()[:24]
            t['dynamic_peer']=site['role']=='hub' and not rows[t['peer']]['settings']['endpoint']
            t['mobile_initiator']=site['role']=='spoke' and not rows[name]['settings']['endpoint']
            if site['role']=='hub':
                t['exported_prefixes'] = (list(site['prefixes']) if isolated else private_routes(peer['prefixes']))
                t['dynamic_out'] = not isolated
            else:
                t['accepted_prefixes'] = private_routes(site['prefixes'])
                t['dynamic_in'] = True
            gateway = site.get('internet_gateway')
            if gateway and (site['role']=='spoke' or controls['internet']):
                field = 'exported_prefixes' if site['role']=='hub' else 'accepted_prefixes'
                t[field] = sorted(set(t[field])|{'0.0.0.0/0'})
            # Route-based selectors authorize the hub trust domain up front;
            # exact spoke sources, route filters and firewall enforce policy.
            hub_ts = ['0.0.0.0/0'] if gateway else [str(n) for n in overlay._PRIVATE]
            t['local_ts'] = ([t['local_address'].split('/')[0]+'/32'] +
                             (hub_ts if site['role']=='hub' else list(site['prefixes'])))
            t['remote_ts'] = ([t['peer_address']+'/32'] +
                              (list(peer['prefixes']) if site['role']=='hub' else hub_ts))
        site['frr_config'] = render_frr(site)
        if site['role']=='hub' and not controls['internet']:
            site['frr_config']='\n'.join(line for line in site['frr_config'].splitlines() if ' default-originate ' not in line)+'\n'
        if site['transport']=='ipsec': site['swanctl_config'] = overlay.render_swanctl(site)
        else:
            site['stunnel_config'] = overlay.render_stunnel(site)
            site['openvpn_configs'] = overlay.render_openvpn(site)
    for link in value['links']:
        tunnel=next(t for t in value['sites'][link['a']['site']]['tunnels'] if t['peer']==link['b']['site'])
        link.update(id=tunnel['id'],if_id=tunnel['if_id'],subnet=str(ipaddress.ip_interface(tunnel['local_address']).network))
        link['a']['address']=tunnel['local_address'].split('/')[0];link['b']['address']=tunnel['peer_address']
    return value


def additive(old, new):
    for key in ('network','hub','ca'):
        if old[key] != new[key]: raise ValueError('Live addition cannot change hub/network authority')
    previous = {x['node']:x for x in old['roster']}
    current = {x['node']:x for x in new['roster']}
    if not previous.keys() <= current.keys() or any(current[n]!=v for n,v in previous.items()):
        raise ValueError('Disable before removing, renewing or changing an existing site')
    if new['revision'] <= old['revision']: raise ValueError('A newer additive hub revision is required')
    return current.keys()-previous.keys()


class LiveRuntime(r.Runtime):
    """Standalone runtime extension; all shell inputs remain compiler-owned."""
    def _passive_peer(self, tunnel):
        return bool(tunnel.get('dynamic_peer')) and not tunnel['initiator']

    def _reservations(self, site):
        return sorted(set(super()._reservations(site)) | ({site['internet_egress']} if site.get('internet_egress') else set()))

    @staticmethod
    def _egress_route(site, inventory):
        iface=site['internet_egress'];row=inventory['interfaces'].get(iface,{})
        addresses=[a['local'] for a in row.get('addr_info',[]) if a.get('family')=='inet' and a.get('scope')=='global']
        defaults=[v for v in inventory['routes'] if v.get('dev')==iface and v.get('dst')=='default' and v.get('table','main') in ('main',254) and v.get('type','unicast')=='unicast']
        if 'UP' not in row.get('flags',[]) or len(addresses)!=1 or len(defaults)!=1 or not defaults[0].get('gateway'):
            raise r.RuntimeErrorSafe('Hub Internet WAN requires one active IPv4 address and its own default gateway')
        return iface,str(ipaddress.IPv4Address(addresses[0])),str(ipaddress.IPv4Address(defaults[0]['gateway']))

    @staticmethod
    def _gateway_egress_errors(site, inventory):
        if not site.get('internet_egress'):return r.Runtime._gateway_egress_errors(site,inventory)
        try:
            iface,source,gateway=LiveRuntime._egress_route(site,inventory)
            networks=[ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network for a in inventory['interfaces'][iface]['addr_info'] if a.get('family')=='inet']
            if not any(ipaddress.ip_address(gateway) in n for n in networks):raise r.RuntimeErrorSafe('Internet WAN gateway must be directly connected')
            underlay=[ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network for u in site['uplinks'] for a in inventory['interfaces'].get(u['iface'],{}).get('addr_info',[]) if a.get('family')=='inet']
            if any(a.overlaps(b) for a in networks for b in underlay):raise r.RuntimeErrorSafe('Hub WAN connected subnets overlap')
            prefixes=site.get('internet_gateway',{}).get('spoke_prefixes',[])+site['prefixes']
            if any(ipaddress.ip_network(p).overlaps(n) for p in prefixes for n in networks):raise r.RuntimeErrorSafe('Advertised LAN overlaps the Hub Internet WAN')
            return []
        except (KeyError,ValueError,r.RuntimeErrorSafe) as exc:return [str(exc)]

    @staticmethod
    def _tls_port_errors(site,sources):
        errors=r.Runtime._tls_port_errors(site,sources)
        if not site.get('obfs4_cert'):return errors
        port=4443 if site['role']=='hub' else 3443
        # Live-add's synthetic all-initiator probe checks only its new VPN ports.
        if site['role']=='hub' and all(t['initiator'] for t in site['tunnels']):return errors
        try:
            for filename in ('tcp','tcp6'):
                for line in Path('/proc/net/'+filename).read_text().splitlines()[1:]:
                    columns=line.split()
                    if columns[3]=='0A' and int(columns[1].rsplit(':',1)[1],16)==port:
                        errors.append('Private obfs4 bridge backend port is already in use')
        except (OSError,ValueError,IndexError):errors.append('Bridge socket ownership could not be observed')
        return errors

    def _commands(self, network_id, plan, site, sources, gateways, revision, **kwargs):
        operations = super()._commands(network_id,plan,site,sources,gateways,revision,**kwargs)
        # All future private NLRI must fail closed when absent from the main RIB.
        operations = [o for o in operations if not (o['argv'][:4]==[r.IP,'route','add','blackhole'] and '0.0.0.0/0' not in o['argv']) and o['kind']!='gateway_throw']
        guards=[]
        for prefix in map(str,overlay._PRIVATE):
            args=['blackhole',prefix,'proto',r.ROUTE_PROTOCOL,'metric',r.GUARD_METRIC]
            guards.append({'argv':[r.IP,'route','add',*args],'undo':[r.IP,'route','del',*args],'kind':'command'})
        gateway=site.get('internet_gateway')
        if gateway and gateway['role']=='spoke':
            for prefix in map(str,overlay._PRIVATE):
                args=['throw',prefix,'table',str(gateway['policy_table']),'proto',r.ROUTE_PROTOCOL]
                guards.append({'argv':[r.IP,'route','add',*args],'undo':[r.IP,'route','del',*args],'kind':'gateway_throw'})
        if gateway and site.get('internet_egress'):
            iface,source,next_hop=self._egress_route(site,self._inventory())
            table=str(gateway['policy_table']);priority=str(self._gateway_priority(gateway))
            def op(argv,**extra):return {'argv':[r.IP,*argv],'undo':[r.IP,*[('del' if x=='add' else x) for x in argv]],'kind':'command',**extra}
            # Private destinations fall through to authenticated main-table BGP.
            for prefix in sorted(set(map(str,overlay._PRIVATE))|set(r.RESERVED)|{plan['overlay_cidr']}):
                guards.append(op(['route','add','throw',prefix,'table',table,'proto',r.ROUTE_PROTOCOL]))
            guards.append(op(['route','add','blackhole','default','table',table,'proto',r.ROUTE_PROTOCOL,'metric',r.GUARD_METRIC],purpose='egress_guard'))
            guards.append(op(['route','add','default','via',next_hop,'dev',iface,'src',source,'table',table,'proto',r.ROUTE_PROTOCOL,'metric','100'],purpose='egress_default'))
            for tunnel in site['tunnels']:
                for prefix in plan['sites'][tunnel['peer']]['prefixes']:
                    rule=op(['rule','add','priority',priority,'from',prefix,'iif',tunnel['if_name'],'table',table],owner_name=tunnel['if_name'],owner_cookie='console-overlay:'+network_id+':'+revision.name,kind='gateway_rule',source_prefix=prefix,incoming_interface=tunnel['if_name'],purpose='egress_selector')
                    # Install these after interface aliases, before the firewall/services.
                    index=next(i for i,o in enumerate(operations) if o['kind']=='firewall')
                    operations.insert(index,rule)
        if site.get('obfs4_cert'):
            unit='console-overlay-obfs4@'+network_id+'.service'
            index=next(i for i,o in enumerate(operations) if o['kind']=='service')
            operations.insert(index,{'argv':[r.SYSTEMCTL,'start',unit],'undo':[r.SYSTEMCTL,'stop',unit],'kind':'service'})
        return guards+operations

    @staticmethod
    def _matches_egress_route(row, operation):
        args=operation['argv']
        def arg(name):return args[args.index(name)+1]
        return (row.get('type','unicast')=='unicast' and row.get('dst')=='default'
                and str(row.get('table'))==arg('table') and str(row.get('protocol'))==r.ROUTE_PROTOCOL
                and row.get('dev')==arg('dev') and row.get('gateway')==arg('via')
                and row.get('prefsrc')==arg('src') and row.get('metric',0)==int(arg('metric'))
                and not row.get('multipath'))

    def reconcile_egress(self, payload):
        """Repair only the journaled Hub egress default after DHCP/carrier changes."""
        request,identity,compiled,site=self._compile(payload)
        if not site.get('internet_egress'):return {'ok':True,'state':'not_applicable'}
        network=request['network_id'];path=self.state_root/network/'state.json'
        with self._lock():
            state=self._state(network)
            if state.get('phase')!='configured' or any(state.get(k) for k in ('pending','live_add','live_policy')):
                return {'ok':True,'state':'runtime_busy'}
            if state.get('payload_sha256')!=self._payload_hash(request):
                raise r.RuntimeErrorSafe('Egress reconciliation requires the current signed configuration')
            ops=state['operations'];tag=lambda name:[o for o in ops if o.get('purpose')==name]
            if len(tag('egress_default'))!=1 or len(tag('egress_guard'))!=1:
                raise r.RuntimeErrorSafe('Owned egress journal is incomplete')
            firewall=next((o for o in ops if o['kind']=='firewall'),None)
            if not firewall or not self._owned_present(firewall) or not self._owned_present(tag('egress_guard')[0]):
                return {'ok':True,'state':'waiting_for_runtime'}
            inventory=self._inventory();old=tag('egress_default')[0];index=ops.index(old)
            table=old['argv'][old['argv'].index('table')+1]
            defaults=[v for v in inventory['routes'] if str(v.get('table'))==table and v.get('dst')=='default' and v.get('type','unicast')=='unicast']
            tx=state.get('egress_repair');allowed=[old]+([tx['new']] if tx else [])
            if len(defaults)>1 or any(not any(self._matches_egress_route(v,o) for o in allowed) for v in defaults):
                raise r.RuntimeErrorSafe('Foreign egress default detected; no route was replaced')
            # Complete/cancel a durable prior intent using only exact owned routes.
            if tx:
                if any(self._matches_egress_route(v,tx['new']) for v in defaults):old=tx['new'];ops[index]=old
                state.pop('egress_repair');r._atomic(path,state)
            if self._gateway_egress_errors(site,inventory):return {'ok':True,'state':'waiting_for_internet_wan'}
            iface,source,gateway=self._egress_route(site,inventory)
            for operation in tag('egress_selector'):
                if not self._owned_present(operation):raise r.RuntimeErrorSafe('Owned egress selector is missing')
            new=deepcopy(old)
            for key,value in (('dev',iface),('src',source),('via',gateway)):
                for command in ('argv','undo'):new[command][new[command].index(key)+1]=value
            present=any(self._matches_egress_route(v,old) for v in defaults)
            if present and new==old:return {'ok':True,'state':'healthy'}
            state['egress_repair']={'old':old,'new':new,'boot_id':self._boot_id()};r._atomic(path,state)
            if present:self.runner.run(old['undo'])
            self.runner.run(new['argv'])
            state['operations'][index]=new;state.pop('egress_repair');r._atomic(path,state)
            return {'ok':True,'state':'egress_restored'}

    @staticmethod
    def _firewall(network_id, plan, site, sources):
        def strings(values):return '{ '+', '.join('"'+x+'"' for x in sorted(set(values)))+' }'
        def prefixes(values):return '{ '+', '.join(sorted(set(values)))+' }'
        name='csd_'+hashlib.sha256(network_id.encode()).hexdigest()[:12]
        tunnels=site['tunnels'];xs=strings(t['if_name'] for t in tunnels);lans=strings(site['lan_interfaces']);own=prefixes(site['prefixes']);wans=strings(u['iface'] for u in site['uplinks'])
        lines=[f'table inet {name} {{',f' comment "console-overlay:{network_id}"',' chain input { type filter hook input priority -10; policy accept;']
        for t in tunnels:
            local=t['local_address'].split('/')[0]
            lines.append(f'  iifname "{t["if_name"]}" ip saddr {t["peer_address"]} ip daddr {local} tcp dport 179 accept')
            source_match='' if t.get('dynamic_peer') else f'ip saddr {t["remote_endpoint"]} '
            if site['transport']=='ipsec':lines.append(f'  iifname "{t["local_uplink"]}" {source_match}ip daddr {sources[t["local_uplink"]]} udp dport {{ 500, 4500 }} accept')
            elif not t['initiator']:lines.append(f'  iifname "{t["local_uplink"]}" {source_match}ip daddr {sources[t["local_uplink"]]} tcp dport 443 accept')
        lines += [f'  iifname {xs} ct state {{ established, related }} accept','  tcp dport 179 drop']
        if site['transport']=='ipsec':lines += ['  udp dport { 500, 4500 } drop']
        else:
            for iface in sorted({t['local_uplink'] for t in tunnels if not t['initiator']}):
                lines.append(f'  iifname "{iface}" ip daddr {sources[iface]} tcp dport 443 drop')
        for t in tunnels:
            allowed=prefixes(p for p in t['accepted_prefixes'] if p!='0.0.0.0/0')
            if site['prefixes']:
                lines.append(f'  iifname "{t["if_name"]}" ip saddr {allowed} ip daddr {own} accept')
            lines.append(f'  iifname "{t["if_name"]}" ip saddr {t["peer_address"]} ip daddr {t["local_address"].split("/")[0]} icmp type echo-request accept')
        lines += [f'  iifname {xs} drop',' }',' chain forward { type filter hook forward priority -10; policy accept;']
        for t in tunnels:
            lines += [f'  iifname \"{t["if_name"]}\" counter comment \"rx:{t["id"]}\"',f'  oifname \"{t["if_name"]}\" counter comment \"tx:{t["id"]}\"']
        if site['role']=='hub' and site['isolate_spokes']:lines.append(f'  iifname {xs} oifname {xs} drop')
        for t in tunnels:
            allowed=prefixes(p for p in t['accepted_prefixes'] if p!='0.0.0.0/0')
            if site['lan_interfaces']:
                lines += [f'  iifname {lans} ip saddr {own} oifname "{t["if_name"]}" ip daddr {allowed} accept',f'  iifname "{t["if_name"]}" ip saddr {allowed} oifname {lans} ip daddr {own} accept']
            if site['role']=='hub' and not site['isolate_spokes']:
                remote=prefixes(p for n,s in plan['sites'].items() if n!=site['name'] for p in s['prefixes'])
                lines.append(f'  iifname "{t["if_name"]}" ip saddr {allowed} oifname {xs} ip daddr {remote} accept')
        gateway=site.get('internet_gateway')
        if site.get('internet_egress'):wans=strings([site['internet_egress']])
        if gateway and (site['role']=='spoke' or site.get('hub_policy',{}).get('internet',True)):
            blocked=prefixes(r.GATEWAY_NON_INTERNET)
            if site['role']=='hub':
                for t in tunnels:
                    allowed=prefixes(p for p in t['accepted_prefixes'] if p!='0.0.0.0/0')
                    lines += [f'  iifname "{t["if_name"]}" ip saddr {allowed} oifname {wans} ip daddr {blocked} drop',f'  iifname "{t["if_name"]}" ip saddr {allowed} oifname {wans} accept']
                lines.append(f'  iifname {wans} oifname {xs} ip daddr {prefixes(gateway["spoke_prefixes"])} ct state {{ established, related }} accept')
            else:
                lines += [f'  iifname {lans} ip saddr {own} oifname {xs} ip daddr {blocked} drop',f'  iifname {lans} ip saddr {own} oifname {xs} accept',f'  iifname {xs} oifname {lans} ip daddr {own} ct state {{ established, related }} accept']
        lines += [f'  iifname {xs} drop',f'  oifname {xs} drop']
        if site['lan_interfaces']:
            lines += [f'  iifname {lans} drop',f'  oifname {lans} drop']
        lines += [' }']
        if gateway and site['role']=='hub' and site.get('hub_policy',{}).get('internet',True):
            lines += [' chain gateway_nat { type nat hook postrouting priority srcnat; policy accept;',f'  iifname {xs} oifname {wans} ip saddr {prefixes(gateway["spoke_prefixes"])} ip daddr != {prefixes(r.GATEWAY_NON_INTERNET)} masquerade',' }']
        return '\n'.join(lines+['}'])+'\n'

    def _revision(self, payload, compiled, site, preflight):
        revision = super()._revision(payload, compiled, site, preflight)
        if site.get('obfs4_cert'):
            source=preflight['sources']['eth0'];hub=site['role']=='hub'
            config={'role':site['role'],'listen':source+':443' if hub else '127.0.0.1:3443','target':'127.0.0.1:4443' if hub else site['tunnels'][0]['remote_endpoint']+':443','source':source,'interface':'eth0','cert':site['obfs4_cert'],'state_dir':'/etc/parto/standalone/obfs4' if hub else ''}
            path=revision/'obfs4.json';text=json.dumps(config,sort_keys=True)
            if path.exists() and path.read_text()!=text:raise r.RuntimeErrorSafe('Immutable bridge configuration changed')
            if not path.exists():r._atomic(path,text)
        target = revision/'standalone-underlay.json'
        text = json.dumps({k:preflight.get(k,{}) for k in ('sources','gateways','mtus','endpoint_routes')},sort_keys=True)
        if target.exists() and target.read_text()!=text:
            raise r.RuntimeErrorSafe('Immutable standalone underlay changed')
        if not target.exists(): r._atomic(target,text)
        if site['transport']=='tls':r._atomic(self.state_root/payload['network_id']/'stunnel-live.conf',(revision/'stunnel.conf').read_text())
        return revision

    def _live_preflight(self, payload, identity, compiled, site, previous, added):
        errors = self._migration_errors()+self._model_errors(payload,identity)+self._pki_errors(payload,identity,site)
        inventory=self._inventory()
        errors += self._conflicts(site,inventory)+self._lan_routing_errors(site,inventory)
        if site.get('internet_gateway',{}).get('role')=='hub':errors += self._gateway_egress_errors(site,inventory)
        revision=self.state_root/payload['network_id']/'revisions'/previous['revision']
        flight=r._json(revision/'standalone-underlay.json')
        if set(flight)!= {'sources','gateways','mtus','endpoint_routes'}:
            errors.append('Existing image predates live peer additions; use a fresh baseline')
        if errors:raise r.RuntimeErrorSafe('; '.join(sorted(set(errors))))
        for operation in previous['operations']:
            if not self._owned_present(operation):
                raise r.RuntimeErrorSafe('Existing owned resources are missing; live addition refused')
        if site['transport']=='tls':
            live_file=self.state_root/payload['network_id']/'stunnel-live.conf'
            if not r._root_file(live_file,private=True) or live_file.read_text()!=(revision/'stunnel.conf').read_text():
                raise r.RuntimeErrorSafe('Trusted live TLS configuration differs from its revision')
            probe=deepcopy(site);probe['tunnels']=[{**t,'initiator':True} for t in added]
            errors=self._tls_port_errors(probe,flight['sources'])
            if errors:raise r.RuntimeErrorSafe('; '.join(errors))
        for daemon in (('obfs4',) if site.get('obfs4_cert') else ())+('bgpd','zebra','stunnel' if site['transport']=='tls' else 'charon'):
            unit=f'console-overlay-{daemon}@{payload["network_id"]}.service'
            if self.runner.run([r.SYSTEMCTL,'is-active',unit],check=False)['stdout'].strip()!='active':
                raise r.RuntimeErrorSafe('Existing routing/transport service is not active')
        for iface,source in flight['sources'].items():
            row=inventory['interfaces'].get(iface,{})
            addresses=[x['local'] for x in row.get('addr_info',[]) if x.get('family')=='inet' and x.get('scope')=='global']
            if addresses!=[source] or 'UP' not in row.get('flags',[]) or min(1400,int(row.get('mtu',0))-96)!=flight['mtus'][iface]:
                raise r.RuntimeErrorSafe('Existing underlay changed; live addition refused')
        protected=list(overlay._PROTECTED)
        for up in site['uplinks']:
            for address in inventory['interfaces'][up['iface']].get('addr_info',[]):
                if address.get('family')=='inet':protected.append(ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}").network)
        for member in compiled['sites'].values():
            for prefix in member['prefixes']:
                if any(ipaddress.ip_network(prefix).overlaps(n) for n in protected):
                    raise r.RuntimeErrorSafe('A site prefix overlaps protected or underlay addressing')
        for t in added:
            if any(x.get('ifname')==t['if_name'] or x.get('linkinfo',{}).get('info_data',{}).get('if_id')==t['if_id'] for x in inventory['links']):
                raise r.RuntimeErrorSafe('New tunnel interface is already occupied')
            if any(str(x.get('table'))==str(t['table']) for x in inventory['routes']) or any(int(x.get('priority',-1)) in (10000+t['if_id'],20000+t['if_id']) for x in inventory['rules']):
                raise r.RuntimeErrorSafe('New tunnel routing resources are already occupied')
            iface=t['local_uplink'];source=flight['sources'][iface]
            if self._passive_peer(t):
                flight['endpoint_routes'][t['id']]={'gateway':flight['gateways'][iface],'iface':iface,'source':source}
                continue
            try:
                route=self.runner.data([r.IP,'-j','route','get',t['remote_endpoint'],'from',source,'oif',iface])
            except r.RuntimeErrorSafe:
                route=[]
            gateway=endpoint_gateway(route,iface,t['remote_endpoint'],inventory['interfaces'][iface],lambda:self._configured_gateway(iface,inventory['interfaces'][iface]))
            flight['endpoint_routes'][t['id']]={'gateway':gateway,'iface':iface,'source':source}
        return flight

    def _reload_transport(self, network, site, revision):
        if site['transport']=='ipsec':
            self.runner.run([r.SWANCTL,'--load-conns','--file',str(revision/'swanctl.conf'),'--uri',f'unix:///run/console-overlay/{network}/charon.vici'])
        else:
            self.runner.run([r.SYSTEMCTL,'kill','--kill-who=main','--signal=HUP',f'console-overlay-stunnel@{network}.service'])

    def _current(self, network, revision):
        import os
        directory=self.state_root/network
        link=directory/'.current-next';link.unlink(missing_ok=True)
        link.symlink_to('revisions/'+revision);os.replace(link,directory/'current')
        config=directory/'revisions'/revision/'stunnel.conf'
        if config.exists():
            r._atomic(directory/'stunnel-live.conf',config.read_text())
            for peer in (config.parent/'tls').glob('*'):
                target=self.state_root/'tls'/(network+'--'+peer.name);r._private_directory(target)
                next_link=target/'.current-next';next_link.unlink(missing_ok=True);next_link.symlink_to(peer);os.replace(next_link,target/'current')

    @staticmethod
    def _boot_id():
        try:return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        except OSError as exc:raise r.RuntimeErrorSafe('Current boot identity cannot be verified') from exc

    def recover_addition(self, network):
        """Rollback an interrupted append without stopping pre-existing peers."""
        self.recover_policy(network)
        state=self._state(network);transaction=state.get('live_add')
        if not transaction:return
        if not transaction.get('boot_id'):raise r.RuntimeErrorSafe('Interrupted addition has no trusted boot binding')
        previous=transaction['previous'];old_revision=self.state_root/network/'revisions'/previous['revision']
        site=transaction['site'];revision=self.state_root/network/'revisions'/transaction['revision']
        # A journal remains durable if any rollback action fails; no broad cleanup.
        self._current(network,previous['revision'])
        if transaction.get('boot_id')==self._boot_id():
            self.runner.run([r.VTYSH,'-N','csd-'+network,'-f',str(revision/'remove-neighbors.conf')])
            if site['transport']=='ipsec':
                for t in transaction['added_tunnels']:
                    self.runner.run([r.SWANCTL,'--terminate','--ike',t['id'],'--uri',f'unix:///run/console-overlay/{network}/charon.vici'],check=False)
            self._reload_transport(network,site,old_revision)
            firewall=next(o for o in previous['operations'] if o['kind']=='firewall')
            if not self._owned_present(firewall):raise r.RuntimeErrorSafe('Owned firewall unavailable during live-add recovery')
            self.runner.run([r.NFT,'-f',str(revision/'rollback-firewall.nft')])
        errors=self._undo(transaction['operations']+([transaction['pending']] if transaction.get('pending') else []))
        if errors:raise r.RuntimeErrorSafe('; '.join(errors))
        if site['transport']=='tls':
            import os
            for t in transaction['old_tunnels']:
                directory=self.state_root/'tls'/f'{network}--{t["id"]}'
                link=directory/'.current-next';link.unlink(missing_ok=True);link.symlink_to(old_revision/'tls'/t['id']);os.replace(link,directory/'current')
        r._atomic(self.state_root/network/'state.json',previous)

    def add_peers(self, old_payload, new_payload, old_roster, new_roster):
        additive(old_roster,new_roster)
        network=new_payload['network_id'];path=self.state_root/network/'state.json'
        with self._lock():
            self.recover_addition(network)
            previous=self._state(network)
            if previous.get('phase')!='configured' or previous.get('pending'):
                raise r.RuntimeErrorSafe('Existing runtime must be fully configured for live addition')
            if previous.get('payload_sha256')!=self._payload_hash(r._request(old_payload)):
                raise r.RuntimeErrorSafe('Applied configuration differs from the current signed roster')
            request,identity,compiled,site=self._compile(new_payload)
            self._mutation_generation(request);generation,_=self._fence(request,previous)
            old_plan=plan(old_payload['config'],network,old_roster,site.get('hub_policy'))
            old_site=old_plan['sites'][identity['device']]
            # Existing tunnel selectors and policy must remain byte-equivalent.
            old_tunnels={t['peer']:t for t in old_site['tunnels']}
            additions=[t for t in site['tunnels'] if t['peer'] not in old_tunnels]
            for t in site['tunnels']:
                if t['peer'] in old_tunnels:
                    old=old_tunnels[t['peer']]
                    ignored={'peer_identity','peer_cert_cn','persistent_initiator'}
                    if {k:v for k,v in t.items() if k not in ignored}!={k:v for k,v in old.items() if k not in ignored}:
                        raise r.RuntimeErrorSafe('Existing tunnel policy would change; disable before importing')
            if site['role']!='hub' or not additions:
                raise r.RuntimeErrorSafe('Only additive hub peer approval can update a running topology')
            flight=self._live_preflight(request,identity,compiled,site,previous,additions)
            old_revision=self.state_root/network/'revisions'/previous['revision']
            try:revision=self._revision(request,compiled,site,flight)
            except Exception:
                self._current(network,previous['revision']);raise
            table='csd_'+hashlib.sha256(network.encode()).hexdigest()[:12]
            for filename,source in [('replace-firewall.nft',revision),('rollback-firewall.nft',old_revision)]:
                r._atomic(revision/filename,f'delete table inet {table}\n'+(source/'firewall.nft').read_text())
                self.runner.run([r.NFT,'--check','-f',str(revision/filename)])
            delta=deepcopy(site);delta['tunnels']=additions
            r._atomic(revision/'add-neighbors.conf',render_frr(delta,delta=True))
            inverse=[f'router bgp {site["effective_asn"]}']+[f' no neighbor {t["peer_address"]}' for t in additions]+['exit']
            for t in additions:
                tag='SD'+str(t['if_id']);inverse += [f'no ip prefix-list {tag}IN',f'no ip prefix-list {tag}OUT',f'no route-map {tag}IN']
            r._atomic(revision/'remove-neighbors.conf','\n'.join(inverse)+'\n')
            names={t['if_name'] for t in additions};units={f'console-overlay-openvpn@{network}--{t["id"]}.service' for t in additions}
            operations=[o for o in self._commands(network,compiled,site,flight['sources'],flight['gateways'],revision,mtus=flight['mtus'],endpoint_routes=flight['endpoint_routes']) if o.get('owner_name') in names or (o['kind']=='service' and o['argv'][-1] in units)]
            transaction={'boot_id':self._boot_id(),'previous':previous,'site':site,'old_tunnels':old_site['tunnels'],'added_tunnels':additions,'revision':revision.name,'operations':[],'pending':None}
            state=deepcopy(previous);state['live_add']=transaction;r._atomic(path,state)
            try:
                for o in operations:
                    transaction['pending']=o;r._atomic(path,state);self.runner.run(o['argv'])
                    if o['kind']=='interface_alias' and not self._owned_present(o):raise r.RuntimeErrorSafe('New interface ownership was not installed')
                    transaction['operations'].append(o);transaction['pending']=None;r._atomic(path,state)
                self.runner.run([r.NFT,'-f',str(revision/'replace-firewall.nft')])
                self._reload_transport(network,site,revision)
                self.runner.run([r.VTYSH,'-N','csd-'+network,'-f',str(revision/'add-neighbors.conf')])
                state.pop('live_add');state.update(revision=revision.name,generation=generation,payload_sha256=self._payload_hash(request),updated=int(time.time()),operations=previous['operations']+operations,interfaces=self._reservations(site))
                # Root state commit is reconciled by the immutable caller before
                # processing another request, including after a process crash.
                state['standalone_commit']=new_roster['revision'];r._atomic(path,state)
                return {'ok':True,'state':'peers_added_live','added':len(additions),'existing_peers_preserved':True}
            except Exception:
                self.recover_addition(network)
                raise


    def _soft_out(self, network, site):
        for tunnel in site['tunnels']:
            self.runner.run([r.VTYSH,'-N','csd-'+network,'-c','clear bgp ipv4 unicast '+tunnel['peer_address']+' soft out'])

    def recover_policy(self, network):
        state=self._state(network);tx=state.get('live_policy')
        if not tx:return
        previous=tx['previous'];old=self.state_root/network/'revisions'/previous['revision']
        new=self.state_root/network/'revisions'/tx['revision']
        self._current(network,previous['revision'])
        if tx['boot_id']==self._boot_id():
            self.runner.run([r.VTYSH,'-N','csd-'+network,'-f',str(new/'rollback-policy.conf')])
            self.runner.run([r.NFT,'-f',str(new/'rollback-firewall.nft')])
            self._soft_out(network,tx['site'])
        r._atomic(self.state_root/network/'state.json',previous)

    def change_policy(self, old_payload, new_payload, old_roster, new_roster, old_policy):
        network=new_payload['network_id'];path=self.state_root/network/'state.json'
        with self._lock():
            self.recover_addition(network)
            previous=self._state(network)
            if previous.get('phase')!='configured' or previous.get('pending'):
                raise r.RuntimeErrorSafe('Activate the hub before changing live sharing policy')
            if previous.get('payload_sha256')!=self._payload_hash(r._request(old_payload)):
                raise r.RuntimeErrorSafe('Applied configuration differs from the current hub state')
            request,identity,compiled,site=self._compile(new_payload)
            if site['role']!='hub':raise r.RuntimeErrorSafe('Only a hub can change sharing policy')
            self._mutation_generation(request);generation,_=self._fence(request,previous)
            old_site=plan(old_payload['config'],network,old_roster,old_policy)['sites'][identity['device']]
            flight=self._live_preflight(request,identity,compiled,site,previous,[])
            old_revision=self.state_root/network/'revisions'/previous['revision']
            revision=self._revision(request,compiled,site,flight)
            table='csd_'+hashlib.sha256(network.encode()).hexdigest()[:12]
            for filename,source in [('replace-firewall.nft',revision),('rollback-firewall.nft',old_revision)]:
                r._atomic(revision/filename,f'delete table inet {table}\n'+(source/'firewall.nft').read_text())
                self.runner.run([r.NFT,'--check','-f',str(revision/filename)])
            r._atomic(revision/'live-policy.conf',policy_commands(site))
            r._atomic(revision/'rollback-policy.conf',policy_commands(old_site))
            tx={'previous':previous,'revision':revision.name,'boot_id':self._boot_id(),'site':site}
            state=deepcopy(previous);state['live_policy']=tx;r._atomic(path,state)
            try:
                # Atomic firewall first: stale/forced routes and established NAT
                # flows cannot bypass a disable while BGP withdrawals converge.
                self.runner.run([r.NFT,'-f',str(revision/'replace-firewall.nft')])
                self.runner.run([r.VTYSH,'-N','csd-'+network,'-f',str(revision/'live-policy.conf')])
                self._soft_out(network,site)
                self._current(network,revision.name)
                state.pop('live_policy');state.update(revision=revision.name,generation=generation,payload_sha256=self._payload_hash(request),updated=int(time.time()),standalone_commit=new_roster['revision'])
                r._atomic(path,state)
                return {'ok':True,'state':'policy_updated_live','policy':site['hub_policy'],'existing_peers_preserved':True}
            except Exception:
                self.recover_policy(network);raise

    def traffic(self, network, tunnels):
        """Read only owned overlay interface counters; rates computed by console."""
        state=self._state(network)
        owners={o.get('owner_name'):o.get('owner_cookie') for o in state.get('operations',[]) if o.get('kind')=='interface_alias'}
        result={}
        for t in tunnels:
            iface=t.get('interface')
            if not iface:continue
            root=Path('/sys/class/net')/iface
            try:
                if not owners.get(iface) or (root/'ifalias').read_text().strip()!=owners[iface]:continue
                result[t['id']]={k:int((root/'statistics'/(k+'_bytes')).read_text()) for k in ('rx','tx')}
                result[t['id']]['ifindex']=int((root/'ifindex').read_text())
            except (OSError,ValueError):continue
        return result
