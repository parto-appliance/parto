"""Spoke-only LAN addressing and an optional LAN-bound DHCP server."""
from pathlib import Path
import ipaddress
import json
import subprocess
import uuid
import overlay
import vm_identity
import overlay_runtime as runtime

CONFIG=Path('/etc/parto/standalone/lan-dhcp.conf')
SETTINGS=Path('/etc/parto/standalone/lan-settings.json')
READY=Path('/etc/parto/vm-network-ready')
INTENT=Path('/etc/parto/standalone/lan-intent.json')
UNIT='standalone-lan-dhcp.service'

def validate(value,wan_networks=(),other_networks=()):
    if not isinstance(value,dict) or set(value)!={'address','dhcp','pool_start','pool_end','lease_hours'} or type(value['dhcp']) is not bool or type(value['lease_hours']) is not int or not 1<=value['lease_hours']<=168:
        raise ValueError('Invalid LAN/DHCP settings')
    address=ipaddress.IPv4Interface(value['address']);net=address.network
    if not any(net.subnet_of(n) for n in overlay._PRIVATE) or any(net.overlaps(n) for n in [*overlay._PROTECTED,*map(ipaddress.ip_network,wan_networks),*map(ipaddress.ip_network,other_networks)]):
        raise ValueError('LAN must be a private subnet separate from WAN, other sites and reserved ranges')
    if address.ip in (net.network_address,net.broadcast_address):raise ValueError('Choose a usable LAN gateway address')
    result={**value,'address':str(address)}
    if value['dhcp']:
        first,last=ipaddress.IPv4Address(value['pool_start']),ipaddress.IPv4Address(value['pool_end'])
        if first not in net or last not in net or int(first)>int(last) or first==net.network_address or last==net.broadcast_address or int(first)<=int(address.ip)<=int(last):
            raise ValueError('DHCP pool must fit the LAN and exclude its gateway, network and broadcast addresses')
        result.update(pool_start=str(first),pool_end=str(last))
    else:result.update(pool_start='',pool_end='')
    return result

def config(value):
    v=validate(value);addr=ipaddress.ip_interface(v['address'])
    if not v['dhcp']:return '# DHCP disabled\n'
    return '\n'.join(['port=0','interface=eth1','except-interface=eth0','bind-interfaces','dhcp-authoritative',
        f'dhcp-range={v["pool_start"]},{v["pool_end"]},{addr.network.netmask},{v["lease_hours"]}h',
        f'dhcp-option=option:router,{addr.ip}','dhcp-option=option:dns-server,1.1.1.1,8.8.8.8',
        'dhcp-leasefile=/var/lib/standalone-lan-dhcp/dnsmasq.leases'])+'\n'

def run(args,check=True):
    result=subprocess.run(args,capture_output=True,text=True,timeout=45)
    if check and result.returncode:raise ValueError('LAN settings could not be applied; the previous settings are retained')
    return result

def observed_wans():
    rows=json.loads(run(['/usr/sbin/ip','-j','-4','address','show','dev','eth0']).stdout)
    return [str(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network) for r in rows for a in r.get('addr_info',[]) if a.get('family')=='inet']

def change_address(address):
    run(['/usr/bin/nmcli','connection','modify','console-vm-eth1','ipv4.method','manual','ipv4.addresses',address,'ipv4.gateway','','ipv4.dns','','ipv4.never-default','yes','ipv4.ignore-auto-routes','yes'])
    run(['/usr/bin/nmcli','connection','up','console-vm-eth1'])
    rows=json.loads(run(['/usr/sbin/ip','-j','-4','address','show','dev','eth1']).stdout)
    expected=ipaddress.ip_interface(address)
    if not any(a.get('local')==str(expected.ip) and a.get('prefixlen')==expected.network.prefixlen for r in rows for a in r.get('addr_info',[])):
        raise ValueError('The LAN address could not be verified')

def dhcp(value):
    runtime._atomic(CONFIG,config(value))
    if value['dhcp']:
        run(['/usr/sbin/dnsmasq','--test','--conf-file='+str(CONFIG)])
        run(['/usr/bin/systemctl','enable',UNIT]);run(['/usr/bin/systemctl','restart',UNIT])
        if run(['/usr/bin/systemctl','is-active',UNIT]).stdout.strip()!='active':raise ValueError('The LAN DHCP server did not start')
    else:run(['/usr/bin/systemctl','disable','--now',UNIT])

def recover(state,save):
    if not INTENT.exists():return
    if not runtime._root_file(INTENT,private=True):raise ValueError('LAN recovery intent is not root-private')
    intent=runtime._json(INTENT)
    if state.get('lan_revision')!=intent['token']:
        change_address(intent['old']['address']);dhcp(intent['old'])
        vm_identity._write(READY,intent['ready']);runtime._atomic(SETTINGS,intent['old'])
    INTENT.unlink()

def defaults(ready):
    row=next(r for r in ready['interfaces'] if r['name']=='eth1')
    return {'address':row['address'],'dhcp':False,'pool_start':'','pool_end':'','lease_hours':12}

def apply(state,value,save,disable,roster,active=False):
    if state['settings']['role']!='spoke':raise ValueError('LAN/DHCP controls are available only on spokes')
    ready=runtime._json(READY);old=runtime._json(SETTINGS) if SETTINGS.exists() else defaults(ready)
    others=[p for row in roster['roster'] if row['node']!=state['node'] for p in row['settings']['prefixes']]
    chosen=validate(value,observed_wans(),others);net=str(ipaddress.ip_interface(chosen['address']).network)
    changed=state['settings']['prefixes']!=[net]
    if changed and (state.get('enabled') or active):state=disable(state)
    candidate=json.loads(json.dumps(state));candidate['lan']=chosen;candidate['generation']+=1;candidate['lan_revision']=uuid.uuid4().hex
    if changed:
        candidate['settings']['prefixes']=[net]
        candidate['lan_reapproval_required']=any(r['node']==state['node'] for r in roster['roster'])
    fresh=json.loads(json.dumps(ready))
    for row in fresh['interfaces']:
        if row['name']=='eth1':row.update(address=chosen['address'],mode='static',role='LAN')
    runtime._atomic(INTENT,{'token':candidate['lan_revision'],'old':old,'ready':ready})
    try:
        run(['/usr/bin/systemctl','stop',UNIT]);change_address(chosen['address']);dhcp(chosen)
        vm_identity._write(READY,fresh);runtime._atomic(SETTINGS,chosen);save(candidate);INTENT.unlink()
    except Exception:
        recover(state,save);raise
    return candidate,{'ok':True,'state':'lan_saved','lan':chosen,'reapproval_required':candidate.get('lan_reapproval_required',False)}

def info(state):
    if state.get('lan'):return state['lan']
    return defaults(runtime._json(READY)) if READY.exists() else None
