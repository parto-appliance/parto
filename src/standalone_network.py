"""Parto fixed adapter roles selected by Hub deployment mode and NIC count."""
import sys
sys.path.insert(0,'/usr/local/lib/parto-vm')
import vm_network as network
original_validate=network.validate


def roles(role,mode,names):
    if names not in (['eth0'],['eth0','eth1'],['eth0','eth1','eth2']):
        raise network.NetworkError('fixed_wan_lan_required')
    if role=='spoke':
        if len(names)<2:raise network.NetworkError('spoke_lan_required')
        return ['WAN','LAN']+(['Unused'] if len(names)==3 else [])
    if mode=='dual':
        if len(names)!=3:raise network.NetworkError('hub_dual_wan_requires_three_adapters')
        return ['WAN','LAN','WAN']
    return ['WAN']+(['LAN'] if len(names)>=2 else [])+(['Unused'] if len(names)==3 else [])


def validate(payload):
    if not isinstance(payload,dict) or set(payload)-{'interfaces','node_role','hub_wan_mode'}:
        raise network.NetworkError('invalid_settings')
    role=payload.get('node_role','spoke')
    if role not in ('hub','spoke') or (role=='spoke' and 'hub_wan_mode' in payload):raise network.NetworkError('invalid_settings')
    value=original_validate({'interfaces':payload.get('interfaces')});rows=value['interfaces']
    # Read older completed profiles without changing their original adapter roles.
    mode=payload.get('hub_wan_mode','dual' if sum(r['role']=='WAN' for r in rows)==2 else 'single')
    if mode not in ('single','dual'):raise network.NetworkError('invalid_hub_deployment')
    expected=roles(role,mode,[r['name'] for r in rows])
    if [r['role'] for r in rows]!=expected:raise network.NetworkError('fixed_wan_lan_required')
    for row in rows:
        if row['role']=='LAN' and row['mode'] not in (('static','disabled') if role=='hub' else ('static',)):
            raise network.NetworkError('spoke_lan_required')
        if row['role']=='Unused' and row['mode']!='disabled':raise network.NetworkError('invalid_unused_adapter')
    result={**value,'node_role':role}
    if role=='hub':result['hub_wan_mode']=mode
    return result


def validate_node(settings,ready):
    """Bind signed route/egress claims to completed local network setup."""
    value=validate({k:ready[k] for k in ('interfaces','node_role','hub_wan_mode') if k in ready})
    if ready.get('node_role') and ready['node_role']!=settings['role']:
        raise ValueError('The node role must match the role selected before network setup')
    egress=[r['name'] for r in value['interfaces'] if r['role']=='WAN' and r['name']!='eth0']
    if (settings.get('egress') or None)!=(egress[0] if egress else None):
        raise ValueError('Hub Internet egress must match the selected deployment and active second WAN')
    import ipaddress
    lans=[r for r in value['interfaces'] if r['role']=='LAN' and r['mode']=='static']
    if settings['wan']!='eth0' or settings['lans']!=[r['name'] for r in lans] or settings['prefixes']!=sorted(str(ipaddress.ip_interface(r['address']).network) for r in lans):
        raise ValueError('Advertised LANs must match the active local LAN configuration')
    if settings['role']=='spoke' and not lans:raise ValueError('A spoke requires an active LAN')


def main():
    network.validate=validate
    return network.main()
