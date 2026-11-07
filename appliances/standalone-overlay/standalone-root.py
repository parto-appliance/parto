#!/usr/bin/python3
"""Fixed offline configuration entry point; no caller-supplied runtime plans."""
from copy import deepcopy
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import stat
import tempfile
import uuid
import subprocess
sys.path.insert(0,'/usr/local/lib/parto-overlay')
sys.path.insert(0,'/usr/local/lib/parto-vm')
import overlay
import overlay_runtime as runtime
import standalone_overlay as exchange
import standalone_live as live
import standalone_lan as lan
import standalone_network as network
import vm_identity
import standalone_workflow as workflow
STATE = Path('/etc/parto/standalone/state.json')
INSTALL = Path('/etc/parto/standalone-install.json')
# Shared readiness checks require root-owned local authority, not estate assembly.
# This override is confined to this separate process and immutable standalone image.
runtime.DEVICE_DETAIL = STATE
IMMUTABLE_HELPERS = frozenset({'overlay.py','overlay_runtime.py','standalone_overlay.py','standalone_live.py','standalone_lan.py','standalone_network.py','standalone_workflow.py','standalone-root.py'})

def read():
    if not runtime._root_file(STATE,private=True): raise ValueError('Standalone setup is missing or not root-private')
    state = runtime._json(STATE)
    instance = vm_identity.check()
    if state.get('instance_id') != instance['instance_id']: raise ValueError('Standalone key belongs to another VM instance')
    return state

def bundle(state):
    return exchange.hub_file(state) if state['settings']['role']=='hub' else state['hub_file']

def body(state, *, allow_expired=False):
    envelope = bundle(state)
    ca = exchange.x509.load_pem_x509_certificate(envelope['body']['ca'].encode())
    fingerprint = state.get('trusted_fingerprint') or exchange.fingerprint(ca.public_bytes(exchange.serialization.Encoding.DER))
    return exchange.read_hub(envelope,fingerprint,allow_expired=allow_expired)

def topology(state, current):
    """Project the approved topology on the Hub only."""
    if state['settings']['role'] != 'hub':
        return None
    sites = []
    for row in current['roster']:
        site = row['settings']
        if row['node'] == state['node']:
            site = state['settings']
        sites.append({
            'id': row['node'], 'peer': f"agent{row['slot']:05d}",
            **{key: site[key] for key in ('role', 'label', 'endpoint', 'wan', 'lans', 'prefixes')},
            'egress': site.get('egress'),
        })
    local = next((site for site in sites if site['id'] == state['node']), None)
    if local is None:
        site = state['settings']
        local = {'id': state['node'], 'role': site['role'], 'label': site['label'],
                 'endpoint': site['endpoint'], 'wan': site['wan'], 'lans': site['lans'],
                 'prefixes': site['prefixes'], 'egress': site.get('egress')}
        sites.append(local)
    interfaces = {local['wan'], *local['lans'], local['egress']} - {None}
    addresses = {}
    try:
        rows = json.loads(subprocess.check_output([runtime.IP, '-j', '-4', 'address', 'show'], timeout=3))
        for row in rows:
            if row['ifname'] in interfaces:
                addresses[row['ifname']] = [
                    f"{address['local']}/{address['prefixlen']}"
                    for address in row['addr_info'] if address['scope'] == 'global'
                ]
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return {'sites': sites, 'local': state['node'], 'addresses': addresses,
            'policy': live.hub_policy(current, state.get('policy'))}


def name_connections(answer, state):
    labels = {f"agent{r['slot']:05d}": r['settings']['label'] for r in body(state, allow_expired=True)['roster']}
    for tunnel in answer.get('tunnels', []):
        tunnel['peer_label'] = labels.get(tunnel.get('peer'), tunnel.get('peer', 'Unknown site'))
    return answer

def transport_binary_valid(pins):
    binary=Path('/usr/local/libexec/parto-transport')
    try:return runtime._root_file(binary) and hashlib.sha256(binary.read_bytes()).hexdigest()==pins.get('obfs4_binary')
    except OSError:return False

class Engine(live.LiveRuntime):
    restore_unit = "console-standalone-restore.service"
    def status(self, request):
        state=read();answer=name_connections(super().status(request),state)
        if state['settings'].get('obfuscated') and answer.get('ready'):
            active=self.runner.run([runtime.SYSTEMCTL,'is-active','console-overlay-obfs4@'+state['network']+'.service'],check=False)['stdout'].strip()=='active'
            answer['obfs4']='active' if active else 'down'
            if not active:
                answer['ready']=False;answer['established']=False;answer['established_count']=0
                answer.setdefault('errors',[]).append('Obfuscated transport wrapper is not active')
                for row in answer.get('tunnels',[]):row['tls']='down'
        return answer

    def _supported_transports(self):
        return runtime._json(INSTALL).get('transports',[])
    def __init__(self, *, cleanup=False):
        super().__init__();self.cleanup=cleanup
    def _model_errors(self, payload, identity):
        return [] if identity.get("model")=="vm" else ["Standalone image requires a VM"]

    def _identity(self):
        state = getattr(self,'candidate',None) or read(); roster = body(state,allow_expired=self.cleanup)['roster']
        row = next((r for r in roster if r['node']==state['node']),None)
        if row is None: raise runtime.RuntimeErrorSafe('The hub has not approved this spoke')
        return {'device':f"agent{row['slot']:05d}",'board_serial':state['instance_id'],'model':'vm'}

    def _migration_errors(self, *, enrollment=False):
        errors = []
        if not runtime._root_file(INSTALL): return ['Standalone immutable helper installation is missing']
        pins = runtime._json(INSTALL)
        for name, digest in pins.get('helpers',{}).items():
            if name not in IMMUTABLE_HELPERS:
                errors.append('Unexpected immutable helper'); continue
            path = Path('/usr/local/lib/parto-overlay')/name
            if not runtime._root_file(path) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                errors.append('Immutable standalone helper differs: '+name)
        if set(pins.get('helpers',{})) != IMMUTABLE_HELPERS:
            errors.append('Standalone helper pins incomplete')
        if Path(__file__).resolve()!=Path('/usr/local/lib/parto-overlay/standalone-root.py'):
            errors.append('Root mutation requires the installed immutable helper')
        if not self._netlayer_lock_valid(): errors.append('Shared network lock is not trusted')
        if not runtime._root_file('/etc/systemd/system/console-overlay-stunnel@.service.d/30-live-peers.conf'):
            errors.append('Standalone live TLS service override is missing')
        for name in ('parto-egress-reconcile.service','parto-egress-reconcile.timer'):
            if not runtime._root_file('/etc/systemd/system/'+name):errors.append('Parto egress recovery unit is missing')
        binary=Path('/usr/local/libexec/parto-transport')
        if not transport_binary_valid(pins):
            errors.append('Immutable obfs4 transport binary differs or is missing')
        if not runtime._root_file('/etc/systemd/system/console-overlay-obfs4@.service'):
            errors.append('Obfuscated transport unit is missing')
        return errors

    def _compile(self,payload):
        payload=runtime._request(payload);local=self._identity()
        try:
            plan=overlay.compile_plan(payload['config'],payload['network_id'],allow_lanless_hub=True)
        except (ValueError,TypeError,KeyError) as exc:
            raise runtime.RuntimeErrorSafe('Parto configuration is invalid') from exc
        site=plan['sites'].get(local['device'])
        if not site:raise runtime.RuntimeErrorSafe('This device is not a member of the network')
        current = body(getattr(self,'candidate',None) or read(),allow_expired=self.cleanup)
        state=getattr(self,'candidate',None) or read()
        plan = live.plan(payload['config'], payload['network_id'], current,state.get('policy') if state['settings']['role']=='hub' else None)
        site = plan['sites'][local['device']]
        identities = {f"agent{r['slot']:05d}":exchange.identity(r['node'],current['network']) for r in current['roster']}
        for name, member in plan['sites'].items():
            member['identity']=identities[name]
            for tunnel in member['tunnels']:
                tunnel['peer_identity']=identities[tunnel['peer']]
                tunnel['peer_cert_cn']=identities[tunnel['peer']]
                tunnel['persistent_initiator']=True
        return payload,local,plan,site

def payload(state, *, allow_expired=False):
    current = body(state,allow_expired=allow_expired)
    return {'network_id':state['network'],'config':exchange.desired(current),'lab_mode':True,
            # The legacy engine's ownership fields are local transaction bindings,
            # never portal registration or tenant credentials in this appliance.
            'tenant':'standalone-'+state['network'],'registration_id':state['instance_id'],
            'generation':state.get('generation',1)}

def credentials(state):
    current = body(state)
    row = next((r for r in current['roster'] if r['node']==state['node']),None)
    if row is None: raise ValueError('Ask the hub to approve the spoke file, then import its updated hub file')
    cert = exchange.x509.load_pem_x509_certificate(row['cert'].encode())
    if exchange.public_bytes(cert.public_key()) != exchange.public_bytes(exchange.load_key(state['key']).public_key()):
        raise ValueError('Issued certificate does not match the local private key')
    directory = runtime.PKI_ROOT/state['network']; runtime._private_directory(directory)
    request = payload(state); local = Engine()._identity()
    authorization = {'network_id':state['network'],**local,'tenant':request['tenant'],
                     'registration_id':request['registration_id'],'lab_mode':request['lab_mode']}
    for name,value in {'ca.pem':current['ca'],'crl.pem':current['crl'],'cert.pem':row['cert'],'key.pem':state['key'],
                       'authorization.json':json.dumps(authorization)}.items(): runtime._atomic(directory/name,value)

def active(state):
    return Engine()._state(state['network']).get('phase') not in (None,'disabled')

def save(state):
    runtime._private_directory(STATE.parent); runtime._atomic(STATE,json.dumps(state,sort_keys=True))

def apply_state(action, state, engine):
    if state.get('lan_reapproval_required'):raise ValueError('LAN subnet changed: export a new spoke request and import the hub approval before activation')
    if action=='restore' and not state.get('enabled'):return {'ok':True,'state':'disabled'}
    if action=='apply':
        if active(state): raise ValueError('Disable the existing runtime before reapplying')
        state['generation']+=1;save(state)
    current=engine._state(state['network'])
    if action=='restore' and current.get('phase') not in (None,'disabled'):
        # Reconcile owned resources before readiness checks, so a partially
        # restored daemon cannot block cleanup by owning its own ports.
        state['generation']+=1;save(state)
        stopped=engine.disable(payload(state))
        if not stopped['ok']:return stopped
    credentials(state)
    # Preflight avoids recording an enabled intent for a malformed LAN/PKI.
    check=engine.preflight(payload(state))
    if not check['ready']:return {**check,'ok':False}
    state['enabled']=True;save(state)
    # A prior failed apply tombstone must be superseded on the next retry.
    state['generation']+=1;save(state)
    return engine.apply(payload(state))


def finish_removal(state, candidate, intent):
    # Stop the old runtime before publishing the revoked roster. An interrupted
    # operation can resume from either side of the atomic roster write.
    if state['revision'] != candidate['revision']:
        cleanup = Engine(cleanup=True)
        cleanup.candidate = state
        old = payload(state, allow_expired=True)
        old['generation'] = candidate['generation'] - 1
        stopped = cleanup.disable(old)
        if not stopped.get('ok'):
            return stopped
        save(candidate)
    else:
        candidate = state
    if candidate['enabled']:
        answer = apply_state('restore', candidate, Engine())
        if not answer.get('ok'):
            return answer
    intent.unlink()
    return {'ok': True, 'state': 'spoke_removed'}


def interface_addresses():
    rows = json.loads(subprocess.check_output([runtime.IP, '-j', 'address', 'show'], timeout=3))
    return [{'name': row['ifname'], 'up': 'UP' in row.get('flags', []),
             'addresses': [f"{a['local']}/{a['prefixlen']}" for a in row.get('addr_info', [])
                           if a.get('family') in ('inet', 'inet6') and a.get('scope') == 'global']}
            for row in rows if row['ifname'] != 'lo' and 'UP' in row.get('flags', [])]


def web_auth(value):
    import crypt
    import hmac
    import spwd
    password = value.get('password')
    if set(value) != {'password'} or not isinstance(password, str) or not 1 <= len(password) <= 256:
        raise ValueError('Invalid login')
    if not runtime._json(Path('/etc/parto/vm-network-ready')).get('interfaces'):
        raise ValueError('Finish console network setup first')
    hashed = spwd.getspnam('root').sp_pwdp
    if not hashed or hashed.startswith(('!', '*')) or not hmac.compare_digest(crypt.crypt(password, hashed) or '', hashed):
        raise ValueError('Invalid login')
    return {'ok': True}


def web_initialize(value):
    ready = runtime._json(Path('/etc/parto/vm-network-ready'))
    role = ready['node_role']
    lans = [r for r in ready['interfaces'] if r['role'] == 'LAN' and r['mode'] != 'disabled']
    wans = [r for r in ready['interfaces'] if r['role'] == 'WAN']
    if any(r['mode'] != 'static' for r in lans):
        raise ValueError('Use static LAN addressing in console setup')
    transport = value.get('transport')
    if transport not in ('ipsec', 'tls', 'ng'):
        raise ValueError('Choose a supported transport')
    settings = {'label': value.get('label', ''), 'role': role,
                'transport': 'tls' if transport == 'ng' else transport,
                'endpoint': value.get('endpoint', '') if role == 'hub' else '',
                'wan': 'eth0', 'lans': [r['name'] for r in lans],
                'prefixes': sorted(str(exchange.ipaddress.ip_interface(r['address']).network) for r in lans),
                'internet_gateway': value.get('internet_gateway', False) if role == 'hub' else False,
                'isolate_spokes': value.get('isolate_spokes', True) if role == 'hub' else False}
    if transport == 'ng':
        settings['obfuscated'] = True
    if role == 'hub' and len(wans) == 2:
        settings['egress'] = next(r['name'] for r in wans if r['name'] != 'eth0')
    answer = operate('initialize', {'settings': settings, 'hub_file': value.get('hub_file'),
                                     'fingerprint': value.get('fingerprint')})
    state = read();state['web_setup'] = {'complete': False};save(state)
    return answer


def web_info():
    answer = {'ok': True, 'interfaces': interface_addresses(), 'configured': STATE.exists()}
    if not STATE.exists():
        ready = runtime._json(Path('/etc/parto/vm-network-ready'))
        answer['role'] = ready.get('node_role')
        answer['network'] = ready
        answer['workflow'] = workflow.status(None, role=answer['role'])
        return answer
    info = operate('info', {})
    # Spokes receive only their own identity and Hub, never the other spokes.
    if info['role'] == 'spoke':
        state = read()
        roster = body(state, allow_expired=True)['roster']
        sites = [{'id': r['node'], 'peer': f"agent{r['slot']:05d}",
                  **{k: r['settings'][k] for k in ('label', 'role', 'wan', 'lans', 'prefixes', 'endpoint')},
                  'egress': r['settings'].get('egress')}
                 for r in roster if r['node'] == state['node'] or r['settings']['role'] == 'hub']
        info['peers'] = [p for p in info['peers'] if p['node'] == state['node'] or p['role'] == 'hub']
        info['topology'] = {'sites': sites, 'local': state['node'], 'policy': {}}
    answer.update(info)
    state = read()
    answer['workflow'] = workflow.status(state, body(state, allow_expired=True))
    answer['status'] = operate('status', {})
    return answer


def operate(action,value):
    if action == 'web-auth': return web_auth(value)
    if action == 'web-initialize': return web_initialize(value)
    if action == 'web-info': return web_info()
    if action=='initialize':
        if STATE.exists(): raise ValueError('This node is already configured')
        if set(value)-{'settings','hub_file','fingerprint'}: raise ValueError('Unsupported setup fields')
        settings=deepcopy(value['settings'])
        ready=runtime._json(Path('/etc/parto/vm-network-ready'))
        network.validate_node(settings,ready)
        if settings.get('obfuscated') and settings.get('role')=='hub':
            if settings.get('obfuscated') is not True or settings.get('transport')!='tls':raise ValueError('Choose obfuscated TLS for this Hub')
            pins=runtime._json(INSTALL);binary=Path('/usr/local/libexec/parto-transport')
            if not transport_binary_valid(pins):raise ValueError('Immutable obfs4 binary is not installed')
            directory=Path('/etc/parto/standalone/obfs4');runtime._private_directory(directory)
            result=subprocess.run([str(binary),'init','--state-dir',str(directory)],capture_output=True,text=True,timeout=30)
            if result.returncode:raise ValueError('Could not initialize private bridge identity')
            descriptor=json.loads(result.stdout)
            if set(descriptor)!={'cert','iat_mode'} or descriptor['iat_mode']!=0:raise ValueError('Invalid local bridge descriptor')
            settings['obfs4_cert']=descriptor['cert']
        state=exchange.new(settings,value.get('hub_file'),value.get('fingerprint'))
        state.update(instance_id=vm_identity.check()['instance_id'],generation=1,enabled=False)
        save(state)
        if state['settings'].get('egress'):runtime._atomic(STATE.parent/'egress-reconcile-enabled','enabled\n')
        return {'ok':True,'state':'awaiting_peer_files'}
    state=read()
    intent=STATE.parent/'live-add-intent.json'
    if intent.exists():
        if not runtime._root_file(intent,private=True):raise ValueError('Live addition recovery intent is not trusted')
        recovery=runtime._json(intent);engine=Engine();journal=engine._state(state['network'])
        if journal.get('standalone_commit')==recovery['revision'] and journal.get('payload_sha256')==engine._payload_hash(runtime._request(payload(recovery))):
            save(recovery);state=recovery
        else:
            with engine._lock():
                engine.recover_addition(state['network'])
                if journal.get('revision'):engine._current(state['network'],journal['revision'])
        intent.unlink()
    lan.recover(state,save)
    removal = STATE.parent/'remove-spoke-intent.json'
    if removal.exists():
        if not runtime._root_file(removal, private=True):
            raise ValueError('Spoke removal recovery intent is not trusted')
        recovered = runtime._json(removal)
        answer = finish_removal(state, recovered, removal)
        if not answer.get('ok') or action == 'restore':
            return answer
        state = read()
        if action == 'remove' and not any(row['node'] == value.get('node') for row in state['roster']):
            return answer
    if action == 'remove':
        if set(value) != {'node'} or not isinstance(value['node'], str):
            raise ValueError('Choose an approved spoke')
        candidate = exchange.remove(state, value['node'])
        if not (state.get('enabled') or active(state)):
            candidate['generation'] += 1
            save(candidate)
            return {'ok': True, 'state': 'spoke_removed'}
        candidate['generation'] += 2
        candidate['enabled'] = bool(state.get('enabled') and len(candidate['roster']) > 1)
        runtime._atomic(removal, json.dumps(candidate, sort_keys=True))
        return finish_removal(state, candidate, removal)
    if action == 'web-progress':
        candidate = workflow.advance(state, body(state, allow_expired=True), value)
        save(candidate)
        return {'ok': True, 'workflow': workflow.status(candidate, body(candidate, allow_expired=True))}
    if action=='reconcile':
        if not state.get('enabled') or state['settings']['role']!='hub' or not state['settings'].get('egress'):return {'ok':True,'state':'not_applicable'}
        return Engine().reconcile_egress(payload(state))
    if action=='lan':
        def disable(current):
            current['enabled']=False;current['generation']+=1;save(current)
            answer=Engine(cleanup=True).disable(payload(current,allow_expired=True))
            if not answer.get('ok'):raise ValueError('Disable this spoke before changing its LAN subnet')
            return current
        candidate,answer=lan.apply(state,value,save,disable,body(state),active(state))
        return answer
    if action=='export':
        if set(value) - {'recipient', 'invitation'}: raise ValueError('Unsupported export fields')
        if state['settings']['role'] == 'hub':
            if value.get('invitation') is True:
                if value.get('recipient') is not None: raise ValueError('An invitation cannot name a recipient')
                exported = exchange.invitation_file(state)
            else:
                if not value.get('recipient'): raise ValueError('Choose an approved spoke, or export a hub invitation')
                exported = exchange.hub_file(state, value['recipient'])
        else:
            if value: raise ValueError('A spoke exports only its own request')
            exported = exchange.request_file(state)
        return {'ok':True,'file':exported}
    if action=='info':
        current = body(state,allow_expired=True)
        return {'ok':True,'node':state['node'],'label':state['settings']['label'],'role':state['settings']['role'],'transport':state['settings']['transport'],'obfuscated':state['settings'].get('obfuscated',False),
                'enabled':state.get('enabled',False),'revision':current['revision'],
                'topology':topology(state,current),
                'lan':lan.info(state) if state['settings']['role']=='spoke' else None,
                'lan_reapproval_required':state.get('lan_reapproval_required',False),
                'policy':live.hub_policy(current,state.get('policy')) if state['settings']['role']=='hub' else None,
                'fingerprint': exchange.fingerprint(exchange.x509.load_pem_x509_certificate(current['ca'].encode()).public_bytes(exchange.serialization.Encoding.DER)) if state['settings']['role']=='hub' else
                               exchange.fingerprint(exchange.public_bytes(exchange.load_key(state['key']).public_key())),
                'peers':[{'node':r['node'],'label':r['settings']['label'],'role':r['settings']['role'],'endpoint':r['settings']['endpoint']} for r in current['roster']]}
    if action=='policy':
        if state['settings']['role']!='hub':raise ValueError('Only the hub administrator can change sharing policy')
        chosen=live.hub_policy(body(state),value)
        if chosen==live.hub_policy(body(state),state.get('policy')):
            return {'ok':True,'state':'policy_unchanged','policy':chosen}
        candidate=deepcopy(state);candidate['policy']=chosen;candidate['generation']+=1
        if state.get('enabled') or active(state):
            engine=Engine();engine.candidate=candidate
            runtime._atomic(intent,json.dumps(candidate,sort_keys=True))
            try:answer=engine.change_policy(payload(state),payload(candidate),body(state),body(candidate),live.hub_policy(body(state),state.get('policy')))
            except Exception:
                with engine._lock():
                    engine.recover_policy(state['network'])
                    journal=engine._state(state['network'])
                    if journal.get('revision'):engine._current(state['network'],journal['revision'])
                intent.unlink(missing_ok=True);raise
            save(candidate);intent.unlink();return answer
        save(candidate);return {'ok':True,'state':'policy_saved','policy':chosen}
    if action in ('import','refresh'):
        if state.get('enabled') or active(state):
            if action!='import' or state['settings']['role']!='hub':raise ValueError('A running hub can approve new spokes; disable before other peer changes')
            candidate=exchange.approve(deepcopy(state),value['file'],value['fingerprint'])
            candidate['generation']+=1
            live.additive(body(state),body(candidate))
            engine=Engine();engine.candidate=candidate
            runtime._atomic(intent,json.dumps(candidate,sort_keys=True))
            try:
                answer=engine.add_peers(payload(state),payload(candidate),body(state),body(candidate))
            except Exception:
                with engine._lock():
                    engine.recover_addition(state['network'])
                    journal=engine._state(state['network'])
                    if journal.get('revision'):engine._current(state['network'],journal['revision'])
                intent.unlink(missing_ok=True)
                raise
            save(candidate);intent.unlink();return answer
        if action=='import':
            state=exchange.approve(state,value['file'],value['fingerprint']) if state['settings']['role']=='hub' else exchange.accept(state,value['file'])
            state.pop('lan_reapproval_required',None)
        elif state['settings']['role']=='hub':
            state['revision']+=1
            ca=exchange.x509.load_pem_x509_certificate(state['ca'].encode());key=exchange.load_key(state['ca_key'])
            for row in state['roster']:
                old=exchange.x509.load_pem_x509_certificate(row['cert'].encode())
                row['cert']=exchange.pem(exchange.leaf(old.public_key(),ca,key,row['node'],state['network']))
            state['crl']=exchange.pem(exchange.crl(ca,key,state['revoked']))
        else: raise ValueError('Ask the hub for a fresh file')
        state['generation']+=1;save(state);return {'ok':True,'state':'peer_files_saved'}
    engine=Engine(cleanup=action=='disable')
    if action=='status':
        if len(body(state)['roster'])<2 or not any(r['node']==state['node'] for r in body(state)['roster']):
            return {'ok':True,'state':'awaiting_peer_files','established':False}
        answer=name_connections(engine.status(payload(state)), state)
        answer['traffic']=engine.traffic(state['network'],answer.get('tunnels',[]))
        answer['policy']=live.hub_policy(body(state),state.get('policy')) if state['settings']['role']=='hub' else None
        return answer
    if action=='disable':
        state['enabled']=False;state['generation']+=1;save(state)
        if len(body(state,allow_expired=True)['roster'])<2:return {'ok':True,'state':'disabled'}
        return engine.disable(payload(state,allow_expired=True))
    if action in ('apply','restore'):
        return apply_state(action, state, engine)
    raise ValueError('Unsupported action')

EXCHANGE_INBOX = Path('/var/lib/parto-inbox')


def inbox_name(name):
    if (not isinstance(name, str) or not name.endswith('.json')
            or Path(name).name != name or '\x00' in name):
        raise ValueError('Choose a JSON file in the SCP inbox.')
    return name


@contextlib.contextmanager
def inbox_directory():
    directory = os.open(EXCHANGE_INBOX, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('The SCP inbox must be controlled by root.')
        yield directory
    finally:
        os.close(directory)


def read_inbox(value):
    if set(value) != {'name'}:
        raise ValueError('Choose a JSON file in the SCP inbox.')
    name = inbox_name(value['name'])
    with inbox_directory() as directory:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_nlink != 1 or metadata.st_mode & 0o022):
                raise ValueError('Choose a regular file uploaded to the SCP inbox as root.')
            raw = stream.read(exchange.MAX_FILE * 2 + 1)
        if len(raw) > exchange.MAX_FILE * 2:
            raise ValueError('Exchange file is too large.')
        return {'ok': True, 'file': exchange.parse(raw.decode('utf-8'))}


def write_inbox(value):
    if set(value) != {'name', 'file'}:
        raise ValueError('Expected a filename and an exchange file.')
    name = inbox_name(value['name'])
    raw = json.dumps(value['file'], separators=(',', ':'))
    exchange.parse(raw)
    with inbox_directory() as directory:
        fd, temporary = tempfile.mkstemp(prefix='.exchange-', dir=EXCHANGE_INBOX)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(Path(temporary).name, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(Path(temporary).name, dir_fd=directory)
    return {'ok': True}


def main():
    try:
        if os.geteuid()!=0 or len(sys.argv)!=2:raise ValueError('Root helper action required')
        action=sys.argv[1]
        if action not in ('initialize','import','export','info','status','apply','disable','restore','remove','refresh','policy','lan','reconcile','read-inbox','write-inbox','web-auth','web-info','web-initialize','web-progress'):raise ValueError('Unsupported action')
        if Engine()._migration_errors():raise ValueError('; '.join(Engine()._migration_errors()))
        value={}
        if action in ('initialize','import','remove','export','policy','lan','read-inbox','write-inbox','web-auth','web-initialize','web-progress'):
            limit = exchange.MAX_FILE * 2 + 1024 if action == 'write-inbox' else exchange.MAX_FILE
            raw = sys.stdin.buffer.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('Input exceeds file limit')
            value = json.loads(raw) if action == 'write-inbox' else exchange.parse(raw.decode())
            if not isinstance(value, dict):
                raise ValueError('Expected a JSON object')
        if action == 'web-auth':
            print(json.dumps(web_auth(value)))
            return 0
        if action in ('read-inbox', 'write-inbox'):
            handler = read_inbox if action == 'read-inbox' else write_inbox
            print(json.dumps(handler(value)))
            return 0
        runtime._private_directory(STATE.parent)
        lock=STATE.parent/'operation.lock'
        with lock.open('a') as handle:
            os.chmod(lock,0o600);fcntl.flock(handle,fcntl.LOCK_EX)
            answer=operate(action,value)
        print(json.dumps(answer));return 0 if answer.get('ok') else 1
    except Exception as exc:
        # No private key, raw stdin, command stderr or password is returned.
        safe=str(exc) if isinstance(exc,(ValueError,runtime.RuntimeErrorSafe,vm_identity.IdentityError)) else 'Standalone operation failed; check local system logs'
        print(json.dumps({'ok':False,'errors':[safe]}));return 1
if __name__=='__main__':sys.exit(main())
