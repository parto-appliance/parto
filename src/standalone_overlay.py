"""Offline hub authority and signed, public-only OVERLAY peer exchange.

No enrollment, portal client or estate credentials are used here. A spoke keeps
its private key and sends a signed CSR descriptor. The hub approves it and returns
an updated signed roster containing the issued certificate; peers never share keys.
"""
from __future__ import annotations
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import re
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import overlay

MAX_FILE = 256 * 1024
NODE = re.compile(r'[0-9a-f]{32}\Z')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def fingerprint(value):
    return hashlib.sha256(value).hexdigest()

def pem(value):
    return value.public_bytes(serialization.Encoding.PEM).decode()

def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()

def load_key(value):
    return serialization.load_pem_private_key(value.encode(), password=None)

def public_bytes(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

def identity(node, network):
    return hashlib.sha256(('identity:'+network+':'+node).encode()).hexdigest()[:32]+'.'+hashlib.sha256(('domain:'+network).encode()).hexdigest()[:24]

def parse(raw):
    if not isinstance(raw, str) or len(raw.encode()) > MAX_FILE*2:
        raise ValueError('Peer file is too large')
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj: raise ValueError('Duplicate JSON field')
            obj[key] = value
        return obj
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict): raise ValueError('Peer file must be a JSON object')
    if value.get('format')!='sealed-exchange' and len(raw.encode())>MAX_FILE:raise ValueError('Peer file is too large')
    return value

def sign(body, key):
    body = deepcopy(body)
    return {'body': body, 'signature': base64.b64encode(key.sign(canonical(body), ec.ECDSA(hashes.SHA384()))).decode()}

def verify(envelope, public):
    if not isinstance(envelope, dict) or set(envelope) != {'body', 'signature'}:
        raise ValueError('Invalid signed peer file')
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP384R1):
        raise ValueError('Peer key must be ECDSA P-384')
    try:
        public.verify(base64.b64decode(envelope['signature'], validate=True), canonical(envelope['body']), ec.ECDSA(hashes.SHA384()))
    except Exception as exc:
        raise ValueError('Peer file signature is invalid') from exc
    return envelope['body']

def settings(value):
    fields = {'label', 'role', 'transport', 'endpoint', 'wan', 'lans', 'prefixes', 'internet_gateway'}
    if not isinstance(value, dict) or not fields <= set(value) or set(value)-fields-{'lab_mode','isolate_spokes','egress','obfuscated','obfs4_cert'}: raise ValueError('Invalid standalone settings')
    value = deepcopy(value)
    if 'isolate_spokes' in value and (type(value['isolate_spokes']) is not bool or (value['isolate_spokes'] and value['role'] != 'hub')):
        raise ValueError('Spoke isolation is a hub-only boolean policy')
    if value['role'] not in ('hub', 'spoke') or value['transport'] not in ('ipsec', 'tls'):
        raise ValueError('Choose hub or spoke and IPsec or TLS')
    if type(value['internet_gateway']) is not bool:
        raise ValueError('Internet Gateway must be boolean')
    # Accept the former flag in existing signed files, but never export it in
    # new settings. Reachability is independent of address scope in Parto.
    if 'lab_mode' in value and type(value.pop('lab_mode')) is not bool:
        raise ValueError('Invalid legacy endpoint policy')
    if value['role'] != 'hub' and value['internet_gateway']:
        raise ValueError('Only the hub can enable Internet Gateway')
    if not isinstance(value['label'], str) or not 1 <= len(value['label']) <= 80 or any(ord(c) < 32 for c in value['label']):
        raise ValueError('Use a printable node label of up to 80 characters')
    # Reuse the authoritative compiler shape, prefix and endpoint checks on a
    # non-overlapping validation peer. This does not create a runtime node.
    overlay._iface(value['wan'], 'WAN')
    minimum = 0 if value['role'] == 'hub' else 1
    if not isinstance(value['lans'], list) or not minimum <= len(value['lans']) <= 8 or len(set(value['lans'])) != len(value['lans']):
        raise ValueError('A spoke requires a LAN; only a hub may leave its LAN unused')
    for lan in value['lans']:
        overlay._iface(lan, 'LAN')
        if lan == value['wan']: raise ValueError('WAN and LAN must be separate')
    value['endpoint'] = overlay._ipv4(value['endpoint'], 'Hub transport endpoint', True, blank=value['role']=='spoke')
    if 'obfuscated' in value and type(value['obfuscated']) is not bool:
        raise ValueError('Obfuscated transport choice must be boolean')
    if value.get('obfuscated'):
        if value['transport']!='tls':raise ValueError('Obfs4 wraps the authenticated TLS transport only')
        if value['role']=='hub':
            cert=value.get('obfs4_cert','')
            if not isinstance(cert,str) or not re.fullmatch(r'[A-Za-z0-9+/]{70}',cert) or len(base64.b64decode(cert+'==',validate=True))!=52:
                raise ValueError('Hub obfs4 descriptor is missing or invalid')
        elif 'obfs4_cert' in value:raise ValueError('Spokes use the signed Hub bridge descriptor')
    elif 'obfs4_cert' in value:raise ValueError('Bridge descriptor requires obfuscated TLS')
    if 'egress' in value:
        if value['role']!='hub' or value['egress'] not in ('eth1','eth2') or value['wan']=='eth2' or 'eth2' in value['lans']:
            raise ValueError('Only the Hub may use a separate WAN as Internet egress')
    if not isinstance(value['prefixes'], list) or not minimum <= len(value['prefixes']) <= 32:
        raise ValueError('A spoke must advertise its LAN subnet')
    if bool(value['lans']) != bool(value['prefixes']):
        raise ValueError('An unused hub LAN must have no advertised prefixes')
    prefixes = []
    for prefix in value['prefixes']:
        network = ipaddress.IPv4Network(prefix, strict=True)
        if not any(network.subnet_of(private) for private in overlay._PRIVATE) or any(network.overlaps(p) for p in overlay._PROTECTED):
            raise ValueError('LAN prefixes must be private and outside the reserved overlay/management ranges')
        if any(network.overlaps(p) for p in prefixes): raise ValueError('LAN prefixes overlap')
        prefixes.append(network)
    value['prefixes'] = sorted(str(n) for n in prefixes)
    return value

def csr(key, node, network):
    name = identity(node, network)
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False).sign(key, hashes.SHA384())

def authority(key, network):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hashlib.sha256(('authority:'+network).encode()).hexdigest())])
    return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=3650)).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True).add_extension(
        x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).sign(key, hashes.SHA384())

def issue(request, ca, ca_key, node, network):
    name = identity(node, network)
    if not request.is_signature_valid or request.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]):
        raise ValueError('CSR identity or proof of key ownership is invalid')
    if request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) != [name]:
        raise ValueError('CSR identity must match this node and network')
    return leaf(request.public_key(), ca, ca_key, node, network)

def leaf(public, ca, ca_key, node, network):
    now = datetime.now(timezone.utc)
    return x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity(node, network))])).issuer_name(ca.subject).public_key(public).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=365)).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(identity(node, network))]), critical=False).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(
        x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public), critical=False).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False).sign(ca_key, hashes.SHA384())

def crl(ca, key, revoked=()):
    now = datetime.now(timezone.utc)
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(now-timedelta(minutes=5)).next_update(now+timedelta(days=365)).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
    for serial in revoked:
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build())
    return builder.sign(key, hashes.SHA384())

def request_file(state):
    body = {'schema': 2, 'kind': 'standalone-spoke', 'network': state['network'], 'node': state['node'],
            'settings': state['settings'], 'csr': state['csr'],
            'fingerprint': fingerprint(public_bytes(load_key(state['key']).public_key()))}
    return sign(body, load_key(state['key']))

def hub_file(state, recipient=None):
    if state['settings']['role'] != 'hub': raise ValueError('Only a hub exports a roster')
    if recipient is not None and not any(r['node'] == recipient and r['settings']['role'] == 'spoke' for r in state['roster']):
        raise ValueError('Choose an approved spoke as the approval recipient')
    ca = x509.load_pem_x509_certificate(state['ca'].encode())
    body = {'schema': 2, 'kind': 'standalone-hub', 'network': state['network'], 'hub': state['node'],
            'revision': state['revision'], 'ca': state['ca'], 'crl': state['crl'], 'roster': [r for r in state['roster'] if recipient is None or r['node'] in (state['node'],recipient)],
            'recipient': recipient, 'fingerprint': fingerprint(ca.public_bytes(serialization.Encoding.DER))}
    return sign(body, load_key(state['ca_key']))

def invitation_file(state):
    envelope=hub_file(state)
    envelope['body']['roster']=[r for r in envelope['body']['roster'] if r['node']==state['node']]
    return sign(envelope['body'],load_key(state['ca_key']))


def _exchange_password(value):
    if not isinstance(value,str) or not 16<=len(value)<=256 or any(c in value for c in ('\x00','\r','\n')):
        raise ValueError('Use an exchange passphrase of 16–256 characters without line breaks')
    return value.encode('utf-8')


def seal(envelope, passphrase):
    """Optional file confidentiality; signed inner envelope remains authoritative."""
    raw=canonical(envelope)
    if len(raw)>MAX_FILE:raise ValueError('Peer file is too large')
    salt=os.urandom(16);nonce=os.urandom(12)
    header={'format':'sealed-exchange','version':1,'kdf':'scrypt-32768-8-1','salt':base64.b64encode(salt).decode(),'nonce':base64.b64encode(nonce).decode()}
    key=Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(_exchange_password(passphrase))
    return {**header,'ciphertext':base64.b64encode(AESGCM(key).encrypt(nonce,raw,canonical(header))).decode()}


def unseal(envelope, passphrase):
    try:
        if not isinstance(envelope,dict) or set(envelope)!={'format','version','kdf','salt','nonce','ciphertext'}:raise ValueError()
        if envelope['format']!='sealed-exchange' or type(envelope['version']) is not int or envelope['version']!=1 or envelope['kdf']!='scrypt-32768-8-1':raise ValueError()
        if len(canonical(envelope))>MAX_FILE*2:raise ValueError()
        salt=base64.b64decode(envelope['salt'],validate=True);nonce=base64.b64decode(envelope['nonce'],validate=True);ciphertext=base64.b64decode(envelope['ciphertext'],validate=True)
        if len(salt)!=16 or len(nonce)!=12 or not 16<=len(ciphertext)<=MAX_FILE+16:raise ValueError()
        key=Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(_exchange_password(passphrase))
        header={k:v for k,v in envelope.items() if k!='ciphertext'}
        value=parse(AESGCM(key).decrypt(nonce,ciphertext,canonical(header)).decode())
        if set(value)!={'body','signature'}:raise ValueError()
        return value
    except Exception as exc:raise ValueError('Cannot unlock exchange file: incorrect passphrase or damaged file') from exc


def read_hub(envelope, expected_fingerprint, *, allow_expired=False):
    try:
        body = envelope['body']; ca = x509.load_pem_x509_certificate(body['ca'].encode())
        if fingerprint(ca.public_bytes(serialization.Encoding.DER)) != expected_fingerprint:
            raise ValueError('Hub CA fingerprint differs from the trusted fingerprint')
        verify(envelope, ca.public_key())
        fields = {'schema','kind','network','hub','revision','ca','crl','roster'}
        if body.get('schema') == 2:
            fields |= {'recipient', 'fingerprint'}
            if body.get('fingerprint') != expected_fingerprint:
                raise ValueError('Embedded hub fingerprint does not match its authority')
            if body.get('recipient') is not None and (not isinstance(body['recipient'], str) or not NODE.fullmatch(body['recipient'])):
                raise ValueError('Invalid approval recipient')
        if set(body) != fields or body['schema'] not in (1, 2) or body['kind'] != 'standalone-hub':
            raise ValueError('Unsupported hub file')
        if not NODE.fullmatch(body['network']) or not NODE.fullmatch(body['hub']) or type(body['revision']) is not int or body['revision'] < 1:
            raise ValueError('Invalid hub identity or revision')
        ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes, ec.ECDSA(ca.signature_hash_algorithm))
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca: raise ValueError('Hub authority is not a CA')
        revocations = x509.load_pem_x509_crl(body['crl'].encode())
        ca.public_key().verify(revocations.signature, revocations.tbs_certlist_bytes, ec.ECDSA(revocations.signature_hash_algorithm))
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if revocations.issuer != ca.subject or (now < revocations.last_update or (not allow_expired and now >= revocations.next_update)):
            raise ValueError('Hub revocation list is expired or not current; ask for a fresh hub file')
        if now < ca.not_valid_before or (not allow_expired and now >= ca.not_valid_after): raise ValueError('Hub authority is expired or clock is incorrect')
        if not isinstance(body['roster'], list) or not 1 <= len(body['roster']) <= 32: raise ValueError('Invalid hub roster')
        nodes, slots, prefixes = set(), set(), []
        hubs = []
        for row in body['roster']:
            if set(row) != {'node','slot','settings','cert'} or not NODE.fullmatch(row['node']) or type(row['slot']) is not int or not 1 <= row['slot'] <= 32:
                raise ValueError('Invalid roster member')
            if row['node'] in nodes or row['slot'] in slots: raise ValueError('Duplicate roster node or slot')
            nodes.add(row['node']); slots.add(row['slot']); config = settings(row['settings'])
            if config['role'] == 'hub': hubs.append(row['node'])
            if config['transport'] != body['roster'][0]['settings']['transport'] or config.get('obfuscated',False)!=body['roster'][0]['settings'].get('obfuscated',False):
                raise ValueError('Transport profiles must match')
            for prefix in config['prefixes']:
                net = ipaddress.ip_network(prefix)
                if any(net.overlaps(p) for p in prefixes): raise ValueError('Peer LAN prefixes overlap')
                prefixes.append(net)
            cert = x509.load_pem_x509_certificate(row['cert'].encode())
            ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            if cert.issuer != ca.subject or (now < cert.not_valid_before or (not allow_expired and now >= cert.not_valid_after)) or revocations.get_revoked_certificate_by_serial_number(cert.serial_number):
                raise ValueError('Node certificate is expired, revoked or issued by another hub')
            if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError('A node cannot act as a certificate authority')
            if cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) != [identity(row['node'], body['network'])]:
                raise ValueError('Certificate identity profile differs. Use a fresh Hub and Spokes on the same version; do not mix older exchange files.')
        if hubs != [body['hub']]: raise ValueError('Exactly one designated hub is required')
        if body.get('recipient') is not None and not any(r['node'] == body['recipient'] and r['settings']['role'] == 'spoke' for r in body['roster']):
            raise ValueError('Approval recipient is absent from the roster')
        if len(body['roster']) > 1: desired(body)
        return body
    except ValueError: raise
    except Exception as exc: raise ValueError('Invalid hub file or certificate') from exc

def new(settings_value, hub=None, trusted_fingerprint=None):
    config = settings(settings_value); node = uuid.uuid4().hex; network = uuid.uuid4().hex
    key = ec.generate_private_key(ec.SECP384R1())
    state = {'schema':1, 'node':node, 'settings':config, 'key':key_pem(key), 'revision':1}
    if config['role'] == 'spoke':
        if hub is None: raise ValueError('Import the hub file before creating a spoke')
        body = read_hub(hub, trusted_fingerprint)
        if body.get('recipient') is not None:
            raise ValueError('Use a hub invitation to create a new spoke, not another spoke approval')
        hub_settings = next(r['settings'] for r in body['roster'] if r['node'] == body['hub'])
        if config['transport'] != hub_settings['transport'] or config.get('obfuscated',False)!=hub_settings.get('obfuscated',False):
            raise ValueError('Spoke transport profile must match the hub')
        network = body['network']; state.update(hub_file=hub, trusted_fingerprint=trusted_fingerprint)
    state.update(network=network, csr=pem(csr(key,node,network)))
    if config['role'] == 'hub':
        ca_key = ec.generate_private_key(ec.SECP384R1()); ca = authority(ca_key,network)
        cert = issue(x509.load_pem_x509_csr(state['csr'].encode()),ca,ca_key,node,network)
        state.update(ca_key=key_pem(ca_key),ca=pem(ca),crl=pem(crl(ca,ca_key)),roster=[{'node':node,'slot':1,'settings':config,'cert':pem(cert)}],revoked=[])
    return state

def approve(state, envelope, expected_fingerprint):
    state = deepcopy(state)
    if state['settings']['role'] != 'hub': raise ValueError('Only the hub approves spoke files')
    body = envelope.get('body', {}); request = x509.load_pem_x509_csr(body.get('csr','').encode())
    if fingerprint(public_bytes(request.public_key())) != expected_fingerprint: raise ValueError('Spoke key fingerprint differs')
    verify(envelope,request.public_key())
    fields = {'schema','kind','network','node','settings','csr'}
    if body.get('schema') == 2:
        fields.add('fingerprint')
        if body.get('fingerprint') != expected_fingerprint: raise ValueError('Embedded spoke fingerprint does not match its key')
    if set(body) != fields or body['schema'] not in (1, 2) or body['kind'] != 'standalone-spoke': raise ValueError('Unsupported spoke file')
    if body['network'] != state['network'] or not NODE.fullmatch(body['node']): raise ValueError('Spoke belongs to another network')
    config = settings(body['settings'])
    if config['role'] != 'spoke': raise ValueError('Only spoke requests can be imported')
    if any(r['node'] == body['node'] for r in state['roster']): raise ValueError('Spoke is already approved; remove it before replacing its settings')
    free = set(range(2,33)) - {r['slot'] for r in state['roster']}
    if not free: raise ValueError('This hub supports up to 31 spokes')
    ca = x509.load_pem_x509_certificate(state['ca'].encode()); ca_key = load_key(state['ca_key'])
    cert = issue(request,ca,ca_key,body['node'],state['network'])
    state['roster'].append({'node':body['node'],'slot':min(free),'settings':config,'cert':pem(cert)})
    state['revision'] += 1; state['crl'] = pem(crl(ca,ca_key,state['revoked']))
    read_hub(hub_file(state),fingerprint(ca.public_bytes(serialization.Encoding.DER)))
    return state

def accept(state, envelope):
    state = deepcopy(state)
    if state['settings']['role'] != 'spoke': raise ValueError('Only a spoke imports the hub roster')
    body = read_hub(envelope,state['trusted_fingerprint'])
    if body['schema'] == 2 and body['recipient'] != state['node']:
        raise ValueError('This approval file is not addressed to this spoke')
    previous = state['hub_file']['body']
    if body['network'] != state['network'] or body['hub'] != previous['hub'] or body['revision'] < previous['revision']:
        raise ValueError('Hub identity changed or an old roster was replayed')
    if body['revision'] == previous['revision'] and canonical(body) != canonical(previous): raise ValueError('Hub revision has conflicting contents')
    row = next((r for r in body['roster'] if r['node'] == state['node']),None)
    if row is None: raise ValueError('Hub has not approved this spoke, or has removed it')
    cert = x509.load_pem_x509_certificate(row['cert'].encode())
    if row['settings'] != state['settings'] or public_bytes(cert.public_key()) != public_bytes(load_key(state['key']).public_key()):
        raise ValueError('Hub certificate or settings do not match this spoke')
    state['hub_file'] = envelope
    return state

def remove(state, node):
    state = deepcopy(state)
    if state['settings']['role'] != 'hub' or node == state['node']: raise ValueError('Only a hub can remove a spoke')
    row = next((r for r in state['roster'] if r['node']==node),None)
    if row is None: raise ValueError('Spoke not found')
    state['revoked'].append(x509.load_pem_x509_certificate(row['cert'].encode()).serial_number)
    state['roster'].remove(row);state['revision']+=1
    state['crl']=pem(crl(x509.load_pem_x509_certificate(state['ca'].encode()),load_key(state['ca_key']),state['revoked']))
    return state

def desired(body):
    rows = sorted(body['roster'],key=lambda r:r['slot'])
    names = {r['node']: f"agent{r['slot']:05d}" for r in rows}
    config = {'name':'Parto','topology':'hub_spoke','transport':rows[0]['settings']['transport'],
              'hub':names[body['hub']], 'internet_gateway': next(r['settings']['internet_gateway'] for r in rows if r['node']==body['hub']),
              'sites':[{'name':names[r['node']],'mode':'active_passive','uplinks':[{'iface':r['settings']['wan'],'endpoint':r['settings']['endpoint'],'priority':1}],
                        'lan_interfaces':r['settings']['lans'],'prefixes':r['settings']['prefixes']} for r in rows]}
    return overlay.validate_config(config,lab_mode=True,allow_lanless_hub=True)


def inspect_peer(envelope):
    """Verify public proof and return display metadata; this does not establish trust."""
    body = envelope.get('body', {})
    if body.get('kind') == 'standalone-hub':
        ca = x509.load_pem_x509_certificate(body['ca'].encode())
        digest = fingerprint(ca.public_bytes(serialization.Encoding.DER))
        checked = read_hub(envelope, digest)
        row = next(r for r in checked['roster'] if r['node'] == checked['hub'])
    elif body.get('kind') == 'standalone-spoke':
        request = x509.load_pem_x509_csr(body['csr'].encode())
        if not request.is_signature_valid: raise ValueError('Invalid spoke CSR signature')
        digest = fingerprint(public_bytes(request.public_key()))
        verify(envelope, request.public_key())
        if body.get('schema') not in (1, 2): raise ValueError('Unsupported spoke file')
        if body.get('schema') == 2 and body.get('fingerprint') != digest:
            raise ValueError('Embedded spoke fingerprint does not match its key')
        row = {'node': body['node'], 'settings': settings(body['settings'])}
    else:
        raise ValueError('Choose a signed hub or spoke peer file')
    return {'fingerprint': digest, 'node': row['node'], 'label': row['settings']['label'],
            'role': row['settings']['role'], 'endpoint': row['settings']['endpoint'],
            'recipient': body.get('recipient')}
