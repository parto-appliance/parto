#!/usr/bin/python3
"""Small appliance-local HTTPS UI; privileged operations use the fixed helper."""
import base64
from collections import deque
import hashlib
import hmac
import http.server
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

sys.path.insert(0, '/home/overlay/BootScript')
import standalone_overlay as exchange

HELPER = ['sudo', '-n', '/usr/bin/python3', '-I', '/usr/local/lib/parto-overlay/standalone-root.py']
WEB = Path('/opt/parto-web')
LIMIT = exchange.MAX_FILE * 2 + 8192
LOCK = threading.Lock()
SESSIONS = {}
FAILURES = {}
HISTORY = deque(maxlen=721)
NETWORK_READY = Path('/etc/parto/vm-network-ready')


def helper(action, value=None, *, timeout=180):
    result = subprocess.run(HELPER + [action], input=json.dumps(value or {}), text=True,
                            capture_output=True, timeout=timeout)
    answer = json.loads(result.stdout)
    if not answer.get('ok'):
        raise ValueError('; '.join(answer.get('errors', ['Operation failed'])))
    return answer


def unpack(value):
    file = value['file']
    if not isinstance(file, dict):
        raise ValueError('Choose a JSON exchange file')
    if file.get('format') == 'sealed-exchange':
        file = exchange.unseal(file, value.get('passphrase', ''))
    return file


def safe_filename(label, suffix):
    import re
    return (re.sub(r'[^\w .-]', '-', label, flags=re.UNICODE).strip(' .')[:60] or 'site') + '-' + suffix + '.json'


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    wan_only = False

    def verify_request(self, request, address):
        if not self.wan_only:
            return True
        try:
            # The input firewall gates ingress. Also reject a LAN address routed
            # in through WAN (Linux can accept local IPs on a different NIC).
            ready = json.loads(NETWORK_READY.read_text())
            wans = {'eth0'}
            if ready.get('node_role') == 'hub' and ready.get('hub_wan_mode') == 'dual':
                wans.add('eth2')
            destination = ipaddress.ip_address(request.getsockname()[0])
            destination = getattr(destination, 'ipv4_mapped', None) or destination
            rows = json.loads(subprocess.check_output(
                ['/usr/sbin/ip', '-j', 'address', 'show', 'up'], timeout=2))
            return any(ipaddress.ip_address(item['local']) == destination
                       for row in rows if row['ifname'] in wans
                       for item in row.get('addr_info', []) if item.get('scope') == 'global')
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return False

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
    request_queue_size = 16

    def get_request(self):
        conn, addr = super().get_request()
        conn.settimeout(15)
        return conn, addr


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'Parto'
    sys_version = ''

    def log_message(self, *_):
        pass  # Never log request bodies, file contents, passwords or session tokens.

    def send(self, value, status=200, cookie=None, content_type='application/json'):
        raw = json.dumps(value).encode() if content_type == 'application/json' else value
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(raw)

    def session(self):
        from http.cookies import SimpleCookie
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            token = cookie['parto_session'].value
        except (KeyError, ValueError):
            return None
        with LOCK:
            session = SESSIONS.get(token)
            if session and session['expires'] > time.monotonic():
                return token, session
            SESSIONS.pop(token, None)
        return None

    def do_GET(self):
        path = urlsplit(self.path).path
        assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8'),
                  '/logo.png': ('logo.png', 'image/png')}
        if path in assets:
            name, mime = assets[path]
            self.send((WEB / name).read_bytes(), content_type=mime)
            return
        auth = self.session()
        if not auth:
            self.send({'ok': False, 'error': 'Sign in'}, 401)
            return
        try:
            if path != '/api/state':
                self.send({'ok': False}, 404)
                return
            answer = helper('web-info')
            peers = {str(row['id']) for row in answer.get('status', {}).get('tunnels', [])}
            answer['sample_time'] = int(time.time())
            with LOCK:
                answer['history'] = [[sample[0], {k: v for k, v in sample[1].items() if k in peers}]
                                     for sample in HISTORY if answer['sample_time'] - 3600 <= sample[0] <= answer['sample_time']]
            answer['csrf'] = auth[1]['csrf']
            self.send(answer)
        except Exception:
            self.send({'ok': False, 'error': 'Status unavailable; retry shortly'}, 503)

    def do_POST(self):
        try:
            # Browsers must originate from this exact HTTPS host, including port.
            if self.headers.get('Origin') != 'https://' + self.headers.get('Host', ''):
                self.send({'ok': False, 'error': 'Origin rejected'}, 403)
                return
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                self.send({'ok': False}, 415)
                return
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= LIMIT:
                self.send({'ok': False, 'error': 'Request exceeds file limit'}, 413)
                return
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('Incomplete request')
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError('Expected JSON object')
            path = urlsplit(self.path).path
            if path == '/api/login':
                self.login(value)
                return
            auth = self.session()
            if not auth or not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), auth[1]['csrf']):
                self.send({'ok': False, 'error': 'Sign in again'}, 401)
                return
            if path == '/api/logout':
                with LOCK:
                    SESSIONS.pop(auth[0], None)
                self.send({'ok': True}, cookie='parto_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict')
                return
            if path == '/api/inspect':
                file = unpack(value)
                peer = exchange.inspect_peer(file)
                if peer['role'] == 'hub':
                    hub = next(r for r in file['body']['roster'] if r['node'] == file['body']['hub'])
                    peer['transport'] = 'ng' if hub['settings'].get('obfuscated') else hub['settings']['transport']
                self.send({'ok': True, 'peer': peer})
                return
            if path == '/api/export':
                info = helper('info')
                recipient = value.get('recipient')
                args = ({'recipient': recipient} if recipient else {'invitation': True}) if info['role'] == 'hub' else {}
                file = helper('export', args)['file']
                label, suffix = info['label'], 'request'
                if info['role'] == 'hub':
                    suffix = 'approved' if recipient else 'invitation'
                    if recipient:
                        label = next(p['label'] for p in info['peers'] if p['node'] == recipient and p['role'] == 'spoke')
                if value.get('encrypt'):
                    if value.get('passphrase') != value.get('confirm'):
                        raise ValueError('Exchange passphrases do not match')
                    file = exchange.seal(file, value.get('passphrase', ''))
                progress = {'event': suffix if suffix != 'approved' else 'approval'}
                if recipient: progress['node'] = recipient
                helper('web-progress', progress)
                self.send({'ok': True, 'filename': safe_filename(label, suffix), 'file': file})
                return
            if path == '/api/finish':
                self.send(helper('web-progress', {'event': 'complete'}))
                return
            action = path.removeprefix('/api/')
            if action not in ('initialize', 'import', 'apply', 'disable', 'refresh', 'remove', 'policy', 'lan'):
                self.send({'ok': False}, 404)
                return
            if action in ('initialize', 'import'):
                if action == 'initialize':
                    # Root builds interface roles/prefixes from the saved network setup.
                    if value.get('file'):
                        file = unpack(value)
                        peer = exchange.inspect_peer(file)
                        if value.get('trusted') is not True:
                            raise ValueError('Confirm the Hub identity before continuing')
                        value = {k: value[k] for k in ('label', 'transport', 'endpoint', 'internet_gateway', 'isolate_spokes') if k in value} | {'hub_file': file, 'fingerprint': peer['fingerprint']}
                    else:
                        value = {k: value[k] for k in ('label', 'transport', 'endpoint', 'internet_gateway', 'isolate_spokes') if k in value}
                    self.send(helper('web-initialize', value))
                    return
                file = unpack(value)
                peer = exchange.inspect_peer(file)
                if value.get('trusted') is not True:
                    raise ValueError('Confirm the peer identity before importing')
                value = {'file': file, 'fingerprint': peer['fingerprint']}
            self.send(helper(action, value))
        except ValueError as exc:
            self.send({'ok': False, 'error': str(exc)}, 400)
        except Exception:
            self.send({'ok': False, 'error': 'Operation failed; check appliance status'}, 400)

    def login(self, value):
        now = time.monotonic()
        address = self.client_address[0]
        with LOCK:
            for key in list(FAILURES):
                if FAILURES[key]['until'] <= now:
                    FAILURES.pop(key)
            record = FAILURES.setdefault(address, {'count': 0, 'until': now + 300})
            if record['count'] >= 5 or sum(r['count'] for r in FAILURES.values()) >= 50:
                self.send({'ok': False, 'error': 'Too many attempts; retry in five minutes'}, 429)
                return
            record['count'] += 1
        try:
            if value.get('username') != 'admin':
                raise ValueError()
            helper('web-auth', {'password': value.get('password', '')})
        except Exception:
            self.send({'ok': False, 'error': 'Invalid login or console setup incomplete'}, 401)
            return
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with LOCK:
            FAILURES.pop(address, None)
            for key in list(SESSIONS):
                if SESSIONS[key]['expires'] <= now:
                    SESSIONS.pop(key)
            if len(SESSIONS) >= 32:
                SESSIONS.pop(next(iter(SESSIONS)))
            SESSIONS[token] = {'csrf': csrf, 'expires': now + 1800}
        self.send({'ok': True, 'csrf': csrf}, cookie=f'parto_session={token}; Path=/; Max-Age=1800; Secure; HttpOnly; SameSite=Strict')


def sample_traffic():
    """Keep one hour of interval rates, even when all browsers are closed."""
    previous = {}
    last = time.monotonic()
    while True:
        time.sleep(5)
        try:
            counters = helper('status', timeout=4).get('traffic', {})
        except (ValueError, OSError, subprocess.SubprocessError):
            counters = {}
        now = time.monotonic()
        rates = {}
        if 0 < now - last <= 15:
            for key, counter in counters.items():
                old = previous.get(key)
                if not old or old['ifindex'] != counter['ifindex']:
                    continue
                delta = [counter[field] - old[field] for field in ('rx', 'tx')]
                if min(delta) >= 0:
                    rates[key] = [round(value * 8 / (now - last) / 1e6, 5) for value in delta]
        with LOCK:
            HISTORY.append((int(time.time()), rates))
        previous, last = counters, now


def main():
    server = Server(('::', 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/var/lib/parto-web/server.crt', '/var/lib/parto-web/server.key')
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.wan_only = True
    threading.Thread(target=sample_traffic, daemon=True).start()
    server.serve_forever()


if __name__ == '__main__':
    main()
