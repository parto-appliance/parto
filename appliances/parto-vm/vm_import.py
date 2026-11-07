"""Read optional OVF setup hints; never apply settings or grant identity/access."""
import json
import subprocess
import xml.etree.ElementTree as E
from vm_console import validate_page


def parse_settings(xml):
    if not isinstance(xml, str) or len(xml) > 65536 or '<!DOCTYPE' in xml or '<!ENTITY' in xml:
        return None
    try:
        root = E.fromstring(xml)
        for p in root.iter():
            if p.tag.rsplit('}', 1)[-1] != 'Property':
                continue
            attrs = {k.rsplit('}', 1)[-1]: v for k, v in p.attrib.items()}
            if attrs.get('key') != 'overlay.setup':
                continue
            value = json.loads(attrs.get('value', ''))
            rows = value['interfaces']
            if not 1 <= len(rows) <= 8 or [r['name'] for r in rows] != ['eth%d' % n for n in range(len(rows))]:
                return None
            if any(r['role'] not in ('WAN', 'LAN') for r in rows):
                return None
            return value if not validate_page(value, 'interfaces') else None
    except (E.ParseError, ValueError, KeyError, TypeError):
        pass
    return None


def read_settings():
    try:
        r = subprocess.run(['vmtoolsd', '--cmd', 'info-get guestinfo.ovfEnv'],
                           capture_output=True, text=True, timeout=3)
        return parse_settings(r.stdout) if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None
