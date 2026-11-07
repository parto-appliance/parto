#!/usr/bin/env python3
"""Overlay an audited uninitialized package base with a local-only appliance."""
import hashlib
import json
from pathlib import Path
import shutil


def stage(source,rootfs):
    source,root=Path(source),Path(rootfs)
    manifest=root/'opt/parto-vm/build.json';build=json.loads(manifest.read_text())
    for filename,target in [('src/overlay.py','overlay.py'),('src/overlay_runtime.py','overlay_runtime.py'),
                            ('src/standalone_overlay.py','standalone_overlay.py'),('src/standalone_workflow.py','standalone_workflow.py'),('src/standalone_lan.py','standalone_lan.py'),('src/standalone_network.py','standalone_network.py'),('src/standalone_live.py','standalone_live.py'),('appliances/standalone-overlay/standalone-root.py','standalone-root.py')]:
        path=root/'usr/local/lib/parto-overlay'/target;path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source/filename,path);path.chmod(0o644)
    for name in ('standalone-console.py','install.sh'):
        path=root/'opt/parto-vm'/name;shutil.copyfile(source/'appliances/standalone-overlay'/name,path);path.chmod(0o755)
    web = root/'opt/parto-web';web.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source/'appliances/standalone-overlay/parto-web.py', web/'parto-web.py')
    for asset in (source/'appliances/standalone-overlay/web').iterdir():
        if asset.is_file():
            shutil.copyfile(asset, web/asset.name)
            build['source_files'][str(asset.relative_to(source))] = hashlib.sha256(asset.read_bytes()).hexdigest()
    shutil.copyfile(source/'appliances/standalone-overlay/assets/parto-mark.png', web/'logo.png')
    for path in (source/'configs/overlay').glob('*.service'):
        if path.name=='console-overlay-restore.service':continue
        target=root/'etc/systemd/system'/path.name;shutil.copyfile(path,target);target.chmod(0o644)
        drop=target.parent/(path.name+'.d');drop.mkdir(exist_ok=True)
        (drop/'20-standalone-identity.conf').write_text('[Unit]\nRequires=parto-vm-identity.service\nAfter=parto-vm-identity.service\n')
        if path.name=='console-overlay-stunnel@.service':
            (drop/'30-live-peers.conf').write_text('[Service]\nExecStart=\nExecStart=/usr/bin/stunnel4 /var/lib/parto-overlay/%i/stunnel-live.conf\n')
    target=root/'etc/tmpfiles.d/parto-overlay.conf';target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source/'configs/overlay/console-overlay.tmpfiles',target)
    # Keep only the standalone console's dependencies; no managed application or lab defaults.
    old=root/'home/overlay/BootScript';app=root/'home/overlay/BootScript'
    allowed=['standalone_overlay.py','overlay.py','gui_v2/theme.py']
    data={name:next(path for path in [old/name,app/name,source/'src'/name] if path.exists()).read_bytes() for name in allowed}
    shutil.rmtree(old,ignore_errors=True);shutil.rmtree(app,ignore_errors=True)
    for name,value in data.items():
        path=app/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value)
    (app/'gui_v2/__init__.py').write_text('"""Standalone console theme."""\n')
    (app/'kiosk_cursor.py').write_text('def cursor():\n from PyQt5.QtCore import Qt\n from PyQt5.QtGui import QCursor\n return QCursor(Qt.ArrowCursor)\n')
    vm=root/'usr/local/lib/parto-vm';vm.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source/'appliances/parto-vm/runtime/vm_network.py',vm/'vm_network.py')
    (root/'usr/local/libexec').mkdir(parents=True,exist_ok=True)
    if not (root/'opt/parto-vm/install-guest.sh').exists():shutil.copyfile(source/'appliances/parto-vm/install-guest.sh',root/'opt/parto-vm/install-guest.sh')
    (root/'usr/local/libexec/console-vm-network').write_text("#!/usr/bin/python3\nimport sys\nsys.path.insert(0,'/usr/local/lib/parto-overlay')\nfrom standalone_network import main, validate\nif __name__ == '__main__':\n    raise SystemExit(main())\n")
    (root/'usr/local/libexec/console-vm-network').chmod(0o755)
    unit=root/'etc/systemd/system/standalone-lan-dhcp.service'
    unit.write_text('[Unit]\nDescription=Standalone spoke LAN DHCP server\nAfter=NetworkManager.service network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStartPre=/usr/bin/install -d -m 0750 -o dnsmasq -g root /var/lib/standalone-lan-dhcp\nExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/parto/standalone/lan-dhcp.conf --pid-file=/run/standalone-lan-dhcp.pid\nRestart=on-failure\nRestartSec=3\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n')
    # Only staged copies are normalized; the shared managed appliance is unchanged.
    for base in [app,root/'opt/parto-vm',root/'usr/local/lib/parto-overlay',vm,root/'opt/splash']:
        for path in base.rglob('*'):
            if path.is_file() and path.suffix in ('.py','.sh','.conf','.service'):
                text=path.read_text();path.write_text(text.replace('/home/overlay','/home/overlay').replace('example.invalid','example.invalid').replace('overlay:overlay','overlay:overlay').replace('id overlay','id overlay').replace('usermod --lock overlay','usermod --lock overlay').replace('/etc/sudoers.d/90-overlay','/etc/sudoers.d/90-overlay').replace(' overlay',' overlay').replace('overlay ALL','overlay ALL').replace('autologin-user=overlay','autologin-user=overlay'))
    # Standalone artwork replaces all legacy guest splash/header images.
    artwork=source/'appliances/standalone-overlay/assets/parto-mark.png'
    for name in ['opt/splash/logo-badge.png','opt/splash/splash-quiet.png','usr/share/plymouth/themes/parto/splash.png']:
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(artwork,path)
    binary=source/'appliances/standalone-overlay/artifacts'/('transport-'+build['architecture'])/'parto-transport'
    if not binary.is_file():raise ValueError('Build the pinned obfs4 transport adapter before staging')
    target=root/'usr/local/libexec/parto-transport';shutil.copyfile(binary,target);target.chmod(0o755)
    transport_source=source/'appliances/standalone-overlay/transport'
    hashes={str(p.relative_to(transport_source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in transport_source.rglob('*') if p.is_file()}
    for name in ('main.go','go.mod','go.sum','UPSTREAM.json','build.sh'):
        build['source_files']['appliances/standalone-overlay/transport/'+name]=hashes[name]
    build['obfs4']={'implementation':'Lyrebird obfs4','sources_sha256':hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
    notices=root/'usr/share/doc/parto-transport';notices.mkdir(parents=True,exist_ok=True)
    for path in transport_source.rglob('*'):
        if path.is_file() and (path.name.startswith(('LICENSE','COPYING','PATENTS','GO-')) or path.name=='UPSTREAM.json'):
            target=notices/path.relative_to(transport_source);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
    (root/'etc/systemd/system/console-overlay-obfs4@.service').write_text('[Unit]\nDescription=Parto obfuscated stream transport (%i)\nRequires=parto-vm-identity.service\nAfter=network-online.target parto-vm-identity.service\nConditionPathExists=/var/lib/parto-overlay/%i/current/obfs4.json\n[Service]\nType=simple\nExecStart=/usr/local/libexec/parto-transport run --config /var/lib/parto-overlay/%i/current/obfs4.json\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=15\nUMask=0077\nNoNewPrivileges=true\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=-/etc/parto/standalone/obfs4\nProtectKernelModules=true\nProtectKernelTunables=true\nProtectControlGroups=true\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW\nRestrictAddressFamilies=AF_INET AF_UNIX\nLimitNOFILE=1024\nMemoryMax=192M\nTasksMax=128\nEnvironment=GOMEMLIMIT=128MiB\n')
    build['product_name']='Parto'
    build['source_files']['appliances/standalone-overlay/assets/parto-mark.png']=hashlib.sha256(artwork.read_bytes()).hexdigest()
    pins={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'usr/local/lib/parto-overlay').glob('*.py')}
    (root/'etc/parto/standalone-install.json').write_text(json.dumps({'schema':1,'helpers':pins,'transports':['ipsec','tls'],'obfs4_binary':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2)+'\n')
    (root/'etc/parto/appliance-type').write_text('standalone-overlay\n')
    # Remove call-home launchers, trust/config templates and migration inputs.
    for name in ('usr/local/libexec/console-vm-bootstrap','usr/local/libexec/console-vm-overlay-install',
                 'opt/parto-vm/vm_claim_transport.py','usr/local/share/parto-vm/bootstrap-ca.crt',
                 'usr/local/share/parto-vm/prestage-client.conf','usr/local/share/parto-vm/prestage-stunnel.conf',
                 'etc/parto/vm-bootstrap.json'):
        (root/name).unlink(missing_ok=True)
    shutil.rmtree(root/'opt/parto-vm/source',ignore_errors=True)
    for path in sorted((source/'appliances/standalone-overlay').iterdir()):
        if path.is_file() and path.suffix in ('.py','.sh'):
            build['source_files'][str(path.relative_to(source))]=hashlib.sha256(path.read_bytes()).hexdigest()
    build['appliance_type']='standalone-overlay';build['registration_required']=False
    build['source_tree_sha256']=hashlib.sha256(json.dumps(build['source_files'],sort_keys=True).encode()).hexdigest()
    manifest.write_text(json.dumps(build,indent=2,sort_keys=True)+'\n')

if __name__=='__main__':
    import sys
    stage(sys.argv[1],sys.argv[2])
