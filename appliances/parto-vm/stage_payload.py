#!/usr/bin/env python3
"""Minimal public build input; no management service, estate or private lab payload."""
import hashlib,json,os,shutil,subprocess
from pathlib import Path

def stage(source,rootfs,version,architecture='amd64'):
    source,root=Path(source),Path(rootfs);copied={}
    def copy(name,target,mode=0o644):
        src=source/name;dst=root/target;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst);dst.chmod(mode);copied[name]=hashlib.sha256(src.read_bytes()).hexdigest()
    shutil.rmtree(root/'opt/splash',ignore_errors=True)
    app='home/overlay/BootScript/'
    for name in ['standalone_overlay.py','overlay.py','gui_v2/theme.py','gui_v2/__init__.py','kiosk_cursor.py']:
        copy('src/'+name,app+name)
    for path in (source/'configs/splash').iterdir():
        if path.is_file() and not path.name.startswith('.'):
            copy('configs/splash/'+path.name,'opt/splash/'+path.name,0o755 if path.suffix=='.sh' else 0o644)
    for name in ['install-guest.sh','console-launcher.py','vm_console.py','vm_import.py']:
        copy('appliances/parto-vm/'+name,'opt/parto-vm/'+name,0o755)
    for name in ['parto.plymouth','parto.script']:
        copy('appliances/parto-vm/splash/'+name,'usr/share/plymouth/themes/parto/'+name)
    copy('configs/splash/splash-quiet.png','usr/share/plymouth/themes/parto/splash.png')
    for name,target in [('vm_access.py','usr/local/libexec/console-vm-access'),('vm_network.py','usr/local/libexec/console-vm-network'),('parto-vm-identity.service','etc/systemd/system/parto-vm-identity.service')]:
        copy('appliances/parto-vm/runtime/'+name,target,0o755 if name.endswith('.py') else 0o644)
    copy('src/vm_identity.py','usr/local/lib/parto-vm/vm_identity.py')
    for name,target in [('configs/security/10-kiosk-lockdown.conf','etc/lightdm/lightdm.conf.d/10-kiosk-lockdown.conf'),('configs/security/99-kiosk-sysrq.conf','etc/sysctl.d/99-kiosk-sysrq.conf'),('configs/security/10-journal-persist.conf','etc/systemd/journald.conf.d/10-parto.conf')]:copy(name,target)
    for directory in [source/'configs/overlay',source/'appliances/standalone-overlay',source/'appliances/parto-vm']:
        for path in directory.iterdir():
            if path.is_file() and (path.suffix in ('.py','.sh','.service','.tmpfiles') or path.name=='Dockerfile'):copied[str(path.relative_to(source))]=hashlib.sha256(path.read_bytes()).hexdigest()
    build={'schema_version':1,'appliance_version':version,'architecture':architecture,'base':'Debian 12 Bookworm','source_sha':os.environ.get('CONSOLE_SOURCE_SHA','unknown'),'source_tree_dirty':os.environ.get('CONSOLE_SOURCE_DIRTY')=='true','source_files':copied,'source_tree_sha256':hashlib.sha256(json.dumps(copied,sort_keys=True).encode()).hexdigest(),'identity_baked':False,'credentials_baked':False}
    path=root/'opt/parto-vm/build.json';path.write_text(json.dumps(build,indent=2,sort_keys=True)+'\n');(root/'etc/parto').mkdir(parents=True,exist_ok=True);(root/'etc/parto/platform').write_text('vm\n');return build

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--rootfs',required=True);p.add_argument('--version',required=True);p.add_argument('--architecture',default='amd64');a=p.parse_args();stage(a.source,a.rootfs,a.version,a.architecture)
