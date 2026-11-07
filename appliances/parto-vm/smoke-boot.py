#!/usr/bin/env python3
"""Boot an ephemeral copy under x86 QEMU and record actual guest evidence."""
import base64
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid


def network_acceptance_errors(settings, expected_code, result, inspected, state):
    """Restricted slirp supplies DHCP addresses without a router or DNS option.

    https://github.com/qemu/libslirp/blob/master/src/bootp.c
    A static WAN separately proves the default route; LAN can never supply it.
    """
    errors = []
    if result.get("exitcode") != expected_code or inspected.get("exitcode") != 0:
        errors.append("command_result")
    if settings.get("interfaces") and len(settings["interfaces"]) > 8:
        expected_ready = False
    else:
        expected_ready = expected_code == 0
    if state.get("ready") != expected_ready:
        errors.append("readiness_gate")
    if state.get("unexpected_assembly_paths"):
        errors.append("unexpected_assembly")
    defaults = [route for route in state.get("routes", []) if route.get("dst") == "default"]
    wan_names = {r["name"] for r in settings.get("interfaces", []) if r["role"] == "WAN"} or {"eth0"}
    if any(route.get("dev") not in wan_names for route in defaults):
        errors.append("non_wan_default")
    if expected_code == 0 and settings.get("wan_mode") == "static":
        if len(defaults) != 1 or defaults[0].get("gateway") != settings["wan_gateway"]:
            errors.append("static_wan_default")
    if expected_code == 0 and "interfaces" in settings:
        for row in settings["interfaces"]:
            if row["role"] == "WAN" and row["mode"] == "static":
                if not any(r.get("dev") == row["name"] and r.get("gateway") == row["gateway"] for r in defaults):
                    errors.append("static_wan_default")
    return errors


def installed_source_targets(source_files):
    """Map staged inputs to independently checked installed guest paths."""
    here = "appliances/parto-vm/"
    kit_sources = {"overlay.py", "overlay_runtime.py", "overlay_enrollment.py", "overlay_guard.py",
                   "router.py", "vwire.py", "webaccess.py", "netconfig.py", "cellular.py",
                   "wifi_nm.py", "uplink.py", "Boot-Menu.py", "vm_identity.py", "prestage_handover.py"}
    fixed = {
        "configs/openvpn/prestage-client.conf.example": "/usr/local/share/parto-vm/prestage-client.conf",
        "configs/stunnel-prestage-OnConsoleunit.conf": "/usr/local/share/parto-vm/prestage-stunnel.conf",
        "configs/99-parto.rules": "/etc/udev/rules.d/99-parto.rules",
        "configs/99-parto-linkdown.conf": "/etc/sysctl.d/99-parto-linkdown.conf",

        "configs/security/99-kiosk-sysrq.conf": "/etc/sysctl.d/99-kiosk-sysrq.conf",
        "configs/security/10-journal-persist.conf": "/etc/systemd/journald.conf.d/10-journal-persist.conf",
        "systemd/console-prestage-handover.service": "/etc/systemd/system/console-prestage-handover.service",
        "systemd/console-prestage-handover.timer": "/etc/systemd/system/console-prestage-handover.timer",
        "tools/overlay_migration.py": "/opt/parto-vm/source/tools/overlay_migration.py",
    }
    targets, provenance_only = {}, []
    for source, digest in source_files.items():
        paths = []
        if source.startswith("src/"):
            paths.append("/home/overlay/BootScript/" + source.removeprefix("src/"))
            if source.removeprefix("src/") in kit_sources:
                paths.append("/opt/parto-vm/source/" + source)
        elif source.startswith("configs/splash/"):
            paths.append("/opt/splash/" + source.removeprefix("configs/splash/"))
        elif source.startswith("configs/overlay/"):
            paths.append("/opt/parto-vm/source/" + source)
        elif source in fixed:
            paths.append(fixed[source])
        elif source.startswith(here + "runtime/"):
            name = source.removeprefix(here + "runtime/")
            if name.endswith((".service", ".timer")):
                paths.append("/etc/systemd/system/" + name)
            elif name in ("vm_bootstrap.py", "vm_network.py", "vm_overlay_install.py", "vm_access.py"):
                paths.append("/usr/local/libexec/" + {"vm_bootstrap.py": "console-vm-bootstrap",
                    "vm_access.py": "console-vm-access", "vm_network.py": "console-vm-network", "vm_overlay_install.py": "console-vm-overlay-install"}[name])
            elif name == "vm-bootstrap.json":
                paths.append("/etc/parto/" + name)
            elif name == "bootstrap-ca.crt":
                paths.append("/usr/local/share/parto-vm/" + name)
            else:
                paths.append("/opt/parto-vm/" + name)
        elif source.startswith(here + "splash/"):
            paths.append("/usr/share/plymouth/themes/parto/" + source.removeprefix(here + "splash/"))
        elif source in (here + "install-guest.sh", here + "console-launcher.py", here + "vm_console.py", here + "vm_import.py"):
            paths.append("/opt/parto-vm/" + source.removeprefix(here))
        if source == "src/vm_identity.py":
            paths.append("/usr/local/lib/parto-vm/vm_identity.py")
        if source == "configs/splash/splash-quiet.png":
            paths.append("/usr/share/plymouth/themes/parto/splash.png")
        if not paths:
            provenance_only.append(source)
        for path in paths:
            targets[path] = {"source": source, "sha256": digest}
    return targets, provenance_only


class RPC:
    def __init__(self, path, qmp=False, timeout=10):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.file = self.sock.makefile("rwb", buffering=0)
        if qmp:
            self.file.readline()
            self.call("qmp_capabilities")

    def call(self, command, arguments=None):
        data = {"execute": command}
        if arguments is not None:
            data["arguments"] = arguments
        self.file.write(json.dumps(data).encode() + b"\n")
        while True:
            reply = json.loads(self.file.readline())
            if "error" in reply:
                raise RuntimeError(reply["error"])
            if "return" in reply:
                return reply["return"]

    def close(self):
        self.file.close()
        self.sock.close()


def guest_exec(agent, argv):
    pid = agent.call("guest-exec", {"path": argv[0], "arg": argv[1:], "capture-output": True})["pid"]
    for _ in range(90):
        state = agent.call("guest-exec-status", {"pid": pid})
        if state.get("exited"):
            return {"exitcode": state.get("exitcode"),
                    "stdout": base64.b64decode(state.get("out-data", "")).decode(errors="replace"),
                    "stderr": base64.b64decode(state.get("err-data", "")).decode(errors="replace")}
        time.sleep(1)
    raise RuntimeError("guest evidence command timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=os.environ.get("APPLIANCE_VERSION", "0.4.0"))
    parser.add_argument("--disk")
    parser.add_argument("--verify-network", action="store_true", default=os.environ.get("VERIFY_NETWORK") == "1")
    parser.add_argument("--adapters", type=int, choices=range(2, 9), default=int(os.environ.get("ADAPTERS", "2")))
    args = parser.parse_args()
    if args.verify_network and args.adapters != 8:
        parser.error("expanded network acceptance requires eight adapters")
    output = Path("/output") / ("boot-" + args.version + ("-expanded" if args.adapters > 2 else ""))
    output.mkdir(parents=True, exist_ok=True)
    disk = args.disk or f"/work/parto-vm-{args.version}-amd64.raw"
    instance = str(uuid.uuid4())
    qmp_path, qga_path = "/tmp/console-vm-qmp.sock", "/tmp/console-vm-qga.sock"
    for path in (qmp_path, qga_path):
        Path(path).unlink(missing_ok=True)
    command = ["qemu-system-x86_64", "-machine", "pc", "-accel", "tcg,thread=multi",
               "-m", "2048", "-smp", "2", "-snapshot",
               "-drive", f"file={disk},format=raw,if=none,id=disk",
               "-device", "lsi53c895a,id=scsi", "-device", "scsi-hd,drive=disk",
               "-netdev", "user,id=wan,restrict=yes", "-device", "e1000,netdev=wan,mac=52:54:00:ca:00:01",
               "-netdev", "user,id=lan,net=10.99.0.0/24,restrict=yes",
               "-device", "e1000,netdev=lan,mac=52:54:00:ca:00:02",
               "-smbios", "type=1,uuid=" + instance,
               "-display", "none", "-serial", "file:" + str(output / "boot-serial.log"),
               "-qmp", f"unix:{qmp_path},server=on,wait=off",
               "-chardev", f"socket,path={qga_path},server=on,wait=off,id=qga",
               "-device", "virtio-serial", "-device", "virtserialport,chardev=qga,name=org.qemu.guest_agent.0"]
    for n in range(2, args.adapters):
        command.extend(["-netdev", "user,id=extra%d,net=10.%d.0.0/24,restrict=yes" % (n, 100+n), "-device", "e1000,netdev=extra%d,mac=52:54:00:ca:00:%02x" % (n, n+1)])
    def screen(monitor, name):
        try:
            target = output / (name + ".png")
            monitor.call("screendump", {"filename": str(target), "format": "png"})
        except RuntimeError:
            target = output / (name + ".ppm")
            monitor.call("screendump", {"filename": str(target)})
        return target.name

    log = open(output / "boot-qemu.log", "wb")
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    agent, monitor = None, None
    frames = []
    started = time.monotonic()
    try:
        deadline = time.monotonic() + 360
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("QEMU exited before guest boot")
            try:
                if monitor is None:
                    monitor = RPC(qmp_path, qmp=True)
                frames.append({"seconds": round(time.monotonic() - started, 1),
                               "file": screen(monitor, f"boot-frame-{len(frames):03}")})
                if agent is None:
                    agent = RPC(qga_path, timeout=1)
                agent.call("guest-ping")
                agent.sock.settimeout(10)
                break
            except (OSError, RuntimeError, ValueError):
                if agent:
                    agent.close()
                agent = None
                time.sleep(2)
        if agent is None:
            if monitor:
                screen(monitor, "boot-console")
            raise RuntimeError("guest agent did not become ready within six minutes")
        time.sleep(25)
        evidence = {"schema_version": 1, "booted_under": "QEMU x86_64 TCG",
                    "temporary_overlay": True, "instance_uuid": instance,
                    "appliance_version": args.version, "attached_adapters": args.adapters, "disk": disk, "early_boot_frames": frames,
                    "external_network_blocked": True,
                    "hypervisor_import_acceptance": {"proxmox": "pending", "esxi": "pending"}}
        checks = {
            "services": ["/usr/bin/systemctl", "is-active", "lightdm", "NetworkManager", "parto-vm-identity", "qemu-guest-agent"],
            "failed_units": ["/usr/bin/systemctl", "--failed", "--no-legend"],
            "interfaces": ["/usr/sbin/ip", "-brief", "-4", "address"],
            "routes": ["/usr/sbin/ip", "-4", "route"],
            "identity": ["/usr/bin/python3", "/usr/local/lib/parto-vm/vm_identity.py", "check"],
            "enrollment_status": ["/usr/bin/cat", "/run/parto-vm/bootstrap-status.json"],
            "display_processes": ["/usr/bin/pgrep", "-af", "console-launcher|Boot-Menu|Xorg"],
            "wizard_process": ["/usr/bin/pgrep", "-af", "/opt/parto-vm/console-launcher.py"],
            "ntp_service": ["/usr/bin/systemctl", "is-active", "chrony"],
            "unconfigured_access": ["/usr/bin/python3", "-c", "import pathlib,subprocess; assert not pathlib.Path('/etc/parto/vm-access-ready').exists(); shadow=pathlib.Path('/etc/shadow').read_text(); assert next(x for x in shadow.splitlines() if x.startswith('root:')).split(':')[1] in ('!','!!','*','!*','!!*'); c=subprocess.check_output(['/usr/sbin/sshd','-T'],text=True); assert 'permitrootlogin no' in c and 'passwordauthentication no' in c; assert len([p for p in pathlib.Path('/sys/class/net').iterdir() if (p/'device').exists()])==%d; print('Adapter count matches; no template login password')" % args.adapters],
            "required_ping": ["/usr/bin/ping", "-c", "1", "-W", "2", "127.0.0.1"],
            "appliance_user_ping": ["/usr/bin/sudo", "-u", "overlay", "/usr/bin/ping", "-I", "lo", "-c", "1", "-W", "2", "127.0.0.1"],
            "icmp_group_scope": ["/usr/bin/python3", "-c", "import pathlib,pwd; p=pathlib.Path('/etc/sysctl.d/60-parto-vm-icmp.conf'); expected=str(pwd.getpwnam('overlay').pw_gid); value=pathlib.Path('/proc/sys/net/ipv4/ping_group_range').read_text().split(); assert value==[expected,expected] and expected=='1000'; assert p.stat().st_uid==0 and not p.stat().st_mode&0o022; print('ICMP echo sockets limited to appliance group 1000')"],
            "watchdog_handover_gate": ["/usr/bin/python3", "-c", "import json,pathlib; p=pathlib.Path('/etc/systemd/system/DetectNetwork.service.d/20-vm-handover.conf'); content=p.read_text(); absent=not pathlib.Path('/etc/parto/handover_complete').exists(); valid='ConditionPathExists=/etc/parto/handover_complete' in content and p.stat().st_uid==0 and not p.stat().st_mode&0o022; print(json.dumps({'dropin':str(p),'root_owned':p.stat().st_uid==0,'handover_complete_absent':absent,'condition_valid':valid})); raise SystemExit(not(valid and absent))"],
            "assembly_gate_absent": ["/usr/bin/test", "!", "-e", "/etc/parto/vm-network-ready"],
            "tls_dependencies": ["/usr/bin/python3", "-c", "import importlib.util,pathlib; p='/opt/parto-vm/source/tools/overlay_migration.py'; s=importlib.util.spec_from_file_location('vm_tls_dependencies',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); scope={'__name__':'vm_dependency_check','__file__':p}; exec(compile(m.INSTALL_BODY,p,'exec'),scope); scope['check_tls_dependencies'](); assert pathlib.Path('/etc/modules-load.d/parto-vm-overlay.conf').read_text().splitlines()==['xfrm_interface','tun']; assert all(pathlib.Path('/opt/parto-vm/source/configs/overlay/'+n).is_file() for n in ('console-overlay-openvpn@.service','console-overlay-stunnel@.service')); print('Trusted TUN, supported OpenVPN/stunnel and both private service templates present')"],
            "unassembled": ["/usr/bin/python3", "-c", "import pathlib,json; paths=['/etc/parto/device.json','/var/lib/parto/vm-bootstrap-request.json','/etc/pki/tls/private/vm-bootstrap.pem']; present=[p for p in paths if pathlib.Path(p).exists()]; print(json.dumps({'unexpected_assembly_paths':present})); raise SystemExit(bool(present))"],
            "app_log": ["/usr/bin/tail", "-n", "8", "/home/overlay/BootScript/Logs/application.log"],
            "generic_ike_bgp_services": ["/usr/bin/systemctl", "is-enabled", "frr", "strongswan", "strongswan-starter", "strongswan-swanctl"],
        }
        for name, argv in checks.items():
            evidence[name] = guest_exec(agent, argv)
        evidence["console_image"] = screen(monitor, "boot-console")
        # Verify actual installed bytes before any disposable network mutation.
        # Build-only inputs remain provenance records, with no invented target.
        build_result = guest_exec(agent, ["/usr/bin/cat", "/opt/parto-vm/build.json"])
        if build_result["exitcode"] != 0:
            raise RuntimeError("installed guest build provenance is missing")
        targets, provenance_only = installed_source_targets(json.loads(build_result["stdout"])["source_files"])
        source_check = """import hashlib,json,pathlib,sys
targets=json.loads(sys.argv[1]); mismatches=[]
for path, expected in targets.items():
 p=pathlib.Path(path)
 if not p.is_file() or p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected['sha256']:
  mismatches.append({'path':path,'source':expected['source']})
markers={path:pathlib.Path(path).read_text().strip() for path in ('/etc/parto/platform','/home/overlay/BootScript/model','/home/overlay/BootScript/gui_version')}
markers_ok=list(markers.values())==['vm','vm','2']
print(json.dumps({'target_count':len(targets),'mismatches':mismatches,'generated_markers':markers,'markers_valid':markers_ok}))
raise SystemExit(bool(mismatches) or not markers_ok)
"""
        evidence["installed_source_check"] = guest_exec(agent, ["/usr/bin/python3", "-c", source_check, json.dumps(targets)])
        evidence["build_only_provenance_inputs"] = provenance_only
        failed = [name for name in ("services", "identity", "wizard_process", "ntp_service", "unconfigured_access", "required_ping", "appliance_user_ping", "icmp_group_scope", "watchdog_handover_gate", "assembly_gate_absent", "unassembled", "tls_dependencies")
                  if evidence[name]["exitcode"] != 0]
        if evidence["installed_source_check"]["exitcode"] != 0:
            failed.append("installed_source_check")
        if failed:
            (output / "boot-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
            raise RuntimeError("guest boot acceptance failed: " + ", ".join(failed))
        if args.verify_network:
            # These mutations affect only QEMU's disposable snapshot after the
            # pristine Welcome was recorded. The restricted WAN cannot reach
            # any enrollment service. Never add a host forward or allow WAN.
            access_script = r"""import json,pathlib,secrets,subprocess,pty,os,select,time,fcntl,termios
subprocess.run(['systemctl','stop','parto-vm-bootstrap.timer'],check=True)
password=secrets.token_urlsafe(24)
r=subprocess.run(['/usr/local/libexec/console-vm-access','apply'],input=json.dumps({'password':password}),text=True,capture_output=True)
assert r.returncode==0 and json.loads(r.stdout)['ok']
assert password not in pathlib.Path('/etc/parto/vm-access-ready').read_text()
master,slave=pty.openpty()
p=subprocess.Popen(['ssh','-tt','-o','PubkeyAuthentication=no','-o','GSSAPIAuthentication=no','-o','PreferredAuthentications=password','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','root@127.0.0.1','id -u'],stdin=slave,stdout=slave,stderr=slave,start_new_session=True,preexec_fn=lambda:fcntl.ioctl(0,termios.TIOCSCTTY,0))
os.close(slave)
data=b''; sent=False; deadline=time.monotonic()+30
while time.monotonic()<deadline:
 if select.select([master],[],[],1)[0]:
  try: chunk=os.read(master,4096)
  except OSError: break
  data+=chunk
  if not sent and b'password:' in data.lower(): os.write(master,(password+'\n').encode()); sent=True
 if p.poll() is not None: break
if p.poll() is None: p.kill()
p.wait(); os.close(master)
assert sent and p.returncode==0 and b'\r\n0\r\n' in data, 'SSH password login failed: sent=%s rc=%s bytes=%s' % (sent,p.returncode,len(data))
assert subprocess.run(['systemctl','is-active','--quiet','getty@tty2.service']).returncode==0
print(json.dumps({'root_password_ssh_login':True,'console_getty_active':True,'public_marker_has_no_password':True,'disposable_snapshot_only':True}))
"""
            evidence["operator_access"] = guest_exec(agent, ["/usr/bin/python3", "-c", access_script])
            if evidence["operator_access"]["exitcode"] != 0:
                (output / "boot-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
                raise RuntimeError("password login acceptance failed")
            def rows():
                return [{"name": "eth%d" % n, "role": "WAN" if n==0 else "LAN" if n==1 else "Unused", "mode": "dhcp" if n==0 else "disabled"} for n in range(args.adapters)]
            base = rows()
            static = rows(); static[0].update(mode="static",address="10.0.2.15/24",gateway="10.0.2.2",dns="10.0.2.3")
            isolated = rows(); isolated[1].update(mode="static",address="10.20.0.1/24")
            multi = rows(); multi[1].update(role="WAN",mode="dhcp"); multi[2].update(role="LAN",mode="static",address="10.20.0.1/24"); multi[3].update(role="LAN",mode="static",address="10.21.0.1/24")
            lan_dhcp = rows(); lan_dhcp[1].update(mode="dhcp")
            overlap = rows(); overlap[1].update(mode="static",address="10.0.2.200/24")
            too_many = rows()+[{"name":"eth8","role":"LAN","mode":"disabled"}]
            scenarios = [("lan-dhcp-client-isolated", {"interfaces": lan_dhcp}, 0), ("dhcp-unused", {"interfaces": base}, 0), ("static-wan-default", {"interfaces": static}, 0),
                         ("dhcp-isolated-lan", {"interfaces": isolated}, 0), ("two-wan-two-lan", {"interfaces": multi}, 0),
                         ("reject-overlap", {"interfaces": overlap}, 1), ("reject-ninth", {"interfaces":too_many}, 1)]
            inspect_script = """import json,pathlib,subprocess
profiles={}
for name in ('console-vm-eth%d' % n for n in range(8)):
 profiles[name]=subprocess.check_output(['nmcli','-t','-f','connection.interface-name,connection.autoconnect,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.never-default,ipv6.method','connection','show',name],text=True)
paths=['/etc/parto/device.json','/var/lib/parto/vm-bootstrap-request.json','/etc/pki/tls/private/vm-bootstrap.pem']
present=[p for p in paths if pathlib.Path(p).exists()]
present.extend(str(p) for p in pathlib.Path('/etc/pki/tls/private').glob('*') if p.is_file())
present.extend(str(p) for p in pathlib.Path('/var/lib/parto').rglob('*.csr'))
print(json.dumps({'profiles':profiles,'routes':json.loads(subprocess.check_output(['ip','-j','-4','route'],text=True)),'addresses':json.loads(subprocess.check_output(['ip','-j','-4','address'],text=True)),'ready':pathlib.Path('/etc/parto/vm-network-ready').exists(),'unexpected_assembly_paths':sorted(set(present))}))
"""
            evidence["network_scenarios"] = []
            evidence["restricted_dhcp_limit"] = {"gateway_and_dns_options_omitted": True,
                "source": "https://github.com/qemu/libslirp/blob/master/src/bootp.c",
                "default_route_verified_with": "static-wan-default"}
            for name, settings, expected_code in scenarios:
                result = guest_exec(agent, ["/usr/bin/python3", "-c",
                    "import subprocess,sys; r=subprocess.run(['/usr/local/libexec/console-vm-network','apply'],input=sys.argv[1],text=True,capture_output=True); print(r.stdout,end=''); print(r.stderr,end='',file=sys.stderr); raise SystemExit(r.returncode)", json.dumps(settings)])
                inspected = guest_exec(agent, ["/usr/bin/python3", "-c", inspect_script])
                state = json.loads(inspected["stdout"]) if inspected["exitcode"] == 0 else {}
                entry = {"scenario": name, "settings": settings, "apply": result, "state": state}
                evidence["network_scenarios"].append(entry)
                entry["acceptance_errors"] = network_acceptance_errors(settings, expected_code, result, inspected, state)
                if entry["acceptance_errors"]:
                    (output / "boot-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
                    raise RuntimeError("isolated guest network acceptance failed: " + name)
                if name == "reject-overlap" and json.loads(result["stdout"]).get("error") != "lan_wan_overlap":
                    raise RuntimeError("overlap failed for a reason other than the expected safety check")
            evidence["post_network_identity"] = guest_exec(agent, checks["identity"])
            evidence["post_network_unassembled"] = guest_exec(agent, checks["unassembled"])
            if evidence["post_network_unassembled"]["exitcode"] != 0:
                raise RuntimeError("network acceptance created unexpected assembly state")
        (output / "boot-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps({"booted": True, "evidence": str(output / "boot-evidence.json"),
                          "services": evidence["services"], "enrollment": evidence["enrollment_status"]}))
    finally:
        if agent:
            agent.close()
        if monitor:
            try:
                monitor.call("quit")
            except (OSError, ValueError, RuntimeError):
                pass
            monitor.close()
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=15)
        log.close()


if __name__ == "__main__":
    main()
