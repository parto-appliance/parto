#!/usr/bin/python3
"""Set this VM's operator-chosen root password through private stdin only."""
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, "/usr/local/lib/parto-vm")
import vm_identity
READY = Path("/etc/parto/vm-access-ready")
COMPLETE = Path("/etc/parto/handover_complete")
CONF = Path("/etc/ssh/sshd_config.d/20-console-vm.conf")

def validate(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128 or any(c in password for c in "\r\n\x00:"):
        raise ValueError("password_invalid")
    return password

def apply(password):
    vm_identity.check()
    if COMPLETE.exists() or READY.exists():
        raise ValueError("access_already_configured")
    validate(password)
    # chpasswd receives no secret through argv, disk, logs or public status.
    result = subprocess.run(["/usr/sbin/chpasswd"], input="root:" + password + "\n", text=True,
                            capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError("password_apply_failed")
    CONF.write_text("PermitRootLogin yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nGSSAPIAuthentication yes\n")
    CONF.chmod(0o644)
    subprocess.run(["/usr/sbin/sshd", "-t"], check=True, capture_output=True, timeout=15)
    subprocess.run(["/usr/bin/systemctl", "reload", "ssh.service"], check=True, capture_output=True, timeout=15)
    vm_identity._write(READY, {"schema_version": 1, "root_password_set": True})

def main():
    try:
        if os.geteuid() != 0 or sys.argv[1:] != ["apply"]:
            raise ValueError("not_authorized")
        raw = sys.stdin.buffer.read(2049)
        if len(raw) > 2048:
            raise ValueError("password_invalid")
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"password"}:
            raise ValueError("password_invalid")
        apply(value["password"])
        print(json.dumps({"ok": True}))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, vm_identity.IdentityError):
        print(json.dumps({"ok": False, "error": "password_apply_failed"}))
        return 1
if __name__ == "__main__":
    sys.exit(main())
