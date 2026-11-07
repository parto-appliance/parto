#!/usr/bin/env python3
"""Refuse initialized guest state before reusing a package cache or sealing an OVA."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

IDENTITY_PATHS = (
    "etc/parto/standalone/state.json", "var/lib/parto-overlay",
    "etc/parto/device.json", "etc/parto/vm-instance.json",
    "etc/parto/vm-identity-hold.json", "etc/parto/handover_complete",
    "etc/parto/customer.json", "home/overlay/BootScript/device.json",
    "etc/parto/vm-network-ready", "etc/parto/vm-access-ready",
    "home/overlay/BootScript/manifest.json", "etc/openvpn/client/prestage.conf",
    "etc/openvpn/prestage.conf", "etc/parto/prestage", "etc/parto/overlay-pki",
    "var/lib/parto/vm-bootstrap-request.json", "etc/krb5.keytab",
    "etc/pki/tls/private/vm-bootstrap.pem", "home/overlay/.ssh/authorized_keys",
)


def audit(rootfs, phase="cache"):
    root = Path(rootfs)
    unexpected = [name for name in IDENTITY_PATHS if (root / name).exists() or (root / name).is_symlink()]
    for name in ("etc/parto", "home/overlay/BootScript", "etc/openvpn", "etc/pki/tls/private"):
        directory = root / name
        if directory.exists():
            for path in directory.rglob("*"):
                if (path.is_file() or path.is_symlink()) and (path.name == ".env" or path.suffix in (".key", ".pem", ".keytab")):
                    unexpected.append(str(path.relative_to(root)))
    shadow = root / "etc/shadow"
    if shadow.exists():
        for line in shadow.read_text().splitlines():
            fields = line.split(":")
            if fields[0] in ("root", "overlay", "operator") and fields[1] not in ("!", "!!", "*", "!*", "!!*"):
                unexpected.append("etc/shadow:" + fields[0] + "-password")
    if phase == "sealed":
        for path in (root / "etc/ssh").glob("ssh_host_*"):
            unexpected.append(str(path.relative_to(root)))
        for name in ("etc/machine-id", "var/lib/dbus/machine-id", "var/lib/systemd/random-seed"):
            path = root / name
            if path.is_symlink() or (path.exists() and path.stat().st_size):
                unexpected.append(name)
    unexpected = sorted(set(unexpected))
    if unexpected:
        raise ValueError("initialized or credential-bearing template; preserve it and use a fresh package cache: " + ", ".join(unexpected))
    return {"schema_version": 1, "phase": phase, "passed": True, "identity_baked": False,
            "credentials_baked": False, "unexpected_paths": [],
            "machine_id_bytes": (root / "etc/machine-id").stat().st_size if (root / "etc/machine-id").exists() else None}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--phase", choices=("cache", "sealed"), default="cache")
    parser.add_argument("--output")
    args = parser.parse_args()
    result = audit(args.rootfs, args.phase)
    data = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(data)
    print(data, end="")
