#!/usr/bin/env python3
"""Prepare a fresh Apple Silicon Fusion VM bundle from a verified ARM64 OVA.

Fusion on Apple Silicon does not support OVF/OVA import. This helper converts
the exact embedded disk using Fusion's installed disk manager, verifies logical
sector equivalence with qemu-img, and writes a powered-off VM configuration.
It does not register, start or alter any existing VM or host network.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "parto-vm"))
from package_ova import STANDALONE_NETWORK_NAMES, sha256
from validate_ova import validate

DISK_MANAGER = "/Applications/VMware Fusion.app/Contents/Library/vmware-vdiskmanager"
QEMU_IMAGE = "parto-vm-builder:bookworm"


def vmx_bytes(display_name, network_names=STANDALONE_NETWORK_NAMES):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,100}", display_name):
        raise ValueError("bundle name must use plain letters, numbers, spaces, dots, underscores or hyphens")
    config = {".encoding": "UTF-8", "config.version": "8", "virtualHW.version": "21",
              "virtualHW.productCompatibility": "hosted", "guestOS": "arm-other5xlinux-64",
              "firmware": "efi", "displayName": display_name, "numvcpus": "2", "memsize": "2048",
              "nvram": "appliance.nvram", "svga.present": "TRUE", "mks.enable3d": "FALSE",
              # Fusion's GUI reads literal monitor settings differently from
              # headless VMCLI defaults. Both fields are needed for the native
              # console to open and deliver input to the setup wizard.
              "svga.numDisplays": "1", "svga.autodetect": "FALSE",
              "pciBridge0.present": "TRUE", "vmci0.present": "TRUE", "hpet0.present": "TRUE",
              "usb_xhci.present": "TRUE", "nvme0.present": "TRUE", "nvme0:0.present": "TRUE",
              "nvme0:0.fileName": "boot.vmdk", "guestinfo.parto.architecture": "arm64",
              "guestinfo.parto.family": "standalone-overlay"}
    for number in range(4, 8):
        config.update({f"pciBridge{number}.present": "TRUE", f"pciBridge{number}.virtualDev": "pcieRootPort",
                       f"pciBridge{number}.functions": "8"})
    # Disconnected defaults make opening the companion safe before the user
    # chooses the WAN/LAN mappings. The lab harness maps these with native CLI.
    for slot, name in enumerate(network_names):
        network = "nat" if name.startswith("WAN") else "hostonly"
        config.update({f"ethernet{slot}.present": "TRUE", f"ethernet{slot}.virtualDev": "vmxnet3",
                       f"ethernet{slot}.connectionType": network, f"ethernet{slot}.startConnected": "FALSE",
                       f"ethernet{slot}.addressType": "generated"})
    return ("".join(f'{key} = "{value}"\n' for key, value in config.items())).encode("utf-8")


def qemu_command(arguments, source_dir, bundle, qemu_img=None, qemu_image=QEMU_IMAGE):
    binary = qemu_img or shutil.which("qemu-img")
    if binary:
        return [str(binary), *arguments]
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("sector verification requires qemu-img or Docker with the existing VM builder image")
    translated = [arg.replace(str(bundle) + "/", "/bundle/").replace(str(source_dir) + "/", "/input/")
                  for arg in arguments]
    return [docker, "run", "--rm", "--pull", "never", "--network", "none", "--entrypoint", "qemu-img",
            "-v", f"{source_dir}:/input:ro", "-v", f"{bundle}:/bundle:ro", qemu_image, *translated]


def run(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
    if result.returncode:
        raise RuntimeError(f"tool failed ({result.returncode}): {result.stdout.strip()}")
    return result.stdout


def prepare(ova, output, disk_manager=DISK_MANAGER, qemu_img=None, qemu_image=QEMU_IMAGE):
    ova, bundle = Path(ova).resolve(), Path(output).absolute()
    if bundle.suffix != ".vmwarevm":
        raise ValueError("output must be a new .vmwarevm directory")
    if bundle.exists() or bundle.is_symlink():
        raise ValueError("output already exists; preserve it and choose a fresh bundle name")
    if not Path(disk_manager).is_file():
        raise RuntimeError("Fusion's installed vmware-vdiskmanager is required")
    validation = validate(ova, expected_architecture="arm64")
    network_names=validation["network_adapters"]
    config = vmx_bytes(bundle.stem, network_names)
    source_ova_sha = sha256(ova)
    bundle.parent.mkdir(parents=True, exist_ok=True)
    bundle.mkdir(mode=0o700)
    disk = bundle / "boot.vmdk"
    with tempfile.TemporaryDirectory(prefix="standalone-fusion-disk-", dir=bundle.parent) as temp:
        source_dir = Path(temp)
        with tarfile.open(ova, "r:") as archive:
            disk_name = next(name for name in validation["files"] if name.endswith(".vmdk"))
            source = source_dir / disk_name
            with archive.extractfile(disk_name) as stream, source.open("xb") as target:
                shutil.copyfileobj(stream, target, length=1024 * 1024)
        source_disk_sha = sha256(source)
        if source_disk_sha != validation["member_sha256"][disk_name] or sha256(ova) != source_ova_sha:
            raise ValueError("source OVA or extracted disk changed after archive validation")
        conversion_log = run([str(disk_manager), "-r", str(source), "-t", "0", str(disk)])
        if not disk.is_file() or disk.is_symlink():
            raise RuntimeError("Fusion disk conversion did not produce a regular disk")
        disk_info = {}
        for label, path in (("ova_disk", source), ("fusion_disk", disk)):
            disk_info[label] = json.loads(run(qemu_command(["info", "--output=json", "-f", "vmdk", str(path)],
                                                         source_dir, bundle, qemu_img, qemu_image)))
            if disk_info[label].get("virtual-size") != validation["disk_capacity_bytes"]:
                raise ValueError("converted disk capacity differs from the verified OVA")
        compare_log = run(qemu_command(["compare", "-f", "vmdk", "-F", "vmdk", str(source), str(disk)],
                                       source_dir, bundle, qemu_img, qemu_image))
    # Do not advertise a usable bundle until both capacity and real logical
    # sector comparison pass. A failed conversion leaves its new disk for review.
    vmx = bundle / "appliance.vmx"
    vmx.write_bytes(config)
    (bundle / "conversion.log").write_text(conversion_log + "\n" + compare_log)
    mapping = "\n".join(f"  Adapter {slot + 1}: {name}" for slot, name in enumerate(network_names))
    (bundle / "README.txt").write_text(
        "Parto for VMware Fusion on Apple Silicon\n\n"
        "Open appliance.vmx in VMware Fusion. Before first power-on, open VM Settings.\n"
        "Both adapters start disconnected. Map and connect WAN and LAN\n"
        "to their appropriate networks. Adapter 1 is WAN; adapter 2 is LAN.\n"
        + mapping + "\n\n"
        "Set a root password in the native setup wizard. Exchange only the exported\n"
        "public peer JSON files and verify the hub fingerprint with the hub owner.\n\n"
        "Fusion on Apple Silicon cannot import the companion OVA directly. This VM\n"
        "uses that OVA's exact disk, converted and checked for identical sectors.\n"
        "fusion-provenance.json records the source hashes and conversion checks.\n")
    receipt = {"schema_version": 1, "architecture": "arm64", "family": "standalone-overlay",
               "source_ova": ova.name, "source_ova_sha256": source_ova_sha, "source_disk": disk_name,
               "source_disk_sha256": source_disk_sha, "disk": disk.name, "disk_sha256": sha256(disk),
               "disk_capacity_bytes": validation["disk_capacity_bytes"], "vmx": vmx.name, "vmx_sha256": sha256(vmx),
               "conversion": {"tool": Path(disk_manager).name, "tool_sha256": sha256(disk_manager),
                              "format": "single growable VMware VMDK", "qemu_img_sector_compare": "passed",
                              "capacity_comparison": "passed"},
               "preparation": {"source_file": Path(__file__).name, "source_sha256": sha256(__file__)},
               "hardware": {"guest_os": "arm-other5xlinux-64", "firmware": "efi", "hardware_version": 21,
                            "disk_controller": "nvme", "ethernet": "vmxnet3", "network_adapters": list(network_names),
                            "display_monitors": 1, "display_autodetect": False,
                            "adapters_connected": False},
               "hypervisor_acceptance": "pending; this helper does not start Fusion",
               "direct_ova_import": "unsupported on Apple Silicon Fusion; use this exact-disk companion"}
    (bundle / "fusion-provenance.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ova", required=True)
    parser.add_argument("--output", required=True, help="Fresh .vmwarevm directory; never overwrite an existing VM")
    parser.add_argument("--disk-manager", default=DISK_MANAGER)
    parser.add_argument("--qemu-img", help="Installed qemu-img executable; otherwise use the local builder Docker image")
    parser.add_argument("--qemu-image", default=QEMU_IMAGE, help="Already installed Docker image providing qemu-img")
    args = parser.parse_args()
    print(json.dumps(prepare(args.ova, args.output, args.disk_manager, args.qemu_img, args.qemu_image), sort_keys=True))
