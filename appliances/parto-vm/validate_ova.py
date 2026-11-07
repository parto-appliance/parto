#!/usr/bin/env python3
"""Verify the manifest, official offline OVF/CIM schemas and disk/controller wiring."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tarfile
import xml.etree.ElementTree as E

OVF = "http://schemas.dmtf.org/ovf/envelope/1"
RASD = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
VMW = "http://www.vmware.com/schema/ovf"
VSSD = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
NS = {"ovf": OVF, "rasd": RASD, "vmw": VMW, "vssd": VSSD}
SCHEMAS = Path(__file__).resolve().parent / "schemas"


def validate_descriptor(descriptor):
    """Use the actual DMTF OVF 1.0 XSD and its exact imported CIM schemas.

    The vendored originals retain their public URLs and notices. An XML catalog
    resolves every import locally; --nonet prevents validation fetching code or
    schemas. This check is independent of the descriptor generator.
    """
    sources = json.loads((SCHEMAS / "sources.json").read_text())
    for entry in sources["schemas"]:
        if hashlib.sha256((SCHEMAS / entry["file"]).read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError(f"official schema checksum mismatch: {entry['file']}")
    xmllint = shutil.which("xmllint")
    if not xmllint:
        raise RuntimeError("OVF XSD validation requires xmllint (Debian: libxml2-utils)")
    if b"<!DOCTYPE" in descriptor or b"<!ENTITY" in descriptor:
        raise ValueError("OVF descriptor must not declare a DTD or entities")
    env = dict(os.environ, XML_CATALOG_FILES=str(SCHEMAS / "catalog.xml"))
    result = subprocess.run(
        [xmllint, "--nonet", "--noout", "--schema", str(SCHEMAS / "dsp8023_1.0.0.xsd"), "-"],
        input=descriptor, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30)
    if result.returncode:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"OVF XSD validation failed: {error}")
    return E.fromstring(descriptor)


def validate_vmdk(stream, size, expected_name):
    """Check the embedded descriptor as well as the sparse header.

    A VMDK with ddb.adapterType=ide cannot be advertised as a SCSI disk. The
    extent name and sector count must also agree with this archive's file.
    """
    header = stream.read(512)
    if len(header) != 512:
        raise ValueError("VMDK header is truncated")
    magic, version, flags, sectors = struct.unpack_from("<IIIQ", header)
    if magic != 0x564D444B or version != 3 or not flags & 0x10000:
        raise ValueError("disk is not compressed streamOptimized VMDK")
    offset, descriptor_sectors = struct.unpack_from("<QQ", header, 28)
    if not offset or not 1 <= descriptor_sectors <= 128 or (offset + descriptor_sectors) * 512 > size:
        raise ValueError("VMDK embedded descriptor is missing or outside disk")
    stream.seek(offset * 512)
    descriptor = stream.read(descriptor_sectors * 512).split(b"\0", 1)[0].decode("ascii")
    if not re.search(r'^createType\s*=\s*"streamOptimized"\s*$', descriptor, re.M):
        raise ValueError("VMDK descriptor must declare streamOptimized")
    extents = re.findall(r'^RW\s+(\d+)\s+SPARSE\s+"([^"]+)"\s*$', descriptor, re.M)
    if extents != [(str(sectors), expected_name)]:
        raise ValueError("VMDK extent name or capacity differs from archive")
    adapters = re.findall(r'^ddb\.adapterType\s*=\s*"([^"]+)"\s*$', descriptor, re.M)
    if len(adapters) != 1 or adapters[0] not in ("ide", "lsilogic"):
        raise ValueError("VMDK descriptor has unsupported or ambiguous adapter type")
    return {"capacity": sectors * 512, "adapter_type": adapters[0]}


def descriptor_architecture(root):
    """Accept legacy amd64 descriptors; require explicit complete ARM wiring.

    The OVA hash binds this declaration. It does not prove the guest's binaries
    are ARM: packaging also checks the guest build provenance, and hypervisor
    acceptance must confirm the running guest architecture.
    """
    hardware = root.find("ovf:VirtualSystem/ovf:VirtualHardwareSection", NS)
    config = {}
    for node in hardware.findall("vmw:Config", NS):
        key = node.get(f"{{{VMW}}}key")
        if key in config:
            raise ValueError("OVF hardware configuration keys must be unique")
        config[key] = node.get(f"{{{VMW}}}value")
    architecture = config.get("guestinfo.parto.architecture", "amd64")
    if architecture not in ("amd64", "arm64"):
        raise ValueError("OVF declares an unsupported appliance architecture")
    os_section = root.find("ovf:VirtualSystem/ovf:OperatingSystemSection", NS)
    os_type = os_section.get(f"{{{VMW}}}osType", "") if os_section is not None else ""
    if architecture == "arm64":
        if config.get("guestinfo.parto.family") != "standalone-overlay":
            raise ValueError("ARM64 OVF must declare the standalone OVERLAY family")
        if config.get("firmware") != "efi":
            raise ValueError("ARM64 OVF requires EFI firmware")
        if os_type != "other5xLinux64Guest" or config.get("guestOS") != "arm-other5xlinux-64":
            raise ValueError("ARM64 OVF requires the ARM guest identifier")
        if hardware.findtext("ovf:System/vssd:VirtualSystemType", namespaces=NS) != "vmx-21":
            raise ValueError("ARM64 OVF requires VMware virtual hardware 21")
        # Initial 0.1.6 ARM artifacts predate the native GUI monitor fix and
        # remain valid immutable history. If monitor settings are declared,
        # require the complete proven one-display configuration.
        if ("svga.numDisplays" in config or "svga.autodetect" in config) and (
                config.get("svga.numDisplays") != "1" or config.get("svga.autodetect") != "FALSE"):
            raise ValueError("ARM64 OVF requires one explicit monitor with display autodetect disabled")
    elif os_type.startswith("arm-") or config.get("guestOS", "").startswith("arm-") or config.get("firmware") != "bios":
        raise ValueError("amd64 OVF architecture differs from its guest or firmware declaration")
    return architecture


def validate(path, expected_architecture=None):
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != 3 or len(set(names)) != 3 or not names[0].endswith(".ovf"):
            raise ValueError("OVA must contain OVF first, manifest and one disk")
        if any(not member.isfile() or PurePosixPath(member.name).name != member.name for member in members):
            raise ValueError("OVA contains a link, special file or nonportable path")
        manifest_name = next((name for name in names if name.endswith(".mf")), None)
        disk_name = next((name for name in names if name.endswith(".vmdk")), None)
        if not manifest_name or not disk_name:
            raise ValueError("OVA requires a SHA-256 manifest and VMDK")
        manifest = archive.extractfile(manifest_name).read().decode("ascii")
        hashes = {}
        for line in manifest.splitlines():
            match = re.fullmatch(r"SHA256\(([^)]+)\)= ([0-9a-f]{64})", line)
            if not match or match[1] in hashes:
                raise ValueError("manifest entries must be unique SHA-256 hashes")
            hashes[match[1]] = match[2]
        if set(hashes) != {names[0], disk_name}:
            raise ValueError("manifest does not cover exactly OVF and disk")
        for name, expected in hashes.items():
            h = hashlib.sha256()
            stream = archive.extractfile(name)
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
            if h.hexdigest() != expected:
                raise ValueError(f"manifest checksum mismatch: {name}")
        root = validate_descriptor(archive.extractfile(names[0]).read())
        architecture = descriptor_architecture(root)
        if expected_architecture is not None and architecture != expected_architecture:
            raise ValueError("OVA architecture differs from expected architecture")
        refs = root.findall("ovf:References/ovf:File", NS)
        if len(refs) != 1 or refs[0].get(f"{{{OVF}}}href") != disk_name:
            raise ValueError("OVF disk reference does not match archive")
        if int(refs[0].get(f"{{{OVF}}}size", "0")) != archive.getmember(disk_name).size:
            raise ValueError("OVF disk reference has incorrect byte size")
        disks = root.findall("ovf:DiskSection/ovf:Disk", NS)
        if len(disks) != 1 or not disks[0].get(f"{{{OVF}}}format", "").endswith("#streamOptimized"):
            raise ValueError("OVF must advertise one streamOptimized disk")
        if disks[0].get(f"{{{OVF}}}fileRef") != refs[0].get(f"{{{OVF}}}id"):
            raise ValueError("OVF disk fileRef does not match declared file id")
        if disks[0].get(f"{{{OVF}}}capacityAllocationUnits") != "byte":
            raise ValueError("OVF disk capacity must be expressed in bytes")
        networks = root.findall("ovf:NetworkSection/ovf:Network", NS)
        network_names = [node.get(f"{{{OVF}}}name") for node in networks]
        if not 1 <= len(networks) <= 8 or len(set(network_names)) != len(network_names):
            raise ValueError("OVF requires one to eight distinct adapter networks")
        config = {n.get(f"{{{VMW}}}key"): n.get(f"{{{VMW}}}value") for n in root.findall(".//vmw:Config", NS)}
        if config.get("guestinfo.parto.family") == "standalone-overlay" and network_names not in (["WAN", "LAN"], ["WAN", "LAN", "Internet"]):
            raise ValueError("Standalone OVA requires WAN, LAN and optional Hub Internet adapters, in that order")
        items = root.findall("ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item", NS)
        nics = [item for item in items if item.findtext("rasd:ResourceType", namespaces=NS) == "10"]
        if len(nics) != len(networks) or sorted(item.findtext("rasd:Connection", namespaces=NS) for item in nics) != sorted(network_names):
            raise ValueError("OVF must wire each Ethernet adapter to its declared network")
        if architecture == "arm64" and any(item.findtext("rasd:ResourceSubType", namespaces=NS) != "VMXNET3" for item in nics):
            raise ValueError("ARM64 OVF requires VMXNET3 Ethernet adapters")
        disk_info = validate_vmdk(archive.extractfile(disk_name), archive.getmember(disk_name).size, disk_name)
        if int(disks[0].get(f"{{{OVF}}}capacity", "0")) != disk_info["capacity"]:
            raise ValueError("OVF capacity differs from VMDK virtual capacity")
        ids = [item.findtext("rasd:InstanceID", namespaces=NS) for item in items]
        if len(ids) != len(set(ids)):
            raise ValueError("OVF hardware InstanceID values must be unique")
        boot_disks = [item for item in items if item.findtext("rasd:ResourceType", namespaces=NS) == "17"]
        if len(boot_disks) != 1 or boot_disks[0].findtext("rasd:HostResource", namespaces=NS) != "ovf:/disk/" + disks[0].get(f"{{{OVF}}}diskId", ""):
            raise ValueError("OVF must attach exactly one declared boot disk")
        parent = boot_disks[0].findtext("rasd:Parent", namespaces=NS)
        controllers = [item for item in items if item.findtext("rasd:InstanceID", namespaces=NS) == parent]
        # A streamOptimized VMDK retains a legacy ddb.adapterType (there is no
        # NVMe value in that transport descriptor). ARM guests attach that disk
        # to the explicit NVMe device, never to the legacy transport adapter.
        expected_type = "20" if architecture == "arm64" else "6" if disk_info["adapter_type"] == "lsilogic" else "5"
        if len(controllers) != 1 or controllers[0].findtext("rasd:ResourceType", namespaces=NS) != expected_type:
            raise ValueError("OVF disk controller differs from VMDK adapter type")
        if expected_type == "6" and controllers[0].findtext("rasd:ResourceSubType", namespaces=NS) != "lsilogic":
            raise ValueError("OVF SCSI controller differs from VMDK adapter type")
        if architecture == "arm64":
            if controllers[0].findtext("rasd:ResourceSubType", namespaces=NS) != "vmware.nvme.controller":
                raise ValueError("ARM64 OVF boot disk requires the NVMe controller")
            if disk_info["adapter_type"] != "lsilogic":
                raise ValueError("ARM64 OVA requires the canonical lsilogic VMDK transport metadata")
            if any(item.findtext("rasd:ResourceType", namespaces=NS) in ("5", "6") for item in items):
                raise ValueError("ARM64 OVF must not declare IDE or SCSI controllers")
        return {"valid": True, "files": names, "architecture": architecture,
                "member_sha256": hashes,
                "network_adapters": network_names, "disk_capacity_bytes": disk_info["capacity"],
                "vmdk_adapter_type": disk_info["adapter_type"],
                "guest_disk_controller": "nvme" if architecture == "arm64" else disk_info["adapter_type"],
                "ovf_xsd": "DMTF DSP8023 1.0.0 (offline)"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ova")
    parser.add_argument("--architecture", choices=("amd64", "arm64"), help="Reject a different declared architecture")
    args = parser.parse_args()
    print(json.dumps(validate(args.ova, expected_architecture=args.architecture)))
