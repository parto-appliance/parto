#!/usr/bin/env python3
"""Package a real boot disk as an OVF 1.0 appliance with SHA-256 manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import xml.etree.ElementTree as E

OVF = "http://schemas.dmtf.org/ovf/envelope/1"
RASD = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
VSSD = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
VMW = "http://www.vmware.com/schema/ovf"
STANDALONE_NETWORK_NAMES = ("WAN", "LAN", "Internet")
NETWORK_NAMES = ("WAN1", "WAN2", "LAN1", "LAN2", "LAN3", "LAN4", "LAN5", "LAN6")
DEPLOYMENT_NOTICE = """BEFORE FIRST POWER-ON

This template includes two WAN and six LAN adapters.

1. Leave 'Power on automatically' unchecked.
2. Click Finish to create the VM.
3. Open the powered-off VM's Edit settings.
4. Add or remove adapters for your OVERLAY operations.
   Keep a maximum of eight total interfaces.
5. Check each adapter's port-group mapping.
6. Power on and complete the console setup wizard.
   Confirm interface roles and IP addressing there.

This is deployment guidance, not additional license terms.
"""
for prefix, uri in (("ovf", OVF), ("rasd", RASD), ("vssd", VSSD), ("vmw", VMW)):
    E.register_namespace(prefix, uri)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def vmdk_capacity(path):
    with open(path, "rb") as stream:
        header = stream.read(512)
    if len(header) < 512 or struct.unpack_from("<I", header)[0] != 0x564D444B:
        raise ValueError("input is not a VMware sparse VMDK")
    version, flags, capacity = struct.unpack_from("<IIQ", header, 4)
    if version != 3 or not flags & 0x10000:
        raise ValueError("OVA disk must be a compressed streamOptimized VMDK")
    return capacity * 512


def ovf_bytes(disk_name, size, capacity, version, architecture="amd64", family="managed-overlay"):
    if architecture not in ("amd64", "arm64"):
        raise ValueError("unsupported appliance architecture")
    if architecture == "arm64" and family != "standalone-overlay":
        raise ValueError("ARM64 is supported only for standalone OVERLAY")
    names = STANDALONE_NETWORK_NAMES if family == "standalone-overlay" else NETWORK_NAMES
    notice_text = ("Parto ships with three adapters: 1 transport WAN, 2 LAN, 3 Hub unfiltered Internet WAN. Keep all three on a Hub; LAN may be unused. Spokes require 1 and 2; leave 3 disconnected or remove it before boot." if family == "standalone-overlay" else DEPLOYMENT_NOTICE)
    root = E.Element(f"{{{OVF}}}Envelope")
    refs = E.SubElement(root, f"{{{OVF}}}References")
    E.SubElement(refs, f"{{{OVF}}}File", {f"{{{OVF}}}id": "diskfile", f"{{{OVF}}}href": disk_name,
                                        f"{{{OVF}}}size": str(size)})
    disks = E.SubElement(root, f"{{{OVF}}}DiskSection")
    E.SubElement(disks, f"{{{OVF}}}Info").text = f"OVERLAY appliance Debian {architecture} boot disk"
    E.SubElement(disks, f"{{{OVF}}}Disk", {f"{{{OVF}}}diskId": "disk1", f"{{{OVF}}}fileRef": "diskfile",
                 f"{{{OVF}}}capacity": str(capacity), f"{{{OVF}}}capacityAllocationUnits": "byte",
                 f"{{{OVF}}}format": "http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"})
    networks = E.SubElement(root, f"{{{OVF}}}NetworkSection")
    E.SubElement(networks, f"{{{OVF}}}Info").text = "Transport WAN, LAN and Hub Internet WAN" if family == "standalone-overlay" else "Two WAN and six LAN adapters; edit the powered-off VM before first boot"
    for name in names:
        node = E.SubElement(networks, f"{{{OVF}}}Network", {f"{{{OVF}}}name": name})
        E.SubElement(node, f"{{{OVF}}}Description").text = f"{name}: confirm role in console setup after editing VM interfaces"
    vm = E.SubElement(root, f"{{{OVF}}}VirtualSystem", {f"{{{OVF}}}id": "OVERLAY-VM"})
    E.SubElement(vm, f"{{{OVF}}}Info").text = "OVERLAY virtual appliance"
    E.SubElement(vm, f"{{{OVF}}}Name").text = f"Parto {version}" if family == "standalone-overlay" else f"OVERLAY Virtual Appliance {version}"
    annotation = E.SubElement(vm, f"{{{OVF}}}AnnotationSection")
    E.SubElement(annotation, f"{{{OVF}}}Info").text = "Before first power-on: edit the VM interfaces"
    E.SubElement(annotation, f"{{{OVF}}}Annotation").text = notice_text
    # Host Client displays OVF EulaSection text before Finish. This is an
    # operational notice, explicitly not a new license or a custom wizard page.
    notice = E.SubElement(vm, f"{{{OVF}}}EulaSection")
    E.SubElement(notice, f"{{{OVF}}}Info").text = "Deployment notice: edit interfaces before first power-on"
    E.SubElement(notice, f"{{{OVF}}}License").text = notice_text
    # A legacy guest descriptor lets ESXi 6.7 import the modern Debian guest;
    # debian11_64Guest is only available starting with vSphere 7.0.
    # The OVF osType uses a VIM enum, while ARM Fusion's native VMX guestOS
    # key is declared separately below. Do not substitute a VMX key here.
    os_type = "debian9_64Guest" if architecture == "amd64" else "other5xLinux64Guest"
    os_section = E.SubElement(vm, f"{{{OVF}}}OperatingSystemSection", {f"{{{OVF}}}id": "96", f"{{{VMW}}}osType": os_type})
    E.SubElement(os_section, f"{{{OVF}}}Info").text = "Debian GNU/Linux 12 (64-bit)"
    E.SubElement(os_section, f"{{{OVF}}}Description").text = f"Debian GNU/Linux 12 Bookworm {architecture}"
    hardware = E.SubElement(vm, f"{{{OVF}}}VirtualHardwareSection")
    E.SubElement(hardware, f"{{{OVF}}}Info").text = "Three fixed Ethernet adapters; graphical console" if family == "standalone-overlay" else "Eight virtual Ethernet adapters; graphical hypervisor console"
    system = E.SubElement(hardware, f"{{{OVF}}}System")
    for name, value in (("ElementName", "Virtual Hardware Family"), ("InstanceID", "0"),
                        ("VirtualSystemIdentifier", "OVERLAY-VM"), ("VirtualSystemType", "vmx-14" if architecture == "amd64" else "vmx-21")):
        E.SubElement(system, f"{{{VSSD}}}{name}").text = value

    def item(instance, name, kind, fields=()):
        node = E.SubElement(hardware, f"{{{OVF}}}Item")
        # CIM_ResourceAllocationSettingData is an xs:sequence, not a bag of
        # properties. Its property references are in lexical order. Inserting
        # AllocationUnits after ResourceType is rejected by ESXi's OVF parser.
        properties = (("ElementName", name), ("InstanceID", str(instance)), ("ResourceType", str(kind)), *fields)
        for key, value in sorted(properties):
            E.SubElement(node, f"{{{RASD}}}{key}").text = str(value)

    item(1, "2 virtual CPUs", 3, (("VirtualQuantity", "2"),))
    item(2, "2048 MiB RAM", 4, (("AllocationUnits", "byte * 2^20"), ("VirtualQuantity", "2048")))
    if architecture == "amd64":
        item(3, "SCSI controller", 6, (("Address", "0"), ("ResourceSubType", "lsilogic")))
    else:
        # VMware's NVMe OVF bus type is 20; the VMDK's legacy adapterType
        # describes its transport format, not this guest's NVMe attachment.
        item(3, "NVMe controller", 20, (("Address", "0"), ("ResourceSubType", "vmware.nvme.controller")))
    item(4, "Boot disk", 17, (("Parent", "3"), ("AddressOnParent", "0"), ("HostResource", "ovf:/disk/disk1")))
    for slot, name in enumerate(names):
        instance = 5 + slot
        item(instance, name, 10, (("AddressOnParent", str(slot)), ("AutomaticAllocation", "true"),
                                  ("Connection", name), ("ResourceSubType", "E1000" if architecture == "amd64" else "VMXNET3")))
    settings = {"firmware": "bios" if architecture == "amd64" else "efi"}
    if architecture == "arm64":
        settings.update({"guestinfo.parto.architecture": architecture,
                         "guestinfo.parto.family": family,
                         "guestOS": "arm-other5xlinux-64",
                         "svga.numDisplays": "1", "svga.autodetect": "FALSE"})
    for key, value in settings.items():
        E.SubElement(hardware, f"{{{VMW}}}Config", {f"{{{OVF}}}required": "false", f"{{{VMW}}}key": key, f"{{{VMW}}}value": value})
    E.indent(root)
    return E.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def packaging_provenance():
    """Record packaging tools separately from the disk's original guest build."""
    here = Path(__file__).resolve().parent
    paths = [here / name for name in ("package_ova.py", "validate_ova.py", "build-linux.sh", "Dockerfile")]
    paths.extend(sorted((here / "schemas").glob("*")))
    files = {str(path.relative_to(here)): sha256(path) for path in paths if path.is_file()}
    data = {"source_files": files,
            "source_tree_sha256": hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "source_sha": None, "source_tree_dirty": None,
            "ovf_schema": "DMTF DSP8023 1.0.0 with original CIM 2.19.0+ imports"}
    try:
        data["source_sha"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=here, text=True).strip()
        data["source_tree_dirty"] = bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--", str(here)], cwd=here, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        pass  # A standalone build can still record exact tool content hashes.
    data["source_sha"] = os.environ.get("CONSOLE_SOURCE_SHA", data["source_sha"])
    if "CONSOLE_SOURCE_DIRTY" in os.environ:
        data["source_tree_dirty"] = os.environ["CONSOLE_SOURCE_DIRTY"] == "true"
    return data


def validate_guest_provenance(build, architecture, family):
    if build.get("architecture", "amd64") != architecture:
        raise ValueError("guest build architecture differs from requested packaging architecture")
    if build.get("family", build.get("appliance_type", family)) != family:
        raise ValueError("guest build family differs from requested packaging family")
    if architecture == "arm64":
        if build.get("family", build.get("appliance_type")) != "standalone-overlay":
            raise ValueError("ARM64 guest provenance must explicitly declare standalone OVERLAY")
        evidence = build.get("guest_architecture_evidence", {})
        loader = evidence.get("efi_fallback", {})
        if (evidence.get("dpkg_architecture") != "arm64" or evidence.get("python_elf_machine") != 183 or
                loader.get("pe_machine") != 0xaa64 or loader.get("path") != "/boot/efi/EFI/BOOT/BOOTAA64.EFI" or
                not re.fullmatch(r"[0-9a-f]{64}", loader.get("sha256", ""))):
            raise ValueError("ARM64 packaging requires matching guest package, ELF and EFI build evidence")


def package(disk, output, version, build_manifest=None, repackage_from=None, family="managed-overlay", architecture="amd64"):
    if family not in ("managed-overlay", "standalone-overlay"):
        raise ValueError("unknown appliance family")
    if architecture not in ("amd64", "arm64"):
        raise ValueError("unsupported appliance architecture")
    if architecture == "arm64" and family != "standalone-overlay":
        raise ValueError("ARM64 is supported only for standalone OVERLAY")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("appliance version must have major.minor.patch form")
    disk, output = Path(disk), Path(output)
    if build_manifest and repackage_from:
        raise ValueError("choose a guest build manifest or an existing appliance provenance record")
    guest_build = json.loads(Path(build_manifest).read_text()) if build_manifest else None
    if guest_build:
        validate_guest_provenance(guest_build, architecture, family)
    if architecture == "arm64" and not (build_manifest or repackage_from):
        raise ValueError("ARM64 packaging requires a guest build provenance record")
    if repackage_from:
        old_path = Path(repackage_from)
        previous = json.loads(old_path.read_text())
        if previous.get("architecture", "amd64") != architecture:
            raise ValueError("repackaging cannot change guest architecture")
        if previous.get("family", family) != family:
            raise ValueError("repackaging cannot change appliance family")
        validate_guest_provenance(previous["build"], architecture, family)
        if version == previous["appliance_version"]:
            raise ValueError("repackaging requires a fresh version; preserve the original artifact")
        old_ova = old_path.parent / previous["ova"]
        if sha256(old_ova) != previous["ova_sha256"]:
            raise ValueError("original OVA checksum differs from its provenance record")
        with tarfile.open(old_ova, "r:") as archive:
            old_disk = next(member.name for member in archive.getmembers() if member.name.endswith(".vmdk"))
            old_manifest = next(member.name for member in archive.getmembers() if member.name.endswith(".mf"))
            entries = dict(re.findall(r"^SHA256\(([^)]+)\)= ([0-9a-f]{64})$", archive.extractfile(old_manifest).read().decode("ascii"), re.M))
        old_disk_sha = sha256(old_path.parent / old_disk)
        if entries.get(old_disk) != old_disk_sha:
            raise ValueError("original disk checksum differs from the original OVA manifest")
    capacity = vmdk_capacity(disk)
    output.mkdir(parents=True, exist_ok=True)
    stem = f"{'parto-vm' if family == 'managed-overlay' else 'parto'}-{version}-{architecture}"
    ovf, manifest, ova = (output / f"{stem}.{suffix}" for suffix in ("ovf", "mf", "ova"))
    from validate_ova import validate, validate_descriptor
    descriptor = ovf_bytes(disk.name, disk.stat().st_size, capacity, version, architecture, family)
    validate_descriptor(descriptor)
    ovf.write_bytes(descriptor)
    manifest.write_text("".join(f"SHA256({path.name})= {sha256(path)}\n" for path in (ovf, disk)))
    with tarfile.open(ova, "w", format=tarfile.USTAR_FORMAT) as archive:
        for path in (ovf, manifest, disk):
            info = archive.gettarinfo(str(path), arcname=path.name)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode = 0o644
            with open(path, "rb") as stream:
                archive.addfile(info, stream)
    validation = validate(ova, expected_architecture=architecture)
    digest = sha256(ova)
    (output / f"{stem}.ova.sha256").write_text(f"{digest}  {ova.name}\n")
    data = {"schema_version": 1, "appliance_version": version, "ova": ova.name,
            "ova_sha256": digest, "disk_sha256": sha256(disk), "disk_capacity_bytes": capacity, "architecture": architecture,
            "family": family,
            "packaging": packaging_provenance(), "validation": {"archive_manifest_xsd_and_disk_wiring": validation},
            "hypervisor_acceptance": ({"proxmox": "pending", "esxi": "pending"} if architecture == "amd64" else
                                      {"fusion": "pending; exact-disk VM bundle required, direct OVA import unsupported"})}
    if build_manifest:
        data["build"] = guest_build
    if repackage_from:
        data["build"] = previous["build"]
        data["guest_image_version"] = previous.get("guest_image_version", previous["appliance_version"])
        data["repackaged_from"] = {
            "appliance_version": previous["appliance_version"], "ova": previous["ova"],
            "ova_sha256": previous["ova_sha256"], "disk": old_disk, "disk_sha256": old_disk_sha,
            "build_manifest": old_path.name, "build_manifest_sha256": sha256(old_path),
            "previous_validation": previous.get("validation", {})}
        data["validation"]["guest_sector_equivalence"] = "pending qemu-img comparison"
    (output / f"{stem}.build.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-manifest")
    parser.add_argument("--family", choices=("managed-overlay", "standalone-overlay"), default="managed-overlay")
    parser.add_argument("--architecture", choices=("amd64", "arm64"), default="amd64")
    parser.add_argument("--repackage-from", help="Existing .build.json; preserve original guest provenance, record new packaging separately")
    args = parser.parse_args()
    result = package(args.disk, args.output, args.version, args.build_manifest, args.repackage_from, args.family, args.architecture)
    print(json.dumps({key: result[key] for key in ("appliance_version", "ova", "ova_sha256", "disk_sha256", "disk_capacity_bytes")}))
