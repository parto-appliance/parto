#!/usr/bin/env python3
"""Repackage a pristine Parto OVA with VMware-native stream disks, without booting.

Guest sectors/version remain unchanged. Packaging revision names preserve the
original artifact. No checksum bypass or hypervisor/lab mutation is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

OVF = 'http://schemas.dmtf.org/ovf/envelope/1'
DISK_MANAGER = '/Applications/VMware Fusion.app/Contents/Library/vmware-vdiskmanager'


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def extract_verified(source, directory):
    with tarfile.open(source, 'r:') as archive:
        members = archive.getmembers()
        if (len(members) != 3 or len({m.name for m in members}) != 3
                or any(not m.isfile() or Path(m.name).name != m.name for m in members)):
            raise ValueError('Expected three unique regular, flat OVF/manifest/VMDK members')
        by_suffix = {}
        for member in members:
            suffix = Path(member.name).suffix
            if suffix not in ('.ovf', '.mf', '.vmdk') or suffix in by_suffix:
                raise ValueError('Unexpected or duplicate package member type')
            target = directory / member.name
            with archive.extractfile(member) as incoming, target.open('wb') as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            by_suffix[suffix] = target
    lines = by_suffix['.mf'].read_text().splitlines()
    checks = {}
    for line in lines:
        match = re.fullmatch(r'SHA256\(([^)]+)\)\s*=\s*([a-fA-F0-9]{64})', line)
        if not match or match[1] in checks:
            raise ValueError('Expected unique SHA256 manifest entries')
        checks[match[1]] = match[2].lower()
    if set(checks) != {by_suffix['.ovf'].name, by_suffix['.vmdk'].name}:
        raise ValueError('Manifest must cover the descriptor and disk exactly')
    for path in (by_suffix['.ovf'], by_suffix['.vmdk']):
        if digest(path) != checks[path.name]:
            raise ValueError('Source manifest mismatch: ' + path.name)
    return by_suffix


def stream_info(path):
    with path.open('rb') as stream:
        header = stream.read(512)
        stream.seek(-512, 2)
        eos = stream.read()
    if len(header) != 512 or struct.unpack_from('<I', header)[0] != 0x564d444b:
        raise ValueError('Expected sparse VMDK')
    version, flags, sectors = struct.unpack_from('<IIQ', header, 4)
    if version != 3 or flags & 0x30000 != 0x30000:
        raise ValueError('Expected compressed stream VMDK with markers')
    return {'capacity_bytes': sectors * 512, 'flags': flags,
            'sector_aligned': path.stat().st_size % 512 == 0,
            'last_sector_zero': eos == bytes(512)}


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def compare(directory, original, converted, image):
    qemu = shutil.which('qemu-img')
    args = ['compare', '-f', 'vmdk', '-F', 'vmdk']
    if qemu:
        return run([qemu, *args, str(original), str(converted)])
    return run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
                '--entrypoint', 'qemu-img', '-v', str(directory) + ':/images:ro', image,
                *args, '/images/' + original.name, '/images/' + converted.name])


def repackage(source, output, converted_disk=None, disk_manager=DISK_MANAGER,
              image='parto-vm-builder:bookworm'):
    source, output = Path(source).resolve(), Path(output).absolute()
    match = re.fullmatch(r'parto-(\d+\.\d+\.\d+)-(amd64|arm64)\.ova', source.name)
    if not match or output.suffix != '.ova' or output.exists():
        raise ValueError('Use an original versioned Parto source and a NEW output OVA')
    if output.name != source.stem + '-vmware-r1.ova':
        raise ValueError('Use the vmware-r1 suffix; never silently replace an artifact')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='parto-vmware-', dir=output.parent) as name:
        directory = Path(name)
        files = extract_verified(source, directory)
        original = files['.vmdk']
        disk = directory / (output.stem + '-disk.vmdk')
        if converted_disk:
            shutil.copyfile(converted_disk, disk)
        else:
            run([disk_manager, '-r', str(original), '-t', '5', '-z', '6', str(disk)])
        old_info, new_info = stream_info(original), stream_info(disk)
        with disk.open('rb') as stream:
            header = stream.read(512)
            offset, count = struct.unpack_from('<QQ', header, 28)
            if not offset or not 1 <= count <= 128:
                raise ValueError('Converted VMDK descriptor is missing or oversized')
            stream.seek(offset * 512)
            embedded = stream.read(count * 512).decode('ascii').rstrip('\x00')
        extents = re.findall(r'^RW ([0-9]+) SPARSE "([^"\r\n]+)"\s*$', embedded, re.M)
        if extents != [(str(new_info['capacity_bytes'] // 512), disk.name)]:
            raise ValueError('Converted VMDK extent must match its final archive filename')
        if old_info['capacity_bytes'] != new_info['capacity_bytes']:
            raise ValueError('Disk capacity changed')
        comparison = compare(directory, original, disk, image)
        descriptor = files['.ovf'].read_bytes()
        # Preserve the original hardware, architecture, networking and product metadata.
        # Only the disk filename and byte size in References change.
        old_name = original.name.encode()
        if descriptor.count(old_name) != 1:
            raise ValueError('Expected exactly one disk reference')
        descriptor = descriptor.replace(old_name, disk.name.encode())
        size = str(original.stat().st_size).encode()
        pattern = rb'(ovf:size=")' + size + rb'(")'
        descriptor, count = re.subn(pattern, lambda m: m[1] + str(disk.stat().st_size).encode() + m[2], descriptor)
        if count != 1:
            raise ValueError('Expected exactly one referenced disk size')
        root = ET.fromstring(descriptor)
        if not root.find('.//{' + OVF + '}VirtualSystem/{' + OVF + '}Name').text.startswith('Parto '):
            raise ValueError('Standalone Parto descriptor required')
        ovf = directory / (output.stem + '.ovf'); ovf.write_bytes(descriptor)
        manifest = directory / (output.stem + '.mf')
        manifest.write_text(''.join('SHA256(' + p.name + ')= ' + digest(p) + '\n' for p in (ovf, disk)))
        with tarfile.open(output, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for path in (ovf, manifest, disk):
                member = tarfile.TarInfo(path.name); member.size = path.stat().st_size
                member.mode = 0o644; member.uid = member.gid = 0; member.mtime = 0
                with path.open('rb') as stream: archive.addfile(member, stream)
        checked = directory / 'checked'; checked.mkdir(); extract_verified(output, checked)
        data = {'guest_version': match[1], 'architecture': match[2], 'packaging_revision': 'vmware-r1',
                'source_ova': source.name, 'source_sha256': digest(source),
                'ova': output.name, 'ova_sha256': digest(output), 'disk_sha256': digest(disk),
                'source_disk_layout': old_info, 'new_disk_layout': new_info,
                'guest_sector_comparison': comparison.strip(), 'internal_sha256_manifest': 'passed',
                'converter': 'VMware vmware-vdiskmanager -t 5 -z 6',
                'repackager_sha256': digest(Path(__file__)),
                'workstation_26_manual_import': 'pending external tester'}
        output.with_suffix('.ova.sha256').write_text(data['ova_sha256'] + '  ' + output.name + '\n')
        output.with_suffix('.packaging.json').write_text(json.dumps(data, indent=2) + '\n')
    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source'); parser.add_argument('output')
    parser.add_argument('--converted-disk', help='Previously VMware-converted disk; sectors are still verified')
    args = parser.parse_args()
    print(json.dumps(repackage(args.source, args.output, args.converted_disk), indent=2))
