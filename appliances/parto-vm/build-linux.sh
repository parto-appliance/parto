#!/usr/bin/env bash
set -euo pipefail
HERE=/source/appliances/parto-vm
VERSION=${APPLIANCE_VERSION:-0.4.0}
APPLIANCE_TYPE=${APPLIANCE_TYPE:-managed-overlay}
ARCH=${APPLIANCE_ARCH:-amd64}
case "$ARCH:$APPLIANCE_TYPE" in
  amd64:managed-overlay|amd64:standalone-overlay)
    KERNEL_PACKAGE=linux-image-amd64
    GRUB_PACKAGES=(grub-pc-bin grub-efi-amd64-bin)
    GRUB_TARGET=x86_64-efi; EFI_FALLBACK=BOOTX64.EFI; QEMU_USER=qemu-x86_64-static
    ;;
  arm64:standalone-overlay)
    KERNEL_PACKAGE=linux-image-arm64
    GRUB_PACKAGES=(grub-efi-arm64-bin)
    GRUB_TARGET=arm64-efi; EFI_FALLBACK=BOOTAA64.EFI; QEMU_USER=qemu-aarch64-static
    ;;
  *) echo "Unsupported appliance architecture/family: $ARCH/$APPLIANCE_TYPE" >&2; exit 2 ;;
esac
case "$APPLIANCE_TYPE" in
  managed-overlay) STEM=parto-vm ;;
  standalone-overlay) STEM=parto ;;
  *) echo "Unknown appliance type" >&2; exit 2 ;;
esac
DISK=/work/$STEM-$VERSION-$ARCH.raw
ROOTFS=/work/rootfs
MIRROR=${DEBIAN_MIRROR:-https://deb.debian.org/debian}
mkdir -p /work "$ROOTFS"
if [ "${BUILD_MODE:-build}" != prepare ] && \
   { [ -e "$DISK" ] || [ -e "/output/$STEM-$VERSION-$ARCH.ova" ] || [ -e "/output/$STEM-$VERSION-$ARCH-disk.vmdk" ]; }; then
    echo "Appliance $VERSION already exists; choose a fresh version to preserve its disk and artifact." >&2
    exit 2
fi
if [ -f /work/architecture ] && [ "$(cat /work/architecture)" != "$ARCH" ]; then
    echo 'Build cache belongs to another architecture; use a separate BUILD_VOLUME.' >&2
    exit 2
fi
# Older amd64 caches have no marker. Inspect their actual package architecture
# before accepting the cache or replacing any staged application bytes.
if [ -f /work/debootstrap.complete ] && \
   [ "$(chroot "$ROOTFS" dpkg --print-architecture)" != "$ARCH" ]; then
    echo 'Cached Debian root has a different architecture; preserve it and use a separate BUILD_VOLUME.' >&2
    exit 2
fi
python3 "$HERE/audit_template.py" --rootfs "$ROOTFS" --phase cache
# Reuse only the package base, never a sealed appliance or its device identity.
if [ ! -f /work/debootstrap.complete ]; then
    rm -rf "$ROOTFS"
    debootstrap --arch="$ARCH" --variant=minbase --foreign bookworm "$ROOTFS" "$MIRROR"
    [ ! -x "/usr/bin/$QEMU_USER" ] || cp "/usr/bin/$QEMU_USER" "$ROOTFS/usr/bin/"
    chroot "$ROOTFS" /debootstrap/debootstrap --second-stage
    touch /work/debootstrap.complete
fi
[ "$(chroot "$ROOTFS" dpkg --print-architecture)" = "$ARCH" ] || { echo 'Guest package architecture mismatch' >&2; exit 2; }
printf '%s\n' "$ARCH" > /work/architecture
mount --bind /dev "$ROOTFS/dev"
mount -t proc proc "$ROOTFS/proc"
mount -t sysfs sysfs "$ROOTFS/sys"
cleanup() {
    set +e
    umount "$ROOTFS/mnt/boot/efi" 2>/dev/null
    umount "$ROOTFS/mnt" 2>/dev/null
    [ -z "${LOOP:-}" ] || { umount /work/disk/boot/efi; umount /work/disk; losetup -d "$LOOP"; }
    umount "$ROOTFS/sys" "$ROOTFS/proc" "$ROOTFS/dev"
}
trap cleanup EXIT
cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb $MIRROR bookworm main
deb https://deb.debian.org/debian-security bookworm-security main
deb $MIRROR bookworm-updates main
EOF
# Package postinsts must not start an IKE/BGP/SSH daemon in the builder.
printf '#!/bin/sh\nexit 101\n' > "$ROOTFS/usr/sbin/policy-rc.d"
chmod 0755 "$ROOTFS/usr/sbin/policy-rc.d"
mkdir -p "$ROOTFS/etc/initramfs-tools/conf.d"
printf 'MODULES=list\n' > "$ROOTFS/etc/initramfs-tools/conf.d/console-vm"
cat > "$ROOTFS/etc/initramfs-tools/modules" <<'EOF'
# Explicit disk and graphics support; never autodetect the Docker host's drivers.
ext4
sd_mod
virtio_pci
virtio_blk
virtio_scsi
ahci
vmw_pvscsi
nvme
vmxnet3
vmwgfx
EOF
if [ "$ARCH" = amd64 ]; then
    cat >> "$ROOTFS/etc/initramfs-tools/modules" <<'EOF'
ata_piix
mptspi
sym53c8xx
# Early graphical splash on VMware and QEMU's x86 display adapters.
bochs
qxl
cirrus
EOF
fi
PACKAGES=(
      "$KERNEL_PACKAGE" systemd-sysv chrony initramfs-tools grub2-common "${GRUB_PACKAGES[@]}"
      dosfstools openssh-server sudo locales dbus network-manager iproute2 iputils-ping
      zstd plymouth plymouth-themes
      openvpn stunnel4
      traceroute tcpdump iperf3 nftables iptables bridge-utils ethtool dnsmasq
      python3 python3-pyqt5 python3-cryptography python3-requests python3-xdg
      lightdm lightdm-gtk-greeter openbox xserver-xorg-core
      xserver-xorg-video-all xserver-xorg-input-all x11-xserver-utils
      x11-xkb-utils xinput dconf-cli onboard unclutter fonts-dejavu-core
      qemu-guest-agent open-vm-tools ca-certificates curl openssl
      charon-systemd strongswan-swanctl libstrongswan-standard-plugins frr
)
PACKAGE_HASH=$(printf '%s\n' "${PACKAGES[@]}" | sha256sum | cut -d' ' -f1)
if [ ! -f /work/packages.complete ] || [ "$(cat /work/packages.complete)" != "$PACKAGE_HASH" ]; then
    chroot "$ROOTFS" apt-get update
    chroot "$ROOTFS" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PACKAGES[@]}"
    printf '%s\n' "$PACKAGE_HASH" > /work/packages.complete
fi
if [ "${BUILD_MODE:-build}" = prepare ]; then
    echo "Debian $ARCH package base is ready."
    exit 0
fi
python3 "$HERE/audit_template.py" --rootfs "$ROOTFS" --phase cache
python3 "$HERE/stage_payload.py" --source /source --rootfs "$ROOTFS" --version "$VERSION" --architecture "$ARCH"
if [ "$APPLIANCE_TYPE" = standalone-overlay ]; then
    python3 /source/appliances/standalone-overlay/stage.py /source "$ROOTFS"
fi
chroot "$ROOTFS" /opt/parto-vm/install-guest.sh
INITRAMFS_KERNEL=$(find "$ROOTFS/boot" -maxdepth 1 -name 'initrd.img-*' -printf '%f\n' | sort -V | tail -1)
chroot "$ROOTFS" lsinitramfs "/boot/$INITRAMFS_KERNEL" > "/output/initramfs-$VERSION.list"
python3 - "$VERSION" "$ARCH" <<'PY'
from pathlib import Path
import sys
entries = Path('/output/initramfs-' + sys.argv[1] + '.list').read_text().splitlines()
required = ['/' + name + '.ko' for name in (('bochs', 'vmwgfx', 'qxl', 'cirrus') if sys.argv[2] == 'amd64' else ('vmwgfx', 'vmxnet3', 'nvme'))]
required += ['/plymouth/themes/parto/' + name for name in ('parto.plymouth', 'parto.script', 'splash.png')]
missing = [suffix for suffix in required if not any(entry.endswith(suffix) for entry in entries)]
if missing:
    raise SystemExit('Splash initramfs inputs missing: ' + ', '.join(missing))
print('Early splash theme and framebuffer modules verified in initramfs.')
PY
# The executable's ELF machine is independent of the builder's uname. Record
# package and binary evidence in the guest manifest, not an assumed host model.
chroot "$ROOTFS" python3 - "$ARCH" "$KERNEL_PACKAGE" <<'PY'
import hashlib,json,struct,subprocess,sys
from pathlib import Path
architecture=sys.argv[1]
actual=subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()
binary=Path(sys.executable).read_bytes()
machine=struct.unpack_from('<H',binary,18)[0] if binary[:6] == b'\x7fELF\x02\x01' else None
if actual != architecture or machine != {'amd64':62,'arm64':183}[architecture]:
    raise SystemExit('Guest package/ELF architecture mismatch')
kernels=sorted(Path('/boot').glob('vmlinuz-*'))
if not kernels:
    raise SystemExit('Guest kernel is missing')
manifest=Path('/opt/parto-vm/build.json');build=json.loads(manifest.read_text())
build['guest_architecture_evidence']={'dpkg_architecture':actual,'python_elf_machine':machine,
    'kernel_package':subprocess.check_output(['dpkg-query','-W','-f=${Package} ${Version} ${Architecture}',sys.argv[2]],text=True),
    'kernels':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in kernels}}
manifest.write_text(json.dumps(build,indent=2,sort_keys=True)+'\n')
PY
rm -f "$ROOTFS/usr/sbin/policy-rc.d"
chroot "$ROOTFS" apt-get clean
rm -rf "$ROOTFS/var/lib/apt/lists/"* "$ROOTFS/tmp/"* "$ROOTFS/var/tmp/"*
find "$ROOTFS/var/log" -type f -exec truncate -s 0 {} \;
rm -f "$ROOTFS/etc/ssh/ssh_host_"* "$ROOTFS/etc/machine-id" "$ROOTFS/var/lib/dbus/machine-id"
touch "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/systemd/random-seed" "$ROOTFS/usr/bin/qemu-x86_64-static" "$ROOTFS/usr/bin/qemu-aarch64-static"
python3 "$HERE/audit_template.py" --rootfs "$ROOTFS" --phase sealed \
  --output "/output/sealed-template-audit-$VERSION.json"

# Keep the GPT layout stable. ARM boots only its EFI fallback; the small first
# partition is reserved and never receives an x86 BIOS bootloader in an ARM disk.
rm -f "$DISK"
truncate -s 12G "$DISK"
parted -s "$DISK" mklabel gpt mkpart bios 1MiB 2MiB set 1 bios_grub on \
    mkpart efi fat32 2MiB 258MiB set 2 esp on mkpart root ext4 258MiB 100%
[ -e /dev/loop-control ] || mknod /dev/loop-control c 10 237
for i in $(seq 0 31); do [ -e "/dev/loop$i" ] || mknod "/dev/loop$i" b 7 "$i"; done
LOOP=$(losetup --find --show --partscan "$DISK")
sleep 1
for partition in 2 3; do
    NODE="$(basename "$LOOP")p$partition"
    DEVICE_NUMBER=$(cat "/sys/class/block/$NODE/dev")
    [ -e "/dev/$NODE" ] || mknod "/dev/$NODE" b "${DEVICE_NUMBER%:*}" "${DEVICE_NUMBER#*:}"
done
mkfs.vfat -F 32 "${LOOP}p2"
mkfs.ext4 -F -L parto-vm "${LOOP}p3"
mkdir -p /work/disk
mount "${LOOP}p3" /work/disk
mkdir -p /work/disk/boot/efi
mount "${LOOP}p2" /work/disk/boot/efi
# Do not copy bind-mounted host /dev, /proc or /sys into the guest.
tar -C "$ROOTFS" --exclude=./dev --exclude=./proc --exclude=./sys -cf - . | \
    tar -C /work/disk -xf -
mkdir -p /work/disk/dev /work/disk/proc /work/disk/sys
ROOT_UUID=$(blkid -s UUID -o value "${LOOP}p3")
EFI_UUID=$(blkid -s UUID -o value "${LOOP}p2")
printf 'UUID=%s / ext4 defaults 0 1\nUUID=%s /boot/efi vfat umask=0077 0 2\n' \
  "$ROOT_UUID" "$EFI_UUID" > /work/disk/etc/fstab
# Run this guest architecture's GRUB tools, never the Docker host's GRUB.
mount --bind /work/disk "$ROOTFS/mnt"
mount --bind /work/disk/boot/efi "$ROOTFS/mnt/boot/efi"
if [ "$ARCH" = amd64 ]; then
    chroot "$ROOTFS" grub-install --target=i386-pc --boot-directory=/mnt/boot "$LOOP"
fi
chroot "$ROOTFS" grub-install --target="$GRUB_TARGET" --efi-directory=/mnt/boot/efi \
  --boot-directory=/mnt/boot --removable --no-nvram
umount "$ROOTFS/mnt/boot/efi" "$ROOTFS/mnt"
python3 - "$ROOTFS" "$ARCH" "$EFI_FALLBACK" <<'PY'
import hashlib,json,struct,sys
from pathlib import Path
root=Path(sys.argv[1]);architecture=sys.argv[2]
loader=Path('/work/disk/boot/efi/EFI/BOOT')/sys.argv[3]
raw=loader.read_bytes()
offset=struct.unpack_from('<I',raw,0x3c)[0] if raw[:2] == b'MZ' and len(raw)>=0x40 else 0
machine=struct.unpack_from('<H',raw,offset+4)[0] if offset and raw[offset:offset+4] == b'PE\0\0' else None
if machine != {'amd64':0x8664,'arm64':0xaa64}[architecture]:
    raise SystemExit('EFI fallback loader architecture mismatch')
manifest=root/'opt/parto-vm/build.json';build=json.loads(manifest.read_text())
build['guest_architecture_evidence']['efi_fallback']={'path':'/boot/efi/EFI/BOOT/'+sys.argv[3],
    'pe_machine':machine,'sha256':hashlib.sha256(raw).hexdigest()}
manifest.write_text(json.dumps(build,indent=2,sort_keys=True)+'\n')
# This manifest must also be present inside the disk, not just beside the OVA.
Path('/work/disk/opt/parto-vm/build.json').write_bytes(manifest.read_bytes())
Path('/output/guest-architecture-'+build['appliance_version']+'-'+architecture+'.json').write_text(
    json.dumps(build['guest_architecture_evidence'],indent=2,sort_keys=True)+'\n')
PY
KERNEL=$(find /work/disk/boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' | sort -V | tail -1)
INITRD=${KERNEL/vmlinuz/initrd.img}
cat > /work/disk/boot/grub/grub.cfg <<EOF
set default=0
set timeout=2
menuentry '${APPLIANCE_TITLE:-OVERLAY Virtual Appliance}' {
    search --no-floppy --fs-uuid --set=root $ROOT_UUID
    linux /boot/$KERNEL root=UUID=$ROOT_UUID ro net.ifnames=0 biosdevname=0 quiet splash loglevel=3 vt.global_cursor_default=0 systemd.show_status=false plymouth.ignore-serial-consoles console=ttyS0,115200n8 console=tty0
    initrd /boot/$INITRD
}
EOF
sync
umount /work/disk/boot/efi /work/disk
losetup -d "$LOOP"
LOOP=
VMDK=/output/$STEM-$VERSION-$ARCH-disk.vmdk
qemu-img convert -p -f raw -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$DISK" "$VMDK"
python3 "$HERE/package_ova.py" --disk "$VMDK" --output /output --version "$VERSION" \
    --build-manifest "$ROOTFS/opt/parto-vm/build.json" --family "$APPLIANCE_TYPE" --architecture "$ARCH"
python3 "$HERE/validate_ova.py" "/output/$STEM-${VERSION}-$ARCH.ova"
echo 'Appliance disk and OVA built; boot acceptance remains a separate verification.'
