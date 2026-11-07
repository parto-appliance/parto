#!/usr/bin/env bash
# Invoked inside the new guest root, never on the user's machine or a Pi.
set -euo pipefail
id overlay >/dev/null 2>&1 || useradd --create-home --shell /bin/bash overlay
install -d -m 0755 -o root -g root /etc/parto /var/lib/parto
usermod --lock overlay
usermod --lock root
usermod -a -G audio,video,netdev overlay
chown overlay:overlay /home/overlay
chown -R overlay:overlay /home/overlay/BootScript
install -d -m 0755 -o root -g root /home/overlay/.config/openbox /etc/lightdm/lightdm.conf.d
# Existing application network controls use noninteractive sudo, as on the Pi.
printf 'overlay ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-overlay
chmod 0440 /etc/sudoers.d/90-overlay
visudo -c
cat > /etc/lightdm/lightdm.conf <<'EOF'
[Seat:*]
autologin-user=overlay
autologin-session=openbox
autologin-user-timeout=0
xserver-command=X
EOF
cat > /home/overlay/.config/openbox/autostart <<'EOF'
xsetroot -solid black &
while true; do
    /usr/bin/python3 /opt/parto-vm/console-launcher.py
    sleep 3
done &
EOF
chmod 0644 /home/overlay/.config/openbox/autostart
cp /etc/xdg/openbox/rc.xml /home/overlay/.config/openbox/rc.xml
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as E
p = Path('/home/overlay/.config/openbox/rc.xml')
r = E.fromstring(p.read_text())
n = {'o':'http://openbox.org/3.4/rc'}
for node in r.findall('o:keyboard',n):
    for child in list(node): node.remove(child)
for node in r.findall('o:mouse/o:context',n):
    if node.get('name') == 'Root':
        for child in list(node): node.remove(child)
p.write_bytes(E.tostring(r,encoding='utf-8',xml_declaration=True))
PY
# One DHCP WAN; no implicit LAN lease, gateway, bridge or NAT is created.
install -d -m 0755 /etc/NetworkManager/conf.d /etc/NetworkManager/system-connections
printf '[main]\nno-auto-default=*\n' > /etc/NetworkManager/conf.d/20-console-vm.conf
cat > /etc/NetworkManager/system-connections/console-vm-wan.nmconnection <<'EOF'
[connection]
id=console-vm-wan
type=ethernet
interface-name=eth0
autoconnect=true
[ipv4]
method=auto
route-metric=100
[ipv6]
method=disabled
EOF
chmod 0600 /etc/NetworkManager/system-connections/console-vm-wan.nmconnection
cat > /etc/NetworkManager/system-connections/console-vm-lan.nmconnection <<'EOF'
[connection]
id=console-vm-lan
type=ethernet
interface-name=eth1
autoconnect=false
[ipv4]
method=disabled
never-default=true
[ipv6]
method=disabled
EOF
chmod 0600 /etc/NetworkManager/system-connections/console-vm-lan.nmconnection
# Both transport kernels must be ready before registration-bound bootstrap.
printf 'xfrm_interface\ntun\n' > /etc/modules-load.d/parto-vm-overlay.conf
printf 'overlay-appliance\n' > /etc/hostname
printf '127.0.0.1 localhost\n127.0.1.1 overlay-appliance\n::1 localhost ip6-localhost ip6-loopback\n' > /etc/hosts
install -d /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/20-console-vm.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
GSSAPIAuthentication yes
EOF
cat > /etc/systemd/system/console-vm-hostkeys.service <<'EOF'
[Unit]
Description=Generate this VM's unique SSH host keys
Before=ssh.service
ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key
[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
# VM clone guard stays in every trust-bearing transport's dependency chain.
for unit in openvpn@prestage openvpn@client stunnel@prestage stunnel@stunnel console-prestage-handover; do
    install -d "/etc/systemd/system/$unit.service.d"
    printf '[Unit]\nRequires=parto-vm-identity.service\nAfter=parto-vm-identity.service\n' \
        > "/etc/systemd/system/$unit.service.d/10-vm-identity.conf"
done
# The claim bundle installs/enables this watchdog while pre-stage still owns
# tun0. It may start only after successful cutover and the subsequent reboot.
install -d -m 0755 /etc/systemd/system/DetectNetwork.service.d
# The rootfs tar copy does not retain file capabilities. Give only the kiosk's
# primary group ICMP echo sockets; dashboard/watchdog probes need no raw socket.
[ "$(id -g overlay)" = 1000 ] || { echo 'Unexpected appliance group' >&2; exit 1; }
cat > /etc/sysctl.d/60-parto-vm-icmp.conf <<'EOF'
# Appliance user may use ICMP echo sockets without raw-socket capabilities.
net.ipv4.ping_group_range = 1000 1000
EOF
cat > /etc/systemd/system/DetectNetwork.service.d/20-vm-handover.conf <<'EOF'
[Unit]
ConditionPathExists=/etc/parto/handover_complete
EOF
systemctl mask --force frr.service strongswan.service strongswan-starter.service strongswan-swanctl.service \
  ipsec.service
systemctl disable ser2net.service 2>/dev/null || true
systemctl disable dnsmasq.service sssd.service 2>/dev/null || true
systemctl disable systemd-networkd.service systemd-networkd-wait-online.service 2>/dev/null || true
systemctl enable NetworkManager.service chrony.service lightdm.service ssh.service console-vm-hostkeys.service \
  parto-vm-identity.service
if [ "$(cat /etc/parto/appliance-type 2>/dev/null || true)" != standalone-overlay ]; then
  systemctl enable parto-vm-bootstrap.timer console-prestage-handover.timer
fi
systemctl enable qemu-guest-agent.service open-vm-tools.service 2>/dev/null || true
systemctl set-default graphical.target
# This VM has an initramfs and DRM-capable virtual graphics. Use the Pi's PNG
# artwork with Plymouth, then let the native launcher show the same logo at X.
test -f /usr/share/plymouth/themes/parto/parto.plymouth
test -f /usr/share/plymouth/themes/parto/splash.png
plymouth-set-default-theme parto
update-initramfs -u -k all
dpkg-query -W -f='${Package}\t${Version}\n' > /opt/parto-vm/packages.tsv

# Operator root console access is enabled after the wizard sets its password.
rm -f /etc/X11/xorg.conf.d/10-kiosk-lockdown.conf
cat > /etc/X11/xorg.conf.d/20-console-vm-console.conf <<'EOF'
Section "ServerFlags"
    Option "DontVTSwitch" "false"
    Option "DontZap" "true"
EndSection
EOF
systemctl enable getty@tty2.service

# A separate family overlay removes managed enrollment before sealing.
if [ "$(cat /etc/parto/appliance-type 2>/dev/null || true)" = standalone-overlay ]; then
    /opt/parto-vm/install.sh
fi
