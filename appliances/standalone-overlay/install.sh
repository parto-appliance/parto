#!/usr/bin/env bash
# Runs only in the fresh standalone guest chroot.
set -euo pipefail
for unit in parto-vm-bootstrap.service parto-vm-bootstrap.timer console-prestage-handover.service console-prestage-handover.timer DetectNetwork.service openvpn@prestage.service openvpn@client.service stunnel@prestage.service stunnel@stunnel.service sssd.service certmonger.service; do
    systemctl disable "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/$unit"
    systemctl mask --force "$unit"
done
cat > /home/overlay/.config/openbox/autostart <<'EOF'
xsetroot -solid black &
while true; do
    /usr/bin/python3 /opt/parto-vm/standalone-console.py
    sleep 3
done &
EOF
cat > /etc/systemd/system/console-standalone-restore.service <<'EOF'
[Unit]
Description=Restore Parto and retry until the WAN is ready
Requires=parto-vm-identity.service
After=parto-vm-identity.service network-online.target
Wants=network-online.target
ConditionPathExists=/etc/parto/standalone/state.json
StartLimitIntervalSec=0
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /usr/local/lib/parto-overlay/standalone-root.py restore
Restart=on-failure
RestartSec=15
TimeoutStartSec=180
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
systemctl enable console-standalone-restore.service
# A suspended VM can resume hours behind after chrony has used its boot-time
# steps. Allow large corrections from chrony's selected sources at any uptime.
sed -i -E 's/^[[:space:]]*makestep[[:space:]].*/makestep 60 -1/' /etc/chrony/chrony.conf
grep -qx 'makestep 60 -1' /etc/chrony/chrony.conf
# The network engine maintains guarded routes and exact prefix/NAT policies.
printf 'net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.rp_filter = 0\nnet.ipv4.conf.default.rp_filter = 0\n' > /etc/sysctl.d/90-parto-overlay.conf
printf 'parto\n' > /etc/hostname
printf '127.0.0.1 localhost\n127.0.1.1 parto\n::1 localhost ip6-localhost ip6-loopback\n' > /etc/hosts
install -d -m 0755 -o overlay -g overlay /home/overlay/standalone-exchange
install -d -m 0755 -o root -g root /var/lib/parto-inbox

# Only the standalone template's obsolete account backup files are removed.
rm -f /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-

# Reconcile only owned egress routes; never restart transport/BGP on WAN2 changes.
cat > /etc/systemd/system/parto-egress-reconcile.service <<'EOF_UNIT'
[Unit]
Description=Parto Internet WAN route recovery
After=NetworkManager.service
ConditionPathExists=/etc/parto/standalone/state.json
ConditionPathExists=/etc/parto/standalone/egress-reconcile-enabled
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /usr/local/lib/parto-overlay/standalone-root.py reconcile
TimeoutStartSec=45
UMask=0077
EOF_UNIT
cat > /etc/systemd/system/parto-egress-reconcile.timer <<'EOF_UNIT'
[Unit]
Description=Parto Internet WAN recovery timer
[Timer]
OnBootSec=15
OnCalendar=*-*-* *:*:0/5
AccuracySec=1
[Install]
WantedBy=timers.target
EOF_UNIT
systemctl enable parto-egress-reconcile.timer

# Separate web service user: only the fixed validated helper is privileged.
id parto-web >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin parto-web
usermod --lock parto-web
printf 'parto-web ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/lib/parto-overlay/standalone-root.py *\n' > /etc/sudoers.d/91-parto-web
chmod 0440 /etc/sudoers.d/91-parto-web
cat > /usr/local/libexec/parto-web-certificate <<'EOF'
#!/bin/sh
set -eu
install -d -m 0750 -o root -g parto-web /var/lib/parto-web
if [ ! -s /var/lib/parto-web/server.key ] || [ ! -s /var/lib/parto-web/server.crt ]; then
 umask 077
 openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 -subj /CN=Parto -keyout /var/lib/parto-web/server.key -out /var/lib/parto-web/server.crt >/dev/null 2>&1
fi
chown root:parto-web /var/lib/parto-web/server.key /var/lib/parto-web/server.crt
chmod 0640 /var/lib/parto-web/server.key
chmod 0644 /var/lib/parto-web/server.crt
chmod 0755 /var/lib/parto-web
EOF
chmod 0755 /usr/local/libexec/parto-web-certificate
cat > /etc/systemd/system/parto-web-certificate.service <<'EOF'
[Unit]
Description=Create this appliance's local HTTPS identity
Before=parto-web.service
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/parto-web-certificate
RemainAfterExit=yes
UMask=0077
EOF
cat > /etc/systemd/system/parto-web.service <<'EOF'
[Unit]
Description=Parto local HTTPS management
After=network.target parto-web-certificate.service
Requires=parto-web-certificate.service
[Service]
User=parto-web
Group=parto-web
ExecStartPre=+/usr/sbin/nft -f /etc/parto-management.nft
ExecStart=/usr/bin/python3 /opt/parto-web/parto-web.py
Restart=on-failure
RestartSec=5
UMask=0077
PrivateTmp=yes
ProtectHome=read-only
MemoryMax=192M
TasksMax=64
LimitNOFILE=256
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/parto-management.nft <<'EOF'
add table inet parto_management
flush table inet parto_management
add chain inet parto_management input { type filter hook input priority -10; policy accept; }
add rule inet parto_management input tcp dport 8443 iifname != { "eth0", "eth2" } drop
EOF
systemctl enable parto-web.service
