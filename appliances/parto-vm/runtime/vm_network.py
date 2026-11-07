#!/usr/bin/python3
"""Apply reviewed WAN/LAN roles to at most eight VM adapters, never OVERLAY policy.

Only this root-owned helper writes the public readiness marker. Input is bounded
JSON, interface/profile names are restricted to eth0..eth7; no shell or caller path is used.
"""
import fcntl
import ipaddress
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, "/usr/local/lib/parto-vm")
import vm_identity

READY = Path("/etc/parto/vm-network-ready")
COMPLETE = Path("/etc/parto/handover_complete")
LOCK = Path("/run/parto-vm/network.lock")


class NetworkError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def usable(value):
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
        raise NetworkError("invalid_address")
    return address


def interface(value):
    if not isinstance(value, str) or "/" not in value:
        raise NetworkError("address_prefix_required")
    address = ipaddress.IPv4Interface(value.strip())
    usable(address.ip)
    if address.network.prefixlen < 1 or (address.network.prefixlen < 31 and
            address.ip in (address.network.network_address, address.network.broadcast_address)):
        raise NetworkError("invalid_address")
    return address


def validate_legacy(payload):
    if not isinstance(payload, dict) or set(payload) - {"wan_mode", "wan_address", "wan_gateway", "wan_dns", "lan_mode", "lan_address"}:
        raise NetworkError("invalid_settings")
    if any(not isinstance(value, str) or len(value) > 160 for value in payload.values()):
        raise NetworkError("invalid_settings")
    wan_mode, lan_mode = payload.get("wan_mode"), payload.get("lan_mode")
    if wan_mode not in ("dhcp", "static") or lan_mode not in ("disabled", "static"):
        raise NetworkError("invalid_settings")
    settings = {"wan_mode": wan_mode, "lan_mode": lan_mode}
    try:
        if wan_mode == "static":
            address = interface(payload.get("wan_address", ""))
            gateway = usable(payload.get("wan_gateway", ""))
            if (gateway not in address.network or gateway == address.ip or
                    (address.network.prefixlen < 31 and gateway in
                     (address.network.network_address, address.network.broadcast_address))):
                raise NetworkError("gateway_outside_wan")
            servers = payload.get("wan_dns", "").replace(",", " ").split()
            if not 1 <= len(servers) <= 3:
                raise NetworkError("dns_required")
            settings.update(wan_address=str(address), wan_gateway=str(gateway),
                            wan_dns=",".join(str(usable(server)) for server in servers))
        if lan_mode == "static":
            lan = interface(payload.get("lan_address", ""))
            settings["lan_address"] = str(lan)
            if wan_mode == "static" and lan.network.overlaps(address.network):
                raise NetworkError("lan_wan_overlap")
    except ipaddress.AddressValueError:
        raise NetworkError("invalid_address") from None
    except ipaddress.NetmaskValueError:
        raise NetworkError("invalid_address") from None
    return settings


def call(argv, allowed=(0,)):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if result.returncode not in allowed:
        raise NetworkError("network_apply_failed")
    return result.stdout


def modify(profile, pairs):
    call(["nmcli", "connection", "modify", profile, *pairs])


def apply_legacy(settings):
    """Keep a failed/partial network attempt outside the enrollment gate."""
    vm_identity.check()
    if COMPLETE.exists():
        raise NetworkError("already_registered")
    # Stop a pending retry before changing WAN. Keys and request state remain
    # intact, so the supported bootstrap retry retains its original binding.
    READY.unlink(missing_ok=True)
    call(["systemctl", "stop", "parto-vm-bootstrap.service"])
    common = ["ipv4.never-default", "no", "ipv4.ignore-auto-dns", "no", "ipv4.may-fail", "no", "ipv6.method", "disabled"]
    if settings["wan_mode"] == "dhcp":
        modify("console-vm-wan", [*common, "ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", "", "ipv4.dns", ""])
    else:
        modify("console-vm-wan", [*common, "ipv4.method", "manual", "ipv4.addresses", settings["wan_address"],
                                  "ipv4.gateway", settings["wan_gateway"], "ipv4.dns", settings["wan_dns"]])
    call(["nmcli", "connection", "up", "console-vm-wan"])
    if settings["lan_mode"] == "static":
        lan = interface(settings["lan_address"])
        addresses = json.loads(call(["ip", "-j", "-4", "address", "show", "dev", "eth0"]))
        for adapter in addresses:
            for address in adapter.get("addr_info", []):
                if address.get("family") == "inet":
                    wan = ipaddress.IPv4Interface("%s/%s" % (address["local"], address["prefixlen"]))
                    if lan.network.overlaps(wan.network):
                        raise NetworkError("lan_wan_overlap")
        modify("console-vm-lan", ["ipv4.method", "manual", "ipv4.addresses", settings["lan_address"],
                                  "ipv4.gateway", "", "ipv4.dns", "", "ipv4.routes", "", "ipv4.never-default", "yes",
                                  "ipv6.method", "disabled", "connection.autoconnect", "yes"])
        call(["nmcli", "connection", "up", "console-vm-lan"])
    else:
        modify("console-vm-lan", ["ipv4.method", "disabled", "ipv4.addresses", "", "ipv4.gateway", "", "ipv4.dns", "",
                                  "ipv4.routes", "", "ipv4.never-default", "yes", "ipv6.method", "disabled",
                                  "connection.autoconnect", "no"])
        # NetworkManager returns 10 when the disabled profile was never active.
        call(["nmcli", "connection", "down", "console-vm-lan"], allowed=(0, 10))
    vm_identity.check()
    READY.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".vm-network-", dir=READY.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            os.fchmod(handle.fileno(), 0o644)
            json.dump({"schema_version": 1, **settings}, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, READY)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)



def inventory():
    names = sorted(p.name for p in Path("/sys/class/net").iterdir()
                   if (p / "device").exists() and (p / "type").read_text().strip() == "1")
    if not 1 <= len(names) <= 8 or any(not re.fullmatch(r"eth[0-7]", name) for name in names):
        raise NetworkError("interface_limit")
    return names


def validate(payload):
    if isinstance(payload, dict) and "interfaces" not in payload:
        return validate_legacy(payload)
    if not isinstance(payload, dict) or set(payload) != {"interfaces"}:
        raise NetworkError("invalid_settings")
    rows = payload["interfaces"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 8:
        raise NetworkError("interface_limit")
    result, names, subnets = [], set(), []
    for row in rows:
        if not isinstance(row, dict) or set(row) - {"name", "role", "mode", "address", "gateway", "dns"}:
            raise NetworkError("invalid_settings")
        if any(not isinstance(v, str) or len(v) > 160 for v in row.values()):
            raise NetworkError("invalid_settings")
        name, role, mode = row.get("name"), row.get("role"), row.get("mode")
        if not isinstance(name, str) or not re.fullmatch(r"eth[0-7]", name) or name in names:
            raise NetworkError("invalid_settings")
        names.add(name)
        if role not in ("WAN", "LAN", "Unused") or mode not in ({"WAN": ("dhcp", "static"), "LAN": ("disabled", "dhcp", "static"), "Unused": ("disabled",)}.get(role, ())):
            raise NetworkError("invalid_settings")
        item = {"name": name, "role": role, "mode": mode}
        if mode == "static":
            try:
                address = interface(row.get("address", ""))
                if any(address.network.overlaps(n) for n in subnets):
                    raise NetworkError("lan_wan_overlap")
                subnets.append(address.network)
                item["address"] = str(address)
                if role == "WAN":
                    checked = validate_legacy({"wan_mode": "static", "wan_address": str(address),
                        "wan_gateway": row.get("gateway", ""), "wan_dns": row.get("dns", ""), "lan_mode": "disabled"})
                    item.update(gateway=checked["wan_gateway"], dns=checked["wan_dns"])
                elif row.get("gateway") or row.get("dns"):
                    raise NetworkError("invalid_settings")
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                raise NetworkError("invalid_address") from None
        result.append(item)
    if not any(r["role"] == "WAN" for r in result):
        raise NetworkError("wan_required")
    return {"interfaces": sorted(result, key=lambda r: r["name"])}


def apply(settings):
    if "interfaces" not in settings:
        return apply_legacy(settings)
    vm_identity.check()
    if COMPLETE.exists():
        raise NetworkError("already_registered")
    settings = validate(settings)
    if [r["name"] for r in settings["interfaces"]] != inventory():
        raise NetworkError("interface_inventory_changed")
    READY.unlink(missing_ok=True)
    call(["systemctl", "stop", "parto-vm-bootstrap.service"])
    # Remove only the initial appliance-owned profiles. Other OS profiles stay.
    for profile in ("console-vm-wan", "console-vm-lan"):
        call(["nmcli", "connection", "delete", profile], allowed=(0, 10))
    actual = []
    # WAN routes have deterministic preference in adapter order. LANs never
    # install a default route or DHCP server, bridge, NAT or OVERLAY policy.
    for rank, row in enumerate(settings["interfaces"]):
        name, role, mode = row["name"], row["role"], row["mode"]
        profile = "console-vm-" + name
        call(["nmcli", "connection", "delete", profile], allowed=(0, 10))
        call(["nmcli", "connection", "add", "type", "ethernet", "ifname", name, "con-name", profile])
        pairs = ["connection.autoconnect", "no" if mode == "disabled" else "yes",
                 "ipv6.method", "disabled", "ipv4.never-default", "no" if role == "WAN" else "yes",
                 "ipv4.ignore-auto-routes", "no" if role == "WAN" else "yes",
                 "ipv4.route-metric", str(100 + rank * 100), "ipv4.ignore-auto-dns", "no" if role == "WAN" else "yes",
                 "ipv4.method", {"dhcp": "auto", "static": "manual", "disabled": "disabled"}[mode],
                 "ipv4.addresses", row.get("address", ""), "ipv4.gateway", row.get("gateway", ""),
                 "ipv4.dns", row.get("dns", ""), "ipv4.routes", ""]
        modify(profile, pairs)
        if mode != "disabled":
            call(["nmcli", "connection", "up", profile])
            observed = json.loads(call(["ip", "-j", "-4", "address", "show", "dev", name]))
            for adapter in observed:
                for addr in adapter.get("addr_info", []):
                    if addr.get("family") == "inet":
                        subnet = ipaddress.IPv4Interface("%s/%s" % (addr["local"], addr["prefixlen"])).network
                        if any(subnet.overlaps(old) for old in actual):
                            raise NetworkError("lan_wan_overlap")
                        actual.append(subnet)
        else:
            call(["nmcli", "connection", "down", profile], allowed=(0, 10))
    vm_identity.check()
    vm_identity._write(READY, {"schema_version": 2, **settings})

def main():
    try:
        if os.geteuid() != 0 or sys.argv[1:] != ["apply"]:
            raise NetworkError("not_authorized")
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise NetworkError("invalid_settings")
        settings = validate(json.loads(raw))
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        with LOCK.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            apply(settings)
        print(json.dumps({"ok": True}))
        return 0
    except vm_identity.IdentityError:
        code = "identity_hold"
    except NetworkError as error:
        code = error.code
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        code = "network_apply_failed"
    print(json.dumps({"ok": False, "error": code}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
