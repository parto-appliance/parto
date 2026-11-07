"""Presentation and public status helpers for the VM's native setup wizard."""
import ipaddress
import re


ERRORS = {
    "interface_limit": ("At most eight adapters", "Attach one to eight Ethernet adapters before continuing."),
    "wan_required": ("A WAN is required", "Assign at least one adapter as WAN."),
    "interface_inventory_changed": ("The adapters changed", "Restart setup to review the currently attached adapters."),
    "clock_not_ready": ("The VM clock is not ready", "Let automatic time synchronization finish, then retry. Your identity and setup are saved."),
    "certificate_not_yet_valid": ("The VM clock is not ready", "Let automatic time synchronization finish, then retry. Your identity and setup are saved."),
    "certificate_invalid": ("The secure connection could not be verified", "Check the VM clock. If it is correct, contact support to check the appliance certificate, then retry. Your identity and setup are saved."),
    "network_unreachable": ("Waiting for the WAN connection", "Check adapter 1, its network, gateway and DNS. You can return to network setup or retry."),
    "network_not_ready": ("The network setup is not complete", "Return to WAN and LAN setup, review the settings, then choose Next to apply them."),
    "enrollment_unavailable": ("Registration is not available yet", "Check your WAN connection, then retry. If this continues, contact support. Your settings and identity are saved."),
    "registration_expired": ("This registration code expired", "Contact support to retry. Your VM identity and network settings are saved."),
    "lan_wan_overlap": ("WAN and LAN must use different networks", "Choose an isolated LAN subnet that does not overlap the WAN subnet, then try again."),
    "identity_hold": ("VM identity protection stopped this instance", "This disk belongs to another VM, or its hypervisor identity changed. Import a fresh OVA for another spoke. Keep this disk for recovery; its identity and credentials have been preserved."),
    "already_registered": ("This VM is already registered", "Open the OVERLAY appliance to manage this device and its networks."),
    "network_apply_failed": ("The network settings could not be applied", "Check that both virtual adapters are attached. Review the WAN and LAN settings, then try again."),
    "invalid_address": ("An address is not valid", "Review the IPv4 addresses and prefixes. Use a host address on each network, then try again."),
    "address_prefix_required": ("The address needs a network prefix", "Enter the address and prefix together, for example 10.20.0.1/24."),
    "gateway_outside_wan": ("The WAN gateway is not valid", "Use another host address on the WAN subnet as the gateway, then try again."),
    "dns_required": ("A DNS server is needed", "Enter one to three IPv4 DNS server addresses for the static WAN connection."),
}


def error_text(code):
    return ERRORS.get(code, ("Setup could not finish", "Your VM identity is preserved. Check the connection and retry. If this continues, contact support."))


def registration_code(status):
    """Format only a known public registration identifier, never service text."""
    product = status.get("product_serial", "")
    if (status.get("state") == "hold" or status.get("code") == "registration_expired"
            or not isinstance(product, str)
            or not re.fullmatch(r"[0-9a-hjkmnp-tv-zA-HJKMNP-TV-Z]{12}", product)):
        return ""
    product = product.upper()
    return "-".join(product[index:index + 4] for index in range(0, 12, 4))


def status_text(status):
    """Translate only known public milestones/errors; never display service text."""
    code = status.get("error_code") or status.get("error") or status.get("code")
    if code:
        return (*error_text(str(code)), True)
    state = status.get("state", "")
    if state == "assembling":
        return "Preparing this unit", "Connecting securely and requesting this VM's registration code…", False
    if state == "awaiting_claim":
        return "Register this appliance", "Open portal.example.invalid, sign in, and add this registration code. Setup will finish after you claim it.", False
    if state == "claim_accepted":
        return "Your registration was accepted", "Finishing secure management setup and opening the OVERLAY appliance…", False
    if state == "prestage":
        return "Ready for the customer portal", "The pre-stage code is ready. The registration screen will show it next.", False
    if state == "registered":
        return "This VM is registered", "Opening the OVERLAY appliance…", False
    if state == "hold":
        return (*error_text("identity_hold"), True)
    # Earlier public status files have messages only. Classify locally; their
    # raw contents never reach the screen.
    message = str(status.get("message", "")).lower()
    if any(word in message for word in ("clock", "not yet valid", "not_before", "notbefore")):
        return (*error_text("clock_not_ready"), True)
    if any(word in message for word in ("certificate", "tls", "ssl", "pinned", " ca ")):
        return (*error_text("certificate_invalid"), True)
    if "cannot reach" in message or "network" in message:
        return (*error_text("network_unreachable"), True)
    if "http" in message or "refused" in message or "window" in message:
        return (*error_text("enrollment_unavailable"), True)
    if state == "waiting":
        return (*error_text("setup_failed"), True)
    return "Preparing this unit", "Waiting for secure assembly. This can take a moment…", False


def validate_page(settings, page):
    """Quick form feedback; the immutable root helper validates authoritatively."""
    try:
        if "interfaces" in settings:
            # Same validator as the root helper, imported from packaged source.
            import importlib.util
            from importlib.machinery import SourceFileLoader
            from pathlib import Path
            path = Path("/usr/local/libexec/console-vm-network")
            if not path.exists(): path = Path(__file__).parent / "runtime/vm_network.py"
            spec = importlib.util.spec_from_loader("vm_network_validation", SourceFileLoader("vm_network_validation", str(path)))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.validate(settings)
            return ""
        if page == "wan" and settings["wan_mode"] == "static":
            if "/" not in settings["wan_address"]:
                return "Enter the WAN address with a prefix, for example 192.168.1.20/24."
            address = ipaddress.IPv4Interface(settings["wan_address"])
            gateway = ipaddress.IPv4Address(settings["wan_gateway"])
            if gateway not in address.network or gateway == address.ip:
                return "The gateway must be another address on the WAN subnet."
            servers = settings["wan_dns"].replace(",", " ").split()
            if not 1 <= len(servers) <= 3:
                return "Enter one to three DNS server addresses."
            for server in servers:
                ipaddress.IPv4Address(server)
        if page == "lan" and settings["lan_mode"] == "static":
            if "/" not in settings["lan_address"]:
                return "Enter the LAN address with a prefix, for example 10.20.0.1/24."
            lan = ipaddress.IPv4Interface(settings["lan_address"])
            if settings["wan_mode"] == "static" and lan.network.overlaps(ipaddress.IPv4Interface(settings["wan_address"]).network):
                return "WAN and LAN must use different subnets."
    except (ValueError, KeyError) as error:
        if hasattr(error, "code"): return " · ".join(error_text(error.code))
        return "Enter valid IPv4 addresses and a prefix between 1 and 32."
    return ""


def review_text(settings):
    if "interfaces" in settings:
        lines = ["Root password: configured for console and SSH"]
        for row in settings["interfaces"]:
            lines.append("\n%s · %s · %s" % (row["name"], row["role"], row["mode"]))
            if row.get("address"): lines.append(row["address"])
            if row.get("gateway"): lines.append("Gateway: %s · DNS: %s" % (row["gateway"], row.get("dns", "")))
        return "\n".join(lines)
    wan = ("DHCP (automatic address, gateway and DNS)" if settings["wan_mode"] == "dhcp" else
           "%s\nGateway: %s · DNS: %s" % (settings["wan_address"], settings["wan_gateway"], settings["wan_dns"]))
    lan = "Disabled — no address or routing" if settings["lan_mode"] == "disabled" else settings["lan_address"] + " · no gateway"
    return "Adapter 1 · eth0 · WAN\n%s\n\nAdapter 2 · eth1 · isolated LAN\n%s" % (wan, lan)
