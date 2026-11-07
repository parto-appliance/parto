"""OVERLAY desired-state validation and deterministic, secret-free compilation.

This module has no device or database side effects. The portal uses it to review
a topology; the privileged runtime recompiles it and proves local reachability,
dedicated network PKI and underlay routing before installing anything. Generated
IPsec previews deliberately contain local-source placeholders until that proof.
"""
from collections.abc import Mapping
from copy import deepcopy
import hashlib
import ipaddress
import itertools
import re


SCHEMA_VERSION = 1
PRODUCTION_MODELS = frozenset(("4g", "lan4g"))
MAX_MESH_SITES = 5
MAX_HUB_SITES = 32
MAX_PREFIXES_PER_SITE = 32
OVERLAY_CIDR = "10.254.0.0/16"
PROTECTED_CIDRS = ("192.168.4.0/24", "192.168.50.0/23", OVERLAY_CIDR)
IKE_PROPOSAL = "aes256gcm16-prfsha384-ecp384"
ESP_PROPOSAL = "aes256gcm16-ecp384"
_PRIVATE = tuple(ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_PROTECTED = tuple(ipaddress.ip_network(n) for n in PROTECTED_CIDRS)
_AGENT = re.compile(r"agent[a-z0-9]{2,16}\Z")
_NETWORK = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\Z")
_IFACE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}\Z")
_UNSAFE_IFACE = re.compile(r"(?:lo(?:\d+)?|tun.*|tap.*|xfrm.*|ipsec.*|cs[0-9a-f]+|"
                           r"wg.*|veth.*|docker.*|virbr.*|sit.*|gre.*)\Z", re.I)
_KINDS = frozenset(("physical", "ethernet", "wired", "vlan", "bridge",
                    "cellular", "wwan", "wifi", "wireless"))
_LAN_KINDS = frozenset(("physical", "ethernet", "wired", "vlan", "bridge"))


def _object(value, label, fields):
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    unknown = set(value) - set(fields)
    if unknown:
        raise ValueError(f"{label} has unsupported fields: {', '.join(sorted(map(str, unknown)))}")
    return value


def _text(value, label, pattern=None):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a nonempty string without surrounding spaces")
    if pattern and not pattern.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _iface(value, label):
    value = _text(value, label, _IFACE)
    if _UNSAFE_IFACE.fullmatch(value):
        raise ValueError(f"{label} cannot be a management tunnel or virtual overlay interface")
    return value


def _ipv4(value, label, lab_mode, blank=False):
    if blank and value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"{label} must be an IPv4 address") from exc
    if (address.is_unspecified or address.is_loopback or address.is_multicast
            or address.is_link_local or address.is_reserved
            or str(address) == "255.255.255.255"):
        raise ValueError(f"{label} must be a usable unicast IPv4 address")
    if any(address in network for network in _PROTECTED):
        raise ValueError(f"{label} overlaps a protected management or overlay range")
    if not lab_mode and not address.is_global:
        raise ValueError(f"{label} must be a public IPv4 address outside laboratory mode")
    return str(address)


def _observed_interfaces(record, site_name):
    interfaces = record.get("interfaces")
    if not isinstance(interfaces, list):
        raise ValueError(f"{site_name}: live interface inventory is unavailable")
    rows = {}
    for row in interfaces:
        if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
            raise ValueError(f"{site_name}: live interface inventory is invalid")
        if row["name"] in rows:
            raise ValueError(f"{site_name}: live interface inventory contains duplicate names")
        rows[row["name"]] = row
    return rows


def _check_observed(iface, rows, site_name, lan=False):
    row = rows.get(iface)
    if row is None or row.get("present") is False:
        raise ValueError(f"{site_name}: interface {iface} is not present on this agent")
    if row.get("kind") not in (_LAN_KINDS if lan else _KINDS):
        raise ValueError(f"{site_name}: interface {iface} has an unsupported role/type")
    if row.get("busy") or row.get("master"):
        raise ValueError(f"{site_name}: interface {iface} is owned by another bridge or feature")
    if not lan:
        if row.get("kind") in ("wifi", "wireless") and row.get("wifi_mode") not in ("infrastructure", "station"):
            raise ValueError(f"{site_name}: Wi-Fi uplink {iface} must be connected as a client")
        if row.get("uplink_eligible") is False:
            raise ValueError(f"{site_name}: uplink {iface} is unavailable: " +
                             str(row.get("uplink_reason") or "unsupported interface role"))
    return row


def _connected_network(row):
    address = row.get("ip")
    prefix = row.get("prefix", row.get("mask"))
    if address and "/" in str(address):
        value = str(address)
    elif address and prefix is not None:
        value = f"{address}/{prefix}"
    else:
        return None
    try:
        return ipaddress.IPv4Interface(value).network
    except (ValueError, TypeError):
        raise ValueError("Live uplink address/prefix inventory is invalid") from None


def _integer(value, label, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _private_address(value, label):
    value = _ipv4(value, label, True)
    if not any(ipaddress.IPv4Address(value) in n for n in _PRIVATE):
        raise ValueError(f"{label} must be an RFC1918 private address")
    return value


def _router_id(value, label):
    # A router ID identifies a protocol instance; it need not be an assigned
    # private address and does not create a route to this value.
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a nonzero unicast IPv4 identifier")
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(f"{label} must be a nonzero unicast IPv4 identifier") from None
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError(f"{label} must be a nonzero unicast IPv4 identifier")
    return str(address)


def _routing_prefixes(values, label, allowed):
    if not isinstance(values, list) or len(values) > MAX_PREFIXES_PER_SITE:
        raise ValueError(f"{label} must contain up to {MAX_PREFIXES_PER_SITE} exact authorized prefixes")
    if any(not isinstance(p, str) or p not in allowed for p in values):
        raise ValueError(f"{label} must use exact authorized site prefixes")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} contains duplicate prefixes")
    return sorted(values)


def validate_site_routing(value, site, all_prefixes=None, rows=None):
    """Canonical LAN routing; every import belongs to this site's authorized ranges.

    Live inventory, when supplied, additionally proves next hops and peers are
    usable on the explicitly selected LAN. The privileged runtime repeats that
    proof from kernel addresses rather than trusting the portal's inventory.
    """
    name, lans, owned = site["name"], site["lan_interfaces"], site["prefixes"]
    allowed = owned if all_prefixes is None else all_prefixes
    value = _object(value, f"{name} routing", ("static_routes", "ospf", "bgp"))
    result = {}

    def lan(value):
        iface = _iface(value, f"{name} routing LAN interface")
        if iface not in lans:
            raise ValueError(f"{name}: routing interface must be a selected LAN interface")
        return iface

    def connected(address, iface):
        if rows is None:
            return
        row = _check_observed(iface, rows, name, lan=True)
        network = _connected_network(row)
        if network is None or ipaddress.IPv4Address(address) not in network:
            raise ValueError(f"{name}: next hop or peer must be directly connected on {iface}")
        try:
            own = ipaddress.ip_interface(str(row.get("ip")) +
                                        ("" if "/" in str(row.get("ip")) else "/" + str(row.get("prefix", row.get("mask"))))).ip
        except ValueError:
            raise ValueError(f"{name}: selected LAN address is unavailable") from None
        if ipaddress.ip_address(address) in (own, network.network_address, network.broadcast_address):
            raise ValueError(f"{name}: next hop or peer must be another usable LAN host")

    if "static_routes" in value:
        raw = value["static_routes"]
        if not isinstance(raw, list) or len(raw) > MAX_PREFIXES_PER_SITE:
            raise ValueError(f"{name}: static routes must contain up to {MAX_PREFIXES_PER_SITE} entries")
        routes, seen = [], set()
        for route in raw:
            route = _object(route, f"{name} static route", ("prefix", "next_hop", "interface", "metric"))
            prefix = _routing_prefixes([route.get("prefix")], f"{name} static route", owned)[0]
            if prefix in seen:
                raise ValueError(f"{name}: duplicate static route prefix")
            seen.add(prefix)
            iface = lan(route.get("interface"))
            next_hop = _private_address(route.get("next_hop"), f"{name} static next hop")
            if ipaddress.ip_address(next_hop) in ipaddress.ip_network(prefix):
                raise ValueError(f"{name}: static next hop cannot be inside its routed destination")
            connected(next_hop, iface)
            routes.append({"prefix": prefix, "next_hop": next_hop, "interface": iface,
                           "metric": _integer(route.get("metric", 100), f"{name} static metric", 0, 65535)})
        result["static_routes"] = sorted(routes, key=lambda r: r["prefix"])

    for protocol in ("ospf", "bgp"):
        if protocol not in value:
            continue
        fields = (("enabled", "router_id", "interfaces", "import_prefixes", "export_prefixes") if protocol == "ospf"
                  else ("enabled", "local_asn", "router_id", "peers"))
        raw = _object(value[protocol], f"{name} {protocol}", fields)
        enabled = raw.get("enabled")
        if type(enabled) is not bool:
            raise ValueError(f"{name}: {protocol} enabled must be a boolean")
        if not enabled:
            if set(raw) != {"enabled"}:
                raise ValueError(f"{name}: disabled {protocol} must omit its configuration")
            result[protocol] = {"enabled": False}
            continue
        router_id = _router_id(raw.get("router_id"), f"{name} {protocol} router ID")
        if protocol == "ospf":
            interfaces = raw.get("interfaces")
            if not isinstance(interfaces, list) or not 1 <= len(interfaces) <= 8:
                raise ValueError(f"{name}: OSPF requires one to eight LAN interfaces")
            imports = _routing_prefixes(raw.get("import_prefixes"), f"{name} OSPF import", owned)
            exports = _routing_prefixes(raw.get("export_prefixes"), f"{name} OSPF export", allowed)
            entries, seen = [], set()
            for entry in interfaces:
                entry = _object(entry, f"{name} OSPF interface", ("interface", "area", "cost", "passive"))
                iface = lan(entry.get("interface"))
                if iface in seen:
                    raise ValueError(f"{name}: duplicate OSPF interface")
                seen.add(iface)
                if rows is not None:
                    network = _connected_network(_check_observed(iface, rows, name, lan=True))
                    if network is None or str(network) not in owned or str(network) not in exports:
                        raise ValueError(f"{name}: OSPF connected LAN subnet must be an exact site and export prefix")
                try:
                    area = str(ipaddress.IPv4Address(entry.get("area")))
                except (ValueError, TypeError):
                    raise ValueError(f"{name}: OSPF area must be a dotted IPv4 area identifier") from None
                if not isinstance(entry.get("area"), str) or type(entry.get("passive")) is not bool:
                    raise ValueError(f"{name}: OSPF area and passive flag are invalid")
                entries.append({"interface": iface, "area": area,
                                "cost": _integer(entry.get("cost"), f"{name} OSPF cost", 1, 65535),
                                "passive": entry["passive"]})
            result[protocol] = {"enabled": True, "router_id": router_id,
                                "interfaces": sorted(entries, key=lambda e: e["interface"]),
                                "import_prefixes": imports, "export_prefixes": exports}
        else:
            local_asn = _integer(raw.get("local_asn"), f"{name} local ASN", 1, 4294967294)
            peers = raw.get("peers")
            if not isinstance(peers, list) or not 1 <= len(peers) <= 16:
                raise ValueError(f"{name}: BGP requires one to sixteen LAN peers")
            entries, seen = [], set()
            for peer in peers:
                peer = _object(peer, f"{name} BGP peer", ("address", "interface", "remote_asn", "session_type",
                                                       "import_prefixes", "export_prefixes", "local_preference", "weight", "as_path_prepend"))
                iface = lan(peer.get("interface"))
                address = _private_address(peer.get("address"), f"{name} BGP peer address")
                if address in seen:
                    raise ValueError(f"{name}: duplicate BGP peer address")
                seen.add(address)
                connected(address, iface)
                remote_asn = _integer(peer.get("remote_asn"), f"{name} remote ASN", 1, 4294967294)
                kind = peer.get("session_type")
                if kind not in ("ibgp", "ebgp") or (kind == "ibgp") != (local_asn == remote_asn):
                    raise ValueError(f"{name}: iBGP requires equal ASNs and eBGP requires different ASNs")
                prepend = _integer(peer.get("as_path_prepend", 0), f"{name} AS-path prepend count", 0, 10)
                if kind == "ibgp" and prepend:
                    raise ValueError(f"{name}: AS-path prepending requires an eBGP peer")
                entries.append({"address": address, "interface": iface, "remote_asn": remote_asn,
                                "session_type": kind,
                                "import_prefixes": _routing_prefixes(peer.get("import_prefixes"), f"{name} BGP import", owned),
                                "export_prefixes": _routing_prefixes(peer.get("export_prefixes"), f"{name} BGP export", allowed),
                                "local_preference": _integer(peer.get("local_preference", 100), f"{name} local preference", 0, 4294967295),
                                "weight": _integer(peer.get("weight", 0), f"{name} BGP weight", 0, 65535),
                                "as_path_prepend": prepend})
            result[protocol] = {"enabled": True, "router_id": router_id, "local_asn": local_asn,
                                "peers": sorted(entries, key=lambda e: int(ipaddress.ip_address(e["address"])))}
    return result


def validate_config(config, inventory=None, lab_mode=False, *, allow_lanless_hub=False):
    """Return canonical desired state, or raise a useful ``ValueError``.

    Inventory is authoritative, keyed by agent name, with model and observed
    interfaces. Access/ownership and one-network-per-agent are portal concerns;
    passing an access-filtered inventory also prevents selecting unseen agents.
    Laboratory mode relaxes hardware eligibility and public endpoint requirements
    only; route isolation, prefix filters and shape validation remain mandatory.
    """
    config = _object(config, "OVERLAY configuration", ("name", "topology", "transport", "hub", "sites", "internet_gateway"))
    if type(lab_mode) is not bool:
        raise ValueError("Laboratory mode must be a server-controlled boolean")
    if inventory is not None and not isinstance(inventory, Mapping):
        raise ValueError("Agent inventory must be an object")
    name = _text(config.get("name"), "Network name")
    if len(name) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("Network name must contain 1–80 printable characters")
    topology = config.get("topology")
    if topology not in ("hub_spoke", "full_mesh"):
        raise ValueError("Topology must be hub_spoke or full_mesh")
    internet_gateway = config.get("internet_gateway", False)
    if type(internet_gateway) is not bool:
        raise ValueError("Internet Gateway must be a boolean")
    if internet_gateway and topology != "hub_spoke":
        raise ValueError("Internet Gateway requires a hub-and-spoke topology")
    transport = config.get("transport", "ipsec")
    if transport not in ("ipsec", "tls"):
        raise ValueError("Transport must be ipsec or tls")
    raw_sites = config.get("sites")
    maximum = MAX_MESH_SITES if topology == "full_mesh" else MAX_HUB_SITES
    if not isinstance(raw_sites, list) or not 2 <= len(raw_sites) <= maximum:
        raise ValueError(f"{topology} requires 2–{maximum} sites")
    all_prefixes, names, sites, all_endpoints, wan_networks = [], set(), [], [], []
    routing_values, routing_inventory = {}, {}
    for raw in raw_sites:
        raw = _object(raw, "Site", ("name", "mode", "uplinks", "lan_interfaces", "prefixes", "routing"))
        site_name = _text(raw.get("name"), "Agent name", _AGENT)
        if site_name in names:
            raise ValueError(f"Agent {site_name} was selected more than once")
        names.add(site_name)
        mode = raw.get("mode")
        if mode not in ("active_passive", "active_active"):
            raise ValueError(f"{site_name}: uplink mode must be active_passive or active_active")
        rows = None
        if inventory is not None:
            record = inventory.get(site_name)
            if not isinstance(record, Mapping):
                raise ValueError(f"{site_name}: agent is outside the available inventory")
            if not lab_mode and record.get("model") not in PRODUCTION_MODELS:
                raise ValueError(f"{site_name}: production OVERLAY requires Pi 5 4G or Pi 5 4G LAN")
            rows = _observed_interfaces(record, site_name)
        raw_uplinks = raw.get("uplinks")
        if not isinstance(raw_uplinks, list) or not 1 <= len(raw_uplinks) <= 2:
            raise ValueError(f"{site_name}: select one or two uplink interfaces")
        uplinks, selected, priorities, endpoints = [], set(), set(), set()
        for up in raw_uplinks:
            up = _object(up, f"{site_name} uplink", ("iface", "endpoint", "priority"))
            iface = _iface(up.get("iface"), f"{site_name} uplink interface")
            if iface in selected:
                raise ValueError(f"{site_name}: uplink interface {iface} is duplicated")
            selected.add(iface)
            priority = up.get("priority")
            if type(priority) is not int or priority not in (1, 2):
                raise ValueError(f"{site_name}: uplink priority must be 1 or 2")
            if priority in priorities:
                raise ValueError(f"{site_name}: uplink order must use distinct priorities")
            priorities.add(priority)
            endpoint = _ipv4(up.get("endpoint", ""), f"{site_name}/{iface} endpoint", lab_mode, blank=True)
            if endpoint:
                if endpoint in endpoints:
                    raise ValueError(f"{site_name}: uplinks must use distinct reachable IPv4 endpoints")
                endpoints.add(endpoint)
                all_endpoints.append((site_name, iface, ipaddress.IPv4Address(endpoint)))
            if rows is not None:
                row = _check_observed(iface, rows, site_name)
                network = _connected_network(row)
                if network:
                    wan_networks.append((site_name, iface, network))
            uplinks.append({"iface": iface, "endpoint": endpoint, "priority": priority})
        if priorities != set(range(1, len(uplinks) + 1)):
            raise ValueError(f"{site_name}: order uplinks starting with priority 1")
        lanless_hub = allow_lanless_hub and topology == "hub_spoke" and site_name == config.get("hub")
        lans = raw.get("lan_interfaces")
        if not isinstance(lans, list) or not (0 if lanless_hub else 1) <= len(lans) <= 8:
            raise ValueError(f"{site_name}: select one to eight internal LAN interfaces")
        lan_interfaces = []
        for value in lans:
            iface = _iface(value, f"{site_name} LAN interface")
            if iface in selected or iface in lan_interfaces:
                raise ValueError(f"{site_name}: uplink and LAN interfaces must be distinct and unique")
            if rows is not None:
                _check_observed(iface, rows, site_name, lan=True)
            lan_interfaces.append(iface)
        # A VLAN is a distinct L3 interface. A bridge and its physical members
        # are not distinct paths: using them on opposite sides bypasses isolation.
        if rows is not None:
            for iface in selected:
                members = set(rows[iface].get("members") or [])
                if members.intersection(lan_interfaces):
                    raise ValueError(f"{site_name}: LAN interfaces overlap uplink bridge members")
            for iface in lan_interfaces:
                if set(rows[iface].get("members") or []).intersection(selected):
                    raise ValueError(f"{site_name}: uplinks overlap LAN bridge members")
        raw_prefixes = raw.get("prefixes")
        if not isinstance(raw_prefixes, list) or not (0 if lanless_hub else 1) <= len(raw_prefixes) <= MAX_PREFIXES_PER_SITE:
            raise ValueError(f"{site_name}: advertise 1–{MAX_PREFIXES_PER_SITE} private IPv4 prefixes")
        if lanless_hub and bool(lans) != bool(raw_prefixes):
            raise ValueError(f"{site_name}: an unused hub LAN must have no advertised prefixes")
        prefixes = []
        for value in raw_prefixes:
            if not isinstance(value, str) or "/" not in value:
                raise ValueError(f"{site_name}: every prefix must be an IPv4 network CIDR")
            try:
                network = ipaddress.IPv4Network(value, strict=True)
            except ValueError as exc:
                raise ValueError(f"{site_name}: {value!r} must be a network CIDR without host bits") from exc
            if not any(network.subnet_of(private) for private in _PRIVATE):
                raise ValueError(f"{site_name}: {network} must be an RFC1918 private prefix; defaults are forbidden")
            if any(network.overlaps(protected) for protected in _PROTECTED):
                raise ValueError(f"{site_name}: {network} overlaps a protected management or overlay range")
            for owner, previous in all_prefixes:
                if network.overlaps(previous):
                    raise ValueError(f"{site_name}: {network} overlaps {owner}'s {previous}")
            all_prefixes.append((site_name, network))
            prefixes.append(str(network))
        sites.append({"name": site_name, "mode": mode,
                      "uplinks": sorted(uplinks, key=lambda up: (up["priority"], up["iface"])),
                      "lan_interfaces": sorted(lan_interfaces),
                      "prefixes": sorted(prefixes, key=lambda p: (int(ipaddress.ip_network(p).network_address),
                                                                  ipaddress.ip_network(p).prefixlen))})
        if "routing" in raw:
            routing_values[site_name], routing_inventory[site_name] = raw["routing"], rows
    authorized_prefixes = [str(prefix) for _owner, prefix in all_prefixes]
    for site in sites:
        if site["name"] in routing_values:
            site["routing"] = validate_site_routing(routing_values[site["name"]], site,
                                                    authorized_prefixes, routing_inventory[site["name"]])
    for owner, prefix in all_prefixes:
        for wan_owner, iface, network in wan_networks:
            if prefix.overlaps(network):
                raise ValueError(f"{owner}: {prefix} overlaps {wan_owner}/{iface}'s uplink subnet {network}")
        for wan_owner, iface, endpoint in all_endpoints:
            if endpoint in prefix:
                raise ValueError(f"{owner}: {prefix} includes {wan_owner}/{iface}'s WAN endpoint")
    hub = config.get("hub") or None
    if topology == "hub_spoke":
        if not isinstance(hub, str) or hub not in names:
            raise ValueError("Select one participating agent as the hub")
    elif hub is not None:
        raise ValueError("A full mesh has no hub; clear the hub selection")
    canonical = {"name": name, "topology": topology, "hub": hub,
                 "sites": sorted(sites, key=lambda site: site["name"])}
    # Preserve existing draft hashes and boot requests that predate transport.
    if "transport" in config:
        canonical["transport"] = transport
    # Old saved revisions omit this opt-in; retain their exact request hashes.
    if "internet_gateway" in config:
        canonical["internet_gateway"] = internet_gateway
    return canonical


def _prefix_list(name, prefixes):
    return [f"ip prefix-list {name} seq {5 * (i + 1)} permit {prefix}"
            for i, prefix in enumerate(prefixes)] + [f"ip prefix-list {name} seq 65535 deny 0.0.0.0/0 le 32"]


def _render_frr(site, asn):
    lines = ["! Generated Parto OVERLAY; exact authorized routes only",
             "frr defaults traditional", f"hostname {site['name']}-overlay", "!",
             f"router bgp {asn}", f" bgp router-id {site['router_id']}",
             " bgp network import-check", " no bgp default ipv4-unicast"]
    if site["role"] == "hub":
        lines.append(f" bgp cluster-id {site['router_id']}")
    routing = site.get("routing", {})
    bgp, ospf = routing.get("bgp", {}), routing.get("ospf", {})
    gateway = site.get("internet_gateway", {})
    gateway_hub = gateway.get("role") == "hub"
    for tunnel in site["tunnels"]:
        peer = tunnel["peer_address"]
        source = tunnel["local_address"].split("/")[0]
        lines.extend((f" neighbor {peer} remote-as {tunnel.get('peer_asn', asn)}",
                      f" neighbor {peer} description {tunnel['peer']}:{tunnel['peer_uplink']}",
                      f" neighbor {peer} update-source {source}",
                      f" neighbor {peer} timers 10 30"))
    if bgp.get("enabled"):
        for peer in bgp["peers"]:
            address = peer["address"]
            lines.extend((f" neighbor {address} remote-as {peer['remote_asn']}",
                          f" neighbor {address} description LAN:{peer['interface']}",
                          f" neighbor {address} update-source {peer['interface']}",
                          f" neighbor {address} timers 10 30"))
    lines.append(" address-family ipv4 unicast")
    # Runtime must verify these exact routes exist through selected LAN ports;
    # import-check withdraws them when their backing route disappears.
    dynamic = set(ospf.get("import_prefixes", []))
    for peer in bgp.get("peers", []):
        dynamic.update(peer["import_prefixes"])
    # LAN BGP routes must retain their selected path/attributes rather than
    # being replaced by self-originated `network` routes. OSPF routes enter BGP
    # through exact, selected-LAN redistribution. Connected/static site ranges
    # retain import-check, and an absent future dynamic range stays withdrawn.
    lines.extend(f"  network {prefix}" for prefix in site["prefixes"] if prefix not in dynamic)
    if dynamic:
        lines.append("  redistribute connected route-map LANOWN")
        if not gateway_hub:
            lines.append("  redistribute kernel route-map LANOWN")
        if ospf.get("enabled"):
            lines.append("  redistribute ospf route-map LANOSPFTOBGP")
    if gateway_hub:
        # Origination is conditional on a main-table kernel default whose
        # next hop is on a selected WAN. LAN/overlay imports never authorize
        # a default and a missing backing WAN route withdraws this candidate.
        lines.append("  redistribute kernel route-map CSGWKERNEL")
    lines.append(f"  maximum-paths ibgp {4 if site['mode'] == 'active_active' else 1}")
    if any(t.get("peer_asn", asn) != asn for t in site["tunnels"]):
        lines.append(f"  maximum-paths {4 if site['mode'] == 'active_active' else 1}")
    for tunnel in site["tunnels"]:
        peer, tag = tunnel["peer_address"], f"SD{tunnel['if_id']}"
        lines.extend((f"  neighbor {peer} activate", f"  neighbor {peer} route-map {tag}IN in",
                      f"  neighbor {peer} prefix-list {tag}OUT out",
                      f"  neighbor {peer} maximum-prefix {len(tunnel['accepted_prefixes'])}"))
        if gateway_hub:
            lines.append(f"  neighbor {peer} default-originate route-map CSGWORIGIN")
        if tunnel.get("peer_asn", asn) != asn:
            # LAN ASNs may repeat at different sites. Rewrite an overlay
            # neighbor's ASN when transiting another site's exact owned range.
            # LAN peer paths retain ordinary AS-loop protection.
            lines.extend((f"  neighbor {peer} as-override", f"  neighbor {peer} next-hop-self force"))
        elif site["role"] == "hub":
            lines.extend((f"  neighbor {peer} route-reflector-client", f"  neighbor {peer} next-hop-self force"))
        else:
            lines.append(f"  neighbor {peer} next-hop-self")
    if bgp.get("enabled"):
        for i, peer in enumerate(bgp["peers"], 1):
            address, tag = peer["address"], f"LAN{i}"
            lines.extend((f"  neighbor {address} activate", f"  neighbor {address} route-map {tag}IN in",
                          f"  neighbor {address} route-map {tag}OUT out",
                          f"  neighbor {address} maximum-prefix {max(1, len(peer['import_prefixes']))}",
                          f"  neighbor {address} next-hop-self force"))
            if peer["session_type"] == "ibgp":
                # The appliance is the LAN client's reflector, permitting
                # LAN↔overlay iBGP propagation in both directions.
                lines.append(f"  neighbor {address} route-reflector-client")
    lines.extend((" exit-address-family", "!"))
    for tunnel in site["tunnels"]:
        tag = f"SD{tunnel['if_id']}"
        lines.extend(_prefix_list(f"{tag}IN", tunnel["accepted_prefixes"]))
        lines.extend(_prefix_list(f"{tag}OUT", tunnel["exported_prefixes"]))
        if gateway.get("role") == "spoke":
            # The received default has a separate kernel table. The device's
            # own WAN default, tunnel sockets and portal traffic remain local.
            lines.extend((f"route-map {tag}IN permit 5", " match ip address prefix-list CSGWDEFAULT",
                          f" set table {gateway['policy_table']}",
                          f" set local-preference {tunnel['local_preference']}"))
        lines.extend((f"route-map {tag}IN permit 10", f" match ip address prefix-list {tag}IN",
                      f" set local-preference {tunnel['local_preference']}",
                      f"route-map {tag}IN deny 100", "!"))
    if gateway:
        lines.extend(_prefix_list("CSGWDEFAULT", ["0.0.0.0/0"]))
    if gateway_hub:
        # FRR 8.4 matches a single interface per route-map entry, so separate
        # entries express either selected uplink without broadening the filter.
        for i, up in enumerate(site["uplinks"], 1):
            lines.extend((f"route-map CSGWKERNEL permit {i * 5}",
                          " match ip address prefix-list CSGWDEFAULT", f" match interface {up['iface']}"))
        if dynamic:
            for i, iface in enumerate(site["lan_interfaces"], 1):
                lines.extend((f"route-map CSGWKERNEL permit {100 + i * 5}",
                              " match ip address prefix-list LANOWN", f" match interface {iface}"))
        lines.extend(("route-map CSGWKERNEL deny 1000", "!", "route-map CSGWORIGIN permit 10",
                      " match ip address prefix-list CSGWDEFAULT", "route-map CSGWORIGIN deny 100", "!"))
    if bgp.get("enabled"):
        for i, peer in enumerate(bgp["peers"], 1):
            tag = f"LAN{i}"
            lines.extend(_prefix_list(tag + "IN", peer["import_prefixes"]))
            lines.extend(_prefix_list(tag + "OUT", peer["export_prefixes"]))
            lines.extend((f"route-map {tag}IN permit 10", f" match ip address prefix-list {tag}IN",
                          " set ip next-hop peer-address",
                          f" set local-preference {peer['local_preference']}", f" set weight {peer['weight']}",
                          f"route-map {tag}IN deny 100", f"route-map {tag}OUT permit 10",
                          f" match ip address prefix-list {tag}OUT"))
            if peer["as_path_prepend"]:
                lines.append(" set as-path prepend " + " ".join([str(asn)] * peer["as_path_prepend"]))
            lines.extend((f"route-map {tag}OUT deny 100", "!"))
    if dynamic:
        lines.extend(_prefix_list("LANOWN", sorted(dynamic)))
        lines.extend(("route-map LANOWN permit 10", " match ip address prefix-list LANOWN",
                      " match interface " + " ".join(site["lan_interfaces"]),
                      "route-map LANOWN deny 100", "!"))
        if ospf.get("enabled"):
            lines.extend(_prefix_list("LANOSPFTOBGP", ospf["import_prefixes"]))
            lines.extend(("route-map LANOSPFTOBGP permit 10", " match ip address prefix-list LANOSPFTOBGP",
                          " match interface " + " ".join(entry["interface"] for entry in ospf["interfaces"]),
                          "route-map LANOSPFTOBGP deny 100", "!"))
    lines.extend(("line vty", "!"))
    return "\n".join(lines) + "\n"


def render_ospfd(site):
    """LAN-only OSPF with exact route-install/import and redistribution bounds."""
    ospf = site.get("routing", {}).get("ospf", {})
    if not ospf.get("enabled"):
        return ""
    lines = ["! Generated Parto LAN OSPF", "frr defaults traditional",
             f"hostname {site['name']}-overlay", "!"]
    for entry in ospf["interfaces"]:
        lines.extend((f"interface {entry['interface']}", f" ip ospf area {entry['area']}",
                      f" ip ospf cost {entry['cost']}",
                      " ip ospf passive" if entry["passive"] else " no ip ospf passive", "!"))
    lines.extend(("router ospf", f" ospf router-id {ospf['router_id']}", " passive-interface default"))
    lines.extend((" redistribute bgp route-map LANOSPF-OUT",
                  " redistribute kernel route-map LANOSPF-OUT",
                  " redistribute connected route-map LANOSPF-OUT", "!"))
    lines.extend(_prefix_list("LANOSPF-OUT", ospf["export_prefixes"]))
    lines.extend(("route-map LANOSPF-OUT permit 10", " match ip address prefix-list LANOSPF-OUT",
                  "route-map LANOSPF-OUT deny 100", "!", "line vty", "!"))
    return "\n".join(lines) + "\n"


def render_zebra(site):
    """FRR 8.4 OSPF FIB policy lives in Zebra, not an IOS distribute-list."""
    lines = ["hostname console-overlay", "!"]
    ospf = site.get("routing", {}).get("ospf", {})
    if ospf.get("enabled"):
        lines.extend(_prefix_list("LANOSPF-IN", ospf["import_prefixes"]))
        lines.extend(("route-map LANOSPF-IN permit 10", " match ip address prefix-list LANOSPF-IN",
                      " match interface " + " ".join(entry["interface"] for entry in ospf["interfaces"]),
                      "route-map LANOSPF-IN deny 100", "!", "ip protocol ospf route-map LANOSPF-IN", "!"))
    return "\n".join(lines) + "\n"


def render_swanctl(site, local_sources=None):
    """Render IPsec from a compiled site; bind IKE to verified per-uplink IPs.

    Omit local_sources only for a reviewable template. Supplying sources refuses
    missing endpoints or unverified addresses instead of accepting wildcards.
    The runtime owns loading dedicated credentials; no secret bytes enter here.
    """
    lines = ["# Generated Parto OVERLAY; dedicated network trust only", "connections {"]
    for tunnel in site["tunnels"]:
        iface = tunnel["local_uplink"]
        source = f"__LOCAL_SOURCE_{iface}__"
        dynamic = bool(tunnel.get('dynamic_peer')) and not tunnel['initiator']
        endpoint = '%any' if dynamic else tunnel["remote_endpoint"] or "__REMOTE_ENDPOINT_REQUIRED__"
        if local_sources is not None:
            if not isinstance(local_sources, Mapping) or not local_sources.get(iface):
                raise ValueError(f"Missing verified local address for uplink {iface}")
            source = _ipv4(local_sources[iface], f"{iface} source address", True)
            if not tunnel["remote_endpoint"] and not dynamic:
                raise ValueError(f"Missing endpoint for {tunnel['peer']}/{tunnel['peer_uplink']}")
        lines.extend((f"  {tunnel['id']} {{", "    version = 2", f"    local_addrs = {source}",
                      f"    remote_addrs = {endpoint}", f"    proposals = {IKE_PROPOSAL}",
                      f"    mobike = {'yes' if tunnel.get('mobile_initiator') else 'no'}", "    encap = yes",
                      f"    unique = {'replace' if dynamic or tunnel.get('mobile_initiator') else 'never'}",
                      "    fragmentation = yes", "    keyingtries = 0", "    dpd_delay = 10s",
                      "    rekey_time = 4h", "    reauth_time = 24h", "    over_time = 30m",
                      "    local {", "      auth = pubkey", f"      id = {site['identity']}",
                      f"      certs = {site['pki_paths']['cert']}", "    }", "    remote {",
                      "      auth = pubkey", f"      id = {tunnel['peer_identity']}",
                      f"      cacerts = {site['pki_paths']['ca']}", "      revocation = strict", "    }",
                      "    children {", f"      {tunnel['id']}-data {{",
                      f"        local_ts = {', '.join(tunnel['local_ts'])}",
                      f"        remote_ts = {', '.join(tunnel['remote_ts'])}",
                      f"        esp_proposals = {ESP_PROPOSAL}",
                      f"        if_id_in = {tunnel['if_id']}", f"        if_id_out = {tunnel['if_id']}",
                      f"        set_mark_out = {tunnel['mark']}", "        mode = tunnel",
                      "        rekey_time = 50m", "        life_time = 60m", "        rand_time = 5m",
                      f"        dpd_action = {'clear' if dynamic else 'restart'}",
                      f"        close_action = {'start' if tunnel.get('persistent_initiator') and tunnel['initiator'] else 'none'}",
                      f"        start_action = {('trap|start' if tunnel.get('persistent_initiator') else 'start') if tunnel['initiator'] else 'none'}",
                      "      }", "    }", "  }"))
    lines.append("}")
    return "\n".join(lines) + "\n"


def _tls_material(site, paths=None):
    paths = paths or site["pki_paths"]
    # Only compiler-owned absolute paths can enter privileged daemon configs.
    for key in ("ca", "cert", "key", "crl"):
        value = paths.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or ".." in value.split("/"):
            raise ValueError("Invalid TLS credential path")
    return paths


def render_stunnel(site, local_sources=None, pki_paths=None):
    """One WAN-bound 443 listener per uplink, SNI dispatch to private p2p VPNs."""
    paths = _tls_material(site, pki_paths)
    lines = ["; Dedicated Parto OVERLAY", "foreground = yes", "pid =", "debug = warning"]
    listeners = {}
    for t in site["tunnels"]:
        iface, port = t["local_uplink"], 35000 + t["if_id"]
        source = "__LOCAL_SOURCE_%s__" % iface
        endpoint = t["remote_endpoint"] or "__REMOTE_ENDPOINT_REQUIRED__"
        if local_sources is not None:
            if not local_sources.get(iface) or (not t["remote_endpoint"] and not (t.get("dynamic_peer") and not t["initiator"])):
                raise ValueError("TLS requires verified source and peer endpoint")
            source = _ipv4(local_sources[iface], "TLS source", True)
        sni = t.get("transport_server_name") or "%s.%s.overlay.parto.invalid" % (t["id"], site["network_id"])
        lines += ["", "[%s]" % t["id"], "client = %s" % ("yes" if t["initiator"] else "no"),
                  "cert = " + paths["cert"], "key = " + paths["key"], "CAfile = " + paths["ca"],
                  "CRLfile = " + paths["crl"], "verifyChain = yes", "requireCert = yes",
                  "checkHost = " + t["peer_identity"], "sslVersionMin = TLSv1.3",
                  "ciphersuites = TLS_AES_256_GCM_SHA384", "TIMEOUTclose = 0"]
        if t["initiator"]:
            lines += ["accept = 127.0.0.1:%d" % port, "connect = " + ("127.0.0.1:3443" if t.get("obfs4") else "%s:443" % endpoint),
                      "local = " + ("127.0.0.1" if t.get("obfs4") else source), "sni = " + sni,
                      "socket = r:SO_BINDTODEVICE=" + ("lo" if t.get("obfs4") else iface), "socket = a:SO_BINDTODEVICE=lo"]
        else:
            lines += ["connect = 127.0.0.1:%d" % port, "socket = r:SO_BINDTODEVICE=lo"]
            if iface not in listeners:
                listeners[iface] = t["id"]
                lines += ["accept = " + ("127.0.0.1:4443" if t.get("obfs4") else "%s:443" % source), "socket = a:SO_BINDTODEVICE=" + ("lo" if t.get("obfs4") else iface)]
            else:
                lines += ["sni = %s:%s" % (listeners[iface], sni)]
    return "\n".join(lines) + "\n"


def render_openvpn(site, pki_paths=None, mtus=None):
    """TLS-mode point-to-point TUN; all addresses/routes are helper-owned."""
    paths = _tls_material(site, pki_paths)
    configs = {}
    for t in site["tunnels"]:
        port = 35000 + t["if_id"]
        instance = "%s--%s" % (site["network_id"], t["id"])
        lines = ["# Dedicated Parto OVERLAY", "dev " + t["if_name"], "dev-type tun", "topology p2p",
                 "ifconfig %s %s" % (t["local_address"].split("/")[0], t["peer_address"]),
                 "ifconfig-noexec", "route-noexec", "script-security 0", "persist-key", "persist-tun",
                 "tun-mtu %d" % (mtus or {}).get(t["local_uplink"], 1400),
                 "ca " + paths["ca"], "cert " + paths["cert"], "key " + paths["key"],
                 "crl-verify " + paths["crl"], "tls-version-min 1.3", "tls-version-max 1.3",
                 "tls-ciphersuites TLS_AES_256_GCM_SHA384", "data-ciphers AES-256-GCM",
                 "data-ciphers-fallback AES-256-GCM", "cipher AES-256-GCM", "allow-compression no",
                 "remote-cert-ku 80", 'remote-cert-eku "TLS Web %s Authentication"' % ("Server" if t["initiator"] else "Client"),
                 "verify-x509-name %s name" % t.get("peer_cert_cn", t["peer"]), "reneg-sec 3600", "ping 10", "ping-restart 30",
                 "tmp-dir /run/console-overlay-tls/%s" % instance,
                 "management /run/console-overlay-tls/%s/management.sock unix" % instance,
                 "management-client-user root", "management-client-group root",
                 "verb 3"]
        if t["initiator"]:
            lines += ["tls-client", "proto tcp-client", "remote 127.0.0.1 %d" % port, "nobind", "connect-retry 3 10"]
        else:
            lines += ["tls-server", "dh none", "proto tcp-server", "local 127.0.0.1", "port %d" % port]
        configs[t["id"]] = "\n".join(lines) + "\n"
    return configs


STRONGSWAN_CONFIG = """# Dedicated daemon configuration; routing belongs to the OVERLAY runtime
charon {
  install_routes = no
  install_virtual_ip = no
  plugins {
    kernel-netlink {
      install_routes_xfrmi = no
    }
  }
}
"""


def compile_plan(config, network_id, *, allow_lanless_hub=False):
    """Compile canonical desired state into a bounded reproducible topology.

    Structural validation is repeated, with laboratory endpoint syntax allowed.
    Callers separately enforce authorization, hardware mode and live inventory.
    No plan constitutes permission or evidence of safe deployment.
    """
    config = validate_config(config, lab_mode=True, allow_lanless_hub=allow_lanless_hub)
    network_id = _text(network_id, "Network identifier", _NETWORK)
    transport = config.get("transport", "ipsec")
    digest = hashlib.sha256(network_id.encode("ascii")).hexdigest()
    asn = 4200000000 + int(digest[:8], 16) % 94967294
    prefix_by_site = {site["name"]: site["prefixes"] for site in config["sites"]}
    all_prefixes = sorted(itertools.chain.from_iterable(prefix_by_site.values()))
    internet_gateway = config.get("internet_gateway", False)
    gateway_prefixes = sorted(p for name, prefixes in prefix_by_site.items()
                              if name != config["hub"] for p in prefixes)
    gateway_table = 51000 + int(digest[:4], 16) % 8000
    sites = {}
    blockers = []
    for i, desired in enumerate(config["sites"], 1):
        name = desired["name"]
        role = "mesh" if config["topology"] == "full_mesh" else ("hub" if name == config["hub"] else "spoke")
        pki_root = f"/etc/parto/overlay/pki/{network_id}"
        site = deepcopy(desired)
        site.update({"transport": transport, "network_id": network_id, "role": role, "identity": f"{name}.{network_id}.overlay.parto.invalid",
                     "router_id": f"10.254.255.{i}", "tunnels": [],
                     "pki_paths": {"ca": f"{pki_root}/ca.pem", "cert": f"{pki_root}/cert.pem",
                                   "key": f"{pki_root}/key.pem", "crl": f"{pki_root}/crl.pem", "authorization": f"{pki_root}/authorization.json"}})
        bgp = desired.get("routing", {}).get("bgp", {})
        if bgp.get("enabled"):
            site["router_id"] = bgp["router_id"]
        site["effective_asn"] = bgp["local_asn"] if bgp.get("enabled") else asn
        if internet_gateway:
            site["internet_gateway"] = {"role": role, "hub": config["hub"],
                                        "spoke_prefixes": gateway_prefixes,
                                        "default_prefix": "0.0.0.0/0", "policy_table": gateway_table}
        sites[name] = site
        for up in site["uplinks"]:
            if not up["endpoint"]:
                blockers.append(f"{name}/{up['iface']}: reachable IPv4 endpoint is required")
    if len({site["router_id"] for site in sites.values()}) != len(sites):
        raise ValueError("BGP router IDs must be unique within this OVERLAY network")
    if config["topology"] == "full_mesh":
        pairs = list(itertools.combinations(sorted(sites), 2))
    else:
        pairs = sorted(tuple(sorted((config["hub"], name))) for name in sites if name != config["hub"])
    links = []
    overlay_start = int(ipaddress.ip_network(OVERLAY_CIDR).network_address)
    for left, right in pairs:
        for left_up, right_up in itertools.product(sites[left]["uplinks"], sites[right]["uplinks"]):
            ordinal = len(links)
            if_id = 1000 + ordinal
            link_id = f"sd{digest[:6]}{if_id:04x}"
            addresses = [str(ipaddress.IPv4Address(overlay_start + 2 * ordinal + offset)) for offset in (0, 1)]
            link = {"id": link_id, "if_id": if_id, "subnet": f"{addresses[0]}/31",
                    "a": {"site": left, "uplink": left_up["iface"], "endpoint": left_up["endpoint"],
                          "address": addresses[0]},
                    "b": {"site": right, "uplink": right_up["iface"], "endpoint": right_up["endpoint"],
                          "address": addresses[1]}}
            links.append(link)
            for own, peer, own_up, peer_up, local_address, peer_address in (
                    (left, right, left_up, right_up, addresses[0], addresses[1]),
                    (right, left, right_up, left_up, addresses[1], addresses[0])):
                site = sites[own]
                if site["role"] == "hub":
                    accepted = list(prefix_by_site[peer])
                    exported = [p for name, prefixes in prefix_by_site.items() if name != peer for p in prefixes]
                    local_data, remote_data = exported, accepted
                elif site["role"] == "spoke":
                    accepted = [p for name, prefixes in prefix_by_site.items() if name != own for p in prefixes]
                    exported = list(prefix_by_site[own])
                    local_data, remote_data = exported, accepted
                else:
                    accepted, exported = list(prefix_by_site[peer]), list(prefix_by_site[own])
                    local_data, remote_data = exported, accepted
                if internet_gateway:
                    if site["role"] == "hub":
                        exported = exported + ["0.0.0.0/0"]
                        local_data = ["0.0.0.0/0"]
                    else:
                        accepted = accepted + ["0.0.0.0/0"]
                        remote_data = ["0.0.0.0/0"]
                local_penalty = own_up["priority"] - 1 if site["mode"] == "active_passive" else 0
                peer_penalty = peer_up["priority"] - 1 if sites[peer]["mode"] == "active_passive" else 0
                site["tunnels"].append({"id": link_id, "if_name": f"cs{digest[:6]}{if_id:04x}",
                    "if_id": if_id, "mark": 0xCA000000 + if_id, "table": 40000 + if_id,
                    "local_address": f"{local_address}/31", "peer_address": peer_address,
                    "local_uplink": own_up["iface"], "peer_uplink": peer_up["iface"], "peer": peer,
                    "local_endpoint": own_up["endpoint"], "remote_endpoint": peer_up["endpoint"],
                    "local_priority": own_up["priority"], "peer_priority": peer_up["priority"],
                    "local_preference": 300 - 100 * local_penalty - 10 * peer_penalty,
                    "peer_identity": sites[peer]["identity"],
                    "initiator": site["role"] == "spoke" if config["topology"] == "hub_spoke" else own < peer,
                    "accepted_prefixes": sorted(accepted), "exported_prefixes": sorted(exported),
                    "local_ts": [f"{local_address}/32"] + sorted(local_data),
                    "remote_ts": [f"{peer_address}/32"] + sorted(remote_data)})
                if any(s.get("routing", {}).get("bgp", {}).get("enabled") for s in sites.values()):
                    site["tunnels"][-1]["peer_asn"] = sites[peer]["effective_asn"]
    for name, site in sites.items():
        remote_prefixes = [p for owner, prefixes in prefix_by_site.items() if owner != name for p in prefixes]
        site["frr_config"] = _render_frr(site, site["effective_asn"])
        if site.get("routing", {}).get("ospf", {}).get("enabled"):
            site["ospfd_config"] = render_ospfd(site)
            site["zebra_config"] = render_zebra(site)
        if transport == "ipsec":
            site["swanctl_config"] = render_swanctl(site)
            site["strongswan_config"] = STRONGSWAN_CONFIG
        else:
            site["stunnel_config"] = render_stunnel(site)
            site["openvpn_configs"] = render_openvpn(site)
        site["listen_addresses"] = [t["local_address"].split("/")[0] for t in site["tunnels"]]
        site["forwarding"] = {"local_prefixes": site["prefixes"], "remote_prefixes": sorted(remote_prefixes),
                              "allowed_prefixes": all_prefixes, "transit": site["role"] == "hub",
                              "fail_closed": True, "nat": False,
                              "uplink_forwarding": False, "bgp_port": 179, "tunnel_mtu": 1400}
        if internet_gateway:
            site["forwarding"].update(internet_gateway=deepcopy(site["internet_gateway"]),
                                      nat=site["role"] == "hub", uplink_forwarding=site["role"] == "hub")
    return {"schema_version": SCHEMA_VERSION, "network_id": network_id, "name": config["name"],
            "topology": config["topology"], "transport": transport, "hub": config["hub"], "asn": asn,
            "internet_gateway": internet_gateway,
            "overlay_cidr": OVERLAY_CIDR, "sites": sites, "links": links,
            "summary": {"sites": len(sites), "site_pairs": len(pairs), "tunnels": len(links),
                        "bgp_sessions": len(links), "ready": not blockers,
                        "ready_for_preflight": not blockers, "deployment_ready": False,
                        "blockers": blockers,
                        "notes": [("Public reachability and UDP 500/4500 must be verified; NAT-T cannot make two CGNAT-only sites directly reachable." if transport == "ipsec" else
                                  "Reachable TCP 443 endpoints are required; TLS does not create inbound reachability through CGNAT."),
                                  "LAN return routes, dedicated network PKI/revocation and isolated underlay policy routing require runtime preflight.",
                                  "Hub-and-spoke direct spoke shortcuts are deferred; traffic transits the hub."]}}
