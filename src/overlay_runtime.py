#!/usr/bin/env python3
"""Device OVERLAY runtime. Root mutations run only from the immutable helper copy.

The JSON stdin contract is {network_id, config, tenant, registration_id}. There
are no command, path, script or certificate fields accepted from a caller.
Neither an approved plan nor successful apply is evidence of established SAs.
"""
from __future__ import annotations

import contextlib
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import socket
import stat
import subprocess
import sys
import tempfile
import time

import overlay

STATE_ROOT = Path("/var/lib/parto-overlay")
PKI_ROOT = Path("/etc/parto/overlay/pki")
MIGRATION = Path("/etc/parto/overlay/migration.json")
UPGRADE_HOLD = Path("/var/lib/parto-overlay-upgrades/active.json")
DEVICE_DETAIL = Path("/etc/parto/device.json")
MANIFEST = Path("/home/overlay/BootScript/manifest.json")
HELPER_ROOT = Path("/usr/local/lib/parto-overlay")
NETLAYER_LOCK = Path("/run/lock/parto-netlayer.lock")
IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"
NMCLI = "/usr/bin/nmcli"
SYSTEMCTL = "/usr/bin/systemctl"
SWANCTL = "/usr/sbin/swanctl"
OPENSSL = "/usr/bin/openssl"
VTYSH = "/usr/bin/vtysh"
OPENVPN = "/usr/sbin/openvpn"
STUNNEL = "/usr/bin/stunnel4"
TLS_RUN = Path("/run/console-overlay-tls")
RESERVED = ("192.168.4.0/24", "192.168.50.0/24", "192.168.51.0/24")
NETWORK_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
DEVICE_RE = re.compile(r"^agent[0-9]{2,5}$")
MAX_INPUT = 256 * 1024
MAX_OUTPUT = 1024 * 1024
# 196 is FRR staticd's protocol and may be replayed at static distance 1.
# A private kernel marker plus distance 255 in the metric high byte keeps the
# fail-closed guard below usable BGP routes in both Zebra and Linux.
ROUTE_PROTOCOL = "242"
GUARD_METRIC = str((255 << 24) | 42760)
# Gateway service applies to forwarded customer traffic, never host-originated
# control traffic. Private/management destinations retain the existing exact
# site-prefix policy; enabling Internet Gateway must not expose WAN management.
GATEWAY_NON_INTERNET = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
                        "224.0.0.0/4", "240.0.0.0/4")


class RuntimeErrorSafe(Exception):
    """Bounded message safe for portal transport, without daemon stderr/secrets."""


def _same_route_destination(observed, expected):
    """iproute2 omits /32 and /128 from JSON host destinations."""
    if not isinstance(observed, str) or not isinstance(expected, str):
        return False
    try:
        if observed == "default":
            observed = "0.0.0.0/0"
        if expected == "default":
            expected = "0.0.0.0/0"
        return ipaddress.ip_network(observed, strict=False) == ipaddress.ip_network(expected, strict=False)
    except ValueError:
        return False


def _json(path, default=None):
    try:
        value = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return {} if default is None else default
    except (ValueError, OSError) as exc:
        raise RuntimeErrorSafe("cannot read validated state: %s" % Path(path).name) from exc
    if not isinstance(value, dict):
        raise RuntimeErrorSafe("invalid object: %s" % Path(path).name)
    return value


def _root_file(path, private=False):
    """Reject symlinks, writable ancestors, wrong owner and permissive keys."""
    path = Path(path)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            return False
        if info.st_mode & (0o077 if private else 0o022):
            return False
        for parent in path.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
        return True
    except OSError:
        return False


def _private_directory(path):
    path = Path(path)
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


def _atomic(path, value):
    path = Path(path)
    _private_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(value if isinstance(value, str) else json.dumps(value, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def _request(payload):
    if not isinstance(payload, dict) or set(payload) - {"network_id", "config", "customer", "tenant", "registration_id", "lab_mode", "generation"}:
        raise RuntimeErrorSafe("request has unsupported fields")
    network_id = payload.get("network_id")
    if not isinstance(network_id, str) or not NETWORK_RE.fullmatch(network_id):
        raise RuntimeErrorSafe("invalid network_id")
    if not isinstance(payload.get("config"), dict):
        raise RuntimeErrorSafe("config must be an object")
    for key in ("tenant", "registration_id"):
        if key in payload and (not isinstance(payload[key], str) or not 1 <= len(payload[key]) <= 128):
            raise RuntimeErrorSafe("invalid %s" % key)
    if "lab_mode" in payload and not isinstance(payload["lab_mode"], bool):
        raise RuntimeErrorSafe("lab_mode must be boolean")
    if "customer" in payload and payload["customer"] != payload.get("tenant"):
        raise RuntimeErrorSafe("customer and tenant identity differ")
    if "generation" in payload and (type(payload["generation"]) is not int or not 1 <= payload["generation"] <= (2 ** 63 - 1)):
        raise RuntimeErrorSafe("generation must be a positive integer")
    return payload


class Runner:
    """Fixed argv, clean environment, bounded execution/output, never shell=True."""

    def run(self, argv, *, check=True, environment=None):
        if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or "\0" in x for x in argv):
            raise RuntimeErrorSafe("invalid runtime command")
        allowed = {IP, NFT, NMCLI, SYSTEMCTL, SWANCTL, OPENSSL, VTYSH}
        if argv[0] not in allowed:
            raise RuntimeErrorSafe("runtime executable is not allowed")
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
        env.update(environment or {})
        try:
            # Files cap memory use even if a daemon emits more than the read limit.
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                def cap_files():
                    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * MAX_OUTPUT, 2 * MAX_OUTPUT))
                process = subprocess.Popen(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                           env=env, close_fds=True, preexec_fn=cap_files)
                try:
                    returncode = process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeErrorSafe("runtime command timed out: %s" % Path(argv[0]).name)
                out.seek(0)
                data = out.read(MAX_OUTPUT + 1)
                if len(data) > MAX_OUTPUT:
                    raise RuntimeErrorSafe("runtime response exceeded limit")
                if check and returncode:
                    raise RuntimeErrorSafe("runtime command failed: %s" % Path(argv[0]).name)
                return {"returncode": returncode, "stdout": data.decode("utf-8", errors="replace")}
        except OSError as exc:
            raise RuntimeErrorSafe("runtime executable unavailable: %s" % Path(argv[0]).name) from exc

    def data(self, argv):
        result = self.run(argv)
        try:
            return json.loads(result["stdout"])
        except ValueError as exc:
            raise RuntimeErrorSafe("runtime returned invalid JSON") from exc


class Runtime:
    restore_unit = "console-overlay-restore.service"
    def __init__(self, runner=None, state_root=STATE_ROOT, pki_root=PKI_ROOT):
        self.runner = runner or Runner()
        self.state_root = Path(state_root)
        self.pki_root = Path(pki_root)
        self._lock_depth = 0

    def _identity(self):
        manifest = _json(MANIFEST)
        if not _root_file(DEVICE_DETAIL):
            raise RuntimeErrorSafe("hardware identity assembly is missing or not root-trusted")
        detail = _json(DEVICE_DETAIL)
        name = manifest.get("device")
        if not isinstance(name, str) or not DEVICE_RE.fullmatch(name):
            raise RuntimeErrorSafe("current claimed device identity is unavailable")
        if not isinstance(detail.get("serial"), str) or not detail["serial"]:
            raise RuntimeErrorSafe("board identity is unavailable")
        if manifest.get("model") and manifest["model"] != detail.get("model"):
            raise RuntimeErrorSafe("claimed product differs from root-owned hardware assembly")
        if detail.get("model") == "vm":
            try:
                import vm_identity
            except ImportError as exc:
                raise RuntimeErrorSafe("VM instance identity helper is unavailable") from exc
            try:
                instance = vm_identity.check()
            except vm_identity.IdentityError as exc:
                raise RuntimeErrorSafe("VM instance identity is unavailable or on hold") from exc
            if instance.get("serial") != detail["serial"]:
                raise RuntimeErrorSafe("VM instance differs from the root-owned assembly identity")
        return {"device": name, "board_serial": detail["serial"], "model": detail.get("model")}

    def _compile(self, payload):
        payload = _request(payload)
        identity = self._identity()
        try:
            plan = overlay.compile_plan(payload["config"], payload["network_id"])
        except (ValueError, TypeError, KeyError) as exc:
            raise RuntimeErrorSafe("OVERLAY configuration is invalid") from exc
        site = plan.get("sites", {}).get(identity["device"])
        if not site:
            raise RuntimeErrorSafe("this device is not a member of the network")
        if site.get("model") and site["model"] != identity["model"]:
            raise RuntimeErrorSafe("site product no longer matches this device")
        return payload, identity, plan, site

    def _state(self, network_id):
        path = self.state_root / network_id / "state.json"
        if path.exists() and not _root_file(path, private=True):
            raise RuntimeErrorSafe("runtime state ownership is invalid")
        value = _json(path)
        if path.exists() and not value:
            raise RuntimeErrorSafe("existing runtime state journal is empty")
        return value

    def _inventory(self):
        addresses = self.runner.data([IP, "-j", "address", "show"])
        routes = self.runner.data([IP, "-j", "route", "show", "table", "all"])
        rules = self.runner.data([IP, "-j", "rule", "show"])
        links = self.runner.data([IP, "-j", "-d", "link", "show"])
        if not all(isinstance(x, list) for x in (addresses, routes, rules, links)):
            raise RuntimeErrorSafe("kernel inventory is incomplete")
        return {"interfaces": {row["ifname"]: row for row in addresses},
                "routes": routes, "rules": rules, "links": links}

    def _uplink_role_error(self, iface):
        """Prove the active Wi-Fi profile is a client, independently of the portal."""
        kind = self.runner.run([NMCLI, "-g", "GENERAL.TYPE", "device", "show", iface])["stdout"].strip()
        wireless = (kind in ("wifi", "802-11-wireless") or iface.startswith("wl")
                    or Path("/sys/class/net/%s/wireless" % iface).is_dir())
        if not wireless:
            return None
        uuid = self.runner.run([NMCLI, "-g", "GENERAL.CON-UUID", "device", "show", iface])["stdout"].strip()
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uuid):
            return "Wi-Fi uplink %s must have a verified active client connection" % iface
        mode = self.runner.run([NMCLI, "-g", "802-11-wireless.mode", "connection", "show", uuid])["stdout"].strip()
        if mode not in ("infrastructure", "station"):
            return "Wi-Fi uplink %s must be connected as a client; hotspot, mesh and unverified roles cannot be used" % iface
        return None

    def _configured_gateway(self, iface, row):
        """Observe NM's active/profile gateway without creating a main default."""
        values = self.runner.run([NMCLI, "-g", "IP4.GATEWAY", "device", "show", iface])["stdout"]
        candidates = {line.strip() for line in values.splitlines() if line.strip() and line.strip() != "--"}
        if not candidates:
            uuid = self.runner.run([NMCLI, "-g", "GENERAL.CON-UUID", "device", "show", iface])["stdout"].strip()
            if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uuid):
                values = self.runner.run([NMCLI, "-g", "ipv4.gateway", "connection", "show", uuid])["stdout"]
                candidates = {line.strip() for line in values.splitlines() if line.strip() and line.strip() != "--"}
        if len(candidates) != 1:
            return None
        try:
            address = ipaddress.IPv4Address(next(iter(candidates)))
            networks = [ipaddress.ip_interface("%s/%s" % (a["local"], a["prefixlen"])).network
                        for a in row.get("addr_info", []) if a.get("family") == "inet"]
            if not address.is_unspecified and any(address in network for network in networks) and not any(
                    str(address) == a.get("local") for a in row.get("addr_info", [])):
                return str(address)
        except ValueError:
            pass
        return None

    def _conflicts(self, site, inventory):
        used = {u["iface"] for u in site["uplinks"]} | set(site["lan_interfaces"])
        conflicts = []
        router = _json("/home/overlay/.parto_router.json")
        if router.get("wan") or router.get("lan"):
            conflicts.append("router mode is configured; forwarding ownership must be resolved")
        # vwire's saved members are the last chosen pair, even after disable.
        # Its actual kernel master relationship proves current ownership.
        for row in inventory["links"]:
            if row.get("ifname") in used and row.get("master"):
                conflicts.append("selected interface is enslaved to another feature")
        web = _json("/var/lib/parto/webaccess.json")
        legacy = _json("/home/overlay/.parto_webaccess.json")
        for store in (web, legacy):
            for iface, value in (store.get("interfaces") or {}).items():
                if iface in used and isinstance(value, dict) and value.get("enabled"):
                    conflicts.append("selected interface hosts Web Terminal access")
        uplink_state = _json("/home/overlay/.parto_uplink.json")
        pinned = uplink_state.get("iface")
        if uplink_state.get("trial"):
            conflicts.append("an uplink trial is pending; allow management recovery to finish before activation")
        if pinned in site["lan_interfaces"]:
            conflicts.append("selected LAN is the declared management uplink")
        for route in inventory["routes"]:
            if route.get("dst") == "default" and route.get("dev") in site["lan_interfaces"]:
                conflicts.append("selected LAN currently carries a default uplink")
        return sorted(set(conflicts))

    def _migration_errors(self, *, enrollment=False):
        errors = []
        # Any in-progress marker, including an unsafe dangling symlink, fences
        # runtime and enrollment until the guarded upgrade has been recovered.
        if os.path.lexists(UPGRADE_HOLD):
            return ["OVERLAY helper upgrade requires recovery"]
        if not _root_file(MIGRATION, private=True):
            return ["root-helper migration is not installed or trusted"]
        migration = _json(MIGRATION)
        if migration.get("schema_version") != 1 or migration.get("activation_enabled") is not True:
            errors.append("root-helper migration has not enabled activation")
        if not self._netlayer_lock_valid():
            errors.append("shared network operation lock is missing or untrusted")
        for filename, field in (("overlay_runtime.py", "runtime_sha256"), ("overlay.py", "compiler_sha256"),
                                ("overlay_enrollment.py", "enrollment_sha256")):
            if field == "enrollment_sha256" and not enrollment and field not in migration:
                # Earlier manual PKI migrations remain usable. The new signed
                # enrollment verbs explicitly require this additional pin.
                continue
            source = HELPER_ROOT / filename
            if not _root_file(source) or hashlib.sha256(source.read_bytes()).hexdigest() != migration.get(field):
                errors.append("immutable %s helper does not match migration" % filename)
        if os.geteuid() == 0 and Path(__file__).resolve() != HELPER_ROOT / "overlay_runtime.py":
            errors.append("root mutation requires the immutable installed helper")
        return errors

    @staticmethod
    def _netlayer_info_valid(info):
        try:
            group_id = grp.getgrnam("overlay").gr_gid
        except KeyError:
            return False
        return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == group_id
                and stat.S_IMODE(info.st_mode) == 0o660 and info.st_nlink == 1)

    def _netlayer_lock_valid(self):
        try:
            return self._netlayer_info_valid(NETLAYER_LOCK.lstat())
        except OSError:
            return False

    @staticmethod
    def _mutation_generation(payload):
        generation = payload.get("generation")
        if type(generation) is not int or not 1 <= generation <= 2 ** 63 - 1:
            raise RuntimeErrorSafe("apply and disable require a positive operation generation")
        if not payload.get("tenant") or not payload.get("registration_id"):
            raise RuntimeErrorSafe("mutations require current tenant and registration identity")
        return generation

    @staticmethod
    def _payload_hash(payload):
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _fence(self, payload, state):
        generation = self._mutation_generation(payload)
        previous = state.get("generation", 0)
        if type(previous) is not int or previous < 0:
            raise RuntimeErrorSafe("saved operation generation is invalid")
        if generation < previous:
            raise RuntimeErrorSafe("stale OVERLAY operation generation")
        identity = self._identity()
        if state and any(state.get(key) != value for key, value in
                         (("device", identity["device"]), ("tenant", payload.get("tenant")),
                          ("registration_id", payload.get("registration_id")))):
            raise RuntimeErrorSafe("mutation identity does not match the applied registration")
        if state.get("board_serial") is not None and state["board_serial"] != identity["board_serial"]:
            raise RuntimeErrorSafe("mutation hardware does not match the applied registration")
        # Signed credential preparation also reserves the operation generation.
        # Keep its intent under PKI rather than creating a disabled tombstone:
        # the prepared generation must still be able to perform its first Apply.
        intent_directory = self.pki_root / (".enrollment-" + payload["network_id"])
        if intent_directory.exists():
            path = intent_directory / "state.json"
            if not _root_file(path, private=True):
                raise RuntimeErrorSafe("credential generation journal is not root-private")
            intent = _json(path)
            fields = {"schema_version", "phase", "binding", "generation", "nonce", "csr_sha256"}
            if intent.get("phase") == "installed":
                fields.add("bundle_sha256")
            binding = {"schema_version": 1, "network_id": payload["network_id"],
                       "device": identity["device"], "board_serial": identity["board_serial"],
                       "tenant": payload.get("tenant"), "registration_id": payload.get("registration_id"),
                       "lab_mode": payload.get("lab_mode", False)}
            if (set(intent) != fields or type(intent.get("schema_version")) is not int or intent["schema_version"] != 1
                    or intent.get("phase") not in ("csr_pending", "installed")
                    or type(intent.get("generation")) is not int or not 1 <= intent["generation"] <= 2 ** 63 - 1
                    or not isinstance(intent.get("binding"), dict) or intent["binding"] != binding
                    or type(intent["binding"].get("schema_version")) is not int
                    or type(intent["binding"].get("lab_mode")) is not bool
                    or any(not isinstance(intent.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", intent[field])
                           for field in ("nonce", "csr_sha256"))
                    or (intent["phase"] == "installed" and
                        (not isinstance(intent.get("bundle_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", intent["bundle_sha256"])))):
                raise RuntimeErrorSafe("credential generation journal does not bind the current registration")
            if generation < intent["generation"]:
                raise RuntimeErrorSafe("stale OVERLAY operation generation before credential preparation")
        return generation, previous

    def _pki_errors(self, payload, identity, site):
        directory = self.pki_root / payload["network_id"]
        paths = {key: directory / name for key, name in (("authorization", "authorization.json"),
                 ("ca", "ca.pem"), ("cert", "cert.pem"), ("key", "key.pem"))}
        if not all(_root_file(path, private=True) for path in paths.values()):
            return ["dedicated network PKI is missing or not root-private"]
        authorization = _json(paths["authorization"])
        expected = {"network_id": payload["network_id"], "device": identity["device"],
                    "board_serial": identity["board_serial"], "tenant": payload.get("tenant"),
                    "registration_id": payload.get("registration_id")}
        if any(not value or authorization.get(key) != value for key, value in expected.items()):
            return ["PKI authorization does not bind the current tenant, network and registration"]
        if authorization.get("lab_mode", False) != payload.get("lab_mode", False):
            return ["PKI authorization does not permit the requested lab policy"]
        try:
            self.runner.run([OPENSSL, "verify", "-CAfile", str(paths["ca"]), "-purpose", "sslclient", str(paths["cert"])])
            self.runner.run([OPENSSL, "x509", "-in", str(paths["cert"]), "-noout", "-checkend", "86400"])
            certificate = self.runner.run([OPENSSL, "x509", "-in", str(paths["cert"]), "-noout", "-ext", "subjectAltName"])["stdout"]
            sans = re.findall(r"DNS:([^,\s]+)", certificate)
            if sans != [site["identity"]]:
                return ["certificate must have exactly the network-bound device DNS identity"]
            cert_key = self.runner.run([OPENSSL, "x509", "-in", str(paths["cert"]), "-pubkey", "-noout"])["stdout"].strip()
            private_key = self.runner.run([OPENSSL, "pkey", "-in", str(paths["key"]), "-pubout"])["stdout"].strip()
            if cert_key != private_key:
                return ["OVERLAY certificate and private key do not match"]
            # A pre-provisioned, current network-specific CRL is required because
            # the compiler sets strict revocation verification for peers.
            if not _root_file(directory / "crl.pem", private=True):
                return ["dedicated network revocation list is missing"]
            self.runner.run([OPENSSL, "crl", "-in", str(directory / "crl.pem"), "-CAfile", str(paths["ca"]), "-verify", "-noout"])
            self.runner.run([OPENSSL, "verify", "-CAfile", str(paths["ca"]), "-CRLfile", str(directory / "crl.pem"),
                             "-crl_check", str(paths["cert"])])
        except RuntimeErrorSafe:
            return ["dedicated network certificate, key or revocation validation failed"]
        return []

    def _model_errors(self, payload, identity):
        if not payload.get("lab_mode", False) and identity["model"] not in overlay.PRODUCTION_MODELS:
            return ["production OVERLAY requires Pi 5 4G or Pi 5 4G LAN"]
        return []

    def _supported_transports(self):
        return _json(MIGRATION).get("transports", [])

    def _passive_peer(self, tunnel):
        """Managed runtimes require fixed peer endpoints; standalone opts in."""
        return False

    def preflight(self, payload):
        payload, identity, plan, site = self._compile(payload)
        errors = []
        tls = site.get("transport", "ipsec") == "tls"
        inventory = self._inventory()
        errors.extend(self._model_errors(payload, identity))
        errors.extend(self._conflicts(site, inventory))
        errors.extend(self._migration_errors())
        if not _root_file(DEVICE_DETAIL):
            errors.append("hardware identity is not root-owned")
        dependencies = [IP, NFT, NMCLI, SYSTEMCTL, OPENSSL, VTYSH, "/usr/lib/frr/zebra", "/usr/lib/frr/bgpd"]
        ospf_enabled = site.get("routing", {}).get("ospf", {}).get("enabled", False)
        if ospf_enabled:
            dependencies.append("/usr/lib/frr/ospfd")
        dependencies += [OPENVPN, STUNNEL] if tls else [SWANCTL, "/usr/sbin/charon-systemd"]
        if tls:
            if "tls" not in self._supported_transports():
                errors.append("root-helper migration does not support TLS")
            try:
                tun = Path("/dev/net/tun").lstat()
                if tun.st_uid != 0 or not stat.S_ISCHR(tun.st_mode) or os.major(tun.st_rdev) != 10 or os.minor(tun.st_rdev) != 200:
                    errors.append("trusted TUN device is unavailable")
            except OSError:
                errors.append("trusted TUN device is unavailable")
        for path in dependencies:
            if not _root_file(Path(path).resolve()) or not os.access(path, os.X_OK):
                errors.append("required dedicated-runtime dependency is unavailable: %s" % Path(path).name)
        errors.extend(self._pki_errors(payload, identity, site))
        try:
            forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        except OSError:
            forwarding = ""
        if forwarding != "1":
            errors.append("IPv4 forwarding must be enabled by the approved migration")
        for key in ("all", "default"):
            try:
                if Path("/proc/sys/net/ipv4/conf/%s/rp_filter" % key).read_text().strip() != "0":
                    errors.append("multipath reverse-path filtering requires the approved migration")
            except OSError:
                errors.append("reverse-path filtering settings could not be observed")
        for iface in {u["iface"] for u in site["uplinks"]} | set(site["lan_interfaces"]):
            try:
                if Path("/proc/sys/net/ipv4/conf/%s/rp_filter" % iface).read_text().strip() != "0":
                    errors.append("selected interface %s requires migration reverse-path filtering settings" % iface)
            except OSError:
                errors.append("selected interface reverse-path filtering could not be observed")
        # Raw daemon/NetworkManager instances can own these ports without a
        # system-wide service. Inspect sockets as well as service names.
        for filename in ("udp", "udp6", "tcp", "tcp6"):
            try:
                for line in Path("/proc/net/" + filename).read_text().splitlines()[1:]:
                    columns = line.split()
                    port = int(columns[1].rsplit(":", 1)[1], 16)
                    if (not tls and filename.startswith("udp") and port in (500, 4500)) or (filename.startswith("tcp") and port == 179 and columns[3] == "0A"):
                        errors.append("an existing daemon owns an IPsec or BGP listen port")
            except (OSError, ValueError, IndexError):
                errors.append("IPsec/BGP socket ownership could not be observed")
        for daemon in (("stunnel", "openvpn", "zebra", "bgpd") if tls else ("charon", "zebra", "bgpd")):
            if not _root_file("/etc/systemd/system/console-overlay-%s@.service" % daemon):
                errors.append("dedicated daemon unit migration is missing: %s" % daemon)
        if ospf_enabled and not _root_file("/etc/systemd/system/console-overlay-ospfd@.service"):
            errors.append("dedicated daemon unit migration is missing: ospfd")
        if not _root_file("/etc/systemd/system/" + self.restore_unit):
            errors.append("boot restoration unit migration is missing")
        elif self.runner.run([SYSTEMCTL, "is-enabled", self.restore_unit], check=False)["stdout"].strip() != "enabled":
            errors.append("boot restoration unit has not been enabled by migration")
        for unit in (("frr.service",) if tls else ("strongswan.service", "strongswan-starter.service", "strongswan-swanctl.service", "frr.service")):
            result = self.runner.run([SYSTEMCTL, "is-active", unit], check=False)
            if result["stdout"].strip() == "active":
                errors.append("an existing IPsec/FRR service owns the shared kernel/ports: %s" % unit)
        sources, gateways, mtus, endpoint_routes = {}, {}, {}, {}
        protected = [ipaddress.ip_network(n) for n in RESERVED + (plan["overlay_cidr"],)]
        for uplink in site["uplinks"]:
            iface = uplink["iface"]
            row = inventory["interfaces"].get(iface)
            if not row or "UP" not in row.get("flags", []):
                errors.append("uplink %s is absent or down" % iface)
                continue
            try:
                role_error = self._uplink_role_error(iface)
                if role_error:
                    errors.append(role_error)
                    continue
            except RuntimeErrorSafe:
                errors.append("uplink %s role could not be verified" % iface)
                continue
            addresses = [a["local"] for a in row.get("addr_info", []) if a.get("family") == "inet" and a.get("scope") == "global"]
            if len(addresses) != 1:
                errors.append("uplink %s requires exactly one usable IPv4 source" % iface)
                continue
            sources[iface] = str(ipaddress.IPv4Address(addresses[0]))
            if int(row.get("mtu", 0)) < 1376:
                errors.append("uplink %s has insufficient verified MTU for the overlay" % iface)
            else:
                # IPv4, NAT-T and AES-GCM ESP padding allowance. LAN tests must
                # still prove ICMP PMTU delivery with real carrier paths.
                mtus[iface] = min(1400, int(row["mtu"]) - 96)
            for address in row.get("addr_info", []):
                if address.get("family") == "inet":
                    protected.append(ipaddress.ip_interface("%s/%s" % (address["local"], address["prefixlen"])).network)
            defaults = [r for r in inventory["routes"] if r.get("dev") == iface and r.get("dst") == "default"
                        and r.get("table", "main") in ("main", 254)]
            candidates = {r.get("gateway") for r in defaults}
            if len(candidates) > 1:
                errors.append("uplink %s requires an explicit unique underlay default route" % iface)
                continue
            gateways[iface] = next(iter(candidates)) if candidates else None
        if len(set(sources.values())) != len(sources):
            errors.append("selected uplinks share an IPv4 source; IKE source policy cannot disambiguate them")
        for iface in site["lan_interfaces"]:
            row = inventory["interfaces"].get(iface)
            if not row or "UP" not in row.get("flags", []):
                errors.append("LAN %s is absent or down" % iface)
        errors.extend(self._lan_routing_errors(site, inventory))
        for row in inventory["routes"]:
            if str(row.get("dev", "")).startswith(("tun", "tap", "wg")) and row.get("dst") not in (None, "default"):
                try:
                    protected.append(ipaddress.ip_network(row["dst"]))
                except ValueError:
                    errors.append("management route inventory is invalid")
        for prefix in [p for s in plan["sites"].values() for p in s["prefixes"]]:
            net = ipaddress.ip_network(prefix)
            if any(net.overlaps(p) for p in protected):
                errors.append("advertised prefix overlaps management or overlay addressing")
            if any(ipaddress.ip_address(addr) in net for addr in sources.values()):
                errors.append("advertised prefix covers an underlay source address")
        routing = site.get("routing", {})
        declared = {r["prefix"] for r in routing.get("static_routes", [])}
        declared.update(routing.get("ospf", {}).get("import_prefixes", []))
        for peer in routing.get("bgp", {}).get("peers", []):
            declared.update(peer["import_prefixes"])
        for prefix in site["prefixes"]:
            routes = [r for r in inventory["routes"] if _same_route_destination(r.get("dst"), prefix) and r.get("dev") in site["lan_interfaces"]
                      and r.get("table", "main") in ("main", 254) and r.get("type", "unicast") == "unicast"]
            if not routes and prefix not in declared:
                errors.append("prefix %s has no exact reachable main-table route on a selected LAN" % prefix)
            foreign = [r for r in inventory["routes"] if _same_route_destination(r.get("dst"), prefix)
                       and r.get("table", "main") in ("main", 254) and r.get("dev") not in site["lan_interfaces"]]
            if foreign:
                errors.append("prefix %s has an existing route outside the selected LAN" % prefix)
        if tls:
            errors.extend(self._tls_port_errors(site, sources))
        state = self._state(payload["network_id"])
        if state.get("phase") not in (None, "disabled"):
            errors.append("network is already applied or requires cleanup before replacement")
        if self.state_root.exists():
            for directory in self.state_root.iterdir():
                if directory.is_dir() and directory.name != payload["network_id"]:
                    previous = _json(directory / "state.json")
                    if previous.get("phase") not in (None, "disabled"):
                        errors.append("another OVERLAY network already owns this device")
        existing_names = {row.get("ifname") for row in inventory["links"]}
        existing_ids = {row.get("linkinfo", {}).get("info_data", {}).get("if_id") for row in inventory["links"]}
        existing_tables = {str(r.get("table", "main")) for r in inventory["routes"]}
        existing_priorities = {int(r.get("priority", -1)) for r in inventory["rules"]}
        gateway = site.get("internet_gateway")
        if gateway:
            if str(gateway["policy_table"]) in existing_tables:
                errors.append("requested Internet Gateway policy table already exists")
            if self._gateway_priority(gateway) in existing_priorities:
                errors.append("requested Internet Gateway policy priority already exists")
            if gateway["role"] == "hub":
                errors.extend(self._gateway_egress_errors(site, inventory))
        firewall = self.runner.data([NFT, "-j", "list", "tables"])
        table_name = "csd_" + hashlib.sha256(payload["network_id"].encode()).hexdigest()[:12]
        if any(row.get("table", {}).get("name") == table_name for row in firewall.get("nftables", [])):
            errors.append("requested OVERLAY firewall table already exists")
        for tunnel in site["tunnels"]:
            if_id = int(tunnel["if_id"])
            if not 1000 <= if_id < 10000 or int(tunnel["table"]) != 40000 + if_id:
                errors.append("compiler generated resource IDs outside reserved space")
                continue
            if tunnel["if_name"] in existing_names or if_id in existing_ids or str(tunnel["table"]) in existing_tables:
                errors.append("requested XFRM interface or policy table already exists")
            if any(p in existing_priorities for p in (10000 + if_id, 20000 + if_id)):
                errors.append("requested source/mark policy priority already exists")
            endpoint = tunnel.get("remote_endpoint")
            if self._passive_peer(tunnel):
                iface = tunnel['local_uplink']
                if iface in sources:
                    if not gateways.get(iface):
                        gateways[iface]=self._configured_gateway(iface,inventory['interfaces'][iface])
                    if not gateways.get(iface):errors.append('Passive transport WAN requires its own default gateway')
                    endpoint_routes[tunnel['id']] = {'gateway':gateways.get(iface), 'iface':iface, 'source':sources[iface]}
                continue
            if not endpoint:
                errors.append("public endpoints are missing; this is a draft plan")
                continue
            try:
                endpoint_address = ipaddress.IPv4Address(endpoint)
            except ValueError:
                errors.append("remote endpoint is not an IPv4 address")
                continue
            if not payload.get("lab_mode", False) and not endpoint_address.is_global:
                errors.append("production IPsec endpoint must be globally routable")
            iface = tunnel["local_uplink"]
            if iface not in sources or iface not in gateways:
                continue
            try:
                route = self.runner.data([IP, "-j", "route", "get", endpoint, "from", sources[iface], "oif", iface])
                if route and route[0].get("dev") == iface and route[0].get("type", "unicast") == "unicast":
                    endpoint_routes[tunnel["id"]] = {"gateway": route[0].get("gateway"), "iface": iface,
                                                      "source": sources[iface]}
                    continue
            except RuntimeErrorSafe:
                pass
            try:
                # Portal-managed non-management LAN profiles deliberately have
                # never-default set. A live/profile gateway within this uplink's
                # connected subnet suffices for a private endpoint /32 route.
                gateway = self._configured_gateway(iface, inventory["interfaces"][iface])
                if gateway:
                    endpoint_routes[tunnel["id"]] = {"gateway": gateway, "iface": iface, "source": sources[iface]}
                else:
                    errors.append("endpoint underlay route or connected NetworkManager gateway cannot be verified on %s" % iface)
            except RuntimeErrorSafe:
                errors.append("endpoint underlay route cannot be verified on %s" % iface)
        return {"ok": True, "ready": not errors, "state": "ready" if not errors else "not_ready",
                "network_id": payload["network_id"], "device": identity["device"], "errors": sorted(set(errors)),
                "sources": sources, "gateways": gateways, "mtus": mtus,
                "endpoint_routes": endpoint_routes,
                "tunnels_expected": len(site["tunnels"])}

    @staticmethod
    def _gateway_priority(gateway):
        # Before the main-table rule (32766); all selectors require a LAN iif.
        return 5000 + (int(gateway["policy_table"]) - 51000) % 1000

    @staticmethod
    def _gateway_egress_errors(site, inventory):
        """Prove the hub's currently preferred host default uses selected WANs."""
        uplinks = {u["iface"] for u in site["uplinks"]}
        defaults = [r for r in inventory["routes"]
                    if r.get("table", "main") in ("main", 254)
                    and _same_route_destination(r.get("dst"), "0.0.0.0/0")
                    and r.get("type", "unicast") == "unicast"]
        if not defaults:
            return ["Internet Gateway hub requires a reachable default route on a selected uplink"]
        preferred = min(r.get("metric", 0) for r in defaults)
        for route in defaults:
            if route.get("metric", 0) != preferred:
                continue
            interfaces = {n.get("dev") for n in route.get("multipath", [])} or {route.get("dev")}
            if not interfaces or not interfaces <= uplinks or any(
                    "UP" not in inventory["interfaces"].get(iface, {}).get("flags", []) for iface in interfaces):
                return ["Internet Gateway hub preferred default must use only active selected uplinks"]
        return []

    @staticmethod
    def _lan_routing_errors(site, inventory):
        """Prove LAN routing endpoints from live kernel state before mutations."""
        routing, errors = site.get("routing", {}), []
        neighbors = [(r["interface"], r["next_hop"], "static next hop")
                     for r in routing.get("static_routes", [])]
        neighbors += [(p["interface"], p["address"], "BGP peer")
                      for p in routing.get("bgp", {}).get("peers", [])]
        for iface, address, label in neighbors:
            rows = inventory["interfaces"].get(iface, {}).get("addr_info", [])
            try:
                local = [ipaddress.ip_interface("%s/%s" % (a["local"], a["prefixlen"]))
                         for a in rows if a.get("family") == "inet" and a.get("scope") == "global"]
                peer = ipaddress.ip_address(address)
                if not any(peer in a.network and peer not in (a.ip, a.network.network_address, a.network.broadcast_address)
                           for a in local):
                    errors.append("%s must be another directly connected host on LAN %s" % (label, iface))
                routes = [r for r in inventory["routes"] if r.get("table", "main") in ("main", 254)
                          and r.get("dev") == iface and not r.get("gateway") and r.get("type", "unicast") == "unicast"
                          and r.get("dst") not in (None, "default") and peer in ipaddress.ip_network(r["dst"])]
                if not routes:
                    errors.append("%s has no directly connected main-table route on LAN %s" % (label, iface))
            except (ValueError, KeyError, TypeError):
                errors.append("LAN routing address inventory is invalid")
        for route in routing.get("static_routes", []):
            if any(_same_route_destination(r.get("dst"), route["prefix"]) and r.get("table", "main") in ("main", 254)
                   for r in inventory["routes"]):
                errors.append("static route %s already exists; foreign routes are preserved" % route["prefix"])
        for entry in routing.get("ospf", {}).get("interfaces", []):
            rows = inventory["interfaces"].get(entry["interface"], {}).get("addr_info", [])
            try:
                addresses = [a["local"] for a in rows if a.get("family") == "inet" and a.get("scope") == "global"]
                if len(addresses) != 1:
                    errors.append("OSPF LAN %s requires one private IPv4 address" % entry["interface"])
                else:
                    overlay._private_address(addresses[0], "OSPF LAN address")
                    networks = [ipaddress.ip_interface("%s/%s" % (a["local"], a["prefixlen"])).network
                                for a in rows if a.get("family") == "inet" and a.get("scope") == "global"]
                    exports = routing.get("ospf", {}).get("export_prefixes", [])
                    if any(str(network) not in site["prefixes"] or str(network) not in exports for network in networks):
                        errors.append("OSPF LAN connected subnet must be an exact authorized site and export prefix")
            except (ValueError, KeyError, TypeError):
                errors.append("OSPF LAN address must be private and outside management ranges")
        return sorted(set(errors))

    def _reservations(self, site):
        interfaces = {u["iface"] for u in site["uplinks"]} | set(site["lan_interfaces"])
        links = self.runner.data([IP, "-j", "-d", "link", "show"])
        by_index = {row.get("ifindex"): row.get("ifname") for row in links}
        by_name = {row.get("ifname"): row for row in links}
        queue = list(interfaces)
        while queue:
            name = queue.pop()
            row = by_name.get(name, {})
            parent = row.get("link") or by_index.get(row.get("link_index"))
            if not parent and "." in name:
                parent = name.split(".", 1)[0]
            if isinstance(parent, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", parent) and parent not in interfaces:
                interfaces.add(parent)
                queue.append(parent)
        return sorted(interfaces)

    def guard(self):
        """No-input root reservation oracle for existing network feature guards."""
        if os.geteuid() != 0 or self._migration_errors():
            return {"ok": False, "active": True, "interfaces": [],
                    "errors": ["root OVERLAY reservations could not be verified"]}
        interfaces, active = set(), False
        if self.state_root.exists():
            for directory in self.state_root.iterdir():
                if not directory.is_dir() or not NETWORK_RE.fullmatch(directory.name):
                    continue
                state = self._state(directory.name)
                if not state:
                    if (directory / "state.json").exists():
                        raise RuntimeErrorSafe("existing interface reservation journal is empty")
                    continue
                if state.get("phase") not in {"applying", "configured", "disabled", "disabling", "cleanup_required", "restore_pending"}:
                    raise RuntimeErrorSafe("interface reservation journal has an unknown phase")
                if state["phase"] == "disabled":
                    if state.get("operations") or state.get("pending"):
                        raise RuntimeErrorSafe("disabled interface reservation journal retains operations")
                    continue
                active = True
                rows = state.get("interfaces")
                if not isinstance(rows, list) or not rows:
                    revision = state.get("revision", "")
                    if not re.fullmatch(r"[0-9a-f]{64}", revision):
                        raise RuntimeErrorSafe("active interface reservations are incomplete")
                    source = directory / "revisions" / revision / "request.json"
                    if not _root_file(source, private=True):
                        raise RuntimeErrorSafe("active interface reservations are untrusted")
                    payload = _request(_json(source))
                    plan = overlay.compile_plan(payload["config"], payload["network_id"])
                    site = plan["sites"].get(state.get("device"))
                    if not site:
                        raise RuntimeErrorSafe("active interface reservations have no device")
                    rows = self._reservations(site)
                if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", name) for name in rows):
                    raise RuntimeErrorSafe("active interface reservations are invalid")
                interfaces.update(rows)
        return {"ok": True, "active": active, "interfaces": sorted(interfaces)}

    @contextlib.contextmanager
    def _lock(self):
        if os.geteuid() != 0:
            raise RuntimeErrorSafe("mutation requires the root helper")
        if self._lock_depth:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        try:
            network_descriptor = os.open(NETLAYER_LOCK, os.O_RDWR | os.O_NOFOLLOW)
        except OSError as exc:
            raise RuntimeErrorSafe("shared network operation lock is unavailable") from exc
        try:
            descriptor_info = os.fstat(network_descriptor)
            path_info = NETLAYER_LOCK.lstat()
            if (not self._netlayer_info_valid(descriptor_info)
                    or (descriptor_info.st_dev, descriptor_info.st_ino) != (path_info.st_dev, path_info.st_ino)):
                raise RuntimeErrorSafe("shared network operation lock is untrusted")
            deadline = time.monotonic() + 3
            while True:
                try:
                    fcntl.flock(network_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeErrorSafe("another network feature operation is running")
                    time.sleep(0.05)
            with self._state_lock():
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0
        finally:
            os.close(network_descriptor)

    @contextlib.contextmanager
    def _state_lock(self):
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.state_root.is_symlink() or self.state_root.stat().st_uid != 0 or self.state_root.stat().st_mode & 0o022:
            raise RuntimeErrorSafe("runtime state directory is not trusted")
        descriptor = os.open(self.state_root / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise RuntimeErrorSafe("runtime operation lock is not root-private")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeErrorSafe("another OVERLAY operation is running") from exc
            yield
        finally:
            os.close(descriptor)

    @staticmethod
    def _tls_port_errors(site, sources):
        ports = {35000 + t["if_id"] for t in site["tunnels"]}
        listener_sources = {sources.get(t["local_uplink"]) for t in site["tunnels"] if not t["initiator"]}
        errors = []
        for version in ("tcp", "tcp6"):
            try:
                for line in Path("/proc/net/" + version).read_text().splitlines()[1:]:
                    fields = line.split()
                    if fields[3] != "0A":
                        continue
                    address, raw_port = fields[1].split(":")
                    port = int(raw_port, 16)
                    # A v6 wildcard may also reserve IPv4 on a dual-stack socket.
                    packed = bytes.fromhex(address)
                    if version == "tcp":
                        local = str(ipaddress.IPv4Address(packed[::-1]))
                    else:
                        ipv6 = ipaddress.IPv6Address(b"".join(packed[i:i+4][::-1] for i in range(0, 16, 4)))
                        local = str(ipv6.ipv4_mapped or ipv6)
                    if port in ports and local in ("127.0.0.1", "0.0.0.0", "::"):
                        errors.append("a private TLS backend port is already in use")
                    if port == 443 and listener_sources and (local in listener_sources or local in ("0.0.0.0", "::")):
                        errors.append("TCP 443 is already in use on a selected uplink")
            except (OSError, ValueError, IndexError):
                errors.append("TLS socket ownership could not be observed")
        return sorted(set(errors))

    def _commands(self, network_id, plan, site, sources, gateways, revision, mtus=None, endpoint_routes=None):
        """Exact paired add/delete commands, never flush or replace foreign state."""
        operations = []
        cookie = "console-overlay:%s:%s" % (network_id, revision.name)
        def add(argv, undo, kind="command", **metadata):
            operations.append({"argv": argv, "undo": undo, "kind": kind, **metadata})
        all_prefixes = sorted({p for s in plan["sites"].values() for p in s["prefixes"]})
        remote_prefixes = sorted(set(all_prefixes) - set(site["prefixes"]))
        for route in site.get("routing", {}).get("static_routes", []):
            # Kernel routes use a private protocol and an administrative
            # distance of 1 in the metric high byte, understood by Zebra.
            args = [route["prefix"], "via", route["next_hop"], "dev", route["interface"],
                    "proto", ROUTE_PROTOCOL, "metric", str((1 << 24) | route["metric"])]
            add([IP, "route", "add"] + args, [IP, "route", "del"] + args, "static_route")
        # Unavailable BGP destinations cannot fall through to a WAN default.
        for prefix in remote_prefixes:
            args = ["blackhole", prefix, "proto", ROUTE_PROTOCOL, "metric", GUARD_METRIC]
            add([IP, "route", "add"] + args, [IP, "route", "del"] + args)
        for tunnel in site["tunnels"]:
            start_index = len(operations)
            iface, name, ident = tunnel["local_uplink"], tunnel["if_name"], int(tunnel["if_id"])
            source, endpoint = sources[iface], tunnel["remote_endpoint"]
            table, mark = str(tunnel["table"]), str(tunnel["mark"])
            if site.get("transport", "ipsec") == "tls":
                # Until the alias is committed, failed creation enters a hold;
                # cleanup must never guess ownership of an unlabelled TUN.
                add([IP, "tuntap", "add", "dev", name, "mode", "tun"],
                    [IP, "link", "delete", "dev", name], "interface", name=name, cookie=cookie)
            else:
                add([IP, "link", "add", "name", name, "type", "xfrm", "dev", iface, "if_id", str(ident)],
                    [IP, "link", "delete", "dev", name], "interface", name=name, cookie=cookie)
            # Linux 6.1 accepts IFLA_IFALIAS in RTM_NEWLINK but does not
            # install it during creation. Set it through RTM_SETLINK for both
            # transports, then prove it before addresses/routes are added.
            # A crash before this succeeds leaves a durable ownership hold;
            # an absent cookie must never authorize deletion of a link.
            add([IP, "link", "set", "dev", name, "alias", cookie],
                [IP, "link", "set", "dev", name, "alias", cookie],
                "interface_alias", name=name, cookie=cookie)
            add([IP, "address", "add", tunnel["local_address"], "dev", name],
                [IP, "address", "del", tunnel["local_address"], "dev", name])
            add([IP, "link", "set", "dev", name, "mtu", str((mtus or {}).get(iface, 1400)), "up"], [IP, "link", "set", "dev", name, "down"])
            passive = self._passive_peer(tunnel)
            route = ["default" if passive else endpoint + "/32", "dev", iface, "src", source, "table", table, "proto", ROUTE_PROTOCOL]
            gateway = (endpoint_routes or {}).get(tunnel["id"], {}).get("gateway", gateways[iface])
            if endpoint_routes is not None:
                gateway = endpoint_routes[tunnel["id"]].get("gateway")
            if gateway:
                route.extend(["via", str(gateway), "onlink"])
            add([IP, "route", "add"] + route, [IP, "route", "del"] + route)
            for selectors, priority in ((["from", source + "/32"] + ([] if passive else ["to", endpoint + "/32"]), 10000 + ident),
                                        (["fwmark", mark + "/0xffffffff"], 20000 + ident)):
                rule = ["priority", str(priority)] + selectors + ["table", table]
                add([IP, "rule", "add"] + rule, [IP, "rule", "del"] + rule)
            for operation in operations[start_index:]:
                operation.update(owner_name=name, owner_cookie=cookie)
        gateway = site.get("internet_gateway")
        if gateway and gateway["role"] == "spoke":
            table, priority = str(gateway["policy_table"]), str(self._gateway_priority(gateway))
            # FRR installs only its authenticated hub default in this table.
            # Preserve the main table for inter-site/connected management routes,
            # and blackhole internet if the BGP default is withdrawn.
            destinations = sorted(set(all_prefixes) | set(RESERVED) | {plan["overlay_cidr"]})
            for prefix in destinations:
                args = ["throw", prefix, "table", table, "proto", ROUTE_PROTOCOL]
                add([IP, "route", "add"] + args, [IP, "route", "del"] + args, "gateway_throw")
            args = ["blackhole", "0.0.0.0/0", "table", table, "proto", ROUTE_PROTOCOL, "metric", GUARD_METRIC]
            add([IP, "route", "add"] + args, [IP, "route", "del"] + args, "gateway_guard")
            for iface in sorted(site["lan_interfaces"]):
                for prefix in sorted(site["prefixes"]):
                    rule = ["priority", priority, "from", prefix, "iif", iface, "table", table]
                    add([IP, "rule", "add"] + rule, [IP, "rule", "del"] + rule, "gateway_rule",
                        source_prefix=prefix, incoming_interface=iface)
        # One atomic dedicated nftables table; scalable prefix sets avoid a
        # quadratic number of firewall commands or shared-chain modifications.
        table_name = "csd_" + hashlib.sha256(network_id.encode()).hexdigest()[:12]
        add([NFT, "-f", str(revision / "firewall.nft")],
            [NFT, "delete", "table", "inet", table_name], "firewall", name=table_name,
            cookie="console-overlay:" + network_id)
        # Services are independent of any system-wide strongSwan/FRR instance.
        if site.get("transport", "ipsec") == "tls":
            for tunnel in site["tunnels"]:
                unit = "console-overlay-openvpn@%s--%s.service" % (network_id, tunnel["id"])
                add([SYSTEMCTL, "start", unit], [SYSTEMCTL, "stop", unit], "service")
        daemons = ["stunnel" if site.get("transport", "ipsec") == "tls" else "charon", "zebra"]
        if site.get("routing", {}).get("ospf", {}).get("enabled"):
            daemons.append("ospfd")
        daemons.append("bgpd")
        for daemon in daemons:
            unit = "console-overlay-%s@%s.service" % (daemon, network_id)
            add([SYSTEMCTL, "start", unit], [SYSTEMCTL, "stop", unit], "service")
        return operations

    @staticmethod
    def _firewall(network_id, plan, site, sources):
        # Every interpolated field comes from compile_plan validation; callers
        # cannot supply nft syntax, paths, arbitrary commands or generated text.
        def strings(items):
            return "{ " + ", ".join('"%s"' % item for item in sorted(set(items))) + " }"
        def prefixes(items):
            return "{ " + ", ".join(sorted(set(items))) + " }"
        table_name = "csd_" + hashlib.sha256(network_id.encode()).hexdigest()[:12]
        remote = [p for name, s in plan["sites"].items() if name != site["name"] for p in s["prefixes"]]
        own, lans = prefixes(site["prefixes"]), strings(site["lan_interfaces"])
        xfrms = strings(t["if_name"] for t in site["tunnels"])
        wans = strings(u["iface"] for u in site["uplinks"])
        lines = ["table inet %s {" % table_name, ' comment "console-overlay:%s"' % network_id,
                 " chain input { type filter hook input priority -10; policy accept;"]
        for t in site["tunnels"]:
            local = str(ipaddress.ip_interface(t["local_address"]).ip)
            lines.append('  iifname "%s" ip saddr %s ip daddr %s tcp dport 179 accept' %
                         (t["if_name"], t["peer_address"], local))
            if site.get("transport", "ipsec") == "ipsec":
                lines.append('  iifname "%s" ip saddr %s ip daddr %s udp dport { 500, 4500 } accept' %
                             (t["local_uplink"], t["remote_endpoint"], sources[t["local_uplink"]]))
            elif not t["initiator"]:
                lines.append('  iifname "%s" ip saddr %s ip daddr %s tcp dport 443 accept' %
                             (t["local_uplink"], t["remote_endpoint"], sources[t["local_uplink"]]))
        routing = site.get("routing", {})
        for peer in routing.get("bgp", {}).get("peers", []):
            lines.append('  iifname "%s" ip saddr %s tcp dport 179 accept' %
                         (peer["interface"], peer["address"]))
        for entry in routing.get("ospf", {}).get("interfaces", []):
            if not entry["passive"]:
                lines.append('  iifname "%s" ip saddr %s ip protocol ospf accept' % (entry["interface"], own))
        if routing.get("ospf", {}).get("enabled"):
            lines.append("  ip protocol ospf drop")
        lines.append("  tcp dport 179 drop")
        if site.get("transport", "ipsec") == "ipsec":
            lines.append("  udp dport { 500, 4500 } drop")
        else:
            # Preserve HTTPS/estate services on all other interfaces/addresses.
            for iface in sorted({t["local_uplink"] for t in site["tunnels"] if not t["initiator"]}):
                lines.append('  iifname "%s" ip daddr %s tcp dport 443 drop' % (iface, sources[iface]))
        lines.extend((" }", " chain forward { type filter hook forward priority -10; policy accept;"))
        for t in site["tunnels"]:
            # 0/0 is a routing permission, not unrestricted source validation.
            allowed = prefixes(p for p in t["accepted_prefixes"] if p != "0.0.0.0/0")
            lines.append('  iifname %s ip saddr %s oifname "%s" ip daddr %s accept' % (lans, own, t["if_name"], allowed))
            lines.append('  iifname "%s" ip saddr %s oifname %s ip daddr %s accept' % (t["if_name"], allowed, lans, own))
            if site["role"] == "hub":
                lines.append('  iifname "%s" ip saddr %s oifname %s ip daddr %s accept' %
                             (t["if_name"], allowed, xfrms, prefixes(remote)))
        gateway = site.get("internet_gateway")
        if gateway:
            blocked = prefixes(GATEWAY_NON_INTERNET)
            if gateway["role"] == "hub":
                for t in site["tunnels"]:
                    authorized = prefixes(p for p in t["accepted_prefixes"] if p != "0.0.0.0/0")
                    lines.append('  iifname "%s" ip saddr %s oifname %s ip daddr %s drop' %
                                 (t["if_name"], authorized, wans, blocked))
                    lines.append('  iifname "%s" ip saddr %s oifname %s accept' %
                                 (t["if_name"], authorized, wans))
                lines.append('  iifname %s oifname %s ip daddr %s ct state { established, related } accept' %
                             (wans, xfrms, prefixes(gateway["spoke_prefixes"])))
            else:
                lines.append('  iifname %s ip saddr %s oifname %s ip daddr %s drop' %
                             (lans, own, xfrms, blocked))
                lines.append('  iifname %s ip saddr %s oifname %s accept' % (lans, own, xfrms))
                lines.append('  iifname %s oifname %s ip daddr %s ct state { established, related } accept' %
                             (xfrms, lans, own))
        lines.extend(("  iifname %s drop" % xfrms, "  oifname %s drop" % xfrms,
                      "  iifname %s oifname %s ip saddr %s ip daddr %s accept" % (lans, lans, own, own),
                      # Enabling global forwarding must not make the estate VPN
                      # or an unselected WAN a customer traffic transit path.
                      "  iifname %s drop" % lans, "  oifname %s drop" % lans,
                      "  iifname %s oifname %s drop" % (wans, lans),
                      "  iifname %s oifname %s drop" % (lans, wans),
                      "  ip daddr %s drop" % prefixes(remote), " }",
                      " chain output { type filter hook output priority -10; policy accept;",
                      "  oifname %s ip daddr %s accept" % (xfrms, prefixes(remote)),
                      "  ip daddr %s drop" % prefixes(remote)))
        if routing:
            lines.extend(("  oifname %s ip daddr %s accept" % (lans, own), "  ip daddr %s drop" % own))
        # NAT is scoped to forwarded spoke traffic and this owned table. Host
        # traffic, the estate VPN, hub LAN and other features are unaffected.
        if gateway and gateway["role"] == "hub":
            lines.extend((" }", " chain gateway_nat { type nat hook postrouting priority srcnat; policy accept;",
                          "  iifname %s oifname %s ip saddr %s ip daddr != %s masquerade" %
                          (xfrms, wans, prefixes(gateway["spoke_prefixes"]), prefixes(GATEWAY_NON_INTERNET))))
        lines.extend((" }", "}"))
        return "\n".join(lines) + "\n"

    def _revision(self, payload, plan, site, preflight):
        canonical = json.dumps({"payload": payload, "sources": preflight["sources"], "gateways": preflight["gateways"],
                                "mtus": preflight.get("mtus", {}), "endpoint_routes": preflight.get("endpoint_routes", {})}, sort_keys=True)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        network_dir = self.state_root / payload["network_id"]
        revision = network_dir / "revisions" / digest
        _private_directory(revision)
        files = {"frr.conf": site["frr_config"], "request.json": json.dumps(payload, sort_keys=True),
                 "zebra.conf": site.get("zebra_config", "hostname console-overlay\n!\n"),
                 "firewall.nft": self._firewall(payload["network_id"], plan, site, preflight["sources"])}
        if site.get("routing", {}).get("ospf", {}).get("enabled"):
            files["ospfd.conf"] = site["ospfd_config"]
        if site.get("transport", "ipsec") == "ipsec":
            files["swanctl.conf"] = overlay.render_swanctl(site, local_sources=preflight["sources"])
            files["strongswan.conf"] = site["strongswan_config"] + "\ncharon-systemd {\n  plugins {\n    vici { socket = unix:///run/console-overlay/%s/charon.vici }\n  }\n}\n" % payload["network_id"]
        else:
            paths = {"ca": str(revision / "x509ca/ca.pem"), "cert": str(revision / "x509/cert.pem"),
                     "key": str(revision / "private/key.pem"), "crl": str(revision / "x509crl/crl.pem")}
            files["stunnel.conf"] = overlay.render_stunnel(site, preflight["sources"], paths)
            for ident, value in overlay.render_openvpn(site, paths, preflight.get("mtus")).items():
                files["tls/%s/openvpn.conf" % ident] = value
        for filename, value in files.items():
            target = revision / filename
            if target.exists() and target.read_text() != value:
                raise RuntimeErrorSafe("immutable runtime revision was altered")
            if not target.exists():
                _atomic(target, value)
        pki = self.pki_root / payload["network_id"]
        for subdir, filename in (("x509", "cert.pem"), ("private", "key.pem"), ("x509ca", "ca.pem"), ("x509crl", "crl.pem")):
            target = revision / subdir / filename
            if target.exists() and target.read_bytes() != (pki / filename).read_bytes():
                raise RuntimeErrorSafe("immutable runtime certificate revision was altered")
            if not target.exists():
                _atomic(target, (pki / filename).read_text())
        # Systemd's fixed instance templates read current; only our root code
        # may atomically redirect it to an immutable validated revision.
        current = network_dir / "current"
        temp_link = network_dir / ".current-next"
        temp_link.unlink(missing_ok=True)
        temp_link.symlink_to("revisions/" + digest)
        os.replace(temp_link, current)
        if site.get("transport", "ipsec") == "tls":
            for tunnel in site["tunnels"]:
                instance = "%s--%s" % (payload["network_id"], tunnel["id"])
                directory = self.state_root / "tls" / instance
                _private_directory(directory)
                link = directory / ".current-next"
                link.unlink(missing_ok=True)
                link.symlink_to(revision / "tls" / tunnel["id"])
                os.replace(link, directory / "current")
        self.runner.run([NFT, "--check", "-f", str(revision / "firewall.nft")])
        return revision

    def _undo(self, operations):
        failed = []
        for operation in reversed(operations):
            try:
                if not self._owned_present(operation):
                    continue
                result = self.runner.run(operation["undo"], check=False)
                if result["returncode"]:
                    failed.append("cleanup command failed: %s" % Path(operation["undo"][0]).name)
            except RuntimeErrorSafe as exc:
                failed.append(str(exc))
        return sorted(set(failed))

    def _owned_present(self, operation):
        """Prove an exact recorded resource exists before deletion; absent is safe."""
        undo = operation["undo"]
        if undo[0] == IP:
            links = self.runner.data([IP, "-j", "-d", "link", "show"])
            if operation.get("owner_name"):
                owners = [row for row in links if row.get("ifname") == operation["owner_name"]]
                if owners and owners[0].get("ifalias") != operation["owner_cookie"]:
                    raise RuntimeErrorSafe("XFRM ownership changed; cleanup refused")
            if operation["kind"] == "interface":
                matches = [row for row in links if row.get("ifname") == operation["name"]]
                if not matches:
                    return False
                if matches[0].get("ifalias") != operation["cookie"]:
                    raise RuntimeErrorSafe("interface ownership changed; cleanup refused")
            elif undo[1] in ("address", "link"):
                name = undo[undo.index("dev") + 1]
                if not any(row.get("ifname") == name for row in links):
                    return False
                if undo[1] == "address":
                    addresses = self.runner.data([IP, "-j", "address", "show", "dev", name])
                    value = ipaddress.ip_interface(undo[3])
                    if not any(a.get("local") == str(value.ip) and a.get("prefixlen") == value.network.prefixlen
                               for row in addresses for a in row.get("addr_info", [])):
                        return False
            elif undo[1] == "route":
                routes = self.runner.data([IP, "-j", "route", "show", "table", "all"])
                route_types = {"blackhole", "throw", "unreachable", "prohibit"}
                destination = undo[4] if undo[3] in route_types else undo[3]
                table = undo[undo.index("table") + 1] if "table" in undo else "main"
                matches = [r for r in routes if _same_route_destination(r.get("dst"), destination)
                           and str(r.get("table", "main")) in (table, "254" if table == "main" else table)]
                if not matches:
                    return False
                protocol = undo[undo.index("proto") + 1]
                if not any(str(r.get("protocol")) == protocol for r in matches):
                    raise RuntimeErrorSafe("route ownership changed; cleanup refused")
                metric = int(undo[undo.index("metric") + 1]) if "metric" in undo else 0
                gateway = undo[undo.index("via") + 1] if "via" in undo else None
                iface = undo[undo.index("dev") + 1] if "dev" in undo else None
                source = undo[undo.index("src") + 1] if "src" in undo else None
                route_type = undo[3] if undo[3] in route_types else "unicast"
                owned = [r for r in matches if str(r.get("protocol")) == protocol
                         and r.get("metric", 0) == metric and r.get("gateway") == gateway
                         and r.get("dev") == iface and r.get("prefsrc") == source
                         and r.get("type", "unicast") == route_type and not r.get("multipath")
                         and ("onlink" in r.get("flags", [])) == ("onlink" in undo)]
                if not owned:
                    label = "static route" if operation["kind"] == "static_route" else "route"
                    raise RuntimeErrorSafe("%s ownership changed; cleanup refused" % label)
            elif undo[1] == "rule":
                rules = self.runner.data([IP, "-j", "rule", "show"])
                priority = int(undo[undo.index("priority") + 1])
                table = undo[undo.index("table") + 1]
                matches = [r for r in rules if int(r.get("priority", -1)) == priority]
                if not matches:
                    return False
                if not any(str(r.get("table")) == table for r in matches):
                    raise RuntimeErrorSafe("policy rule ownership changed; cleanup refused")
                if operation["kind"] == "gateway_rule" and not any(
                        str(r.get("table")) == table
                        and _same_route_destination(
                            (r.get("src", "") + "/" + str(r["srclen"])) if "srclen" in r else r.get("src"),
                            operation["source_prefix"])
                        and r.get("iif") == operation["incoming_interface"]
                        and r.get("dst", "all") == "all"
                        and not set(r) - {"priority", "src", "srclen", "iif", "table", "dst", "protocol"}
                        for r in matches):
                    raise RuntimeErrorSafe("Internet Gateway policy rule ownership changed; cleanup refused")
        elif operation["kind"] == "firewall":
            tables = self.runner.data([NFT, "-j", "list", "tables"]).get("nftables", [])
            matches = [r["table"] for r in tables if r.get("table", {}).get("name") == operation["name"]
                       and r.get("table", {}).get("family") == "inet"]
            if not matches:
                return False
            details = self.runner.data([NFT, "-j", "list", "table", "inet", operation["name"]]).get("nftables", [])
            table = next((row["table"] for row in details if row.get("table", {}).get("name") == operation["name"]
                          and row.get("table", {}).get("family") == "inet"), {})
            comment = table.get("comment")
            if table and "comment" not in table:
                # nftables 1.0.6 omits table comments from JSON, although the
                # kernel stores them and native text reports them. Only that
                # omission may use the strict table-level text proof. A
                # reported but different cookie always remains a refusal.
                text = self.runner.run([NFT, "list", "table", "inet", operation["name"]])["stdout"]
                header = r"\Atable[ \t]+inet[ \t]+%s[ \t]*\{[ \t]*\n" % re.escape(operation["name"])
                match = re.match(header + r'[ \t]*comment[ \t]+("(?:[^"\\\n]|\\[^\n])*")[ \t]*;?[ \t]*\n', text)
                if match:
                    try:
                        comment = json.loads(match.group(1))
                    except ValueError:
                        comment = None
            if comment != operation["cookie"]:
                raise RuntimeErrorSafe("firewall table ownership changed; cleanup refused")
        return True

    def apply(self, payload, *, _restore=False):
        payload, identity, plan, site = self._compile(payload)
        self._mutation_generation(payload)
        with self._lock():
            previous_state = self._state(payload["network_id"])
            generation, previous = self._fence(payload, previous_state)
            if previous_state and generation == previous:
                if (previous_state.get("phase") == "configured"
                        and previous_state.get("payload_sha256") == self._payload_hash(payload)):
                    return {**self.status(payload), "applied": True, "idempotent": True}
                if not (_restore and previous_state.get("phase") == "disabled"):
                    raise RuntimeErrorSafe("operation generation cannot reactivate disabled or incomplete state")
            if previous_state.get("phase") in (None, "disabled"):
                # Fence even a readiness failure: an older SSH Apply must not
                # arrive later and activate a superseded desired operation.
                _atomic(self.state_root / payload["network_id"] / "state.json",
                        {"schema_version": 1, "network_id": payload["network_id"],
                         "device": identity["device"], "tenant": payload.get("tenant"),
                         "board_serial": identity["board_serial"],
                         "registration_id": payload.get("registration_id"), "generation": generation,
                         "phase": "disabled", "operations": [], "pending": None, "interfaces": [],
                         "updated": int(time.time())})
            preflight = self.preflight(payload)
            if not preflight["ready"]:
                return {**preflight, "ok": False}
            revision = self._revision(payload, plan, site, preflight)
            state_path = self.state_root / payload["network_id"] / "state.json"
            state = {"schema_version": 1, "network_id": payload["network_id"],
                     "device": identity["device"], "registration_id": payload.get("registration_id"),
                     "board_serial": identity["board_serial"],
                     "generation": generation, "payload_sha256": self._payload_hash(payload),
                     "tenant": payload.get("tenant"), "transport": site.get("transport", "ipsec"), "phase": "applying", "revision": revision.name,
                     "interfaces": self._reservations(site),
                     "operations": [], "pending": None, "updated": int(time.time())}
            _atomic(state_path, state)
            try:
                operations = self._commands(payload["network_id"], plan, site,
                                            preflight["sources"], preflight["gateways"], revision,
                                            mtus=preflight.get("mtus"), endpoint_routes=preflight.get("endpoint_routes"))
                for operation in operations:
                    state["pending"] = operation
                    _atomic(state_path, state)
                    self.runner.run(operation["argv"])
                    if operation["kind"] == "interface_alias" and not self._owned_present(operation):
                        raise RuntimeErrorSafe("interface ownership cookie was not installed")
                    state["operations"].append(operation)
                    state["pending"] = None
                    _atomic(state_path, state)
                state["phase"] = "configured"
                _atomic(state_path, state)
            except RuntimeErrorSafe as exc:
                # A timed-out command may already have changed the kernel.
                # Inspect its exact owned pending resource as part of rollback.
                rollback = state["operations"] + ([state["pending"]] if state["pending"] else [])
                errors = self._undo(rollback)
                state.update(phase="cleanup_required" if errors else "disabled", pending=state["pending"] if errors else None,
                             errors=[str(exc)] + errors, updated=int(time.time()))
                if not errors:
                    state["operations"] = []
                _atomic(state_path, state)
                return {"ok": False, "ready": False, "state": state["phase"], "errors": state["errors"]}
        status = self.status(payload)
        status["ok"] = True
        status["applied"] = True
        return status

    def disable(self, payload):
        payload, identity, _plan, _site = self._compile(payload)
        self._mutation_generation(payload)
        if self._migration_errors():
            return {"ok": False, "state": "not_ready", "errors": self._migration_errors()}
        with self._lock():
            state_path = self.state_root / payload["network_id"] / "state.json"
            state = self._state(payload["network_id"])
            generation, _previous = self._fence(payload, state)
            if not state or state.get("phase") == "disabled":
                # A durable tombstone fences an SSH apply that arrives after a
                # newer Disable, including when no activation ever reached us.
                state = {"schema_version": 1, "network_id": payload["network_id"],
                         "device": identity["device"], "tenant": payload.get("tenant"),
                         "board_serial": identity["board_serial"],
                         "registration_id": payload.get("registration_id"), "generation": generation,
                         "phase": "disabled", "operations": [], "pending": None, "interfaces": [],
                         "updated": int(time.time())}
                _atomic(state_path, state)
                return {"ok": True, "state": "disabled", "errors": []}
            if any(state.get(key) != value for key, value in (("device", identity["device"]),
                   ("tenant", payload.get("tenant")), ("registration_id", payload.get("registration_id")))):
                raise RuntimeErrorSafe("cleanup identity does not match the applied registration")
            state.update(phase="disabling", generation=generation)
            _atomic(state_path, state)
            operations = state.get("operations", []) + ([state["pending"]] if state.get("pending") else [])
            errors = self._undo(operations)
            state.update(phase="cleanup_required" if errors else "disabled", errors=errors, updated=int(time.time()))
            if not errors:
                state["operations"] = []
                state["pending"] = None
            _atomic(state_path, state)
            return {"ok": not errors, "state": state["phase"], "errors": errors}

    def _tls_connected(self, network_id, tunnel, deadline):
        instance = "%s--%s" % (network_id, tunnel["id"])
        path = TLS_RUN / instance / "management.sock"
        try:
            for parent in (TLS_RUN, path.parent):
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o022 if parent == TLS_RUN else 0o077):
                    return False
            info = path.lstat()
            # OpenVPN intentionally chmods UNIX sockets to 0777. The root-
            # private parent plus kernel peer-credential checks protect access.
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(min(0.2, remaining))
                connection.connect(str(path))
                connection.sendall(b"state\n")
                data = b""
                while len(data) < 65536 and time.monotonic() < deadline:
                    connection.settimeout(min(0.2, max(0.001, deadline - time.monotonic())))
                    part = connection.recv(min(4096, 65536 - len(data)))
                    if not part:
                        break
                    data += part
                    if b"END" in data.splitlines():
                        break
                if b"END" not in data.splitlines():
                    return False
                # Unsolicited >STATE notifications are never current-state proof.
                rows = [line.split(",") for line in data.decode("ascii", "replace").splitlines()
                        if re.match(r"^[0-9]+,", line)]
                return len(rows) == 1 and rows[0][1:3] == ["CONNECTED", "SUCCESS"]
        except (OSError, ValueError, IndexError):
            return False

    def status(self, payload):
        payload, identity, _plan, site = self._compile(payload)
        try:
            state = self._state(payload["network_id"])
        except RuntimeErrorSafe:
            return {"ok": True, "state": "unknown", "ready": False,
                    "errors": ["root-helper status is required to observe private runtime state"]}
        if not state or state.get("phase") == "disabled":
            return {"ok": True, "state": "disabled", "ready": False, "network_id": payload["network_id"],
                    "device": identity["device"], "tunnels": [], "established": False, "errors": []}
        if any(state.get(key) is not None and state[key] != value for key, value in
               (("device", identity["device"]), ("tenant", payload.get("tenant")),
                ("registration_id", payload.get("registration_id")))):
            return {"ok": False, "state": "identity_mismatch", "ready": False, "established": False,
                    "errors": ["applied runtime belongs to a different device registration"]}
        if state.get("transport", "ipsec") != site.get("transport", "ipsec"):
            return {"ok": False, "state": "configuration_mismatch", "ready": False, "established": False,
                    "errors": ["applied transport differs from the requested configuration"]}
        errors, ipsec, peers = [], set(), {}
        tls = site.get("transport", "ipsec") == "tls"
        if not tls:
            try:
                data = self.runner.run([SWANCTL, "--list-sas", "--raw", "--uri",
                                        "unix:///run/console-overlay/%s/charon.vici" % payload["network_id"]])["stdout"]
                ipsec = established_children(data)
            except RuntimeErrorSafe:
                errors.append("IPsec state could not be observed")
        else:
            wrapper = "console-overlay-stunnel@%s.service" % payload["network_id"]
            wrapper_active = self.runner.run([SYSTEMCTL, "is-active", wrapper], check=False)["stdout"].strip() == "active"
            deadline = time.monotonic() + 2
            if not wrapper_active:
                errors.append("TLS wrapper is not active")
        try:
            summary = self.runner.data([VTYSH, "-N", "csd-" + payload["network_id"], "-c", "show bgp ipv4 unicast summary json"])
            peers = summary.get("ipv4Unicast", summary).get("peers", {})
        except (RuntimeErrorSafe, AttributeError):
            errors.append("BGP state could not be observed")
        rows = []
        for tunnel in site["tunnels"]:
            peer = peers.get(tunnel["peer_address"], {})
            encrypted = ("established" if wrapper_active and self._tls_connected(payload["network_id"], tunnel, deadline) else "down") if tls else ("established" if str(tunnel["id"]) + "-data" in ipsec else "unknown" if errors else "down")
            rows.append({"id": tunnel["id"], "peer": tunnel.get("peer"), "interface": tunnel["if_name"],
                         "tunnel": encrypted, ("tls" if tls else "ipsec"): encrypted,
                         "bgp": peer.get("state", "unknown" if errors else "down"),
                         "prefixes_received": peer.get("pfxRcd", 0), "uplink": tunnel["local_uplink"]})
        established = sum(row["tunnel"] == "established" and row["bgp"] == "Established" for row in rows)
        phase = state.get("phase", "unknown")
        fully_established = phase == "configured" and bool(rows) and established == len(rows)
        if phase == "configured":
            phase = "established" if rows and established == len(rows) else "degraded" if established else "connecting"
        return {"ok": True, "state": phase, "transport": "tls" if tls else "ipsec", "ready": fully_established, "network_id": payload["network_id"],
                "device": identity["device"], "tunnels": rows, "established": fully_established,
                "established_count": established, "total_count": len(rows), "errors": errors}

    def restore(self):
        """Private boot entry: replay only root-owned saved desired state."""
        if os.geteuid() != 0 or self._migration_errors():
            raise RuntimeErrorSafe("boot restoration requires the immutable approved migration")
        with self._lock():
            return self._restore_locked()

    def _restore_locked(self):
        results = []
        if self.state_root.exists():
            for directory in self.state_root.iterdir():
                if not directory.is_dir() or not NETWORK_RE.fullmatch(directory.name):
                    continue
                state = self._state(directory.name)
                if not state or state.get("phase") == "disabled":
                    continue
                revision = state.get("revision", "")
                if not re.fullmatch(r"[0-9a-f]{64}", revision):
                    raise RuntimeErrorSafe("saved revision identity is invalid")
                source = directory / "revisions" / revision / "request.json"
                if not _root_file(source, private=True):
                    raise RuntimeErrorSafe("saved boot configuration is not root-private")
                payload = _request(_json(source))
                payload["generation"] = state.get("generation", 0)
                self._mutation_generation(payload)
                disabled = self.disable(payload)
                result = self.apply(payload, _restore=True) if disabled["ok"] else disabled
                if disabled["ok"] and not result["ok"]:
                    current = self._state(directory.name)
                    if current.get("phase") == "disabled":
                        # DHCP or the modem may become usable after
                        # network-online.target. Keep desired state for the
                        # fixed boot unit's bounded retry rather than losing it.
                        current.update(phase="restore_pending", revision=revision,
                                       errors=result.get("errors", []), updated=int(time.time()))
                        _atomic(directory / "state.json", current)
                results.append(result)
        return {"ok": all(result["ok"] for result in results), "networks": results}


def established_children(raw):
    """Read swanctl --raw nested VICI output without accepting IKE-only health."""
    # VICI swanctl raw prints a nested brace tree. Track CHILD contexts: an
    # ESTABLISHED IKE alone is insufficient; CHILD must actually be INSTALLED.
    tokens = re.findall(r"[{}]|[^\s{}=]+\s*=\s*[^\s{}]+|[^\s{}=]+", raw)
    stack, installed = [], set()
    pending = None
    for token in tokens:
        token = token.strip()
        if token == "{":
            stack.append({"label": pending or ""})
            pending = None
        elif token == "}":
            if stack:
                frame = stack.pop()
                if frame.get("state") == "INSTALLED" and any(item["label"] == "child-sas" for item in stack) and frame.get("name"):
                    installed.add(frame["name"])
        elif "=" in token:
            key, value = [item.strip() for item in token.split("=", 1)]
            if stack and key in ("state", "name"):
                stack[-1][key] = value
        else:
            pending = token
    return installed


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv == ["restore"]:
            result = Runtime().restore()
            print(json.dumps(result, separators=(",", ":")))
            return 0 if result["ok"] else 1
        if argv == ["guard"]:
            result = Runtime().guard()
            print(json.dumps(result, separators=(",", ":")))
            return 0 if result["ok"] else 1
        credential_verbs = {"credentials-status", "credentials-csr", "credentials-install"}
        if len(argv) != 1 or argv[0] not in {"status", "preflight", "apply", "disable"} | credential_verbs:
            raise RuntimeErrorSafe("expected exactly one action: status, preflight, apply or disable")
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise RuntimeErrorSafe("request exceeded limit")
        try:
            payload = json.loads(data)
        except ValueError as exc:
            raise RuntimeErrorSafe("request must be JSON on stdin") from exc
        if argv[0] in credential_verbs:
            from overlay_enrollment import Enrollment
            result = Enrollment(Runtime()).dispatch(argv[0], payload)
        else:
            result = getattr(Runtime(), argv[0])(_request(payload))
    except RuntimeErrorSafe as exc:
        result = {"ok": False, "ready": False, "state": "error", "errors": [str(exc)]}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {"ok": False, "ready": False, "state": "error", "errors": ["runtime validation or state operation failed"]}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
