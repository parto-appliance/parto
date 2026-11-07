#!/usr/bin/env python3
"""Per-import virtual appliance identity and a fail-closed copied-disk guard.

The OVA contains no instance, pre-stage or estate identity. Its first boot
mints a random instance UUID, binds it to the hypervisor's SMBIOS UUID, and then
asks the management bootstrap API for a serial and pre-stage credential. Reboots
keep the serial. A copied initialized disk must not call home or start OVERLAY
under the source instance's credentials: a changed UUID creates a persistent
hold, without rewriting any identity or removing any credential.

Hypervisors must supply a unique SMBIOS UUID when importing each clean OVA.
Clones that deliberately preserve their source UUID cannot be distinguished by
guest firmware; they are unsupported. The image's service gates all tunnels on
this check. Runtime helpers also check the binding before applying VM OVERLAY.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import uuid


UUID_PATH = "/sys/class/dmi/id/product_uuid"
IDENTITY_PATH = "/etc/parto/vm-instance.json"
HOLD_PATH = "/etc/parto/vm-identity-hold.json"
DETAIL_PATH = "/etc/parto/device.json"
LOCK_PATH = "/var/lib/parto/vm-identity.lock"
_SERIAL = re.compile(r"[0-9a-f]{16}\Z")
_EXISTING_IDENTITY = (
    DETAIL_PATH,
    "/home/overlay/BootScript/manifest.json",
    "/etc/krb5.keytab",
    "/etc/openvpn/client/prestage.conf",
    "/etc/openvpn/prestage.conf",
    "/etc/parto/prestage",
    "/etc/parto/overlay-pki",
    "/etc/pki/tls/private/vm-bootstrap.pem",
    "/var/lib/parto/vm-bootstrap-request.json",
)


class IdentityError(RuntimeError):
    """A bounded, credential-free operator error."""


def _at(root, path):
    return Path(root) / path.lstrip("/")


def _json(path):
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        raise IdentityError("VM identity file is unreadable or invalid") from None
    if not isinstance(data, dict):
        raise IdentityError("VM identity file must contain an object")
    return data


def _trusted_file(path):
    """Root-owned in the installed guest, and never a symlink or group writable.

    Tests can use a non-root temporary tree; the service and CLI require root,
    and the privileged OVERLAY helper separately requires root ownership.
    """
    try:
        info = path.lstat()
        return (path.is_file() and not path.is_symlink()
                and not info.st_mode & 0o022
                and info.st_uid == os.geteuid())
    except OSError:
        return False


def _uuid(value):
    try:
        parsed = uuid.UUID(str(value).strip())
    except (ValueError, AttributeError):
        raise IdentityError("hypervisor SMBIOS UUID is missing or invalid") from None
    if parsed.int in (0, (1 << 128) - 1):
        raise IdentityError("hypervisor SMBIOS UUID is not unique")
    return str(parsed)


def hypervisor_uuid(path=UUID_PATH):
    try:
        value = Path(path).read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise IdentityError("hypervisor SMBIOS UUID is unavailable") from None
    return _uuid(value)


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".%s-" % path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o644)
            json.dump(data, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def check(root="/", *, current_uuid=None):
    """Return the existing identity only if its firmware binding still matches.

    This never initializes, repairs, rotates or clears a hold. Restoring an old
    UUID alone does not clear a previously detected clone incident.
    """
    if _at(root, HOLD_PATH).exists():
        raise IdentityError("VM identity is on hold; review the clone/import before recovery")
    path = _at(root, IDENTITY_PATH)
    if not _trusted_file(path):
        raise IdentityError("VM instance identity is missing or not trusted")
    state = _json(path)
    serial = state.get("serial")
    if (state.get("schema_version") != 1 or state.get("model") != "vm"
            or not isinstance(serial, str)
            or (serial and not _SERIAL.fullmatch(serial))):
        raise IdentityError("VM instance identity is invalid")
    _uuid(state.get("instance_id"))
    recorded = _uuid(state.get("hypervisor_uuid"))
    observed = _uuid(current_uuid) if current_uuid is not None else hypervisor_uuid(
        _at(root, UUID_PATH))
    if recorded != observed:
        raise IdentityError("initialized VM disk was copied to a different hypervisor UUID")
    detail = _at(root, DETAIL_PATH)
    if detail.exists():
        if not _trusted_file(detail):
            raise IdentityError("VM pre-stage assembly identity is not trusted")
        assembled = _json(detail)
        if assembled.get("serial") != serial or assembled.get("model") != "vm":
            raise IdentityError("VM assembly identity differs from the instance binding")
    return state


def ensure(root="/", *, current_uuid=None):
    """Initialize a clean imported template once, or verify an existing guest.

    Existing credentials without their instance record are an incident, not a
    blank template. A failed check records a hold and leaves all identity bytes
    intact for investigation. This function does not contact management.
    """
    lock_path = _at(root, LOCK_PATH)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            if _at(root, HOLD_PATH).exists():
                raise IdentityError("VM identity is on hold; review the clone/import before recovery")
            observed = _uuid(current_uuid) if current_uuid is not None else hypervisor_uuid(
                _at(root, UUID_PATH))
            path = _at(root, IDENTITY_PATH)
            if not path.exists() and not path.is_symlink():
                if any(_at(root, name).exists() for name in _EXISTING_IDENTITY):
                    raise IdentityError("existing appliance credentials have no VM instance binding")
                instance = uuid.uuid4()
                _write(path, {"schema_version": 1, "model": "vm",
                              "instance_id": str(instance), "serial": "",
                              "hypervisor_uuid": observed,
                              "created_at": int(time.time())})
            return check(root, current_uuid=observed)
        except IdentityError as exc:
            hold = _at(root, HOLD_PATH)
            if not hold.exists():
                _write(hold, {"schema_version": 1, "reason": str(exc),
                              "detected_at": int(time.time()),
                              "recovery": "Import the clean OVA as a new VM. Keep this disk for review; "
                                          "do not remove credentials or regenerate its identity."})
            raise


def bind_serial(serial, root="/", *, current_uuid=None):
    """Adopt management's serial once without changing the local instance UUID.

    A retry may return the same serial. A different serial on an initialized VM
    is never adopted; root bootstrap must keep its original private key and use
    management's idempotent enrollment lookup.
    """
    if not isinstance(serial, str) or not _SERIAL.fullmatch(serial):
        raise IdentityError("management assigned an invalid VM serial")
    lock_path = _at(root, LOCK_PATH)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = check(root, current_uuid=current_uuid)
        if state["serial"]:
            if state["serial"] != serial:
                raise IdentityError("management serial differs from this VM's existing identity")
            return state
        if _at(root, DETAIL_PATH).exists():
            raise IdentityError("assembled VM cannot adopt another serial")
        state["serial"] = serial
        state["serial_assigned_at"] = int(time.time())
        _write(_at(root, IDENTITY_PATH), state)
        return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("ensure", "check"))
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("VM identity guard must run as root", file=sys.stderr)
        return 1
    try:
        state = ensure() if args.action == "ensure" else check()
    except IdentityError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(state, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
