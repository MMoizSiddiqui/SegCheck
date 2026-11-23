"""Validated inventory configuration without discovery scans or network changes."""
import copy
import ipaddress
import re
import socket

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError

from segcheck_web.extensions import db
from segcheck_web.models import Zone, Asset
from segcheck_web.models.environment import EnvironmentSettings


class EnvironmentError(ValueError):
    pass


def field(form, name, maximum=160, required=True):
    values = form.getlist(name)
    if len(values) > 1 or (required and len(values) != 1):
        raise EnvironmentError(f"Supply exactly one {name.replace('_', ' ')}.")
    value = values[0].strip() if values else ""
    if (required and not value) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise EnvironmentError(f"Invalid {name.replace('_', ' ')}.")
    return value


def literal_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise EnvironmentError("Enter a literal IPv4 or IPv6 address.") from exc
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
        raise EnvironmentError("Use a unicast network address outside loopback and link-local ranges.")
    return str(address)


def settings():
    record = db.session.get(EnvironmentSettings, 1)
    return record, copy.deepcopy(record.payload) if record else {"networks": {}}


def _commit():
    try:
        db.session.commit()
    except (IntegrityError, StaleDataError) as exc:
        db.session.rollback()
        raise EnvironmentError("Configuration changed or conflicts with an existing record. Reload and retry.") from exc


def _save_settings(record, payload, form):
    revision = field(form, "revision", 10)
    if revision != str(record.revision if record else 0):
        raise EnvironmentError("Configuration changed. Reload before saving.")
    if record:
        record.payload = payload
    else:
        db.session.add(EnvironmentSettings(id=1, payload=payload))


def save_zone(form):
    key = field(form, "zone_key", 32)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,31}", key):
        raise EnvironmentError("Zone keys use 2–32 letters, numbers, underscores or hyphens, starting with a letter.")
    name = field(form, "name", 120)
    role = field(form, "role", 16, required=False) or "custom"
    if role not in {"guest", "corporate", "hr", "cde", "dmz", "server", "untrusted", "management", "custom"}:
        raise EnvironmentError("Choose a supported zone role.")
    try:
        network = ipaddress.ip_network(field(form, "cidr", 64), strict=True)
    except ValueError as exc:
        raise EnvironmentError("Enter a subnet with its network address, such as 10.20.0.0/24.") from exc
    if network.prefixlen == 0 or network.is_multicast or network.is_loopback or network.is_link_local:
        raise EnvironmentError("Use a specific unicast network subnet.")
    gateway = field(form, "gateway", 45, required=False)
    if gateway:
        gateway = literal_ip(gateway)
        if ipaddress.ip_address(gateway) not in network:
            raise EnvironmentError("Gateway must belong to the zone subnet.")
    record, payload = settings()
    for other_key, other in payload["networks"].items():
        other_network = ipaddress.ip_network(other["cidr"])
        if other_key != key and other_network.version == network.version and other_network.overlaps(network):
            raise EnvironmentError("Zone subnets must not overlap; separate routing domains are not supported yet.")
    zone = db.session.query(Zone).filter_by(zone_key=key).one_or_none()
    if zone is None:
        if db.session.query(Zone).count() >= 100:
            raise EnvironmentError("The installation supports at most 100 inventory zones.")
        zone = Zone(zone_key=key, name=name)
        db.session.add(zone)
    # Existing asset and source assignments must remain valid after a subnet edit.
    for asset in zone.assets:
        if ipaddress.ip_address(asset.address) not in network:
            raise EnvironmentError("The new subnet excludes an existing asset.")
    if payload.get("source_zone") == key and ipaddress.ip_address(payload["source_ip"]) not in network:
        raise EnvironmentError("The new subnet excludes the configured local probe address.")
    zone.name = name
    payload["networks"][key] = {"cidr": str(network), "gateway": gateway, "role": role}
    _save_settings(record, payload, form)
    _commit()


def save_asset(form):
    key = field(form, "zone_key", 32)
    zone = db.session.query(Zone).filter_by(zone_key=key).one_or_none()
    _, payload = settings()
    config = payload["networks"].get(key)
    if zone is None or config is None:
        raise EnvironmentError("Configure the target zone and subnet first.")
    address = literal_ip(field(form, "address", 45))
    if ipaddress.ip_address(address) not in ipaddress.ip_network(config["cidr"]):
        raise EnvironmentError("Asset address must belong to its zone subnet.")
    name = field(form, "name", 160)
    asset_id = field(form, "asset_id", 10, required=False)
    if asset_id:
        if not re.fullmatch(r"[1-9][0-9]{0,9}", asset_id):
            raise EnvironmentError("Invalid asset identifier.")
        asset = db.session.get(Asset, int(asset_id))
        if asset is None:
            raise EnvironmentError("Asset not found.")
    else:
        if db.session.query(Asset).count() >= 1000:
            raise EnvironmentError("The installation supports at most 1000 inventory assets.")
        asset = Asset()
        db.session.add(asset)
    asset.name, asset.address, asset.zone_id = name, address, zone.id
    _commit()


def save_profile(form):
    record, payload = settings()
    source_zone = field(form, "source_zone", 32)
    config = payload["networks"].get(source_zone)
    if config is None:
        raise EnvironmentError("Configure the local probe's zone first.")
    source_ip = literal_ip(field(form, "source_ip", 45))
    if ipaddress.ip_address(source_ip) not in ipaddress.ip_network(config["cidr"]):
        raise EnvironmentError("The probe address must belong to its assigned zone subnet.")
    payload.update(organization=field(form, "organization"), site=field(form, "site"),
                   source_zone=source_zone, source_ip=source_ip)
    _save_settings(record, payload, form)
    _commit()


def source_address_available(source_ip):
    """Check that the OS accepts a local bind; never transmit a packet."""
    try:
        address = ipaddress.ip_address(source_ip)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.bind((source_ip, 0))
        return True
    except (OSError, ValueError):
        return False


def local_addresses():
    """This computer's own unicast addresses (no packet is sent)."""
    found = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
    except OSError:
        infos = []
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0].split("%")[0])
        except ValueError:
            continue
        if not (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast):
            if str(address) not in found:
                found.append(str(address))
    return found


def zone_for(addresses):
    """(zone_key, address) for the most specific configured zone containing one of the addresses."""
    _, environment = settings()
    best = None
    for rank, address in enumerate(addresses):
        ip = ipaddress.ip_address(address)
        for key, network in environment.get("networks", {}).items():
            try:
                subnet = ipaddress.ip_network(network.get("cidr", ""))
            except ValueError:
                continue
            if ip.version == subnet.version and ip in subnet:
                score = (subnet.prefixlen, -rank)  # most specific subnet first
                if best is None or score > best[0]:
                    best = (score, key, address)
    return (best[1], best[2]) if best else (None, None)


def this_machine():
    """Where this PC sits: its addresses and the department (zone) whose subnet contains one of them."""
    record, payload = settings()
    addresses = local_addresses()
    zone, address = zone_for(addresses)
    current = payload.get("source_ip")
    return {"addresses": addresses, "zone": zone, "address": address,
            "zone_name": (db.session.query(Zone.name).filter_by(zone_key=zone).scalar() if zone else None),
            "current_here": bool(current) and source_address_available(current),
            "revision": record.revision if record else 0}


def use_this_machine(form):
    """Make this computer the probe: its address and the zone whose subnet contains it."""
    record, payload = settings()
    position = this_machine()
    if position["zone"] is None:
        shown = ", ".join(position["addresses"]) or "none found"
        raise EnvironmentError(f"None of this PC's addresses ({shown}) is inside a configured zone. "
                               "Add this department's subnet as a zone first.")
    from werkzeug.datastructures import MultiDict
    save_profile(MultiDict({"organization": payload.get("organization") or "Not configured",
                            "site": payload.get("site") or "Not configured",
                            "source_zone": position["zone"], "source_ip": position["address"],
                            "revision": field(form, "revision", 10)}))
    return position


DEVICE_KINDS = {
    "pfsense": "pfSense / OPNsense firewall (filterlog syslog)",
    "iptables": "Linux iptables / nftables firewall (kernel LOG syslog)",
    "fortigate": "Fortinet FortiGate (FortiOS traffic log syslog)",
    "cisco": "Cisco ASA / Firepower Threat Defense (syslog)",
    "sophos": "Sophos Firewall / XG (syslog)",
    "mikrotik": "MikroTik RouterOS (firewall topic syslog)",
    "other": "Other firewall or router (no log parser)",
    "none": "No enforcing device / unknown (records a limitation)",
}
MAX_DEVICES = 20
MAX_OTHER_ADDRESSES = 16
LOG_KINDS = {"pfsense", "iptables", "fortigate", "cisco", "sophos", "mikrotik"}  # firewalls whose logs SegCheck reads


def save_device(form):
    """Declare a boundary device between zones; optional read-only syslog feed."""
    record, payload = settings()
    devices = list(payload.get("devices", []))
    name = field(form, "name", 80)
    kind = field(form, "kind", 16)
    if kind not in DEVICE_KINDS:
        raise EnvironmentError("Choose a supported boundary device type.")
    zones = form.getlist("zones")
    networks = payload.get("networks", {})
    if len(zones) < 2 or len(set(zones)) != len(zones) or any(zone not in networks for zone in zones):
        raise EnvironmentError("Select at least two configured zones that this device separates.")
    interface_ip = field(form, "interface_ip", 45, required=False)
    if interface_ip:
        interface_ip = literal_ip(interface_ip)
        if not any(ipaddress.ip_address(interface_ip) in ipaddress.ip_network(networks[zone]["cidr"]) for zone in zones):
            raise EnvironmentError("The interface IP must belong to one of the selected zones' subnets.")
    # The device's own addresses in the other networks (management-plane targets only; never used for logs).
    other_ips = []
    for raw in form.getlist("other_ips")[:MAX_OTHER_ADDRESSES + 1]:
        address = literal_ip(raw)
        if not any(ipaddress.ip_address(address) in ipaddress.ip_network(networks[zone]["cidr"]) for zone in zones):
            raise EnvironmentError(f"{address} is not inside any of the networks this firewall separates.")
        if address != interface_ip and address not in other_ips:
            other_ips.append(address)
    if len(other_ips) > MAX_OTHER_ADDRESSES:
        raise EnvironmentError(f"At most {MAX_OTHER_ADDRESSES} other firewall addresses are supported.")
    logging_enabled = field(form, "logging", 3, required=False) == "on"
    sender_ip, log_port, listen_ip = "", 0, ""
    if logging_enabled:
        if kind not in LOG_KINDS:
            raise EnvironmentError("Log collection is available for pfSense/OPNsense, Linux, FortiGate, Cisco ASA/FTD, "
                                   "Sophos and MikroTik firewalls.")
        # Empty sender = learn it: the first address that sends a recognised firewall log is used.
        sender_ip = field(form, "log_sender_ip", 45, required=False)
        sender_ip = literal_ip(sender_ip) if sender_ip else ""
        raw_port = field(form, "log_port", 5)
        if not raw_port.isdigit() or not 1024 <= int(raw_port) <= 65535:
            raise EnvironmentError("Use a log port between 1024 and 65535 (no administrator rights needed), e.g. 5514.")
        log_port = int(raw_port)
        listen_ip = field(form, "log_listen_ip", 45, required=False)
        if listen_ip:
            listen_ip = literal_ip(listen_ip)
            if not source_address_available(listen_ip):
                raise EnvironmentError("The listen address must be an address of this PC (see ipconfig). Leave it empty to use this PC's probe address.")
        if any(other.get("logging") and other.get("log_port") == log_port and other["id"] != _device_id(name) for other in devices):
            raise EnvironmentError("Another device already uses that log port.")
    device_id = _device_id(name)
    replacing = field(form, "device_id", 40, required=False)
    devices = [device for device in devices if device["id"] not in {device_id, replacing}]
    if len(devices) >= MAX_DEVICES:
        raise EnvironmentError(f"At most {MAX_DEVICES} boundary devices are supported.")
    devices.append({"id": device_id, "name": name, "kind": kind, "zones": zones, "interface_ip": interface_ip,
                    "other_ips": other_ips, "logging": logging_enabled, "log_sender_ip": sender_ip, "log_port": log_port,
                    "log_listen_ip": listen_ip})
    payload["devices"] = sorted(devices, key=lambda item: item["name"].lower())
    _save_settings(record, payload, form)
    _commit()
    _remove_interface_assets(name)  # addresses removed from the form must stop being tested
    for address in ([interface_ip] if interface_ip else []) + other_ips:
        _register_interface_asset(name, address, zones, networks)


def delete_device(form):
    record, payload = settings()
    device_id = field(form, "device_id", 40)
    payload_before = list(payload.get("devices", []))
    devices = [device for device in payload.get("devices", []) if device["id"] != device_id]
    if len(devices) == len(payload.get("devices", [])):
        raise EnvironmentError("Device not found.")
    payload["devices"] = devices
    _save_settings(record, payload, form)
    _commit()
    for device in payload_before:
        if device["id"] == device_id:
            _remove_interface_assets(device["name"])


def _device_id(name):
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:32]
    if not slug:
        raise EnvironmentError("Give the device a name with letters or numbers.")
    return slug


def is_device_address(asset_name):
    """Assets named '<device> interface' are a firewall's own addresses, not systems in that network."""
    return asset_name.endswith(" interface")


def register_device_address(name, address, zones, networks):
    _register_interface_asset(name, address, zones, networks)


def _remove_interface_assets(device_name):
    for asset in db.session.query(Asset).filter_by(name=f"{device_name} interface").all():
        db.session.delete(asset)
    _commit()


def _register_interface_asset(name, address, zones, networks):
    """Make the device interface a registered target so management-plane checks can run."""
    zone_key = next(zone for zone in zones if ipaddress.ip_address(address) in ipaddress.ip_network(networks[zone]["cidr"]))
    zone = db.session.query(Zone).filter_by(zone_key=zone_key).one_or_none()
    if zone is None or db.session.query(Asset).filter_by(address=address, zone_id=zone.id).first():
        return
    db.session.add(Asset(name=f"{name} interface", address=address, zone_id=zone.id))
    _commit()


def boundary_gaps(payload, source_zone, destination_zones):
    """Cross-zone paths that have no declared boundary device (blocking)."""
    devices = payload.get("devices", [])
    return sorted({destination for destination in destination_zones if destination != source_zone and not any(
        source_zone in device.get("zones", []) and destination in device.get("zones", []) for device in devices)})


def delete_zone(form):
    """Remove a zone with its hosts; devices stop listing it. The probe's own zone cannot be removed."""
    record, payload = settings()
    key = field(form, "zone_key", 32)
    if key == payload.get("source_zone"):
        raise EnvironmentError("This is the network SegCheck runs from. Change it in Step 1 instead.")
    zone = db.session.query(Zone).filter_by(zone_key=key).one_or_none()
    if zone is None and key not in payload.get("networks", {}):
        raise EnvironmentError("That network no longer exists.")
    if zone is not None:
        for asset in list(zone.assets):
            db.session.delete(asset)
        db.session.flush()
        db.session.delete(zone)
    payload.get("networks", {}).pop(key, None)
    for device in payload.get("devices", []):
        device["zones"] = [z for z in device.get("zones", []) if z != key]
    _save_settings(record, payload, form)
    _commit()


def delete_asset(form):
    asset_id = field(form, "asset_id", 10)
    if not re.fullmatch(r"[1-9][0-9]{0,9}", asset_id):
        raise EnvironmentError("Invalid host identifier.")
    asset = db.session.get(Asset, int(asset_id))
    if asset is None:
        raise EnvironmentError("That host no longer exists.")
    db.session.delete(asset)
    _commit()
