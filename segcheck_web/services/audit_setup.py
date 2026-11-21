"""The guided audit: Step 1 where you are, Step 2 targets, Step 3 firewall, Step 4 checks, launch.

Everything is stored in the normal environment settings (zones, hosts, boundary device), so reports
keep the same structure and evidence. These helpers only make each step one simple action.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import socket
from datetime import datetime

import yaml
from werkzeug.datastructures import MultiDict

from segcheck_web.extensions import db
from segcheck_web.models import Asset, Zone
from segcheck_web.services import environment as env
from segcheck_web.services.environment import EnvironmentError, settings

# Plain-language network types; each maps to a zone role used by the standards (PCI scope etc.).
NETWORK_TYPES = {
    "corporate": "Office / staff PCs",
    "guest": "Guest or visitor Wi-Fi",
    "dmz": "DMZ / public-facing servers",
    "cde": "Card data environment (CDE, PCI scope)",
    "server": "Internal servers",
    "hr": "HR / personal data",
    "untrusted": "Internet, partners or VPN",
    "custom": "Other",
}

# Step 4 "own rules": services a person can pick without knowing ports.
SERVICES = {
    "web": ("Web (HTTP/HTTPS)", "tcp", [80, 443]),
    "rdp": ("Remote Desktop", "tcp", [3389]),
    "ssh": ("SSH", "tcp", [22]),
    "admin": ("Any remote admin (SSH, Telnet, RDP, VNC, WinRM)", "tcp", [22, 23, 3389, 5900, 5985, 5986]),
    "db": ("Databases (SQL Server, Oracle, MySQL, PostgreSQL, Redis, MongoDB)", "tcp", [1433, 1521, 3306, 5432, 6379, 27017]),
    "files": ("File sharing (SMB, NFS)", "tcp", [139, 445, 2049]),
    "ldap": ("Directory (LDAP)", "tcp", [389, 636]),
    "dns": ("DNS", "udp", [53]),
    "snmp": ("SNMP", "udp", [161]),
    "ping": ("Ping (ICMP)", "icmp", []),
    "windows": ("Windows domain (Kerberos, RPC, LDAP, SMB, Global Catalog)", "tcp", [88, 135, 389, 445, 636, 3268]),
    "email": ("Email (SMTP, POP3, IMAP and their TLS ports)", "tcp", [25, 110, 143, 465, 587, 993, 995]),
    "print": ("Printing (LPD, IPP, raw 9100)", "tcp", [515, 631, 9100]),
    "webalt": ("Web admin / alternate web ports", "tcp", [8000, 8008, 8080, 8443, 8888, 9443]),
}

DEFAULT_LOG_PORT = 5514


def _form(**values):
    record, _ = settings()
    data = MultiDict()
    for key, value in values.items():
        for item in value if isinstance(value, (list, tuple)) else [value]:
            data.add(key, "" if item is None else str(item))
    data["revision"] = str(record.revision if record else 0)
    return data


def _slug(name, taken):
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    base = base if base and base[0].isalpha() else f"net-{base}".strip("-")
    base = (base or "net")[:28]
    if len(base) < 2:
        base = f"{base}-net"
    key, number = base, 2
    while key in taken:
        key, number = f"{base[:26]}-{number}", number + 1
    return key


def state():
    """Everything the audit page shows: where you are, targets with hosts, firewall, readiness."""
    record, payload = settings()
    networks = payload.get("networks", {})
    zones = {zone.zone_key: zone for zone in db.session.query(Zone).all()}
    source = payload.get("source_zone")
    targets = []
    for key, network in networks.items():
        if key == source:
            continue
        zone = zones.get(key)
        hosts = sorted(zone.assets, key=lambda a: ipaddress.ip_address(a.address)) if zone else []
        targets.append({"key": key, "name": zone.name if zone else key, "cidr": network["cidr"],
                        "type": network.get("role", "custom"), "hosts": [h for h in hosts if not h.name.endswith(" interface")],
                        "gateway": network.get("gateway", "")})
    devices = payload.get("devices", [])
    firewall = devices[0] if devices else None
    here = None
    if source and source in networks:
        here = {"key": source, "name": zones[source].name if source in zones else source,
                "cidr": networks[source]["cidr"], "gateway": networks[source].get("gateway", ""),
                "type": networks[source].get("role", "custom"), "ip": payload.get("source_ip", ""),
                "organization": payload.get("organization", ""),
                "present": env.source_address_available(payload.get("source_ip", ""))}
    here_hosts = []
    if here and source in zones:
        here_hosts = sorted((a for a in zones[source].assets if not a.name.endswith(" interface")),
                            key=lambda a: ipaddress.ip_address(a.address))
        here["hosts"] = here_hosts
    hosts_total = sum(len(t["hosts"]) for t in targets) + len(here_hosts)
    return {"revision": record.revision if record else 0, "here": here, "targets": targets, "firewall": firewall,
            "hosts_total": hosts_total,
            "steps": {"here": bool(here), "targets": hosts_total > 0,
                      # No other network to test = no boundary to declare (only hosts in this PC's own network).
                      "firewall": (not targets and bool(here_hosts)) or (firewall is not None and bool(targets) and
                                                                         all(t["key"] in firewall.get("zones", []) for t in targets))}}


# ---------------- Step 1: where you are ----------------

def set_here(name, cidr, ip, gateway="", kind="corporate", organization=""):
    """Make this PC's network the source of the audit."""
    name = (name or "").strip() or "This PC's network"
    if kind not in NETWORK_TYPES:
        raise EnvironmentError("Choose what kind of network this PC is in.")
    try:
        network = ipaddress.ip_network((cidr or "").strip(), strict=False)
    except ValueError as exc:
        raise EnvironmentError("Enter this network's subnet, for example 10.50.0.0/24.") from exc
    ip = (ip or "").strip()
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise EnvironmentError("Enter this PC's IP address (see ipconfig).") from exc
    if address not in network:
        raise EnvironmentError(f"This PC's address {ip} is not inside {network}. Check the subnet.")
    if not env.source_address_available(ip):
        raise EnvironmentError(f"{ip} is not an address of this PC. Pick one of the detected networks, or check ipconfig.")
    _, payload = settings()
    networks = payload.get("networks", {})
    old = payload.get("source_zone") if payload.get("source_zone") in networks else None
    same_place = old and networks[old]["cidr"] == str(network)
    # Moving into a network that is already a target (next department): it becomes "where you are";
    # its hosts stay, as hosts in this PC's own network.
    was_target = next((key for key, net in networks.items() if key != old and net["cidr"] == str(network)), None)
    key = old if same_place else (was_target or _slug(name, set(networks)))
    env.save_zone(_form(zone_key=key, name=name, role=kind, cidr=str(network), gateway=gateway or ""))
    env.save_profile(_form(organization=(organization or "").strip() or "Not set", site=name, source_zone=key, source_ip=ip))
    if old and not same_place:
        env.delete_zone(_form(zone_key=old))  # the PC moved: the previous "here" network is no longer used
    _sync_firewall_zones()
    return key


# ---------------- Step 2: targets ----------------

def _hosts_from_text(text):
    found, bad = [], []
    for token in re.split(r"[\s,;]+", text or ""):
        if not token:
            continue
        try:
            found.append(str(ipaddress.ip_address(token)))
        except ValueError:
            bad.append(token)
    if bad:
        raise EnvironmentError(f"Not an IP address: {', '.join(bad[:5])}. Enter addresses like 10.30.0.20, separated by spaces or new lines.")
    return list(dict.fromkeys(found))


def add_targets(rows):
    """Add several target networks at once. rows: [{name, cidr, type, hosts (text)}]."""
    added = []
    for number, row in enumerate(rows, start=1):
        name = (row.get("name") or "").strip()
        cidr = (row.get("cidr") or "").strip()
        hosts = _hosts_from_text(row.get("hosts", ""))
        if not (name or cidr or hosts):
            continue
        if not cidr:
            if not hosts:
                raise EnvironmentError(f"Row {number}: enter the network (e.g. 10.30.0.0/24) or at least one host address.")
            first = ipaddress.ip_address(hosts[0])
            cidr = str(ipaddress.ip_network(f"{first}/{24 if first.version == 4 else 64}", strict=False))
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise EnvironmentError(f"Row {number}: '{cidr}' is not a network. Use the form 10.30.0.0/24.") from exc
        kind = row.get("type") or "custom"
        if kind not in NETWORK_TYPES:
            raise EnvironmentError(f"Row {number}: choose the kind of network.")
        _, payload = settings()
        key = _slug(name or f"net-{network.network_address}", set(payload.get("networks", {})))
        env.save_zone(_form(zone_key=key, name=name or f"Network {network}", role=kind, cidr=str(network), gateway=""))
        add_hosts(key, hosts)
        added.append(key)
    if not added:
        raise EnvironmentError("Fill in at least one target network.")
    _sync_firewall_zones()
    return added


def add_hosts(zone_key, addresses, names=None):
    names = names or {}
    zone = db.session.query(Zone).filter_by(zone_key=zone_key).one_or_none()
    if zone is None:
        raise EnvironmentError("That target network no longer exists. Reload the page.")
    existing = {asset.address for asset in zone.assets}
    count = 0
    for address in addresses:
        if address in existing:
            continue
        env.save_asset(_form(zone_key=zone_key, name=names.get(address) or address, address=address))
        existing.add(address)
        count += 1
    return count


def remove_target(zone_key):
    env.delete_zone(_form(zone_key=zone_key))
    _sync_firewall_zones()


def remove_host(asset_id):
    env.delete_asset(_form(asset_id=asset_id))


# ---------------- Step 3: firewall ----------------

def free_udp_port(address, start=DEFAULT_LOG_PORT):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    for port in range(start, start + 50):
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind((address, port))
                return port
            except OSError:
                continue
    raise EnvironmentError(f"No free UDP port between {start} and {start + 49} on {address}. Close other syslog tools and retry.")


def set_firewall(mode, kind="pfsense", firewall_ip="", logs=True, port=None, listen_ip="", sender_ip=""):
    """mode 'none': no firewall (or unknown), tested straight through the router.
    mode 'firewall': a firewall separates this PC from the targets; optionally connect its logs."""
    record, payload = settings()
    if not payload.get("source_zone"):
        raise EnvironmentError("Do Step 1 first: SegCheck needs to know where this PC is.")
    zones = list(payload.get("networks", {}))
    if len(zones) < 2:
        raise EnvironmentError("Do Step 2 first: add at least one target network.")
    for device in list(payload.get("devices", [])):
        env.delete_device(_form(device_id=device["id"]))
    if mode == "none":
        env.save_device(_form(name="No firewall", kind="none", zones=zones))
        return {"port": None}
    if kind not in {"pfsense", "iptables", "other"}:
        raise EnvironmentError("Choose the firewall type.")
    firewall_ip = (firewall_ip or "").strip()
    here_cidr = payload["networks"][payload["source_zone"]]["cidr"]
    interface = firewall_ip if firewall_ip and _inside(firewall_ip, here_cidr) else ""
    values = dict(name="Firewall", kind=kind, zones=zones, interface_ip=interface)
    chosen_port = None
    if logs and kind in {"pfsense", "iptables"}:
        listen_ip = (listen_ip or payload["source_ip"]).strip()
        chosen_port = int(port) if port else free_udp_port(listen_ip)
        values.update(logging="on", log_port=chosen_port, log_listen_ip=listen_ip,
                      log_sender_ip=(sender_ip or firewall_ip or "").strip())
    env.save_device(_form(**values))
    return {"port": chosen_port}


def _inside(address, cidr):
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(cidr)
    except ValueError:
        return False


def _sync_firewall_zones():
    """The firewall (or 'no firewall') always sits between this PC and every target network."""
    record, payload = settings()
    devices = payload.get("devices", [])
    zones = list(payload.get("networks", {}))
    if not devices or all(set(d.get("zones", [])) == set(zones) for d in devices):
        return
    for device in devices:
        device["zones"] = zones
    record.payload = payload
    db.session.commit()


def use_learned_sender(sender_ip):
    record, payload = settings()
    for device in payload.get("devices", []):
        if device.get("logging"):
            device["log_sender_ip"] = env.literal_ip(sender_ip)
    record.payload = payload
    db.session.commit()


# ---------------- Step 4: what to check ----------------

MAX_RULE_ADDRESSES = 256
MAX_RULE_PORTS = 400
CSV_FIELDS = ["from", "to", "service", "protocol", "ports", "must", "reason"]


def parse_addresses(text, number=None):
    """IPs from what a person types: '10.30.0.20', '10.30.0.10-20', '10.30.0.10-10.30.0.40', '10.30.0.0/28',
    any mix separated by spaces, commas or new lines. At most MAX_RULE_ADDRESSES."""
    where = f"Rule {number}: " if number else ""
    found = []
    for token in re.split(r"[\s,;]+", (text or "").strip()):
        if not token:
            continue
        try:
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                if network.num_addresses > MAX_RULE_ADDRESSES + 2:
                    raise EnvironmentError(f"{where}{token} has {network.num_addresses} addresses; one rule covers at most {MAX_RULE_ADDRESSES}.")
                found += [str(ip) for ip in (network.hosts() if network.num_addresses > 2 else network)]
            elif "-" in token:
                first, last = token.split("-", 1)
                start = ipaddress.ip_address(first)
                end = ipaddress.ip_address(last) if "." in last or ":" in last else ipaddress.ip_address(
                    f"{first.rsplit('.', 1)[0]}.{last}")
                if int(end) < int(start):
                    raise EnvironmentError(f"{where}the range {token} runs backwards.")
                if int(end) - int(start) + 1 > MAX_RULE_ADDRESSES:
                    raise EnvironmentError(f"{where}{token} has more than {MAX_RULE_ADDRESSES} addresses.")
                found += [str(ipaddress.ip_address(value)) for value in range(int(start), int(end) + 1)]
            else:
                found.append(str(ipaddress.ip_address(token)))
        except EnvironmentError:
            raise
        except ValueError as exc:
            raise EnvironmentError(f"{where}'{token}' is not an address, range or subnet. Examples: 10.30.0.20, "
                                   "10.30.0.10-20, 10.30.0.0/28.") from exc
    found = list(dict.fromkeys(found))
    if len(found) > MAX_RULE_ADDRESSES:
        raise EnvironmentError(f"{where}at most {MAX_RULE_ADDRESSES} addresses per rule.")
    return found


def parse_ports(text, number=None):
    """Ports from '80, 443, 8000-8100'. At most MAX_RULE_PORTS."""
    where = f"Rule {number}: " if number else ""
    ports = []
    for token in re.split(r"[\s,;]+", (text or "").strip()):
        if not token:
            continue
        try:
            if "-" in token:
                first, last = (int(part) for part in token.split("-", 1))
                if last < first:
                    raise EnvironmentError(f"{where}the port range {token} runs backwards.")
                ports += list(range(first, last + 1))
            else:
                ports.append(int(token))
        except EnvironmentError:
            raise
        except ValueError as exc:
            raise EnvironmentError(f"{where}ports must be numbers or ranges, e.g. 8080, 9000-9010.") from exc
    ports = sorted(set(ports))
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise EnvironmentError(f"{where}give ports between 1 and 65535, e.g. 8080, 9000-9010.")
    if len(ports) > MAX_RULE_PORTS:
        raise EnvironmentError(f"{where}{len(ports)} ports is too many for one rule (at most {MAX_RULE_PORTS}).")
    return ports


def hosts_for_addresses(addresses, number=None):
    """Typed addresses → hosts, each added to the Step 1/Step 2 network that contains it."""
    where = f"Rule {number}: " if number else ""
    _, payload = settings()
    networks = {key: ipaddress.ip_network(net["cidr"]) for key, net in payload.get("networks", {}).items()}
    by_zone = {}
    for address in addresses:
        ip = ipaddress.ip_address(address)
        homes = [key for key, net in networks.items() if ip.version == net.version and ip in net]
        if not homes:
            raise EnvironmentError(f"{where}{address} is not inside any network of Step 1 or Step 2. "
                                   "Add its network in Step 2 first (then rules can target it).")
        by_zone.setdefault(max(homes, key=lambda key: networks[key].prefixlen), []).append(address)
    hosts = []
    for zone_key, ips in by_zone.items():
        add_hosts(zone_key, ips)
        zone = db.session.query(Zone).filter_by(zone_key=zone_key).one()
        wanted = set(ips)
        hosts += [asset for asset in zone.assets if asset.address in wanted]
    return hosts


def service_for(row, number=None):
    """(label, protocol, ports) for a rule row: a named service/bundle, or protocol + ports."""
    where = f"Rule {number}: " if number else ""
    service = (row.get("service") or "").strip()
    if service in ("", "custom"):
        protocol = (row.get("protocol") or "tcp").strip().lower()
        if protocol == "icmp":
            return SERVICES["ping"]
        if protocol not in {"tcp", "udp"}:
            raise EnvironmentError(f"{where}the protocol must be TCP, UDP or ICMP.")
        ports = parse_ports(row.get("ports", ""), number)
        return f"{protocol.upper()} {compact_ports(ports)}", protocol, ports
    if service in SERVICES:
        return SERVICES[service]
    raise EnvironmentError(f"{where}choose a service.")


def compact_ports(ports):
    """[80, 443, 8000, 8001, 8002] → '80, 443, 8000-8002'."""
    parts, start, previous = [], None, None
    for port in sorted(ports):
        if start is None:
            start = previous = port
        elif port == previous + 1:
            previous = port
        else:
            parts.append(str(start) if start == previous else f"{start}-{previous}")
            start = previous = port
    if start is not None:
        parts.append(str(start) if start == previous else f"{start}-{previous}")
    return ", ".join(parts)


def custom_policy(rows, here_name):
    """A policy document from simple rows: target, service, must, optional reason.

    target: a host id, 'net:<zone>' (all hosts of a network) or 'text' with row['targets'] holding typed
    addresses, ranges or subnets (added as hosts to the network that contains them)."""
    _, payload = settings()
    source = payload.get("source_zone")
    zones = {zone.zone_key: zone for zone in db.session.query(Zone).all()}
    checks = []
    for number, row in enumerate(rows, start=1):
        target, must = row.get("target", ""), row.get("must", "")
        if not (target or row.get("service")) or (target == "text" and not (row.get("targets") or "").strip()
                                                  and not row.get("reason")):
            continue
        label, protocol, ports = service_for(row, number)
        if must not in {"deny", "allow"}:
            raise EnvironmentError(f"Rule {number}: choose 'must be blocked' or 'must work'.")
        reason = " ".join((row.get("reason") or "").split())[:500]
        if target == "text":
            hosts = hosts_for_addresses(parse_addresses(row.get("targets", ""), number), number)
        elif target.startswith("net:"):
            zone = zones.get(target[4:])
            hosts = [a for a in zone.assets] if zone else []
        else:
            asset = db.session.get(Asset, int(target)) if target.isdigit() else None
            hosts = [asset] if asset else []
        if not hosts:
            raise EnvironmentError(f"Rule {number}: choose a target host or network that has hosts, or type addresses.")
        for asset in hosts:
            check = {"name": f"{here_name} → {asset.name}: {label} {'must be blocked' if must == 'deny' else 'must work'}"[:160],
                     "source_zone": source, "destination_zone": asset.zone.zone_key,
                     "destination_host": asset.address, "protocol": protocol, "ports": list(ports), "expected": must,
                     "rationale": reason or "Auditor-defined rule.", "pci_requirements": [], "framework_mappings": []}
            if protocol == "icmp":
                check.pop("ports")
            checks.append(check)
    if not checks:
        raise EnvironmentError("Add at least one rule.")
    return checks


def policy_document(name, checks):
    """Wrap checks into a policy document with stable check ids and the zones they use."""
    _, payload = settings()
    zones = {zone.zone_key: zone.name for zone in db.session.query(Zone).all()}
    used = sorted({c["source_zone"] for c in checks} | {c["destination_zone"] for c in checks})
    for number, check in enumerate(checks, start=1):
        check["id"] = f"CHK-{number:03d}"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return {"schema_version": 1, "policy_id": f"AUDIT-{stamp}-{secrets.token_hex(2).upper()}", "name": name[:120],
            "organization": payload.get("organization") or "Not set", "pci_dss_version": "4.0.1",
            "zones": [{"id": key, "name": zones.get(key, key)} for key in used], "checks": checks}


def as_yaml(document):
    return yaml.safe_dump(document, sort_keys=False).encode("utf-8")
