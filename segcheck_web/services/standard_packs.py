"""Standards-based segmentation policy packs.

Each pack turns the configured environment (zone roles, assets and declared
boundary devices) into many concrete checks. A single forbidden path such as
Guest → CDE is exercised with several probe *methods* — remote administration,
databases, web, file/directory services, infrastructure UDP and ICMP — because
an attacker can try any of them. Every generated check carries a plain-language
rationale for the analyst and a *supporting* framework mapping. Mappings are
traceability, not a claim that the whole control is satisfied.

Packs only use addresses the administrator registered. Nothing is scanned.
"""

from __future__ import annotations

import ipaddress
import re

from segcheck_web.extensions import db
from segcheck_web.models import Asset, Policy, Zone
from segcheck_web.services.assessment_execution import MAX_WEB_PROBE_ATTEMPTS

# --------------------------------------------------------------------------- probe groups
PROBE_GROUPS = {
    "remote_admin": {
        "label": "Remote administration", "protocol": "tcp", "ports": [22, 23, 3389, 5900, 5985, 5986],
        "detail": "SSH 22, Telnet 23, RDP 3389, VNC 5900, WinRM 5985/5986",
        "why": "Interactive administration is the most direct way to take over a system. No out-of-scope network should reach these services.",
    },
    "database": {
        "label": "Databases and data stores", "protocol": "tcp", "ports": [1433, 1521, 3306, 5432, 6379, 27017],
        "detail": "MSSQL 1433, Oracle 1521, MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017",
        "why": "Cardholder and other sensitive data usually lives here. Direct database reachability bypasses application controls.",
    },
    "web_app": {
        "label": "Web and application services", "protocol": "tcp", "ports": [80, 443, 8080, 8443],
        "detail": "HTTP 80, HTTPS 443, alternate HTTP 8080/8443",
        "why": "Payment and admin web interfaces are common attack surfaces; they should only be reachable from approved sources.",
    },
    "file_directory": {
        "label": "File sharing and directory", "protocol": "tcp", "ports": [139, 445, 389, 636, 2049],
        "detail": "NetBIOS 139, SMB 445, LDAP 389, LDAPS 636, NFS 2049",
        "why": "File shares and directory services enable lateral movement and credential theft across a boundary.",
    },
    "infra_udp": {
        "label": "Infrastructure UDP", "protocol": "udp", "ports": [53, 123, 161],
        "detail": "DNS 53 (query), NTP 123 (client request), SNMP 161 (v3 discovery, no credentials)",
        "why": "UDP services are often forgotten in firewall rules and can leak data or allow reconnaissance and tunnelling.",
    },
    "icmp": {
        "label": "Network-layer reachability (ICMP echo)", "protocol": "icmp", "ports": [],
        "detail": "One ICMP echo request",
        "why": "A ping reply shows the path is routed and open at layer 3, which helps an attacker map the protected network.",
    },
    "mgmt_plane": {
        "label": "Boundary device management plane", "protocol": "tcp", "ports": [22, 80, 443],
        "detail": "SSH 22, HTTP 80, HTTPS 443 on the firewall's own interface",
        "why": "If a user network can reach the firewall's management interface, an attacker could change the rules that create segmentation.",
    },
    "mgmt_plane_udp": {
        "label": "Boundary device SNMP", "protocol": "udp", "ports": [161],
        "detail": "SNMP 161 (v3 discovery)",
        "why": "SNMP exposure on a firewall can disclose its configuration and interfaces to an untrusted network.",
    },
}

FULL_DENY = ["remote_admin", "database", "web_app", "file_directory", "infra_udp", "icmp"]
CORE_DENY = ["remote_admin", "database", "file_directory", "icmp"]


def _map(framework, version, control, title):
    return {"framework": framework, "version": version, "control_id": control, "title": title, "relationship": "supporting"}


PCI_1131 = _map("pci_dss", "4.0.1", "1.3.1", "Inbound traffic to the CDE is restricted")
PCI_1132 = _map("pci_dss", "4.0.1", "1.3.2", "Outbound traffic from the CDE is restricted")
PCI_1142 = _map("pci_dss", "4.0.1", "1.4.2", "Inbound traffic from untrusted networks is restricted")
PCI_1145 = _map("pci_dss", "4.0.1", "11.4.5", "Segmentation controls are tested")
NIST_SC7 = _map("nist_sp800_53", "Rev5", "SC-7", "Boundary protection")
NIST_SC75 = _map("nist_sp800_53", "Rev5", "SC-7(5)", "Deny by default, allow by exception")
NIST_AC4 = _map("nist_sp800_53", "Rev5", "AC-4", "Information flow enforcement")
ISO_822 = _map("iso27002", "2022", "8.22", "Segregation of networks")
ISO_820 = _map("iso27002", "2022", "8.20", "Networks security")
CIS_122 = _map("cis_controls", "v8", "12.2", "Establish and maintain a secure network architecture")
CIS_134 = _map("cis_controls", "v8", "13.4", "Perform traffic filtering between network segments")

SENSITIVE_ROLES = {"cde", "server", "hr"}

# --------------------------------------------------------------------------- packs
PACKS = [
    {
        "key": "pci-cde-isolation", "standard": "PCI DSS 4.0.1", "family": "pci",
        "title": "CDE isolation from out-of-scope networks",
        "controls": "Req. 1.3.1 · 11.4.5",
        "summary": "Proves the probe's out-of-scope zone cannot reach any service on any CDE system, using every probe method.",
        "analyst": "PCI DSS 11.4.5 requires segmentation to be tested from each out-of-scope network. Run this pack once from every non-CDE zone. A FAIL means cardholder systems are reachable, so the zone is effectively in PCI scope.",
        "source": "out_of_scope", "targets": "cde", "groups": FULL_DENY, "mappings": [PCI_1145, PCI_1131], "pci": ["1.3.1", "11.4.5"],
    },
    {
        "key": "pci-untrusted-to-cde", "standard": "PCI DSS 4.0.1", "family": "pci",
        "title": "Untrusted/DMZ networks to CDE",
        "controls": "Req. 1.4.2 · 11.4.5",
        "summary": "From an untrusted, guest or DMZ zone, checks that no service on CDE systems is reachable.",
        "analyst": "Requirement 1.4.2 restricts inbound traffic from untrusted networks. Guest Wi-Fi and DMZ are the classic examples. Probe sits in that zone.",
        "source": "untrusted", "targets": "cde", "groups": FULL_DENY, "mappings": [PCI_1142, PCI_1145], "pci": ["1.4.2", "11.4.5"],
    },
    {
        "key": "pci-cde-egress", "standard": "PCI DSS 4.0.1", "family": "pci",
        "title": "CDE outbound restriction",
        "controls": "Req. 1.3.2",
        "summary": "From inside the CDE, checks that CDE systems cannot open connections to other zones' systems.",
        "analyst": "Requirement 1.3.2 limits what the CDE may initiate. Unrestricted egress lets malware exfiltrate card data. The probe must run on a host inside the CDE.",
        "source": "cde", "targets": "non_cde", "groups": ["remote_admin", "web_app", "file_directory", "infra_udp", "icmp"],
        "mappings": [PCI_1132], "pci": ["1.3.2"],
    },
    {
        "key": "nist-sc7-boundary", "standard": "NIST SP 800-53 Rev. 5", "family": "nist",
        "title": "Boundary protection between zones",
        "controls": "SC-7 · AC-4",
        "summary": "Every registered system in every other zone must not be reachable on administration, data, file or ICMP paths.",
        "analyst": "SC-7 requires communications at managed boundaries to be controlled, and AC-4 requires information flows to be enforced. This pack tests every zone boundary from the probe's position.",
        "source": "any", "targets": "other_zones", "groups": CORE_DENY, "mappings": [NIST_SC7, NIST_AC4], "pci": [],
    },
    {
        "key": "nist-sc7-deny-default", "standard": "NIST SP 800-53 Rev. 5", "family": "nist",
        "title": "Deny-by-default to sensitive zones",
        "controls": "SC-7(5)",
        "summary": "Against CDE, server and HR zones, uses the full method set: anything reachable that was not explicitly approved is a finding.",
        "analyst": "SC-7(5) expects boundary devices to deny traffic by default. Approved flows should be modelled separately as allow checks (Required connectivity template).",
        "source": "any", "targets": "sensitive", "groups": FULL_DENY, "mappings": [NIST_SC75], "pci": [],
    },
    {
        "key": "iso-8-22-segregation", "standard": "ISO/IEC 27002:2022", "family": "iso",
        "title": "Segregation of networks",
        "controls": "8.22",
        "summary": "Checks that the probe's network domain is segregated from all other configured domains.",
        "analyst": "Control 8.22 expects groups of services, users and systems to be segregated. Connectivity results support, but do not replace, a design and configuration review.",
        "source": "any", "targets": "other_zones", "groups": CORE_DENY, "mappings": [ISO_822], "pci": [],
    },
    {
        "key": "iso-8-20-mgmt-plane", "standard": "ISO/IEC 27002:2022", "family": "iso",
        "title": "Firewall management plane protection",
        "controls": "8.20 · NIST SC-7",
        "summary": "Checks that the boundary device's own interface in the probe zone does not expose SSH, web admin or SNMP.",
        "analyst": "Control 8.20 covers securing network devices. If a guest can reach the firewall's admin interface, segmentation can be undone. Uses the boundary devices you declared.",
        "source": "any", "targets": "devices", "groups": ["mgmt_plane", "mgmt_plane_udp"], "mappings": [ISO_820, NIST_SC7], "pci": [],
    },
    {
        "key": "cis-12-13-filtering", "standard": "CIS Controls v8", "family": "cis",
        "title": "Traffic filtering between segments",
        "controls": "12.2 · 13.4",
        "summary": "Broad cross-segment filtering check from the probe zone to all other zones, including infrastructure UDP.",
        "analyst": "CIS 13.4 asks for traffic filtering between network segments, and 12.2 asks for a secure network architecture. This pack gives a quick baseline across every boundary.",
        "source": "any", "targets": "other_zones", "groups": ["remote_admin", "database", "file_directory", "infra_udp", "icmp"],
        "mappings": [CIS_134, CIS_122], "pci": [],
    },
]
PACKS_BY_KEY = {pack["key"]: pack for pack in PACKS}
FAMILIES = {"pci": "PCI DSS 4.0.1", "nist": "NIST SP 800-53", "iso": "ISO/IEC 27002", "cis": "CIS Controls v8"}


class PackError(ValueError):
    pass


def _targets(pack, environment, source_zone):
    networks = environment.get("networks", {})
    role = lambda key: networks.get(key, {}).get("role", "custom")
    kind = pack["targets"]
    if kind == "devices":
        rows = []
        for device in environment.get("devices", []):
            address = device.get("interface_ip")
            if address and source_zone in device.get("zones", []):
                rows.append({"name": f"{device['name']} ({source_zone} interface)", "address": address, "zone": source_zone})
        return rows
    rows = []
    for asset, zone in db.session.query(Asset, Zone).join(Zone, Asset.zone_id == Zone.id).order_by(Zone.zone_key, Asset.name).all():
        if zone.zone_key == source_zone or zone.zone_key not in networks:
            continue
        zone_role = role(zone.zone_key)
        if (kind == "cde" and zone_role == "cde") or (kind == "non_cde" and zone_role != "cde") \
                or kind == "other_zones" or (kind == "sensitive" and zone_role in SENSITIVE_ROLES):
            rows.append({"name": asset.name, "address": asset.address, "zone": zone.zone_key})
    return rows


def _source_ok(pack, environment, source_zone):
    source_role = environment.get("networks", {}).get(source_zone, {}).get("role", "custom")
    rule = pack["source"]
    if rule == "out_of_scope":
        return source_role != "cde", "Run from a non-CDE zone (the probe zone is the CDE)."
    if rule == "untrusted":
        return source_role in {"guest", "dmz", "untrusted"}, "Run from a Guest, DMZ or Untrusted zone."
    if rule == "cde":
        return source_role == "cde", "Run with the local probe inside a CDE zone."
    return True, ""


def evaluate_pack(pack, environment, groups=None):
    """Explain whether a pack can be generated here, and what it would test."""
    source_zone = environment.get("source_zone", "")
    if not source_zone or not environment.get("source_ip"):
        return {"ready": False, "reason": "Configure the local probe zone and IP first.", "targets": [], "attempts": 0}
    ok, why = _source_ok(pack, environment, source_zone)
    if not ok:
        return {"ready": False, "reason": why, "targets": [], "attempts": 0}
    targets = _targets(pack, environment, source_zone)
    if not targets:
        need = {"cde": "a CDE zone with at least one registered asset", "non_cde": "assets in non-CDE zones",
                "sensitive": "assets in CDE, server or HR zones", "devices": "a boundary device with an interface IP in the probe zone",
                "other_zones": "assets in other zones"}[pack["targets"]]
        return {"ready": False, "reason": f"Needs {need}.", "targets": [], "attempts": 0}
    per_target = sum(max(1, len(PROBE_GROUPS[g]["ports"])) for g in selected_groups(pack, groups))
    attempts = per_target * len(targets)
    return {"ready": True, "reason": "", "targets": targets, "attempts": attempts,
            "parts": -(-attempts // MAX_WEB_PROBE_ATTEMPTS)}


def selected_groups(pack, groups=None):
    """The pack's probe groups, limited to the ones the auditor ticked (at least one)."""
    if groups is None:
        return list(pack["groups"])
    chosen = [group for group in pack["groups"] if group in set(groups)]
    if not chosen:
        raise PackError("Tick at least one kind of probe for this standard.")
    return chosen


def _unique_key(base):
    key = re.sub(r"[^A-Z0-9-]", "-", base.upper())[:56].strip("-")
    candidate, number = key, 2
    while db.session.query(Policy.id).filter_by(policy_key=candidate).first():
        candidate = f"{key}-{number}"
        number += 1
    return candidate


def build_pack_documents(pack_key, environment, groups=None):
    """Return one or more policy documents (dicts) for the pack, split to the attempt limit.

    groups: the probe groups to use (a subset of the pack's own); None = all of the pack's groups."""
    pack = PACKS_BY_KEY.get(pack_key)
    if pack is None:
        raise PackError("Unknown policy pack.")
    status = evaluate_pack(pack, environment, groups)
    if not status["ready"]:
        raise PackError(status["reason"])
    source_zone = environment["source_zone"]
    zone_names = {zone.zone_key: zone.name for zone in db.session.query(Zone).all()}
    checks, attempts_per_check = [], []
    for target in status["targets"]:
        for group_key in selected_groups(pack, groups):
            group = PROBE_GROUPS[group_key]
            check = {
                "name": f"{source_zone} must not reach {target['name']} — {group['label']}"[:160],
                "source_zone": source_zone, "destination_zone": target["zone"],
                "destination_host": str(ipaddress.ip_address(target["address"])),
                "protocol": group["protocol"], "ports": list(group["ports"]), "expected": "deny",
                "rationale": (f"{group['why']} Probe: {group['detail']}. Standard: {pack['standard']} "
                              f"{pack['controls']} (supporting technical check).")[:2000],
                "pci_requirements": list(pack["pci"]),
                "framework_mappings": [dict(mapping) for mapping in pack["mappings"]],
            }
            if group["protocol"] == "icmp":
                check.pop("ports")
            checks.append(check)
            attempts_per_check.append(max(1, len(group["ports"])))
    parts, current, used = [], [], 0
    for check, cost in zip(checks, attempts_per_check):
        if current and used + cost > MAX_WEB_PROBE_ATTEMPTS:
            parts.append(current)
            current, used = [], 0
        current.append(check)
        used += cost
    if current:
        parts.append(current)
    documents = []
    base_key = f"{pack['family']}-{pack['key'].split('-', 1)[1]}-{source_zone}"
    for index, part in enumerate(parts, start=1):
        suffix = f" (part {index} of {len(parts)})" if len(parts) > 1 else ""
        for number, check in enumerate(part, start=1):
            check["id"] = f"{pack['family'].upper()}-{number:03}"
        zones = {source_zone} | {check["destination_zone"] for check in part}
        documents.append({
            "schema_version": 1,
            "policy_id": _unique_key(base_key + (f"-P{index}" if len(parts) > 1 else "")),
            "name": f"{pack['standard']} · {pack['title']} · from {source_zone}{suffix}"[:160],
            "organization": environment.get("organization", "Organisation"),
            "pci_dss_version": "4.0.1",
            "zones": [{"id": key, "name": zone_names.get(key, key)} for key in sorted(zones)],
            "checks": part,
        })
    return pack, documents
