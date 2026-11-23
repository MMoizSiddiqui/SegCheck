"""Explain applicability using exact policy targets and declared inventory."""
import hashlib
import hmac
import ipaddress
import json

from segcheck.policy_engine import validate_policy_data
from segcheck.probe import probe_points
from segcheck_web.extensions import db
from segcheck_web.models import Asset, Zone
from segcheck_web.services.assessment_execution import MAX_WEB_PROBE_ATTEMPTS
from segcheck_web.services.environment import settings, source_address_available


def build_plan(version, policy_status, *, check_local_address=True):
    """Plan a run from this PC (the configured probe address and zone)."""
    record, environment = settings()
    snapshot = version.snapshot
    digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    if not hmac.compare_digest(digest, version.snapshot_sha256):
        raise ValueError("Stored policy snapshot integrity verification failed.")
    policy = validate_policy_data(snapshot)
    blockers = []
    source_zone = environment.get("source_zone", "")
    source_ip = environment.get("source_ip", "")
    if policy_status != "active":
        blockers.append("Activate this reviewed policy before execution.")
    if not environment.get("organization") or not source_ip or not source_zone:
        blockers.append("Complete the organisation and local probe configuration.")
    elif check_local_address and not source_address_available(source_ip):
        blockers.append("The Step 1 address is not an address of this PC any more (another network?). "
                        "Open Step 1 and pick one of the networks this PC is in now.")
    # Assets are matched by explicit address AND declared destination zone.
    inventory = {(asset.address, zone.zone_key) for asset, zone in
                 db.session.query(Asset, Zone).join(Zone, Asset.zone_id == Zone.id).all()}
    rows = []
    attempts = 0
    for check in policy.checks:
        reasons = []
        selected = check.source_zone == source_zone
        if not selected:
            reasons.append("Requires a probe in another source zone; this path will not run.")
        if check.protocol not in {"tcp", "udp", "icmp"}:
            reasons.append("No executable probe method exists for this protocol.")
        if source_ip and ipaddress.ip_address(source_ip).version != ipaddress.ip_address(check.destination_host).version:
            reasons.append("The configured source and target IP families differ.")
        if (str(ipaddress.ip_address(check.destination_host)), check.destination_zone) not in inventory:
            reasons.append("Register this exact target address in its destination zone.")
        path_devices = [device for device in environment.get("devices", [])
                        if check.source_zone in device.get("zones", []) and check.destination_zone in device.get("zones", [])]
        if selected and check.source_zone != check.destination_zone and not path_devices:
            reasons.append(f"Do Step 3 (Firewall): say what is between {check.source_zone} and {check.destination_zone} "
                           "('There is a firewall' or 'No firewall, or I don't know').")
        network = environment.get("networks", {}).get(check.destination_zone)
        if network is None or ipaddress.ip_address(check.destination_host) not in ipaddress.ip_network(network["cidr"]):
            reasons.append("Target is outside the configured destination subnet.")
        if selected:
            attempts += len(probe_points(check))
            blockers.extend(f"{check.id}: {reason}" for reason in reasons)
        rows.append({"id": check.id, "name": check.name, "source": check.source_zone,
                     "destination": check.destination_zone, "host": check.destination_host,
                     "protocol": check.protocol, "ports": check.ports, "expected": check.expected,
                     "selected": selected, "ready": selected and not reasons, "reasons": reasons,
                     "attempts": len(probe_points(check)),
                     "boundary": [{"name": device["name"], "kind": device.get("kind"), "logging": bool(device.get("logging"))}
                                  for device in path_devices],
                     "framework_mappings": check.framework_mappings})
    if not any(row["selected"] for row in rows):
        blockers.append("This policy has no checks from the configured probe zone.")
    if attempts > MAX_WEB_PROBE_ATTEMPTS:
        blockers.append(f"The scope requires {attempts} attempts; the limit is {MAX_WEB_PROBE_ATTEMPTS}.")
    return {"environment": environment, "environment_revision": record.revision if record else 0,
            "source_zone": source_zone, "source_ip": source_ip,
            "rows": rows, "attempts": attempts, "blockers": blockers, "ready": not blockers,
            "policy_digest": digest}
