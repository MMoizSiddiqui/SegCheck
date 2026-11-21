"""Correlate scoped probe measurements with configured pfSense filterlog evidence.

This module does not perform network scans and does not independently
authenticate syslog senders. It produces a separate evidence assessment;
it never modifies the original probe measurement.
"""

from __future__ import annotations

import ipaddress
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from io import BytesIO

from .secure_files import SecureFileError, read_bounded_file
from .policy_engine import (
    PolicyValidationError,
    SegmentationPolicy,
    load_policy,
)


class EvidenceCorrelationError(ValueError):
    """Raised when correlation inputs or integration configuration are invalid."""


MAX_JSONL_LINE_BYTES = 65536
MAX_MATCHING_EVENTS_PER_CHECK = 1000
VALID_ACTIONS = {"block", "pass"}
VALID_DIRECTIONS = {"in", "out"}
VALID_PROTOCOLS = {"tcp", "udp"}
VALID_EXPECTATIONS = {"allow", "deny"}
VALID_OBSERVATIONS = {"reachable", "blocked", "inconclusive"}


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceCorrelationError(f"{field} must be a non-empty string")
    return value.strip()


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceCorrelationError(f"{field} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceCorrelationError(f"{field} is not a valid ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceCorrelationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _ip(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise EvidenceCorrelationError(f"{field} must be an IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise EvidenceCorrelationError(f"{field} must be a valid IP address") from exc


def _port(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise EvidenceCorrelationError(f"{field} must be an integer from 1 to 65535")
    return value


def _load_json(path: str | Path, label: str) -> dict[str, Any]:
    try:
        raw = read_bounded_file(
            path,
            max_bytes=4 * 1024 * 1024,
            label=label,
        )
        value = json.loads(raw.decode("utf-8"))
    except SecureFileError as exc:
        raise EvidenceCorrelationError(str(exc)) from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EvidenceCorrelationError(f"{label} file is not valid JSON") from exc

    if not isinstance(value, dict):
        raise EvidenceCorrelationError(f"{label} root must be a JSON object")
    return value


def _load_configuration(path: str | Path) -> dict[str, Any]:
    try:
        import yaml

        raw = read_bounded_file(
            path,
            max_bytes=1 * 1024 * 1024,
            label="Evidence configuration",
        )
        config = yaml.safe_load(raw.decode("utf-8"))
    except (SecureFileError, UnicodeDecodeError) as exc:
        raise EvidenceCorrelationError(str(exc)) from exc
    except yaml.YAMLError as exc:
        raise EvidenceCorrelationError(f"Invalid evidence configuration YAML: {exc}") from exc

    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise EvidenceCorrelationError("Evidence configuration schema_version must be 1")

    integration = config.get("integration")
    correlation = config.get("correlation")
    if not isinstance(integration, dict) or not isinstance(correlation, dict):
        raise EvidenceCorrelationError("Configuration requires integration and correlation mappings")

    if integration.get("platform") != "pfsense":
        raise EvidenceCorrelationError("Only the pfsense integration is currently supported")

    _nonempty_string(integration.get("id"), "integration.id")
    _nonempty_string(integration.get("name"), "integration.name")

    sources = integration.get("event_sources")
    mappings = integration.get("check_mappings")
    if not isinstance(sources, list) or not sources:
        raise EvidenceCorrelationError("integration.event_sources must be a non-empty list")
    if not isinstance(mappings, list) or not mappings:
        raise EvidenceCorrelationError("integration.check_mappings must be a non-empty list")

    source_ids: set[str] = set()
    for index, source in enumerate(sources):
        prefix = f"integration.event_sources[{index}]"
        if not isinstance(source, dict):
            raise EvidenceCorrelationError(f"{prefix} must be an object")
        source_id = _nonempty_string(source.get("id"), f"{prefix}.id")
        if source_id in source_ids:
            raise EvidenceCorrelationError(f"Duplicate event source id: {source_id}")
        source_ids.add(source_id)
        source["sender_ip"] = _ip(source.get("sender_ip"), f"{prefix}.sender_ip")

    mapping_keys: set[tuple[str, int]] = set()
    for index, mapping in enumerate(mappings):
        prefix = f"integration.check_mappings[{index}]"
        if not isinstance(mapping, dict):
            raise EvidenceCorrelationError(f"{prefix} must be an object")
        check_id = _nonempty_string(mapping.get("check_id"), f"{prefix}.check_id")

        source_id = _nonempty_string(
            mapping.get("event_source_id"), f"{prefix}.event_source_id"
        )
        if source_id not in source_ids:
            raise EvidenceCorrelationError(f"{prefix} references an unknown event source")

        _nonempty_string(mapping.get("interface"), f"{prefix}.interface")
        _nonempty_string(mapping.get("rule_tracker"), f"{prefix}.rule_tracker")

        action = _nonempty_string(mapping.get("action"), f"{prefix}.action").lower()
        direction = _nonempty_string(mapping.get("direction"), f"{prefix}.direction").lower()
        protocol = _nonempty_string(mapping.get("protocol"), f"{prefix}.protocol").lower()
        if action not in VALID_ACTIONS:
            raise EvidenceCorrelationError(f"{prefix}.action must be block or pass")
        if direction not in VALID_DIRECTIONS:
            raise EvidenceCorrelationError(f"{prefix}.direction must be in or out")
        if protocol not in VALID_PROTOCOLS:
            raise EvidenceCorrelationError(f"{prefix}.protocol must be tcp or udp")

        mapping["action"] = action
        mapping["direction"] = direction
        mapping["protocol"] = protocol
        mapping["source_ip"] = _ip(mapping.get("source_ip"), f"{prefix}.source_ip")
        mapping["destination_ip"] = _ip(
            mapping.get("destination_ip"), f"{prefix}.destination_ip"
        )
        destination_port = _port(
            mapping.get("destination_port"), f"{prefix}.destination_port"
        )
        mapping_key = (check_id, destination_port)
        if mapping_key in mapping_keys:
            raise EvidenceCorrelationError(
                f"Duplicate check mapping for {check_id} on port {destination_port}"
            )
        mapping_keys.add(mapping_key)
        mapping["destination_port"] = destination_port

    for key in ("before_seconds", "after_seconds"):
        value = correlation.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 60
        ):
            raise EvidenceCorrelationError(
                f"correlation.{key} must be a finite number between 0 and 60"
            )

    if correlation.get("duplicate_handling") != "group_by_probe_attempt":
        raise EvidenceCorrelationError(
            "correlation.duplicate_handling must be group_by_probe_attempt"
        )

    return config


def _read_events(path: str | Path):
    """Yield bounded JSONL records; malformed lines are ignored, never trusted."""
    try:
        raw_data = read_bounded_file(
            path,
            max_bytes=64 * 1024 * 1024,
            label="Evidence JSONL file",
        )
    except SecureFileError as exc:
        raise EvidenceCorrelationError(str(exc)) from exc

    handle = BytesIO(raw_data)
    line_number = 0

    while True:
        raw_line = handle.readline(MAX_JSONL_LINE_BYTES + 1)
        if not raw_line:
            break
        line_number += 1

        if len(raw_line) > MAX_JSONL_LINE_BYTES:
            yield {"_invalid_line": line_number, "_error": "line_too_large"}
            while raw_line and not raw_line.endswith(b"\\n"):
                raw_line = handle.readline(MAX_JSONL_LINE_BYTES + 1)
            continue

        try:
            record = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            yield {"_invalid_line": line_number, "_error": "invalid_json"}
            continue

        if not isinstance(record, dict):
            yield {"_invalid_line": line_number, "_error": "record_not_object"}
            continue

        record["_line_number"] = line_number
        yield record


def _source_lookup(integration: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in integration["event_sources"]}


def _packet_signature(parsed: dict[str, Any]) -> tuple[Any, ...]:
    """Identify retransmissions of the same TCP packet within a probe attempt."""
    fields = parsed.get("filterlog_fields")
    packet_length = flags = sequence = acknowledgement = None

    if isinstance(fields, list) and len(fields) > 25:
        # pfSense IPv4 filterlog: length=17, flags=23,
        # sequence=24, acknowledgement=25.
        packet_length = int(fields[17])
        flags = fields[23]
        sequence = fields[24]
        acknowledgement = fields[25]

    return (
        parsed.get("source_ip"),
        parsed.get("source_port"),
        parsed.get("destination_ip"),
        parsed.get("destination_port"),
        parsed.get("protocol"),
        packet_length,
        flags,
        sequence,
        acknowledgement,
    )


def _valid_packet_metadata(parsed: dict[str, Any]) -> bool:
    """Verify parsed packet metadata against its original pfSense CSV fields."""
    if not isinstance(parsed, dict):
        return False

    fields = parsed.get("filterlog_fields")

    if (
        not isinstance(fields, list)
        or len(fields) < 26
        or not all(isinstance(value, str) for value in fields)
    ):
        return False

    try:
        source_ip = _ip(parsed.get("source_ip"), "event.source_ip")
        destination_ip = _ip(
            parsed.get("destination_ip"), "event.destination_ip"
        )
    except EvidenceCorrelationError:
        return False

    protocol = parsed.get("protocol")
    if protocol not in VALID_PROTOCOLS:
        return False

    source_port = parsed.get("source_port")
    destination_port = parsed.get("destination_port")

    if (
        isinstance(source_port, bool)
        or not isinstance(source_port, int)
        or not 0 <= source_port <= 65535
    ):
        return False

    if (
        isinstance(destination_port, bool)
        or not isinstance(destination_port, int)
        or not 1 <= destination_port <= 65535
    ):
        return False

    # Validate the original filterlog fields rather than trusting the
    # collector's parsed representation alone.
    if not fields[17].isdigit():
        return False

    packet_length = int(fields[17])
    if not 20 <= packet_length <= 65535:
        return False

    expected_protocol_id = {"tcp": "6", "udp": "17"}[protocol]

    try:
        raw_source_ip = str(ipaddress.ip_address(fields[18]))
        raw_destination_ip = str(ipaddress.ip_address(fields[19]))
        raw_source_port = int(fields[20])
        raw_destination_port = int(fields[21])
    except (ValueError, IndexError):
        return False

    if not 0 <= raw_source_port <= 65535:
        return False

    if not 1 <= raw_destination_port <= 65535:
        return False

    expected_values = (
        (fields[5], "match"),
        (fields[6], parsed.get("action")),
        (fields[7], parsed.get("direction")),
        (fields[8], "4"),
        (fields[15], expected_protocol_id),
        (fields[16], protocol),
        (raw_source_ip, source_ip),
        (raw_destination_ip, destination_ip),
        (raw_source_port, source_port),
        (raw_destination_port, destination_port),
        (fields[3], str(parsed.get("rule_tracker"))),
        (fields[4], parsed.get("interface")),
    )

    if any(actual != expected for actual, expected in expected_values):
        return False

    if parsed.get("action") not in VALID_ACTIONS:
        return False

    if parsed.get("direction") not in VALID_DIRECTIONS:
        return False

    return True


def correlate_probe(
    probe_path: str | Path,
    evidence_config_path: str | Path,
    events_path: str | Path,
    policy_path: str | Path,
    *,
    _probe_data: dict[str, Any] | None = None,
    _policy: SegmentationPolicy | None = None,
) -> dict[str, Any]:
    """Correlate one probe run against its authoritative policy and pfSense evidence."""
    probe = (
        _load_json(probe_path, "Probe")
        if _probe_data is None
        else _probe_data
    )

    if not isinstance(probe, dict):
        raise EvidenceCorrelationError("Probe input must be a JSON object")
    measurement = probe.get("measurement")
    observations = probe.get("observations")
    if not isinstance(measurement, dict) or not isinstance(observations, dict):
        raise EvidenceCorrelationError(
            "Probe JSON must contain measurement and observations objects"
        )

    run_id = _nonempty_string(measurement.get("run_id"), "measurement.run_id")

    if _policy is None:
        try:
            policy = load_policy(policy_path)
        except PolicyValidationError as exc:
            raise EvidenceCorrelationError(
                f"Authoritative policy is invalid: {exc}"
            ) from exc
    else:
        if not isinstance(_policy, SegmentationPolicy):
            raise EvidenceCorrelationError(
                "Supplied authoritative policy has an invalid type"
            )
        policy = _policy

    probe_policy_id = _nonempty_string(
        measurement.get("policy_id"), "measurement.policy_id"
    )
    if probe_policy_id != policy.policy_id:
        raise EvidenceCorrelationError(
            "Probe policy_id does not match the authoritative policy"
        )

    probe_source_zone = _nonempty_string(
        measurement.get("source_zone"), "measurement.source_zone"
    )
    policy_zone_ids = {zone.id for zone in policy.zones}
    if probe_source_zone not in policy_zone_ids:
        raise EvidenceCorrelationError(
            "Probe source_zone is not defined in the authoritative policy"
        )
    details = measurement.get("details")
    if not isinstance(details, list):
        raise EvidenceCorrelationError("measurement.details must be a list")

    selected_checks = {
        check.id: check
        for check in policy.checks
        if check.source_zone == probe_source_zone
    }
    if not selected_checks:
        raise EvidenceCorrelationError(
            "Authoritative policy contains no checks for the probe source zone"
        )

    if set(observations) != set(selected_checks):
        raise EvidenceCorrelationError(
            "Probe observations do not exactly match the policy checks for its source zone"
        )

    for check_id, observed in observations.items():
        if observed not in {"reachable", "inconclusive"}:
            raise EvidenceCorrelationError(
                f"Root observation for {check_id} has an invalid probe state"
            )

    expected_detail_keys = {
        (check.id, port)
        for check in selected_checks.values()
        for port in check.ports
    }

    probe_details: dict[tuple[str, int], dict[str, Any]] = {}

    for index, detail in enumerate(details):
        prefix = f"measurement.details[{index}]"
        if not isinstance(detail, dict):
            raise EvidenceCorrelationError(f"{prefix} must be an object")

        check_id = _nonempty_string(detail.get("check_id"), f"{prefix}.check_id")
        if check_id not in selected_checks:
            raise EvidenceCorrelationError(
                f"{prefix} references a check outside the selected policy scope"
            )

        port = _port(detail.get("port"), f"{prefix}.port")
        detail_key = (check_id, port)

        if detail_key in probe_details:
            raise EvidenceCorrelationError(
                f"Duplicate probe detail for check {check_id} on port {port}"
            )

        check = selected_checks[check_id]
        expected_fields = {
            "check_name": check.name,
            "source_zone": check.source_zone,
            "destination_zone": check.destination_zone,
            "destination_host": check.destination_host,
            "protocol": check.protocol,
            "expected": check.expected,
        }

        for field, expected_value in expected_fields.items():
            if detail.get(field) != expected_value:
                raise EvidenceCorrelationError(
                    f"{prefix}.{field} does not match the authoritative policy"
                )

        if port not in check.ports:
            raise EvidenceCorrelationError(
                f"{prefix}.port is not defined by the authoritative policy"
            )

        observed = detail.get("observed")
        if observed not in {"reachable", "inconclusive"}:
            raise EvidenceCorrelationError(
                f"{prefix}.observed has an invalid probe state"
            )

        source_ip = detail.get("source_ip")
        if source_ip is not None:
            _ip(source_ip, f"{prefix}.source_ip")

        probe_start = _timestamp(detail.get("started_at"), f"{prefix}.started_at")
        probe_end = _timestamp(detail.get("completed_at"), f"{prefix}.completed_at")
        if probe_end < probe_start:
            raise EvidenceCorrelationError(
                f"{prefix} completed before it started"
            )

        probe_details[detail_key] = detail

    if set(probe_details) != expected_detail_keys:
        missing = sorted(expected_detail_keys - set(probe_details))
        unexpected = sorted(set(probe_details) - expected_detail_keys)
        raise EvidenceCorrelationError(
            f"Probe details do not cover the authoritative policy ports "
            f"(missing={missing}, unexpected={unexpected})"
        )

    for check_id, check in selected_checks.items():
        port_observations = [
            probe_details[(check_id, port)]["observed"]
            for port in check.ports
        ]

        if check.expected == "deny":
            aggregate = (
                "reachable"
                if "reachable" in port_observations
                else "inconclusive"
            )
        else:
            aggregate = (
                "reachable"
                if all(value == "reachable" for value in port_observations)
                else "inconclusive"
            )

        if observations[check_id] != aggregate:
            raise EvidenceCorrelationError(
                f"Root observation for {check_id} does not match its port-level results"
            )

    config = _load_configuration(evidence_config_path)
    integration = config["integration"]
    correlation = config["correlation"]
    sources = _source_lookup(integration)
    mappings = integration["check_mappings"]

    for mapping in mappings:
        check_id = mapping["check_id"]
        check = selected_checks.get(check_id)

        if check is None:
            raise EvidenceCorrelationError(
                f"Firewall mapping references a check outside the selected policy scope: {check_id}"
            )

        port = mapping["destination_port"]
        if port not in check.ports:
            raise EvidenceCorrelationError(
                f"Firewall mapping for {check_id} references an unauthorized policy port: {port}"
            )

        if (
            mapping["destination_ip"] != check.destination_host
            or mapping["protocol"] != check.protocol
        ):
            raise EvidenceCorrelationError(
                f"Firewall mapping for {check_id}:{port} conflicts with the authoritative policy"
            )

    results: list[dict[str, Any]] = []

    for mapping in mappings:
        check_id = mapping["check_id"]
        port = mapping["destination_port"]
        detail = probe_details.get((check_id, port))
        if detail is None:
            results.append({
                "check_id": check_id,
                "port": port,
                "status": "not_evaluated",
                "reason": "no_probe_detail_for_mapped_check",
                "matched_event_count": 0,
                "unique_packet_count": 0,
                "event_ids": [],
            })
            continue

        source = sources[mapping["event_source_id"]]

        required_action = "block" if detail["expected"] == "deny" else "pass"
        if mapping["action"] != required_action:
            results.append({
                "check_id": check_id,
                "port": port,
                "status": "inconclusive",
                "reason": "mapping_action_conflicts_with_policy_expectation",
                "matched_event_count": 0,
                "unique_packet_count": 0,
                "event_ids": [],
            })
            continue

        expected = {
            "source_ip": mapping["source_ip"],
            "destination_ip": mapping["destination_ip"],
            "protocol": mapping["protocol"],
            "destination_port": mapping["destination_port"],
        }

        # The probe itself must describe the same exact flow as the mapping.
        probe_source = detail.get("source_ip")
        if not isinstance(probe_source, str) or not probe_source:
            results.append({
                "check_id": check_id,
                "port": port,
                "status": "inconclusive",
                "reason": "probe_source_ip_missing",
                "matched_event_count": 0,
                "unique_packet_count": 0,
                "event_ids": [],
            })
            continue

        try:
            probe_start = _timestamp(detail.get("started_at"), "detail.started_at")
            probe_end = _timestamp(detail.get("completed_at"), "detail.completed_at")
            if probe_end < probe_start:
                raise EvidenceCorrelationError("Probe detail completed before it started")
            probe_flow = {
                "source_ip": _ip(probe_source, "detail.source_ip"),
                "destination_ip": _ip(detail.get("destination_host"), "detail.destination_host"),
                "protocol": _nonempty_string(detail.get("protocol"), "detail.protocol").lower(),
                "destination_port": _port(detail.get("port"), "detail.port"),
            }
        except EvidenceCorrelationError as exc:
            results.append({
                "check_id": check_id,
                "port": port,
                "status": "inconclusive",
                "reason": f"invalid_probe_detail: {exc}",
                "matched_event_count": 0,
                "unique_packet_count": 0,
                "event_ids": [],
            })
            continue

        if probe_flow != expected:
            results.append({
                "check_id": check_id,
                "port": port,
                "status": "inconclusive",
                "reason": "probe_flow_does_not_match_configured_mapping",
                "matched_event_count": 0,
                "unique_packet_count": 0,
                "event_ids": [],
            })
            continue

        lower = probe_start - timedelta(seconds=correlation["before_seconds"])
        upper = probe_end + timedelta(seconds=correlation["after_seconds"])

        matching: list[dict[str, Any]] = []
        malformed_count = 0
        evidence_limit_exceeded = False
        seen_event_ids: set[str] = set()
        duplicate_event_id = False

        # Iterate over the bounded in-memory JSONL snapshot.
        # _read_events enforces total-file and per-line size limits.
        # The file is reread for each mapped check.
        for event in _read_events(events_path):
            if "_invalid_line" in event:
                malformed_count += 1
                continue

            parsed = event.get("parsed")
            if not isinstance(parsed, dict):
                continue
            try:
                event_sender_ip = _ip(event.get("sender_ip"), "event.sender_ip")
            except EvidenceCorrelationError:
                continue

            if event_sender_ip != source["sender_ip"]:
                continue
            if parsed.get("event_type") != "pf_filterlog":
                continue
            if parsed.get("parse_status") != "parsed":
                continue
            if not _valid_packet_metadata(parsed):
                continue
            try:
                received_at = _timestamp(event.get("received_at"), "event.received_at")
            except EvidenceCorrelationError:
                continue
            if not lower <= received_at <= upper:
                continue

            exact_fields = (
                parsed.get("interface") == mapping["interface"]
                and str(parsed.get("rule_tracker")) == mapping["rule_tracker"]
                and parsed.get("action") == mapping["action"]
                and parsed.get("direction") == mapping["direction"]
                and str(parsed.get("protocol", "")).lower() == mapping["protocol"]
                and parsed.get("source_ip") == expected["source_ip"]
                and parsed.get("destination_ip") == expected["destination_ip"]
                and parsed.get("destination_port") == expected["destination_port"]
            )
            if not exact_fields:
                continue

            # Require a unique, non-empty event ID for traceability.
            event_id = event.get("event_id")
            if not isinstance(event_id, str) or not event_id.strip():
                continue
            event_id = event_id.strip()

            if event_id in seen_event_ids:
                duplicate_event_id = True
                continue

            if len(matching) >= MAX_MATCHING_EVENTS_PER_CHECK:
                evidence_limit_exceeded = True
                break

            seen_event_ids.add(event_id)

            matching.append({
                "event_id": event_id,
                "line_number": event.get("_line_number"),
                "received_at": received_at.isoformat(timespec="milliseconds"),
                "sender_ip": event["sender_ip"],
                "interface": parsed["interface"],
                "rule_tracker": str(parsed["rule_tracker"]),
                "action": parsed["action"],
                "direction": parsed["direction"],
                "source_ip": parsed["source_ip"],
                "source_port": parsed.get("source_port"),
                "destination_ip": parsed["destination_ip"],
                "destination_port": parsed["destination_port"],
                "protocol": parsed["protocol"],
                "packet_signature": _packet_signature(parsed),
            })

        unique_signatures = {
            item["packet_signature"] for item in matching
        }
        event_ids = [item["event_id"] for item in matching]

        if evidence_limit_exceeded:
            status = "inconclusive"
            reason = "matching_event_limit_exceeded"
        elif duplicate_event_id:
            status = "ambiguous"
            reason = "duplicate_event_id"
        elif not matching:
            status = "no_matching_evidence"
            reason = "no_event_matched_all_configured_fields_within_time_window"
        elif len(unique_signatures) > 1:
            status = "ambiguous"
            reason = "multiple_distinct_packet_signatures_matched_one_probe_window"
        elif (
            detail["observed"] == "reachable" and mapping["action"] == "block"
        ):
            status = "contradictory"
            reason = "probe_and_firewall_evidence_conflict"
        else:
            status = "corroborated"
            reason = "exact_firewall_rule_event_correlated_with_probe_attempt"

        results.append({
            "check_id": check_id,
            "port": port,
            "status": status,
            "reason": reason,
            "probe_observed": detail.get("observed"),
            "configured_firewall_action": mapping["action"],
            "matched_event_count": len(matching),
            "unique_packet_count": len(unique_signatures),
            "duplicate_packet_count": max(0, len(matching) - len(unique_signatures)),
            "event_ids": event_ids,
            "events": [
                {key: value for key, value in item.items() if key != "packet_signature"}
                for item in matching
            ],
            "malformed_jsonl_line_count": malformed_count,
            "evidence_limit_exceeded": evidence_limit_exceeded,
            "correlation_window": {
                "start": lower.isoformat(timespec="milliseconds"),
                "end": upper.isoformat(timespec="milliseconds"),
            },
        })

    return {
        "correlation_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "integration": {
            "id": integration["id"],
            "name": integration["name"],
            "platform": integration["platform"],
        },
        "probe_run_id": run_id,
        "probe_source_zone": measurement.get("source_zone"),
        "results": results,
        "trust_and_scope_limitations": [
            "Syslog sender identity is based on source-IP allowlisting, not cryptographic authentication.",
            "UDP syslog does not guarantee delivery, confidentiality, or sender authenticity.",
            "received_at is collector receipt time, not a verified firewall event timestamp.",
            "Reliable time correlation depends on synchronized probe-host and firewall clocks.",
            "A correlated event supports only the exact configured flow, rule, and probe window.",
            "Corroborated means an event matched the configured correlation criteria; it is not cryptographic verification of firewall enforcement or a PCI DSS compliance determination.",
            "Multiple retransmission records are grouped and are not independent probe attempts.",
            "This report does not establish full PCI DSS compliance or replace a qualified assessment.",
        ],
    }
