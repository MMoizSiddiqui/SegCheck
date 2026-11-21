"""End-to-end segmentation assessment orchestration.

Combines policy evaluation with firewall evidence correlation.
Correlated evidence is supplemental and cannot independently establish
or change a compliance decision.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .secure_files import SecureFileError, read_bounded_file
from .evidence_correlator import correlate_probe
from .policy_engine import (
    PolicyValidationError,
    SegmentationPolicy,
    evaluate_policy,
    load_policy,
)


class AssessmentError(ValueError):
    """Raised when an assessment cannot be safely constructed."""


VALID_EVIDENCE_STATUSES = {
    "corroborated",
    "contradictory",
    "ambiguous",
    "no_matching_evidence",
    "inconclusive",
    "not_evaluated",
}


def _load_probe_snapshot(path: str | Path) -> dict[str, Any]:
    """Load one bounded, regular-file probe snapshot for the assessment."""
    try:
        raw = read_bounded_file(
            path,
            max_bytes=4 * 1024 * 1024,
            label="Probe file",
        )
        probe = json.loads(raw.decode("utf-8"))
    except SecureFileError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            raise AssessmentError(f"Probe file not found: {path}") from exc
        raise AssessmentError(f"Unable to read valid probe JSON: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssessmentError(f"Unable to read valid probe JSON: {exc}") from exc

    if not isinstance(probe, dict):
        raise AssessmentError("Probe input must be a JSON object")

    return probe


def _validate_correlated_event(event, check, port, prefix):
    """Validate the bounded, displayable fields of one retained firewall event."""
    required = {
        "event_id", "line_number", "received_at", "sender_ip",
        "interface", "rule_tracker", "action", "direction",
        "source_ip", "source_port", "destination_ip",
        "destination_port", "protocol",
    }
    if set(event) != required:
        raise AssessmentError(
            f"{prefix} has event details with an unexpected field set"
        )

    event_id = event["event_id"]
    if (
        not isinstance(event_id, str)
        or not event_id.strip()
        or event_id != event_id.strip()
        or len(event_id) > 256
    ):
        raise AssessmentError(f"{prefix} has invalid event details: event ID")

    line_number = event["line_number"]
    if (
        isinstance(line_number, bool)
        or not isinstance(line_number, int)
        or line_number < 1
    ):
        raise AssessmentError(f"{prefix} has invalid event details: line number")

    received_at = event["received_at"]
    if not isinstance(received_at, str) or not 1 <= len(received_at) <= 64:
        raise AssessmentError(f"{prefix} has invalid event details: receipt time")
    try:
        parsed_time = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AssessmentError(
            f"{prefix} has invalid event details: receipt time"
        ) from exc
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise AssessmentError(
            f"{prefix} has invalid event details: receipt time must include a timezone"
        )

    for field, maximum in (
        ("interface", 64),
        ("rule_tracker", 64),
    ):
        value = event[field]
        if (
            not isinstance(value, str)
            or not value.strip()
            or value != value.strip()
            or len(value) > maximum
        ):
            raise AssessmentError(
                f"{prefix} has invalid event details: {field}"
            )

    for field in ("sender_ip", "source_ip", "destination_ip"):
        value = event[field]
        if not isinstance(value, str) or len(value) > 64:
            raise AssessmentError(
                f"{prefix} has invalid event details: {field}"
            )
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise AssessmentError(
                f"{prefix} has invalid event details: {field}"
            ) from exc

    source_port = event["source_port"]
    if (
        isinstance(source_port, bool)
        or not isinstance(source_port, int)
        or not 1 <= source_port <= 65535
    ):
        raise AssessmentError(
            f"{prefix} has invalid event details: source port"
        )

    if (
        isinstance(event["destination_port"], bool)
        or not isinstance(event["destination_port"], int)
        or event["destination_port"] != port
    ):
        raise AssessmentError(
            f"{prefix} has event details inconsistent with the policy port"
        )

    if event["protocol"] != check.protocol:
        raise AssessmentError(
            f"{prefix} has event details inconsistent with the policy protocol"
        )

    try:
        observed_destination = ipaddress.ip_address(event["destination_ip"])
        policy_destination = ipaddress.ip_address(check.destination_host)
    except ValueError as exc:
        raise AssessmentError(
            f"{prefix} has event details with an invalid policy destination"
        ) from exc

    if observed_destination != policy_destination:
        raise AssessmentError(
            f"{prefix} has event details inconsistent with the policy destination"
        )

    expected_action = "block" if check.expected == "deny" else "pass"
    if event["action"] != expected_action:
        raise AssessmentError(
            f"{prefix} has event details inconsistent with the policy expectation"
        )

    if event["direction"] not in {"in", "out"}:
        raise AssessmentError(
            f"{prefix} has invalid event details: direction"
        )


def _validate_correlation(
    correlation: dict[str, Any],
    policy: SegmentationPolicy,
    source_zone: str,
) -> dict[tuple[str, int], dict[str, Any]]:
    """Validate correlation output before attaching it to an assessment."""
    if not isinstance(correlation, dict):
        raise AssessmentError("Correlation output must be an object")

    results = correlation.get("results")
    if not isinstance(results, list):
        raise AssessmentError("Correlation results must be a list")

    selected_checks = {
        check.id: check
        for check in policy.checks
        if check.source_zone == source_zone
    }

    evidence_by_port: dict[tuple[str, int], dict[str, Any]] = {}

    for index, item in enumerate(results):
        prefix = f"Correlation result {index}"

        if not isinstance(item, dict):
            raise AssessmentError(f"{prefix} must be an object")

        check_id = item.get("check_id")
        port = item.get("port")

        if not isinstance(check_id, str) or check_id not in selected_checks:
            raise AssessmentError(f"{prefix} references an invalid check")

        if isinstance(port, bool) or not isinstance(port, int):
            raise AssessmentError(f"{prefix} has an invalid port")

        if port not in selected_checks[check_id].ports:
            raise AssessmentError(
                f"{prefix} references an unauthorized port"
            )

        status = item.get("status")
        if not isinstance(status, str) or status not in VALID_EVIDENCE_STATUSES:
            raise AssessmentError(f"{prefix} has an invalid evidence status")

        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise AssessmentError(f"{prefix} has an invalid reason")

        event_count = item.get("matched_event_count")
        if (
            isinstance(event_count, bool)
            or not isinstance(event_count, int)
            or event_count < 0
        ):
            raise AssessmentError(f"{prefix} has an invalid event count")

        unique_count = item.get("unique_packet_count")
        if (
            isinstance(unique_count, bool)
            or not isinstance(unique_count, int)
            or unique_count < 0
            or unique_count > event_count
        ):
            raise AssessmentError(f"{prefix} has an invalid unique packet count")

        event_ids = item.get("event_ids")
        if (
            not isinstance(event_ids, list)
            or any(
                not isinstance(event_id, str) or not event_id.strip()
                for event_id in event_ids
            )
        ):
            raise AssessmentError(f"{prefix} has invalid event IDs")

        if len(event_ids) != event_count:
            raise AssessmentError(
                f"{prefix} event count does not match its event IDs"
            )

        if len(set(event_ids)) != len(event_ids):
            raise AssessmentError(f"{prefix} contains duplicate event IDs")

        duplicate_count = item.get("duplicate_packet_count")
        if duplicate_count is not None:
            if (
                isinstance(duplicate_count, bool)
                or not isinstance(duplicate_count, int)
                or duplicate_count < 0
                or duplicate_count != event_count - unique_count
            ):
                raise AssessmentError(
                    f"{prefix} has an inconsistent duplicate packet count"
                )

        limit_exceeded = item.get("evidence_limit_exceeded", False)
        if not isinstance(limit_exceeded, bool):
            raise AssessmentError(
                f"{prefix} has an invalid evidence-limit flag"
            )

        if status in {"not_evaluated", "no_matching_evidence"}:
            if event_count != 0 or unique_count != 0 or limit_exceeded:
                raise AssessmentError(
                    f"{prefix} has event counts inconsistent with its status"
                )

        elif status in {"corroborated", "contradictory"}:
            if event_count < 1 or unique_count != 1 or limit_exceeded:
                raise AssessmentError(
                    f"{prefix} has packet counts inconsistent with its status"
                )

        elif status == "ambiguous":
            if event_count < 1 or limit_exceeded:
                raise AssessmentError(
                    f"{prefix} has event counts inconsistent with ambiguity"
                )
            if (
                reason == "multiple_distinct_packet_signatures_matched_one_probe_window"
                and unique_count < 2
            ):
                raise AssessmentError(
                    f"{prefix} reports multiple packet signatures without "
                    "multiple unique packets"
                )

        elif status == "inconclusive":
            is_limit_result = reason == "matching_event_limit_exceeded"
            if limit_exceeded != is_limit_result:
                raise AssessmentError(
                    f"{prefix} has an inconsistent evidence-limit result"
                )
            if is_limit_result and event_count < 1:
                raise AssessmentError(
                    f"{prefix} reports an exceeded limit without retained events"
                )
            if not is_limit_result and (
                event_count != 0 or unique_count != 0
            ):
                raise AssessmentError(
                    f"{prefix} has unexpected events for this inconclusive result"
                )

        events = item.get("events")
        if event_count > 0 and "events" not in item:
            raise AssessmentError(
                f"{prefix} has event counts but no retained event details"
            )
        if "events" in item:
            if (
                not isinstance(events, list)
                or len(events) != event_count
                or any(not isinstance(event, dict) for event in events)
                or [event.get("event_id") for event in events] != event_ids
            ):
                raise AssessmentError(
                    f"{prefix} has event details inconsistent with its event IDs"
                )
            for event in events:
                _validate_correlated_event(
                    event,
                    selected_checks[check_id],
                    port,
                    prefix,
                )

        malformed_count = item.get("malformed_jsonl_line_count", 0)
        if (
            isinstance(malformed_count, bool)
            or not isinstance(malformed_count, int)
            or malformed_count < 0
        ):
            raise AssessmentError(
                f"{prefix} has an invalid malformed-line count"
            )

        key = (check_id, port)
        if key in evidence_by_port:
            raise AssessmentError(
                "Duplicate evidence result for a check and port"
            )

        evidence_by_port[key] = item

    return evidence_by_port


def create_assessment(
    probe_path: str | Path,
    policy_path: str | Path,
    evidence_config_path: str | Path,
    events_path: str | Path,
) -> dict[str, Any]:
    """Build an assessment using one probe and policy snapshot."""

    # Load each authoritative input once for this assessment.
    probe = _load_probe_snapshot(probe_path)

    try:
        policy = load_policy(policy_path)
    except PolicyValidationError as exc:
        raise AssessmentError(
            f"Unable to load authoritative policy: {exc}"
        ) from exc

    measurement = probe.get("measurement")
    observations = probe.get("observations")

    if not isinstance(measurement, dict):
        raise AssessmentError("Probe measurement must be an object")

    if not isinstance(observations, dict):
        raise AssessmentError("Probe observations must be an object")

    run_id = measurement.get("run_id")
    source_zone = measurement.get("source_zone")

    if not isinstance(run_id, str) or not run_id.strip():
        raise AssessmentError("Probe run ID must be a non-empty string")

    if not isinstance(source_zone, str) or not source_zone.strip():
        raise AssessmentError("Probe source zone must be a non-empty string")

    if measurement.get("policy_id") != policy.policy_id:
        raise AssessmentError(
            "Probe policy does not match the authoritative policy"
        )

    # The correlator receives the exact same in-memory snapshots.
    correlation = correlate_probe(
        probe_path=probe_path,
        evidence_config_path=evidence_config_path,
        events_path=events_path,
        policy_path=policy_path,
        _probe_data=probe,
        _policy=policy,
    )

    if not isinstance(correlation, dict):
        raise AssessmentError("Correlation output must be an object")

    if correlation.get("probe_run_id") != run_id:
        raise AssessmentError(
            "Correlation result does not match the probe run"
        )

    if correlation.get("probe_source_zone") != source_zone:
        raise AssessmentError(
            "Correlation result does not match the probe source zone"
        )

    evidence_by_port = _validate_correlation(
        correlation,
        policy,
        source_zone,
    )

    # The existing evaluator remains the sole source of compliance decisions.
    report = evaluate_policy(policy, observations)

    for result in report["results"]:
        port_evidence = []

        for port in result["ports"]:
            evidence = evidence_by_port.get((result["check_id"], port))

            if evidence is None:
                port_evidence.append({
                    "port": port,
                    "status": "not_evaluated",
                    "reason": "no_correlated_evidence_result_for_this_port",
                })
            else:
                port_evidence.append({
                    "port": port,
                    "status": evidence["status"],
                    "reason": evidence["reason"],
                    "matched_event_count": evidence.get(
                        "matched_event_count", 0
                    ),
                    "event_ids": evidence.get("event_ids", []),
                })

        result["firewall_evidence"] = port_evidence

    evidence_statuses = [
        item["status"] for item in evidence_by_port.values()
    ]

    evidence_summary = {
        "total": len(evidence_statuses),
        "corroborated": evidence_statuses.count("corroborated"),
        "contradictory": evidence_statuses.count("contradictory"),
        "ambiguous": evidence_statuses.count("ambiguous"),
        "no_matching_evidence": evidence_statuses.count(
            "no_matching_evidence"
        ),
        "inconclusive": evidence_statuses.count("inconclusive"),
        "not_evaluated": evidence_statuses.count("not_evaluated"),
    }

    evaluated_check_ids = [
        check.id
        for check in policy.checks
        if check.source_zone == source_zone
    ]

    not_evaluated_check_ids = [
        check.id
        for check in policy.checks
        if check.source_zone != source_zone
    ]

    report["assessment"] = {
        "assessment_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(
            timespec="milliseconds"
        ),
        "probe_run_id": run_id,
        "source_zone": source_zone,
        "scope": {
            "scope_type": "source_zone_only",
            "evaluated_check_ids": evaluated_check_ids,
            "not_evaluated_check_ids": not_evaluated_check_ids,
            "policy_check_count": len(policy.checks),
            "scope_warning": (
                "This assessment covers only the selected source zone. "
                "Checks belonging to other source zones were not exercised. "
                "Their INCONCLUSIVE results must not be interpreted as "
                "completed tests."
            ),
        },
        "evidence_informs_compliance_decision": False,
        "evidence_summary": evidence_summary,
        "decision_method": (
            "Compliance decisions are derived from validated policy "
            "expectations and network probe observations. Firewall evidence "
            "is supplemental and does not independently establish enforcement."
        ),
    }

    report["correlation"] = correlation

    return report
