"""Execute and persist bounded assessments against immutable policy versions."""

from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import json
import math
from functools import partial
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError

from segcheck.assessment import AssessmentError, _validate_correlation
from segcheck.evidence_correlator import correlate_probe
from segcheck.policy_engine import PolicyValidationError, evaluate_policy, validate_policy_data
from segcheck.probe import method_probe, probe_points, probe_policy, tcp_connect_probe

from segcheck_web.extensions import db
from segcheck_web.models import Assessment, Policy, PolicyVersion, User
from segcheck_web.services.findings import attach_guidance
from segcheck_web.services.patience import Patience, RunStopped, RunWatch


MAX_WEB_PROBE_ATTEMPTS = 400  # a whole standard in one run; each attempt times out after 1 s
WEB_PROBE_TIMEOUT_SECONDS = 1.0
MAX_ASSESSMENT_REPORT_BYTES = 4 * 1024 * 1024


class AssessmentExecutionError(ValueError):
    """Raised when a web assessment cannot safely be executed or saved."""


def _measurement_timestamp(value, field):
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise AssessmentExecutionError(
            f"Probe measurement has an invalid {field} timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AssessmentExecutionError(
            f"Probe measurement has an invalid {field} timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AssessmentExecutionError(
            f"Probe measurement {field} timestamp must include a timezone"
        )
    return parsed


def _validate_probe_measurement(measurement, policy, source_zone, observations):
    """Validate and return a safe, policy-bound copy of the probe measurement."""
    if not isinstance(measurement, dict):
        raise AssessmentExecutionError("Probe engine returned an invalid measurement")

    if (
        measurement.get("policy_id") != policy.policy_id
        or measurement.get("source_zone") != source_zone
    ):
        raise AssessmentExecutionError(
            "Probe measurement identity does not match the requested assessment"
        )

    run_id = measurement.get("run_id")
    if (
        not isinstance(run_id, str)
        or not run_id.strip()
        or run_id != run_id.strip()
        or len(run_id) > 64
    ):
        raise AssessmentExecutionError("Probe measurement has an invalid run ID")

    started_at = _measurement_timestamp(
        measurement.get("started_at"), "run start"
    )
    completed_at = _measurement_timestamp(
        measurement.get("completed_at"), "run completion"
    )
    if completed_at < started_at:
        raise AssessmentExecutionError(
            "Probe measurement completed before it started"
        )

    method = measurement.get("method")
    scope = measurement.get("scope")
    interpretation_limit = measurement.get("interpretation_limit")
    for field, value, maximum in (
        ("method", method, 500),
        ("scope", scope, 1000),
        ("interpretation limit", interpretation_limit, 2000),
    ):
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > maximum
        ):
            raise AssessmentExecutionError(
                f"Probe measurement has an invalid {field}"
            )

    timeout = measurement.get("timeout_seconds")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout != WEB_PROBE_TIMEOUT_SECONDS
    ):
        raise AssessmentExecutionError(
            "Probe measurement timeout does not match the web assessment limit"
        )

    selected_checks = {
        check.id: check
        for check in policy.checks
        if check.source_zone == source_zone
    }
    expected_keys = {
        (check.id, port)
        for check in selected_checks.values()
        for port in probe_points(check)
    }

    details = measurement.get("details")
    if not isinstance(details, list) or len(details) != len(expected_keys):
        raise AssessmentExecutionError(
            "Probe measurement does not cover the complete selected policy scope"
        )

    clean_details = []
    observed_by_check = {check_id: [] for check_id in selected_checks}
    seen_keys = set()

    for index, detail in enumerate(details):
        label = f"Probe measurement detail {index}"
        if not isinstance(detail, dict):
            raise AssessmentExecutionError(f"{label} must be an object")

        check_id = detail.get("check_id")
        port = detail.get("port")
        if (
            not isinstance(check_id, str)
            or check_id not in selected_checks
            or isinstance(port, bool)
            or not isinstance(port, int)
        ):
            raise AssessmentExecutionError(f"{label} has an invalid check or port")

        key = (check_id, port)
        check = selected_checks[check_id]
        if key not in expected_keys or key in seen_keys:
            raise AssessmentExecutionError(
                f"{label} is duplicated or outside the selected policy scope"
            )
        seen_keys.add(key)

        expected_fields = {
            "check_name": check.name,
            "source_zone": check.source_zone,
            "destination_zone": check.destination_zone,
            "destination_host": check.destination_host,
            "protocol": check.protocol,
            "expected": check.expected,
        }
        if any(detail.get(field) != value for field, value in expected_fields.items()):
            raise AssessmentExecutionError(
                f"{label} conflicts with the authoritative policy snapshot"
            )

        observed = detail.get("observed")
        if observed not in {"reachable", "inconclusive"}:
            raise AssessmentExecutionError(f"{label} has an invalid observation")

        reason = detail.get("reason")
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > 512
        ):
            raise AssessmentExecutionError(f"{label} has an invalid reason")

        duration = detail.get("duration_ms")
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or not 0 <= duration <= 60000
        ):
            raise AssessmentExecutionError(f"{label} has an invalid duration")

        source_ip = detail.get("source_ip")
        if source_ip is not None:
            if not isinstance(source_ip, str) or len(source_ip) > 64:
                raise AssessmentExecutionError(f"{label} has an invalid source IP")
            try:
                ipaddress.ip_address(source_ip)
            except ValueError as exc:
                raise AssessmentExecutionError(
                    f"{label} has an invalid source IP"
                ) from exc

        detail_started = _measurement_timestamp(
            detail.get("started_at"), f"detail {index} start"
        )
        detail_completed = _measurement_timestamp(
            detail.get("completed_at"), f"detail {index} completion"
        )
        if (
            detail_completed < detail_started
            or detail_started < started_at
            or detail_completed > completed_at
        ):
            raise AssessmentExecutionError(
                f"{label} timestamps fall outside the probe run window"
            )

        observed_by_check[check_id].append(observed)
        clean_details.append({
            "check_id": check_id,
            "check_name": check.name,
            "source_zone": check.source_zone,
            "source_ip": source_ip,
            "destination_zone": check.destination_zone,
            "destination_host": check.destination_host,
            "protocol": check.protocol,
            "port": port,
            "expected": check.expected,
            "observed": observed,
            "reason": reason,
            "duration_ms": float(duration),
            "started_at": detail_started.isoformat(timespec="milliseconds"),
            "completed_at": detail_completed.isoformat(timespec="milliseconds"),
        })

    if seen_keys != expected_keys:
        raise AssessmentExecutionError(
            "Probe measurement is missing one or more policy ports"
        )

    if not isinstance(observations, dict) or set(observations) != set(selected_checks):
        raise AssessmentExecutionError(
            "Probe observations do not match the selected policy checks"
        )

    for check_id, check in selected_checks.items():
        states = observed_by_check[check_id]
        aggregate = (
            "reachable"
            if (
                any(state == "reachable" for state in states)
                if check.expected == "deny"
                else all(state == "reachable" for state in states)
            )
            else "inconclusive"
        )
        if observations.get(check_id) != aggregate:
            raise AssessmentExecutionError(
                f"Probe observation for {check_id} conflicts with its port measurements"
            )

    return {
        "measurement_version": 1,
        "policy_id": policy.policy_id,
        "run_id": run_id,
        "started_at": started_at.isoformat(timespec="milliseconds"),
        "completed_at": completed_at.isoformat(timespec="milliseconds"),
        "source_zone": source_zone,
        "method": method,
        "timeout_seconds": float(timeout),
        "scope": scope,
        "interpretation_limit": interpretation_limit,
        "source_ip_semantics": (
            "The source IP is selected by local OS route lookup and is not "
            "explicitly bound to the TCP socket by this probe implementation."
        ),
        "details": clean_details,
    }


def _canonical_snapshot_digest(snapshot):
    """Calculate the digest using the policy import canonical JSON format."""
    encoded = json.dumps(
        snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _without_icmp(policy, probe):
    """Copies of the policy and probe data restricted to port-based (TCP/UDP) checks."""
    import dataclasses
    keep = {check.id for check in policy.checks if check.protocol != "icmp"}
    if len(keep) == len(policy.checks):
        return policy, probe
    filtered_policy = dataclasses.replace(policy, checks=tuple(check for check in policy.checks if check.id in keep))
    filtered_probe = copy.deepcopy(probe)
    filtered_probe["observations"] = {key: value for key, value in probe.get("observations", {}).items() if key in keep}
    measurement = filtered_probe.get("measurement", {})
    measurement["details"] = [detail for detail in measurement.get("details", []) if detail.get("check_id") in keep]
    return filtered_policy, filtered_probe


def _not_configured_evidence(report):
    """Mark firewall evidence unavailable without implying a successful check."""
    total = 0

    for result in report["results"]:
        entries = []
        for port in result["ports"]:
            entries.append({
                "port": port,
                "status": "not_evaluated",
                "reason": "firewall_integration_not_configured",
            })
            total += 1
        result["firewall_evidence"] = entries

    return {
        "status": "not_configured",
        "total": total,
        "corroborated": 0,
        "contradictory": 0,
        "ambiguous": 0,
        "no_matching_evidence": 0,
        "inconclusive": 0,
        "not_evaluated": total,
    }


def _attach_correlated_evidence(report, correlation, policy, source_zone):
    evidence_by_port = _validate_correlation(
        correlation,
        policy,
        source_zone,
    )

    for result in report["results"]:
        entries = []
        for port in result["ports"]:
            evidence = evidence_by_port.get((result["check_id"], port))
            if evidence is None:
                entries.append({
                    "port": port,
                    "status": "not_evaluated",
                    "reason": "no_correlated_evidence_result_for_this_port",
                })
            else:
                entries.append({
                    "port": port,
                    "status": evidence["status"],
                    "reason": evidence["reason"],
                    "matched_event_count": evidence.get(
                        "matched_event_count", 0
                    ),
                    "event_ids": evidence.get("event_ids", []),
                })
        result["firewall_evidence"] = entries

    statuses = [item["status"] for item in evidence_by_port.values()]
    return {
        "status": "configured",
        "total": len(statuses),
        "corroborated": statuses.count("corroborated"),
        "contradictory": statuses.count("contradictory"),
        "ambiguous": statuses.count("ambiguous"),
        "no_matching_evidence": statuses.count("no_matching_evidence"),
        "inconclusive": statuses.count("inconclusive"),
        "not_evaluated": statuses.count("not_evaluated"),
    }


def _log_readers(environment, source_ip):
    """(logged_block, any_log_since) for the run, or (None, None) when no log feed was set up in Step 3."""
    devices = [device for device in (environment or {}).get("devices", []) if device.get("logging")]
    if not devices:
        return None, None
    try:
        from flask import current_app
        from segcheck_web.services.firewall_connector import _parse_time, registry
        connectors = registry(current_app._get_current_object())
    except RuntimeError:
        return None, None

    def any_log_since(since):
        earliest = since - timedelta(seconds=5)
        return any((_parse_time(event.get("received_at")) or earliest) >= earliest
                   for device in devices for event in connectors.events_for(device["id"]))

    def logged_block(host, port, protocol, since):
        earliest = since - timedelta(seconds=1)
        for device in devices:
            for event in connectors.events_for(device["id"]):
                when = _parse_time(event.get("received_at"))
                if (when is not None and when >= earliest and event.get("action") == "block"
                        and event.get("destination_ip") == host and event.get("protocol") == protocol
                        and event.get("source_ip") == source_ip
                        and (protocol == "icmp" or event.get("destination_port") == port)):
                    return True
        return False
    return logged_block, any_log_since


def execute_assessment(
    *,
    policy_id,
    policy_version_id,
    source_zone,
    actor_user_id,
    probe_func=None,
    source_ip=None,
    environment_context=None,
    execution_guard=None,
    progress_callback=None,
):
    """Run a bounded source-zone assessment and persist its immutable report.

    Firewall evidence paths are read only from trusted Flask application
    configuration. They are never accepted from the browser.
    """
    if (
        isinstance(policy_id, bool)
        or not isinstance(policy_id, int)
        or policy_id < 1
        or isinstance(policy_version_id, bool)
        or not isinstance(policy_version_id, int)
        or policy_version_id < 1
        or isinstance(actor_user_id, bool)
        or not isinstance(actor_user_id, int)
        or actor_user_id < 1
    ):
        raise AssessmentExecutionError("Invalid assessment reference")

    if not isinstance(source_zone, str) or not source_zone.strip():
        raise AssessmentExecutionError("A source zone is required")

    if len(source_zone) > 64:
        raise AssessmentExecutionError("Source zone exceeds the allowed length")

    # Load only the exact requested version and verify its ownership.
    policy_record = db.session.get(Policy, policy_id)
    version = (
        db.session.query(PolicyVersion)
        .filter_by(id=policy_version_id, policy_id=policy_id)
        .one_or_none()
    )
    actor = db.session.get(User, actor_user_id)

    if policy_record is None or version is None:
        db.session.rollback()
        raise AssessmentExecutionError("The selected policy version was not found")

    if policy_record.status != "active":
        db.session.rollback()
        raise AssessmentExecutionError("Only active policies can be assessed")

    if actor is None or not actor.is_active:
        db.session.rollback()
        raise AssessmentExecutionError("The authenticated account is unavailable")

    try:
        snapshot = copy.deepcopy(version.snapshot)
        stored_digest = version.snapshot_sha256

        if not isinstance(snapshot, dict):
            raise AssessmentExecutionError("Stored policy snapshot is invalid")

        calculated_digest = _canonical_snapshot_digest(snapshot)
        if (
            not isinstance(stored_digest, str)
            or not hmac.compare_digest(calculated_digest, stored_digest)
        ):
            raise AssessmentExecutionError(
                "Stored policy snapshot integrity verification failed"
            )

        policy = validate_policy_data(snapshot)
        if policy.policy_id != policy_record.policy_key:
            raise AssessmentExecutionError(
                "Stored policy identity does not match its database record"
            )

        if source_zone not in {zone.id for zone in policy.zones}:
            raise AssessmentExecutionError("The selected source zone is not in this policy")

        selected_checks = [
            check for check in policy.checks
            if check.source_zone == source_zone
        ]
        if not selected_checks:
            raise AssessmentExecutionError(
                "The selected source zone has no policy checks"
            )

        unsupported = [
            check.id for check in selected_checks if check.protocol not in {"tcp", "udp", "icmp"}
        ]
        if unsupported:
            raise AssessmentExecutionError(
                "No probe method exists for check(s): " + ", ".join(unsupported)
            )

        attempt_count = sum(len(probe_points(check)) for check in selected_checks)
        if attempt_count > MAX_WEB_PROBE_ATTEMPTS:
            raise AssessmentExecutionError(
                f"Selected scope requires {attempt_count} connection attempts; "
                f"the web limit is {MAX_WEB_PROBE_ATTEMPTS}"
            )

        policy_version_digest = stored_digest

    except (PolicyValidationError, TypeError, ValueError) as exc:
        db.session.rollback()
        if isinstance(exc, AssessmentExecutionError):
            raise
        raise AssessmentExecutionError(
            "The stored policy snapshot could not be validated"
        ) from exc

    if source_ip is not None:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
            if any(ipaddress.ip_address(check.destination_host).version != ipaddress.ip_address(source_ip).version
                   for check in selected_checks):
                raise ValueError("Source and target address families differ")
        except ValueError as exc:
            db.session.rollback()
            raise AssessmentExecutionError("Source and target IP families must match") from exc
        if probe_func is not None:
            raise AssessmentExecutionError("A bound assessment cannot override the TCP probe")
        # Answers are final; a silent attempt is tried once more (longer wait, adapted to this network) unless the
        # firewall's log already shows it blocked that exact attempt. See services/patience.py.
        logged_block, any_log_since = _log_readers(environment_context, source_ip)
        patience = Patience(logged_block)
        # Stops the run early when its setup makes the rest pointless (see patience.RunWatch).
        logging_device = next((d for d in (environment_context or {}).get("devices", []) if d.get("logging")), {})
        hint = (f" on UDP port {logging_device.get('log_port')} of {logging_device.get('log_listen_ip') or source_ip}"
                if logging_device.get("log_port") else "")
        watch = RunWatch(any_log_since, hint)
        tcp_once = partial(tcp_connect_probe, source_ip=source_ip)
        other_once = partial(method_probe, source_ip=source_ip)

        def watched(outcome):
            try:
                watch.check(outcome)
            except RunStopped as exc:
                raise AssessmentExecutionError(str(exc)[:500]) from exc
            return outcome

        def probe_func(host, port, timeout):
            return watched(patience.attempt(lambda wait: tcp_once(host, port, wait), host, port, "tcp"))

        def protocol_probe(protocol, host, port, timeout):
            return watched(patience.attempt(lambda wait: other_once(protocol, host, port, wait), host, port, protocol))
    else:
        protocol_probe = None

    if execution_guard is not None or progress_callback is not None:
        actual_probe = probe_func or tcp_connect_probe
        actual_method = protocol_probe or method_probe

        def reporting_probe(host, port, timeout):
            if execution_guard is not None:
                execution_guard()
            outcome = actual_probe(host, port, timeout)
            if progress_callback is not None:
                progress_callback(host, port, outcome, "tcp")
            return outcome

        def reporting_method(protocol, host, port, timeout):
            if execution_guard is not None:
                execution_guard()
            outcome = actual_method(protocol, host, port, timeout)
            if progress_callback is not None:
                progress_callback(host, port, outcome, protocol)
            return outcome

        probe_func = reporting_probe
        protocol_probe = reporting_method

    # Release the database read transaction before performing network I/O.
    db.session.rollback()

    try:
        probe = probe_policy(
            policy,
            source_zone,
            timeout=WEB_PROBE_TIMEOUT_SECONDS,
            probe_func=probe_func,
            protocol_probe=protocol_probe,
        )
        if not isinstance(probe, dict):
            raise AssessmentExecutionError("Probe engine returned an invalid result")

        measurement = probe.get("measurement")
        observations = probe.get("observations")
        validated_measurement = _validate_probe_measurement(
            measurement,
            policy,
            source_zone,
            observations,
        )
        run_id = validated_measurement["run_id"]
        if source_ip is not None:
            if any(detail["source_ip"] != source_ip for detail in validated_measurement["details"]):
                raise AssessmentExecutionError("Measurement source does not match the bound probe address")
            validated_measurement["source_ip_semantics"] = (
                "TCP/UDP sockets and ICMP echo explicitly bound to the configured address of the PC running SegCheck. "
                "Zone membership is an administrator declaration, not independent proof."
            )
            validated_measurement["method"] = (
                "Per check protocol: TCP connect handshake, UDP protocol request/response, "
                "or ICMP echo, each explicitly bound to the configured local source address"
            )

        # The existing evaluator remains the sole compliance decision-maker.
        report = evaluate_policy(policy, observations)
        report["probe_measurement"] = validated_measurement

        evidence_config = current_app_config("SEGCHECK_EVIDENCE_CONFIG_PATH")
        events_path = current_app_config("SEGCHECK_EVIDENCE_EVENTS_PATH")

        if bool(evidence_config) != bool(events_path):
            raise AssessmentExecutionError(
                "Firewall evidence integration is only partially configured"
            )

        # The legacy server-side pfSense correlator understands TCP/UDP port mappings only.
        # ICMP attempts are left out of it (they get boundary-connector evidence instead).
        legacy_policy, legacy_probe = _without_icmp(policy, probe)
        if evidence_config and events_path and legacy_policy.checks:
            correlation = correlate_probe(
                None,
                evidence_config,
                events_path,
                None,
                _probe_data=legacy_probe,
                _policy=legacy_policy,
            )
            if (
                not isinstance(correlation, dict)
                or correlation.get("probe_run_id") != run_id
                or correlation.get("probe_source_zone") != source_zone
            ):
                raise AssessmentExecutionError(
                    "Firewall correlation does not match this probe run"
                )
            evidence_summary = _attach_correlated_evidence(
                report,
                correlation,
                legacy_policy,
                source_zone,
            )
            report["correlation"] = correlation
        else:
            evidence_summary = _not_configured_evidence(report)

        evaluated_ids = [
            check.id for check in policy.checks
            if check.source_zone == source_zone
        ]
        not_evaluated_ids = [
            check.id for check in policy.checks
            if check.source_zone != source_zone
        ]
        attach_guidance(report, set(evaluated_ids))

        report["assessment"] = {
            "assessment_version": 2,
            "generated_at": datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "probe_run_id": run_id,
            "source_zone": source_zone,
            "scope": {
                "scope_type": "source_zone_only",
                "evaluated_check_ids": evaluated_ids,
                "not_evaluated_check_ids": not_evaluated_ids,
                "policy_check_count": len(policy.checks),
                "probe_attempt_count": attempt_count,
                "scope_warning": (
                    "This assessment covers only the selected source zone. "
                    "Checks belonging to other source zones were not exercised. "
                    "Their INCONCLUSIVE results must not be interpreted as "
                    "completed tests."
                ),
            },
            "evidence_informs_compliance_decision": False,
            "evidence_status": evidence_summary["status"],
            "evidence_summary": evidence_summary,
            "decision_method": (
                "Compliance decisions are derived from validated policy "
                "expectations and network probe observations. Firewall evidence "
                "is supplemental and does not independently establish enforcement."
            ),
        }

        if environment_context is not None:
            report["assessment"]["environment"] = copy.deepcopy(environment_context)
            # Read-only cross-check of each attempt against declared boundary devices' logs.
            from flask import current_app
            from segcheck_web.services.firewall_connector import cross_check, registry
            report["boundary_evidence"] = cross_check(
                validated_measurement["details"], environment_context, registry(current_app._get_current_object()),
                wait=True,  # only sleeps when a listening device is on a tested path
            )

        encoded_report = json.dumps(
            report,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

        if len(encoded_report) > MAX_ASSESSMENT_REPORT_BYTES:
            raise AssessmentExecutionError(
                "Generated assessment report exceeds the storage limit"
            )

        if execution_guard is not None:
            execution_guard()

        record = Assessment(
            policy_id=policy_id,
            policy_version_id=policy_version_id,
            actor_user_id=actor_user_id,
            policy_version_sha256=policy_version_digest,
            source_zone=source_zone,
            probe_run_id=run_id,
            summary=copy.deepcopy(report["summary"]),
            report=report,
        )

        db.session.add(record)
        db.session.commit()
        return record

    except AssessmentExecutionError:
        db.session.rollback()
        raise
    except (
        AssessmentError, PolicyValidationError, ValueError, TypeError, OSError
    ) as exc:
        db.session.rollback()
        raise AssessmentExecutionError(
            "Assessment could not be completed safely"
        ) from exc
    except IntegrityError as exc:
        db.session.rollback()
        raise AssessmentExecutionError(
            "Assessment persistence violated a database integrity constraint"
        ) from exc
    except Exception:
        db.session.rollback()
        raise


def current_app_config(key):
    """Read a trusted server-side setting without accepting request data."""
    from flask import current_app
    return current_app.config.get(key)
