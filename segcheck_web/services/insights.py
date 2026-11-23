"""Read-only analytics derived from persisted assessment reports and inventory.

Everything here is computed from saved, immutable reports and the configured
environment. Nothing probes the network, and nothing is inferred beyond what a
report recorded: checks a run did not exercise are counted separately and never
treated as completed coverage.
"""

from __future__ import annotations

from datetime import datetime, timezone

from segcheck_web.extensions import db
from segcheck_web.models import Assessment, Policy, PolicyVersion
from segcheck_web.models.jobs import AssessmentJob
from segcheck_web.services.report_analysis import _evidence_by_check, _evidence_state

RESULT_KEYS = ("pass", "fail", "inconclusive")
MAX_REPORTS = 60


def _iso(value):
    """ISO-8601 with explicit UTC; SQLite returns naive UTC datetimes."""
    if not isinstance(value, datetime):
        return None
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat()


def _scope(report):
    assessment = report.get("assessment") if isinstance(report, dict) else None
    scope = assessment.get("scope") if isinstance(assessment, dict) else None
    if not isinstance(scope, dict):  # Older reports store a descriptive string.
        return None, set()
    evaluated = scope.get("evaluated_check_ids")
    skipped = scope.get("not_evaluated_check_ids") or []
    return (set(evaluated) if isinstance(evaluated, list) else None), set(skipped if isinstance(skipped, list) else [])


def _duration_ms(report):
    measurement = report.get("probe_measurement", {}) if isinstance(report, dict) else {}
    try:
        started = datetime.fromisoformat(str(measurement["started_at"]).replace("Z", "+00:00"))
        completed = datetime.fromisoformat(str(measurement["completed_at"]).replace("Z", "+00:00"))
        return max(0, round((completed - started).total_seconds() * 1000))
    except (KeyError, ValueError, TypeError):
        return None


def outcome(result, evidence):
    """One check's outcome in the report's own words ("pass", "fail" or "inconclusive").

    Same rules as the report's rule cards: a block the firewall logged for every attempt
    is passed (proven); a firewall-logged pass, or an approved flow that did not answer, is
    failed; silence without that proof stays inconclusive ("No answer: not proven").
    """
    raw = str(result.get("result", "")).upper()
    expected = result.get("expected")
    state = _evidence_state((evidence or {}).get(result.get("check_id"), {}))
    if raw == "FAIL":
        return "fail"
    if raw == "PASS":
        return "pass"
    if raw != "INCONCLUSIVE":
        return None
    if expected == "allow":
        return "fail"
    if expected == "deny" and state == "passed":
        return "fail"
    if expected == "deny" and state == "corroborated":
        return "pass"
    return "inconclusive"


def assessment_breakdown(report):
    """Split one report into exercised outcomes and not-exercised checks."""
    evaluated, skipped = _scope(report)
    counts = {key: 0 for key in RESULT_KEYS}
    counts["not_exercised"] = 0
    if not isinstance(report, dict):
        return counts
    evidence = _evidence_by_check(report)
    results = report.get("results", [])
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        check_id = result.get("check_id")
        if check_id in skipped or (evaluated is not None and check_id not in evaluated):
            counts["not_exercised"] += 1
            continue
        key = outcome(result, evidence)
        if key in RESULT_KEYS:
            counts[key] += 1
    return counts


def build_insights(environment, actor_id=None):
    """Return dashboard analytics. Bounded to the latest MAX_REPORTS reports."""
    networks = environment.get("networks", {}) if isinstance(environment, dict) else {}
    roles = {key: value.get("role", "custom") for key, value in networks.items()}
    cde_zones = sorted(key for key, role in roles.items() if role == "cde")

    records = (
        db.session.query(Assessment)
        .order_by(Assessment.created_at.desc(), Assessment.id.desc())
        .limit(MAX_REPORTS)
        .all()
    )

    outcomes = {key: 0 for key in RESULT_KEYS}
    outcomes["not_exercised"] = 0
    runs = []
    paths = {}
    tested_cde_sources = {}

    for record in records:
        report = record.report if isinstance(record.report, dict) else {}
        breakdown = assessment_breakdown(report)
        for key, value in breakdown.items():
            outcomes[key] += value
        evaluated, skipped = _scope(report)
        runs.append({
            "id": record.id,
            "created_at": _iso(record.created_at),
            "policy": record.policy.name if record.policy else f"Policy #{record.policy_id}",
            "source_zone": record.source_zone,
            "breakdown": breakdown,
            "duration_ms": _duration_ms(report),
            "url": f"/assessments/{record.id}",
        })
        # Latest observation per exact check path (records are newest first).
        evidence = _evidence_by_check(report)
        for result in report.get("results", []) if isinstance(report.get("results"), list) else []:
            if not isinstance(result, dict):
                continue
            check_id = result.get("check_id")
            if check_id in skipped or (evaluated is not None and check_id not in evaluated):
                continue
            source = result.get("source_zone")
            destination = result.get("destination_zone")
            if not isinstance(source, str) or not isinstance(destination, str):
                continue
            ports = result.get("ports") if isinstance(result.get("ports"), list) else []
            path_key = (source, destination, result.get("destination_host"), tuple(ports), result.get("expected"))
            edge = paths.setdefault((source, destination), {
                "source": source, "destination": destination,
                "pass": 0, "fail": 0, "inconclusive": 0, "_seen": set(),
                "last_tested": _iso(record.created_at), "assessment_id": record.id,
                "cde": roles.get(destination) == "cde",
            })
            if path_key in edge["_seen"]:
                continue
            edge["_seen"].add(path_key)
            key = outcome(result, evidence)
            if key in RESULT_KEYS:
                edge[key] += 1
            if roles.get(destination) == "cde":
                tested_cde_sources.setdefault(source, _iso(record.created_at))

    edges = []
    for edge in paths.values():
        edge.pop("_seen", None)
        edge["status"] = "fail" if edge["fail"] else "inconclusive" if edge["inconclusive"] else "pass"
        edges.append(edge)

    # Policy coverage of the CDE from current active policy versions.
    active_versions = []
    for policy in db.session.query(Policy).filter(Policy.status == "active").limit(200):
        version = (
            db.session.query(PolicyVersion)
            .filter_by(policy_id=policy.id)
            .order_by(PolicyVersion.version_number.desc())
            .first()
        )
        if version is not None and isinstance(version.snapshot, dict):
            active_versions.append(version.snapshot)

    cde_checks = 0
    planned_cde_sources = set()
    mapped_controls = {}
    for snapshot in active_versions:
        for check in snapshot.get("checks", []):
            if not isinstance(check, dict):
                continue
            if check.get("destination_zone") in cde_zones:
                cde_checks += 1
                planned_cde_sources.add(check.get("source_zone"))
            for mapping in check.get("framework_mappings", []) or []:
                if isinstance(mapping, dict):
                    label = f"{mapping.get('framework', '')} {mapping.get('control_id', '')}".strip()
                    mapped_controls[label] = mapped_controls.get(label, 0) + 1

    out_of_scope_zones = sorted(key for key, role in roles.items() if role != "cde")
    untested = [zone for zone in out_of_scope_zones if zone not in tested_cde_sources]

    jobs = (
        db.session.query(AssessmentJob)
        .filter(AssessmentJob.actor_user_id == actor_id)
        .order_by(AssessmentJob.id.desc())
        .limit(8)
        .all()
    )

    return {
        "outcomes": outcomes,
        "runs": list(reversed(runs[:12])),
        "edges": edges,
        "pci": {
            "cde_zones": cde_zones,
            "cde_checks_active": cde_checks,
            "planned_sources": sorted(source for source in planned_cde_sources if isinstance(source, str)),
            "tested_sources": [{"zone": zone, "last_tested": when} for zone, when in sorted(tested_cde_sources.items())],
            "untested_sources": untested,
            "out_of_scope_zones": out_of_scope_zones,
        },
        "controls": sorted(({"label": key, "checks": value} for key, value in mapped_controls.items() if key),
                           key=lambda item: -item["checks"])[:8],
        "activity": [{
            "id": job.id, "status": job.status, "completed": job.completed, "total": job.total,
            "updated_at": _iso(job.updated_at), "assessment_id": job.assessment_id,
            "url": f"/jobs/{job.id}",
        } for job in jobs],
    }
