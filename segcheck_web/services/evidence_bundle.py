"""Assessor evidence bundle: one ZIP per saved assessment, with a SHA-256 manifest.

Built only from the immutable stored record; nothing is re-run or re-evaluated.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import yaml

from segcheck_web.services.assessment_pdf import generate_assessment_pdf
from segcheck_web.services.report_analysis import analyse

FIXED_TIME = (2020, 1, 1, 0, 0, 0)  # deterministic archive entries


def _dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False).encode("utf-8")


def build_bundle(record) -> bytes:
    report = record.report if isinstance(record.report, dict) else {}
    assessment = report.get("assessment") if isinstance(report.get("assessment"), dict) else {}
    environment = assessment.get("environment") if isinstance(assessment.get("environment"), dict) else {}
    version = record.policy_version
    analysis = analyse(report, environment.get("networks", {}))
    summary = {
        "assessment_id": record.id, "probe_run_id": record.probe_run_id, "source_zone": record.source_zone,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "policy": record.policy.name if record.policy is not None else None,
        "policy_version": version.version_number if version is not None else None,
        "policy_snapshot_sha256": record.policy_version_sha256,
        "status": analysis["status"], "headline": analysis["headline"], "counts": analysis["counts"],
        "controls": [{key: c[key] for key in ("framework", "control_id", "title", "checks", "FAIL", "PASS", "INCONCLUSIVE", "corroborated")}
                     for c in analysis["controls"]],
    }
    files = {
        "report.pdf": generate_assessment_pdf(record),
        "report.json": json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2).encode("utf-8"),
        "summary.json": _dump(summary),
        "environment.json": _dump(environment),
        "boundary-evidence.json": _dump(report.get("boundary_evidence") or {"note": "No boundary evidence recorded."}),
    }
    if version is not None and isinstance(version.snapshot, dict):
        files["policy-snapshot.yaml"] = yaml.safe_dump(version.snapshot, sort_keys=False, allow_unicode=True).encode("utf-8")
    files["README.txt"] = (
        f"SegCheck evidence bundle - assessment #{record.id}\n\n"
        "report.pdf             Analyst report (executive summary, control matrix, heatmap, guidance)\n"
        "report.json            The exact immutable report stored by SegCheck\n"
        "summary.json           Machine-readable outcome and control summary\n"
        "environment.json       Zones, probe position, boundary devices at execution time\n"
        "boundary-evidence.json Firewall log cross-check per probe attempt\n"
        "policy-snapshot.yaml   The policy version that was tested (its SHA-256 is in summary.json)\n"
        "MANIFEST.sha256        SHA-256 of every file above (verify with: sha256sum -c MANIFEST.sha256)\n\n"
        "Decision rules: a reply on a denied path is FAIL; silence, refusal or an unreachable route is\n"
        "INCONCLUSIVE and never a pass. Firewall logs support but never change a decision. The results\n"
        "cover the configured checks only and do not certify PCI DSS compliance.\n"
    ).encode("utf-8")
    manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files.items()))
    files["MANIFEST.sha256"] = manifest.encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(f"segcheck-assessment-{record.id}/{name}", date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, files[name])
    return buffer.getvalue()
