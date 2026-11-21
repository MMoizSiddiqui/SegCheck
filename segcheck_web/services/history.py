"""Audit history: list every past audit, delete one, or delete everything.

Saved reports can never be changed. They can be deleted only here, on explicit request: each
protected row gets a one-off grant (record_deletions) in the same transaction, and the database
triggers allow a delete only while that exact grant exists. After deleting, the database file is
compacted (VACUUM) so the removed data is not left behind inside the file.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy import text

from segcheck_web.extensions import db
from segcheck_web.models import Assessment, Policy, PolicyVersion
from segcheck_web.models.jobs import AssessmentJob, AssessmentLease
from segcheck_web.services.report_analysis import analyse

ACTIVE = {"queued", "running"}


class HistoryError(ValueError):
    pass


def audits(actor_id=None):
    """Newest first: finished audits (with their verdict) and runs that never produced a report."""
    rows = []
    for record in db.session.query(Assessment).order_by(Assessment.created_at.desc(), Assessment.id.desc()).all():
        report = record.report if isinstance(record.report, dict) else {}
        environment = (report.get("assessment") or {}).get("environment") or {}
        verdict = analyse(report, environment.get("networks") or {})
        policy = db.session.get(Policy, record.policy_id)
        rows.append({"kind": "report", "id": record.id, "name": policy.name if policy else f"Audit {record.id}",
                     "created_at": record.created_at, "source_zone": record.source_zone,
                     "source_ip": environment.get("source_ip", ""), "status": verdict["status"],
                     "headline": verdict["headline"], "counts": verdict["counts"]})
    unfinished = (db.session.query(AssessmentJob).filter(AssessmentJob.assessment_id.is_(None))
                  .order_by(AssessmentJob.created_at.desc()).all())
    for job in unfinished:
        version = db.session.get(PolicyVersion, job.policy_version_id)
        rows.append({"kind": "run", "id": job.id, "name": version.policy.name if version else f"Run {job.id}",
                     "created_at": job.created_at, "status": job.status, "headline": job.message,
                     "active": job.status in ACTIVE})
    rows.sort(key=lambda row: row["created_at"], reverse=True)
    return rows


def _grant(table, ids):
    ids = sorted(set(ids))
    for row_id in ids:
        db.session.execute(text("INSERT INTO record_deletions (table_name, row_id) VALUES (:t, :r)"), {"t": table, "r": row_id})
    return ids


def _delete(table, ids):
    if ids:
        _grant(table, ids)
        db.session.execute(text(f"DELETE FROM {table} WHERE id IN ({','.join(str(int(i)) for i in ids)})"))


def _ids(sql, **params):
    return [row[0] for row in db.session.execute(text(sql), params).all()]


def _remove_policy_if_unused(policy_id):
    """Delete a policy with all its versions when no remaining report or run uses it."""
    if _ids("SELECT id FROM assessments WHERE policy_id = :p", p=policy_id):
        return
    versions = _ids("SELECT id FROM policy_versions WHERE policy_id = :p", p=policy_id)
    if versions:
        joined = ",".join(str(v) for v in versions)
        jobs = _ids(f"SELECT id FROM assessment_jobs WHERE policy_version_id IN ({joined})")
        if jobs:
            db.session.execute(text(f"DELETE FROM assessment_jobs WHERE id IN ({','.join(str(j) for j in jobs)})"))
        _delete("policy_checks", _ids(f"SELECT id FROM policy_checks WHERE policy_version_id IN ({joined})"))
        _delete("policy_version_zones", _ids(f"SELECT id FROM policy_version_zones WHERE policy_version_id IN ({joined})"))
        _delete("policy_versions", versions)
    _delete("policy_lifecycle_events", _ids("SELECT id FROM policy_lifecycle_events WHERE policy_id = :p", p=policy_id))
    db.session.execute(text("DELETE FROM policies WHERE id = :p"), {"p": policy_id})


def _refuse_while_running():
    if db.session.get(AssessmentLease, 1) is not None:
        raise HistoryError("An audit is running. Wait for it to finish (or cancel it), then delete.")


def _finish():
    db.session.execute(text("DELETE FROM record_deletions"))
    db.session.commit()
    compact()


def compact():
    """Rewrite the database file so deleted data is really gone from disk (SQLite VACUUM)."""
    db.session.remove()
    with db.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql("VACUUM")


def delete_report(assessment_id: int):
    _refuse_while_running()
    record = db.session.get(Assessment, assessment_id)
    if record is None:
        raise HistoryError("That audit no longer exists.")
    policy_id = record.policy_id
    jobs = _ids("SELECT id FROM assessment_jobs WHERE assessment_id = :a", a=assessment_id)
    if jobs:
        db.session.execute(text(f"DELETE FROM assessment_jobs WHERE id IN ({','.join(str(j) for j in jobs)})"))
    _delete("assessments", [assessment_id])
    _remove_policy_if_unused(policy_id)
    _finish()


def delete_run(job_id: int):
    """Delete a run that never produced a report (failed, cancelled or interrupted)."""
    job = db.session.get(AssessmentJob, job_id)
    if job is None or job.assessment_id is not None:
        raise HistoryError("That run no longer exists.")
    if job.status in ACTIVE:
        raise HistoryError("This run is still active. Cancel it first.")
    version = db.session.get(PolicyVersion, job.policy_version_id)
    db.session.execute(text("DELETE FROM assessment_jobs WHERE id = :j"), {"j": job_id})
    if version is not None:
        _remove_policy_if_unused(version.policy_id)
    _finish()


def delete_all(data_dir: Path | None = None, firewall_logs=True, backups=False):
    """Delete every audit; optionally the saved firewall logs and the automatic database backups."""
    _refuse_while_running()
    if db.session.query(AssessmentJob).filter(AssessmentJob.status.in_(ACTIVE)).first():
        raise HistoryError("A run is still queued. Cancel it first.")
    db.session.execute(text("DELETE FROM assessment_jobs"))
    _delete("assessments", _ids("SELECT id FROM assessments"))
    for policy_id in _ids("SELECT id FROM policies"):
        _remove_policy_if_unused(policy_id)
    _finish()
    removed = []
    if data_dir is not None:
        if firewall_logs:
            evidence = data_dir / "evidence"
            for item in evidence.glob("*.jsonl") if evidence.exists() else []:
                item.unlink(missing_ok=True)
                removed.append(item.name)
        if backups and (data_dir / "backups").exists():
            shutil.rmtree(data_dir / "backups", ignore_errors=True)
            removed.append("backups")
    return removed


def discard_policy(policy_id: int):
    """Remove a just-created policy that never ran (launch was blocked). No report is involved."""
    db.session.rollback()
    _remove_policy_if_unused(policy_id)
    db.session.execute(text("DELETE FROM record_deletions"))
    db.session.commit()
