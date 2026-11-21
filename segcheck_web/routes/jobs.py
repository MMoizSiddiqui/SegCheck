"""Authenticated live execution progress and explicit cancellation."""
from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, url_for
from flask_login import current_user

from segcheck_web.extensions import db, login_manager
from datetime import timezone

from segcheck_web.models import PolicyVersion, utc_now
from segcheck_web.models.jobs import AssessmentJob, AssessmentLease
from segcheck_web.services.assessment_jobs import ACTIVE, expire_stale_jobs

jobs_bp = Blueprint("jobs", __name__, url_prefix="/jobs")


@jobs_bp.before_request
def authenticate():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()


def _iso(value):
    """ISO-8601 with an explicit UTC offset (SQLite returns naive UTC values)."""
    if value is None:
        return None
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat()


def _policy_name(job):
    version = db.session.get(PolicyVersion, job.policy_version_id)
    return version.policy.name if version is not None and version.policy is not None else None


def _owned(job_id):
    expire_stale_jobs()
    job = db.session.query(AssessmentJob).filter_by(id=job_id, actor_user_id=current_user.id).one_or_none()
    if job is None:
        abort(404)
    return job


@jobs_bp.get("/<int:job_id>")
def detail(job_id):
    job = _owned(job_id)
    from segcheck_web.services.report_view import glossary
    return render_template("assessments/job.html", job=job, policy_name=_policy_name(job),
                           created_iso=_iso(job.created_at), reasons=glossary())


@jobs_bp.get("/<int:job_id>/status")
def status(job_id):
    job = _owned(job_id)
    response = jsonify({"id": job.id, "status": job.status, "total": job.total,
                        "completed": job.completed, "events": job.events, "message": job.message,
                        "assessment_url": url_for("assessments.assessment_detail", assessment_id=job.assessment_id) if job.assessment_id else None,
                        "cancel_requested": job.cancel_requested,
                        "created_at": _iso(job.created_at), "updated_at": _iso(job.updated_at),
                        "policy": _policy_name(job)})
    response.headers["Cache-Control"] = "no-store"
    return response



@jobs_bp.post("/<int:job_id>/cancel")
def cancel(job_id):
    job = _owned(job_id)
    if job.status in ACTIVE:
        job.cancel_requested = True
        job.updated_at = utc_now()
        job.message = "Cancellation requested. The current bounded attempt may finish before execution stops."
        if job.status == "queued":
            job.status = "cancelled"
            db.session.query(AssessmentLease).filter_by(id=1, job_id=job.id).delete(synchronize_session=False)
        db.session.commit()
    return redirect(url_for("jobs.detail", job_id=job_id))
