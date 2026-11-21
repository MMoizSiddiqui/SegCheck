"""One local execution at a time; durable progress with bounded worker lifetime."""
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, timezone

from sqlalchemy.exc import IntegrityError

from segcheck_web.extensions import db
from segcheck_web.models import PolicyVersion, User, utc_now
from segcheck_web.models.jobs import AssessmentJob, AssessmentLease
from segcheck_web.services.assessment_execution import execute_assessment, AssessmentExecutionError
from segcheck_web.services.assessment_plan import build_plan

ACTIVE = {"queued", "running"}
_executor_lock = threading.Lock()


class JobBusy(ValueError):
    pass


def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def expire_stale_jobs():
    lease = db.session.get(AssessmentLease, 1)
    if lease is not None and _aware(lease.expires_at) < utc_now():
        job_id = lease.job_id
        removed = db.session.query(AssessmentLease).filter(
            AssessmentLease.id == 1, AssessmentLease.job_id == job_id,
            AssessmentLease.expires_at < utc_now()).delete(synchronize_session=False)
        if removed:
            job = db.session.get(AssessmentJob, job_id)
            if job is not None and job.status in ACTIVE:
                job.status = "interrupted"
                job.message = "Execution heartbeat expired. Partial observations are not a completed assessment. Review before starting a new run."
                job.updated_at = utc_now()
        db.session.commit()


def create_job(version, plan, actor_id, preview_token):
    expire_stale_jobs()
    nonce = hashlib.sha256(f"{actor_id}:{preview_token}".encode()).hexdigest()
    existing = db.session.query(AssessmentJob).filter_by(nonce=nonce).one_or_none()
    if existing:
        return existing, False
    if not plan["ready"]:
        raise AssessmentExecutionError("The selected scope is not ready.")
    job = AssessmentJob(actor_user_id=actor_id, policy_version_id=version.id,
        policy_digest=plan["policy_digest"], environment_revision=plan["environment_revision"],
        nonce=nonce, total=plan["attempts"], completed=0, events=[])
    try:
        db.session.add(job)
        db.session.flush()
        db.session.add(AssessmentLease(id=1, job_id=job.id, expires_at=utc_now() + timedelta(seconds=90)))
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        existing = db.session.query(AssessmentJob).filter_by(nonce=nonce).one_or_none()
        if existing:
            return existing, False
        raise JobBusy("Another assessment is running. Wait for it to finish or cancel it from its progress page.") from exc
    return job, True


def _control(job_id):
    db.session.expire_all()
    job = db.session.get(AssessmentJob, job_id)
    lease = db.session.get(AssessmentLease, 1)
    if job is None or job.status not in ACTIVE or lease is None or lease.job_id != job_id or _aware(lease.expires_at) < utc_now():
        raise AssessmentExecutionError("Execution lease is unavailable or expired.")
    actor = db.session.get(User, job.actor_user_id)
    if job.cancel_requested or actor is None or not actor.is_active:
        raise AssessmentExecutionError("Execution was cancelled or the account is no longer active.")
    return job, lease


def run_job(app, job_id):
    with app.app_context():
        job = None
        try:
            job, lease = _control(job_id)
            version = db.session.get(PolicyVersion, job.policy_version_id)
            plan = build_plan(version, version.policy.status)
            if not plan["ready"] or plan["policy_digest"] != job.policy_digest or plan["environment_revision"] != job.environment_revision:
                raise AssessmentExecutionError("Configuration or policy changed before execution. Review a new preview.")
            actor_id, policy_id, version_id = job.actor_user_id, version.policy_id, version.id
            job.status, job.message, job.updated_at = "running", "Running explicit TCP checks", utc_now()
            lease.expires_at = utc_now() + timedelta(seconds=90)
            db.session.commit()

            def guard():
                _control(job_id)
                db.session.rollback()  # Never hold a read transaction across a network attempt.

            def progress(host, port, outcome, protocol="tcp"):
                current, held = _control(job_id)
                events = list(current.events)
                if len(events) >= current.total:
                    raise AssessmentExecutionError("Probe progress exceeded the authorized scope.")
                events.append({"host": host, "port": port, "protocol": protocol, "observed": outcome.state,
                               "reason": outcome.reason, "duration_ms": outcome.duration_ms})
                current.events, current.completed = events, len(events)
                current.message = f"Measured {current.completed} of {current.total} connections"
                current.updated_at = utc_now()
                held.expires_at = utc_now() + timedelta(seconds=90)
                db.session.commit()

            record = execute_assessment(policy_id=policy_id, policy_version_id=version_id,
                source_zone=plan["source_zone"], actor_user_id=actor_id, source_ip=plan["source_ip"],
                environment_context={**plan["environment"], "revision": plan["environment_revision"]},
                execution_guard=guard, progress_callback=progress)
            job = db.session.get(AssessmentJob, job_id)
            job.status, job.assessment_id = "completed", record.id
            job.message = "Assessment evaluated and saved. Open the immutable report for final results."
        except Exception as exc:
            db.session.rollback()
            job = db.session.get(AssessmentJob, job_id)
            if job is not None and job.status in ACTIVE:
                job.status = "cancelled" if job.cancel_requested else "failed"
                if job.cancel_requested:
                    job.message = (f"Cancelled by the operator after {job.completed} of {job.total} attempts. "
                                   "Partial observations are not saved as an assessment report.")
                else:
                    job.message = str(exc)[:500] if isinstance(exc, AssessmentExecutionError) else "Execution could not be completed safely. Review configuration and retry."
            if not isinstance(exc, AssessmentExecutionError):
                app.logger.exception("Assessment job failed")
        finally:
            if job is not None:
                job.updated_at = utc_now()
            db.session.query(AssessmentLease).filter_by(id=1, job_id=job_id).delete(synchronize_session=False)
            db.session.commit()
            db.session.remove()


def start_worker(app, job_id):
    with _executor_lock:
        if "segcheck_executor" not in app.extensions:
            app.extensions["segcheck_executor"] = ThreadPoolExecutor(max_workers=1, thread_name_prefix="segcheck-local")
    app.extensions["segcheck_executor"].submit(run_job, app, job_id)
