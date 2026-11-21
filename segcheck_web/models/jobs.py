"""Bounded live execution state, separate from immutable assessment records."""
from sqlalchemy import CheckConstraint, ForeignKey
from segcheck_web.extensions import db
from segcheck_web.models import utc_now


class AssessmentJob(db.Model):
    __tablename__ = "assessment_jobs"
    __table_args__ = (
        CheckConstraint("status IN ('queued','running','completed','failed','cancelled','interrupted')", name="ck_job_status"),
        CheckConstraint("total BETWEEN 1 AND 400 AND completed BETWEEN 0 AND total", name="ck_job_progress"),
        CheckConstraint("length(nonce) = 64", name="ck_job_nonce"),
        CheckConstraint("length(CAST(events AS TEXT)) <= 196608", name="ck_job_events"),
    )
    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    policy_version_id = db.Column(db.Integer, ForeignKey("policy_versions.id", ondelete="RESTRICT"), nullable=False)
    assessment_id = db.Column(db.Integer, ForeignKey("assessments.id", ondelete="RESTRICT"), unique=True)
    nonce = db.Column(db.String(64), unique=True, nullable=False)
    policy_digest = db.Column(db.String(64), nullable=False)
    environment_revision = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(16), nullable=False, default="queued")
    total = db.Column(db.Integer, nullable=False)
    completed = db.Column(db.Integer, nullable=False, default=0)
    events = db.Column(db.JSON, nullable=False, default=list)
    cancel_requested = db.Column(db.Boolean, nullable=False, default=False)
    message = db.Column(db.String(500), nullable=False, default="Waiting for local execution")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)


class AssessmentLease(db.Model):
    __tablename__ = "assessment_execution_lease"
    __table_args__ = (CheckConstraint("id = 1", name="ck_execution_lease_singleton"),)
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, ForeignKey("assessment_jobs.id", ondelete="RESTRICT"), nullable=False, unique=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)


class RecordDeletion(db.Model):
    """One-off permission to delete exactly one protected row (History → delete). See migration f3a9c1d7e2b4."""
    __tablename__ = "record_deletions"
    __table_args__ = (db.UniqueConstraint("table_name", "row_id", name="uq_record_deletion"),)
    id = db.Column(db.Integer, primary_key=True)
    table_name = db.Column(db.String(40), nullable=False)
    row_id = db.Column(db.Integer, nullable=False)
