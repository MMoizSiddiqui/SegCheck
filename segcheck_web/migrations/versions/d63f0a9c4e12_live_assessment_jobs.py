"""Add bounded assessment jobs and one installation-wide execution lease."""
from alembic import op
import sqlalchemy as sa

revision = "d63f0a9c4e12"
down_revision = "c52e9f8b3d01"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("bootstrap_claim",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_bootstrap_singleton"),
    )
    op.create_table("assessment_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("policy_version_id", sa.Integer(), sa.ForeignKey("policy_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id", ondelete="RESTRICT"), unique=True),
        sa.Column("nonce", sa.String(64), unique=True, nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("environment_revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("completed", sa.Integer(), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('queued','running','completed','failed','cancelled','interrupted')", name="ck_job_status"),
        sa.CheckConstraint("total BETWEEN 1 AND 20 AND completed BETWEEN 0 AND total", name="ck_job_progress"),
        sa.CheckConstraint("length(nonce) = 64", name="ck_job_nonce"),
        sa.CheckConstraint("length(CAST(events AS TEXT)) <= 32768", name="ck_job_events"),
    )
    op.create_table("assessment_execution_lease",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("assessment_jobs.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_execution_lease_singleton"),
    )


def downgrade():
    op.drop_table("assessment_execution_lease")
    op.drop_table("assessment_jobs")
    op.drop_table("bootstrap_claim")
