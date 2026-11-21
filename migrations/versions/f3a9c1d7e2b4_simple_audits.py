"""Simple audits: one audit runs as one job, and audit history can be deleted on request.

* assessment_jobs: up to 400 attempts per run (a whole standard in one run) and a larger
  bounded event log.
* record_deletions: one-off grants. A saved report, policy version, check, zone row or
  lifecycle event can only be deleted while a grant for exactly that row exists in the same
  transaction (written by the History page's delete). Updates stay impossible: saved records
  can never be changed.
"""
from alembic import op
import sqlalchemy as sa

revision = "f3a9c1d7e2b4"
down_revision = "e7a1c3f9b250"
branch_labels = None
depends_on = None

PROTECTED = {
    "assessments": ("trg_assessments_immutable_delete", "assessments records are immutable"),
    "policy_versions": ("trg_policy_versions_immutable_delete", "policy_versions records are immutable"),
    "policy_version_zones": ("trg_policy_version_zones_immutable_delete", "policy_version_zones records are immutable"),
    "policy_checks": ("trg_policy_checks_immutable_delete", "policy_checks records are immutable"),
    "policy_lifecycle_events": ("trg_policy_lifecycle_events_immutable_delete", "policy lifecycle audit events are immutable"),
}


def _rebuild_jobs(maximum, events):
    with op.batch_alter_table("assessment_jobs", recreate="always") as batch:
        batch.drop_constraint("ck_job_progress", type_="check")
        batch.drop_constraint("ck_job_events", type_="check")
        batch.create_check_constraint("ck_job_progress", f"total BETWEEN 1 AND {maximum} AND completed BETWEEN 0 AND total")
        batch.create_check_constraint("ck_job_events", f"length(CAST(events AS TEXT)) <= {events}")


def upgrade():
    op.create_table(
        "record_deletions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("table_name", sa.String(40), nullable=False),
        sa.Column("row_id", sa.Integer(), nullable=False),
        sa.UniqueConstraint("table_name", "row_id", name="uq_record_deletion"),
    )
    for table, (trigger, message) in PROTECTED.items():
        op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        op.execute(
            f"CREATE TRIGGER {trigger} BEFORE DELETE ON {table} "
            f"WHEN NOT EXISTS (SELECT 1 FROM record_deletions WHERE table_name = '{table}' AND row_id = OLD.id) "
            f"BEGIN SELECT RAISE(ABORT, '{message}'); END;"
        )
    _rebuild_jobs(400, 196608)


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM assessment_jobs WHERE total > 120")).scalar():
        raise RuntimeError("Runs above 120 attempts exist; restore a pre-upgrade backup instead of downgrading.")
    _rebuild_jobs(120, 98304)
    for table, (trigger, message) in PROTECTED.items():
        op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        op.execute(f"CREATE TRIGGER {trigger} BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT, '{message}'); END;")
    op.drop_table("record_deletions")
