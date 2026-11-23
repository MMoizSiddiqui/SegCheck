"""Allow ICMP checks and larger multi-method assessment runs.

* policy_checks: protocol may now be 'icmp' (echo reachability, no port).
* assessment_jobs: up to 120 attempts per run; larger bounded event log.

SQLite cannot alter CHECK constraints in place, so both tables are rebuilt with
batch operations. Rebuilding drops triggers on the table, so the immutability
triggers protecting historical policy checks are captured first and recreated
verbatim afterwards. Row data is copied unchanged.
"""
from alembic import op
import sqlalchemy as sa

revision = "e7a1c3f9b250"
down_revision = "d63f0a9c4e12"
branch_labels = None
depends_on = None


def _triggers(table):
    bind = op.get_bind()
    return [row[0] for row in bind.execute(
        sa.text("SELECT sql FROM sqlite_master WHERE type='trigger' AND tbl_name=:t AND sql IS NOT NULL ORDER BY name"),
        {"t": table},
    )]


def _rebuild_policy_checks(protocols):
    saved = _triggers("policy_checks")
    with op.batch_alter_table("policy_checks", recreate="always") as batch:
        batch.drop_constraint("ck_policy_checks_valid_protocol", type_="check")
        batch.create_check_constraint("ck_policy_checks_valid_protocol", f"protocol IN ({protocols})")
    existing = set(_triggers("policy_checks"))
    for statement in saved:
        if statement not in existing:
            op.execute(statement)


def _rebuild_jobs(maximum, events):
    with op.batch_alter_table("assessment_jobs", recreate="always") as batch:
        batch.drop_constraint("ck_job_progress", type_="check")
        batch.drop_constraint("ck_job_events", type_="check")
        batch.create_check_constraint("ck_job_progress", f"total BETWEEN 1 AND {maximum} AND completed BETWEEN 0 AND total")
        batch.create_check_constraint("ck_job_events", f"length(CAST(events AS TEXT)) <= {events}")


def upgrade():
    _rebuild_policy_checks("'tcp', 'udp', 'icmp'")
    _rebuild_jobs(120, 98304)


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM policy_checks WHERE protocol = 'icmp'")).scalar():
        raise RuntimeError("ICMP policy checks exist; restore a pre-upgrade backup instead of downgrading.")
    if bind.execute(sa.text("SELECT COUNT(*) FROM assessment_jobs WHERE total > 20")).scalar():
        raise RuntimeError("Assessment jobs above 20 attempts exist; restore a pre-upgrade backup instead.")
    _rebuild_jobs(20, 32768)
    _rebuild_policy_checks("'tcp', 'udp'")
