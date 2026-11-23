"""add policy lifecycle audit events

Revision ID: 7572e67f5302
Revises: 7c2f91a6d3e4
Create Date: 2026-11-09 15:49:44.818391

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7572e67f5302'
down_revision = '7c2f91a6d3e4'
branch_labels = None
depends_on = None


def upgrade():
    """Create the lifecycle audit table and protect its records."""
    bind = op.get_bind()

    if bind.dialect.name != "sqlite":
        raise RuntimeError(
            "Policy lifecycle audit immutability currently supports SQLite only"
        )

    op.create_table(
        "policy_lifecycle_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("from_status", sa.String(length=16), nullable=False),
        sa.Column("to_status", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("actor_identifier", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "from_status IN ('draft', 'active', 'archived')",
            name="ck_policy_lifecycle_from_status",
        ),
        sa.CheckConstraint(
            "to_status IN ('draft', 'active', 'archived')",
            name="ck_policy_lifecycle_to_status",
        ),
        sa.CheckConstraint(
            "actor_identifier IS NULL OR length(actor_identifier) <= 128",
            name="ck_policy_lifecycle_actor_length",
        ),
        sa.CheckConstraint(
            "from_status != to_status",
            name="ck_policy_lifecycle_status_changed",
        ),
        sa.CheckConstraint(
            "length(trim(reason)) BETWEEN 1 AND 500",
            name="ck_policy_lifecycle_reason_length",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"], ["policies.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_policy_lifecycle_policy_created",
        "policy_lifecycle_events",
        ["policy_id", "created_at"],
        unique=False,
    )

    for operation in ("update", "delete"):
        trigger_name = f"trg_policy_lifecycle_events_immutable_{operation}"
        sql = (
            f"CREATE TRIGGER {trigger_name} "
            f"BEFORE {operation.upper()} ON policy_lifecycle_events "
            "BEGIN "
            "SELECT RAISE(ABORT, "
            "'policy lifecycle audit events are immutable'); "
            "END;"
        )
        op.execute(sql)


def downgrade():
    """Remove lifecycle audit protections and the audit table."""
    bind = op.get_bind()

    if bind.dialect.name != "sqlite":
        raise RuntimeError(
            "Policy lifecycle audit immutability currently supports SQLite only"
        )

    op.execute(
        "DROP TRIGGER IF EXISTS "
        "trg_policy_lifecycle_events_immutable_update"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS "
        "trg_policy_lifecycle_events_immutable_delete"
    )

    op.drop_index(
        "ix_policy_lifecycle_policy_created",
        table_name="policy_lifecycle_events",
    )
    op.drop_table("policy_lifecycle_events")
