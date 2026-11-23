"""Protect historical policy versions

Revision ID: 7c2f91a6d3e4
Revises: 1d38f72b4aa1
Create Date: 2026-11-09 13:35:51.128923

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '7c2f91a6d3e4'
down_revision = '1d38f72b4aa1'
branch_labels = None
depends_on = None


def upgrade():
    """Prevent modification or deletion of historical policy records."""
    bind = op.get_bind()

    if bind.dialect.name != "sqlite":
        raise RuntimeError(
            "Historical policy immutability migration currently "
            "supports SQLite only"
        )

    protected_tables = (
        "policy_versions",
        "policy_version_zones",
        "policy_checks",
    )

    for table in protected_tables:
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_immutable_update
            BEFORE UPDATE ON {table}
            BEGIN
                SELECT RAISE(
                    ABORT,
                    '{table} records are immutable'
                );
            END;
            """
        )

        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_immutable_delete
            BEFORE DELETE ON {table}
            BEGIN
                SELECT RAISE(
                    ABORT,
                    '{table} records are immutable'
                );
            END;
            """
        )


def downgrade():
    """Remove immutability triggers without modifying stored records."""
    bind = op.get_bind()

    if bind.dialect.name != "sqlite":
        raise RuntimeError(
            "Historical policy immutability migration currently "
            "supports SQLite only"
        )

    for table in (
        "policy_versions",
        "policy_version_zones",
        "policy_checks",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_update")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable_delete")
