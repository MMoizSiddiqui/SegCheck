"""add policy check framework mappings

Revision ID: 6eb351123c3a
Revises: de8bd543aabc
Create Date: 2026-11-10 05:28:48.965105

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6eb351123c3a'
down_revision = 'de8bd543aabc'
branch_labels = None
depends_on = None


def _restore_policy_check_immutability_triggers():
    """Restore triggers removed by SQLite batch table reconstruction."""
    op.execute("""
        CREATE TRIGGER trg_policy_checks_immutable_update
        BEFORE UPDATE ON policy_checks
        BEGIN
            SELECT RAISE(
                ABORT,
                'policy_checks records are immutable'
            );
        END;
    """)

    op.execute("""
        CREATE TRIGGER trg_policy_checks_immutable_delete
        BEFORE DELETE ON policy_checks
        BEGIN
            SELECT RAISE(
                ABORT,
                'policy_checks records are immutable'
            );
        END;
    """)


def upgrade():
    # Add with a temporary database default so existing rows receive [].
    op.add_column(
        'policy_checks',
        sa.Column(
            'framework_mappings',
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )

    # Remove the temporary default while retaining NOT NULL.
    # SQLite batch mode rebuilds the table and drops its existing triggers.
    with op.batch_alter_table('policy_checks', schema=None) as batch_op:
        batch_op.alter_column(
            'framework_mappings',
            existing_type=sa.JSON(),
            existing_nullable=False,
            server_default=None,
        )

    # Reinstall the protections from the original immutability migration.
    _restore_policy_check_immutability_triggers()


def downgrade():
    # SQLite batch mode also removes triggers during downgrade.
    with op.batch_alter_table('policy_checks', schema=None) as batch_op:
        batch_op.drop_column('framework_mappings')

    # The previous migration still requires these protections.
    _restore_policy_check_immutability_triggers()
