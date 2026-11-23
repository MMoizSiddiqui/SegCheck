"""Add versioned installation environment settings.

Revision ID: c52e9f8b3d01
Revises: b41d8e7a2c90
"""
from alembic import op
import sqlalchemy as sa

revision = "c52e9f8b3d01"
down_revision = "b41d8e7a2c90"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "environment_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_environment_singleton"),
        sa.CheckConstraint("revision >= 1", name="ck_environment_revision"),
        sa.CheckConstraint("length(CAST(payload AS TEXT)) <= 65536", name="ck_environment_size"),
    )


def downgrade():
    op.drop_table("environment_settings")
