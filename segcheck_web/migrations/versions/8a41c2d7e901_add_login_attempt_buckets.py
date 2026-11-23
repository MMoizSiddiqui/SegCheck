"""add privacy-preserving login attempt buckets

Revision ID: 8a41c2d7e901
Revises: 6eb351123c3a
Create Date: 2026-11-10
"""

from alembic import op
import sqlalchemy as sa


revision = "8a41c2d7e901"
down_revision = "6eb351123c3a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "login_attempt_buckets",
        sa.Column("bucket_key", sa.String(length=64), nullable=False),
        sa.Column("bucket_type", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column(
            "window_started_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "blocked_until",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.CheckConstraint(
            "bucket_type IN ('account_source', 'source')",
            name="ck_login_attempt_buckets_type",
        ),
        sa.CheckConstraint(
            "attempts >= 0",
            name="ck_login_attempt_buckets_attempts",
        ),
        sa.CheckConstraint(
            "length(bucket_key) = 64",
            name="ck_login_attempt_buckets_key_length",
        ),
        sa.PrimaryKeyConstraint("bucket_key"),
    )

    op.create_index(
        "ix_login_attempt_buckets_blocked_until",
        "login_attempt_buckets",
        ["blocked_until"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_login_attempt_buckets_blocked_until",
        table_name="login_attempt_buckets",
    )
    op.drop_table("login_attempt_buckets")
