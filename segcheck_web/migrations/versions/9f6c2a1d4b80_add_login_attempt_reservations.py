"""add short-lived login attempt reservations

Revision ID: 9f6c2a1d4b80
Revises: 8a41c2d7e901
Create Date: 2026-11-10
"""

from alembic import op
import sqlalchemy as sa


revision = "9f6c2a1d4b80"
down_revision = "8a41c2d7e901"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "login_attempt_reservations",
        sa.Column("reservation_key", sa.String(length=64), nullable=False),
        sa.Column("account_bucket_key", sa.String(length=64), nullable=False),
        sa.Column("source_bucket_key", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(reservation_key) = 64",
            name="ck_login_attempt_reservations_key_length",
        ),
        sa.CheckConstraint(
            "length(account_bucket_key) = 64",
            name="ck_login_attempt_reservations_account_key_length",
        ),
        sa.CheckConstraint(
            "length(source_bucket_key) = 64",
            name="ck_login_attempt_reservations_source_key_length",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_login_attempt_reservations_expiry",
        ),
        sa.PrimaryKeyConstraint("reservation_key"),
    )

    op.create_index(
        "ix_login_attempt_reservations_account_bucket",
        "login_attempt_reservations",
        ["account_bucket_key"],
        unique=False,
    )
    op.create_index(
        "ix_login_attempt_reservations_source_bucket",
        "login_attempt_reservations",
        ["source_bucket_key"],
        unique=False,
    )
    op.create_index(
        "ix_login_attempt_reservations_expires_at",
        "login_attempt_reservations",
        ["expires_at"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_login_attempt_reservations_expires_at",
        table_name="login_attempt_reservations",
    )
    op.drop_index(
        "ix_login_attempt_reservations_source_bucket",
        table_name="login_attempt_reservations",
    )
    op.drop_index(
        "ix_login_attempt_reservations_account_bucket",
        table_name="login_attempt_reservations",
    )
    op.drop_table("login_attempt_reservations")
