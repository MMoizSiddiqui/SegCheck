"""add immutable assessment records

Revision ID: b41d8e7a2c90
Revises: 9f6c2a1d4b80
Create Date: 2026-11-10
"""

from alembic import op
import sqlalchemy as sa


revision = "b41d8e7a2c90"
down_revision = "9f6c2a1d4b80"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()

    if bind.dialect.name != "sqlite":
        raise RuntimeError(
            "Assessment immutability migration currently supports SQLite only"
        )

    # SQLite requires a unique parent key matching the composite
    # foreign-key target exactly.
    op.create_index(
        "uq_policy_versions_policy_id_id",
        "policy_versions",
        ["policy_id", "id"],
        unique=True,
    )

    op.create_table(
        "assessments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("policy_version_id", sa.Integer(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=False),
        sa.Column("policy_version_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_zone", sa.String(length=64), nullable=False),
        sa.Column("probe_run_id", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("report", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(policy_version_sha256) = 64",
            name="ck_assessments_policy_digest_length",
        ),
        sa.CheckConstraint(
            "length(trim(source_zone)) BETWEEN 1 AND 64",
            name="ck_assessments_source_zone_length",
        ),
        sa.CheckConstraint(
            "length(trim(probe_run_id)) BETWEEN 1 AND 64",
            name="ck_assessments_probe_run_id_length",
        ),
        sa.CheckConstraint(
            "length(CAST(report AS TEXT)) <= 4194304",
            name="ck_assessments_report_size",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["policies.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id", "policy_version_id"],
            ["policy_versions.policy_id", "policy_versions.id"],
            ondelete="RESTRICT",
            name="fk_assessments_policy_version_owner",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("probe_run_id"),
    )

    op.create_index(
        "ix_assessments_policy_created",
        "assessments",
        ["policy_id", "created_at"],
    )
    op.create_index(
        "ix_assessments_actor_created",
        "assessments",
        ["actor_user_id", "created_at"],
    )
    op.create_index(
        "ix_assessments_created_at",
        "assessments",
        ["created_at"],
    )

    for operation in ("update", "delete"):
        op.execute(
            f"""
            CREATE TRIGGER trg_assessments_immutable_{operation}
            BEFORE {operation.upper()} ON assessments
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'assessments records are immutable'
                );
            END;
            """
        )


def downgrade():
    bind = op.get_bind()

    if bind.dialect.name != "sqlite":
        raise RuntimeError(
            "Assessment immutability migration currently supports SQLite only"
        )

    op.execute("DROP TRIGGER IF EXISTS trg_assessments_immutable_update")
    op.execute("DROP TRIGGER IF EXISTS trg_assessments_immutable_delete")

    op.drop_index("ix_assessments_created_at", table_name="assessments")
    op.drop_index("ix_assessments_actor_created", table_name="assessments")
    op.drop_index("ix_assessments_policy_created", table_name="assessments")
    op.drop_table("assessments")

    op.drop_index(
        "uq_policy_versions_policy_id_id",
        table_name="policy_versions",
    )
