"""Migration regression tests for login attempt buckets."""

from pathlib import Path

import pytest
from flask_migrate import downgrade, upgrade
from sqlalchemy import event, text
from sqlalchemy.exc import IntegrityError

from segcheck_web import create_app
from segcheck_web.extensions import db


MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"

PREVIOUS_REVISION = "6eb351123c3a"
LATEST_REVISION = "f3a9c1d7e2b4"


def test_login_bucket_migration_upgrade_downgrade_and_reupgrade(
    tmp_path,
):
    """Verify schema, constraints, data preservation and reversibility."""
    database_path = tmp_path / "login-bucket-migration.sqlite3"

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "migration-test-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        engine = db.engine

        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        event.listen(engine, "connect", enable_foreign_keys)

        try:
            # Start from the schema immediately before this migration.
            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision=PREVIOUS_REVISION,
            )

            # Insert an existing record to verify it survives migration.
            with engine.begin() as connection:
                connection.execute(text("""
                    INSERT INTO policies (
                        id, policy_key, name, description, status,
                        pci_dss_version, tags, created_at, updated_at
                    )
                    VALUES (
                        1, 'THROTTLE-MIGRATION-001',
                        'Existing Policy',
                        'Must survive login throttle migration',
                        'draft', '4.0.1', '[]',
                        '2026-11-01 10:00:00',
                        '2026-11-01 10:00:00'
                    )
                """))

            # Upgrade to the latest migration.
            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision="head",
            )

            with engine.connect() as connection:
                revision = connection.execute(text("""
                    SELECT version_num FROM alembic_version
                """)).scalar_one()

                assert revision == LATEST_REVISION

                policy = connection.execute(text("""
                    SELECT policy_key
                    FROM policies
                    WHERE id = 1
                """)).scalar_one()

                assert policy == "THROTTLE-MIGRATION-001"

                columns = {
                    item["name"]: item
                    for item in connection.execute(text(
                        "PRAGMA table_info('login_attempt_buckets')"
                    )).mappings()
                }

                assert set(columns) == {
                    "bucket_key",
                    "bucket_type",
                    "attempts",
                    "window_started_at",
                    "blocked_until",
                    "updated_at",
                }

                assert columns["bucket_key"]["pk"] == 1
                assert columns["bucket_type"]["notnull"] == 1
                assert columns["attempts"]["notnull"] == 1
                assert columns["window_started_at"]["notnull"] == 1
                assert columns["blocked_until"]["notnull"] == 0
                assert columns["updated_at"]["notnull"] == 1

                indexes = {
                    item["name"]
                    for item in connection.execute(text(
                        "PRAGMA index_list('login_attempt_buckets')"
                    )).mappings()
                }

                assert (
                    "ix_login_attempt_buckets_blocked_until" in indexes
                )

                table_sql = connection.execute(text("""
                    SELECT sql
                    FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'login_attempt_buckets'
                """)).scalar_one()

                assert "ck_login_attempt_buckets_type" in table_sql
                assert "ck_login_attempt_buckets_attempts" in table_sql
                assert "ck_login_attempt_buckets_key_length" in table_sql

            # Verify a valid bucket can be stored.
            with engine.begin() as connection:
                connection.execute(text("""
                    INSERT INTO login_attempt_buckets (
                        bucket_key, bucket_type, attempts,
                        window_started_at, blocked_until, updated_at
                    )
                    VALUES (
                        :key, 'account_source', 2,
                        '2026-11-10 12:00:00', NULL,
                        '2026-11-10 12:00:00'
                    )
                """), {"key": "a" * 64})

            # Each invalid row must be rejected by a database constraint.
            invalid_rows = [
                {
                    "key": "b" * 64,
                    "bucket_type": "unknown",
                    "attempts": 1,
                },
                {
                    "key": "c" * 64,
                    "bucket_type": "source",
                    "attempts": -1,
                },
                {
                    "key": "short",
                    "bucket_type": "source",
                    "attempts": 1,
                },
            ]

            for invalid in invalid_rows:
                with pytest.raises(IntegrityError):
                    with engine.begin() as connection:
                        connection.execute(text("""
                            INSERT INTO login_attempt_buckets (
                                bucket_key, bucket_type, attempts,
                                window_started_at, blocked_until,
                                updated_at
                            )
                            VALUES (
                                :key, :bucket_type, :attempts,
                                '2026-11-10 12:00:00', NULL,
                                '2026-11-10 12:00:00'
                            )
                        """), invalid)

            # Downgrade only the login-throttle migration.
            downgrade(
                directory=str(MIGRATIONS_DIR),
                revision=PREVIOUS_REVISION,
            )

            with engine.connect() as connection:
                revision = connection.execute(text("""
                    SELECT version_num FROM alembic_version
                """)).scalar_one()

                assert revision == PREVIOUS_REVISION

                table_exists = connection.execute(text("""
                    SELECT COUNT(*)
                    FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'login_attempt_buckets'
                """)).scalar_one()

                assert table_exists == 0

                assert connection.execute(text("""
                    SELECT COUNT(*)
                    FROM policies
                    WHERE policy_key = 'THROTTLE-MIGRATION-001'
                """)).scalar_one() == 1

            # Re-upgrade and verify the table is recreated cleanly.
            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision="head",
            )

            with engine.connect() as connection:
                revision = connection.execute(text("""
                    SELECT version_num FROM alembic_version
                """)).scalar_one()

                assert revision == LATEST_REVISION

                assert connection.execute(text("""
                    SELECT COUNT(*) FROM login_attempt_buckets
                """)).scalar_one() == 0

                assert connection.execute(text("""
                    SELECT COUNT(*)
                    FROM policies
                    WHERE policy_key = 'THROTTLE-MIGRATION-001'
                """)).scalar_one() == 1

        finally:
            db.session.remove()
            event.remove(engine, "connect", enable_foreign_keys)
            engine.dispose()
