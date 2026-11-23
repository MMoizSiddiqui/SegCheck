"""Migration regression tests for login attempt reservations."""

from pathlib import Path

import pytest
from flask_migrate import downgrade, upgrade
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from segcheck_web import create_app
from segcheck_web.extensions import db


MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "segcheck_web" / "migrations"

PREVIOUS_REVISION = "8a41c2d7e901"
LATEST_REVISION = "f3a9c1d7e2b4"


def test_login_reservation_migration_upgrade_downgrade_and_reupgrade(
    tmp_path,
):
    """Verify schema, constraints, existing data and reversibility."""
    database_path = tmp_path / "login-reservation-migration.sqlite3"

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "reservation-migration-test-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        engine = db.engine

        try:
            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision=PREVIOUS_REVISION,
            )

            # Preserve an existing throttle bucket through the migration.
            with engine.begin() as connection:
                connection.execute(text("""
                    INSERT INTO login_attempt_buckets (
                        bucket_key, bucket_type, attempts,
                        window_started_at, blocked_until, updated_at
                    )
                    VALUES (
                        :key, 'account_source', 1,
                        '2026-11-10 12:00:00', NULL,
                        '2026-11-10 12:00:00'
                    )
                """), {"key": "a" * 64})

            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision="head",
            )

            with engine.connect() as connection:
                revision = connection.execute(text("""
                    SELECT version_num FROM alembic_version
                """)).scalar_one()
                assert revision == LATEST_REVISION

                columns = {
                    item["name"]: item
                    for item in connection.execute(text(
                        "PRAGMA table_info('login_attempt_reservations')"
                    )).mappings()
                }

                assert set(columns) == {
                    "reservation_key",
                    "account_bucket_key",
                    "source_bucket_key",
                    "created_at",
                    "expires_at",
                }

                assert columns["reservation_key"]["pk"] == 1
                for name in (
                    "account_bucket_key",
                    "source_bucket_key",
                    "created_at",
                    "expires_at",
                ):
                    assert columns[name]["notnull"] == 1

                indexes = {
                    item["name"]
                    for item in connection.execute(text(
                        "PRAGMA index_list('login_attempt_reservations')"
                    )).mappings()
                }

                assert indexes == {
                    "ix_login_attempt_reservations_account_bucket",
                    "ix_login_attempt_reservations_source_bucket",
                    "ix_login_attempt_reservations_expires_at",
                    "sqlite_autoindex_login_attempt_reservations_1",
                }

                table_sql = connection.execute(text("""
                    SELECT sql
                    FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'login_attempt_reservations'
                """)).scalar_one()

                for constraint in (
                    "ck_login_attempt_reservations_key_length",
                    "ck_login_attempt_reservations_account_key_length",
                    "ck_login_attempt_reservations_source_key_length",
                    "ck_login_attempt_reservations_expiry",
                ):
                    assert constraint in table_sql

                existing_bucket = connection.execute(text("""
                    SELECT attempts
                    FROM login_attempt_buckets
                    WHERE bucket_key = :key
                """), {"key": "a" * 64}).scalar_one()

                assert existing_bucket == 1

            valid = {
                "key": "c" * 64,
                "account": "a" * 64,
                "source": "b" * 64,
                "created": "2026-11-10 12:00:00",
                "expires": "2026-11-10 12:05:00",
            }

            with engine.begin() as connection:
                connection.execute(text("""
                    INSERT INTO login_attempt_reservations (
                        reservation_key, account_bucket_key,
                        source_bucket_key, created_at, expires_at
                    )
                    VALUES (
                        :key, :account, :source, :created, :expires
                    )
                """), valid)

            invalid_rows = [
                {**valid, "key": "short"},
                {**valid, "key": "d" * 64, "account": "short"},
                {**valid, "key": "e" * 64, "source": "short"},
                {
                    **valid,
                    "key": "f" * 64,
                    "expires": "2026-11-10 12:00:00",
                },
                {
                    **valid,
                    "key": "g" * 64,
                    "expires": "2026-11-10 11:59:59",
                },
            ]

            for invalid in invalid_rows:
                with pytest.raises(IntegrityError):
                    with engine.begin() as connection:
                        connection.execute(text("""
                            INSERT INTO login_attempt_reservations (
                                reservation_key, account_bucket_key,
                                source_bucket_key, created_at, expires_at
                            )
                            VALUES (
                                :key, :account, :source, :created, :expires
                            )
                        """), invalid)

            # Downgrade only the new reservation migration.
            downgrade(
                directory=str(MIGRATIONS_DIR),
                revision=PREVIOUS_REVISION,
            )

            with engine.connect() as connection:
                revision = connection.execute(text("""
                    SELECT version_num FROM alembic_version
                """)).scalar_one()
                assert revision == PREVIOUS_REVISION

                reservation_table = connection.execute(text("""
                    SELECT COUNT(*)
                    FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'login_attempt_reservations'
                """)).scalar_one()
                assert reservation_table == 0

                bucket_count = connection.execute(text("""
                    SELECT COUNT(*)
                    FROM login_attempt_buckets
                    WHERE bucket_key = :key
                """), {"key": "a" * 64}).scalar_one()
                assert bucket_count == 1

            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision="head",
            )

            with engine.connect() as connection:
                revision = connection.execute(text("""
                    SELECT version_num FROM alembic_version
                """)).scalar_one()
                assert revision == LATEST_REVISION

                count = connection.execute(text("""
                    SELECT COUNT(*) FROM login_attempt_reservations
                """)).scalar_one()
                assert count == 0

                bucket_count = connection.execute(text("""
                    SELECT COUNT(*)
                    FROM login_attempt_buckets
                    WHERE bucket_key = :key
                """), {"key": "a" * 64}).scalar_one()
                assert bucket_count == 1

        finally:
            db.session.remove()
            engine.dispose()
