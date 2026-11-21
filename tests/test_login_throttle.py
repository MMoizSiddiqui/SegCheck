"""Tests for privacy-preserving database-backed login throttling."""

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import event

from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import LoginAttemptBucket
from segcheck_web.services import login_throttle


TEST_SECRET = "isolated-test-secret-for-login-throttling"
TEST_USERNAME = "throttle-admin"
TEST_IP = "203.0.113.45"


@pytest.fixture
def app():
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": TEST_SECRET,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "LOGIN_RATE_LIMIT_ENABLED": True,
        "LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX": 2,
        "LOGIN_RATE_LIMIT_SOURCE_MAX": 10,
        "LOGIN_RATE_LIMIT_WINDOW_SECONDS": 60,
        "LOGIN_RATE_LIMIT_BLOCK_SECONDS": 30,
    })

    with application.app_context():
        engine = db.engine

        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        event.listen(engine, "connect", enable_foreign_keys)
        db.create_all()

    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()
        event.remove(engine, "connect", enable_foreign_keys)
        engine.dispose()


def get_bucket(bucket_type, username=TEST_USERNAME, source=TEST_IP):
    keys = login_throttle._keys(username, source)
    key = keys[bucket_type]

    return db.session.get(LoginAttemptBucket, key)


def test_account_source_bucket_blocks_at_configured_threshold(app):
    with app.app_context():
        assert not login_throttle.is_login_throttled(
            TEST_USERNAME, TEST_IP
        )

        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        assert not login_throttle.is_login_throttled(
            TEST_USERNAME, TEST_IP
        )

        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        assert login_throttle.is_login_throttled(
            TEST_USERNAME, TEST_IP
        )

        bucket = get_bucket("account_source")
        assert bucket.attempts == 2
        assert bucket.blocked_until is not None


def test_source_wide_bucket_is_independent_of_account_bucket(app):
    with app.app_context():
        login_throttle.record_failed_login("first-admin", TEST_IP)
        login_throttle.record_failed_login("second-admin", TEST_IP)

        first = get_bucket("account_source", "first-admin")
        second = get_bucket("account_source", "second-admin")
        source = get_bucket("source")

        assert first.attempts == 1
        assert second.attempts == 1
        assert source.attempts == 2
        assert source.blocked_until is None


def test_different_sources_have_independent_buckets(app):
    with app.app_context():
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)
        login_throttle.record_failed_login(
            TEST_USERNAME, "198.51.100.20"
        )

        first = get_bucket("account_source", source=TEST_IP)
        second = get_bucket(
            "account_source", source="198.51.100.20"
        )

        assert first.attempts == 1
        assert second.attempts == 1


def test_active_block_is_not_extended_by_more_failures(app, monkeypatch):
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(login_throttle, "_utc_now", lambda: now)

    with app.app_context():
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        bucket = get_bucket("account_source")
        original_expiry = bucket.blocked_until

        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        db.session.refresh(bucket)
        assert bucket.attempts == 2
        assert bucket.blocked_until == original_expiry


def test_expired_block_resets_attempt_counter(app, monkeypatch):
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    clock = {"now": now}
    monkeypatch.setattr(
        login_throttle, "_utc_now", lambda: clock["now"]
    )

    with app.app_context():
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        assert login_throttle.is_login_throttled(
            TEST_USERNAME, TEST_IP
        )

        clock["now"] = now + timedelta(seconds=31)

        assert not login_throttle.is_login_throttled(
            TEST_USERNAME, TEST_IP
        )

        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        bucket = get_bucket("account_source")
        assert bucket.attempts == 1
        assert bucket.blocked_until is None


def test_successful_login_clear_does_not_clear_source_bucket(app):
    with app.app_context():
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        assert get_bucket("account_source") is not None
        assert get_bucket("source") is not None

        login_throttle.clear_account_source_bucket(
            TEST_USERNAME, TEST_IP
        )

        assert get_bucket("account_source") is None
        assert get_bucket("source") is not None


def test_equivalent_ip_representations_use_same_bucket(app):
    with app.app_context():
        compressed = login_throttle._keys(
            TEST_USERNAME, "::1"
        )
        expanded = login_throttle._keys(
            TEST_USERNAME, "0:0:0:0:0:0:0:1"
        )

        assert compressed == expanded


def test_invalid_source_ip_is_rejected(app):
    with app.app_context():
        with pytest.raises(ValueError):
            login_throttle.record_failed_login(
                TEST_USERNAME, "not-an-ip-address"
            )


def test_raw_username_and_ip_are_not_stored(app):
    with app.app_context():
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        buckets = db.session.query(LoginAttemptBucket).all()
        assert len(buckets) == 2

        stored_values = repr([
            {
                "key": bucket.bucket_key,
                "type": bucket.bucket_type,
                "attempts": bucket.attempts,
            }
            for bucket in buckets
        ])

        assert TEST_USERNAME not in stored_values
        assert TEST_IP not in stored_values


def test_disabled_throttling_does_not_create_buckets(app):
    with app.app_context():
        app.config["LOGIN_RATE_LIMIT_ENABLED"] = False

        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        assert not login_throttle.is_login_throttled(
            TEST_USERNAME, TEST_IP
        )
        assert db.session.query(LoginAttemptBucket).count() == 0


def test_cleanup_removes_old_inactive_buckets(app, monkeypatch):
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(login_throttle, "_utc_now", lambda: now)

    with app.app_context():
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        bucket = get_bucket("account_source")
        bucket.updated_at = now - timedelta(seconds=200)
        db.session.commit()

        deleted = login_throttle.cleanup_expired_login_buckets()

        assert deleted >= 1
        assert get_bucket("account_source") is None


def test_source_wide_limit_blocks_different_accounts(app):
    with app.app_context():
        app.config["LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX"] = 100
        app.config["LOGIN_RATE_LIMIT_SOURCE_MAX"] = 2

        login_throttle.record_failed_login("first-admin", TEST_IP)

        assert not login_throttle.is_login_throttled(
            "second-admin", TEST_IP
        )

        login_throttle.record_failed_login("second-admin", TEST_IP)

        # The source-wide bucket blocks even a different account.
        assert login_throttle.is_login_throttled(
            "third-admin", TEST_IP
        )

        source_bucket = get_bucket("source")
        assert source_bucket.attempts == 2
        assert source_bucket.blocked_until is not None


def test_secret_rotation_changes_bucket_identifiers(app):
    with app.app_context():
        original = login_throttle._keys(TEST_USERNAME, TEST_IP)

        app.config["SECRET_KEY"] = "rotated-test-secret"

        rotated = login_throttle._keys(TEST_USERNAME, TEST_IP)

        assert original["account_source"] != rotated["account_source"]
        assert original["source"] != rotated["source"]


def test_concurrent_failed_logins_do_not_lose_increments(tmp_path):
    worker_count = 12
    database_path = tmp_path / "concurrent-throttle.sqlite3"

    application = create_app({
        "TESTING": True,
        "SECRET_KEY": TEST_SECRET,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "connect_args": {"timeout": 30}
        },
        "LOGIN_RATE_LIMIT_ENABLED": True,
        "LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX": 100,
        "LOGIN_RATE_LIMIT_SOURCE_MAX": 100,
        "LOGIN_RATE_LIMIT_WINDOW_SECONDS": 60,
        "LOGIN_RATE_LIMIT_BLOCK_SECONDS": 30,
    })

    with application.app_context():
        engine = db.engine
        db.create_all()

    barrier = Barrier(worker_count)

    def submit_failed_login():
        with application.app_context():
            barrier.wait(timeout=15)
            login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

    try:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(submit_failed_login)
                for _ in range(worker_count)
            ]

            for future in futures:
                future.result(timeout=45)

        with application.app_context():
            account_bucket = get_bucket("account_source")
            source_bucket = get_bucket("source")

            assert account_bucket is not None
            assert source_bucket is not None
            assert account_bucket.attempts == worker_count
            assert source_bucket.attempts == worker_count

    finally:
        with application.app_context():
            db.session.remove()
            db.drop_all()
            engine.dispose()
