"""Security and concurrency tests for atomic login reservations."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest
from sqlalchemy import event

from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import (
    LoginAttemptBucket,
    LoginAttemptReservation,
)
from segcheck_web.services import login_throttle


TEST_SECRET = "isolated-test-secret-for-login-reservations"
TEST_IP = "203.0.113.45"
TEST_USERNAME = "reservation-admin"


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
        "LOGIN_RATE_LIMIT_RESERVATION_TTL_SECONDS": 60,
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


def reservation_count():
    return db.session.query(LoginAttemptReservation).count()


def get_bucket(username=TEST_USERNAME, source=TEST_IP, bucket_type="account_source"):
    keys = login_throttle._keys(username, source)
    return db.session.get(
        LoginAttemptBucket,
        keys[bucket_type],
        populate_existing=True,
    )


def test_reservations_consume_capacity_without_recording_failures(app):
    with app.app_context():
        admitted_one, token_one = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )
        admitted_two, token_two = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )
        admitted_three, token_three = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )

        assert admitted_one is True
        assert admitted_two is True
        assert admitted_three is False
        assert token_one
        assert token_two
        assert token_one != token_two
        assert token_three is None

        assert reservation_count() == 2
        assert db.session.query(LoginAttemptBucket).count() == 0


def test_failed_settlement_atomically_records_both_buckets(app):
    with app.app_context():
        admitted, token = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )
        assert admitted is True

        login_throttle.settle_failed_login(token)

        assert reservation_count() == 0

        account = get_bucket()
        source = get_bucket(bucket_type="source")

        assert account is not None
        assert source is not None
        assert account.attempts == 1
        assert source.attempts == 1


def test_reservation_token_is_single_use(app):
    with app.app_context():
        admitted, token = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )
        assert admitted is True

        login_throttle.settle_failed_login(token)

        with pytest.raises(login_throttle.LoginReservationError):
            login_throttle.settle_failed_login(token)

        account = get_bucket()
        source = get_bucket(bucket_type="source")

        assert account.attempts == 1
        assert source.attempts == 1


def test_success_settlement_preserves_other_reservations_and_source_history(app):
    with app.app_context():
        # One completed failure plus two active reservations must fit.
        app.config["LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX"] = 3
        login_throttle.record_failed_login(TEST_USERNAME, TEST_IP)

        admitted_one, token_one = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )
        admitted_two, token_two = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )

        assert admitted_one is True
        assert admitted_two is True
        assert reservation_count() == 2

        login_throttle.settle_successful_login(token_one)

        assert reservation_count() == 1
        assert get_bucket() is None

        source = get_bucket(bucket_type="source")
        assert source is not None
        assert source.attempts == 1

        login_throttle.settle_failed_login(token_two)

        assert reservation_count() == 0
        account = get_bucket()
        source = get_bucket(bucket_type="source")

        assert account.attempts == 1
        assert source.attempts == 2
        assert reservation_count() == 0
        account = get_bucket()
        source = get_bucket(bucket_type="source")

        assert account.attempts == 1
        assert source.attempts == 2


def test_expired_reservations_do_not_consume_capacity(app, monkeypatch):
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    clock = {"now": now}
    monkeypatch.setattr(
        login_throttle, "_utc_now", lambda: clock["now"]
    )

    with app.app_context():
        admitted, stale_token = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )
        assert admitted is True

        clock["now"] = now + timedelta(seconds=61)

        admitted, fresh_token = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )

        assert admitted is True
        assert fresh_token
        assert reservation_count() == 1

        with pytest.raises(login_throttle.LoginReservationError):
            login_throttle.settle_failed_login(stale_token)

        login_throttle.settle_successful_login(fresh_token)
        assert reservation_count() == 0


def test_expiry_cleanup_removes_only_expired_reservations(app, monkeypatch):
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    clock = {"now": now}
    monkeypatch.setattr(
        login_throttle, "_utc_now", lambda: clock["now"]
    )

    with app.app_context():
        admitted, expired_token = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )
        assert admitted is True

        clock["now"] = now + timedelta(seconds=61)

        admitted, active_token = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )
        assert admitted is True

        deleted = login_throttle.cleanup_expired_login_reservations()

        assert deleted == 0
        assert reservation_count() == 1

        # The next admission already removed the expired reservation.
        assert expired_token != active_token

        login_throttle.settle_successful_login(active_token)
        assert reservation_count() == 0


def test_source_limit_counts_reservations_across_accounts(app):
    with app.app_context():
        app.config["LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX"] = 10
        app.config["LOGIN_RATE_LIMIT_SOURCE_MAX"] = 2

        first, first_token = login_throttle.reserve_login_attempt(
            "first-admin", TEST_IP
        )
        second, second_token = login_throttle.reserve_login_attempt(
            "second-admin", TEST_IP
        )
        third, third_token = login_throttle.reserve_login_attempt(
            "third-admin", TEST_IP
        )

        assert first is True
        assert second is True
        assert third is False
        assert first_token
        assert second_token
        assert third_token is None
        assert reservation_count() == 2

        login_throttle.settle_successful_login(first_token)
        login_throttle.settle_successful_login(second_token)


def test_disabled_throttling_uses_no_reservation(app):
    with app.app_context():
        app.config["LOGIN_RATE_LIMIT_ENABLED"] = False

        admitted, token = login_throttle.reserve_login_attempt(
            TEST_USERNAME, TEST_IP
        )

        assert admitted is True
        assert token is None

        login_throttle.settle_failed_login(token)
        login_throttle.settle_successful_login(token)

        assert reservation_count() == 0
        assert db.session.query(LoginAttemptBucket).count() == 0


@pytest.mark.parametrize("token", ["x" * 10, "é" * 32, None, 123])
def test_invalid_reservation_tokens_are_rejected(app, token):
    with app.app_context():
        with pytest.raises(login_throttle.LoginReservationError):
            login_throttle.settle_failed_login(token)


def test_concurrent_reservations_never_exceed_configured_capacity(tmp_path):
    worker_count = 16
    database_path = tmp_path / "concurrent-reservations.sqlite3"

    application = create_app({
        "TESTING": True,
        "SECRET_KEY": TEST_SECRET,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "connect_args": {"timeout": 30}
        },
        "LOGIN_RATE_LIMIT_ENABLED": True,
        "LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX": 2,
        "LOGIN_RATE_LIMIT_SOURCE_MAX": 2,
        "LOGIN_RATE_LIMIT_WINDOW_SECONDS": 60,
        "LOGIN_RATE_LIMIT_BLOCK_SECONDS": 30,
        "LOGIN_RATE_LIMIT_RESERVATION_TTL_SECONDS": 60,
    })

    with application.app_context():
        engine = db.engine
        db.create_all()

    barrier = Barrier(worker_count)

    def reserve():
        with application.app_context():
            barrier.wait(timeout=15)
            return login_throttle.reserve_login_attempt(
                TEST_USERNAME, TEST_IP
            )

    try:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(reserve)
                for _ in range(worker_count)
            ]
            results = [future.result(timeout=45) for future in futures]

        admitted = [
            token for allowed, token in results if allowed
        ]
        rejected = [
            token for allowed, token in results if not allowed
        ]

        assert len(admitted) == 2
        assert all(admitted)
        assert rejected == [None] * (worker_count - 2)

        with application.app_context():
            assert (
                db.session.query(LoginAttemptReservation).count() == 2
            )

            for token in admitted:
                login_throttle.settle_successful_login(token)

            assert (
                db.session.query(LoginAttemptReservation).count() == 0
            )

    finally:
        with application.app_context():
            db.session.remove()
            db.drop_all()
            engine.dispose()
