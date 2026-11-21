"""Privacy-preserving, database-backed login throttling."""

import hashlib
import hmac
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from segcheck_web.extensions import db
from segcheck_web.models import (
    LoginAttemptBucket,
    LoginAttemptReservation,
)


def _utc_now():
    return datetime.now(timezone.utc)


def _positive_integer(value, setting_name, maximum=86400):
    """Validate a bounded integer configuration value."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"{setting_name} must be an integer")

    if not 1 <= value <= maximum:
        raise RuntimeError(
            f"{setting_name} must be between 1 and {maximum}"
        )

    return value


def _settings():
    """Load and validate throttling settings."""
    config = current_app.config

    account_limit = _positive_integer(
        config["LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX"],
        "LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX",
        1000,
    )
    source_limit = _positive_integer(
        config["LOGIN_RATE_LIMIT_SOURCE_MAX"],
        "LOGIN_RATE_LIMIT_SOURCE_MAX",
        10000,
    )
    window_seconds = _positive_integer(
        config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"],
        "LOGIN_RATE_LIMIT_WINDOW_SECONDS",
    )
    block_seconds = _positive_integer(
        config["LOGIN_RATE_LIMIT_BLOCK_SECONDS"],
        "LOGIN_RATE_LIMIT_BLOCK_SECONDS",
    )

    return account_limit, source_limit, window_seconds, block_seconds


def _bucket_key(bucket_type, username, source):
    """Derive a non-reversible, context-separated bucket identifier."""
    secret = current_app.config.get("SECRET_KEY")

    if not isinstance(secret, str) or not secret:
        raise RuntimeError("A signing secret is required for login throttling")

    if not isinstance(source, str) or not source:
        raise ValueError("A valid request source is required")

    try:
        source = ipaddress.ip_address(source).compressed
    except ValueError as exc:
        raise ValueError("A valid IP address is required") from exc

    if username is not None and not isinstance(username, str):
        raise ValueError("A valid username is required")

    message = (
        bucket_type + "\0" +
        (username if username is not None else "") + "\0" +
        source
    ).encode("utf-8")

    return hmac.new(
        secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def _keys(username, source):
    return {
        "account_source": _bucket_key(
            "account_source", username, source
        ),
        "source": _bucket_key("source", None, source),
    }


def is_login_throttled(username, source):
    """Return True if either relevant bucket is currently blocked."""
    if not current_app.config.get("LOGIN_RATE_LIMIT_ENABLED", True):
        return False

    keys = _keys(username, source)
    now = _utc_now()

    statement = select(LoginAttemptBucket.bucket_key).where(
        LoginAttemptBucket.bucket_key.in_(list(keys.values())),
        LoginAttemptBucket.blocked_until.is_not(None),
        LoginAttemptBucket.blocked_until > now,
    ).limit(1)

    return db.session.execute(statement).first() is not None


def _record_bucket(key, bucket_type, maximum, window_seconds,
                   block_seconds, now, executor=None):
    """Atomically increment a bucket and establish a temporary block."""
    table = LoginAttemptBucket.__table__
    cutoff = now - timedelta(seconds=window_seconds)
    block_expiry = now + timedelta(seconds=block_seconds)

    insert_statement = sqlite_insert(table).values(
        bucket_key=key,
        bucket_type=bucket_type,
        attempts=1,
        window_started_at=now,
        blocked_until=(
            block_expiry if maximum <= 1 else None
        ),
        updated_at=now,
    )

    existing_block_active = table.c.blocked_until > now
    window_expired = table.c.window_started_at <= cutoff
    previous_block_expired = and_(
        table.c.blocked_until.is_not(None),
        table.c.blocked_until <= now,
    )
    reset_bucket = or_(window_expired, previous_block_expired)

    next_attempts = case(
        (existing_block_active, table.c.attempts),
        (reset_bucket, 1),
        else_=table.c.attempts + 1,
    )

    next_window_start = case(
        (existing_block_active, table.c.window_started_at),
        (reset_bucket, now),
        else_=table.c.window_started_at,
    )

    next_blocked_until = case(
        (existing_block_active, table.c.blocked_until),
        (next_attempts >= maximum, block_expiry),
        else_=None,
    )

    statement = insert_statement.on_conflict_do_update(
        index_elements=[table.c.bucket_key],
        set_={
            "attempts": next_attempts,
            "window_started_at": next_window_start,
            "blocked_until": next_blocked_until,
            "updated_at": now,
        },
    )

    target = db.session if executor is None else executor
    target.execute(statement)


def record_failed_login(username, source):
    """Atomically record a failed login in both relevant buckets."""
    if not current_app.config.get("LOGIN_RATE_LIMIT_ENABLED", True):
        return

    account_limit, source_limit, window_seconds, block_seconds = (
        _settings()
    )
    keys = _keys(username, source)
    now = _utc_now()

    try:
        _record_bucket(
            keys["account_source"],
            "account_source",
            account_limit,
            window_seconds,
            block_seconds,
            now,
        )
        _record_bucket(
            keys["source"],
            "source",
            source_limit,
            window_seconds,
            block_seconds,
            now,
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


def clear_account_source_bucket(username, source):
    """Clear only the successful account/source combination."""
    if not current_app.config.get("LOGIN_RATE_LIMIT_ENABLED", True):
        return

    key = _keys(username, source)["account_source"]

    try:
        db.session.execute(
            db.delete(LoginAttemptBucket).where(
                LoginAttemptBucket.bucket_key == key,
                LoginAttemptBucket.bucket_type == "account_source",
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


def cleanup_expired_login_buckets():
    """Delete expired, inactive buckets to keep storage bounded."""
    if not current_app.config.get("LOGIN_RATE_LIMIT_ENABLED", True):
        return 0

    _, _, window_seconds, block_seconds = _settings()
    now = _utc_now()
    retention = timedelta(
        seconds=max(window_seconds, block_seconds) * 2
    )
    cutoff = now - retention

    try:
        result = db.session.execute(
            db.delete(LoginAttemptBucket).where(
                LoginAttemptBucket.updated_at < cutoff,
                or_(
                    LoginAttemptBucket.blocked_until.is_(None),
                    LoginAttemptBucket.blocked_until <= now,
                ),
            )
        )
        db.session.commit()
        return result.rowcount or 0
    except Exception:
        db.session.rollback()
        raise


class LoginReservationError(ValueError):
    """Raised when a login reservation cannot be settled safely."""


def _reservation_settings():
    """Return the validated lifetime for in-progress login reservations."""
    return _positive_integer(
        current_app.config["LOGIN_RATE_LIMIT_RESERVATION_TTL_SECONDS"],
        "LOGIN_RATE_LIMIT_RESERVATION_TTL_SECONDS",
        300,
    )


def _reservation_digest(token):
    """Derive a keyed, non-reversible database identifier for a token."""
    secret = current_app.config.get("SECRET_KEY")

    if not isinstance(secret, str) or not secret:
        raise RuntimeError("A signing secret is required for login reservations")

    if not isinstance(token, str) or not 20 <= len(token) <= 128:
        raise LoginReservationError("Invalid login reservation token")

    try:
        token_bytes = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LoginReservationError(
            "Invalid login reservation token"
        ) from exc

    return hmac.new(
        secret.encode("utf-8"),
        b"segcheck-login-reservation\\0" + token_bytes,
        hashlib.sha256,
    ).hexdigest()

def _immediate_transaction(operation):
    """Run a short operation under a SQLite immediate write transaction."""
    connection = db.engine.connect()

    try:
        # Acquire SQLite's reserved write lock before reading capacity.
        # This serializes admission across threads and worker processes.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        result = operation(connection)
        connection.commit()
        return result
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _utc_datetime(value):
    """Normalize SQLite's potentially naive UTC datetime values."""
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _effective_bucket_attempts(connection, key, maximum, now, cutoff):
    """Return current failures plus active reservations, or None if blocked."""
    table = LoginAttemptBucket.__table__
    row = connection.execute(
        select(table).where(table.c.bucket_key == key)
    ).mappings().first()

    if row is None:
        attempts = 0
    else:
        blocked_until = _utc_datetime(row["blocked_until"])
        window_started_at = _utc_datetime(row["window_started_at"])

        if blocked_until is not None and blocked_until > now:
            return None

        if (
            window_started_at <= cutoff
            or (blocked_until is not None and blocked_until <= now)
        ):
            attempts = 0
        else:
            attempts = row["attempts"]

    reservations = LoginAttemptReservation.__table__
    active_count = connection.execute(
        select(func.count())
        .select_from(reservations)
        .where(
            reservations.c.expires_at > now,
            or_(
                reservations.c.account_bucket_key == key,
                reservations.c.source_bucket_key == key,
            ),
        )
    ).scalar_one()

    total = attempts + active_count

    if total >= maximum:
        return None

    return total


def reserve_login_attempt(username, source):
    """Atomically reserve capacity before performing password verification.

    Returns (True, token) when admitted, (False, None) when throttled,
    and (True, None) when throttling is disabled.
    """
    if not current_app.config.get("LOGIN_RATE_LIMIT_ENABLED", True):
        return True, None

    account_limit, source_limit, window_seconds, _ = _settings()
    ttl_seconds = _reservation_settings()
    keys = _keys(username, source)

    token = secrets.token_urlsafe(32)
    digest = _reservation_digest(token)
    now = _utc_now()
    expires_at = now + timedelta(seconds=ttl_seconds)
    cutoff = now - timedelta(seconds=window_seconds)

    def reserve(connection):
        reservation_table = LoginAttemptReservation.__table__

        # Expired reservations never consume capacity, even if cleanup
        # has not yet been run by a maintenance task.
        connection.execute(
            db.delete(LoginAttemptReservation).where(
                reservation_table.c.expires_at <= now
            )
        )

        account_total = _effective_bucket_attempts(
            connection,
            keys["account_source"],
            account_limit,
            now,
            cutoff,
        )
        if account_total is None:
            return False

        source_total = _effective_bucket_attempts(
            connection,
            keys["source"],
            source_limit,
            now,
            cutoff,
        )
        if source_total is None:
            return False

        connection.execute(
            reservation_table.insert().values(
                reservation_key=digest,
                account_bucket_key=keys["account_source"],
                source_bucket_key=keys["source"],
                created_at=now,
                expires_at=expires_at,
            )
        )
        return True

    admitted = _immediate_transaction(reserve)

    if not admitted:
        return False, None

    return True, token


def _settle_login_reservation(token, outcome):
    """Consume one reservation and atomically record its final outcome."""
    if not current_app.config.get("LOGIN_RATE_LIMIT_ENABLED", True):
        return

    if token is None:
        raise LoginReservationError("A login reservation is required")

    digest = _reservation_digest(token)
    account_limit, source_limit, window_seconds, block_seconds = _settings()
    now = _utc_now()

    def settle(connection):
        table = LoginAttemptReservation.__table__
        reservation = connection.execute(
            select(table).where(table.c.reservation_key == digest)
        ).mappings().first()

        if reservation is None:
            raise LoginReservationError(
                "Login reservation is missing or already settled"
            )

        expires_at = _utc_datetime(reservation["expires_at"])

        if expires_at <= now:
            connection.execute(
                db.delete(LoginAttemptReservation).where(
                    table.c.reservation_key == digest
                )
            )
            return False

        # Delete only this request's reservation. The surrounding
        # transaction makes deletion and failure accounting indivisible.
        connection.execute(
            db.delete(LoginAttemptReservation).where(
                table.c.reservation_key == digest
            )
        )

        if outcome == "failed":
            _record_bucket(
                reservation["account_bucket_key"],
                "account_source",
                account_limit,
                window_seconds,
                block_seconds,
                now,
                executor=connection,
            )
            _record_bucket(
                reservation["source_bucket_key"],
                "source",
                source_limit,
                window_seconds,
                block_seconds,
                now,
                executor=connection,
            )
        elif outcome == "success":
            bucket_table = LoginAttemptBucket.__table__
            connection.execute(
                db.delete(LoginAttemptBucket).where(
                    bucket_table.c.bucket_key
                    == reservation["account_bucket_key"],
                    bucket_table.c.bucket_type == "account_source",
                )
            )
        else:
            raise ValueError("Unsupported login reservation outcome")

        return True

    settled = _immediate_transaction(settle)

    if not settled:
        raise LoginReservationError("Login reservation has expired")


def settle_failed_login(token):
    """Consume a reservation and record one failed attempt."""
    _settle_login_reservation(token, "failed")


def settle_successful_login(token):
    """Consume a reservation and clear only its account/source failures."""
    _settle_login_reservation(token, "success")


def release_login_reservation(token):
    """Release one request's reservation without recording a failure."""
    if not current_app.config.get("LOGIN_RATE_LIMIT_ENABLED", True):
        return

    if token is None:
        return

    digest = _reservation_digest(token)
    table = LoginAttemptReservation.__table__

    def release(connection):
        result = connection.execute(
            db.delete(LoginAttemptReservation).where(
                table.c.reservation_key == digest
            )
        )
        return result.rowcount or 0

    return _immediate_transaction(release)


def cleanup_expired_login_reservations():
    """Remove expired reservations without affecting active requests."""
    if not current_app.config.get("LOGIN_RATE_LIMIT_ENABLED", True):
        return 0

    now = _utc_now()

    def cleanup(connection):
        result = connection.execute(
            db.delete(LoginAttemptReservation).where(
                LoginAttemptReservation.expires_at <= now
            )
        )
        return result.rowcount or 0

    return _immediate_transaction(cleanup)
