"""Security tests for local SegCheck administrator authentication."""

import re

from flask import render_template_string

import pytest
from sqlalchemy import event
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash

from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import LoginAttemptBucket, User
from segcheck_web.services import login_throttle


BASE_URL = "https://localhost"
TEST_USERNAME = "test-admin"
TEST_PASSWORD = "TestAdmin-Password-2026!"


@pytest.fixture
def app():
    """Create an isolated application and database for each test."""

    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })

    # Database setup gets its own application context. Do not keep this
    # context open across test-client requests: Flask-WTF caches CSRF
    # tokens on g, which must be request-scoped.
    with application.app_context():
        engine = db.engine

        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        event.listen(engine, "connect", enable_foreign_keys)
        db.create_all()

        # Generate a fresh CSRF token in a genuine request context.
        def test_csrf_token_endpoint():
            return render_template_string("{{ csrf_token() }}")

        application.add_url_rule(
            "/_test/csrf-token",
            endpoint="_test_csrf_token",
            view_func=test_csrf_token_endpoint,
        )

    # Each test-client request now receives its normal Flask contexts.
    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()
        event.remove(engine, "connect", enable_foreign_keys)

        # Dispose of the isolated test database connection pool.
        engine.dispose()


def create_test_user(
    app,
    username=TEST_USERNAME,
    password=TEST_PASSWORD,
    is_active=True,
):
    """Create a test administrator using a real password hash."""

    with app.app_context():
        user = User(
            username=username,
            password_hash=generate_password_hash(
                password,
                method="scrypt",
            ),
            is_active=is_active,
        )
        db.session.add(user)
        db.session.commit()
        return user.id


def get_csrf_token(client):
    """Obtain a genuine CSRF token from the login form."""

    response = client.get("/login", base_url=BASE_URL)

    assert response.status_code == 200

    match = re.search(
        rb'name="csrf_token"\s+value="([^"]+)"',
        response.data,
    )

    assert match is not None, "Login form did not render a CSRF token"

    return match.group(1).decode("ascii")


def login_with_credentials(
    client,
    csrf_token,
    username=TEST_USERNAME,
    password=TEST_PASSWORD,
    **extra_data,
):
    """Submit credentials through the actual CSRF-protected endpoint."""

    data = {
        "csrf_token": csrf_token,
        "username": username,
        "password": password,
    }
    data.update(extra_data)

    return client.post(
        "/login",
        base_url=BASE_URL,
        headers={"Referer": f"{BASE_URL}/login"},
        data=data,
        follow_redirects=False,
    )


def authenticated_test_client(app):
    """Create an administrator and authenticate through the login route."""

    create_test_user(app)

    client = app.test_client()
    csrf_token = get_csrf_token(client)

    response = login_with_credentials(client, csrf_token)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    # Obtain a new CSRF token through a genuine request after login.
    # The endpoint is test-only and uses Flask-WTF's real token generator.
    csrf_response = client.get(
        "/_test/csrf-token",
        base_url=BASE_URL,
    )

    assert csrf_response.status_code == 200

    post_login_token = csrf_response.get_data(as_text=True).strip()
    assert post_login_token, "Post-login CSRF token was not generated"

    return client, post_login_token


def test_dashboard_requires_authentication(app):
    """The organisation overview must not disclose data before login."""

    response = app.test_client().get(
        "/",
        base_url=BASE_URL,
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_authenticated_dashboard_renders_real_workspace_overview(app):
    """An authenticated administrator can open the overview dashboard."""

    client, _csrf_token = authenticated_test_client(app)

    response = client.get("/", base_url=BASE_URL)

    assert response.status_code == 200
    assert b"Overview" in response.data
    assert b"Audits on this PC" in response.data
    assert b"New audit" in response.data
    assert b"Recorded check results" in response.data


def test_health_endpoint_remains_public(app):
    """Health monitoring must not require an administrator session."""

    response = app.test_client().get(
        "/api/health",
        base_url=BASE_URL,
    )

    assert response.status_code == 200


def test_audit_routes_reject_unauthenticated_users(app):
    """The audit pages must redirect unauthenticated users to login."""

    response = app.test_client().get(
        "/audit/",
        base_url=BASE_URL,
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_valid_credentials_authenticate_user_and_clear_old_session(app):
    """Successful login must establish authentication without old session data."""

    create_test_user(app)

    client = app.test_client()

    # Simulate data stored in a pre-authentication session.
    with client.session_transaction(base_url=BASE_URL) as session:
        session["pre_authentication_marker"] = "untrusted-old-state"

    csrf_token = get_csrf_token(client)
    response = login_with_credentials(client, csrf_token)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    with client.session_transaction(base_url=BASE_URL) as session:
        assert "_user_id" in session
        assert session["_fresh"] is True
        assert "pre_authentication_marker" not in session


def test_invalid_credentials_return_generic_error(app):
    """Invalid credentials must not disclose whether an account exists."""

    create_test_user(app)

    client = app.test_client()
    csrf_token = get_csrf_token(client)

    response = login_with_credentials(
        client,
        csrf_token,
        username=TEST_USERNAME,
        password="Definitely-Wrong-Password!",
    )

    assert response.status_code == 401
    assert b"Invalid username or password." in response.data


def test_unknown_username_returns_same_generic_error(app):
    """Unknown usernames must receive the same public error as bad passwords."""

    client = app.test_client()
    csrf_token = get_csrf_token(client)

    response = login_with_credentials(
        client,
        csrf_token,
        username="unknown-admin",
        password="Definitely-Wrong-Password!",
    )

    assert response.status_code == 401
    assert b"Invalid username or password." in response.data


def test_unknown_username_still_performs_password_verification(
    app, monkeypatch
):
    """Unknown usernames must still incur password-hash verification."""

    calls = []

    def record_verification(password_hash, password):
        calls.append((password_hash, password))
        return False

    monkeypatch.setattr(
        "segcheck_web.routes.auth.check_password_hash",
        record_verification,
    )

    client = app.test_client()
    csrf_token = get_csrf_token(client)

    response = login_with_credentials(
        client,
        csrf_token,
        username="unknown-admin",
        password="Definitely-Wrong-Password!",
    )

    assert response.status_code == 401
    assert b"Invalid username or password." in response.data
    assert len(calls) == 1
    assert calls[0][0].startswith("scrypt:")
    assert calls[0][1] == "Definitely-Wrong-Password!"


def test_inactive_account_still_performs_password_verification(
    app, monkeypatch
):
    """Inactive accounts are verified but never authenticated."""

    create_test_user(app, is_active=False)

    with app.app_context():
        user = db.session.query(User).filter_by(
            username=TEST_USERNAME
        ).one()
        stored_hash = user.password_hash

    calls = []

    def record_verification(password_hash, password):
        calls.append((password_hash, password))
        return True

    monkeypatch.setattr(
        "segcheck_web.routes.auth.check_password_hash",
        record_verification,
    )

    client = app.test_client()
    csrf_token = get_csrf_token(client)
    response = login_with_credentials(client, csrf_token)

    assert response.status_code == 401
    assert b"Invalid username or password." in response.data
    assert calls == [(stored_hash, TEST_PASSWORD)]

    with client.session_transaction(base_url=BASE_URL) as session:
        assert "_user_id" not in session


def test_inactive_account_cannot_authenticate(app):
    """Disabled administrator accounts must not establish a session."""

    create_test_user(app, is_active=False)

    client = app.test_client()
    csrf_token = get_csrf_token(client)

    response = login_with_credentials(client, csrf_token)

    assert response.status_code == 401
    assert b"Invalid username or password." in response.data

    with client.session_transaction(base_url=BASE_URL) as session:
        assert "_user_id" not in session


def test_login_rejects_missing_csrf_token(app):
    """Login must reject requests without a CSRF token."""

    create_test_user(app)

    response = app.test_client().post(
        "/login",
        base_url=BASE_URL,
        headers={"Referer": f"{BASE_URL}/login"},
        data={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    assert response.status_code == 400


def test_login_rejects_invalid_csrf_token(app):
    """Login must reject a forged CSRF token."""

    create_test_user(app)

    response = app.test_client().post(
        "/login",
        base_url=BASE_URL,
        headers={"Referer": f"{BASE_URL}/login"},
        data={
            "csrf_token": "forged-invalid-token",
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    assert response.status_code == 400


def test_login_does_not_follow_external_next_url(app):
    """Successful authentication must not redirect to an attacker URL."""

    create_test_user(app)

    client = app.test_client()
    csrf_token = get_csrf_token(client)

    response = login_with_credentials(
        client,
        csrf_token,
        next="https://attacker.example/",
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    assert "attacker.example" not in response.headers["Location"]


def test_logout_requires_csrf_protection(app):
    """Logout must reject a POST request without a valid CSRF token."""

    client, _csrf_token = authenticated_test_client(app)

    response = client.post(
        "/logout",
        base_url=BASE_URL,
        headers={"Referer": f"{BASE_URL}/login"},
    )

    assert response.status_code == 400


def test_valid_logout_ends_authenticated_session(app):
    """A valid CSRF-protected logout must terminate the session."""

    client, csrf_token = authenticated_test_client(app)

    response = client.post(
        "/logout",
        base_url=BASE_URL,
        headers={"Referer": f"{BASE_URL}/login"},
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )

    assert response.status_code == 302, (
        f"Logout returned HTTP {response.status_code}: "
        f"{response.data.decode('utf-8', errors='replace')}"
    )
    assert response.headers["Location"].endswith("/login")

    with client.session_transaction(base_url=BASE_URL) as session:
        assert "_user_id" not in session

    protected_response = client.get(
        "/audit/",
        base_url=BASE_URL,
        follow_redirects=False,
    )

    assert protected_response.status_code == 302
    assert "/login" in protected_response.headers["Location"]


def test_password_is_stored_as_a_hash_not_plaintext(app):
    """The database must never contain the submitted plaintext password."""

    create_test_user(app)

    with app.app_context():
        user = db.session.query(User).filter_by(
            username=TEST_USERNAME
        ).one()

        assert user.password_hash != TEST_PASSWORD
        assert check_password_hash(user.password_hash, TEST_PASSWORD)
        assert user.password_hash.startswith("scrypt:")


def test_create_admin_cli_provisions_initial_account(app):
    """The CLI must create the first administrator with a password hash."""

    runner = app.test_cli_runner()

    result = runner.invoke(
        args=["create-admin"],
        input=(
            "initial-admin\n"
            "Strong-Admin-Password-2026!\n"
            "Strong-Admin-Password-2026!\n"
        ),
    )

    assert result.exit_code == 0, result.output
    assert "created successfully" in result.output.lower()

    with app.app_context():
        user = db.session.query(User).filter_by(
            username="initial-admin"
        ).one()

        assert user.is_active is True
        assert user.password_hash != "Strong-Admin-Password-2026!"
        assert check_password_hash(
            user.password_hash,
            "Strong-Admin-Password-2026!",
        )


def test_create_admin_cli_refuses_second_account(app):
    """Initial provisioning must not create additional accounts."""

    create_test_user(app)

    runner = app.test_cli_runner()
    result = runner.invoke(args=["create-admin"])

    assert result.exit_code != 0
    assert "already exists" in result.output.lower()

    with app.app_context():
        assert db.session.query(User).count() == 1


# ---------------------------------------------------------------------------
# Authentication throttling security regression tests
# ---------------------------------------------------------------------------

def test_forwarded_headers_cannot_spoof_login_source(app):
    """Untrusted forwarding headers must not override the TCP peer address."""

    real_ip = "203.0.113.10"
    forged_ip = "198.51.100.77"

    client = app.test_client()
    client.environ_base["REMOTE_ADDR"] = real_ip
    csrf_token = get_csrf_token(client)

    response = client.post(
        "/login",
        base_url=BASE_URL,
        headers={
            "Referer": f"{BASE_URL}/login",
            "X-Forwarded-For": forged_ip,
            "X-Real-IP": forged_ip,
        },
        data={
            "csrf_token": csrf_token,
            "username": TEST_USERNAME,
            "password": "Definitely-Wrong-Password!",
        },
    )

    assert response.status_code == 401

    with app.app_context():
        real_keys = login_throttle._keys(TEST_USERNAME, real_ip)
        forged_keys = login_throttle._keys(TEST_USERNAME, forged_ip)

        assert db.session.get(
            LoginAttemptBucket, real_keys["source"]
        ) is not None

        assert db.session.get(
            LoginAttemptBucket, forged_keys["source"]
        ) is None


def test_malformed_username_still_increments_source_bucket(app):
    """Malformed usernames must not bypass source-wide attempt accounting."""

    source_ip = "203.0.113.21"
    client = app.test_client()
    client.environ_base["REMOTE_ADDR"] = source_ip
    csrf_token = get_csrf_token(client)

    response = client.post(
        "/login",
        base_url=BASE_URL,
        headers={"Referer": f"{BASE_URL}/login"},
        data={
            "csrf_token": csrf_token,
            "username": "x",
            "password": "Some-Password-2026!",
        },
    )

    assert response.status_code == 401
    assert b"Invalid username or password." in response.data

    with app.app_context():
        keys = login_throttle._keys(None, source_ip)

        account_bucket = db.session.get(
            LoginAttemptBucket, keys["account_source"]
        )
        source_bucket = db.session.get(
            LoginAttemptBucket, keys["source"]
        )

        assert account_bucket is not None
        assert account_bucket.attempts == 1
        assert source_bucket is not None
        assert source_bucket.attempts == 1


def test_active_throttle_blocks_before_password_verification(
    app, monkeypatch
):
    """A blocked login must not perform another expensive password check."""

    app.config["LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX"] = 1
    app.config["LOGIN_RATE_LIMIT_SOURCE_MAX"] = 100

    create_test_user(app)

    client = app.test_client()
    csrf_token = get_csrf_token(client)

    first_response = login_with_credentials(
        client,
        csrf_token,
        password="Definitely-Wrong-Password!",
    )

    assert first_response.status_code == 401

    def unexpected_password_verification(*_args, **_kwargs):
        pytest.fail("Password verification ran despite an active throttle.")

    monkeypatch.setattr(
        "segcheck_web.routes.auth.check_password_hash",
        unexpected_password_verification,
    )

    blocked_response = login_with_credentials(
        client,
        csrf_token,
        password=TEST_PASSWORD,
    )

    assert blocked_response.status_code == 429
    assert "Retry-After" in blocked_response.headers


def test_throttle_database_failure_fails_closed(app, monkeypatch):
    """A throttle database error must never permit authentication."""

    create_test_user(app)

    def database_failure(*_args, **_kwargs):
        raise SQLAlchemyError("simulated database failure")

    def unexpected_password_verification(*_args, **_kwargs):
        pytest.fail("Password verification ran after throttle failure.")

    monkeypatch.setattr(
        "segcheck_web.routes.auth.reserve_login_attempt",
        database_failure,
    )
    monkeypatch.setattr(
        "segcheck_web.routes.auth.check_password_hash",
        unexpected_password_verification,
    )

    client = app.test_client()
    csrf_token = get_csrf_token(client)

    response = login_with_credentials(client, csrf_token)

    assert response.status_code == 503
    assert b"simulated database failure" not in response.data


def test_successful_login_clears_only_account_source_bucket(app):
    """The login route must preserve the source-wide failure history."""

    create_test_user(app)

    source_ip = "203.0.113.31"

    with app.app_context():
        login_throttle.record_failed_login(TEST_USERNAME, source_ip)

        keys = login_throttle._keys(TEST_USERNAME, source_ip)

        assert db.session.get(
            LoginAttemptBucket, keys["account_source"]
        ) is not None

        assert db.session.get(
            LoginAttemptBucket, keys["source"]
        ) is not None

    client = app.test_client()
    client.environ_base["REMOTE_ADDR"] = source_ip
    csrf_token = get_csrf_token(client)

    response = login_with_credentials(client, csrf_token)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    with app.app_context():
        assert db.session.get(
            LoginAttemptBucket, keys["account_source"]
        ) is None

        source_bucket = db.session.get(
            LoginAttemptBucket, keys["source"]
        )

        assert source_bucket is not None
        assert source_bucket.attempts == 1
