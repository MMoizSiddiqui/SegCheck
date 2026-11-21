import os
"""Tests for the SegCheck web application foundation."""

import pytest

from segcheck_web import create_app


@pytest.fixture
def app():
    return create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })


@pytest.fixture
def client(app):
    return app.test_client()


def test_application_factory_creates_flask_app(app):
    assert app.name == "segcheck_web"
    assert app.config["TESTING"] is True


def test_health_endpoint_reports_database_available(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ok",
        "database": "available",
    }


def test_unknown_route_returns_not_found(client):
    response = client.get("/route-that-does-not-exist")

    assert response.status_code == 404


def test_test_database_does_not_require_production_storage(app):
    assert app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite://"


def test_production_startup_prepares_private_sqlite_storage(
    tmp_path,
    monkeypatch,
):
    import os
    import stat

    data_dir = tmp_path / "segcheck-data"
    monkeypatch.setenv("SEGCHECK_DATA_DIR", str(data_dir))

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "integration-test-secret",
    })

    database_path = data_dir / "segcheck.sqlite3"

    assert database_path.is_file()
    assert app.config["SQLALCHEMY_DATABASE_URI"]

    if os.name == "posix":
        assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(database_path.stat().st_mode) == 0o600
        assert data_dir.stat().st_uid == os.getuid()
        assert database_path.stat().st_uid == os.getuid()

    response = app.test_client().get("/api/health")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ok",
        "database": "available",
    }


@pytest.mark.skipif(os.name != "posix", reason="POSIX path/permission/symlink semantics; Windows ACL behaviour is verified separately")
def test_production_startup_rejects_symlinked_storage_path(
    tmp_path,
    monkeypatch,
):
    from segcheck_web.database_storage import DatabaseStorageError

    actual_directory = tmp_path / "actual"
    actual_directory.mkdir(mode=0o700)

    linked_directory = tmp_path / "linked"
    linked_directory.symlink_to(
        actual_directory,
        target_is_directory=True,
    )

    monkeypatch.setenv("SEGCHECK_DATA_DIR", str(linked_directory))

    with pytest.raises(DatabaseStorageError, match="symbolic links"):
        create_app({
            "TESTING": True,
            "SECRET_KEY": "integration-test-secret",
        })

    assert not (actual_directory / "segcheck.sqlite3").exists()


def test_production_startup_reuses_existing_private_database(
    tmp_path,
    monkeypatch,
):
    import os
    import stat

    data_dir = tmp_path / "segcheck-data"
    data_dir.mkdir(mode=0o700)

    database_path = data_dir / "segcheck.sqlite3"
    database_path.write_bytes(b"")

    if os.name == "posix":
        database_path.chmod(0o600)

    monkeypatch.setenv("SEGCHECK_DATA_DIR", str(data_dir))

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "integration-test-secret",
    })

    response = app.test_client().get("/api/health")

    assert response.status_code == 200
    assert response.get_json()["database"] == "available"

    if os.name == "posix":
        assert stat.S_IMODE(database_path.stat().st_mode) == 0o600


def test_production_rejects_missing_secret_key():
    with pytest.raises(RuntimeError, match="SEGCHECK_SECRET_KEY"):
        create_app({
            "TESTING": False,
            "SECRET_KEY": None,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
        })


@pytest.mark.parametrize("secret", ["short", "x" * 31])
def test_production_rejects_secret_below_minimum_length(secret):
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        create_app({
            "TESTING": False,
            "SECRET_KEY": secret,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
        })


def test_production_accepts_secret_meeting_minimum_length():
    # This verifies the length check, not the secret's entropy.
    app = create_app({
        "TESTING": False,
        "SECRET_KEY": "test-secret-" + ("x" * 32),
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })

    assert app.config["SECRET_KEY"] == "test-secret-" + ("x" * 32)


def test_secure_session_and_request_defaults():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })

    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    # Allow multipart request overhead; the policy importer separately
    # enforces the 1 MiB limit on the uploaded policy file itself.
    assert app.config["MAX_CONTENT_LENGTH"] == 1_048_576 + 16_384

def test_debug_mode_is_rejected():
    with pytest.raises(RuntimeError, match="Debug mode"):
        create_app({
            "TESTING": True,
            "DEBUG": True,
            "SECRET_KEY": "test-only-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
        })


def test_security_sensitive_defaults_are_enforced():
    app = create_app({
        "TESTING": True,
        "DEBUG": False,
        "PROPAGATE_EXCEPTIONS": True,
        "TRAP_HTTP_EXCEPTIONS": True,
        "TRAP_BAD_REQUEST_ERRORS": True,
        "SQLALCHEMY_ECHO": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })

    assert app.config["DEBUG"] is False
    assert app.config["PROPAGATE_EXCEPTIONS"] is False
    assert app.config["TRAP_HTTP_EXCEPTIONS"] is False
    assert app.config["TRAP_BAD_REQUEST_ERRORS"] is False
    assert app.config["SQLALCHEMY_ECHO"] is False


def test_health_response_includes_security_headers(client):
    response = client.get("/api/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == (
        "strict-origin-when-cross-origin"
    )
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]

