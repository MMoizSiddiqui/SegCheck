
"""Shared fixtures for authenticated SegCheck web tests."""

import re

import pytest
from werkzeug.security import generate_password_hash

from segcheck_web.extensions import db
from segcheck_web.models import User


TEST_USERNAME = "test-admin"
TEST_PASSWORD = "TestAdmin-Password-2026!"


@pytest.fixture
def authenticated_client(app):
    """Return a client authenticated through the real CSRF-protected login."""

    with app.app_context():
        user = User(
            username=TEST_USERNAME,
            password_hash=generate_password_hash(
                TEST_PASSWORD,
                method="scrypt",
            ),
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    client = app.test_client()
    base_url = "https://localhost"

    # Obtain a genuine CSRF token from the login form.
    login_page = client.get("/login", base_url=base_url)

    assert login_page.status_code == 200

    token_match = re.search(
        rb'name="csrf_token"\s+value="([^"]+)"',
        login_page.data,
    )
    assert token_match is not None, "Login form CSRF token was not rendered"

    csrf_token = token_match.group(1).decode("ascii")

    # Authenticate through the actual login endpoint.
    response = client.post(
        "/login",
        base_url=base_url,
        headers={
            "Referer": "https://localhost/login",
        },
        data={
            "csrf_token": csrf_token,
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200, (
        f'Login failed with HTTP {response.status_code}: '
        f'{response.data.decode("utf-8", errors="replace")}'
    )
    assert b"Audits on this PC" in response.data

    return client
