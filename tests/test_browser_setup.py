"""One-time administrator setup cannot be taken over or replayed."""
from werkzeug.datastructures import MultiDict
from werkzeug.security import check_password_hash

from test_environment_workflow import app, get_token, post
from segcheck_web.extensions import db
from segcheck_web.models import User
from segcheck_web.models.bootstrap import BootstrapClaim

TOKEN = "test-installation-token-with-at-least-32-bytes"


def test_setup_disabled_without_installation_token(app):
    assert app.test_client().get("/setup", base_url="https://localhost").status_code == 404


def test_browser_setup_is_one_time_and_hashes_password(app):
    app.config["SEGCHECK_SETUP_TOKEN"] = TOKEN
    client = app.test_client()
    csrf = get_token(client, "/setup")
    response = post(client, "/setup", dict(csrf_token=csrf, setup_token=TOKEN,
        username="First.Admin", password="Strong-Setup-Pass-2026!", confirm_password="Strong-Setup-Pass-2026!"))
    assert response.status_code == 302 and response.headers["Location"].endswith("/login")
    with app.app_context():
        user = db.session.query(User).one()
        assert user.username == "first.admin"
        assert user.password_hash.startswith("scrypt:")
        assert check_password_hash(user.password_hash, "Strong-Setup-Pass-2026!")
        assert db.session.query(BootstrapClaim).count() == 1
    assert client.get("/setup", base_url="https://localhost").status_code == 404
    assert post(client, "/setup", dict(csrf_token=csrf, setup_token=TOKEN,
        username="second-admin", password="Strong-Setup-Pass-2026!", confirm_password="Strong-Setup-Pass-2026!")).status_code == 404


def test_setup_requires_csrf_and_correct_secret(app):
    app.config["SEGCHECK_SETUP_TOKEN"] = TOKEN
    client = app.test_client()
    assert post(client, "/setup", {}).status_code == 400
    csrf = get_token(client, "/setup")
    response = post(client, "/setup", dict(csrf_token=csrf, setup_token="wrong-token",
        username="first-admin", password="Strong-Setup-Pass-2026!", confirm_password="Strong-Setup-Pass-2026!"))
    assert response.status_code == 404
    with app.app_context():
        assert db.session.query(User).count() == 0
        assert db.session.query(BootstrapClaim).count() == 0


def test_setup_does_not_accept_duplicate_or_mismatched_passwords(app):
    app.config["SEGCHECK_SETUP_TOKEN"] = TOKEN
    client = app.test_client()
    csrf = get_token(client, "/setup")
    values = MultiDict([("csrf_token", csrf), ("setup_token", TOKEN), ("username", "first-admin"),
                       ("password", "Strong-Setup-Pass-2026!"), ("password", "other"),
                       ("confirm_password", "Strong-Setup-Pass-2026!")])
    response = post(client, "/setup", values)
    assert response.status_code == 200
    with app.app_context():
        assert db.session.query(User).count() == 0


def test_provisioning_claim_remains_closed_if_users_are_removed(app):
    app.config["SEGCHECK_SETUP_TOKEN"] = TOKEN
    with app.app_context():
        db.session.add(BootstrapClaim(id=1))
        db.session.commit()
    assert app.test_client().get("/setup", base_url="https://localhost").status_code == 404


def test_concurrent_initial_setup_creates_only_one_administrator(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from segcheck_web import create_app
    application = create_app({"TESTING": True, "SECRET_KEY": "concurrent-setup-test-secret",
                              "SEGCHECK_SETUP_TOKEN": TOKEN,
                              "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'setup.sqlite3'}"})
    with application.app_context():
        db.create_all()
    clients = [application.test_client(), application.test_client()]
    tokens = [get_token(client, "/setup") for client in clients]

    def attempt(index):
        return post(clients[index], "/setup", dict(csrf_token=tokens[index], setup_token=TOKEN,
            username=f"initial-admin-{index}", password="Strong-Setup-Pass-2026!",
            confirm_password="Strong-Setup-Pass-2026!")).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, range(2)))
    assert outcomes.count(302) == 1
    assert all(code in {302, 404, 409} for code in outcomes)
    with application.app_context():
        assert db.session.query(User).count() == 1
        assert db.session.query(BootstrapClaim).count() == 1
        db.session.remove()
        db.drop_all()
