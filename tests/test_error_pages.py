"""Every error a person can hit explains itself: what happened and what to do."""
from flask import abort

from test_environment_workflow import app  # noqa: F401

BASE = "https://localhost"


def test_unknown_page_explains_itself(app, authenticated_client):
    response = authenticated_client.get("/no-such-page", base_url=BASE)
    assert response.status_code == 404
    assert b"Not found" in response.data and b"What to do" in response.data
    assert b"Traceback" not in response.data and response.headers["Cache-Control"] == "no-store"


def test_api_errors_are_json_with_guidance(app, authenticated_client):
    response = authenticated_client.get("/api/does-not-exist", base_url=BASE)
    assert response.status_code == 404 and response.is_json
    body = response.get_json()
    assert body["title"] == "Not found" and body["what_to_do"]


def test_expired_form_is_explained_not_a_bare_400(app, authenticated_client):
    response = authenticated_client.post("/audit/here", base_url=BASE, data={"name": "x"},
                                         headers={"Referer": BASE + "/audit/"})
    assert response.status_code == 400
    assert b"This form expired" in response.data and b"Reload the page" in response.data


def fresh_app(**config):
    from segcheck_web import create_app
    from segcheck_web.extensions import db
    application = create_app({"TESTING": True, "SECRET_KEY": "error-page-test-secret", "SQLALCHEMY_DATABASE_URI": "sqlite://", **config})
    with application.app_context():
        db.create_all()
    return application


def test_abort_detail_is_shown_with_the_explanation():
    application = fresh_app()

    @application.get("/test-conflict")
    def conflict():
        abort(409, description="Stored policy or environment could not be validated")
    response = application.test_client().get("/test-conflict", base_url=BASE)
    assert response.status_code == 409
    assert b"Cannot do that right now" in response.data and b"could not be validated" in response.data


def test_unexpected_crash_shows_reference_and_logs_it(tmp_path):
    application = fresh_app(SEGCHECK_PROPAGATE_ERRORS=False, SEGCHECK_DATA_DIR=str(tmp_path))

    @application.get("/test-crash")
    def crash():
        raise RuntimeError("boom secret detail")
    response = application.test_client().get("/test-crash", base_url=BASE)
    assert response.status_code == 500
    assert b"Something went wrong inside SegCheck" in response.data and b"Reference:" in response.data
    assert b"boom secret detail" not in response.data and b"Traceback" not in response.data
    log = (tmp_path / "logs" / "errors.log").read_text(encoding="utf-8")
    assert "boom secret detail" in log and "incident" in log
