"""Focused security and workflow tests for assessment routes."""

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import event
from werkzeug.datastructures import MultiDict

from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import Assessment, Policy, PolicyVersion, User
from segcheck_web.services.policy_import import import_policy_file


LAB_POLICY = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures"
    / "lab-policy.yaml"
)


@pytest.fixture
def app():
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })

    with application.app_context():
        engine = db.engine

        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        event.listen(engine, "connect", enable_foreign_keys)
        db.create_all()

    try:
        yield application
    finally:
        with application.app_context():
            db.session.remove()
            db.drop_all()

        event.remove(engine, "connect", enable_foreign_keys)


@pytest.fixture
def active_policy(app):
    with app.app_context():
        policy = import_policy_file(LAB_POLICY)
        policy.status = "active"
        db.session.commit()
        version = policy.versions[0]
        return {
            "policy_id": policy.id,
            "version_id": version.id,
        }


def workspace_csrf(client):
    response = client.get(
        "/assessments/",
        base_url="https://localhost",
    )
    assert response.status_code == 200

    match = re.search(
        rb'name="csrf_token"\s+value="([^"]+)"',
        response.data,
    )
    assert match is not None
    return match.group(1).decode("ascii")


def post_run(client, setup, token, **overrides):
    data = {
        "csrf_token": token,
        "policy_version_id": str(setup["version_id"]),
        "source_zone": "guest",
        "authorized": "yes",
    }
    data.update(overrides)

    return client.post(
        "/assessments/run",
        base_url="https://localhost",
        headers={"Referer": "https://localhost/assessments/"},
        data=data,
    )


def test_assessment_workspace_requires_authentication(app):
    response = app.test_client().get(
        "/assessments/",
        base_url="https://localhost",
    )

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]















def test_saved_assessment_detail_displays_persisted_report(
    app, active_policy, authenticated_client
):
    with app.app_context():
        version = db.session.get(
            PolicyVersion, active_policy["version_id"]
        )
        actor = db.session.query(User).filter_by(is_active=True).first()
        assert version is not None
        assert actor is not None

        record = Assessment(
            policy_id=active_policy["policy_id"],
            policy_version_id=version.id,
            actor_user_id=actor.id,
            policy_version_sha256=version.snapshot_sha256,
            source_zone="guest",
            probe_run_id="PROBE-DETAIL-TEST",
            summary={
                "total": 1,
                "pass": 1,
                "fail": 0,
                "inconclusive": 0,
            },
            report={
                "summary": {
                    "total": 1,
                    "pass": 1,
                    "fail": 0,
                    "inconclusive": 0,
                },
                "assessment": {
                    "assessment_version": 1,
                    "probe_run_id": "PROBE-DETAIL-TEST",
                    "source_zone": "guest",
                    "scope": "source_zone_only",
                    "evidence_status": "not_configured",
                    "evidence_summary": {
                        "status": "not_configured",
                        "total": 1,
                        "not_evaluated": 1,
                    },
                    "decision_method": "Probe observations determine results.",
                },
                "decision_boundary": (
                    "This assessment is not a full PCI DSS certification."
                ),
                "results": [
                    {
                        "check_id": "CHECK-DETAIL",
                        "check_name": "Saved detail test",
                        "source_zone": "guest",
                        "destination_zone": "cde",
                        "destination_host": "192.0.2.20",
                        "protocol": "tcp",
                        "ports": [443],
                        "expected": "allow",
                        "observed": "reachable",
                        "result": "PASS",
                        "explanation": "The saved probe observation matched.",
                        "rationale": "Test rationale.",
                        "pci_requirements": [],
                        "framework_mappings": {},
                        "firewall_evidence": [
                            {
                                "port": 443,
                                "status": "not_evaluated",
                                "reason": "firewall_integration_not_configured",
                                "matched_event_count": 0,
                                "event_ids": [],
                            }
                        ],
                    }
                ],
            },
        )
        db.session.add(record)
        db.session.commit()
        assessment_id = record.id

    response = authenticated_client.get(
        f"/assessments/{assessment_id}",
        base_url="https://localhost",
    )

    assert response.status_code == 200
    assert b"PROBE-DETAIL-TEST" in response.data
    assert b"CHECK-DETAIL" in response.data
    assert b"Saved detail test" in response.data
    assert b"Not configured" not in response.data, "the unused pfSense-file evidence panel stays hidden"
    assert b"Rule by rule" in response.data and b"Results cover" in response.data


def test_assessment_detail_returns_404_for_nonexistent_record(
    app, authenticated_client
):
    response = authenticated_client.get(
        "/assessments/999999",
        base_url="https://localhost",
    )

    assert response.status_code == 404



def _create_pdf_test_assessment(app, active_policy):
    with app.app_context():
        version = db.session.get(
            PolicyVersion, active_policy["version_id"]
        )
        actor = db.session.query(User).filter_by(is_active=True).first()
        assert version is not None
        assert actor is not None

        record = Assessment(
            policy_id=active_policy["policy_id"],
            policy_version_id=version.id,
            actor_user_id=actor.id,
            policy_version_sha256=version.snapshot_sha256,
            source_zone="guest",
            probe_run_id="PROBE-PDF-TEST",
            summary={
                "total": 1,
                "pass": 0,
                "fail": 0,
                "inconclusive": 1,
            },
            report={
                "summary": {
                    "total": 1,
                    "pass": 0,
                    "fail": 0,
                    "inconclusive": 1,
                },
                "assessment": {
                    "probe_run_id": "PROBE-PDF-TEST",
                    "source_zone": "guest",
                    "scope": "source_zone_only",
                    "evidence_status": "not_configured",
                },
                "results": [{
                    "check_id": "PDF-CHECK-001",
                    "check_name": "Persisted PDF evidence test",
                    "result": "INCONCLUSIVE",
                    "explanation": "Persisted observation; no probe rerun.",
                    "firewall_evidence": [{
                        "port": 443,
                        "status": "not_evaluated",
                        "reason": "firewall_integration_not_configured",
                        "matched_event_count": 0,
                        "event_ids": [],
                    }],
                }],
            },
        )
        db.session.add(record)
        db.session.commit()
        return record.id


def test_assessment_pdf_requires_authentication(app):
    response = app.test_client().get(
        "/assessments/999999/report.pdf",
        base_url="https://localhost",
    )

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_assessment_pdf_returns_404_for_nonexistent_record(
    app, authenticated_client
):
    response = authenticated_client.get(
        "/assessments/999999/report.pdf",
        base_url="https://localhost",
    )

    assert response.status_code == 404


def test_assessment_pdf_downloads_persisted_report_without_rerunning(
    app, active_policy, authenticated_client, monkeypatch
):
    assessment_id = _create_pdf_test_assessment(app, active_policy)

    def unexpected_execution(**_kwargs):
        raise AssertionError("PDF export must not rerun network probes")

    monkeypatch.setattr(
        "segcheck_web.services.assessment_execution.execute_assessment",
        unexpected_execution,
    )

    response = authenticated_client.get(
        f"/assessments/{assessment_id}/report.pdf",
        base_url="https://localhost",
    )

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.headers["Content-Disposition"].startswith("attachment;")
    assert f"segcheck-assessment-{assessment_id}.pdf" in (
        response.headers["Content-Disposition"]
    )
    assert response.data.startswith(b"%PDF-")
    assert len(response.data) > 500
