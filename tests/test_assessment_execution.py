"""Focused tests for bounded web assessment execution and persistence."""

from pathlib import Path

import pytest
import yaml
from sqlalchemy import event

from segcheck.probe import ProbeOutcome
from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import Assessment, Policy, PolicyVersion, User
from segcheck_web.services.assessment_execution import (
    AssessmentExecutionError,
    execute_assessment,
)
from segcheck_web.services.policy_import import (
    import_policy_content,
    import_policy_file,
)

LAB_POLICY = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
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

        yield application

        db.session.remove()
        db.drop_all()
        event.remove(engine, "connect", enable_foreign_keys)


@pytest.fixture
def assessment_setup(app):
    with app.app_context():
        policy = import_policy_file(LAB_POLICY)
        policy.status = "active"
        db.session.commit()

        version = db.session.query(PolicyVersion).filter_by(
            policy_id=policy.id
        ).one()

        actor = User(
            username="assessment-admin",
            password_hash="x" * 64,
            is_active=True,
        )
        db.session.add(actor)
        db.session.commit()

        yield {
            "policy_id": policy.id,
            "version_id": version.id,
            "actor_id": actor.id,
        }


def _inconclusive_probe(_host, _port, _timeout):
    return ProbeOutcome(
        state="inconclusive",
        reason="controlled_test_probe",
        duration_ms=0.1,
        source_ip="192.0.2.10",
    )


def _execute(setup, **overrides):
    arguments = {
        "policy_id": setup["policy_id"],
        "policy_version_id": setup["version_id"],
        "source_zone": "guest",
        "actor_user_id": setup["actor_id"],
        "probe_func": _inconclusive_probe,
    }
    arguments.update(overrides)
    return execute_assessment(**arguments)


def test_executes_and_persists_source_zone_assessment(app, assessment_setup):
    with app.app_context():
        record = _execute(assessment_setup)

        assert record.id is not None
        assert record.policy_id == assessment_setup["policy_id"]
        assert record.policy_version_id == assessment_setup["version_id"]
        assert record.actor_user_id == assessment_setup["actor_id"]
        assert record.source_zone == "guest"

        scope = record.report["assessment"]["scope"]
        assert scope["scope_type"] == "source_zone_only"
        assert scope["evaluated_check_ids"] == ["SEG-001"]
        assert scope["not_evaluated_check_ids"] == [
            "SEG-002", "SEG-003", "SEG-004", "SEG-005"
        ]

        assert record.report["assessment"]["evidence_status"] == "not_configured"
        assert record.report["assessment"]["evidence_informs_compliance_decision"] is False

        measurement = record.report["probe_measurement"]
        assert measurement["measurement_version"] == 1
        assert measurement["run_id"] == record.probe_run_id
        assert measurement["source_ip_semantics"].startswith(
            "The source IP is selected by local OS route lookup"
        )
        assert len(measurement["details"]) == 1
        detail = measurement["details"][0]
        assert detail["check_id"] == "SEG-001"
        assert detail["port"] == 443
        assert detail["observed"] == "inconclusive"
        assert detail["reason"] == "controlled_test_probe"
        assert record.report["assessment"]["assessment_version"] == 2
        assert db.session.query(Assessment).count() == 1



def test_rejects_non_active_policy_before_probing(app, assessment_setup):
    with app.app_context():
        policy = db.session.get(Policy, assessment_setup["policy_id"])
        policy.status = "archived"
        db.session.commit()

        probe_calls = []

        def probe(*args):
            probe_calls.append(args)
            return _inconclusive_probe(*args)

        with pytest.raises(AssessmentExecutionError, match="active policies"):
            _execute(assessment_setup, probe_func=probe)

        assert probe_calls == []
        assert db.session.query(Assessment).count() == 0


def test_rejects_snapshot_digest_mismatch_before_probing(
    app, assessment_setup, monkeypatch
):
    import segcheck_web.services.assessment_execution as execution

    monkeypatch.setattr(
        execution,
        "_canonical_snapshot_digest",
        lambda _snapshot: "0" * 64,
    )
    probe_calls = []

    def probe(*args):
        probe_calls.append(args)
        return _inconclusive_probe(*args)

    with app.app_context():
        with pytest.raises(AssessmentExecutionError, match="integrity"):
            _execute(assessment_setup, probe_func=probe)

        assert probe_calls == []
        assert db.session.query(Assessment).count() == 0


def test_rejects_policy_version_owned_by_another_policy(app, assessment_setup):
    with app.app_context():
        data = yaml.safe_load(LAB_POLICY.read_text(encoding="utf-8"))
        data["policy_id"] = "SEGCHECK-POLICY-SECOND"
        data["name"] = "Second test policy"

        second_policy = import_policy_content(
            yaml.safe_dump(data, sort_keys=False).encode("utf-8")
        )
        second_version = db.session.query(PolicyVersion).filter_by(
            policy_id=second_policy.id
        ).one()

        with pytest.raises(AssessmentExecutionError, match="not found"):
            _execute(assessment_setup, policy_version_id=second_version.id)

        assert db.session.query(Assessment).count() == 0


def test_rejects_inactive_actor_before_probing(app, assessment_setup):
    with app.app_context():
        actor = db.session.get(User, assessment_setup["actor_id"])
        actor.is_active = False
        db.session.commit()

        probe_calls = []

        def probe(*args):
            probe_calls.append(args)
            return _inconclusive_probe(*args)

        with pytest.raises(AssessmentExecutionError, match="unavailable"):
            _execute(assessment_setup, probe_func=probe)

        assert probe_calls == []
        assert db.session.query(Assessment).count() == 0


def test_probe_failure_does_not_persist_assessment(app, assessment_setup):
    def failing_probe(_host, _port, _timeout):
        raise OSError("simulated connection failure")

    with app.app_context():
        with pytest.raises(
            AssessmentExecutionError,
            match="could not be completed",
        ):
            _execute(assessment_setup, probe_func=failing_probe)

        assert db.session.query(Assessment).count() == 0


def test_partial_firewall_configuration_fails_closed(app, assessment_setup):
    with app.app_context():
        app.config["SEGCHECK_EVIDENCE_CONFIG_PATH"] = "/trusted/evidence.yaml"
        app.config["SEGCHECK_EVIDENCE_EVENTS_PATH"] = None

        with pytest.raises(
            AssessmentExecutionError,
            match="partially configured",
        ):
            _execute(assessment_setup)

        assert db.session.query(Assessment).count() == 0

def test_rejects_probe_measurement_with_missing_policy_port(
    app, assessment_setup, monkeypatch
):
    import segcheck_web.services.assessment_execution as execution

    original = execution.probe_policy

    def incomplete_probe(*args, **kwargs):
        result = original(*args, **kwargs)
        result["measurement"]["details"].pop()
        return result

    monkeypatch.setattr(execution, "probe_policy", incomplete_probe)

    with app.app_context():
        with pytest.raises(AssessmentExecutionError, match="complete selected policy scope"):
            _execute(assessment_setup)
        assert db.session.query(Assessment).count() == 0


def test_rejects_probe_observation_that_conflicts_with_port_measurement(
    app, assessment_setup, monkeypatch
):
    import segcheck_web.services.assessment_execution as execution

    original = execution.probe_policy

    def inconsistent_probe(*args, **kwargs):
        result = original(*args, **kwargs)
        result["observations"]["SEG-001"] = "reachable"
        return result

    monkeypatch.setattr(execution, "probe_policy", inconsistent_probe)

    with app.app_context():
        with pytest.raises(AssessmentExecutionError, match="conflicts with its port measurements"):
            _execute(assessment_setup)
        assert db.session.query(Assessment).count() == 0


def test_rejects_invalid_probe_source_ip_before_persistence(
    app, assessment_setup, monkeypatch
):
    import segcheck_web.services.assessment_execution as execution

    original = execution.probe_policy

    def invalid_source_probe(*args, **kwargs):
        result = original(*args, **kwargs)
        result["measurement"]["details"][0]["source_ip"] = "not-an-ip"
        return result

    monkeypatch.setattr(execution, "probe_policy", invalid_source_probe)

    with app.app_context():
        with pytest.raises(AssessmentExecutionError, match="invalid source IP"):
            _execute(assessment_setup)
        assert db.session.query(Assessment).count() == 0

