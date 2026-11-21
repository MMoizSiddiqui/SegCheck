"""Tests for controlled policy lifecycle transitions and audit events."""

from pathlib import Path

import pytest
from sqlalchemy import event

from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import Policy, PolicyLifecycleEvent
from segcheck_web.services.policy_import import import_policy_file
from segcheck_web.services.policy_lifecycle import (
    PolicyLifecycleArchivedError,
    PolicyLifecycleError,
    PolicyLifecycleNotFoundError,
    PolicyLifecycleTransitionError,
    transition_policy_status,
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
def app_context(app):
    with app.app_context():
        yield


@pytest.fixture
def imported_policy(app_context):
    return import_policy_file(LAB_POLICY)


@pytest.mark.parametrize(
    ("initial", "target"),
    [
        ("draft", "active"),
        ("draft", "archived"),
        ("active", "draft"),
        ("active", "archived"),
    ],
)
def test_allowed_transition_creates_audit_event(
    imported_policy, initial, target
):
    imported_policy.status = initial
    db.session.commit()

    audit = transition_policy_status(
        imported_policy.id,
        target,
        "Approved lifecycle change for testing",
        actor_identifier="test-operator",
    )

    db.session.expire_all()

    policy = db.session.get(Policy, imported_policy.id)
    events = db.session.query(PolicyLifecycleEvent).all()

    assert policy.status == target
    assert len(events) == 1
    assert audit.id == events[0].id
    assert audit.policy_id == policy.id
    assert audit.from_status == initial
    assert audit.to_status == target
    assert audit.reason == "Approved lifecycle change for testing"
    assert audit.actor_identifier == "test-operator"
    assert audit.created_at is not None


def test_reason_is_trimmed_and_actor_can_be_absent(imported_policy):
    audit = transition_policy_status(
        imported_policy.id,
        "active",
        "  Approved for operational use  ",
    )

    assert audit.reason == "Approved for operational use"
    assert audit.actor_identifier is None


def test_archived_policy_is_terminal(imported_policy):
    imported_policy.status = "archived"
    db.session.commit()

    with pytest.raises(PolicyLifecycleArchivedError):
        transition_policy_status(
            imported_policy.id,
            "draft",
            "Attempt to reopen",
        )

    db.session.expire_all()
    assert db.session.get(Policy, imported_policy.id).status == "archived"
    assert db.session.query(PolicyLifecycleEvent).count() == 0


def test_same_status_transition_is_rejected(imported_policy):
    with pytest.raises(PolicyLifecycleTransitionError, match="already"):
        transition_policy_status(
            imported_policy.id,
            "draft",
            "No actual status change",
        )

    assert db.session.query(PolicyLifecycleEvent).count() == 0


def test_invalid_transition_is_rejected(imported_policy):
    with pytest.raises(PolicyLifecycleTransitionError):
        transition_policy_status(
            imported_policy.id,
            "invalid",
            "Invalid transition",
        )

    assert imported_policy.status == "draft"
    assert db.session.query(PolicyLifecycleEvent).count() == 0


def test_unknown_policy_is_rejected(app_context):
    with pytest.raises(PolicyLifecycleNotFoundError):
        transition_policy_status(
            99999,
            "active",
            "Policy does not exist",
        )

    assert db.session.query(PolicyLifecycleEvent).count() == 0


@pytest.mark.parametrize(
    ("reason", "message"),
    [
        ("", "blank"),
        ("   ", "blank"),
        (None, "reason"),
        ("x" * 501, "500"),
    ],
)
def test_invalid_reason_is_rejected(imported_policy, reason, message):
    with pytest.raises(PolicyLifecycleError, match=message):
        transition_policy_status(
            imported_policy.id,
            "active",
            reason,
        )

    assert imported_policy.status == "draft"
    assert db.session.query(PolicyLifecycleEvent).count() == 0


@pytest.mark.parametrize(
    ("actor", "message"),
    [
        ("", "blank"),
        ("   ", "blank"),
        ("x" * 129, "128"),
        (123, "text"),
    ],
)
def test_invalid_actor_identifier_is_rejected(
    imported_policy, actor, message
):
    with pytest.raises(PolicyLifecycleError, match=message):
        transition_policy_status(
            imported_policy.id,
            "active",
            "Approved transition",
            actor_identifier=actor,
        )

    assert imported_policy.status == "draft"
    assert db.session.query(PolicyLifecycleEvent).count() == 0


def test_failed_audit_insert_rolls_back_status_change(imported_policy):
    def reject_audit_insert(_mapper, _connection, _target):
        raise RuntimeError("Simulated audit insert failure")

    event.listen(
        PolicyLifecycleEvent,
        "before_insert",
        reject_audit_insert,
    )

    try:
        with pytest.raises(RuntimeError, match="audit insert failure"):
            transition_policy_status(
                imported_policy.id,
                "active",
                "This transition must roll back",
            )
    finally:
        event.remove(
            PolicyLifecycleEvent,
            "before_insert",
            reject_audit_insert,
        )

    db.session.expire_all()

    policy = db.session.get(Policy, imported_policy.id)

    assert policy.status == "draft"
    assert db.session.query(PolicyLifecycleEvent).count() == 0


def test_lifecycle_audit_event_cannot_be_updated_or_deleted(imported_policy):
    audit = transition_policy_status(
        imported_policy.id,
        "active",
        "Approved transition",
    )

    audit.reason = "Tampered reason"

    with pytest.raises(ValueError, match="cannot be modified"):
        db.session.commit()

    db.session.rollback()

    audit = db.session.get(PolicyLifecycleEvent, audit.id)
    db.session.delete(audit)

    with pytest.raises(ValueError, match="cannot be deleted"):
        db.session.commit()

    db.session.rollback()

    assert db.session.query(PolicyLifecycleEvent).count() == 1
