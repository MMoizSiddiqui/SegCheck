"""Integration tests for historical policy immutability migrations."""

import json
from pathlib import Path

import pytest
from flask_migrate import upgrade
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import (
    Assessment,
    Policy,
    PolicyCheck,
    PolicyLifecycleEvent,
    PolicyVersion,
    PolicyVersionZone,
    User,
)


MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "segcheck_web" / "migrations"

EXPECTED_TRIGGERS = {
    "trg_policy_versions_immutable_update",
    "trg_policy_versions_immutable_delete",
    "trg_policy_version_zones_immutable_update",
    "trg_policy_version_zones_immutable_delete",
    "trg_policy_checks_immutable_update",
    "trg_policy_checks_immutable_delete",
    "trg_policy_lifecycle_events_immutable_update",
    "trg_policy_lifecycle_events_immutable_delete",
    "trg_assessments_immutable_update",
    "trg_assessments_immutable_delete",
}


@pytest.fixture
def migrated_database(tmp_path):
    database_path = tmp_path / "migration-test.sqlite3"

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "migration-test-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        engine = db.engine

        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        event.listen(engine, "connect", enable_foreign_keys)

        try:
            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision="head",
            )

            yield db.session
        finally:
            db.session.remove()
            event.remove(engine, "connect", enable_foreign_keys)


def test_framework_mapping_migration_preserves_existing_policy_checks(
    tmp_path,
):
    """Existing checks survive upgrade and receive an empty mapping list."""
    database_path = tmp_path / "legacy-policy-checks.sqlite3"

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "migration-test-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        engine = db.engine

        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        event.listen(engine, "connect", enable_foreign_keys)

        try:
            # Build the database exactly as an installation on the
            # previous migration revision would look.
            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision="de8bd543aabc",
            )

            # Insert legacy records using the old schema, before the
            # framework_mappings column exists.
            with engine.begin() as connection:
                connection.execute(text("""
                    INSERT INTO policies (
                        id, policy_key, name, description, status,
                        pci_dss_version, tags, created_at, updated_at
                    )
                    VALUES (
                        1, 'LEGACY-001', 'Legacy Policy',
                        'Pre-framework migration policy', 'draft',
                        '4.0.1', '[]',
                        '2026-11-01 10:00:00',
                        '2026-11-01 10:00:00'
                    )
                """))

                connection.execute(text("""
                    INSERT INTO policy_versions (
                        id, policy_id, version_number, schema_version,
                        snapshot, snapshot_sha256, created_at
                    )
                    VALUES (
                        1, 1, 1, 1, '{"schema_version": 1}',
                        :digest, '2026-11-01 10:00:00'
                    )
                """), {"digest": "a" * 64})

                connection.execute(text("""
                    INSERT INTO policy_version_zones (
                        id, policy_version_id, zone_key, name, description
                    )
                    VALUES
                        (1, 1, 'guest', 'Guest', ''),
                        (2, 1, 'cde', 'CDE', '')
                """))

                connection.execute(text("""
                    INSERT INTO policy_checks (
                        id, policy_version_id, check_key, name,
                        source_zone_key, destination_zone_key,
                        destination_host, protocol, ports, expected,
                        rationale, pci_requirements
                    )
                    VALUES (
                        1, 1, 'LEGACY-CHECK-001', 'Legacy Guest to CDE',
                        'guest', 'cde', '10.30.0.10', 'tcp', '[443]',
                        'deny', 'Legacy segmentation protection.',
                        '["11.4.5"]'
                    )
                """))

            # Apply the new migration to the populated database.
            upgrade(
                directory=str(MIGRATIONS_DIR),
                revision="head",
            )

            with engine.connect() as connection:
                check = connection.execute(text("""
                    SELECT
                        id,
                        check_key,
                        name,
                        framework_mappings,
                        pci_requirements
                    FROM policy_checks
                    WHERE id = 1
                """)).mappings().one()

                assert check["check_key"] == "LEGACY-CHECK-001"
                assert check["name"] == "Legacy Guest to CDE"
                assert json.loads(check["framework_mappings"]) == []
                assert json.loads(check["pci_requirements"]) == [
                    "11.4.5"
                ]

                assert connection.execute(text(
                    "SELECT COUNT(*) FROM policies"
                )).scalar_one() == 1

                assert connection.execute(text(
                    "SELECT COUNT(*) FROM policy_versions"
                )).scalar_one() == 1

                assert connection.execute(text(
                    "SELECT COUNT(*) FROM policy_version_zones"
                )).scalar_one() == 2

                column = connection.execute(text("""
                    PRAGMA table_info('policy_checks')
                """)).mappings()

                mapping_column = next(
                    item for item in column
                    if item["name"] == "framework_mappings"
                )

                assert mapping_column["notnull"] == 1
                assert mapping_column["dflt_value"] is None

                triggers = set(connection.execute(text("""
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'trigger'
                """)).scalars())

                assert (
                    "trg_policy_checks_immutable_update" in triggers
                )
                assert (
                    "trg_policy_checks_immutable_delete" in triggers
                )

            # Verify the migrated historical check is still immutable.
            with pytest.raises(DBAPIError):
                with engine.begin() as connection:
                    connection.execute(text("""
                        UPDATE policy_checks
                        SET name = 'TAMPERED'
                        WHERE id = 1
                    """))

        finally:
            db.session.remove()
            event.remove(engine, "connect", enable_foreign_keys)


def create_history(session, policy_key="MIGRATION-TEST"):
    policy = Policy(
        policy_key=policy_key,
        name="Migration Test Policy",
        description="Temporary migration integration test",
        status="draft",
        pci_dss_version="4.0.1",
    )
    session.add(policy)
    session.flush()

    version = PolicyVersion(
        policy_id=policy.id,
        version_number=1,
        schema_version=1,
        snapshot={"schema_version": 1},
        snapshot_sha256="a" * 64,
    )
    session.add(version)
    session.flush()

    guest = PolicyVersionZone(
        policy_version_id=version.id,
        zone_key="guest",
        name="Guest",
    )
    cde = PolicyVersionZone(
        policy_version_id=version.id,
        zone_key="cde",
        name="CDE",
    )
    session.add_all([guest, cde])
    session.flush()

    check = PolicyCheck(
        policy_version_id=version.id,
        check_key="CHECK-001",
        name="Guest to CDE",
        source_zone_key="guest",
        destination_zone_key="cde",
        destination_host="10.30.0.10",
        protocol="tcp",
        ports=[443],
        expected="deny",
        rationale="Guest access to CDE must be denied.",
        pci_requirements=["11.4.5"],
    )
    session.add(check)
    session.commit()

    return {
        "version_id": version.id,
        "zone_id": guest.id,
        "check_id": check.id,
        "policy_id": policy.id,
    }


def test_migration_installs_all_ten_immutability_triggers(
    migrated_database,
):
    triggers = set(
        db.session.execute(text("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'trigger'
        """)).scalars()
    )

    assert triggers == EXPECTED_TRIGGERS


@pytest.mark.parametrize(
    ("table", "operation", "statement", "record_key"),
    [
        (
            "policy_versions",
            "UPDATE",
            "UPDATE policy_versions "
            "SET snapshot_sha256 = :value WHERE id = :id",
            "version_id",
        ),
        (
            "policy_versions",
            "DELETE",
            "DELETE FROM policy_versions WHERE id = :id",
            "version_id",
        ),
        (
            "policy_version_zones",
            "UPDATE",
            "UPDATE policy_version_zones "
            "SET name = :value WHERE id = :id",
            "zone_id",
        ),
        (
            "policy_version_zones",
            "DELETE",
            "DELETE FROM policy_version_zones WHERE id = :id",
            "zone_id",
        ),
        (
            "policy_checks",
            "UPDATE",
            "UPDATE policy_checks "
            "SET name = :value WHERE id = :id",
            "check_id",
        ),
        (
            "policy_checks",
            "DELETE",
            "DELETE FROM policy_checks WHERE id = :id",
            "check_id",
        ),
    ],
)
def test_database_triggers_reject_direct_sql_mutation(
    migrated_database,
    table,
    operation,
    statement,
    record_key,
):
    identifiers = create_history(migrated_database)

    with pytest.raises(DBAPIError):
        with db.engine.begin() as connection:
            connection.execute(
                text(statement),
                {
                    "id": identifiers[record_key],
                    "value": "TAMPERED",
                },
            )


def create_lifecycle_event(session, policy_id):
    audit = PolicyLifecycleEvent(
        policy_id=policy_id,
        from_status="draft",
        to_status="active",
        reason="Approved for operational use",
        actor_identifier="migration-test",
    )
    session.add(audit)
    session.commit()
    return audit.id


@pytest.mark.parametrize(
    ("operation", "statement"),
    [
        (
            "UPDATE",
            "UPDATE policy_lifecycle_events "
            "SET reason = :value WHERE id = :id",
        ),
        (
            "DELETE",
            "DELETE FROM policy_lifecycle_events WHERE id = :id",
        ),
    ],
)
def test_database_triggers_reject_direct_lifecycle_audit_mutation(
    migrated_database,
    operation,
    statement,
):
    identifiers = create_history(migrated_database)
    audit_id = create_lifecycle_event(
        migrated_database,
        identifiers["policy_id"],
    )

    with pytest.raises(DBAPIError):
        with db.engine.begin() as connection:
            connection.execute(
                text(statement),
                {
                    "id": audit_id,
                    "value": "TAMPERED",
                },
            )

    audit = migrated_database.get(PolicyLifecycleEvent, audit_id)

    assert audit is not None
    assert audit.reason == "Approved for operational use"
    assert audit.from_status == "draft"
    assert audit.to_status == "active"


def test_database_allows_inserting_lifecycle_audit_events(
    migrated_database,
):
    identifiers = create_history(migrated_database)

    audit_id = create_lifecycle_event(
        migrated_database,
        identifiers["policy_id"],
    )

    audit = migrated_database.get(PolicyLifecycleEvent, audit_id)

    assert audit is not None
    assert audit.policy_id == identifiers["policy_id"]
    assert audit.reason == "Approved for operational use"


def test_migration_allows_inserting_a_new_policy_version(
    migrated_database,
):
    identifiers = create_history(migrated_database)

    second_version = PolicyVersion(
        policy_id=identifiers["policy_id"],
        version_number=2,
        schema_version=1,
        snapshot={"schema_version": 1, "revision": 2},
        snapshot_sha256="b" * 64,
    )
    migrated_database.add(second_version)
    migrated_database.flush()

    guest = PolicyVersionZone(
        policy_version_id=second_version.id,
        zone_key="guest",
        name="Guest",
    )
    cde = PolicyVersionZone(
        policy_version_id=second_version.id,
        zone_key="cde",
        name="CDE",
    )
    migrated_database.add_all([guest, cde])
    migrated_database.flush()

    migrated_database.add(PolicyCheck(
        policy_version_id=second_version.id,
        check_key="CHECK-002",
        name="Guest to CDE v2",
        source_zone_key="guest",
        destination_zone_key="cde",
        destination_host="10.30.0.10",
        protocol="tcp",
        ports=[443],
        expected="deny",
        rationale="New policy version.",
        pci_requirements=["11.4.5"],
    ))
    migrated_database.commit()

    assert migrated_database.query(PolicyVersion).count() == 2
    assert migrated_database.query(PolicyVersionZone).count() == 4
    assert migrated_database.query(PolicyCheck).count() == 2



def create_assessment_record(session, history, run_id="PROBE-MIGRATION-001"):
    user = User(
        username="migration-admin",
        password_hash="test-password-hash",
        is_active=True,
    )
    session.add(user)
    session.flush()

    assessment = Assessment(
        policy_id=history["policy_id"],
        policy_version_id=history["version_id"],
        actor_user_id=user.id,
        policy_version_sha256="a" * 64,
        source_zone="guest",
        probe_run_id=run_id,
        summary={"pass": 1, "fail": 0, "inconclusive": 0},
        report={
            "report_version": 1,
            "probe_run_id": run_id,
            "summary": {"pass": 1, "fail": 0, "inconclusive": 0},
        },
    )
    session.add(assessment)
    session.commit()
    return assessment, user


def test_assessment_can_be_created_with_matching_historical_references(
    migrated_database,
):
    history = create_history(migrated_database)
    assessment, user = create_assessment_record(
        migrated_database,
        history,
    )

    assert assessment.id is not None
    assert assessment.policy_id == history["policy_id"]
    assert assessment.policy_version_id == history["version_id"]
    assert assessment.actor_user_id == user.id
    assert assessment.policy.id == history["policy_id"]
    assert assessment.policy_version.id == history["version_id"]
    assert assessment.actor.id == user.id


def test_assessment_rejects_policy_and_version_ownership_mismatch(
    migrated_database,
):
    first = create_history(
        migrated_database,
        policy_key="MIGRATION-TEST-ONE",
    )
    second = create_history(
        migrated_database,
        policy_key="MIGRATION-TEST-TWO",
    )

    user = User(
        username="mismatch-admin",
        password_hash="test-password-hash",
        is_active=True,
    )
    migrated_database.add(user)
    migrated_database.flush()

    assessment = Assessment(
        policy_id=second["policy_id"],
        policy_version_id=first["version_id"],
        actor_user_id=user.id,
        policy_version_sha256="a" * 64,
        source_zone="guest",
        probe_run_id="PROBE-MISMATCH-001",
        summary={},
        report={},
    )
    migrated_database.add(assessment)

    with pytest.raises(DBAPIError):
        migrated_database.commit()

    migrated_database.rollback()


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_assessment_is_immutable_through_orm(
    migrated_database,
    operation,
):
    history = create_history(migrated_database)
    assessment, _user = create_assessment_record(
        migrated_database,
        history,
        run_id=f"PROBE-ORM-{operation.upper()}",
    )

    if operation == "update":
        assessment.source_zone = "tampered"
        expected_message = "Historical policy records cannot be modified"
    else:
        migrated_database.delete(assessment)
        expected_message = "Historical policy records cannot be deleted"

    with pytest.raises(ValueError, match=expected_message):
        migrated_database.commit()

    migrated_database.rollback()


@pytest.mark.parametrize(
    ("operation", "statement"),
    [
        (
            "update",
            "UPDATE assessments SET source_zone = 'tampered' WHERE id = :id",
        ),
        (
            "delete",
            "DELETE FROM assessments WHERE id = :id",
        ),
    ],
)
def test_assessment_database_triggers_reject_direct_sql_mutation(
    migrated_database,
    operation,
    statement,
):
    history = create_history(migrated_database)
    assessment, _user = create_assessment_record(
        migrated_database,
        history,
        run_id=f"PROBE-SQL-{operation.upper()}",
    )

    with pytest.raises(DBAPIError):
        migrated_database.execute(
            text(statement),
            {"id": assessment.id},
        )
        migrated_database.commit()

    migrated_database.rollback()


def test_assessment_actor_foreign_key_prevents_user_deletion(
    migrated_database,
):
    history = create_history(migrated_database)
    assessment, user = create_assessment_record(
        migrated_database,
        history,
        run_id="PROBE-ACTOR-FK-001",
    )

    with pytest.raises(DBAPIError):
        migrated_database.execute(
            text("DELETE FROM users WHERE id = :id"),
            {"id": user.id},
        )
        migrated_database.commit()

    migrated_database.rollback()

    persisted = migrated_database.get(Assessment, assessment.id)
    assert persisted is not None
    assert persisted.actor_user_id == user.id
