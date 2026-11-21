"""Database model and integrity tests."""

import pytest
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError

from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import (
    Asset,
    Policy,
    PolicyCheck,
    PolicyVersion,
    PolicyVersionZone,
    Zone,
)


@pytest.fixture
def database():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })

    with app.app_context():
        # SQLite requires this setting to enforce declared foreign keys.
        def enable_foreign_keys(connection, record):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        event.listen(db.engine, "connect", enable_foreign_keys)
        db.create_all()

        yield db.session

        db.session.remove()
        db.drop_all()
        event.remove(db.engine, "connect", enable_foreign_keys)


def create_policy_version(session, policy_key="POLICY-TEST", version_number=1):
    policy = Policy(
        policy_key=policy_key,
        name="Test Segmentation Policy",
        description="Test policy",
        status="draft",
        pci_dss_version="4.0.1",
        tags=["test"],
    )
    session.add(policy)
    session.flush()

    version = PolicyVersion(
        policy_id=policy.id,
        version_number=version_number,
        schema_version=1,
        snapshot={"schema_version": 1},
        snapshot_sha256="a" * 64,
    )
    session.add(version)
    session.flush()

    return policy, version


def add_zone(session, version, zone_key):
    zone = PolicyVersionZone(
        policy_version_id=version.id,
        zone_key=zone_key,
        name=zone_key.title(),
        description="Test zone",
    )
    session.add(zone)
    session.flush()
    return zone


def create_check(version, check_key="CHECK-001", **overrides):
    values = {
        "policy_version_id": version.id,
        "check_key": check_key,
        "name": "Guest to CDE",
        "source_zone_key": "guest",
        "destination_zone_key": "cde",
        "destination_host": "10.30.0.10",
        "protocol": "tcp",
        "ports": [443],
        "expected": "deny",
        "rationale": "Guest networks must not access the CDE.",
        "pci_requirements": ["11.4.5"],
    }
    values.update(overrides)
    return PolicyCheck(**values)


def test_policy_version_and_check_relationships(database):
    policy, version = create_policy_version(database)
    add_zone(database, version, "guest")
    add_zone(database, version, "cde")

    check = create_check(version)
    database.add(check)
    database.commit()

    assert policy.versions == [version]
    assert version.policy is policy
    assert version.checks == [check]
    assert check.policy_version is version
    assert {zone.zone_key for zone in version.zones} == {"guest", "cde"}


def test_asset_belongs_to_zone(database):
    zone = Zone(
        zone_key="cde",
        name="Cardholder Data Environment",
        description="Restricted payment-card network",
    )
    database.add(zone)
    database.flush()

    asset = Asset(
        name="Payment API",
        address="10.30.0.10",
        hostname="payment-api.internal",
        zone=zone,
    )
    database.add(asset)
    database.commit()

    assert asset.zone is zone
    assert zone.assets == [asset]


def test_duplicate_policy_version_number_is_rejected(database):
    policy, version = create_policy_version(database)
    database.commit()

    duplicate = PolicyVersion(
        policy_id=policy.id,
        version_number=version.version_number,
        schema_version=1,
        snapshot={"schema_version": 1},
        snapshot_sha256="b" * 64,
    )
    database.add(duplicate)

    with pytest.raises(IntegrityError):
        database.commit()

    database.rollback()


@pytest.mark.parametrize("status", ["invalid", "deleted", "enabled", ""])
def test_invalid_policy_status_is_rejected(database, status):
    database.add(Policy(
        policy_key="POLICY-INVALID",
        name="Invalid Status Policy",
        status=status,
        pci_dss_version="4.0.1",
    ))

    with pytest.raises(IntegrityError):
        database.commit()

    database.rollback()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol", "sctp"),
        ("protocol", ""),
        ("expected", "maybe"),
        ("expected", ""),
    ],
)
def test_invalid_policy_check_values_are_rejected(database, field, value):
    _, version = create_policy_version(database)
    add_zone(database, version, "guest")
    add_zone(database, version, "cde")

    database.add(create_check(version, **{field: value}))

    with pytest.raises(IntegrityError):
        database.commit()

    database.rollback()


@pytest.mark.parametrize(
    ("field", "zone_key"),
    [
        ("source_zone_key", "missing-source"),
        ("destination_zone_key", "missing-destination"),
    ],
)
def test_check_cannot_reference_nonexistent_version_zone(
    database, field, zone_key
):
    _, version = create_policy_version(database)
    add_zone(database, version, "guest")
    add_zone(database, version, "cde")

    database.add(create_check(version, **{field: zone_key}))

    with pytest.raises(IntegrityError):
        database.commit()

    database.rollback()


@pytest.mark.parametrize(
    ("field", "zone_key"),
    [
        ("source_zone_key", "admin"),
        ("destination_zone_key", "admin"),
    ],
)
def test_check_cannot_reference_zone_from_another_policy_version(
    database, field, zone_key
):
    _, version_one = create_policy_version(database, "POLICY-ONE", 1)
    add_zone(database, version_one, "guest")
    add_zone(database, version_one, "cde")

    _, version_two = create_policy_version(database, "POLICY-TWO", 1)
    add_zone(database, version_two, "admin")

    database.add(create_check(version_one, **{field: zone_key}))

    with pytest.raises(IntegrityError):
        database.commit()

    database.rollback()


def test_duplicate_check_key_within_version_is_rejected(database):
    _, version = create_policy_version(database)
    add_zone(database, version, "guest")
    add_zone(database, version, "cde")

    database.add_all([
        create_check(version, "CHECK-DUPLICATE"),
        create_check(version, "CHECK-DUPLICATE"),
    ])

    with pytest.raises(IntegrityError):
        database.commit()

    database.rollback()


@pytest.mark.parametrize(
    ("model_name", "field", "new_value"),
    [
        ("version", "snapshot_sha256", "b" * 64),
        ("zone", "name", "Modified zone"),
        ("check", "name", "Modified check"),
    ],
)
def test_historical_policy_records_cannot_be_updated(
    database, model_name, field, new_value
):
    _, version = create_policy_version(database)
    guest = add_zone(database, version, "guest")
    cde = add_zone(database, version, "cde")
    check = create_check(version)
    database.add(check)
    database.commit()

    records = {
        "version": version,
        "zone": guest,
        "check": check,
    }

    record = records[model_name]
    setattr(record, field, new_value)

    with pytest.raises(
        ValueError,
        match="Historical policy records cannot be modified",
    ):
        database.commit()

    database.rollback()


@pytest.mark.parametrize("model_name", ["version", "zone", "check"])
def test_historical_policy_records_cannot_be_deleted(
    database, model_name
):
    _, version = create_policy_version(database)
    guest = add_zone(database, version, "guest")
    add_zone(database, version, "cde")
    check = create_check(version)
    database.add(check)
    database.commit()

    records = {
        "version": version,
        "zone": guest,
        "check": check,
    }

    database.delete(records[model_name])

    with pytest.raises(
        ValueError,
        match="Historical policy records cannot be deleted",
    ):
        database.commit()

    database.rollback()


def test_policy_metadata_remains_editable(database):
    policy, _version = create_policy_version(database)
    database.commit()

    policy.name = "Updated policy name"
    database.commit()

    assert policy.name == "Updated policy name"


def test_new_policy_version_records_can_be_inserted(database):
    policy, first_version = create_policy_version(database)
    add_zone(database, first_version, "guest")
    add_zone(database, first_version, "cde")
    database.commit()

    second_version = PolicyVersion(
        policy_id=policy.id,
        version_number=2,
        schema_version=1,
        snapshot={"schema_version": 1, "revision": 2},
        snapshot_sha256="d" * 64,
    )
    database.add(second_version)
    database.flush()

    database.add_all([
        add_zone(database, second_version, "guest"),
        add_zone(database, second_version, "cde"),
    ])
    database.add(create_check(second_version, "CHECK-002"))
    database.commit()

    assert [item.version_number for item in policy.versions] == [1, 2]
    assert len(second_version.zones) == 2
    assert len(second_version.checks) == 1


def test_policy_version_numbers_must_be_positive(database):
    policy, _ = create_policy_version(database)

    database.add(PolicyVersion(
        policy_id=policy.id,
        version_number=0,
        schema_version=1,
        snapshot={"schema_version": 1},
        snapshot_sha256="c" * 64,
    ))

    with pytest.raises(IntegrityError):
        database.commit()

    database.rollback()
