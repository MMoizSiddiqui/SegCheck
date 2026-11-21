"""Tests for validated, transactional policy imports."""

import hashlib
import json
from pathlib import Path

import pytest
import yaml
from sqlalchemy import event

from segcheck.policy_engine import PolicyValidationError
from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import (
    Policy,
    PolicyCheck,
    PolicyVersion,
    PolicyVersionZone,
)
from segcheck_web.services.policy_import import (
    DuplicatePolicyError,
    PolicyImportError,
    import_policy_content,
    import_policy_file,
)


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

        yield application

        db.session.remove()
        db.drop_all()
        event.remove(engine, "connect", enable_foreign_keys)


@pytest.fixture
def app_context(app):
    with app.app_context():
        yield


def test_imports_lab_policy_with_all_zones_and_checks(app_context):
    imported = import_policy_file(LAB_POLICY)

    assert imported.policy_key == "SEGCHECK-POLICY-001"
    assert imported.status == "draft"
    assert imported.pci_dss_version == "4.0.1"

    version = db.session.query(PolicyVersion).filter_by(
        policy_id=imported.id
    ).one()

    assert version.version_number == 1
    assert version.schema_version == 1
    assert len(version.snapshot_sha256) == 64

    zones = db.session.query(PolicyVersionZone).filter_by(
        policy_version_id=version.id
    ).all()

    checks = db.session.query(PolicyCheck).filter_by(
        policy_version_id=version.id
    ).all()

    assert len(zones) == 7
    assert len(checks) == 5

    assert {zone.zone_key for zone in zones} == {
        "internet", "dmz", "app", "cde", "corporate", "guest", "admin"
    }

    assert {check.check_key for check in checks} == {
        "SEG-001", "SEG-002", "SEG-003", "SEG-004", "SEG-005"
    }


def test_import_persists_framework_mappings_in_checks_and_snapshot(
    app_context,
):
    data = yaml.safe_load(LAB_POLICY.read_text(encoding="utf-8"))
    data["checks"][0]["framework_mappings"] = [
        {
            "framework": "pci_dss",
            "version": "4.0.1",
            "control_id": "11.4.5",
            "title": "Segmentation testing",
            "relationship": "direct",
        },
        {
            "framework": "nist_csf",
            "version": "2.0",
            "control_id": "PR.PS-04",
            "title": "Network protection",
            "relationship": "supporting",
        },
    ]

    content = yaml.safe_dump(data, sort_keys=False).encode("utf-8")
    imported = import_policy_content(content)

    version = db.session.query(PolicyVersion).filter_by(
        policy_id=imported.id
    ).one()

    check = db.session.query(PolicyCheck).filter_by(
        policy_version_id=version.id,
        check_key="SEG-001",
    ).one()

    expected = data["checks"][0]["framework_mappings"]

    assert check.framework_mappings == expected

    snapshot_check = next(
        item for item in version.snapshot["checks"]
        if item["id"] == "SEG-001"
    )
    assert snapshot_check["framework_mappings"] == expected


def test_import_without_framework_mappings_persists_empty_lists(app_context):
    data = yaml.safe_load(LAB_POLICY.read_text(encoding="utf-8"))
    for check in data["checks"]:
        check.pop("framework_mappings", None)

    imported = import_policy_content(
        yaml.safe_dump(data, sort_keys=False).encode("utf-8")
    )

    version = db.session.query(PolicyVersion).filter_by(
        policy_id=imported.id
    ).one()

    checks = db.session.query(PolicyCheck).filter_by(
        policy_version_id=version.id
    ).all()

    assert checks
    assert all(check.framework_mappings == [] for check in checks)

    assert all(
        item["framework_mappings"] == []
        for item in version.snapshot["checks"]
    )


def test_snapshot_hash_matches_canonical_snapshot(app_context):
    imported = import_policy_file(LAB_POLICY)

    version = db.session.query(PolicyVersion).filter_by(
        policy_id=imported.id
    ).one()

    encoded = json.dumps(
        version.snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    expected_hash = hashlib.sha256(encoded).hexdigest()

    assert version.snapshot_sha256 == expected_hash


def test_duplicate_policy_id_is_rejected_without_creating_records(app_context):
    first = import_policy_file(LAB_POLICY)

    with pytest.raises(DuplicatePolicyError):
        import_policy_file(LAB_POLICY)

    assert db.session.query(Policy).count() == 1
    assert db.session.query(PolicyVersion).count() == 1
    assert first.policy_key == "SEGCHECK-POLICY-001"


def test_invalid_policy_is_rejected_without_database_changes(
    app_context, tmp_path
):
    invalid_file = tmp_path / "invalid-policy.yaml"
    invalid_file.write_text(
        "schema_version: 999\n",
        encoding="utf-8",
    )

    with pytest.raises(PolicyValidationError):
        import_policy_file(invalid_file)

    assert db.session.query(Policy).count() == 0
    assert db.session.query(PolicyVersion).count() == 0


def test_missing_policy_file_is_rejected(app_context, tmp_path):
    missing_file = tmp_path / "does-not-exist.yaml"

    with pytest.raises(PolicyValidationError):
        import_policy_file(missing_file)

    assert db.session.query(Policy).count() == 0


def test_oversized_policy_name_is_rejected_before_persistence(
    app_context, tmp_path
):
    data = yaml.safe_load(LAB_POLICY.read_text(encoding="utf-8"))
    data["name"] = "A" * 161

    oversized_file = tmp_path / "oversized-policy.yaml"
    oversized_file.write_text(
        yaml.safe_dump(data, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(PolicyImportError, match="policy name"):
        import_policy_file(oversized_file)

    assert db.session.query(Policy).count() == 0


def test_failed_check_insert_rolls_back_entire_import(
    app_context,
):
    def reject_check_insert(_mapper, _connection, _target):
        raise RuntimeError("Simulated database insert failure")

    event.listen(PolicyCheck, "before_insert", reject_check_insert)

    try:
        with pytest.raises(RuntimeError, match="Simulated database"):
            import_policy_file(LAB_POLICY)
    finally:
        event.remove(
            PolicyCheck,
            "before_insert",
            reject_check_insert,
        )

    db.session.expire_all()

    assert db.session.query(Policy).count() == 0
    assert db.session.query(PolicyVersion).count() == 0
    assert db.session.query(PolicyVersionZone).count() == 0
    assert db.session.query(PolicyCheck).count() == 0



def test_import_policy_content_creates_initial_version(app_context):
    from segcheck_web.services.policy_import import import_policy_content

    content = LAB_POLICY.read_bytes()
    imported = import_policy_content(content)

    assert imported.policy_key == "SEGCHECK-POLICY-001"
    assert imported.status == "draft"

    version = db.session.query(PolicyVersion).filter_by(
        policy_id=imported.id
    ).one()

    assert version.version_number == 1
    assert len(version.snapshot_sha256) == 64
    assert db.session.query(PolicyVersionZone).filter_by(
        policy_version_id=version.id
    ).count() == 7
    assert db.session.query(PolicyCheck).filter_by(
        policy_version_id=version.id
    ).count() == 5


def test_import_policy_content_rejects_duplicate_yaml_keys(app_context):
    from segcheck_web.services.policy_import import import_policy_content

    content = (
        LAB_POLICY.read_text(encoding="utf-8")
        + "\npolicy_id: ATTACKER-POLICY\n"
    ).encode("utf-8")

    with pytest.raises(PolicyValidationError, match="Invalid YAML"):
        import_policy_content(content)

    assert db.session.query(Policy).count() == 0
    assert db.session.query(PolicyVersion).count() == 0


def test_import_policy_content_rejects_non_bytes(app_context):
    from segcheck_web.services.policy_import import import_policy_content

    with pytest.raises(PolicyImportError, match="must be bytes"):
        import_policy_content("not bytes")

    assert db.session.query(Policy).count() == 0


def test_import_policy_content_rejects_oversized_content(app_context):
    from segcheck.policy_engine import MAX_POLICY_BYTES
    from segcheck_web.services.policy_import import import_policy_content

    with pytest.raises(PolicyImportError, match="exceeds"):
        import_policy_content(b" " * (MAX_POLICY_BYTES + 1))

    assert db.session.query(Policy).count() == 0


def test_import_policy_content_rejects_invalid_utf8(app_context):
    from segcheck_web.services.policy_import import import_policy_content

    with pytest.raises(PolicyValidationError, match="UTF-8"):
        import_policy_content(b"\xff\xfe")

    assert db.session.query(Policy).count() == 0
