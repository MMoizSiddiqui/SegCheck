"""On a real (migrated) database: saved reports cannot be changed or deleted, except through History."""
from pathlib import Path

import pytest
import yaml
from flask_migrate import downgrade, upgrade
from sqlalchemy import text
from werkzeug.datastructures import MultiDict
from werkzeug.security import generate_password_hash

from segcheck.probe import ProbeOutcome
from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import Assessment, Policy, User
from segcheck_web.services import history
from segcheck_web.services.assessment_execution import execute_assessment
from segcheck_web.services.environment import save_asset, save_profile, save_zone, settings
from segcheck_web.services.policy_import import import_policy_content
from segcheck_web.services.policy_lifecycle import transition_policy_status

MIGRATIONS = Path(__file__).resolve().parents[1] / "segcheck_web" / "migrations"


def form(**values):
    return MultiDict({key: str(value) for key, value in values.items()})


@pytest.fixture
def migrated(tmp_path, monkeypatch):
    database = tmp_path / "history.sqlite3"
    app = create_app({"TESTING": True, "SECRET_KEY": "history-protection-test-secret",
                      "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database}"})
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                        lambda host, port, timeout, source_ip: ProbeOutcome("reachable", "test", 1.0, source_ip))
    with app.app_context():
        upgrade(directory=str(MIGRATIONS), revision="head")
        db.session.add(User(username="auditor", password_hash=generate_password_hash("Strong-Pass-2026!", method="scrypt"), is_active=True))
        db.session.commit()
        save_zone(form(zone_key="hr", name="HR", role="hr", cidr="10.50.0.0/24", revision=0))
        save_zone(form(zone_key="cde", name="CDE", role="cde", cidr="10.30.0.0/24", revision=settings()[0].revision))
        save_asset(form(zone_key="cde", name="Card DB", address="10.30.0.20"))
        save_profile(form(organization="Test", site="HQ", source_zone="hr", source_ip="10.50.0.23", revision=settings()[0].revision))
        yield app, database


def make_report(name):
    document = {"schema_version": 1, "policy_id": name, "name": name, "organization": "Test", "pci_dss_version": "4.0.1",
                "zones": [{"id": "hr", "name": "HR"}, {"id": "cde", "name": "CDE"}],
                "checks": [{"id": "CHK-001", "name": "HR must not reach the card DB", "source_zone": "hr", "destination_zone": "cde",
                            "destination_host": "10.30.0.20", "protocol": "tcp", "ports": [5432], "expected": "deny",
                            "rationale": "test", "pci_requirements": [], "framework_mappings": []}]}
    policy = import_policy_content(yaml.safe_dump(document).encode())
    transition_policy_status(policy.id, "active", "Activated for the history protection test.", actor_identifier="auditor")
    version = policy.versions[-1]
    actor = db.session.query(User).one()
    return execute_assessment(policy_id=policy.id, policy_version_id=version.id, source_zone="hr",
                              actor_user_id=actor.id, source_ip="10.50.0.23", environment_context=settings()[1]).id


def test_reports_cannot_be_changed_or_deleted_behind_historys_back(migrated):
    app, _ = migrated
    with app.app_context():
        report_id = make_report("PROTECT-001")
        for statement in (f"UPDATE assessments SET source_zone = 'x' WHERE id = {report_id}",
                          f"DELETE FROM assessments WHERE id = {report_id}",
                          "DELETE FROM policy_checks", "DELETE FROM policy_versions"):
            with pytest.raises(Exception, match="immutable"):
                db.session.execute(text(statement))
            db.session.rollback()
        # A grant for another row does not unlock this one.
        db.session.execute(text("INSERT INTO record_deletions (table_name, row_id) VALUES ('assessments', 999)"))
        with pytest.raises(Exception, match="immutable"):
            db.session.execute(text(f"DELETE FROM assessments WHERE id = {report_id}"))
        db.session.rollback()
        assert db.session.get(Assessment, report_id) is not None


def test_history_delete_removes_the_audit_and_compacts_the_file(migrated):
    app, database = migrated
    with app.app_context():
        keep = make_report("KEEP-001")
        drop = make_report("DROP-001")
        history.delete_report(drop)
        assert db.session.get(Assessment, drop) is None and db.session.get(Assessment, keep) is not None
        assert [p.policy_key for p in db.session.query(Policy).all()] == ["KEEP-001"]
        assert db.session.execute(text("SELECT COUNT(*) FROM record_deletions")).scalar() == 0
        # Changing the remaining report is still impossible.
        with pytest.raises(Exception, match="immutable"):
            db.session.execute(text(f"UPDATE assessments SET source_zone = 'x' WHERE id = {keep}"))
        db.session.rollback()
        history.delete_all()
        assert db.session.query(Assessment).count() == 0 and db.session.query(Policy).count() == 0
    assert b"DROP-001" not in database.read_bytes() and b"KEEP-001" not in database.read_bytes()


def test_migration_downgrades_cleanly(migrated):
    app, _ = migrated
    with app.app_context():
        downgrade(directory=str(MIGRATIONS), revision="e7a1c3f9b250")
        names = {row[0] for row in db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        assert "record_deletions" not in names
        upgrade(directory=str(MIGRATIONS), revision="head")
        assert db.session.execute(text("SELECT version_num FROM alembic_version")).scalar() == "f3a9c1d7e2b4"
