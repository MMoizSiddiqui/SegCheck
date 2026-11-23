"""Configuration, applicability and reviewed execution trust boundaries."""
import copy
import re
from types import SimpleNamespace

import pytest
import yaml
from flask_migrate import upgrade, downgrade
from sqlalchemy import inspect, text
from werkzeug.datastructures import MultiDict

from segcheck.probe import tcp_connect_probe
from segcheck_web import create_app
from segcheck_web.extensions import db
from segcheck_web.models import Zone, Asset, PolicyVersion
from segcheck_web.models.environment import EnvironmentSettings
from segcheck_web.services.environment import (
    EnvironmentError, save_device, save_zone, save_asset, save_profile, settings,
)
from segcheck_web.services.policy_import import import_policy_content
from segcheck_web.services.assessment_plan import build_plan
from segcheck_web.services.assessment_execution import execute_assessment


@pytest.fixture
def app():
    application = create_app({"TESTING": True, "SECRET_KEY": "environment-test-secret",
                              "SQLALCHEMY_DATABASE_URI": "sqlite://"})
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def form(**values):
    return MultiDict({name: str(value) for name, value in values.items()})


def configure():
    save_zone(form(zone_key="guest", name="Guest", cidr="10.20.0.0/24", gateway="10.20.0.1", revision=0))
    save_zone(form(zone_key="cde", name="CDE", cidr="10.30.0.0/24", revision=1))
    save_asset(form(zone_key="cde", name="Payment", address="10.30.0.10"))
    save_profile(form(organization="Example Bank", site="Main", source_zone="guest",
                      source_ip="10.20.0.100", revision=2))
    declare_boundary(revision=3)


def declare_boundary(revision, zones=("guest", "cde")):
    """Every cross-zone path needs a declared boundary device (here: no log feed)."""
    data = MultiDict({"name": "Lab firewall", "kind": "pfsense", "revision": str(revision)})
    for zone in zones:
        data.add("zones", zone)
    save_device(data)


def policy_data():
    return {"schema_version": 1, "policy_id": "EXAMPLE-001", "name": "Protect CDE",
            "organization": "Example Bank", "pci_dss_version": "4.0.1",
            "zones": [{"id": "guest", "name": "Guest"}, {"id": "cde", "name": "CDE"}],
            "checks": [{"id": "CHECK-001", "name": "Protect payment service", "source_zone": "guest",
                        "destination_zone": "cde", "destination_host": "10.30.0.10",
                        "protocol": "tcp", "ports": [443], "expected": "deny",
                        "rationale": "Restrict guest access", "pci_requirements": []}]}


def import_example(data=None):
    policy = import_policy_content(yaml.safe_dump(data or policy_data()).encode())
    policy.status = "active"
    db.session.commit()
    return policy.versions[0]


def get_token(client, path, name="csrf_token"):
    response = client.get(path, base_url="https://localhost")
    assert response.status_code == 200
    match = re.search(fr'name="{name}"\s+value="([^"]+)"'.encode(), response.data)
    assert match
    return match.group(1).decode()


def post(client, path, data):
    return client.post(path, data=data, base_url="https://localhost",
                       headers={"Referer": "https://localhost" + path})


def test_inventory_round_trip_and_canonical_addresses(app):
    with app.app_context():
        configure()
        record, payload = settings()
        assert record.revision == 4  # zones, profile and boundary device
        assert payload["networks"]["guest"]["gateway"] == "10.20.0.1"
        assert payload["source_ip"] == "10.20.0.100"
        assert db.session.query(Zone).count() == 2
        assert db.session.query(Asset).one().zone.zone_key == "cde"


@pytest.mark.parametrize("overrides", [
    {"cidr": "10.20.0.7/24"}, {"gateway": "10.99.0.1"},
    {"zone_key": "x;id"}, {"cidr": "0.0.0.0/0"}, {"revision": 9},
])
def test_invalid_zone_does_not_persist(app, overrides):
    with app.app_context():
        values = dict(zone_key="guest", name="Guest", cidr="10.20.0.0/24", revision=0)
        values.update(overrides)
        with pytest.raises(EnvironmentError):
            save_zone(form(**values))
        db.session.rollback()
        assert db.session.query(Zone).count() == 0


def test_overlapping_subnets_and_excluded_assets_rejected(app):
    with app.app_context():
        configure()
        with pytest.raises(EnvironmentError, match="overlap"):
            save_zone(form(zone_key="corp", name="Corp", cidr="10.30.0.0/25", revision=4))
        db.session.rollback()
        with pytest.raises(EnvironmentError, match="excludes an existing asset"):
            save_zone(form(zone_key="cde", name="CDE", cidr="10.31.0.0/24", revision=4))
        db.session.rollback()
        assert settings()[1]["networks"]["cde"]["cidr"] == "10.30.0.0/24"


@pytest.mark.parametrize("address", ["example.com", "127.0.0.1", "169.254.1.2", "224.0.0.1", "10.31.0.1", "::1"])
def test_asset_address_validation(app, address):
    with app.app_context():
        configure()
        with pytest.raises(EnvironmentError):
            save_asset(form(zone_key="cde", name="Bad target", address=address))
        db.session.rollback()
        assert db.session.query(Asset).count() == 1


def test_duplicate_fields_rejected(app):
    with app.app_context():
        values = form(zone_key="guest", name="Guest", cidr="10.20.0.0/24", revision=0)
        values.add("cidr", "10.30.0.0/24")
        with pytest.raises(EnvironmentError):
            save_zone(values)
        db.session.rollback()


def test_plan_reports_other_source_and_udp_gap(app):
    with app.app_context():
        configure()
        data = policy_data()
        other = copy.deepcopy(data["checks"][0])
        other.update(id="CHECK-OTHER", source_zone="cde")
        data["checks"].append(other)
        version = import_example(data)
        plan = build_plan(version, "active", check_local_address=False)
        assert plan["ready"] and plan["attempts"] == 1
        assert not plan["rows"][1]["selected"]
        assert "another source zone" in plan["rows"][1]["reasons"][0]
        data["policy_id"] = "UDP-EXAMPLE"
        data["checks"][0]["protocol"] = "udp"
        version = import_example(data)
        plan = build_plan(version, "active", check_local_address=False)
        # UDP now has an executable request/response probe method.
        assert plan["ready"] and plan["attempts"] == 1
        data["policy_id"] = "ICMP-EXAMPLE"
        data["checks"][0]["protocol"] = "icmp"
        data["checks"][0]["ports"] = []
        version = import_example(data)
        plan = build_plan(version, "active", check_local_address=False)
        # ICMP echo is one portless attempt.
        assert plan["ready"] and plan["attempts"] == 1


def test_plan_blocks_missing_inventory_and_nonlocal_source(app, monkeypatch):
    with app.app_context():
        configure()
        version = import_example()
        monkeypatch.setattr("segcheck_web.services.assessment_plan.source_address_available", lambda _: False)
        plan = build_plan(version, "active")
        assert not plan["ready"]
        assert any("not an address of this PC" in reason for reason in plan["blockers"])
        asset = db.session.query(Asset).one()
        asset.address = "10.30.0.11"
        db.session.commit()
        plan = build_plan(version, "active", check_local_address=False)
        assert any("Register this exact target" in reason for reason in plan["blockers"])


















def test_tcp_socket_is_explicitly_bound(monkeypatch):
    calls = []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    monkeypatch.setattr("segcheck.probe.socket.create_connection", lambda *a, **k: (calls.append((a, k)) or Connection()))
    outcome = tcp_connect_probe("10.30.0.10", 443, 1.0, source_ip="10.20.0.100")
    assert outcome.state == "reachable" and outcome.source_ip == "10.20.0.100"
    assert calls[0][1]["source_address"] == ("10.20.0.100", 0)
    with pytest.raises(ValueError):
        tcp_connect_probe("2001:db8::10", 443, 1.0, source_ip="10.20.0.100")


def test_bound_assessment_preserves_environment_and_exports_saved_report(app, authenticated_client, monkeypatch):
    from segcheck.probe import ProbeOutcome
    from segcheck_web.models import User
    with app.app_context():
        configure()
        version = import_example()
        actor = db.session.query(User).one()
        monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                            lambda host, port, timeout, source_ip: ProbeOutcome("reachable", "tcp_connect_succeeded", 1.0, source_ip))
        record = execute_assessment(policy_id=version.policy_id, policy_version_id=version.id,
            source_zone="guest", actor_user_id=actor.id, source_ip="10.20.0.100",
            environment_context=settings()[1])
        report = copy.deepcopy(record.report)
        assessment_id = record.id
        assert report["assessment"]["environment"]["organization"] == "Example Bank"
        assert report["results"][0]["result"] == "FAIL"
        assert "explicitly bound" in report["probe_measurement"]["source_ip_semantics"]
    response = authenticated_client.get(f"/assessments/{assessment_id}/report.json", base_url="https://localhost")
    assert response.status_code == 200 and response.get_json() == report
    assert response.headers["Cache-Control"] == "no-store"
    assert "attachment" in response.headers["Content-Disposition"]




def test_environment_migration_roundtrip(tmp_path):
    from pathlib import Path
    migration_dir = str(Path(__file__).resolve().parents[1] / "segcheck_web" / "migrations")
    app = create_app({"TESTING": True, "SECRET_KEY": "migration-test-secret",
                      "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'environment.sqlite3'}"})
    with app.app_context():
        upgrade(directory=migration_dir, revision="head")
        assert "environment_settings" in inspect(db.engine).get_table_names()
        db.session.execute(text("INSERT INTO environment_settings (id, payload, revision) VALUES (1, '{}', 1)"))
        db.session.commit()
        downgrade(directory=migration_dir, revision="b41d8e7a2c90")
        assert "environment_settings" not in inspect(db.engine).get_table_names()
        assert "assessments" in inspect(db.engine).get_table_names()
        upgrade(directory=migration_dir, revision="head")
        assert "environment_settings" in inspect(db.engine).get_table_names()
