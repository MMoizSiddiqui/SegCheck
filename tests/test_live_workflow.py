"""Cross-platform discovery parsing and bounded live execution behavior."""
from datetime import timedelta
import copy

import pytest
from werkzeug.datastructures import MultiDict

from test_environment_workflow import app, configure, import_example, get_token, post
from segcheck.probe import ProbeOutcome
from segcheck_web.extensions import db
from segcheck_web.models import Assessment, Asset, Policy, User, utc_now
from segcheck_web.models.jobs import AssessmentJob, AssessmentLease
from segcheck_web.services.environment import settings, save_zone, save_asset
from segcheck_web.services.assessment_plan import build_plan
from segcheck_web.services.assessment_jobs import create_job, run_job, expire_stale_jobs, JobBusy
from segcheck_web.services.network_discovery import parse_linux, parse_windows, parse_macos, discover_local_network, DiscoveryUnavailable


def test_linux_discovery_filters_local_only_addresses():
    rows = parse_linux([{"ifname": "eth0", "addr_info": [
        {"local": "10.20.0.100", "prefixlen": 24},
        {"local": "fe80::1234", "prefixlen": 64}]},
        {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]}],
        [{"dev": "eth0", "gateway": "10.20.0.1"}])
    assert rows == [{"interface": "eth0", "source_ip": "10.20.0.100", "cidr": "10.20.0.0/24", "gateway": "10.20.0.1", "family": "IPv4"}]


def test_windows_and_macos_discovery_adapters():
    rows = parse_windows({"Interface": "Ethernet", "Address": "10.20.0.100", "Prefix": 24, "Gateway": "10.20.0.1,2001:db8::1"})
    assert rows[0]["cidr"] == "10.20.0.0/24" and rows[0]["gateway"] == "10.20.0.1"
    rows = parse_macos("en0: flags=8863\n\tinet 10.20.0.100 netmask 0xffffff00 broadcast 10.20.0.255\n\tinet6 fe80::1%en0 prefixlen 64", "   gateway: 10.20.0.1\n interface: en0\n")
    assert len(rows) == 1 and rows[0]["gateway"] == "10.20.0.1"


def test_discovery_unsupported_os_falls_back(monkeypatch):
    monkeypatch.setattr("segcheck_web.services.network_discovery.platform.system", lambda: "UnknownOS")
    with pytest.raises(DiscoveryUnavailable, match="manual"):
        discover_local_network()




def prepare_job(app, monkeypatch, token="reviewed-token"):
    monkeypatch.setattr("segcheck_web.services.assessment_plan.source_address_available", lambda _: True)
    with app.app_context():
        configure()
        version = import_example()
        actor = db.session.query(User).one()
        job, created = create_job(version, build_plan(version, "active"), actor.id, token)
        assert created
        return job.id


def test_worker_records_real_progress_then_immutable_assessment(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    calls = []
    def probe(host, port, timeout, *, source_ip):
        calls.append((host, port, source_ip))
        return ProbeOutcome("reachable", "controlled_tcp_result", .5, source_ip)
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe", probe)
    run_job(app, job_id)
    with app.app_context():
        job = db.session.get(AssessmentJob, job_id)
        assert job.status == "completed" and job.completed == 1
        assert job.events[0]["observed"] == "reachable"
        record = db.session.get(Assessment, job.assessment_id)
        assert record.report["results"][0]["result"] == "FAIL"
        assert record.report["assessment"]["environment"]["source_ip"] == "10.20.0.100"
        assert db.session.query(AssessmentLease).count() == 0
    assert calls == [("10.30.0.10", 443, "10.20.0.100")]
    response = authenticated_client.get(f"/jobs/{job_id}/status", base_url="https://localhost")
    assert response.get_json()["assessment_url"]
    assert response.headers["Cache-Control"] == "no-store"


def test_job_admission_idempotent_and_single_installation_lease(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    with app.app_context():
        first = db.session.get(AssessmentJob, job_id)
        version = first.policy_version_id
        from segcheck_web.models import PolicyVersion
        version = db.session.get(PolicyVersion, version)
        plan = build_plan(version, "active")
        replay, created = create_job(version, plan, first.actor_user_id, "reviewed-token")
        assert replay.id == job_id and not created
        with pytest.raises(JobBusy):
            create_job(version, plan, first.actor_user_id, "different-preview")
        assert db.session.query(AssessmentJob).count() == 1


def test_cancelled_queued_job_never_probes(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe", lambda *a, **k: pytest.fail("Cancelled job probed"))
    token = get_token(authenticated_client, f"/jobs/{job_id}")
    assert post(authenticated_client, f"/jobs/{job_id}/cancel", {"csrf_token": token}).status_code == 302
    run_job(app, job_id)
    with app.app_context():
        assert db.session.get(AssessmentJob, job_id).status == "cancelled"
        assert db.session.query(Assessment).count() == 0


def test_cancel_during_attempt_aborts_before_report(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    def cancel_in_probe(host, port, timeout, *, source_ip):
        job = db.session.get(AssessmentJob, job_id)
        job.cancel_requested = True
        db.session.commit()
        return ProbeOutcome("reachable", "controlled_tcp_result", .5, source_ip)
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe", cancel_in_probe)
    run_job(app, job_id)
    with app.app_context():
        assert db.session.get(AssessmentJob, job_id).status == "cancelled"
        assert db.session.query(Assessment).count() == 0


def test_expired_lease_is_interrupted_not_completed(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    with app.app_context():
        lease = db.session.get(AssessmentLease, 1)
        lease.expires_at = utc_now() - timedelta(seconds=1)
        db.session.commit()
        expire_stale_jobs()
        assert db.session.get(AssessmentJob, job_id).status == "interrupted"
        assert db.session.query(AssessmentLease).count() == 0
        assert db.session.query(Assessment).count() == 0


def test_job_status_ownership_and_cancel_csrf(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    assert post(authenticated_client, f"/jobs/{job_id}/cancel", {}).status_code == 400
    with app.app_context():
        other = User(username="another-admin", password_hash="test-only", is_active=True)
        db.session.add(other)
        db.session.flush()
        db.session.get(AssessmentJob, job_id).actor_user_id = other.id
        db.session.commit()
    assert authenticated_client.get(f"/jobs/{job_id}/status", base_url="https://localhost").status_code == 404


def test_queued_job_revalidates_environment_before_any_probe(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    with app.app_context():
        record, payload = settings()
        payload["site"] = "Changed after authorization"
        record.payload = payload
        db.session.commit()
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe", lambda *a, **k: pytest.fail("Changed scope was probed"))
    run_job(app, job_id)
    with app.app_context():
        job = db.session.get(AssessmentJob, job_id)
        assert job.status == "failed" and job.completed == 0
        assert db.session.query(Assessment).count() == 0
        assert db.session.query(AssessmentLease).count() == 0






def test_live_dashboard_has_no_fabricated_counts(app, authenticated_client):
    response = authenticated_client.get("/api/dashboard", base_url="https://localhost")
    assert response.status_code == 200
    assert response.get_json()["metrics"] == {"policies": 0, "assets": 0, "assessments": 0, "zones": 0}
    assert response.get_json()["results"] == {"total": 0, "pass": 0, "fail": 0, "inconclusive": 0}
    assert response.headers["Cache-Control"] == "no-store"
