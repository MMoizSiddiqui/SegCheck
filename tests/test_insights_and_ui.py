"""Read-only dashboard insights, report rendering and live-console API additions."""
import errno
import socket

import pytest

from test_environment_workflow import app, configure, import_example
from test_live_workflow import prepare_job
from segcheck.probe import ProbeOutcome, _socket_error_label, tcp_connect_probe
from segcheck_web.extensions import db
from segcheck_web.models import Assessment
from segcheck_web.models.jobs import AssessmentJob
from segcheck_web.services.assessment_jobs import run_job
from segcheck_web.services.insights import assessment_breakdown, build_insights


def test_breakdown_separates_not_exercised_checks():
    report = {
        "results": [
            {"check_id": "A", "result": "PASS"},
            {"check_id": "B", "result": "FAIL"},
            {"check_id": "C", "result": "INCONCLUSIVE"},
            {"check_id": "D", "result": "INCONCLUSIVE"},
        ],
        "assessment": {"scope": {"evaluated_check_ids": ["A", "B", "C"], "not_evaluated_check_ids": ["D"]}},
    }
    assert assessment_breakdown(report) == {"pass": 1, "fail": 1, "inconclusive": 1, "not_exercised": 1}


@pytest.mark.parametrize("report", [
    {},
    {"results": "not-a-list"},
    {"results": [None, "x", {"check_id": "A", "result": "PASS"}], "assessment": {"scope": "legacy descriptive scope"}},
    {"assessment": "legacy"},
])
def test_breakdown_tolerates_legacy_and_malformed_reports(report):
    counts = assessment_breakdown(report)
    assert set(counts) == {"pass", "fail", "inconclusive", "not_exercised"}
    assert all(isinstance(value, int) and value >= 0 for value in counts.values())


def test_empty_installation_insights_are_empty(app):
    with app.app_context():
        insights = build_insights({"networks": {}}, actor_id=1)
    assert insights["outcomes"] == {"pass": 0, "fail": 0, "inconclusive": 0, "not_exercised": 0}
    assert insights["runs"] == [] and insights["edges"] == [] and insights["activity"] == []
    assert insights["pci"]["cde_zones"] == [] and insights["pci"]["untested_sources"] == []


def test_completed_run_feeds_paths_coverage_and_dashboard_api(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                        lambda host, port, timeout, *, source_ip: ProbeOutcome("reachable", "controlled", .4, source_ip))
    run_job(app, job_id)
    response = authenticated_client.get("/api/dashboard", base_url="https://localhost")
    data = response.get_json()
    # Backwards-compatible keys keep their exact shape.
    assert set(data["metrics"]) == {"policies", "assets", "assessments", "zones"}
    assert set(data["results"]) == {"total", "pass", "fail", "inconclusive"}
    insights = data["insights"]
    assert insights["outcomes"]["fail"] == 1
    assert insights["runs"][-1]["breakdown"]["fail"] == 1
    edge = insights["edges"][0]
    assert edge["source"] == "guest" and edge["status"] == "fail"
    assert insights["activity"][0]["status"] == "completed"
    assert data["generated_at"].endswith("+00:00")


def test_activity_feed_is_restricted_to_the_requesting_user(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    with app.app_context():
        owner = db.session.get(AssessmentJob, job_id).actor_user_id
        assert build_insights({"networks": {}}, actor_id=owner)["activity"]
        assert build_insights({"networks": {}}, actor_id=owner + 999)["activity"] == []


def test_job_status_reports_utc_timestamps_and_policy(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    data = authenticated_client.get(f"/jobs/{job_id}/status", base_url="https://localhost").get_json()
    assert data["created_at"].endswith("+00:00") and data["updated_at"].endswith("+00:00")
    assert data["policy"]
    page = authenticated_client.get(f"/jobs/{job_id}", base_url="https://localhost")
    assert page.status_code == 200 and b'id="radar"' in page.data and b"Connection lanes" in page.data


def test_cancelled_job_message_is_specific(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    with app.app_context():
        job = db.session.get(AssessmentJob, job_id)
        job.cancel_requested = True
        db.session.commit()
    run_job(app, job_id)
    with app.app_context():
        job = db.session.get(AssessmentJob, job_id)
        assert job.status == "cancelled"
        assert "Cancelled by the operator" in job.message and job.assessment_id is None


def test_report_page_shows_scope_observations_and_exports(app, authenticated_client, monkeypatch):
    job_id = prepare_job(app, monkeypatch)
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                        lambda host, port, timeout, *, source_ip: ProbeOutcome("inconclusive", "connection_timeout; not proof", 1000.0, source_ip))
    run_job(app, job_id)
    with app.app_context():
        assessment_id = db.session.get(AssessmentJob, job_id).assessment_id
    page = authenticated_client.get(f"/assessments/{assessment_id}", base_url="https://localhost")
    body = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "Environment at execution" in body and "10.20.0.100" in body
    assert "connection_timeout; not proof" in body  # per-port observation reason
    assert f"/assessments/{assessment_id}/report.json" in body and f"/assessments/{assessment_id}/report.pdf" in body
    assert "Results cover only the rules in this audit" in body and "PCI DSS" not in body.split("<main")[1].split("Technical detail")[0]
    assert "No reply within 1 second" in body  # every attempt explained in plain words
    # The environment section is inside <main>, not rendered before the layout.
    assert body.index("<main") < body.index("Environment at execution")


def test_socket_error_labels_are_stable_and_bounded():
    assert _socket_error_label(OSError(errno.ENETUNREACH, "x")) == "network_unreachable"
    windows_error = OSError(10051, "x")
    windows_error.winerror = 10051
    assert _socket_error_label(windows_error) == "network_unreachable"
    assert _socket_error_label(OSError(99999, "custom")) == "OSError"


def test_probe_reports_network_unreachable_label(monkeypatch):
    def unreachable(*args, **kwargs):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")
    monkeypatch.setattr(socket, "create_connection", unreachable)
    outcome = tcp_connect_probe("192.0.2.10", 443, 1.0, source_ip="192.0.2.20")
    assert outcome.state == "inconclusive"
    assert outcome.reason == "socket_error_network_unreachable; not proof of segmentation"


def test_windows_discovery_uses_extended_timeout(monkeypatch):
    seen = {}
    def fake_run(command, timeout=3):
        seen["timeout"] = timeout
        return '[{"Interface":"Ethernet 2","Address":"192.168.56.1","Prefix":24,"Gateway":""}]'
    monkeypatch.setattr("segcheck_web.services.network_discovery.platform.system", lambda: "Windows")
    monkeypatch.setattr("segcheck_web.services.network_discovery._run", fake_run)
    from segcheck_web.services.network_discovery import discover_local_network
    result = discover_local_network()
    assert seen["timeout"] >= 10
    assert result["interfaces"][0]["cidr"] == "192.168.56.0/24"


def test_templates_contain_no_csp_blocked_inline_handlers_or_styles():
    """The CSP (default-src 'self') silently blocks inline handlers/styles."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1] / "segcheck_web" / "templates"
    offenders = []
    for template in root.rglob("*.html"):
        text = template.read_text(encoding="utf-8")
        if re.search(r"\son[a-z]+\s*=\s*[\"']", text, re.I) or re.search(r"\sstyle\s*=\s*[\"']", text, re.I):
            offenders.append(template.name)
        if re.search(r"<script(?![^>]*\bsrc=)[^>]*>", text, re.I):
            offenders.append(template.name + " (inline script)")
    assert offenders == []


def test_static_assets_are_cache_busted(app, authenticated_client):
    page = authenticated_client.get("/", base_url="https://localhost").get_data(as_text=True)
    assert "/static/js/ui.js?v=" in page and "/static/css/ui.css?v=" in page
