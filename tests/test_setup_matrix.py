"""Every way Step 3 can be set up (or half set up) x every kind of probe result x both Step 4 modes, run end to end:
launch, run, then the saved report page, PDF and JSON. Each report must load, give the right verdict and explain it
in plain words (no blanks, no 'None', no raw errors)."""
from datetime import datetime, timezone

import pytest

from test_audit_flow import BASE, local, post, setup_audit  # noqa: F401
from test_environment_workflow import app  # noqa: F401
from segcheck.probe import ProbeOutcome
from segcheck_web.extensions import db
from segcheck_web.models import Assessment
from segcheck_web.models.jobs import AssessmentJob
from segcheck_web.services import report_view
from segcheck_web.services.assessment_jobs import run_job

CARD_DB, PAY_API, SERVER = "10.30.0.20", "10.30.0.21", "10.70.0.10"


class FakeFirewall:
    """Stands in for the log listener: records a log line for each attempt the 'firewall' decides about."""

    def __init__(self, logging_works):
        self.logging_works, self.events = logging_works, []

    def status(self):
        return {"firewall": {"listening": True, "connected": bool(self.events), "learned_sender": None}}

    def events_for(self, device_id):
        return list(self.events) if device_id == "firewall" else []

    def decide(self, host, port, protocol, action):
        if self.logging_works:
            self.events.append({"received_at": datetime.now(timezone.utc).isoformat(), "format": "iptables",
                                "action": action, "protocol": protocol, "source_ip": "10.50.0.23",
                                "destination_ip": host, "destination_port": port if protocol != "icmp" else None,
                                "rule": "SEGCHECK-ACCEPT legacy-reporting" if action == "pass" else "SEGCHECK-DROP"})


FIREWALLS = {
    "no-firewall": {"mode": "none"},
    "firewall-other-no-logs": {"mode": "firewall", "kind": "other", "firewall_ip": "10.50.0.1"},
    "firewall-logs-never-arrive": {"mode": "firewall", "kind": "iptables", "firewall_ip": "", "logs": "on"},
    "firewall-logs-working": {"mode": "firewall", "kind": "iptables", "firewall_ip": "10.50.0.1", "logs": "on"},
    "firewall-logs-and-rule-export": {"mode": "firewall", "kind": "iptables", "firewall_ip": "10.50.0.1", "logs": "on"},
}
RULES = ":FORWARD DROP [0:0]\n-A FORWARD -s 10.50.0.0/24 -d 10.30.0.20/32 -p tcp -m multiport --dports 5432 " \
        "-m comment --comment legacy-reporting -j ACCEPT\n"
OUTCOMES = {
    "all-silent": set(),
    "card-db-open": {(CARD_DB, 5432)},
    "everything-refused": "refused",
}
LAUNCHES = {
    "one-standard": {"mode": "standard", "pack": "pci-cde-isolation", "groups": ["database", "icmp"]},
    "several-standards": {"mode": "standard", "scope": "several", "pack": ["pci-cde-isolation", "nist-sc7-boundary"],
                          "groups": ["database", "icmp"]},
    "own-rules": {"mode": "custom", "r_target": ["text", "text"], "r_service": ["custom", "custom"],
                  "r_must": ["deny", "allow"], "r_protocol": ["tcp", "tcp"], "r_ports": ["5432", "445"],
                  "r_targets": [CARD_DB, SERVER], "r_reason": ["Card data stays isolated", "Staff need the file server"]},
}
BAD_TEXT = [b"None</", b">None<", b"undefined", b"Traceback", b"NaN", b"{{", b"}}", b"[object Object]"]


def _run(app, client, monkeypatch, firewall_key, outcome_key, launch_key):
    fake = FakeFirewall(logging_works=firewall_key in {"firewall-logs-working", "firewall-logs-and-rule-export"})
    monkeypatch.setattr("segcheck_web.services.audit_setup.free_udp_port", lambda ip, start=5514: 5514)
    monkeypatch.setattr("segcheck_web.services.firewall_connector.registry", lambda app: fake)
    monkeypatch.setattr("segcheck_web.services.firewall_connector.LOG_WAIT_SECONDS", 0)
    monkeypatch.setattr("segcheck_web.services.patience.LOG_GRACE", 0.05)
    monkeypatch.setattr("segcheck_web.services.patience.LOG_POLL", 0.01)
    open_doors = OUTCOMES[outcome_key]

    def answer(host, port, protocol):
        if open_doors == "refused":
            fake.decide(host, port, protocol, "pass")
            return ProbeOutcome("inconclusive", "connection_refused_service_may_be_closed; not proof of segmentation",
                                2.0, "10.50.0.23")
        if (host, port) in open_doors:
            fake.decide(host, port, protocol, "pass")
            return ProbeOutcome("reachable", "tcp_connect_succeeded", 3.0, "10.50.0.23")
        fake.decide(host, port, protocol, "block")
        reason = "connection_timeout; not proof of firewall filtering" if protocol == "tcp" else "icmp_no_echo_reply; not proof"
        return ProbeOutcome("inconclusive", reason, 1000.0, "10.50.0.23")

    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                        lambda host, port, timeout, *, source_ip: answer(host, port, "tcp"))
    monkeypatch.setattr("segcheck_web.services.assessment_execution.method_probe",
                        lambda protocol, host, port, timeout, *, source_ip: answer(host, port, protocol))
    started = []
    monkeypatch.setattr("segcheck_web.routes.audit.start_worker", lambda a, job_id: started.append(job_id))

    setup_audit(client)
    saved = post(client, "/audit/firewall", FIREWALLS[firewall_key])
    assert saved.status_code == 302
    if firewall_key == "firewall-logs-and-rule-export":
        post(client, "/audit/firewall/rules", {"export_text": RULES})
    launched = post(client, "/audit/launch", LAUNCHES[launch_key])
    assert "/jobs/" in launched.headers["Location"], client.get(launched.headers["Location"], base_url=BASE).data[-3000:]
    run_job(app, started[-1])
    with app.app_context():
        job = db.session.get(AssessmentJob, started[-1])
        if firewall_key == "firewall-logs-never-arrive" and outcome_key == "all-silent" and launch_key != "own-rules":
            # Logs were set up, none arrived and nothing answered: the run stops early and says what to fix.
            assert job.status == "failed" and job.assessment_id is None, job.message
            assert job.message.startswith("Stopped early after") and "Step 3b" in job.message and "No report was saved" in job.message
            return None, fake
        assert job.status == "completed", job.message
        return job.assessment_id, fake


@pytest.mark.parametrize("launch_key", LAUNCHES)
@pytest.mark.parametrize("outcome_key", OUTCOMES)
@pytest.mark.parametrize("firewall_key", FIREWALLS)
def test_every_setup_gives_a_complete_and_correct_report(app, authenticated_client, local, monkeypatch,
                                                         firewall_key, outcome_key, launch_key):
    assessment_id, fake = _run(app, authenticated_client, monkeypatch, firewall_key, outcome_key, launch_key)
    if assessment_id is None:
        return  # stopped early on purpose (checked in _run)
    page = authenticated_client.get(f"/assessments/{assessment_id}", base_url=BASE)
    assert page.status_code == 200
    body = page.data
    for bad in BAD_TEXT:
        assert bad not in body, (bad, firewall_key, outcome_key, launch_key)
    text = body.decode("utf-8")
    proven = firewall_key in {"firewall-logs-working", "firewall-logs-and-rule-export"}

    # The verdict at the top must match what happened, and never claim proof without logs.
    if outcome_key == "card-db-open":
        assert "FAILED" in text and "5432" in text
        if firewall_key == "firewall-logs-and-rule-export":
            assert "legacy-reporting" in text, "the rule behind the hole is named"
    elif outcome_key == "all-silent" and launch_key != "own-rules":
        if proven:
            assert "Blocked, and proven" in text or "PASSED" in text
        else:
            assert "not proven" in text and "Blocked, and proven" not in text, "silence without logs is never proof"
    if not proven:
        assert "proven by firewall log" not in text

    # What limited the run is said at the top, with what to do.
    if firewall_key == "firewall-logs-never-arrive":
        assert "The firewall&#39;s logs did not arrive" in text and "What to do:" in text
    with app.app_context():
        view = report_view.build(db.session.get(Assessment, assessment_id).report)
    if firewall_key in {"no-firewall", "firewall-other-no-logs"} and view["counts"]["unproven"]:
        assert "Problems in this run" in text and "What to do:" in text, "unproven results always say how to get proof"
    if firewall_key in {"no-firewall", "firewall-other-no-logs"} and not view["counts"]["unproven"]:
        assert not [p for p in view["problems"] if p["tone"] == "fix"], "nothing to fix when every result is definite"
    if proven and outcome_key != "everything-refused":
        assert "Problems in this run" not in text, "a clean, proven run has nothing to fix"

    # Own rules: the reason and both directions are explained.
    if launch_key == "own-rules":
        assert "Card data stays isolated" in text and "Staff need the file server" in text

    # Several standards: one verdict per standard.
    if launch_key == "several-standards":
        assert "Verdict per standard" in text

    # Every attempt carries a plain-language explanation, and the exports work.
    assert "Every attempt explained" in text
    pdf = authenticated_client.get(f"/assessments/{assessment_id}/report.pdf", base_url=BASE)
    assert pdf.status_code == 200 and pdf.data[:4] == b"%PDF"
    data = authenticated_client.get(f"/assessments/{assessment_id}/report.json", base_url=BASE)
    assert data.status_code == 200 and data.get_json()["results"]


@pytest.mark.parametrize("step3", [None, {"mode": ""}, {"mode": "firewall", "kind": "nonsense"},
                                   {"mode": "firewall", "kind": "iptables", "firewall_ip": "not-an-ip"}])
def test_half_finished_setup_cannot_launch_and_says_what_is_missing(app, authenticated_client, local, monkeypatch, step3):
    monkeypatch.setattr("segcheck_web.services.audit_setup.free_udp_port", lambda ip, start=5514: 5514)
    started = []
    monkeypatch.setattr("segcheck_web.routes.audit.start_worker", lambda a, job_id: started.append(job_id))
    assert post(authenticated_client, "/audit/here", {"name": "HR", "type": "hr", "cidr": "10.50.0.0/24",
                                                      "ip": "10.50.0.23", "organization": "PaySecure"}).status_code == 302
    post(authenticated_client, "/audit/targets", {"t_name": ["Card systems"], "t_cidr": ["10.30.0.0/24"], "t_type": ["cde"],
                                                  "t_hosts": [CARD_DB]})
    if step3 is not None:
        page = authenticated_client.get(post(authenticated_client, "/audit/firewall", step3).headers["Location"],
                                        base_url=BASE).data
        assert b"flash-error" in page, "a wrong Step 3 is refused with a message"
    launched = post(authenticated_client, "/audit/launch", {"mode": "standard", "pack": "pci-cde-isolation"})
    page = authenticated_client.get(launched.headers["Location"], base_url=BASE).data
    assert not started, "nothing runs on a half-finished setup"
    assert b"flash-error" in page and (b"Step 3" in page or b"Finish Steps 1" in page)
