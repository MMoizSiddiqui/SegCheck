"""Analyst report layer, PDF layout and legacy-correlator ICMP handling."""
import base64
import re
import types
import zlib
from datetime import datetime

import yaml

from test_environment_workflow import app, configure, get_token
from test_packs_and_boundaries import cde_role
from segcheck.probe import ProbeOutcome
from segcheck_web.extensions import db
from segcheck_web.models import Assessment, User
from segcheck_web.services.assessment_jobs import create_job, run_job
from segcheck_web.services.assessment_pdf import generate_assessment_pdf
from segcheck_web.services.assessment_plan import build_plan
from segcheck_web.services.environment import settings
from segcheck_web.services.policy_import import import_policy_content
from segcheck_web.services.report_analysis import analyse
from segcheck_web.services.standard_packs import build_pack_documents


def row(check_id, result, protocol="tcp", ports=(22, 23, 3389, 5900, 5985, 5986), expected="deny", mappings=None):
    return {"check_id": check_id, "check_name": f"guest must not reach CDE {check_id}", "source_zone": "guest", "destination_zone": "cde",
            "destination_host": "10.30.0.10", "protocol": protocol, "ports": list(ports), "expected": expected, "result": result,
            "framework_mappings": mappings or [{"framework": "pci_dss", "version": "4.0.1", "control_id": "11.4.5", "title": "Segmentation", "relationship": "supporting"}],
            "pci_requirements": ["11.4.5"]}


def evidence(*pairs):
    return {"attempts": [{"check_id": check_id, "evidence": state} for check_id, state in pairs], "summary": {}, "note": "n"}


def test_violation_summary_and_specific_guidance():
    report = {"results": [row("C1", "FAIL"), row("C2", "INCONCLUSIVE", "icmp", ())],
              "probe_measurement": {"details": [{"check_id": "C1", "observed": "reachable", "port": 3389}]},
              "boundary_evidence": evidence(("C1", "logged_pass"), ("C2", "logged_block")),
              "assessment": {"source_zone": "guest", "scope": {"not_evaluated_check_ids": []}}}
    analysis = analyse(report, {"cde": {"role": "cde"}})
    assert analysis["status"] == "violation" and analysis["counts"]["fail"] == 1
    assert "in scope" in analysis["meaning"] and "11.4.5" in analysis["meaning"]
    first = analysis["checks"][0]
    assert first["method"] == "remote_admin" and "jump host" in first["guidance"][0]
    assert "passed this traffic" in first["guidance"][1]
    assert analysis["findings"][0]["level"] == "critical" and "3389" in analysis["findings"][0]["text"]
    assert analysis["checks"][1]["method"] == "icmp" and analysis["checks"][1]["evidence"] == "corroborated"


def test_enforced_unproven_and_open_boundary_states():
    enforced = analyse({"results": [row("C1", "INCONCLUSIVE")], "boundary_evidence": evidence(("C1", "logged_block"))})
    assert enforced["status"] == "enforced" and "strong segmentation-test evidence" in enforced["meaning"]
    unproven = analyse({"results": [row("C1", "INCONCLUSIVE")]})
    assert unproven["status"] == "unproven" and "firewall evidence" in unproven["checks"][0]["guidance"][0]
    open_boundary = analyse({"results": [row("C1", "INCONCLUSIVE")], "boundary_evidence": evidence(("C1", "logged_pass"))})
    assert open_boundary["status"] == "violation" and open_boundary["counts"]["open_boundary"] == 1
    assert "deny rule is missing" in open_boundary["checks"][0]["guidance"][0]


def test_control_matrix_heatmap_and_not_exercised():
    report = {"results": [row("C1", "INCONCLUSIVE"), row("C2", "INCONCLUSIVE", ports=(1433, 1521, 3306, 5432, 6379, 27017)),
                          {**row("C3", "INCONCLUSIVE"), "source_zone": "corporate"}],
              "boundary_evidence": evidence(("C1", "logged_block"), ("C2", "logged_block")),
              "assessment": {"scope": {"not_evaluated_check_ids": ["C3"]}}}
    analysis = analyse(report)
    control = analysis["controls"][0]
    assert control["control_id"] == "11.4.5" and control["checks"] == 3 and control["corroborated"] == 2 and control["NOT EXERCISED"] == 1
    assert [method["label"] for method in analysis["methods"]] == ["Remote admin", "Databases"]
    assert analysis["heatmap"][0]["cells"][0]["result"] == "NOT EXERCISED" or analysis["checks"][2]["result"] == "NOT EXERCISED"
    assert "probe in another zone" in analysis["findings"][-1]["text"]


def test_legacy_reports_without_new_fields_still_analyse():
    analysis = analyse({"results": [{"check_id": "X", "result": "PASS", "expected": "allow", "protocol": "tcp", "ports": [443]}], "assessment": {"scope": "legacy"}})
    assert analysis["checks"][0]["method_label"] == "TCP 443" and analysis["counts"]["exercised"] == 1


def _pdf_text(pdf):
    text = b""
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        chunk = match.group(1).strip()
        try:
            if chunk.endswith(b"~>"):
                chunk = base64.a85decode(chunk if chunk.startswith(b"<~") else b"<~" + chunk, adobe=True)
            chunk = zlib.decompress(chunk)
        except Exception:
            pass
        text += chunk
    return text


def _run_pack(app, monkeypatch, outcome):
    monkeypatch.setattr("segcheck_web.services.assessment_plan.source_address_available", lambda _: True)
    with app.app_context():
        configure()
        cde_role()
        _pack, documents = build_pack_documents("pci-cde-isolation", settings()[1])
        policy = import_policy_content(yaml.safe_dump(documents[0], sort_keys=False).encode())
        policy.status = "active"
        db.session.commit()
        version = policy.versions[0]
        job, _ = create_job(version, build_plan(version, "active"), db.session.query(User).one().id, "analysis-token")
        job_id = job.id
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                        lambda host, port, timeout, *, source_ip: ProbeOutcome(outcome(port), "stub", .2, source_ip))
    monkeypatch.setattr("segcheck_web.services.assessment_execution.method_probe",
                        lambda protocol, host, port, timeout, *, source_ip: ProbeOutcome("inconclusive", f"{protocol}_stub", .2, source_ip))
    run_job(app, job_id)
    with app.app_context():
        from segcheck_web.models.jobs import AssessmentJob
        return db.session.get(AssessmentJob, job_id).assessment_id


def test_report_page_and_pdf_contain_analyst_sections(app, authenticated_client, monkeypatch):
    assessment_id = _run_pack(app, monkeypatch, lambda port: "reachable" if port == 3389 else "inconclusive")
    page = authenticated_client.get(f"/assessments/{assessment_id}", base_url="https://localhost").get_data(as_text=True)
    for marker in ("FAILED", "Rule by rule", "Summary and what to fix", "Segmentation violation", "Method coverage heatmap", "Control matrix",
                   "Analyst guidance", "jump host", 'id="check-PCI-001"', "What to do:", "PCI DSS 4.0.1 segmentation test"):
        assert marker in page
    with app.app_context():
        record = db.session.get(Assessment, assessment_id)
        pdf = generate_assessment_pdf(record)
    text = _pdf_text(pdf)
    for marker in (b"Executive summary", b"Result in plain words", b"FAILED", b"ACTION REQUIRED", b"Control matrix", b"Method coverage heatmap", b"Check results and analyst guidance", b"Appendix: audit trail", b"SHA-256 of the JSON file"):
        assert marker in text
    assert len(re.findall(rb"/Type /Page\b(?!s)", pdf)) <= 12


def test_icmp_checks_skip_the_legacy_correlator(app, authenticated_client, monkeypatch):
    seen = {}

    def fake_correlate(*args, _probe_data, _policy):
        seen["protocols"] = {check.protocol for check in _policy.checks}
        seen["detail_protocols"] = {detail["protocol"] for detail in _probe_data["measurement"]["details"]}
        return {"probe_run_id": _probe_data["measurement"]["run_id"], "probe_source_zone": "guest"}

    def fake_attach(report, correlation, policy, source_zone):
        seen["attached_checks"] = {check.id for check in policy.checks}
        return {"status": "configured", "total": 0, "corroborated": 0, "contradictory": 0, "ambiguous": 0,
                "no_matching_evidence": 0, "inconclusive": 0, "not_evaluated": 0}

    monkeypatch.setattr("segcheck_web.services.assessment_execution.correlate_probe", fake_correlate)
    monkeypatch.setattr("segcheck_web.services.assessment_execution._attach_correlated_evidence", fake_attach)
    app.config["SEGCHECK_EVIDENCE_CONFIG_PATH"] = "/trusted/evidence.yaml"
    app.config["SEGCHECK_EVIDENCE_EVENTS_PATH"] = "/trusted/events.jsonl"
    assessment_id = _run_pack(app, monkeypatch, lambda port: "inconclusive")
    assert assessment_id is not None
    assert "icmp" not in seen["protocols"] and "icmp" not in seen["detail_protocols"]
    assert seen["protocols"] == {"tcp", "udp"} and len(seen["attached_checks"]) == 5




def test_heatmap_never_hides_a_fail_behind_other_source_zones():
    fail = row("CORP-04", "FAIL", ports=(5432,))
    other = {**row("GUEST-02", "INCONCLUSIVE", ports=(5432,)), "source_zone": "guest"}
    report = {"results": [fail, other], "assessment": {"scope": {"not_evaluated_check_ids": ["GUEST-02"]}}}
    analysis = analyse(report)
    cells = [cell for target in analysis["heatmap"] for cell in target["cells"] if cell]
    assert [cell["result"] for cell in cells] == ["FAIL"]
    assert analysis["counts"]["not_exercised"] == 1


def test_allowed_flows_do_not_hide_an_enforced_deny_and_outages_are_findings():
    base = {"probe_measurement": {"details": []}, "assessment": {"source_zone": "hr", "scope": {"not_evaluated_check_ids": []}}}
    report = {**base, "results": [row("A1", "PASS", expected="allow"), row("D1", "INCONCLUSIVE")],
              "boundary_evidence": evidence(("A1", "logged_pass"), ("D1", "logged_block"))}
    analysis = analyse(report, {"cde": {"role": "cde"}})
    assert analysis["status"] == "enforced" and "1 approved flow(s) work" in analysis["meaning"]
    down = {**base, "results": [row("A1", "INCONCLUSIVE", expected="allow"), row("D1", "INCONCLUSIVE")],
            "boundary_evidence": evidence(("A1", "logged_block"), ("D1", "logged_block"))}
    analysis = analyse(down, {"cde": {"role": "cde"}})
    assert analysis["status"] == "attention" and analysis["counts"]["allowed_down"] == 1  # matches the top verdict
    assert any("Approved flow not working" in finding["text"] for finding in analysis["findings"])
