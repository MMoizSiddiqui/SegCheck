"""Standards packs, multi-method probes, boundary devices and the read-only log connector."""
import socket
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from werkzeug.datastructures import MultiDict

from test_environment_workflow import app, configure, declare_boundary, form, get_token, post
from segcheck.policy_engine import PolicyValidationError, validate_policy_data
from segcheck.probe import ProbeOutcome, icmp_echo_probe, probe_points, udp_request_probe
from segcheck_web.extensions import db
from segcheck_web.models import Asset, Policy, User
from segcheck_web.services.assessment_jobs import create_job, run_job
from segcheck_web.services.assessment_plan import build_plan
from segcheck_web.services.environment import EnvironmentError, save_asset, save_device, save_zone, settings
from segcheck_web.services.firewall_connector import ConnectorRegistry, cross_check, parse_firewall_line
from segcheck_web.services.policy_import import import_policy_content
from segcheck_web.services.standard_packs import PACKS_BY_KEY, PackError, build_pack_documents, evaluate_pack


def cde_role(revision=4):
    save_zone(form(zone_key="cde", name="CDE", cidr="10.30.0.0/24", role="cde", revision=revision))


# ----------------------------------------------------------------- schema / probes
def test_icmp_checks_are_portless_and_count_one_attempt():
    policy = validate_policy_data({"schema_version": 1, "policy_id": "P-1", "name": "n", "organization": "o", "pci_dss_version": "4.0.1",
        "zones": [{"id": "za", "name": "A"}, {"id": "zb", "name": "B"}],
        "checks": [{"id": "C1", "name": "ping", "source_zone": "za", "destination_zone": "zb", "destination_host": "192.0.2.1",
                    "protocol": "icmp", "expected": "deny", "rationale": "r"}]})
    assert policy.checks[0].ports == () and probe_points(policy.checks[0]) == (0,)
    with pytest.raises(PolicyValidationError, match="empty or omitted"):
        validate_policy_data({"schema_version": 1, "policy_id": "P-2", "name": "n", "organization": "o", "pci_dss_version": "4.0.1",
            "zones": [{"id": "za", "name": "A"}, {"id": "zb", "name": "B"}],
            "checks": [{"id": "C1", "name": "ping", "source_zone": "za", "destination_zone": "zb", "destination_host": "192.0.2.1",
                        "protocol": "icmp", "ports": [443], "expected": "deny", "rationale": "r"}]})


def test_udp_probe_only_counts_a_real_reply_as_reachable():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    import threading
    def echo():
        data, peer = server.recvfrom(4096)
        server.sendto(b"reply:" + data[:8], peer)
    threading.Thread(target=echo, daemon=True).start()
    outcome = udp_request_probe("127.0.0.1", port, 1.0)
    server.close()
    assert outcome.state == "reachable" and "reply_received" in outcome.reason
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    outcome = udp_request_probe("127.0.0.1", silent.getsockname()[1], 0.3)
    silent.close()
    assert outcome.state == "inconclusive"


def test_icmp_probe_requires_an_echo_reply(monkeypatch):
    import subprocess
    replies = {"ok": "Reply from 192.0.2.1: bytes=32 time<1ms TTL=64", "unreach": "Reply from 192.0.2.254: Destination host unreachable."}
    for key, expected in (("ok", "reachable"), ("unreach", "inconclusive")):
        monkeypatch.setattr(subprocess, "run", lambda *a, _k=key, **kw: subprocess.CompletedProcess(a, 0, replies[_k], ""))
        assert icmp_echo_probe("192.0.2.1", 0, 1.0).state == expected


# ----------------------------------------------------------------- boundary devices
def test_cross_zone_path_requires_a_declared_boundary(app):
    with app.app_context():
        from test_environment_workflow import save_profile, policy_data, import_example
        save_zone(form(zone_key="guest", name="Guest", cidr="10.20.0.0/24", revision=0))
        save_zone(form(zone_key="cde", name="CDE", cidr="10.30.0.0/24", revision=1))
        save_asset(form(zone_key="cde", name="Payment", address="10.30.0.10"))
        save_profile(form(organization="Bank", site="HQ", source_zone="guest", source_ip="10.20.0.100", revision=2))
        version = import_example()
        plan = build_plan(version, "active", check_local_address=False)
        assert not plan["ready"] and any("Do Step 3 (Firewall)" in item for item in plan["blockers"])
        declare_boundary(revision=3)
        plan = build_plan(version, "active", check_local_address=False)
        assert plan["ready"] and plan["rows"][0]["boundary"][0]["name"] == "Lab firewall"


def test_device_validation_and_interface_asset(app):
    with app.app_context():
        configure()
        bad = MultiDict({"name": "FW", "kind": "pfsense", "revision": "4", "zones": "guest"})
        with pytest.raises(EnvironmentError, match="at least two"):
            save_device(bad)
        bad = MultiDict([("name", "FW"), ("kind", "pfsense"), ("revision", "4"), ("zones", "guest"), ("zones", "cde"),
                         ("logging", "on"), ("log_sender_ip", "10.20.0.1"), ("log_port", "514")])
        with pytest.raises(EnvironmentError, match="1024"):
            save_device(bad)
        good = MultiDict([("name", "Edge FW"), ("kind", "pfsense"), ("revision", "4"), ("zones", "guest"), ("zones", "cde"),
                          ("interface_ip", "10.20.0.1"), ("logging", "on"), ("log_sender_ip", "10.20.0.1"), ("log_port", "5514")])
        save_device(good)
        devices = settings()[1]["devices"]
        assert {device["id"] for device in devices} == {"lab-firewall", "edge-fw"}
        assert db.session.query(Asset).filter_by(address="10.20.0.1").one().name == "Edge FW interface"


# ----------------------------------------------------------------- packs
def test_pci_pack_generates_every_method_for_each_cde_asset(app):
    with app.app_context():
        configure()
        cde_role()
        save_asset(form(zone_key="cde", name="Payment DB", address="10.30.0.20"))
        environment = settings()[1]
        status = evaluate_pack(PACKS_BY_KEY["pci-cde-isolation"], environment)
        assert status["ready"] and len(status["targets"]) == 2 and status["attempts"] == 2 * (6 + 6 + 4 + 5 + 3 + 1)
        pack, documents = build_pack_documents("pci-cde-isolation", environment)
        checks = documents[0]["checks"]
        assert {check["protocol"] for check in checks} == {"tcp", "udp", "icmp"}
        assert all(check["expected"] == "deny" for check in checks)
        assert all(any(mapping["control_id"] == "11.4.5" for mapping in check["framework_mappings"]) for check in checks)
        for document in documents:
            policy = import_policy_content(yaml.safe_dump(document, sort_keys=False).encode())
            assert policy.status == "draft"


def test_packs_explain_why_they_are_not_ready(app):
    with app.app_context():
        configure()
        environment = settings()[1]
        assert "CDE zone" in evaluate_pack(PACKS_BY_KEY["pci-cde-isolation"], environment)["reason"]
        assert "inside a CDE" in evaluate_pack(PACKS_BY_KEY["pci-cde-egress"], environment)["reason"]
        with pytest.raises(PackError):
            build_pack_documents("pci-cde-egress", environment)


def test_large_packs_split_at_the_attempt_limit(app):
    with app.app_context():
        configure()
        cde_role()
        for index in range(2, 22):  # 21 CDE hosts x 25 attempts = 525, above the 400 per run
            save_asset(form(zone_key="cde", name=f"CDE host {index}", address=f"10.30.0.{index + 10}"))
        _pack, documents = build_pack_documents("pci-cde-isolation", settings()[1])
        assert len(documents) > 1
        for document in documents:
            cost = sum(max(1, len(check.get("ports", []))) for check in document["checks"])
            assert cost <= 400
        assert len({document["policy_id"] for document in documents}) == len(documents)




def test_multi_method_job_records_protocols_and_boundary_evidence(app, authenticated_client, monkeypatch):
    monkeypatch.setattr("segcheck_web.services.assessment_plan.source_address_available", lambda _: True)
    with app.app_context():
        configure()
        cde_role()
        _pack, documents = build_pack_documents("pci-cde-isolation", settings()[1])
        policy = import_policy_content(yaml.safe_dump(documents[0], sort_keys=False).encode())
        policy.status = "active"
        db.session.commit()
        version = policy.versions[0]
        actor = db.session.query(User).one()
        job, _ = create_job(version, build_plan(version, "active"), actor.id, "pack-token")
        job_id = job.id
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                        lambda host, port, timeout, *, source_ip: ProbeOutcome("reachable" if port == 443 else "inconclusive", "stub", .3, source_ip))
    monkeypatch.setattr("segcheck_web.services.assessment_execution.method_probe",
                        lambda protocol, host, port, timeout, *, source_ip: ProbeOutcome("inconclusive", f"{protocol}_stub", .3, source_ip))
    run_job(app, job_id)
    with app.app_context():
        from segcheck_web.models.jobs import AssessmentJob
        from segcheck_web.models import Assessment
        job = db.session.get(AssessmentJob, job_id)
        assert job.status == "completed" and job.total == 25
        assert {event["protocol"] for event in job.events} == {"tcp", "udp", "icmp"}
        report = db.session.get(Assessment, job.assessment_id).report
        verdicts = {row["check_id"]: row["result"] for row in report["results"]}
        assert "FAIL" in verdicts.values()  # web check reached 443
        evidence = report["boundary_evidence"]
        assert evidence["summary"]["not_connected"] == 25
        assert "a logged block proves" in evidence["note"] and "unauthenticated" in evidence["note"]


# ----------------------------------------------------------------- log connector
PF_BLOCK = "<134>Nov 12 10:00:00 pfSense filterlog[123]: 5,,,1791895687,em2,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,10.20.0.100,10.30.0.10,51515,8080,0,S,1,,64240,,mss"
IPT_DROP = "<4>Nov 12 10:00:00 gw kernel: SEGCHECK-DROP IN=eth1 OUT=eth2 MAC=aa SRC=10.20.0.100 DST=10.30.0.10 LEN=60 TOS=0x00 PROTO=TCP SPT=40000 DPT=22 WINDOW=64240 SYN"
IPT_ICMP = "<4>Nov 12 10:00:00 gw kernel: SEGCHECK-ACCEPT IN=eth1 OUT=eth2 SRC=10.20.0.100 DST=10.30.0.10 LEN=84 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1"


def test_log_parsers_extract_decisions():
    pf = parse_firewall_line(PF_BLOCK)
    assert pf["action"] == "block" and pf["destination_port"] == 8080 and pf["protocol"] == "tcp"
    ipt = parse_firewall_line(IPT_DROP)
    assert ipt["action"] == "block" and ipt["destination_port"] == 22 and ipt["source_ip"] == "10.20.0.100"
    icmp = parse_firewall_line(IPT_ICMP)
    assert icmp["action"] == "pass" and icmp["protocol"] == "icmp" and icmp["destination_port"] is None
    assert parse_firewall_line("hello world") is None


def test_cross_check_interprets_firewall_decisions():
    now = datetime.now(timezone.utc)
    environment = {"devices": [{"id": "fw", "name": "FW", "kind": "pfsense", "zones": ["guest", "cde"], "logging": True}]}
    registry = ConnectorRegistry()

    class FakeListener:
        listening, device = True, {"id": "fw", "name": "FW", "kind": "pfsense"}
        events = [{"received_at": now.isoformat(), **parse_firewall_line(PF_BLOCK)},
                  {"received_at": now.isoformat(), **parse_firewall_line(IPT_ICMP)}]
        def status(self):
            return {"listening": True}
    registry.listeners["fw"] = FakeListener()

    def detail(protocol, port, observed):
        return {"check_id": "C1", "source_zone": "guest", "destination_zone": "cde", "destination_host": "10.30.0.10",
                "source_ip": "10.20.0.100", "protocol": protocol, "port": port, "observed": observed,
                "started_at": (now - timedelta(milliseconds=200)).isoformat(), "completed_at": now.isoformat()}
    result = cross_check([detail("tcp", 8080, "inconclusive"), detail("icmp", 0, "inconclusive"),
                          detail("tcp", 443, "reachable"), detail("tcp", 8080, "reachable")], environment, registry, wait=False)
    evidence = [row["evidence"] for row in result["attempts"]]
    assert evidence == ["logged_block", "logged_pass", "no_matching_log", "logged_block"]
    assert result["summary"]["contradictions"] == 1 and result["summary"]["open_at_boundary"] == 1
    assert "corroborated" in result["attempts"][0]["interpretation"]


def test_listener_accepts_only_the_declared_sender():
    from segcheck_web.services.firewall_connector import DeviceListener
    import time
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    listener = DeviceListener({"id": "fw", "name": "FW", "kind": "iptables", "log_port": port, "log_sender_ip": "127.0.0.2"}, "127.0.0.1", None)
    listener.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(IPT_DROP.encode(), ("127.0.0.1", port))
        for _ in range(20):
            if listener.stats["received"]:
                break
            time.sleep(0.05)
        assert listener.stats["rejected_sender"] == 1 and listener.stats["parsed"] == 0
    finally:
        listener.stop()


def test_device_log_listener_can_use_a_fixed_address(app, monkeypatch):
    with app.app_context():
        configure()
        monkeypatch.setattr("segcheck_web.services.environment.source_address_available", lambda ip: ip == "10.20.0.100")
        bad = MultiDict([("name", "Core FW"), ("kind", "iptables"), ("revision", "4"), ("zones", "guest"), ("zones", "cde"),
                         ("logging", "on"), ("log_sender_ip", "10.20.0.1"), ("log_port", "5514"), ("log_listen_ip", "10.99.0.5")])
        with pytest.raises(EnvironmentError, match="must be an address of this PC"):
            save_device(bad)
        good = MultiDict([("name", "Core FW"), ("kind", "iptables"), ("revision", "4"), ("zones", "guest"), ("zones", "cde"),
                          ("logging", "on"), ("log_sender_ip", "10.20.0.1"), ("log_port", "5514"), ("log_listen_ip", "10.20.0.100")])
        save_device(good)
        device = next(d for d in settings()[1]["devices"] if d["id"] == "core-fw")
        assert device["log_listen_ip"] == "10.20.0.100"
    started = []
    monkeypatch.setattr("segcheck_web.services.firewall_connector.DeviceListener.start", lambda self: started.append(self.bind_ip))
    registry = ConnectorRegistry()
    registry.sync({"source_ip": "10.40.0.100", "devices": [dict(device)]}, None)
    assert started == ["10.20.0.100"]  # fixed listen address wins over the moving probe IP
