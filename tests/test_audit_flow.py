"""The guided audit end to end: Step 1-4, discovery, firewall, launch, and history deletion."""
import re

import pytest

from test_environment_workflow import app, get_token  # noqa: F401
from segcheck.probe import ProbeOutcome
from segcheck_web.extensions import db
from segcheck_web.models import Assessment, Asset, Policy, User, Zone
from segcheck_web.models.jobs import AssessmentJob, AssessmentLease
from segcheck_web.services import audit_setup, history
from segcheck_web.services.assessment_jobs import run_job
from segcheck_web.services.environment import settings

BASE = "https://localhost"


@pytest.fixture
def local(monkeypatch):
    """Pretend 10.50.0.23 is this PC's address; nothing is sent anywhere."""
    monkeypatch.setattr("segcheck_web.services.environment.source_address_available", lambda ip: ip == "10.50.0.23")
    monkeypatch.setattr("segcheck_web.services.assessment_plan.source_address_available", lambda ip: ip == "10.50.0.23")
    monkeypatch.setattr("segcheck_web.routes.audit._detected", lambda: [
        {"interface": "Ethernet", "source_ip": "10.50.0.23", "cidr": "10.50.0.0/24", "gateway": "10.50.0.1", "family": "IPv4"}])


@pytest.fixture
def no_worker(monkeypatch):
    started = []
    monkeypatch.setattr("segcheck_web.routes.audit.start_worker", lambda app, job_id: started.append(job_id))
    return started


def post(client, path, data):
    token = get_token(client, "/audit/")
    return client.post(path, data={"csrf_token": token, **data}, base_url=BASE, headers={"Referer": BASE + "/audit/"})


def setup_audit(client, firewall="none"):
    assert post(client, "/audit/here", {"name": "HR department", "type": "hr", "cidr": "10.50.0.0/24",
                                        "ip": "10.50.0.23", "gateway": "10.50.0.1", "organization": "PaySecure"}).status_code == 302
    post(client, "/audit/targets", {"t_name": ["Card systems", "Servers", ""], "t_cidr": ["10.30.0.0/24", "", ""],
                                    "t_type": ["cde", "server", "custom"], "t_hosts": ["10.30.0.20 10.30.0.21", "10.70.0.10", ""]})
    post(client, "/audit/firewall", {"mode": firewall})


# ---------------- access control ----------------

@pytest.mark.parametrize("method,path", [("get", "/audit/"), ("post", "/audit/here"), ("post", "/audit/targets"),
                                         ("post", "/audit/firewall"), ("post", "/audit/launch"), ("get", "/audit/firewall/status"),
                                         ("get", "/assessments/"), ("post", "/assessments/delete-all")])
def test_every_audit_page_requires_sign_in(app, method, path):
    response = getattr(app.test_client(), method)(path, base_url=BASE)
    assert response.status_code in {302, 400} and (response.status_code == 400 or "/login" in response.headers["Location"])


def test_forms_need_a_valid_csrf_token(app, authenticated_client, local):
    response = authenticated_client.post("/audit/here", data={"name": "x"}, base_url=BASE, headers={"Referer": BASE + "/audit/"})
    assert response.status_code == 400 and b"This form expired" in response.data


def test_deactivated_account_loses_its_session(app, authenticated_client, local):
    with app.app_context():
        db.session.query(User).one().is_active = False
        db.session.commit()
    response = authenticated_client.get("/audit/", base_url=BASE)
    assert response.status_code == 302 and "/login" in response.headers["Location"]


# ---------------- Step 1 ----------------

def test_step1_uses_this_pcs_network_and_explains_mistakes(app, authenticated_client, local):
    page = authenticated_client.get("/audit/", base_url=BASE).data
    assert b"Step 1" in page and b"10.50.0.23" in page and b"Step 4" in page
    bad = post(authenticated_client, "/audit/here", {"name": "HR", "cidr": "10.50.0.0/24", "ip": "10.60.0.5", "type": "hr"})
    page = authenticated_client.get(bad.headers["Location"], base_url=BASE).data
    assert b"is not inside 10.50.0.0/24" in page
    post(authenticated_client, "/audit/here", {"name": "HR department", "cidr": "10.50.0.0/24", "ip": "10.50.0.23", "type": "hr"})
    with app.app_context():
        _, payload = settings()
        assert payload["source_ip"] == "10.50.0.23" and payload["networks"][payload["source_zone"]]["role"] == "hr"


# ---------------- Step 2 ----------------

def test_step2_adds_several_networks_at_once_and_derives_the_subnet(app, authenticated_client, local):
    setup_audit(authenticated_client)
    with app.app_context():
        _, payload = settings()
        networks = {zone.name: payload["networks"][zone.zone_key] for zone in db.session.query(Zone).all()}
        assert networks["Card systems"]["role"] == "cde" and networks["Servers"]["cidr"] == "10.70.0.0/24"
        assert {a.address for a in db.session.query(Asset).all()} >= {"10.30.0.20", "10.30.0.21", "10.70.0.10"}


def test_step2_errors_are_specific_and_nothing_half_saved(app, authenticated_client, local):
    setup_audit(authenticated_client)
    response = post(authenticated_client, "/audit/targets", {"t_name": ["Bad"], "t_cidr": [""], "t_type": ["custom"], "t_hosts": ["10.30.0.x"]})
    page = authenticated_client.get(response.headers["Location"], base_url=BASE).data
    assert b"Not an IP address: 10.30.0.x" in page
    response = post(authenticated_client, "/audit/targets", {"t_name": ["Overlap"], "t_cidr": ["10.30.0.0/16"], "t_type": ["custom"], "t_hosts": [""]})
    assert b"overlaps Card systems (10.30.0.0/24), a target network already added" in authenticated_client.get(
        response.headers["Location"], base_url=BASE).data


def test_step2_names_are_escaped_and_hosts_can_be_removed(app, authenticated_client, local):
    setup_audit(authenticated_client)
    post(authenticated_client, "/audit/targets", {"t_name": ["<script>x</script>"], "t_cidr": ["10.90.0.0/24"], "t_type": ["custom"], "t_hosts": ["10.90.0.5"]})
    page = authenticated_client.get("/audit/", base_url=BASE).data
    assert b"<script>x</script>" not in page and b"&lt;script&gt;" in page
    with app.app_context():
        host = db.session.query(Asset).filter_by(address="10.90.0.5").one()
        key = host.zone.zone_key
    post(authenticated_client, f"/audit/hosts/{host.id}/remove", {})
    post(authenticated_client, f"/audit/targets/{key}/remove", {})
    with app.app_context():
        assert db.session.query(Asset).filter_by(address="10.90.0.5").count() == 0
        assert key not in settings()[1]["networks"]


def test_known_hosts_and_ping_sweep_stay_inside_the_target_network(app, authenticated_client, local, monkeypatch):
    setup_audit(authenticated_client)
    monkeypatch.setattr("segcheck_web.services.target_discovery.neighbour_table",
                        lambda: {"10.30.0.20": "aa:bb:cc:00:00:01", "10.30.0.99": "aa:bb:cc:00:00:02", "192.168.1.1": "aa:bb:cc:00:00:03"})
    monkeypatch.setattr("segcheck_web.services.target_discovery._names", lambda addresses: {})
    with app.app_context():
        key = next(z.zone_key for z in db.session.query(Zone).all() if z.name == "Card systems")
    known = authenticated_client.get(f"/audit/targets/{key}/known", base_url=BASE)
    assert known.headers["Cache-Control"] == "no-store"
    assert [h["address"] for h in known.get_json()["hosts"]] == ["10.30.0.20", "10.30.0.99"]
    pinged = []
    monkeypatch.setattr("segcheck_web.services.target_discovery.icmp_echo_probe",
                        lambda host, port, timeout, source_ip=None: pinged.append(host) or ProbeOutcome(
                            "reachable" if host == "10.30.0.7" else "inconclusive", "test", 1.0, source_ip))
    token = get_token(authenticated_client, "/audit/")
    swept = authenticated_client.post(f"/audit/targets/{key}/sweep", data={"csrf_token": token},
                                      base_url=BASE, headers={"Referer": BASE + "/audit/"}).get_json()
    assert swept["pinged"] == 254 and len(pinged) == 254 and all(p.startswith("10.30.0.") for p in pinged)
    assert {h["address"] for h in swept["hosts"]} == {"10.30.0.7", "10.30.0.20", "10.30.0.99"}


def test_ping_sweep_refuses_networks_larger_than_a_slash_24():
    from segcheck_web.services.target_discovery import DiscoveryError, ping_sweep
    with pytest.raises(DiscoveryError, match="at most 256"):
        ping_sweep("10.0.0.0/16")


# ---------------- Step 3 ----------------

def test_step3_no_firewall_covers_every_network_even_ones_added_later(app, authenticated_client, local):
    setup_audit(authenticated_client)
    post(authenticated_client, "/audit/targets", {"t_name": ["Late"], "t_cidr": ["10.95.0.0/24"], "t_type": ["custom"], "t_hosts": ["10.95.0.2"]})
    with app.app_context():
        payload = settings()[1]
        device = payload["devices"][0]
        assert device["kind"] == "none" and set(device["zones"]) == set(payload["networks"])


def test_step3_firewall_with_logs_picks_a_free_port_and_can_learn_the_sender(app, authenticated_client, local, monkeypatch):
    setup_audit(authenticated_client, firewall="none")
    monkeypatch.setattr("segcheck_web.services.audit_setup.free_udp_port", lambda address, start=5514: 5517)
    post(authenticated_client, "/audit/firewall", {"mode": "firewall", "kind": "pfsense", "firewall_ip": "", "logs": "on"})
    with app.app_context():
        device = settings()[1]["devices"][0]
        assert device["kind"] == "pfsense" and device["log_port"] == 5517 and device["log_sender_ip"] == ""
        assert device["log_listen_ip"] == "10.50.0.23"
    page = authenticated_client.get("/audit/", base_url=BASE).data
    assert b"10.50.0.23:5517" in page and b"Firewall Events" in page


def test_free_udp_port_skips_a_busy_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("127.0.0.1", 0))
        port = busy.getsockname()[1]
        assert audit_setup.free_udp_port("127.0.0.1", port) > port


def test_listener_learns_the_firewall_from_its_first_recognised_log():
    import socket
    import time
    from segcheck_web.services.firewall_connector import DeviceListener
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    listener = DeviceListener({"id": "fw", "name": "FW", "kind": "iptables", "log_port": port, "log_sender_ip": ""}, "127.0.0.1", None)
    listener.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"just noise", ("127.0.0.1", port))
            sender.sendto(b"kernel: SEGCHECK-DROP IN=eth0 OUT=eth1 SRC=10.50.0.23 DST=10.30.0.20 LEN=60 PROTO=TCP SPT=5000 DPT=5432 SYN",
                          ("127.0.0.1", port))
        for _ in range(40):
            if listener.stats["parsed"]:
                break
            time.sleep(0.05)
        status = listener.status()
        assert status["learned_sender"] == "127.0.0.1" and status["parsed"] == 1 and status["unparsed"] == 1
        assert listener.events[0]["action"] == "block"
    finally:
        listener.stop()


# ---------------- Step 4 and launch ----------------

def test_launch_needs_step1_first_and_never_probes_without_it(app, authenticated_client, local, no_worker):
    response = post(authenticated_client, "/audit/launch", {"mode": "standard", "pack": "pci-cde-isolation", "groups": ["database"]})
    assert "#step-1" in response.headers["Location"] and not no_worker
    with app.app_context():
        assert db.session.query(AssessmentJob).count() == 0 and db.session.query(Policy).count() == 0


def test_standard_with_ticked_probes_runs_as_one_job(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    response = post(authenticated_client, "/audit/launch", {"mode": "standard", "pack": "pci-cde-isolation",
                                                            "groups": ["database", "icmp"]})
    assert "/jobs/" in response.headers["Location"] and len(no_worker) == 1
    with app.app_context():
        job = db.session.get(AssessmentJob, no_worker[0])
        assert job.total == 2 * (6 + 1)  # two CDE hosts x (6 database ports + 1 ping)
        assert "PCI DSS" in db.session.query(Policy).one().name


def test_own_rules_mix_blocked_and_approved_services(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    with app.app_context():
        host = db.session.query(Asset).filter_by(address="10.70.0.10").one().id
        cde = next(z.zone_key for z in db.session.query(Zone).all() if z.name == "Card systems")
    response = post(authenticated_client, "/audit/launch", {
        "mode": "custom",
        "r_target": [f"net:{cde}", str(host), str(host)], "r_service": ["db", "ldap", "custom"],
        "r_must": ["deny", "allow", "deny"], "r_protocol": ["tcp", "tcp", "udp"], "r_ports": ["", "", "9999"]})
    assert "/jobs/" in response.headers["Location"], response.headers["Location"]
    with app.app_context():
        checks = db.session.query(Policy).one().versions[-1].checks
        assert sorted((c.destination_host, c.expected, c.protocol) for c in checks) == [
            ("10.30.0.20", "deny", "tcp"), ("10.30.0.21", "deny", "tcp"), ("10.70.0.10", "allow", "tcp"), ("10.70.0.10", "deny", "udp")]


def test_own_rules_explain_bad_ports(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    with app.app_context():
        host = str(db.session.query(Asset).filter_by(address="10.70.0.10").one().id)
    response = post(authenticated_client, "/audit/launch", {"mode": "custom", "r_target": [host],
                                                            "r_service": ["custom"], "r_must": ["deny"], "r_protocol": ["tcp"], "r_ports": ["99999"]})
    page = authenticated_client.get(response.headers["Location"], base_url=BASE).data
    assert b"ports between 1 and 65535" in page and not no_worker


def test_blocked_launch_explains_why_and_leaves_nothing_behind(app, authenticated_client, local, no_worker, monkeypatch):
    setup_audit(authenticated_client)
    monkeypatch.setattr("segcheck_web.services.assessment_plan.source_address_available", lambda ip: False)
    response = post(authenticated_client, "/audit/launch", {"mode": "standard", "pack": "pci-cde-isolation"})
    page = authenticated_client.get(response.headers["Location"], base_url=BASE).data
    assert b"not an address of this PC" in page and not no_worker
    with app.app_context():
        assert db.session.query(Policy).count() == 0


def run_audit(app, client, monkeypatch, reachable=()):
    started = []
    monkeypatch.setattr("segcheck_web.routes.audit.start_worker", lambda a, job_id: started.append(job_id))
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                        lambda host, port, timeout, *, source_ip: ProbeOutcome(
                            "reachable" if (host, port) in reachable else "inconclusive", "test", 1.0, source_ip))
    post(client, "/audit/launch", {"mode": "standard", "pack": "pci-cde-isolation", "groups": ["database"]})
    run_job(app, started[-1])
    with app.app_context():
        return db.session.get(AssessmentJob, started[-1]).assessment_id


def test_finished_audit_appears_in_history_and_can_be_deleted(app, authenticated_client, local, monkeypatch):
    setup_audit(authenticated_client)
    first = run_audit(app, authenticated_client, monkeypatch, reachable={("10.30.0.20", 5432)})
    second = run_audit(app, authenticated_client, monkeypatch)
    page = authenticated_client.get("/assessments/", base_url=BASE).data
    assert b"FAILED" in page and b"NO HOLE FOUND" in page and f"#{first}".encode() in page
    assert b"1 failed" in page, "the mix of results is shown next to the verdict"
    post(authenticated_client, f"/assessments/{first}/delete", {})
    with app.app_context():
        assert db.session.get(Assessment, first) is None and db.session.get(Assessment, second) is not None
        assert db.session.query(Policy).count() == 1
    refused = post(authenticated_client, "/assessments/delete-all", {"confirm": "nope"})
    assert b"Type DELETE" in authenticated_client.get(refused.headers["Location"], base_url=BASE).data
    post(authenticated_client, "/assessments/delete-all", {"confirm": "DELETE"})
    with app.app_context():
        assert db.session.query(Assessment).count() == 0 and db.session.query(Policy).count() == 0
        assert db.session.query(AssessmentJob).count() == 0


def test_history_refuses_to_delete_while_an_audit_runs(app, authenticated_client, local, monkeypatch):
    setup_audit(authenticated_client)
    done = run_audit(app, authenticated_client, monkeypatch)
    with app.app_context():
        job = db.session.query(AssessmentJob).first()
        db.session.add(AssessmentLease(id=1, job_id=job.id, expires_at=job.created_at))
        db.session.commit()
        with pytest.raises(history.HistoryError, match="running"):
            history.delete_report(done)


def test_connector_starts_a_listener_when_the_sender_is_to_be_learned():
    import socket
    from segcheck_web.services.firewall_connector import ConnectorRegistry
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    registry = ConnectorRegistry()
    registry.sync({"source_ip": "127.0.0.1", "devices": [{"id": "fw", "name": "FW", "kind": "pfsense", "logging": True,
                                                          "log_port": port, "log_sender_ip": "", "log_listen_ip": ""}]}, None)
    try:
        assert registry.status()["fw"]["listening"] is True
    finally:
        registry.stop_all()


def test_editing_the_firewall_reopens_the_same_log_port_immediately():
    import socket
    from segcheck_web.services.firewall_connector import ConnectorRegistry
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    device = {"id": "fw", "name": "FW", "kind": "pfsense", "logging": True, "log_port": port, "log_sender_ip": "", "log_listen_ip": ""}
    registry = ConnectorRegistry()
    try:
        registry.sync({"source_ip": "127.0.0.1", "devices": [device]}, None)
        registry.sync({"source_ip": "127.0.0.1", "devices": [{**device, "log_sender_ip": "127.0.0.1"}]}, None)
        status = registry.status()["fw"]
        assert status["listening"] is True and status["error"] is None
    finally:
        registry.stop_all()


def test_moving_into_a_target_network_makes_it_where_you_are(app, authenticated_client, local, monkeypatch):
    setup_audit(authenticated_client)
    monkeypatch.setattr("segcheck_web.services.environment.source_address_available", lambda ip: ip in {"10.50.0.23", "10.70.0.99"})
    response = post(authenticated_client, "/audit/here", {"name": "Server room", "type": "server", "cidr": "10.70.0.0/24", "ip": "10.70.0.99"})
    assert "#step-2" in response.headers["Location"]
    with app.app_context():
        payload = settings()[1]
        source = payload["source_zone"]
        assert payload["networks"][source]["cidr"] == "10.70.0.0/24" and payload["source_ip"] == "10.70.0.99"
        assert {a.address for a in db.session.query(Zone).filter_by(zone_key=source).one().assets} == {"10.70.0.10"}
        assert "10.50.0.0/24" not in {n["cidr"] for n in payload["networks"].values()}  # the previous place is gone


def test_discovery_never_offers_this_pc_itself(app, authenticated_client, local, monkeypatch):
    setup_audit(authenticated_client)
    monkeypatch.setattr("segcheck_web.services.target_discovery.neighbour_table",
                        lambda: {"10.50.0.1": "aa:bb:cc:00:00:01", "10.50.0.23": "aa:bb:cc:00:00:02"})
    monkeypatch.setattr("segcheck_web.services.target_discovery._names", lambda addresses: {})
    monkeypatch.setattr("segcheck_web.services.environment.local_addresses", lambda: ["10.50.0.23"])
    with app.app_context():
        here_key = settings()[1]["source_zone"]
    hosts = authenticated_client.get(f"/audit/targets/{here_key}/known", base_url=BASE).get_json()["hosts"]
    assert [h["address"] for h in hosts] == ["10.50.0.1"]


# ---------------- own rules for real office networks ----------------

def test_typed_addresses_accept_lists_ranges_and_subnets():
    assert audit_setup.parse_addresses("10.30.0.20, 10.30.0.10-12\n10.30.0.0/30") == [
        "10.30.0.20", "10.30.0.10", "10.30.0.11", "10.30.0.12", "10.30.0.1", "10.30.0.2"]
    assert audit_setup.parse_addresses("10.30.0.250-10.30.1.1") == ["10.30.0.250", "10.30.0.251", "10.30.0.252",
                                                                   "10.30.0.253", "10.30.0.254", "10.30.0.255", "10.30.1.0", "10.30.1.1"]
    assert audit_setup.parse_addresses("10.30.0.5 10.30.0.5") == ["10.30.0.5"]


@pytest.mark.parametrize("text,message", [("10.30.0.20-10", "runs backwards"), ("10.30.0.0/16", "at most 256"),
                                          ("10.0.0.0-10.0.2.0", "more than 256"), ("printer", "is not an address")])
def test_typed_addresses_explain_mistakes(text, message):
    with pytest.raises(audit_setup.EnvironmentError, match=message):
        audit_setup.parse_addresses(text, 3)


def test_ports_accept_ranges_and_explain_mistakes():
    assert audit_setup.parse_ports("443, 80 8000-8002") == [80, 443, 8000, 8001, 8002]
    assert audit_setup.compact_ports([80, 443, 8000, 8001, 8002]) == "80, 443, 8000-8002"
    for text, message in (("9010-9000", "runs backwards"), ("http", "numbers or ranges"), ("0", "between 1 and 65535"),
                          ("1-1000", "too many")):
        with pytest.raises(audit_setup.EnvironmentError, match=message):
            audit_setup.parse_ports(text)


def test_own_rules_with_typed_ranges_bundles_and_reasons(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    response = post(authenticated_client, "/audit/launch", {
        "mode": "custom",
        "r_target": ["text", "text"], "r_service": ["custom", "windows"], "r_must": ["deny", "deny"],
        "r_protocol": ["tcp", "tcp"], "r_ports": ["5432, 8000-8001", ""],
        "r_targets": ["10.30.0.40-41", "10.70.0.10"], "r_reason": ["HR must not reach card data - PCI DSS 1.3.1", ""]})
    assert "/jobs/" in response.headers["Location"], response.headers["Location"]
    with app.app_context():
        checks = db.session.query(Policy).one().versions[-1].checks
        typed = sorted((c.destination_host, tuple(c.ports), c.rationale) for c in checks if c.destination_host.startswith("10.30"))
        assert typed == [("10.30.0.40", (5432, 8000, 8001), "HR must not reach card data - PCI DSS 1.3.1"),
                         ("10.30.0.41", (5432, 8000, 8001), "HR must not reach card data - PCI DSS 1.3.1")]
        windows = next(c for c in checks if c.destination_host == "10.70.0.10")
        assert list(windows.ports) == [88, 135, 389, 445, 636, 3268] and windows.rationale == "Auditor-defined rule."
        # the typed addresses became hosts of the network that contains them
        assert {a.address for a in db.session.query(Asset).all()} >= {"10.30.0.40", "10.30.0.41"}


def test_typed_address_outside_every_network_is_refused(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    response = post(authenticated_client, "/audit/launch", {
        "mode": "custom", "r_target": ["text"], "r_service": ["web"], "r_must": ["deny"],
        "r_protocol": ["tcp"], "r_ports": [""], "r_targets": ["192.168.9.9"], "r_reason": [""]})
    page = authenticated_client.get(response.headers["Location"], base_url=BASE).data
    assert b"192.168.9.9 is not inside any network" in page and not no_worker
    with app.app_context():
        assert db.session.query(Policy).count() == 0


def test_rule_reason_is_shown_in_the_report(app, authenticated_client, local, monkeypatch):
    setup_audit(authenticated_client)
    started = []
    monkeypatch.setattr("segcheck_web.routes.audit.start_worker", lambda a, job_id: started.append(job_id))
    monkeypatch.setattr("segcheck_web.services.assessment_execution.tcp_connect_probe",
                        lambda host, port, timeout, *, source_ip: ProbeOutcome("inconclusive", "test", 1.0, source_ip))
    post(authenticated_client, "/audit/launch", {
        "mode": "custom", "r_target": ["text"], "r_service": ["custom"], "r_must": ["deny"],
        "r_protocol": ["tcp"], "r_ports": ["5432"], "r_targets": ["10.30.0.20"], "r_reason": ["Card data stays isolated <b>"]})
    run_job(app, started[-1])
    with app.app_context():
        assessment_id = db.session.get(AssessmentJob, started[-1]).assessment_id
    page = authenticated_client.get(f"/assessments/{assessment_id}", base_url=BASE).data
    assert b"Rule reason:" in page and b"Card data stays isolated &lt;b&gt;" in page


def test_example_csv_lists_the_access_matrix_columns(app, authenticated_client):
    response = authenticated_client.get("/audit/rules-template.csv", base_url=BASE)
    assert response.status_code == 200 and response.mimetype == "text/csv"
    assert response.data.decode().splitlines()[0] == ",".join(audit_setup.CSV_FIELDS)
    assert app.test_client().get("/audit/rules-template.csv", base_url=BASE).status_code == 302


def test_several_standards_run_once_with_every_mapping(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    response = post(authenticated_client, "/audit/launch", {"mode": "standard", "scope": "several",
                                                            "pack": ["pci-cde-isolation", "nist-sc7-boundary", "iso-8-22-segregation"],
                                                            "groups": ["database"]})
    assert "/jobs/" in response.headers["Location"], response.headers["Location"]
    with app.app_context():
        checks = db.session.query(Policy).one().versions[-1].checks
        keys = [(c.destination_host, tuple(c.ports)) for c in checks]
        assert len(keys) == len(set(keys)), "each probe is sent once"
        cde = next(c for c in checks if c.destination_host == "10.30.0.20")
        frameworks = {m["framework"] for m in cde.framework_mappings}
        assert frameworks == {"pci_dss", "nist_sp800_53", "iso27002"}


def test_several_standards_explains_ones_that_do_not_fit(app, authenticated_client, local, no_worker):
    setup_audit(authenticated_client)
    response = post(authenticated_client, "/audit/launch", {"mode": "standard", "scope": "several",
                                                            "pack": ["pci-cde-egress"]})
    page = authenticated_client.get(response.headers["Location"], base_url=BASE).data
    assert b"None of the chosen standards fits" in page and not no_worker


def test_rule_export_is_loaded_explained_and_removed(app, authenticated_client, local):
    setup_audit(authenticated_client, firewall="firewall")
    bad = post(authenticated_client, "/audit/firewall/rules", {"export_text": "not a rule export"})
    assert b"Not a rule export" in authenticated_client.get(bad.headers["Location"], base_url=BASE).data
    good = post(authenticated_client, "/audit/firewall/rules", {"export_text": ":FORWARD DROP [0:0]\n-A FORWARD -s 10.50.0.0/24 -d 10.30.0.20/32 -p tcp -m multiport --dports 5432 -j ACCEPT\n"})
    page = authenticated_client.get(good.headers["Location"], base_url=BASE).data
    assert b"loaded 2 Linux FORWARD rule(s)" in page and b"2 rule(s) loaded" in page
    with app.app_context():
        assert settings()[1]["ruleset"]["kind"] == "iptables"
    post(authenticated_client, "/audit/firewall/rules/remove", {})
    with app.app_context():
        assert "ruleset" not in settings()[1]


@pytest.mark.parametrize("encoding", ["utf-16", "utf-8-sig"])
def test_rule_export_file_saved_by_windows_powershell_is_read(app, authenticated_client, local, encoding):
    import io
    setup_audit(authenticated_client, firewall="firewall")
    data = ":FORWARD DROP [0:0]\n-A FORWARD -s 10.50.0.0/24 -d 10.30.0.20/32 -p tcp -m multiport --dports 5432 -j ACCEPT\n".encode(encoding)
    token = get_token(authenticated_client, "/audit/")
    response = authenticated_client.post("/audit/firewall/rules", data={"csrf_token": token, "export": (io.BytesIO(data), "rules.txt")},
                                         content_type="multipart/form-data", base_url=BASE, headers={"Referer": BASE + "/audit/"})
    assert b"loaded 2 Linux FORWARD rule(s)" in authenticated_client.get(response.headers["Location"], base_url=BASE).data
