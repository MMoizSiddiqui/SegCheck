"""The firewall's own addresses in every network (ISO/IEC 27002 8.20, NIST SC-7): stored, tested only by the
management-plane check, never treated as servers by other standards, and attributed to the right rules."""
import pytest

from test_audit_flow import BASE, local, no_worker, post, setup_audit  # noqa: F401
from test_environment_workflow import app  # noqa: F401
from segcheck_web.extensions import db
from segcheck_web.models import Asset, Policy
from segcheck_web.services.environment import settings
from segcheck_web.services.firewall_connector import cross_check
from segcheck_web.services.rule_attribution import first_match, parse_export

FIREWALL = {"mode": "firewall", "kind": "iptables", "firewall_ip": "10.50.0.1", "logs": "on"}


@pytest.fixture
def ports(monkeypatch):
    monkeypatch.setattr("segcheck_web.services.audit_setup.free_udp_port", lambda ip, start=5514: 5514)


def _page(client, response):
    return client.get(response.headers["Location"], base_url=BASE).data


def test_other_addresses_are_saved_and_shown(app, authenticated_client, local, ports):
    setup_audit(authenticated_client)
    response = post(authenticated_client, "/audit/firewall", {**FIREWALL, "other_ips": "10.30.0.1, 10.70.0.1 10.30.0.1"})
    page = _page(authenticated_client, response)
    assert b"Step 3 saved" in page and b'value="10.30.0.1 10.70.0.1"' in page
    assert b"Only for the firewall-management check" in page and b"does <strong>not</strong> change how the" in page
    with app.app_context():
        assert settings()[1]["devices"][0]["other_ips"] == ["10.30.0.1", "10.70.0.1"]
        own = {a.address for a in db.session.query(Asset).filter_by(name="Firewall interface")}
        assert own == {"10.50.0.1", "10.30.0.1", "10.70.0.1"}


@pytest.mark.parametrize("value,message", [
    ("10.30.0.999", b"is not an IP address"),
    ("10.50.0.23", b"is this PC, not the firewall"),
    ("10.50.0.254", b"is in this PC&#39;s own network"),
    ("192.168.9.1", b"is not inside any target network from Step 2"),
])
def test_wrong_other_addresses_are_explained(app, authenticated_client, local, ports, value, message):
    setup_audit(authenticated_client)
    page = _page(authenticated_client, post(authenticated_client, "/audit/firewall", {**FIREWALL, "other_ips": value}))
    assert message in page, page[:0]
    with app.app_context():
        assert settings()[1]["devices"][0]["kind"] == "none", "nothing saved on a wrong entry"


def test_removed_addresses_stop_being_targets(app, authenticated_client, local, ports):
    setup_audit(authenticated_client)
    post(authenticated_client, "/audit/firewall", {**FIREWALL, "other_ips": "10.30.0.1 10.70.0.1"})
    post(authenticated_client, "/audit/firewall", {**FIREWALL, "other_ips": "10.30.0.1"})
    with app.app_context():
        assert {a.address for a in db.session.query(Asset).filter_by(name="Firewall interface")} == {"10.50.0.1", "10.30.0.1"}
    post(authenticated_client, "/audit/firewall", {"mode": "none"})
    with app.app_context():
        assert db.session.query(Asset).filter_by(name="Firewall interface").count() == 0


def test_management_check_tests_every_address_and_others_ignore_them(app, authenticated_client, local, ports, no_worker):
    setup_audit(authenticated_client)
    post(authenticated_client, "/audit/firewall", {**FIREWALL, "other_ips": "10.30.0.1 10.70.0.1"})
    response = post(authenticated_client, "/audit/launch", {"mode": "standard", "scope": "several",
                                                            "pack": ["iso-8-20-mgmt-plane", "pci-cde-isolation", "nist-sc7-boundary"]})
    assert "/jobs/" in response.headers["Location"], response.headers["Location"]
    with app.app_context():
        checks = db.session.query(Policy).one().versions[-1].checks
        firewall = {"10.50.0.1", "10.30.0.1", "10.70.0.1"}
        management = [c for c in checks if c.destination_host in firewall]
        assert {c.destination_host for c in management} == firewall, "every door of the firewall is tried"
        assert {tuple(c.ports) for c in management} <= {(22, 80, 443), (161,)}, "only the admin ports"
        assert all(m["control_id"] in {"8.20", "SC-7"} for c in management for m in c.framework_mappings)
        assert {c.destination_host for c in checks} - firewall == {"10.30.0.20", "10.30.0.21", "10.70.0.10"}


def test_page_suggests_addresses_but_never_adds_them_alone(app, authenticated_client, local, ports):
    setup_audit(authenticated_client)
    post(authenticated_client, "/audit/firewall", FIREWALL)
    config = """<?xml version="1.0"?><pfsense><interfaces>
      <lan><descr>HR</descr><ipaddr>10.50.0.1</ipaddr><subnet>24</subnet></lan>
      <opt1><descr>CDE</descr><ipaddr>10.30.0.1</ipaddr><subnet>24</subnet></opt1></interfaces>
      <filter><rule><type>block</type><interface>lan</interface><source><any/></source><destination><any/></destination></rule></filter></pfsense>"""
    page = _page(authenticated_client, post(authenticated_client, "/audit/firewall/rules", {"export_text": config}))
    assert b'data-add-address="10.30.0.1"' in page and b"from the loaded config.xml" in page
    with app.app_context():
        assert settings()[1]["devices"][0]["other_ips"] == []


IPTABLES = """*nat
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -s 10.80.0.0/24 -m comment --comment admin-network-manages-firewall -j ACCEPT
-A INPUT -j NFLOG --nflog-prefix SEGCHECK-DROP --nflog-group 1
-A INPUT -m comment --comment firewall-self-protection -j DROP
-A FORWARD -s 10.40.0.0/24 -d 10.30.0.20/32 -p tcp -m multiport --dports 5432 -j ACCEPT
COMMIT
"""


def test_traffic_to_the_firewall_uses_its_input_rules():
    rules = parse_export(IPTABLES)
    blocked = first_match(rules, "10.40.0.100", "10.30.0.1", "tcp", 22, to_device=True)
    assert (blocked["action"], blocked["label"], blocked["where"]) == ("block", "firewall-self-protection", "INPUT rule 2")
    assert first_match(rules, "10.80.0.5", "10.30.0.1", "tcp", 22, to_device=True)["label"] == "admin-network-manages-firewall"
    through = first_match(rules, "10.40.0.100", "10.30.0.20", "tcp", 5432)
    assert through["action"] == "pass" and through["where"] == "FORWARD rule 1"
    assert first_match(rules, "10.40.0.100", "10.30.0.21", "tcp", 22)["label"] == "FORWARD chain default policy (DROP)", \
        "the filter table's policy, not the nat table's ACCEPT"
    unprotected = parse_export("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\nCOMMIT\n")
    assert "no rule protects the firewall itself" in first_match(unprotected, "10.40.0.100", "10.40.0.1", "tcp", 443,
                                                                  to_device=True)["label"]
    old = {"kind": "iptables", "rules": rules["rules"], "interfaces": {}}  # loaded before INPUT was read
    assert first_match(old, "10.40.0.100", "10.30.0.1", "tcp", 22, to_device=True) is None


def test_pfsense_anti_lockout_and_self_rules():
    config = """<?xml version="1.0"?><pfsense><system><webgui><protocol>https</protocol></webgui><ssh><enable>enabled</enable></ssh></system>
      <interfaces><lan><ipaddr>10.40.0.1</ipaddr><subnet>24</subnet></lan><opt1><ipaddr>10.30.0.1</ipaddr><subnet>24</subnet></opt1></interfaces>
      <filter><rule><type>block</type><interface>lan</interface><protocol>tcp</protocol><source><network>lan</network></source>
        <destination><network>(self)</network><port>22</port></destination><descr>no admin from staff</descr></rule></filter></pfsense>"""
    rules = parse_export(config)
    lockout = first_match(rules, "10.40.0.100", "10.40.0.1", "tcp", 443, to_device=True)
    assert lockout["label"] == "pfSense anti-lockout rule (built in)" and lockout["action"] == "pass"
    other_door = first_match(rules, "10.40.0.100", "10.30.0.1", "tcp", 22, to_device=True)
    assert other_door["label"] == "no admin from staff" and other_door["action"] == "block"
    off = parse_export(config.replace("<protocol>https</protocol>", "<protocol>https</protocol><noantilockout/>"))
    assert first_match(off, "10.40.0.100", "10.40.0.1", "tcp", 22, to_device=True)["label"] == "no admin from staff"


def test_cross_check_explains_attempts_to_the_firewall_itself():
    environment = {"devices": [{"id": "fw", "name": "Firewall", "kind": "iptables", "zones": ["corp", "cde"],
                                "interface_ip": "10.40.0.1", "other_ips": ["10.30.0.1"]}],
                   "ruleset": parse_export(IPTABLES)}
    details = [{"check_id": "STD-001", "protocol": "tcp", "destination_host": "10.30.0.1", "port": 22, "observed": "inconclusive",
                "source_zone": "corp", "destination_zone": "cde", "source_ip": "10.40.0.100"}]
    record = cross_check(details, environment, None, wait=False)["attempts"][0]
    assert record["to_firewall"] and record["config_rule"]["label"] == "firewall-self-protection"


def test_a_typo_never_wipes_the_saved_step3(app, authenticated_client, local, ports):
    """Autosave sends every change: a wrong value must leave the last good Step 3 in place."""
    setup_audit(authenticated_client)
    post(authenticated_client, "/audit/firewall", {**FIREWALL, "other_ips": "10.30.0.1"})
    for wrong in ({"firewall_ip": "10.50.0.999"}, {"other_ips": "10.30.0.1 nonsense"}, {"kind": "checkpoint"}):
        post(authenticated_client, "/audit/firewall", {**FIREWALL, "other_ips": "10.30.0.1", **wrong})
        with app.app_context():
            device = settings()[1]["devices"][0]
            assert (device["kind"], device["interface_ip"], device["other_ips"]) == ("iptables", "10.50.0.1", ["10.30.0.1"]), wrong


def test_its_address_in_this_network_is_checked_against_its_logs_too():
    """Same network as this PC, but the target is the firewall itself: its decision (and log) still applies."""
    environment = {"devices": [{"id": "fw", "name": "Firewall", "kind": "iptables", "zones": ["corp", "cde"],
                                "interface_ip": "10.40.0.1", "other_ips": []}], "ruleset": parse_export(IPTABLES)}
    details = [{"check_id": "STD-001", "protocol": "tcp", "destination_host": "10.40.0.1", "port": 443, "observed": "inconclusive",
                "source_zone": "corp", "destination_zone": "corp", "source_ip": "10.40.0.100"}]
    record = cross_check(details, environment, None, wait=False)["attempts"][0]
    assert record["to_firewall"] and record["devices"] == ["Firewall"] and record["evidence"] != "same_zone"
    assert record["config_rule"]["label"] == "firewall-self-protection"


def test_empty_firewall_address_is_learned_from_its_first_log(app, authenticated_client, local, ports):
    """Left empty: the first log line comes from the firewall's address here, so SegCheck fills it in (and tests it)."""
    from segcheck_web.services import audit_setup
    setup_audit(authenticated_client)
    post(authenticated_client, "/audit/firewall", {**FIREWALL, "firewall_ip": ""})
    page = authenticated_client.get("/audit/", base_url=BASE).data
    assert b"Not sure? Leave it empty." in page and b"not known yet" in page
    with app.app_context():
        assert audit_setup.adopt_learned_address({"firewall": {"learned_sender": "192.168.7.1"}}) is None, "not in this network"
        assert audit_setup.adopt_learned_address({"firewall": {"learned_sender": "10.50.0.1"}}) == "10.50.0.1"
        assert settings()[1]["devices"][0]["interface_ip"] == "10.50.0.1"
        assert db.session.query(Asset).filter_by(name="Firewall interface", address="10.50.0.1").count() == 1
        assert audit_setup.adopt_learned_address({"firewall": {"learned_sender": "10.50.0.2"}}) is None, "never overwrites"
    page = authenticated_client.get("/audit/", base_url=BASE).data
    assert b"Filled in automatically" in page and b'value="10.50.0.1"' in page
