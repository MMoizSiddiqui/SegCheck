"""FortiGate, Cisco ASA/FTD, Sophos and MikroTik: their syslog lines are read, and Step 3 gives each its own steps."""
import pytest

from test_audit_flow import BASE, local, post, setup_audit  # noqa: F401
from test_environment_workflow import app  # noqa: F401
from segcheck_web.services.firewall_connector import parse_firewall_line
from segcheck_web.services.rule_attribution import log_rule_label

SRC, DST = "10.40.0.100", "10.30.0.20"

LINES = [
    ("fortigate", "block", "tcp", 5432, "implicit deny (policy 0)",
     '<189>date=2026-11-22 time=10:00:00 devname="FGT60F" devid="FGT60FTK" logid="0000000013" type="traffic" subtype="forward" '
     'level="notice" vd="root" srcip=10.40.0.100 srcport=51000 srcintf="port2" dstip=10.30.0.20 dstport=5432 dstintf="port3" '
     'proto=6 action="deny" policyid=0 service="tcp/5432"'),
    ("fortigate", "pass", "tcp", 5432, "legacy-reporting",
     '<189>date=2026-11-22 devname="FGT60F" logid="0000000013" type="traffic" srcip=10.40.0.100 srcport=51000 dstip=10.30.0.20 '
     'dstport=5432 proto=6 action="close" policyid=7 policyname="legacy-reporting"'),
    ("sophos", "block", "tcp", 5432, "default drop",
     'device_name="SFW" log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" fw_rule_id="0" '
     'src_ip="10.40.0.100" dst_ip="10.30.0.20" protocol="TCP" src_port="51000" dst_port="5432" in_interface="Port2"'),
    ("sophos", "pass", "tcp", 5432, "legacy-reporting",
     'device="SFW" log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" status="Allow" fw_rule_id=7 '
     'fw_rule_name="legacy-reporting" src_ip=10.40.0.100 dst_ip=10.30.0.20 protocol="TCP" src_port=51000 dst_port=5432'),
    ("cisco", "block", "tcp", 5432, "INSIDE_IN",
     '<164>Nov 22 2026 10:00:00: %ASA-4-106023: Deny tcp src inside:10.40.0.100/51000 dst dmz:10.30.0.20/5432 by access-group "INSIDE_IN" [0x0, 0x0]'),
    ("cisco", "block", "icmp", None, "INSIDE_IN",
     '%ASA-4-106023: Deny icmp src inside:10.40.0.100 dst dmz:10.30.0.20 (type 8, code 0) by access-group "INSIDE_IN" [0x0, 0x0]'),
    ("cisco", "pass", "tcp", 5432, "INSIDE_IN",
     '%ASA-6-106100: access-list INSIDE_IN permitted tcp inside/10.40.0.100(51000) -> dmz/10.30.0.20(5432) hit-cnt 1 first hit [0x1, 0x0]'),
    ("cisco", "pass", "tcp", 5432, "",
     '%ASA-6-302013: Built outbound TCP connection 1234 for dmz:10.30.0.20/5432 (10.30.0.20/5432) to inside:10.40.0.100/51000 (10.40.0.100/51000)'),
    ("cisco", "block", "tcp", 5432, "implicit deny",
     '%FTD-2-106001: Inbound TCP connection denied from 10.40.0.100/51000 to 10.30.0.20/5432 flags SYN  on interface inside'),
    ("mikrotik", "block", "tcp", 5432, "final drop-and-log rule (SEGCHECK-DROP)",
     '<134>firewall,info SEGCHECK-DROP forward: in:ether2 out:ether3, connection-state:new src-mac 02:42:0a:28:00:64, '
     'proto TCP (SYN), 10.40.0.100:51000->10.30.0.20:5432, len 60'),
    ("mikrotik", "pass", "tcp", 5432, "legacy",
     'firewall,info SEGCHECK-ACCEPT-legacy forward: in:ether2 out:ether3, connection-state:new proto TCP (SYN), '
     '10.40.0.100:51000->10.30.0.20:5432, len 60'),
]


@pytest.mark.parametrize("fmt,action,protocol,port,rule,line", LINES, ids=[f"{l[0]}-{l[1]}-{i}" for i, l in enumerate(LINES)])
def test_vendor_log_lines_are_read(fmt, action, protocol, port, rule, line):
    event = parse_firewall_line(line)
    assert event and event["format"] == fmt and event["action"] == action and event["protocol"] == protocol
    assert (event["source_ip"], event["destination_ip"], event["destination_port"]) == (SRC, DST, port)
    assert log_rule_label(event) == rule or (rule == "" and log_rule_label(event) == "")


def test_linux_and_pfsense_lines_still_use_their_own_readers():
    linux = parse_firewall_line("Nov 21 21:45:12 ulogd[1]: SEGCHECK-DROP IN=eth1 OUT=eth2 SRC=10.40.0.100 DST=10.30.0.20 PROTO=TCP SPT=1 DPT=5432")
    assert linux["format"] == "iptables" and linux["action"] == "block"
    assert parse_firewall_line("hello, not a firewall line") is None


@pytest.mark.parametrize("kind,expected", [
    ("fortigate", b"config log syslogd setting"), ("cisco", b"logging host inside 10.50.0.23 udp/"),
    ("sophos", b"System services"), ("mikrotik", b"/system logging action add name=segcheck target=remote remote=10.50.0.23"),
    ("iptables", b"iptables -A FORWARD -j LOG"), ("pfsense", b"Send log messages to remote syslog server"),
])
def test_each_firewall_type_gets_its_own_setup_steps(app, authenticated_client, local, monkeypatch, kind, expected):
    monkeypatch.setattr("segcheck_web.services.audit_setup.free_udp_port", lambda ip: 5514)
    setup_audit(authenticated_client)
    response = post(authenticated_client, "/audit/firewall", {"mode": "firewall", "kind": kind, "firewall_ip": "", "logs": "on"})
    page = authenticated_client.get(response.headers["Location"], base_url=BASE).data
    assert b"UDP port 5514" in page and expected in page
    assert page.index(b'substep-badge">3a') < page.index(b'substep-badge">3b'), "choose first, then the logs"


def test_each_standard_explains_itself_and_lists_what_it_will_try(app, authenticated_client, local):
    setup_audit(authenticated_client)
    page = authenticated_client.get("/audit/", base_url=BASE).data
    assert page.count(b"What this checks, in full") == 8, "one expander per standard"
    for text in (b"What the standard asks", b"Why it matters", b"PASS means", b"FAIL means",
                 b"What SegCheck will try", b"connection attempt", b"Not available from where this PC is"):
        assert text in page, text


def _nested_forms(html):
    """Forms inside forms are dropped by the browser: their buttons then submit the outer form instead."""
    from html.parser import HTMLParser

    class Finder(HTMLParser):
        depth, nested = 0, 0

        def handle_starttag(self, tag, attrs):
            if tag == "form":
                self.nested += self.depth > 0
                self.depth += 1

        def handle_endtag(self, tag):
            if tag == "form":
                self.depth -= 1

    finder = Finder()
    finder.feed(html.decode("utf-8"))
    return finder.nested, finder.depth


@pytest.mark.parametrize("kind", ["none", "iptables", "fortigate", "other"])
def test_no_form_is_nested_inside_another(app, authenticated_client, local, monkeypatch, kind):
    monkeypatch.setattr("segcheck_web.services.audit_setup.free_udp_port", lambda ip: 5514)
    setup_audit(authenticated_client)
    mode = "none" if kind == "none" else "firewall"
    post(authenticated_client, "/audit/firewall", {"mode": mode, "kind": kind if mode == "firewall" else "", "firewall_ip": "", "logs": "on"})
    for url in ("/audit/", "/assessments/", "/"):
        page = authenticated_client.get(url, base_url=BASE, follow_redirects=True).data
        assert _nested_forms(page) == (0, 0), url
    page = authenticated_client.get("/audit/", base_url=BASE).data
    save = page.index(b"Save firewall choice")
    assert page.rfind(b"<form", 0, save) > page.rfind(b"</form>", 0, save), "Save firewall choice sits inside its own form"
    assert page.index(b'substep-badge">3a') < save < (page.find(b'substep-badge">3b') if kind not in ("none", "other") else len(page))


@pytest.mark.parametrize("ours,second_port", [(True, b"5514"), (False, b"5515")], ids=["held-by-segcheck", "taken-by-another-program"])
def test_saving_step3_again_keeps_the_log_port(app, authenticated_client, local, monkeypatch, ours, second_port):
    """The firewall already sends to the first port, so saving again keeps it while SegCheck's own listener holds it.
    If another program took the port meanwhile, saving again moves to the next free one (the README's fix for that)."""
    ports = iter([5514, 5515])
    monkeypatch.setattr("segcheck_web.services.audit_setup.free_udp_port", lambda ip, start=5514: next(ports))
    monkeypatch.setattr("segcheck_web.services.audit_setup._port_still_ours", lambda ip, port: ours)
    setup_audit(authenticated_client)
    form = {"mode": "firewall", "kind": "iptables", "firewall_ip": "", "logs": "on"}
    for expected in (b"5514", second_port):
        response = post(authenticated_client, "/audit/firewall", form)
        page = authenticated_client.get(response.headers["Location"], base_url=BASE).data
        assert b"UDP port " + expected in page
    assert b"None</strong>" not in page
    assert b'data-step-finish="3" data-next="4" data-done="yes"' in page and b"Save Step 3 and continue" in page
