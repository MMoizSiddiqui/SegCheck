"""Every wrong entry in New audit (Step 1-4) is refused with a message that says what is wrong and what to do."""
import html
import re

import pytest

from test_audit_flow import BASE, local, no_worker, post  # noqa: F401
from test_environment_workflow import app  # noqa: F401
from segcheck_web.extensions import db
from segcheck_web.models import Zone

HERE = {"name": "HR", "type": "hr", "cidr": "10.50.0.0/24", "ip": "10.50.0.23", "gateway": "10.50.0.1", "organization": "X"}


def message(client, response):
    page = client.get(response.headers["Location"], base_url=BASE).data.decode()
    found = re.findall(r'class="flash-message flash-(\w+)">([^<]*)<', page)
    return [(kind, html.unescape(text)) for kind, text in found]


def refused(client, response, expected):
    got = message(client, response)
    assert got and got[0][0] == "error" and expected in got[0][1], got


@pytest.mark.parametrize("change,expected", [
    ({"name": "A" * 500}, "The network's name is too long (500 characters); use at most 120."),
    ({"organization": "O" * 500}, "The client's name is too long"),
    ({"cidr": "abc"}, "Enter this network's subnet, for example 10.50.0.0/24."),
    ({"cidr": "10.50.0.0/2"}, "10.50.0.0/2 has 1,073,741,824 addresses. A network here is one department, usually a /24 (256 addresses). Did you mean 10.50.0.0/24?"),
    ({"ip": "abc"}, "Enter this PC's IP address"),
    ({"ip": "10.60.0.5"}, "This PC's address 10.60.0.5 is not inside 10.50.0.0/24."),
    ({"gateway": "abc"}, "Gateway: 'abc' is not an IP address."),
    ({"gateway": "10.60.0.1"}, "Gateway 10.60.0.1 is not inside 10.50.0.0/24."),
    ({"gateway": "10.50.0.23"}, "The gateway is the router's address, not this PC's own (10.50.0.23)."),
    ({"type": "zzz"}, "Choose what kind of network this PC is in."),
])
def test_step1_wrong_entries(app, authenticated_client, local, change, expected):
    refused(authenticated_client, post(authenticated_client, "/audit/here", {**HERE, **change}), expected)


def row(name="T", cidr="10.30.0.0/24", kind="cde", hosts="10.30.0.20"):
    return {"t_name": [name], "t_cidr": [cidr], "t_type": [kind], "t_hosts": [hosts]}


@pytest.mark.parametrize("data,expected", [
    (row("", "", "custom", ""), "Fill in at least one target network."),
    (row(cidr="abc"), "Row 1: 'abc' is not a network. Use the form 10.30.0.0/24."),
    (row(cidr="10.0.0.0/8"), "Row 1: 10.0.0.0/8 has 16,777,216 addresses."),
    (row(cidr="10.50.0.0/24", hosts=""), "Row 1: 10.50.0.0/24 overlaps HR (10.50.0.0/24), this PC's network (Step 1)."),
    (row(hosts="abc"), "Not an IP address: abc."),
    (row(hosts="10.99.0.5"), "Row 1: 10.99.0.5 is not inside 10.30.0.0/24."),
    (row(hosts="10.30.0.0"), "Row 1: 10.30.0.0 is the network address of 10.30.0.0/24, not a machine. Machines use 10.30.0.1 to 10.30.0.254."),
    (row(hosts="10.30.0.255"), "Row 1: 10.30.0.255 is the broadcast address of 10.30.0.0/24, not a machine."),
    (row(name="N" * 500), "Row 1: the name is too long (500 characters); use at most 120."),
    (row(kind="zzz"), "Row 1: choose the kind of network."),
])
def test_step2_wrong_entries(app, authenticated_client, local, data, expected):
    post(authenticated_client, "/audit/here", HERE)
    refused(authenticated_client, post(authenticated_client, "/audit/targets", data), expected)
    with app.app_context():
        assert db.session.query(Zone).count() == 1, "nothing half saved"


@pytest.mark.parametrize("hosts,expected", [
    ("", "Type at least one host address first"), ("abc", "Not an IP address: abc."),
    ("10.99.0.1", "10.99.0.1 is not inside 10.30.0.0/24."), ("10.30.0.0", "10.30.0.0 is the network address"),
])
def test_add_hosts_on_a_card_wrong_entries(app, authenticated_client, local, hosts, expected):
    post(authenticated_client, "/audit/here", HERE)
    post(authenticated_client, "/audit/targets", row())
    with app.app_context():
        key = next(z.zone_key for z in db.session.query(Zone).all() if z.name == "T")
    refused(authenticated_client, post(authenticated_client, f"/audit/targets/{key}/hosts", {"hosts": hosts}), expected)


@pytest.mark.parametrize("data,expected", [
    ({"mode": "zzz"}, "Choose 'No firewall, or I don't know' or 'There is a firewall'."),
    ({"mode": "firewall", "kind": "zzz"}, "Choose the firewall type."),
    ({"mode": "firewall", "kind": "iptables", "firewall_ip": "abc", "logs": "on"}, "Firewall's address: 'abc' is not an IP address."),
    ({"mode": "firewall", "kind": "iptables", "firewall_ip": "10.99.0.1", "logs": "on"}, "Firewall's address 10.99.0.1 is not inside this PC's network 10.50.0.0/24."),
    ({"mode": "firewall", "kind": "iptables", "sender_ip": "abc", "logs": "on"}, "Logs come from: 'abc' is not an IP address."),
    ({"mode": "firewall", "kind": "iptables", "listen_ip": "abc", "logs": "on"}, "This PC receives logs on: 'abc' is not an IP address."),
    ({"mode": "firewall", "kind": "iptables", "listen_ip": "10.50.0.99", "logs": "on"}, "10.50.0.99 is not an address of this PC."),
])
def test_step3_wrong_entries(app, authenticated_client, local, data, expected):
    post(authenticated_client, "/audit/here", HERE)
    post(authenticated_client, "/audit/targets", row())
    refused(authenticated_client, post(authenticated_client, "/audit/firewall", data), expected)


def test_step3_confirming_a_junk_sender_is_refused(app, authenticated_client, local):
    post(authenticated_client, "/audit/here", HERE)
    refused(authenticated_client, post(authenticated_client, "/audit/firewall/sender", {"sender_ip": "abc"}), "'abc' is not an IP address.")


def test_step4_type_addresses_chosen_but_left_empty(app, authenticated_client, local, no_worker):
    post(authenticated_client, "/audit/here", HERE)
    post(authenticated_client, "/audit/targets", row())
    post(authenticated_client, "/audit/firewall", {"mode": "none"})
    response = post(authenticated_client, "/audit/launch", {"mode": "custom", "r_target": ["text"], "r_targets": [""],
                                                            "r_service": ["web"], "r_must": ["deny"]})
    refused(authenticated_client, response, "Rule 1: you chose 'Type addresses…' but typed none.")
    assert not no_worker
