from pathlib import Path
import socket

import pytest

from segcheck.policy_engine import load_policy
from segcheck.probe import ProbeOutcome, probe_policy, tcp_connect_probe

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "tests" / "fixtures" / "lab-policy.yaml"


def test_probe_only_tests_checks_from_selected_source_zone(monkeypatch):
    policy = load_policy(POLICY_PATH)
    calls = []

    def fake_probe(host, port, timeout):
        calls.append((host, port, timeout))
        return ProbeOutcome("reachable", "test_success", 1.0)

    run = probe_policy(policy, "guest", timeout=0.5, probe_func=fake_probe)
    assert set(run["observations"]) == {"SEG-001"}
    assert calls == [("10.30.0.10", 443, 0.5)]
    assert run["measurement"]["source_zone"] == "guest"


def test_deny_policy_successful_connection_is_recorded_reachable():
    policy = load_policy(POLICY_PATH)
    run = probe_policy(
        policy, "guest", probe_func=lambda host, port, timeout: ProbeOutcome("reachable", "test_success", 0.5)
    )
    assert run["observations"]["SEG-001"] == "reachable"


def test_failed_tcp_connect_does_not_claim_a_deny_policy_pass():
    policy = load_policy(POLICY_PATH)
    run = probe_policy(
        policy, "guest", probe_func=lambda host, port, timeout: ProbeOutcome("inconclusive", "timeout", 1500)
    )
    assert run["observations"]["SEG-001"] == "inconclusive"


def test_unknown_source_zone_is_rejected():
    with pytest.raises(ValueError, match="Unknown source zone"):
        probe_policy(load_policy(POLICY_PATH), "not-a-zone")


def test_tcp_probe_classifies_connection_refusal_as_inconclusive(monkeypatch):
    def refused(*args, **kwargs):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(socket, "create_connection", refused)
    outcome = tcp_connect_probe("127.0.0.1", 8765, 0.5)
    assert outcome.state == "inconclusive"
    assert "not proof of segmentation" in outcome.reason


def test_tcp_probe_rejects_hostname_targets():
    with pytest.raises(ValueError, match="literal IP address"):
        tcp_connect_probe("example.com", 443)


def test_tcp_probe_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="between 0.1 and 10"):
        tcp_connect_probe("127.0.0.1", 8765, 20)


def test_probe_records_source_ip_and_per_attempt_timestamps():
    policy = load_policy(POLICY_PATH)

    def fake_probe(host, port, timeout):
        return ProbeOutcome(
            "inconclusive",
            "test_timeout",
            100.0,
            source_ip="10.20.0.100",
        )

    run = probe_policy(policy, "guest", probe_func=fake_probe)
    detail = run["measurement"]["details"][0]

    assert detail["source_ip"] == "10.20.0.100"
    assert detail["started_at"]
    assert detail["completed_at"]
    assert detail["started_at"] <= detail["completed_at"]
    assert run["measurement"]["started_at"]
    assert run["measurement"]["completed_at"]


def test_probe_records_unknown_source_ip_when_route_lookup_fails(monkeypatch):
    from segcheck import probe as probe_module

    monkeypatch.setattr(
        probe_module,
        "_determine_source_ip",
        lambda host, port: None,
    )

    policy = load_policy(POLICY_PATH)
    run = probe_policy(
        policy,
        "guest",
        probe_func=lambda host, port, timeout: ProbeOutcome(
            "inconclusive", "test_timeout", 100.0
        ),
    )

    assert run["measurement"]["details"][0]["source_ip"] is None


def test_source_ip_route_lookup_does_not_require_a_tcp_connection(monkeypatch):
    from segcheck import probe as probe_module

    class FakeRouteSocket:
        def __init__(self, *args, **kwargs):
            self.connected_to = None

        def connect(self, address):
            self.connected_to = address

        def getsockname(self):
            return ("10.20.0.100", 0)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        probe_module.socket,
        "socket",
        FakeRouteSocket,
    )

    assert probe_module._determine_source_ip("10.30.0.10", 8080) == "10.20.0.100"


def test_probe_rejects_blocked_state_from_injected_probe():
    policy = load_policy(POLICY_PATH)

    def fake_probe(host, port, timeout):
        return ProbeOutcome("blocked", "claimed_block", 1.0)

    with pytest.raises(ValueError, match="firewall blocking requires separate evidence"):
        probe_policy(policy, "guest", probe_func=fake_probe)


def test_probe_rejects_invalid_probe_return_type():
    policy = load_policy(POLICY_PATH)

    with pytest.raises(ValueError, match="must return a ProbeOutcome"):
        probe_policy(
            policy,
            "guest",
            probe_func=lambda host, port, timeout: {"state": "reachable"},
        )


def test_deny_aggregation_never_infers_blocking():
    from segcheck.probe import _aggregate_check_observation

    assert _aggregate_check_observation("deny", ["inconclusive"]) == "inconclusive"
    assert _aggregate_check_observation(
        "deny", ["inconclusive", "inconclusive"]
    ) == "inconclusive"
    assert _aggregate_check_observation(
        "deny", ["reachable", "inconclusive"]
    ) == "reachable"


def test_allow_aggregation_requires_all_ports_reachable():
    from segcheck.probe import _aggregate_check_observation

    assert _aggregate_check_observation("allow", ["reachable"]) == "reachable"
    assert _aggregate_check_observation(
        "allow", ["reachable", "inconclusive"]
    ) == "inconclusive"
