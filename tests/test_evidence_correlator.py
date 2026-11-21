import json
from pathlib import Path

import pytest

from segcheck.evidence_correlator import (
    EvidenceCorrelationError,
    correlate_probe,
)


CHECK_ID = "LIVE-SEG-001"
RUN_ID = "PROBE-TEST-001"


def make_probe(source_ip="10.20.0.100", observed="inconclusive"):
    return {
        "observations": {CHECK_ID: observed},
        "measurement": {
            "run_id": RUN_ID,
            "policy_id": "TEST-POLICY-001",
            "source_zone": "guest",
            "details": [
                {
                    "check_id": CHECK_ID,
                    "check_name": "Guest must not reach CDE HTTP",
                    "source_zone": "guest",
                    "destination_zone": "cde",
                    "source_ip": source_ip,
                    "destination_host": "10.30.0.10",
                    "protocol": "tcp",
                    "port": 8080,
                    "expected": "deny",
                    "observed": observed,
                    "started_at": "2026-11-05T17:07:46.022+00:00",
                    "completed_at": "2026-11-05T17:07:49.058+00:00",
                }
            ],
        },
    }


def make_event(
    event_id="event-001",
    received_at="2026-11-05T17:07:46.343566+00:00",
    sender_ip="10.20.0.1",
    rule_tracker="1791895687",
    interface="em2",
    action="block",
    source_ip="10.20.0.100",
    destination_ip="10.30.0.10",
    destination_port=8080,
    source_port=47666,
    sequence="3175080121",
    packet_length="60",
):
    fields = [
        "1", "95", "", rule_tracker, interface, "match", action, "in",
        "4", "0x0", "", "64", "58033", "0", "DF", "6", "tcp", packet_length,
        source_ip, destination_ip, str(source_port), str(destination_port),
        "0", "S", sequence, "", "64240", "", "mss;sackOK;TS;nop;wscale",
    ]

    return {
        "event_id": event_id,
        "received_at": received_at,
        "sender_ip": sender_ip,
        "sender_port": 514,
        "raw_message": "test filterlog event",
        "parsed": {
            "event_type": "pf_filterlog",
            "parse_status": "parsed",
            "filterlog_fields": fields,
            "rule_tracker": rule_tracker,
            "interface": interface,
            "action": action,
            "direction": "in",
            "protocol": "tcp",
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
        },
    }


def write_inputs(tmp_path, events, probe=None, config=None):
    probe_path = tmp_path / "probe.json"
    config_path = tmp_path / "evidence.yaml"
    events_path = tmp_path / "events.jsonl"
    policy_path = tmp_path / "policy.yaml"

    probe_path.write_text(
        json.dumps(probe or make_probe()),
        encoding="utf-8",
    )

    config_path.write_text(
        config or """
schema_version: 1
integration:
  id: pfsense-lab
  name: PaySecure pfSense Lab
  platform: pfsense
  event_sources:
    - id: pfsense-guest-firewall
      sender_ip: 10.20.0.1
      description: Lab firewall
  check_mappings:
    - check_id: LIVE-SEG-001
      event_source_id: pfsense-guest-firewall
      interface: em2
      rule_tracker: "1791895687"
      action: block
      direction: in
      protocol: tcp
      source_ip: 10.20.0.100
      destination_ip: 10.30.0.10
      destination_port: 8080
correlation:
  before_seconds: 2
  after_seconds: 5
  duplicate_handling: group_by_probe_attempt
""",
        encoding="utf-8",
    )

    events_path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    policy_path.write_text(
        """schema_version: 1
policy_id: TEST-POLICY-001
name: Test policy
organization: Test
pci_dss_version: "4.0.1"
zones:
  - id: guest
    name: Guest
  - id: cde
    name: CDE
checks:
  - id: LIVE-SEG-001
    name: Guest must not reach CDE HTTP
    source_zone: guest
    destination_zone: cde
    destination_host: 10.30.0.10
    protocol: tcp
    ports: [8080]
    expected: deny
    rationale: Test policy
    pci_requirements: ["11.4.5"]
""",
        encoding="utf-8",
    )

    return probe_path, config_path, events_path, policy_path


def run_correlation(tmp_path, events, probe=None, config=None):
    paths = write_inputs(tmp_path, events, probe, config)
    return correlate_probe(*paths)


def test_exact_firewall_event_is_correlated(tmp_path):
    report = run_correlation(tmp_path, [make_event()])

    result = report["results"][0]
    assert report["probe_run_id"] == RUN_ID
    assert result["status"] == "corroborated"
    assert result["matched_event_count"] == 1
    assert result["unique_packet_count"] == 1
    assert result["event_ids"] == ["event-001"]


def test_retransmissions_are_grouped_as_one_packet_signature(tmp_path):
    first = make_event(event_id="event-001")
    second = make_event(
        event_id="event-002",
        received_at="2026-11-05T17:07:47.338397+00:00",
    )

    report = run_correlation(tmp_path, [first, second])
    result = report["results"][0]

    assert result["status"] == "corroborated"
    assert result["matched_event_count"] == 2
    assert result["unique_packet_count"] == 1
    assert result["duplicate_packet_count"] == 1


def test_different_packet_lengths_are_ambiguous(tmp_path):
    first = make_event(event_id="event-001", packet_length="60")
    second = make_event(
        event_id="event-002",
        packet_length="80",
        received_at="2026-11-05T17:07:47.338397+00:00",
    )

    report = run_correlation(tmp_path, [first, second])
    result = report["results"][0]

    assert result["status"] == "ambiguous"
    assert result["matched_event_count"] == 2
    assert result["unique_packet_count"] == 2


def test_invalid_packet_length_is_not_correlated(tmp_path):
    event = make_event(packet_length="invalid")

    report = run_correlation(tmp_path, [event])
    assert report["results"][0]["status"] == "no_matching_evidence"


def test_stale_event_is_not_correlated(tmp_path):
    stale = make_event(
        received_at="2026-11-05T16:54:16.222320+00:00"
    )

    report = run_correlation(tmp_path, [stale])
    assert report["results"][0]["status"] == "no_matching_evidence"


@pytest.mark.parametrize(
    "changes",
    [
        {"sender_ip": "10.20.0.99"},
        {"rule_tracker": "1111111111"},
        {"interface": "em3"},
        {"action": "pass"},
        {"source_ip": "10.20.0.101"},
        {"destination_ip": "10.30.0.20"},
        {"destination_port": 5432},
    ],
)
def test_mismatched_event_is_not_correlated(tmp_path, changes):
    event = make_event(**changes)

    report = run_correlation(tmp_path, [event])
    assert report["results"][0]["status"] == "no_matching_evidence"


def test_missing_probe_source_ip_is_inconclusive(tmp_path):
    report = run_correlation(
        tmp_path,
        [make_event()],
        probe=make_probe(source_ip=None),
    )

    result = report["results"][0]
    assert result["status"] == "inconclusive"
    assert result["reason"] == "probe_source_ip_missing"


def test_distinct_packet_signatures_are_ambiguous(tmp_path):
    first = make_event(event_id="event-001")
    second = make_event(
        event_id="event-002",
        source_port=47667,
        sequence="123456789",
        received_at="2026-11-05T17:07:47.338397+00:00",
    )

    report = run_correlation(tmp_path, [first, second])
    result = report["results"][0]

    assert result["status"] == "ambiguous"
    assert result["matched_event_count"] == 2
    assert result["unique_packet_count"] == 2


def test_malformed_jsonl_is_ignored_and_counted(tmp_path):
    paths = write_inputs(tmp_path, [make_event()])
    events_path = paths[2]

    with events_path.open("a", encoding="utf-8") as handle:
        handle.write("{this is not valid JSON}\n")

    report = correlate_probe(*paths)
    result = report["results"][0]

    assert result["status"] == "corroborated"
    assert result["malformed_jsonl_line_count"] == 1


def test_invalid_configuration_is_rejected(tmp_path):
    invalid_config = """
schema_version: 1
integration:
  id: pfsense-lab
  name: Test
  platform: pfsense
  event_sources:
    - id: pfsense-guest-firewall
      sender_ip: not-an-ip
  check_mappings:
    - check_id: LIVE-SEG-001
      event_source_id: pfsense-guest-firewall
      interface: em2
      rule_tracker: "1791895687"
      action: block
      direction: in
      protocol: tcp
      source_ip: 10.20.0.100
      destination_ip: 10.30.0.10
      destination_port: 8080
correlation:
  before_seconds: 2
  after_seconds: 5
  duplicate_handling: group_by_probe_attempt
"""

    with pytest.raises(EvidenceCorrelationError):
        run_correlation(tmp_path, [make_event()], config=invalid_config)


def test_duplicate_event_ids_are_not_counted_as_independent_evidence(tmp_path):
    event = make_event(event_id="event-duplicate")

    report = run_correlation(tmp_path, [event, event.copy()])
    result = report["results"][0]

    assert result["status"] == "ambiguous"
    assert result["reason"] == "duplicate_event_id"


def test_reachable_probe_with_matching_block_event_is_contradictory(tmp_path):
    report = run_correlation(
        tmp_path,
        [make_event()],
        probe=make_probe(observed="reachable"),
    )
    result = report["results"][0]

    assert result["status"] == "contradictory"
    assert result["reason"] == "probe_and_firewall_evidence_conflict"


def test_firewall_action_must_match_policy_expectation(tmp_path):
    config = """
schema_version: 1
integration:
  id: pfsense-lab
  name: PaySecure pfSense Lab
  platform: pfsense
  event_sources:
    - id: pfsense-guest-firewall
      sender_ip: 10.20.0.1
  check_mappings:
    - check_id: LIVE-SEG-001
      event_source_id: pfsense-guest-firewall
      interface: em2
      rule_tracker: "1791895687"
      action: pass
      direction: in
      protocol: tcp
      source_ip: 10.20.0.100
      destination_ip: 10.30.0.10
      destination_port: 8080
correlation:
  before_seconds: 2
  after_seconds: 5
  duplicate_handling: group_by_probe_attempt
"""

    report = run_correlation(
        tmp_path,
        [make_event()],
        config=config,
    )
    result = report["results"][0]

    assert result["status"] == "inconclusive"
    assert result["reason"] == "mapping_action_conflicts_with_policy_expectation"


def test_root_observation_must_match_detail_observation(tmp_path):
    probe = make_probe()
    probe["observations"][CHECK_ID] = "reachable"

    paths = write_inputs(tmp_path, [make_event()], probe=probe)

    with pytest.raises(EvidenceCorrelationError):
        correlate_probe(*paths)


def test_probe_rejects_unknown_observation_state(tmp_path):
    probe = make_probe(observed="maybe")
    paths = write_inputs(tmp_path, [make_event()], probe=probe)

    with pytest.raises(EvidenceCorrelationError):
        correlate_probe(*paths)
def test_malformed_packet_fields_do_not_crash_or_match(tmp_path):
    event = make_event()
    event["parsed"]["source_port"] = {"unexpected": "object"}

    report = run_correlation(tmp_path, [event])
    result = report["results"][0]

    assert result["status"] == "no_matching_evidence"
    assert result["matched_event_count"] == 0


def test_malformed_sender_ip_is_not_correlated(tmp_path):
    event = make_event(sender_ip={"unexpected": "object"})

    report = run_correlation(tmp_path, [event])
    result = report["results"][0]

    assert result["status"] == "no_matching_evidence"
    assert result["matched_event_count"] == 0


def test_conflicting_duplicate_event_id_is_ambiguous(tmp_path):
    first = make_event(event_id="event-duplicate")
    second = make_event(
        event_id="event-duplicate",
        source_port=47667,
        sequence="123456789",
        received_at="2026-11-05T17:07:47.338397+00:00",
    )

    report = run_correlation(tmp_path, [first, second])
    result = report["results"][0]

    assert result["status"] == "ambiguous"
    assert result["reason"] == "duplicate_event_id"


def test_matching_event_limit_is_inconclusive(tmp_path, monkeypatch):
    import segcheck.evidence_correlator as correlator

    monkeypatch.setattr(correlator, "MAX_MATCHING_EVENTS_PER_CHECK", 2)

    events = [
        make_event(event_id="event-limit-1"),
        make_event(event_id="event-limit-2", source_port=47667),
        make_event(event_id="event-limit-3", source_port=47668),
    ]

    report = run_correlation(tmp_path, events)
    result = report["results"][0]

    assert result["status"] == "inconclusive"
    assert result["reason"] == "matching_event_limit_exceeded"
    assert result["evidence_limit_exceeded"] is True
    assert result["matched_event_count"] == 2


def test_multiple_ports_for_one_check_are_correlated_independently(tmp_path):
    second_port = 8443
    second_event = make_event(
        event_id="event-8443",
        destination_port=second_port,
        sequence="987654321",
    )

    paths = write_inputs(
        tmp_path,
        [make_event(), second_event],
    )
    probe_path, config_path, events_path, policy_path = paths

    probe = json.loads(probe_path.read_text(encoding="utf-8"))
    second_detail = dict(probe["measurement"]["details"][0])
    second_detail["port"] = second_port
    probe["measurement"]["details"].append(second_detail)
    probe_path.write_text(json.dumps(probe), encoding="utf-8")

    policy_text = policy_path.read_text(encoding="utf-8")
    policy_path.write_text(
        policy_text.replace("ports: [8080]", "ports: [8080, 8443]"),
        encoding="utf-8",
    )

    config_text = config_path.read_text(encoding="utf-8")
    second_mapping = """    - check_id: LIVE-SEG-001
      event_source_id: pfsense-guest-firewall
      interface: em2
      rule_tracker: "1791895687"
      action: block
      direction: in
      protocol: tcp
      source_ip: 10.20.0.100
      destination_ip: 10.30.0.10
      destination_port: 8443
"""
    config_path.write_text(
        config_text.replace("correlation:\n", second_mapping + "correlation:\n"),
        encoding="utf-8",
    )

    report = correlate_probe(*paths)

    assert len(report["results"]) == 2
    assert {
        (result["check_id"], result["port"], result["status"])
        for result in report["results"]
    } == {
        (CHECK_ID, 8080, "corroborated"),
        (CHECK_ID, 8443, "corroborated"),
    }


def test_duplicate_mapping_for_same_check_and_port_is_rejected(tmp_path):
    paths = write_inputs(tmp_path, [make_event()])
    config_path = paths[1]

    config_text = config_path.read_text(encoding="utf-8")
    duplicate_mapping = """    - check_id: LIVE-SEG-001
      event_source_id: pfsense-guest-firewall
      interface: em2
      rule_tracker: "1791895687"
      action: block
      direction: in
      protocol: tcp
      source_ip: 10.20.0.100
      destination_ip: 10.30.0.10
      destination_port: 8080
"""
    config_path.write_text(
        config_text.replace("correlation:\n", duplicate_mapping + "correlation:\n"),
        encoding="utf-8",
    )

    with pytest.raises(EvidenceCorrelationError, match="Duplicate check mapping"):
        correlate_probe(*paths)


def test_probe_detail_must_match_authoritative_policy(tmp_path):
    probe = make_probe()
    probe["measurement"]["details"][0]["destination_host"] = "10.30.0.99"

    paths = write_inputs(tmp_path, [make_event()], probe=probe)

    with pytest.raises(EvidenceCorrelationError, match="authoritative policy"):
        correlate_probe(*paths)
