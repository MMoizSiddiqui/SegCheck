import json

import pytest

from segcheck.assessment import (
    AssessmentError,
    _validate_correlation,
    create_assessment,
)
from segcheck.evidence_correlator import correlate_probe
from segcheck.policy_engine import load_policy
from test_evidence_correlator import make_event, make_probe, write_inputs


def build_assessment(tmp_path, events, probe=None, config=None):
    paths = write_inputs(tmp_path, events, probe, config)

    return create_assessment(
        probe_path=paths[0],
        evidence_config_path=paths[1],
        events_path=paths[2],
        policy_path=paths[3],
    )


def test_correlated_block_event_does_not_create_pass(tmp_path):
    report = build_assessment(
        tmp_path,
        [make_event()],
        probe=make_probe(observed="inconclusive"),
    )

    result = report["results"][0]

    assert result["result"] == "INCONCLUSIVE"
    assert result["firewall_evidence"][0]["status"] == "corroborated"
    assert report["assessment"]["evidence_informs_compliance_decision"] is False


def test_missing_firewall_event_is_reported(tmp_path):
    report = build_assessment(
        tmp_path,
        [],
        probe=make_probe(observed="inconclusive"),
    )

    result = report["results"][0]

    assert result["result"] == "INCONCLUSIVE"
    assert result["firewall_evidence"][0]["status"] == "no_matching_evidence"
    assert report["assessment"]["evidence_summary"]["no_matching_evidence"] == 1


def test_reachable_denied_connection_remains_fail(tmp_path):
    report = build_assessment(
        tmp_path,
        [make_event()],
        probe=make_probe(observed="reachable"),
    )

    result = report["results"][0]

    assert result["result"] == "FAIL"
    assert result["firewall_evidence"][0]["status"] == "contradictory"


def test_assessment_contains_probe_and_policy_identity(tmp_path):
    report = build_assessment(
        tmp_path,
        [],
        probe=make_probe(),
    )

    assert report["assessment"]["probe_run_id"] == "PROBE-TEST-001"
    assert report["assessment"]["source_zone"] == "guest"
    assert report["policy"]["id"] == "TEST-POLICY-001"


def test_malformed_probe_json_is_rejected(tmp_path):
    probe_path = tmp_path / "probe.json"
    probe_path.write_text("{invalid json", encoding="utf-8")

    config_path = tmp_path / "evidence.yaml"
    config_path.write_text("invalid: true", encoding="utf-8")

    events_path = tmp_path / "events.jsonl"
    events_path.write_text("", encoding="utf-8")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("", encoding="utf-8")

    with pytest.raises(Exception):
        create_assessment(
            probe_path,
            policy_path,
            config_path,
            events_path,
        )


def test_assessment_reuses_single_probe_and_policy_snapshots(
    tmp_path, monkeypatch
):
    import segcheck.assessment as assessment_module

    paths = write_inputs(
        tmp_path,
        [],
        make_probe(observed="inconclusive"),
    )

    original_probe_loader = assessment_module._load_probe_snapshot
    original_policy_loader = assessment_module.load_policy
    original_correlator = assessment_module.correlate_probe
    original_evaluator = assessment_module.evaluate_policy

    captured = {
        "probe_loads": 0,
        "policy_loads": 0,
        "probe": None,
        "policy": None,
        "correlator_probe": None,
        "correlator_policy": None,
        "evaluator_policy": None,
    }

    def tracked_probe_loader(path):
        captured["probe_loads"] += 1
        probe = original_probe_loader(path)
        captured["probe"] = probe
        return probe

    def tracked_policy_loader(path):
        captured["policy_loads"] += 1
        policy = original_policy_loader(path)
        captured["policy"] = policy
        return policy

    def tracked_correlator(*args, **kwargs):
        captured["correlator_probe"] = kwargs.get("_probe_data")
        captured["correlator_policy"] = kwargs.get("_policy")
        return original_correlator(*args, **kwargs)

    def tracked_evaluator(policy, observations):
        captured["evaluator_policy"] = policy
        return original_evaluator(policy, observations)

    monkeypatch.setattr(
        assessment_module, "_load_probe_snapshot", tracked_probe_loader
    )
    monkeypatch.setattr(
        assessment_module, "load_policy", tracked_policy_loader
    )
    monkeypatch.setattr(
        assessment_module, "correlate_probe", tracked_correlator
    )
    monkeypatch.setattr(
        assessment_module, "evaluate_policy", tracked_evaluator
    )

    report = assessment_module.create_assessment(
        probe_path=paths[0],
        evidence_config_path=paths[1],
        events_path=paths[2],
        policy_path=paths[3],
    )

    assert captured["probe_loads"] == 1
    assert captured["policy_loads"] == 1

    assert captured["correlator_probe"] is captured["probe"]
    assert captured["correlator_policy"] is captured["policy"]
    assert captured["evaluator_policy"] is captured["policy"]

    assert report["assessment"]["probe_run_id"] == "PROBE-TEST-001"
    assert report["results"][0]["result"] == "INCONCLUSIVE"



def _build_correlation_inputs(tmp_path, events, probe=None):
    paths = write_inputs(tmp_path, events, probe=probe)
    correlation = correlate_probe(*paths)
    policy = load_policy(paths[3])
    return correlation, policy


def test_validator_accepts_duplicate_event_id_ambiguity(tmp_path):
    event = make_event(event_id="duplicate-id")
    correlation, policy = _build_correlation_inputs(
        tmp_path, [event, event.copy()]
    )

    result = correlation["results"][0]
    assert result["status"] == "ambiguous"
    assert result["reason"] == "duplicate_event_id"
    assert result["matched_event_count"] == 1
    assert result["event_ids"] == ["duplicate-id"]

    validated = _validate_correlation(correlation, policy, "guest")
    assert validated[("LIVE-SEG-001", 8080)]["status"] == "ambiguous"


def test_validator_accepts_event_limit_exceeded_with_retained_events(
    tmp_path, monkeypatch
):
    import segcheck.evidence_correlator as correlator_module

    monkeypatch.setattr(
        correlator_module, "MAX_MATCHING_EVENTS_PER_CHECK", 2
    )

    events = [
        make_event(event_id="limit-1"),
        make_event(event_id="limit-2", source_port=47667),
        make_event(event_id="limit-3", source_port=47668),
    ]

    correlation, policy = _build_correlation_inputs(tmp_path, events)
    result = correlation["results"][0]

    assert result["status"] == "inconclusive"
    assert result["reason"] == "matching_event_limit_exceeded"
    assert result["evidence_limit_exceeded"] is True
    assert result["matched_event_count"] == 2

    validated = _validate_correlation(correlation, policy, "guest")
    assert validated[("LIVE-SEG-001", 8080)]["matched_event_count"] == 2


def test_validator_rejects_event_count_mismatch(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    correlation["results"][0]["event_ids"] = []

    with pytest.raises(AssessmentError, match="event count"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_rejects_duplicate_retained_event_ids(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    result = correlation["results"][0]
    result["matched_event_count"] = 2
    result["event_ids"] = ["event-001", "event-001"]

    with pytest.raises(AssessmentError, match="duplicate event IDs"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_rejects_inconsistent_packet_counts(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    correlation["results"][0]["duplicate_packet_count"] = 1

    with pytest.raises(AssessmentError, match="duplicate packet count"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_rejects_no_matching_status_with_events(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    result = correlation["results"][0]
    result["status"] = "no_matching_evidence"
    result["reason"] = "no_event_matched_all_configured_fields_within_time_window"

    with pytest.raises(AssessmentError, match="inconsistent with its status"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_rejects_invalid_evidence_limit_flag(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    correlation["results"][0]["evidence_limit_exceeded"] = "false"

    with pytest.raises(AssessmentError, match="evidence-limit flag"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_rejects_event_detail_id_mismatch(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    correlation["results"][0]["events"][0]["event_id"] = "different-id"

    with pytest.raises(AssessmentError, match="event details"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_rejects_ambiguous_multiple_signatures_without_two_packets(
    tmp_path,
):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    result = correlation["results"][0]
    result["status"] = "ambiguous"
    result["reason"] = (
        "multiple_distinct_packet_signatures_matched_one_probe_window"
    )

    with pytest.raises(AssessmentError, match="multiple packet signatures"):
        _validate_correlation(correlation, policy, "guest")

def test_validator_rejects_event_detail_with_invalid_sender_ip(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    correlation["results"][0]["events"][0]["sender_ip"] = "not-an-ip"

    with pytest.raises(AssessmentError, match="event details"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_rejects_event_detail_for_wrong_policy_destination(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    correlation["results"][0]["events"][0]["destination_ip"] = "192.0.2.55"

    with pytest.raises(AssessmentError, match="policy destination"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_requires_retained_details_for_matched_events(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    del correlation["results"][0]["events"]

    with pytest.raises(AssessmentError, match="no retained event details"):
        _validate_correlation(correlation, policy, "guest")


def test_validator_rejects_event_detail_with_invalid_line_number(tmp_path):
    correlation, policy = _build_correlation_inputs(
        tmp_path, [make_event()]
    )
    correlation["results"][0]["events"][0]["line_number"] = True

    with pytest.raises(AssessmentError, match="line number"):
        _validate_correlation(correlation, policy, "guest")

