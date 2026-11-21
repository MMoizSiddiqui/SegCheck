from pathlib import Path

import pytest

from segcheck.policy_engine import (
    PolicyValidationError,
    evaluate_check,
    evaluate_policy,
    load_policy,
    validate_policy_data,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "fixtures" / "lab-policy.yaml"


def test_example_policy_loads_and_has_five_checks():
    policy = load_policy(POLICY_PATH)
    assert policy.policy_id == "SEGCHECK-POLICY-001"
    assert len(policy.zones) == 7
    assert len(policy.checks) == 5


def test_deny_policy_fails_when_path_is_reachable():
    policy = load_policy(POLICY_PATH)
    result = evaluate_check(policy.checks[0], "reachable")
    assert result.result == "FAIL"


def test_deny_policy_blocked_without_verified_evidence_is_inconclusive():
    policy = load_policy(POLICY_PATH)
    result = evaluate_check(policy.checks[0], "blocked")
    assert result.observed == "blocked"
    assert result.result == "INCONCLUSIVE"


def test_evaluate_check_rejects_caller_asserted_blocked_verification():
    policy = load_policy(POLICY_PATH)
    with pytest.raises(TypeError):
        evaluate_check(
            policy.checks[0], "blocked", blocked_evidence_verified=True
        )


def test_missing_observation_is_inconclusive_not_pass():
    policy = load_policy(POLICY_PATH)
    report = evaluate_policy(policy, {})
    assert report["summary"]["inconclusive"] == 5
    assert report["summary"]["pass"] == 0


def test_demo_observations_report_one_violation():
    import json

    policy = load_policy(POLICY_PATH)
    data = json.loads((ROOT / "fixtures" / "sample-observations.json").read_text(encoding="utf-8"))
    report = evaluate_policy(policy, data["observations"])
    assert report["summary"] == {"total": 5, "pass": 2, "fail": 1, "inconclusive": 2}
    assert report["results"][0]["check_id"] == "SEG-001"
    assert report["results"][0]["result"] == "FAIL"


def test_invalid_port_is_rejected():
    policy_data = {
        "schema_version": 1,
        "policy_id": "TEST-POLICY",
        "name": "Test",
        "organization": "Example",
        "pci_dss_version": "4.0.1",
        "zones": [{"id": "guest", "name": "Guest"}, {"id": "cde", "name": "CDE"}],
        "checks": [{
            "id": "SEG-001", "name": "Bad port", "source_zone": "guest",
            "destination_zone": "cde", "destination_host": "10.0.0.2",
            "protocol": "tcp", "ports": [70000], "expected": "deny",
            "rationale": "Testing invalid port.", "pci_requirements": []
        }]
    }
    with pytest.raises(PolicyValidationError, match="between 1 and 65535"):
        validate_policy_data(policy_data)


def test_policy_requires_explicit_verification_for_blocked_pass():
    policy = load_policy(POLICY_PATH)
    report = evaluate_policy(policy, {"SEG-001": "blocked"})
    assert report["results"][0]["result"] == "INCONCLUSIVE"


def test_policy_rejects_caller_asserted_blocked_verification():
    policy = load_policy(POLICY_PATH)
    with pytest.raises(TypeError):
        evaluate_policy(
            policy,
            {"SEG-001": "blocked"},
            verified_blocked_checks={"SEG-001"},
        )


def test_unknown_observation_check_id_is_rejected():
    policy = load_policy(POLICY_PATH)
    with pytest.raises(ValueError, match="unknown check id"):
        evaluate_policy(policy, {"SEG-999": "blocked"})


def test_unknown_observation_state_is_rejected():
    policy = load_policy(POLICY_PATH)
    with pytest.raises(ValueError, match="Unsupported observation"):
        evaluate_policy(policy, {"SEG-001": "maybe"})



def test_policy_yaml_rejects_duplicate_mapping_keys():
    from segcheck.policy_engine import parse_policy_yaml

    content = """
schema_version: 1
policy_id: TEST-POLICY
policy_id: ATTACKER-POLICY
"""

    with pytest.raises(PolicyValidationError, match="Invalid YAML"):
        parse_policy_yaml(content)


def test_policy_yaml_rejects_duplicate_nested_mapping_keys():
    from segcheck.policy_engine import parse_policy_yaml

    content = """
schema_version: 1
policy_id: TEST-POLICY
name: Test
organization: Example
pci_dss_version: "4.0.1"
zones:
  - id: guest
    name: Guest
    name: Attacker Controlled Name
checks:
  - id: SEG-001
    name: Test
    source_zone: guest
    destination_zone: guest
    destination_host: 10.0.0.1
    protocol: tcp
    ports: [443]
    expected: deny
    rationale: Test
"""

    with pytest.raises(PolicyValidationError, match="Invalid YAML"):
        parse_policy_yaml(content)


def test_policy_yaml_rejects_invalid_utf8_bytes():
    from segcheck.policy_engine import parse_policy_yaml

    with pytest.raises(PolicyValidationError, match="UTF-8"):
        parse_policy_yaml(b"\xff\xfe\xfa")


def test_policy_yaml_rejects_oversized_content():
    from segcheck.policy_engine import (
        MAX_POLICY_BYTES,
        parse_policy_yaml,
    )

    with pytest.raises(PolicyValidationError, match="exceeds"):
        parse_policy_yaml(b" " * (MAX_POLICY_BYTES + 1))


def _framework_mapping_test_policy():
    return {
        "schema_version": 1,
        "policy_id": "TEST-POLICY",
        "name": "Framework mapping test",
        "organization": "Example",
        "pci_dss_version": "4.0.1",
        "zones": [
            {"id": "guest", "name": "Guest"},
            {"id": "cde", "name": "Cardholder Data Environment"},
        ],
        "checks": [{
            "id": "SEG-001",
            "name": "Guest to CDE restriction",
            "source_zone": "guest",
            "destination_zone": "cde",
            "destination_host": "10.0.0.10",
            "protocol": "tcp",
            "ports": [443],
            "expected": "deny",
            "rationale": "Guest traffic must not reach the CDE.",
        }],
    }


def test_framework_mappings_are_validated_and_serialized():
    data = _framework_mapping_test_policy()
    data["checks"][0]["framework_mappings"] = [
        {
            "framework": "PCI_DSS",
            "version": "4.0.1",
            "control_id": "11.4.5",
            "title": "Segmentation testing",
            "relationship": "direct",
        },
        {
            "framework": "custom_security",
            "version": "1.0",
            "control_id": "NET-01",
            "title": "Network isolation",
        },
    ]

    policy = validate_policy_data(data)
    mappings = policy.checks[0].framework_mappings

    assert len(mappings) == 2
    assert mappings[0].framework == "pci_dss"
    assert mappings[0].relationship == "direct"
    assert mappings[1].relationship == "supporting"

    result = evaluate_check(policy.checks[0], "reachable").to_dict()
    assert result["framework_mappings"][0]["control_id"] == "11.4.5"
    assert result["framework_mappings"][1]["framework"] == "custom_security"


def test_existing_policy_without_framework_mappings_remains_compatible():
    data = _framework_mapping_test_policy()
    policy = validate_policy_data(data)

    assert policy.checks[0].framework_mappings == ()
    result = evaluate_check(policy.checks[0], "reachable").to_dict()
    assert result["framework_mappings"] == []


@pytest.mark.parametrize("invalid_value", [
    "not-a-list",
    {},
    123,
])
def test_framework_mappings_reject_invalid_container(invalid_value):
    data = _framework_mapping_test_policy()
    data["checks"][0]["framework_mappings"] = invalid_value

    with pytest.raises(PolicyValidationError, match="must be a list"):
        validate_policy_data(data)


def test_framework_mappings_reject_non_mapping_entries():
    data = _framework_mapping_test_policy()
    data["checks"][0]["framework_mappings"] = ["pci_dss"]

    with pytest.raises(PolicyValidationError, match="must be a mapping"):
        validate_policy_data(data)


@pytest.mark.parametrize("missing_field", [
    "framework",
    "version",
    "control_id",
    "title",
])
def test_framework_mapping_requires_all_identity_fields(missing_field):
    data = _framework_mapping_test_policy()
    mapping = {
        "framework": "pci_dss",
        "version": "4.0.1",
        "control_id": "11.4.5",
        "title": "Segmentation testing",
    }
    del mapping[missing_field]
    data["checks"][0]["framework_mappings"] = [mapping]

    with pytest.raises(PolicyValidationError):
        validate_policy_data(data)


def test_framework_mapping_rejects_invalid_framework_identifier():
    data = _framework_mapping_test_policy()
    data["checks"][0]["framework_mappings"] = [{
        "framework": "../pci-dss",
        "version": "4.0.1",
        "control_id": "11.4.5",
        "title": "Segmentation testing",
    }]

    with pytest.raises(PolicyValidationError, match="framework identifier"):
        validate_policy_data(data)


@pytest.mark.parametrize("relationship", [
    [],
    {},
    1,
    True,
    "unrelated",
])
def test_framework_mapping_rejects_invalid_relationship(relationship):
    data = _framework_mapping_test_policy()
    data["checks"][0]["framework_mappings"] = [{
        "framework": "pci_dss",
        "version": "4.0.1",
        "control_id": "11.4.5",
        "title": "Segmentation testing",
        "relationship": relationship,
    }]

    with pytest.raises(PolicyValidationError, match="relationship"):
        validate_policy_data(data)


def test_framework_mapping_rejects_duplicate_control_mapping():
    data = _framework_mapping_test_policy()
    mapping = {
        "framework": "pci_dss",
        "version": "4.0.1",
        "control_id": "11.4.5",
        "title": "Segmentation testing",
    }
    data["checks"][0]["framework_mappings"] = [mapping, dict(mapping)]

    with pytest.raises(PolicyValidationError, match="duplicates"):
        validate_policy_data(data)


@pytest.mark.parametrize(("field", "limit"), [
    ("version", 32),
    ("control_id", 128),
    ("title", 256),
])
def test_framework_mapping_rejects_oversized_fields(field, limit):
    data = _framework_mapping_test_policy()
    mapping = {
        "framework": "pci_dss",
        "version": "4.0.1",
        "control_id": "11.4.5",
        "title": "Segmentation testing",
    }
    mapping[field] = "X" * (limit + 1)
    data["checks"][0]["framework_mappings"] = [mapping]

    with pytest.raises(PolicyValidationError, match="exceeds"):
        validate_policy_data(data)
