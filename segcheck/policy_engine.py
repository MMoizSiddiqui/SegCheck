"""Validated policy loading and deterministic segmentation evaluation.

This module does not perform network scans. It compares trusted, normalized
observations with the policy expectation. The scanning adapter will be a
separate module so network measurement and compliance decisions stay separate.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from .secure_files import SecureFileError, read_bounded_file


class PolicyValidationError(ValueError):
    """Raised when a policy file is malformed or unsafe to evaluate."""


VALID_PROTOCOLS = {"tcp", "udp", "icmp"}
VALID_EXPECTATIONS = {"allow", "deny"}
VALID_OBSERVATIONS = {"reachable", "blocked", "inconclusive"}
VALID_RESULTS = {"PASS", "FAIL", "INCONCLUSIVE"}
_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,31}$")


MAX_POLICY_BYTES = 1_048_576

MAX_FRAMEWORK_VERSION_LENGTH = 32
MAX_FRAMEWORK_CONTROL_ID_LENGTH = 128
MAX_FRAMEWORK_TITLE_LENGTH = 256


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys and YAML aliases."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            event = self.get_event()
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "YAML aliases are not permitted in policy files",
                event.start_mark,
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None, None, "expected a YAML mapping", node.start_mark
            )

        # Resolve YAML merge keys before checking for duplicates.
        self.flatten_mapping(node)
        mapping = {}

        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)

            try:
                hash(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from exc

            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate mapping key {key!r}",
                    key_node.start_mark,
                )

            mapping[key] = self.construct_object(value_node, deep=deep)

        return mapping


def parse_policy_yaml(content: str | bytes) -> SegmentationPolicy:
    """Decode, strictly parse and validate bounded policy YAML content."""
    if isinstance(content, bytes):
        raw = content
    elif isinstance(content, str):
        try:
            raw = content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PolicyValidationError(
                "Policy content must be valid UTF-8"
            ) from exc
    else:
        raise PolicyValidationError("Policy content must be text or bytes")

    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyValidationError(
            f"Policy content exceeds the {MAX_POLICY_BYTES}-byte limit"
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyValidationError(
            "Policy content must be valid UTF-8"
        ) from exc

    try:
        data = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise PolicyValidationError(
            "Invalid YAML policy content: duplicate keys, aliases or malformed YAML"
        ) from exc
    except RecursionError as exc:
        raise PolicyValidationError(
            "Policy YAML nesting exceeds the supported depth"
        ) from exc

    return validate_policy_data(data)


@dataclass(frozen=True)
class Zone:
    id: str
    name: str
    description: str = ""


@dataclass(frozen=True)
class FrameworkMapping:
    """A traceability relationship between a check and a framework control."""

    framework: str
    version: str
    control_id: str
    title: str
    relationship: str


@dataclass(frozen=True)
class SegmentationCheck:
    id: str
    name: str
    source_zone: str
    destination_zone: str
    destination_host: str
    protocol: str
    ports: tuple[int, ...]
    expected: str
    rationale: str
    pci_requirements: tuple[str, ...]
    framework_mappings: tuple[FrameworkMapping, ...] = ()


@dataclass(frozen=True)
class SegmentationPolicy:
    schema_version: int
    policy_id: str
    name: str
    organization: str
    pci_dss_version: str
    zones: tuple[Zone, ...]
    checks: tuple[SegmentationCheck, ...]


@dataclass(frozen=True)
class EvaluationResult:
    check_id: str
    check_name: str
    source_zone: str
    destination_zone: str
    destination_host: str
    protocol: str
    ports: tuple[int, ...]
    expected: str
    observed: str
    result: str
    rationale: str
    pci_requirements: tuple[str, ...]
    explanation: str
    framework_mappings: tuple[FrameworkMapping, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["ports"] = list(self.ports)
        result["pci_requirements"] = list(self.pci_requirements)
        result["framework_mappings"] = [
            asdict(mapping) for mapping in self.framework_mappings
        ]
        return result


def _require_string(data: Mapping[str, Any], key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicyValidationError(f"{context}.{key} must be a non-empty string")
    return value.strip()


def _require_id(value: str, context: str) -> str:
    if not _ID_PATTERN.fullmatch(value):
        raise PolicyValidationError(
            f"{context} '{value}' must be 2-32 characters, start with a letter, "
            "and contain only letters, digits, '_' or '-'"
        )
    return value


def validate_policy_data(data: Any) -> SegmentationPolicy:
    """Validate a decoded YAML policy and return an immutable typed policy."""
    if not isinstance(data, dict):
        raise PolicyValidationError("Policy root must be a YAML mapping/object")

    schema_version = data.get("schema_version")
    if schema_version != 1:
        raise PolicyValidationError("schema_version must be the integer 1")

    policy_id = _require_string(data, "policy_id", "policy")
    name = _require_string(data, "name", "policy")
    organization = _require_string(data, "organization", "policy")
    pci_dss_version = _require_string(data, "pci_dss_version", "policy")

    raw_zones = data.get("zones")
    if not isinstance(raw_zones, list) or not raw_zones:
        raise PolicyValidationError("zones must be a non-empty list")

    zones: list[Zone] = []
    zone_ids: set[str] = set()
    for index, raw_zone in enumerate(raw_zones):
        context = f"zones[{index}]"
        if not isinstance(raw_zone, dict):
            raise PolicyValidationError(f"{context} must be a mapping/object")
        zone_id = _require_id(_require_string(raw_zone, "id", context), context)
        zone_name = _require_string(raw_zone, "name", context)
        description = raw_zone.get("description", "")
        if not isinstance(description, str):
            raise PolicyValidationError(f"{context}.description must be a string")
        if zone_id in zone_ids:
            raise PolicyValidationError(f"Duplicate zone id: {zone_id}")
        zone_ids.add(zone_id)
        zones.append(Zone(zone_id, zone_name, description.strip()))

    raw_checks = data.get("checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        raise PolicyValidationError("checks must be a non-empty list")

    checks: list[SegmentationCheck] = []
    check_ids: set[str] = set()
    for index, raw_check in enumerate(raw_checks):
        context = f"checks[{index}]"
        if not isinstance(raw_check, dict):
            raise PolicyValidationError(f"{context} must be a mapping/object")

        check_id = _require_id(_require_string(raw_check, "id", context), context)
        if check_id in check_ids:
            raise PolicyValidationError(f"Duplicate check id: {check_id}")
        check_ids.add(check_id)

        check_name = _require_string(raw_check, "name", context)
        source_zone = _require_string(raw_check, "source_zone", context)
        destination_zone = _require_string(raw_check, "destination_zone", context)
        if source_zone not in zone_ids:
            raise PolicyValidationError(
                f"{context}.source_zone '{source_zone}' is not defined in zones"
            )
        if destination_zone not in zone_ids:
            raise PolicyValidationError(
                f"{context}.destination_zone '{destination_zone}' is not defined in zones"
            )

        destination_host = _require_string(raw_check, "destination_host", context)
        try:
            ipaddress.ip_address(destination_host)
        except ValueError as exc:
            raise PolicyValidationError(
                f"{context}.destination_host must be a valid IPv4 or IPv6 address"
            ) from exc

        protocol = _require_string(raw_check, "protocol", context).lower()
        if protocol not in VALID_PROTOCOLS:
            raise PolicyValidationError(
                f"{context}.protocol must be one of: {', '.join(sorted(VALID_PROTOCOLS))}"
            )

        raw_ports = raw_check.get("ports")
        if protocol == "icmp":
            # ICMP echo has no transport port. Accept an omitted or empty list only.
            if raw_ports not in (None, []):
                raise PolicyValidationError(f"{context}.ports must be empty or omitted for icmp checks")
            raw_ports = []
        elif not isinstance(raw_ports, list) or not raw_ports:
            raise PolicyValidationError(f"{context}.ports must be a non-empty list")
        ports: list[int] = []
        for port in raw_ports:
            # bool is a subclass of int in Python, so reject it explicitly.
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise PolicyValidationError(
                    f"{context}.ports entries must be integers between 1 and 65535"
                )
            if port in ports:
                raise PolicyValidationError(f"{context}.ports contains duplicate port {port}")
            ports.append(port)

        expected = _require_string(raw_check, "expected", context).lower()
        if expected not in VALID_EXPECTATIONS:
            raise PolicyValidationError("{context}.expected must be 'allow' or 'deny'".format(context=context))

        rationale = _require_string(raw_check, "rationale", context)
        requirements = raw_check.get("pci_requirements", [])
        if not isinstance(requirements, list) or any(
            not isinstance(item, str) or not item.strip() for item in requirements
        ):
            raise PolicyValidationError(
                f"{context}.pci_requirements must be a list of non-empty strings"
            )

        raw_mappings = raw_check.get("framework_mappings", [])
        if not isinstance(raw_mappings, list):
            raise PolicyValidationError(
                f"{context}.framework_mappings must be a list"
            )

        framework_mappings = []
        mapping_keys = set()

        for mapping_index, raw_mapping in enumerate(raw_mappings):
            mapping_context = f"{context}.framework_mappings[{mapping_index}]"

            if not isinstance(raw_mapping, dict):
                raise PolicyValidationError(
                    f"{mapping_context} must be a mapping/object"
                )

            framework = _require_string(
                raw_mapping, "framework", mapping_context
            ).lower()

            if not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", framework):
                raise PolicyValidationError(
                    f"{mapping_context}.framework must be a valid lowercase "
                    "framework identifier"
                )

            version = _require_string(
                raw_mapping, "version", mapping_context
            )
            control_id = _require_string(
                raw_mapping, "control_id", mapping_context
            )
            title = _require_string(
                raw_mapping, "title", mapping_context
            )

            if len(version) > MAX_FRAMEWORK_VERSION_LENGTH:
                raise PolicyValidationError(
                    f"{mapping_context}.version exceeds "
                    f"{MAX_FRAMEWORK_VERSION_LENGTH} characters"
                )
            if len(control_id) > MAX_FRAMEWORK_CONTROL_ID_LENGTH:
                raise PolicyValidationError(
                    f"{mapping_context}.control_id exceeds "
                    f"{MAX_FRAMEWORK_CONTROL_ID_LENGTH} characters"
                )
            if len(title) > MAX_FRAMEWORK_TITLE_LENGTH:
                raise PolicyValidationError(
                    f"{mapping_context}.title exceeds "
                    f"{MAX_FRAMEWORK_TITLE_LENGTH} characters"
                )

            relationship = raw_mapping.get("relationship", "supporting")

            if (
                not isinstance(relationship, str)
                or relationship not in {"direct", "supporting"}
            ):
                raise PolicyValidationError(
                    f"{mapping_context}.relationship must be 'direct' "
                    "or 'supporting'"
                )

            mapping_key = (framework, version, control_id)
            if mapping_key in mapping_keys:
                raise PolicyValidationError(
                    f"{mapping_context} duplicates a framework control mapping"
                )
            mapping_keys.add(mapping_key)

            framework_mappings.append(
                FrameworkMapping(
                    framework=framework,
                    version=version,
                    control_id=control_id,
                    title=title,
                    relationship=relationship,
                )
            )

        checks.append(
            SegmentationCheck(
                id=check_id,
                name=check_name,
                source_zone=source_zone,
                destination_zone=destination_zone,
                destination_host=destination_host,
                protocol=protocol,
                ports=tuple(ports),
                expected=expected,
                rationale=rationale,
                pci_requirements=tuple(item.strip() for item in requirements),
                framework_mappings=tuple(framework_mappings),
            )
        )

    return SegmentationPolicy(
        schema_version=schema_version,
        policy_id=policy_id,
        name=name,
        organization=organization,
        pci_dss_version=pci_dss_version,
        zones=tuple(zones),
        checks=tuple(checks),
    )


def load_policy(path: str | Path) -> SegmentationPolicy:
    """Read bounded policy YAML safely and validate it before use."""
    policy_path = Path(path)
    try:
        raw = read_bounded_file(
            policy_path,
            max_bytes=MAX_POLICY_BYTES,
            label="Policy file",
        )
    except SecureFileError as exc:
        raise PolicyValidationError(str(exc)) from exc

    return parse_policy_yaml(raw)


def evaluate_check(
    check: SegmentationCheck,
    observed: str | None,
) -> EvaluationResult:
    """Evaluate one check without accepting caller-asserted evidence verification."""
    normalized_observed = (observed or "inconclusive").strip().lower()
    if normalized_observed not in VALID_OBSERVATIONS:
        raise ValueError(
            f"Unsupported observation '{observed}'. Expected one of: "
            f"{', '.join(sorted(VALID_OBSERVATIONS))}"
        )

    if normalized_observed == "blocked":
        result = "INCONCLUSIVE"
        explanation = (
            "Traffic was reported as blocked, but this observation has not been "
            "independently verified through a trusted evidence mechanism."
        )
    elif normalized_observed == "inconclusive":
        result = "INCONCLUSIVE"
        explanation = (
            "The available observation is insufficient to determine policy compliance."
        )
    elif check.expected == "deny" and normalized_observed == "reachable":
        result = "FAIL"
        explanation = (
            "Traffic was reachable even though the policy requires it to be denied."
        )
    elif check.expected == "allow" and normalized_observed == "reachable":
        result = "PASS"
        explanation = "Traffic was reachable as required by the allow policy."
    else:
        raise ValueError(f"Unsupported evaluation state: {normalized_observed}")

    return EvaluationResult(
        check_id=check.id,
        check_name=check.name,
        source_zone=check.source_zone,
        destination_zone=check.destination_zone,
        destination_host=check.destination_host,
        protocol=check.protocol,
        ports=check.ports,
        expected=check.expected,
        observed=normalized_observed,
        result=result,
        rationale=check.rationale,
        pci_requirements=check.pci_requirements,
        explanation=explanation,
        framework_mappings=check.framework_mappings,
    )


def evaluate_policy(
    policy: SegmentationPolicy,
    observations: Mapping[str, str],
) -> dict[str, Any]:
    """Evaluate observations without accepting caller-asserted evidence verification."""
    if not isinstance(observations, Mapping):
        raise ValueError("observations must be a mapping of check IDs to states")

    known_ids = {check.id for check in policy.checks}
    unknown_ids = set(observations) - known_ids
    if unknown_ids:
        raise ValueError(
            f"Observation(s) refer to unknown check id(s): {', '.join(sorted(unknown_ids))}"
        )

    results = [
        evaluate_check(check, observations.get(check.id))
        for check in policy.checks
    ]

    summary = {
        "total": len(results),
        "pass": sum(result.result == "PASS" for result in results),
        "fail": sum(result.result == "FAIL" for result in results),
        "inconclusive": sum(result.result == "INCONCLUSIVE" for result in results),
    }

    return {
        "report_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy": {
            "id": policy.policy_id,
            "name": policy.name,
            "organization": policy.organization,
            "pci_dss_version": policy.pci_dss_version,
        },
        "decision_boundary": (
            "Results apply only to the configured checks and supplied observations; "
            "they are not a compliance certification."
        ),
        "summary": summary,
        "results": [result.to_dict() for result in results],
    }
