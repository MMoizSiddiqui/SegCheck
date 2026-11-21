"""Validated, transactional import of segmentation policies."""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from sqlalchemy.exc import IntegrityError

from segcheck.policy_engine import (
    MAX_POLICY_BYTES,
    PolicyValidationError,
    load_policy,
    parse_policy_yaml,
)
from segcheck_web.extensions import db
from segcheck_web.models import (
    Policy,
    PolicyCheck,
    PolicyVersion,
    PolicyVersionZone,
)


class PolicyImportError(ValueError):
    """Raised when a validated policy cannot safely be imported."""


class DuplicatePolicyError(PolicyImportError):
    """Raised when a policy identifier already exists."""


def _canonical_snapshot(policy):
    """Build deterministic JSON-compatible data from a validated policy."""
    snapshot = asdict(policy)

    # Dataclass tuples become JSON arrays through recursive normalization.
    def normalize(value):
        if isinstance(value, dict):
            return {
                key: normalize(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [normalize(item) for item in value]
        return value

    snapshot = normalize(snapshot)

    encoded = json.dumps(
        snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    return snapshot, hashlib.sha256(encoded).hexdigest()


def _validate_persistence_limits(policy):
    """Reject valid engine policies that exceed database field limits."""
    limits = (
        (policy.policy_id, 64, "policy_id"),
        (policy.name, 160, "policy name"),
        (policy.pci_dss_version, 32, "PCI DSS version"),
    )

    for value, maximum, label in limits:
        if len(value) > maximum:
            raise PolicyImportError(
                f"{label} exceeds the database limit of {maximum} characters"
            )

    for zone in policy.zones:
        for value, maximum, label in (
            (zone.id, 64, "zone ID"),
            (zone.name, 120, "zone name"),
        ):
            if len(value) > maximum:
                raise PolicyImportError(
                    f"{label} exceeds the database limit of {maximum} characters"
                )

    for check in policy.checks:
        for value, maximum, label in (
            (check.id, 64, "check ID"),
            (check.name, 160, "check name"),
            (check.destination_host, 45, "destination host"),
            (check.protocol, 8, "protocol"),
            (check.expected, 8, "expected result"),
        ):
            if len(value) > maximum:
                raise PolicyImportError(
                    f"{label} exceeds the database limit of {maximum} characters"
                )


def _persist_validated_policy(validated):
    """Persist a validated policy as a draft and immutable version 1."""
    _validate_persistence_limits(validated)

    snapshot, snapshot_hash = _canonical_snapshot(validated)

    existing = db.session.query(Policy.id).filter_by(
        policy_key=validated.policy_id
    ).first()

    if existing is not None:
        raise DuplicatePolicyError(
            f"Policy ID '{validated.policy_id}' already exists"
        )

    try:
        policy = Policy(
            policy_key=validated.policy_id,
            name=validated.name,
            description="",
            status="draft",
            pci_dss_version=validated.pci_dss_version,
            tags=[],
        )
        db.session.add(policy)
        db.session.flush()

        version = PolicyVersion(
            policy_id=policy.id,
            version_number=1,
            schema_version=validated.schema_version,
            snapshot=snapshot,
            snapshot_sha256=snapshot_hash,
        )
        db.session.add(version)
        db.session.flush()

        db.session.add_all([
            PolicyVersionZone(
                policy_version_id=version.id,
                zone_key=zone.id,
                name=zone.name,
                description=zone.description,
            )
            for zone in validated.zones
        ])
        db.session.flush()

        db.session.add_all([
            PolicyCheck(
                policy_version_id=version.id,
                check_key=check.id,
                name=check.name,
                source_zone_key=check.source_zone,
                destination_zone_key=check.destination_zone,
                destination_host=check.destination_host,
                protocol=check.protocol,
                ports=list(check.ports),
                expected=check.expected,
                rationale=check.rationale,
                pci_requirements=list(check.pci_requirements),
                framework_mappings=[
                    asdict(mapping) for mapping in check.framework_mappings
                ],
            )
            for check in validated.checks
        ])

        db.session.commit()
        return policy

    except IntegrityError as exc:
        db.session.rollback()
        raise PolicyImportError(
            "Policy import violated a database integrity constraint"
        ) from exc

    except Exception:
        db.session.rollback()
        raise


def import_policy_content(content: bytes):
    """Validate and import bounded YAML content without using filesystem paths."""
    if not isinstance(content, bytes):
        raise PolicyImportError("Policy upload content must be bytes")

    if len(content) > MAX_POLICY_BYTES:
        raise PolicyImportError(
            f"Policy content exceeds the {MAX_POLICY_BYTES}-byte limit"
        )

    validated = parse_policy_yaml(content)
    return _persist_validated_policy(validated)


def import_policy_file(path):
    """Validate and import an explicitly selected local policy file.

    Retained for trusted local callers and existing CLI workflows.
    Browser upload handlers should use import_policy_content instead.
    """
    try:
        validated = load_policy(Path(path))
    except PolicyValidationError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise PolicyImportError(
            "Unable to read the selected policy file"
        ) from exc

    return _persist_validated_policy(validated)
