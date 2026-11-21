"""SegCheck database models.

Each installation represents one organisation. Policy versions and their
checks/zones are stored as separate historical snapshots.
"""

from datetime import datetime, timezone

from flask_login import UserMixin

from sqlalchemy import CheckConstraint, ForeignKey, ForeignKeyConstraint
from sqlalchemy import Index, UniqueConstraint
from sqlalchemy import event

from segcheck_web.extensions import db


def utc_now():
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class LoginAttemptBucket(db.Model):
    """Privacy-preserving state for bounded login-attempt throttling."""

    __tablename__ = "login_attempt_buckets"
    __table_args__ = (
        CheckConstraint(
            "bucket_type IN ('account_source', 'source')",
            name="ck_login_attempt_buckets_type",
        ),
        CheckConstraint(
            "attempts >= 0",
            name="ck_login_attempt_buckets_attempts",
        ),
        CheckConstraint(
            "length(bucket_key) = 64",
            name="ck_login_attempt_buckets_key_length",
        ),
        Index("ix_login_attempt_buckets_blocked_until", "blocked_until"),
    )

    bucket_key = db.Column(db.String(64), primary_key=True)
    bucket_type = db.Column(db.String(16), nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    window_started_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
    )
    blocked_until = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )


class LoginAttemptReservation(db.Model):
    """A short-lived, privacy-preserving login capacity reservation."""

    __tablename__ = "login_attempt_reservations"
    __table_args__ = (
        CheckConstraint(
            "length(reservation_key) = 64",
            name="ck_login_attempt_reservations_key_length",
        ),
        CheckConstraint(
            "length(account_bucket_key) = 64",
            name="ck_login_attempt_reservations_account_key_length",
        ),
        CheckConstraint(
            "length(source_bucket_key) = 64",
            name="ck_login_attempt_reservations_source_key_length",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_login_attempt_reservations_expiry",
        ),
        Index(
            "ix_login_attempt_reservations_account_bucket",
            "account_bucket_key",
        ),
        Index(
            "ix_login_attempt_reservations_source_bucket",
            "source_bucket_key",
        ),
        Index(
            "ix_login_attempt_reservations_expires_at",
            "expires_at",
        ),
    )

    reservation_key = db.Column(db.String(64), primary_key=True)
    account_bucket_key = db.Column(db.String(64), nullable=False)
    source_bucket_key = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    expires_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
    )


class User(UserMixin, db.Model):
    """A local SegCheck administrator account."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "length(username) BETWEEN 3 AND 64",
            name="ck_users_username_length",
        ),
        CheckConstraint(
            "username = lower(trim(username))",
            name="ck_users_username_normalized",
        ),
        CheckConstraint(
            "length(password_hash) BETWEEN 1 AND 255",
            name="ck_users_password_hash_length",
        ),
        Index("ix_users_is_active", "is_active"),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    def __repr__(self):
        return f"<User {self.username!r}>"


def _protect_historical_policy_records(
    session, flush_context, instances
):
    """Reject ORM updates and deletes of persisted policy snapshots."""
    protected_models = (
        PolicyVersion,
        PolicyVersionZone,
        PolicyCheck,
        PolicyLifecycleEvent,
        Assessment,
    )

    for record in session.dirty:
        if (
            isinstance(record, protected_models)
            and session.is_modified(record, include_collections=True)
        ):
            raise ValueError(
                "Historical policy records cannot be modified"
            )

    for record in session.deleted:
        if isinstance(record, protected_models):
            raise ValueError(
                "Historical policy records cannot be deleted"
            )


class Zone(db.Model):
    """A network security zone in this SegCheck installation."""

    __tablename__ = "zones"

    id = db.Column(db.Integer, primary_key=True)
    zone_key = db.Column(db.String(64), nullable=False, unique=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    assets = db.relationship("Asset", back_populates="zone")

    def __repr__(self):
        return f"<Zone {self.zone_key!r}>"


class Asset(db.Model):
    """An inventoried host or service endpoint assigned to a network zone."""

    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_address", "address"),
        Index("ix_assets_zone_id", "zone_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(253), nullable=True)
    description = db.Column(db.Text, nullable=False, default="")
    zone_id = db.Column(
        db.Integer, ForeignKey("zones.id", ondelete="RESTRICT"), nullable=False
    )
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    zone = db.relationship("Zone", back_populates="assets")

    def __repr__(self):
        return f"<Asset {self.name!r} ({self.address})>"


class Policy(db.Model):
    """The editable identity and lifecycle state of a segmentation policy."""

    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint(
            "status IN ('draft', 'active', 'archived')",
            name="ck_policies_valid_status",
        ),
        Index("ix_policies_status", "status"),
        Index("ix_policies_pci_dss_version", "pci_dss_version"),
    )

    id = db.Column(db.Integer, primary_key=True)
    policy_key = db.Column(db.String(64), nullable=False, unique=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="draft")
    pci_dss_version = db.Column(db.String(32), nullable=False)
    tags = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    versions = db.relationship(
        "PolicyVersion",
        back_populates="policy",
        order_by="PolicyVersion.version_number",
    )

    def __repr__(self):
        return f"<Policy {self.policy_key!r} ({self.status})>"


class PolicyVersion(db.Model):
    """A numbered, historical snapshot of a validated segmentation policy."""

    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint(
            "policy_id", "version_number", name="uq_policy_versions_policy_number"
        ),
        CheckConstraint("version_number >= 1", name="ck_policy_versions_positive_number"),
        CheckConstraint("schema_version >= 1", name="ck_policy_versions_schema_version"),
        Index("ix_policy_versions_policy_id", "policy_id"),
        Index(
            "uq_policy_versions_policy_id_id",
            "policy_id",
            "id",
            unique=True,
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(
        db.Integer, ForeignKey("policies.id", ondelete="RESTRICT"), nullable=False
    )
    version_number = db.Column(db.Integer, nullable=False)
    schema_version = db.Column(db.Integer, nullable=False)
    snapshot = db.Column(db.JSON, nullable=False)
    snapshot_sha256 = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    policy = db.relationship("Policy", back_populates="versions")
    zones = db.relationship("PolicyVersionZone", back_populates="policy_version")
    checks = db.relationship("PolicyCheck", back_populates="policy_version")

    def __repr__(self):
        return f"<PolicyVersion policy={self.policy_id} version={self.version_number}>"


class PolicyVersionZone(db.Model):
    """A zone definition captured inside one specific policy version."""

    __tablename__ = "policy_version_zones"
    __table_args__ = (
        UniqueConstraint(
            "policy_version_id",
            "zone_key",
            name="uq_policy_version_zones_version_key",
        ),
        Index("ix_policy_version_zones_key", "zone_key"),
    )

    id = db.Column(db.Integer, primary_key=True)
    policy_version_id = db.Column(
        db.Integer,
        ForeignKey("policy_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    zone_key = db.Column(db.String(64), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")

    policy_version = db.relationship("PolicyVersion", back_populates="zones")

    def __repr__(self):
        return f"<PolicyVersionZone {self.zone_key!r}>"


class PolicyCheck(db.Model):
    """A searchable segmentation check belonging to one policy version."""

    __tablename__ = "policy_checks"
    __table_args__ = (
        UniqueConstraint(
            "policy_version_id",
            "check_key",
            name="uq_policy_checks_version_key",
        ),
        ForeignKeyConstraint(
            ["policy_version_id", "source_zone_key"],
            ["policy_version_zones.policy_version_id", "policy_version_zones.zone_key"],
            ondelete="RESTRICT",
            name="fk_policy_checks_source_zone",
        ),
        ForeignKeyConstraint(
            ["policy_version_id", "destination_zone_key"],
            ["policy_version_zones.policy_version_id", "policy_version_zones.zone_key"],
            ondelete="RESTRICT",
            name="fk_policy_checks_destination_zone",
        ),
        CheckConstraint(
            "protocol IN ('tcp', 'udp', 'icmp')", name="ck_policy_checks_valid_protocol"
        ),
        CheckConstraint(
            "expected IN ('allow', 'deny')", name="ck_policy_checks_valid_expectation"
        ),
        Index("ix_policy_checks_source_zone", "source_zone_key"),
        Index("ix_policy_checks_destination_zone", "destination_zone_key"),
        Index("ix_policy_checks_protocol", "protocol"),
        Index("ix_policy_checks_expected", "expected"),
    )

    id = db.Column(db.Integer, primary_key=True)
    policy_version_id = db.Column(
        db.Integer,
        ForeignKey("policy_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    check_key = db.Column(db.String(64), nullable=False)
    name = db.Column(db.String(160), nullable=False)
    source_zone_key = db.Column(db.String(64), nullable=False)
    destination_zone_key = db.Column(db.String(64), nullable=False)
    destination_host = db.Column(db.String(45), nullable=False)
    protocol = db.Column(db.String(8), nullable=False)
    ports = db.Column(db.JSON, nullable=False)
    expected = db.Column(db.String(8), nullable=False)
    rationale = db.Column(db.Text, nullable=False)
    pci_requirements = db.Column(db.JSON, nullable=False, default=list)
    framework_mappings = db.Column(db.JSON, nullable=False, default=list)

    policy_version = db.relationship("PolicyVersion", back_populates="checks")

    def __repr__(self):
        return f"<PolicyCheck {self.check_key!r}>"


class PolicyLifecycleEvent(db.Model):
    """Append-only audit record for a policy lifecycle transition."""

    __tablename__ = "policy_lifecycle_events"
    __table_args__ = (
        CheckConstraint(
            "from_status IN ('draft', 'active', 'archived')",
            name="ck_policy_lifecycle_from_status",
        ),
        CheckConstraint(
            "to_status IN ('draft', 'active', 'archived')",
            name="ck_policy_lifecycle_to_status",
        ),
        CheckConstraint(
            "from_status != to_status",
            name="ck_policy_lifecycle_status_changed",
        ),
        CheckConstraint(
            "length(trim(reason)) BETWEEN 1 AND 500",
            name="ck_policy_lifecycle_reason_length",
        ),
        CheckConstraint(
            "actor_identifier IS NULL OR length(actor_identifier) <= 128",
            name="ck_policy_lifecycle_actor_length",
        ),
        Index(
            "ix_policy_lifecycle_policy_created",
            "policy_id",
            "created_at",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(
        db.Integer,
        ForeignKey("policies.id", ondelete="RESTRICT"),
        nullable=False,
    )
    from_status = db.Column(db.String(16), nullable=False)
    to_status = db.Column(db.String(16), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    actor_identifier = db.Column(db.String(128), nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    policy = db.relationship("Policy")

    def __repr__(self):
        return (
            f"<PolicyLifecycleEvent policy={self.policy_id} "
            f"{self.from_status}->{self.to_status}>"
        )



class Assessment(db.Model):
    """Immutable record of one completed network segmentation assessment."""

    __tablename__ = "assessments"
    __table_args__ = (
        ForeignKeyConstraint(
            ["policy_id", "policy_version_id"],
            ["policy_versions.policy_id", "policy_versions.id"],
            ondelete="RESTRICT",
            name="fk_assessments_policy_version_owner",
        ),
        CheckConstraint(
            "length(policy_version_sha256) = 64",
            name="ck_assessments_policy_digest_length",
        ),
        CheckConstraint(
            "length(trim(source_zone)) BETWEEN 1 AND 64",
            name="ck_assessments_source_zone_length",
        ),
        CheckConstraint(
            "length(trim(probe_run_id)) BETWEEN 1 AND 64",
            name="ck_assessments_probe_run_id_length",
        ),
        CheckConstraint(
            "length(CAST(report AS TEXT)) <= 4194304",
            name="ck_assessments_report_size",
        ),
        Index(
            "ix_assessments_policy_created",
            "policy_id",
            "created_at",
        ),
        Index("ix_assessments_actor_created", "actor_user_id", "created_at"),
        Index("ix_assessments_created_at", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(
        db.Integer,
        ForeignKey("policies.id", ondelete="RESTRICT"),
        nullable=False,
    )
    policy_version_id = db.Column(db.Integer, nullable=False)
    actor_user_id = db.Column(
        db.Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    policy_version_sha256 = db.Column(db.String(64), nullable=False)
    source_zone = db.Column(db.String(64), nullable=False)
    probe_run_id = db.Column(db.String(64), nullable=False, unique=True)
    summary = db.Column(db.JSON, nullable=False)
    report = db.Column(db.JSON, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    policy = db.relationship(
        "Policy",
        foreign_keys=[policy_id],
        viewonly=True,
    )
    policy_version = db.relationship(
        "PolicyVersion",
        foreign_keys=[policy_id, policy_version_id],
        primaryjoin=(
            "and_(Assessment.policy_id == PolicyVersion.policy_id, "
            "Assessment.policy_version_id == PolicyVersion.id)"
        ),
        viewonly=True,
    )
    actor = db.relationship(
        "User",
        foreign_keys=[actor_user_id],
        viewonly=True,
    )

    def __repr__(self):
        return (
            f"<Assessment policy={self.policy_id} "
            f"version={self.policy_version_id} run={self.probe_run_id!r}>"
        )


event.listen(
    db.session.session_factory,
    "before_flush",
    _protect_historical_policy_records,
)


__all__ = [
    "Asset",
    "Assessment",
    "User",
    "Policy",
    "PolicyCheck",
    "PolicyLifecycleEvent",
    "PolicyVersion",
    "PolicyVersionZone",
    "Zone",
]
