"""Atomic, one-time initial administrator provisioning gate."""
from sqlalchemy import CheckConstraint
from segcheck_web.extensions import db
from segcheck_web.models import utc_now


class BootstrapClaim(db.Model):
    __tablename__ = "bootstrap_claim"
    __table_args__ = (CheckConstraint("id = 1", name="ck_bootstrap_singleton"),)
    id = db.Column(db.Integer, primary_key=True)
    claimed_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
