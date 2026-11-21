"""Installation environment metadata; assessment reports keep their own copy."""

from sqlalchemy import CheckConstraint
from segcheck_web.extensions import db


class EnvironmentSettings(db.Model):
    __tablename__ = "environment_settings"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_environment_singleton"),
        CheckConstraint("revision >= 1", name="ck_environment_revision"),
        CheckConstraint("length(CAST(payload AS TEXT)) <= 65536", name="ck_environment_size"),
    )
    id = db.Column(db.Integer, primary_key=True)
    payload = db.Column(db.JSON, nullable=False)
    revision = db.Column(db.Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": revision}
