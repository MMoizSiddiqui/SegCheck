"""Application health endpoint."""

from flask import Blueprint, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from ..extensions import db

health_bp = Blueprint("health", __name__)


@health_bp.get("/api/health")
def health():
    try:
        with db.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return jsonify({
            "status": "unavailable",
            "database": "unavailable",
        }), 503

    return jsonify({
        "status": "ok",
        "database": "available",
    }), 200
