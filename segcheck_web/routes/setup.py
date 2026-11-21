"""Token-protected browser provisioning, available only before the first user."""
import hashlib
import hmac
import re

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash

from segcheck_web.extensions import db
from segcheck_web.models import User
from segcheck_web.models.bootstrap import BootstrapClaim
from segcheck_web.services.environment import field, EnvironmentError

setup_bp = Blueprint("setup", __name__)


def setup_available():
    token = current_app.config.get("SEGCHECK_SETUP_TOKEN")
    return (isinstance(token, str) and 32 <= len(token.encode()) <= 512
            and db.session.query(User.id).first() is None
            and db.session.get(BootstrapClaim, 1) is None)


@setup_bp.route("/setup", methods=["GET", "POST"])
def first_admin():
    if not setup_available():
        abort(404)
    if request.method == "POST":
        try:
            token = field(request.form, "setup_token", 512)
            configured = current_app.config["SEGCHECK_SETUP_TOKEN"]
            if not hmac.compare_digest(hashlib.sha256(token.encode()).digest(), hashlib.sha256(configured.encode()).digest()):
                abort(404)
            username = field(request.form, "username", 64).lower()
            passwords = request.form.getlist("password")
            confirmations = request.form.getlist("confirm_password")
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]", username):
                raise EnvironmentError("Use a username of 3–64 lowercase letters, digits, dots, underscores or hyphens, starting and ending with a letter or digit.")
            if len(passwords) != 1 or len(confirmations) != 1 or passwords[0] != confirmations[0]:
                raise EnvironmentError("Supply matching password and confirmation values.")
            password = passwords[0]
            if len(password) < 12 or len(password.encode()) > 1024:
                raise EnvironmentError("Password must contain at least 12 characters and no more than 1024 UTF-8 bytes.")
            # The singleton claim and user commit atomically. Concurrent requests
            # cannot create two initial administrators with different usernames.
            db.session.add(BootstrapClaim(id=1))
            db.session.add(User(username=username, password_hash=generate_password_hash(password, method="scrypt"), is_active=True))
            db.session.commit()
            flash("Initial administrator created. Sign in to configure the environment.", "success")
            return redirect(url_for("auth.login"))
        except EnvironmentError as exc:
            db.session.rollback()
            flash(str(exc), "error")
        except SQLAlchemyError:
            db.session.rollback()
            abort(409, description="Initial provisioning is unavailable or was already claimed. Reload before retrying.")
    response = current_app.make_response(render_template("auth/setup.html"))
    response.headers["Cache-Control"] = "no-store"
    return response
