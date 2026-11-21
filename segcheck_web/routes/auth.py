"""Local administrator authentication routes."""

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_user, logout_user
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from sqlalchemy.exc import SQLAlchemyError

from segcheck_web.extensions import db
from segcheck_web.models import User
from segcheck_web.services.login_throttle import (
    release_login_reservation,
    reserve_login_attempt,
    settle_failed_login,
    settle_successful_login,
)


# Reused for unknown usernames to avoid skipping expensive scrypt verification.
_DUMMY_PASSWORD_HASH = generate_password_hash(
    "segcheck-dummy-password-not-used-for-authentication",
    method="scrypt",
)


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a local administrator with reservation-based throttling."""

    if current_user.is_authenticated:
        return redirect(url_for("dashboard.overview"))

    if request.method != "POST":
        return render_template("auth/login.html")

    username_value = request.form.get("username", "")
    password = request.form.get("password", "")

    username_is_string = isinstance(username_value, str)
    password_is_string = isinstance(password, str)

    username = (
        username_value.strip().lower()
        if username_is_string
        else ""
    )

    username_valid = 3 <= len(username) <= 64
    password_valid_input = (
        password_is_string
        and len(password.encode("utf-8")) <= 1024
    )

    # Malformed usernames still consume source-wide capacity.
    throttle_username = username if username_valid else None
    source = request.remote_addr
    reservation_token = None

    try:
        admitted, reservation_token = reserve_login_attempt(
            throttle_username,
            source,
        )

        if not admitted:
            return (
                render_template("auth/login.html"),
                429,
                {
                    "Retry-After": str(
                        current_app.config[
                            "LOGIN_RATE_LIMIT_BLOCK_SECONDS"
                        ]
                    )
                },
            )

        if not username_valid or not password_valid_input:
            settle_failed_login(reservation_token)
            flash("Invalid username or password.", "error")
            return render_template("auth/login.html"), 401

        user_record = db.session.query(
            User.id,
            User.password_hash,
            User.is_active,
        ).filter_by(username=username).one_or_none()

        password_hash = (
            user_record.password_hash
            if user_record is not None
            else _DUMMY_PASSWORD_HASH
        )
        password_matches = check_password_hash(password_hash, password)

        user_id = user_record.id if user_record is not None else None
        user_is_active = (
            bool(user_record.is_active)
            if user_record is not None
            else False
        )

        # Close the ORM read transaction before the reservation service
        # opens its own short SQLite write transaction.
        db.session.rollback()

        if (
            user_record is None
            or not user_is_active
            or not password_matches
        ):
            settle_failed_login(reservation_token)
            flash("Invalid username or password.", "error")
            return render_template("auth/login.html"), 401

        # Establish no session unless reservation settlement succeeds.
        settle_successful_login(reservation_token)

        # Reload the ORM user only after the independent write transaction.
        user = db.session.get(User, user_id)
        if user is None or not user.is_active:
            db.session.rollback()
            flash("Invalid username or password.", "error")
            return render_template("auth/login.html"), 401

    except (ValueError, SQLAlchemyError):
        db.session.rollback()

        # Best-effort release; the request remains unauthenticated.
        if reservation_token is not None:
            try:
                release_login_reservation(reservation_token)
            except (ValueError, SQLAlchemyError):
                db.session.rollback()

        return render_template("auth/login.html"), 503

    session.clear()
    login_user(user, remember=False, fresh=True)

    return redirect(url_for("dashboard.overview"))


@auth_bp.post("/logout")
def logout():
    """End the current administrator session."""

    logout_user()
    session.clear()

    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))
