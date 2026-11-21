
"""SegCheck Flask application factory."""

import os
import re

import click
from flask import Flask, request
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash

from segcheck.storage import resolve_data_dir
from .database_storage import prepare_database_file
from .config import Config
from .extensions import csrf, db, login_manager, migrate


def create_app(test_config=None):
    """Create and configure an independent SegCheck web application."""

    app = Flask("segcheck_web")
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    # Debug mode is never permitted through the application factory.
    if app.config.get("DEBUG") is True:
        raise RuntimeError("Debug mode is not permitted for SegCheck")

    app.config["DEBUG"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.config["TRAP_HTTP_EXCEPTIONS"] = False
    app.config["TRAP_BAD_REQUEST_ERRORS"] = False
    app.config["SQLALCHEMY_ECHO"] = False

    # Never start with a missing or weak production signing secret.
    secret_key = app.config.get("SECRET_KEY")

    if not isinstance(secret_key, str) or not secret_key:
        raise RuntimeError(
            "SEGCHECK_SECRET_KEY must be configured before starting SegCheck"
        )

    if not app.config.get("TESTING") and len(secret_key.encode("utf-8")) < 32:
        raise RuntimeError(
            "SEGCHECK_SECRET_KEY must contain at least 32 bytes in production"
        )

    # Do not create production storage when a test supplies its own database.
    if "SQLALCHEMY_DATABASE_URI" not in (test_config or {}):
        data_dir = resolve_data_dir()
        database_path = prepare_database_file(data_dir)
        app.config["SEGCHECK_DATA_DIR"] = str(data_dir)

        app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
            "sqlite",
            database=str(database_path),
        ).render_as_string(hide_password=False)

    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        raise RuntimeError("A database URI must be configured")

    db.init_app(app)
    migrate.init_app(app, db)

    # Authentication and global CSRF protection.
    login_manager.session_protection = "strong"
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to access SegCheck."
    login_manager.login_message_category = "error"
    login_manager.init_app(app)
    from .errors import register_error_pages
    register_error_pages(app)
    csrf.init_app(app)

    # Register database models.
    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        """Load a session user using a strictly validated database ID."""
        if not isinstance(user_id, str) or not user_id.isdecimal():
            return None

        user = db.session.get(User, int(user_id))
        return user if user is not None and user.is_active else None

    # Register application routes.
    from .routes.auth import auth_bp
    from .routes.health import health_bp
    from .routes.assessments import assessments_bp
    from .routes.dashboard import dashboard_bp
    from .routes.jobs import jobs_bp
    from .routes.audit import audit_bp
    from .routes.setup import setup_bp, setup_available
    from .models.bootstrap import BootstrapClaim

    app.register_blueprint(auth_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(assessments_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(jobs_bp)
    app.register_blueprint(audit_bp)

    from .services.report_view import explain as explain_reason
    app.jinja_env.globals["explain"] = explain_reason  # plain words for a probe's raw reason code
    app.register_blueprint(setup_bp)

    @app.context_processor
    def probe_position_context():
        from flask_login import current_user as user
        if not getattr(user, "is_authenticated", False):
            return {"probe_context": None}
        try:
            from .services.environment import settings
            payload = settings()[1]
            return {"probe_context": {"source_ip": payload.get("source_ip"), "source_zone": payload.get("source_zone")}}
        except SQLAlchemyError:
            return {"probe_context": None}

    @app.context_processor
    def installation_setup_context():
        return {"setup_available": setup_available() if request.endpoint == "auth.login" else False}

    @app.cli.command("create-admin")
    def create_admin():
        """Interactively provision the initial SegCheck administrator."""

        if db.session.query(User.id).first() is not None:
            raise click.ClickException(
                "An account already exists. Initial administrator "
                "provisioning is no longer available."
            )

        username = click.prompt("Administrator username")
        username = username.strip().lower()

        if (
            not 3 <= len(username) <= 64
            or not username.isascii()
            or not re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]",
                username,
            )
        ):
            raise click.ClickException(
                "Username must be 3–64 characters and contain only "
                "lowercase letters, numbers, dots, underscores or hyphens. "
                "It must start and end with a letter or number."
            )

        password = click.prompt(
            "Administrator password",
            hide_input=True,
            confirmation_prompt=True,
        )

        if (
            len(password) < 12
            or len(password.encode("utf-8")) > 1024
        ):
            raise click.ClickException(
                "Password must contain at least 12 characters "
                "and no more than 1024 UTF-8 bytes."
            )

        user = User(
            username=username,
            password_hash=generate_password_hash(
                password,
                method="scrypt",
            ),
            is_active=True,
        )

        db.session.add(user)

        try:
            db.session.add(BootstrapClaim(id=1))
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            raise click.ClickException(
                "Administrator creation failed. Check the database "
                "and whether an account already exists."
            )

        click.echo("Initial SegCheck administrator created successfully.")

    @app.before_request
    def start_firewall_connectors_once():
        """Resume read-only log listeners for declared devices after a restart."""
        if app.config.get("TESTING") or app.extensions.get("segcheck_connectors_started"):
            return
        app.extensions["segcheck_connectors_started"] = True
        try:
            from .services.environment import settings
            from .services.firewall_connector import evidence_directory, registry
            registry(app).sync(settings()[1], evidence_directory())
        except Exception:  # Connectors are optional; never block the UI.
            app.logger.exception("Firewall log connectors could not be started")

    @app.url_defaults
    def static_cache_bust(endpoint, values):
        """Version local assets by modification time so upgrades are never stale."""
        if endpoint == "static" and "filename" in values and "v" not in values:
            try:
                values["v"] = int(os.stat(os.path.join(app.static_folder, values["filename"])).st_mtime)
            except (OSError, TypeError, ValueError):
                pass

    @app.after_request
    def add_security_headers(response):
        """Apply baseline browser security headers to every response."""

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    return app
