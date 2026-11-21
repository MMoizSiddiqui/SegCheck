"""Secure default configuration for the SegCheck web application."""

import os
from datetime import timedelta


class Config:
    # Production must supply a strong secret through the environment.
    SECRET_KEY = os.environ.get("SEGCHECK_SECRET_KEY")
    SEGCHECK_SETUP_TOKEN = os.environ.get("SEGCHECK_SETUP_TOKEN")

    # Debugging and exception behaviour.
    DEBUG = False
    TESTING = False
    PROPAGATE_EXCEPTIONS = False
    TRAP_HTTP_EXCEPTIONS = False
    TRAP_BAD_REQUEST_ERRORS = False

    # Session security.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_PATH = "/"
    SESSION_REFRESH_EACH_REQUEST = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Database-backed login throttling.
    LOGIN_RATE_LIMIT_ENABLED = True
    LOGIN_RATE_LIMIT_ACCOUNT_SOURCE_MAX = 5
    LOGIN_RATE_LIMIT_SOURCE_MAX = 20
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = 900
    LOGIN_RATE_LIMIT_BLOCK_SECONDS = 900
    LOGIN_RATE_LIMIT_RESERVATION_TTL_SECONDS = 60

    # Optional server-side firewall evidence integration.
    # Configure both paths together; never accept them from browser input.
    SEGCHECK_EVIDENCE_CONFIG_PATH = None
    SEGCHECK_EVIDENCE_EVENTS_PATH = None


    # Request and database defaults.
    # Multipart uploads need a small envelope allowance.
    # Individual policy content remains limited to 1 MiB by the import service.
    MAX_CONTENT_LENGTH = 1_048_576 + 16_384
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    JSON_SORT_KEYS = False
