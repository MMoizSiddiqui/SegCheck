"""Run a local SegCheck review instance against an explicit, separate data directory.

This helper exists so a reviewer can launch the real application (not a mock)
without touching the production installation:

    python scripts/run_review_instance.py --data-dir C:\\path\\to\\review-data

* The data directory must be an absolute path chosen deliberately by the operator.
  The database inside it is upgraded with the normal Alembic migrations.
* The signing secret comes from SEGCHECK_SECRET_KEY, or from a private
  ``review-secret.key`` file inside that review data directory. The file is only
  generated for that review directory; an existing production secret is never
  read, replaced or printed.
* The server binds to loopback only, with debug and the reloader disabled.
* A visible banner marks every page as a separate review instance.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SECRET_FILENAME = "review-secret.key"


def _review_secret(data_dir: Path) -> str:
    configured = os.environ.get("SEGCHECK_SECRET_KEY")
    if configured:
        return configured
    secret_path = data_dir / SECRET_FILENAME
    if secret_path.exists():
        value = secret_path.read_text(encoding="utf-8").strip()
        if len(value.encode("utf-8")) < 32:
            raise SystemExit(f"{secret_path} is too short; expected at least 32 bytes.")
        return value
    value = secrets.token_urlsafe(48)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(secret_path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", required=True, help="Absolute review data directory")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--no-upgrade", action="store_true", help="Skip `db upgrade`")
    parser.add_argument("--host", default="127.0.0.1", help="Listen address (default loopback). Only use 0.0.0.0 inside an isolated container.")
    parser.add_argument("--no-banner", action="store_true", help="Hide the review-instance banner (the office lab, a demo installation of its own)")
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir).expanduser()
    if not data_dir.is_absolute():
        raise SystemExit("--data-dir must be an absolute path")
    data_dir.mkdir(parents=True, exist_ok=True)
    if not 1024 <= args.port <= 65535:
        raise SystemExit("--port must be between 1024 and 65535")

    os.environ["SEGCHECK_DATA_DIR"] = str(data_dir)
    os.environ["SEGCHECK_SECRET_KEY"] = _review_secret(data_dir)

    from flask_migrate import upgrade
    from segcheck_web import create_app

    app = create_app({
        "SEGCHECK_REVIEW_MODE": not args.no_banner,
        # Loopback HTTP review: Chromium accepts Secure cookies on localhost,
        # but keep the production default (Secure) unchanged elsewhere.
        "SESSION_COOKIE_SECURE": os.environ.get("SEGCHECK_REVIEW_INSECURE_COOKIE") != "1",
    })

    if not args.no_upgrade:
        with app.app_context():
            upgrade(directory=str(PROJECT_ROOT / "segcheck_web" / "migrations"))

    if args.host not in {"127.0.0.1", "::1"} and os.environ.get("SEGCHECK_CONTAINER") != "1":
        raise SystemExit("Refusing a non-loopback listen address outside the SegCheck lab container.")
    print(f"SegCheck review instance: http://{args.host}:{args.port}  (data: {data_dir})", flush=True)
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
