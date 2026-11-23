"""One-file launcher: run this and SegCheck starts on http://127.0.0.1:5000.

    python start_segcheck.py                       # your normal installation
    python start_segcheck.py --data-dir <folder>   # a specific data folder
    python start_segcheck.py --port 5050 --no-browser

What it does, in order:
1. Creates ./.venv and installs requirements.txt the first time (and again only
   when requirements.txt changes). Then re-runs itself inside that environment.
2. Uses your data folder (default: %LOCALAPPDATA%\\SegCheck on Windows,
   ~/.local/share/segcheck on Linux) or SEGCHECK_DATA_DIR / --data-dir.
3. Keeps a stable signing secret: SEGCHECK_SECRET_KEY if set, otherwise a private
   `secret.key` file in the data folder (created once, never printed).
4. Backs up an existing database before applying any pending migration.
5. If no administrator exists yet, prints a one-time setup link for /setup.
6. Starts the server on loopback only (debug off) and opens your browser.

Run it as a normal user. Stop with Ctrl+C.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import venv
import webbrowser
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQUIREMENTS = ROOT / "requirements.txt"
REQUIRED_MODULES = ("flask", "flask_sqlalchemy", "flask_migrate", "flask_login", "flask_wtf", "yaml", "reportlab", "alembic", "waitress")


def say(message):
    print(f"[segcheck] {message}", flush=True)


def _venv_python(path: Path) -> Path:
    return path / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _has_requirements() -> bool:
    import importlib.util
    return all(importlib.util.find_spec(name) is not None for name in REQUIRED_MODULES)


def _venv_location() -> Path:
    """Project .venv, unless overridden or the project sits on a VirtualBox shared folder."""
    if os.environ.get("SEGCHECK_VENV"):
        return Path(os.environ["SEGCHECK_VENV"]).expanduser()
    shared_folder = os.name == "posix" and any(part.startswith("sf_") for part in ROOT.parts) or "/media/sf_" in str(ROOT)
    if shared_folder:  # vboxsf does not support the symlinks/permissions a venv needs
        return Path.home() / ".venvs" / "segcheck"
    local = ROOT / ".venv"
    if local.exists() or _writable(ROOT):
        return local
    # The SegCheck folder is read-only for this user (e.g. under Program Files): keep the
    # environment in the user's own folder instead. Nothing else changes.
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    fallback = base / "SegCheck" / "venv"
    if not fallback.exists():
        say(f"Fixed automatically: this SegCheck folder ({ROOT}) is read-only for your account, so SegCheck's")
        say(f"  private Python environment goes to {fallback} instead. Nothing to do.")
    return fallback


def _writable(folder: Path) -> bool:
    probe = folder / f".segcheck-write-test-{os.getpid()}"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def _install_advice():
    """Steps for a failed package install, depending on whether the internet is reachable."""
    import socket
    try:
        socket.create_connection(("pypi.org", 443), timeout=5).close()
        online = True
    except OSError:
        online = False
    if not online:
        return ("This PC cannot reach the internet (pypi.org), which is needed once to download the packages.",
                "Connect to the internet (or a network without a blocking proxy) and start SegCheck again.",
                "Behind a company proxy: set it first, e.g.  set HTTPS_PROXY=http://proxy.company.local:8080",
                "No internet on this PC at all? Copy the SegCheck folder (with its .venv) from a PC of the same Windows and Python version.")
    return ("The internet works, so the problem is local. The messages just above say which package failed.",
            "Start SegCheck again; a half-finished download often succeeds the second time.",
            "If it repeats: delete the .venv folder in the SegCheck folder (it is rebuilt automatically) and start again.",
            "Antivirus can block package files: allow the SegCheck folder.")


def ensure_environment():
    """Use a ready interpreter, or create/refresh a virtual environment and re-run inside it."""
    if sys.version_info < (3, 11):
        raise Problem(f"SegCheck needs Python 3.11 or newer; this is Python {sys.version_info[0]}.{sys.version_info[1]}.",
                      "Double-click SegCheck.exe: it finds a newer Python or offers to install Python 3.12 for you.",
                      "Or install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH').",
                      "Then double-click SegCheck.exe again.")
    if _has_requirements():
        return  # e.g. an already-activated venv such as ~/.venvs/segcheck on Kali
    venv_dir = _venv_location()
    venv_py = _venv_python(venv_dir)
    stamp = venv_dir / ".segcheck-requirements.sha256"
    inside = Path(sys.prefix).resolve() == venv_dir.resolve()
    wanted = hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()
    if venv_py.exists() and not inside and subprocess.call([str(venv_py), "-c", "pass"], stderr=subprocess.DEVNULL) != 0:
        # Typically the Python it was made from was upgraded or removed. It only holds downloaded packages.
        say(f"Fixed automatically: the private environment {venv_dir} no longer works "
            "(Python was probably upgraded or removed), so it is being rebuilt. Your data is not affected.")
        shutil.rmtree(venv_dir, ignore_errors=True)
    if not venv_py.exists():
        say(f"First start: creating SegCheck's private Python environment in {venv_dir} ...")
        try:
            venv.EnvBuilder(with_pip=True).create(venv_dir)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise Problem(f"The private Python environment could not be created ({exc}).",
                          "On Debian/Kali/Ubuntu install the venv module:  sudo apt install python3-venv",
                          "On Windows: check there is free disk space and that antivirus is not blocking this folder.",
                          "Then start SegCheck again.") from None
    if not stamp.exists() or stamp.read_text().strip() != wanted:
        say("Installing SegCheck's packages (internet needed once; 1-3 minutes)...")
        install = [str(venv_py), "-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", str(REQUIREMENTS)]
        if subprocess.call(install) != 0:
            say("The install did not finish; trying once more automatically...")
            if subprocess.call(install) != 0:
                raise Problem("SegCheck's packages could not be downloaded and installed.",
                              *_install_advice()) from None
        stamp.write_text(wanted)
    VENV_PY = venv_py
    if not inside:
        os.environ["SEGCHECK_LAUNCHER_CHILD"] = "1"
        sys.exit(subprocess.call([str(VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]]))


def stable_secret(data_dir: Path) -> str:
    if os.environ.get("SEGCHECK_SECRET_KEY"):
        return os.environ["SEGCHECK_SECRET_KEY"]
    path = data_dir / "secret.key"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(48)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)
    say(f"Created a private signing secret: {path}")
    return value


def backup_if_migrating(database: Path, head: str):
    if not database.exists() or database.stat().st_size == 0:
        return
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        try:
            current = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower():
                return  # not readable at all: never let a damaged file become the "newest backup"
            current = None
        except sqlite3.DatabaseError:
            return  # damaged file (handled by the restore step), not something to back up
    if current and current[0] == head:
        return
    backups = database.parent / "backups"
    backups.mkdir(exist_ok=True)
    target = backups / f"segcheck-before-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.sqlite3"
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as source, closing(sqlite3.connect(target)) as copy:
        source.backup(copy)
    say(f"Database needs an upgrade; backup saved to {target}")


class Problem(Exception):
    """A startup problem the person can fix: a plain title plus the steps to fix it."""

    def __init__(self, title, *steps):
        super().__init__(title)
        self.title, self.steps = title, steps


def explain(problem):
    print("", flush=True)
    say(f"PROBLEM: {problem.title}")
    for number, step in enumerate(problem.steps, start=1):
        say(f"  {number}. {step}")
    say("More help: README.md, section 'Troubleshooting'.")


def port_free(host, port):
    import socket
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host if host != "localhost" else "127.0.0.1", port))
            return True
        except OSError:
            return False


def segcheck_already_running(port):
    """True only when SegCheck itself (not another web program) answers on this port."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2) as response:
            return "SegCheck" in (response.headers.get("Server") or "")
    except urllib.error.HTTPError as response:
        return "SegCheck" in (response.headers.get("Server") or "")
    except OSError:
        return False


def running_segcheck_port(preferred):
    """Port of a SegCheck already running on this PC, or None.

    Looks at the requested port, the ports SegCheck moves to when that one is taken (the next 20),
    and the default range 5000-5020."""
    candidates = dict.fromkeys([*range(preferred, preferred + 21), *range(5000, 5021)])
    for port in candidates:
        if not port_free("127.0.0.1", port) and segcheck_already_running(port):
            return port
    return None


def free_port_near(host, port):
    for candidate in range(port + 1, port + 51):
        if candidate <= 65535 and port_free(host, candidate):
            return candidate
    return None


def restore_newest_backup(database: Path):
    """Move a damaged database aside (never deleted) and put the newest automatic backup in its place."""
    def healthy(path):
        try:
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as check:
                return (check.execute("PRAGMA quick_check").fetchone()[0] == "ok"  # intact
                        and check.execute("SELECT version_num FROM alembic_version").fetchone() is not None)  # really SegCheck's
        except sqlite3.DatabaseError:
            return False

    backups = [p for p in sorted((database.parent / "backups").glob("segcheck-before-*.sqlite3"), key=lambda p: p.stat().st_mtime)
               if healthy(p)]
    if not backups:
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    damaged = database.with_name(f"segcheck-damaged-{stamp}.sqlite3")
    database.replace(damaged)
    for suffix in ("-wal", "-shm", "-journal"):
        side = database.with_name(database.name + suffix)
        if side.exists():
            side.replace(damaged.with_name(damaged.name + suffix))
    with closing(sqlite3.connect(backups[-1].as_uri() + "?mode=ro", uri=True)) as source, closing(sqlite3.connect(database)) as copy:
        source.backup(copy)
    return backups[-1], damaged


def check_writable(data_dir: Path):
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise Problem(f"SegCheck cannot write to its data folder ({data_dir}): {exc.strerror or exc}",
                      "Check there is free disk space and that your account may write there.",
                      "Or choose a folder you can write to:  --data-dir D:\\SegCheckData") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Start SegCheck (opens in your browser)")
    parser.add_argument("--data-dir", help="Absolute data folder (default: standard installation folder)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    data_dir = None
    try:
        data_dir = run(args)
        return 0
    except Problem as problem:
        explain(problem)
        return 1
    except KeyboardInterrupt:
        print("", flush=True)
        say("SegCheck stopped. Everything is saved" + (f" in {data_dir}." if data_dir else "."))
        return 0
    except Exception as exc:  # noqa: BLE001 (last resort: never show a raw traceback to the user)
        import traceback
        known = data_dir or (Path(os.environ["SEGCHECK_DATA_DIR"]) if os.environ.get("SEGCHECK_DATA_DIR") else None)
        log_dir = (known or ROOT) / "logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with (log_dir / "launcher-error.log").open("a", encoding="utf-8") as handle:
                handle.write(f"\n=== {datetime.now(timezone.utc).isoformat()} ===\n{traceback.format_exc()}")
            where = log_dir / "launcher-error.log"
        except OSError:
            where = None
        explain(Problem(f"SegCheck could not start: {type(exc).__name__}: {exc}",
                        "Try again once; temporary problems (a busy file, antivirus scanning) often clear.",
                        f"The full technical details are in {where}." if where else "Run it again from a terminal to see details.",
                        "Your existing data was not changed; database upgrades always make a backup first."))
        return 1


def run(args):
    import logging
    if not 1024 <= args.port <= 65535:
        say(f"Fixed automatically: port {args.port} cannot be used (ports below 1024 need administrator rights, "
            "the highest is 65535), so SegCheck uses port 5000.")
        args.port = 5000
    ensure_environment()
    sys.path.insert(0, str(ROOT))
    if args.data_dir:
        os.environ["SEGCHECK_DATA_DIR"] = str(Path(args.data_dir).expanduser().resolve())
    from segcheck.storage import resolve_data_dir
    data_dir = resolve_data_dir()
    check_writable(data_dir)

    running = running_segcheck_port(args.port)
    if running:
        url = f"http://127.0.0.1:{running}"
        say(f"SegCheck is already running. Opening {url}  (nothing else to do)")
        if not args.no_browser:
            webbrowser.open(url)
        return data_dir
    if not port_free("127.0.0.1", args.port):
        wanted = args.port
        args.port = free_port_near("127.0.0.1", wanted)
        if args.port is None:
            raise Problem(f"Port {wanted} and the 50 ports after it are all in use.",
                          "Close some programs (or restart the PC) and start SegCheck again.",
                          "Or choose a port yourself:  SegCheck.exe --port 8500")
        say(f"Fixed automatically: port {wanted} is used by another program, so SegCheck uses port {args.port} instead.")
        say("  Nothing to do: the browser opens at the new address.")
    url = f"http://127.0.0.1:{args.port}"

    os.environ["SEGCHECK_SECRET_KEY"] = stable_secret(data_dir)
    if not os.environ.get("SEGCHECK_SETUP_TOKEN"):
        os.environ["SEGCHECK_SETUP_TOKEN"] = secrets.token_urlsafe(32)  # in memory for this run only

    from alembic.script import ScriptDirectory
    from flask_migrate import upgrade
    from sqlalchemy.exc import DatabaseError, OperationalError
    from segcheck_web import create_app
    from segcheck_web.extensions import db
    from segcheck_web.models import User

    app = create_app()
    migrations = ROOT / "segcheck_web" / "migrations"
    database = data_dir / "segcheck.sqlite3"
    def prepare_database():
        with app.app_context():
            head = ScriptDirectory.from_config(app.extensions["migrate"].migrate.get_config(str(migrations))).get_current_head()
            backup_if_migrating(database, head)
            logging.disable(logging.INFO)  # migration chatter is not useful to the person starting SegCheck
            try:
                upgrade(directory=str(migrations))
            finally:
                logging.disable(logging.NOTSET)
            found = db.session.query(User.id).first() is not None
            db.session.remove()
            return found

    database_errors = (OperationalError, DatabaseError, sqlite3.DatabaseError)
    try:
        try:
            has_admin = prepare_database()
        except database_errors as exc:
            reason = str(getattr(exc, "orig", exc)).lower()
            damaged = any(word in reason for word in ("not a database", "malformed", "disk image", "file is encrypted"))
            if not damaged:
                raise
            with app.app_context():
                db.engine.dispose()  # release the damaged file before moving it
            restored = restore_newest_backup(database)
            if not restored:
                raise
            backup, aside = restored
            say("Fixed automatically: the database file was damaged (for example the PC lost power")
            say("  while SegCheck was running). It was restored from the newest automatic backup:")
            say(f"    {backup.name}")
            say(f"  The damaged file was kept, not deleted: {aside.name}")
            say("  Next step: check your most recent assessments. Work done after that backup may be missing.")
            has_admin = prepare_database()
    except database_errors as exc:
        reason = str(getattr(exc, "orig", exc))
        if "locked" in reason.lower():
            raise Problem("The database is in use by another program (probably another SegCheck window).",
                          "Look for another black SegCheck window on the taskbar and use that one, or close it.",
                          "Then start SegCheck again.") from None
        raise Problem(f"The database could not be opened or upgraded ({reason}).",
                      f"No automatic backup was available to restore. Backups are kept in {data_dir / 'backups'}.",
                      "If you have your own copy of the data folder, close SegCheck and copy its segcheck.sqlite3 back.",
                      f"To start with an empty database instead: close SegCheck, rename {database.name} "
                      "(for example to segcheck-old.sqlite3), start again. Nothing is deleted that way.") from None
    say("Database ready.")

    say(f"Data folder: {data_dir}  (everything you do is saved here, on this PC)")
    if has_admin:
        say(f"Open {url} and sign in.")
        landing = url
    else:
        landing = url + "/setup"
        say(f"First start: create your administrator account at {landing}")
        say(f"    with this one-time setup token: {os.environ['SEGCHECK_SETUP_TOKEN']}")

    if not args.no_browser:
        def open_when_ready():
            for _ in range(60):
                try:
                    with urllib.request.urlopen(url + "/api/health", timeout=1):
                        break
                except OSError:
                    time.sleep(0.5)
            try:
                opened = webbrowser.open(landing)
            except Exception:  # noqa: BLE001 (no usable browser is not a reason to stop SegCheck)
                opened = False
            if not opened:
                say(f"The browser did not open by itself. Open a browser and go to  {landing}")
        threading.Thread(target=open_when_ready, daemon=True).start()

    from waitress import serve
    logging.getLogger("waitress").setLevel(logging.ERROR)
    say(f"SegCheck is ready at {url}")
    say("Keep this window open while you use SegCheck. Close it or press Ctrl+C to stop.")
    serve(app, host="127.0.0.1", port=args.port, threads=8, ident="SegCheck")  # this PC only
    return data_dir


if __name__ == "__main__":
    sys.exit(main())
