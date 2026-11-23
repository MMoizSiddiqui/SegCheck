"""Back up and upgrade an existing local SegCheck database; never create one."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
HEAD = 'f3a9c1d7e2b4'


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def records(connection):
    result = {}
    tables = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT IN ('alembic_version', 'sqlite_sequence') ORDER BY name"
    ).fetchall()
    for (name,) in tables:
        rows = connection.execute(f'SELECT * FROM {quote(name)} ORDER BY rowid')
        digest = hashlib.sha256()
        count = 0
        for row in rows:
            digest.update(repr(row).encode('utf-8'))
            digest.update(b'\n')
            count += 1
        result[name] = (count, digest.hexdigest())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, help='Existing installation directory; defaults to current installation settings')
    parser.add_argument('--check', action='store_true', help='Check access and revision without writing')
    args = parser.parse_args()
    if args.data_dir:
        os.environ['SEGCHECK_DATA_DIR'] = str(args.data_dir.resolve())
    from segcheck.storage import resolve_data_dir
    source = resolve_data_dir() / 'segcheck.sqlite3'
    if not source.is_file() or source.is_symlink():
        raise RuntimeError(f'Expected an existing regular database: {source}')
    print(f'Database: {source}')
    with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as connection:
        revision = connection.execute('SELECT version_num FROM alembic_version').fetchone()[0]
        if connection.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise RuntimeError('Database integrity check failed; migration was not started')
    print(f'Current revision: {revision}')
    if revision not in {'b41d8e7a2c90', 'c52e9f8b3d01', 'd63f0a9c4e12', 'e7a1c3f9b250', HEAD}:
        raise RuntimeError('Unexpected revision; migration was not started')
    descriptor = os.open(source, os.O_RDWR)
    os.close(descriptor)
    if args.check:
        print('Write access verified. Check only; no changes made.')
        return
    if revision == HEAD:
        print('Database is already up to date. No changes needed.')
        return
    # Run with the application stopped so validation compares a stable installation.
    backups = source.parent / 'backups'
    if backups.is_symlink():
        raise RuntimeError('Backup directory must not be a symbolic link')
    backups.mkdir(mode=0o700, exist_ok=True)
    backup = backups / ('segcheck-before-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '.sqlite3')
    descriptor = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as original, sqlite3.connect(backup) as saved:
        original.backup(saved)
        if saved.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise RuntimeError('Backup integrity check failed; migration was not started')
        baseline = records(saved)
    print(f'Verified backup: {backup}', flush=True)
    from flask_migrate import upgrade
    from segcheck_web import create_app
    # A signing key is needed to construct the app, but migrations do not use
    # browser sessions. This process-only key is neither saved nor used to run a server.
    app = create_app({'SECRET_KEY': os.environ.get('SEGCHECK_SECRET_KEY') or secrets.token_hex(32)})
    with app.app_context():
        upgrade(directory=str(ROOT / 'segcheck_web' / 'migrations'), revision=HEAD)
    with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as connection:
        assert connection.execute('SELECT version_num FROM alembic_version').fetchone() == (HEAD,)
        assert connection.execute('PRAGMA integrity_check').fetchone() == ('ok',)
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        after = records(connection)
        for name, signature in baseline.items():
            if after.get(name) != signature:
                raise RuntimeError(f'Existing records changed in {name}; retain the backup and investigate')
    print(f'SUCCESS: upgraded to {HEAD}; all existing records preserved.')
    print('Existing installation secret and settings were not changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'STOPPED: {exc}', file=sys.stderr)
        print('Do not delete the database or backups. No automatic restore was attempted.', file=sys.stderr)
        sys.exit(1)
