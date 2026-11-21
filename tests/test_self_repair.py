"""Problems SegCheck fixes by itself: busy port, damaged database, a broken setup."""
import socket
import sqlite3
from contextlib import closing

import start_segcheck


def make_segcheck_db(path, version="head1"):
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE alembic_version (version_num TEXT)")
        db.execute("INSERT INTO alembic_version VALUES (?)", (version,))
        db.execute("CREATE TABLE notes (text TEXT)")
        db.execute("INSERT INTO notes VALUES ('my assessment')")
        db.commit()


def test_busy_port_moves_to_the_next_free_one():
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert not start_segcheck.port_free("127.0.0.1", port)
        other = start_segcheck.free_port_near("127.0.0.1", port)
        assert other is not None and other > port and start_segcheck.port_free("127.0.0.1", other)


def test_another_web_program_is_not_mistaken_for_segcheck():
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        assert start_segcheck.segcheck_already_running(busy.getsockname()[1]) is False


def test_damaged_database_is_restored_from_the_newest_good_backup(tmp_path):
    database = tmp_path / "segcheck.sqlite3"
    backups = tmp_path / "backups"
    backups.mkdir()
    make_segcheck_db(backups / "segcheck-before-20260101T000000Z.sqlite3")
    (backups / "segcheck-before-20260102T000000Z.sqlite3").write_bytes(b"")  # empty: not a usable backup
    database.write_bytes(b"garbage " * 500)

    start_segcheck.backup_if_migrating(database, "head1")  # a damaged file must never become a "backup"
    assert len(list(backups.iterdir())) == 2

    backup, aside = start_segcheck.restore_newest_backup(database)
    assert backup.name == "segcheck-before-20260101T000000Z.sqlite3"
    assert aside.read_bytes().startswith(b"garbage")  # kept, not deleted
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT text FROM notes").fetchone() == ("my assessment",)


def test_no_good_backup_means_no_change(tmp_path):
    database = tmp_path / "segcheck.sqlite3"
    database.write_bytes(b"garbage")
    assert start_segcheck.restore_newest_backup(database) is None
    assert database.read_bytes() == b"garbage"
