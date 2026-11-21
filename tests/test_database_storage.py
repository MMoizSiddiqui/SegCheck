"""Security tests for SQLite database storage preparation."""

import os
import stat
from pathlib import Path

import pytest

from segcheck_web.database_storage import (
    DatabaseStorageError,
    prepare_database_file,
)


def test_creates_database_file_with_private_permissions(tmp_path):
    path = prepare_database_file(tmp_path)

    assert path == tmp_path / "segcheck.sqlite3"
    assert path.is_file()

    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_uid == os.getuid()
        assert path.stat().st_nlink == 1


def test_reuses_existing_private_database(tmp_path):
    path = tmp_path / "segcheck.sqlite3"
    path.write_bytes(b"")

    if os.name == "posix":
        path.chmod(0o600)

    result = prepare_database_file(tmp_path)

    assert result == path
    assert path.exists()


def test_rejects_relative_database_directory():
    with pytest.raises(DatabaseStorageError, match="absolute path"):
        prepare_database_file("relative/database")


def test_rejects_filesystem_root_database_directory():
    if os.name != "posix":
        pytest.skip("POSIX filesystem root validation")

    with pytest.raises(
        DatabaseStorageError,
        match="must not be filesystem root",
    ):
        prepare_database_file(Path("/"))


def test_rejects_database_symlink(tmp_path):
    if not hasattr(os, "symlink") or not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("Symlink protection is unavailable on this platform")

    target = tmp_path / "outside.sqlite3"
    target.write_bytes(b"")
    if os.name == "posix":
        target.chmod(0o600)

    link = tmp_path / "segcheck.sqlite3"
    link.symlink_to(target)

    with pytest.raises(DatabaseStorageError):
        prepare_database_file(tmp_path)

    assert target.read_bytes() == b""


def test_rejects_database_hardlink(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX hardlink validation")

    database = tmp_path / "segcheck.sqlite3"
    database.write_bytes(b"")
    database.chmod(0o600)

    os.link(database, tmp_path / "unexpected-link.sqlite3")

    with pytest.raises(DatabaseStorageError, match="hard links"):
        prepare_database_file(tmp_path)


def test_rejects_database_with_unexpected_owner_permissions(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission validation")

    database = tmp_path / "segcheck.sqlite3"
    database.write_bytes(b"")
    database.chmod(0o700)

    with pytest.raises(DatabaseStorageError, match="exactly 0600"):
        prepare_database_file(tmp_path)


def test_rejects_database_with_unsafe_permissions(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission validation")

    database = tmp_path / "segcheck.sqlite3"
    database.write_bytes(b"")
    database.chmod(0o644)

    with pytest.raises(DatabaseStorageError, match="permissions"):
        prepare_database_file(tmp_path)


def test_rejects_database_directory_instead_of_file(tmp_path):
    (tmp_path / "segcheck.sqlite3").mkdir()

    with pytest.raises(DatabaseStorageError, match="regular file"):
        prepare_database_file(tmp_path)


def test_rejects_symlinked_ancestor_directory(tmp_path):
    if not hasattr(os, "symlink") or os.name != "posix":
        pytest.skip("POSIX symlink validation")

    actual_parent = tmp_path / "actual-parent"
    actual_parent.mkdir(mode=0o700)

    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)

    target = linked_parent / "segcheck"

    with pytest.raises(DatabaseStorageError, match="symbolic links"):
        prepare_database_file(target)

    assert not (actual_parent / "segcheck").exists()


def test_creates_missing_storage_directory_components(tmp_path):
    target = tmp_path / "new-parent" / "nested" / "segcheck"

    result = prepare_database_file(target)

    assert result == target / "segcheck.sqlite3"
    assert result.is_file()

    if os.name == "posix":
        for directory in (
            target,
            target.parent,
            target.parent.parent,
        ):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            assert directory.stat().st_uid == os.getuid()


@pytest.mark.skipif(os.name != "posix", reason="POSIX path/permission/symlink semantics; Windows ACL behaviour is verified separately")
def test_rejects_non_directory_storage_ancestor(tmp_path):
    file_component = tmp_path / "not-a-directory"
    file_component.write_text("not a directory", encoding="utf-8")

    target = file_component / "segcheck"

    with pytest.raises(DatabaseStorageError, match="must be directories"):
        prepare_database_file(target)


@pytest.mark.skipif(os.name != "posix", reason="POSIX path/permission/symlink semantics; Windows ACL behaviour is verified separately")
def test_rejects_symlink_storage_directory(tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("Symlinks unavailable")

    actual_directory = tmp_path / "actual"
    actual_directory.mkdir()
    if os.name == "posix":
        actual_directory.chmod(0o700)

    linked_directory = tmp_path / "linked"
    linked_directory.symlink_to(actual_directory, target_is_directory=True)

    with pytest.raises(DatabaseStorageError, match="symbolic link"):
        prepare_database_file(linked_directory)

    assert not (actual_directory / "segcheck.sqlite3").exists()
