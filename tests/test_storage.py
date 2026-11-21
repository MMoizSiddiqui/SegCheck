import os
import stat

import pytest

from segcheck.storage import (
    default_evidence_path,
    default_report_path,
    ensure_private_directory,
    get_storage_paths,
    resolve_data_dir,
)


@pytest.mark.skipif(os.name != "posix", reason="POSIX path/permission/symlink semantics; Windows ACL behaviour is verified separately")
def test_linux_default_storage_path():
    result = resolve_data_dir(
        environ={},
        system="Linux",
        home="/home/testuser",
    )

    assert str(result) == "/home/testuser/.local/share/segcheck"


@pytest.mark.skipif(os.name != "posix", reason="POSIX path/permission/symlink semantics; Windows ACL behaviour is verified separately")
def test_linux_xdg_storage_path():
    result = resolve_data_dir(
        environ={"XDG_DATA_HOME": "/custom/data"},
        system="Linux",
        home="/home/testuser",
    )

    assert str(result) == "/custom/data/segcheck"


def test_windows_default_storage_path():
    result = resolve_data_dir(
        environ={"LOCALAPPDATA": r"C:\Users\testuser\AppData\Local"},
        system="Windows",
        home=r"C:\Users\testuser",
    )

    assert str(result).endswith(r"SegCheck")
    assert "AppData" in str(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX path/permission/symlink semantics; Windows ACL behaviour is verified separately")
def test_macos_default_storage_path():
    result = resolve_data_dir(
        environ={},
        system="Darwin",
        home="/Users/testuser",
    )

    assert str(result) == (
        "/Users/testuser/Library/Application Support/SegCheck"
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX path/permission/symlink semantics; Windows ACL behaviour is verified separately")
def test_explicit_storage_override():
    result = resolve_data_dir(
        environ={"SEGCHECK_DATA_DIR": "/srv/segcheck-data"},
        system="Linux",
        home="/home/testuser",
    )

    assert str(result) == "/srv/segcheck-data"


def test_relative_override_is_rejected():
    with pytest.raises(ValueError, match="absolute path"):
        resolve_data_dir(
            environ={"SEGCHECK_DATA_DIR": "relative/storage"},
            system="Linux",
        )


def test_relative_xdg_path_is_rejected():
    with pytest.raises(ValueError, match="absolute path"):
        resolve_data_dir(
            environ={"XDG_DATA_HOME": "relative/data"},
            system="Linux",
        )


def test_windows_without_localappdata_is_rejected():
    with pytest.raises(ValueError, match="LOCALAPPDATA"):
        resolve_data_dir(environ={}, system="Windows")


def test_storage_layout_does_not_create_directories_by_default(tmp_path):
    root = tmp_path / "segcheck-data"

    paths = get_storage_paths(
        environ={"SEGCHECK_DATA_DIR": str(root)},
        system="Linux",
    )

    assert paths.root == root
    assert paths.reports == root / "reports"
    assert paths.evidence == root / "evidence"
    assert not root.exists()


def test_storage_layout_creates_private_directories(tmp_path):
    root = tmp_path / "segcheck-data"

    paths = get_storage_paths(
        environ={"SEGCHECK_DATA_DIR": str(root)},
        system="Linux",
        create=True,
    )

    assert paths.root.is_dir()
    assert paths.reports.is_dir()
    assert paths.evidence.is_dir()

    if os.name == "posix":
        for directory in (paths.root, paths.reports, paths.evidence):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_existing_private_directory_is_preserved(tmp_path):
    directory = tmp_path / "existing"
    directory.mkdir(mode=0o700)
    existing_file = directory / "important.json"
    existing_file.write_text('{"preserve": true}', encoding="utf-8")

    ensure_private_directory(directory)

    assert existing_file.read_text(encoding="utf-8") == (
        '{"preserve": true}'
    )


def test_existing_directory_with_unsafe_permissions_is_rejected(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission check")

    directory = tmp_path / "unsafe"
    directory.mkdir(mode=0o700)
    directory.chmod(0o755)

    with pytest.raises(ValueError, match="group/other permissions"):
        ensure_private_directory(directory)


def test_default_report_path_uses_private_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("SEGCHECK_DATA_DIR", str(tmp_path / "private"))

    result = default_report_path("assessment.json")

    assert result == tmp_path / "private" / "reports" / "assessment.json"
    assert result.parent.is_dir()


def test_default_evidence_path_uses_private_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("SEGCHECK_DATA_DIR", str(tmp_path / "private"))

    result = default_evidence_path("events.jsonl")

    assert result == tmp_path / "private" / "evidence" / "events.jsonl"
    assert result.parent.is_dir()


@pytest.mark.parametrize("filename", ["", "../outside.json", "/tmp/outside.json"])
def test_default_paths_reject_path_traversal(filename):
    with pytest.raises(ValueError, match="simple filename"):
        default_report_path(filename)
