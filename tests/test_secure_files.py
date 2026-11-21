import os
import stat
from types import SimpleNamespace

import pytest

from segcheck import secure_files
from segcheck.secure_files import SecureFileError, read_bounded_file


def test_reads_regular_file_within_limit(tmp_path):
    path = tmp_path / "input.json"
    path.write_bytes(b'{"ok": true}')

    assert read_bounded_file(
        path,
        max_bytes=20,
        label="Test input",
    ) == b'{"ok": true}'


def test_accepts_file_exactly_at_size_limit(tmp_path):
    path = tmp_path / "exact.bin"
    path.write_bytes(b"12345678")

    assert read_bounded_file(
        path,
        max_bytes=8,
        label="Test input",
    ) == b"12345678"


def test_rejects_file_larger_than_size_limit(tmp_path):
    path = tmp_path / "oversized.bin"
    path.write_bytes(b"123456789")

    with pytest.raises(SecureFileError, match="maximum allowed size"):
        read_bounded_file(
            path,
            max_bytes=8,
            label="Test input",
        )


def test_read_limit_still_applies_if_file_grows_after_stat(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "growing.bin"
    path.write_bytes(b"12345")

    real_fstat = os.fstat

    def report_smaller_size(descriptor):
        metadata = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_size=0,
        )

    monkeypatch.setattr(secure_files.os, "fstat", report_smaller_size)

    with pytest.raises(SecureFileError, match="maximum allowed size"):
        read_bounded_file(
            path,
            max_bytes=4,
            label="Growing test input",
        )


def test_rejects_directory_as_input(tmp_path):
    with pytest.raises(SecureFileError, match="regular file"):
        read_bounded_file(
            tmp_path,
            max_bytes=100,
            label="Test input",
        )


def test_rejects_symlink_when_platform_supports_nofollow(tmp_path):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("Platform does not expose O_NOFOLLOW")

    target = tmp_path / "target.txt"
    link = tmp_path / "link.txt"
    target.write_text("sensitive content", encoding="utf-8")
    link.symlink_to(target)

    with pytest.raises(SecureFileError):
        read_bounded_file(
            link,
            max_bytes=100,
            label="Symlink input",
        )


@pytest.mark.parametrize("invalid_limit", [0, -1, True, False, 1.5, "100", None])
def test_rejects_invalid_size_limits(tmp_path, invalid_limit):
    path = tmp_path / "input.txt"
    path.write_text("content", encoding="utf-8")

    with pytest.raises(ValueError, match="max_bytes"):
        read_bounded_file(
            path,
            max_bytes=invalid_limit,
            label="Test input",
        )


def test_rejects_missing_file(tmp_path):
    path = tmp_path / "does-not-exist.txt"

    with pytest.raises(SecureFileError, match="Unable to safely read"):
        read_bounded_file(
            path,
            max_bytes=100,
            label="Missing input",
        )
