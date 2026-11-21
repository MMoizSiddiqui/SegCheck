"""Bounded and defensive local input-file reading."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class SecureFileError(ValueError):
    """An input file could not be safely opened or exceeded its size limit."""


def read_bounded_file(
    path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read a regular file with a hard byte limit and no symlink following."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")

    file_path = Path(path)
    # O_BINARY prevents Windows CRLF translation; it is 0/absent on POSIX.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)

    if os.path.isdir(file_path):
        # Windows reports directories as EACCES from os.open; give the
        # same explicit message that POSIX produces after fstat().
        raise SecureFileError(f"{label} must be a regular file")

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK

    descriptor = None

    try:
        descriptor = os.open(file_path, flags)
        metadata = os.fstat(descriptor)

        if not stat.S_ISREG(metadata.st_mode):
            raise SecureFileError(f"{label} must be a regular file")

        if metadata.st_size > max_bytes:
            raise SecureFileError(
                f"{label} exceeds the maximum allowed size of {max_bytes} bytes"
            )

        chunks = []
        total = 0

        while True:
            chunk = os.read(
                descriptor,
                min(65536, max_bytes + 1 - total),
            )
            if not chunk:
                break

            total += len(chunk)
            if total > max_bytes:
                raise SecureFileError(
                    f"{label} exceeds the maximum allowed size of {max_bytes} bytes"
                )

            chunks.append(chunk)

        return b"".join(chunks)

    except SecureFileError:
        raise
    except OSError as exc:
        raise SecureFileError(
            f"Unable to safely read {label}: {exc}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
