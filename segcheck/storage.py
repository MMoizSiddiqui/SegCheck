"""Cross-platform private application storage for SegCheck.

Storage paths are resolved centrally. Importing this module does not create
directories or move existing data.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


DATA_DIR_ENV = "SEGCHECK_DATA_DIR"


@dataclass(frozen=True)
class StoragePaths:
    """Resolved locations used by SegCheck."""

    root: Path
    reports: Path
    evidence: Path


def resolve_data_dir(
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
    home: str | Path | None = None,
) -> Path:
    """Resolve the application data directory without creating it."""

    env = os.environ if environ is None else environ

    override = env.get(DATA_DIR_ENV)
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise ValueError(
                f"{DATA_DIR_ENV} must be an absolute path"
            )
        return path

    operating_system = system or platform.system()
    home_path = Path(home).expanduser() if home is not None else Path.home()

    if operating_system == "Windows":
        base = env.get("LOCALAPPDATA")
        if not base:
            raise ValueError(
                "LOCALAPPDATA is required to resolve SegCheck storage on Windows"
            )
        return Path(base).expanduser() / "SegCheck"

    if operating_system == "Darwin":
        return home_path / "Library" / "Application Support" / "SegCheck"

    xdg_data_home = env.get("XDG_DATA_HOME")
    if xdg_data_home:
        xdg_path = Path(xdg_data_home).expanduser()
        if not xdg_path.is_absolute():
            raise ValueError("XDG_DATA_HOME must be an absolute path")
        return xdg_path / "segcheck"

    return home_path / ".local" / "share" / "segcheck"


def ensure_private_directory(path: str | Path) -> Path:
    """Create a private directory and enforce restrictive POSIX permissions.

    On Windows, directory permissions are governed by Windows ACLs. This
    function does not claim to configure or verify those ACLs.
    """

    directory = Path(path).expanduser()

    if not directory.is_absolute():
        raise ValueError("Storage directory must be an absolute path")

    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)

        if not directory.is_dir():
            raise ValueError("Storage path exists but is not a directory")

        if os.name == "posix":
            current_mode = directory.stat().st_mode & 0o777

            if current_mode & 0o077:
                raise PermissionError(
                    "Storage directory has group/other permissions; "
                    f"expected private permissions, found {current_mode:04o}: "
                    f"{directory}"
                )

            directory.chmod(0o700)

    except OSError as exc:
        raise ValueError(
            f"Unable to prepare private storage directory {directory}: {exc}"
        ) from exc

    return directory


def get_storage_paths(
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
    home: str | Path | None = None,
    create: bool = False,
) -> StoragePaths:
    """Resolve SegCheck storage locations.

    Set create=True when an application component is ready to use storage.
    """

    root = resolve_data_dir(environ=environ, system=system, home=home)

    paths = StoragePaths(
        root=root,
        reports=root / "reports",
        evidence=root / "evidence",
    )

    if create:
        ensure_private_directory(paths.root)
        ensure_private_directory(paths.reports)
        ensure_private_directory(paths.evidence)

    return paths


def default_report_path(filename: str) -> Path:
    """Return a report path inside SegCheck's private report directory."""

    if not filename or Path(filename).name != filename:
        raise ValueError("Report filename must be a simple filename")

    paths = get_storage_paths(create=True)
    return paths.reports / filename


def default_evidence_path(filename: str) -> Path:
    """Return an evidence path inside SegCheck's private evidence directory."""

    if not filename or Path(filename).name != filename:
        raise ValueError("Evidence filename must be a simple filename")

    paths = get_storage_paths(create=True)
    return paths.evidence / filename
