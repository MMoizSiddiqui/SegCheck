"""Secure preparation of the SegCheck SQLite database file."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from segcheck.storage import ensure_private_directory


DATABASE_FILENAME = "segcheck.sqlite3"


class DatabaseStorageError(RuntimeError):
    """The database path cannot be prepared safely."""


def _validate_database_descriptor(
    descriptor: int,
    *,
    expected_entry_info: os.stat_result | None = None,
) -> None:
    metadata = os.fstat(descriptor)

    if not stat.S_ISREG(metadata.st_mode):
        raise DatabaseStorageError(
            "SQLite database path must refer to a regular file"
        )

    if expected_entry_info is not None:
        if (
            metadata.st_dev != expected_entry_info.st_dev
            or metadata.st_ino != expected_entry_info.st_ino
        ):
            raise DatabaseStorageError(
                "SQLite database file changed during validation"
            )

    if os.name == "posix":
        if metadata.st_uid != os.getuid():
            raise DatabaseStorageError(
                "SQLite database must be owned by the current user"
            )

        if metadata.st_nlink != 1:
            raise DatabaseStorageError(
                "SQLite database must not have additional hard links"
            )

        permissions = stat.S_IMODE(metadata.st_mode)

        if permissions != 0o600:
            raise DatabaseStorageError(
                "SQLite database must have exactly 0600 permissions"
            )


def _open_private_directory(directory: Path) -> int:
    """Open a directory by traversing every component without following links.

    Existing ancestors may use normal system permissions. The final
    application directory must be owned by the current user and mode 0700.
    Newly created components are also made private.
    """

    required_flags = ("O_DIRECTORY", "O_NOFOLLOW")

    if any(not hasattr(os, flag) for flag in required_flags):
        raise DatabaseStorageError(
            "Secure POSIX directory traversal is unavailable"
        )

    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
    ):
        raise DatabaseStorageError(
            "Required POSIX directory-descriptor operations are unavailable"
        )

    components = directory.parts[1:]

    if any(component in ("", ".", "..") for component in components):
        raise DatabaseStorageError(
            "Database storage path contains an unsafe component"
        )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)

    current_fd = os.open("/", flags)

    try:
        for index, component in enumerate(components):
            is_final = index == len(components) - 1
            created = False

            try:
                os.mkdir(component, mode=0o700, dir_fd=current_fd)
                created = True
            except FileExistsError:
                pass

            try:
                entry_info = os.stat(
                    component,
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError as exc:
                raise DatabaseStorageError(
                    "Database storage directory changed during traversal"
                ) from exc

            if stat.S_ISLNK(entry_info.st_mode):
                raise DatabaseStorageError(
                    "Database storage path must not contain symbolic links"
                )

            if not stat.S_ISDIR(entry_info.st_mode):
                raise DatabaseStorageError(
                    "Database storage path components must be directories"
                )

            child_fd = os.open(component, flags, dir_fd=current_fd)

            try:
                opened_info = os.fstat(child_fd)

                if (
                    opened_info.st_dev != entry_info.st_dev
                    or opened_info.st_ino != entry_info.st_ino
                ):
                    raise DatabaseStorageError(
                        "Database storage directory changed during validation"
                    )

                if created:
                    if opened_info.st_uid != os.getuid():
                        raise DatabaseStorageError(
                            "New storage directory is not owned by the current user"
                        )

                    os.fchmod(child_fd, 0o700)
                    opened_info = os.fstat(child_fd)

                    if stat.S_IMODE(opened_info.st_mode) != 0o700:
                        raise DatabaseStorageError(
                            "Unable to establish private permissions "
                            "on new storage directory"
                        )

                if is_final:
                    if opened_info.st_uid != os.getuid():
                        raise DatabaseStorageError(
                            "Database storage directory must be owned "
                            "by the current user"
                        )

                    if stat.S_IMODE(opened_info.st_mode) != 0o700:
                        raise DatabaseStorageError(
                            "Database storage directory must have "
                            "0700 permissions"
                        )

            except BaseException:
                os.close(child_fd)
                raise

            os.close(current_fd)
            current_fd = child_fd

        return current_fd

    except BaseException:
        os.close(current_fd)
        raise


def prepare_database_file(data_dir: str | Path) -> Path:
    """Prepare a private SQLite database file without following symlinks.

    POSIX directory traversal and file ownership/permissions are checked.
    Windows ACLs are managed by the operating system and are not verified
    by this implementation.
    """

    directory = Path(data_dir).expanduser()

    if not directory.is_absolute():
        raise DatabaseStorageError(
            "Database storage directory must be an absolute path"
        )

    if directory == Path(directory.anchor):
        raise DatabaseStorageError(
            "Database storage directory must not be filesystem root"
        )

    try:
        if os.name == "posix":
            if ".." in directory.parts:
                raise DatabaseStorageError(
                    "Database storage path must not contain parent traversal"
                )

            directory_fd = _open_private_directory(directory)

            try:
                filename = DATABASE_FILENAME

                try:
                    entry_info = os.stat(
                        filename,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    entry_info = None

                if entry_info is not None:
                    if stat.S_ISLNK(entry_info.st_mode):
                        raise DatabaseStorageError(
                            "SQLite database must not be a symbolic link"
                        )

                    if not stat.S_ISREG(entry_info.st_mode):
                        raise DatabaseStorageError(
                            "SQLite database path must refer to a regular file"
                        )

                common_flags = os.O_RDWR
                common_flags |= getattr(os, "O_NOFOLLOW", 0)
                common_flags |= getattr(os, "O_NONBLOCK", 0)
                common_flags |= getattr(os, "O_CLOEXEC", 0)

                try:
                    descriptor = os.open(
                        filename,
                        common_flags | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    try:
                        entry_info = os.stat(
                            filename,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError as exc:
                        raise DatabaseStorageError(
                            "SQLite database entry changed during validation"
                        ) from exc

                    if stat.S_ISLNK(entry_info.st_mode):
                        raise DatabaseStorageError(
                            "SQLite database must not be a symbolic link"
                        )

                    if not stat.S_ISREG(entry_info.st_mode):
                        raise DatabaseStorageError(
                            "SQLite database path must refer to a regular file"
                        )

                    descriptor = os.open(
                        filename,
                        common_flags,
                        dir_fd=directory_fd,
                    )

                try:
                    _validate_database_descriptor(
                        descriptor,
                        expected_entry_info=entry_info,
                    )
                finally:
                    os.close(descriptor)

            finally:
                os.close(directory_fd)

        else:
            # Windows fallback: ACL verification is not implemented here.
            ensure_private_directory(directory)
            database_path = directory / DATABASE_FILENAME

            if database_path.is_symlink():
                raise DatabaseStorageError(
                    "SQLite database must not be a symbolic link"
                )

            if database_path.exists() and not database_path.is_file():
                raise DatabaseStorageError(
                    "SQLite database path must refer to a regular file"
                )

            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
            descriptor = os.open(database_path, flags, 0o600)

            try:
                _validate_database_descriptor(descriptor)
            finally:
                os.close(descriptor)

        return directory / DATABASE_FILENAME

    except DatabaseStorageError:
        raise
    except (OSError, ValueError) as exc:
        raise DatabaseStorageError(
            f"Unable to prepare SQLite database storage: {exc}"
        ) from exc
