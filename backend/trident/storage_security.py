"""Platform-specific protection for Trident's local sensitive files."""

from __future__ import annotations

import csv
import os
import re
import secrets
import stat
import subprocess
from functools import lru_cache
from pathlib import Path


_SID_RE = re.compile(r"^S-1-5(?:-\d+)+$")
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_TEMP_FILE_ATTEMPTS = 10


def _system_tool(name: str) -> Path:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return system_root / "System32" / f"{name}.exe"


@lru_cache(maxsize=1)
def _windows_user_sid() -> str:
    result = subprocess.run(
        [str(_system_tool("whoami")), "/user", "/fo", "csv", "/nh"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise OSError("Unable to determine the current Windows user for file permissions")
    for row in csv.reader(result.stdout.splitlines()):
        if len(row) > 1 and _SID_RE.fullmatch(row[-1].strip()):
            return row[-1].strip()
    raise OSError("Unable to determine the current Windows user for file permissions")


def _restrict_windows_acl(path: Path, *, directory: bool) -> None:
    user_sid = _windows_user_sid()
    inheritance = "(OI)(CI)F" if directory else "F"
    entries = [
        f"*{user_sid}:{inheritance}",
        f"*{_SYSTEM_SID}:{inheritance}",
        f"*{_ADMINISTRATORS_SID}:{inheritance}",
    ]
    tool = str(_system_tool("icacls"))
    # Disable inherited access, replace grants for the approved principals, and
    # remove common broad explicit grants. Avoid `icacls /reset`: on populated
    # app-data trees it can walk a large hierarchy and reset unrelated child
    # ACLs. Arguments are passed without a shell so paths cannot become commands.
    result = subprocess.run(
        [tool, str(path), "/inheritance:r", "/grant:r", *entries,
         "/remove:g", "*S-1-1-0", "*S-1-5-11", "*S-1-5-32-545", "/C"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise OSError("Unable to enforce restrictive Windows permissions for Trident data")


def _is_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether Windows resolved this path component as a reparse point.

    ``Path.is_symlink()`` detects Windows symbolic links, but junctions and
    other reparse points are also capable of redirecting a sensitive path.
    Refuse all reparse points so config and database writes cannot be redirected
    through a directory junction.
    """
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_attribute)


@lru_cache(maxsize=512)
def _restrict_windows_acl_cached(
    path: Path, directory: bool, device: int, inode: int, modified_ns: int,
) -> None:
    """Avoid spawning icacls repeatedly for the same unchanged filesystem object."""
    del device, inode, modified_ns  # identity fields participate in the cache key
    _restrict_windows_acl(path, directory=directory)


def secure_directory(path: Path, *, force: bool = False) -> None:
    """Create and restrict a Trident-owned directory to its current user."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and (path.is_symlink() or _is_reparse_point(metadata)):
        raise OSError("Trident sensitive-data directory must not be a symbolic link or reparse point")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if path.is_symlink() or _is_reparse_point(metadata):
        raise OSError("Trident sensitive-data directory must not be a symbolic link or reparse point")
    if not path.is_dir():
        raise OSError("Trident data directory is not a directory")
    if os.name == "nt":
        metadata = path.stat()
        if force:
            _restrict_windows_acl(path, directory=True)
        else:
            _restrict_windows_acl_cached(
                path, True, metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns,
            )
    else:
        if path.stat().st_mode & 0o777 != 0o700:
            path.chmod(0o700)


def secure_file(path: Path, *, force: bool = False) -> None:
    """Restrict an existing regular file to its current user."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if path.is_symlink() or _is_reparse_point(metadata) or not path.is_file():
        raise OSError("Trident sensitive-data path must be a regular file, not a reparse point")
    if not metadata.st_mode:
        raise OSError("Unable to inspect Trident sensitive-data file")
    if os.name == "nt":
        if force:
            _restrict_windows_acl(path, directory=False)
        else:
            _restrict_windows_acl_cached(
                path, False, metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns,
            )
    else:
        if metadata.st_mode & 0o777 != 0o600:
            path.chmod(0o600)


def _create_private_temp(path: Path) -> tuple[int, Path]:
    """Create a private sibling without retrying access-denied errors.

    ``tempfile.mkstemp`` retries ``PermissionError`` on Windows as though the
    candidate name already existed. A restrictive directory ACL can therefore
    make a failed credential write spin through thousands of names. Here only
    an actual name collision is retried; every other OS error fails promptly.
    """
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for _ in range(_TEMP_FILE_ATTEMPTS):
        temp_path = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
        try:
            return os.open(temp_path, flags, 0o600), temp_path
        except FileExistsError:
            continue
    raise FileExistsError("Unable to create a unique private temporary file")


def atomic_write_private(path: Path, payload: bytes) -> None:
    """Atomically replace a private file without creating a readable window."""
    secure_directory(path.parent, force=True)
    fd, temp_path = _create_private_temp(path)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1  # ownership transferred; do not close a later reused descriptor
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        secure_file(temp_path, force=True)
        os.replace(temp_path, path)
        secure_file(path, force=True)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        temp_path.unlink(missing_ok=True)
        raise
