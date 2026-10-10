"""Extraction helpers for downloaded scanner runtimes and user ZIP inputs."""

from __future__ import annotations

import stat
import tarfile
import zipfile
from pathlib import Path

MAX_ARCHIVE_MEMBERS = 100_000
MAX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024


def _check_archive_budget(member_count: int, total_bytes: int) -> None:
    if member_count > MAX_ARCHIVE_MEMBERS:
        raise RuntimeError("archive exceeds the maximum supported member count")
    if total_bytes > MAX_EXTRACTED_BYTES:
        raise RuntimeError("archive exceeds the maximum supported extracted size")


def _copy_member(source, output, limit: int) -> int:
    copied = 0
    while chunk := source.read(min(1024 * 1024, limit - copied + 1)):
        copied += len(chunk)
        if copied > limit:
            raise RuntimeError("archive member exceeds the remaining extraction budget")
        output.write(chunk)
    return copied


def _member_target(root: Path, member: str) -> Path:
    if not member or "\x00" in member:
        raise RuntimeError("unsafe empty or NUL-containing archive member")
    normalized = member.replace("\\", "/")
    if any(part == ".." for part in normalized.split("/")):
        raise RuntimeError(f"unsafe path in archive (path traversal): {member}")
    root_path = root.resolve()
    target = (root_path / member).resolve()
    try:
        target.relative_to(root_path)
    except ValueError as exc:
        raise RuntimeError(f"unsafe path in archive (path traversal): {member}") from exc
    return target


def safe_extract_zip(archive: zipfile.ZipFile, destination: str | Path) -> None:
    """Extract regular ZIP files/directories while rejecting links and escapes."""
    root = Path(destination)
    if root.is_symlink():
        raise RuntimeError("archive destination must not be a symbolic link")
    root.mkdir(parents=True, exist_ok=True)
    _ = root.resolve()
    members = archive.infolist()
    _check_archive_budget(len(members), sum(info.file_size for info in members if not info.is_dir()))
    copied_total = 0
    for info in members:
        target = _member_target(root, info.filename)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise RuntimeError(f"symbolic links are not allowed in archives: {info.filename}")
        if info.is_dir() or info.filename.endswith(("/", "\\")):
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with archive.open(info, "r") as source, target.open("wb") as output:
                copied_total += _copy_member(source, output, MAX_EXTRACTED_BYTES - copied_total)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        permissions = mode & 0o777
        if permissions:
            target.chmod(permissions & ~0o022)


def safe_extract_tar(archive: tarfile.TarFile, destination: str | Path) -> None:
    """Extract regular TAR files/directories; reject links and special nodes."""
    root = Path(destination)
    if root.is_symlink():
        raise RuntimeError("archive destination must not be a symbolic link")
    root.mkdir(parents=True, exist_ok=True)
    members = archive.getmembers()
    _check_archive_budget(len(members), sum(member.size for member in members if member.isfile()))
    copied_total = 0
    for member in members:
        target = _member_target(root, member.name)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile():
            raise RuntimeError(f"links and special files are not allowed in archives: {member.name}")
        source = archive.extractfile(member)
        if source is None:
            raise RuntimeError(f"could not read archive member: {member.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with source, target.open("wb") as output:
                copied_total += _copy_member(source, output, MAX_EXTRACTED_BYTES - copied_total)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        permissions = member.mode & 0o777
        if permissions:
            target.chmod(permissions & ~0o022)
