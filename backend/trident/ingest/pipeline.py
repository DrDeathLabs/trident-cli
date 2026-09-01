"""Ingestion pipeline — import code into a workspace for scanning.

Supports: git clone, zip upload, host-mounted directory, and the demo VulnBank.
Validates the tree (refuses to ingest if a scorecard file is present — blinding).
Enriches: detects languages, records commit hash.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from trident.config import settings
from trident.eval.guard import workspace_has_scorecard
from trident.events.publisher import EventType, publish_event

# Extensions -> language mapping for enrichment
LANG_EXT = {
    ".py": "python", ".go": "go", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".rs": "rust", ".c": "c", ".cpp": "cpp",
}

# VULNBANK path inside the image (copied at build time)
VULNBANK_DIR = os.environ.get("TRIDENT_VULNBANK_DIR", "/app/vulnbank")


def _detect_languages(workspace: str) -> list[str]:
    langs: set[str] = set()
    for root, _dirs, files in os.walk(workspace):
        # Skip common heavy dirs
        if any(part in {".git", "node_modules", "__pycache__", ".venv", "vendor"} for part in root.split(os.sep)):
            continue
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            lang = LANG_EXT.get(ext)
            if lang:
                langs.add(lang)
    return sorted(langs)


def _safe_extract_zip(zf: zipfile.ZipFile, dest: str) -> None:
    """Extract a zip, refusing entries that would escape `dest` (zip-slip)."""
    dest_real = os.path.realpath(dest)
    for member in zf.namelist():
        target = os.path.realpath(os.path.join(dest, member))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            raise RuntimeError(f"unsafe path in archive (zip-slip): {member}")
    zf.extractall(dest)


# Schemes we'll actually hand to `git clone`, plus the scp-like git@host:path
# form. Deliberately excludes `ext::` (runs an arbitrary shell command as the
# "transport") and `file://` (reads local paths on the worker).
_GIT_URL_RE = re.compile(
    r"^(https?|git|ssh)://\S+$"
    r"|^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:\S+$"
)


def _validate_git_source_ref(source_ref: str) -> None:
    """Guard against git-clone argument/transport injection.

    `source_ref` is user-controlled. Two git-specific attacks apply: a value
    starting with '-' can be parsed as an OPTION rather than a URL (e.g.
    --upload-pack=<cmd> can achieve RCE on the worker), and git's `ext::`
    transport lets the "URL" itself run an arbitrary shell command. The scheme
    allowlist blocks both; the leading-'-' check and the protocol.*.allow flags
    on the actual clone call (below) are defense in depth, not the only guard.
    """
    ref = (source_ref or "").strip()
    if not ref or ref.startswith("-"):
        raise ValueError(f"refusing to clone: invalid or unsafe source_ref: {source_ref!r}")
    if not _GIT_URL_RE.match(ref):
        raise ValueError(
            "refusing to clone: source_ref must be an http(s)/git/ssh URL or an "
            f"scp-like git@host:path — got: {source_ref!r}"
        )


def _make_workspace(job_id: str) -> str:
    base = settings.workspaces_dir
    base.mkdir(parents=True, exist_ok=True)
    ws = base / job_id
    ws.mkdir(parents=True, exist_ok=True)
    return str(ws)


def ingest(db: Session, job_id: str, source_type: str, source_ref: str) -> tuple[str, list[str], str | None]:
    """Ingest a source into a workspace. Returns (workspace_path, languages, commit_hash)."""
    ws = _make_workspace(job_id)
    commit_hash: str | None = None

    if source_type == "demo":
        # Copy the bundled VulnBank target
        src = Path(VULNBANK_DIR)
        if not src.exists():
            raise FileNotFoundError(
                f"VulnBank demo target not found at {src}. Ensure vulnbank/ is copied into the image."
            )
        publish_event(db, job_id, EventType.JOB_INGEST_PROGRESS, {"stage": "copying demo target (VulnBank)"})
        for item in src.iterdir():
            if item.name.startswith("."):
                continue
            dst = Path(ws) / item.name
            if item.is_dir():
                shutil.copytree(item, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dst)

    elif source_type == "git":
        _validate_git_source_ref(source_ref)
        publish_event(db, job_id, EventType.JOB_INGEST_PROGRESS, {"stage": "cloning git repo"})
        rc = subprocess.run(
            # -c protocol.{ext,file}.allow=never: even if a future change ever
            # loosens the scheme allowlist above, git itself still refuses the
            # ext:: (arbitrary command) and file:: (local read) transports.
            # `--` separates the URL from options so a validated-but-adjacent
            # edge case can't be reinterpreted as a flag.
            ["git", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never",
             "clone", "--depth", "1", "--", source_ref, ws],
            capture_output=True, text=True, timeout=300,
        )
        if rc.returncode != 0:
            raise RuntimeError(f"git clone failed: {rc.stderr[:500]}")
        # Record commit hash
        try:
            ch = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ws, capture_output=True, text=True)
            commit_hash = ch.stdout.strip() or None
        except Exception:
            commit_hash = None

    elif source_type == "upload":
        # source_ref is the path to an uploaded zip in workspaces/uploads
        zip_path = source_ref
        if not os.path.exists(zip_path):
            raise FileNotFoundError(f"uploaded archive not found: {zip_path}")
        publish_event(db, job_id, EventType.JOB_INGEST_PROGRESS, {"stage": "extracting uploaded archive"})
        with zipfile.ZipFile(zip_path) as zf:
            _safe_extract_zip(zf, ws)
        os.remove(zip_path)

    elif source_type == "mount":
        # source_ref is a local directory — scan it in-place, no copy needed.
        # Copying a 1 GB+ repo wastes minutes and disk space; tools only read.
        #
        # Windows-path translation for Docker: if running on Linux and source_ref
        # looks like a Windows path (e.g. C:\Software\CyberOps), remap it to the
        # container bind-mount at /software/<rest>. docker-compose.yml mounts
        # C:/Software → /software:ro for exactly this purpose.
        resolved_ref = source_ref
        if sys.platform != "win32":
            m = re.match(r'^[A-Za-z]:[/\\]Software[/\\](.+)$', source_ref)
            if m:
                resolved_ref = "/software/" + m.group(1).replace("\\", "/")
        if not os.path.isdir(resolved_ref):
            raise FileNotFoundError(f"mounted path not found: {resolved_ref}")
        publish_event(db, job_id, EventType.JOB_INGEST_PROGRESS, {"stage": "linking mounted directory"})
        db.commit()
        # Point workspace at the original path directly.
        ws = resolved_ref
        # commit_hash already initialized to None above

    else:
        raise ValueError(f"unknown source_type: {source_type}")

    # Blinding guard
    if workspace_has_scorecard(ws):
        shutil.rmtree(ws, ignore_errors=True)
        raise RuntimeError(
            "Ingestion aborted: the source tree contains a scorecard file. "
            "Trident refuses to scan trees containing scorecards (blinding)."
        )

    languages = _detect_languages(ws)
    publish_event(db, job_id, EventType.JOB_INGEST_COMPLETE, {
        "workspace": ws, "languages": languages,
    })
    return ws, languages, commit_hash