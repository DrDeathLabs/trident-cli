"""Binary tool installer — downloads / installs all 12 scanner tools.

Invoked by `trident install-tools`. Puts binaries in settings.tools_dir so
they are found by resolve_binary() without any PATH changes.

Tools handled:
  GitHub binary downloads:  osv-scanner, trufflehog, gitleaks, grype, trivy
  go install:               gosec, govulncheck  (requires Go on PATH)
  pip install:              semgrep, bandit, checkov, pip-audit  (same Python env)
  node built-in:            npm-audit  (requires Node/npm on PATH — only checked)
"""

from __future__ import annotations

import fnmatch
import io
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import httpx

# (repo, windows_pattern, linux_pattern, darwin_pattern, exe_in_archive_or_None)
# Patterns use fnmatch wildcards against the release asset filename.
# exe_in_archive: the filename inside the archive to extract; None = asset IS the binary.
_TOOLS: dict[str, dict] = {
    "osv-scanner": {
        "repo": "google/osv-scanner",
        "windows_amd64": ("osv-scanner_*windows*amd64*.exe", None),
        "linux_amd64":   ("osv-scanner_*linux*amd64*",       None),
        "darwin_amd64":  ("osv-scanner_*darwin*amd64*",      None),
        "darwin_arm64":  ("osv-scanner_*darwin*arm64*",      None),
    },
    "trufflehog": {
        "repo": "trufflesecurity/trufflehog",
        "windows_amd64": ("trufflehog_*windows_amd64.tar.gz", "trufflehog.exe"),
        "linux_amd64":   ("trufflehog_*linux_amd64.tar.gz",   "trufflehog"),
        "darwin_amd64":  ("trufflehog_*darwin_amd64.tar.gz",  "trufflehog"),
        "darwin_arm64":  ("trufflehog_*darwin_arm64.tar.gz",  "trufflehog"),
    },
    "gitleaks": {
        "repo": "gitleaks/gitleaks",
        "windows_amd64": ("gitleaks_*windows_x64.zip",       "gitleaks.exe"),
        "linux_amd64":   ("gitleaks_*linux_x64.tar.gz",      "gitleaks"),
        "darwin_amd64":  ("gitleaks_*darwin_x64.tar.gz",     "gitleaks"),
        "darwin_arm64":  ("gitleaks_*darwin_arm64.tar.gz",   "gitleaks"),
    },
    "grype": {
        "repo": "anchore/grype",
        "windows_amd64": ("grype_*windows_amd64.zip",        "grype.exe"),
        "linux_amd64":   ("grype_*linux_amd64.tar.gz",       "grype"),
        "darwin_amd64":  ("grype_*darwin_amd64.tar.gz",      "grype"),
        "darwin_arm64":  ("grype_*darwin_arm64.tar.gz",      "grype"),
    },
    "trivy": {
        "repo": "aquasecurity/trivy",
        "windows_amd64": ("trivy_*windows-64bit.zip",         "trivy.exe"),
        "linux_amd64":   ("trivy_*Linux-64bit.tar.gz",        "trivy"),
        "darwin_amd64":  ("trivy_*macOS-64bit.tar.gz",        "trivy"),
        "darwin_arm64":  ("trivy_*macOS-ARM64.tar.gz",        "trivy"),
    },
}


def _platform_key() -> str:
    """Return a key like 'windows_amd64' matching the _TOOLS dict."""
    system = sys.platform  # 'win32', 'linux', 'darwin'
    machine = platform.machine().lower()
    if system == "win32":
        os_part = "windows"
    elif system == "darwin":
        os_part = "darwin"
    else:
        os_part = "linux"
    if machine in ("amd64", "x86_64"):
        arch_part = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch_part = "arm64"
    else:
        arch_part = "amd64"
    return f"{os_part}_{arch_part}"


def _latest_release_assets(repo: str, client: httpx.Client) -> list[dict]:
    """Return the assets list from the latest GitHub release."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    r = client.get(url, timeout=30, headers={"Accept": "application/vnd.github+json"})
    r.raise_for_status()
    return r.json().get("assets", [])


def _find_asset(assets: list[dict], pattern: str) -> dict | None:
    for a in assets:
        if fnmatch.fnmatch(a["name"].lower(), pattern.lower()):
            return a
    return None


def _extract_binary(data: bytes, filename: str, target_name: str | None, dest: Path) -> Path:
    """Extract the binary from a zip/tar.gz archive (or treat data as a direct binary)."""
    if filename.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = zf.namelist()
            match = target_name or next(
                (m for m in members if not m.endswith("/")), members[0]
            )
            # Find the member regardless of directory prefix
            member = next((m for m in members if m.endswith(match) or m.endswith(match.lstrip("/"))), match)
            data = zf.read(member)
    elif filename.endswith(".tar.gz") or filename.endswith(".tgz"):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            members = tf.getnames()
            match = target_name or next(
                (m for m in members if not m.endswith("/")), members[0]
            )
            member = next((m for m in members if m.endswith(match)), match)
            f = tf.extractfile(member)
            if f is None:
                raise RuntimeError(f"Could not extract {match} from archive")
            data = f.read()
    # data is now the raw binary bytes
    dest.write_bytes(data)
    if sys.platform != "win32":
        dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return dest


# Go tools installed via `go install`.
_GO_TOOLS: dict[str, str] = {
    "gosec":       "github.com/securego/gosec/v2/cmd/gosec@latest",
    "govulncheck": "golang.org/x/vuln/cmd/govulncheck@latest",
}

# Pip tools installed into the same Python interpreter running Trident.
_PIP_TOOLS: list[str] = ["semgrep", "bandit", "checkov", "pip-audit"]

# Tools that ship with Node — just checked for presence.
_NODE_TOOLS: list[str] = ["npm-audit"]

# Human-readable install guides for missing prerequisites.
_PREREQ_GUIDES = {
    "go": "Install Go from https://go.dev/dl/ (required for gosec, govulncheck)",
    "node": "Install Node.js from https://nodejs.org/ (required for npm-audit)",
}

# Version-check commands for every tool type.
_VERSION_ARGS: dict[str, list[str]] = {
    "osv-scanner":  ["--version"],
    "trufflehog":   ["--version"],
    "gitleaks":     ["version"],
    "grype":        ["version"],
    "trivy":        ["--version"],
    "gosec":        ["--version"],
    "govulncheck":  ["-version"],
    "semgrep":      ["--version"],
    "bandit":       ["--version"],
    "checkov":      ["--version"],
    "pip-audit":    ["--version"],
    "npm-audit":    None,  # verified via npm --version (not a standalone binary)
}

ALL_TOOLS: list[str] = (
    list(_TOOLS.keys()) + list(_GO_TOOLS.keys()) + _PIP_TOOLS + _NODE_TOOLS
)


def _go_available() -> bool:
    return shutil.which("go") is not None


def _node_available() -> bool:
    return shutil.which("node") is not None or shutil.which("npm") is not None


def _install_go_runtime(tools_dir: Path, client: httpx.Client, echo=print) -> Path:
    """Download and extract the Go toolchain into tools_dir/go_runtime/. Returns path to go binary."""
    echo("  go runtime: fetching release manifest from go.dev ...")
    resp = client.get("https://go.dev/dl/?mode=json", timeout=30)
    resp.raise_for_status()
    files = resp.json()[0]["files"]
    os_, arch = _platform_key().split("_", 1)
    try:
        match = next(
            f for f in files
            if f["os"] == os_ and f["arch"] == arch and f["kind"] == "archive"
        )
    except StopIteration:
        raise RuntimeError(f"No Go release archive found for {os_}/{arch}")
    filename = match["filename"]
    echo(f"  go runtime: downloading {filename} ({match['size'] // 1_048_576} MB) ...")
    data = client.get(f"https://dl.google.com/go/{filename}", timeout=600).content
    dest = tools_dir / "go_runtime"
    dest.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if sys.platform == "win32" else ""
    go_bin = dest / "go" / "bin" / f"go{suffix}"
    # Extract the entire archive into dest; Go archives unpack as a "go/" subtree.
    if filename.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(dest)
    if not go_bin.exists():
        raise RuntimeError(f"Go binary not found at expected path {go_bin} after extraction")
    if sys.platform != "win32":
        go_bin.chmod(go_bin.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    echo(f"  go runtime: OK -> {go_bin}")
    return go_bin


def install_pip_tools(echo=print) -> dict[str, bool]:
    """Install pip-managed scanner tools into the current Python environment."""
    results: dict[str, bool] = {}
    for pkg in _PIP_TOOLS:
        echo(f"  {pkg}: queued for pip installation ...")
    try:
        # Resolve them together.  Installing each package separately lets the
        # last package silently replace shared dependencies selected by an
        # earlier one (notably Click: Semgrep pins 8.4.x while other scanners
        # accept newer releases).
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", *_PIP_TOOLS],
            capture_output=True, timeout=1200,
        )
        if r.returncode == 0:
            for pkg in _PIP_TOOLS:
                echo(f"  {pkg}: OK")
                results[pkg] = True
        else:
            msg = (r.stderr or r.stdout or b"").decode(errors="replace").strip()[:500]
            echo(f"  pip scanner install FAILED - {msg}")
            for pkg in _PIP_TOOLS:
                results[pkg] = False
    except Exception as exc:
        echo(f"  pip scanner install FAILED - {exc}")
        for pkg in _PIP_TOOLS:
            results[pkg] = False
    return results


def install_go_tools(tools_dir: Path, client: httpx.Client, echo=print) -> dict[str, bool]:
    """Install Go-based tools via `go install`, bootstrapping Go itself if needed."""
    results: dict[str, bool] = {}
    if _go_available():
        go_bin = Path(shutil.which("go"))  # type: ignore[arg-type]
    else:
        try:
            go_bin = _install_go_runtime(tools_dir, client, echo)
        except Exception as exc:
            echo(f"  [error] Could not bootstrap Go runtime: {exc}")
            for name in _GO_TOOLS:
                results[name] = False
            return results
    for name, pkg in _GO_TOOLS.items():
        echo(f"  {name}: go install {pkg} ...")
        try:
            r = subprocess.run(
                [str(go_bin), "install", pkg],
                capture_output=True, timeout=300,
                env={
                    **os.environ,
                    "GOBIN": str(tools_dir),
                    "CGO_ENABLED": "0",
                    "PATH": str(go_bin.parent) + os.pathsep + os.environ.get("PATH", ""),
                },
            )
            if r.returncode == 0:
                echo(f"  {name}: OK")
                results[name] = True
            else:
                msg = (r.stderr or r.stdout or b"").decode(errors="replace").strip()[:200]
                echo(f"  {name}: FAILED - {msg}")
                results[name] = False
        except Exception as exc:
            echo(f"  {name}: FAILED - {exc}")
            results[name] = False
    return results


def check_node_tools(echo=print) -> dict[str, str]:
    """Check npm/node availability for npm-audit. Returns {name: 'system'|'missing'}."""
    status: dict[str, str] = {}
    if _node_available():
        status["npm-audit"] = "system"
    else:
        echo(f"  [warn] Node.js not found - {_PREREQ_GUIDES['node']}")
        status["npm-audit"] = "missing"
    return status


def install_tool(name: str, tools_dir: Path, client: httpx.Client,
                 echo=print) -> bool:
    """Download and install one binary tool. Returns True on success."""
    spec = _TOOLS.get(name)
    if spec is None:
        echo(f"  {name}: no binary installer (install via pip or system package manager)")
        return False

    platform_key = _platform_key()
    asset_spec = spec.get(platform_key)
    if asset_spec is None:
        echo(f"  {name}: no binary available for platform {platform_key}")
        return False

    pattern, binary_in_archive = asset_spec
    repo = spec["repo"]

    try:
        echo(f"  {name}: fetching latest release from {repo} ...")
        assets = _latest_release_assets(repo, client)
        asset = _find_asset(assets, pattern)
        if asset is None:
            echo(f"  {name}: FAILED (no asset matching '{pattern}')")
            return False

        echo(f"  {name}: downloading {asset['name']} ({asset['size'] // 1024} KB) ...")
        r = client.get(asset["browser_download_url"], timeout=120, follow_redirects=True)
        r.raise_for_status()

        tools_dir.mkdir(parents=True, exist_ok=True)
        suffix = ".exe" if sys.platform == "win32" else ""
        dest = tools_dir / (name + suffix)

        _extract_binary(r.content, asset["name"], binary_in_archive, dest)
        echo(f"  {name}: OK -> {dest}")
        return True
    except Exception as exc:
        echo(f"  {name}: FAILED ({exc})")
        return False


def install_all(tools_dir: Path, echo=print) -> dict[str, bool]:
    """Install all tools: GitHub binaries + Go tools + pip tools. Returns {name: success}."""
    results: dict[str, bool] = {}
    with httpx.Client() as client:
        for name in _TOOLS:
            results[name] = install_tool(name, tools_dir, client, echo=echo)
        results.update(install_go_tools(tools_dir=tools_dir, client=client, echo=echo))
    results.update(install_pip_tools(echo=echo))
    node_status = check_node_tools(echo=echo)
    for name, state in node_status.items():
        results[name] = state == "system"
    return results


def check_tools(tools_dir: Path) -> dict[str, str]:
    """Return status for all 12 tools: 'managed'|'system'|'pip'|'missing'."""
    status: dict[str, str] = {}

    # GitHub-managed binaries
    for name in _TOOLS:
        suffix = ".exe" if sys.platform == "win32" else ""
        if (tools_dir / (name + suffix)).exists():
            status[name] = "managed"
        elif shutil.which(name):
            status[name] = "system"
        else:
            status[name] = "missing"

    # Go tools — check managed path first (GOBIN=tools_dir), then system PATH
    for name in _GO_TOOLS:
        suffix = ".exe" if sys.platform == "win32" else ""
        if (tools_dir / (name + suffix)).exists():
            status[name] = "managed"
        elif shutil.which(name):
            status[name] = "system"
        else:
            status[name] = "missing"

    # Pip tools — check importability
    import importlib
    from trident.tools.base import python_env_binary
    _pip_pkg_map = {"semgrep": "semgrep", "bandit": "bandit", "checkov": "checkov", "pip-audit": "pip_audit"}
    for tool_name, module in _pip_pkg_map.items():
        try:
            importlib.util.find_spec(module)
            if python_env_binary(tool_name) or shutil.which(tool_name) or shutil.which(tool_name.replace("-", "_")):
                status[tool_name] = "pip"
            else:
                status[tool_name] = "missing"
        except Exception:
            status[tool_name] = "missing"

    # Node tools
    status["npm-audit"] = "system" if _node_available() else "missing"

    return status


def verify_tools(tools_dir: Path, echo=print) -> dict[str, bool]:
    """Run each tool's version command to confirm it executes. Returns {name: ok}."""
    from trident.tools.base import resolve_binary

    results: dict[str, bool] = {}
    for name, args in _VERSION_ARGS.items():
        # npm-audit: verify via `npm --version`
        if args is None:
            npm = shutil.which("npm")
            if npm:
                try:
                    r = subprocess.run([npm, "--version"], capture_output=True, timeout=10)
                    ver = (r.stdout or r.stderr or b"").decode(errors="replace").strip().splitlines()
                    echo(f"  OK {name:<20} npm {ver[0] if ver else '?'} (npm audit)")
                    results[name] = True
                except Exception as exc:
                    echo(f"  FAIL {name:<20} ERROR: {exc}")
                    results[name] = False
            else:
                echo(f"  FAIL {name:<20} npm not found")
                results[name] = False
            continue

        try:
            binary = resolve_binary(name)
        except Exception:
            binary = shutil.which(name) or name
        try:
            r = subprocess.run(
                [binary] + args, capture_output=True, timeout=15,
            )
            version_line = (r.stdout or r.stderr or b"").decode(errors="replace").splitlines()
            version = version_line[0].strip()[:60] if version_line else "?"
            ok = r.returncode == 0
            icon = "OK" if ok else "FAIL"
            echo(f"  {icon} {name:<20} {version}")
            results[name] = ok
        except Exception as exc:
            echo(f"  FAIL {name:<20} ERROR: {exc}")
            results[name] = False
    return results


def warmup_dbs(tools_dir: Path, echo=print) -> None:
    """Pre-download vulnerability databases for trivy and grype so they don't
    slow down the first real scan. Semgrep rules are cached on first use."""
    import subprocess
    import tempfile
    from trident.tools.base import resolve_binary

    # Trivy: explicit DB download (avoids 1–3 min delay on first scan).
    # --download-db-only is a subcommand flag in trivy v0.52+, not global.
    echo("[trident] warming up trivy vulnerability DB ...")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [resolve_binary("trivy"), "fs", "--download-db-only", "--quiet", tmp],
                timeout=300, check=False,
            )
        echo("[trident] trivy DB ready")
    except Exception as exc:
        echo(f"[trident] trivy warmup failed (non-fatal): {exc}")

    # Grype: triggers DB update
    echo("[trident] warming up grype vulnerability DB ...")
    try:
        subprocess.run(
            [resolve_binary("grype"), "db", "update"],
            timeout=300, check=False,
        )
        echo("[trident] grype DB ready")
    except Exception as exc:
        echo(f"[trident] grype warmup failed (non-fatal): {exc}")

    # Semgrep: cache rules by scanning an empty temp directory
    echo("[trident] warming up semgrep rules ...")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [resolve_binary("semgrep"), "scan", "--config", "auto", "--quiet", tmp],
                timeout=120, check=False,
            )
        echo("[trident] semgrep rules cached")
    except Exception as exc:
        echo(f"[trident] semgrep warmup failed (non-fatal): {exc}")
