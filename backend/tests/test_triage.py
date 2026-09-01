"""Triage rubric — the transparent factors→tier mapping (no LLM)."""

from __future__ import annotations

from unittest.mock import patch

from trident.models import Finding
from trident.reliability.schemas import TriageAssessment
from trident.triage import _classify, apply_class_guard, apply_corpus_guard, tier_for


def _a(**kw):
    return TriageAssessment(**kw)


def _f(**kw):
    kw.setdefault("tool", "semgrep")
    kw.setdefault("rule_id", "")
    kw.setdefault("title", "")
    return Finding(**kw)


def test_p0_is_unauth_remote_rce_trivial():
    a = _a(impact="rce", attack_vector="remote_unauth", exploitability="trivial")
    assert tier_for(a) == "P0"


def test_authed_or_hard_drops_below_p0():
    # same catastrophic impact but requires a login -> not P0
    assert tier_for(_a(impact="rce", attack_vector="remote_auth", exploitability="trivial")) == "P1"
    # unauth remote but hard to exploit -> not P0
    assert tier_for(_a(impact="rce", attack_vector="remote_unauth", exploitability="difficult")) == "P1"


def test_local_high_impact_is_gated():
    # RCE but only via local shell -> P2, not an internet emergency
    assert tier_for(_a(impact="rce", attack_vector="local", exploitability="trivial")) == "P2"


def test_hygiene_is_low():
    assert tier_for(_a(impact="info_disclosure", attack_vector="local", exploitability="difficult")) == "P4"
    assert tier_for(_a(impact="other", attack_vector="physical", exploitability="difficult")) == "P4"


def test_chain_membership_bumps_up_one_tier():
    a = _a(impact="data_exposure", attack_vector="remote_auth", exploitability="moderate")
    solo = tier_for(a, in_chain=False)
    chained = tier_for(a, in_chain=True)
    assert int(chained[1]) == int(solo[1]) - 1  # one tier more urgent


def test_p0_never_bumps_out_of_range():
    a = _a(impact="rce", attack_vector="remote_unauth", exploitability="trivial")
    assert tier_for(a, in_chain=True) == "P0"


# --- class guard -------------------------------------------------------------

def test_classify_secret_and_hygiene():
    assert _classify(_f(title="Possible hardcoded password: 'admin123'")) == "secret"
    assert _classify(_f(rule_id="generic.secrets.security.detected-jwt-token")) == "secret"
    assert _classify(_f(tool="gitleaks", rule_id="aws-key")) == "secret"
    assert _classify(_f(title="Use of weak MD5 hash for security")) == "hygiene"
    assert _classify(_f(rule_id="python.django.security.audit.csrf-exempt")) == "hygiene"
    assert _classify(_f(title="Flask Debug Mode Enabled")) == "hygiene"


def test_classify_leaves_real_vulns_untouched():
    # genuinely-remote lookalikes and real code-exec must NOT be down-ranked
    assert _classify(_f(title="Predictable and Reversible Session Token")) is None
    assert _classify(_f(title="Predictable and Leaked Password Reset Tokens")) is None
    assert _classify(_f(rule_id="python.flask.security.insecure-deserialization")) is None
    assert _classify(_f(title="Server-Side Template Injection (SSTI)")) is None
    assert _classify(_f(rule_id="subprocess-shell-true")) is None


def test_secret_guard_caps_p0_to_p2():
    # model over-rates a hardcoded key as remote_unauth auth_bypass trivial -> P0
    a = _a(impact="auth_bypass", attack_vector="remote_unauth", exploitability="trivial")
    f = _f(title="Hardcoded Django SECRET_KEY")
    assert tier_for(a) == "P0"                       # ungated model verdict
    imp, vec, note = apply_class_guard(f, a)
    assert vec == "local" and imp == "data_exposure" and note
    assert tier_for(a, impact=imp, attack_vector=vec) == "P2"


def test_hygiene_guard_caps_to_p3():
    a = _a(impact="rce", attack_vector="remote_unauth", exploitability="trivial")
    f = _f(title="Standard pseudo-random generators are not suitable")
    imp, vec, note = apply_class_guard(f, a)
    assert vec == "local" and imp == "dos" and note
    assert tier_for(a, impact=imp, attack_vector=vec) == "P3"


def test_guarded_secret_still_climbs_if_chained():
    # reachability escape hatch: a secret proven reachable via a chain -> P1
    a = _a(impact="auth_bypass", attack_vector="remote_unauth", exploitability="trivial")
    f = _f(title="Hardcoded Flask Secret Key")
    imp, vec, _ = apply_class_guard(f, a)
    assert tier_for(a, in_chain=True, impact=imp, attack_vector=vec) == "P1"


def test_guard_passes_through_unmatched():
    a = _a(impact="rce", attack_vector="remote_unauth", exploitability="trivial")
    f = _f(title="Insecure Deserialization leading to RCE")
    imp, vec, note = apply_class_guard(f, a)
    assert (imp, vec, note) == ("rce", "remote_unauth", None)


# --- corpus guard ------------------------------------------------------------

_FAKE_PROFILES = {
    "CWE-89":  {"cve_count": 5000, "expected_tier": "P1"},  # SQLi → typically P1
    "CWE-200": {"cve_count": 3000, "expected_tier": "P3"},  # info disclosure → P3
    "CWE-798": {"cve_count": 1000, "expected_tier": "P1"},  # hardcoded creds → P1
}


def test_corpus_guard_caps_overescalated_finding():
    # LLM rates info-disclosure at P1 (remote_auth + data_exposure); corpus says P3.
    a = _a(impact="data_exposure", attack_vector="remote_auth", exploitability="moderate")
    f = _f(cwe="CWE-200")
    assert tier_for(a) == "P1"
    with patch("trident.triage._corpus_profiles", return_value=_FAKE_PROFILES):
        imp, vec, note = apply_corpus_guard(f, a, "data_exposure", "remote_auth")
    assert note is not None and "↓" in note
    assert tier_for(a, impact=imp, attack_vector=vec) >= "P3"


def test_corpus_guard_raises_underescalated_finding():
    # LLM rates SQLi at P3 (local + dos); corpus says P1 → corpus raises it.
    a = _a(impact="dos", attack_vector="local", exploitability="moderate")
    f = _f(cwe="CWE-89")
    assert tier_for(a) == "P3"
    with patch("trident.triage._corpus_profiles", return_value=_FAKE_PROFILES):
        imp, vec, note = apply_corpus_guard(f, a, "dos", "local")
    assert note is not None and "↑" in note
    assert tier_for(a, impact=imp, attack_vector=vec) <= "P1"


def test_class_guard_overrides_corpus_raise_for_hygiene():
    # New pipeline order: corpus runs first (raises weak-crypto to P1), then class
    # guard runs and knocks it back down to P3. No guard_fired flag needed.
    a = _a(impact="dos", attack_vector="local", exploitability="moderate")
    f = _f(title="Use of weak MD5 hash", cwe="CWE-89")  # hygiene + CWE that corpus raises
    with patch("trident.triage._corpus_profiles", return_value=_FAKE_PROFILES):
        imp_c, vec_c, corpus_note = apply_corpus_guard(f, a, a.impact, a.attack_vector)
    # Corpus raised it
    assert corpus_note is not None and "↑" in corpus_note
    # Class guard overrides corpus output
    imp_g, vec_g, guard_note = apply_class_guard(f, a, imp_c, vec_c)
    assert guard_note is not None, "hygiene class guard must fire"
    assert vec_g == "local" and imp_g == "dos"
    assert tier_for(a, impact=imp_g, attack_vector=vec_g) >= "P3"


def test_corpus_raise_then_reachability_caps():
    # New pipeline: corpus raises SQLi from P3 to P1, then reachability caps
    # vector to local → final tier P2 (correct: real SQLi, not HTTP-reachable today).
    a = _a(impact="dos", attack_vector="local", exploitability="moderate")
    f = _f(title="SQL Injection", cwe="CWE-89")
    with patch("trident.triage._corpus_profiles", return_value=_FAKE_PROFILES):
        imp, vec, corpus_note = apply_corpus_guard(f, a, a.impact, a.attack_vector)
    assert corpus_note is not None and "↑" in corpus_note
    imp2, vec2, guard_note = apply_class_guard(f, a, imp, vec)
    assert guard_note is None   # not secret/hygiene
    # Simulate reachability cap to local
    from trident.triage import _cap, _VECTOR_RANK
    vec3 = _cap(vec2, _VECTOR_RANK, "local")
    assert vec3 == "local"
    assert tier_for(a, impact=imp2, attack_vector=vec3) == "P2"


def test_three_guard_pipeline_secret_in_chain():
    # New order: corpus first (raises CWE-798), class guard overrides, chain bump promotes.
    a = _a(impact="auth_bypass", attack_vector="remote_unauth", exploitability="trivial")
    f = _f(title="Hardcoded API key", cwe="CWE-798")
    with patch("trident.triage._corpus_profiles", return_value=_FAKE_PROFILES):
        imp, vec, corpus_note = apply_corpus_guard(f, a, a.impact, a.attack_vector)
    imp2, vec2, guard_note = apply_class_guard(f, a, imp, vec)
    assert guard_note is not None and vec2 == "local"
    # Final tier with chain bump
    assert tier_for(a, in_chain=True, impact=imp2, attack_vector=vec2) < "P4"


def test_three_guard_pipeline_sqli_unreachable():
    # New order: corpus raises SQLi (P3→P1), class guard passes through (not hygiene),
    # reachability caps vector to local → P2.  Vector never goes back above local.
    a = _a(impact="rce", attack_vector="remote_unauth", exploitability="trivial")
    f = _f(title="SQL Injection", cwe="CWE-89")
    with patch("trident.triage._corpus_profiles", return_value=_FAKE_PROFILES):
        imp, vec, corpus_note = apply_corpus_guard(f, a, a.impact, a.attack_vector)
    imp2, vec2, guard_note = apply_class_guard(f, a, imp, vec)
    assert guard_note is None   # not secret/hygiene
    from trident.triage import _cap, _VECTOR_RANK
    vec3 = _cap(vec2, _VECTOR_RANK, "local")    # simulated reachability cap
    assert vec3 == "local"
    assert tier_for(a, impact=imp2, attack_vector=vec3) <= "P2"
