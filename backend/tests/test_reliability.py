"""WS1: schema-constrained parsing — failure must be distinguishable from a verdict."""

from __future__ import annotations

from trident.reliability.parse import parse_validated
from trident.reliability.schemas import JudgeVerdict, ReviewVerdict


def test_coerces_messy_but_correct_output():
    obj, err = parse_validated(
        '{"verdict":"TRUE POSITIVE","confidence":"85","severity":"CRITICAL","cwe":"89"}',
        ReviewVerdict,
    )
    assert err is None
    assert obj.verdict == "confirmed"
    assert obj.confidence == 0.85
    assert obj.severity == "critical"
    assert obj.cwe == "CWE-89"


def test_garbage_is_failure_not_default():
    obj, err = parse_validated("the model declined to answer", ReviewVerdict)
    assert obj is None
    assert err  # a real error message, not a silent 'disputed'


def test_confidence_clamped_and_scaled():
    obj, _ = parse_validated('{"verdict":"confirmed","confidence":250}', ReviewVerdict)
    assert 0.0 <= obj.confidence <= 1.0


def test_fenced_json_is_parsed():
    obj, err = parse_validated('```json\n{"final_verdict":"refuted","final_confidence":0.9}\n```', JudgeVerdict)
    assert err is None
    assert obj.final_verdict == "refuted"


def test_unknown_verdict_defaults_to_disputed_but_validates():
    obj, err = parse_validated('{"verdict":"maybe?","confidence":0.5}', ReviewVerdict)
    assert err is None
    assert obj.verdict == "disputed"
