"""Train and serve a GradientBoostingClassifier on cwe_profiles."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

_TIER_MAP = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
_TIER_REVERSE = {v: k for k, v in _TIER_MAP.items()}

_AV_CLASSES = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]
_IMPACT_CLASSES = ["rce", "auth_bypass", "data_exposure", "data_tampering",
                   "ssrf", "injection", "dos", "info_disclosure", "other"]

_FEATURE_NAMES = (
    ["median_cvss", "mean_epss", "kev_rate", "exploit_rate"]
    + [f"av_{v}" for v in _AV_CLASSES]
    + [f"impact_{v}" for v in _IMPACT_CLASSES]
)


def model_path() -> Path:
    data_dir = Path(os.environ.get("CALIBRATION_DATA_DIR", "/data/calibration"))
    return data_dir / "model.joblib"


@lru_cache(maxsize=1)
def load_model():
    import joblib
    return joblib.load(model_path())


def _row_to_features(row: dict | sqlite3.Row) -> list[float]:
    def get(key, default=0.0):
        val = row[key] if isinstance(row, sqlite3.Row) else row.get(key)
        return float(val) if val is not None else default

    av = row["modal_attack_vector"] or ""
    impact = row["modal_impact"] or ""

    return (
        [get("median_cvss"), get("mean_epss"), get("kev_rate"), get("exploit_rate")]
        + [1.0 if av == v else 0.0 for v in _AV_CLASSES]
        + [1.0 if impact == v else 0.0 for v in _IMPACT_CLASSES]
    )


def train(conn: sqlite3.Connection) -> dict:
    """Train GradientBoostingClassifier on cwe_profiles. Returns metrics dict."""
    import joblib
    from sklearn.ensemble import GradientBoostingClassifier

    rows = conn.execute(
        "SELECT * FROM cwe_profiles WHERE expected_tier IS NOT NULL"
    ).fetchall()

    if len(rows) < 5:
        raise ValueError(f"Too few profiles to train: {len(rows)}")

    X = [_row_to_features(r) for r in rows]
    y = [_TIER_MAP.get(r["expected_tier"], 4) for r in rows]

    clf = GradientBoostingClassifier(n_estimators=200, max_depth=4, random_state=42)
    clf.fit(X, y)

    preds = clf.predict(X)
    accuracy = sum(p == t for p, t in zip(preds, y)) / len(y)

    trained_at = datetime.now(timezone.utc).isoformat()
    clf._trained_at = trained_at
    clf._accuracy = round(accuracy, 4)
    clf._n_samples = len(rows)
    clf._feature_names = _FEATURE_NAMES

    mp = model_path()
    mp.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, mp)

    # Bust the LRU cache so next predict() loads fresh model
    load_model.cache_clear()

    return {"accuracy": round(accuracy, 4), "n_samples": len(rows), "trained_at": trained_at}


def predict(cwe: str, conn: sqlite3.Connection) -> dict | None:
    row = conn.execute(
        "SELECT * FROM cwe_profiles WHERE cwe=?", (cwe,)
    ).fetchone()
    if row is None:
        return None

    clf = load_model()
    features = [_row_to_features(row)]
    pred_class = int(clf.predict(features)[0])
    proba = clf.predict_proba(features)[0]
    confidence = float(proba[pred_class])

    importances = clf.feature_importances_
    top_idx = sorted(range(len(importances)), key=lambda i: -importances[i])[:3]
    top_features = [_FEATURE_NAMES[i] for i in top_idx]

    return {
        "expected_tier": _TIER_REVERSE[pred_class],
        "confidence": round(confidence, 4),
        "top_features": top_features,
    }
