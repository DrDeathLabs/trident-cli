"""Persistent TOML-backed configuration for the Trident CLI.

Stored at platformdirs.user_config_dir("Trident") / "config.toml".

Resolution order (highest wins):
  1. CLI flags
  2. Environment variables
  3. Config file
  4. Built-in defaults
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import platformdirs

try:
    import tomllib  # stdlib in 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore[no-reuse-def]

import tomli_w


# ---------------------------------------------------------------------------
# Schema: all configurable keys with defaults and descriptions
# ---------------------------------------------------------------------------

CONFIG_SCHEMA: dict[str, dict] = {
    # LLM backend
    "llm.backend": {
        "default": "ollama",
        "description": "LLM provider: ollama, openai, anthropic",
        "valid": ["ollama", "openai", "anthropic"],
        "env": "LLM_BACKEND",
    },
    "llm.base_url": {
        "default": "http://localhost:11434",
        "description": "Ollama base URL",
        "env": "OLLAMA_HOST",
    },
    "llm.openai_api_key": {
        "default": "",
        "description": "OpenAI API key (or set env OPENAI_API_KEY)",
        "env": "OPENAI_API_KEY",
        "secret": True,
    },
    "llm.anthropic_api_key": {
        "default": "",
        "description": "Anthropic API key (or set env ANTHROPIC_API_KEY)",
        "env": "ANTHROPIC_API_KEY",
        "secret": True,
    },
    "llm.expert_model": {
        "default": "",
        "description": "Model for expert reviewers (blank = backend default)",
        "env": "EXPERT_MODEL",
    },
    "llm.judge_model": {
        "default": "",
        "description": "Model for the judge (blank = same as expert)",
        "env": "JUDGE_MODEL",
    },
    # Scan behaviour
    "scan.max_iterations": {
        "default": 3,
        "description": "Max council debate iterations",
        "env": "MAX_ITERATIONS",
    },
    "scan.max_llm_calls": {
        "default": 0,
        "description": "Budget cap on LLM calls (0 = unlimited)",
        "env": "MAX_LLM_CALLS",
    },
    "scan.agentic": {
        "default": False,
        "description": "Enable agentic mode (tool-calling experts)",
        "env": "AGENTIC",
    },
    "scan.severity_gate": {
        "default": "high",
        "description": "CI exit-1 threshold: critical, high, medium, low",
        "valid": ["critical", "high", "medium", "low"],
        "env": "TRIDENT_SEVERITY_GATE",
    },
    # Output
    "output.format": {
        "default": "table",
        "description": "Default output format: table, json, sarif",
        "valid": ["table", "json", "sarif"],
    },
    "output.quiet": {
        "default": False,
        "description": "Suppress progress output",
    },
    # Model / calibration
    "model.data_dir": {
        "default": "",
        "description": "Calibration data directory (blank = platform default)",
        "env": "CALIBRATION_DATA_DIR",
    },
}


def _config_path() -> Path:
    return Path(platformdirs.user_config_dir("Trident")) / "config.toml"


def _load_file() -> dict:
    p = _config_path()
    if not p.exists():
        return {}
    try:
        with p.open("rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def _save_file(data: dict) -> None:
    p = _config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("wb") as f:
        tomli_w.dump(data, f)


def _get_nested(data: dict, section: str, key: str) -> Any:
    return data.get(section, {}).get(key)


def _set_nested(data: dict, section: str, key: str, value: Any) -> None:
    if section not in data:
        data[section] = {}
    data[section][key] = value


def _parse_key(dotted: str) -> tuple[str, str]:
    """Split 'llm.backend' → ('llm', 'backend'). Raises ValueError if invalid."""
    if dotted not in CONFIG_SCHEMA:
        raise ValueError(
            f"Unknown config key: {dotted!r}\n"
            f"Run 'trident config list' to see all valid keys."
        )
    parts = dotted.split(".", 1)
    return parts[0], parts[1]


def _coerce(dotted: str, value: str) -> Any:
    """Coerce a string value to the schema's expected type."""
    default = CONFIG_SCHEMA[dotted]["default"]
    if isinstance(default, bool):
        return value.lower() in ("true", "1", "yes", "on")
    if isinstance(default, int):
        return int(value)
    valid = CONFIG_SCHEMA[dotted].get("valid")
    if valid and value not in valid:
        raise ValueError(f"Invalid value {value!r} for {dotted}. Valid: {valid}")
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get(dotted: str) -> tuple[Any, str]:
    """Return (value, source) where source is 'default'|'config'|'env'."""
    schema = CONFIG_SCHEMA.get(dotted)
    if schema is None:
        raise ValueError(f"Unknown config key: {dotted!r}")
    section, key = dotted.split(".", 1)

    # Env var overrides config file
    env_key = schema.get("env")
    if env_key and os.environ.get(env_key):
        return _coerce(dotted, os.environ[env_key]), "env"

    # Config file
    file_data = _load_file()
    file_val = _get_nested(file_data, section, key)
    if file_val is not None:
        return file_val, "config"

    return schema["default"], "default"


def set_value(dotted: str, value: str) -> None:
    """Persist a value to the config file."""
    _parse_key(dotted)  # validates
    coerced = _coerce(dotted, value)
    section, key = dotted.split(".", 1)
    data = _load_file()
    _set_nested(data, section, key, coerced)
    _save_file(data)


def reset(dotted: str | None = None) -> None:
    """Reset one key (or all keys) to defaults by removing from the config file."""
    if dotted is None:
        p = _config_path()
        if p.exists():
            p.unlink()
        return
    _parse_key(dotted)  # validates
    section, key = dotted.split(".", 1)
    data = _load_file()
    if section in data and key in data[section]:
        del data[section][key]
        if not data[section]:
            del data[section]
        _save_file(data)


def config_path() -> Path:
    return _config_path()


def all_values() -> list[dict]:
    """Return a list of {key, value, source, description, default} for every key."""
    result = []
    for dotted, schema in CONFIG_SCHEMA.items():
        value, source = get(dotted)
        result.append({
            "key": dotted,
            "value": value,
            "source": source,
            "description": schema["description"],
            "default": schema["default"],
            "secret": schema.get("secret", False),
        })
    return result
