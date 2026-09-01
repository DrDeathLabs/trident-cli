"""Trident configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import platformdirs


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _app_data_dir() -> Path:
    """Per-OS app-data directory for desktop mode (SQLite file, workspaces,
    downloaded scanner binaries) — resolves to the right place on
    macOS/Windows/Linux with no Docker/Tauri-side plumbing needed."""
    return Path(platformdirs.user_data_dir("Trident"))


@dataclass
class LLMConfig:
    backend: str = field(default_factory=lambda: _env("LLM_BACKEND", "ollama"))
    ollama_host: str = field(default_factory=lambda: _env("OLLAMA_HOST", "http://localhost:11434"))
    # One default model for every council role (experts, judge, red-team), with
    # optional per-role overrides and a per-job override via the scan profile.
    default_model: str = field(default_factory=lambda: _env("EXPERT_MODEL", "gemma4:31b-cloud"))
    judge_model: str = field(default_factory=lambda: _env("JUDGE_MODEL", ""))
    redteam_model: str = field(default_factory=lambda: _env("REDTEAM_MODEL", ""))
    # Triage is a one-time calibration/judgment pass; it can use a stronger or
    # better-calibrated model than the per-iteration scan without the scan cost.
    triage_model: str = field(default_factory=lambda: _env("TRIAGE_MODEL", ""))
    embedding_model: str = field(default_factory=lambda: _env("EMBEDDING_MODEL", "qwen3-embedding:0.6b"))
    request_timeout: int = int(_env("LLM_TIMEOUT", "300"))
    max_retries: int = int(_env("LLM_MAX_RETRIES", "3"))
    # Bounded parallelism for LLM calls (aligns with Ollama's OLLAMA_NUM_PARALLEL).
    concurrency: int = int(_env("LLM_CONCURRENCY", "4"))

    def model_for(self, role: str) -> str:
        """Model for a council role: a per-role override, else the default."""
        if role == "judge" and self.judge_model:
            return self.judge_model
        if role == "redteam" and self.redteam_model:
            return self.redteam_model
        return self.default_model


@dataclass
class LoopConfig:
    max_iterations: int = int(_env("MAX_ITERATIONS", "3"))
    min_new_findings: int = int(_env("MIN_NEW_FINDINGS", "2"))
    max_llm_calls: int = int(_env("MAX_LLM_CALLS", "0"))  # 0 = unlimited
    # Always run the adversarial judge on a would-be-confirmed finding at/above
    # this severity, even if experts are unanimously confident — self-reported
    # confidence is an unreliable trigger (models over-report), so the findings
    # that matter get an independent second opinion regardless. "" disables.
    judge_severity_floor: str = _env("JUDGE_SEVERITY_FLOOR", "high")


@dataclass
class AgentConfig:
    """Agentic expert exploration (tool-calling). Off by default; per-job via profile."""
    enabled: bool = field(default_factory=lambda: _env("AGENTIC", "false").lower() == "true")
    max_steps: int = int(_env("AGENT_MAX_STEPS", "6"))


@dataclass
class DBConfig:
    # "sqlite" (default — standalone CLI and desktop mode, no server needed) or
    # "postgres" (Docker/Compose deployment — set TRIDENT_DB_BACKEND=postgres).
    backend: str = field(default_factory=lambda: _env("TRIDENT_DB_BACKEND", "sqlite"))
    host: str = field(default_factory=lambda: _env("POSTGRES_HOST", "localhost"))
    port: int = int(_env("POSTGRES_PORT", "5432"))
    user: str = field(default_factory=lambda: _env("POSTGRES_USER", "trident"))
    password: str = field(default_factory=lambda: _env("POSTGRES_PASSWORD", "trident_dev_pw"))
    db: str = field(default_factory=lambda: _env("POSTGRES_DB", "trident"))
    sqlite_path: Path = field(
        # Path("") is truthy (any Path object is), so check the raw string
        # first rather than `Path(_env(...)) or default` — that `or` never
        # falls through.
        default_factory=lambda: (
            Path(_env("TRIDENT_SQLITE_PATH")) if _env("TRIDENT_SQLITE_PATH")
            else _app_data_dir() / "trident.db"
        )
    )

    @property
    def url(self) -> str:
        if self.backend == "sqlite":
            self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            return f"sqlite:///{self.sqlite_path}"
        return (
            f"postgresql+psycopg2://{self.user}:{self.password}@{self.host}:{self.port}/{self.db}"
        )


@dataclass
class RedisConfig:
    url: str = field(default_factory=lambda: _env("REDIS_URL", "redis://localhost:6379/0"))
    broker_url: str = field(default_factory=lambda: _env("CELERY_BROKER_URL", "redis://localhost:6379/1"))
    result_backend: str = field(
        default_factory=lambda: _env("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")
    )


@dataclass
class Settings:
    llm: LLMConfig = field(default_factory=LLMConfig)
    loop: LoopConfig = field(default_factory=LoopConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    db: DBConfig = field(default_factory=DBConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    # "inprocess" (default — standalone CLI and desktop mode, no Redis/broker) or
    # "celery" (Docker/Compose deployment — set TRIDENT_TASK_BACKEND=celery).
    task_backend: str = field(default_factory=lambda: _env("TRIDENT_TASK_BACKEND", "inprocess"))
    workspaces_dir: Path = field(
        # docker-compose.yml always sets TRIDENT_WORKSPACES=/workspaces
        # explicitly, so Docker mode is unaffected; this fallback only matters
        # for a desktop/local run where nothing set it, and `/workspaces`
        # wouldn't be writable/meaningful on Windows or macOS anyway.
        default_factory=lambda: (
            Path(_env("TRIDENT_WORKSPACES")) if _env("TRIDENT_WORKSPACES")
            else _app_data_dir() / "workspaces"
        )
    )
    # A terminal job's extracted source is deleted after this many days even if
    # nobody ever clicks delete — otherwise disk fills up indefinitely on a
    # long-running instance. Findings/history stay in Postgres; only the
    # on-disk source copy is swept. 0 disables the sweep.
    workspace_retention_days: int = int(_env("WORKSPACE_RETENTION_DAYS", "14"))
    # Where `trident install-tools` places downloaded binaries so they are
    # found without needing to touch the system PATH.
    tools_dir: Path = field(
        default_factory=lambda: (
            Path(_env("TRIDENT_TOOLS_DIR")) if _env("TRIDENT_TOOLS_DIR")
            else _app_data_dir() / "bin"
        )
    )

    # Default enabled tools and experts
    enabled_tools: list[str] = field(
        default_factory=lambda: [
            "semgrep", "bandit", "gosec", "trivy", "grype",
            "gitleaks", "pip-audit", "npm-audit",
            # Tier-1 net-wideners: all-ecosystem SCA, verified secrets, IaC/config,
            # reachability-aware Go. Overlap is collapsed by correlate.py.
            "osv-scanner", "trufflehog", "checkov", "govulncheck",
        ]
    )
    # Domain reviewers only. The judge and red-team are separate roles,
    # constructed directly by the orchestrator (not part of the review pool).
    enabled_experts: list[str] = field(
        default_factory=lambda: [
            "injection", "auth", "crypto", "dependency", "secrets_config",
        ]
    )


settings = Settings()
