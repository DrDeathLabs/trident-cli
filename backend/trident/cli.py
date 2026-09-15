"""Trident CLI - pipeline-friendly scan entry point.

Exit codes:
  0  clean (no findings at or above --severity-gate tier)
  1  findings found at or above --severity-gate tier
  2  scan error (ingest failed, unhandled exception)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections import Counter
from pathlib import Path

import click

from trident import __version__

_TIER_RANK: dict[str, int] = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}

# Mapping from human-readable severity to P-tiers
_SEVERITY_TO_TIER: dict[str, str] = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
}


def _detect_source(workspace: str) -> tuple[str, str]:
    """Return (source_type, source_ref) from a workspace argument."""
    if workspace.startswith(("https://", "http://", "git@", "ssh://")):
        return "git", workspace
    p = Path(workspace).resolve()
    if p.suffix == ".zip":
        return "upload", str(p)
    return "mount", str(p)


async def _run_scan(
    job_id: str, source_type: str, source_ref: str,
    target_name: str, profile: dict,
    run_guards: bool = True,
    quiet: bool = False,
) -> bool:
    from trident.tasks.bodies import ingest_job_body, scan_job_body, triage_job_body

    progress_task = None
    q = None

    if not quiet and not os.environ.get("TRIDENT_DISABLE_EVENTS"):
        try:
            from trident.events import inprocess_bus
            loop = asyncio.get_event_loop()
            inprocess_bus.set_main_loop(loop)
            q = inprocess_bus.subscribe(job_id)

            from trident.progress import ScanProgress
            from trident.config import settings
            max_iters = int(profile.get("max_iterations", settings.loop.max_iterations))
            sp = ScanProgress(
                job_id,
                target_name=target_name,
                max_iterations=max_iters,
                run_guards=run_guards,
            )
            progress_task = asyncio.create_task(sp.run(q))
        except Exception:
            q = None
            progress_task = None

    try:
        ok = await asyncio.to_thread(
            ingest_job_body, job_id, source_type, source_ref,
            target_name, False, None, profile,
        )
        if not ok:
            return False
        await asyncio.to_thread(scan_job_body, job_id)
        # run_scan records orchestration failures on the Job rather than
        # raising them through the worker boundary. Surface those failures to
        # the CLI as exit code 2 instead of emitting an apparently clean report.
        from trident.db import db_session
        from trident.models import Job
        with db_session() as db:
            if (job := db.get(Job, job_id)) is None or job.status == "failed":
                return False
        if run_guards:
            await asyncio.to_thread(triage_job_body, job_id)
        # Triage can be complete while individual model requests remain
        # unresolved. Make that integrity state visible to the job/report
        # consumers instead of presenting it as a clean completion.
        with db_session() as db:
            from trident.models import Finding, Job, JobStatus
            job = db.get(Job, job_id)
            unresolved = db.query(Finding).filter(
                Finding.job_id == job_id,
                Finding.status.in_(("unresolved", "unresolved_model_error", "unreviewed")),
            ).count()
            if job and unresolved and job.status != JobStatus.failed.value:
                job.status = JobStatus.completed_with_unresolved.value
                job.error = f"{unresolved} finding(s) remain unresolved; no fail-open verdict was assigned"
                db.commit()
        return True
    finally:
        if progress_task is not None and not progress_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(progress_task), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                progress_task.cancel()
                try:
                    await progress_task
                except asyncio.CancelledError:
                    pass
        if q is not None:
            try:
                from trident.events import inprocess_bus
                inprocess_bus.unsubscribe(job_id, q)
            except Exception:
                pass


def _render_table(findings: list, name: str, actions: list[dict] | None = None) -> str:
    counts: Counter = Counter(f.priority or "??" for f in findings)
    lines = [
        f"Trident Scan - {name}",
        "-" * 62,
        f"  {'Tier':<5}| {'Count':>5} | Sample",
        "-" * 62,
    ]
    for tier in ("P0", "P1", "P2", "P3", "P4"):
        n = counts.get(tier, 0)
        sample = next(
            (
                f"{f.title[:44]}  ({Path(f.file or '').name}:{f.line_start})"
                for f in findings
                if f.priority == tier
            ),
            "-",
        )
        lines.append(f"  {tier:<5}| {n:>5} | {sample}")
    basis_counts: Counter = Counter(
        (getattr(f, "triage", None) or {}).get("evidence_basis") or "unknown"
        for f in findings
    )
    basis_text = ", ".join(f"{basis}={count}" for basis, count in basis_counts.items()) or "none"
    lines += [
        "-" * 62,
        f"  Total confirmed: {len(findings)}",
        f"  Retained for remediation: {len(findings)}",
        f"  Evidence basis: {basis_text}",
        "",
        "Triage plan:",
    ]
    if actions is not None:
        lines.extend(["", f"Remediation actions: {len(actions)}"])
        for action in actions:
            label = " ".join(filter(None, [action.get("package"), action.get("version")]))
            label = label or action.get("action_id", "")
            lines.append(
                f"  {action.get('action_id')} | {label} | "
                f"highest={action.get('highest_priority') or 'untriaged'} | "
                f"occurrences={action.get('occurrence_count', 0)}"
            )
        lines.append("")
    from trident.triage import PLAYBOOK
    for tier in ("P0", "P1", "P2", "P3", "P4"):
        playbook = PLAYBOOK[tier]
        lines.append(
            f"  {tier}: {counts.get(tier, 0)} | {playbook['label']} | SLA: {playbook['sla']}"
        )
        lines.append(f"       {playbook['how']}")
    return "\n".join(lines)


def _check_corpus_guard(quiet: bool) -> None:
    """Warn if the corpus guard is inactive (no calibration DB)."""
    from trident.model_manager import corpus_db_path
    if not corpus_db_path().exists() and not quiet:
        click.echo(
            "[trident] [warning] Corpus guard inactive - run 'trident model refresh' to enable",
            err=True,
        )


@click.group(context_settings={"max_content_width": 100})
@click.version_option(version=__version__, prog_name="trident")
def cli():
    """Trident - AI-assisted code security analysis engine.

    Runs 12 scanner tools (SAST, SCA, secrets), then an AI council of security
    experts reviews every finding. Three guards (class, corpus, reachability)
    automatically correct severity over- and under-escalations.

    \b
    First-time setup:
      trident install-tools --verify --warmup
      trident config set llm.backend openai
      trident config set llm.openai_api_key sk-...
      trident model refresh                     (optional - enables corpus guard)

    \b
    Run a scan:
      trident scan .                            table output, default gate
      trident scan . --format sarif > out.sarif SARIF for GitHub code scanning
      trident scan . --severity-gate critical   exit 1 only on critical findings
      trident scan . --backend anthropic        use Anthropic instead of Ollama

    \b
    Configure:
      trident config show                       all current settings + sources
      trident config set scan.severity_gate high
      trident config list                       all available keys

    \b
    Deep-dive help topics (run 'trident help <topic>'):
      setup      first-time install walkthrough
      backends   Ollama / OpenAI / Anthropic setup
      ci         GitHub Actions, GitLab CI, SARIF upload
      config     full config key reference
      output     table / json / sarif format details
      guards     what the three AI guards do
      experts    what each AI council expert reviews
      tools      all 12 scanner tools explained

    \b
    Exit codes: 0 = clean  |  1 = findings at/above severity gate  |  2 = scan error
    """


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command("inspect")
@click.argument("report", type=click.Path(dir_okay=False))
@click.option("--mapping", "mapping_path", type=click.Path(dir_okay=False), default=None,
              help="Use an explicit trident-json-mapping-v1 mapping.")
@click.option("--write-mapping", type=click.Path(dir_okay=False), default=None,
              help="Write the deterministic mapping proposal to FILE.")
@click.option("--no-schema-ai", is_flag=True, default=False,
              help="Disable optional model-assisted schema mapping.")
@click.option("--format", "inspect_format", type=click.Choice(["text", "json"]),
              default="text", show_default=True)
def inspect(report: str, mapping_path: str | None, write_mapping: str | None,
            no_schema_ai: bool, inspect_format: str):
    """Inspect REPORT without scanners, persistence, Council review, or triage."""
    from trident.ingest.importers import parse_report
    from trident.ingest.mapping import mapping_from_file

    try:
        mapping = mapping_from_file(mapping_path) if mapping_path else None
        parsed = parse_report(
            report, input_format="auto", mapping=mapping, no_schema_ai=no_schema_ai,
        )
    except Exception as exc:
        raise click.ClickException(f"inspect failed: {exc}") from exc
    if write_mapping:
        if not parsed.mapping:
            raise click.ClickException(
                "--write-mapping is available for generic JSON mappings; "
                "known adapters are deterministic and do not need a mapping file"
            )
        target = Path(write_mapping).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(parsed.mapping, indent=2) + "\n", encoding="utf-8")
    stats = parsed.mapping_stats or {}
    accounting = parsed.accounting or {}
    result = {
        "path": parsed.path,
        "detected_format": parsed.format,
        "candidate_record_collection": (parsed.mapping or {}).get("records"),
        "record_count": parsed.records,
        "mapping": parsed.mapping,
        "mapping_source": parsed.mapping_source,
        "mapping_confidence": stats.get("confidence"),
        "mapping_validation": stats,
        "accounting": accounting,
        "unmapped_important_fields": [
            field for field in ("rule_id", "title", "description", "severity", "cwe", "cve", "package", "file")
            if parsed.mapping and field not in (parsed.mapping.get("fields") or {})
        ],
        "warnings": [
            "source context was not supplied; source reachability is not inferred",
            "report values are untrusted data and are not instructions",
        ],
    }
    if inspect_format == "json":
        click.echo(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return
    click.echo(f"Format: {parsed.format}")
    click.echo(f"Candidate records: {result['candidate_record_collection'] or 'known adapter'}")
    click.echo(f"Records discovered: {parsed.records}")
    click.echo(f"Mapping source: {parsed.mapping_source}")
    click.echo(f"Mapping confidence: {stats.get('confidence', 1.0):.2f}")
    if parsed.mapping:
        for field, selector in parsed.mapping.get("fields", {}).items():
            coverage = (stats.get("coverage") or {}).get(field)
            suffix = f" ({coverage:.0%})" if isinstance(coverage, (int, float)) else ""
            click.echo(f"  {field}: {selector}{suffix}")
    click.echo("Accounting:")
    for key in ("mapped", "partially_mapped", "out_of_scope", "skipped", "malformed", "unsupported", "unexplained"):
        click.echo(f"  {key}: {accounting.get(key, 0)}")
    if result["unmapped_important_fields"]:
        click.echo("Unmapped important fields: " + ", ".join(result["unmapped_important_fields"]))
    for warning in result["warnings"]:
        click.echo(f"Warning: {warning}")

@cli.command()
@click.argument("workspace", required=False, default=None)
@click.option(
    "--input-file", "input_files", multiple=True, type=click.Path(dir_okay=False),
    help="Import standardized or heterogeneous JSON vulnerability evidence instead of running scanners. Repeatable.",
)
@click.option(
    "--input-format", type=click.Choice(["auto", "sonarqube", "dependency-check", "sarif", "cyclonedx", "generic-json"]),
    default="auto", show_default=True, help="Format for imported JSON reports.",
)
@click.option(
    "--mapping", "mapping_path", type=click.Path(dir_okay=False), default=None,
    help="Explicit trident-json-mapping-v1 mapping for heterogeneous JSON.",
)
@click.option(
    "--no-schema-ai", is_flag=True, default=False,
    help="Disable optional model-assisted schema mapping.",
)
@click.option(
    "--source-dir", type=click.Path(file_okay=False), default=None,
    help="Optional source context for imported findings; scanner tools are not run.",
)
@click.option(
    "--scanner-corpus", type=click.Path(exists=True, dir_okay=False), default=None,
    help="Replay a frozen scanner corpus through correlation, model review, triage, and exporters.",
)
@click.option(
    "--discover-novel", is_flag=True, default=False,
    help="With --source-dir, allow source-based novel discovery in import mode.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["table", "sarif", "json"]),
    default=None,
    show_default=True,
    help="Output format: table (default), sarif, json.",
)
@click.option(
    "--output", "-o",
    "output_format_legacy",
    type=click.Choice(["table", "sarif", "json"]),
    default=None,
    hidden=True,
    help="Alias for --format (deprecated).",
)
@click.option(
    "--output-file", "-f",
    type=click.Path(),
    default=None,
    help="Write output to FILE instead of stdout.",
)
@click.option(
    "--triage-output-file",
    type=click.Path(),
    default=None,
    help="Write the automatic worked triage report to FILE in the selected format.",
)
@click.option(
    "--severity-gate",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="CI exit-1 threshold (critical/high/medium/low). Overrides config.",
)
@click.option(
    "--fail-on",
    default=None,
    type=click.Choice(["P0", "P1", "P2", "P3", "P4"]),
    help="CI exit-1 threshold using P-tier notation (P0-P4). Alternative to --severity-gate.",
)
@click.option(
    "--backend",
    type=click.Choice(["ollama", "openai", "anthropic"]),
    default=None,
    help="LLM provider. Overrides config and env.",
)
@click.option("--model", default=None, help="LLM model name. Overrides config and env.")
@click.option("--target-name", default=None, help="Display name for this scan target.")
@click.option("--max-iterations", default=None, type=int, help="Override max scan iterations.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress progress output.")
@click.option(
    "--no-guards", "no_guards", is_flag=True, default=False,
    help="Skip all guards (class, corpus, reachability). Debug use only.",
)
@click.pass_context
def scan(
    ctx,
    workspace: str,
    input_files: tuple[str, ...],
    input_format: str,
    mapping_path: str | None,
    no_schema_ai: bool,
    source_dir: str | None,
    scanner_corpus: str | None,
    discover_novel: bool,
    output_format: str | None,
    output_format_legacy: str | None,
    output_file: str | None,
    triage_output_file: str | None,
    severity_gate: str | None,
    fail_on: str | None,
    backend: str | None,
    model: str | None,
    target_name: str | None,
    max_iterations: int | None,
    quiet: bool,
    no_guards: bool,
):
    """Scan WORKSPACE or import external scanner reports and report findings.

    WORKSPACE can be a local directory path,
    a git URL (https:// or git@), or a .zip archive path.
    With --input-file, scanner subprocesses are not run.

    Exit codes: 0 = clean, 1 = findings at/above severity gate, 2 = scan error.

    \b
    Examples:
      trident scan .
      trident scan --input-file sonar.json
      trident scan --input-file sonar.json --input-file dependency-check.json
      trident scan . --format sarif > results.sarif
      trident scan ./myrepo --backend openai --model gpt-4o
      trident scan ./myrepo --severity-gate critical
      OPENAI_API_KEY=sk-... trident scan . --backend openai --format sarif
    """
    from trident.config import settings
    from trident.db import db_session, engine
    from trident.models import Base, Finding, Job

    workspace = workspace or "."
    if scanner_corpus and input_files:
        raise click.UsageError("--scanner-corpus cannot be combined with --input-file")
    if discover_novel and not input_files:
        raise click.UsageError("--discover-novel requires --input-file")
    if discover_novel and not source_dir:
        raise click.UsageError("--discover-novel requires --source-dir")
    if source_dir and not input_files:
        raise click.UsageError("--source-dir requires --input-file")

    # Resolve output format (--format wins over deprecated --output/-o)
    resolved_format = output_format or output_format_legacy

    # Load format from config if not specified
    if resolved_format is None:
        try:
            from trident import config_manager
            resolved_format, _ = config_manager.get("output.format")
        except Exception:
            resolved_format = "table"

    if output_file and triage_output_file:
        if Path(output_file).resolve() == Path(triage_output_file).resolve():
            raise click.UsageError("--output-file and --triage-output-file must be different files")

    # Resolve severity gate
    if severity_gate:
        fail_on_tier = _SEVERITY_TO_TIER.get(severity_gate, "P1")
    elif fail_on:
        fail_on_tier = fail_on
    else:
        try:
            from trident import config_manager
            gate, _ = config_manager.get("scan.severity_gate")
            fail_on_tier = _SEVERITY_TO_TIER.get(gate, "P1")
        except Exception:
            fail_on_tier = "P1"

    # Apply backend/model overrides to environment (picked up by get_llm_backend)
    if backend:
        os.environ["LLM_BACKEND"] = backend
    if model:
        os.environ["EXPERT_MODEL"] = model

    # Load quiet from config if not set via flag
    if not quiet:
        try:
            from trident import config_manager
            q, _ = config_manager.get("output.quiet")
            quiet = bool(q)
        except Exception:
            pass

    if input_files:
        source_type = "import"
        source_ref = str(Path(input_files[0]).resolve())
        name = target_name or (Path(source_dir).name if source_dir else "imported reports")
    else:
        source_type, source_ref = _detect_source(workspace)
        name = target_name or Path(workspace).name or workspace
    profile: dict = {}
    if scanner_corpus:
        profile["scanner_corpus"] = str(Path(scanner_corpus).resolve())
    if input_files:
        from trident.ingest.importers import prepare_import
        try:
            _reports, import_profile = prepare_import(
                list(input_files), input_format, source_dir,
                mapping_path=mapping_path, no_schema_ai=no_schema_ai,
            )
        except Exception as exc:
            click.echo(f"[trident] import error: {exc}", err=True)
            sys.exit(2)
        profile.update(import_profile)
        profile["discover_novel"] = bool(discover_novel)
    if max_iterations is not None:
        profile["max_iterations"] = max_iterations
    else:
        try:
            from trident import config_manager
            iters, _ = config_manager.get("scan.max_iterations")
            if iters and iters != 3:
                profile["max_iterations"] = iters
        except Exception:
            pass

    Base.metadata.create_all(engine)
    from trident.db import apply_migrations
    apply_migrations()

    with db_session() as db:
        job = Job(
            target_name=name,
            source_type=source_type,
            source_ref=source_ref,
            workspace_path="",
            status="queued",
            profile=profile,
            max_iterations=int(profile.get("max_iterations", settings.loop.max_iterations)),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        job_id = job.id

    if not quiet:
        click.echo(f"[trident] scanning {name!r}  (job {job_id})", err=True)
        if not no_guards:
            _check_corpus_guard(quiet)

    try:
        ok = asyncio.run(_run_scan(
            job_id, source_type, source_ref, name, profile,
            run_guards=not no_guards,
            quiet=quiet,
        ))
    except Exception as exc:
        click.echo(f"[trident] scan error: {exc}", err=True)
        sys.exit(2)

    if not ok:
        with db_session() as db:
            job = db.get(Job, job_id)
            err = (job.error if job else None) or "unknown error during ingest"
        click.echo(f"[trident] scan failed: {err}", err=True)
        sys.exit(2)

    with db_session() as db:
        confirmed = (
            db.query(Finding)
            .filter(Finding.job_id == job_id, Finding.status == "confirmed")
            .order_by(Finding.priority.asc().nullslast(), Finding.created_at.asc())
            .all()
        )

        if resolved_format == "sarif":
            from trident.reporters.exporters import to_sarif
            payload = json.dumps(to_sarif(db, job_id), indent=2)
        elif resolved_format == "json":
            from trident.reporters.exporters import to_json
            payload = json.dumps(to_json(db, job_id), indent=2)
        else:
            from trident.reporters.exporters import _remediation_actions
            payload = _render_table(confirmed, name,
                                    _remediation_actions(db, job_id, confirmed))

        triage_payload = None
        if triage_output_file:
            from trident.reporters.exporters import (
                to_triage_json,
                to_triage_sarif,
                to_triage_table,
            )
            if resolved_format == "json":
                triage_payload = json.dumps(to_triage_json(db, job_id), indent=2)
            elif resolved_format == "sarif":
                triage_payload = json.dumps(to_triage_sarif(db, job_id), indent=2)
            else:
                triage_payload = to_triage_table(db, job_id)

    threshold = _TIER_RANK.get(fail_on_tier, 1)
    blocker_count = sum(
        1 for f in confirmed
        if f.priority and _TIER_RANK.get(f.priority, 99) <= threshold
    )

    if output_file:
        Path(output_file).write_text(payload, encoding="utf-8")
        if not quiet:
            click.echo(f"[trident] {resolved_format} written to {output_file}", err=True)
    else:
        click.echo(payload)

    if triage_output_file:
        Path(triage_output_file).write_text(triage_payload or "", encoding="utf-8")
        if not quiet:
            click.echo(
                f"[trident] {resolved_format} triage report written to {triage_output_file}",
                err=True,
            )

    # An unresolved model decision is a scan-integrity error, not an ordinary
    # severity-gate finding.  Check it before the P-tier gate so exit status
    # cannot misrepresent a degraded result as a normal security failure.
    with db_session() as db:
        from trident.models import Job
        final_job = db.get(Job, job_id)
        if final_job and final_job.status == "completed_with_unresolved":
            if not quiet:
                click.echo("[trident] unresolved model decisions remain - exit 2", err=True)
            sys.exit(2)

    if blocker_count:
        if not quiet:
            click.echo(
                f"[trident] {blocker_count} finding(s) at or above {fail_on_tier} - exit 1",
                err=True,
            )
        sys.exit(1)
    elif not quiet:
        click.echo(f"[trident] no findings at or above {fail_on_tier} - clean", err=True)

# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------

@cli.command("help")
@click.argument("topic", default="")
def help_cmd(topic: str):
    """Show detailed help for a topic.

    \b
    Topics: setup, backends, ci, config, output, guards, experts, tools
    \b
    Examples:
      trident help
      trident help setup
      trident help backends
      trident help ci
    """
    from trident.help_texts import render_topic
    try:
        from rich.console import Console
        console = Console()
        text = render_topic(topic.lower() if topic else "")
        console.print(text)
    except ImportError:
        # Fallback: strip rich markup
        import re
        text = render_topic(topic.lower() if topic else "")
        plain = re.sub(r"\[/?[^\]]+\]", "", text)
        click.echo(plain)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

@cli.group()
def config():
    """Manage persistent Trident configuration.

    Settings are stored in a TOML file at the platform config directory.
    Run 'trident config path' to see the file location.

    Resolution order: CLI flag > env var > config file > default.

    \b
    Examples:
      trident config set llm.backend openai
      trident config show
      trident config list
    """


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """Set KEY to VALUE in the config file.

    \b
    Examples:
      trident config set llm.backend openai
      trident config set llm.openai_api_key sk-...
      trident config set scan.severity_gate high
      trident config set scan.max_iterations 5
    """
    from trident import config_manager
    try:
        config_manager.set_value(key, value)
        click.echo(f"[trident] {key} = {value!r}")
    except ValueError as e:
        click.echo(f"[trident] error: {e}", err=True)
        raise SystemExit(1)


@config.command("get")
@click.argument("key")
def config_get(key: str):
    """Print the current value of KEY."""
    from trident import config_manager
    try:
        value, source = config_manager.get(key)
        click.echo(f"{value}  [{source}]")
    except ValueError as e:
        click.echo(f"[trident] error: {e}", err=True)
        raise SystemExit(1)


@config.command("show")
def config_show():
    """Show all configuration values with their sources."""
    from trident import config_manager
    values = config_manager.all_values()
    col1 = max(len(v["key"]) for v in values) + 2
    col2 = 40
    click.echo(f"\n  {'Key':<{col1}} {'Value':<{col2}} Source")
    click.echo("  " + "-" * (col1 + col2 + 20))
    last_section = None
    for v in values:
        section = v["key"].split(".")[0]
        if section != last_section:
            click.echo("")
            last_section = section
        display = v["value"]
        if v["secret"] and display:
            display = display[:4] + "***" + display[-2:] if len(str(display)) > 8 else "***"
        click.echo(f"  {v['key']:<{col1}} {str(display):<{col2}} [{v['source']}]")
    click.echo("")


@config.command("list")
def config_list():
    """List all configurable keys with descriptions and defaults."""
    from trident import config_manager
    col_key = 30
    col_default = 20
    click.echo(f"\n  {'Key':<{col_key}} {'Default':<{col_default}} Description")
    click.echo("  " + "-" * 80)
    last_section = None
    for key, schema in config_manager.CONFIG_SCHEMA.items():
        section = key.split(".")[0]
        if section != last_section:
            click.echo("")
            last_section = section
        default = repr(schema["default"]) if isinstance(schema["default"], (bool, int)) else schema["default"]
        click.echo(f"  {key:<{col_key}} {str(default):<{col_default}} {schema['description']}")
    click.echo("")


@config.command("reset")
@click.argument("key", default="")
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt.")
def config_reset(key: str, yes: bool):
    """Reset KEY to its default, or reset ALL keys if KEY is omitted."""
    from trident import config_manager
    if not key:
        if not yes:
            click.confirm("[trident] Reset all config to defaults?", abort=True)
        config_manager.reset(None)
        click.echo("[trident] all config reset to defaults")
    else:
        try:
            config_manager.reset(key)
            click.echo(f"[trident] {key} reset to default")
        except ValueError as e:
            click.echo(f"[trident] error: {e}", err=True)
            raise SystemExit(1)


@config.command("path")
def config_path():
    """Print the path to the config file."""
    from trident import config_manager
    click.echo(config_manager.config_path())


@config.command("edit")
def config_edit():
    """Open the config file in $EDITOR."""
    from trident import config_manager
    p = config_manager.config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("# Trident configuration\n")
    editor = os.environ.get("EDITOR", "notepad" if sys.platform == "win32" else "vi")
    os.execlp(editor, editor, str(p))


# ---------------------------------------------------------------------------
# model
# ---------------------------------------------------------------------------

@cli.group()
def model():
    """Manage the statistical severity calibration model.

    The corpus guard uses ~1,200 CWE profiles derived from 285K+ CVEs
    to automatically correct AI severity over/under-escalations.

    \b
    First-time setup:
      trident model refresh          # download all feeds + build + train

    \b
    Day-to-day:
      trident model status           # check freshness
      trident model refresh          # refresh everything
      trident model build            # rebuild from existing data (no download)
    """


@model.command("status")
def model_status():
    """Show feed freshness, corpus profile count, and model accuracy."""
    from trident import model_manager
    status = model_manager.get_status()

    if not status["corpus_db_exists"]:
        click.echo("[trident] No corpus database found.")
        click.echo("[trident] Run 'trident model refresh' to download vulnerability data and train.")
        raise SystemExit(1)

    click.echo(f"\n  Corpus DB:  {model_manager.corpus_db_path()}")
    click.echo(f"  Profiles:   {status['corpus_profiles']} CWE profiles")

    click.echo("\n  Feed status:")
    for feed, info in status.get("feeds", {}).items():
        last = info.get("last_run") or "never"
        rows = info.get("rows", 0)
        click.echo(f"    {feed:<15} {rows:>8,} rows    last: {last}")

    if status.get("model"):
        m = status["model"]
        click.echo(f"\n  Model:       {model_manager.model_path()}")
        click.echo(f"  Accuracy:    {m.get('accuracy', '?')}")
        click.echo(f"  N samples:   {m.get('n_samples', '?')}")
        click.echo(f"  Trained at:  {m.get('trained_at', '?')}")
    else:
        click.echo("\n  Model:       not trained - run 'trident model refresh'")
    click.echo("")


@model.command("refresh")
@click.option("--source", default=None,
              help="Comma-separated feed names to refresh (default: all).")
@click.option("--force", is_flag=True, default=False,
              help="Re-download even if data is fresh.")
@click.option("--yes", "-y", is_flag=True, default=False,
              help="Skip confirmation prompt (for scripted / CI use).")
def model_refresh(source: str | None, force: bool, yes: bool):
    """Download vulnerability feeds, build corpus, train model.

    NVD download can take 5-20 minutes on first run; subsequent runs are
    incremental and much faster.

    \b
    Examples:
      trident model refresh
      trident model refresh --source nvd,epss
      trident model refresh --force
      trident model refresh --yes          # skip confirmation in CI
    """
    from trident import model_manager

    sources = [s.strip() for s in source.split(",")] if source else None

    # Warn if a usable model already exists - rebuilding is expensive.
    if not yes and model_manager.model_path().exists():
        info = model_manager.get_model_info()
        if info and "error" not in info:
            trained = info.get("trained_at") or "unknown date"
            acc = info.get("accuracy", "?")
            n = info.get("n_samples", "?")
            click.echo(
                f"\n[trident] A trained corpus guard model already exists:\n"
                f"          accuracy {acc}  |  {n} samples  |  trained {trained}\n",
                err=True,
            )
        click.echo(
            "[trident] 'trident model refresh' re-downloads all vulnerability feeds\n"
            "          and rebuilds the model from scratch.\n"
            "          NVD alone can take 5-20 minutes on the first run.\n",
            err=True,
        )
        click.confirm("Proceed with full model refresh?", abort=True)

    try:
        import rich  # noqa: F401
        _model_refresh_live(model_manager, sources, force)
    except ImportError:
        _model_refresh_plain(model_manager, sources, force)


def _model_refresh_live(model_manager, sources, force):
    from trident.calibration.feeds import ALL_FEEDS
    from trident.progress import ModelProgress

    target_feeds = sources or ALL_FEEDS
    mp = ModelProgress(feeds=target_feeds)

    try:
        mp.run(model_manager, sources=sources, force=force)
    except Exception as exc:
        click.echo(f"[trident] model refresh failed: {exc}", err=True)
        raise SystemExit(2)

    click.echo("\n[trident] corpus guard is now active.", err=True)
    click.echo(f"[trident] DB: {model_manager.corpus_db_path()}", err=True)


def _model_refresh_plain(model_manager, sources, force):
    click.echo("[trident] downloading feeds...")

    def on_progress(feed_name, status, rows_or_stats):
        if feed_name.startswith("__"):
            return
        if status == "done":
            click.echo(f"  OK {feed_name:<15} {int(rows_or_stats):,} rows")
        elif status == "error":
            click.echo(f"  FAIL {feed_name:<15} failed")

    results = model_manager.refresh(sources=sources, force=force, progress_cb=on_progress)
    n_profiles = results.get("profile_count", 0)
    m_stats = results.get("model") or {}
    accuracy = m_stats.get("accuracy", "?")
    click.echo(f"[trident] corpus: {n_profiles:,} CWE profiles")
    click.echo(f"[trident] model:  accuracy {accuracy}")
    click.echo("[trident] corpus guard is now active.")


@model.command("build")
def model_build():
    """Rebuild CWE profiles and retrain model from existing data (no download)."""
    from trident import model_manager
    click.echo("[trident] building corpus from existing data...")
    n = model_manager.build_corpus_only()
    click.echo(f"[trident] {n:,} CWE profiles written")
    click.echo("[trident] training model...")
    stats = model_manager.train_only()
    acc = stats.get("accuracy", "?")
    click.echo(f"[trident] model trained: accuracy {acc}")


@model.command("train")
def model_train():
    """Retrain the sklearn model from existing CWE profiles only."""
    from trident import model_manager
    if not model_manager.corpus_db_path().exists():
        click.echo("[trident] No corpus DB found. Run 'trident model refresh' first.", err=True)
        raise SystemExit(1)
    click.echo("[trident] training model...")
    stats = model_manager.train_only()
    acc = stats.get("accuracy", "?")
    n = stats.get("n_samples", "?")
    click.echo(f"[trident] accuracy={acc}  n_samples={n}")


@model.command("info")
def model_info():
    """Show model accuracy, feature importances, and training metadata."""
    from trident import model_manager
    info = model_manager.get_model_info()
    if info is None:
        click.echo("[trident] No model found. Run 'trident model refresh' first.", err=True)
        raise SystemExit(1)
    if "error" in info:
        click.echo(f"[trident] model error: {info['error']}", err=True)
        raise SystemExit(1)
    click.echo(f"\n  Model type:  {info.get('model_type', '?')}")
    click.echo(f"  Trained at:  {info.get('trained_at', '?')}")
    click.echo(f"  Accuracy:    {info.get('accuracy', '?')}")
    click.echo(f"  N samples:   {info.get('n_samples', '?')}")
    if info.get("top_features"):
        click.echo("\n  Top features:")
        for feat in info["top_features"][:10]:
            bar = "#" * int(feat["importance"] * 50)
            click.echo(f"    {feat['name']:<30} {feat['importance']:.4f} {bar}")
    click.echo("")


@model.command("reset")
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt.")
def model_reset(yes: bool):
    """Delete the corpus database and trained model."""
    from trident import model_manager
    if not yes:
        click.confirm(
            "[trident] Delete corpus DB and model? (You'll need to run 'trident model refresh' again.)",
            abort=True,
        )
    model_manager.reset_all()
    click.echo("[trident] corpus DB and model deleted.")


@model.command("path")
def model_path_cmd():
    """Print the calibration data directory path."""
    from trident import model_manager
    click.echo(model_manager._data_dir())


# ---------------------------------------------------------------------------
# validation / replay
# ---------------------------------------------------------------------------

@cli.group()
def validate():
    """Create and replay deterministic validation evidence."""


@validate.command("export-corpus")
@click.argument("job_id")
@click.option("--output", "output_file", required=True, type=click.Path())
def validate_export_corpus(job_id: str, output_file: str):
    """Export scanner findings from JOB_ID to a frozen, scanner-free corpus."""
    from trident.db import db_session
    from trident.validation.replay import export_corpus
    with db_session() as db:
        payload = export_corpus(db, job_id, output_file)
    click.echo(json.dumps({"output": str(Path(output_file).resolve()),
                           "records": len(payload["records"]),
                           "corpus_sha256": payload["corpus_sha256"],
                           "scanner_subprocesses": False}, indent=2))


@validate.command("replay-corpus")
@click.argument("corpus", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_file", required=True, type=click.Path())
def validate_replay_corpus(corpus: str, output_file: str):
    """Restore a frozen scanner corpus without launching scanner subprocesses."""
    from trident.db import db_session, engine
    from trident.models import Base
    from trident.validation.replay import restore_corpus
    Base.metadata.create_all(engine)
    with db_session() as db:
        job = restore_corpus(db, corpus)
        result = {"format": "trident-frozen-scanner-replay", "job_id": job.id,
                  "status": job.status, "records": len(job.findings),
                  "scanner_subprocesses": False,
                  "corpus": str(Path(corpus).resolve())}
    Path(output_file).write_text(json.dumps(result, indent=2), encoding="utf-8")
    click.echo(json.dumps({**result, "output": str(Path(output_file).resolve())}, indent=2))


@validate.command("replay-decisions")
@click.argument("artifact", type=click.Path(exists=True, dir_okay=False))
def validate_replay_decisions(artifact: str):
    """Validate an LLM decision replay artifact without model or scanner calls."""
    from trident.validation.replay import replay_decisions
    try:
        result = replay_decisions(artifact)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, indent=2))


@validate.command("export-decisions")
@click.argument("run_id")
@click.option("--output", "output_file", required=True, type=click.Path())
def validate_export_decisions(run_id: str, output_file: str):
    """Export the durable typed-decision ledger for RUN_ID."""
    from trident.db import db_session
    from trident.validation.replay import export_decisions
    with db_session() as db:
        payload = export_decisions(db, run_id, output_file)
    click.echo(json.dumps({"output": str(Path(output_file).resolve()),
                           "run_id": run_id, "decisions": len(payload["decisions"])}, indent=2))


# ---------------------------------------------------------------------------
# install-tools
# ---------------------------------------------------------------------------

@cli.command("install-tools")
@click.option("--tool", default=None, help="Install only this tool (default: all).")
@click.option("--check", is_flag=True, default=False, help="Show status for all 12 tools without installing.")
@click.option("--verify", is_flag=True, default=False, help="Run each tool to confirm it executes.")
@click.option("--warmup", is_flag=True, default=False,
              help="Pre-download trivy/grype vulnerability DBs and semgrep rules.")
def install_tools(tool: str | None, check: bool, verify: bool, warmup: bool):
    """Download and install all 12 required scanner tools.

    Installs Go binaries (osv-scanner, trufflehog, gitleaks, grype, trivy),
    Go tools via 'go install' (gosec, govulncheck - requires Go on PATH),
    Python tools via pip (semgrep, bandit, checkov, pip-audit),
    and verifies Node.js is present for npm-audit.

    \b
    Recommended first-time setup:
      trident install-tools --verify --warmup
    """
    from trident.config import settings
    from trident.tools.installer import (
        _TOOLS, ALL_TOOLS, check_node_tools, check_tools, verify_tools, warmup_dbs,
        install_all, install_tool as _install_one,
    )

    tools_dir = settings.tools_dir
    click.echo(f"[trident] tools directory: {tools_dir}")

    if check:
        status = check_tools(tools_dir)
        for name, state in status.items():
            icon = {"managed": "OK", "system": "--", "pip": "--", "missing": "MISSING"}.get(state, "?")
            click.echo(f"  {icon} {name:<20} {state}")
        if verify:
            click.echo("[trident] verifying tools ...")
            verify_tools(tools_dir, echo=click.echo)
        return

    # --verify alone: skip install, just run version checks
    if verify and not tool and not warmup:
        click.echo("[trident] verifying tools ...")
        bad = [n for n, ok in verify_tools(tools_dir, echo=click.echo).items() if not ok]
        if bad:
            click.echo(f"[trident] verification failed for: {', '.join(bad)}", err=True)
            raise SystemExit(1)
        return

    if tool:
        if tool not in ALL_TOOLS:
            click.echo(f"[trident] unknown tool: {tool}", err=True)
            raise SystemExit(1)
        if tool in _TOOLS:
            import httpx
            with httpx.Client() as client:
                results = {tool: _install_one(tool, tools_dir, client, echo=click.echo)}
        else:
            # Pip or Go tool — handled in install_all logic
            from trident.tools.installer import install_go_tools, install_pip_tools, _GO_TOOLS, _PIP_TOOLS
            if tool in _GO_TOOLS:
                import httpx
                with httpx.Client() as client:
                    results = install_go_tools(tools_dir=tools_dir, client=client, echo=click.echo)
                results = {tool: results.get(tool, False)}
            elif tool in _PIP_TOOLS:
                results = install_pip_tools(echo=click.echo)
                results = {tool: results.get(tool, False)}
            else:
                results = {tool: check_node_tools(echo=click.echo).get(tool) == "system"}
    else:
        results = install_all(tools_dir, echo=click.echo)

    failed = [n for n, ok in results.items() if not ok]
    if failed:
        click.echo(f"\n[trident] {len(failed)} tool(s) failed or skipped: {', '.join(failed)}", err=True)

    succeeded = [n for n, ok in results.items() if ok]
    if succeeded:
        click.echo(f"\n[trident] {len(succeeded)} tool(s) ready: {', '.join(succeeded)}")

    if verify:
        click.echo("[trident] verifying tools ...")
        bad = [n for n, ok in verify_tools(tools_dir, echo=click.echo).items() if not ok]
        if bad:
            click.echo(f"[trident] verification failed for: {', '.join(bad)}", err=True)
            raise SystemExit(1)

    if warmup:
        warmup_dbs(tools_dir, echo=click.echo)

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
