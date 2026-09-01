"""Rich live progress display for trident scan.

Consumes events from the in-process event bus and renders a live terminal
display showing each tool's status, the AI council iteration progress, and
the guard-model (triage) phase.

Event sequence:
  scan.tools.start  →  tool.started / tool.complete / tool.error
  job.iteration.start  →  scan.experts.start  →  finding.confirmed/refuted
  job.complete          (end of council — guards not yet run)
  triage.start          (guard model begins, only when run_guards=True)
  triage.complete       (guard model done — consumer stops here)

When run_guards=False the consumer stops on job.complete instead.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

_SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# Bar characters for NVD page progress
_BAR_FULL = "█"
_BAR_EMPTY = "░"
_BAR_WIDTH = 20


def _bar(fraction: float) -> str:
    filled = int(fraction * _BAR_WIDTH)
    return _BAR_FULL * filled + _BAR_EMPTY * (_BAR_WIDTH - filled)


class ScanProgress:
    """Async event consumer that drives a Rich live display during a scan."""

    def __init__(
        self,
        job_id: str,
        target_name: str = "",
        max_iterations: int = 3,
        run_guards: bool = True,
    ):
        self.job_id = job_id
        self.target_name = target_name
        self.max_iterations = max_iterations
        self.run_guards = run_guards

        # --- tools phase ---
        self._tools: list[str] = []
        self._tool_status: dict[str, str] = {}   # waiting / running / done / error
        self._tool_findings: dict[str, int] = {}
        self._tool_start_ts: dict[str, float] = {}
        self._tool_duration: dict[str, float] = {}

        # --- council phase ---
        self._in_council = False
        self._iteration = 0
        self._total_to_review = 0
        self._confirmed = 0
        self._refuted = 0
        self._council_done = False

        # --- guards phase ---
        self._guards_active = False
        self._guards_findings = 0
        self._guards_done = False
        self._guards_tier_counts: dict[str, int] = {}
        self._guards_start_ts: float = 0.0

        # --- terminal state ---
        self._done = False
        self._frame = 0

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def handle(self, ev: dict[str, Any]) -> None:
        etype = ev.get("type", "")

        if etype == "scan.tools.start":
            for t in ev.get("tools", []):
                if t not in self._tools:
                    self._tools.append(t)
                    self._tool_status[t] = "waiting"

        elif etype == "tool.started":
            t = ev.get("tool", "")
            if not t:
                return
            self._tool_status[t] = "running"
            self._tool_start_ts[t] = time.monotonic()
            if t not in self._tools:
                self._tools.append(t)

        elif etype == "tool.complete":
            t = ev.get("tool", "")
            if not t:
                return
            self._tool_status[t] = "done"
            self._tool_findings[t] = ev.get("findings", 0)
            self._tool_duration[t] = ev.get("duration_s", 0.0)
            if t not in self._tools:
                self._tools.append(t)

        elif etype == "tool.error":
            t = ev.get("tool", "")
            if not t:
                return
            self._tool_status[t] = "error"
            if t not in self._tools:
                self._tools.append(t)

        elif etype == "tool.finding":
            t = ev.get("tool", "")
            if t:
                self._tool_findings[t] = self._tool_findings.get(t, 0) + 1

        elif etype == "job.iteration.start":
            self._in_council = True
            self._iteration = ev.get("iteration", self._iteration + 1)

        elif etype == "scan.experts.start":
            self._in_council = True
            if self._iteration == 0:
                self._iteration = ev.get("iteration", 1)
            self._total_to_review = ev.get("findings_to_review", 0)

        elif etype == "finding.confirmed":
            self._confirmed += 1

        elif etype == "finding.refuted":
            self._refuted += 1

        elif etype == "job.complete":
            self._council_done = True
            if not self.run_guards:
                self._done = True

        elif etype == "triage.start":
            self._guards_active = True
            self._guards_findings = ev.get("findings", 0)
            self._guards_start_ts = time.monotonic()

        elif etype == "triage.complete":
            self._guards_done = True
            self._guards_tier_counts = ev.get("counts", {})
            self._done = True

        elif etype == "job.failed":
            self._done = True

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render(self) -> Any:
        from rich.console import Group
        from rich.text import Text

        self._frame = (self._frame + 1) % len(_SPINNER)
        spin = _SPINNER[self._frame]
        lines: list[Any] = []

        # --- tools ---
        for tool in self._tools:
            status = self._tool_status.get(tool, "waiting")
            findings = self._tool_findings.get(tool, 0)
            dur = self._tool_duration.get(tool)

            if status == "done":
                count = f"{findings} finding{'s' if findings != 1 else ''}"
                dur_s = f"  {dur:.1f}s" if dur is not None else ""
                lines.append(Text.assemble(
                    ("  ✓  ", "green"),
                    (f"{tool:<16}", ""),
                    (count, "dim"),
                    (dur_s, "dim"),
                ))
            elif status == "running":
                start = self._tool_start_ts.get(tool, time.monotonic())
                elapsed = time.monotonic() - start
                lines.append(Text.assemble(
                    (f"  {spin}  ", "cyan"),
                    (f"{tool:<16}", ""),
                    (f"running...  {elapsed:.0f}s", "dim"),
                ))
            elif status == "error":
                lines.append(Text.assemble(
                    ("  ✗  ", "red"),
                    (f"{tool:<16}", ""),
                    ("error", "red"),
                ))
            else:
                lines.append(Text.assemble(
                    ("  ·  ", "dim"),
                    (f"{tool:<16}", "dim"),
                    ("waiting", "dim"),
                ))

        # --- council ---
        if self._in_council:
            lines.append(Text("  " + "─" * 44, style="dim"))
            total = self._total_to_review if self._total_to_review else "?"
            iter_str = f"iteration {self._iteration}/{self.max_iterations}"

            if self._council_done:
                lines.append(Text.assemble(
                    ("  ✓  ", "green"),
                    ("Council complete  ", ""),
                    (f"confirmed: {self._confirmed}  refuted: {self._refuted}", "dim"),
                ))
            else:
                lines.append(Text.assemble(
                    (f"  {spin}  ", "cyan"),
                    (f"Council  ·  {iter_str}  ", ""),
                    (f"confirmed: {self._confirmed}  refuted: {self._refuted} / {total}", "dim"),
                ))

        # --- guards ---
        if self._guards_active or (self._council_done and self.run_guards and not self._in_council):
            if self._in_council:
                lines.append(Text("  " + "─" * 44, style="dim"))
            else:
                if not self._in_council and self._tools:
                    lines.append(Text("  " + "─" * 44, style="dim"))

            if self._guards_done:
                tier_summary = "  ".join(
                    f"{t}: {self._guards_tier_counts.get(t, 0)}"
                    for t in ("P0", "P1", "P2", "P3")
                    if self._guards_tier_counts.get(t, 0) > 0
                ) or "no findings"
                lines.append(Text.assemble(
                    ("  ✓  ", "green"),
                    ("Guards complete  ", ""),
                    (tier_summary, "dim"),
                ))
            elif self._guards_active:
                elapsed = time.monotonic() - self._guards_start_ts
                lines.append(Text.assemble(
                    (f"  {spin}  ", "cyan"),
                    ("Guards  ·  class  corpus  reachability  ", ""),
                    (f"{self._guards_findings} findings  {elapsed:.0f}s", "dim"),
                ))
            else:
                lines.append(Text.assemble(
                    ("  ·  ", "dim"),
                    ("Guards", "dim"),
                    ("  waiting for council...", "dim"),
                ))

        return Group(*lines)

    # ------------------------------------------------------------------
    # Main async loop
    # ------------------------------------------------------------------

    async def run(self, q: asyncio.Queue) -> None:
        from rich.live import Live
        from rich.console import Console

        console = Console(stderr=True)
        with Live(self.render(), console=console, refresh_per_second=10) as live:
            while not self._done:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=0.1)
                    self.handle(ev)
                    live.update(self.render())
                except asyncio.TimeoutError:
                    live.update(self.render())
                except asyncio.CancelledError:
                    break
            live.update(self.render())


# ---------------------------------------------------------------------------
# ModelProgress — live display for `trident model refresh`
# ---------------------------------------------------------------------------

class ModelProgress:
    """Thread-safe live display for the model-refresh pipeline.

    Feed downloads, corpus build, and model training are shown in three
    sections. NVD shows per-page progress with a bar; all other feeds show
    a spinner while downloading and a row count when done.

    Usage::

        mp = ModelProgress(feeds=["nvd", "epss", ...])
        results = mp.run(model_manager, sources=sources, force=force)
    """

    def __init__(self, feeds: list[str]):
        import threading
        self._feeds = feeds
        self._feed_status: dict[str, str] = {f: "waiting" for f in feeds}
        self._feed_rows: dict[str, int] = {}
        self._feed_start: dict[str, float] = {}
        self._feed_duration: dict[str, float] = {}

        self._nvd_fetched = 0
        self._nvd_total = 0

        self._corpus_status = "waiting"   # waiting / running / done
        self._corpus_profiles = 0
        self._corpus_start: float = 0.0
        self._corpus_duration: float = 0.0

        self._model_status = "waiting"    # waiting / running / done
        self._model_accuracy: Any = None
        self._model_samples: Any = None
        self._model_start: float = 0.0
        self._model_duration: float = 0.0

        self._done = False
        self._error: str | None = None
        self._frame = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Callbacks (called from background thread — must be thread-safe)
    # ------------------------------------------------------------------

    def on_progress(self, feed: str, status: str, rows_or_stats: Any) -> None:
        with self._lock:
            if feed == "__corpus__":
                if status == "start":
                    self._corpus_status = "running"
                    self._corpus_start = time.monotonic()
                elif status == "done":
                    self._corpus_status = "done"
                    self._corpus_profiles = int(rows_or_stats)
                    self._corpus_duration = time.monotonic() - self._corpus_start
            elif feed == "__model__":
                if status == "start":
                    self._model_status = "running"
                    self._model_start = time.monotonic()
                elif status == "done":
                    self._model_status = "done"
                    self._model_duration = time.monotonic() - self._model_start
                    if isinstance(rows_or_stats, dict):
                        self._model_accuracy = rows_or_stats.get("accuracy", "?")
                        self._model_samples = rows_or_stats.get("n_samples", "?")
            else:
                if status == "start":
                    self._feed_status[feed] = "running"
                    self._feed_start[feed] = time.monotonic()
                elif status == "done":
                    self._feed_status[feed] = "done"
                    self._feed_rows[feed] = int(rows_or_stats)
                    self._feed_duration[feed] = time.monotonic() - self._feed_start.get(feed, time.monotonic())
                elif status == "error":
                    self._feed_status[feed] = "error"
                    self._feed_duration[feed] = time.monotonic() - self._feed_start.get(feed, time.monotonic())

    def on_page(self, feed: str, fetched: int, total: int) -> None:
        if feed == "nvd":
            with self._lock:
                self._nvd_fetched = fetched
                self._nvd_total = total

    # ------------------------------------------------------------------
    # Rendering (called from main thread)
    # ------------------------------------------------------------------

    def render(self) -> Any:
        from rich.console import Group
        from rich.text import Text

        self._frame = (self._frame + 1) % len(_SPINNER)
        spin = _SPINNER[self._frame]
        lines: list[Any] = []

        # --- feeds ---
        with self._lock:
            feeds = list(self._feeds)
            feed_status = dict(self._feed_status)
            feed_rows = dict(self._feed_rows)
            feed_dur = dict(self._feed_duration)
            nvd_fetched, nvd_total = self._nvd_fetched, self._nvd_total
            corpus_status = self._corpus_status
            corpus_profiles = self._corpus_profiles
            corpus_dur = self._corpus_duration
            model_status = self._model_status
            model_acc = self._model_accuracy
            model_samples = self._model_samples
            model_dur = self._model_duration

        for feed in feeds:
            status = feed_status.get(feed, "waiting")
            rows = feed_rows.get(feed, 0)
            dur = feed_dur.get(feed)

            if status == "done":
                dur_s = f"  {dur:.1f}s" if dur is not None else ""
                lines.append(Text.assemble(
                    ("  ✓  ", "green"),
                    (f"{feed:<16}", ""),
                    (f"{rows:,} rows", "dim"),
                    (dur_s, "dim"),
                ))
            elif status == "running":
                if feed == "nvd" and nvd_total > 0:
                    pct = nvd_fetched / nvd_total
                    bar = _bar(pct)
                    lines.append(Text.assemble(
                        (f"  {spin}  ", "cyan"),
                        (f"{feed:<16}", ""),
                        (f"{bar}  ", "cyan"),
                        (f"{nvd_fetched:,} / {nvd_total:,}", "dim"),
                    ))
                else:
                    lines.append(Text.assemble(
                        (f"  {spin}  ", "cyan"),
                        (f"{feed:<16}", ""),
                        ("downloading...", "dim"),
                    ))
            elif status == "error":
                lines.append(Text.assemble(
                    ("  ✗  ", "red"),
                    (f"{feed:<16}", ""),
                    ("failed", "red"),
                ))
            else:
                lines.append(Text.assemble(
                    ("  ·  ", "dim"),
                    (f"{feed:<16}", "dim"),
                    ("waiting", "dim"),
                ))

        # --- corpus build ---
        lines.append(Text("  " + "─" * 44, style="dim"))
        if corpus_status == "done":
            dur_s = f"  {corpus_dur:.1f}s" if corpus_dur else ""
            lines.append(Text.assemble(
                ("  ✓  ", "green"),
                ("Corpus built  ", ""),
                (f"{corpus_profiles:,} CWE profiles", "dim"),
                (dur_s, "dim"),
            ))
        elif corpus_status == "running":
            lines.append(Text.assemble(
                (f"  {spin}  ", "cyan"),
                ("Building corpus  ", ""),
                ("joining CVEs across feeds...", "dim"),
            ))
        else:
            lines.append(Text.assemble(
                ("  ·  ", "dim"),
                ("Corpus build", "dim"),
                ("  waiting for feeds...", "dim"),
            ))

        # --- model training ---
        if model_status == "done":
            dur_s = f"  {model_dur:.1f}s" if model_dur else ""
            acc_s = f"accuracy {model_acc}" if model_acc is not None else ""
            n_s = f"  n_samples: {model_samples:,}" if isinstance(model_samples, int) else ""
            lines.append(Text.assemble(
                ("  ✓  ", "green"),
                ("Model trained  ", ""),
                (acc_s, "dim"),
                (n_s, "dim"),
                (dur_s, "dim"),
            ))
        elif model_status == "running":
            lines.append(Text.assemble(
                (f"  {spin}  ", "cyan"),
                ("Training model  ", ""),
                ("GradientBoostingClassifier...", "dim"),
            ))
        else:
            lines.append(Text.assemble(
                ("  ·  ", "dim"),
                ("Model training", "dim"),
                ("  waiting for corpus...", "dim"),
            ))

        return Group(*lines)

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self, model_manager: Any, sources: list[str] | None, force: bool) -> dict[str, Any]:
        """Run refresh in a background thread, display live progress in main thread."""
        import threading
        from rich.live import Live
        from rich.console import Console

        console = Console(stderr=True)
        result: dict[str, Any] = {}
        exc_holder: list[BaseException] = []

        def _worker() -> None:
            try:
                result.update(model_manager.refresh(
                    sources=sources,
                    force=force,
                    progress_cb=self.on_progress,
                    page_cb=self.on_page,
                ))
            except BaseException as e:
                exc_holder.append(e)
            finally:
                with self._lock:
                    self._done = True

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()

        with Live(self.render(), console=console, refresh_per_second=10) as live:
            while True:
                with self._lock:
                    done = self._done
                if done:
                    break
                time.sleep(0.1)
                live.update(self.render())
            live.update(self.render())

        thread.join()

        if exc_holder:
            raise exc_holder[0]

        return result
