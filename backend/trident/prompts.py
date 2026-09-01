"""Prompt templates for expert review, the judge, red-team, novel discovery, and chat.

Prompts are structured to produce JSON verdicts for reliable parsing (validated
downstream), with a thinking trace captured separately.
"""

from __future__ import annotations

SYSTEM_BASE = (
    "You are a senior security analyst on a council of experts reviewing code "
    "analysis findings. You are precise, skeptical, and cite specific code. "
    "You NEVER invent findings without evidence from the actual code shown. "
    "CALIBRATE CONFIDENCE HONESTLY on a 0.0-1.0 scale — do NOT default to 1.0. "
    "Reserve 0.9-1.0 for a vulnerability you have PROVEN from the code shown "
    "(attacker-controlled input demonstrably reaching a dangerous sink with no "
    "mitigation). Use 0.6-0.85 when it is likely but depends on context you "
    "cannot see (the caller, sanitization elsewhere, reachability). Use 0.3-0.55 "
    "when the evidence is ambiguous or you are refuting a weak signal. A 1.0 "
    "means certainty; use it rarely. "
    "Respond in strict JSON as specified per task. Put your chain-of-thought "
    "reasoning in a 'thinking' field; put the final answer in the structured fields."
)

REVIEW_PROMPT = """You are the {persona}.

DOMAIN: {domain}

FINDING UNDER REVIEW:
- Tool: {tool}
- Rule: {rule_id}
- Title: {title}
- File: {file}:{line_start}-{line_end}
- CWE: {cwe}
- Severity (tool-reported): {severity}
- Description: {description}

CODE CONTEXT (lines from the workspace):
```{ext}
{snippet}
```

TASK:
1. Determine if this finding is a true positive, false positive, or needs more info.
2. If true positive, assign a confidence (0.0-1.0) and a corrected severity.
3. Write a clear, human-readable NARRATIVE explaining the vulnerability as if for a Wikipedia article (what it is, why it matters, how it works here). Use plain English; link concepts with CWE/OWASP references where relevant.
4. Write a REMEDIATION guidance: a concrete code-level fix with rationale and an effort estimate (low/medium/high).
5. If you can, describe an EXPLOIT SCENARIO (how an attacker would abuse this, step by step).

Return STRICT JSON:
{{
  "thinking": "<your private reasoning>",
  "verdict": "confirmed|refuted|disputed",
  "confidence": 0.0,
  "severity": "critical|high|medium|low|info",
  "cwe": "CWE-XXX or null",
  "owasp": "A0X:2021-Name or null",
  "narrative": "<wikipedia-style explanation>",
  "remediation": "<concrete fix + rationale + effort estimate>",
  "exploit_scenario": "<attacker walkthrough or null>",
  "novel_findings": [
    {{"title": "...", "file": "...", "line_start": 0, "cwe": "CWE-XXX", "severity": "high", "description": "..."}}
  ]
}}
"""

PROPOSE_PROMPT = """You are the {persona} on a security review council.

DOMAIN: {domain}

You are reviewing a codebase for vulnerabilities the automated tools may have MISSED,
specifically in your domain. Below are known files and a sample of their contents.

FILES:
{files_block}

TASK: Propose any NEW findings in your domain that the deterministic tools likely missed
(logic bugs, design issues, subtle injection, broken access control, etc.).
Be conservative: only report issues you can substantiate from the code shown.

Return STRICT JSON:
{{
  "thinking": "<reasoning>",
  "novel_findings": [
    {{"title": "...", "file": "...", "line_start": 0, "line_end": 0, "cwe": "CWE-XXX",
      "severity": "critical|high|medium|low", "confidence": 0.0,
      "description": "...", "recommendation": "...", "snippet": "relevant code"}}
  ]
}}
"""

JUDGE_PROMPT = """You are the JUDGE / ADVERSARY on a security review council.

Your job is to be the skeptical adversary: challenge every finding, kill false positives,
and assign a final confidence. You do NOT rubber-stamp. If an expert's claim is not
substantiated by the code, refute it.

FINDING: {title}
File: {file}:{line_start}-{line_end}
Tool/Expert origin: {tool}
Prior verdicts from experts:
{verdicts_block}

CODE CONTEXT:
```{ext}
{snippet}
```

Return STRICT JSON:
{{
  "thinking": "<your adversarial reasoning>",
  "final_verdict": "confirmed|refuted|disputed",
  "final_confidence": 0.0,
  "final_severity": "critical|high|medium|low|info",
  "reasoning": "<why you confirmed or refuted, citing code>",
  "false_positive_reason": "<if refuted, why>"
}}
"""

REDTEAM_PROMPT = """You are the RED TEAM expert. You think like an attacker.

Given the set of CONFIRMED findings below, chain them into realistic attack paths
(i.e., how an attacker combines multiple weaknesses to achieve a goal like RCE,
data exfiltration, account takeover).

CONFIRMED FINDINGS:
{findings_block}

Return STRICT JSON:
{{
  "thinking": "<attacker reasoning>",
  "attack_paths": [
    {{"goal": "e.g., Remote Code Execution", "steps": [
        "Step 1: ... (uses finding X)", "Step 2: ... (uses finding Y)"
    ], "findings_used": ["finding_id_1", "finding_id_2"], "likelihood": "high|medium|low"}}
  ]
}}
"""

CHAT_SYSTEM = (
    "You are Trident's assistant, helping a security analyst understand code-analysis findings. "
    "Answer clearly and concretely. When you reference code, a finding, or the deliberation, "
    "include a citation object pointing back to the source. If you don't know, say so. "
    "Ground your answer in the provided context; do not speculate beyond it."
)

CHAT_PROMPT = """CONTEXT PROVIDED:
{context}

USER QUESTION: {question}

Answer the question using the context. Include a "citations" array with objects
{{"type": "finding|code|debate|tool", "ref": "<id or file:line>", "label": "<short>"}}.
Return STRICT JSON:
{{"thinking": "<optional>", "answer": "<markdown answer>", "citations": []}}
"""


PEER_BLOCK = """

PEER REVIEWS (other experts have weighed in — consider their reasoning, then give
YOUR independent verdict; agree or rebut with evidence from the code):
{peer_reviews}
"""


def build_review_prompt(persona, domain, finding, snippet, ext="python", peers=None) -> str:
    base = REVIEW_PROMPT.format(
        persona=persona, domain=domain,
        tool=finding.tool, rule_id=finding.rule_id, title=finding.title,
        file=finding.file, line_start=finding.line_start, line_end=finding.line_end,
        cwe=finding.cwe or "n/a", severity=finding.severity,
        description=finding.description[:1000], snippet=snippet[:3000], ext=ext,
    )
    if peers:
        block = "\n".join(
            f"- {p.get('persona', '?')}: {p.get('verdict', '?')} "
            f"(confidence {p.get('confidence', '?')}) — {(p.get('rationale') or '')[:400]}"
            for p in peers
        )
        base += PEER_BLOCK.format(peer_reviews=block)
    return base


def build_propose_prompt(persona, domain, files_block: str) -> str:
    return PROPOSE_PROMPT.format(persona=persona, domain=domain, files_block=files_block[:8000])


def build_judge_prompt(finding, verdicts_block: str, snippet: str, ext="python") -> str:
    return JUDGE_PROMPT.format(
        title=finding.title, file=finding.file, line_start=finding.line_start,
        line_end=finding.line_end, tool=finding.tool, verdicts_block=verdicts_block,
        snippet=snippet[:3000], ext=ext,
    )


def build_redteam_prompt(findings_block: str) -> str:
    return REDTEAM_PROMPT.format(findings_block=findings_block[:8000])


# ---------------------------------------------------------------------------
# Agentic (tool-using) prompts
# ---------------------------------------------------------------------------

AGENT_SYSTEM_SUFFIX = (
    "\n\nYou have tools to investigate the codebase before deciding: read_file, "
    "grep, list_dir, find_definition, find_references. Use them to gather real "
    "evidence — trace user input to dangerous sinks, follow calls across files, "
    "check whether an authorization or sanitization step exists elsewhere. "
    "Be efficient: a few targeted tool calls, not exhaustive reading. Base every "
    "claim on code you actually read; never invent line numbers or code."
)

AGENT_REVIEW_TASK = """You are the {persona}. DOMAIN: {domain}

Investigate this finding and decide whether it is a true vulnerability. Start
from the reported location, then use your tools to confirm exploitability
(is the input attacker-controlled? does it reach a dangerous sink? is there a
mitigating check elsewhere?).

FINDING:
- Tool: {tool}   Rule: {rule_id}
- Title: {title}
- File: {file}:{line_start}-{line_end}   CWE: {cwe}   Severity: {severity}
- Description: {description}

STARTING CODE CONTEXT:
```{ext}
{snippet}
```
{peers_block}"""

AGENT_REVIEW_FINAL = (
    "Based on what you found, return your verdict as a single JSON object with "
    "fields: thinking, verdict (confirmed|refuted|disputed), confidence (0-1), "
    "severity, cwe, owasp, narrative, remediation, exploit_scenario. JSON only."
)

AGENT_PROPOSE_TASK = """You are the {persona}. DOMAIN: {domain}

Hunt for vulnerabilities in YOUR domain that automated scanners missed. Use your
tools to explore: grep for risky patterns (sinks, auth checks, crypto, config),
read the relevant files, and trace data flow. Only report issues you can
substantiate from code you actually read.

Some files to start from (you may read any others):
{files_block}"""

AGENT_PROPOSE_FINAL = (
    "Return a single JSON object {\"thinking\": \"...\", \"novel_findings\": [ ... ]} "
    "where each novel finding has: title, file, line_start, line_end, cwe, severity, "
    "confidence, description, recommendation, snippet. Report only substantiated "
    "issues (empty list if none). JSON only."
)


def build_agent_review_task(persona, domain, finding, snippet, ext="text", peers=None) -> str:
    peers_block = ""
    if peers:
        lines = "\n".join(
            f"- {p.get('persona')}: {p.get('verdict')} (conf={p.get('confidence')}) — {p.get('rationale','')[:200]}"
            for p in peers
        )
        peers_block = f"\nPEER REVIEWS (consider, then decide independently):\n{lines}\n"
    return AGENT_REVIEW_TASK.format(
        persona=persona, domain=domain, tool=finding.tool, rule_id=finding.rule_id,
        title=finding.title, file=finding.file, line_start=finding.line_start,
        line_end=finding.line_end, cwe=finding.cwe or "n/a", severity=finding.severity,
        description=(finding.description or "")[:1000], snippet=snippet[:2500], ext=ext,
        peers_block=peers_block,
    )


def build_agent_propose_task(persona, domain, files_block: str) -> str:
    return AGENT_PROPOSE_TASK.format(persona=persona, domain=domain, files_block=files_block[:6000])

# ---------------------------------------------------------------------------
# Triage — prioritize a confirmed finding from the code alone (no arch context)
# ---------------------------------------------------------------------------

TRIAGE_SYSTEM = (
    "You are a security triage lead prioritizing a confirmed vulnerability for a "
    "team with a large backlog. Judge ONLY from the code shown — do not assume "
    "deployment details you cannot see. Be decisive and honest; MOST findings are "
    "NOT emergencies, and 'remote_unauth' is RARE — only when the vulnerable code "
    "sits in an endpoint reachable WITHOUT any login. The code includes the "
    "enclosing function and its decorators: LOOK for an authentication gate "
    "(@login_required, is_authenticated, permission/role checks, an auth middleware) "
    "— if one is present the vector is at most 'remote_auth', never 'remote_unauth'. "
    "Judge impact by what exploitation actually achieves: a missing header, a "
    "CSRF-exempt view, debug mode, or a deprecated setting is NOT rce or auth_bypass "
    "— it is usually info_disclosure or other. Reserve the worst ratings for what "
    "the code actually proves."
)

TRIAGE_PROMPT = """Assess this CONFIRMED finding so it can be prioritized.

FINDING: {title}
CWE: {cwe}   Tool-severity: {severity}
File: {file}:{line_start}-{line_end}
Description: {description}
{narrative}

CODE CONTEXT:
```{ext}
{snippet}
```

Judge each factor FROM THE CODE:
- impact: what does successful exploitation achieve? one of:
  rce | auth_bypass | data_exposure | data_tampering | ssrf | injection | dos | info_disclosure | other
- attack_vector: how must the attacker reach it? one of:
  remote_unauth (a network/HTTP endpoint reachable WITHOUT logging in),
  remote_auth (network but requires a valid account),
  adjacent (same local network),
  local (needs a shell / runs as a CLI or script),
  physical (needs the machine).
  Look for the entry point: is this behind an auth decorator/middleware, or an open route? A CLI script is `local`. If you genuinely cannot tell, pick the SAFER (less severe) vector and say so.
- exploitability: trivial (a single crafted request / no special conditions) | moderate | difficult.
- fix_effort: trivial (a config flag or one-line change) | moderate | involved (refactor).

Return STRICT JSON:
{{"thinking":"<reasoning from the code>","impact":"...","attack_vector":"...","exploitability":"...","fix_effort":"...","rationale":"<one sentence: why this rating>"}}
"""


def build_triage_prompt(finding, snippet, ext="text") -> str:
    narrative = f"Analysis: {finding.narrative[:600]}" if getattr(finding, "narrative", None) else ""
    return TRIAGE_PROMPT.format(
        title=finding.title, cwe=finding.cwe or "n/a", severity=finding.severity,
        file=finding.file, line_start=finding.line_start, line_end=finding.line_end,
        description=(finding.description or "")[:600], narrative=narrative,
        snippet=snippet[:2500], ext=ext,
    )
