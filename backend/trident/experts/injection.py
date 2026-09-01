"""Injection expert — SQLi, XSS, command injection, SSRF, path traversal, deserialization."""

from __future__ import annotations

from trident.prompts import SYSTEM_BASE
from trident.experts.base import ExpertBase, register_expert


@register_expert
class InjectionExpert(ExpertBase):
    name = "injection"
    persona = "Injection Expert"
    domain = "Injection flaws: SQLi, XSS, command injection, SSRF, path traversal, template/deserialization"
    domains = {"CWE-89", "CWE-78", "CWE-79", "CWE-918", "CWE-22", "CWE-502", "CWE-94", "CWE-1333", "CWE-90", "CWE-611"}
    keywords = ("injection", "sqli", "xss", "ssrf", "traversal", "deserialization", "eval", "exec", "pickle", "template")
    system_prompt = SYSTEM_BASE + "\n" + (
        "You specialize in injection vulnerabilities: SQL injection (CWE-89), "
        "OS command injection (CWE-78), XSS (CWE-79), SSRF (CWE-918), path traversal (CWE-22), "
        "insecure deserialization (CWE-502), code injection (CWE-94)."
    )
