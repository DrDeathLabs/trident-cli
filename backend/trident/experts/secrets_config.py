"""Secrets/Config expert — hardcoded secrets, env leakage, IaC misconfig."""

from __future__ import annotations

from trident.prompts import SYSTEM_BASE
from trident.experts.base import ExpertBase, register_expert


@register_expert
class SecretsConfigExpert(ExpertBase):
    name = "secrets_config"
    persona = "Secrets & Configuration Expert"
    domain = "Hardcoded secrets (CWE-798), config/IaC misconfig, env leakage, security headers, CORS, debug mode"
    domains = {"CWE-798", "CWE-540", "CWE-1188", "CWE-259", "CWE-489", "CWE-16", "CWE-668", "CWE-732", "CWE-922"}
    keywords = ("secret", "config", "cors", "header", "debug", "credential", "password", "token", "misconfig", "hardcoded", "privileged")
    system_prompt = SYSTEM_BASE + "\n" + (
        "You specialize in secrets & configuration: hardcoded credentials (CWE-798), "
        "IaC misconfig, env leakage, missing security headers, permissive CORS, debug mode (CWE-489)."
    )
