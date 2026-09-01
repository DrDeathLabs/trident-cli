"""Auth/Access expert — authentication, authorization, IDOR, JWT, sessions, privilege escalation."""

from __future__ import annotations

from trident.prompts import SYSTEM_BASE
from trident.experts.base import ExpertBase, register_expert


@register_expert
class AuthExpert(ExpertBase):
    name = "auth"
    persona = "Auth & Access Control Expert"
    domain = "Authentication, authorization, IDOR (CWE-639), broken access control, JWT, sessions, privilege escalation"
    domains = {"CWE-287", "CWE-862", "CWE-863", "CWE-639", "CWE-285", "CWE-306", "CWE-269", "CWE-347", "CWE-284", "CWE-250"}
    keywords = ("auth", "idor", "jwt", "session", "privilege", "login", "authorization", "authentication", "access")
    system_prompt = SYSTEM_BASE + "\n" + (
        "You specialize in authentication & access control: broken authn (CWE-287), "
        "missing authz (CWE-862), incorrect authz (CWE-863), IDOR (CWE-639), "
        "JWT weaknesses incl. alg confusion (CWE-347), session management, privilege escalation (CWE-269)."
    )
