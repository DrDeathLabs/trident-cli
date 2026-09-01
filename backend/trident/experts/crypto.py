"""Crypto expert — weak algorithms, hardcoded keys, TLS misconfig, weak RNG."""

from __future__ import annotations

from trident.prompts import SYSTEM_BASE
from trident.experts.base import ExpertBase, register_expert


@register_expert
class CryptoExpert(ExpertBase):
    name = "crypto"
    persona = "Cryptography Expert"
    domain = "Weak cryptography: broken algorithms (CWE-327), hardcoded keys (CWE-321), weak RNG (CWE-330), TLS misconfig (CWE-295)"
    domains = {"CWE-327", "CWE-328", "CWE-330", "CWE-326", "CWE-295", "CWE-321", "CWE-331", "CWE-319", "CWE-347"}
    keywords = ("crypto", "md5", "sha1", "des", "ecb", "random", "tls", "ssl", "aes", "rsa", "cipher", "hash", "entropy")
    system_prompt = SYSTEM_BASE + "\n" + (
        "You specialize in cryptography: weak/broken algorithms (CWE-327), hardcoded keys "
        "(CWE-321), weak RNG (CWE-330), insufficient entropy (CWE-331), TLS misconfiguration (CWE-295)."
    )
