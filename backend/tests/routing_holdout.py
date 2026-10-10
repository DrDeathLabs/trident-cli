"""Independent, labeled holdout cases for legacy routing preservation."""

HOLDOUT = (
    {
        "id": "holdout_sparse_eval",
        "required": {"injection"},
        "tool": "sarif-import", "rule_id": "eval-flow", "title": "Dynamic evaluation",
        "description": "An untrusted expression reaches eval.", "cwe": None,
    },
    {
        "id": "holdout_session_rotation",
        "required": {"auth"},
        "tool": "semgrep", "rule_id": "session-rotation", "title": "Session weakness",
        "description": "A session identifier survives privilege changes.", "cwe": "CWE-384",
    },
    {
        "id": "holdout_rsa_strength",
        "required": {"crypto"},
        "tool": "semgrep", "rule_id": "rsa-strength", "title": "RSA key strength is insufficient",
        "description": "The configured modulus is below policy.", "cwe": "CWE-326",
    },
    {
        "id": "holdout_sbom_component",
        "required": {"dependency"},
        "tool": "grype", "rule_id": "CVE-2025-76543", "title": "Affected SBOM component",
        "description": "The bill of materials contains an affected package.", "cwe": "CWE-937",
    },
    {
        "id": "holdout_cors_origin",
        "required": {"secrets_config"},
        "tool": "semgrep", "rule_id": "cors-origin", "title": "CORS accepts untrusted origins",
        "description": "Credentialed requests accept wildcard origins.", "cwe": "CWE-942",
    },
    {
        "id": "holdout_jwt_confusion",
        "required": {"auth", "crypto"},
        "tool": "semgrep", "rule_id": "jwt-policy", "title": "JWT signature policy is weak",
        "description": "The token verifier permits an unsafe algorithm.", "cwe": "CWE-347",
    },
    {
        "id": "holdout_access_query",
        "required": {"injection", "auth"},
        "tool": "semgrep", "rule_id": "account-query", "title": "Authentication query uses untrusted SQL",
        "description": "Account lookup interpolates a caller-controlled identifier.", "cwe": "CWE-89",
    },
    {
        "id": "holdout_weak_random_token",
        "required": {"crypto"},
        "tool": "bandit", "rule_id": "random-token", "title": "Predictable random token",
        "description": "A security token is derived from a weak PRNG.", "cwe": "CWE-330",
    },
    {
        "id": "holdout_secret_privilege",
        "required": {"secrets_config", "auth"},
        "tool": "gitleaks", "rule_id": "privileged-secret", "title": "Exposed privileged credential",
        "description": "A leaked service credential enables privilege escalation.", "cwe": "CWE-269",
    },
    {
        "id": "holdout_package_name_crypto",
        "required": {"dependency"},
        "tool": "trivy", "rule_id": "package-advisory", "title": "crypto-helper has an affected version",
        "description": "A package advisory affects the installed release.", "cwe": "CWE-937",
    },
)
