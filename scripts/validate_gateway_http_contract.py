"""Exercise the installed Trident wheel against a real local /v1 HTTP server."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend" / "tests"))

from openai_compatible_harness import OpenAICompatibleServer  # noqa: E402


_CLIENT_SCRIPT = """
from trident.llm.base import ChatMessage
from trident.llm.openai_backend import OpenAIBackend
import json
import os

backend = OpenAIBackend(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url=os.environ["TRIDENT_TEST_BASE_URL"],
    model="security-expert",
    timeout=5,
    max_retries=0,
)
try:
    health = backend.health()
    completion = backend.chat([ChatMessage("user", "Synthetic acceptance request")],
                              model="enterprise-sec-model")
    embeddings = backend.embed(["synthetic embedding input"], model="embedding-alias")
finally:
    backend.client.close()
print(json.dumps({
    "health_status": health["status"],
    "model_alias_available": health["expert_model_available"],
    "completion_received": bool(completion.content),
    "embedding_count": len(embeddings),
}))
"""


def main() -> dict:
    if len(sys.argv) != 3:
        raise SystemExit("usage: validate_gateway_http_contract.py <venv-python> <evidence-dir>")
    python = str(Path(sys.argv[1]).resolve())
    destination = Path(sys.argv[2]).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with OpenAICompatibleServer(api_key="synthetic-wheel-key") as server:
        env = os.environ.copy()
        env["OPENAI_API_KEY"] = "synthetic-wheel-key"
        env["TRIDENT_TEST_BASE_URL"] = f"{server.base_url}/v1/"
        with tempfile.TemporaryDirectory(prefix="gateway-contract-") as cwd:
            completed = subprocess.run(
                [python, "-c", _CLIENT_SCRIPT], cwd=cwd, env=env,
                capture_output=True, text=True, timeout=45,
            )
        calls = server.calls
    client = json.loads(completed.stdout.strip()) if completed.returncode == 0 else {}
    evidence = {
        "installed_wheel_python_exit_code": completed.returncode,
        "client_result": client,
        "call_count": len(calls),
        "paths_in_order": [call["path"] for call in calls],
        "models_in_order": [call["model"] for call in calls],
        "authenticated_calls": sum(bool(call["auth_present"]) for call in calls),
        "all_calls_authenticated": bool(calls) and all(call["auth_present"] for call in calls),
        "http_log": "gateway-http-contract-log.json",
    }
    expected_paths = ["/v1/models", "/v1/chat/completions", "/v1/embeddings"]
    expected_models = [None, "enterprise-sec-model", "embedding-alias"]
    evidence["passed"] = (
        completed.returncode == 0 and client == {
            "health_status": "ok", "model_alias_available": True,
            "completion_received": True, "embedding_count": 1,
        } and evidence["paths_in_order"] == expected_paths
        and evidence["models_in_order"] == expected_models
        and evidence["all_calls_authenticated"]
    )
    (destination / "gateway-http-contract-log.json").write_text(
        json.dumps(calls, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
    )
    (destination / "gateway-http-contract-evidence.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8",
    )
    if not evidence["passed"]:
        raise RuntimeError(json.dumps(evidence, indent=2) + "\n" + completed.stderr[-1_000:])
    return evidence


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
