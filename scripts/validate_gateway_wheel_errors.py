"""Exercise gateway success and failure cases through an installed Trident wheel."""

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

_CLIENT = r"""
import json, os, sys
from pathlib import Path
import trident
from trident.llm.base import ChatMessage, LLMError, LLMUnavailable
from trident.llm.openai_backend import OpenAIBackend

case = os.environ["TRIDENT_GATEWAY_CASE"]
key = os.environ["OPENAI_API_KEY"]
backend = OpenAIBackend(
    api_key=key,
    base_url=os.environ["TRIDENT_TEST_BASE_URL"],
    model="wheel-error-alias",
    timeout=float(os.environ.get("TRIDENT_TEST_TIMEOUT", "2")),
    max_retries=0,
)
result = {"case": case, "installed_version": trident.__version__,
          "loaded_from_venv": Path(trident.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())}
try:
    if case == "empty-model-list":
        health = backend.health()
        result.update(status=health["status"], models=health["models"],
                      expert_model_available=health["expert_model_available"])
    elif case == "malformed-structured-response":
        import trident.llm.base as llm_base
        from trident.config import settings
        from trident.reliability.schemas import ReviewVerdict
        from trident.reliability.structured import chat_structured
        llm_base._llm = backend
        settings.llm.max_repair_retries = 0
        structured = chat_structured(
            [ChatMessage("user", "Synthetic structured-response check")],
            ReviewVerdict, model="wheel-error-alias",
        )
        result.update(ok=structured.ok, status=structured.status,
                      error_type=type(structured.error).__name__ if structured.error else None)
    else:
        try:
            backend.chat([ChatMessage("user", "Synthetic gateway error check")],
                         model="wheel-error-alias")
            result.update(ok=True)
        except Exception as exc:
            message = str(exc)
            result.update(ok=False, error_type=type(exc).__name__, message=message,
                          credential_echoed=key in message,
                          response_body_echoed="synthetic failure" in message)
finally:
    backend.client.close()
print(json.dumps(result, sort_keys=True))
"""


def _run_client(python: Path, case: str, base_url: str, key: str, folder: Path,
                *, timeout: float = 2) -> dict:
    env = os.environ.copy()
    for name in ("TRIDENT_LLM_MOCK", "TRIDENT_OPENAI_API_KEY", "TRIDENT_OPENAI_BASE_URL",
                 "OPENAI_BASE_URL", "OPENAI_API_KEY", "TRIDENT_SQLITE_PATH",
                 "TRIDENT_LLM_LEDGER_PATH"):
        env.pop(name, None)
    env.update({
        "TRIDENT_GATEWAY_CASE": case,
        "TRIDENT_TEST_BASE_URL": base_url,
        "TRIDENT_TEST_TIMEOUT": str(timeout),
        "OPENAI_API_KEY": key,
        "APPDATA": str(folder / "appdata"),
        "LOCALAPPDATA": str(folder / "appdata"),
        "TRIDENT_LLM_LEDGER_PATH": str(folder / "ledger.sqlite"),
        "PYTHONIOENCODING": "utf-8",
    })
    (folder / "appdata").mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wheel-gateway-case-") as cwd:
        completed = subprocess.run(
            [str(python), "-c", _CLIENT], cwd=cwd, env=env,
            capture_output=True, text=True, timeout=45, check=False,
        )
    if completed.returncode != 0:
        raise AssertionError(f"installed wheel gateway case {case} failed to execute")
    result = json.loads(completed.stdout.strip())
    if not result.get("loaded_from_venv"):
        raise AssertionError(f"gateway case {case} did not import the installed wheel")
    return result


def run(python_executable: str, evidence_dir: str) -> dict:
    python = Path(python_executable).resolve()
    destination = Path(evidence_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    api_key = "synthetic-wheel-error-key"
    rows = []

    for name, status in (("http-401", 401), ("http-403", 403),
                         ("http-404", 404), ("http-500", 500)):
        expected_key = "synthetic-expected-key" if name == "http-401" else api_key
        client_key = api_key if name != "http-401" else "synthetic-wrong-key"
        with OpenAICompatibleServer(api_key=expected_key) as server:
            if status != 401:
                server.set_behavior("/v1/chat/completions", status=status)
            result = _run_client(python, name, f"{server.base_url}/v1", client_key,
                                 destination / name)
            calls = list(server.calls)
        expected_type = "LLMError"
        passed = (result.get("ok") is False and result.get("error_type") == expected_type
                  and str(status) in result.get("message", "")
                  and not result.get("credential_echoed")
                  and not result.get("response_body_echoed")
                  and len(calls) == 1 and calls[0]["auth_present"])
        rows.append({"case": name, "passed": passed, "result": result,
                     "request_count": len(calls), "auth_present": bool(calls and calls[0]["auth_present"])})
        (destination / f"{name}-http-log.json").write_text(
            json.dumps(calls, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        )

    with OpenAICompatibleServer(api_key=api_key) as server:
        server.set_behavior("/v1/chat/completions", malformed_json=True)
        result = _run_client(python, "malformed-json", f"{server.base_url}/v1", api_key,
                             destination / "malformed-json")
        calls = list(server.calls)
    passed = (result.get("error_type") == "LLMError"
              and "malformed JSON" in result.get("message", "")
              and not result.get("credential_echoed")
              and not result.get("response_body_echoed") and len(calls) == 1)
    rows.append({"case": "malformed-json", "passed": passed,
                 "request_count": len(calls), "auth_present": bool(calls and calls[0]["auth_present"])})
    (destination / "malformed-json-http-log.json").write_text(
        json.dumps(calls, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
    )

    with OpenAICompatibleServer(api_key=api_key) as server:
        server.set_behavior("/v1/chat/completions", response={"choices": []})
        result = _run_client(python, "malformed-envelope", f"{server.base_url}/v1", api_key,
                             destination / "malformed-envelope")
        calls = list(server.calls)
    passed = (result.get("error_type") == "LLMError"
              and "invalid chat completion" in result.get("message", "") and len(calls) == 1)
    rows.append({"case": "malformed-envelope", "passed": passed,
                 "request_count": len(calls), "auth_present": bool(calls and calls[0]["auth_present"])})

    with OpenAICompatibleServer(api_key=api_key) as server:
        server.set_behavior("/v1/chat/completions", chat_content="not a structured response")
        result = _run_client(python, "malformed-structured-response", f"{server.base_url}/v1",
                             api_key, destination / "malformed-structured-response")
        calls = list(server.calls)
    passed = not result.get("ok") and len(calls) == 1 and calls[0]["auth_present"]
    rows.append({"case": "malformed-structured-response", "passed": passed,
                 "result": result, "request_count": len(calls),
                 "auth_present": bool(calls and calls[0]["auth_present"])})

    with OpenAICompatibleServer(api_key=api_key) as server:
        server.set_behavior("/v1/models", empty_models=True)
        result = _run_client(python, "empty-model-list", f"{server.base_url}/v1", api_key,
                             destination / "empty-model-list")
        calls = list(server.calls)
    passed = (result.get("status") == "ok" and result.get("models") == []
              and result.get("expert_model_available") is False and len(calls) == 1)
    rows.append({"case": "empty-model-list", "passed": passed,
                 "result": result, "request_count": len(calls),
                 "auth_present": bool(calls and calls[0]["auth_present"])})

    with OpenAICompatibleServer(api_key=api_key) as server:
        server.set_behavior("/v1/chat/completions", delay=0.15)
        result = _run_client(python, "timeout", f"{server.base_url}/v1", api_key,
                             destination / "timeout", timeout=0.02)
        calls = list(server.calls)
    passed = (result.get("error_type") == "LLMUnavailable"
              and "timed out" in result.get("message", "") and len(calls) == 1)
    rows.append({"case": "timeout", "passed": passed,
                 "request_count": len(calls), "auth_present": bool(calls and calls[0]["auth_present"])})

    failed_server = OpenAICompatibleServer(api_key=api_key)
    failed_url = failed_server.base_url
    failed_server.close()
    result = _run_client(python, "connection-failure", f"{failed_url}/v1", api_key,
                         destination / "connection-failure")
    rows.append({"case": "connection-failure", "passed": result.get("error_type") == "LLMUnavailable",
                 "result": result, "request_count": 0, "auth_present": False})

    with OpenAICompatibleServer(api_key=api_key) as destination_server:
        with OpenAICompatibleServer(api_key=api_key) as source_server:
            source_server.set_behavior(
                "/v1/chat/completions", status=302,
                redirect_to=f"{destination_server.base_url}/v1/chat/completions",
            )
            result = _run_client(python, "redirect", f"{source_server.base_url}/v1", api_key,
                                 destination / "redirect")
            source_calls = list(source_server.calls)
            destination_calls = list(destination_server.calls)
    passed = (result.get("error_type") == "LLMError"
              and "302" in result.get("message", "") and len(source_calls) == 1
              and source_calls[0]["auth_present"] and not destination_calls)
    rows.append({"case": "redirect", "passed": passed,
                 "source_request_count": len(source_calls),
                 "destination_request_count": len(destination_calls),
                 "source_auth_present": bool(source_calls and source_calls[0]["auth_present"])})

    payload = {"installed_wheel_python": str(python.name), "scenario_count": len(rows),
               "all_passed": all(row["passed"] for row in rows), "cases": rows}
    (destination / "gateway-errors.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
    )
    print(json.dumps({"scenario_count": len(rows), "all_passed": payload["all_passed"],
                      "cases": [{"case": row["case"], "passed": row["passed"]} for row in rows]}, indent=2))
    return payload


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: validate_gateway_wheel_errors.py WHEEL_PYTHON EVIDENCE_DIR")
    outcome = run(sys.argv[1], sys.argv[2])
    raise SystemExit(0 if outcome["all_passed"] else 1)
