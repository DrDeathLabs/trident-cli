"""Real localhost HTTP server for OpenAI-compatible integration tests."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class OpenAICompatibleServer:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model_alias: str = "security-expert",
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        ssl_context: ssl.SSLContext | None = None,
        log_path: str | Path | None = None,
        api_prefix: str = "/v1",
    ):
        self.api_key = api_key
        self.model_alias = model_alias
        self.calls: list[dict] = []
        self.behaviors: dict[str, deque] = defaultdict(deque)
        self.judge_sequences: dict[str, list[dict]] = {}
        self.judge_counts: dict[str, int] = defaultdict(int)
        self.marker_responses: list[tuple[str, str, dict]] = []
        self.marker_failures: list[tuple[str, str, int]] = []
        self.log_path = Path(log_path) if log_path else None
        normalized_prefix = "/" + api_prefix.strip("/")
        if normalized_prefix == "/":
            raise ValueError("api_prefix must contain a path component")
        self.api_prefix = normalized_prefix
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def _body(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b""
                try:
                    return json.loads(raw), raw
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return None, raw

            def _response(self, status: int, payload=None, *, raw: bytes | None = None, headers=None):
                if raw is None:
                    raw = json.dumps(payload or {}).encode("utf-8")
                    content_type = "application/json"
                else:
                    content_type = "application/json"
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                    pass

            def _record(self, body):
                auth = self.headers.get("Authorization", "")
                path = self.path.split("?", 1)[0]
                route = owner._canonical_route(path)
                with owner.lock:
                    messages = body.get("messages", []) if isinstance(body, dict) else []
                    system = next(
                        (message.get("content", "") for message in messages
                         if message.get("role") == "system"),
                        "",
                    )
                    record = {
                        "order": len(owner.calls) + 1,
                        "method": self.command,
                        "path": path,
                        "route": route,
                        "role": owner._role_for(route, system),
                        "model": body.get("model") if isinstance(body, dict) else None,
                        "auth_present": auth.startswith("Bearer ") and bool(auth[7:]),
                        "request_body": body,
                    }
                    owner.calls.append(record)
                    owner._write_log()
                    behavior_queue = owner.behaviors[path] or owner.behaviors[route]
                    behavior = behavior_queue.popleft() if behavior_queue else {}
                return record, behavior, auth

            def _handle(self):
                body, raw_body = self._body() if self.command == "POST" else ({}, b"")
                record, behavior, auth = self._record(body)
                messages = body.get("messages", []) if isinstance(body, dict) else []
                system = next((m.get("content", "") for m in messages if m.get("role") == "system"), "")
                prompt = next((m.get("content", "") for m in messages if m.get("role") == "user"), "")
                role = owner._role_for(record["route"], system)
                for failed_role, marker, failure_status in owner.marker_failures:
                    if role == failed_role and marker.lower() in prompt.lower():
                        behavior = {**behavior, "status": failure_status}
                        break
                delay = float(behavior.get("delay", 0))
                if delay:
                    time.sleep(delay)
                status = int(behavior.get("status", 200))
                if owner.api_key and auth != f"Bearer {owner.api_key}":
                    status = 401
                if status != 200:
                    headers = {}
                    if behavior.get("redirect_to"):
                        headers["Location"] = behavior["redirect_to"]
                    return self._response(
                        status, {"error": {"message": "synthetic failure"}}, headers=headers,
                    )
                if behavior.get("malformed_json"):
                    return self._response(200, raw=b"{malformed-json")
                if "response" in behavior:
                    return self._response(200, behavior["response"])
                if behavior.get("malformed_request"):
                    return self._response(400, {"error": "malformed request"})
                if record["route"] == "/v1/models" and self.command == "GET":
                    models = [] if behavior.get("empty_models") else [{"id": owner.model_alias, "object": "model"}]
                    return self._response(200, {"object": "list", "data": models})
                if record["route"] == "/v1/embeddings":
                    texts = body.get("input", []) if isinstance(body, dict) else []
                    values = [{"object": "embedding", "index": idx, "embedding": [0.25, 0.5, 0.75]}
                              for idx, _ in enumerate(texts)]
                    return self._response(200, {"object": "list", "data": values, "model": record["model"]})
                if record["route"] == "/v1/chat/completions":
                    low = system.lower()
                    if "you are the judge" in low:
                        sequence = next((key for key in owner.judge_sequences if key.lower() in prompt.lower()), None)
                        if sequence:
                            with owner.lock:
                                index = owner.judge_counts[sequence]
                                owner.judge_counts[sequence] += 1
                            results = owner.judge_sequences[sequence]
                            content = results[min(index, len(results) - 1)]
                        elif "no prior expert verdicts" in prompt.lower():
                            content = {"final_verdict": "disputed", "final_confidence": 0.5,
                                       "reasoning": "Synthetic finding lacks enough review context."}
                        else:
                            content = {"final_verdict": "confirmed", "final_confidence": 0.9,
                                       "final_severity": "high", "reasoning": "Synthetic evidence reviewed."}
                    elif "red team expert" in low:
                        ids = [line[3:].split("]", 1)[0] for line in prompt.splitlines()
                               if line.startswith("- [") and "] " in line]
                        content = {"attack_paths": ([{
                            "goal": "Synthetic attack chain",
                            "steps": ["Use the confirmed issue to reach its impact."],
                            "findings_used": ids[:2], "likelihood": "medium",
                        }] if ids else [])}
                    elif "security triage lead" in low:
                        content = {"impact": "other", "attack_vector": "local",
                                   "exploitability": "moderate", "fix_effort": "moderate",
                                   "rationale": "Synthetic conservative triage."}
                    else:
                        if "authentication & access control" in low and "peer reviews" not in prompt.lower():
                            content = {"verdict": "disputed", "confidence": 0.5,
                                       "severity": "high", "narrative": "Synthetic initial auth review."}
                        else:
                            content = {"verdict": "confirmed", "confidence": 0.95,
                                       "severity": "high", "narrative": "Synthetic domain review."}
                    for response_role, marker, response_content in owner.marker_responses:
                        if role == response_role and marker.lower() in prompt.lower():
                            content = response_content
                            break
                    if "chat_content" in behavior:
                        content = behavior["chat_content"]
                    output = {
                        "id": "chatcmpl-synthetic", "object": "chat.completion",
                        "model": record["model"], "choices": [{"index": 0,
                            "message": {"role": "assistant", "content": json.dumps(content)},
                            "finish_reason": "stop"}],
                    }
                    return self._response(200, output)
                return self._response(404, {"error": "not found"})

            do_GET = _handle
            do_POST = _handle

        if ":" in bind_host:
            class IPv6ThreadingHTTPServer(ThreadingHTTPServer):
                address_family = socket.AF_INET6

            server_type = IPv6ThreadingHTTPServer
        else:
            server_type = ThreadingHTTPServer
        self.httpd = server_type((bind_host, bind_port), Handler)
        if ssl_context:
            self.httpd.socket = ssl_context.wrap_socket(self.httpd.socket, server_side=True)
        self.scheme = "https" if ssl_context else "http"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @staticmethod
    def _role_for(path: str, system: str) -> str:
        if path != "/v1/chat/completions":
            return "other"
        low = system.lower()
        if "red team expert" in low:
            return "redteam"
        if "you are the judge" in low:
            return "judge"
        if "security triage lead" in low:
            return "triage"
        return "expert"

    def _canonical_route(self, request_path: str) -> str:
        """Map a configured API prefix to the harness's canonical /v1 routes."""
        if self.api_prefix == "/v1":
            return request_path
        if request_path == self.api_prefix:
            return "/v1"
        if request_path.startswith(self.api_prefix + "/"):
            return "/v1" + request_path[len(self.api_prefix):]
        return request_path

    @property
    def base_url(self):
        host = self.httpd.server_address[0]
        if ":" in host:
            host = f"[{host}]"
        return f"{self.scheme}://{host}:{self.httpd.server_address[1]}"

    def set_behavior(self, path: str, **behavior):
        with self.lock:
            self.behaviors[path].append(behavior)

    def _write_log(self):
        """Persist synthetic request metadata without storing auth values."""
        if self.log_path is None:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.log_path.with_suffix(self.log_path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.calls, indent=2), encoding="utf-8")
        temporary.replace(self.log_path)

    def set_judge_sequence(self, marker: str, responses: list[dict]):
        self.judge_sequences[marker] = responses

    def set_marker_response(self, role: str, marker: str, content: dict):
        """Return a deterministic structured response when a prompt contains marker."""
        with self.lock:
            self.marker_responses.append((role, marker, content))

    def set_marker_failure(self, role: str, marker: str, status: int = 500):
        """Return a controlled HTTP failure for matching model-visible evidence."""
        with self.lock:
            self.marker_failures.append((role, marker, status))

    def close(self):
        if self.thread.is_alive():
            self.httpd.shutdown()
            self.httpd.server_close()
            self.thread.join(timeout=2)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
