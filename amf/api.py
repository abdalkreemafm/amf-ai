from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import modules  # noqa: F401
from .core import RunResult, get_module, list_modules, utc_now
from .profiles import PROFILES, profile_modules
from .safety import SafetyError, SafetyPolicy, load_allowlist


class AMFRequestHandler(BaseHTTPRequestHandler):
    server_version = "AMF-API/0.2"

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin", "")
        if origin in {"http://127.0.0.1:5173", "http://localhost:5173"}:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:5173")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/api/health":
            self._send(200, {"ok": True, "version": "0.2.0", "mode": "local-only"})
            return
        if self.path == "/api/modules":
            self._send(200, {"modules": [module.metadata() for module in list_modules()]})
            return
        if self.path == "/api/profiles":
            self._send(200, {"profiles": [{"name": name, "description": item["description"], "module_count": len(profile_modules(name))} for name, item in PROFILES.items()]})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 64 * 1024:
                raise ValueError("request body too large")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            results = run_scan(payload)
            self._send(200, {"results": [result.to_dict("both") for result in results]})
        except (SafetyError, KeyError, ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception:
            self._send(500, {"error": "internal scan error"})

    def log_message(self, format: str, *args: object) -> None:
        return


def run_scan(payload: dict[str, Any]) -> list[RunResult]:
    if not isinstance(payload, dict):
        raise ValueError("request must be a JSON object")
    target = payload.get("target")
    if not isinstance(target, str) or not target:
        raise ValueError("target is required")
    allow = payload.get("allow", [])
    if not isinstance(allow, list) or not all(isinstance(item, str) for item in allow):
        raise ValueError("allow must be a list of URLs")
    execute = bool(payload.get("execute", False))
    timeout = float(payload.get("timeout", 5.0))
    profile = payload.get("profile", "full")
    if not isinstance(profile, str):
        raise ValueError("profile must be a string")
    policy = SafetyPolicy(load_allowlist(allow), execute=execute, timeout=timeout)
    normalized = policy.validate(target)
    results: list[RunResult] = []
    for module in profile_modules(profile):
        result = RunResult(module.name, normalized, "execute" if execute else "dry-run", utc_now())
        if execute:
            try:
                result.findings = module.run(normalized, timeout=timeout)
            except Exception as exc:
                result.error = str(exc)
        results.append(result)
    return results


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("AMF API only supports loopback hosts")
    server = ThreadingHTTPServer((host, port), AMFRequestHandler)
    print(f"AMF API listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    serve()
