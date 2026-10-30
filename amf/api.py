from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from . import modules  # noqa: F401
from .api_scan import run_scan
from .correlation import correlate_results
from .integrations import tool_catalog
from .jobs import JobManager
from .core import list_modules
from .profiles import PROFILES, profile_modules
from .safety import SafetyError

JOB_MANAGER = JobManager()


class AMFRequestHandler(BaseHTTPRequestHandler):
    server_version = "AMF-API/0.3"

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

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64 * 1024:
            raise ValueError("request body too large")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("request must be a JSON object")
        return payload

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:5173")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._send(200, {"ok": True, "version": "0.3.0", "mode": "local-only"})
        elif path == "/api/modules":
            self._send(200, {"modules": [module.metadata() for module in list_modules()]})
        elif path == "/api/profiles":
            self._send(200, {"profiles": [{"name": name, "description": item["description"], "module_count": len(profile_modules(name))} for name, item in PROFILES.items()]})
        elif path == "/api/tools":
            self._send(200, {"tools": tool_catalog()})
        elif path.startswith("/api/jobs/"):
            self._get_job(path)
        else:
            self._send(404, {"error": "not found"})

    def _get_job(self, path: str) -> None:
        parts = path.strip("/").split("/")
        job = JOB_MANAGER.get(parts[2]) if len(parts) >= 3 else None
        if not job:
            self._send(404, {"error": "job not found"})
            return
        if len(parts) == 4 and parts[3] == "events":
            self._send(200, {"events": [{"at": job.finished_at or job.started_at or job.created_at, "status": job.status, "progress": job.progress, "total": job.total, "current_module": job.current_module}]})
            return
        self._send(200, {"job": job.to_dict()})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        try:
            payload = {} if path.startswith("/api/jobs/") and path.endswith("/cancel") else self._read_json()
            if path == "/api/scan":
                results = run_scan(payload)
                self._send(200, {"results": [result.to_dict("both") for result in results], "correlation": correlate_results(results).to_dict()})
                return
            if path == "/api/jobs":
                job = JOB_MANAGER.create(payload)
                self._send(202, {"job": job.to_dict()})
                return
            if path.startswith("/api/jobs/") and path.endswith("/cancel"):
                job_id = path.strip("/").split("/")[2]
                job = JOB_MANAGER.cancel(job_id)
                if not job:
                    self._send(404, {"error": "job not found"})
                else:
                    self._send(202, {"job": job.to_dict()})
                return
            self._send(404, {"error": "not found"})
        except (SafetyError, KeyError, ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception:
            self._send(500, {"error": "internal scan error"})

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("AMF API only supports loopback hosts")
    server = ThreadingHTTPServer((host, port), AMFRequestHandler)
    print(f"AMF API listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    serve()
