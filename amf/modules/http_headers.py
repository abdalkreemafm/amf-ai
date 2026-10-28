from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..core import Finding, Module, register


_SECURITY_HEADERS = {
    "strict-transport-security": (
        "Missing HSTS header",
        "medium",
        "Enable Strict-Transport-Security for HTTPS deployments.",
    ),
    "content-security-policy": (
        "Missing Content-Security-Policy header",
        "medium",
        "Define a restrictive Content-Security-Policy appropriate for the application.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options header",
        "low",
        "Set X-Content-Type-Options to nosniff.",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options header",
        "low",
        "Set X-Frame-Options or use frame-ancestors in CSP.",
    ),
}


@register
class HTTPHeadersModule(Module):
    name = "scanner/http_headers"
    description = "Checks common HTTP security headers without exploiting the target."
    tags = ("http", "headers", "hardening")

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        request = Request(target, method="HEAD", headers={"User-Agent": "AMF-Defensive/0.1"})
        try:
            with urlopen(request, timeout=timeout) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                status = response.status
        except HTTPError as exc:
            headers = {key.lower(): value for key, value in exc.headers.items()}
            status = exc.code
        except (URLError, TimeoutError, OSError) as exc:
            return [Finding(self.name, "HTTP request failed", "info", str(exc), "Verify the target and network policy.")]

        findings: list[Finding] = []
        for header, (title, severity, remediation) in _SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(Finding(self.name, title, severity, f"HTTP status: {status}", remediation))
        if "server" in headers:
            findings.append(Finding(self.name, "Server header exposed", "info", "The response discloses a Server header.", "Consider minimizing version disclosure where operationally appropriate.", {"server": headers["server"]}))
        return findings
