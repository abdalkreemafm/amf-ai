from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import Finding
from .base import ToolAdapter, ToolInfo, run_command


class OpenSSLTLSAdapter(ToolAdapter):
    info = ToolInfo("openssl", "openssl", "TLS handshake and certificate summary", ("tls", "certificate"), version_args=("version",))

    def run(self, target: str, *, timeout: float) -> list[Finding]:
        parsed = urlparse(target)
        if parsed.scheme != "https" or not parsed.hostname:
            return [Finding("tool/openssl", "OpenSSL adapter requires HTTPS", "info", target, "Use an HTTPS target for TLS inspection.", finding_type="input-validation")]
        port = parsed.port or 443
        try:
            result = run_command("openssl", ["s_client", "-connect", f"{parsed.hostname}:{port}", "-servername", parsed.hostname, "-brief", "-no_ticket"], timeout=timeout)
        except FileNotFoundError as exc:
            return [Finding("tool/openssl", "OpenSSL is not installed", "info", str(exc), "Install openssl using the platform package manager if authorized.", finding_type="tool-unavailable")]
        except TimeoutError:
            return [Finding("tool/openssl", "OpenSSL probe timed out", "medium", target, "Check connectivity and TLS endpoint availability.", finding_type="tool-timeout")]
        output = (result.stdout + "\n" + result.stderr).strip()
        if result.returncode != 0:
            return [Finding("tool/openssl", "TLS handshake failed", "medium", "OpenSSL could not complete the handshake.", "Review certificate chain, protocol support, and server TLS configuration.", evidence={"host": parsed.hostname, "exit_code": result.returncode, "output_preview": output[:600]}, finding_type="tls-handshake-error", confidence="medium")]
        protocol = re.search(r"Protocol version:\s*(\S+)", output)
        cipher = re.search(r"Ciphersuite:\s*(\S+)", output)
        return [Finding("tool/openssl", "TLS handshake completed", "info", "OpenSSL completed a TLS handshake.", "Keep protocol and cipher configuration aligned with current hardening guidance.", evidence={"host": parsed.hostname, "port": port, "protocol": protocol.group(1) if protocol else "reported-by-openssl", "cipher": cipher.group(1) if cipher else "reported-by-openssl"}, finding_type="tls-observation", confidence="high")]
