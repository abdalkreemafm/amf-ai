from __future__ import annotations

import socket
from urllib.parse import urlparse

from ..core import Finding
from .base import ToolAdapter, ToolInfo


class LocalDNSAdapter(ToolAdapter):
    info = ToolInfo("dns", "python", "Local hostname and address resolution", ("ipv4", "ipv6"))

    def available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "python socket resolver"

    def run(self, target: str, *, timeout: float) -> list[Finding]:
        hostname = urlparse(target).hostname
        if not hostname:
            return [Finding("tool/dns", "Invalid hostname", "info", target, "Provide an HTTP or HTTPS URL.", finding_type="input-validation")]
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
        except socket.gaierror as exc:
            return [Finding("tool/dns", "DNS resolution failed", "medium", str(exc), "Check DNS configuration and hostname spelling.", finding_type="dns-resolution-error", confidence="medium", evidence={"hostname": hostname})]
        return [Finding("tool/dns", "DNS addresses resolved", "info", f"Resolved {hostname} to {len(addresses)} address(es).", "Review whether all resolved addresses are expected and authorized.", finding_type="asset-discovery", confidence="high", evidence={"hostname": hostname, "addresses": addresses})]
