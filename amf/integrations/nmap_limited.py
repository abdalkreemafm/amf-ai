from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import Finding
from .base import ToolAdapter, ToolInfo, run_command


class LimitedNmapAdapter(ToolAdapter):
    info = ToolInfo("nmap", "nmap", "Bounded service discovery for explicitly authorized targets", ("ports", "service-discovery"))

    def run(self, target: str, *, timeout: float) -> list[Finding]:
        hostname = urlparse(target).hostname
        if not hostname:
            return [Finding("tool/nmap", "Invalid target hostname", "info", target, "Provide an HTTP or HTTPS URL.", finding_type="input-validation")]
        try:
            result = run_command("nmap", ["-Pn", "-T2", "--top-ports", "20", "--version-light", "--open", hostname], timeout=min(timeout, 60.0))
        except FileNotFoundError as exc:
            return [Finding("tool/nmap", "Nmap is not installed", "info", str(exc), "Install nmap separately only when authorized and needed.", finding_type="tool-unavailable")]
        except TimeoutError:
            return [Finding("tool/nmap", "Nmap probe timed out", "medium", target, "Reduce scope or review network reachability.", finding_type="tool-timeout")]
        lines = [line.strip() for line in result.stdout.splitlines() if re.match(r"^\d+/(tcp|udp)\s+open\s+", line.strip())]
        return [Finding("tool/nmap", "Open services discovered", "info", f"Nmap reported {len(lines)} open service(s).", "Review every exposed service and restrict unnecessary exposure.", evidence={"host": hostname, "services": lines[:20], "exit_code": result.returncode}, finding_type="service-discovery", confidence="medium")]
