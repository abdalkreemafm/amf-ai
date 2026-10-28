from __future__ import annotations

import json
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from ..core import Finding, Module, register


def _txt(name: str, timeout: float) -> list[str]:
    request = Request(f"https://cloudflare-dns.com/dns-query?{urlencode({'name': name, 'type': 'TXT'})}", headers={"Accept": "application/dns-json", "User-Agent": "AMF-Defensive/0.2"})
    try:
        with urlopen(request, timeout=timeout) as response:
            answers = json.loads(response.read().decode("utf-8")).get("Answer", [])
        return [str(item.get("data", "")).strip('"') for item in answers if item.get("data")]
    except (OSError, TimeoutError, json.JSONDecodeError):
        return []


@register
class DNSEmailSecurityModule(Module):
    name = "scanner/dns_email_security"
    description = "Checks SPF and DMARC posture using DNS-over-HTTPS; no changes are made."
    tags = ("dns", "spf", "dmarc", "email")

    def run(self, target: str, *, timeout: float = 5.0, **kwargs: object) -> list[Finding]:
        hostname = urlparse(target).hostname
        if not hostname:
            return [Finding(self.name, "Invalid target hostname", "info", target, "Provide a valid HTTP or HTTPS URL.", finding_type="input-validation")]
        findings: list[Finding] = []
        spf = next((item for item in _txt(hostname, timeout) if "v=spf1" in item.lower()), None)
        if not spf:
            findings.append(Finding(self.name, "Missing SPF record", "medium", f"No SPF TXT record was found for {hostname}.", "Publish an SPF record for authorized mail servers.", evidence={"domain": hostname}, finding_type="missing-spf", confidence="medium", title_ar="غياب سجل SPF", title_en="Missing SPF record", description_ar="لم يتم العثور على سجل SPF للنطاق.", description_en="No SPF record was found for the domain.", remediation_ar="أضف سجل SPF يحدد خوادم البريد المصرح لها.", remediation_en="Publish an SPF record identifying authorized mail servers."))
        dmarc = next((item for item in _txt(f"_dmarc.{hostname}", timeout) if "v=dmarc1" in item.lower()), None)
        policy = next((part.split("=", 1)[1].strip().lower() for part in (dmarc or "").split(";") if part.strip().lower().startswith("p=") and "=" in part), "none")
        if not dmarc:
            findings.append(Finding(self.name, "Missing DMARC record", "medium", f"No DMARC record was found for {hostname}.", "Publish a DMARC policy under _dmarc.<domain>.", evidence={"domain": hostname}, finding_type="missing-dmarc", confidence="medium", title_ar="غياب سجل DMARC", title_en="Missing DMARC record", description_ar="لم يتم العثور على سجل DMARC.", description_en="No DMARC record was found.", remediation_ar="أضف سجل DMARC مع سياسة وتقارير.", remediation_en="Publish a DMARC record with policy and reporting."))
        elif policy == "none":
            findings.append(Finding(self.name, "DMARC monitoring-only policy", "low", dmarc, "Move to quarantine or reject after validating legitimate mail sources.", evidence={"domain": hostname, "policy": policy}, finding_type="dmarc-monitoring-only", confidence="high", title_ar="سياسة DMARC للمراقبة فقط", title_en="DMARC monitoring-only policy", description_ar="السياسة لا تفرض حظر الرسائل المنتحلة.", description_en="The policy reports but does not enforce against spoofing.", remediation_ar="ارفع السياسة إلى quarantine أو reject بعد التحقق.", remediation_en="Upgrade to quarantine or reject after validation."))
        return findings
