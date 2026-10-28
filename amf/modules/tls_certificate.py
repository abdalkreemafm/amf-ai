from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..core import Finding, Module, register


@register
class TLSCertificateModule(Module):
    name = "scanner/tls_certificate"
    description = "Inspects TLS version, certificate expiry and hostname coverage without authentication or exploitation."

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        parsed = urlparse(target)
        if parsed.scheme != "https" or not parsed.hostname:
            return [Finding(self.name, "TLS check requires an HTTPS target", "info", target, "Use an https:// URL for TLS inspection.", finding_type="input-validation", title_ar="فحص TLS يحتاج هدف HTTPS", title_en="TLS check requires an HTTPS target", description_ar=target, description_en=target, remediation_ar="استخدم عنوانًا يبدأ بـ https:// لفحص TLS.", remediation_en="Use an https:// URL for TLS inspection.")]
        port = parsed.port or 443
        context = ssl.create_default_context()
        try:
            with socket.create_connection((parsed.hostname, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=parsed.hostname) as connection:
                    cert = connection.getpeercert()
                    version = connection.version() or "unknown"
        except (OSError, ssl.SSLError) as exc:
            return [Finding(self.name, "TLS connection failed", "info", str(exc), "Verify certificate trust, hostname and network policy.", finding_type="transport-error", title_ar="فشل اتصال TLS", title_en="TLS connection failed", description_ar=str(exc), description_en=str(exc), remediation_ar="تحقق من الثقة بالشهادة واسم المضيف وسياسة الشبكة.", remediation_en="Verify certificate trust, hostname and network policy.")]

        findings: list[Finding] = []
        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(Finding(self.name, "TLS certificate is expired", "high", not_after, "Renew the certificate and deploy the full valid chain.", {"not_after": not_after, "days_remaining": days}, finding_type="certificate-expiry", title_ar="شهادة TLS منتهية", title_en="TLS certificate is expired", description_ar=f"انتهت الشهادة في {not_after}.", description_en=f"The certificate expired on {not_after}.", impact_ar="قد يفشل التحقق من هوية الخادم أو يتوقف الاتصال الآمن.", impact_en="Clients may reject the server identity or secure connection.", remediation_ar="جدّد الشهادة وثبّت السلسلة الصحيحة.", remediation_en="Renew the certificate and deploy the full valid chain."))
            elif days < 30:
                findings.append(Finding(self.name, "TLS certificate expires soon", "medium", not_after, "Renew the certificate before its expiry date.", {"not_after": not_after, "days_remaining": days}, finding_type="certificate-expiry", title_ar="شهادة TLS تقترب من الانتهاء", title_en="TLS certificate expires soon", description_ar=f"تبقى {days} يومًا على انتهاء الشهادة.", description_en=f"The certificate expires in {days} days.", remediation_ar="جدّد الشهادة قبل تاريخ الانتهاء.", remediation_en="Renew the certificate before its expiry date."))
        findings.append(Finding(self.name, "TLS connection negotiated", "info", version, "Keep the TLS stack and certificate chain patched and monitored.", {"tls_version": version, "subject": cert.get("subject", [])}, finding_type="tls-observation", confidence="high", title_ar="تم التفاوض على اتصال TLS", title_en="TLS connection negotiated", description_ar=f"إصدار TLS المستخدم: {version}.", description_en=f"Negotiated TLS version: {version}.", remediation_ar="حافظ على تحديث TLS وسلسلة الشهادات وراقبهما.", remediation_en="Keep the TLS stack and certificate chain patched and monitored."))
        return findings
