from __future__ import annotations

import socket
from urllib.parse import urlparse

from ..core import Finding, Module, register


@register
class DNSBasicModule(Module):
    name = "scanner/dns_basic"
    description = "Resolves the target hostname and reports IPv4/IPv6 addresses without zone enumeration."

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        parsed = urlparse(target)
        if not parsed.hostname:
            return [Finding(self.name, "Target hostname is invalid", "info", target, "Provide an absolute HTTP(S) URL.", finding_type="input-validation", title_ar="اسم المضيف غير صالح", title_en="Target hostname is invalid", description_ar=target, description_en=target, remediation_ar="أدخل عنوان HTTP(S) كاملًا.", remediation_en="Provide an absolute HTTP(S) URL.")]
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            records = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            return [Finding(self.name, "DNS resolution failed", "medium", str(exc), "Verify DNS records and the target hostname.", finding_type="dns-resolution", title_ar="فشل حل DNS", title_en="DNS resolution failed", description_ar=str(exc), description_en=str(exc), remediation_ar="تحقق من سجلات DNS واسم المضيف.", remediation_en="Verify DNS records and the target hostname.")]
        finally:
            socket.setdefaulttimeout(previous)
        addresses = sorted({record[4][0] for record in records})
        return [Finding(self.name, "DNS resolution observed", "info", ", ".join(addresses), "Review exposed addresses and restrict unnecessary public services.", {"hostname": parsed.hostname, "addresses": addresses}, finding_type="asset-discovery", title_ar="تم اكتشاف عناوين DNS", title_en="DNS resolution observed", description_ar=f"العناوين المكتشفة: {', '.join(addresses)}", description_en=f"Observed addresses: {', '.join(addresses)}", remediation_ar="راجع العناوين المكشوفة وقيّد الخدمات العامة غير الضرورية.", remediation_en="Review exposed addresses and restrict unnecessary public services.")]
