from __future__ import annotations

import re

from ..core import Finding, Module, register
from .http_utils import fetch_document


_DIRECTORY_INDEX = re.compile(r"<title>\s*(?:index of|directory listing)", re.I)


@register
class ServerMisconfigurationModule(Module):
    name = "scanner/server_misconfiguration"
    description = "Checks passive server misconfiguration indicators in normal HTTP responses."

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        document = fetch_document(target, timeout=timeout)
        if isinstance(document, str):
            return [Finding(self.name, "HTTP request failed", "info", document, "Verify the target and network policy.", finding_type="transport-error", title_ar="فشل طلب HTTP", title_en="HTTP request failed", description_ar=document, description_en=document, remediation_ar="تحقق من الهدف وسياسة الشبكة.", remediation_en="Verify the target and network policy.")]
        findings: list[Finding] = []
        server = document.headers.get("Server", "")
        powered = document.headers.get("X-Powered-By", "")
        if server or powered:
            disclosed = {key: value for key, value in (("Server", server), ("X-Powered-By", powered)) if value}
            findings.append(Finding(self.name, "Server technology details disclosed", "low", str(disclosed), "Minimize unnecessary version and framework disclosure.", disclosed, finding_type="information-disclosure", title_ar="كشف تفاصيل تقنية الخادم", title_en="Server technology details disclosed", description_ar=f"الرؤوس المكشوفة: {disclosed}", description_en=f"Disclosed headers: {disclosed}", remediation_ar="قلل كشف إصدارات الخادم والأطر غير الضروري.", remediation_en="Minimize unnecessary server and framework version disclosure."))
        if _DIRECTORY_INDEX.search(document.body):
            findings.append(Finding(self.name, "Directory listing appears enabled", "medium", "The response resembles a directory index.", {"status": document.status}, finding_type="directory-listing", title_ar="يبدو أن استعراض محتويات المجلد مفعّل", title_en="Directory listing appears enabled", description_ar="الاستجابة تشبه صفحة فهرس مجلد.", description_en="The response resembles a directory index.", impact_ar="قد يكشف ملفات وموارد داخلية غير مقصودة.", impact_en="It may expose unintended files and internal resources.", remediation_ar="عطّل directory listing واسمح بالوصول إلى الملفات المطلوبة فقط.", remediation_en="Disable directory listing and expose only required files."))
        return findings
