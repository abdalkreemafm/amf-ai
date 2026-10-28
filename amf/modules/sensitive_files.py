from __future__ import annotations

from urllib.parse import urljoin, urlparse

from ..core import Finding, Module, register
from .http_utils import HTTPDocument, fetch_document


@register
class SensitiveFilesModule(Module):
    name = "scanner/sensitive_files"
    description = "Checks exposed configuration and repository metadata without returning secret contents."
    tags = ("http", "secrets", "git", "configuration")

    def run(self, target: str, *, timeout: float = 5.0, **kwargs: object) -> list[Finding]:
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.hostname:
            return [Finding(self.name, "Invalid URL", "info", target, "Provide an absolute HTTP or HTTPS URL.", finding_type="input-validation")]
        base = f"{parsed.scheme}://{parsed.netloc}"
        findings: list[Finding] = []

        checks = (("/.env", "Environment configuration file", "high", ("app_key=", "api_key=", "database_url=", "db_password=", "secret=")), ("/.git/HEAD", "Git repository metadata", "high", ("ref:", "refs/heads/")))
        for path, label, severity, markers in checks:
            url = urljoin(base, path)
            document = fetch_document(url, timeout=timeout, max_bytes=4096)
            if not isinstance(document, HTTPDocument) or document.status != 200:
                continue
            body = document.body.lower()
            is_match = any(marker in body for marker in markers)
            if path == "/.env":
                is_match = is_match or ("=" in document.body and "<html" not in body and "<!doctype" not in body)
            if is_match:
                findings.append(Finding(self.name, f"Exposed {label}", severity, f"A sensitive resource was reachable at {url}.", "Remove it from the public web root and deny access at the web server.", evidence={"url": url, "status": document.status, "content_length": len(document.body), "content_preview": "[REDACTED: sensitive content omitted]"}, finding_type="sensitive-file-exposure", confidence="high", title_ar=f"كشف {label}", title_en=f"Exposed {label}", description_ar=f"تم الوصول إلى مورد حساس في {url}.", description_en=f"A sensitive resource was reachable at {url}.", impact_ar="قد يكشف إعدادات أو شفرة أو أسرارًا للتطبيق.", impact_en="May disclose application configuration, source metadata, or secrets.", remediation_ar="احذف المورد من جذر الويب وامنع الوصول إليه من إعدادات الخادم.", remediation_en="Remove it from the web root and deny access in the server configuration."))

        security_url = urljoin(base, "/.well-known/security.txt")
        security = fetch_document(security_url, timeout=timeout, max_bytes=4096)
        if not isinstance(security, HTTPDocument) or security.status != 200 or "contact:" not in security.body.lower():
            findings.append(Finding(self.name, "Missing security.txt policy", "low", f"No valid policy was found at {security_url}.", "Publish a security.txt contact policy under /.well-known/security.txt.", evidence={"url": security_url}, finding_type="security-txt-missing", confidence="medium", title_ar="غياب سياسة security.txt", title_en="Missing security.txt policy", description_ar="لم يتم العثور على سياسة واضحة للإبلاغ عن الثغرات.", description_en="No clear vulnerability disclosure policy was found.", remediation_ar="أضف ملف security.txt مع وسيلة اتصال آمنة.", remediation_en="Publish security.txt with a secure vulnerability-reporting contact."))
        return findings
