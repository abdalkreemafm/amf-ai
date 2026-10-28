from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..core import Finding, Module, register


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@register
class HTTPRedirectsModule(Module):
    name = "scanner/http_redirects"
    description = "Checks whether HTTP endpoints redirect to HTTPS without following unsafe chains."

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        request = Request(target, method="HEAD", headers={"User-Agent": "AMF-Defensive/0.1"})
        opener = build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                location = response.headers.get("Location", "")
        except HTTPError as exc:
            status = exc.code
            location = exc.headers.get("Location", "")
        except (URLError, TimeoutError, OSError) as exc:
            return [Finding(self.name, "HTTP request failed", "info", str(exc), "Verify the target and network policy.", finding_type="transport-error", title_ar="فشل طلب HTTP", title_en="HTTP request failed", description_ar=str(exc), description_en=str(exc), remediation_ar="تحقق من الهدف وسياسة الشبكة.", remediation_en="Verify the target and network policy.")]

        if target.lower().startswith("http://") and not location.lower().startswith("https://"):
            return [Finding(self.name, "HTTP endpoint does not redirect to HTTPS", "medium", f"HTTP status: {status}; Location: {location or '<missing>'}", "Redirect HTTP requests to the equivalent HTTPS URL.", {"status": status, "location": location}, finding_type="transport-security", confidence="high", title_ar="نقطة HTTP لا تحوّل إلى HTTPS", title_en="HTTP endpoint does not redirect to HTTPS", description_ar=f"رمز HTTP: {status}؛ العنوان: {location or 'غير موجود'}", description_en=f"HTTP status: {status}; Location: {location or '<missing>'}", impact_ar="قد يسمح ذلك بإرسال البيانات عبر اتصال غير مشفر.", impact_en="Users may send data over an unencrypted connection.", remediation_ar="حوّل طلبات HTTP إلى عنوان HTTPS المكافئ.", remediation_en="Redirect HTTP requests to the equivalent HTTPS URL.")]
        return []
