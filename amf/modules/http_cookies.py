from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..core import Finding, Module, register


@register
class HTTPCookiesModule(Module):
    name = "scanner/http_cookies"
    description = "Checks Secure, HttpOnly and SameSite attributes on HTTP cookies."

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        request = Request(target, method="HEAD", headers={"User-Agent": "AMF-Defensive/0.1"})
        try:
            with urlopen(request, timeout=timeout) as response:
                headers = response.headers
        except HTTPError as exc:
            headers = exc.headers
        except (URLError, TimeoutError, OSError) as exc:
            return [Finding(self.name, "HTTP request failed", "info", str(exc), "Verify the target and network policy.", finding_type="transport-error", confidence="high", title_ar="فشل طلب HTTP", title_en="HTTP request failed", description_ar=str(exc), description_en=str(exc), remediation_ar="تحقق من الهدف وسياسة الشبكة.", remediation_en="Verify the target and network policy.")]

        findings: list[Finding] = []
        get_all = getattr(headers, "get_all", None)
        cookies = get_all("Set-Cookie", []) if get_all else headers.get("Set-Cookie", [])
        if isinstance(cookies, str):
            cookies = [cookies]
        for cookie in cookies:
            cookie_name = cookie.split("=", 1)[0].strip()
            lowered = cookie.lower()
            checks = [
                ("secure", "medium", "Cookie missing Secure attribute", "خاصية Secure مفقودة من Cookie", "Set Secure for cookies sent over HTTPS.", "فعّل Secure لملفات Cookie المرسلة عبر HTTPS."),
                ("httponly", "medium", "Cookie missing HttpOnly attribute", "خاصية HttpOnly مفقودة من Cookie", "Set HttpOnly when JavaScript does not need cookie access.", "فعّل HttpOnly عندما لا تحتاج JavaScript إلى قراءة Cookie."),
                ("samesite", "low", "Cookie missing SameSite attribute", "خاصية SameSite مفقودة من Cookie", "Set SameSite according to the application's cross-site requirements.", "حدّد SameSite وفق متطلبات الوصول عبر المواقع."),
            ]
            for marker, severity, title_en, title_ar, remediation_en, remediation_ar in checks:
                if marker not in lowered:
                    findings.append(Finding(self.name, title_en, severity, f"Cookie: {cookie_name}", remediation_en, {"cookie": cookie_name}, finding_type="cookie-security", confidence="high", title_ar=title_ar, title_en=title_en, description_ar=f"ملف Cookie: {cookie_name}", description_en=f"Cookie: {cookie_name}", remediation_ar=remediation_ar, remediation_en=remediation_en))
        return findings
