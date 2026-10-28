from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..core import Finding, Module, register


@register
class HTTPCORSModule(Module):
    name = "scanner/http_cors"
    description = "Inspects CORS for wildcard and arbitrary-origin reflection using a harmless GET header."
    tags = ("http", "cors", "api", "configuration")

    def run(self, target: str, *, timeout: float = 5.0, **kwargs: object) -> list[Finding]:
        test_origin = "https://amf-security-test.invalid"
        request = Request(target, method="GET", headers={"User-Agent": "AMF-Defensive/0.2", "Origin": test_origin})
        try:
            with urlopen(request, timeout=timeout) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                status = response.status
        except HTTPError as exc:
            headers = {key.lower(): value for key, value in exc.headers.items()}
            status = exc.code
        except (URLError, TimeoutError, OSError) as exc:
            return [Finding(self.name, "CORS probe request failed", "info", str(exc), "Verify connectivity and firewall rules.", finding_type="network-error", confidence="low", evidence={"error": str(exc)})]

        allow_origin = headers.get("access-control-allow-origin", "").strip()
        credentials = headers.get("access-control-allow-credentials", "").strip().lower()
        evidence = {"status": status, "allow_origin": allow_origin, "allow_credentials": credentials}
        if allow_origin == "*" and credentials == "true":
            return [Finding(self.name, "CORS wildcard combined with credentials", "high", "The response allows all origins while enabling credentials.", "Never combine wildcard origin with credentials; use an explicit allowlist.", evidence=evidence, finding_type="cors-misconfiguration", confidence="high", title_ar="استخدام CORS شامل مع تفعيل الاعتمادات", title_en="CORS wildcard combined with credentials", description_ar="الاستجابة تسمح بكل الأصول مع تفعيل الاعتمادات.", description_en="The response allows all origins while enabling credentials.", remediation_ar="استخدم قائمة بيضاء صريحة ولا تجمع النجمة مع الاعتمادات.", remediation_en="Use an explicit origin allowlist and never combine wildcard with credentials.")]
        if allow_origin == test_origin:
            severity = "high" if credentials == "true" else "medium"
            return [Finding(self.name, "CORS origin reflection detected", severity, "The probe origin was reflected in Access-Control-Allow-Origin.", "Validate Origin against a strict server-side allowlist.", evidence=evidence, finding_type="cors-origin-reflection", confidence="high" if credentials == "true" else "medium", title_ar="اكتشاف انعكاس أصل CORS", title_en="CORS origin reflection detected", description_ar="الخادم أعاد الأصل التجريبي كما هو؛ يجب التحقق منه مقابل قائمة موثوقة.", description_en="The server reflected the probe origin; validate it against a trusted allowlist.", remediation_ar="تحقق من Origin مقابل قائمة نطاقات موثوقة قبل إعادته.", remediation_en="Validate Origin against an approved allowlist before reflecting it.")]
        if allow_origin == "*":
            return [Finding(self.name, "CORS wildcard origin exposed", "low", "The response allows any origin to read this resource.", "Ensure the resource is public and contains no sensitive data, or restrict origins.", evidence=evidence, finding_type="cors-wildcard", confidence="high", title_ar="سماح شامل في CORS", title_en="CORS wildcard origin exposed", description_ar="الخادم يسمح لأي نطاق بقراءة المورد.", description_en="The server permits any external origin to read the resource.", remediation_ar="قيّد الأصول أو تأكد أن المورد عام ولا يحتوي بيانات حساسة.", remediation_en="Restrict origins or ensure the resource is truly public and non-sensitive.")]
        return []
