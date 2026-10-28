from __future__ import annotations

import re

from ..core import Finding, Module, register
from .http_utils import fetch_document


_SINKS = re.compile(r"innerHTML|outerHTML|document\.write\s*\(|dangerouslySetInnerHTML|v-html", re.I)
_INLINE_EVENTS = re.compile(r"\son[a-z]+\s*=", re.I)
_FORMS = re.compile(r"<form\b", re.I)


@register
class XSSSurfaceModule(Module):
    name = "scanner/http_xss_surface"
    description = "Passively identifies HTML forms and client-side dangerous sinks; it never injects XSS payloads."

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        document = fetch_document(target, timeout=timeout)
        if isinstance(document, str):
            return [Finding(self.name, "HTTP request failed", "info", document, "Verify the target and network policy.", finding_type="transport-error", title_ar="فشل طلب HTTP", title_en="HTTP request failed", description_ar=document, description_en=document, remediation_ar="تحقق من الهدف وسياسة الشبكة.", remediation_en="Verify the target and network policy.")]
        indicators = []
        if _FORMS.search(document.body):
            indicators.append("html-form")
        if _SINKS.search(document.body):
            indicators.append("client-side-sink")
        if _INLINE_EVENTS.search(document.body):
            indicators.append("inline-event-handler")
        if not indicators:
            return []
        return [Finding(self.name, "Potential XSS attack surface detected", "low", f"Indicators: {', '.join(indicators)}", "Use contextual output encoding, avoid dangerous DOM sinks, validate input, and deploy a restrictive CSP.", {"status": document.status, "indicators": indicators}, finding_type="xss-risk-indicator", confidence="low", title_ar="مؤشرات سطح محتمل لثغرات XSS", title_en="Potential XSS attack surface detected", description_ar=f"تم العثور على مؤشرات: {', '.join(indicators)}. هذا مؤشر يحتاج مراجعة يدوية وليس إثباتًا للاستغلال.", description_en=f"Indicators found: {', '.join(indicators)}. This is a review signal, not proof of exploitability.", impact_ar="قد تصبح المدخلات غير المرمّزة خطرة إذا وصلت إلى هذه الأسطح.", impact_en="Unencoded input may become dangerous if it reaches these sinks.", remediation_ar="استخدم ترميزًا سياقيًا وتجنب أسطح DOM الخطرة وفعّل CSP مقيدة.", remediation_en="Use contextual output encoding, avoid dangerous DOM sinks, and deploy a restrictive CSP.")]
