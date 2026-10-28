from __future__ import annotations

import re

from ..core import Finding, Module, register
from .http_utils import fetch_document


_PATTERNS = {
    "mysql": re.compile(r"mysql|mysqli|sql syntax.*near", re.I),
    "postgresql": re.compile(r"postgresql|pg_query|psql:\s+error", re.I),
    "sqlite": re.compile(r"sqlite error|sqlite3\.operationalerror", re.I),
    "mssql": re.compile(r"microsoft sql server|unclosed quotation mark|sqlexception", re.I),
    "oracle": re.compile(r"ora-\d{5}|oracle error", re.I),
    "odbc": re.compile(r"odbc sql server driver|odbc driver", re.I),
}


@register
class SQLDatabaseErrorModule(Module):
    name = "scanner/http_sql_errors"
    description = "Passively detects database error signatures in a normal HTTP response; it never injects input."
    tags = ("http", "database", "disclosure", "sql")

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        document = fetch_document(target, timeout=timeout)
        if isinstance(document, str):
            return [Finding(self.name, "HTTP request failed", "info", document, "Verify the target and network policy.", finding_type="transport-error", title_ar="فشل طلب HTTP", title_en="HTTP request failed", description_ar=document, description_en=document, remediation_ar="تحقق من الهدف وسياسة الشبكة.", remediation_en="Verify the target and network policy.")]
        matches = [name for name, pattern in _PATTERNS.items() if pattern.search(document.body)]
        if not matches:
            return []
        return [Finding(self.name, "Database error details exposed", "medium", f"Database signatures: {', '.join(matches)}", "Return generic error pages and keep detailed database errors in server-side logs.", {"status": document.status, "signatures": matches}, finding_type="sql-error-disclosure", confidence="medium", title_ar="تسريب تفاصيل أخطاء قاعدة البيانات", title_en="Database error details exposed", description_ar=f"ظهرت مؤشرات أخطاء قواعد بيانات: {', '.join(matches)}", description_en=f"Database error signatures appeared: {', '.join(matches)}", impact_ar="قد تكشف التفاصيل نوع قاعدة البيانات وبنية الاستعلامات وتساعد على تطوير هجمات لاحقة.", impact_en="Details may reveal database technology and query structure, aiding further attacks.", remediation_ar="اعرض رسائل خطأ عامة وخزّن التفاصيل في سجلات الخادم فقط.", remediation_en="Return generic errors and keep details in server-side logs.")]
