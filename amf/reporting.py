from __future__ import annotations

import html
import json
from typing import Any, Iterable

from .core import RunResult


def to_json(results: Iterable[RunResult], language: str = "both") -> str:
    return json.dumps([result.to_dict(language) for result in results], ensure_ascii=False, indent=2)


def to_markdown(results: Iterable[RunResult], language: str = "both") -> str:
    lines = ["# AMF Security Assessment Report", "", "# تقرير تقييم أمني AMF", ""]
    for result in results:
        lines += [f"## {result.module} — {result.target}", f"- Mode / الوضع: `{result.mode}`", f"- Started / بدأ: `{result.started_at}`", ""]
        if result.error:
            lines += [f"- Error / خطأ: `{result.error}`", ""]
        if not result.findings:
            lines += ["No findings were recorded. / لم تُسجل نتائج.", ""]
        for index, finding in enumerate(result.findings, 1):
            item = finding.to_dict(language)
            lines += [f"### {index}. {item['title_en']} / {item['title_ar']}", f"- **Type / النوع:** `{item['type']}`", f"- **Severity / الخطورة:** `{item['severity']}`", f"- **Confidence / الثقة:** `{item['confidence']}`", f"- **Description / الوصف:** {item['description_en']} / {item['description_ar']}", f"- **Impact / الأثر:** {item['impact_en'] or 'See description'} / {item['impact_ar'] or 'راجع الوصف'}", f"- **Remediation / الإصلاح:** {item['remediation_en']} / {item['remediation_ar']}", f"- **Evidence / الدليل:** `{json.dumps(item['evidence'], ensure_ascii=False)}`", ""]
    return "\n".join(lines)


def to_sarif(results: Iterable[RunResult]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
    for result in results:
        for finding in result.findings:
            item = finding.to_dict("both")
            rule_id = f"{result.module}/{item['type']}"
            rules.setdefault(rule_id, {"id": rule_id, "name": item["title_en"].replace(" ", ""), "shortDescription": {"text": item["title_en"]}, "fullDescription": {"text": item["description_en"]}, "defaultConfiguration": {"level": levels.get(item["severity"], "warning")}, "help": {"text": item["remediation_en"]}, "properties": {"precision": item["confidence"], "tags": ["security", "defensive", item["type"]]}})
            sarif_results.append({"ruleId": rule_id, "level": levels.get(item["severity"], "warning"), "message": {"text": item["title_en"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": result.target}, "region": {"startLine": 1}}}], "properties": {"severity": item["severity"], "confidence": item["confidence"], "evidence": item["evidence"]}})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "AMF AI Defensive Framework", "semanticVersion": "0.2.0", "rules": list(rules.values())}}, "results": sarif_results}]}, ensure_ascii=False, indent=2)


def to_html(results: Iterable[RunResult], language: str = "both") -> str:
    markdown = html.escape(to_markdown(results, language)).replace("\n", "<br>\n")
    return f"<!doctype html><html lang='ar'><meta charset='utf-8'><title>AMF Report</title><style>body{{font-family:system-ui;max-width:1000px;margin:2rem auto;line-height:1.6}}br{{display:block}}</style><body><pre style='white-space:pre-wrap'>{markdown}</pre></body></html>"


def render(results: Iterable[RunResult], output_format: str, language: str = "both") -> str:
    if output_format == "json":
        return to_json(results, language)
    if output_format == "markdown":
        return to_markdown(results, language)
    if output_format == "html":
        return to_html(results, language)
    if output_format == "sarif":
        return to_sarif(results)
    raise ValueError(f"unsupported report format: {output_format}")
