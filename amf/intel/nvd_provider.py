from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from threading import Lock
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .cache import IntelCache
from .models import Advisory, IntelEvidence, ProductMatch


class NVDProviderError(RuntimeError):
    pass


class NVDProvider:
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."

    def __init__(self, cache: IntelCache | None = None, *, api_key: str | None = None, transport=None, sleep=time.sleep, min_interval: float | None = None, timeout: float = 10.0, max_retries: int = 3) -> None:
        self.cache = cache or IntelCache()
        self.api_key = api_key if api_key is not None else os.environ.get("AMF_NVD_API_KEY", "")
        self.transport = transport or self._default_transport
        self.sleep = sleep
        self.timeout = timeout
        self.max_retries = max_retries
        self.min_interval = min_interval if min_interval is not None else (0.6 if self.api_key else 6.0)
        self._rate_lock = Lock()
        self._last_request = 0.0

    @staticmethod
    def _default_transport(url: str, headers: dict[str, str], timeout: float):
        return urlopen(Request(url, headers=headers), timeout=timeout)

    def _wait_for_rate_limit(self) -> None:
        with self._rate_lock:
            delay = self.min_interval - (time.monotonic() - self._last_request)
            if delay > 0:
                self.sleep(delay)
            self._last_request = time.monotonic()

    def _request(self, params: dict[str, str | int]) -> tuple[dict, str, str]:
        query = urlencode(params)
        url = f"{self.API_URL}?{query}" if query else self.API_URL
        headers = {"Accept": "application/json", "User-Agent": "AMF-AI/0.3.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        for attempt in range(self.max_retries + 1):
            self._wait_for_rate_limit()
            try:
                response = self.transport(url, headers, self.timeout)
                status = getattr(response, "status", 200)
                raw = response.read(25 * 1024 * 1024)
                if status in (429, 503):
                    if attempt >= self.max_retries:
                        raise NVDProviderError(f"NVD request rate-limited after {attempt + 1} attempts")
                    retry_after = float(getattr(response, "headers", {}).get("Retry-After", "1"))
                    self.sleep(max(0.0, retry_after))
                    continue
                if status >= 400:
                    raise NVDProviderError(f"NVD request failed with HTTP {status}")
                return json.loads(raw), url, hashlib.sha256(raw).hexdigest()
            except NVDProviderError:
                raise
            except Exception as exc:
                if attempt >= self.max_retries:
                    raise NVDProviderError(f"NVD request failed: {exc}") from exc
                self.sleep(min(2 ** attempt, 8))
        raise NVDProviderError("NVD request failed")

    def fetch(self, *, cve_id: str | None = None, cpe_name: str | None = None, last_mod_start: str | None = None, last_mod_end: str | None = None, page_size: int = 2000) -> list[Advisory]:
        if cve_id:
            cached = self.cache.get_advisory(cve_id)
            if cached:
                return [cached]
        params: dict[str, str | int] = {"startIndex": 0, "resultsPerPage": min(max(page_size, 1), 2000)}
        if cve_id:
            params["cveIds"] = cve_id
        if cpe_name:
            params["cpeName"] = cpe_name
        if last_mod_start:
            params["lastModStartDate"] = last_mod_start
        if last_mod_end:
            params["lastModEndDate"] = last_mod_end
        advisories: list[Advisory] = []
        try:
            while True:
                payload, source_url, raw_hash = self._request(params)
                page = self._normalize(payload, source_url=source_url, raw_hash=raw_hash)
                advisories.extend(page)
                total = int(payload.get("totalResults", len(advisories)))
                if not page or len(advisories) >= total:
                    break
                params["startIndex"] = int(params["startIndex"]) + int(payload.get("resultsPerPage", len(page)))
            self.cache.save_advisories(advisories)
            return advisories
        except NVDProviderError:
            if cve_id:
                cached = self.cache.get_advisory(cve_id)
                if cached:
                    return [cached]
            raise

    def sync_modified(self, *, start: str | None = None, end: str | None = None, page_size: int = 2000) -> list[Advisory]:
        start = start or self.cache.get_cursor("nvd")
        end = end or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        advisories = self.fetch(last_mod_start=start, last_mod_end=end, page_size=page_size)
        self.cache.set_cursor("nvd", end)
        return advisories

    def import_feed(self, raw: bytes, *, expected_sha256: str, cursor: str | None = None) -> int:
        actual = hashlib.sha256(raw).hexdigest()
        if actual.lower() != expected_sha256.lower():
            raise NVDProviderError("NVD feed SHA-256 checksum mismatch")
        payload = json.loads(raw)
        advisories = self._normalize(payload, source_url="https://nvd.nist.gov/vuln/data-feeds", raw_hash=actual)
        self.cache.save_advisories(advisories)
        if cursor:
            self.cache.set_cursor("nvd", cursor)
        return len(advisories)

    def _normalize(self, payload: dict, *, source_url: str, raw_hash: str) -> list[Advisory]:
        retrieved_at = datetime.now(timezone.utc).isoformat()
        results: list[Advisory] = []
        for wrapper in payload.get("vulnerabilities", []):
            cve = wrapper.get("cve", wrapper)
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions", [])
            summary = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            metric = next(iter(metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []) or []), {})
            cvss = metric.get("cvssData", {})
            references = tuple(item.get("url", "") for item in cve.get("references", []) if item.get("url"))
            matches: list[ProductMatch] = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria")
                        if criteria:
                            matches.append(ProductMatch(criteria, "medium", "CPE criteria supplied by NVD", bool(match.get("vulnerable", True))))
            results.append(Advisory(
                cve_id=cve_id, summary=summary, severity=str(cvss.get("baseSeverity", "unknown")).lower(), cvss_score=cvss.get("baseScore"),
                published_at=cve.get("published"), modified_at=cve.get("lastModified"), references=references, product_matches=tuple(matches),
                evidence=IntelEvidence("nvd", cve_id, retrieved_at, source_url, "NVD API/data feeds", "medium" if matches else "low", raw_hash),
            ))
        return results
