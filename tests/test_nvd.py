import hashlib
import json
import unittest
from datetime import datetime, timezone

from amf.intel.cache import IntelCache
from amf.intel.nvd_provider import NVDProvider, NVDProviderError


class FakeResponse:
    def __init__(self, status, payload, headers=None):
        self.status = status
        self._payload = payload
        self.headers = headers or {}

    def read(self, _limit=None):
        if isinstance(self._payload, bytes):
            return self._payload
        return json.dumps(self._payload).encode()


class NVDProviderTests(unittest.TestCase):
    def setUp(self):
        self.cache = IntelCache(":memory:")
        self.requests = []

    def provider(self, responses):
        def transport(url, headers, timeout):
            self.requests.append((url, headers, timeout))
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        return NVDProvider(cache=self.cache, transport=transport, sleep=lambda _seconds: None, min_interval=0, timeout=2)

    def test_fetch_paginates_and_normalizes_provenance(self):
        payload = lambda cve: {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [{"cve": {
                "id": cve,
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Example issue"}],
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/" + cve}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*", "vulnerable": True}]}]}],
            }}],
        }
        provider = self.provider([FakeResponse(200, payload("CVE-2024-0001"))])
        advisories = provider.fetch(cpe_name="cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*")
        self.assertEqual(advisories[0].cve_id, "CVE-2024-0001")
        self.assertEqual(advisories[0].severity, "high")
        self.assertEqual(advisories[0].evidence.source, "nvd")
        self.assertEqual(advisories[0].evidence.source_id, "CVE-2024-0001")
        self.assertTrue(advisories[0].evidence.raw_hash)
        self.assertEqual(len(self.requests), 1)

    def test_rate_limit_retries_and_keeps_api_key_out_of_urls(self):
        provider = self.provider([FakeResponse(429, {"message": "slow down"}, {"Retry-After": "0"}), FakeResponse(200, {"totalResults": 0, "vulnerabilities": []})])
        provider.api_key = "secret-api-key-value"
        self.assertEqual(provider.fetch(), [])
        self.assertEqual(len(self.requests), 2)
        self.assertNotIn("secret-api-key-value", self.requests[0][0])
        self.assertEqual(self.requests[0][1]["apiKey"], "secret-api-key-value")

    def test_cache_is_used_when_network_is_unavailable(self):
        provider = self.provider([FakeResponse(200, {"totalResults": 0, "vulnerabilities": []})])
        advisory = provider._normalize({"vulnerabilities": [{"cve": {"id": "CVE-2024-0002", "descriptions": [{"lang": "en", "value": "Cached"}]}}]}, source_url="fixture", raw_hash="fixture")[0]
        self.cache.save_advisories([advisory])
        offline = NVDProvider(cache=self.cache, transport=lambda *_args: (_ for _ in ()).throw(TimeoutError("offline")), sleep=lambda _seconds: None, min_interval=0)
        self.assertEqual(offline.fetch(cve_id="CVE-2024-0002")[0].cve_id, "CVE-2024-0002")

    def test_feed_checksum_and_incremental_cursor_are_persisted(self):
        provider = self.provider([])
        feed = json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2024-0003", "descriptions": [{"lang": "en", "value": "Feed"}]}}]}).encode()
        digest = hashlib.sha256(feed).hexdigest()
        imported = provider.import_feed(feed, expected_sha256=digest, cursor="2024-02-01T00:00:00Z")
        self.assertEqual(imported, 1)
        self.assertEqual(self.cache.get_cursor("nvd"), "2024-02-01T00:00:00Z")
        with self.assertRaises(NVDProviderError):
            provider.import_feed(feed, expected_sha256="0" * 64)

    def test_incremental_sync_uses_saved_cursor_and_advances_it(self):
        provider = self.provider([FakeResponse(200, {"totalResults": 0, "vulnerabilities": []})])
        self.cache.set_cursor("nvd", "2024-02-01T00:00:00Z")
        provider.sync_modified(end="2024-02-02T00:00:00Z")
        self.assertIn("lastModStartDate=2024-02-01T00%3A00%3A00Z", self.requests[0][0])
        self.assertIn("lastModEndDate=2024-02-02T00%3A00%3A00Z", self.requests[0][0])
        self.assertEqual(self.cache.get_cursor("nvd"), "2024-02-02T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
