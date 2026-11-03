from __future__ import annotations

import statistics
import sys
import timeit
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from amf.correlation import correlate_intel
from amf.intel.models import Advisory, IntelEvidence, ProductMatch
from amf.intel.nvd_provider import NVDProvider


def main() -> None:
    advisories = [
        Advisory(
            f"CVE-2024-{index:04d}",
            "fixture issue",
            "high",
            8.8,
            product_matches=(ProductMatch("cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*", "medium", "fixture CPE"),),
            evidence=IntelEvidence("nvd", f"CVE-2024-{index:04d}", "2024-01-01T00:00:00Z", "fixture", "NVD API/data feeds", "medium", "hash"),
        )
        for index in range(1000)
    ]
    payload = {
        "vulnerabilities": [
            {"cve": {"id": f"CVE-2024-{index:04d}", "descriptions": [{"lang": "en", "value": "fixture"}], "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"}]}]}]}}
            for index in range(500)
        ]
    }
    provider = NVDProvider(transport=lambda *_: None, min_interval=0)
    correlation = timeit.repeat(lambda: correlate_intel("https://lab.local", advisories), repeat=5, number=1)
    normalization = timeit.repeat(lambda: provider._normalize(payload, source_url="fixture", raw_hash="hash"), repeat=5, number=1)
    print(f"correlation_1000_median_ms={statistics.median(correlation) * 1000:.2f}")
    print(f"normalize_500_median_ms={statistics.median(normalization) * 1000:.2f}")


if __name__ == "__main__":
    main()
