from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from .core import RunResult, utc_now
from .intel.models import Advisory


@dataclass(frozen=True)
class Asset:
    identifier: str
    kind: str = "url"
    confidence: str = "high"
    sources: tuple[str, ...] = ()
    observed_at: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["sources"] = list(self.sources)
        return data


@dataclass(frozen=True)
class Observation:
    asset: str
    source: str
    kind: str
    value: str
    confidence: str
    observed_at: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationSummary:
    assets: list[Asset] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    duplicate_groups: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"assets": [item.to_dict() for item in self.assets], "observations": [item.to_dict() for item in self.observations], "duplicate_groups": self.duplicate_groups}


def _asset_kind(identifier: str) -> str:
    parsed = urlparse(identifier)
    return "hostname" if parsed.hostname and not parsed.path.strip("/") else "url"


def correlate_results(results: list[RunResult]) -> CorrelationSummary:
    assets_by_id: dict[str, Asset] = {}
    observations_by_key: dict[tuple[str, str, str], Observation] = {}
    source_sets: dict[tuple[str, str, str], set[str]] = {}
    duplicates = 0
    for result in results:
        asset_id = result.target
        existing = assets_by_id.get(asset_id)
        sources = set(existing.sources if existing else ())
        sources.add(result.module)
        assets_by_id[asset_id] = Asset(asset_id, _asset_kind(asset_id), "high", tuple(sorted(sources)), existing.observed_at if existing else result.started_at)
        for finding in result.findings:
            key = (asset_id, finding.finding_type, finding.title_en or finding.title)
            observation = Observation(asset_id, result.module, finding.finding_type, finding.title_en or finding.title, finding.confidence.lower(), result.started_at, {"severity": finding.severity.lower(), "evidence_keys": sorted(finding.evidence)})
            if key in observations_by_key:
                duplicates += 1
                source_sets[key].add(result.module)
                continue
            observations_by_key[key] = observation
            source_sets[key] = {result.module}
    observations = []
    for key, observation in observations_by_key.items():
        sources = sorted(source_sets[key])
        observations.append(Observation(observation.asset, ",".join(sources), observation.kind, observation.value, observation.confidence, observation.observed_at, {**observation.evidence, "sources": sources}))
    return CorrelationSummary(list(assets_by_id.values()), observations, duplicates)


def correlate_intel(asset: str, advisories: list[Advisory]) -> CorrelationSummary:
    """Attach external advisories to one asset without treating them as confirmed findings."""
    asset_item = Asset(asset, _asset_kind(asset), "high", ("nvd",), utc_now())
    observations: list[Observation] = []
    seen: set[str] = set()
    for advisory in advisories:
        if advisory.cve_id in seen:
            continue
        seen.add(advisory.cve_id)
        confidence = "medium" if advisory.product_matches else "low"
        matching_reason = advisory.product_matches[0].matching_reason if advisory.product_matches else "No explicit CPE match was supplied"
        observations.append(Observation(
            asset,
            advisory.evidence.source,
            "potential-match",
            advisory.cve_id,
            confidence,
            advisory.evidence.retrieved_at,
            {
                "source": advisory.evidence.source,
                "source_id": advisory.evidence.source_id,
                "source_url": advisory.evidence.source_url,
                "license": advisory.evidence.license,
                "retrieved_at": advisory.evidence.retrieved_at,
                "raw_hash": advisory.evidence.raw_hash,
                "summary": advisory.summary,
                "severity": advisory.severity,
                "cvss_score": advisory.cvss_score,
                "references": list(advisory.references),
                "cpe_matches": [item.to_dict() for item in advisory.product_matches],
                "matching_reason": matching_reason,
                "review_status": "needs-review",
            },
        ))
    return CorrelationSummary([asset_item], observations, len(advisories) - len(observations))
