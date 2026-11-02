from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class IntelEvidence:
    source: str
    source_id: str
    retrieved_at: str
    source_url: str
    license: str
    confidence: str
    raw_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProductMatch:
    cpe_name: str
    confidence: str
    matching_reason: str
    vulnerable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Advisory:
    cve_id: str
    summary: str
    severity: str = "unknown"
    cvss_score: float | None = None
    published_at: str | None = None
    modified_at: str | None = None
    references: tuple[str, ...] = ()
    product_matches: tuple[ProductMatch, ...] = ()
    evidence: IntelEvidence = field(default_factory=lambda: IntelEvidence("unknown", "", "", "", "", "low", ""))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["references"] = list(self.references)
        data["product_matches"] = [item.to_dict() for item in self.product_matches]
        data["evidence"] = self.evidence.to_dict()
        return data
