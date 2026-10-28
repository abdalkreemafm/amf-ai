from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


@dataclass(frozen=True)
class Finding:
    module: str
    title: str
    severity: str
    description: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    finding_type: str = "security-misconfiguration"
    confidence: str = "high"
    title_ar: str = ""
    title_en: str = ""
    description_ar: str = ""
    description_en: str = ""
    impact_ar: str = ""
    impact_en: str = ""
    remediation_ar: str = ""
    remediation_en: str = ""

    def to_dict(self, language: str = "both") -> dict[str, Any]:
        data = asdict(self)
        data["type"] = data.pop("finding_type")
        data["severity"] = self.severity.lower()
        data["confidence"] = self.confidence.lower()
        data["title_ar"] = self.title_ar or self.title
        data["title_en"] = self.title_en or self.title
        data["description_ar"] = self.description_ar or self.description
        data["description_en"] = self.description_en or self.description
        data["remediation_ar"] = self.remediation_ar or self.remediation
        data["remediation_en"] = self.remediation_en or self.remediation
        if language == "ar":
            for key in ("title", "description", "remediation"):
                data[key] = data[f"{key}_ar"]
        elif language == "en":
            for key in ("title", "description", "remediation"):
                data[key] = data[f"{key}_en"]
        return data


@dataclass
class RunResult:
    module: str
    target: str
    mode: str
    started_at: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self, language: str = "both") -> dict[str, Any]:
        return {"module": self.module, "target": self.target, "mode": self.mode, "started_at": self.started_at, "findings": [item.to_dict(language) for item in self.findings], "error": self.error}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Module:
    name = ""
    description = ""
    category = "scanner"
    risk = "passive"
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        raise NotImplementedError

    def metadata(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "category": self.category, "risk": self.risk, "tags": list(self.tags), "references": list(self.references)}


_REGISTRY: dict[str, Callable[[], Module]] = {}


def register(module_factory: Callable[[], Module]) -> Callable[[], Module]:
    instance = module_factory()
    if not instance.name:
        raise ValueError("module name cannot be empty")
    if instance.name in _REGISTRY:
        raise ValueError(f"duplicate module: {instance.name}")
    _REGISTRY[instance.name] = module_factory
    return module_factory


def get_module(name: str) -> Module:
    try:
        return _REGISTRY[name]()
    except KeyError as exc:
        raise KeyError(f"unknown module: {name}") from exc


def list_modules() -> list[Module]:
    return [_REGISTRY[name]() for name in sorted(_REGISTRY)]


def search_modules(query: str = "", category: str | None = None) -> list[Module]:
    needle = query.casefold().strip()
    modules = list_modules()
    return [module for module in modules if (not category or module.category == category) and (not needle or needle in (module.name + " " + module.description + " " + " ".join(module.tags)).casefold())]
