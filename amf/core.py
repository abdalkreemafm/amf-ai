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


@dataclass
class RunResult:
    module: str
    target: str
    mode: str
    started_at: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at,
            "findings": [asdict(item) for item in self.findings],
            "error": self.error,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Module:
    name = ""
    description = ""

    def run(self, target: str, *, timeout: float = 5.0) -> list[Finding]:
        raise NotImplementedError


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
