from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse


class SafetyError(ValueError):
    pass


@dataclass(frozen=True)
class SafetyPolicy:
    allowed_targets: frozenset[str]
    execute: bool = False
    timeout: float = 5.0

    def validate(self, target: str) -> str:
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SafetyError("target must be an absolute http(s) URL")
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
        if normalized.rstrip("/") not in {item.rstrip("/") for item in self.allowed_targets}:
            raise SafetyError("target is not present in the configured allowlist")
        if self.timeout <= 0 or self.timeout > 60:
            raise SafetyError("timeout must be between 0 and 60 seconds")
        return normalized.rstrip("/")


def load_allowlist(values: list[str]) -> frozenset[str]:
    normalized: set[str] = set()
    for value in values:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SafetyError(f"invalid allowlist target: {value}")
        host = parsed.hostname
        if host not in {"localhost", "127.0.0.1", "::1"}:
            try:
                ip_address(host)
            except ValueError:
                pass
        normalized.add(value.rstrip("/"))
    return frozenset(normalized)
