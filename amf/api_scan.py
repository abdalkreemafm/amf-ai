from __future__ import annotations

from threading import Event
from typing import Any, Callable

from . import modules  # noqa: F401
from .core import RunResult, utc_now
from .profiles import profile_modules
from .safety import SafetyPolicy, load_allowlist, require_authorized_execution

ProgressCallback = Callable[[int, int, str], None]


def run_scan(payload: dict[str, Any], progress: ProgressCallback | None = None, cancel_event: Event | None = None) -> list[RunResult]:
    if not isinstance(payload, dict):
        raise ValueError("request must be a JSON object")
    target = payload.get("target")
    if not isinstance(target, str) or not target:
        raise ValueError("target is required")
    allow = payload.get("allow", [])
    if not isinstance(allow, list) or not all(isinstance(item, str) for item in allow):
        raise ValueError("allow must be a list of URLs")
    execute = bool(payload.get("execute", False))
    require_authorized_execution(execute, bool(payload.get("confirm_authorized_use", False)))
    timeout = float(payload.get("timeout", 5.0))
    profile = payload.get("profile", "full")
    if not isinstance(profile, str):
        raise ValueError("profile must be a string")
    policy = SafetyPolicy(load_allowlist(allow), execute=execute, timeout=timeout)
    normalized = policy.validate(target)
    modules_to_run = profile_modules(profile)
    results: list[RunResult] = []
    for index, module in enumerate(modules_to_run, start=1):
        if cancel_event and cancel_event.is_set():
            raise CancelledError()
        if progress:
            progress(index - 1, len(modules_to_run), module.name)
        result = RunResult(module.name, normalized, "execute" if execute else "dry-run", utc_now())
        if execute:
            try:
                result.findings = module.run(normalized, timeout=timeout)
            except Exception as exc:
                result.error = str(exc)
        results.append(result)
        if progress:
            progress(index, len(modules_to_run), module.name)
    return results


class CancelledError(Exception):
    pass
