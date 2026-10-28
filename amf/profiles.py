from __future__ import annotations

from .core import Module, list_modules


PROFILES: dict[str, dict[str, object]] = {
    "quick": {"description": "Core HTTP and TLS posture checks", "modules": ["scanner/http_headers", "scanner/http_cookies", "scanner/http_redirects", "scanner/tls_certificate"]},
    "web": {"description": "Web response and server configuration review", "modules": ["scanner/http_headers", "scanner/http_cookies", "scanner/http_cors", "scanner/http_redirects", "scanner/http_sql_errors", "scanner/http_xss_surface", "scanner/sensitive_files", "scanner/server_misconfiguration"]},
    "discovery": {"description": "Passive asset and service discovery", "modules": ["scanner/dns_basic", "scanner/dns_email_security", "scanner/http_headers", "scanner/tls_certificate"]},
    "full": {"description": "All registered non-exploitative modules", "modules": []},
}


def profile_modules(name: str) -> list[Module]:
    try:
        profile = PROFILES[name]
    except KeyError as exc:
        raise KeyError(f"unknown profile: {name}") from exc
    names = profile["modules"]
    if not names:
        return list_modules()
    by_name = {module.name: module for module in list_modules()}
    return [by_name[module_name] for module_name in names if module_name in by_name]
