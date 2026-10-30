from __future__ import annotations

from .base import ToolAdapter, ToolInfo
from .dns_local import LocalDNSAdapter
from .nmap_limited import LimitedNmapAdapter
from .openssl_tls import OpenSSLTLSAdapter

ADAPTERS: dict[str, ToolAdapter] = {
    "dns": LocalDNSAdapter(),
    "openssl": OpenSSLTLSAdapter(),
    "nmap": LimitedNmapAdapter(),
}


def tool_catalog() -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for adapter in ADAPTERS.values():
        items.append({"name": adapter.info.name, "executable": adapter.info.executable, "description": adapter.info.description, "capabilities": list(adapter.info.capabilities), "available": adapter.available(), "version": adapter.version()})
    return items
