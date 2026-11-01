from __future__ import annotations

from dataclasses import dataclass
import json
import os
import secrets
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from ..safety import SafetyError


READ_ONLY_METHODS = frozenset({"core.version", "module.search", "module.info", "module.options"})
SAFE_MODULE_TYPES = frozenset({"auxiliary", "exploit"})
MAX_RESPONSE_BYTES = 1_048_576


@dataclass(frozen=True)
class MetasploitRPCConfig:
    url: str
    token: str
    timeout: float = 5.0

    def __post_init__(self) -> None:
        validate_rpc_endpoint(self.url)
        if len(self.token) < 16:
            raise SafetyError("AMF_MSF_RPC_TOKEN must be at least 16 characters")
        if self.timeout <= 0 or self.timeout > 30:
            raise SafetyError("AMF_MSF_RPC_TIMEOUT must be between 0 and 30 seconds")

    @classmethod
    def from_environment(cls) -> "MetasploitRPCConfig":
        url = os.environ.get("AMF_MSF_RPC_URL", "http://127.0.0.1:8081/api/v1/json-rpc")
        token = os.environ.get("AMF_MSF_RPC_TOKEN", "")
        try:
            timeout = float(os.environ.get("AMF_MSF_RPC_TIMEOUT", "5"))
        except ValueError as exc:
            raise SafetyError("AMF_MSF_RPC_TIMEOUT must be a number") from exc
        validate_rpc_endpoint(url)
        if len(token) < 16:
            raise SafetyError("AMF_MSF_RPC_TOKEN must be at least 16 characters")
        if timeout <= 0 or timeout > 30:
            raise SafetyError("AMF_MSF_RPC_TIMEOUT must be between 0 and 30 seconds")
        return cls(url=url, token=token, timeout=timeout)


def validate_rpc_endpoint(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SafetyError("AMF_MSF_RPC_URL must be an absolute http(s) URL")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SafetyError("Metasploit RPC must use HTTPS when it is not bound to loopback")


def validate_module_reference(module_type: str, fullname: str) -> None:
    if module_type not in SAFE_MODULE_TYPES:
        raise SafetyError("only auxiliary and exploit metadata are allowed")
    if not fullname or len(fullname) > 200 or fullname.startswith("/") or ".." in fullname:
        raise SafetyError("invalid Metasploit module reference")
    if any(char.isspace() for char in fullname):
        raise SafetyError("module fullname must not contain whitespace")


class MetasploitMetadataClient:
    """Read-only JSON-RPC client; it never exposes module.execute or session methods."""

    def __init__(self, config: MetasploitRPCConfig | None = None) -> None:
        self.config = config or MetasploitRPCConfig.from_environment()

    def call(self, method: str, params: list[Any]) -> Any:
        if method not in READ_ONLY_METHODS:
            raise SafetyError(f"Metasploit RPC method is blocked: {method}")
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": secrets.token_hex(8)}).encode("utf-8")
        request = Request(
            self.config.url,
            data=body,
            method="POST",
            headers={"Authorization": f"Bearer {self.config.token}", "Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=self.config.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except Exception as exc:
            raise ConnectionError(f"Metasploit RPC request failed: {type(exc).__name__}") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SafetyError("Metasploit RPC response is too large")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SafetyError("Metasploit RPC returned invalid JSON") from exc
        if "error" in payload:
            error = payload["error"]
            raise SafetyError(f"Metasploit RPC error: {error.get('message', 'unknown error')}")
        return payload.get("result")

    def version(self) -> Any:
        return self.call("core.version", [])

    def search(self, query: str = "") -> Any:
        if len(query) > 128:
            raise SafetyError("Metasploit search query is too long")
        return self.call("module.search", [query])

    def info(self, module_type: str, fullname: str) -> Any:
        validate_module_reference(module_type, fullname)
        return self.call("module.info", [module_type, fullname])

    def options(self, module_type: str, fullname: str) -> Any:
        validate_module_reference(module_type, fullname)
        return self.call("module.options", [module_type, fullname])


def metasploit_status() -> dict[str, object]:
    configured = bool(os.environ.get("AMF_MSF_RPC_TOKEN"))
    return {
        "name": "metasploit-rpc-metadata",
        "configured": configured,
        "url": os.environ.get("AMF_MSF_RPC_URL", "http://127.0.0.1:8081/api/v1/json-rpc"),
        "capabilities": sorted(READ_ONLY_METHODS),
        "execution": "metadata-only",
    }
