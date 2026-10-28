from __future__ import annotations

from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class HTTPDocument:
    status: int
    headers: object
    body: str


def fetch_document(target: str, *, timeout: float = 5.0, max_bytes: int = 1_000_000) -> HTTPDocument | str:
    request = Request(target, method="GET", headers={"User-Agent": "AMF-Defensive/0.1", "Accept": "text/html, text/plain, application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(max_bytes + 1)
            return HTTPDocument(response.status, response.headers, raw[:max_bytes].decode("utf-8", errors="replace"))
    except HTTPError as exc:
        raw = exc.read(max_bytes + 1)
        return HTTPDocument(exc.code, exc.headers, raw[:max_bytes].decode("utf-8", errors="replace"))
    except (URLError, TimeoutError, OSError) as exc:
        return str(exc)
