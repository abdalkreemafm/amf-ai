from __future__ import annotations

import json
import sqlite3
from typing import Iterable

from .models import Advisory, IntelEvidence, ProductMatch


class IntelCache:
    def __init__(self, path: str = "~/.cache/amf-ai/intel.sqlite3") -> None:
        self.path = path
        if path != ":memory:":
            from pathlib import Path
            expanded = Path(path).expanduser()
            expanded.parent.mkdir(parents=True, exist_ok=True)
            self.path = str(expanded)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sources (name TEXT PRIMARY KEY, retrieved_at TEXT NOT NULL, metadata TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS advisories (cve_id TEXT PRIMARY KEY, payload TEXT NOT NULL, modified_at TEXT);
            CREATE TABLE IF NOT EXISTS cpe_matches (cve_id TEXT NOT NULL, cpe_name TEXT NOT NULL, PRIMARY KEY (cve_id, cpe_name));
            CREATE TABLE IF NOT EXISTS sync_state (source TEXT PRIMARY KEY, cursor TEXT NOT NULL);
            """
        )
        self.connection.commit()

    def save_advisories(self, advisories: Iterable[Advisory]) -> None:
        advisories = list(advisories)
        rows = [(item.cve_id, json.dumps(item.to_dict(), ensure_ascii=False), item.modified_at) for item in advisories]
        if not rows:
            return
        with self.connection:
            self.connection.executemany("INSERT OR REPLACE INTO advisories(cve_id, payload, modified_at) VALUES (?, ?, ?)", rows)
            self.connection.executemany(
                "DELETE FROM cpe_matches WHERE cve_id = ?",
                [(row[0],) for row in rows],
            )
            for advisory in advisories:
                self.connection.executemany(
                    "INSERT OR REPLACE INTO cpe_matches(cve_id, cpe_name) VALUES (?, ?)",
                    [(advisory.cve_id, match.cpe_name) for match in advisory.product_matches],
                )

    def get_advisory(self, cve_id: str) -> Advisory | None:
        row = self.connection.execute("SELECT payload FROM advisories WHERE cve_id = ?", (cve_id,)).fetchone()
        if not row:
            return None
        return _advisory_from_dict(json.loads(row[0]))

    def set_cursor(self, source: str, cursor: str) -> None:
        with self.connection:
            self.connection.execute("INSERT OR REPLACE INTO sync_state(source, cursor) VALUES (?, ?)", (source, cursor))

    def get_cursor(self, source: str) -> str | None:
        row = self.connection.execute("SELECT cursor FROM sync_state WHERE source = ?", (source,)).fetchone()
        return row[0] if row else None


def _advisory_from_dict(data: dict) -> Advisory:
    evidence = data["evidence"]
    return Advisory(
        cve_id=data["cve_id"], summary=data["summary"], severity=data.get("severity", "unknown"), cvss_score=data.get("cvss_score"),
        published_at=data.get("published_at"), modified_at=data.get("modified_at"), references=tuple(data.get("references", [])),
        product_matches=tuple(ProductMatch(**item) for item in data.get("product_matches", [])),
        evidence=IntelEvidence(**evidence),
    )
