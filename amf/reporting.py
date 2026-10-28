from __future__ import annotations

import json
from typing import Iterable

from .core import RunResult


def to_json(results: Iterable[RunResult]) -> str:
    return json.dumps([result.to_dict() for result in results], ensure_ascii=False, indent=2)
