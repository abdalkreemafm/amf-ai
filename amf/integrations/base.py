from __future__ import annotations

from dataclasses import dataclass
import shutil
import subprocess
from typing import Sequence

from ..core import Finding


@dataclass(frozen=True)
class ToolInfo:
    name: str
    executable: str
    description: str
    capabilities: tuple[str, ...]
    optional: bool = True
    version_args: tuple[str, ...] = ("--version",)


class ToolAdapter:
    info: ToolInfo

    def available(self) -> bool:
        return shutil.which(self.info.executable) is not None

    def version(self) -> str | None:
        path = shutil.which(self.info.executable)
        if not path:
            return None
        try:
            result = subprocess.run([path, *self.info.version_args], capture_output=True, text=True, timeout=3, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        line = (result.stdout or result.stderr).splitlines()
        return line[0][:160] if line else None

    def run(self, target: str, *, timeout: float) -> list[Finding]:
        raise NotImplementedError


def run_command(executable: str, args: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    path = shutil.which(executable)
    if not path:
        raise FileNotFoundError(f"optional tool not installed: {executable}")
    try:
        return subprocess.run([path, *args], capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"tool timed out after {timeout:g}s: {executable}") from exc
