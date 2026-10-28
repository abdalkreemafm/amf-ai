from __future__ import annotations

import cmd
import shlex
import sys
from pathlib import Path

from .core import RunResult, get_module, list_modules, utc_now
from .reporting import to_json
from .safety import SafetyError, SafetyPolicy, load_allowlist
from . import modules  # noqa: F401 - registers built-in modules


class AMFConsole(cmd.Cmd):
    intro = "AMF Defensive Console. Type help or ? to list commands."
    prompt = "amf > "

    def __init__(self, *, output=None):
        super().__init__(stdin=None, stdout=output or sys.stdout)
        self.selected: str | None = None
        self.options: dict[str, str] = {
            "TARGET": "",
            "ALLOW": "",
            "EXECUTE": "false",
            "TIMEOUT": "5",
        }
        self.last_result: RunResult | None = None

    def emptyline(self):
        return None

    def do_list(self, _line: str):
        """List available defensive modules."""
        for module in list_modules():
            print(f"{module.name}\t{module.description}", file=self.stdout)

    def do_info(self, line: str):
        """Show module information: info <module>"""
        name = line.strip() or self.selected
        if not name:
            print("usage: info <module>", file=self.stdout)
            return
        try:
            module = get_module(name)
        except KeyError as exc:
            print(f"error: {exc}", file=self.stdout)
            return
        print(f"Name: {module.name}\nDescription: {module.description}", file=self.stdout)

    def do_use(self, line: str):
        """Select a module: use <module>"""
        name = line.strip()
        if not name:
            print("usage: use <module>", file=self.stdout)
            return
        try:
            module = get_module(name)
        except KeyError as exc:
            print(f"error: {exc}", file=self.stdout)
            return
        self.selected = module.name
        self.prompt = f"amf ({self.selected}) > "
        print(f"selected {self.selected}", file=self.stdout)

    def do_options(self, _line: str):
        """Show current module options."""
        print("Name     Value", file=self.stdout)
        for key, value in self.options.items():
            print(f"{key:<8} {value or '<empty>'}", file=self.stdout)

    def do_set(self, line: str):
        """Set an option: set TARGET <url>"""
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            print(f"error: {exc}", file=self.stdout)
            return
        if len(parts) < 2 or parts[0].upper() not in self.options:
            print("usage: set TARGET|ALLOW|EXECUTE|TIMEOUT <value>", file=self.stdout)
            return
        key, value = parts[0].upper(), " ".join(parts[1:])
        if key == "EXECUTE" and value.lower() not in {"true", "false", "yes", "no", "1", "0"}:
            print("error: EXECUTE must be true or false", file=self.stdout)
            return
        self.options[key] = value
        print(f"{key} => {value}", file=self.stdout)

    def _run(self, execute: bool):
        if not self.selected:
            print("error: select a module first with use", file=self.stdout)
            return
        target = self.options["TARGET"]
        allow = self.options["ALLOW"]
        if not target or not allow:
            print("error: set TARGET and ALLOW before checking", file=self.stdout)
            return
        try:
            timeout = float(self.options["TIMEOUT"])
            policy = SafetyPolicy(load_allowlist([allow]), execute=execute, timeout=timeout)
            normalized = policy.validate(target)
            module = get_module(self.selected)
        except (SafetyError, KeyError, ValueError) as exc:
            print(f"error: {exc}", file=self.stdout)
            return

        mode = "execute" if execute else "dry-run"
        result = RunResult(module.name, normalized, mode, utc_now())
        if execute:
            result.findings = module.run(normalized, timeout=timeout)
            print(f"completed: {len(result.findings)} finding(s)", file=self.stdout)
        else:
            print("dry-run: no network request was made", file=self.stdout)
        self.last_result = result

    def do_check(self, _line: str):
        """Validate configuration without a network request."""
        self._run(execute=False)

    def do_run(self, _line: str):
        """Run the selected module; requires EXECUTE=true and an allowlisted target."""
        enabled = self.options["EXECUTE"].lower() in {"true", "yes", "1"}
        if not enabled:
            print("run blocked: set EXECUTE true, or use check for dry-run", file=self.stdout)
            return
        self._run(execute=True)

    def do_report(self, line: str):
        """Print or save the last result: report [path.json]"""
        if not self.last_result:
            print("no result available", file=self.stdout)
            return
        payload = to_json([self.last_result])
        path = line.strip()
        if path:
            Path(path).write_text(payload + "\n", encoding="utf-8")
            print(f"report: {path}", file=self.stdout)
        else:
            print(payload, file=self.stdout)

    def do_clear(self, _line: str):
        """Clear the terminal using ANSI control sequences."""
        print("\033[2J\033[H", end="", file=self.stdout)

    def do_exit(self, _line: str):
        """Exit the console."""
        return True

    do_quit = do_exit
    do_EOF = do_exit


def start_console() -> int:
    AMFConsole().cmdloop()
    return 0
