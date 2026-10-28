from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from . import __version__
from .core import RunResult, get_module, list_modules, utc_now
from .reporting import to_json
from .safety import SafetyError, SafetyPolicy, load_allowlist
from .console import start_console
from . import modules  # noqa: F401 - registers built-in modules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="amf", description="AMF defensive security assessment framework")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="list available modules")
    info = sub.add_parser("info", help="show module information")
    info.add_argument("module")
    check = sub.add_parser("check", help="run one non-exploitative check")
    check.add_argument("module")
    check.add_argument("target")
    check.add_argument("--allow", action="append", default=[], help="explicitly allow this exact URL")
    check.add_argument("--execute", action="store_true", help="enable the network request after allowlist validation")
    check.add_argument("--timeout", type=float, default=5.0)
    check.add_argument("--report", type=Path)
    sub.add_parser("doctor", help="show runtime and safety defaults")
    sub.add_parser("console", help="open the interactive Termux console")
    return parser


def run_check(args: argparse.Namespace) -> int:
    try:
        allowlist = load_allowlist(args.allow)
        policy = SafetyPolicy(allowlist, execute=args.execute, timeout=args.timeout)
        target = policy.validate(args.target)
        module = get_module(args.module)
    except (SafetyError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not policy.execute:
        result = RunResult(module.name, target, "dry-run", utc_now())
        print("dry-run: no network request was made")
    else:
        result = RunResult(module.name, target, "execute", utc_now())
        result.findings = module.run(target, timeout=policy.timeout)
        print(f"completed: {len(result.findings)} finding(s)")

    payload = to_json([result])
    if args.report:
        args.report.write_text(payload + "\n", encoding="utf-8")
        print(f"report: {args.report}")
    else:
        print(payload)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        return start_console()
    if args.command == "list":
        for module in list_modules():
            print(f"{module.name}\t{module.description}")
        return 0
    if args.command == "info":
        try:
            module = get_module(args.module)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"name": module.name, "description": module.description}, ensure_ascii=False, indent=2))
        return 0
    if args.command == "doctor":
        print(json.dumps({"version": __version__, "python": platform.python_version(), "default_mode": "dry-run", "network_policy": "explicit allowlist required"}, ensure_ascii=False, indent=2))
        return 0
    if args.command == "console":
        return start_console()
    return run_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
