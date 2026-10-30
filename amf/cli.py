from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from . import __version__
from .core import RunResult, get_module, list_modules, search_modules, utc_now
from .profiles import PROFILES, profile_modules
from .reporting import render
from .safety import SafetyError, SafetyPolicy, load_allowlist
from .console import start_console
from . import modules  # noqa: F401 - registers built-in modules
from .integrations import ADAPTERS, tool_catalog

SEVERITY_WEIGHTS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def evaluate_ci_fail_on(results: list[RunResult], threshold: str | None) -> int:
    if not threshold:
        return 0
    limit = SEVERITY_WEIGHTS[threshold]
    matches = [(result.module, finding.title, finding.severity) for result in results for finding in result.findings if SEVERITY_WEIGHTS.get(finding.severity.lower(), 0) >= limit]
    if not matches:
        return 0
    print(f"[CI/CD] {len(matches)} finding(s) meet --fail-on {threshold}", file=sys.stderr)
    for module, title, severity in matches[:5]:
        print(f"- [{severity.upper()}] {module}: {title}", file=sys.stderr)
    return 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="amf", description="AMF defensive security assessment framework")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="list available modules")
    search = sub.add_parser("search", help="search the module catalog")
    search.add_argument("query", nargs="?", default="")
    search.add_argument("--category")
    sub.add_parser("profiles", help="list safe audit profiles")
    sub.add_parser("tools", help="show optional external tool availability")
    info = sub.add_parser("info", help="show module information")
    info.add_argument("module")
    check = sub.add_parser("check", help="run one non-exploitative check")
    check.add_argument("module")
    check.add_argument("target")
    check.add_argument("--allow", action="append", default=[], help="explicitly allow this exact URL")
    check.add_argument("--execute", action="store_true", help="enable the network request after allowlist validation")
    check.add_argument("--timeout", type=float, default=5.0)
    check.add_argument("--report", type=Path)
    check.add_argument("--format", choices=("json", "markdown", "html", "sarif"), default="json")
    check.add_argument("--language", choices=("ar", "en", "both"), default="both")
    check.add_argument("--fail-on", choices=tuple(SEVERITY_WEIGHTS), help="exit 3 when a finding reaches this severity")
    full = sub.add_parser("full", help="run all registered non-exploitative checks")
    full.add_argument("target")
    full.add_argument("--allow", action="append", default=[])
    full.add_argument("--execute", action="store_true")
    full.add_argument("--timeout", type=float, default=5.0)
    full.add_argument("--report", type=Path)
    full.add_argument("--format", choices=("json", "markdown", "html", "sarif"), default="json")
    full.add_argument("--language", choices=("ar", "en", "both"), default="both")
    full.add_argument("--profile", choices=tuple(PROFILES), default="full")
    full.add_argument("--fail-on", choices=tuple(SEVERITY_WEIGHTS), help="exit 3 when a finding reaches this severity")
    external = sub.add_parser("external", help="run one explicitly selected external adapter")
    external.add_argument("tool", choices=tuple(ADAPTERS))
    external.add_argument("target")
    external.add_argument("--allow", action="append", default=[])
    external.add_argument("--execute", action="store_true", help="confirm the authorized network probe")
    external.add_argument("--timeout", type=float, default=10.0)
    external.add_argument("--report", type=Path)
    external.add_argument("--format", choices=("json", "markdown", "html", "sarif"), default="json")
    external.add_argument("--fail-on", choices=tuple(SEVERITY_WEIGHTS))
    sub.add_parser("doctor", help="show runtime and safety defaults")
    api = sub.add_parser("api", help="start the local React dashboard API")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8765)
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

    payload = render([result], args.format, args.language)
    if args.report:
        args.report.write_text(payload + "\n", encoding="utf-8")
        print(f"report: {args.report}")
    else:
        print(payload)
    return evaluate_ci_fail_on([result], args.fail_on)


def run_full(args: argparse.Namespace) -> int:
    try:
        allowlist = load_allowlist(args.allow)
        policy = SafetyPolicy(allowlist, execute=args.execute, timeout=args.timeout)
        target = policy.validate(args.target)
    except (SafetyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    results: list[RunResult] = []
    for module in profile_modules(args.profile):
        result = RunResult(module.name, target, "execute" if args.execute else "dry-run", utc_now())
        if args.execute:
            result.findings = module.run(target, timeout=args.timeout)
        results.append(result)
    if not args.execute:
        print("dry-run: no network request was made")
    else:
        total = sum(len(item.findings) for item in results)
        print(f"completed: {len(results)} module(s), {total} finding(s)")
    payload = render(results, args.format, args.language)
    if args.report:
        args.report.write_text(payload + "\n", encoding="utf-8")
        print(f"report: {args.report}")
    else:
        print(payload)
    return evaluate_ci_fail_on(results, args.fail_on)


def run_external(args: argparse.Namespace) -> int:
    try:
        policy = SafetyPolicy(load_allowlist(args.allow), execute=args.execute, timeout=args.timeout)
        target = policy.validate(args.target)
        adapter = ADAPTERS[args.tool]
    except (SafetyError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result = RunResult(f"tool/{args.tool}", target, "execute" if args.execute else "dry-run", utc_now())
    if not args.execute:
        print("dry-run: external adapter not executed")
    else:
        result.findings = adapter.run(target, timeout=args.timeout)
        print(f"completed: {len(result.findings)} finding(s)")
    payload = render([result], args.format, "both")
    if args.report:
        args.report.write_text(payload + "\n", encoding="utf-8")
        print(f"report: {args.report}")
    else:
        print(payload)
    return evaluate_ci_fail_on([result], args.fail_on)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        return start_console()
    if args.command == "list":
        for module in list_modules():
            print(f"{module.name}\t{module.description}")
        return 0
    if args.command == "search":
        for module in search_modules(args.query, args.category):
            print(f"{module.name}\t[{module.category}/{module.risk}]\t{module.description}")
        return 0
    if args.command == "profiles":
        for name, profile in PROFILES.items():
            print(f"{name}\t{len(profile_modules(name))} module(s)\t{profile['description']}")
        return 0
    if args.command == "tools":
        print(json.dumps(tool_catalog(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "info":
        try:
            module = get_module(args.module)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(module.metadata(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "doctor":
        print(json.dumps({"version": __version__, "python": platform.python_version(), "default_mode": "dry-run", "network_policy": "explicit allowlist required", "external_tools": tool_catalog()}, ensure_ascii=False, indent=2))
        return 0
    if args.command == "api":
        from .api import serve
        try:
            serve(args.host, args.port)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.command == "console":
        return start_console()
    if args.command == "full":
        return run_full(args)
    if args.command == "external":
        return run_external(args)
    return run_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
