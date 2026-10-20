#!/usr/bin/env python3
"""Primary XSS detection module entry point.

Programmatic usage:
    from xss_module import run_xss_module
    result = run_xss_module(crawl_map_path="crawl_map.json", allowed_origins=["http://127.0.0.1:5001"], allow_loopback=True)

CLI:
    python xss_module.py --crawl-map crawl_map.json --origin http://127.0.0.1:5001 --allow-loopback -o findings.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from scanner.logging_utils import setup_logger
from scanner.models import ScanResult
from xss.config import XSSConfig
from xss.engine import run_xss_scan


def build_config_from_args(args: argparse.Namespace) -> XSSConfig:
    origins = list(args.origin or [])
    if args.scope_file:
        text = Path(args.scope_file).read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                origins.append(line)

    marker_only = not args.active_verify and not args.metachar_probes
    if args.marker_only:
        marker_only = True

    return XSSConfig(
        allowed_origins=origins,
        allowed_path_prefixes=args.path_prefix or ["/"],
        allow_loopback=args.allow_loopback,
        allow_private_networks=args.allow_private,
        marker_only=marker_only,
        enable_active_verification=args.active_verify,
        enable_stored_xss=args.enable_stored_xss,
        enable_browser_verification=args.browser_verify,
        enable_metachar_probes=args.metachar_probes,
        enable_extended_probes=args.extended_probes,
        max_extended_probes=args.max_extended_probes,
        timeout=args.timeout,
        connect_timeout=args.connect_timeout,
        max_requests=args.max_requests,
        max_response_bytes=args.max_response_bytes,
        max_stored_submissions=args.max_stored_submissions,
        browser_timeout=args.browser_timeout,
    )


def run_xss_module(
    *,
    crawl_map_path: str | None = None,
    crawl_map: dict[str, Any] | None = None,
    allowed_origins: list[str],
    allow_loopback: bool = False,
    allow_private_networks: bool = False,
    allowed_path_prefixes: list[str] | None = None,
    marker_only: bool = True,
    enable_active_verification: bool = False,
    enable_stored_xss: bool = False,
    enable_browser_verification: bool = False,
    enable_metachar_probes: bool = False,
    enable_extended_probes: bool = False,
    max_extended_probes: int = 2,
    timeout: float = 10.0,
    max_requests: int = 200,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    session: Any = None,
    verbose: bool = False,
) -> ScanResult:
    """Main-scanner integration API (no subprocess required)."""
    setup_logger("web_vuln", verbose=verbose)
    config = XSSConfig(
        allowed_origins=list(allowed_origins),
        allowed_path_prefixes=allowed_path_prefixes or ["/"],
        allow_loopback=allow_loopback,
        allow_private_networks=allow_private_networks,
        marker_only=marker_only,
        enable_active_verification=enable_active_verification,
        enable_stored_xss=enable_stored_xss,
        enable_browser_verification=enable_browser_verification,
        enable_metachar_probes=enable_metachar_probes,
        enable_extended_probes=enable_extended_probes,
        max_extended_probes=max_extended_probes,
        timeout=timeout,
        max_requests=max_requests,
        cookies=cookies or {},
        headers=headers or {},
    )
    return run_xss_scan(
        crawl_map=crawl_map,
        crawl_map_path=crawl_map_path,
        config=config,
        session=session,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Authorized XSS detection module. Requires explicit --origin scope. "
            "Intended for lab / self-authored targets only."
        )
    )
    p.add_argument(
        "--crawl-map",
        required=True,
        help="Path to crawl_map.json produced by the Recon module",
    )
    p.add_argument(
        "--origin",
        action="append",
        default=[],
        help="Allowed origin (repeatable), e.g. http://127.0.0.1:5001",
    )
    p.add_argument(
        "--scope-file",
        help="File with allowed origins, one per line",
    )
    p.add_argument(
        "--path-prefix",
        action="append",
        default=[],
        help="Allowed path prefix (repeatable). Default: /",
    )
    p.add_argument(
        "--allow-loopback",
        action="store_true",
        help="Permit loopback destinations when listed in --origin (lab mode)",
    )
    p.add_argument(
        "--allow-private",
        action="store_true",
        help="Permit private-network IPs when listed in --origin (lab mode)",
    )
    p.add_argument(
        "--marker-only",
        action="store_true",
        help="Force marker-only mode (default when active verification is off)",
    )
    p.add_argument(
        "--active-verify",
        action="store_true",
        help="Opt-in active verification (context probes / optional browser)",
    )
    p.add_argument(
        "--metachar-probes",
        action="store_true",
        help="Send context-sensitive metacharacter probes (requires --active-verify)",
    )
    p.add_argument(
        "--extended-probes",
        action="store_true",
        help=(
            "Opt-in curated extra probes adapted from payload-box/xss-payload-list "
            "(requires --active-verify --metachar-probes)"
        ),
    )
    p.add_argument(
        "--max-extended-probes",
        type=int,
        default=2,
        help="Max extra curated probes per input point (default: 2)",
    )
    p.add_argument(
        "--enable-stored-xss",
        action="store_true",
        help="Opt-in stored XSS submit-and-retrieve testing",
    )
    p.add_argument(
        "--browser-verify",
        action="store_true",
        help="Opt-in Playwright browser execution check (requires --active-verify)",
    )
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--max-requests", type=int, default=200)
    p.add_argument("--max-response-bytes", type=int, default=1_000_000)
    p.add_argument("--max-stored-submissions", type=int, default=5)
    p.add_argument("--browser-timeout", type=float, default=8.0)
    p.add_argument("-o", "--output", help="Write JSON findings to this path")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logger("web_vuln", verbose=args.verbose)

    if not args.origin and not args.scope_file:
        print(
            "error: explicit scope required via --origin and/or --scope-file "
            "(crawl_map URLs are not automatic authorization)",
            file=sys.stderr,
        )
        return 2

    if args.metachar_probes and not args.active_verify:
        print("error: --metachar-probes requires --active-verify", file=sys.stderr)
        return 2
    if args.extended_probes and not (args.active_verify and args.metachar_probes):
        print(
            "error: --extended-probes requires --active-verify and --metachar-probes",
            file=sys.stderr,
        )
        return 2
    if args.browser_verify and not args.active_verify:
        print("error: --browser-verify requires --active-verify", file=sys.stderr)
        return 2

    try:
        config = build_config_from_args(args)
        result = run_xss_scan(crawl_map_path=args.crawl_map, config=config)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    payload = result.to_dict()
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(
            f"wrote {len(result.findings)} findings "
            f"({len(result.outcomes)} outcomes) to {args.output}"
        )
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
