#!/usr/bin/env python3
"""Main scanner orchestrator — runs Recon then detection modules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner.logging_utils import setup_logger
from xss.config import XSSConfig
from xss.engine import run_xss_scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Modular web vulnerability scanner")
    p.add_argument("--crawl-map", required=True, help="Existing crawl_map.json path")
    p.add_argument(
        "--origin",
        action="append",
        required=True,
        help="Allowed origin for active modules (repeatable)",
    )
    p.add_argument("--allow-loopback", action="store_true")
    p.add_argument("--modules", default="xss", help="Comma-separated modules (xss)")
    p.add_argument("--enable-stored-xss", action="store_true")
    p.add_argument("--active-verify", action="store_true")
    p.add_argument("--metachar-probes", action="store_true")
    p.add_argument("-o", "--output", help="Combined findings JSON path")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logger("web_vuln", verbose=args.verbose)
    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    combined = {"modules": {}, "findings": []}

    for name in modules:
        if name != "xss":
            print(f"warning: unknown module {name!r}, skipping", file=sys.stderr)
            continue
        config = XSSConfig(
            allowed_origins=list(args.origin),
            allow_loopback=args.allow_loopback,
            marker_only=not args.active_verify,
            enable_active_verification=args.active_verify,
            enable_metachar_probes=args.metachar_probes,
            enable_stored_xss=args.enable_stored_xss,
        )
        result = run_xss_scan(crawl_map_path=args.crawl_map, config=config)
        combined["modules"]["xss"] = result.to_dict()
        combined["findings"].extend(result.to_dict()["findings"])

    text = json.dumps(combined, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"wrote combined report to {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
