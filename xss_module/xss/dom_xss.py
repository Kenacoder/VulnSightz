"""Experimental DOM-based XSS helpers (stretch goal — not wired into core scan).

Static source/sink matching alone must never be reported as confirmed DOM XSS.
This module is intentionally separate from the reflected/stored pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SOURCE_PATTERNS = [
    r"location\.(hash|search|href|pathname)",
    r"document\.(URL|documentURI|baseURI|referrer)",
    r"window\.name",
]

SINK_PATTERNS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"eval\s*\(",
]


@dataclass
class DomHint:
    kind: str  # source | sink
    pattern: str
    line: int
    excerpt: str


def scan_js_for_dom_hints(source: str) -> list[DomHint]:
    """Return experimental static hints. Not proof of vulnerability."""
    hints: list[DomHint] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, start=1):
        for pat in SOURCE_PATTERNS:
            if re.search(pat, line):
                hints.append(DomHint("source", pat, i, line.strip()[:160]))
        for pat in SINK_PATTERNS:
            if re.search(pat, line):
                hints.append(DomHint("sink", pat, i, line.strip()[:160]))
    return hints
