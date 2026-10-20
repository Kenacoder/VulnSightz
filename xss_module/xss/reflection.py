"""Marker reflection detection and encoding classification."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ReflectionKind(str, Enum):
    ABSENT = "not_reflected"
    RAW = "reflected_raw"
    HTML_ENCODED = "reflected_html_encoded"
    PARTIAL = "reflected_partial"
    TRANSFORMED = "reflected_transformed"
    AMBIGUOUS = "reflected_ambiguous"


@dataclass
class ReflectionHit:
    kind: ReflectionKind
    index: int
    matched_text: str
    snippet: str
    encoding_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "index": self.index,
            "matched_text": self.matched_text,
            "snippet": self.snippet,
            "encoding_notes": self.encoding_notes,
        }


@dataclass
class ReflectionResult:
    marker: str
    hits: list[ReflectionHit]
    kind: ReflectionKind

    def to_dict(self) -> dict[str, Any]:
        return {
            "marker": self.marker,
            "kind": self.kind.value,
            "hits": [h.to_dict() for h in self.hits],
            "count": len(self.hits),
        }


def _snippet(body: str, index: int, length: int, radius: int = 60) -> str:
    start = max(0, index - radius)
    end = min(len(body), index + length + radius)
    return body[start:end]


def _find_all(haystack: str, needle: str) -> list[int]:
    if not needle:
        return []
    out: list[int] = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + max(1, len(needle))
    return out


def classify_marker_reflection(body: str, marker: str) -> ReflectionResult:
    """Classify how a marker appears in a response body."""
    if not body:
        return ReflectionResult(marker=marker, hits=[], kind=ReflectionKind.ABSENT)

    hits: list[ReflectionHit] = []

    # Raw alphanumeric marker
    for idx in _find_all(body, marker):
        hits.append(
            ReflectionHit(
                kind=ReflectionKind.RAW,
                index=idx,
                matched_text=marker,
                snippet=_snippet(body, idx, len(marker)),
                encoding_notes=["raw_substring"],
            )
        )

    # HTML entity variants of the marker itself (rare for alnum, but keep general)
    escaped = html.escape(marker)
    if escaped != marker:
        for idx in _find_all(body, escaped):
            hits.append(
                ReflectionHit(
                    kind=ReflectionKind.HTML_ENCODED,
                    index=idx,
                    matched_text=escaped,
                    snippet=_snippet(body, idx, len(escaped)),
                    encoding_notes=["html.escape"],
                )
            )

    # Partial: marker broken by encoding mid-string or case-folded variants
    if not hits:
        # Look for substantial contiguous prefix/suffix (>= 6 chars)
        prefix = marker[:6]
        if prefix and prefix in body and marker not in body:
            for idx in _find_all(body, prefix):
                hits.append(
                    ReflectionHit(
                        kind=ReflectionKind.PARTIAL,
                        index=idx,
                        matched_text=prefix,
                        snippet=_snippet(body, idx, len(prefix)),
                        encoding_notes=["prefix_only"],
                    )
                )

    if not hits:
        # Case-insensitive transformed
        lower_body = body.lower()
        lower_marker = marker.lower()
        if lower_marker in lower_body and marker not in body:
            idx = lower_body.find(lower_marker)
            hits.append(
                ReflectionHit(
                    kind=ReflectionKind.TRANSFORMED,
                    index=idx,
                    matched_text=body[idx : idx + len(marker)],
                    snippet=_snippet(body, idx, len(marker)),
                    encoding_notes=["case_transformed"],
                )
            )

    if not hits:
        return ReflectionResult(marker=marker, hits=[], kind=ReflectionKind.ABSENT)

    # Prefer most severe classification present
    priority = [
        ReflectionKind.RAW,
        ReflectionKind.PARTIAL,
        ReflectionKind.TRANSFORMED,
        ReflectionKind.HTML_ENCODED,
        ReflectionKind.AMBIGUOUS,
    ]
    kinds = {h.kind for h in hits}
    overall = ReflectionKind.AMBIGUOUS
    for k in priority:
        if k in kinds:
            overall = k
            break
    return ReflectionResult(marker=marker, hits=hits, kind=overall)


def classify_probe_encoding(body: str, marker: str, probe: str) -> ReflectionKind:
    """Compare reflection of marker+probe versus encoded forms of the probe."""
    combined = marker + probe
    if combined in body:
        return ReflectionKind.RAW

    # Common HTML encodings of metacharacters
    encoded_variants = [
        html.escape(combined, quote=True),
        html.escape(combined, quote=False),
        combined.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"),
        combined.replace("<", "&lt;").replace(">", "&gt;"),
        combined.replace('"', "&quot;"),
        combined.replace("'", "&#39;"),
        combined.replace("'", "\\'"),
        combined.replace('"', '\\"'),
        combined.replace("/", "\\/"),
    ]
    for variant in encoded_variants:
        if variant != combined and variant in body:
            return ReflectionKind.HTML_ENCODED

    if marker in body and any(ch in body[body.find(marker) : body.find(marker) + 80] for ch in probe):
        # Some probe characters present near marker
        return ReflectionKind.PARTIAL

    if marker in body:
        return ReflectionKind.TRANSFORMED

    return ReflectionKind.ABSENT


_META_NEAR_MARKER = re.compile(r"""[<>"'`]""")


def nearby_metacharacters(body: str, marker: str, radius: int = 40) -> list[str]:
    idx = body.find(marker)
    if idx < 0:
        return []
    window = body[max(0, idx - radius) : idx + len(marker) + radius]
    return sorted(set(_META_NEAR_MARKER.findall(window)))
