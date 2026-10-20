"""Active verification — context-appropriate probes (opt-in)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from xss.context_analyzer import RenderContext, context_probe_for
from xss.markers import Marker
from xss.payload_catalog import CatalogProbe, primary_probe_for, probes_for_context
from xss.reflection import ReflectionKind, classify_probe_encoding

logger = logging.getLogger("web_vuln.xss.verify")


@dataclass
class ProbeResult:
    probe_id: str
    probe: str
    reflection_kind: ReflectionKind
    metachar_raw: bool
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "probe": self.probe,
            "reflection_kind": self.reflection_kind.value,
            "metachar_raw": self.metachar_raw,
            "details": self.details,
        }


def select_probe(context: RenderContext) -> tuple[str, str] | None:
    """Return (probe_id, probe_string) or None if no safe probe for context."""
    catalog = primary_probe_for(context)
    if catalog is not None:
        return (catalog.probe_id, catalog.fragment)
    probe = context_probe_for(context)
    if probe is None:
        return None
    return (f"probe:{context.value}", probe)


def select_extended_probes(
    context: RenderContext,
    *,
    limit: int = 3,
    include_encoding: bool = True,
    skip_ids: set[str] | None = None,
) -> list[CatalogProbe]:
    """Additional curated probes after the primary breakout check."""
    skip = skip_ids or set()
    probes = probes_for_context(
        context, include_encoding=include_encoding, limit=limit + len(skip)
    )
    return [p for p in probes if p.probe_id not in skip][:limit]


def evaluate_probe_response(
    body: str,
    marker: Marker,
    context: RenderContext,
    probe_id: str,
    probe: str,
) -> ProbeResult:
    kind = classify_probe_encoding(body, marker.value, probe)
    metachar_raw = kind == ReflectionKind.RAW
    # Extra check: for HTML body, ensure '<' reflected unescaped near marker
    if context == RenderContext.HTML_BODY and marker.value in body:
        idx = body.find(marker.value)
        window = body[idx : idx + len(marker.value) + len(probe) + 5]
        if "<" in window and "&lt;" not in window.replace(marker.value, ""):
            # crude: raw < present after marker region
            if marker.value + probe in body or (marker.value in body and "<" in body[idx:idx+40]):
                metachar_raw = metachar_raw or ("<" in body[idx : idx + len(marker.value) + len(probe) + 2])
    return ProbeResult(
        probe_id=probe_id,
        probe=probe,
        reflection_kind=kind,
        metachar_raw=metachar_raw,
        details={"context": context.value},
    )
