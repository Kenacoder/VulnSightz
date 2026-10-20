"""Curated lab-safe XSS probe catalog.

Educational patterns adapted from:
  https://github.com/payload-box/xss-payload-list

Design rules for this scanner:
- Marker-first workflow remains primary.
- Catalog probes are opt-in via enable_extended_probes.
- No blind/XSS-Hunter callbacks, cookie theft, or external script loads.
- alert()/confirm() demo payloads are replaced with unique in-page signals
  or short non-executing breakout probes for reflection analysis.
- Full All-In-One / WAF-bypass wordlists are intentionally NOT imported.
"""

from __future__ import annotations

from dataclasses import dataclass

from xss.context_analyzer import RenderContext

SOURCE_REPO = "https://github.com/payload-box/xss-payload-list"
SOURCE_NOTE = (
    "Curated educational patterns adapted from payload-box/xss-payload-list "
    "(Basic + Context-Guide). Not a full payload dump."
)


@dataclass(frozen=True)
class CatalogProbe:
    probe_id: str
    context: RenderContext
    # Appended after the unique marker for reflection / breakout checks.
    fragment: str
    purpose: str
    # If True, fragment is only suitable when browser verification is enabled
    # and must be rendered via build_catalog_execution_probe().
    execution_template: bool = False


# Short context breakouts — inspired by Cheatsheet.md / Docs/Context-Guide.md
# but kept non-chaining and budget-friendly.
CURATED_BREAKOUTS: tuple[CatalogProbe, ...] = (
    CatalogProbe(
        probe_id="pb.basic.html_body.tag_open",
        context=RenderContext.HTML_BODY,
        fragment="\"'><",
        purpose="Detect raw HTML metacharacter reflection in body context",
    ),
    CatalogProbe(
        probe_id="pb.basic.html_body.script_case",
        context=RenderContext.HTML_BODY,
        fragment="<ScRiPt>",
        purpose="Case-variant tag open reflection (Basic/script-tags inspiration)",
    ),
    CatalogProbe(
        probe_id="pb.basic.attr_double.breakout",
        context=RenderContext.HTML_ATTR_DOUBLE,
        fragment='"x',
        purpose="Double-quoted attribute breakout reflection",
    ),
    CatalogProbe(
        probe_id="pb.basic.attr_double.event_prefix",
        context=RenderContext.HTML_ATTR_DOUBLE,
        fragment='" autofocus x="',
        purpose="Attribute event-handler injection prefix (Basic/event-handlers)",
    ),
    CatalogProbe(
        probe_id="pb.basic.attr_single.breakout",
        context=RenderContext.HTML_ATTR_SINGLE,
        fragment="'x",
        purpose="Single-quoted attribute breakout reflection",
    ),
    CatalogProbe(
        probe_id="pb.basic.attr_unquoted.breakout",
        context=RenderContext.HTML_ATTR_UNQUOTED,
        fragment="x><",
        purpose="Unquoted attribute structural breakout",
    ),
    CatalogProbe(
        probe_id="pb.basic.js_single.breakout",
        context=RenderContext.JS_STRING_SINGLE,
        fragment="';//",
        purpose="JS single-quoted string breakout (Context-Guide)",
    ),
    CatalogProbe(
        probe_id="pb.basic.js_double.breakout",
        context=RenderContext.JS_STRING_DOUBLE,
        fragment='";//',
        purpose="JS double-quoted string breakout",
    ),
    CatalogProbe(
        probe_id="pb.basic.url.javascript_scheme",
        context=RenderContext.URL_ATTRIBUTE,
        fragment="javascript:/*",
        purpose="javascript: scheme reflection in URL attribute (Context-Guide)",
    ),
)

# Encoding transform checks — inspired by Payloads/Bypass/encoding.txt
# Used only to observe whether encoded metacharacters decode in output.
ENCODING_TRANSFORM_PROBES: tuple[CatalogProbe, ...] = (
    CatalogProbe(
        probe_id="pb.encoding.url_lt",
        context=RenderContext.HTML_BODY,
        fragment="%3C",
        purpose="Observe URL-encoded '<' decode/transform behavior",
    ),
    CatalogProbe(
        probe_id="pb.encoding.entity_lt",
        context=RenderContext.HTML_BODY,
        fragment="&lt;",
        purpose="Observe HTML-entity '<' handling (should stay safe if re-encoded)",
    ),
)

# Browser execution templates — Basic/event-handlers patterns with lab signal
# instead of alert(1). Token placeholder: {token}
EXECUTION_TEMPLATES: tuple[CatalogProbe, ...] = (
    CatalogProbe(
        probe_id="pb.exec.img_onerror",
        context=RenderContext.HTML_BODY,
        fragment='<img src=x onerror="window.__XSS_SIGNAL__=\'{token}\'">',
        purpose="img onerror execution signal (Basic/event-handlers)",
        execution_template=True,
    ),
    CatalogProbe(
        probe_id="pb.exec.svg_onload",
        context=RenderContext.HTML_BODY,
        fragment="<svg/onload=\"window.__XSS_SIGNAL__='{token}'\">",
        purpose="svg onload execution signal (Basic/event-handlers)",
        execution_template=True,
    ),
    CatalogProbe(
        probe_id="pb.exec.input_autofocus",
        context=RenderContext.HTML_BODY,
        fragment=(
            "<input autofocus onfocus=\"window.__XSS_SIGNAL__='{token}'\">"
        ),
        purpose="autofocus/onfocus execution signal (Basic/event-handlers)",
        execution_template=True,
    ),
)


def probes_for_context(
    context: RenderContext,
    *,
    include_encoding: bool = False,
    limit: int = 3,
) -> list[CatalogProbe]:
    """Return curated breakout probes for a rendering context."""
    out = [p for p in CURATED_BREAKOUTS if p.context == context]
    if include_encoding and context == RenderContext.HTML_BODY:
        out.extend(ENCODING_TRANSFORM_PROBES)
    return out[: max(0, limit)]


def primary_probe_for(context: RenderContext) -> CatalogProbe | None:
    matched = probes_for_context(context, include_encoding=False, limit=1)
    return matched[0] if matched else None


def build_catalog_execution_probe(token: str, template_id: str | None = None) -> tuple[str, str]:
    """Return (probe_id, html_fragment) with lab execution signal substituted."""
    templates = {p.probe_id: p for p in EXECUTION_TEMPLATES}
    if template_id and template_id in templates:
        chosen = templates[template_id]
    else:
        chosen = EXECUTION_TEMPLATES[0]
    return chosen.probe_id, chosen.fragment.format(token=token)


def catalog_manifest() -> dict:
    return {
        "source": SOURCE_REPO,
        "note": SOURCE_NOTE,
        "breakout_count": len(CURATED_BREAKOUTS),
        "encoding_probe_count": len(ENCODING_TRANSFORM_PROBES),
        "execution_template_count": len(EXECUTION_TEMPLATES),
        "excluded": [
            "Payloads/All-In-One.txt (too large; spraying)",
            "Payloads/Blind (external callbacks)",
            "Payloads/WAF-Bypass (aggressive bypass spraying)",
            "Payloads/BurpIntruder (fuzz wordlists)",
            "cookie/exfiltration demo payloads",
        ],
    }
