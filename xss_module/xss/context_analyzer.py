"""Context-aware classification of marker reflections in HTML responses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from bs4 import BeautifulSoup, Comment


class RenderContext(str, Enum):
    HTML_BODY = "html_body"
    HTML_ATTR_DOUBLE = "html_attribute_double_quoted"
    HTML_ATTR_SINGLE = "html_attribute_single_quoted"
    HTML_ATTR_UNQUOTED = "html_attribute_unquoted"
    JS_STRING_SINGLE = "javascript_string_single"
    JS_STRING_DOUBLE = "javascript_string_double"
    JS_BLOCK = "javascript_block"
    URL_ATTRIBUTE = "url_attribute"
    HTML_COMMENT = "html_comment"
    CSS = "css"
    JSON_IN_HTML = "json_in_html"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


URL_ATTRS = {
    "href",
    "src",
    "action",
    "formaction",
    "xlink:href",
    "poster",
    "data",
    "cite",
}


@dataclass
class ContextOccurrence:
    context: RenderContext
    index: int
    snippet: str
    attribute_name: str | None = None
    tag_name: str | None = None
    executable_candidate: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context.value,
            "index": self.index,
            "snippet": self.snippet,
            "attribute_name": self.attribute_name,
            "tag_name": self.tag_name,
            "executable_candidate": self.executable_candidate,
            "notes": self.notes,
        }


@dataclass
class ContextAnalysis:
    occurrences: list[ContextOccurrence]
    primary: RenderContext
    warrants_verification: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary": self.primary.value,
            "warrants_verification": self.warrants_verification,
            "reasons": self.reasons,
            "occurrences": [o.to_dict() for o in self.occurrences],
        }


def _snippet(body: str, index: int, length: int, radius: int = 70) -> str:
    start = max(0, index - radius)
    end = min(len(body), index + length + radius)
    return body[start:end]


def _find_all(haystack: str, needle: str) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + 1
    return out


def _classify_by_raw_scan(body: str, index: int, marker: str) -> ContextOccurrence:
    """Classify context using a leftward scan of raw HTML around the marker."""
    snippet = _snippet(body, index, len(marker))
    before = body[:index]
    after = body[index + len(marker) :]

    # HTML comment
    last_comment_open = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open > last_comment_close:
        return ContextOccurrence(
            context=RenderContext.HTML_COMMENT,
            index=index,
            snippet=snippet,
            executable_candidate=False,
            notes=["inside_html_comment"],
        )

    # Script block
    last_script_open = max(before.lower().rfind("<script"), before.lower().rfind("<script "))
    # more reliable:
    script_opens = [m.start() for m in re.finditer(r"(?i)<script\b[^>]*>", before)]
    script_closes = [m.start() for m in re.finditer(r"(?i)</script\s*>", before)]
    if script_opens and (not script_closes or script_opens[-1] > script_closes[-1]):
        # Inside script — try to detect string quotes
        region = before[script_opens[-1] :]
        # Count unescaped quotes roughly in the script so far + immediate after
        single = 0
        double = 0
        i = 0
        text = region
        while i < len(text):
            ch = text[i]
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                single += 1
            elif ch == '"':
                double += 1
            i += 1
        # If odd count of a quote type, we are inside that string
        if single % 2 == 1 and double % 2 == 0:
            return ContextOccurrence(
                context=RenderContext.JS_STRING_SINGLE,
                index=index,
                snippet=snippet,
                tag_name="script",
                executable_candidate=True,
                notes=["js_single_quoted_string"],
            )
        if double % 2 == 1 and single % 2 == 0:
            return ContextOccurrence(
                context=RenderContext.JS_STRING_DOUBLE,
                index=index,
                snippet=snippet,
                tag_name="script",
                executable_candidate=True,
                notes=["js_double_quoted_string"],
            )
        return ContextOccurrence(
            context=RenderContext.JS_BLOCK,
            index=index,
            snippet=snippet,
            tag_name="script",
            executable_candidate=True,
            notes=["js_block_non_string_or_ambiguous"],
        )

    # Style block
    style_opens = [m.start() for m in re.finditer(r"(?i)<style\b[^>]*>", before)]
    style_closes = [m.start() for m in re.finditer(r"(?i)</style\s*>", before)]
    if style_opens and (not style_closes or style_opens[-1] > style_closes[-1]):
        return ContextOccurrence(
            context=RenderContext.CSS,
            index=index,
            snippet=snippet,
            tag_name="style",
            executable_candidate=False,
            notes=["inside_style"],
        )

    # Attribute context: find last '<' before index without intervening '>'
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt > last_gt:
        tag_chunk = before[last_lt:index]
        tag_match = re.match(r"<\s*([a-zA-Z0-9:_-]+)", tag_chunk)
        tag_name = tag_match.group(1).lower() if tag_match else None
        # Determine attribute and quote
        attr_match = re.search(
            r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(\"([^\"]*)|'([^']*)|([^\s\"'>]*))$",
            tag_chunk,
            re.DOTALL,
        )
        attr_name = attr_match.group(1).lower() if attr_match else None
        if attr_match:
            if attr_match.group(3) is not None or (
                attr_match.group(2) and attr_match.group(2).startswith('"')
            ):
                # unfinished double-quoted value
                if tag_chunk.count('"') % 2 == 1:
                    ctx = (
                        RenderContext.URL_ATTRIBUTE
                        if attr_name in URL_ATTRS
                        else RenderContext.HTML_ATTR_DOUBLE
                    )
                    return ContextOccurrence(
                        context=ctx,
                        index=index,
                        snippet=snippet,
                        attribute_name=attr_name,
                        tag_name=tag_name,
                        executable_candidate=ctx != RenderContext.URL_ATTRIBUTE
                        or True,
                        notes=["double_quoted_attribute"],
                    )
            if attr_match.group(4) is not None or (
                attr_match.group(2) and attr_match.group(2).startswith("'")
            ):
                if tag_chunk.count("'") % 2 == 1:
                    ctx = (
                        RenderContext.URL_ATTRIBUTE
                        if attr_name in URL_ATTRS
                        else RenderContext.HTML_ATTR_SINGLE
                    )
                    return ContextOccurrence(
                        context=ctx,
                        index=index,
                        snippet=snippet,
                        attribute_name=attr_name,
                        tag_name=tag_name,
                        executable_candidate=True,
                        notes=["single_quoted_attribute"],
                    )
            # unquoted
            if attr_name:
                ctx = (
                    RenderContext.URL_ATTRIBUTE
                    if attr_name in URL_ATTRS
                    else RenderContext.HTML_ATTR_UNQUOTED
                )
                return ContextOccurrence(
                    context=ctx,
                    index=index,
                    snippet=snippet,
                    attribute_name=attr_name,
                    tag_name=tag_name,
                    executable_candidate=True,
                    notes=["unquoted_attribute"],
                )
        return ContextOccurrence(
            context=RenderContext.AMBIGUOUS,
            index=index,
            snippet=snippet,
            tag_name=tag_name,
            executable_candidate=False,
            notes=["inside_tag_but_attr_unclear"],
        )

    # JSON-looking script type application/json
    # Already handled script; treat as body otherwise.
    # Heuristic for JSON embedding
    window = before[-20:] + marker + after[:20]
    if re.search(r"""['"]\s*:\s*['"]?$""", before[-40:]) or '"%s"' % marker in (
        before[-5:] + marker + after[:5]
    ):
        # weak signal
        pass

    return ContextOccurrence(
        context=RenderContext.HTML_BODY,
        index=index,
        snippet=snippet,
        executable_candidate=True,
        notes=["html_body_text"],
    )


def _augment_with_bs4(body: str, marker: str, occurrences: list[ContextOccurrence]) -> None:
    """Cross-check with BeautifulSoup for comments and text nodes."""
    try:
        try:
            soup = BeautifulSoup(body, "lxml")
        except Exception:  # noqa: BLE001
            soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return

    for comment in soup.find_all(string=lambda t: isinstance(t, Comment) and marker in t):
        # Ensure we mark comment contexts
        for occ in occurrences:
            if marker in occ.snippet and occ.context == RenderContext.HTML_BODY:
                # may have been misclassified if comment delimiters odd; leave notes
                occ.notes.append("bs4_also_saw_comment_node")

    for script in soup.find_all("script"):
        text = script.string or script.get_text() or ""
        if marker in text:
            for occ in occurrences:
                if occ.index >= 0 and marker in occ.snippet:
                    if occ.context == RenderContext.HTML_BODY:
                        occ.notes.append("bs4_found_in_script")
                        occ.context = RenderContext.JS_BLOCK
                        occ.executable_candidate = True


def analyze_contexts(body: str, marker: str) -> ContextAnalysis:
    if not body or not marker or marker not in body:
        return ContextAnalysis(
            occurrences=[],
            primary=RenderContext.UNKNOWN,
            warrants_verification=False,
            reasons=["marker_not_present"],
        )

    occurrences: list[ContextOccurrence] = []
    for idx in _find_all(body, marker):
        occurrences.append(_classify_by_raw_scan(body, idx, marker))

    _augment_with_bs4(body, marker, occurrences)

    # Primary = first executable candidate, else first occurrence
    primary = occurrences[0].context if occurrences else RenderContext.UNKNOWN
    for occ in occurrences:
        if occ.executable_candidate and occ.context not in {
            RenderContext.HTML_COMMENT,
            RenderContext.CSS,
        }:
            primary = occ.context
            break

    inert = {
        RenderContext.HTML_COMMENT,
        RenderContext.CSS,
        RenderContext.UNKNOWN,
    }
    warrants = any(
        o.executable_candidate and o.context not in inert for o in occurrences
    )
    reasons = []
    if warrants:
        reasons.append("reflection_in_potentially_executable_context")
    else:
        reasons.append("reflection_only_in_inert_or_unknown_context")

    # Multiple distinct contexts => ambiguous note
    distinct = {o.context for o in occurrences}
    if len(distinct) > 1:
        reasons.append("multiple_distinct_contexts")
        if primary == RenderContext.UNKNOWN:
            primary = RenderContext.AMBIGUOUS

    return ContextAnalysis(
        occurrences=occurrences,
        primary=primary,
        warrants_verification=warrants,
        reasons=reasons,
    )


def context_probe_for(context: RenderContext) -> str | None:
    from xss.markers import (
        PROBE_HTML_BODY,
        PROBE_JS_DOUBLE,
        PROBE_JS_SINGLE,
        PROBE_URL,
    )

    mapping = {
        RenderContext.HTML_BODY: PROBE_HTML_BODY,
        RenderContext.HTML_ATTR_DOUBLE: '"x',
        RenderContext.HTML_ATTR_SINGLE: "'x",
        RenderContext.HTML_ATTR_UNQUOTED: "x><",
        RenderContext.JS_STRING_SINGLE: PROBE_JS_SINGLE,
        RenderContext.JS_STRING_DOUBLE: PROBE_JS_DOUBLE,
        RenderContext.JS_BLOCK: PROBE_JS_SINGLE,
        RenderContext.URL_ATTRIBUTE: PROBE_URL,
    }
    return mapping.get(context)
