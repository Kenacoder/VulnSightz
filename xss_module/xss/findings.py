"""Finding construction, confidence model, and deduplication."""

from __future__ import annotations

from typing import Any

from scanner.models import Finding, Severity, VerificationStatus
from xss.context_analyzer import RenderContext
from xss.reflection import ReflectionKind


REFERENCES = [
    "https://cwe.mitre.org/data/definitions/79.html",
    "https://owasp.org/Top10/2025/A05_2025-Injection/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "https://portswigger.net/web-security/cross-site-scripting",
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://github.com/payload-box/xss-payload-list",
]

REMEDIATION = (
    "Encode untrusted data for the output context (HTML body, attribute, JavaScript, URL). "
    "Prefer templating auto-escaping, validate input where appropriate, and apply a strict "
    "Content-Security-Policy as defense-in-depth. See OWASP XSS Prevention Cheat Sheet."
)


def severity_for(
    *,
    verification_status: str,
    context: RenderContext,
    stored: bool,
) -> str:
    if verification_status == VerificationStatus.CONFIRMED.value:
        return Severity.HIGH.value if stored else Severity.MEDIUM.value
    if verification_status == VerificationStatus.PROBABLE.value:
        return Severity.MEDIUM.value
    if verification_status == VerificationStatus.CANDIDATE.value:
        if context in {
            RenderContext.HTML_COMMENT,
            RenderContext.CSS,
            RenderContext.URL_ATTRIBUTE,
        }:
            return Severity.LOW.value
        return Severity.LOW.value
    return Severity.INFO.value


def build_finding(
    *,
    vulnerability_type: str,
    url: str,
    method: str,
    parameter: str,
    input_type: str,
    context: RenderContext | str,
    payload_or_probe_id: str,
    evidence: dict[str, Any],
    detection_method: str,
    confidence: str,
    verification_status: str,
    http_status: int | None,
    description: str,
    impact: str,
    confidence_reasons: list[str] | None = None,
    title: str | None = None,
) -> Finding:
    ctx = context.value if isinstance(context, RenderContext) else str(context)
    ctx_enum = context if isinstance(context, RenderContext) else RenderContext.AMBIGUOUS
    stored = "stored" in vulnerability_type.lower()
    sev = severity_for(
        verification_status=verification_status,
        context=ctx_enum,
        stored=stored,
    )
    return Finding(
        vulnerability_type=vulnerability_type,
        title=title
        or (
            f"{'Stored' if stored else 'Reflected'} XSS candidate in parameter '{parameter}'"
        ),
        url=url,
        method=method,
        parameter=parameter,
        input_type=input_type,
        context=ctx,
        payload_or_probe_id=payload_or_probe_id,
        evidence=evidence,
        detection_method=detection_method,
        confidence=confidence,
        severity=sev,
        verification_status=verification_status,
        http_status=http_status,
        description=description,
        impact=impact,
        remediation=REMEDIATION,
        references=list(REFERENCES),
        confidence_reasons=confidence_reasons or [],
        module="xss",
    )


def confidence_from_evidence(
    *,
    reflection_kind: ReflectionKind,
    context: RenderContext,
    metachar_raw: bool,
    browser_confirmed: bool,
    inert_context: bool,
) -> tuple[str, str, list[str]]:
    """Return (confidence, verification_status, reasons)."""
    reasons: list[str] = []

    if browser_confirmed:
        reasons.append("browser_execution_signal_observed")
        return "confirmed", VerificationStatus.CONFIRMED.value, reasons

    if inert_context or context in {RenderContext.HTML_COMMENT, RenderContext.CSS}:
        reasons.append("reflection_in_inert_context")
        return "low", VerificationStatus.REJECTED_SAFE.value, reasons

    if reflection_kind in {ReflectionKind.HTML_ENCODED}:
        reasons.append("marker_or_probe_html_encoded")
        return "low", VerificationStatus.REJECTED_SAFE.value, reasons

    if reflection_kind == ReflectionKind.ABSENT:
        reasons.append("no_reflection")
        return "none", VerificationStatus.NOT_APPLICABLE.value, reasons

    if metachar_raw and context in {
        RenderContext.HTML_BODY,
        RenderContext.HTML_ATTR_DOUBLE,
        RenderContext.HTML_ATTR_SINGLE,
        RenderContext.HTML_ATTR_UNQUOTED,
        RenderContext.JS_STRING_SINGLE,
        RenderContext.JS_STRING_DOUBLE,
        RenderContext.JS_BLOCK,
    }:
        reasons.append("context_appropriate_metacharacters_reflected_raw")
        reasons.append(f"context={context.value}")
        return "high", VerificationStatus.PROBABLE.value, reasons

    if reflection_kind == ReflectionKind.RAW and context not in {
        RenderContext.UNKNOWN,
        RenderContext.AMBIGUOUS,
    }:
        reasons.append("alphanumeric_marker_reflected_raw")
        reasons.append("metacharacter_safety_not_proven")
        return "medium", VerificationStatus.CANDIDATE.value, reasons

    reasons.append("insufficient_evidence_for_exploitability")
    return "low", VerificationStatus.CANDIDATE.value, reasons


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str, str]] = set()
    out: list[Finding] = []
    # Prefer higher verification status when duplicates collide
    rank = {
        VerificationStatus.CONFIRMED.value: 5,
        VerificationStatus.PROBABLE.value: 4,
        VerificationStatus.CANDIDATE.value: 3,
        VerificationStatus.INCONCLUSIVE.value: 2,
        VerificationStatus.REJECTED_SAFE.value: 1,
        VerificationStatus.FAILED.value: 0,
        VerificationStatus.NOT_ATTEMPTED.value: 0,
        VerificationStatus.NOT_APPLICABLE.value: 0,
    }
    best: dict[tuple[str, str, str, str, str], Finding] = {}
    for f in findings:
        key = (
            f.vulnerability_type,
            f.url.split("?", 1)[0],
            f.method.upper(),
            f.parameter,
            f.context,
        )
        prev = best.get(key)
        if prev is None or rank.get(f.verification_status, 0) > rank.get(
            prev.verification_status, 0
        ):
            best[key] = f
    for key, f in best.items():
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
