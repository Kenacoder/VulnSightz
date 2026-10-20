"""XSS detection orchestrator — reflected + stored pipelines."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

from scanner.models import Confidence, ScanResult, TestOutcome, VerificationStatus
from xss.browser_verify import (
    build_execution_probe,
    playwright_available,
    verify_url_execution,
)
from xss.config import XSSConfig
from xss.context_analyzer import RenderContext, analyze_contexts
from xss.findings import build_finding, confidence_from_evidence, dedupe_findings
from xss.http_engine import HttpEngine, RequestBudgetExceeded
from xss.input_adapter import InputAdapter, InputPoint
from xss.markers import generate_marker
from xss.reflection import ReflectionKind, classify_marker_reflection
from xss.scope import ScopeController, ScopeError
from xss.stored_xss import StoredXSSEngine
from xss.payload_catalog import catalog_manifest
from xss.verification import (
    evaluate_probe_response,
    select_extended_probes,
    select_probe,
)

logger = logging.getLogger("web_vuln.xss")


def _params_for_point(point: InputPoint, inject_value: str) -> dict[str, str]:
    """Build parameter map injecting into one parameter at a time."""
    if point.source == "form" or point.method.upper() == "POST":
        data = {k: v for k, v in point.form_fields}
        if not data:
            data = {point.parameter: inject_value}
        else:
            data[point.parameter] = inject_value
        return data

    # GET query — preserve other known params from form_fields if any, else single
    params: dict[str, str] = {}
    if point.form_fields:
        params.update({k: v for k, v in point.form_fields})
    # Also pull existing query from URL if present
    existing = parse_qs(urlparse(point.url).query, keep_blank_values=True)
    for k, vals in existing.items():
        params.setdefault(k, vals[0] if vals else "")
    params[point.parameter] = inject_value
    return params


def run_xss_scan(
    crawl_map: dict[str, Any] | None = None,
    *,
    crawl_map_path: str | None = None,
    config: XSSConfig | None = None,
    session: requests.Session | None = None,
) -> ScanResult:
    """Programmatic entry point used by the main scanner and CLI."""
    if config is None:
        raise ValueError("XSSConfig is required")
    config.validate()

    adapter = InputAdapter()
    if crawl_map is None:
        if not crawl_map_path:
            raise ValueError("crawl_map or crawl_map_path is required")
        crawl_map = adapter.load_path(crawl_map_path)
    else:
        crawl_map = adapter.load_data(crawl_map)

    scope = ScopeController(config)
    http = HttpEngine(config, scope, session=session)
    result = ScanResult(module="xss")
    result.limitations.extend(
        [
            "Absence of reflection does not prove an endpoint is safe against all XSS vectors.",
            "DOM-based XSS is not covered by this core pipeline.",
            "Confirmed status requires opt-in browser verification with Playwright.",
        ]
    )

    try:
        points = adapter.extract_input_points(crawl_map)
    except Exception as exc:
        result.errors.append(str(exc))
        return result

    # Filter to in-scope points up front (fail closed per point)
    in_scope: list[InputPoint] = []
    for point in points:
        try:
            scope.check_url(point.url, purpose="input_point")
            in_scope.append(point)
        except ScopeError as exc:
            result.outcomes.append(
                TestOutcome(
                    status="failed",
                    url=point.url,
                    method=point.method,
                    parameter=point.parameter,
                    reason=str(exc),
                )
            )

    findings = []
    try:
        reflected_points = in_scope
        if config.enable_stored_xss:
            # Avoid duplicate state-changing POSTs: stored engine owns forms with renders_to.
            reflected_points = [
                p
                for p in in_scope
                if not (
                    p.source == "form"
                    and p.method.upper() in {"POST", "PUT", "PATCH"}
                    and p.renders_to
                )
            ]
        findings.extend(
            _scan_reflected(reflected_points, config=config, http=http, result=result)
        )
        if config.enable_stored_xss:
            stored = StoredXSSEngine(
                http,
                max_submissions=config.max_stored_submissions,
                render_wait=config.stored_render_wait_seconds,
            )
            s_findings, s_outcomes, s_limits = stored.run(
                in_scope,
                active_verification=config.enable_active_verification,
                metachar_probes=config.enable_metachar_probes,
            )
            findings.extend(s_findings)
            result.outcomes.extend(s_outcomes)
            result.limitations.extend(s_limits)
        else:
            result.limitations.append(
                "stored XSS submission disabled (enable with --enable-stored-xss)"
            )
    except RequestBudgetExceeded as exc:
        result.errors.append(str(exc))
        logger.warning("%s", exc)

    # Drop rejected_safe / not_applicable from findings list — keep as outcomes
    kept = []
    for f in findings:
        if f.verification_status in {
            VerificationStatus.REJECTED_SAFE.value,
            VerificationStatus.NOT_APPLICABLE.value,
        }:
            result.outcomes.append(
                TestOutcome(
                    status="no_finding",
                    url=f.url,
                    method=f.method,
                    parameter=f.parameter,
                    reason="; ".join(f.confidence_reasons) or f.verification_status,
                    http_status=f.http_status,
                    details={"context": f.context, "confidence": f.confidence},
                )
            )
        else:
            kept.append(f)

    result.findings = dedupe_findings(kept)
    result.stats = {
        **http.stats(),
        "input_points_total": len(points),
        "input_points_in_scope": len(in_scope),
        "findings": len(result.findings),
        "marker_only": config.marker_only,
        "active_verification": config.enable_active_verification,
        "stored_xss": config.enable_stored_xss,
        "browser_verification": config.enable_browser_verification,
        "extended_probes": config.enable_extended_probes,
        "payload_catalog": catalog_manifest(),
        "playwright_available": playwright_available(),
    }
    return result


def _scan_reflected(
    points: list[InputPoint],
    *,
    config: XSSConfig,
    http: HttpEngine,
    result: ScanResult,
) -> list[Any]:
    findings: list[Any] = []
    # Prefer GET/query and form fields; skip pure stored-looking duplicates later
    for point in points:
        if point.source == "form" and point.method.upper() == "POST" and point.renders_to:
            # Still test reflection on submission response; stored engine handles persistence.
            pass

        marker = generate_marker()
        params = _params_for_point(point, marker.value)
        method = point.method.upper()

        try:
            if method == "GET":
                resp = http.request(
                    "GET",
                    point.url.split("?", 1)[0],
                    params=params,
                    state_changing=False,
                    dedupe_key=f"reflect:{point.url}:{point.parameter}:{marker.value}",
                )
            else:
                resp = http.request(
                    method,
                    point.url,
                    data=params,
                    state_changing=method in {"POST", "PUT", "PATCH", "DELETE"},
                    dedupe_key=f"reflect:{point.url}:{point.parameter}:{marker.value}",
                )
        except RequestBudgetExceeded:
            raise

        if resp.error:
            status = "inconclusive" if "timeout" in (resp.error or "") else "failed"
            if "out-of-scope" in (resp.error or "") or "not in allowed" in (resp.error or ""):
                status = "failed"
            result.outcomes.append(
                TestOutcome(
                    status=status,
                    url=point.url,
                    method=method,
                    parameter=point.parameter,
                    reason=resp.error,
                    http_status=resp.status_code or None,
                )
            )
            continue

        reflection = classify_marker_reflection(resp.text, marker.value)
        if reflection.kind == ReflectionKind.ABSENT:
            result.outcomes.append(
                TestOutcome(
                    status="no_finding",
                    url=str(resp.url),
                    method=method,
                    parameter=point.parameter,
                    reason="marker_not_reflected",
                    http_status=resp.status_code,
                    details={"marker": marker.value},
                )
            )
            continue

        contexts = analyze_contexts(resp.text, marker.value)
        inert = contexts.primary in {RenderContext.HTML_COMMENT, RenderContext.CSS}
        metachar_raw = False
        probe_id = marker.value
        browser_confirmed = False
        detection_method = "marker_reflection"
        probe_ran = False
        probe_kind: ReflectionKind | None = None

        # Active metachar probes (opt-in, not marker-only)
        if (
            config.enable_active_verification
            and config.enable_metachar_probes
            and not config.marker_only
            and contexts.warrants_verification
            and not inert
        ):
            selected = select_probe(contexts.primary)
            if selected:
                probe_id, probe = selected
                probe_value = marker.value + probe
                probe_params = _params_for_point(point, probe_value)
                try:
                    if method == "GET":
                        probe_resp = http.request(
                            "GET",
                            point.url.split("?", 1)[0],
                            params=probe_params,
                            state_changing=False,
                        )
                    else:
                        probe_resp = http.request(
                            method,
                            point.url,
                            data=probe_params,
                            state_changing=True,
                        )
                except RequestBudgetExceeded:
                    raise

                if not probe_resp.error:
                    probe_result = evaluate_probe_response(
                        probe_resp.text,
                        marker,
                        contexts.primary,
                        probe_id,
                        probe,
                    )
                    probe_ran = True
                    probe_kind = probe_result.reflection_kind
                    metachar_raw = probe_result.metachar_raw
                    detection_method = "marker_plus_context_probe"
                    # Prefer probe response contexts if marker still present
                    if marker.value in probe_resp.text:
                        contexts = analyze_contexts(probe_resp.text, marker.value)
                        resp = probe_resp

                    # Optional curated extended probes (payload-box inspired, budgeted)
                    if (
                        config.enable_extended_probes
                        and config.max_extended_probes > 0
                        and not metachar_raw
                    ):
                        for extra in select_extended_probes(
                            contexts.primary,
                            limit=config.max_extended_probes,
                            include_encoding=True,
                            skip_ids={probe_id},
                        ):
                            extra_value = marker.value + extra.fragment
                            extra_params = _params_for_point(point, extra_value)
                            try:
                                if method == "GET":
                                    extra_resp = http.request(
                                        "GET",
                                        point.url.split("?", 1)[0],
                                        params=extra_params,
                                        state_changing=False,
                                    )
                                else:
                                    extra_resp = http.request(
                                        method,
                                        point.url,
                                        data=extra_params,
                                        state_changing=True,
                                    )
                            except RequestBudgetExceeded:
                                raise
                            if extra_resp.error:
                                continue
                            extra_result = evaluate_probe_response(
                                extra_resp.text,
                                marker,
                                contexts.primary,
                                extra.probe_id,
                                extra.fragment,
                            )
                            probe_ran = True
                            probe_kind = extra_result.reflection_kind
                            probe_id = extra.probe_id
                            detection_method = "marker_plus_extended_catalog_probe"
                            if extra_result.metachar_raw:
                                metachar_raw = True
                                if marker.value in extra_resp.text:
                                    contexts = analyze_contexts(
                                        extra_resp.text, marker.value
                                    )
                                    resp = extra_resp
                                break

        # Optional browser confirmation
        if (
            config.enable_browser_verification
            and config.enable_active_verification
            and contexts.warrants_verification
            and not inert
            and metachar_raw
        ):
            token = generate_marker(prefix="sig").value
            exec_probe = build_execution_probe(token)
            exec_params = _params_for_point(point, exec_probe)
            if method == "GET":
                exec_url = http.build_get_url(point.url.split("?", 1)[0], exec_params)
                try:
                    http.scope.check_url(exec_url, purpose="browser_nav")
                except ScopeError as exc:
                    result.outcomes.append(
                        TestOutcome(
                            status="failed",
                            url=exec_url,
                            method=method,
                            parameter=point.parameter,
                            reason=str(exc),
                        )
                    )
                    exec_url = None
                if exec_url:
                    bres = verify_url_execution(
                        exec_url,
                        signal_token=token,
                        allowed_origins=config.allowed_origins,
                        timeout=config.browser_timeout,
                        cookies=config.cookies or None,
                    )
                    if bres.error and "timeout" in (bres.error or "").lower():
                        result.outcomes.append(
                            TestOutcome(
                                status="inconclusive",
                                url=exec_url,
                                method=method,
                                parameter=point.parameter,
                                reason=bres.error,
                            )
                        )
                    elif bres.attempted and bres.confirmed:
                        browser_confirmed = True
                        detection_method = "browser_execution_signal"
                        probe_id = token
                    elif bres.attempted and not bres.confirmed:
                        result.limitations.append(
                            f"browser verification attempted but signal not observed for {point.parameter}"
                        )
            else:
                result.limitations.append(
                    "browser verification currently applied to GET reflections only"
                )

        # If a context probe proved encoding/escaping, treat as rejected_safe even
        # though the alphanumeric marker itself reflected raw.
        effective_kind = reflection.kind
        if probe_ran and not metachar_raw and probe_kind in {
            ReflectionKind.HTML_ENCODED,
            ReflectionKind.ABSENT,
            ReflectionKind.TRANSFORMED,
        }:
            effective_kind = ReflectionKind.HTML_ENCODED

        conf, vstatus, reasons = confidence_from_evidence(
            reflection_kind=effective_kind,
            context=contexts.primary,
            metachar_raw=metachar_raw,
            browser_confirmed=browser_confirmed,
            inert_context=inert,
        )
        if probe_ran and not metachar_raw:
            reasons.append("context_probe_metacharacters_not_reflected_raw")

        # Marker-only mode: never escalate beyond candidate
        if config.marker_only and vstatus in {
            VerificationStatus.PROBABLE.value,
            VerificationStatus.CONFIRMED.value,
        }:
            vstatus = VerificationStatus.CANDIDATE.value
            conf = Confidence.MEDIUM.value
            reasons.append("marker_only_mode_no_escalation")

        finding = build_finding(
            vulnerability_type="xss.reflected",
            url=str(resp.url),
            method=method,
            parameter=point.parameter,
            input_type=point.input_type,
            context=contexts.primary,
            payload_or_probe_id=probe_id,
            evidence={
                "marker": marker.value,
                "reflection": reflection.to_dict(),
                "contexts": contexts.to_dict(),
                "metachar_raw": metachar_raw,
                "browser_confirmed": browser_confirmed,
                "response_truncated": resp.truncated,
            },
            detection_method=detection_method,
            confidence=conf,
            verification_status=vstatus,
            http_status=resp.status_code,
            description=(
                f"Parameter '{point.parameter}' reflects attacker-controlled input "
                f"in context '{contexts.primary.value}' "
                f"(reflection={reflection.kind.value})."
            ),
            impact=(
                "If exploitable, attackers could execute script in a victim browser "
                "within the application origin."
            ),
            confidence_reasons=reasons,
        )
        findings.append(finding)

    return findings
