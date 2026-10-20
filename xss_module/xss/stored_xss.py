"""Controlled stored-XSS submission and retrieval (opt-in)."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from scanner.models import Confidence, TestOutcome, VerificationStatus
from xss.context_analyzer import RenderContext, analyze_contexts
from xss.findings import build_finding, confidence_from_evidence
from xss.http_engine import HttpEngine, RequestBudgetExceeded
from xss.input_adapter import InputPoint
from xss.markers import Marker, generate_marker
from xss.reflection import ReflectionKind, classify_marker_reflection
from xss.scope import ScopeError

logger = logging.getLogger("web_vuln.xss.stored")


@dataclass
class StoredAttempt:
    input_point: InputPoint
    marker: Marker
    submission_status: int | None
    submission_error: str | None
    render_results: list[dict[str, Any]] = field(default_factory=list)


class StoredXSSEngine:
    def __init__(self, http: HttpEngine, *, max_submissions: int, render_wait: float):
        self.http = http
        self.max_submissions = max_submissions
        self.render_wait = render_wait
        self.submissions = 0
        self._submitted_keys: set[tuple[str, str, str]] = set()

    def eligible_points(self, points: list[InputPoint]) -> list[InputPoint]:
        return [
            p
            for p in points
            if p.source == "form" and p.method.upper() in {"POST", "PUT"} and p.renders_to
        ]

    def run(
        self,
        points: list[InputPoint],
        *,
        active_verification: bool = False,
        metachar_probes: bool = False,
    ) -> tuple[list[Any], list[TestOutcome], list[str]]:
        findings: list[Any] = []
        outcomes: list[TestOutcome] = []
        limitations: list[str] = []

        eligible = self.eligible_points(points)
        no_render = [
            p
            for p in points
            if p.source == "form" and p.method.upper() in {"POST", "PUT"} and not p.renders_to
        ]
        if no_render:
            limitations.append(
                "some forms lack renders_to relationships; stored XSS cannot be "
                "confirmed absent for those submission points"
            )

        for point in eligible:
            if self.submissions >= self.max_submissions:
                outcomes.append(
                    TestOutcome(
                        status="skipped",
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        reason="max_stored_submissions_reached",
                    )
                )
                continue

            key = (point.url, point.method, point.parameter)
            if key in self._submitted_keys:
                outcomes.append(
                    TestOutcome(
                        status="skipped",
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        reason="duplicate_submission_suppressed",
                    )
                )
                continue

            marker = generate_marker(prefix="zzSXSS")
            data = {k: v for k, v in point.form_fields}
            data[point.parameter] = marker.value

            try:
                resp = self.http.request(
                    point.method,
                    point.url,
                    data=data,
                    state_changing=True,
                    dedupe_key=f"stored:{point.url}:{point.parameter}:{marker.value}",
                )
            except RequestBudgetExceeded as exc:
                outcomes.append(
                    TestOutcome(
                        status="failed",
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        reason=str(exc),
                    )
                )
                break

            self.submissions += 1
            self._submitted_keys.add(key)

            if resp.error or not resp.ok:
                outcomes.append(
                    TestOutcome(
                        status="failed",
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        reason=resp.error or f"submission_http_{resp.status_code}",
                        http_status=resp.status_code or None,
                    )
                )
                continue

            if self.render_wait > 0:
                time.sleep(self.render_wait)

            found_any = False
            for render_url in point.renders_to:
                try:
                    self.http.scope.check_url(render_url, purpose="stored_render")
                except ScopeError as exc:
                    outcomes.append(
                        TestOutcome(
                            status="failed",
                            url=render_url,
                            method="GET",
                            parameter=point.parameter,
                            reason=f"render_out_of_scope: {exc}",
                        )
                    )
                    continue

                try:
                    page = self.http.request("GET", render_url, state_changing=False)
                except RequestBudgetExceeded as exc:
                    outcomes.append(
                        TestOutcome(
                            status="failed",
                            url=render_url,
                            method="GET",
                            parameter=point.parameter,
                            reason=str(exc),
                        )
                    )
                    break

                if page.error:
                    outcomes.append(
                        TestOutcome(
                            status="inconclusive",
                            url=render_url,
                            method="GET",
                            parameter=point.parameter,
                            reason=page.error,
                            http_status=page.status_code or None,
                        )
                    )
                    continue

                reflection = classify_marker_reflection(page.text, marker.value)
                if reflection.kind == ReflectionKind.ABSENT:
                    continue

                found_any = True
                contexts = analyze_contexts(page.text, marker.value)
                inert = contexts.primary in {
                    RenderContext.HTML_COMMENT,
                    RenderContext.CSS,
                }
                metachar_raw = False
                probe_id = marker.value

                # Optional metachar follow-up for stored is intentionally not
                # re-submitted by default to avoid polluting persistent storage.
                conf, vstatus, reasons = confidence_from_evidence(
                    reflection_kind=reflection.kind,
                    context=contexts.primary,
                    metachar_raw=metachar_raw,
                    browser_confirmed=False,
                    inert_context=inert,
                )

                # Marker-only stored reflection is at most a candidate unless inert.
                if vstatus == VerificationStatus.PROBABLE.value and not metachar_raw:
                    vstatus = VerificationStatus.CANDIDATE.value
                    conf = Confidence.MEDIUM.value
                    reasons.append("stored_marker_only_no_metachar_confirmation")

                if vstatus == VerificationStatus.REJECTED_SAFE.value:
                    outcomes.append(
                        TestOutcome(
                            status="no_finding",
                            url=render_url,
                            method=point.method,
                            parameter=point.parameter,
                            reason="; ".join(reasons),
                            http_status=page.status_code,
                            details={
                                "marker": marker.value,
                                "context": contexts.primary.value,
                            },
                        )
                    )
                    continue

                findings.append(
                    build_finding(
                        vulnerability_type="xss.stored",
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        input_type=point.input_type,
                        context=contexts.primary,
                        payload_or_probe_id=probe_id,
                        evidence={
                            "submission_url": point.url,
                            "render_url": render_url,
                            "marker": marker.value,
                            "reflection": reflection.to_dict(),
                            "contexts": contexts.to_dict(),
                            "active_verification": active_verification,
                            "metachar_probes_used": metachar_probes,
                        },
                        detection_method="stored_submit_and_retrieve",
                        confidence=conf,
                        verification_status=vstatus,
                        http_status=page.status_code,
                        description=(
                            f"Stored marker submitted via '{point.parameter}' was later "
                            f"observed on {render_url} in context {contexts.primary.value}."
                        ),
                        impact=(
                            "If exploitable, attackers could persist script that executes "
                            "in other users' browsers viewing the rendering page."
                        ),
                        confidence_reasons=reasons,
                        title=f"Stored XSS candidate via '{point.parameter}'",
                    )
                )

            if not found_any:
                outcomes.append(
                    TestOutcome(
                        status="no_finding",
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        reason="marker_not_found_on_render_pages",
                        http_status=resp.status_code,
                        details={"marker": marker.value, "renders_to": list(point.renders_to)},
                    )
                )

        return findings, outcomes, limitations
