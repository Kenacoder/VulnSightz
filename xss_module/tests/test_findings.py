from scanner.models import Finding, VerificationStatus
from xss.context_analyzer import RenderContext
from xss.findings import build_finding, dedupe_findings
from xss.reflection import ReflectionKind
from xss.findings import confidence_from_evidence


def test_encoded_baseline_rejected_safe():
    conf, status, reasons = confidence_from_evidence(
        reflection_kind=ReflectionKind.HTML_ENCODED,
        context=RenderContext.HTML_BODY,
        metachar_raw=False,
        browser_confirmed=False,
        inert_context=False,
    )
    assert status == VerificationStatus.REJECTED_SAFE.value
    assert conf == "low"


def test_inert_marker_not_confirmed():
    conf, status, reasons = confidence_from_evidence(
        reflection_kind=ReflectionKind.RAW,
        context=RenderContext.HTML_COMMENT,
        metachar_raw=False,
        browser_confirmed=False,
        inert_context=True,
    )
    assert status == VerificationStatus.REJECTED_SAFE.value
    assert conf != "confirmed"


def test_dedupe_prefers_higher_verification():
    a = build_finding(
        vulnerability_type="xss.reflected",
        url="http://127.0.0.1:5001/reflect?q=1",
        method="GET",
        parameter="q",
        input_type="text",
        context=RenderContext.HTML_BODY,
        payload_or_probe_id="m1",
        evidence={},
        detection_method="marker_reflection",
        confidence="medium",
        verification_status=VerificationStatus.CANDIDATE.value,
        http_status=200,
        description="d",
        impact="i",
    )
    b = build_finding(
        vulnerability_type="xss.reflected",
        url="http://127.0.0.1:5001/reflect?q=2",
        method="GET",
        parameter="q",
        input_type="text",
        context=RenderContext.HTML_BODY,
        payload_or_probe_id="m2",
        evidence={},
        detection_method="marker_plus_context_probe",
        confidence="high",
        verification_status=VerificationStatus.PROBABLE.value,
        http_status=200,
        description="d",
        impact="i",
    )
    out = dedupe_findings([a, b])
    assert len(out) == 1
    assert out[0].verification_status == VerificationStatus.PROBABLE.value


def test_finding_has_cwe_owasp():
    f = build_finding(
        vulnerability_type="xss.reflected",
        url="http://127.0.0.1:5001/reflect",
        method="GET",
        parameter="q",
        input_type="text",
        context=RenderContext.HTML_BODY,
        payload_or_probe_id="m",
        evidence={},
        detection_method="marker_reflection",
        confidence="medium",
        verification_status=VerificationStatus.CANDIDATE.value,
        http_status=200,
        description="d",
        impact="i",
    )
    assert f.cwe == "CWE-79"
    assert "A05" in f.owasp
    assert isinstance(f, Finding)
