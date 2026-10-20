from xss.reflection import ReflectionKind, classify_marker_reflection, classify_probe_encoding


MARKER = "zzXSS7f3a2cQQ"


def test_marker_absent():
    result = classify_marker_reflection("<div>hello</div>", MARKER)
    assert result.kind == ReflectionKind.ABSENT
    assert result.hits == []


def test_marker_reflected_raw_text():
    body = f"<div>hello {MARKER} world</div>"
    result = classify_marker_reflection(body, MARKER)
    assert result.kind == ReflectionKind.RAW
    assert len(result.hits) >= 1


def test_marker_html_encoded_probe():
    # Alphanumeric marker is raw; probe encoding classification uses metachar variants
    body = f"<div>{MARKER}&lt;script&gt;</div>"
    kind = classify_probe_encoding(body, MARKER, "<script>")
    assert kind == ReflectionKind.HTML_ENCODED


def test_marker_raw_metachar_probe():
    body = f"<div>{MARKER}\"'><</div>"
    kind = classify_probe_encoding(body, MARKER, "\"'><")
    assert kind == ReflectionKind.RAW


def test_marker_partial():
    body = f"<div>{MARKER[:6]}XXX</div>"
    result = classify_marker_reflection(body, MARKER)
    assert result.kind == ReflectionKind.PARTIAL


def test_marker_multiple_times():
    body = f"<div>{MARKER}</div><span>{MARKER}</span>"
    result = classify_marker_reflection(body, MARKER)
    assert len(result.hits) >= 2
