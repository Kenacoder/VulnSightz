import pytest

from xss.config import XSSConfig
from xss.context_analyzer import RenderContext
from xss.payload_catalog import (
    SOURCE_REPO,
    build_catalog_execution_probe,
    catalog_manifest,
    primary_probe_for,
    probes_for_context,
)
from xss.verification import select_extended_probes, select_probe


def test_catalog_has_context_probes():
    assert primary_probe_for(RenderContext.HTML_BODY) is not None
    assert primary_probe_for(RenderContext.JS_STRING_SINGLE) is not None
    assert primary_probe_for(RenderContext.HTML_ATTR_DOUBLE) is not None


def test_select_probe_uses_catalog_ids():
    probe_id, fragment = select_probe(RenderContext.HTML_BODY)
    assert probe_id.startswith("pb.")
    assert "<" in fragment or "'" in fragment or '"' in fragment


def test_execution_templates_use_signal_not_alert():
    probe_id, html = build_catalog_execution_probe("tok123")
    assert "tok123" in html
    assert "__XSS_SIGNAL__" in html
    assert "alert(" not in html
    assert "document.cookie" not in html
    assert probe_id.startswith("pb.exec.")


def test_extended_probes_skip_primary():
    primary = primary_probe_for(RenderContext.HTML_BODY)
    assert primary is not None
    extras = select_extended_probes(
        RenderContext.HTML_BODY, limit=2, skip_ids={primary.probe_id}
    )
    assert all(p.probe_id != primary.probe_id for p in extras)


def test_manifest_excludes_aggressive_lists():
    manifest = catalog_manifest()
    assert SOURCE_REPO in manifest["source"]
    joined = " ".join(manifest["excluded"]).lower()
    assert "blind" in joined
    assert "waf" in joined
    assert "all-in-one" in joined


def test_extended_probes_require_active_flags():
    with pytest.raises(ValueError):
        XSSConfig(
            allowed_origins=["http://127.0.0.1:5001"],
            allow_loopback=True,
            enable_extended_probes=True,
            enable_active_verification=False,
            enable_metachar_probes=False,
        ).validate()


def test_encoding_probes_only_for_body_when_requested():
    body = probes_for_context(
        RenderContext.HTML_BODY, include_encoding=True, limit=10
    )
    assert any("encoding" in p.probe_id for p in body)
    attr = probes_for_context(
        RenderContext.HTML_ATTR_DOUBLE, include_encoding=True, limit=10
    )
    assert not any("encoding" in p.probe_id for p in attr)
