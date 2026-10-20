"""End-to-end XSS engine tests using mocked HTTP responses."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from scanner.models import VerificationStatus
from xss.config import XSSConfig
from xss.engine import run_xss_scan


def _response(url: str, text: str, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.url = url
    resp.is_redirect = False
    resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    resp.encoding = "utf-8"
    resp.iter_content.return_value = [text.encode("utf-8")]
    resp.close = MagicMock()
    return resp


def _config(**kwargs) -> XSSConfig:
    base = dict(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
        marker_only=True,
        max_requests=50,
    )
    base.update(kwargs)
    return XSSConfig(**base)


def _crawl(path: str, param: str = "q") -> dict:
    return {
        "version": "1.0",
        "target": "http://127.0.0.1:5001",
        "pages": [
            {
                "url": f"http://127.0.0.1:5001{path}?{param}=test",
                "method": "GET",
                "params": [
                    {
                        "name": param,
                        "value": "test",
                        "source": "query",
                        "input_type": "text",
                    }
                ],
            }
        ],
        "forms": [],
        "endpoints": [],
    }


def test_encoded_output_zero_confirmed_findings():
    def handler(method, url, **kwargs):
        # Echo query value HTML-encoded
        from urllib.parse import parse_qs, urlparse
        import html as html_mod

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        if not q and kwargs.get("params"):
            q = kwargs["params"].get("q", "")
        body = f"<div>{html_mod.escape(q)}</div>"
        return _response(url, body)

    with patch("requests.Session.request", side_effect=handler):
        # HttpEngine uses session.request — patch on the Session class used by engine
        pass

    cfg = _config()
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            import html as html_mod
            from urllib.parse import urlencode

            params = kwargs.get("params") or {}
            q = params.get("q", "x")
            full = url + ("?" + urlencode(params) if params else "")
            body = f"<div>Result: {html_mod.escape(q)}</div>"
            return _response(full, body)

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=_crawl("/encoded"), config=cfg)

    confirmed = [
        f
        for f in result.findings
        if f.verification_status == VerificationStatus.CONFIRMED.value
    ]
    probable = [
        f
        for f in result.findings
        if f.verification_status == VerificationStatus.PROBABLE.value
    ]
    assert confirmed == []
    assert probable == []


def test_inert_reflection_not_confirmed():
    cfg = _config()
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            params = kwargs.get("params") or {}
            q = params.get("q", "")
            body = f"<!-- user:{q} --><p>ok</p>"
            return _response(url, body)

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=_crawl("/inert"), config=cfg)

    assert all(
        f.verification_status != VerificationStatus.CONFIRMED.value
        for f in result.findings
    )
    # Should be filtered to outcomes as rejected_safe / no finding escalation
    assert not any(
        f.verification_status == VerificationStatus.PROBABLE.value for f in result.findings
    )


def test_raw_body_reflection_candidate():
    cfg = _config(marker_only=True)
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            params = kwargs.get("params") or {}
            q = params.get("q", "")
            body = f"<div>Result: {q}</div>"
            return _response(url, body)

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=_crawl("/reflect"), config=cfg)

    assert len(result.findings) == 1
    assert result.findings[0].verification_status == VerificationStatus.CANDIDATE.value
    assert result.findings[0].cwe == "CWE-79"


def test_multiple_params_tested_independently():
    crawl = {
        "version": "1.0",
        "target": "http://127.0.0.1:5001",
        "pages": [
            {
                "url": "http://127.0.0.1:5001/multi?a=1&b=2",
                "method": "GET",
                "params": [
                    {"name": "a", "value": "1", "source": "query", "input_type": "text"},
                    {"name": "b", "value": "2", "source": "query", "input_type": "text"},
                ],
            }
        ],
        "forms": [],
        "endpoints": [],
    }
    seen_params = []
    cfg = _config()
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            params = kwargs.get("params") or {}
            # Record which param looks like a marker (zzXSS...)
            for k, v in params.items():
                if isinstance(v, str) and v.startswith("zzXSS"):
                    seen_params.append(k)
            a = params.get("a", "")
            b = params.get("b", "")
            import html as html_mod

            body = f"<div>A={a}</div><div>B={html_mod.escape(b)}</div>"
            return _response(url, body)

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=crawl, config=cfg)

    assert "a" in seen_params and "b" in seen_params
    # Parameter a should produce a candidate; b encoded should not confirm
    params_found = {f.parameter for f in result.findings}
    assert "a" in params_found


def test_post_form_handled():
    crawl = {
        "version": "1.0",
        "target": "http://127.0.0.1:5001",
        "pages": [],
        "forms": [
            {
                "action": "http://127.0.0.1:5001/echo",
                "method": "POST",
                "enctype": "application/x-www-form-urlencoded",
                "fields": [
                    {"name": "msg", "value": "", "input_type": "text"},
                    {"name": "submit", "value": "Go", "input_type": "submit"},
                ],
                "renders_to": [],
            }
        ],
        "endpoints": [],
    }
    cfg = _config()
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            assert method == "POST"
            data = kwargs.get("data") or {}
            msg = data.get("msg", "")
            return _response(url, f"<div>{msg}</div>")

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=crawl, config=cfg)

    assert any(f.parameter == "msg" for f in result.findings)


def test_active_metachar_probe_probable():
    cfg = _config(
        marker_only=False,
        enable_active_verification=True,
        enable_metachar_probes=True,
    )
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            params = kwargs.get("params") or {}
            q = params.get("q", "")
            return _response(url, f"<div>Result: {q}</div>")

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=_crawl("/reflect"), config=cfg)

    assert len(result.findings) == 1
    assert result.findings[0].verification_status in {
        VerificationStatus.PROBABLE.value,
        VerificationStatus.CANDIDATE.value,
    }
    # With raw metachar reflection should be probable
    assert result.findings[0].verification_status == VerificationStatus.PROBABLE.value


def test_out_of_scope_input_point_failed_outcome():
    crawl = _crawl("/reflect")
    crawl["pages"][0]["url"] = "http://evil.example/reflect?q=1"
    cfg = _config()
    result = run_xss_scan(crawl_map=crawl, config=cfg)
    assert result.findings == []
    assert any(o.status == "failed" for o in result.outcomes)
