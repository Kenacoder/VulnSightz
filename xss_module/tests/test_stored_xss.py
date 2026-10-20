from unittest.mock import MagicMock, patch

from scanner.models import VerificationStatus
from xss.config import XSSConfig
from xss.engine import run_xss_scan


def _response(url: str, text: str, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.url = url
    resp.is_redirect = False
    resp.headers = {"Content-Type": "text/html"}
    resp.encoding = "utf-8"
    resp.iter_content.return_value = [text.encode("utf-8")]
    resp.close = MagicMock()
    return resp


CRAWL = {
    "version": "1.0",
    "target": "http://127.0.0.1:5001",
    "pages": [],
    "forms": [
        {
            "action": "http://127.0.0.1:5001/comment",
            "method": "POST",
            "enctype": "application/x-www-form-urlencoded",
            "fields": [
                {"name": "body", "value": "", "input_type": "textarea"},
                {"name": "submit", "value": "Post", "input_type": "submit"},
            ],
            "renders_to": ["http://127.0.0.1:5001/comments"],
        }
    ],
    "endpoints": [],
}


def test_stored_marker_found_on_render_page():
    store = {"body": None}
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
        enable_stored_xss=True,
        marker_only=True,
        max_requests=50,
    )
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            if method == "POST":
                data = kwargs.get("data") or {}
                store["body"] = data.get("body")
                return _response(url, "ok", status=302)
            # GET render
            body = f"<ul><li>{store['body']}</li></ul>"
            return _response(url, body)

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=CRAWL, config=cfg)

    stored = [f for f in result.findings if f.vulnerability_type == "xss.stored"]
    assert len(stored) == 1
    assert stored[0].verification_status == VerificationStatus.CANDIDATE.value


def test_stored_marker_not_found():
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
        enable_stored_xss=True,
        marker_only=True,
        max_requests=50,
    )
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            if method == "POST":
                return _response(url, "ok", status=200)
            return _response(url, "<ul></ul>")

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=CRAWL, config=cfg)

    assert not any(f.vulnerability_type == "xss.stored" for f in result.findings)
    assert any("marker_not_found" in o.reason for o in result.outcomes)


def test_failed_submission_not_success():
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
        enable_stored_xss=True,
        max_requests=50,
    )
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            if method == "POST":
                return _response(url, "nope", status=500)
            return _response(url, "<ul></ul>")

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=CRAWL, config=cfg)

    assert not any(f.vulnerability_type == "xss.stored" for f in result.findings)
    assert any(o.status == "failed" for o in result.outcomes)


def test_repeated_submissions_controlled():
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
        enable_stored_xss=True,
        max_stored_submissions=1,
        max_requests=50,
    )
    # Two identical forms
    crawl = {
        "version": "1.0",
        "target": "http://127.0.0.1:5001",
        "pages": [],
        "forms": CRAWL["forms"] + CRAWL["forms"],
        "endpoints": [],
    }
    posts = {"n": 0}
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            if method == "POST":
                posts["n"] += 1
                return _response(url, "ok")
            return _response(url, "<ul></ul>")

        sess.request.side_effect = req
        run_xss_scan(crawl_map=crawl, config=cfg)

    assert posts["n"] == 1


def test_render_out_of_scope_never_fetched():
    crawl = {
        "version": "1.0",
        "target": "http://127.0.0.1:5001",
        "pages": [],
        "forms": [
            {
                "action": "http://127.0.0.1:5001/comment",
                "method": "POST",
                "fields": [{"name": "body", "value": "", "input_type": "text"}],
                "renders_to": ["http://evil.example/comments"],
            }
        ],
        "endpoints": [],
    }
    fetched = []
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
        enable_stored_xss=True,
        max_requests=50,
    )
    with patch("xss.http_engine.requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()

        def req(method, url, **kwargs):
            fetched.append(url)
            return _response(url, "ok")

        sess.request.side_effect = req
        result = run_xss_scan(crawl_map=crawl, config=cfg)

    assert not any("evil.example" in u for u in fetched)
    assert any("render_out_of_scope" in o.reason for o in result.outcomes)
