from unittest.mock import MagicMock, patch

import pytest
import requests

from xss.config import XSSConfig
from xss.http_engine import HttpEngine, RequestBudgetExceeded
from xss.scope import ScopeController


def _cfg(**kwargs):
    base = dict(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
        max_requests=5,
        timeout=2.0,
        connect_timeout=1.0,
    )
    base.update(kwargs)
    return XSSConfig(**base)


def test_request_budget_enforced():
    cfg = _cfg(max_requests=1)
    scope = ScopeController(cfg)
    engine = HttpEngine(cfg, scope)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "http://127.0.0.1:5001/reflect"
    mock_resp.is_redirect = False
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [b"ok"]
    mock_resp.close = MagicMock()

    with patch.object(engine.session, "request", return_value=mock_resp):
        engine.request("GET", "http://127.0.0.1:5001/reflect")
        with pytest.raises(RequestBudgetExceeded):
            engine.request("GET", "http://127.0.0.1:5001/reflect?q=2")


def test_out_of_scope_redirect_rejected():
    cfg = _cfg()
    scope = ScopeController(cfg)
    engine = HttpEngine(cfg, scope)

    redirect = MagicMock()
    redirect.status_code = 302
    redirect.url = "http://127.0.0.1:5001/redirect-external"
    redirect.is_redirect = True
    redirect.headers = {"Location": "http://example.com/"}
    redirect.encoding = "utf-8"
    redirect.iter_content.return_value = []
    redirect.close = MagicMock()

    with patch.object(engine.session, "request", return_value=redirect):
        resp = engine.request("GET", "http://127.0.0.1:5001/redirect-external")
    assert resp.error is not None
    assert "out-of-scope redirect" in resp.error


def test_timeout_reported():
    cfg = _cfg()
    scope = ScopeController(cfg)
    engine = HttpEngine(cfg, scope)

    with patch.object(
        engine.session, "request", side_effect=requests.Timeout("slow")
    ):
        resp = engine.request("GET", "http://127.0.0.1:5001/reflect")
    assert resp.error is not None
    assert "timeout" in resp.error
