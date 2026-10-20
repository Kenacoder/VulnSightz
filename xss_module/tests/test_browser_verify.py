from unittest.mock import MagicMock, patch

from xss.browser_verify import build_execution_probe, verify_url_execution


def test_build_execution_probe_contains_token():
    probe = build_execution_probe("sigTOKEN1")
    assert "sigTOKEN1" in probe
    assert "__XSS_SIGNAL__" in probe


def test_playwright_missing_returns_not_attempted_confirmed_false():
    with patch("xss.browser_verify.playwright_available", return_value=False):
        result = verify_url_execution(
            "http://127.0.0.1:5001/reflect?q=1",
            signal_token="t",
            allowed_origins=["http://127.0.0.1:5001"],
        )
    assert result.attempted is False
    assert result.confirmed is False
    assert result.error == "playwright_not_installed"


def test_browser_timeout_not_clean_success():
    class FakeTimeout(Exception):
        pass

    with patch("xss.browser_verify.playwright_available", return_value=True):
        with patch("xss.browser_verify.sync_playwright", create=True) as sp:
            # Force import path used inside function
            pass

    with patch("xss.browser_verify.playwright_available", return_value=True):
        import xss.browser_verify as bv

        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()
        mock_pw.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        mock_page.goto.side_effect = Exception("Timeout 8000ms exceeded")

        class CM:
            def __enter__(self):
                return mock_pw

            def __exit__(self, *a):
                return False

        with patch.dict("sys.modules", {"playwright": MagicMock(), "playwright.sync_api": MagicMock()}):
            with patch("playwright.sync_api.sync_playwright", return_value=CM()):
                result = bv.verify_url_execution(
                    "http://127.0.0.1:5001/reflect?q=x",
                    signal_token="tok",
                    allowed_origins=["http://127.0.0.1:5001"],
                    timeout=0.1,
                )
    assert result.confirmed is False
    assert result.attempted is True
    assert result.error is not None


def test_external_requests_blocked_handler():
    """Ensure route handler aborts non-allowed origins."""
    aborted = []

    class Route:
        def __init__(self, url):
            self.request = MagicMock(url=url)

        def abort(self):
            aborted.append(self.request.url)

        def continue_(self):
            pass

    # Exercise the closure logic by running verify with a page that triggers route
    with patch("xss.browser_verify.playwright_available", return_value=True):
        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_page = MagicMock()
        mock_pw.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_context.new_page.return_value = mock_page
        mock_page.evaluate.return_value = None

        handlers = {}

        def route(pattern, handler):
            handlers["h"] = handler

        mock_page.route.side_effect = route

        class CM:
            def __enter__(self):
                return mock_pw

            def __exit__(self, *a):
                return False

        with patch.dict(
            "sys.modules",
            {"playwright": MagicMock(), "playwright.sync_api": MagicMock()},
        ):
            with patch("playwright.sync_api.sync_playwright", return_value=CM()):
                from xss.browser_verify import verify_url_execution

                verify_url_execution(
                    "http://127.0.0.1:5001/reflect",
                    signal_token="tok",
                    allowed_origins=["http://127.0.0.1:5001"],
                )
                assert "h" in handlers
                handlers["h"](Route("http://evil.example/x.js"))
                handlers["h"](Route("http://127.0.0.1:5001/ok.js"))

    assert aborted == ["http://evil.example/x.js"]
    mock_context.close.assert_called()
    mock_browser.close.assert_called()
