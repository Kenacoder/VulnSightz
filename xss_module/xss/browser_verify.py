"""Optional isolated browser verification using Playwright (if installed).

Confirms execution via a unique in-page signal. Never contacts external callbacks.
External navigations/subresources outside allowed origins are aborted.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("web_vuln.xss.browser")


@dataclass
class BrowserVerifyResult:
    attempted: bool
    confirmed: bool
    signal: str | None
    error: str | None = None
    console: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "confirmed": self.confirmed,
            "signal": self.signal,
            "error": self.error,
            "console": self.console or [],
        }


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401

        return True
    except ImportError:
        return False


def build_execution_probe(token: str, template_id: str | None = None) -> str:
    """Harmless unique execution marker for training targets.

    Templates adapted from educational Basic/event-handlers patterns
    (payload-box/xss-payload-list), using an in-page signal instead of alert().
    """
    from xss.payload_catalog import build_catalog_execution_probe

    _probe_id, fragment = build_catalog_execution_probe(token, template_id=template_id)
    return fragment


def verify_url_execution(
    url: str,
    *,
    signal_token: str,
    allowed_origins: list[str],
    timeout: float = 8.0,
    cookies: dict[str, str] | None = None,
) -> BrowserVerifyResult:
    if not playwright_available():
        return BrowserVerifyResult(
            attempted=False,
            confirmed=False,
            signal=None,
            error="playwright_not_installed",
        )

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover
        return BrowserVerifyResult(
            attempted=False,
            confirmed=False,
            signal=None,
            error=f"playwright_import_failed: {exc}",
        )

    allowed = {o.rstrip("/").lower() for o in allowed_origins}
    console_msgs: list[str] = []

    def _origin(u: str) -> str:
        p = urlparse(u)
        return f"{p.scheme}://{p.netloc}".lower()

    browser = None
    context = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(java_script_enabled=True)
            if cookies:
                cookie_list = []
                for name, value in cookies.items():
                    cookie_list.append(
                        {
                            "name": name,
                            "value": value,
                            "url": url,
                        }
                    )
                context.add_cookies(cookie_list)

            page = context.new_page()
            page.on("console", lambda msg: console_msgs.append(msg.text))

            def handle_route(route: Any) -> None:
                req_url = route.request.url
                origin = _origin(req_url)
                if origin not in allowed:
                    logger.debug("browser blocked external request: %s", req_url)
                    route.abort()
                else:
                    route.continue_()

            page.route("**/*", handle_route)
            page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            page.wait_for_timeout(min(500, int(timeout * 100)))
            signal = page.evaluate("() => window.__XSS_SIGNAL__ || null")
            confirmed = signal == signal_token
            return BrowserVerifyResult(
                attempted=True,
                confirmed=confirmed,
                signal=signal if isinstance(signal, str) else None,
                console=console_msgs,
            )
    except Exception as exc:
        logger.warning("browser verification failed: %s", exc)
        return BrowserVerifyResult(
            attempted=True,
            confirmed=False,
            signal=None,
            error=f"browser_error: {exc}",
            console=console_msgs,
        )
    finally:
        try:
            if context is not None:
                context.close()
        except Exception:
            pass
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass
