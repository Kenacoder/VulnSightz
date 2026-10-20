"""HTTP request engine with scope checks, budgets, and size limits."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import requests

from scanner.logging_utils import redact_mapping, redact_text
from xss.config import XSSConfig
from xss.scope import ScopeController, ScopeError

logger = logging.getLogger("web_vuln.xss.http")


class RequestBudgetExceeded(Exception):
    """Raised when the configured request budget is exhausted."""


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    truncated: bool = False
    error: str | None = None
    redirected: bool = False
    history_urls: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400


class HttpEngine:
    def __init__(self, config: XSSConfig, scope: ScopeController, session: requests.Session | None = None):
        self.config = config
        self.scope = scope
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = config.user_agent
        if config.headers:
            self.session.headers.update(config.headers)
        if config.cookies:
            self.session.cookies.update(config.cookies)
        self.request_count = 0
        self.failure_count = 0
        self._seen_keys: set[str] = set()

    def remaining_budget(self) -> int:
        return max(0, self.config.max_requests - self.request_count)

    def _budget_check(self) -> None:
        if self.request_count >= self.config.max_requests:
            raise RequestBudgetExceeded(
                f"request budget exhausted ({self.config.max_requests})"
            )

    def build_get_url(self, base_url: str, params: dict[str, str]) -> str:
        parts = urlparse(base_url)
        # Preserve existing query keys not being overridden? Caller supplies full params.
        query = urlencode(list(params.items()), doseq=True)
        return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, query, ""))

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        allow_redirects: bool = True,
        state_changing: bool = False,
        dedupe_key: str | None = None,
    ) -> HttpResponse:
        self._budget_check()
        method = method.upper()
        if dedupe_key and dedupe_key in self._seen_keys:
            logger.debug("skipping duplicate request key=%s", dedupe_key)
            return HttpResponse(
                url=url,
                status_code=0,
                headers={},
                text="",
                error="duplicate_skipped",
            )
        if dedupe_key:
            self._seen_keys.add(dedupe_key)

        try:
            target = self.scope.check_url(url, purpose="request")
        except ScopeError as exc:
            self.failure_count += 1
            logger.warning("scope rejected request: %s", exc)
            return HttpResponse(url=url, status_code=0, headers={}, text="", error=str(exc))

        timeout = (self.config.connect_timeout, self.config.timeout)
        retries = 0 if state_changing else self.config.max_retries
        last_error: str | None = None

        for attempt in range(retries + 1):
            self.request_count += 1
            try:
                # Manual redirect handling for per-hop scope validation.
                resp = self.session.request(
                    method,
                    target,
                    params=params if method == "GET" else None,
                    data=data if method != "GET" else None,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                )
                history: list[str] = []
                redirected = False
                hops = 0
                while allow_redirects and resp.is_redirect and hops < 5:
                    loc = resp.headers.get("Location")
                    if not loc:
                        break
                    next_url = urljoin(str(resp.url), loc)
                    try:
                        next_url = self.scope.check_redirect(next_url)
                    except ScopeError as exc:
                        self.failure_count += 1
                        return HttpResponse(
                            url=str(resp.url),
                            status_code=resp.status_code,
                            headers={k: v for k, v in resp.headers.items()},
                            text="",
                            error=f"out-of-scope redirect: {exc}",
                            redirected=True,
                            history_urls=history,
                        )
                    history.append(next_url)
                    redirected = True
                    hops += 1
                    self.request_count += 1
                    if self.request_count > self.config.max_requests:
                        raise RequestBudgetExceeded("request budget exhausted during redirects")
                    resp = self.session.request(
                        "GET",
                        next_url,
                        timeout=timeout,
                        allow_redirects=False,
                        stream=True,
                    )

                content = self._read_limited(resp)
                text, truncated = content
                safe_headers = redact_mapping({k: v for k, v in resp.headers.items()})
                logger.debug(
                    "%s %s -> %s truncated=%s",
                    method,
                    redact_text(str(resp.url)),
                    resp.status_code,
                    truncated,
                )
                return HttpResponse(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(safe_headers),
                    text=text,
                    truncated=truncated,
                    redirected=redirected,
                    history_urls=history,
                )
            except RequestBudgetExceeded:
                raise
            except requests.Timeout as exc:
                last_error = f"timeout: {exc}"
                self.failure_count += 1
                logger.warning("timeout on %s %s", method, redact_text(target))
            except requests.RequestException as exc:
                last_error = f"request_error: {exc}"
                self.failure_count += 1
                logger.warning("request error on %s %s: %s", method, redact_text(target), exc)
            if state_changing:
                break

        return HttpResponse(
            url=url,
            status_code=0,
            headers={},
            text="",
            error=last_error or "unknown_error",
        )

    def _read_limited(self, resp: requests.Response) -> tuple[str, bool]:
        max_bytes = self.config.max_response_bytes
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    remain = max_bytes - (total - len(chunk))
                    if remain > 0:
                        chunks.append(chunk[:remain])
                    truncated = True
                    break
                chunks.append(chunk)
        finally:
            resp.close()
        raw = b"".join(chunks)
        encoding = resp.encoding or "utf-8"
        try:
            return raw.decode(encoding, errors="replace"), truncated
        except LookupError:
            return raw.decode("utf-8", errors="replace"), truncated

    def stats(self) -> dict[str, Any]:
        return {
            "request_count": self.request_count,
            "failure_count": self.failure_count,
            "remaining_budget": self.remaining_budget(),
            "max_requests": self.config.max_requests,
        }
