"""Unique non-executable marker generation and encoding variants."""

from __future__ import annotations

import html
import secrets
import string
from dataclasses import dataclass


ALPHANUM = string.ascii_letters + string.digits


@dataclass(frozen=True)
class Marker:
    value: str

    @property
    def html_escaped(self) -> str:
        # Alphanumeric markers typically unchanged; keep for API consistency.
        return html.escape(self.value, quote=True)

    def with_probe(self, probe: str) -> str:
        return f"{self.value}{probe}"


def generate_marker(prefix: str = "zzXSS") -> Marker:
    """Generate an unpredictable alphanumeric marker (non-executable)."""
    # Example shape: zzXSS7f3a2cQQ
    token = "".join(secrets.choice(ALPHANUM) for _ in range(8))
    return Marker(value=f"{prefix}{token}")


# Context-sensitive metacharacter probes (used only when explicitly enabled).
# These are intentionally short breakout probes for training targets — not exploit chains.
PROBE_HTML_BODY = "\"'><"
PROBE_ATTR_DOUBLE = "\" autofocus onfocus=/*"
PROBE_ATTR_SINGLE = "' autofocus onfocus=/*"
PROBE_JS_SINGLE = "';//"
PROBE_JS_DOUBLE = '";//'
PROBE_URL = "javascript:/*"

# Harmless browser-execution signal used only with opt-in browser verification.
# Unique token is substituted at runtime.
BROWSER_SIGNAL_TEMPLATE = (
    "<img src=x onerror=\"window.__XSS_SIGNAL__='{token}'\">"
)
