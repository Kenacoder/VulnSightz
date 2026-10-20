"""Scope and policy enforcement — fail closed."""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlparse

from xss.config import XSSConfig

logger = logging.getLogger("web_vuln.xss.scope")


class ScopeError(Exception):
    """Raised when a destination is outside authorized scope."""


PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
}


def _normalize_origin(origin: str) -> str:
    origin = origin.strip().rstrip("/")
    parsed = urlparse(origin if "://" in origin else f"http://{origin}")
    if not parsed.scheme or not parsed.netloc:
        raise ScopeError(f"invalid origin: {origin}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def normalize_origins(origins: list[str]) -> list[str]:
    return [_normalize_origin(o) for o in origins]


def _host_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def is_blocked_host(hostname: str, config: XSSConfig) -> str | None:
    """Return a reason string if host is blocked, else None."""
    host = hostname.lower().strip("[]")
    if host in METADATA_HOSTS:
        return "cloud metadata endpoint blocked"

    ip = _host_ip(host)
    if ip is not None:
        if ip.is_loopback and not config.allow_loopback:
            return "loopback address blocked (set allow_loopback for lab targets)"
        if not config.allow_private_networks:
            for net in PRIVATE_NETWORKS:
                if ip in net:
                    return "private/link-local network blocked"
        return None

    # Hostname loopback aliases
    if host in {"localhost", "localhost.localdomain"} and not config.allow_loopback:
        return "loopback hostname blocked (set allow_loopback for lab targets)"
    return None


class ScopeController:
    def __init__(self, config: XSSConfig):
        self.config = config
        self.allowed_origins = normalize_origins(config.allowed_origins)
        self.path_prefixes = config.allowed_path_prefixes or ["/"]

    def check_url(self, url: str, *, purpose: str = "request") -> str:
        """Validate URL is in scope. Returns normalized URL or raises ScopeError."""
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError(f"{purpose}: unsupported scheme in {url!r}")
        if not parsed.netloc:
            raise ScopeError(f"{purpose}: missing host in {url!r}")

        origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        if origin not in self.allowed_origins:
            raise ScopeError(
                f"{purpose}: origin {origin} not in allowed_origins {self.allowed_origins}"
            )

        reason = is_blocked_host(parsed.hostname or "", self.config)
        # Lab exception: if origin is explicitly allowed and allow_loopback/private set,
        # is_blocked_host already accounts for flags. If host is loopback but origin
        # was explicitly allowed with allow_loopback=False, still block.
        if reason:
            raise ScopeError(f"{purpose}: {reason}: {url}")

        path = parsed.path or "/"
        if not any(path.startswith(prefix) for prefix in self.path_prefixes):
            raise ScopeError(
                f"{purpose}: path {path!r} not under allowed_path_prefixes "
                f"{self.path_prefixes}"
            )

        return url

    def check_redirect(self, url: str) -> str:
        return self.check_url(url, purpose="redirect")
