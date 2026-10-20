"""XSS module configuration and policy defaults."""

from __future__ import annotations

from dataclasses import dataclass, field


DEFAULT_USER_AGENT = "WebVulnScanner/0.1 (+authorized-lab; xss-module)"


@dataclass
class XSSConfig:
    """Runtime policy for XSS detection."""

    # Scope — fail closed unless explicitly configured.
    allowed_origins: list[str] = field(default_factory=list)
    allowed_path_prefixes: list[str] = field(default_factory=lambda: ["/"])
    allow_loopback: bool = False
    allow_private_networks: bool = False

    # Modes (safe defaults)
    marker_only: bool = True
    enable_active_verification: bool = False
    enable_stored_xss: bool = False
    enable_browser_verification: bool = False
    enable_metachar_probes: bool = False
    # Extra curated probes adapted from payload-box/xss-payload-list (opt-in).
    enable_extended_probes: bool = False
    max_extended_probes: int = 2

    # Reliability
    timeout: float = 10.0
    connect_timeout: float = 5.0
    max_response_bytes: int = 1_000_000
    max_requests: int = 200
    max_retries: int = 1
    concurrency: int = 1

    # Auth / session
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    user_agent: str = DEFAULT_USER_AGENT

    # Stored XSS
    max_stored_submissions: int = 5
    stored_render_wait_seconds: float = 0.0

    # Browser
    browser_timeout: float = 8.0

    def validate(self) -> None:
        if not self.allowed_origins:
            raise ValueError(
                "allowed_origins is required; crawl_map URLs are not automatic authorization"
            )
        if self.enable_browser_verification and not self.enable_active_verification:
            raise ValueError(
                "enable_browser_verification requires enable_active_verification=True"
            )
        if self.enable_metachar_probes and self.marker_only:
            # metachar probes imply leaving pure marker-only mode
            self.marker_only = False
        if self.enable_extended_probes:
            if not self.enable_active_verification or not self.enable_metachar_probes:
                raise ValueError(
                    "enable_extended_probes requires enable_active_verification "
                    "and enable_metachar_probes"
                )
            self.marker_only = False
        if self.max_extended_probes < 0:
            raise ValueError("max_extended_probes must be >= 0")
        if self.timeout <= 0 or self.connect_timeout <= 0:
            raise ValueError("timeouts must be positive")
        if self.max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
