"""Shared finding and scan-result data models for scanner modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class Confidence(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    NOT_ATTEMPTED = "not_attempted"
    CANDIDATE = "candidate"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    REJECTED_SAFE = "rejected_safe"


@dataclass
class Finding:
    """Stable finding schema consumed by the main scanner reporter."""

    vulnerability_type: str
    title: str
    url: str
    method: str
    parameter: str
    input_type: str
    context: str
    payload_or_probe_id: str
    evidence: dict[str, Any]
    detection_method: str
    confidence: str
    severity: str
    verification_status: str
    http_status: int | None
    description: str
    impact: str
    remediation: str
    id: str = field(default_factory=lambda: str(uuid4()))
    cwe: str = "CWE-79"
    owasp: str = "A05:2025-Injection"
    references: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    confidence_reasons: list[str] = field(default_factory=list)
    module: str = "xss"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TestOutcome:
    """Non-finding outcome for inconclusive/failed tests."""

    status: str  # inconclusive | failed | skipped | no_finding
    url: str
    method: str
    parameter: str
    reason: str
    http_status: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Top-level result returned by detection modules."""

    module: str
    findings: list[Finding] = field(default_factory=list)
    outcomes: list[TestOutcome] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "findings": [f.to_dict() for f in self.findings],
            "outcomes": [o.to_dict() for o in self.outcomes],
            "stats": self.stats,
            "errors": self.errors,
            "limitations": self.limitations,
        }
