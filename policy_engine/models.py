from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GateDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class Finding:
    source: str
    rule_id: str
    severity: Severity
    title: str
    location: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityPolicy:
    blocked_severities: frozenset[Severity] = field(
        default_factory=lambda: frozenset(
            {
                Severity.HIGH,
                Severity.CRITICAL,
            }
        )
    )
    block_on_unknown: bool = True


@dataclass(frozen=True, slots=True)
class GateResult:
    decision: GateDecision
    total_findings: int
    blocking_findings: tuple[Finding, ...]
    reasons: tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.decision is GateDecision.ALLOW
