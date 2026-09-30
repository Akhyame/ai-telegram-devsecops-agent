"""Strict normalized security scan contracts for local AI."""

import re
import unicodedata
from enum import StrEnum
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from agent.models import Confidence

MAX_BLOCKING_DETAILS = 5

_RULE_ID_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,127}\Z")


class SecurityScanner(StrEnum):
    """Allowlisted security scanner sources."""

    GITLEAKS = "gitleaks"
    PIP_AUDIT = "pip-audit"
    SEMGREP = "semgrep"
    TRIVY_VULNERABILITY = "trivy-vulnerability"
    TRIVY_MISCONFIGURATION = "trivy-misconfiguration"


class SecuritySeverity(StrEnum):
    """Allowlisted normalized security severities."""

    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityScanDecision(StrEnum):
    """Deterministic decisions produced by the Policy Engine."""

    ALLOW = "allow"
    BLOCK = "block"


class SecurityFindingSummary(BaseModel):
    """Minimal allowlisted blocking finding metadata."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    source: SecurityScanner
    rule_id: str = Field(
        min_length=1,
        max_length=128,
    )
    severity: SecuritySeverity

    @field_validator(
        "rule_id",
        mode="before",
    )
    @classmethod
    def _validate_rule_id(
        cls,
        value: object,
    ) -> object:
        if not isinstance(value, str):
            return value

        normalized = value.strip()

        if (
            any(unicodedata.category(character).startswith("C") for character in normalized)
            or _RULE_ID_PATTERN.fullmatch(normalized) is None
        ):
            raise ValueError("Security finding rule ID is invalid.")

        return normalized


class NormalizedSecurityScan(BaseModel):
    """Bounded Policy Engine result passed to AI."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    decision: SecurityScanDecision
    total_findings: int = Field(
        ge=0,
        le=1000,
    )
    blocking_findings: int = Field(
        ge=0,
        le=100,
    )
    blocking_details: tuple[
        SecurityFindingSummary,
        ...,
    ] = Field(
        default=(),
        max_length=MAX_BLOCKING_DETAILS,
    )
    details_truncated: bool = False

    @model_validator(mode="after")
    def _validate_gate_result(self) -> Self:
        if self.blocking_findings > self.total_findings:
            raise ValueError("Blocking findings cannot exceed total findings.")

        if self.decision is SecurityScanDecision.ALLOW:
            if self.blocking_findings != 0 or self.blocking_details or self.details_truncated:
                raise ValueError("An allowed scan cannot contain blocking evidence.")

            return self

        if self.blocking_findings < 1:
            raise ValueError("A blocked scan requires a blocking finding.")

        expected_details = min(
            self.blocking_findings,
            MAX_BLOCKING_DETAILS,
        )

        if len(self.blocking_details) != expected_details:
            raise ValueError("Blocking detail count does not match gate evidence.")

        expected_truncated = self.blocking_findings > MAX_BLOCKING_DETAILS

        if self.details_truncated is not expected_truncated:
            raise ValueError("Blocking detail truncation marker is invalid.")

        return self


class SecurityScanExplanation(BaseModel):
    """Validated scan summary and remediation returned by local AI."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    summary: str = Field(
        min_length=1,
        max_length=300,
    )
    risk_explanation: str = Field(
        min_length=1,
        max_length=300,
    )
    safe_remediation: str = Field(
        min_length=1,
        max_length=300,
    )
    confidence: Confidence

    @field_validator(
        "summary",
        "risk_explanation",
        "safe_remediation",
        mode="before",
    )
    @classmethod
    def _validate_plain_single_line_text(
        cls,
        value: object,
    ) -> object:
        if not isinstance(value, str):
            return value

        normalized = value.strip()

        if any(unicodedata.category(character).startswith("C") for character in normalized):
            raise ValueError("AI scan explanation contains unsafe control characters.")

        return normalized
