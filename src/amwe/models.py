"""Core data models shared across all AMWE stages.

Every stage (collect -> profile -> attack -> report) speaks in these types.
They are immutable on purpose: a finding, once produced by a collector,
is never mutated downstream — it is only ever read or wrapped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """How much a single finding helps an attacker."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single piece of public information discovered about the target.

    Attributes:
        source: The collector that produced this finding (e.g. ``"username"``).
        kind: Machine-readable category (e.g. ``"account"``, ``"email-leak"``).
        value: The human-readable fact (e.g. ``"github.com/denis-mci"``).
        severity: How useful this is to an attacker.
        url: Optional public URL backing the finding, for verification.
    """

    source: str
    kind: str
    value: str
    severity: Severity = Severity.INFO
    url: str | None = None


@dataclass(frozen=True, slots=True)
class Target:
    """The subject of a scan. Always the user themselves (see ``verify``)."""

    email: str
    username: str | None = None
    image_url: str | None = None


@dataclass(slots=True)
class ScanResult:
    """The aggregated output of all collectors for one target."""

    target: Target
    findings: list[Finding] = field(default_factory=list)

    def by_source(self, source: str) -> list[Finding]:
        return [f for f in self.findings if f.source == source]


@dataclass(frozen=True, slots=True)
class Profile:
    """The attacker's-eye summary of a scan, assembled on the user's machine.

    Attributes:
        summary: The readable picture the findings add up to.
        source: ``"ollama"`` if a local model wrote it, ``"deterministic"`` otherwise.
    """

    summary: str
    source: str
