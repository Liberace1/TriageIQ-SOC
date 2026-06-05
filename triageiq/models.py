"""Normalized alert and worklist data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Alert:
    """Internal normalized representation of a SOC alert."""

    id: str
    timestamp: str
    rule_name: str
    severity: str
    message: str
    raw: dict[str, Any] = field(repr=False, default_factory=dict)


@dataclass
class Indicator:
    """A single extracted indicator from an alert."""

    kind: str  # "ip", "domain", "hash", or "username"
    value: str


@dataclass
class EnrichmentHit:
    """Result of enriching one indicator against a source."""

    source: str
    indicator: Indicator
    is_malicious: bool
    confidence: float  # 0.0-1.0
    detail: str


@dataclass
class AttackMapping:
    """Likely MITRE ATT&CK technique mapped from alert keywords."""

    technique_id: str
    technique_name: str
    tactic: str
    matched_keyword: str
    matched_field: str  # "rule_name" or "message"
    confidence: float


@dataclass
class ScoredAlert:
    """Alert with enrichment results, risk score, and explanation."""

    alert: Alert
    indicators: list[Indicator]
    enrichments: list[EnrichmentHit]
    score: float
    reason: str
    attack: AttackMapping | None = None


@dataclass
class Case:
    """Deduplicated worklist entry, possibly merged from multiple alerts."""

    representative: ScoredAlert
    alert_count: int
    alert_ids: list[str]

    @property
    def score(self) -> float:
        return self.representative.score

    @property
    def alert(self) -> Alert:
        return self.representative.alert

    @property
    def indicators(self) -> list[Indicator]:
        return self.representative.indicators

    @property
    def enrichments(self) -> list[EnrichmentHit]:
        return self.representative.enrichments

    @property
    def reason(self) -> str:
        return self.representative.reason

    @property
    def attack(self) -> AttackMapping | None:
        return self.representative.attack
