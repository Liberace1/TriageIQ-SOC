"""TriageIQ - SOC alert enrichment and triage engine."""

__version__ = "0.1.0"

from triageiq.engine import (
    DEFAULT_DEDUP_WINDOW_MINUTES,
    deduplicate_cases,
    extract_indicators,
    ingest_alerts,
    map_alert_to_attack,
    run_pipeline,
    score_alert,
)
from triageiq.enrich import (
    AbuseIPDBEnricher,
    Enricher,
    KnownBadListEnricher,
    default_enrichers,
    enrich_indicators,
)

__all__ = [
    "DEFAULT_DEDUP_WINDOW_MINUTES",
    "AbuseIPDBEnricher",
    "Enricher",
    "KnownBadListEnricher",
    "deduplicate_cases",
    "default_enrichers",
    "enrich_indicators",
    "extract_indicators",
    "ingest_alerts",
    "map_alert_to_attack",
    "run_pipeline",
    "score_alert",
]
