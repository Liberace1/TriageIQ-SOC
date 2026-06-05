"""Ingest, extract, score, ATT&CK map, dedup, and pipeline."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from triageiq.enrich import Enricher, default_enrichers, enrich_indicators
from triageiq.models import Alert, AttackMapping, Case, Indicator, ScoredAlert

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_DEDUP_WINDOW_MINUTES = 60
DEFAULT_ATTACK_MAP_PATH = FIXTURES_DIR / "attack_map.json"

SEVERITY_ALIASES = {
    "info": "low",
    "informational": "low",
    "warning": "medium",
    "warn": "medium",
    "error": "high",
    "critical": "critical",
}
SEVERITY_WEIGHTS = {"low": 2.0, "medium": 5.0, "high": 8.0, "critical": 10.0}
MALICIOUS_HIT_WEIGHT = 4.0
CLEAN_HIT_WEIGHT = -1.0

# --- ingest ---

def ingest_alerts(path: str | Path) -> list[Alert]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Alert file must contain a JSON array")
    alerts: list[Alert] = []
    for raw in data:
        alert_id = str(raw.get("id") or raw.get("alert_id") or "")
        if not alert_id:
            raise ValueError(f"Alert missing required id field: {raw}")
        sev = str(raw.get("severity") or "medium").strip().lower()
        alerts.append(
            Alert(
                id=alert_id,
                timestamp=str(raw.get("timestamp") or raw.get("time") or ""),
                rule_name=str(raw.get("rule_name") or raw.get("rule") or "unknown"),
                severity=SEVERITY_ALIASES.get(sev, sev),
                message=str(raw.get("message") or raw.get("description") or ""),
                raw=raw,
            )
        )
    return alerts


# --- extract ---

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_USER_RE = re.compile(r"\b([A-Za-z0-9_.-]+)\\([A-Za-z0-9_.-]+)\b")
SKIP_DOMAINS = frozenset({"example.com", "local", "localhost"})
SKIP_USERNAMES = frozenset({"system", "local service", "network service", "anonymous"})


def _collect_strings(raw: dict) -> list[str]:
    values: list[str] = []
    for val in raw.values():
        if isinstance(val, str) and val.strip():
            values.append(val)
        elif isinstance(val, list):
            values.extend(str(v) for v in val if v)
    return values


def _normalize_username(value: str) -> str | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    if "\\" in cleaned:
        cleaned = cleaned.rsplit("\\", 1)[-1]
    elif "@" in cleaned:
        cleaned = cleaned.split("@", 1)[0]
    normalized = cleaned.lower()
    if normalized in SKIP_USERNAMES or len(normalized) < 2:
        return None
    return normalized


def extract_indicators(alert: Alert) -> list[Indicator]:
    seen: set[tuple[str, str]] = set()
    indicators: list[Indicator] = []

    def add(kind: str, value: str) -> None:
        normalized = value.strip().lower() if kind in ("domain", "username", "hash") else value.strip()
        key = (kind, normalized)
        if key not in seen:
            seen.add(key)
            indicators.append(Indicator(kind=kind, value=normalized))

    def add_hashes(text: str) -> None:
        for pattern in (SHA256_RE, SHA1_RE, MD5_RE):
            for match in pattern.findall(text):
                add("hash", match)

    raw = alert.raw
    for field in ("source_ip", "dest_ip", "destination_ip", "src_ip", "dst_ip", "ip"):
        if raw.get(field):
            for match in IPV4_RE.findall(str(raw[field])):
                add("ip", match)
    for field in ("domain", "hostname", "dns_query", "url"):
        if raw.get(field):
            for match in DOMAIN_RE.findall(str(raw[field])):
                if match.lower() not in SKIP_DOMAINS:
                    add("domain", match)
    for field in ("file_hash", "sha256", "sha1", "md5", "hash", "file_md5", "imphash"):
        if raw.get(field):
            add_hashes(str(raw[field]))
    for field in ("username", "user", "account", "user_name", "src_user", "dest_user", "target_user"):
        if raw.get(field):
            username = _normalize_username(str(raw[field]))
            if username:
                add("username", username)

    text_blob = " ".join(_collect_strings(raw))
    for match in IPV4_RE.findall(text_blob):
        add("ip", match)
    for match in DOMAIN_RE.findall(text_blob):
        if match.lower() not in SKIP_DOMAINS:
            add("domain", match)
    add_hashes(text_blob)
    for _domain, user in DOMAIN_USER_RE.findall(text_blob):
        username = _normalize_username(user)
        if username:
            add("username", username)
    return indicators


# --- ATT&CK map ---

@dataclass(frozen=True)
class _AttackRule:
    keywords: tuple[str, ...]
    technique_id: str
    technique_name: str
    tactic: str


def _attack_rules(path: Path) -> list[_AttackRule]:
    return [
        _AttackRule(
            keywords=tuple(k.lower() for k in entry["keywords"]),
            technique_id=entry["technique_id"],
            technique_name=entry["technique_name"],
            tactic=entry["tactic"],
        )
        for entry in json.loads(path.read_text(encoding="utf-8"))
    ]


def _keyword_match(text: str, rules: list[_AttackRule]) -> tuple[_AttackRule, str] | None:
    lowered = text.lower()
    best: tuple[_AttackRule, str, int] | None = None
    for rule in rules:
        for keyword in rule.keywords:
            if keyword in lowered and (best is None or len(keyword) > best[2]):
                best = (rule, keyword, len(keyword))
    return (best[0], best[1]) if best else None


def map_alert_to_attack(alert: Alert, map_path: str | Path | None = None) -> AttackMapping | None:
    rules = _attack_rules(Path(map_path) if map_path else DEFAULT_ATTACK_MAP_PATH)
    for field, confidence in (("rule_name", 0.85), ("message", 0.65)):
        hit = _keyword_match(getattr(alert, field), rules)
        if hit:
            rule, keyword = hit
            return AttackMapping(
                technique_id=rule.technique_id,
                technique_name=rule.technique_name,
                tactic=rule.tactic,
                matched_keyword=keyword,
                matched_field=field,
                confidence=confidence,
            )
    return None


# --- score ---

def score_alert(
    alert: Alert,
    indicators: list[Indicator],
    enrichments: list,
    attack: AttackMapping | None = None,
) -> ScoredAlert:
    base = SEVERITY_WEIGHTS.get(alert.severity.lower(), 5.0)
    reasons: list[str] = [f"base severity '{alert.severity}' ({base:.0f})"]
    malicious_hits = [h for h in enrichments if h.is_malicious]
    unique_bad = sorted({h.indicator.value for h in malicious_hits})

    if unique_bad:
        rep = len(unique_bad) * MALICIOUS_HIT_WEIGHT
        reasons.append(
            f"{len(unique_bad)} malicious indicator(s): {', '.join(unique_bad)} (+{rep:.0f})"
        )
        abuse_notes = [
            h.detail.split(" (", 1)[0]
            for h in malicious_hits
            if h.source == "abuseipdb" and h.is_malicious
        ]
        if abuse_notes:
            reasons.append("AbuseIPDB: " + "; ".join(dict.fromkeys(abuse_notes)))
        delta = rep
    elif indicators:
        delta = len(indicators) * CLEAN_HIT_WEIGHT
        reasons.append(f"{len(indicators)} indicator(s) not on blocklist ({delta:.0f})")
    else:
        delta = 0.0
        reasons.append("no indicators extracted (0)")

    final = max(0.0, min(100.0, base + delta))
    return ScoredAlert(
        alert=alert,
        indicators=indicators,
        enrichments=enrichments,
        score=final,
        reason="; ".join(reasons) + f" -> score {final:.1f}",
        attack=attack,
    )


# --- dedup ---

def _parse_timestamp(ts: str) -> datetime:
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _cluster_key(scored: ScoredAlert, window_minutes: int) -> tuple[str, str, str, int]:
    malicious = [h.indicator for h in scored.enrichments if h.is_malicious]
    if malicious:
        indicator = malicious[0]
    elif scored.indicators:
        indicator = sorted(scored.indicators, key=lambda i: (i.kind, i.value))[0]
    else:
        return (scored.alert.rule_name, "none", scored.alert.id, 0)
    bucket = int(_parse_timestamp(scored.alert.timestamp).timestamp()) // (window_minutes * 60)
    return (scored.alert.rule_name, indicator.kind, indicator.value, bucket)


def deduplicate_cases(
    scored: list[ScoredAlert],
    window_minutes: int = DEFAULT_DEDUP_WINDOW_MINUTES,
) -> list[Case]:
    clusters: dict[tuple[str, str, str, int], list[ScoredAlert]] = {}
    for item in scored:
        clusters.setdefault(_cluster_key(item, window_minutes), []).append(item)

    cases: list[Case] = []
    for members in clusters.values():
        rep = max(members, key=lambda s: (s.score, s.alert.timestamp, s.alert.id))
        alert_ids = sorted(m.alert.id for m in members)
        reason = rep.reason
        if len(members) > 1:
            reason += f"; deduped {len(members)} alerts ({', '.join(alert_ids)})"
        cases.append(
            Case(
                representative=replace(rep, reason=reason),
                alert_count=len(members),
                alert_ids=alert_ids,
            )
        )
    return sorted(cases, key=lambda c: c.score, reverse=True)


# --- pipeline ---

def run_pipeline(
    alerts_path: str | Path,
    known_bad_path: str | Path | None = None,
    enrichers: list[Enricher] | None = None,
    dedup_window_minutes: int = DEFAULT_DEDUP_WINDOW_MINUTES,
    attack_map_path: str | Path | None = None,
    abuseipdb_cache_path: str | Path | None = None,
    offline: bool = True,
    abuseipdb_api_key: str | None = None,
) -> list[Case]:
    if enrichers is None:
        enrichers = default_enrichers(
            known_bad_path=known_bad_path,
            abuseipdb_cache_path=abuseipdb_cache_path,
            offline=offline,
            api_key=abuseipdb_api_key,
        )

    scored: list[ScoredAlert] = []
    for alert in ingest_alerts(alerts_path):
        indicators = extract_indicators(alert)
        enrichments = enrich_indicators(indicators, enrichers)
        attack = map_alert_to_attack(alert, map_path=attack_map_path)
        scored.append(score_alert(alert, indicators, enrichments, attack=attack))

    return deduplicate_cases(scored, window_minutes=dedup_window_minutes)
