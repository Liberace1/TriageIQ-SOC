"""Pluggable enrichment sources and orchestration."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable

from triageiq.models import EnrichmentHit, Indicator

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_KNOWN_BAD_PATH = FIXTURES_DIR / "known_bad.txt"
DEFAULT_ABUSEIPDB_CACHE = FIXTURES_DIR / "abuseipdb_cache.json"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
MALICIOUS_SCORE_THRESHOLD = 75

IPV4_LINE_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
HASH_LINE_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


class Enricher(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def enrich(self, indicator: Indicator) -> EnrichmentHit | None: ...


def enrich_indicators(
    indicators: list[Indicator], enrichers: list[Enricher]
) -> list[EnrichmentHit]:
    hits: list[EnrichmentHit] = []
    for indicator in indicators:
        for enricher in enrichers:
            result = enricher.enrich(indicator)
            if result is not None:
                hits.append(result)
    return hits


class KnownBadListEnricher(Enricher):
    """Offline blocklist for IPs, domains, hashes, and usernames."""

    def __init__(self, list_path: str | Path | None = None) -> None:
        path = Path(list_path) if list_path else DEFAULT_KNOWN_BAD_PATH
        self._bad_ips: set[str] = set()
        self._bad_domains: set[str] = set()
        self._bad_hashes: set[str] = set()
        self._bad_usernames: set[str] = set()
        self._load(path)

    @property
    def name(self) -> str:
        return "known_bad_list"

    def _classify_entry(self, entry: str) -> tuple[str, str]:
        if IPV4_LINE_RE.match(entry):
            return "ip", entry
        lower = entry.lower()
        if HASH_LINE_RE.match(lower):
            return "hash", lower
        if "." in entry and not entry.replace(".", "").isdigit():
            return "domain", lower
        return "username", lower

    def _load(self, path: Path) -> None:
        for line in path.read_text(encoding="utf-8").splitlines():
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            kind, value = self._classify_entry(entry)
            if kind == "ip":
                self._bad_ips.add(value)
            elif kind == "domain":
                self._bad_domains.add(value)
            elif kind == "hash":
                self._bad_hashes.add(value)
            else:
                self._bad_usernames.add(value)

    def enrich(self, indicator: Indicator) -> EnrichmentHit | None:
        tables = {
            "ip": self._bad_ips,
            "domain": self._bad_domains,
            "hash": self._bad_hashes,
            "username": self._bad_usernames,
        }
        if indicator.kind not in tables:
            return None
        if indicator.value in tables[indicator.kind]:
            conf = 0.90 if indicator.kind == "username" else 0.95
            return EnrichmentHit(
                source=self.name,
                indicator=indicator,
                is_malicious=True,
                confidence=conf,
                detail=f"{indicator.kind} {indicator.value} is on local known-bad list",
            )
        return EnrichmentHit(
            source=self.name,
            indicator=indicator,
            is_malicious=False,
            confidence=0.0,
            detail=f"No match in known-bad list for {indicator.value}",
        )


class AbuseIPDBEnricher(Enricher):
    """IP reputation via cached fixtures (default) or live API."""

    def __init__(
        self,
        cache_path: str | Path | None = None,
        offline: bool = True,
        api_key: str | None = None,
        live_fetcher: Callable[[str], dict[str, Any] | None] | None = None,
    ) -> None:
        path = Path(cache_path) if cache_path else DEFAULT_ABUSEIPDB_CACHE
        self._offline = offline
        self._api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
        self._live_fetcher = live_fetcher or self._fetch_live
        self._cache: dict[str, dict[str, Any]] = {}
        if self._offline:
            self._cache = json.loads(path.read_text(encoding="utf-8"))

    @property
    def name(self) -> str:
        return "abuseipdb"

    def _fetch_live(self, ip: str) -> dict[str, Any] | None:
        if not self._api_key:
            return None
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        request = urllib.request.Request(
            f"{ABUSEIPDB_CHECK_URL}?{query}",
            headers={"Key": self._api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
            return None
        return payload.get("data")

    def enrich(self, indicator: Indicator) -> EnrichmentHit | None:
        if indicator.kind != "ip":
            return None
        record = self._cache.get(indicator.value) if self._offline else self._live_fetcher(indicator.value)
        if record is None:
            return None
        score = int(record.get("abuseConfidenceScore", 0))
        return EnrichmentHit(
            source=self.name,
            indicator=indicator,
            is_malicious=score >= MALICIOUS_SCORE_THRESHOLD,
            confidence=score / 100.0,
            detail=(
                f"AbuseIPDB score {score}% "
                f"({record.get('totalReports', 0)} reports, {record.get('countryCode', '?')})"
            ),
        )


def default_enrichers(
    known_bad_path: str | Path | None = None,
    abuseipdb_cache_path: str | Path | None = None,
    offline: bool = True,
    api_key: str | None = None,
) -> list[Enricher]:
    return [
        KnownBadListEnricher(known_bad_path),
        AbuseIPDBEnricher(
            cache_path=abuseipdb_cache_path or DEFAULT_ABUSEIPDB_CACHE,
            offline=offline,
            api_key=api_key or os.environ.get("ABUSEIPDB_API_KEY"),
        ),
    ]
