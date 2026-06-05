"""TriageIQ CLI entry point."""

from __future__ import annotations

import argparse
from pathlib import Path

from triageiq.engine import DEFAULT_DEDUP_WINDOW_MINUTES, ingest_alerts, run_pipeline
from triageiq.output import print_worklist_table, write_worklist_json


def main() -> None:
    parser = argparse.ArgumentParser(description="TriageIQ - SOC alert enrichment and triage engine")
    parser.add_argument("alerts", type=Path, help="Path to alerts JSON file")
    parser.add_argument("--out", type=Path, default=Path("worklist.json"), help="Output worklist JSON")
    parser.add_argument("--known-bad", type=Path, default=None, help="Known-bad list path")
    parser.add_argument("--attack-map", type=Path, default=None, help="ATT&CK keyword map JSON")
    parser.add_argument(
        "--dedup-window",
        type=int,
        default=DEFAULT_DEDUP_WINDOW_MINUTES,
        metavar="MINUTES",
        help=f"Dedup window in minutes (default: {DEFAULT_DEDUP_WINDOW_MINUTES})",
    )
    parser.add_argument("--abuseipdb-cache", type=Path, default=None, help="AbuseIPDB cache JSON")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Live AbuseIPDB mode (requires ABUSEIPDB_API_KEY)",
    )
    args = parser.parse_args()

    alerts_in = len(ingest_alerts(args.alerts))
    cases = run_pipeline(
        args.alerts,
        known_bad_path=args.known_bad,
        dedup_window_minutes=args.dedup_window,
        attack_map_path=args.attack_map,
        abuseipdb_cache_path=args.abuseipdb_cache,
        offline=not args.live,
    )
    write_worklist_json(cases, args.out, alerts_in=alerts_in)
    print_worklist_table(cases, alerts_in=alerts_in)


if __name__ == "__main__":
    main()
