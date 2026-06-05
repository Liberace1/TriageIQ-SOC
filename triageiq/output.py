"""Ranked worklist output (console table + JSON)."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from triageiq.models import Case


def _attack_dict(attack) -> dict | None:
    if attack is None:
        return None
    return {
        "technique_id": attack.technique_id,
        "technique_name": attack.technique_name,
        "tactic": attack.tactic,
        "matched_keyword": attack.matched_keyword,
        "matched_field": attack.matched_field,
        "confidence": attack.confidence,
    }


def _case_to_dict(item: Case) -> dict:
    rep = item.representative
    return {
        "id": rep.alert.id,
        "timestamp": rep.alert.timestamp,
        "rule_name": rep.alert.rule_name,
        "severity": rep.alert.severity,
        "score": round(item.score, 1),
        "reason": item.reason,
        "alert_count": item.alert_count,
        "alert_ids": item.alert_ids,
        "attack": _attack_dict(rep.attack),
        "indicators": [{"kind": i.kind, "value": i.value} for i in item.indicators],
        "enrichments": [
            {
                "source": e.source,
                "indicator": e.indicator.value,
                "is_malicious": e.is_malicious,
                "detail": e.detail,
            }
            for e in item.enrichments
        ],
    }


def write_worklist_json(
    cases: list[Case],
    path: str | Path,
    alerts_in: int | None = None,
) -> None:
    """Write ranked worklist to a JSON file."""
    ranked = sorted(cases, key=lambda c: c.score, reverse=True)
    total_alerts = alerts_in if alerts_in is not None else sum(c.alert_count for c in cases)
    payload = {
        "cases": [_case_to_dict(item) for item in ranked],
        "summary": {
            "alerts_in": total_alerts,
            "cases_out": len(ranked),
            "dedup_ratio": round(total_alerts / len(ranked), 2) if ranked else 0,
        },
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def print_worklist_table(
    cases: list[Case],
    console: Console | None = None,
    alerts_in: int | None = None,
) -> None:
    """Print a ranked console table of deduplicated cases."""
    console = console or Console()
    ranked = sorted(cases, key=lambda c: c.score, reverse=True)
    total_alerts = alerts_in if alerts_in is not None else sum(c.alert_count for c in ranked)

    table = Table(title="TriageIQ - Ranked Worklist")
    table.add_column("Rank", style="dim", width=4)
    table.add_column("Score", justify="right", width=6)
    table.add_column("Cnt", justify="right", width=4)
    table.add_column("ID", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=24)
    table.add_column("ATT&CK", width=10)
    table.add_column("Bad", justify="right", width=4)

    for rank, item in enumerate(ranked, start=1):
        bad_count = len({h.indicator.value for h in item.enrichments if h.is_malicious})
        attack_id = item.attack.technique_id if item.attack else "-"
        table.add_row(
            str(rank),
            f"{item.score:.1f}",
            str(item.alert_count),
            item.alert.id,
            item.alert.severity,
            item.alert.rule_name[:24],
            attack_id,
            str(bad_count) if bad_count else "-",
        )

    console.print(table)
    console.print(
        f"\n[dim]{total_alerts} alert(s) -> {len(ranked)} case(s)[/dim]"
    )

    console.print("\n[bold]Top case details[/bold]")
    for rank, item in enumerate(ranked[:5], start=1):
        count_note = f", x{item.alert_count}" if item.alert_count > 1 else ""
        console.print(
            f"\n[cyan]#{rank} {item.alert.id}[/cyan] (score {item.score:.1f}{count_note})"
        )
        console.print(f"  Rule: {item.alert.rule_name}")
        if item.attack:
            console.print(
                f"  ATT&CK: {item.attack.technique_id} "
                f"({item.attack.technique_name}) [{item.attack.tactic}]"
            )
        if item.alert_count > 1:
            console.print(f"  Merged: {', '.join(item.alert_ids)}")
        console.print(f"  Why:  {item.reason}")
        if item.enrichments:
            console.print("  Enrichment:")
            for hit in item.enrichments:
                flag = "MALICIOUS" if hit.is_malicious else "clean"
                console.print(
                    f"    - [{flag}] {hit.indicator.kind}={hit.indicator.value}: {hit.detail}"
                )
