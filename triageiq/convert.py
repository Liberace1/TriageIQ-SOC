"""Convert SIEM alert exports into TriageIQ JSON."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_OUT = DATA_DIR / "wazuh_alerts.json"
WAZUH_DATASET = "kholil-lil/wazuh-alerts"
PLACEHOLDER_IP = re.compile(r"x+\.x+\.x+\.x+", re.I)

SEVERITY_FROM_LEVEL = ((3, "low"), (6, "medium"), (10, "high"), (99, "critical"))
SEVERITY_ALIASES = {
    "info": "low",
    "informational": "low",
    "warning": "medium",
    "warn": "medium",
    "error": "high",
}


def _severity(value: object) -> str:
    if isinstance(value, (int, float)) or str(value or "").isdigit():
        level = int(value or 0)
        for cap, name in SEVERITY_FROM_LEVEL:
            if level <= cap:
                return name
        return "critical"
    text = str(value or "medium").strip().lower()
    return SEVERITY_ALIASES.get(text, text)


def _clean_ip(value: object) -> str | None:
    if not value:
        return None
    ip = str(value).strip()
    return None if PLACEHOLDER_IP.fullmatch(ip) else ip


def _inner_alert(wazuh: dict) -> dict | None:
    data = wazuh.get("data") or {}
    params = data.get("parameters")
    if isinstance(params, dict):
        inner = params.get("alert")
        if isinstance(inner, dict):
            return inner

    full_log = wazuh.get("full_log") or ""
    brace = full_log.find("{")
    if brace < 0:
        return None
    try:
        payload = json.loads(full_log[brace:])
    except json.JSONDecodeError:
        return None
    params = payload.get("parameters")
    if isinstance(params, dict):
        inner = params.get("alert")
        if isinstance(inner, dict):
            return inner
    return None


def _rule_label(rule: dict, message: str) -> str:
    desc = str(rule.get("description") or "").strip()
    if desc and not desc.isdigit() and len(desc) > 2:
        return desc
    if message:
        summary = message.split(".")[0][:100].strip()
        if summary:
            return summary
    rule_id = str(rule.get("id") or "").strip()
    return f"Wazuh rule {rule_id}" if rule_id else "unknown"


def _wazuh_ioc_data(wazuh: dict, inner: dict | None) -> dict:
    data: dict = {}
    for source in (wazuh.get("data"), (inner or {}).get("data")):
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            if key in ("version", "origin", "command", "parameters", "program") or value in (None, ""):
                continue
            if key not in data:
                data[key] = value
    return data


def _effective_wazuh(wazuh: dict) -> dict:
    inner = _inner_alert(wazuh)
    groups = (wazuh.get("rule") or {}).get("groups") or []
    if not inner or "active_response" not in groups:
        return wazuh

    outer_data = wazuh.get("data") or {}
    return {
        **wazuh,
        "rule": inner.get("rule") or wazuh.get("rule"),
        "full_log": inner.get("full_log") or wazuh.get("full_log"),
        "data": _wazuh_ioc_data(wazuh, inner),
        "response_action": outer_data.get("command"),
    }


def normalize_alert(raw: dict) -> dict:
    """Map a flat alert dict to the TriageIQ ingest schema."""
    alert_id = str(raw.get("id") or raw.get("alert_id") or "")
    rule = raw.get("rule_name") or raw.get("rule") or "unknown"
    if isinstance(rule, dict):
        rule = rule.get("description") or rule.get("id") or "unknown"

    out: dict = {
        "id": alert_id,
        "timestamp": str(raw.get("timestamp") or raw.get("time") or ""),
        "rule_name": str(rule),
        "severity": _severity(raw.get("severity", "medium")),
        "message": str(raw.get("message") or raw.get("description") or raw.get("full_log") or ""),
    }

    for src, dst in (
        ("source_ip", "source_ip"),
        ("src_ip", "source_ip"),
        ("dest_ip", "destination_ip"),
        ("dst_ip", "destination_ip"),
        ("destination_ip", "destination_ip"),
        ("domain", "domain"),
        ("hostname", "domain"),
        ("url", "url"),
        ("sha256", "sha256"),
        ("md5", "md5"),
        ("username", "username"),
        ("user", "username"),
    ):
        val = raw.get(src)
        if val and str(val).strip():
            out[dst] = str(val).strip()

    ip = _clean_ip(raw.get("source_ip")) or _clean_ip((raw.get("data") or {}).get("srcip"))
    if ip:
        out["source_ip"] = ip
    ip = _clean_ip((raw.get("data") or {}).get("dstip"))
    if ip:
        out["destination_ip"] = ip

    return out


def from_wazuh(wazuh: dict, label: str | None = None) -> dict:
    effective = _effective_wazuh(wazuh)
    rule = effective.get("rule") or {}
    data = effective.get("data") or {}
    agent = effective.get("agent") or {}
    message = str(effective.get("full_log") or rule.get("description") or "")

    alert = normalize_alert(
        {
            "id": wazuh.get("id"),
            "timestamp": wazuh.get("timestamp"),
            "rule_name": _rule_label(rule, message),
            "severity": rule.get("level", "medium"),
            "message": message,
            "source_ip": _clean_ip(data.get("srcip")) or _clean_ip(agent.get("ip")),
            "destination_ip": _clean_ip(data.get("dstip")),
            "domain": data.get("hostname"),
            "url": data.get("url"),
            "username": data.get("dstuser") or data.get("srcuser"),
        }
    )
    action = effective.get("response_action")
    if action in ("add", "delete"):
        alert["response_action"] = "blocked" if action == "add" else "unblocked"
    if label:
        alert["source_label"] = label
    return alert


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _records(raw: object) -> list[dict]:
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    raise ValueError("Input must be a JSON object or array of alert objects")


def detect_format(record: dict) -> str:
    if "input" in record and isinstance(record.get("input"), (str, dict)):
        return "wazuh"
    if isinstance(record.get("rule"), dict) or "full_log" in record:
        return "wazuh"
    return "triageiq"


def convert_record(record: dict, fmt: str) -> dict:
    if fmt == "wazuh":
        if "input" in record:
            payload = record["input"]
            wazuh = json.loads(payload) if isinstance(payload, str) else payload
            return from_wazuh(wazuh, label=record.get("output"))
        return from_wazuh(record, label=record.get("source_label"))
    return normalize_alert(record)


def convert_alerts(raw: object, fmt: str = "auto") -> list[dict]:
    alerts: list[dict] = []
    for record in _records(raw):
        use_fmt = fmt if fmt != "auto" else detect_format(record)
        if use_fmt not in ("wazuh", "triageiq"):
            raise ValueError(f"Unsupported alert format: {record.keys()}")
        alert = convert_record(record, use_fmt)
        if not alert["id"]:
            raise ValueError(f"Alert missing id after conversion: {record}")
        alerts.append(alert)
    return alerts


def convert_file(input_path: Path, out_path: Path, fmt: str = "auto") -> list[dict]:
    alerts = convert_alerts(_load_json(input_path), fmt=fmt)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    return alerts


def download_wazuh(limit: int | None = None) -> list[dict]:
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise SystemExit(
            "Online download requires: pip install -e \".[convert]\""
        ) from exc

    split = "train" if limit is None else f"train[:{limit}]"
    rows = load_dataset(WAZUH_DATASET, split=split)
    alerts: list[dict] = []
    for row in rows:
        wazuh = json.loads(row["input"])
        alert = from_wazuh(wazuh, label=row.get("output"))
        if alert["id"]:
            alerts.append(alert)
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert alert exports to TriageIQ JSON (flat array schema).",
    )
    parser.add_argument("--input", "-i", type=Path, help="Source alert JSON file")
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        default=DEFAULT_OUT,
        help=f"Output path (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=("auto", "wazuh", "triageiq"),
        default="auto",
        help="Source format (default: auto-detect)",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download Wazuh sample alerts from Hugging Face instead of --input",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="With --download, convert only the first N alerts",
    )
    args = parser.parse_args()

    if args.download:
        alerts = download_wazuh(limit=args.limit)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
        source = f"Hugging Face ({WAZUH_DATASET})"
    elif args.input:
        alerts = convert_file(args.input, args.out, fmt=args.format)
        source = str(args.input)
    else:
        parser.error("Provide --input FILE or --download")

    print(f"Converted {len(alerts)} alert(s) from {source}")
    print(f"Wrote {args.out}")
    print(f"Run triage: python -m triageiq {args.out}")


if __name__ == "__main__":
    main()
