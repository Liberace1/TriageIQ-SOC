# TriageIQ: SOC Alert Enrichment & Triage Engine

**CSC-842 Tool 1 - Security Analytics & Defensive Operations**

## Overview

TriageIQ is a Python tool that takes a JSON file of SOC alerts and returns a ranked worklist of cases worth investigating. It extracts IOCs (IPs, domains, hashes, usernames), enriches them, maps alerts to MITRE ATT&CK, scores risk with a plain-English explanation, and deduplicates repeat noise.

It runs **fully offline** by default using bundled files in `data/`, with no API keys or SIEM connection required.

## Problem Definition

Analysts spend hours enriching alerts before they can prioritize: checking reputation, cross-referencing threat intel, and deduplicating the same alert over and over. Most of that work is low-value noise.

TriageIQ automates that prep work on an exported alert batch and hands back a short, scored, explained worklist.

**How it differs from similar tools:**
- vs **IP-Triage**: enriches every indicator type in a full alert, not just one IP
- vs **ATT&CK Correlator**: ingests fired **alerts**, not raw telemetry

## Pipeline

```
data/alerts.json -> ingest -> extract -> enrich -> ATT&CK -> score -> dedup -> worklist
```

| Stage | What it does |
|-------|--------------|
| Extract | IPs, domains, hashes, usernames |
| Enrich | Local blocklist + AbuseIPDB (cached offline) |
| ATT&CK | Keyword map to technique ID (14 rules) |
| Score | Severity + reputation, with reason string |
| Dedup | Same rule + indicator + 60-min window |

## Repository Structure

```
Security-tool/
├── triageiq/              # source code
├── data/
│   ├── alerts.json        # sample alerts (50)
│   ├── known_bad.txt      # offline blocklist
│   ├── abuseipdb_cache.json
│   └── attack_map.json
├── docs/
│   └── AI_USAGE.md
├── README.md
├── requirements.txt
└── pyproject.toml
```

## Requirements

- Python 3.11+
- `rich` (installed via requirements)

## Setup

```bash
cd Security-tool
pip install -e .
```

## Usage

**Offline demo (recommended):**

```bash
python -m triageiq data/alerts.json --out worklist.json
```

**Optional flags:**

```bash
python -m triageiq data/alerts.json --dedup-window 30
python -m triageiq data/alerts.json --live    # needs ABUSEIPDB_API_KEY
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--out` | `worklist.json` | Output file |
| `--dedup-window` | `60` | Dedup window (minutes) |
| `--live` | off | Live AbuseIPDB API |

## Expected Results

Running against `data/alerts.json`:

```
50 alert(s) -> 45 case(s)
```

Top of the worklist should include high-score malicious cases (e.g. **ALT-005** Ransomware Beacon at **18.0**, ATT&CK **T1486**). Benign traffic (Google DNS, Office 365, internal scans) should sit at the bottom near **0.0**.

Output: ranked console table + `worklist.json` with scores, enrichments, ATT&CK data, and dedup counts.

## Known Limitations

- Reads exported JSON alerts only; no live SIEM/SOAR integration
- ATT&CK mapping and scoring are rule-based/heuristic
- Sample alerts and enrichment data are synthetic
- AbuseIPDB live mode has rate limits

## Safety and Ethics

Defensive tool only. Does not exploit or modify systems. Use only on alert data you are authorized to analyze.

## Generative AI Usage

See [docs/AI_USAGE.md](docs/AI_USAGE.md). AI helped with planning and early implementation; I reviewed and tested everything before submission.

## Author

Ola
