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
alerts.json -> ingest -> extract -> enrich -> ATT&CK -> score -> dedup -> worklist
```

| Stage | What it does |
|-------|--------------|
| Extract | IPs, domains, hashes, usernames |
| Enrich | Local blocklist + AbuseIPDB (cached offline) |
| ATT&CK | Keyword map to technique ID (14 rules) |
| Score | Severity + reputation, with reason string |
| Dedup | Same rule + indicator + 60-min window |

## Alert JSON schema

TriageIQ ingest expects a **JSON array** of flat objects:

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | Unique alert ID (`alert_id` also accepted) |
| `timestamp` | no | ISO-8601 string (`time` also accepted) |
| `rule_name` | no | Alert rule or title (`rule` also accepted) |
| `severity` | no | `low`, `medium`, `high`, `critical` (default: `medium`) |
| `message` | no | Human-readable detail (`description` also accepted) |
| `source_ip`, `destination_ip` | no | IPv4 addresses |
| `domain`, `url` | no | Host or URL indicators |
| `sha256`, `md5` | no | File hashes |
| `username` | no | Account name (`user` also accepted) |

Use **`triageiq-convert`** to transform Wazuh or other nested exports into this schema.

## Repository Structure

```
TriageIQ-SOC/
├── triageiq/              # source (engine, enrich, convert, output)
├── data/
│   ├── alerts.json        # synthetic sample (50)
│   ├── wazuh_alerts.json  # converted Wazuh sample (738)
│   ├── known_bad.txt
│   ├── abuseipdb_cache.json
│   └── attack_map.json
├── README.md
├── requirements.txt
└── pyproject.toml
```

## Requirements

| Requirement | Version / notes |
|-------------|-----------------|
| **Python** | **3.11 or newer** (minimum enforced in `pyproject.toml`: `>=3.11`) |
| **pip** | Required for install; usually bundled with Python |

Python 3.11, 3.12, and 3.13 are supported. Download from [python.org](https://www.python.org/downloads/) if needed.

## Docker Quickstart (recommended)

### Build and run with Docker

```bash
docker build -t triageiq-soc:latest .
docker run --rm -p 8000:8000 triageiq-soc:latest
```

Open http://localhost:8000/ in a browser to access the live SOC dashboard and automatic `triageiq` processing.

Environment variables:
- `POLL_INTERVAL` — seconds between pipeline runs (default 15)
- `TRIAGEIQ_ALERTS_PATH` — path inside container to alerts JSON (default `data/alerts.json`)
- `TRIAGEIQ_WORKLIST_OUT` — output path (default `data/worklist.json`)
- `TRIAGEIQ_DASHBOARD_URL` — ingest URL (default `http://localhost:8000/ingest`)

Example:

```bash
docker run --rm -p 8000:8000 -e POLL_INTERVAL=30 triageiq-soc:latest
```

### Local install (alternative)

### Step 1: Check Python and pip

```bash
python --version
python -m pip --version
```

You need **Python 3.11 or newer**. If `python` is not found, try `python3` instead in the commands below.

### Step 2: Clone the repository

```bash
git clone https://github.com/Liberace1/TriageIQ-SOC.git
cd TriageIQ-SOC
```

### Step 3: Create a virtual environment

```bash
python -m venv .venv
```

### Step 4: Activate the virtual environment

**Windows (Command Prompt or PowerShell):**

```bash
.venv\Scripts\activate
```
```Git bash
source .venv/Scripts/activate
```
**Linux / macOS:**

```bash
source .venv/bin/activate
```

The shell prompt should show `(.venv)` when the environment is active.

### Step 5: Install TriageIQ

```bash
python -m pip install -e .
```

Optional (only if downloading Wazuh alerts from the internet):

```bash
python -m pip install -e ".[convert]"
```

### Step 6: Run the offline demo (synthetic sample)

```bash
python -m triageiq
```

Or specify the sample file and output path explicitly:

```bash
python -m triageiq data/alerts.json --out worklist.json
```

Expected console summary:

```
50 alert(s) -> 45 case(s)
```

### Step 7: Run against the bundled Wazuh sample

```bash
python -m triageiq data/wazuh_alerts.json --out worklist.json
```

Expected console summary:

```
738 alert(s) -> 95 case(s)
```

### Step 8 (optional): Convert your own alert export

If alerts are not already in TriageIQ flat JSON format, convert them first:

```bash
triageiq-convert --input path/to/alerts.json --out data/converted.json
```

Then triage the converted file:

```bash
python -m triageiq data/converted.json --out worklist.json
```

To download and convert the Wazuh sample from Hugging Face instead of using the bundled file:

```bash
triageiq-convert --download --out data/wazuh_alerts.json
python -m triageiq data/wazuh_alerts.json --out worklist.json
```

## Command reference

**Convert alerts (`triageiq-convert`):**

| Flag | Default | Purpose |
|------|---------|---------|
| `--input`, `-i` | required* | Source alert JSON |
| `--out`, `-o` | `data/wazuh_alerts.json` | Output file |
| `--format`, `-f` | `auto` | `auto`, `wazuh`, or `triageiq` |
| `--download` | off | Fetch Wazuh sample from Hugging Face |
| `--limit` | all | Limit rows when using `--download` |

\* `--input` or `--download` is required.

Examples:

```bash
triageiq-convert -i wazuh_export.json -o data/converted.json --format wazuh
triageiq-convert -i flat_alerts.json -o data/converted.json --format triageiq
```

**Run triage (`python -m triageiq`):**

| Flag | Default | Purpose |
|------|---------|---------|
| `alerts` | `data/alerts.json` | Input alert JSON file |
| `--out` | `worklist.json` | Output worklist JSON |
| `--dedup-window` | `60` | Dedup window (minutes) |
| `--live` | off | Live AbuseIPDB API (needs `ABUSEIPDB_API_KEY`) |

Examples:

```bash
python -m triageiq data/alerts.json --dedup-window 30
python -m triageiq data/alerts.json --live
```

## Expected Results

After Step 6 (`data/alerts.json`), top cases include high-score malicious alerts (e.g. **ALT-005** Ransomware Beacon at **18.0**, ATT&CK **T1486**). Benign traffic sits near **0.0**.

Output each run: ranked console table plus `worklist.json` with scores, enrichments, ATT&CK data, and dedup counts.

## Known Limitations

- Reads exported JSON alerts only; no live SIEM/SOAR integration
- ATT&CK mapping and scoring are rule-based/heuristic
- Offline enrichment coverage depends on bundled blocklist and cache
- AbuseIPDB live mode has rate limits

## Safety and Ethics

Defensive tool only. Does not exploit or modify systems. Use only on alert data you are authorized to analyze.
