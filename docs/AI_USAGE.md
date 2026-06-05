# AI Usage Disclosure

I used AI tools while building TriageIQ for CSC-842. It helped most during early planning and when I was moving fast through implementation, but I still had to understand and validate what the tool does.

## Where AI helped

- Shaping the original idea: an alert-to-worklist pipeline instead of a single-indicator lookup tool
- Setting up the Python package, CLI, and pluggable enricher pattern
- Writing the first versions of ingest, extraction, enrichment, scoring, dedup, and ATT&CK mapping
- Building the synthetic sample alerts and offline files in `data/`
- Working through README drafts and fixing Windows terminal output issues
- Folding scattered modules into a smaller layout and cleaning up the repo before submission

## What I checked myself

Before keeping anything, I ran the tool locally and looked at the results:

- Installed with `pip install -e .` and ran `python -m triageiq data/alerts.json`
- Confirmed the sample run reports **50 alert(s) -> 45 case(s)**
- Checked that high-risk cases (ransomware, C2, phishing) rank above benign noise
- Reviewed `worklist.json` for scores, enrichment details, and ATT&CK IDs
- Verified dedup actually merges repeat alerts instead of listing every duplicate
- Removed dev-only files and made sure generated output stays out of git

## How I used AI

I did not paste AI output into the repo unchanged. When a suggestion looked wrong, incomplete, or over-engineered, I changed it or dropped it. The pipeline logic, final file structure, and what shipped in this repository are decisions I signed off on.

**Author:** Ola
