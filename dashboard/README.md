Quick prototype for a live SOC dashboard for TriageIQ


Docker (single-container)
--------------------------------
You can run both the `triageiq` pipeline and the dashboard in a single Docker container. From the repository root build and run:

```bash
docker build -t triageiq-soc:latest Tool1/TriageIQ-SOC
docker run --rm -p 8000:8000 triageiq-soc:latest
```

By default the container will:
- Start the dashboard on port `8000`.
- Run the `triageiq` pipeline every 15s against `data/alerts.json` and write `data/worklist.json`. The pipeline will POST the worklist to the dashboard ingest endpoint so the UI updates automatically.

Environment variables:
- `POLL_INTERVAL` — seconds between pipeline runs (default 15)
- `TRIAGEIQ_ALERTS_PATH` — path inside container to alerts JSON (default `data/alerts.json`)
- `TRIAGEIQ_WORKLIST_OUT` — where triage writes the worklist (default `data/worklist.json`)
- `TRIAGEIQ_DASHBOARD_URL` — URL to POST worklist to (default `http://localhost:8000/ingest`)

Example (change poll interval):

```bash
docker run --rm -p 8000:8000 -e POLL_INTERVAL=30 triageiq-soc:latest
```

Run locally (without Docker):

```bash
python -m pip install -r requirements.txt
python -m uvicorn backend:app --reload --port 8000
```

Open http://localhost:8000/ in a browser. The page connects to a WebSocket at `/ws` and displays incoming alerts. By default the backend reads `../data/alerts.json` and `../data/worklist.json` and streams entries automatically; if those files are missing it will emit synthetic heartbeats.

Next steps:
- Wire `triageiq` engine to publish live events to this websocket (or use Redis/pubsub for scale).
- Improve UI (filtering, severity, tables, links to triage items).

