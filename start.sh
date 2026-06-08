#!/usr/bin/env bash
set -euo pipefail

# Start dashboard (uvicorn) and run triage pipeline periodically.
# Config via env:
# - POLL_INTERVAL (seconds) default 15
# - ALERTS_PATH default data/alerts.json
# - WORKLIST_OUT default data/worklist.json
# - TRIAGEIQ_DASHBOARD_URL default http://localhost:8000/ingest

POLL_INTERVAL=${POLL_INTERVAL:-15}
ALERTS_PATH=${TRIAGEIQ_ALERTS_PATH:-data/alerts.json}
WORKLIST_OUT=${TRIAGEIQ_WORKLIST_OUT:-data/worklist.json}
export TRIAGEIQ_DASHBOARD_URL=${TRIAGEIQ_DASHBOARD_URL:-http://localhost:8000/ingest}

echo "Starting dashboard (uvicorn)..."
nohup python -m uvicorn dashboard.backend:app --host 0.0.0.0 --port 8000 >/tmp/uvicorn.log 2>&1 &
UVICORN_PID=$!
echo "uvicorn pid=$UVICORN_PID"

trap 'echo "Stopping..."; kill $UVICORN_PID || true; exit 0' SIGINT SIGTERM

echo "Entering pipeline loop: alerts=$ALERTS_PATH out=$WORKLIST_OUT interval=${POLL_INTERVAL}s"
mkdir -p "$(dirname "$WORKLIST_OUT")"
while true; do
  if [ -f "$ALERTS_PATH" ]; then
    echo "Running triage pipeline at $(date)" >> /tmp/pipeline.log
    # Run triageiq to produce worklist and (because TRIAGEIQ_DASHBOARD_URL is set)
    # it will POST to the dashboard ingest endpoint as well.
    python -m triageiq "$ALERTS_PATH" --out "$WORKLIST_OUT" || echo "triage run failed" >> /tmp/pipeline.log
  else
    echo "Alerts file not found: $ALERTS_PATH" >> /tmp/pipeline.log
  fi
  sleep ${POLL_INTERVAL}
done
