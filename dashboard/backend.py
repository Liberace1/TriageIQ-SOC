import asyncio
import json
import os
import shutil
from typing import AsyncGenerator

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root():
    return FileResponse(os.path.join(static_dir, "index.html"))

DATA_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data"))
WORKLIST_PATH = os.path.normpath(os.path.join(DATA_DIR, "worklist.json"))

def _resolve_active_alerts_path() -> str:
    raw_path = os.environ.get("TRIAGEIQ_ALERTS_PATH", "data/alerts.json")
    if os.path.isabs(raw_path):
        return os.path.normpath(raw_path)
    return os.path.normpath(os.path.join(os.path.dirname(__file__), "..", raw_path))

ACTIVE_ALERTS_PATH = _resolve_active_alerts_path()

def _sanitize_filename(filename: str) -> str:
    if filename != os.path.basename(filename):
        raise ValueError("Invalid filename")
    if not filename.endswith(".json"):
        raise ValueError("Only JSON files are supported")
    return filename

def list_alert_sources() -> list[str]:
    try:
        entries = sorted(
            f for f in os.listdir(DATA_DIR)
            if f.endswith(".json") and f not in {"worklist.json", "attack_map.json", "abuseipdb_cache.json"}
        )
    except FileNotFoundError:
        return []
    return entries

# In-memory queue and connections for broadcasting
broadcast_queue: asyncio.Queue[dict] = asyncio.Queue()
active_connections: set[WebSocket] = set()


async def alert_producer() -> None:
    """Background task that reads the active alerts file and pushes alerts into the broadcast queue periodically."""
    data = []
    if os.path.exists(ACTIVE_ALERTS_PATH):
        try:
            with open(ACTIVE_ALERTS_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    data = loaded
                else:
                    data = [loaded]
        except Exception:
            data = []

    idx = 0
    while True:
        if data:
            await broadcast_queue.put(data[idx % len(data)])
            idx += 1
        else:
            await broadcast_queue.put({"source": "sim", "message": "heartbeat", "ts": asyncio.get_event_loop().time()})
        await asyncio.sleep(2.0)


async def file_watcher(paths: list[str], interval: float = 1.0) -> None:
    """Watch files for changes and push updated JSON to the broadcast queue."""
    last_mtime: dict[str, float] = {p: 0.0 for p in paths}
    while True:
        for p in paths:
            try:
                if os.path.exists(p):
                    m = os.path.getmtime(p)
                    if m > last_mtime.get(p, 0):
                        last_mtime[p] = m
                        try:
                            with open(p, 'r', encoding='utf-8') as f:
                                content = json.load(f)
                            # push the whole content so frontend can special-case worklist vs single alerts
                            await broadcast_queue.put(content)
                        except Exception:
                            # ignore JSON parse errors or read errors
                            pass
            except Exception:
                pass
        await asyncio.sleep(interval)


async def broadcaster() -> None:
    """Pull alerts from the queue and send to all connected WebSocket clients."""
    while True:
        alert = await broadcast_queue.get()
        text = json.dumps(alert)
        to_remove = []
        for ws in list(active_connections):
            try:
                await ws.send_text(text)
            except Exception:
                to_remove.append(ws)
        for ws in to_remove:
            try:
                active_connections.remove(ws)
            except KeyError:
                pass


@app.post('/ingest')
async def ingest(alert: dict):
    """Accepts a JSON alert posted by external tools and broadcasts it to connected clients."""
    await broadcast_queue.put(alert)
    return {"ok": True}

@app.get('/alerts-files')
async def alerts_files():
    """List alert JSON sources available under the data directory."""
    return {"files": list_alert_sources(), "active": os.path.basename(ACTIVE_ALERTS_PATH)}

@app.get('/alerts-files/{filename}')
async def read_alert_file(filename: str):
    """Read a specific alert JSON file from the data directory for preview."""
    try:
        safe_name = _sanitize_filename(filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    path = os.path.join(DATA_DIR, safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Source file not found")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to read source file")

@app.post('/select-alert-file')
async def select_alert_file(payload: dict):
    """Select an alert file from the data folder and copy it to the active alerts input path."""
    filename = payload.get("filename")
    if not filename:
        raise HTTPException(status_code=400, detail="filename is required")
    try:
        safe_name = _sanitize_filename(filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    source = os.path.join(DATA_DIR, safe_name)
    if not os.path.exists(source):
        raise HTTPException(status_code=404, detail="Source file not found")
    try:
        os.makedirs(os.path.dirname(ACTIVE_ALERTS_PATH), exist_ok=True)
        shutil.copyfile(source, ACTIVE_ALERTS_PATH)
        return {"ok": True, "active": os.path.basename(ACTIVE_ALERTS_PATH), "selected": safe_name}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to activate file: {exc}")


@app.post('/upload-alert-file')
async def upload_alert_file(file: UploadFile = File(...)):
    """Upload a new alert JSON file into the data folder."""
    try:
        safe_name = _sanitize_filename(file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    target_path = os.path.join(DATA_DIR, safe_name)
    try:
        contents = await file.read()
        decoded = contents.decode('utf-8')
        # validate JSON before saving
        json.loads(decoded)
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(target_path, 'wb') as out:
            out.write(contents)
        return {"ok": True, "filename": safe_name, "active": os.path.basename(ACTIVE_ALERTS_PATH)}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid JSON")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to save uploaded file: {exc}")


@app.on_event("startup")
async def startup_tasks():
    # start background producer and broadcaster
    asyncio.create_task(alert_producer())
    asyncio.create_task(broadcaster())
    # watch the active alerts file and worklist file and push updates automatically
    asyncio.create_task(file_watcher([ACTIVE_ALERTS_PATH, WORKLIST_PATH], interval=1.0))


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    active_connections.add(ws)
    try:
        # keep the connection open; if the client sends messages they are ignored
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        try:
            active_connections.remove(ws)
        except KeyError:
            pass
