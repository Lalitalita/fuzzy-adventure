import asyncio
import json
import os
import secrets
import time
from base64 import b64decode
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .analyzer import Store, build_snapshot, parse_audit
from .mock import MockClient
from .opnsense import OpnsenseClient

load_dotenv()
env = os.environ
csv = lambda v: [s.strip() for s in (v or "").split(",") if s.strip()]

MOCK = env.get("MOCK") == "1"
POLL = max(2, int(env.get("POLL_INTERVAL_MS") or 5000) / 1000)
LIMIT = int(env.get("FW_LOG_LIMIT") or 2000)
PUBLIC = Path(__file__).resolve().parent.parent / "public"

if MOCK:
    opn = MockClient()
else:
    if not all(env.get(k) for k in ("OPN_URL", "OPN_API_KEY", "OPN_API_SECRET")):
        raise SystemExit("OPN_URL / OPN_API_KEY / OPN_API_SECRET manquants dans .env (ou lance avec MOCK=1)")
    opn = OpnsenseClient(env["OPN_URL"], env["OPN_API_KEY"], env["OPN_API_SECRET"], env.get("OPN_VERIFY_TLS", "true").lower() != "false")

store = Store(wan=csv(env.get("WAN_INTERFACES")), ignore=csv(env.get("IGNORE_SRC")))
state = {
    "status": {"ok": False, "error": "démarrage…", "lastPoll": 0},
    "system": None, "firmware": None,
    "vulns": {"running": False, "lastRun": 0, "error": None, "items": []},
}
clients: set[asyncio.Queue] = set()


def snapshot() -> dict:
    return build_snapshot(store, {"mock": MOCK, **state})


def broadcast():
    if not clients:
        return
    data = json.dumps(snapshot())
    for q in clients:
        if q.full():
            q.get_nowait()
        q.put_nowait(data)


async def poll_firewall():
    try:
        store.ingest(await opn.get_firewall_log(LIMIT))
        state["status"] = {"ok": True, "error": None, "lastPoll": time.time() * 1000}
    except Exception as e:
        state["status"] = {"ok": False, "error": str(e) or type(e).__name__, "lastPoll": time.time() * 1000}
    broadcast()


async def poll_slow():
    ids, sys_, fw = await asyncio.gather(
        opn.get_ids_alerts(), opn.get_system(), opn.get_firmware_status(), return_exceptions=True)
    if not isinstance(ids, Exception):  # Suricata absent => 404, on ignore
        store.set_ids(ids)
    if not isinstance(sys_, Exception):
        state["system"] = sys_
    if not isinstance(fw, Exception):
        state["firmware"] = fw


async def run_audit():
    v = state["vulns"]
    if v["running"]:
        return
    v.update(running=True, error=None)
    broadcast()
    try:
        v["items"] = parse_audit(await opn.run_audit())
        v["lastRun"] = time.time() * 1000
    except Exception as e:
        v["error"] = str(e) or type(e).__name__
    finally:
        v["running"] = False
        broadcast()


async def every(seconds: float, fn, *, first_delay: float = 0, then=None):
    await asyncio.sleep(first_delay)
    while True:
        await fn()
        if then:
            then()
        await asyncio.sleep(seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await poll_slow()
    tasks = [
        asyncio.create_task(every(POLL, poll_firewall)),
        asyncio.create_task(every(30, poll_slow, first_delay=30, then=broadcast)),
        asyncio.create_task(every(6 * 3600, run_audit)),
    ]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    user, pw = env.get("DASH_USER"), env.get("DASH_PASS")
    if user and pw:
        try:
            u, _, p = b64decode(request.headers.get("authorization", "")[6:]).decode().partition(":")
        except Exception:
            u = p = ""
        if not (secrets.compare_digest(u, user) and secrets.compare_digest(p, pw)):
            return Response("Auth requise", 401, {"WWW-Authenticate": 'Basic realm="SOC"'})
    return await call_next(request)


@app.get("/api/snapshot")
async def api_snapshot():
    return JSONResponse(snapshot())


@app.get("/api/stream")
async def api_stream(request: Request):
    q: asyncio.Queue = asyncio.Queue(maxsize=1)
    clients.add(q)
    q.put_nowait(json.dumps(snapshot()))

    async def gen():
        try:
            while not await request.is_disconnected():
                try:
                    yield f"data: {await asyncio.wait_for(q.get(), 15)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            clients.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.post("/api/audit", status_code=202)
async def api_audit():
    asyncio.create_task(run_audit())


app.mount("/", StaticFiles(directory=PUBLIC, html=True))


if __name__ == "__main__":
    import uvicorn
    host, port = env.get("HOST", "127.0.0.1"), int(env.get("PORT") or 3000)
    print(f"SOC dashboard → http://{host}:{port}  {'[MOCK]' if MOCK else '[' + env['OPN_URL'] + ']'}")
    uvicorn.run(app, host=host, port=port, log_level="warning")
