"""HTTP + WebSocket surface."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import (FastAPI, HTTPException, Query, Request, Response, WebSocket,
                     WebSocketDisconnect)
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db, pipeline
from .analysis import severity as sev
from .analysis.llm import Ollama
from .agent import Conversation
from .config import settings
from .crawler import urls as U
from .events import bus
from .sandbox import Sandbox, SandboxUnavailable

STATIC = Path(__file__).parent / "static"
_tasks: dict[str, asyncio.Task] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    yield
    for task in _tasks.values():
        task.cancel()
    Sandbox.shutdown_all()


app = FastAPI(title="Vunrablity", version="1.0.0", lifespan=lifespan)


# --------------------------------------------------------------------------- models
class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class ChatRequest(BaseModel):
    message: str
    mode: str = "auto"          # auto | answer | agent


class ExecRequest(BaseModel):
    command: str
    timeout: int | None = None


class WriteRequest(BaseModel):
    path: str
    content: str


# --------------------------------------------------------------------------- pages
@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/chat")
async def chat_page():
    return FileResponse(STATIC / "chat.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")


# --------------------------------------------------------------------------- health
@app.get("/api/health")
async def health():
    ollama = await Ollama().health()
    try:
        docker_ok = Sandbox("probe", settings.data_path).info()
        sandbox = {"ok": True, "detail": docker_ok}
    except SandboxUnavailable as exc:
        sandbox = {"ok": False, "detail": str(exc)}
    return {
        "ollama": ollama,
        "sandbox": sandbox,
        "settings": {
            "model": settings.ollama_model,
            "max_pages": settings.crawl_max_pages,
            "max_assets": settings.crawl_max_assets,
            "chunk_lines": settings.analysis_chunk_lines,
            "sandbox_image": settings.sandbox_image,
        },
    }


# --------------------------------------------------------------------------- scans
@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    url = U.normalize(req.url)
    domain = U.registrable_domain(url)
    if not U.looks_like_host(url) or not domain:
        raise HTTPException(400, f"'{req.url}' does not look like a website address.")

    scan_id = db.create_scan(url, domain)
    task = asyncio.create_task(pipeline.run_scan(scan_id, url))
    _tasks[scan_id] = task
    task.add_done_callback(lambda t: _tasks.pop(scan_id, None))
    return {"scan_id": scan_id, "url": url, "domain": domain}


@app.get("/api/scans")
async def scans():
    return {"scans": db.list_scans()}


@app.get("/api/scan/{scan_id}")
async def scan_detail(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "unknown scan")
    findings = db.list_findings(scan_id)
    counts = {s: 0 for s in sev.ORDER}
    for f in findings:
        counts[sev.normalize(f["severity"])] += 1
    return {
        "scan": scan,
        "counts": counts,
        "labels": sev.LABEL,
        "descriptions": sev.DESCRIPTION,
        "file_count": len(db.list_files(scan_id)),
        "findings": findings,
    }


@app.get("/api/scan/{scan_id}/findings")
async def findings(scan_id: str):
    return {"findings": db.list_findings(scan_id)}


@app.get("/api/scan/{scan_id}/files")
async def files(scan_id: str):
    return {"files": db.list_files(scan_id)}


@app.get("/api/scan/{scan_id}/file")
async def file_contents(scan_id: str, path: str = Query(...),
                        start: int = 1, end: int | None = None):
    root = settings.scan_path(scan_id).resolve()
    target = (root / path.lstrip("/")).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise HTTPException(400, "path escapes the scan directory")
    if not target.is_file():
        raise HTTPException(404, "no such file in this mirror")

    text = target.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    end = end or len(lines)
    start = max(1, start)
    return {
        "path": path,
        "total_lines": len(lines),
        "start": start,
        "end": min(end, len(lines)),
        "content": "\n".join(lines[start - 1:end]),
    }


@app.get("/api/scan/{scan_id}/report")
async def report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "unknown scan")
    return scan.get("summary") or {}


@app.get("/api/scan/{scan_id}/report.md", response_class=PlainTextResponse)
async def report_markdown(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "unknown scan")
    return _markdown_report(scan, db.list_findings(scan_id))


@app.get("/api/scan/{scan_id}/messages")
async def messages(scan_id: str):
    return {"messages": db.list_messages(scan_id)}


@app.get("/api/scan/{scan_id}/memory")
async def memory(scan_id: str):
    from .analysis.memory import ScanMemory
    return ScanMemory(scan_id).snapshot()


# --------------------------------------------------------------------------- sandbox
@app.get("/api/scan/{scan_id}/sandbox")
async def sandbox_info(scan_id: str):
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    return box.info()


@app.post("/api/scan/{scan_id}/sandbox/start")
async def sandbox_start(scan_id: str):
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    try:
        await asyncio.to_thread(box.start)
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc))
    return box.info()


@app.post("/api/scan/{scan_id}/sandbox/exec")
async def sandbox_exec(scan_id: str, req: ExecRequest):
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    try:
        result = await asyncio.to_thread(box.exec, req.command, req.timeout)
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc))
    return result.as_dict()


@app.post("/api/scan/{scan_id}/sandbox/stop")
async def sandbox_stop(scan_id: str):
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    await asyncio.to_thread(box.stop)
    return {"stopped": True}


# --------------------------------------------------------------------------- websockets
@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(ws: WebSocket, scan_id: str):
    await ws.accept()
    scan = db.get_scan(scan_id)
    if not scan:
        await ws.send_json({"type": "error", "message": "unknown scan"})
        await ws.close()
        return

    await ws.send_json({"type": "hello", "scan": {
        "id": scan["id"], "url": scan["url"], "status": scan["status"],
        "stage": scan["stage"], "progress": scan["progress"],
        "message": scan["message"],
    }})

    try:
        async for event in bus.subscribe(scan_id):
            await ws.send_json(event)
            if event.get("type") in ("complete", "error"):
                break
    except WebSocketDisconnect:
        return
    except Exception:
        return
    finally:
        try:
            await ws.close()
        except Exception:
            pass


@app.websocket("/ws/chat/{scan_id}")
async def ws_chat(ws: WebSocket, scan_id: str):
    """One socket, one conversation. The model decides whether to talk or act."""
    await ws.accept()
    if not db.get_scan(scan_id):
        await ws.send_json({"type": "error", "message": "unknown scan"})
        await ws.close()
        return

    root = settings.scan_path(scan_id)

    try:
        while True:
            payload = await ws.receive_json()
            message = str(payload.get("message") or "").strip()
            if not message:
                continue

            async def emit(kind: str, data: dict, _ws=ws) -> None:
                await _ws.send_json({"type": kind, **data})
                # Persist everything except raw token spam so a refresh replays
                # the conversation exactly as it happened.
                if kind in ("action_open", "action_result"):
                    db.add_activity(scan_id, kind, data)

            conversation = Conversation(scan_id, root, emit=emit)
            try:
                await conversation.send(message)
            except Exception as exc:
                await ws.send_json({"type": "error",
                                    "message": f"{type(exc).__name__}: {exc}"})
                await ws.send_json({"type": "turn_end", "content": "", "actions": 0})

    except WebSocketDisconnect:
        return
    except Exception as exc:
        try:
            await ws.send_json({"type": "error",
                                "message": f"{type(exc).__name__}: {exc}"})
        except Exception:
            pass


# --------------------------------------------------------------------------- workspace
@app.get("/api/scan/{scan_id}/workspace/tree")
async def workspace_tree(scan_id: str, path: str = "", depth: int = 4):
    """The agent's live workspace, for the file explorer."""
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    try:
        return {"entries": await asyncio.to_thread(box.tree, path, depth)}
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc))


@app.get("/api/scan/{scan_id}/workspace/file")
async def workspace_file(scan_id: str, path: str = Query(...)):
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    try:
        await asyncio.to_thread(box.start)
        content = await asyncio.to_thread(box.read_file, path, 1, 100_000)
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc))
    return {"path": path, "content": content,
            "lines": content.count("\n") + 1, "language": _language_of(path)}


@app.post("/api/scan/{scan_id}/workspace/file")
async def workspace_write(scan_id: str, req: WriteRequest):
    """Save an edit made in the browser back into the workspace."""
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    try:
        result = await asyncio.to_thread(box.write_file, req.path, req.content)
    except SandboxUnavailable as exc:
        raise HTTPException(503, str(exc))
    if not result.ok:
        raise HTTPException(400, result.output)
    return {"saved": True, "path": req.path, "bytes": len(req.content)}


@app.get("/api/scan/{scan_id}/services")
async def list_services(scan_id: str):
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    try:
        return {"services": box.services(), "info": box.info()}
    except SandboxUnavailable as exc:
        return {"services": [], "info": {"error": str(exc)}}


@app.api_route("/preview/{scan_id}/{port}/{path:path}",
               methods=["GET", "POST", "HEAD"])
async def preview(scan_id: str, port: int, path: str, request: Request):
    """Proxy to a server the agent started, so its pages are clickable here.

    Only ports the agent actually bound are reachable, and only on loopback —
    this is a window into the sandbox, not an open relay.
    """
    box = Sandbox.get(scan_id, settings.scan_path(scan_id))
    allowed = {s.get("port") for s in box.services() if s.get("port")}
    allowed |= set(settings.preview_ports)
    if port not in allowed:
        raise HTTPException(403, f"port {port} is not served by this sandbox")

    target = f"http://127.0.0.1:{port}/{path}"
    if request.url.query:
        target += f"?{request.url.query}"
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            upstream = await client.request(
                request.method, target,
                content=await request.body() if request.method == "POST" else None,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"nothing answering on port {port}: {exc}")

    drop = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = {k: v for k, v in upstream.headers.items() if k.lower() not in drop}
    return Response(content=upstream.content, status_code=upstream.status_code,
                    headers=headers,
                    media_type=upstream.headers.get("content-type"))


@app.get("/api/scan/{scan_id}/activity")
async def activity(scan_id: str):
    """Replayed on refresh so the conversation survives a reload."""
    return {"activity": db.list_activity(scan_id)}


LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".json": "json", ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "css", ".sh": "shell", ".bash": "shell",
    ".yml": "yaml", ".yaml": "yaml", ".md": "markdown", ".sql": "sql",
    ".php": "php", ".rb": "ruby", ".go": "go", ".rs": "rust", ".java": "java",
    ".xml": "xml", ".toml": "toml", ".env": "shell",
}


def _language_of(path: str) -> str:
    name = str(path).lower()
    for ext, lang in LANG_BY_EXT.items():
        if name.endswith(ext):
            return lang
    return "text"


# --------------------------------------------------------------------------- misc
@app.exception_handler(SandboxUnavailable)
async def sandbox_error(_, exc: SandboxUnavailable):
    return JSONResponse(status_code=503, content={"detail": str(exc)})


def _markdown_report(scan: dict, findings: list[dict]) -> str:
    summary = scan.get("summary") or {}
    if isinstance(summary, str):
        try:
            summary = json.loads(summary)
        except ValueError:
            summary = {}

    out = [
        f"# Vunrablity report — {scan['url']}",
        "",
        f"**Verdict:** {summary.get('verdict', '—')}",
        f"**Overall risk:** {sev.LABEL.get(summary.get('risk', 'info'), 'Unknown')}",
        "",
        summary.get("summary", ""),
        "",
        "## Findings",
        "",
    ]
    for f in findings:
        loc = f"{f['file_path']}:{f['line_start']}" if f.get("line_start") else f.get("file_path")
        out += [
            f"### [{sev.LABEL.get(f['severity'], f['severity'])}] {f['title']}",
            "",
            f"- **Location:** `{loc}`",
            f"- **Category:** {f.get('category')}  ·  **{f.get('cwe') or 'no CWE'}**"
            f"  ·  confidence {float(f.get('confidence') or 0):.0%}"
            f"  ·  found by `{f.get('source')}`",
            "",
            f"{f.get('explanation') or ''}",
            "",
            "```",
            (f.get("evidence") or "").strip(),
            "```",
            "",
            f"**Fix:** {f.get('fix') or '—'}",
            "",
        ]
    return "\n".join(out)
