"""The deep read, running in the background.

Reading every file with a model is slow. Blocking a fresh scan on it means
staring at a progress bar before you can ask a single question — so it is not
part of scanning any more. It starts when you ask for it, runs concurrently,
and the conversation stays fully usable while it works. Findings appear in the
sidebar as they land.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import threading
import time
from pathlib import Path

from . import db
from .analysis.analyzer import Analyzer
from .analysis.llm import Ollama
from .config import settings
from .events import bus

_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


def status(scan_id: str) -> dict:
    with _LOCK:
        job = _JOBS.get(scan_id)
        if not job:
            return {"state": "idle"}
        return {k: v for k, v in job.items() if k != "task"}


def start(scan_id: str, root: Path, only: str | None = None) -> dict:
    """Begin (or report on) a full read. Returns immediately."""
    with _LOCK:
        job = _JOBS.get(scan_id)
        if job and job.get("state") == "running":
            return {"already_running": True, **{k: v for k, v in job.items()
                                                if k != "task"}}

    crawl = _crawl_context(scan_id, root)
    analyzer = Analyzer(scan_id, root, crawl, llm=Ollama())
    queue = analyzer._reading_queue()
    if only:
        queue = [q for q in queue
                 if fnmatch.fnmatch(q["path"], only)
                 or fnmatch.fnmatch(q["path"].rsplit("/", 1)[-1], only)]
    analyzer.files_queued = len(queue)

    state = {
        "state": "running",
        "done": 0,
        "total": len(queue),
        "findings": 0,
        "started_at": time.time(),
        "concurrency": settings.analysis_concurrency,
        "queued": len(queue),
    }

    async def event(kind: str, payload: dict) -> None:
        if kind == "file_read":
            with _LOCK:
                job = _JOBS.get(scan_id)
                if job:
                    job["done"] = payload.get("done", job["done"])
                    job["total"] = payload.get("total", job["total"])
                    job["findings"] = payload.get("findings", job["findings"])
        await bus.publish(scan_id, {"type": kind, **payload})

    analyzer.on_event = event

    async def runner() -> None:
        try:
            await analyzer.read_files(queue)
            report = await analyzer._write_report()
            _merge_report(scan_id, report)
            await bus.publish(scan_id, {"type": "deepread_done",
                                        "findings": len(analyzer.findings)})
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await bus.publish(scan_id, {"type": "deepread_error",
                                        "message": f"{type(exc).__name__}: {exc}"})
        finally:
            with _LOCK:
                job = _JOBS.get(scan_id)
                if job:
                    job["state"] = "done"
                    job["finished_at"] = time.time()

    task = asyncio.create_task(runner())
    state["task"] = task
    with _LOCK:
        _JOBS[scan_id] = state
    return {k: v for k, v in state.items() if k != "task"}


def stop(scan_id: str) -> bool:
    with _LOCK:
        job = _JOBS.get(scan_id)
    if not job or job.get("state") != "running":
        return False
    task = job.get("task")
    if task:
        task.cancel()
    with _LOCK:
        job["state"] = "cancelled"
    return True


def _crawl_context(scan_id: str, root: Path) -> dict:
    """Reuse the crawl summary written at scan time, if it is still there."""
    inventory = Path(root) / "inventory.json"
    if inventory.is_file():
        try:
            data = json.loads(inventory.read_text(encoding="utf-8"))
            data.pop("files", None)
            return data
        except (ValueError, OSError):
            pass
    scan = db.get_scan(scan_id) or {}
    return {"root_url": scan.get("url"), "headers": {}, "exposures": [],
            "forms": [], "hosts": []}


def _merge_report(scan_id: str, report: dict) -> None:
    """Fold the deep read's verdict into the stored report."""
    scan = db.get_scan(scan_id) or {}
    existing = scan.get("summary")
    if isinstance(existing, str):
        try:
            existing = json.loads(existing)
        except ValueError:
            existing = {}
    merged = {**(existing or {}), **report, "mode": "deep"}
    db.update_scan(scan_id, summary=json.dumps(merged))
