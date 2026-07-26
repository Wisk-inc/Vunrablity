"""Scan orchestration: download -> index -> audit -> report.

Runs as a background task; every stage pushes progress onto the scan's event
bus so the browser can watch it happen.
"""
from __future__ import annotations

import asyncio
import json
import traceback

from . import db
from .analysis.analyzer import Analyzer
from .analysis.llm import Ollama
from .config import settings
from .crawler import SiteDownloader
from .events import bus

async def run_scan(scan_id: str, url: str) -> None:
    dest = settings.scan_path(scan_id)

    async def progress(stage: str, pct: float, message: str) -> None:
        db.update_scan(scan_id, stage=stage, progress=round(pct, 4),
                       message=message, status="running")
        await bus.publish(scan_id, {"type": "progress", "stage": stage,
                                    "progress": round(pct, 4), "message": message})

    async def event(kind: str, payload: dict) -> None:
        await bus.publish(scan_id, {"type": kind, **payload})

    try:
        db.update_scan(scan_id, status="running", stage="fetching", progress=0.01,
                       message="Starting")
        await bus.publish(scan_id, {"type": "progress", "stage": "fetching",
                                    "progress": 0.01, "message": "Starting"})

        # ---------------------------------------------------------- download
        downloader = SiteDownloader(url, dest, on_progress=progress)
        crawl = await downloader.run()
        crawl_dict = crawl.as_dict()

        db.add_files(scan_id, crawl.files)
        await event("inventory", {
            "files": len(crawl.files),
            "bytes": crawl_dict["total_bytes"],
            "hosts": crawl_dict["hosts"],
            "endpoints": crawl_dict["endpoints"][:100],
        })

        # ---------------------------------------------------------- audit
        analyzer = Analyzer(
            scan_id, dest, crawl_dict,
            llm=Ollama(), on_progress=progress, on_event=event,
        )
        report = await analyzer.run()
        report["crawl"] = {
            "files": crawl_dict["file_count"],
            "bytes": crawl_dict["total_bytes"],
            "hosts": crawl_dict["hosts"],
            "endpoints": crawl_dict["endpoints"][:200],
            "exposures": crawl_dict["exposures"],
            "duration": crawl_dict["duration"],
            "errors": crawl_dict["errors"][:20],
        }

        db.update_scan(scan_id, status="complete", stage="done", progress=1.0,
                       message="Audit complete", summary=json.dumps(report))
        (dest / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

        db.add_message(
            scan_id, "assistant",
            _opening_message(report),
            meta={"kind": "report"},
        )
        await bus.publish(scan_id, {"type": "complete", "report": report})

    except asyncio.CancelledError:
        db.update_scan(scan_id, status="cancelled", message="Cancelled")
        raise
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        db.update_scan(scan_id, status="failed", stage="error", message=detail)
        await bus.publish(scan_id, {"type": "error", "message": detail,
                                    "trace": traceback.format_exc()[-2000:]})

def _opening_message(report: dict) -> str:
    counts = report.get("counts", {})
    risk = report.get("risk", "info")
    lines = [
        f"**Audit complete — {report.get('url')}**",
        "",
        report.get("verdict") or "",
        "",
        report.get("summary") or "",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    labels = {"critical": "Critical", "high": "Dangerous", "medium": "Moderate",
              "low": "Small", "info": "Info"}
    for key, label in labels.items():
        lines.append(f"| {label} | {counts.get(key, 0)} |")

    priorities = report.get("priorities") or []
    if priorities:
        lines += ["", "**Fix in this order:**"]
        for p in priorities[:5]:
            files = ", ".join(p.get("files") or [])
            lines.append(f"{p.get('order', '•')}. **{p.get('action')}** — "
                         f"{p.get('why', '')} {f'`{files}`' if files else ''}")

    lines += ["", f"Overall risk: **{labels.get(risk, risk)}**.",
              "", "Ask me anything about these findings. I can also open the "
              "sandbox and check something for you — try *\"prove the XSS in "
              "the search page\"*."]
    return "\n".join(l for l in lines if l is not None)
