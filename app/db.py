"""Tiny SQLite persistence layer.

Everything a scan produces (crawl inventory, findings, chat history, agent
transcript) lands here so a session survives a server restart.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from typing import Any, Iterable

from .config import settings

_LOCAL = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    url          TEXT NOT NULL,
    root_domain  TEXT,
    status       TEXT NOT NULL,
    stage        TEXT,
    progress     REAL DEFAULT 0,
    message      TEXT,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    summary      TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   TEXT NOT NULL,
    path      TEXT NOT NULL,
    url       TEXT,
    kind      TEXT,
    language  TEXT,
    bytes     INTEGER DEFAULT 0,
    lines     INTEGER DEFAULT 0,
    sha256    TEXT,
    analyzed  INTEGER DEFAULT 0,
    UNIQUE(scan_id, path)
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    file_path   TEXT,
    line_start  INTEGER,
    line_end    INTEGER,
    severity    TEXT,
    confidence  REAL,
    title       TEXT,
    category    TEXT,
    cwe         TEXT,
    evidence    TEXT,
    explanation TEXT,
    fix         TEXT,
    source      TEXT,
    verified    TEXT,
    created_at  REAL
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    TEXT NOT NULL,
    role       TEXT NOT NULL,
    content    TEXT NOT NULL,
    meta       TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS memory (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    key        TEXT,
    content    TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS activity (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_scan ON activity(scan_id);
CREATE INDEX IF NOT EXISTS idx_files_scan     ON files(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_messages_scan  ON messages(scan_id);
CREATE INDEX IF NOT EXISTS idx_memory_scan    ON memory(scan_id, kind);
"""


def connect() -> sqlite3.Connection:
    """One connection per thread; SQLite objects are not thread-safe."""
    conn = getattr(_LOCAL, "conn", None)
    if conn is None:
        path = settings.data_path / "vunrablity.db"
        conn = sqlite3.connect(path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA)
        _LOCAL.conn = conn
    return conn


def init() -> None:
    connect()


def _rows(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


# --------------------------------------------------------------------------- scans
def create_scan(url: str, root_domain: str) -> str:
    scan_id = uuid.uuid4().hex[:12]
    now = time.time()
    conn = connect()
    conn.execute(
        "INSERT INTO scans (id, url, root_domain, status, stage, progress, message,"
        " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (scan_id, url, root_domain, "queued", "queued", 0.0, "Queued", now, now),
    )
    conn.commit()
    return scan_id


def update_scan(scan_id: str, **fields: Any) -> None:
    if not fields:
        return
    fields["updated_at"] = time.time()
    if "summary" in fields and not isinstance(fields["summary"], str):
        fields["summary"] = json.dumps(fields["summary"])
    sets = ", ".join(f"{k} = ?" for k in fields)
    conn = connect()
    conn.execute(f"UPDATE scans SET {sets} WHERE id = ?", (*fields.values(), scan_id))
    conn.commit()


def get_scan(scan_id: str) -> dict[str, Any] | None:
    cur = connect().execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    if row is None:
        return None
    scan = dict(row)
    if scan.get("summary"):
        try:
            scan["summary"] = json.loads(scan["summary"])
        except (TypeError, ValueError):
            pass
    return scan


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    cur = connect().execute(
        "SELECT id, url, status, stage, progress, created_at FROM scans"
        " ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )
    return _rows(cur)


# --------------------------------------------------------------------------- files
def add_files(scan_id: str, records: Iterable[dict[str, Any]]) -> None:
    conn = connect()
    conn.executemany(
        "INSERT OR REPLACE INTO files (scan_id, path, url, kind, language, bytes,"
        " lines, sha256) VALUES (?,?,?,?,?,?,?,?)",
        [
            (
                scan_id,
                r["path"],
                r.get("url"),
                r.get("kind"),
                r.get("language"),
                r.get("bytes", 0),
                r.get("lines", 0),
                r.get("sha256"),
            )
            for r in records
        ],
    )
    conn.commit()


def mark_analyzed(scan_id: str, path: str) -> None:
    conn = connect()
    conn.execute(
        "UPDATE files SET analyzed = 1 WHERE scan_id = ? AND path = ?", (scan_id, path)
    )
    conn.commit()


def list_files(scan_id: str) -> list[dict[str, Any]]:
    cur = connect().execute(
        "SELECT * FROM files WHERE scan_id = ? ORDER BY path", (scan_id,)
    )
    return _rows(cur)


# --------------------------------------------------------------------------- findings
def add_finding(scan_id: str, finding: dict[str, Any]) -> str:
    fid = finding.get("id") or uuid.uuid4().hex[:12]
    conn = connect()
    conn.execute(
        "INSERT OR REPLACE INTO findings (id, scan_id, file_path, line_start, line_end,"
        " severity, confidence, title, category, cwe, evidence, explanation, fix,"
        " source, verified, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            fid,
            scan_id,
            finding.get("file_path"),
            finding.get("line_start"),
            finding.get("line_end"),
            finding.get("severity", "info"),
            float(finding.get("confidence", 0.5)),
            finding.get("title", "Untitled finding"),
            finding.get("category"),
            finding.get("cwe"),
            finding.get("evidence"),
            finding.get("explanation"),
            finding.get("fix"),
            finding.get("source", "ai"),
            finding.get("verified"),
            time.time(),
        ),
    )
    conn.commit()
    return fid


def list_findings(scan_id: str) -> list[dict[str, Any]]:
    order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
             " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END")
    cur = connect().execute(
        f"SELECT * FROM findings WHERE scan_id = ? ORDER BY {order}, confidence DESC",
        (scan_id,),
    )
    return _rows(cur)


def get_finding(finding_id: str) -> dict[str, Any] | None:
    cur = connect().execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cur.fetchone()
    return dict(row) if row else None


def set_finding_verification(finding_id: str, verdict: str) -> None:
    conn = connect()
    conn.execute("UPDATE findings SET verified = ? WHERE id = ?", (verdict, finding_id))
    conn.commit()


# --------------------------------------------------------------------------- chat
def add_message(scan_id: str, role: str, content: str, meta: Any = None) -> None:
    conn = connect()
    conn.execute(
        "INSERT INTO messages (scan_id, role, content, meta, created_at)"
        " VALUES (?,?,?,?,?)",
        (scan_id, role, content, json.dumps(meta) if meta else None, time.time()),
    )
    conn.commit()


def list_messages(scan_id: str, limit: int = 200) -> list[dict[str, Any]]:
    cur = connect().execute(
        "SELECT role, content, meta, created_at FROM messages WHERE scan_id = ?"
        " ORDER BY id ASC LIMIT ?",
        (scan_id, limit),
    )
    out = _rows(cur)
    for m in out:
        if m.get("meta"):
            try:
                m["meta"] = json.loads(m["meta"])
            except (TypeError, ValueError):
                m["meta"] = None
    return out


# --------------------------------------------------------------------------- memory
def add_memory(scan_id: str, kind: str, content: str, key: str | None = None) -> None:
    conn = connect()
    conn.execute(
        "INSERT INTO memory (scan_id, kind, key, content, created_at) VALUES (?,?,?,?,?)",
        (scan_id, kind, key, content, time.time()),
    )
    conn.commit()


def list_memory(scan_id: str, kind: str | None = None, limit: int = 400) -> list[dict[str, Any]]:
    conn = connect()
    if kind:
        cur = conn.execute(
            "SELECT * FROM memory WHERE scan_id = ? AND kind = ? ORDER BY id ASC LIMIT ?",
            (scan_id, kind, limit),
        )
    else:
        cur = conn.execute(
            "SELECT * FROM memory WHERE scan_id = ? ORDER BY id ASC LIMIT ?",
            (scan_id, limit),
        )
    return _rows(cur)


# --------------------------------------------------------------------------- activity
def add_activity(scan_id: str, kind: str, payload: Any) -> None:
    """Record what the agent did, so a page refresh can replay it."""
    conn = connect()
    conn.execute(
        "INSERT INTO activity (scan_id, kind, payload, created_at) VALUES (?,?,?,?)",
        (scan_id, kind, json.dumps(payload), time.time()),
    )
    conn.commit()


def list_activity(scan_id: str, limit: int = 500) -> list[dict[str, Any]]:
    cur = connect().execute(
        "SELECT kind, payload, created_at FROM activity WHERE scan_id = ?"
        " ORDER BY id ASC LIMIT ?",
        (scan_id, limit),
    )
    out = []
    for row in cur.fetchall():
        item = dict(row)
        try:
            item["payload"] = json.loads(item["payload"])
        except (TypeError, ValueError):
            item["payload"] = {}
        out.append(item)
    return out
