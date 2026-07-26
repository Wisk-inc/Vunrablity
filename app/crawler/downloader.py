"""The mirror engine.

Given one URL it walks the whole property — pages, scripts, styles, JSON,
source maps, sub-domains it discovers along the way — and writes every byte to
disk so the auditor can read real files instead of guessing from the network.

It is strictly a *downloader*: GET and HEAD only, no payloads, no fuzzing, no
authentication bypass. Everything it learns it learns by asking politely.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable
from urllib import robotparser
from urllib.parse import urlparse

import httpx

from ..config import settings
from . import discovery, urls as U

ProgressFn = Callable[[str, float, str], Awaitable[None]]
EventFn = Callable[[str, dict], Awaitable[None]]

USER_AGENT = (
    "Mozilla/5.0 (compatible; Vunrablity/1.0; +self-assessment scanner) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

TEXTUAL_SUFFIXES = {
    ".html", ".htm", ".xhtml", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".css", ".scss", ".sass", ".less", ".json", ".map", ".xml", ".txt", ".md",
    ".yml", ".yaml", ".toml", ".ini", ".conf", ".env", ".php", ".py", ".rb",
    ".go", ".java", ".cs", ".sql", ".sh", ".svg", ".graphql", ".vue", ".svelte",
}

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3",
    ".pdf", ".zip", ".gz", ".wasm",
}

LANG_BY_SUFFIX = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".vue": "vue", ".svelte": "svelte", ".py": "python", ".rb": "ruby",
    ".php": "php", ".go": "go", ".java": "java", ".cs": "csharp",
    ".html": "html", ".htm": "html", ".css": "css", ".scss": "css",
    ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".xml": "xml",
    ".sql": "sql", ".sh": "shell", ".graphql": "graphql", ".map": "sourcemap",
}


@dataclass
class CrawlResult:
    root_url: str
    root_domain: str
    root_dir: Path
    files: list[dict] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)
    headers: dict[str, dict] = field(default_factory=dict)
    exposures: list[dict] = field(default_factory=list)
    external_hosts: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    def as_dict(self) -> dict:
        return {
            "root_url": self.root_url,
            "root_domain": self.root_domain,
            "root_dir": str(self.root_dir),
            "file_count": len(self.files),
            "total_bytes": sum(f.get("bytes", 0) for f in self.files),
            "hosts": sorted(self.hosts),
            "external_hosts": sorted(self.external_hosts),
            "endpoints": sorted(self.endpoints)[:500],
            "forms": self.forms,
            "headers": self.headers,
            "exposures": self.exposures,
            "errors": self.errors[:100],
            "duration": round((self.finished_at or time.time()) - self.started_at, 2),
        }


class SiteDownloader:
    def __init__(self, url: str, dest: Path, on_progress: ProgressFn | None = None,
                 on_file: "EventFn | None" = None):
        self.root_url = U.normalize(url)
        self.root_domain = U.registrable_domain(self.root_url)
        self.origin = f"{urlparse(self.root_url).scheme}://{urlparse(self.root_url).netloc}"
        self.dest = Path(dest)
        self.site_dir = self.dest / "site"
        self.sources_dir = self.dest / "sources"
        self.site_dir.mkdir(parents=True, exist_ok=True)
        self.sources_dir.mkdir(parents=True, exist_ok=True)
        self.on_progress = on_progress
        self.on_file = on_file

        self.result = CrawlResult(self.root_url, self.root_domain, self.dest)
        self.seen: set[str] = set()
        self.saved: dict[str, dict] = {}
        self._robots: dict[str, robotparser.RobotFileParser] = {}
        self._pages_done = 0
        self._assets_done = 0
        self._pending_announce: list[dict] = []
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ public
    async def run(self) -> CrawlResult:
        limits = httpx.Limits(
            max_connections=settings.crawl_concurrency * 2,
            max_keepalive_connections=settings.crawl_concurrency,
        )
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=settings.crawl_timeout,
            limits=limits,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            verify=False,  # a broken cert is a finding, not a reason to stop
        ) as client:
            self.client = client
            await self._emit("fetching", 0.02, f"Resolving {self.root_domain}")
            await self._load_robots(self.origin)
            await self._seed()
            await self._crawl_pages()
            await self._drain_assets()
            await self._probe_exposures()
        await self._flush_announcements()
        self.result.files = list(self.saved.values())
        self.result.finished_at = time.time()
        self._write_inventory()
        await self._emit("downloaded", 0.45,
                         f"Mirrored {len(self.result.files)} files "
                         f"across {len(self.result.hosts)} hosts")
        return self.result

    # ------------------------------------------------------------------ seeding
    async def _seed(self) -> None:
        self.frontier: asyncio.Queue = asyncio.Queue()
        self.asset_queue: asyncio.Queue = asyncio.Queue()
        await self.frontier.put((self.root_url, 0))
        self.seen.add(self.root_url)

        for name in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
            url = U.normalize(self.origin + name)
            body, meta = await self._fetch(url)
            if body is None:
                continue
            self._persist(url, body, meta)
            text = body.decode("utf-8", "replace")
            found = (discovery.from_robots(url, text) if name.endswith("robots.txt")
                     else discovery.from_sitemap(url, text))
            await self._enqueue(found, depth=1)

    # ------------------------------------------------------------------ page BFS
    async def _crawl_pages(self) -> None:
        workers = [
            asyncio.create_task(self._page_worker())
            for _ in range(settings.crawl_concurrency)
        ]
        await self.frontier.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    async def _page_worker(self) -> None:
        while True:
            url, depth = await self.frontier.get()
            try:
                if self._pages_done >= settings.crawl_max_pages:
                    continue
                await self._handle_page(url, depth)
            except Exception as exc:  # a bad page must not kill the crawl
                self.result.errors.append(f"{url}: {exc}")
            finally:
                self.frontier.task_done()

    async def _handle_page(self, url: str, depth: int) -> None:
        if not self._allowed(url):
            return
        body, meta = await self._fetch(url)
        if body is None:
            return

        async with self._lock:
            self._pages_done += 1
            done = self._pages_done
        self._record_headers(url, meta)
        rel = self._persist(url, body, meta)

        ctype = meta.get("content_type", "")
        text = body.decode(meta.get("charset") or "utf-8", "replace")

        if "html" in ctype or rel.endswith((".html", ".htm")):
            found = discovery.from_html(url, text)
            for i, inline in enumerate(found.inline_scripts):
                self._write_text(
                    self.sources_dir / "inline" / f"{U._sanitize(U.host_of(url))}"
                    / f"{Path(rel).stem}.inline{i}.js",
                    inline, origin_url=url, kind="inline-script",
                )
            self.result.forms.extend(found.forms)
            await self._enqueue(found, depth + 1)
        elif "javascript" in ctype or rel.endswith((".js", ".mjs", ".ts")):
            await self._enqueue(discovery.from_js(url, text), depth + 1)
        elif "css" in ctype or rel.endswith(".css"):
            await self._enqueue(discovery.from_css(url, text), depth + 1)

        await self._flush_announcements()

        if done % 5 == 0:
            pct = 0.05 + 0.25 * min(1.0, done / max(1, settings.crawl_max_pages))
            await self._emit("fetching", pct, f"Crawled {done} pages · {url}")

    # ------------------------------------------------------------------ assets
    async def _drain_assets(self) -> None:
        sem = asyncio.Semaphore(settings.crawl_concurrency)
        pending: list[asyncio.Task] = []

        while not self.asset_queue.empty():
            url = await self.asset_queue.get()
            pending.append(asyncio.create_task(self._handle_asset(url, sem)))
            if len(pending) >= 200:
                await asyncio.gather(*pending, return_exceptions=True)
                pending.clear()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        # Source maps discovered while parsing assets add a second wave.
        if not self.asset_queue.empty():
            await self._drain_assets()

    async def _handle_asset(self, url: str, sem: asyncio.Semaphore) -> None:
        if self._assets_done >= settings.crawl_max_assets:
            return
        async with sem:
            try:
                if not self._allowed(url):
                    return
                body, meta = await self._fetch(url)
                if body is None:
                    return
                async with self._lock:
                    self._assets_done += 1
                    done = self._assets_done
                rel = self._persist(url, body, meta)
                ctype = meta.get("content_type", "")

                if rel.endswith(".map"):
                    self._explode_sourcemap(url, body)
                elif "javascript" in ctype or rel.endswith((".js", ".mjs")):
                    text = body.decode("utf-8", "replace")
                    found = discovery.from_js(url, text)
                    for smap in found.sourcemaps:
                        await self._push_asset(smap)
                    self.result.endpoints |= found.endpoints
                    self.result.hosts |= {h for h in found.hosts if h}
                elif "css" in ctype or rel.endswith(".css"):
                    found = discovery.from_css(url, body.decode("utf-8", "replace"))
                    for a in found.assets:
                        await self._push_asset(a)

                await self._flush_announcements()

                if done % 25 == 0:
                    pct = 0.30 + 0.12 * min(1.0, done / max(1, settings.crawl_max_assets))
                    await self._emit("fetching", pct, f"Downloaded {done} assets")
            except Exception as exc:
                self.result.errors.append(f"{url}: {exc}")

    def _explode_sourcemap(self, url: str, body: bytes) -> None:
        """Unpack `sourcesContent` — the original, unminified application code."""
        pairs = discovery.from_sourcemap(url, body.decode("utf-8", "replace"))
        host = U._sanitize(U.host_of(url))
        for rel, text in pairs[:2000]:
            self._write_text(
                self.sources_dir / host / rel, text,
                origin_url=url, kind="sourcemap-original",
            )

    # ------------------------------------------------------------------ probes
    async def _probe_exposures(self) -> None:
        """Ask for the classics. A 200 with real content is itself the finding."""
        await self._emit("fetching", 0.43, "Checking commonly exposed paths")
        sem = asyncio.Semaphore(settings.crawl_concurrency)

        async def probe(url: str) -> None:
            async with sem:
                body, meta = await self._fetch(url, quiet=True)
                if body is None or meta.get("status") != 200:
                    return
                if len(body) < 8:
                    return
                snippet = body[:400].decode("utf-8", "replace")
                if "<!doctype html" in snippet.lower() and url.rsplit("/", 1)[-1].startswith("."):
                    return  # SPA catch-all route, not a real file
                self._persist(url, body, meta)
                self.result.exposures.append({
                    "url": url,
                    "status": meta.get("status"),
                    "bytes": len(body),
                    "content_type": meta.get("content_type"),
                    "preview": snippet[:200],
                })

        await asyncio.gather(*(probe(u) for u in discovery.probe_urls(self.origin)))

    # ------------------------------------------------------------------ plumbing
    async def _enqueue(self, found: discovery.Extracted, depth: int) -> None:
        self.result.hosts |= {h for h in found.hosts if h}
        self.result.endpoints |= found.endpoints

        if depth <= settings.crawl_max_depth:
            for link in found.links:
                if link in self.seen or not self._in_scope(link):
                    continue
                self.seen.add(link)
                await self.frontier.put((link, depth))

        for asset in found.assets | found.sourcemaps | found.endpoints:
            await self._push_asset(asset)

    async def _push_asset(self, url: str) -> None:
        if url in self.seen or not self._asset_in_scope(url):
            return
        self.seen.add(url)
        await self.asset_queue.put(url)

    def _in_scope(self, url: str) -> bool:
        """Navigation scope: which *pages* the crawler will walk into."""
        return U.same_site(url, self.root_domain, settings.crawl_follow_subdomains)

    def _asset_in_scope(self, url: str) -> bool:
        """Asset scope: which *files* get mirrored.

        Deliberately wider than navigation scope. A bundle served from a CDN,
        a third-party widget, an API on another host — all of it executes in
        your users' browsers and all of it is part of what has to be reviewed.
        Refusing to download it because the hostname differs is how a mirror
        ends up with "only some of the pages".
        """
        if self._in_scope(url):
            return True
        if not settings.crawl_external_assets:
            return False
        host = U.hostname_of(url)
        if not host:
            return False
        self.result.external_hosts.add(host)
        return True

    def _allowed(self, url: str) -> bool:
        if not settings.crawl_respect_robots:
            return True
        parsed = urlparse(url)
        rp = self._robots.get(f"{parsed.scheme}://{parsed.netloc}")
        if rp is None:
            return True
        try:
            return rp.can_fetch(USER_AGENT, url)
        except Exception:
            return True

    async def _load_robots(self, origin: str) -> None:
        try:
            resp = await self.client.get(origin + "/robots.txt")
            if resp.status_code == 200:
                rp = robotparser.RobotFileParser()
                rp.parse(resp.text.splitlines())
                self._robots[origin] = rp
        except Exception:
            pass

    async def _fetch(self, url: str, quiet: bool = False) -> tuple[bytes | None, dict]:
        try:
            async with self.client.stream("GET", url) as resp:
                ctype = (resp.headers.get("content-type") or "").lower()
                length = int(resp.headers.get("content-length") or 0)
                if length > settings.max_file_bytes:
                    return None, {}
                chunks, total = [], 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > settings.max_file_bytes:
                        break
                    chunks.append(chunk)
                meta = {
                    "status": resp.status_code,
                    "content_type": ctype.split(";")[0].strip(),
                    "charset": _charset(ctype),
                    "headers": dict(resp.headers),
                    "final_url": str(resp.url),
                }
                if resp.status_code >= 400:
                    return None, meta
                return b"".join(chunks), meta
        except Exception as exc:
            if not quiet:
                self.result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
            return None, {}

    def _record_headers(self, url: str, meta: dict) -> None:
        host = U.host_of(url)
        if host and host not in self.result.headers:
            self.result.headers[host] = {
                "url": url,
                "status": meta.get("status"),
                "headers": meta.get("headers", {}),
            }

    def _persist(self, url: str, body: bytes, meta: dict) -> str:
        rel = U.local_path_for(url, meta.get("content_type"))
        target = self.site_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        self._register(f"site/{rel}", target, url, meta.get("content_type"))
        return rel

    def _write_text(self, target: Path, text: str, origin_url: str, kind: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", errors="replace")
        rel = str(target.relative_to(self.dest)).replace(os.sep, "/")
        self._register(rel, target, origin_url, None, kind=kind)

    async def _flush_announcements(self) -> None:
        """Emit one event per newly mirrored file.

        `_register` is synchronous (it is called from sync persist helpers), so
        it queues records here and the async callers drain the queue. That keeps
        the browser's "files downloaded" list updating live during the crawl.
        """
        if not self.on_file or not self._pending_announce:
            self._pending_announce.clear()
            return
        pending, self._pending_announce = self._pending_announce, []
        for record in pending:
            await self.on_file("mirrored_file", {
                "path": record["path"],
                "url": record.get("url"),
                "bytes": record.get("bytes", 0),
                "lines": record.get("lines", 0),
                "language": record.get("language"),
                "kind": record.get("kind"),
            })

    def _register(self, rel: str, path: Path, url: str, ctype: str | None,
                  kind: str | None = None) -> None:
        data = path.read_bytes()
        suffix = path.suffix.lower()
        textual = suffix in TEXTUAL_SUFFIXES or (
            suffix not in BINARY_SUFFIXES and _looks_textual(data)
        )
        self.saved[rel] = {
            "path": rel,
            "url": url,
            "kind": kind or ("code" if textual else "binary"),
            "language": LANG_BY_SUFFIX.get(suffix, "text" if textual else "binary"),
            "bytes": len(data),
            "lines": data.count(b"\n") + 1 if textual else 0,
            "sha256": hashlib.sha256(data).hexdigest(),
            "content_type": ctype,
        }
        self._pending_announce.append(self.saved[rel])

    def _write_inventory(self) -> None:
        (self.dest / "inventory.json").write_text(
            json.dumps({**self.result.as_dict(), "files": self.result.files}, indent=2),
            encoding="utf-8",
        )

    async def _emit(self, stage: str, pct: float, message: str) -> None:
        if self.on_progress:
            await self.on_progress(stage, pct, message)


def _charset(content_type: str) -> str | None:
    if "charset=" in content_type:
        return content_type.split("charset=")[-1].split(";")[0].strip() or None
    return None


def _looks_textual(data: bytes) -> bool:
    sample = data[:2048]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 126 or b >= 160)
    return not sample or printable / len(sample) > 0.85
