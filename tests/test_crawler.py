"""The downloader has to actually download everything."""
from __future__ import annotations

import pytest

from app.config import settings
from app.crawler import SiteDownloader
from app.crawler import discovery, urls as U


@pytest.mark.asyncio
async def test_mirrors_pages_assets_and_sourcemap(site_server, scan_dir, monkeypatch):
    monkeypatch.setattr(settings, "crawl_respect_robots", False)
    dest = scan_dir / "scan"
    dest.mkdir()

    result = await SiteDownloader(site_server, dest).run()
    paths = {f["path"] for f in result.files}

    # pages reached by link, by sitemap, and by robots
    assert any(p.endswith("index.html") for p in paths)
    assert any(p.endswith("login.html") for p in paths)
    assert any(p.endswith("search.html") for p in paths)
    assert any(p.endswith("about.html") for p in paths)

    # assets referenced from HTML and from CSS @import
    assert any(p.endswith("app.js") for p in paths)
    assert any(p.endswith("style.css") for p in paths)
    assert any(p.endswith("theme.css") for p in paths)

    # inline <script> lifted out of the page into its own file
    assert any("/inline/" in p for p in paths)

    # the source map was unpacked back into original server code
    recovered = [p for p in paths if p.startswith("sources/") and "handlers" in p]
    assert recovered, f"source map was not exploded; got {sorted(paths)}"
    body = (dest / recovered[0]).read_text()
    assert "child_process" in body and "SELECT * FROM users" in body


@pytest.mark.asyncio
async def test_finds_exposed_files_and_endpoints(site_server, scan_dir, monkeypatch):
    monkeypatch.setattr(settings, "crawl_respect_robots", False)
    dest = scan_dir / "scan2"
    dest.mkdir()

    result = await SiteDownloader(site_server, dest).run()
    exposed = {e["url"].rsplit("/", 1)[-1] for e in result.exposures}

    assert ".env" in exposed
    assert "package.json" in exposed
    assert any(e["url"].endswith(".git/config") for e in result.exposures)

    # API paths lifted out of the JS bundle
    endpoints = {U.normalize(e) for e in result.endpoints}
    assert any("/api/v1/orders" in e for e in endpoints)
    assert any("/api/graphql" in e for e in endpoints)

    # the POST form on the index page was catalogued
    assert any(f["action"].endswith("/api/subscribe") for f in result.forms)

    # response headers were captured for the header checks
    assert result.headers, "no headers recorded"


def test_local_path_is_collision_free():
    a = U.local_path_for("https://x.test/api/items?page=1")
    b = U.local_path_for("https://x.test/api/items?page=2")
    assert a != b
    assert a.startswith("x.test/api/")

    assert U.local_path_for("https://x.test/").endswith("index.html")
    assert U.local_path_for("https://x.test/blog/post").endswith("post.html")


def test_path_traversal_cannot_escape_the_mirror():
    evil = U.local_path_for("https://x.test/../../etc/passwd")
    assert ".." not in evil.split("/")
    assert evil.startswith("x.test/")


def test_scope_is_the_registrable_domain():
    assert U.same_site("https://cdn.acme.test/a.js", "acme.test")
    assert U.same_site("https://acme.test/a.js", "acme.test")
    assert not U.same_site("https://evil.test/a.js", "acme.test")
    assert not U.same_site("https://acme.test.evil.test/a.js", "acme.test")


def test_js_extraction_finds_urls_hosts_and_maps():
    js = """
      const base = "https://api.acme.test/v2";
      fetch("/api/v1/orders");
      axios.post("/api/v1/pay", body);
      const host = "internal.acme.test";
      //# sourceMappingURL=/bundle.js.map
    """
    found = discovery.from_js("https://acme.test/app.js", js)
    assert any("/api/v1/orders" in u for u in found.endpoints)
    assert any("/api/v1/pay" in u for u in found.endpoints)
    assert "api.acme.test" in found.hosts
    assert "internal.acme.test" in found.hosts
    assert any(u.endswith("/bundle.js.map") for u in found.sourcemaps)
