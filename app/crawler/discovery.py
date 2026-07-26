"""Extraction passes that turn downloaded bytes into *more URLs to download*.

Three sources feed the frontier:
  1. HTML  -> anchors, scripts, styles, images, iframes, forms, srcset, meta refresh
  2. CSS   -> url(...) and @import
  3. JS    -> string literals that look like paths, fetch/axios/XHR targets,
              absolute URLs on any host, and `//# sourceMappingURL=` pointers
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable

from bs4 import BeautifulSoup

from . import urls as U

# --------------------------------------------------------------------------- regexes
RE_CSS_URL = re.compile(r"""url\(\s*['"]?([^'")]+)['"]?\s*\)""", re.I)
RE_CSS_IMPORT = re.compile(r"""@import\s+['"]([^'"]+)['"]""", re.I)
RE_SOURCEMAP = re.compile(r"""[#@]\s*sourceMappingURL\s*=\s*(\S+)""")
RE_ABS_URL = re.compile(r"""https?://[A-Za-z0-9._~%\-]+(?:/[^\s'"`<>\\)]*)?""")
RE_JS_PATH = re.compile(r"""['"`](/(?!/)[A-Za-z0-9._~\-/]{1,180})['"`]""")
RE_FETCHY = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\.open|\$\.(?:get|post|ajax)|useSWR|request)\s*\(\s*"""
    r"""[`'"]([^`'"]+)[`'"]""",
    re.I,
)
RE_HOSTNAME = re.compile(
    r"""['"`]((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})['"`]""", re.I
)
RE_API_VERBS = re.compile(r"""["'](/(?:api|v\d|graphql|rest|rpc|auth|oauth)[^"'\s]*)["']""", re.I)

# Paths worth *asking for* on your own property: if any of these come back 200
# with real content, that alone is a finding.
EXPOSURE_PROBES = [
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD",
    "/config.json", "/appsettings.json",
    "/package.json", "/composer.json", "/yarn.lock", "/package-lock.json",
    "/wp-config.php.bak", "/backup.sql", "/db.sql", "/dump.sql",
    "/.DS_Store", "/.htaccess", "/web.config",
    "/server-status", "/phpinfo.php", "/info.php",
    "/actuator", "/actuator/env", "/actuator/health",
    "/debug", "/debug/vars", "/__debug__/",
    "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
    "/api-docs", "/graphql", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/openid-configuration",
    "/admin", "/administrator", "/wp-admin/", "/phpmyadmin/",
]


@dataclass
class Extracted:
    links: set[str] = field(default_factory=set)       # navigable documents
    assets: set[str] = field(default_factory=set)      # js/css/img/font/json
    hosts: set[str] = field(default_factory=set)       # hostnames seen anywhere
    endpoints: set[str] = field(default_factory=set)   # API-ish paths
    forms: list[dict] = field(default_factory=list)
    sourcemaps: set[str] = field(default_factory=set)
    inline_scripts: list[str] = field(default_factory=list)

    def merge(self, other: "Extracted") -> None:
        self.links |= other.links
        self.assets |= other.assets
        self.hosts |= other.hosts
        self.endpoints |= other.endpoints
        self.forms.extend(other.forms)
        self.sourcemaps |= other.sourcemaps
        self.inline_scripts.extend(other.inline_scripts)


ASSET_TAGS = {
    "script": "src",
    "link": "href",
    "img": "src",
    "source": "src",
    "iframe": "src",
    "embed": "src",
    "object": "data",
    "video": "src",
    "audio": "src",
    "track": "src",
}


def from_html(base_url: str, html: str) -> Extracted:
    out = Extracted()
    soup = BeautifulSoup(html, "lxml")

    for a in soup.find_all("a", href=True):
        if (u := U.absolutize(base_url, a["href"])):
            out.links.add(u)

    for tag, attr in ASSET_TAGS.items():
        for el in soup.find_all(tag):
            val = el.get(attr)
            if val and (u := U.absolutize(base_url, val)):
                out.assets.add(u)
            if tag == "link":
                # preload/prefetch/manifest/icon all point at real files
                for extra in ("imagesrcset",):
                    if el.get(extra):
                        out.assets |= _srcset(base_url, el[extra])

    for el in soup.find_all(attrs={"srcset": True}):
        out.assets |= _srcset(base_url, el["srcset"])

    for meta in soup.find_all("meta"):
        if (meta.get("http-equiv") or "").lower() == "refresh":
            content = meta.get("content", "")
            if "url=" in content.lower():
                target = content.split("=", 1)[-1].strip().strip("'\"")
                if (u := U.absolutize(base_url, target)):
                    out.links.add(u)

    for form in soup.find_all("form"):
        action = U.absolutize(base_url, form.get("action") or base_url) or base_url
        out.forms.append({
            "page": base_url,
            "action": action,
            "method": (form.get("method") or "get").upper(),
            "enctype": form.get("enctype"),
            "has_csrf_field": bool(
                form.find("input", attrs={"name": re.compile("csrf|token|nonce", re.I)})
            ),
            "inputs": [
                {
                    "name": i.get("name"),
                    "type": (i.get("type") or "text").lower(),
                    "autocomplete": i.get("autocomplete"),
                }
                for i in form.find_all(("input", "textarea", "select"))
            ],
        })
        out.endpoints.add(action)

    for script in soup.find_all("script"):
        if not script.get("src") and script.string:
            body = script.string.strip()
            if body:
                out.inline_scripts.append(body)
                out.merge(from_js(base_url, body))

    for style in soup.find_all("style"):
        if style.string:
            out.merge(from_css(base_url, style.string))

    out.hosts |= {U.host_of(u) for u in out.links | out.assets if U.host_of(u)}
    return out


def _srcset(base_url: str, value: str) -> set[str]:
    found = set()
    for candidate in value.split(","):
        part = candidate.strip().split(" ")[0]
        if part and (u := U.absolutize(base_url, part)):
            found.add(u)
    return found


def from_css(base_url: str, text: str) -> Extracted:
    out = Extracted()
    for match in RE_CSS_URL.findall(text) + RE_CSS_IMPORT.findall(text):
        if (u := U.absolutize(base_url, match)):
            out.assets.add(u)
    return out


def from_js(base_url: str, text: str) -> Extracted:
    out = Extracted()

    for m in RE_SOURCEMAP.findall(text):
        if (u := U.absolutize(base_url, m)):
            out.sourcemaps.add(u)

    for raw in RE_ABS_URL.findall(text):
        u = U.normalize(raw.rstrip(".,);'\"`"))
        if u:
            out.assets.add(u)
            if (h := U.host_of(u)):
                out.hosts.add(h)

    for pattern in (RE_FETCHY, RE_API_VERBS):
        for m in pattern.findall(text):
            if (u := U.absolutize(base_url, m)):
                out.endpoints.add(u)

    for m in RE_JS_PATH.findall(text):
        # Skip obvious non-routes (regex fragments, unix paths in comments).
        if any(c in m for c in "\\ *?"):
            continue
        if (u := U.absolutize(base_url, m)):
            (out.assets if "." in m.rsplit("/", 1)[-1] else out.links).add(u)

    for h in RE_HOSTNAME.findall(text):
        out.hosts.add(h.lower())

    return out


def from_sourcemap(map_url: str, raw: str) -> list[tuple[str, str]]:
    """Return (original_path, source_text) pairs embedded in a .map file.

    This is how the mirror recovers *pre-bundle* application source — the
    readable code that actually contains the bugs.
    """
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out: list[tuple[str, str]] = []
    for i, src in enumerate(sources):
        if i >= len(contents):
            break
        body = contents[i]
        if not body:
            continue
        clean = re.sub(r"^[a-zA-Z0-9_.\-]+://", "", str(src))
        segments = [s for s in clean.split("/") if s not in ("", ".", "..", "~")]
        rel = "/".join(U._sanitize(s) for s in segments)
        out.append((rel or f"source_{i}.js", body))
    return out


def from_robots(base_url: str, text: str) -> Extracted:
    out = Extracted()
    for line in text.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in ("disallow", "allow") and value and value != "/":
            if (u := U.absolutize(base_url, value.split("*")[0])):
                out.links.add(u)
        elif key == "sitemap" and value:
            if (u := U.absolutize(base_url, value)):
                out.assets.add(u)
    return out


def from_sitemap(base_url: str, text: str) -> Extracted:
    out = Extracted()
    for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I):
        if (u := U.absolutize(base_url, loc)):
            out.links.add(u)
    return out


def probe_urls(origin: str) -> Iterable[str]:
    for path in EXPOSURE_PROBES:
        yield U.normalize(origin.rstrip("/") + path)
