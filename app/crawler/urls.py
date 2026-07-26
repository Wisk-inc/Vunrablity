"""URL / filesystem-path helpers for the mirror."""
from __future__ import annotations

import hashlib
import os
import posixpath
import re
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled snapshot

# Characters that are legal in URLs but a nuisance on disk.
_UNSAFE = re.compile(r"[^A-Za-z0-9._\-/]")

DEFAULT_INDEX = "index.html"


def normalize(url: str) -> str:
    """Canonical form: scheme lowercased, fragment dropped, empty path -> '/'."""
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    # Collapse duplicate slashes but keep the leading one.
    path = re.sub(r"/{2,}", "/", path)
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def registrable_domain(url: str) -> str:
    """`shop.acme.co.uk` -> `acme.co.uk`.

    Hosts with no public suffix — an IP address, `localhost`, an internal
    single-label name — have no registrable domain, so the hostname itself
    becomes the scope boundary.
    """
    host = hostname_of(url)
    if not host:
        return ""
    ext = _EXTRACT(host)
    combined = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return combined or host


def host_of(url: str) -> str:
    """Netloc as written, port included."""
    return urlparse(url).netloc.lower()


def hostname_of(url: str) -> str:
    """Netloc with the port stripped (and IPv6 brackets removed)."""
    netloc = urlparse(url).netloc.lower()
    if not netloc:
        return ""
    if netloc.startswith("["):                     # [::1]:8080
        return netloc.split("]")[0].lstrip("[")
    return netloc.rsplit(":", 1)[0] if ":" in netloc else netloc


_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$"
)
_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def looks_like_host(url: str) -> bool:
    """Is this a plausible website address, rather than a sentence?

    Accepts dotted names and IPv4/IPv6 literals; a bare single label is only
    allowed for `localhost`, since anything else is almost certainly a typo.
    """
    host = hostname_of(normalize(url))
    if not host:
        return False
    if host == "localhost" or _IPV4.match(host) or ":" in host:
        return True
    if not _HOSTNAME.match(host):
        return False
    return "." in host


def same_site(url: str, root_domain: str, allow_subdomains: bool = True) -> bool:
    """Is `url` part of the target property?"""
    host = hostname_of(url)
    if not host or not root_domain:
        return False
    if allow_subdomains:
        return host == root_domain or host.endswith("." + root_domain)
    return host == root_domain


def absolutize(base: str, link: str) -> str | None:
    link = (link or "").strip()
    if not link or link.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
        return None
    if link.startswith("//"):
        link = urlparse(base).scheme + ":" + link
    try:
        return normalize(urljoin(base, link))
    except ValueError:
        return None


def local_path_for(url: str, content_type: str | None = None) -> str:
    """Map a URL onto a stable, collision-free relative path inside the mirror.

    Query strings become part of the filename via a short hash so that
    `/api/items?page=1` and `?page=2` are both preserved.

    Names are kept faithful: `.env` stays `.env` and `.git/config` stays
    `.git/config`. Only an extension-less route that the server answered as
    HTML gains an `.html` suffix, because that is what it really is.
    """
    parts = urlsplit(url)
    host = parts.netloc.lower() or "unknown-host"
    path = parts.path or "/"

    if path.endswith("/"):
        path += DEFAULT_INDEX

    segments = [_sanitize(s) for s in path.split("/") if s not in ("", ".", "..")]
    if not segments:
        segments = [DEFAULT_INDEX]

    name = segments[-1]
    if parts.query:
        digest = hashlib.sha1(parts.query.encode()).hexdigest()[:8]
        stem, ext = posixpath.splitext(name)
        name = f"{stem}__q{digest}{ext}"

    is_dotfile = name.startswith(".") and posixpath.splitext(name)[0] == ""
    has_ext = bool(posixpath.splitext(name)[1])
    looks_html = content_type is None or "html" in (content_type or "")
    if not has_ext and not is_dotfile and looks_html:
        name += ".html"
    segments[-1] = name

    return posixpath.join(_sanitize(host), *segments)


def _sanitize(segment: str) -> str:
    """Make one path segment filesystem-safe without destroying its identity.

    A leading dot is preserved — dot-files are exactly the ones worth finding —
    but `.` and `..` themselves never survive.
    """
    seg = _UNSAFE.sub("_", segment)
    seg = seg.rstrip(". ").lstrip(" ")
    if seg in ("", ".", ".."):
        return "_"
    return seg[:120]


def ensure_parent(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
