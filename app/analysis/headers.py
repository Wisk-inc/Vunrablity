"""Deterministic checks on the response headers the crawler collected."""
from __future__ import annotations

CHECKS = [
    {
        "header": "content-security-policy",
        "title": "No Content-Security-Policy",
        "severity": "medium",
        "explanation": "Without a CSP, any injected script runs with full privileges. "
                       "CSP is the difference between an XSS bug and an XSS incident.",
        "fix": "Add `Content-Security-Policy: default-src 'self'; object-src 'none'; "
               "base-uri 'self'` and tighten from there.",
        "cwe": "CWE-1021",
    },
    {
        "header": "strict-transport-security",
        "title": "No HTTP Strict-Transport-Security",
        "severity": "medium",
        "explanation": "The first request of every session can be downgraded to HTTP "
                       "and intercepted.",
        "fix": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
        "cwe": "CWE-319",
    },
    {
        "header": "x-content-type-options",
        "title": "No X-Content-Type-Options",
        "severity": "low",
        "explanation": "Browsers may sniff a response's type and execute an upload as script.",
        "fix": "Add `X-Content-Type-Options: nosniff`.",
        "cwe": "CWE-430",
    },
    {
        "header": "x-frame-options",
        "title": "No framing protection",
        "severity": "medium",
        "explanation": "The page can be framed by another site and clickjacked.",
        "fix": "Add `X-Frame-Options: DENY`, or `frame-ancestors 'none'` in the CSP.",
        "cwe": "CWE-1021",
        "satisfied_by_csp": "frame-ancestors",
    },
    {
        "header": "referrer-policy",
        "title": "No Referrer-Policy",
        "severity": "low",
        "explanation": "Full URLs — including tokens in query strings — leak to third parties.",
        "fix": "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
        "cwe": "CWE-200",
    },
    {
        "header": "permissions-policy",
        "title": "No Permissions-Policy",
        "severity": "low",
        "explanation": "Embedded content inherits access to camera, microphone, and geolocation.",
        "fix": "Add `Permissions-Policy: geolocation=(), camera=(), microphone=()`.",
        "cwe": "CWE-1021",
    },
]

LEAKY_HEADERS = {
    "server": "high" ,
    "x-powered-by": "medium",
    "x-aspnet-version": "medium",
    "x-aspnetmvc-version": "medium",
    "x-generator": "low",
    "x-drupal-cache": "low",
}


def analyze(headers_by_host: dict[str, dict]) -> list[dict]:
    findings: list[dict] = []

    for host, info in headers_by_host.items():
        raw = {k.lower(): v for k, v in (info.get("headers") or {}).items()}
        where = f"headers/{host}"
        csp = raw.get("content-security-policy", "")

        for check in CHECKS:
            if check["header"] in raw:
                continue
            if check.get("satisfied_by_csp") and check["satisfied_by_csp"] in csp:
                continue
            findings.append({
                "file_path": where,
                "line_start": None,
                "line_end": None,
                "severity": check["severity"],
                "confidence": 0.95,
                "title": f"{check['title']} on {host}",
                "category": "config",
                "cwe": check["cwe"],
                "evidence": f"{info.get('url')} responded without `{check['header']}`",
                "explanation": check["explanation"],
                "fix": check["fix"],
                "source": "header-check",
            })

        if csp:
            for bad, why in (
                ("unsafe-inline", "`unsafe-inline` re-enables exactly the injection CSP prevents."),
                ("unsafe-eval", "`unsafe-eval` allows string-to-code execution."),
                ("*", "A wildcard source lets any origin supply scripts."),
            ):
                if bad in csp:
                    findings.append({
                        "file_path": where,
                        "severity": "medium",
                        "confidence": 0.9,
                        "title": f"CSP weakened by `{bad}` on {host}",
                        "category": "config",
                        "cwe": "CWE-1021",
                        "evidence": csp[:300],
                        "explanation": why,
                        "fix": "Remove the directive and adopt nonces or hashes for "
                               "the scripts that need it.",
                        "source": "header-check",
                    })

        for leaky, severity in LEAKY_HEADERS.items():
            value = raw.get(leaky)
            if value and any(ch.isdigit() for ch in str(value)):
                findings.append({
                    "file_path": where,
                    "severity": "low" if severity == "high" else "info",
                    "confidence": 0.85,
                    "title": f"Software version disclosed via `{leaky}` on {host}",
                    "category": "exposure",
                    "cwe": "CWE-200",
                    "evidence": f"{leaky}: {value}",
                    "explanation": "An exact version tells an attacker which public "
                                   "exploits to try first.",
                    "fix": f"Suppress the `{leaky}` header at the proxy or app server.",
                    "source": "header-check",
                })

        cookies = raw.get("set-cookie", "")
        if cookies:
            missing = [a for a in ("HttpOnly", "Secure", "SameSite")
                       if a.lower() not in cookies.lower()]
            if missing:
                findings.append({
                    "file_path": where,
                    "severity": "medium",
                    "confidence": 0.9,
                    "title": f"Cookie missing {', '.join(missing)} on {host}",
                    "category": "session",
                    "cwe": "CWE-1004",
                    "evidence": cookies[:300],
                    "explanation": "Session cookies without these attributes are "
                                   "readable by script and sent on cross-site requests.",
                    "fix": f"Set {', '.join(missing)} on every session cookie.",
                    "source": "header-check",
                })

    return findings


def analyze_exposures(exposures: list[dict]) -> list[dict]:
    """A downloadable .env or .git/config is its own finding."""
    severe = {
        ".env": ("critical", "Environment file with application secrets is publicly readable."),
        ".git": ("critical", "The Git directory is served, so the full source history is downloadable."),
        "backup": ("critical", "A database backup is publicly downloadable."),
        ".sql": ("critical", "A SQL dump is publicly downloadable."),
        "phpinfo": ("high", "phpinfo() discloses paths, modules, and environment variables."),
        "actuator": ("high", "Spring Actuator endpoints expose configuration and sometimes credentials."),
        "server-status": ("high", "mod_status exposes live request URLs from other users."),
        "swagger": ("low", "The full API surface is published."),
        "openapi": ("low", "The full API surface is published."),
        "graphql": ("medium", "A GraphQL endpoint is reachable; check that introspection is off."),
        ".ds_store": ("low", "Directory listing metadata leaks file names."),
        "config.json": ("high", "An application config file is publicly readable."),
        "appsettings": ("high", "An application config file is publicly readable."),
        "package.json": ("info", "Dependency manifest is public; useful for version targeting."),
        ".htaccess": ("medium", "Server configuration is readable."),
        "web.config": ("high", "IIS configuration — often contains connection strings."),
    }

    out: list[dict] = []
    for exp in exposures:
        url = exp["url"]
        lowered = url.lower()
        match = next((k for k in severe if k in lowered), None)
        if match is None:
            continue
        severity, why = severe[match]
        out.append({
            "file_path": f"exposed/{url.rsplit('/', 1)[-1] or 'root'}",
            "severity": severity,
            "confidence": 0.9,
            "title": f"Publicly readable: {url}",
            "category": "exposure",
            "cwe": "CWE-538",
            "evidence": f"HTTP {exp['status']} · {exp['bytes']} bytes · "
                        f"{exp.get('content_type')}\n{exp.get('preview', '')[:200]}",
            "explanation": why,
            "fix": "Block the path at the web server or CDN and remove the file from "
                   "the deployed artifact. Rotate anything it disclosed.",
            "source": "exposure-probe",
        })
    return out
