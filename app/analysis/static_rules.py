"""Deterministic first pass.

The model is the analyst; these rules are the intern that highlights lines
before the analyst sits down. Two jobs:

  1. Catch the unambiguous stuff (a live AWS key is a live AWS key) so a finding
     exists even if the model is offline or hedges.
  2. Rank files, so the expensive line-by-line audit starts where the smoke is.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    pattern: re.Pattern
    languages: tuple[str, ...]
    note: str
    fix: str


def _r(id, title, severity, category, cwe, pattern, languages, note, fix, flags=re.I):
    return Rule(id, title, severity, category, cwe, re.compile(pattern, flags),
                languages, note, fix)


ANY = ("*",)
WEB = ("javascript", "typescript", "html", "vue", "svelte")

RULES: list[Rule] = [
    # ---------------------------------------------------------------- secrets
    _r("SEC-AWS-KEY", "AWS access key ID committed to shipped code", "critical",
       "secrets", "CWE-798", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", ANY,
       "AWS key IDs in client-delivered code are public the moment they ship.",
       "Revoke the key, move the call server-side, and issue short-lived STS credentials.",
       re.NOFLAG),
    _r("SEC-AWS-SECRET", "Possible AWS secret access key", "critical",
       "secrets", "CWE-798",
       r"""aws.{0,20}(secret|private).{0,20}['"][A-Za-z0-9/+=]{40}['"]""", ANY,
       "A 40-char base64 blob next to an AWS identifier is almost always the secret key.",
       "Revoke immediately and rotate. Never ship long-lived secrets to a browser."),
    _r("SEC-PRIVATE-KEY", "Private key material in a downloadable file", "critical",
       "secrets", "CWE-312",
       r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", ANY,
       "A private key served over HTTP is compromised by definition.",
       "Rotate the key pair, purge it from the build output, and audit access logs."),
    _r("SEC-GENERIC-TOKEN", "Hard-coded credential or API token", "high",
       "secrets", "CWE-798",
       r"""(api[_\-]?key|secret|passwd|password|token|bearer|auth)\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{16,}['"]""",
       ANY,
       "Literal credential assigned in source.",
       "Move to a server-side environment variable and proxy the call."),
    _r("SEC-PRIVATE-KEY-JSON", "Service-account JSON with a private key", "critical",
       "secrets", "CWE-798", r'"private_key"\s*:\s*"-----BEGIN', ANY,
       "Google/GCP service-account files grant broad access.",
       "Delete the key in IAM, rotate, and use workload identity instead."),
    _r("SEC-JWT", "JWT embedded in shipped code", "high", "secrets", "CWE-522",
       r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", ANY,
       "A baked-in token is valid for anyone who views source.",
       "Issue tokens per session at runtime; never inline them.", re.NOFLAG),
    _r("SEC-STRIPE", "Stripe secret key", "critical", "secrets", "CWE-798",
       r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b", ANY,
       "Stripe secret keys can move money.",
       "Roll the key in the Stripe dashboard now; use publishable keys client-side.",
       re.NOFLAG),
    _r("SEC-SLACK", "Slack token", "high", "secrets", "CWE-798",
       r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", ANY,
       "Slack tokens expose workspace data.",
       "Revoke in the Slack app config and rotate.", re.NOFLAG),
    _r("SEC-GITHUB-PAT", "GitHub personal access token", "critical",
       "secrets", "CWE-798", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", ANY,
       "A PAT can read or push to private repositories.",
       "Revoke in GitHub settings and replace with a scoped app token.", re.NOFLAG),
    _r("SEC-DB-URI", "Database connection string with credentials", "critical",
       "secrets", "CWE-798",
       r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s'\"]+:[^\s'\"@]+@", ANY,
       "Inline DSN exposes the database password.",
       "Rotate the password and read the DSN from the server environment."),

    # ---------------------------------------------------------------- xss / dom
    _r("XSS-INNERHTML", "Unsanitized HTML sink (innerHTML/outerHTML)", "high",
       "xss", "CWE-79",
       r"\.(inner|outer)HTML\s*(=|\+=)|insertAdjacentHTML\s*\(", WEB,
       "Assigning untrusted strings to an HTML sink executes attacker markup.",
       "Use textContent, or sanitize with DOMPurify before assignment."),
    _r("XSS-DANGEROUS-PROP", "React dangerouslySetInnerHTML", "high",
       "xss", "CWE-79", r"dangerouslySetInnerHTML", WEB,
       "React's escape hatch bypasses all built-in escaping.",
       "Render as text, or sanitize the value first."),
    _r("XSS-VUE-HTML", "Vue v-html directive", "high", "xss", "CWE-79",
       r"v-html\s*=", WEB,
       "v-html injects raw markup into the DOM.",
       "Prefer mustache interpolation, or sanitize the bound value."),
    _r("XSS-DOCWRITE", "document.write with dynamic content", "medium",
       "xss", "CWE-79", r"document\.write(ln)?\s*\(", WEB,
       "document.write parses its argument as HTML.",
       "Build nodes with createElement/textContent instead."),
    _r("XSS-EVAL", "Dynamic code execution (eval / new Function)", "high",
       "injection", "CWE-95",
       r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"]", WEB,
       "eval turns any injected string into running code.",
       "Replace with explicit logic; use JSON.parse for data."),
    _r("XSS-LOCATION", "Tainted navigation sink", "medium", "xss", "CWE-601",
       r"(location\.(href|replace|assign)|window\.open)\s*[=(]\s*[^'\"]*(location\.(search|hash)|params|query)",
       WEB,
       "URL-derived values flowing into navigation enable open redirect and javascript: XSS.",
       "Allow-list destinations; reject anything not matching a known route."),
    _r("XSS-POSTMESSAGE", "postMessage listener without origin check", "high",
       "xss", "CWE-346",
       r"addEventListener\s*\(\s*['\"]message['\"]", WEB,
       "A message handler that ignores event.origin trusts every frame on the internet.",
       "Check `event.origin` against an allow-list as the handler's first statement."),
    _r("XSS-POSTMESSAGE-STAR", "postMessage to wildcard origin", "medium",
       "xss", "CWE-346", r"postMessage\s*\([^,)]+,\s*['\"]\*['\"]", WEB,
       "'*' delivers the payload to whatever document happens to be loaded.",
       "Name the exact target origin."),

    # ---------------------------------------------------------------- injection
    _r("INJ-SQL", "SQL built by string concatenation", "critical",
       "injection", "CWE-89",
       r"""\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;\n]{0,160}"""
       r"""(\+\s*[\w.$]|\$\{|%\s*\(?\w|\.format\s*\(|<<|\|\|\s*\w)""",
       ANY,
       "Concatenated SQL lets input change the query's meaning.",
       "Use parameterized queries / prepared statements exclusively."),
    _r("INJ-CMD", "Shell execution with interpolated input", "critical",
       "injection", "CWE-78",
       r"(exec|execSync|spawnSync|system|popen|shell_exec|passthru|child_process\.\w+)\s*\([^)]*(\+|\$\{|%s|f['\"])",
       ANY,
       "String-built shell commands allow argument and command injection.",
       "Pass an argv array with shell disabled; never interpolate user data."),
    _r("INJ-DESERIALIZE", "Unsafe deserialization", "critical",
       "injection", "CWE-502",
       r"(pickle\.loads|yaml\.load\s*\((?![^)]*Safe)|unserialize\s*\(|ObjectInputStream)", ANY,
       "These parsers instantiate arbitrary objects from attacker bytes.",
       "Use yaml.safe_load / JSON, and never deserialize untrusted input."),
    _r("INJ-TEMPLATE", "Template rendered from a variable", "high",
       "injection", "CWE-1336",
       r"(render_template_string|Template\s*\(\s*\w+\s*\)|Handlebars\.compile\s*\(\s*\w+)", ANY,
       "User-controlled templates escalate to server-side template injection.",
       "Render fixed template files and pass data as context only."),
    _r("INJ-PATH", "Path built from request input", "high",
       "path-traversal", "CWE-22",
       r"(readFile|readFileSync|open|sendFile|createReadStream|include|require)\s*\([^)]*(req\.|request\.|params|query|argv)",
       ANY,
       "Unvalidated paths reach files outside the intended directory.",
       "Resolve the path and verify it stays under an allowed root before opening."),
    _r("INJ-SSRF", "Outbound request to a caller-supplied URL", "high",
       "ssrf", "CWE-918",
       r"(requests\.(get|post)|urlopen|fetch|axios(\.\w+)?|curl_exec|HttpClient)\s*\([^)]*(req\.|request\.|params|query|body)",
       ANY,
       "A server that fetches user URLs can be pointed at internal services.",
       "Allow-list hosts, resolve DNS first, and block link-local/private ranges."),

    # ---------------------------------------------------------------- crypto
    _r("CRY-WEAK-HASH", "Weak hash function", "medium", "crypto", "CWE-327",
       r"\b(md5|sha1)\s*\(|createHash\s*\(\s*['\"](md5|sha1)['\"]", ANY,
       "MD5 and SHA-1 are broken for integrity and unfit for passwords.",
       "Use SHA-256 for integrity, Argon2id or bcrypt for passwords."),
    _r("CRY-MATH-RANDOM", "Math.random used where randomness matters", "medium",
       "crypto", "CWE-338",
       r"Math\.random\s*\(\s*\)[^;\n]{0,80}(token|id|key|secret|nonce|otp|session|password)",
       WEB,
       "Math.random is predictable; tokens derived from it are guessable.",
       "Use crypto.getRandomValues (browser) or crypto.randomBytes (Node)."),
    _r("CRY-ECB", "AES in ECB mode", "high", "crypto", "CWE-327",
       r"AES[/\-_]?ECB|MODE_ECB", ANY,
       "ECB leaks plaintext structure across blocks.",
       "Use AES-GCM (authenticated) with a unique nonce per message."),
    _r("CRY-TLS-OFF", "TLS verification disabled", "critical", "crypto", "CWE-295",
       r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false))",
       ANY,
       "Skipping certificate checks reduces TLS to plaintext against an active attacker.",
       "Remove the flag and fix the underlying trust-store problem."),
    _r("CRY-HTTP", "Plaintext http:// endpoint", "low", "transport", "CWE-319",
       r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.)", ANY,
       "Cleartext requests are readable and modifiable in transit.",
       "Switch to https:// and add HSTS."),

    # ---------------------------------------------------------------- authz / config
    _r("CFG-CORS-STAR", "CORS wildcard origin", "medium", "config", "CWE-942",
       r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]", ANY,
       "A wildcard origin voids the same-origin policy for this response.",
       "Echo only origins from an explicit allow-list."),
    _r("CFG-CORS-REFLECT", "CORS origin reflected from the request", "high",
       "config", "CWE-942",
       r"Access-Control-Allow-Origin[^\n]{0,60}(req\.headers|request\.headers|origin)", ANY,
       "Reflecting Origin with credentials enabled lets any site read the response.",
       "Compare against a fixed allow-list before echoing."),
    _r("CFG-DEBUG", "Debug mode enabled", "medium", "config", "CWE-489",
       r"(DEBUG\s*[:=]\s*(True|true|1)|app\.debug\s*=\s*True|NODE_ENV\s*[:=]\s*['\"]development)",
       ANY,
       "Debug handlers expose stack traces, config, and sometimes a console.",
       "Force debug off in production builds."),
    _r("CFG-COOKIE", "Cookie set without security attributes", "medium",
       "session", "CWE-1004",
       r"(document\.cookie\s*=|Set-Cookie)(?![^\n]*HttpOnly)", ANY,
       "Cookies without HttpOnly/Secure/SameSite are readable by script and sent cross-site.",
       "Set HttpOnly, Secure, and SameSite=Lax or Strict."),
    _r("CFG-OPEN-FIREBASE", "Firebase config with open database URL", "medium",
       "config", "CWE-284", r"databaseURL\s*:\s*['\"]https://[^'\"]+firebaseio\.com", ANY,
       "Firebase config is public by design — the risk is in the security rules.",
       "Verify Firestore/RTDB rules deny unauthenticated reads and writes."),
    _r("AUT-CLIENT-CHECK", "Authorization decided in client code", "high",
       "authz", "CWE-602",
       r"(isAdmin|is_admin|role\s*===?\s*['\"]admin|hasPermission|canEdit)\s*(===?|\?|&&)", WEB,
       "Client-side role checks are advisory; the browser is under the user's control.",
       "Enforce the same check server-side on every privileged endpoint."),
    _r("AUT-LOCALSTORAGE-TOKEN", "Session token stored in localStorage", "medium",
       "session", "CWE-922",
       r"localStorage\.(setItem|getItem)\s*\(\s*['\"][^'\"]*(token|jwt|auth|session|key)", WEB,
       "localStorage is readable by any script, so one XSS equals full account takeover.",
       "Store sessions in HttpOnly cookies with SameSite set."),

    # ---------------------------------------------------------------- misc
    _r("MSC-TODO-SEC", "Security TODO left in shipped code", "info",
       "hygiene", "CWE-546",
       r"(TODO|FIXME|HACK|XXX)[^\n]{0,60}(secur|auth|inject|sanitiz|escape|validat|token)", ANY,
       "The author already knew about this one.",
       "Resolve or file it before release."),
    _r("MSC-SOURCEMAP", "Source map shipped to production", "low",
       "exposure", "CWE-540", r"sourceMappingURL\s*=", ANY,
       "Source maps hand attackers your original, commented source.",
       "Stop emitting maps in production, or restrict them to internal IPs."),
    _r("MSC-INTERNAL-HOST", "Internal hostname or private IP referenced", "low",
       "exposure", "CWE-200",
       r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|\w+\.(internal|local|corp|intranet))\b",
       ANY,
       "Internal topology leaked to the public build.",
       "Strip internal addresses from client bundles."),
    _r("MSC-EMAIL", "Email address exposed in source", "info", "exposure", "CWE-200",
       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", ANY,
       "Harvestable contact address.",
       "Use a form or obfuscated contact endpoint if this is unintentional."),
]

# Lines longer than this are minified bundles; regex hits there are noise.
MAX_LINE_FOR_RULES = 2000


@dataclass
class RuleHit:
    rule: Rule
    line_no: int
    line: str
    match: str


def scan_text(text: str, language: str = "text") -> list[RuleHit]:
    hits: list[RuleHit] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_FOR_RULES:
            continue
        for rule in RULES:
            if rule.languages != ANY and language not in rule.languages:
                continue
            m = rule.pattern.search(line)
            if m:
                hits.append(RuleHit(rule, idx, line.strip()[:400], m.group(0)[:160]))
    return hits


def hit_to_finding(hit: RuleHit, file_path: str) -> dict:
    return {
        "file_path": file_path,
        "line_start": hit.line_no,
        "line_end": hit.line_no,
        "severity": hit.rule.severity,
        "confidence": 0.55,
        "title": hit.rule.title,
        "category": hit.rule.category,
        "cwe": hit.rule.cwe,
        "evidence": hit.line,
        "explanation": hit.rule.note,
        "fix": hit.rule.fix,
        "source": f"rule:{hit.rule.id}",
    }


def score_file(hits: list[RuleHit]) -> float:
    """Priority score used to order the AI's reading queue."""
    weights = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.2}
    return sum(weights.get(h.rule.severity, 0.5) for h in hits)
