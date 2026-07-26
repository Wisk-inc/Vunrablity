# Vunrablity

A website vulnerability assessor. Give it a URL. It downloads your entire
application, unpacks it into a real sandbox, has a local model read it line by
line, and then lets you talk to that model about what it found — including
letting it run commands in the sandbox to prove or disprove its own claims.

```
  URL  ──▶  mirror  ──▶  organise  ──▶  read every line  ──▶  chat + agent
           (crawler)     (inventory)    (Ollama + rules)      (sandbox)
```

![Landing](docs/screenshot-landing.png)

![Audit chat](docs/screenshot-chat.png)

![AI coverage panel — honest when the model never answered](docs/screenshot-coverage.png)

---

## What it actually does

**1. Downloads everything.** Not just the landing page. The crawler walks
pages, scripts, stylesheets, JSON, images, fonts, `robots.txt`, `sitemap.xml`,
and every sub-domain it discovers on the way. It scrapes URLs out of JavaScript
string literals, `fetch`/`axios`/XHR call sites, and CSS `url()` rules — so
API routes that never appear in a link still end up in the inventory.

**2. Recovers your original source.** If your bundles ship `.js.map` files, it
unpacks `sourcesContent` back into the pre-minified, pre-bundled files you
actually wrote. That is usually where the real bugs live, and it is also a
finding in its own right.

**3. Probes for the classics.** `.env`, `.git/config`, `phpinfo.php`,
`/actuator/env`, database dumps, `swagger.json`. A `200` with real content is
recorded as a finding on the spot. GET requests only — it asks politely and
notes what the server volunteers.

**4. Reads every line.** A local Ollama model walks each file in overlapping
windows of ~120 lines, each labelled with absolute line numbers. It carries a
memory across the whole scan — facts it established, files it summarised,
findings it already recorded — so file 200 is judged in the context of what it
learned in file 3. A deterministic rule engine (60+ patterns) runs first and
hands the model its hits as hints to confirm, downgrade, or reject.

**5. Grades and explains.** Every finding gets a severity — *Critical*,
*Dangerous*, *Moderate*, *Small*, *Informational* — plus a confidence score, a
CWE, the exact offending line, why it is exploitable **here**, and the specific
change to make.

**6. Runs your code, for real.** The mirror is mounted into a Docker container
via [llm-sandbox](https://github.com/vndee/llm-sandbox). The agent can execute
the files it flagged, write and run its own scripts, and grep the tree — the
same way [gpt-engineer](https://github.com/AntonOsika/gpt-engineer) works, but
pointed at auditing instead of authoring. There is a terminal in the UI so you
can drive it yourself.

**7. Then you chat.** The scan redirects you into a chat with the model that
did the reading. Ask why something matters, ask for the patch, or tell it to go
verify a finding and watch it work step by step.

---

## Install

Requires **Python 3.11+**, **Docker**, and **[Ollama](https://ollama.com)**.

```bash
git clone https://github.com/Wisk-inc/Vunrablity.git && cd Vunrablity
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

ollama pull qwen2.5-coder:7b        # or any code-capable model
docker pull python:3.11-slim        # the sandbox base image

cp .env.example .env                # optional — every value has a default
python run.py
```

Open <http://127.0.0.1:8000>, type your domain, press Enter.

The landing page shows two status dots: one for Ollama, one for the sandbox.
If either is dark, the message next to it says what to do about it.

---

## Configuration

Everything lives in `.env` (see `.env.example`). The values worth knowing:

| Setting | Default | What it controls |
| --- | --- | --- |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b` | The model that reads your code |
| `OLLAMA_NUM_CTX` | `8192` | Context window; bigger = more lines per pass |
| `CRAWL_MAX_PAGES` | `400` | Page budget for the crawl |
| `CRAWL_MAX_ASSETS` | `1500` | Asset budget |
| `CRAWL_FOLLOW_SUBDOMAINS` | `true` | Follow `*.yourdomain.com` |
| `CRAWL_RESPECT_ROBOTS` | `true` | Honour `robots.txt` |
| `ANALYSIS_CHUNK_LINES` | `120` | Lines per reading window |
| `ANALYSIS_MAX_FILES` | `400` | Cap on files sent to the model |
| `SANDBOX_BACKEND` | `auto` | `auto` \| `llm-sandbox` \| `docker` \| `none` |
| `SANDBOX_IMAGE` | `python:3.11-slim` | Container base image |
| `SANDBOX_NETWORK` | `none` | Sandbox networking. Leave it off. |
| `AGENT_MAX_STEPS` | `25` | Tool calls per agent investigation |

A bigger model reads better. `qwen2.5-coder:14b` or `deepseek-coder-v2` are
noticeably sharper on subtle logic bugs if you have the VRAM.

---

## The sandbox

One container per scan, started on demand:

- the downloaded copy is bind-mounted **read-only** at `/mirror`
- a writable `tmpfs` copy lives at `/work` — the agent can break it freely
- `--network none`, so the sandbox can never be turned back on the live site
- `--read-only` root, `--cap-drop ALL`, `--security-opt no-new-privileges`
- capped at 1 GB memory, 1 CPU, 256 PIDs

The agent's tools are `list_files`, `read_file`, `grep`, `run`, `python`,
`write_file`, `add_finding`, `remember`, and `finish`. Reads are resolved
against the scan directory and rejected if they try to escape it.

---

## Layout

```
app/
  crawler/      urls.py · discovery.py · downloader.py     the mirror engine
  analysis/     static_rules.py   60+ deterministic patterns
                llm.py            Ollama client (chat, stream, strict JSON)
                memory.py         cross-file memory for the audit
                headers.py        response-header and exposure checks
                analyzer.py       the line-by-line reading loop
                prompts.py        every prompt, in one place
  agent/        tools.py · loop.py                          the investigator
  sandbox/      runner.py                                   the container
  static/       index.html · chat.html · css/ · js/         the UI
  main.py       HTTP + WebSocket surface
  pipeline.py   download → index → audit → report
tests/          51 tests, including a deliberately-broken fixture site and a
                real-Ollama integration test that skips without one
```

---

## Tests

```bash
pytest                       # 51 tests, ~10 seconds
```

`tests/fixtures/site/` is a small website with real planted bugs — a leaked
GitHub token, `innerHTML` from the query string, a source map hiding SQL
injection and command injection, an exposed `.env` and `.git/config`, a
password form posting over plain HTTP. The suite serves it on localhost,
mirrors it, audits it, and asserts the findings come back.

Sandbox tests skip automatically when Docker or the configured image is
unavailable. To run them against a different image:

```bash
VUNRABLITY_TEST_IMAGE=my-image:tag pytest tests/test_sandbox.py
```

### Proving the model is the one finding things

Every test above except one replaces Ollama with a scripted stand-in — that
proves the *plumbing* works, not that a real model reads real code. To prove
that, point `tests/test_llm_integration.py` at a live Ollama:

```bash
ollama pull qwen2.5-coder:7b     # or set OLLAMA_MODEL to whatever you have
pytest tests/test_llm_integration.py -v -s
```

It skips automatically if Ollama isn't reachable. When it runs, it asserts —
against the *real* model's *real* output — that: the model actually answered
(not just that it was asked), at least one finding is attributed to it
(`source: "ai"`, never producible by the rule engine), the finding touches one
of the fixture's planted bugs by content rather than by coincidence, and every
AI-cited line number exists in the real file on disk.

The same guarantee holds at runtime, not just in tests. `Analyzer` only
credits a file as AI-reviewed once the model has returned a chunk it could
actually parse — being *sent* to the model doesn't count, only a real answer
does (see `files_ai_reviewed` in `app/analysis/analyzer.py`). Every finding
carries its `source` (`ai`, `rule:<id>`, `header-check`, `exposure-probe`,
`form-check`, or `agent`), so nothing the rule engine found can be mistaken
for something the model found. The chat UI's "AI coverage" panel renders this
directly: how many files were queued, how many the model actually answered
for, and how the findings split by origin.

---

## Design notes

**Why rules *and* a model?** The rules never miss a live AWS key and never
hallucinate one. The model understands that `innerHTML` assigned a server-side
constant is fine while the same line fed from `location.search` is not. Rules
run first and become hints; the model confirms, downgrades, or rejects each
one. Both sets of findings are kept, tagged with their source.

**Why memory?** A vulnerability is rarely visible in a 120-line window. Knowing
that "auth is a JWT in localStorage" from file 3 is what makes an `innerHTML`
sink in file 90 a critical account-takeover rather than a cosmetic XSS.

**Why is the model local?** Your source code never leaves your machine. That is
the entire reason this uses Ollama rather than a hosted API.

**Degradation.** If Ollama is down, the scan still completes — rules, header
checks, and exposure probes carry it, and the report says so plainly rather
than pretending.

---

## Scope and consent

Scan property you own or are explicitly authorised to test. The crawler issues
`GET`/`HEAD` only: no payloads, no fuzzing, no authentication bypass, no
attempts to modify state. Everything it reports, it learned by asking the
server for files the server chose to serve. The sandbox is offline by design so
that the analysis phase cannot reach your production systems at all.

---

## Interface

Black, white, and glass. No colour-coded severity — severity is carried by
weight and shape, so it reads the same to everyone. The landing page narrates
the crawl as it happens; the chat view puts findings on the left, the
conversation in the middle, and slides out a code viewer, a file browser, or a
live sandbox terminal on the right.
