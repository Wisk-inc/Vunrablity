/* Chat view: findings list, streaming answers, live agent trace, code viewer,
   and a terminal wired straight into the scan's sandbox container. */

const $ = (id) => document.getElementById(id);
const scanId = new URLSearchParams(location.search).get("scan");

const stream   = $("stream");
const inner    = $("streamInner");
const input    = $("input");
const sendBtn  = $("sendBtn");
const drawer   = $("drawer");
const backdrop = $("backdrop");

const SEV = ["critical", "high", "medium", "low", "info"];
const LABEL = { critical: "Critical", high: "Dangerous", medium: "Moderate",
                low: "Small", info: "Info" };

let socket = null;
let mode = "auto";
let findings = [];
let filter = null;
let busy = false;
let liveAgent = null;   // { el, steps }

if (!scanId) location.href = "/";

/* ------------------------------------------------------------------ boot */
(async function boot() {
  await loadScan();
  await loadHistory();
  connect();
  input.focus();
})();

async function loadScan() {
  const res = await fetch(`/api/scan/${scanId}`);
  if (!res.ok) { location.href = "/"; return; }
  const data = await res.json();

  findings = data.findings || [];
  const scan = data.scan || {};
  const summary = scan.summary && typeof scan.summary === "object" ? scan.summary : {};

  $("sideTarget").textContent = scan.url || "—";
  $("headSub").textContent =
    `${data.file_count} files mirrored · ${findings.length} findings · ${scan.status}`;
  $("reportBtn").href = `/api/scan/${scanId}/report.md`;
  $("reportBtn").setAttribute("download", `vunrablity-${scanId}.md`);

  if (summary.verdict || summary.summary) {
    $("verdictBox").hidden = false;
    const risk = summary.risk || "info";
    const chip = $("riskChip");
    chip.className = `sev sev-${risk}`;
    chip.textContent = LABEL[risk] || risk;
    $("filesRead").textContent = `${summary.files_read ?? 0} files read`;
    $("verdictText").textContent = summary.verdict || summary.summary || "";
  }

  renderCoverage(summary.coverage);
  renderCounts(data.counts || {});
  renderFindings();
}

/* Makes the model's actual involvement checkable, not just claimed: how many
   files it was sent, how many it returned a real answer for, and how many of
   the findings on the left came from the model versus the pattern rules. */
function renderCoverage(cov) {
  const box = $("coverageBox");
  if (!cov) { box.hidden = true; return; }
  box.hidden = false;

  const denom = Math.max(1, cov.files_queued_for_ai || 0);
  const pct = Math.round(100 * (cov.files_ai_reviewed || 0) / denom);

  $("coverageTitle").textContent = cov.ai_available
    ? `${cov.ai_model} read ${cov.files_ai_reviewed}/${cov.files_queued_for_ai} queued files`
    : `AI unreachable — rule engine only`;

  const bar = $("coverageFill");
  bar.style.width = `${cov.ai_available ? pct : 0}%`;
  $("coverageFill").parentElement.classList.toggle("degraded", !cov.ai_available);

  const rows = $("coverageRows");
  rows.innerHTML = "";
  const add = (label, value) => {
    const row = document.createElement("div");
    row.className = "coverage-row";
    row.innerHTML = `<span>${label}</span><b></b>`;
    row.querySelector("b").textContent = value;
    rows.appendChild(row);
  };
  add("Chunks sent to the model", `${cov.chunks_sent_to_ai} sent · ${cov.chunks_ai_answered} answered`);
  add("Findings from the AI's reading", cov.findings_from_ai);
  add("Findings from pattern rules", cov.findings_from_rules);
  add("Findings from headers / exposed paths", cov.findings_from_headers_and_probes);
  if (cov.files_vendor_skipped) {
    add("Vendored/minified files skipped", cov.files_vendor_skipped);
  }

  const rows2 = $("coverageRows");
  const existingWarn = rows2.parentElement.querySelector(".coverage-warn");
  existingWarn?.remove();
  if (!cov.ai_available) {
    const warn = document.createElement("div");
    warn.className = "coverage-warn";
    warn.textContent = "The model never answered during this scan. Every finding " +
      "above came from the deterministic rule engine and header checks — start " +
      "Ollama and re-scan for a line-by-line review.";
    rows2.parentElement.appendChild(warn);
  }
}

function renderCounts(counts) {
  const box = $("counts");
  box.innerHTML = "";
  SEV.forEach((s) => {
    const el = document.createElement("div");
    el.className = "count" + (filter === s ? " active" : "");
    el.innerHTML = `<b>${counts[s] || 0}</b><span>${LABEL[s]}</span>`;
    el.onclick = () => { filter = filter === s ? null : s; renderCounts(counts); renderFindings(); };
    box.appendChild(el);
  });
}

/* Maps a finding's raw `source` field to a badge that says plainly whether the
   model found this, or a deterministic check did — the two are never blended
   into one label, so the origin of every claim on screen stays checkable. */
function sourceOrigin(source) {
  if (source === "ai") {
    return { kind: "ai", label: "AI read this", title: "Found by the model while reading this file line by line" };
  }
  if (source === "agent") {
    return { kind: "ai", label: "AI · sandbox-confirmed", title: "Found by the agent while executing code in the sandbox" };
  }
  if (source?.startsWith("rule:")) {
    return { kind: "rule", label: "Pattern rule", title: `Deterministic rule: ${source.slice(5)}` };
  }
  if (source === "header-check") {
    return { kind: "rule", label: "Response headers", title: "Deterministic check of the server's HTTP headers" };
  }
  if (source === "exposure-probe") {
    return { kind: "rule", label: "Exposed path", title: "A well-known path answered with real content" };
  }
  if (source === "form-check") {
    return { kind: "rule", label: "Form check", title: "Deterministic check of a form's markup" };
  }
  return { kind: "rule", label: source || "check", title: source || "" };
}

function renderFindings() {
  const box = $("findings");
  const list = filter ? findings.filter((f) => f.severity === filter) : findings;
  box.innerHTML = "";

  if (!list.length) {
    box.innerHTML = `<div class="empty">${
      filter ? `Nothing at ${LABEL[filter]} severity.` : "No findings recorded."
    }</div>`;
    return;
  }

  list.forEach((f) => {
    const el = document.createElement("article");
    el.className = "finding";
    const origin = sourceOrigin(f.source);
    el.innerHTML = `
      <div class="top">
        <span class="sev sev-${f.severity}">${LABEL[f.severity] || f.severity}</span>
        <span class="origin origin-${origin.kind}" title="${origin.title}">${origin.label}</span>
        <span class="tiny dim" style="margin-left:auto">${Math.round((f.confidence || 0) * 100)}%</span>
      </div>
      <h4></h4>
      <div class="loc"></div>
      <div class="body">
        <h5>Why it matters</h5><p class="why"></p>
        <h5>Evidence</h5><pre class="ev"></pre>
        <h5>Fix</h5><p class="fx"></p>
        <div class="acts">
          <button class="btn" data-act="open">View code</button>
          <button class="btn" data-act="ask">Explain</button>
          <button class="btn" data-act="verify">Verify in sandbox</button>
        </div>
      </div>`;

    el.querySelector("h4").textContent = f.title;
    el.querySelector(".loc").textContent =
      `${f.file_path || "—"}${f.line_start ? ":" + f.line_start : ""}` +
      `${f.cwe ? "  ·  " + f.cwe : ""}`;
    el.querySelector(".why").textContent = f.explanation || "—";
    el.querySelector(".ev").textContent = f.evidence || "—";
    el.querySelector(".fx").textContent = f.fix || "—";

    el.addEventListener("click", (e) => {
      if (e.target.closest("[data-act]")) return;
      document.querySelectorAll(".finding.open").forEach((o) => o !== el && o.classList.remove("open"));
      el.classList.toggle("open");
    });

    el.querySelector('[data-act="open"]').onclick = () => viewCode(f);
    el.querySelector('[data-act="ask"]').onclick = () =>
      send(`Explain "${f.title}" in ${f.file_path}:${f.line_start}. ` +
           `Is it really exploitable, and what exactly do I change?`, "answer");
    el.querySelector('[data-act="verify"]').onclick = () =>
      send(`Verify the finding "${f.title}" at ${f.file_path}:${f.line_start}. ` +
           `Read the file in the sandbox, decide whether it is genuinely exploitable, ` +
           `and show me what you ran.`, "agent");

    box.appendChild(el);
  });
}

/* ------------------------------------------------------------------ history */
async function loadHistory() {
  const res = await fetch(`/api/scan/${scanId}/messages`);
  const { messages } = await res.json();
  if (!messages.length) {
    bubble("assistant", "The audit is still running, or produced no report. " +
                        "Ask me anything once it lands.");
    return;
  }
  messages.forEach((m) => bubble(m.role, m.content));
  scrollDown();
}

/* ------------------------------------------------------------------ socket */
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${proto}://${location.host}/ws/chat/${scanId}`);

  socket.onmessage = (ev) => {
    let e;
    try { e = JSON.parse(ev.data); } catch { return; }

    switch (e.type) {
      case "answer_start":
        startAssistant();
        break;

      case "token":
        appendToken(e.content);
        break;

      case "answer_end":
        finishAssistant(e.content);
        break;

      case "agent_start":
        startAgent();
        break;

      case "agent_step":
        agentStep(e);
        break;

      case "agent_observation":
        agentObservation(e);
        break;

      case "answer":
        finishAgent(e.content);
        if (e.new_findings?.length) loadScan();
        break;

      case "agent_error":
      case "error":
        finishAssistant(`_${e.message || e.error}_`);
        break;
    }
  };

  socket.onclose = () => setBusy(false);
}

/* ------------------------------------------------------------------ sending */
function send(text, forced) {
  const message = (text ?? input.value).trim();
  if (!message || busy) return;
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    bubble("assistant", "_Connection lost. Reload the page._");
    return;
  }
  bubble("user", message);
  input.value = "";
  input.style.height = "auto";
  setBusy(true);
  socket.send(JSON.stringify({ message, mode: forced || mode }));
  scrollDown();
}

sendBtn.onclick = () => send();
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
});
input.addEventListener("input", () => {
  input.style.height = "auto";
  input.style.height = Math.min(input.scrollHeight, 200) + "px";
});
$("chips").addEventListener("click", (e) => {
  if (e.target.classList.contains("chip")) send(e.target.textContent);
});

$("modeToggle").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-mode]");
  if (!btn) return;
  mode = btn.dataset.mode;
  [...$("modeToggle").children].forEach((b) => b.classList.toggle("on", b === btn));
  $("modeHint").textContent = {
    auto:   "Auto — the agent takes over when you ask it to do something",
    answer: "Explain — answers from the audit, no sandbox",
    agent:  "Agent — plans, runs commands in the sandbox, reports back",
  }[mode];
});

function setBusy(v) {
  busy = v;
  sendBtn.disabled = v;
  input.disabled = v;
  if (!v) input.focus();
}

/* ------------------------------------------------------------------ bubbles */
function bubble(role, content) {
  const el = document.createElement("div");
  el.className = `msg ${role}`;
  el.innerHTML = `
    <div class="av">${role === "user"
      ? '<svg class="icon" viewBox="0 0 24 24" style="width:14px;height:14px"><circle cx="12" cy="8" r="3.4"/><path d="M5 20c1.2-3.6 4-5.2 7-5.2s5.8 1.6 7 5.2"/></svg>'
      : '<svg class="icon" style="width:15px;height:15px"><use href="#i-shield"/></svg>'}</div>
    <div class="content"></div>`;
  el.querySelector(".content").innerHTML = md.render(content);
  inner.appendChild(el);
  scrollDown();
  return el;
}

let current = null;
let buffer = "";

function startAssistant() {
  buffer = "";
  current = bubble("assistant", "");
  current.querySelector(".content").classList.add("caret");
}

function appendToken(t) {
  if (!current) startAssistant();
  buffer += t;
  current.querySelector(".content").innerHTML = md.render(buffer);
  scrollDown();
}

function finishAssistant(final) {
  if (!current) current = bubble("assistant", "");
  const c = current.querySelector(".content");
  c.classList.remove("caret");
  c.innerHTML = md.render(final || buffer);
  current = null;
  buffer = "";
  setBusy(false);
  scrollDown();
}

/* ------------------------------------------------------------------ agent */
function startAgent() {
  const el = bubble("assistant", "");
  const c = el.querySelector(".content");
  c.innerHTML = `
    <details class="trace" open>
      <summary>
        <svg class="icon spin" style="width:13px;height:13px"><use href="#i-loop"/></svg>
        <span class="label">Investigating in the sandbox…</span>
      </summary>
      <div class="steps"></div>
    </details>
    <div class="agent-answer"></div>`;
  liveAgent = { el, steps: c.querySelector(".steps"), trace: c.querySelector(".trace") };
  scrollDown();
}

function agentStep(e) {
  if (!liveAgent) startAgent();
  const step = document.createElement("div");
  step.className = "step";
  step.dataset.step = e.step;
  step.innerHTML = `
    <div class="th"></div>
    <div class="call"><b></b><span></span></div>`;
  step.querySelector(".th").textContent = e.thought || "";
  step.querySelector("b").textContent = e.tool;
  step.querySelector(".call span").textContent = summarizeArgs(e.args);
  liveAgent.steps.appendChild(step);
  liveAgent.trace.querySelector(".label").textContent =
    `Step ${e.step} · ${e.tool}`;
  scrollDown();
}

function agentObservation(e) {
  if (!liveAgent) return;
  const step = liveAgent.steps.querySelector(`[data-step="${e.step}"]`);
  if (!step) return;
  const pre = document.createElement("pre");
  pre.textContent = e.observation || "";
  step.appendChild(pre);
  scrollDown();
}

function finishAgent(answer) {
  if (!liveAgent) { finishAssistant(answer); return; }
  const spinner = liveAgent.trace.querySelector(".spin");
  spinner?.classList.remove("spin");
  const count = liveAgent.steps.children.length;
  liveAgent.trace.querySelector(".label").textContent =
    `${count} step${count === 1 ? "" : "s"} in the sandbox`;
  liveAgent.trace.open = false;
  liveAgent.el.querySelector(".agent-answer").innerHTML = md.render(answer || "");
  liveAgent = null;
  setBusy(false);
  scrollDown();
}

function summarizeArgs(args) {
  if (!args || typeof args !== "object") return "";
  const s = JSON.stringify(args);
  return s.length > 160 ? s.slice(0, 160) + "…" : s;
}

function scrollDown() {
  requestAnimationFrame(() => { stream.scrollTop = stream.scrollHeight; });
}

/* ------------------------------------------------------------------ drawer */
function openDrawer(title, path) {
  $("drawerTitle").textContent = title;
  $("drawerPath").textContent = path || "";
  drawer.classList.add("open");
  backdrop.classList.add("on");
}
function closeDrawer() {
  drawer.classList.remove("open");
  backdrop.classList.remove("on");
}
$("drawerClose").onclick = closeDrawer;
backdrop.onclick = closeDrawer;
document.addEventListener("keydown", (e) => e.key === "Escape" && closeDrawer());

async function viewCode(f) {
  if (!f.file_path) return;
  openDrawer("Source", f.file_path);
  const body = $("drawerBody");
  body.innerHTML = `<div class="empty">Loading…</div>`;

  const start = Math.max(1, (f.line_start || 1) - 25);
  const end = (f.line_end || f.line_start || 1) + 40;
  const res = await fetch(
    `/api/scan/${scanId}/file?path=${encodeURIComponent(f.file_path)}&start=${start}&end=${end}`
  );
  if (!res.ok) {
    body.innerHTML = `<div class="empty">This finding is not tied to a file in the
      mirror (it came from response headers or a probe).</div>`;
    return;
  }
  const data = await res.json();
  const pre = document.createElement("div");
  pre.className = "code";
  data.content.split("\n").forEach((line, i) => {
    const n = data.start + i;
    const row = document.createElement("div");
    row.className = "ln" + (n >= (f.line_start || -1) && n <= (f.line_end || -1) ? " mark" : "");
    row.innerHTML = `<span class="n">${n}</span><span class="t"></span>`;
    row.querySelector(".t").textContent = line;
    pre.appendChild(row);
  });
  body.innerHTML = "";
  body.appendChild(pre);
  const marked = body.querySelector(".ln.mark");
  marked?.scrollIntoView({ block: "center" });
}

/* ------------------------------------------------------------------ files */
$("filesBtn").onclick = async () => {
  openDrawer("Mirror", `${findings.length} findings · downloaded copy`);
  const body = $("drawerBody");
  body.innerHTML = `<div class="empty">Loading…</div>`;
  const { files } = await (await fetch(`/api/scan/${scanId}/files`)).json();

  const wrap = document.createElement("div");
  wrap.style.padding = "12px 18px";
  wrap.innerHTML = `<input id="fileFilter" placeholder="filter…" class="mono"
    style="width:100%;background:transparent;border:1px solid var(--line);
           border-radius:8px;padding:9px 11px;color:#fff;outline:none;margin-bottom:12px">`;
  const list = document.createElement("div");
  wrap.appendChild(list);

  const draw = (q = "") => {
    list.innerHTML = "";
    files
      .filter((f) => !q || f.path.toLowerCase().includes(q))
      .slice(0, 800)
      .forEach((f) => {
        const row = document.createElement("div");
        row.style.cssText =
          "display:flex;justify-content:space-between;gap:12px;padding:7px 9px;" +
          "border-bottom:1px solid var(--line-soft);cursor:pointer;font-size:12px";
        row.innerHTML = `<span class="mono" style="word-break:break-all"></span>
                         <span class="tiny dim" style="white-space:nowrap">${f.lines} ln${
                           f.analyzed ? " · read" : ""}</span>`;
        row.querySelector("span").textContent = f.path;
        row.onclick = () => viewCode({ file_path: f.path, line_start: 1, line_end: 1 });
        list.appendChild(row);
      });
  };
  draw();
  body.innerHTML = "";
  body.appendChild(wrap);
  $("fileFilter").oninput = (e) => draw(e.target.value.toLowerCase());
};

/* ------------------------------------------------------------------ terminal */
$("termBtn").onclick = async () => {
  openDrawer("Sandbox", "container · /work · network: none");
  const body = $("drawerBody");
  body.innerHTML = `
    <div class="term">
      <pre class="term-out" id="termOut">Starting container…\n</pre>
      <div class="term-in">
        <span>/work $</span>
        <input id="termIn" spellcheck="false" autocomplete="off"
               placeholder="ls -la  ·  grep -rn 'apiKey' .  ·  python3 -c '...'">
      </div>
    </div>`;

  const out = $("termOut");
  const write = (text, cls) => {
    const span = document.createElement("span");
    if (cls) span.className = cls;
    span.textContent = text;
    out.appendChild(span);
    out.scrollTop = out.scrollHeight;
  };

  try {
    const res = await fetch(`/api/scan/${scanId}/sandbox/start`, { method: "POST" });
    const info = await res.json();
    if (!res.ok) throw new Error(info.detail || "could not start");
    write(`ready · backend=${info.backend} · image=${info.image}\n`);
    write(`the downloaded copy of the site is mounted at /work\n\n`);
  } catch (err) {
    write(`sandbox unavailable: ${err.message}\n`, "err");
    write(`start Docker and reopen this panel.\n`, "err");
    return;
  }

  const termIn = $("termIn");
  termIn.focus();
  const history = [];
  let hIdx = 0;

  termIn.addEventListener("keydown", async (e) => {
    if (e.key === "ArrowUp")   { hIdx = Math.max(0, hIdx - 1); termIn.value = history[hIdx] || ""; return; }
    if (e.key === "ArrowDown") { hIdx = Math.min(history.length, hIdx + 1); termIn.value = history[hIdx] || ""; return; }
    if (e.key !== "Enter") return;

    const cmd = termIn.value.trim();
    if (!cmd) return;
    history.push(cmd); hIdx = history.length;
    termIn.value = "";
    write(`$ ${cmd}\n`, "cmd");
    termIn.disabled = true;

    try {
      const res = await fetch(`/api/scan/${scanId}/sandbox/exec`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd }),
      });
      const data = await res.json();
      if (data.stdout) write(data.stdout.endsWith("\n") ? data.stdout : data.stdout + "\n");
      if (data.stderr) write(data.stderr.endsWith("\n") ? data.stderr : data.stderr + "\n", "err");
      if (!data.stdout && !data.stderr) write(`(exit ${data.exit_code})\n`, "err");
    } catch (err) {
      write(`${err.message}\n`, "err");
    } finally {
      termIn.disabled = false;
      termIn.focus();
    }
  });
};
