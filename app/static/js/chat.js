/* The workspace view.

   One conversation. The model streams prose; when it acts, an action card
   appears and fills in live — a file being written shows its contents arriving
   character by character, a command shows its real output. Clicking any file
   chip opens that file, highlighted, with an Edit button. */

const $ = (id) => document.getElementById(id);
const scanId = new URLSearchParams(location.search).get("scan");

const stream = $("stream");
const inner = $("streamInner");
const input = $("input");
const sendBtn = $("sendBtn");
const drawer = $("drawer");
const backdrop = $("backdrop");

const SEV = ["critical", "high", "medium", "low", "info"];
const LABEL = { critical: "Critical", high: "Dangerous", medium: "Moderate",
                low: "Small", info: "Info" };

const ICON = {
  write: "i-file", append: "i-file", read: "i-file", mkdir: "i-folder",
  move: "i-folder", copy: "i-folder", delete: "i-x", list: "i-folder",
  tree: "i-folder", grep: "i-search", run: "i-terminal", bash: "i-terminal",
  sh: "i-terminal", python: "i-play", node: "i-play", install: "i-box",
  fetch: "i-globe", serve: "i-eye", stop: "i-x", logs: "i-terminal",
  finding: "i-shield", remember: "i-brain",
};

let socket = null;
let findings = [];
let filter = null;
let busy = false;
let sbxTimer = null;

/* current streaming state */
let bubbleEl = null;      // assistant bubble
let proseEl = null;       // prose container inside it
let proseBuf = "";
let actionEl = null;      // action card being filled
let actionBodyEl = null;
let actionBuf = "";
let thinkingEl = null;

if (!scanId) location.href = "/";

/* ------------------------------------------------------------------ boot */
(async function boot() {
  await loadScan();
  await loadHistory();
  connect();
  pollSandbox();
  input.focus();
})();

/* ------------------------------------------------------------------ scan data */
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
  if (summary.coverage) $("modelLabel").textContent = summary.coverage.ai_model || "";

  renderCoverage(summary.coverage);
  renderCounts(data.counts || {});
  renderFindings();
}

function renderCoverage(cov) {
  const box = $("coverageBox");
  if (!cov) { box.hidden = true; return; }
  box.hidden = false;
  const denom = Math.max(1, cov.files_queued_for_ai || 0);
  const pct = Math.round(100 * (cov.files_ai_reviewed || 0) / denom);

  $("coverageTitle").textContent = cov.ai_available
    ? `${cov.ai_model} read ${cov.files_ai_reviewed}/${cov.files_queued_for_ai} files`
    : "AI unreachable — rule engine only";
  $("coverageFill").style.width = `${cov.ai_available ? pct : 0}%`;
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
  add("Chunks sent / answered",
      `${cov.chunks_sent_to_ai} · ${cov.chunks_ai_answered}`);
  add("Findings from the AI", cov.findings_from_ai);
  add("Findings from rules", cov.findings_from_rules);
  add("From headers / exposed paths", cov.findings_from_headers_and_probes);

  rows.parentElement.querySelector(".coverage-warn")?.remove();
  if (!cov.ai_available) {
    const warn = document.createElement("div");
    warn.className = "coverage-warn";
    warn.textContent = "The model never answered during the scan. Everything " +
      "above came from the rule engine and header checks.";
    rows.parentElement.appendChild(warn);
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

function sourceOrigin(source) {
  if (source === "ai") return { kind: "ai", label: "AI read this" };
  if (source === "agent") return { kind: "ai", label: "AI · confirmed" };
  if (source?.startsWith("rule:")) return { kind: "rule", label: "Pattern rule" };
  if (source === "header-check") return { kind: "rule", label: "Headers" };
  if (source === "exposure-probe") return { kind: "rule", label: "Exposed path" };
  if (source === "form-check") return { kind: "rule", label: "Form check" };
  return { kind: "rule", label: source || "check" };
}

function renderFindings() {
  const box = $("findings");
  const list = filter ? findings.filter((f) => f.severity === filter) : findings;
  box.innerHTML = "";
  if (!list.length) {
    box.innerHTML = `<div class="empty">${filter
      ? `Nothing at ${LABEL[filter]} severity.` : "No findings recorded."}</div>`;
    return;
  }
  list.forEach((f) => {
    const el = document.createElement("article");
    el.className = "finding";
    const origin = sourceOrigin(f.source);
    el.innerHTML = `
      <div class="top">
        <span class="sev sev-${f.severity}">${LABEL[f.severity] || f.severity}</span>
        <span class="origin origin-${origin.kind}">${origin.label}</span>
        <span class="tiny dim" style="margin-left:auto">${Math.round((f.confidence || 0) * 100)}%</span>
      </div>
      <h4></h4><div class="loc"></div>
      <div class="body">
        <h5>Why it matters</h5><p class="why"></p>
        <h5>Evidence</h5><pre class="ev"></pre>
        <h5>Fix</h5><p class="fx"></p>
        <div class="acts">
          <button class="btn" data-act="open">Open file</button>
          <button class="btn" data-act="ask">Explain</button>
          <button class="btn" data-act="verify">Prove it</button>
        </div>
      </div>`;
    el.querySelector("h4").textContent = f.title;
    el.querySelector(".loc").textContent =
      `${f.file_path || "—"}${f.line_start ? ":" + f.line_start : ""}${f.cwe ? "  ·  " + f.cwe : ""}`;
    el.querySelector(".why").textContent = f.explanation || "—";
    el.querySelector(".ev").textContent = f.evidence || "—";
    el.querySelector(".fx").textContent = f.fix || "—";
    el.addEventListener("click", (e) => {
      if (e.target.closest("[data-act]")) return;
      document.querySelectorAll(".finding.open").forEach((o) => o !== el && o.classList.remove("open"));
      el.classList.toggle("open");
    });
    el.querySelector('[data-act="open"]').onclick = () =>
      openFile(f.file_path, { line: f.line_start, source: "mirror" });
    el.querySelector('[data-act="ask"]').onclick = () =>
      send(`Explain "${f.title}" in ${f.file_path}:${f.line_start}. Is it really exploitable, and what exactly do I change?`);
    el.querySelector('[data-act="verify"]').onclick = () =>
      send(`Prove whether "${f.title}" at ${f.file_path}:${f.line_start} is genuinely exploitable. Read the real file, write a test if you need one, run it, and show me what happened.`);
    box.appendChild(el);
  });
}

/* ------------------------------------------------------------------ history */
async function loadHistory() {
  const { messages } = await (await fetch(`/api/scan/${scanId}/messages`)).json();
  if (!messages.length) {
    addBubble("assistant",
      "The mirror is ready. Ask me anything about it — or tell me to build, run, " +
      "or check something and I'll do it here in the workspace.");
    return;
  }
  messages.forEach((m) => {
    const el = addBubble(m.role, m.content);
    // Replay the actions that happened inside this turn.
    (m.meta?.transcript || []).forEach((t) => {
      const card = buildAction(t.tool, t.args || {}, t.body || "");
      card.classList.add("collapsed", t.ok ? "ok" : "fail");
      card.querySelector(".state").textContent = t.ok ? "done" : "failed";
      appendOutput(card, t.observation || "");
      el.querySelector(".content").appendChild(card);
    });
  });
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
      case "token":         onToken(e.content); break;
      case "action_open":   onActionOpen(e); break;
      case "action_delta":  onActionDelta(e.text); break;
      case "action_result": onActionResult(e); break;
      case "turn_end":      onTurnEnd(); break;
      case "error":         onToken(`\n\n_${e.message}_\n`); break;
    }
  };
  socket.onclose = () => { setBusy(false); markSandbox(false); };
}

/* ------------------------------------------------------------------ streaming */
function ensureBubble() {
  if (bubbleEl) return;
  bubbleEl = addBubble("assistant", "");
  proseEl = document.createElement("div");
  bubbleEl.querySelector(".content").appendChild(proseEl);
  proseBuf = "";
}

function onToken(text) {
  removeThinking();
  ensureBubble();
  proseBuf += text;
  proseEl.innerHTML = md.render(proseBuf);
  scrollDown();
}

function onActionOpen(e) {
  removeThinking();
  ensureBubble();
  // Prose written before this action stays put; start a fresh prose block after.
  actionBuf = "";
  actionEl = buildAction(e.tool, e.args || {}, "");
  bubbleEl.querySelector(".content").appendChild(actionEl);
  actionBodyEl = actionEl.querySelector(".action-body pre");

  proseEl = document.createElement("div");
  bubbleEl.querySelector(".content").appendChild(proseEl);
  proseBuf = "";
  markSandbox(true, `${e.tool}${e.path ? " " + e.path : ""}`);
  scrollDown();
}

function onActionDelta(text) {
  if (!actionEl) return;
  actionBuf += text;
  const lang = hl.guessLanguage(actionEl.dataset.path || "");
  actionBodyEl.innerHTML = hl.highlightCode(actionBuf, lang);
  actionEl.querySelector(".state").textContent = `${actionBuf.length} bytes`;
  scrollDown();
}

function onActionResult(e) {
  if (!actionEl) return;
  actionEl.classList.add(e.ok ? "ok" : "fail");
  actionEl.querySelector(".state").textContent = e.ok ? "done" : "failed";
  appendOutput(actionEl, e.observation || "");
  const path = e.meta?.path || e.args?.path;
  if (path) attachChip(actionEl, path);
  if (e.meta?.action === "serve") {
    attachPreviewLink(actionEl, e.meta.port);
    refreshSandbox();
  }
  if (e.meta?.action === "finding") loadScan();
  actionEl = null;
  actionBodyEl = null;
  scrollDown();
}

function onTurnEnd() {
  removeThinking();
  bubbleEl = null;
  proseEl = null;
  proseBuf = "";
  actionEl = null;
  setBusy(false);
  markSandbox(false);
  loadScan();
}

/* ------------------------------------------------------------------ action cards */
function buildAction(tool, args, body) {
  const el = document.createElement("div");
  el.className = "action";
  const path = args.path || "";
  el.dataset.path = path;
  const label = path || args.url || args.name || args.pattern || "";
  el.innerHTML = `
    <div class="action-head">
      <svg class="icon" style="width:14px;height:14px"><use href="#${ICON[tool] || "i-terminal"}"/></svg>
      <span class="tool">${md.esc(tool)}</span>
      <span class="target"></span>
      <span class="state"><span class="wave"><i></i><i></i><i></i><i></i><i></i></span></span>
    </div>
    <div class="action-body"><pre></pre></div>`;
  el.querySelector(".target").textContent = label;
  el.querySelector(".action-body pre").innerHTML =
    hl.highlightCode(body, hl.guessLanguage(path));
  el.querySelector(".action-head").onclick = () => el.classList.toggle("collapsed");
  return el;
}

function appendOutput(card, text) {
  if (!text) return;
  const out = document.createElement("div");
  out.className = "action-out";
  const pre = document.createElement("pre");
  pre.textContent = text;
  out.appendChild(pre);
  card.querySelector(".action-body").appendChild(out);
}

function attachChip(card, path) {
  const chip = document.createElement("button");
  chip.className = "chip-file";
  chip.innerHTML = `<svg class="icon"><use href="#i-file"/></svg><span></span>`;
  chip.querySelector("span").textContent = path;
  chip.onclick = (e) => { e.stopPropagation(); openFile(path, { source: "workspace" }); };
  const head = card.querySelector(".action-head");
  head.parentElement.insertBefore(wrapChip(chip), head.nextSibling);
}

function wrapChip(chip) {
  const holder = document.createElement("div");
  holder.style.padding = "8px 12px 2px";
  holder.appendChild(chip);
  return holder;
}

function attachPreviewLink(card, port) {
  if (!port) return;
  const btn = document.createElement("button");
  btn.className = "chip-file";
  btn.innerHTML = `<svg class="icon"><use href="#i-eye"/></svg><span>open preview :${port}</span>`;
  btn.onclick = (e) => { e.stopPropagation(); openPreview(port); };
  card.appendChild(wrapChip(btn));
}

function showThinking() {
  removeThinking();
  thinkingEl = document.createElement("div");
  thinkingEl.className = "msg assistant";
  thinkingEl.innerHTML = `
    <div class="av"><svg class="icon" style="width:15px;height:15px"><use href="#i-shield"/></svg></div>
    <div class="content"><div class="thinking">
      <span class="wave"><i></i><i></i><i></i><i></i><i></i></span>
      <span>thinking…</span>
    </div></div>`;
  inner.appendChild(thinkingEl);
  scrollDown();
}

function removeThinking() {
  thinkingEl?.remove();
  thinkingEl = null;
}

/* ------------------------------------------------------------------ send */
function send(text) {
  const message = (text ?? input.value).trim();
  if (!message || busy) return;
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    addBubble("assistant", "_Connection lost — reload the page._");
    return;
  }
  addBubble("user", message);
  input.value = "";
  input.style.height = "auto";
  setBusy(true);
  showThinking();
  socket.send(JSON.stringify({ message }));
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

function setBusy(v) {
  busy = v;
  sendBtn.disabled = v;
  if (!v) input.focus();
}

function addBubble(role, content) {
  const el = document.createElement("div");
  el.className = `msg ${role}`;
  el.innerHTML = `
    <div class="av">${role === "user"
      ? '<svg class="icon" viewBox="0 0 24 24" style="width:14px;height:14px"><circle cx="12" cy="8" r="3.4"/><path d="M5 20c1.2-3.6 4-5.2 7-5.2s5.8 1.6 7 5.2"/></svg>'
      : '<svg class="icon" style="width:15px;height:15px"><use href="#i-shield"/></svg>'}</div>
    <div class="content"></div>`;
  if (content) el.querySelector(".content").innerHTML = md.render(content);
  inner.appendChild(el);
  scrollDown();
  return el;
}

function scrollDown() {
  requestAnimationFrame(() => { stream.scrollTop = stream.scrollHeight; });
}

/* ------------------------------------------------------------------ drawer */
function openDrawer(title, sub) {
  $("drawerTitle").textContent = title;
  $("drawerPath").textContent = sub || "";
  // Edit/Save belong to the file viewer only; every other panel starts clean.
  $("editBtn").hidden = true;
  $("saveBtn").hidden = true;
  $("savedFlash").textContent = "";
  drawer.classList.add("open");
  backdrop.classList.add("on");
}
function closeDrawer() {
  drawer.classList.remove("open");
  backdrop.classList.remove("on");
  $("editBtn").hidden = true;
  $("saveBtn").hidden = true;
  $("savedFlash").textContent = "";
}
$("drawerClose").onclick = closeDrawer;
backdrop.onclick = closeDrawer;
document.addEventListener("keydown", (e) => e.key === "Escape" && closeDrawer());

/* ------------------------------------------------------------------ file viewer */
let current = { path: null, content: "", source: "workspace" };

async function openFile(path, { line = null, source = "workspace" } = {}) {
  if (!path) return;
  openDrawer("Source", path);
  const body = $("drawerBody");
  body.innerHTML = `<div class="empty">Loading…</div>`;
  $("editBtn").hidden = true;
  $("saveBtn").hidden = true;

  let content = null;
  // Prefer the agent's live workspace; fall back to the pristine mirror.
  const attempts = source === "mirror"
    ? [mirrorUrl(path), workspaceUrl(path)]
    : [workspaceUrl(path), mirrorUrl(path)];

  for (const attempt of attempts) {
    try {
      const res = await fetch(attempt.url);
      if (!res.ok) continue;
      const data = await res.json();
      const text = data.content ?? "";
      if (attempt.kind === "workspace" && /^.*: no such file$/.test(text.trim())) continue;
      content = text;
      current = { path, content, source: attempt.kind };
      break;
    } catch { /* try the next source */ }
  }

  if (content === null) {
    body.innerHTML = `<div class="empty">
      Couldn't read <code>${md.esc(path)}</code>.<br><br>
      Findings from response headers or exposed-path probes aren't backed by a
      file in the mirror.</div>`;
    return;
  }

  renderViewer(content, path, line);
  $("editBtn").hidden = false;
  $("drawerPath").textContent = `${path} · ${current.source}`;
}

function mirrorUrl(path) {
  return { kind: "mirror",
           url: `/api/scan/${scanId}/file?path=${encodeURIComponent(path)}` };
}
function workspaceUrl(path) {
  return { kind: "workspace",
           url: `/api/scan/${scanId}/workspace/file?path=${encodeURIComponent(path)}` };
}

function renderViewer(content, path, line) {
  const body = $("drawerBody");
  const lang = hl.guessLanguage(path);
  const view = document.createElement("div");
  view.className = "codeview";
  view.innerHTML = hl.renderFile(content, lang, {
    start: 1, mark: line ? [line, line] : null,
  });
  body.innerHTML = "";
  body.appendChild(view);
  if (line) view.querySelector(".cl.hit")?.scrollIntoView({ block: "center" });
}

$("editBtn").onclick = () => {
  const body = $("drawerBody");
  body.innerHTML = "";
  const wrap = document.createElement("div");
  wrap.className = "editor-wrap";
  const ta = document.createElement("textarea");
  ta.className = "editor";
  ta.spellcheck = false;
  ta.value = current.content;
  wrap.appendChild(ta);
  body.appendChild(wrap);
  ta.focus();
  $("editBtn").hidden = true;
  $("saveBtn").hidden = false;
  ta.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const s = ta.selectionStart;
      ta.value = ta.value.slice(0, s) + "  " + ta.value.slice(ta.selectionEnd);
      ta.selectionStart = ta.selectionEnd = s + 2;
    }
    if ((e.metaKey || e.ctrlKey) && e.key === "s") { e.preventDefault(); saveFile(ta.value); }
  });
};

$("saveBtn").onclick = () => {
  const ta = $("drawerBody").querySelector(".editor");
  if (ta) saveFile(ta.value);
};

async function saveFile(content) {
  const flash = $("savedFlash");
  flash.textContent = "saving…";
  try {
    const res = await fetch(`/api/scan/${scanId}/workspace/file`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: current.path, content }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
    current.content = content;
    current.source = "workspace";
    flash.textContent = "saved to workspace";
    setTimeout(() => (flash.textContent = ""), 2500);
    $("saveBtn").hidden = true;
    $("editBtn").hidden = false;
    renderViewer(content, current.path, null);
  } catch (err) {
    flash.textContent = err.message;
  }
}

/* ------------------------------------------------------------------ files */
$("filesBtn").onclick = async () => {
  openDrawer("Workspace", "everything that was downloaded");
  const body = $("drawerBody");
  body.innerHTML = `<div class="empty">Loading…</div>`;

  const [mirror, workspace] = await Promise.all([
    fetch(`/api/scan/${scanId}/files`).then((r) => r.json()).catch(() => ({ files: [] })),
    fetch(`/api/scan/${scanId}/workspace/tree?depth=6`).then((r) => r.json()).catch(() => ({ entries: [] })),
  ]);

  const wrap = document.createElement("div");
  wrap.innerHTML = `
    <div class="tabs">
      <button class="tab on" data-tab="mirror">Downloaded (${mirror.files.length})</button>
      <button class="tab" data-tab="workspace">Workspace (${(workspace.entries || []).length})</button>
    </div>
    <div style="padding:12px 16px">
      <input id="fileFilter" placeholder="filter…" class="mono"
        style="width:100%;background:transparent;border:1px solid var(--line);
               border-radius:8px;padding:9px 11px;color:#fff;outline:none;margin-bottom:10px">
      <div id="fileList"></div>
    </div>`;
  body.innerHTML = "";
  body.appendChild(wrap);

  let tab = "mirror";
  const draw = (q = "") => {
    const list = $("fileList");
    list.innerHTML = "";
    const rows = tab === "mirror"
      ? mirror.files.map((f) => ({ path: f.path, meta: `${f.lines} ln`, read: f.analyzed }))
      : (workspace.entries || []).filter((e) => e.type === "file")
          .map((e) => ({ path: e.path, meta: `${e.bytes} B` }));
    rows.filter((r) => !q || r.path.toLowerCase().includes(q))
      .slice(0, 1500)
      .forEach((r) => {
        const row = document.createElement("div");
        row.style.cssText =
          "display:flex;justify-content:space-between;gap:12px;padding:7px 9px;" +
          "border-bottom:1px solid var(--line-soft);cursor:pointer;font-size:12px";
        row.innerHTML = `<span class="mono" style="word-break:break-all"></span>
                         <span class="tiny dim" style="white-space:nowrap">${r.meta}${r.read ? " · read" : ""}</span>`;
        row.querySelector("span").textContent = r.path;
        row.onclick = () => openFile(r.path, { source: tab });
        list.appendChild(row);
      });
    if (!list.children.length) list.innerHTML = `<div class="empty">Nothing matches.</div>`;
  };
  draw();
  $("fileFilter").oninput = (e) => draw(e.target.value.toLowerCase());
  wrap.querySelectorAll(".tab").forEach((b) => {
    b.onclick = () => {
      tab = b.dataset.tab;
      wrap.querySelectorAll(".tab").forEach((x) => x.classList.toggle("on", x === b));
      draw($("fileFilter").value.toLowerCase());
    };
  });
};

/* ------------------------------------------------------------------ preview */
async function openPreview(port) {
  openDrawer("Preview", `the site running in the sandbox`);
  const body = $("drawerBody");
  const services = await fetch(`/api/scan/${scanId}/services`).then((r) => r.json())
    .catch(() => ({ services: [] }));
  const ports = [...new Set([
    ...(port ? [port] : []),
    ...services.services.map((s) => s.port).filter(Boolean),
  ])];
  const chosen = ports[0] || 8080;

  body.innerHTML = `
    <div class="preview-bar">
      <input id="previewPath" value="/" spellcheck="false">
      <button class="btn btn-icon" id="previewGo" title="Reload">
        <svg class="icon"><use href="#i-refresh"/></svg>
      </button>
    </div>
    <div style="flex:1;height:calc(100% - 52px)">
      <iframe class="preview-frame" id="previewFrame"></iframe>
    </div>`;

  const load = () => {
    const p = $("previewPath").value.replace(/^\//, "");
    $("previewFrame").src = `/preview/${scanId}/${chosen}/${p}`;
  };
  $("previewGo").onclick = load;
  $("previewPath").addEventListener("keydown", (e) => { if (e.key === "Enter") load(); });

  if (!ports.length) {
    body.querySelector("#previewFrame").srcdoc =
      `<body style="font:14px system-ui;background:#000;color:#888;padding:32px">
         Nothing is being served yet.<br><br>
         Ask me: <b style="color:#fff">"serve the site so I can click through it"</b>
       </body>`;
  } else {
    load();
  }
}
$("previewBtn").onclick = () => openPreview(null);

/* ------------------------------------------------------------------ shell */
$("termBtn").onclick = async () => {
  openDrawer("Shell", "runs inside the sandbox workspace");
  const body = $("drawerBody");
  body.innerHTML = `
    <div class="term">
      <pre class="term-out" id="termOut">starting…\n</pre>
      <div class="term-in">
        <span>$</span>
        <input id="termIn" spellcheck="false" autocomplete="off"
               placeholder="ls -la · grep -rn apiKey . · pip install requests">
      </div>
    </div>`;
  const out = $("termOut");
  const write = (t, cls) => {
    const s = document.createElement("span");
    if (cls) s.className = cls;
    s.textContent = t;
    out.appendChild(s);
    out.scrollTop = out.scrollHeight;
  };
  try {
    const res = await fetch(`/api/scan/${scanId}/sandbox/start`, { method: "POST" });
    const info = await res.json();
    if (!res.ok) throw new Error(info.detail || "could not start");
    out.textContent = "";
    write(`${info.backend} · ${info.workdir}\n`);
    if (info.isolation) write(`${info.isolation}\n`, "err");
    write("\n");
  } catch (err) {
    write(`sandbox unavailable: ${err.message}\n`, "err");
    return;
  }
  const termIn = $("termIn");
  termIn.focus();
  const history = [];
  let hIdx = 0;
  termIn.addEventListener("keydown", async (e) => {
    if (e.key === "ArrowUp") { hIdx = Math.max(0, hIdx - 1); termIn.value = history[hIdx] || ""; return; }
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
        method: "POST", headers: { "Content-Type": "application/json" },
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
$("sbxPill").onclick = () => $("termBtn").click();

/* ------------------------------------------------------------------ sandbox pill */
function markSandbox(live, label) {
  const pill = $("sbxPill");
  pill.classList.toggle("live", !!live);
  if (label) $("sbxLabel").textContent = label;
  else if (!live) refreshSandbox();
}

async function refreshSandbox() {
  try {
    const info = await (await fetch(`/api/scan/${scanId}/sandbox`)).json();
    const svc = (info.services || []).filter((s) => s.running);
    $("sbxLabel").textContent = info.running
      ? `${info.backend}${svc.length ? ` · ${svc.length} serving` : " · idle"}`
      : "sandbox idle";
  } catch { /* the pill is decoration; never break the page over it */ }
}

function pollSandbox() {
  refreshSandbox();
  sbxTimer = setInterval(refreshSandbox, 8000);
}

/* Exposed so a finding's "Open file" link, the file browser, and automated
   checks can all reach the same viewer. */
window.openFile = openFile;
window.openPreview = openPreview;
