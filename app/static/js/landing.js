/* Landing: take a URL, start the scan, narrate it, then hand off to the chat. */

const $ = (id) => document.getElementById(id);

const form      = $("scanForm");
const input     = $("urlInput");
const goBtn     = $("goBtn");
const wrap      = $("progressWrap");
const bar       = $("progBar");
const pct       = $("progPct");
const msg       = $("progMsg");
const logBox    = $("progLog");
const target    = $("progTarget");
const openBtn   = $("openChatBtn");
const cancelBtn = $("cancelBtn");

const STAGE_ORDER = ["fetching", "downloaded", "analyzing", "done"];
let socket = null;
let scanId = null;

/* ------------------------------------------------------------------ health */
(async function health() {
  try {
    const r = await fetch("/api/health");
    const h = await r.json();

    const ollamaOk = h.ollama?.ok;
    $("dotOllama").className = "dot " + (ollamaOk ? "on" : "off");
    $("ollamaLabel").textContent = ollamaOk
      ? `${h.ollama.model} ready`
      : (h.ollama?.hint || h.ollama?.error || "model unavailable");

    const sandboxOk = h.sandbox?.ok;
    $("dotSandbox").className = "dot " + (sandboxOk ? "on" : "off");
    $("sandboxLabel").textContent = sandboxOk
      ? `sandbox ready (${h.settings.sandbox_image})`
      : "sandbox unavailable — start Docker";
  } catch {
    $("ollamaLabel").textContent = "server unreachable";
    $("sandboxLabel").textContent = "—";
  }
})();

/* ------------------------------------------------------------------ start */
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  goBtn.disabled = true;
  log("→", `requesting scan of ${url}`);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    scanId = data.scan_id;
    target.textContent = data.url;
    wrap.classList.add("show");
    logBox.innerHTML = "";
    log("✓", `scan ${scanId} queued`);
    listen(scanId);
  } catch (err) {
    alert(`Could not start the scan.\n\n${err.message}`);
    goBtn.disabled = false;
  }
});

/* ------------------------------------------------------------------ stream */
function listen(id) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${proto}://${location.host}/ws/scan/${id}`);

  socket.onmessage = (ev) => {
    let e;
    try { e = JSON.parse(ev.data); } catch { return; }

    switch (e.type) {
      case "progress":
        setProgress(e.progress, e.message, e.stage);
        log(stageGlyph(e.stage), e.message);
        break;

      case "inventory":
        log("▣", `${e.files} files · ${fmtBytes(e.bytes)} · ` +
                 `${e.hosts.length} host${e.hosts.length === 1 ? "" : "s"}`);
        (e.hosts || []).slice(0, 8).forEach((h) => log(" ", h, true));
        break;

      case "finding":
        log("!", `[${e.severity}] ${e.title} — ${e.file_path}:${e.line_start ?? "?"}`, true);
        break;

      case "complete":
        setProgress(1, "Audit complete", "done");
        log("✓", "report ready");
        openBtn.disabled = false;
        openBtn.focus();
        setTimeout(() => go(id), 900);
        break;

      case "error":
        setProgress(0, e.message, "error");
        log("✕", e.message, true);
        goBtn.disabled = false;
        break;
    }
  };

  socket.onerror = () => log("✕", "lost connection to the server");
  socket.onclose = () => log("·", "stream closed");
}

/* ------------------------------------------------------------------ ui bits */
function setProgress(value, text, stage) {
  const p = Math.max(0, Math.min(1, value || 0));
  bar.style.width = `${(p * 100).toFixed(1)}%`;
  pct.textContent = `${Math.round(p * 100)}%`;
  if (text) msg.textContent = text;

  const idx = STAGE_ORDER.indexOf(stage);
  document.querySelectorAll(".stage").forEach((el, i) => {
    el.classList.toggle("active", i === idx);
    el.classList.toggle("done", idx > -1 && i < idx);
  });
}

function log(glyph, text, highlight = false) {
  const row = document.createElement("div");
  row.innerHTML = `<b>${glyph}</b><span class="${highlight ? "hit" : ""}"></span>`;
  row.querySelector("span").textContent = text;
  logBox.appendChild(row);
  logBox.scrollTop = logBox.scrollHeight;
  while (logBox.children.length > 400) logBox.removeChild(logBox.firstChild);
}

function stageGlyph(stage) {
  return { fetching: "↓", downloaded: "▣", analyzing: "◈", done: "✓" }[stage] || "·";
}

function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}

function go(id) {
  location.href = `/chat?scan=${id}`;
}

openBtn.addEventListener("click", () => scanId && go(scanId));
cancelBtn.addEventListener("click", () => {
  socket?.close();
  wrap.classList.remove("show");
  goBtn.disabled = false;
});

input.focus();
