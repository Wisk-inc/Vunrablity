/* A small, dependency-free Markdown renderer.
   Everything is HTML-escaped before any formatting is applied, so model output
   can never inject markup into the page. */

(function (global) {
  const esc = (s) =>
    String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

  function inline(text) {
    return text
      .replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`)
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(^|[\s(])\*([^*\n]+)\*/g, "$1<em>$2</em>")
      .replace(/(^|[\s(])_([^_\n]+)_/g, "$1<em>$2</em>")
      .replace(/~~([^~]+)~~/g, "<del>$1</del>")
      .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g,
               '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  }

  function render(src) {
    const lines = esc(src || "").split("\n");
    const out = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];

      // fenced code
      const fence = line.match(/^\s*```(\w+)?\s*$/);
      if (fence) {
        const lang = fence[1] || "";
        const body = [];
        i++;
        while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) body.push(lines[i++]);
        i++;
        out.push(`<pre><code data-lang="${lang}">${body.join("\n")}</code></pre>`);
        continue;
      }

      // table
      if (/^\s*\|/.test(line) && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1] || "")) {
        const head = cells(line);
        i += 2;
        const rows = [];
        while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(cells(lines[i++]));
        out.push(
          "<table><thead><tr>" +
            head.map((c) => `<th>${inline(c)}</th>`).join("") +
            "</tr></thead><tbody>" +
            rows.map((r) => "<tr>" + r.map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>").join("") +
            "</tbody></table>"
        );
        continue;
      }

      // heading
      const h = line.match(/^(#{1,6})\s+(.*)$/);
      if (h) {
        const level = Math.min(h[1].length + 1, 6);
        out.push(`<h${level}>${inline(h[2])}</h${level}>`);
        i++;
        continue;
      }

      // rule
      if (/^\s*([-*_])\s*\1\s*\1[\s\-*_]*$/.test(line)) { out.push("<hr>"); i++; continue; }

      // blockquote
      if (/^\s*>\s?/.test(line)) {
        const body = [];
        while (i < lines.length && /^\s*>\s?/.test(lines[i]))
          body.push(lines[i++].replace(/^\s*>\s?/, ""));
        out.push(`<blockquote>${render(body.join("\n"))}</blockquote>`);
        continue;
      }

      // lists
      if (/^\s*([-*+]|\d+[.)])\s+/.test(line)) {
        const ordered = /^\s*\d+[.)]\s+/.test(line);
        const items = [];
        while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
          items.push(lines[i++].replace(/^\s*([-*+]|\d+[.)])\s+/, ""));
          // continuation lines belong to the item above
          while (i < lines.length && /^\s{2,}\S/.test(lines[i]) &&
                 !/^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
            items[items.length - 1] += " " + lines[i++].trim();
          }
        }
        const tag = ordered ? "ol" : "ul";
        out.push(`<${tag}>` + items.map((t) => `<li>${inline(t)}</li>`).join("") + `</${tag}>`);
        continue;
      }

      // blank
      if (!line.trim()) { i++; continue; }

      // paragraph
      const para = [];
      while (i < lines.length && lines[i].trim() &&
             !/^\s*(#{1,6}\s|```|>|\||([-*+]|\d+[.)])\s)/.test(lines[i])) {
        para.push(lines[i++]);
      }
      out.push(`<p>${inline(para.join(" "))}</p>`);
    }

    return out.join("");
  }

  function cells(row) {
    return row.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
  }

  global.md = { render, esc };
})(window);
