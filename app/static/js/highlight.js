/* A small syntax highlighter.

   No CDN, no dependency, no build step — the page has to work on Replit with
   nothing installed. Tokenising is done with one combined regex per language
   so a 5,000-line bundle still highlights instantly.

   The palette stays monochrome to match the rest of the app: meaning is
   carried by weight, opacity and italics rather than hue, so it reads the
   same for everyone. */

(function (global) {
  const esc = (s) =>
    String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const KEYWORDS = {
    python: "False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield self cls",
    javascript: "abstract arguments await async break case catch class const continue debugger default delete do else enum export extends false finally for from function get if implements import in instanceof interface let new null of package private protected public return set static super switch this throw true try typeof var void while with yield",
    typescript: "abstract any as asserts async await boolean break case catch class const constructor continue declare default delete do else enum export extends false finally for from function get if implements import in infer instanceof interface is keyof let namespace never new null number of private protected public readonly return set static string super switch symbol this throw true try type typeof undefined union unknown var void while yield",
    java: "abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null",
    go: "break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var nil true false",
    rust: "as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while",
    php: "abstract and array as break callable case catch class clone const continue declare default do echo else elseif empty enddeclare endfor endforeach endif endswitch endwhile extends final finally fn for foreach function global goto if implements include include_once instanceof insteadof interface isset list namespace new or print private protected public require require_once return static switch throw trait try unset use var while xor yield true false null",
    ruby: "alias and begin break case class def defined? do else elsif end ensure false for if in module next nil not or redo rescue retry return self super then true undef unless until when while yield",
    css: "important media keyframes import supports charset font-face",
    sql: "SELECT FROM WHERE INSERT INTO UPDATE DELETE JOIN LEFT RIGHT INNER OUTER ON GROUP BY ORDER HAVING LIMIT OFFSET UNION ALL AS AND OR NOT NULL IS IN EXISTS CREATE TABLE ALTER DROP INDEX VALUES SET DISTINCT COUNT SUM AVG MIN MAX",
    shell: "if then else elif fi for while do done case esac function return export local readonly declare source alias unset echo cd exit test",
    yaml: "true false null yes no on off",
    json: "true false null",
  };
  KEYWORDS.jsx = KEYWORDS.javascript;
  KEYWORDS.tsx = KEYWORDS.typescript;
  KEYWORDS.bash = KEYWORDS.sh = KEYWORDS.shell;

  function keywordSet(lang) {
    return new Set((KEYWORDS[lang] || "").split(/\s+/).filter(Boolean));
  }

  /* One pass, alternation ordered so longer constructs win. */
  function rulesFor(lang) {
    const comment =
      lang === "python" || lang === "shell" || lang === "bash" || lang === "sh" ||
      lang === "yaml" || lang === "toml" || lang === "ruby"
        ? /#[^\n]*/
        : lang === "sql"
        ? /--[^\n]*/
        : /\/\/[^\n]*/;

    const block = lang === "python" ? null : /\/\*[\s\S]*?\*\//;

    const strings = [
      /"""[\s\S]*?"""/, /'''[\s\S]*?'''/,          // python docstrings
      /`(?:\\[\s\S]|[^\\`])*`/,                     // template literals
      /"(?:\\[\s\S]|[^\\"\n])*"/,
      /'(?:\\[\s\S]|[^\\'\n])*'/,
    ];

    const parts = [];
    if (block) parts.push({ cls: "c", re: block });
    parts.push({ cls: "c", re: comment });
    strings.forEach((re) => parts.push({ cls: "s", re }));
    parts.push({ cls: "n", re: /\b0[xX][0-9a-fA-F]+\b|\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/ });
    parts.push({ cls: "f", re: /\b[A-Za-z_$][\w$]*(?=\s*\()/ });
    parts.push({ cls: "w", re: /\b[A-Za-z_$][\w$]*\b/ });
    parts.push({ cls: "p", re: /[{}()[\];,.:?!<>=+\-*/%&|^~]+/ });
    return parts;
  }

  function highlightCode(code, lang) {
    lang = (lang || "text").toLowerCase();
    if (lang === "html" || lang === "xml" || lang === "svg") return highlightMarkup(code);
    if (lang === "text" || lang === "markdown" || !KEYWORDS[lang]) {
      // Still colour strings/comments for unknown types — better than nothing.
      if (!KEYWORDS[lang]) lang = "javascript";
    }

    const keywords = keywordSet(lang);
    const parts = rulesFor(lang);
    const combined = new RegExp(
      parts.map((p) => `(${p.re.source})`).join("|"),
      "g"
    );

    let out = "";
    let last = 0;
    let m;
    while ((m = combined.exec(code)) !== null) {
      if (m.index > last) out += esc(code.slice(last, m.index));
      let cls = null;
      for (let i = 0; i < parts.length; i++) {
        if (m[i + 1] !== undefined) { cls = parts[i].cls; break; }
      }
      const text = m[0];
      if (cls === "w") {
        cls = keywords.has(text) ? "k" : null;
      }
      out += cls ? `<span class="t-${cls}">${esc(text)}</span>` : esc(text);
      last = m.index + text.length;
      if (text.length === 0) combined.lastIndex++;   // never spin on empty match
    }
    out += esc(code.slice(last));
    return out;
  }

  function highlightMarkup(code) {
    let out = "";
    let last = 0;
    const re = /<!--[\s\S]*?-->|<\/?([A-Za-z][\w:-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
    let m;
    while ((m = re.exec(code)) !== null) {
      if (m.index > last) out += esc(code.slice(last, m.index));
      const whole = m[0];
      if (whole.startsWith("<!--")) {
        out += `<span class="t-c">${esc(whole)}</span>`;
      } else {
        const attrs = (m[2] || "").replace(
          /([\w:-]+)(\s*=\s*)("[^"]*"|'[^']*')/g,
          (_, name, eq, value) =>
            `<span class="t-a">${esc(name)}</span>${esc(eq)}<span class="t-s">${esc(value)}</span>`
        );
        out += `<span class="t-p">&lt;${whole.startsWith("</") ? "/" : ""}</span>` +
               `<span class="t-k">${esc(m[1])}</span>${attrs}` +
               `<span class="t-p">&gt;</span>`;
      }
      last = m.index + whole.length;
    }
    out += esc(code.slice(last));
    return out;
  }

  function guessLanguage(path) {
    const name = String(path || "").toLowerCase();
    const map = {
      ".py": "python", ".js": "javascript", ".mjs": "javascript",
      ".cjs": "javascript", ".jsx": "jsx", ".ts": "typescript", ".tsx": "tsx",
      ".json": "json", ".html": "html", ".htm": "html", ".xml": "xml",
      ".svg": "xml", ".css": "css", ".scss": "css", ".less": "css",
      ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".yml": "yaml",
      ".yaml": "yaml", ".toml": "toml", ".sql": "sql", ".php": "php",
      ".rb": "ruby", ".go": "go", ".rs": "rust", ".java": "java",
      ".md": "markdown", ".env": "shell", ".map": "json",
    };
    for (const ext in map) if (name.endsWith(ext)) return map[ext];
    if (name.endsWith("dockerfile")) return "shell";
    return "text";
  }

  /* Render a file as numbered, highlighted lines. */
  function renderFile(code, lang, { start = 1, mark = null } = {}) {
    const html = highlightCode(code, lang);
    // Split the *highlighted* html on newlines; spans never span lines because
    // every rule above is line-bounded except block comments and docstrings,
    // which we repair by re-opening the class on each line.
    const lines = html.split("\n");
    let open = null;
    return lines
      .map((line, i) => {
        const n = start + i;
        let body = line;
        if (open) body = `<span class="${open}">` + body;
        const opens = [...line.matchAll(/<span class="(t-[a-z])">/g)];
        const closes = (line.match(/<\/span>/g) || []).length;
        if (opens.length > closes) {
          open = opens[opens.length - 1][1];
          body += "</span>";
        } else if (opens.length === closes) {
          open = null;
        }
        const isMark = mark && n >= mark[0] && n <= mark[1];
        return `<div class="cl${isMark ? " hit" : ""}" data-line="${n}">` +
               `<span class="cn">${n}</span><span class="ct">${body || " "}</span></div>`;
      })
      .join("");
  }

  global.hl = { highlightCode, renderFile, guessLanguage, esc };
})(window);
