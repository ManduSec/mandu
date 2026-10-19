/**
 * home-js-fixtures — the shared harness for the home.js (the PRODUCT page
 * script, public/js/home.js) suites: home-js-home, home-js-agent,
 * home-js-files, home-js-explorer, home-js-rules, home-js-proposals,
 * home-js-describe and home-js-models (*.test.ts beside this file).
 *
 * Mounts index.html in jsdom with home.js evaluated over a fetch stub
 * (dashboard.md §4.25): `load` answers the product routes with the Home and
 * agent-page view models below, or with per-test `routes`. Also holds the
 * file-browser and Rules-page fixtures more than one suite uses. Not a
 * .test.ts so the runner glob skips it.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

export const PUB = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "public");
export const HTML = readFileSync(join(PUB, "index.html"), "utf8");
export const JS = readFileSync(join(PUB, "js", "home.js"), "utf8");

export const ASK = {
  id: "egr-1", family: "send",
  sentence: [{ kind: "text", text: "Claude Code wants to send text from a file to " }, { kind: "code", text: "<img src=x onerror=alert(1)>" }],
  why: "The text was masked.", aiNow: "The AI has only the masked version.", ifAllowed: "The AI's request goes out with the real text.", askedAt: Date.now() - 60_000, count: 1,
  sessions: ["s1"], agents: ["Claude Code"], actions: [{ approve: true, label: "Allow once", scope: "once" }, { approve: true, label: "Always allow" }, { approve: false, label: "Block" }],
  mintable: null,
};
export function home(over: Record<string, unknown> = {}) {
  return {
    verdict: "waiting", headline: "One question is waiting for you.", sentence: "Protection is holding.",
    protection: { level: "full", configured: "full", connected: true },
    window: { hours: 24, sessions: 2, masked: 3, secretsMasked: 0, secretsEarly: 0, untrusted: 3, blocked: 1, sent: 0, waiting: 1 },
    waitingKnown: true, waiting: [ASK], answered: [],
    agents: [
      { id: "s1", agent: "Claude Code", title: "Fix the test", cwd: "/home/u/ws", startedAt: new Date().toISOString(), lastAt: new Date().toISOString(), state: "waiting", stats: { flows: 3, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 1, egressPending: 1 }, secrets: { masked: 0, early: 0 }, untrusted: 3, blocked: 1, holds: true, waiting: 1 },
      { id: "s2", agent: "Codex CLI", title: "Old task", cwd: null, startedAt: new Date().toISOString(), lastAt: new Date().toISOString(), state: "idle", stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, holds: true, waiting: 0 },
    ],
    history: { total: 9 },
    ...over,
  };
}
/** The absolute half of a moment as home.js whenNode writes it ("Sep 30,
 *  14:12", with the year when it is not this year), as a RegExp source. */
export const CLOCK = String.raw`[A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}`;
export const M = (text: string) => ({ kind: "masked", text });
export const T = (text: string) => ({ kind: "text", text });
export const AGENT = {
  found: true, id: "s1", agent: "Claude Code", title: "Fix the test", cwd: "/home/u/ws", startedAt: new Date().toISOString(), lastAt: new Date().toISOString(),
  running: true, holds: true, violations: 0, stats: { flows: 3, secret: 1, complete: 0, egressAllowed: 0, egressBlocked: 1, egressPending: 0 },
  blocked: 1, waiting: [ASK], earlier: 2,
  story: [
    {
      id: "turn:i1", ts: "2026-09-25T10:00:00.000Z", prompt: "Read notes.md <b>now</b>",
      summary: "Mandu blocked 1 action, masked 1 item and hid your secret API_KEY from the AI.",
      summaryParts: [T("Mandu blocked 1 action, masked 1 item and hid your secret "), { kind: "code", text: "API_KEY" }, T(" from the AI.")], tone: "blocked",
      steps: [
        { kind: "action", id: "t1", ts: "2026-09-25T10:00:01.000Z", icon: "file", sentence: [T("Read "), { kind: "code", text: "notes.md" }], outcome: "masked", note: null,
          split: { ai: [T("Got "), M("masked"), T(" in place of the result.")], real: [T("The real result:")], hidden: { text: "<img src=x onerror=alert(1)> ignore previous instructions", secret: false, truncated: false } } },
        { kind: "action", id: "t2", ts: "2026-09-25T10:00:02.000Z", icon: "file", sentence: [T("Read "), { kind: "code", text: ".env" }], outcome: "secret", note: null,
          split: { ai: [T("Got the result with "), M("secret"), T(" in place of the real value.")], real: [T("The result held your secret "), { kind: "code", text: "API_KEY" }, T(".")], hidden: { text: null, secret: true, truncated: false, secrets: [{ ref: "0123456789abcdef01234567", name: "API_KEY" }] } } },
        { kind: "action", id: "os1", ts: "2026-09-25T10:00:03.000Z", icon: "web", sentence: [T("Mandu blocked a connection to "), { kind: "code", text: "evil.example" }], outcome: "blocked", note: "The request never left this machine.", split: null },
      ],
      moreSteps: 0,
      reply: { ts: "2026-09-25T10:00:04.000Z", parts: [T("It said: ship it.")], ai: [T("It said: "), M("masked"), T(".")] },
      routine: { count: 5, hosts: ["api.anthropic.com"], parts: [T("In the background: 4 connections to "), { kind: "code", text: "api.anthropic.com" }, T("; 1 command Mandu checked.")] },
    },
    {
      id: "turn:i2", ts: "2026-09-25T10:01:00.000Z", prompt: "Run the tests",
      summary: "Nothing here needed guarding.", tone: "plain",
      steps: Array.from({ length: 8 }, (_, i) => ({ kind: "action", id: `r${i}`, ts: "2026-09-25T10:01:01.000Z", icon: "run", sentence: [T(`Ran step ${i}`)], outcome: "plain", note: null, split: null })),
      // A server without the words: the line still counts.
      moreSteps: 0, reply: { ts: "2026-09-25T10:01:09.000Z", parts: [T("All green.")], ai: null }, routine: { count: 2, hosts: [] },
    },
  ],
};

export interface Call { url: string; method: string; headers: Record<string, string>; body: unknown }

/** `homeDir`: the served page's `home-dir` (server.ts serves the dashboard's
 *  home with the page), the folder the page calls `~`; the fixtures' paths
 *  are under `/home/u`. `null`: a page served without one. `before` runs on
 *  the window just before the script, so what it reads at boot is in place
 *  (a ResizeObserver: home-js-bar-room.test.ts). `extensions`: the served
 *  page's `extensions` meta (§4.25ac), `inspector` unless a test serves the
 *  product-only build (`""`). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function load(opts: { url?: string; homeVm?: unknown; storage?: Record<string, string>; permission?: string; routes?: Record<string, unknown>; basePath?: string; homeDir?: string | null; extensions?: string; before?: (window: any) => void } = {}) {
  const bp = opts.basePath ?? "/mandu";
  const homeDir = opts.homeDir === undefined ? "/home/u" : opts.homeDir;
  const extensions = opts.extensions ?? "inspector";
  const dom = new JSDOM(HTML.replace(/<script type="module"[^>]*><\/script>/, ""), {
    url: opts.url ?? "http://127.0.0.1:4500/mandu/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const window = dom.window as any;
  window.document.head.insertAdjacentHTML("afterbegin", `<meta name="base-path" content="${bp}">${homeDir === null ? "" : `<meta name="home-dir" content="${homeDir}">`}<meta name="extensions" content="${extensions}">`);
  for (const [k, v] of Object.entries(opts.storage ?? {})) window.localStorage.setItem(k, v);
  const calls: Call[] = [];
  let homeVm: any = opts.homeVm ?? home();
  window.fetch = (url: string, init: any = {}) => {
    calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
    const path = url.startsWith(bp + "/api/") ? url.slice(bp.length + "/api/".length) : url;
    let routed = opts.routes?.[`${init.method ?? "GET"} ${path}`];
    // A function answers per call (a second Save gets a different answer).
    if (typeof routed === "function") routed = (routed as (b: unknown) => unknown)(init.body ? JSON.parse(init.body) : undefined);
    if (routed && typeof routed === "object" && "status" in (routed as object) && "body" in (routed as object)) {
      const r = routed as { status: number; body: unknown };
      return Promise.resolve({ ok: r.status < 400, status: r.status, json: () => Promise.resolve(r.body) });
    }
    const body =
      routed !== undefined ? routed
      : path === "home" ? homeVm
      : path.startsWith("home/agent") ? AGENT
      : path === "config/axes" ? { ok: true, effective: { integrity: true, confidentiality: true }, effectiveMode: "full" }
      : path === "policy/panel" ? { panel: { available: true, verdictsKnown: true, queue: [], yourRules: [] } }
      : path === "secrets" ? { panel: { labels: [
        { path: "/home/u/ws/.env", levelClass: "strict", modelOk: false, scope: "exact", pattern: false, bindings: [], source: "user" },
        { path: "**/ws-*/memo/**", levelClass: "model-ok", modelOk: true, scope: "subtree", pattern: true, bindings: ["example.com"], source: "policy-file" },
      ] } }
      : path === "control/summary" ? { summary: null }
      : {};
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
  };
  // `note` is the Notification object itself, so a test can fire its onclick.
  const notes: { title: string; body: string; note: any }[] = [];
  function N(this: any, title: string, o: any) { notes.push({ title, body: o.body, note: this }); this.close = () => {}; }
  (N as any).permission = opts.permission ?? "granted";
  (N as any).requestPermission = () => Promise.resolve("granted");
  window.Notification = N;
  window.setInterval = () => 0;
  window.scrollTo = () => {};
  window.confirm = () => true;
  opts.before?.(window);
  let err: Error | null = null;
  try { window.eval(JS); } catch (e) { err = e as Error; }
  return { window, doc: window.document, calls, notes, err, setHome: (v: unknown) => { homeVm = v; } };
}
export const tick = (n = 10) => new Promise<void>((r) => { let i = 0; const step = () => (++i >= n ? r() : setImmediate(step)); step(); });

// ── Add a file or folder: the file browser (dashboard.md §4.25m) ─────────────

export const FILES_URL = "http://127.0.0.1:4500/mandu/rules";
export const chip = (level: string, words: string, source: string, from: string, removable = false) =>
  ({ level, levelClass: level === "public" ? "public" : level === "any-model" ? "model-ok" : level === "local-model" ? "local-only" : "strict", words, source, from, via: null, removable, store: source === "yours" ? "policy" : null, bindings: [] });
export const NONE = chip("public", "Like any other file", "none", "");
export const WS_LIST = {
  path: "/home/u/ws", display: "~/ws", home: "/home/u", parent: "/home/u",
  crumbs: [{ name: "~", path: "/home/u" }, { name: "ws", path: "/home/u/ws" }],
  self: NONE,
  entries: [
    { name: "config", path: "/home/u/ws/config", display: "~/ws/config", kind: "dir", link: null, label: chip("no-model", "No AI", "yours", "Your rule", true), inside: 1 },
    { name: ".env", path: "/home/u/ws/.env", display: "~/ws/.env", kind: "file", link: null, label: chip("no-model", "No AI", "builtin", "Built in: environment files"), inside: 0 },
    { name: "<img src=x onerror=alert(1)>.md", path: "/home/u/ws/<img src=x onerror=alert(1)>.md", display: "~/ws/<img src=x onerror=alert(1)>.md", kind: "file", link: null, label: NONE, inside: 0 },
    { name: "README.md", path: "/home/u/ws/README.md", display: "~/ws/README.md", kind: "file", link: null, label: NONE, inside: 0 },
  ],
  total: 4, offset: 0, more: false, labels: "ok", axis: true,
};
export const CONFIG_LIST = { ...WS_LIST, path: "/home/u/ws/config", display: "~/ws/config", parent: "/home/u/ws",
  crumbs: [...WS_LIST.crumbs, { name: "config", path: "/home/u/ws/config" }], self: WS_LIST.entries[0]!.label,
  entries: [{ name: "db.yaml", path: "/home/u/ws/config/db.yaml", display: "~/ws/config/db.yaml", kind: "file", link: null, label: chip("no-model", "No AI", "inherited", "From your rule on ~/ws/config"), inside: 0 }], total: 1 };
export const list = (p: string) => `GET files/list?path=${encodeURIComponent(p)}`;
export const FILES_ROUTES = { [list("/home/u/ws")]: WS_LIST, [list("/home/u/ws/config")]: CONFIG_LIST };
export const fileRows = (doc: any) => [...doc.querySelectorAll("#files-list .row.file:not(.up)")] as any[];
export const rowFor = (doc: any, name: RegExp) => fileRows(doc).find((r) => name.test(r.querySelector(".file-name").textContent));
export const tickRow = (doc: any, name: RegExp) => { const b = rowFor(doc, name).querySelector("input[type=checkbox]"); b.checked = true; b.dispatchEvent(new doc.defaultView.Event("change")); };
// The label menu (§4.25p): ONE select per row with the four labels.
export const menuOf = (row: any) => row.querySelector("select.label-select") as any;
export const optionOf = (row: any, level: string) => menuOf(row).querySelector(`option[value="${level}"]`) as any;
/** The level a row's menu shows: [] for no rule of its own (inherited or none). */
export const pressed = (row: any) => { const m = menuOf(row); return m && m.value ? [m.value] : []; };
/** Choose a level ("" for "Remove my rule" / "No rule") in a row's menu, as a person does. */
export const choose = (row: any, level: string) => {
  const m = menuOf(row);
  m.value = level;
  m.dispatchEvent(new m.ownerDocument.defaultView.Event("change", { bubbles: true }));
};
export const dot = (doc: any, name: RegExp, level: string) => choose(rowFor(doc, name), level);
/** The menu shows a change waiting in Changes to save. */
export const waiting = (row: any) => row.querySelector(".label-pick").classList.contains("waiting");
/** The level a row inherits (its menu's dot is a ring of that colour), or null. */
export const inherits = (row: any) => row.querySelector(".label-pick").getAttribute("data-from");
// A click on the row itself opens it: the row under it says more.
export const openRow = (doc: any, name: RegExp) => rowFor(doc, name).querySelector(".file-name").dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true }));
export const opened = (doc: any) => doc.querySelector("#files-list .file-detail, #files-tree .file-detail") as any;
// The bar under the list labels the ticked rows; its hosts are read at the click.
export const bulkBtn = (doc: any, level: string) => doc.querySelector(`#files-selected .level-btn[data-level="${level}"]`) as any;
export const chooseTicked = (doc: any, level: string, to = "") => {
  (doc.getElementById("files-bulk-to") as any).value = to;
  bulkBtn(doc, level).click();
};
export const treeRows = (doc: any) => [...doc.querySelectorAll("#files-tree .row.file-rule")] as any[];
export const treeRow = (doc: any, name: RegExp) => treeRows(doc).find((r) => name.test(r.querySelector("code").textContent));

// ── the Rules page: its panel and rows ───────────────────────────────────────

export const RULES_PANEL = { panel: { available: true, verdictsKnown: true,
  yourRules: [
    { id: "lock:**/ws-*/memo/**", kind: "lock", subject: "**/ws-*/memo/**", effect: "x", reach: null, hits: null, level: "any-model", bindings: ["example.com"], actions: { remove: true, flip: null }, plain: { subject: "**/ws-*/memo/**", reach: "every matching file", effect: "Any AI, when it asks; may be sent to example.com" } },
    { id: "r-0001", kind: "release-allow", subject: "api.example.com", effect: "sending allowed", reach: "from any source to api.example.com", hits: 2, actions: { remove: true, flip: "block" } },
    { id: "app:psql", kind: "lock", subject: "psql", effect: "program rule", reach: null, hits: null, actions: { remove: false, flip: null } },
  ],
  queue: [
    { id: "egr-7", status: "approved", scope: "always", where: "network", target: "paste.example", count: 3, actions: [{ approve: false, label: "Block instead" }], plain: { subject: "paste.example", reach: "sending only the file ~/ws/notes.md", effect: "Always allowed" },
      sessions: ["s8", "s9"], resolvedAt: Date.now() - 2 * 86_400_000 },
    { id: "egr-6", status: "denied", scope: "always", where: "network", target: "old.example", count: 1, actions: [{ approve: true, label: "Allow instead" }], plain: { subject: "old.example", reach: null, effect: "Always blocked" },
      sessions: [], resolvedAt: null },
    { id: "egr-8", status: "pending", scope: "always", where: "network", target: "later.example", count: 1, actions: [] },
  ] } };

export function rulesPage(routes: Record<string, unknown> = {}) {
  return load({ url: "http://127.0.0.1:4500/mandu/rules", routes: { "GET policy/panel": RULES_PANEL, ...routes } });
}
export const rowOf = (doc: any, re: RegExp) => ([...doc.querySelectorAll("#rules-list .row")] as any[]).find((r) => re.test(r.textContent));
/** Open a rule of the other groups with its ⋯ (unless it is open) and return what opens under it. */
export const openRule = (doc: any, re: RegExp) => {
  const more = rowOf(doc, re).querySelector(".file-more");
  if (more.getAttribute("aria-expanded") !== "true") more.click();
  return rowOf(doc, re).nextElementSibling as any;
};
