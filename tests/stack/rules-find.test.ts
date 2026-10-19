/**
 * rules-find e2e — Rules › Your rules' *Find a rule* box (dashboard.md
 * §4.25f *Find a rule*) through the PRODUCTION wiring:
 * `makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }))` over a
 * REAL ArbiterServer with a file-backed policy of 27 rules (20 files, 4 send
 * rules, 3 connections), and a real DashboardServer serving the product page.
 *
 * The box narrows what the page drew, so what it must prove over real data
 * is that the rows it keeps are the ones that name the text:
 *
 *   1. typing a host keeps exactly its send rule and the file rules that may
 *      be sent there; typing a program, exactly the files it may open; a port,
 *      exactly its connection; the count says "N of 27";
 *   2. typing reads nothing (no request leaves the page for it);
 *   3. in a real headless Chromium at 1280 px and 390 px: the box and the
 *      count fit the card without overflow, the box beside the heading on a
 *      wide screen and under it on a phone;
 *   4. the served page and every answer carry no secret value (the stack
 *      suites' oracle; the box adds no read).
 *
 * The Chromium half self-SKIPs without a Chromium (probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell); the first
 * half runs everywhere, in jsdom over the served page.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const browser = tour.probeBrowser({});

const SECRET = `sk_live_rulesFindCanary_${process.pid}_000000`;
const TOTAL = 27;

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** The served stack, once for both tests. */
let stack: { base: string; home: string } | null = null;
async function start() {
  if (stack) return stack;
  const dir = mkdtempSync(join(tmpdir(), "mandu-rules-find-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, ".env"), `GITHUB_TOKEN=${SECRET}\n`);
  writeFileSync(join(proj, "deploy.token"), `${SECRET}\n`);
  // 20 file rules: two that may go to api.github.com, one docker-compose may
  // open, and 17 more in three folders.
  const paths = [
    `  - { path: "${join(proj, ".env")}", level: no-model, recursive: false, bindings: [api.github.com], readers: [{ app: docker-compose, prints: nothing }] }`,
    `  - { path: "${join(proj, "deploy.token")}", level: no-model, recursive: false, bindings: [api.github.com] }`,
    `  - { path: "${join(proj, "stripe.key")}", level: no-model, recursive: false, bindings: [api.stripe.com] }`,
    ...Array.from({ length: 6 }, (_, i) => `  - { path: "${join(home, "notes", `note-${i}.md`)}", level: any-model, recursive: false }`),
    ...Array.from({ length: 6 }, (_, i) => `  - { path: "${join(home, "contracts", `contract-${i}.pdf`)}", level: local-model, recursive: false }`),
    ...Array.from({ length: 5 }, (_, i) => `  - { path: "${join(home, "keys", `key-${i}.pem`)}", level: no-model, recursive: false }`),
  ];
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    ...paths,
    "user_rules:",
    "  - { id: r-0001, kind: release, to: { host: api.github.com }, mode: allow }",
    "  - { id: r-0002, kind: release, to: { host: api.stripe.com }, mode: allow }",
    "  - { id: r-0003, kind: release, to: { host: paste.example }, mode: block }",
    "  - { id: r-0004, kind: release, to: { host: uploads.example }, mode: block }",
    "destinations:",
    "  - { host: registry.example, connect: allow }",
    "  - { host: git.example, port: 2222, connect: allow }",
    "  - { host: pypi.org, connect: allow }",
    "",
  ].join("\n"));
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  // The key is registered: a page or an answer carrying it is a leak.
  await gate.registerSecret({ path: join(proj, ".env"), sessionKey: "rules-find" });
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production wiring connects");
  const server = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  closers.push(async () => { await server.close(); wired.close(); gate.close(); await arbiter.close(); });
  stack = { base, home };
  return stack;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
/** The rows drawn, in the words a person reads: a file row by its full
 *  path (its tooltip), any other by what it covers. Folded or hidden ones
 *  are left out. */
function drawn(doc: Doc): string[] {
  const files = ([...doc.querySelectorAll("#files-tree .row.file-rule")] as Doc[])
    .filter((r) => !r.closest("[hidden]") && r.getAttribute("data-find") !== "context")
    .map((r) => `file ${r.getAttribute("title")}`);
  const rest = ([...doc.querySelectorAll("#rules-list .row.rule")] as Doc[])
    .filter((r) => !r.closest("[hidden]"))
    .map((r) => `rule ${r.querySelector(".rule-text").firstChild.textContent}`);
  return [...files, ...rest].sort();
}

test("Find a rule over the real arbiter: a host keeps its send rule and the files that may go there, a program the files it opens, a port its connection; no read for it, no value", { timeout: 120_000 }, async () => {
  const { base, home } = await start();
  const panel = await pageFetch(`${base}/api/policy/panel`, { headers: CSRF_ADMIN });
  assert.equal(panel.status, 200);
  const raw = await panel.text();
  assert.ok(!raw.includes(SECRET), "CONFIDENTIALITY VIOLATION: the rules answer carries the value");
  assert.equal((JSON.parse(raw) as Doc).panel.yourRules.length, TOTAL, "27 rules of yours");

  await servedProductPage(base, "/rules", (doc: Doc) => doc.getElementById("rules-count").textContent === String(TOTAL), async (doc: Doc) => {
    const box = doc.getElementById("rules-find");
    const w = doc.defaultView;
    const type = async (text: string) => {
      box.focus();
      box.value = text;
      box.dispatchEvent(new w.Event("input", { bubbles: true }));
      await new Promise((r) => setTimeout(r, 0));
    };
    // Every request the page makes from here on.
    const asked: string[] = [];
    const fetch0 = w.fetch;
    w.fetch = (url: string, init?: unknown) => { asked.push(String(url)); return fetch0(url, init); };

    await type("api.github.com");
    assert.deepEqual(drawn(doc), [
      `file ${join(home, "proj", ".env")}`,
      `file ${join(home, "proj", "deploy.token")}`,
      "rule api.github.com",
    ], "the send rule and the two files that may go there, nothing else");
    assert.equal(doc.getElementById("rules-count").textContent, `3 of ${TOTAL}`);
    assert.equal(doc.activeElement, box, "the focus stays in the box");

    await type("docker-compose");
    assert.deepEqual(drawn(doc), [`file ${join(home, "proj", ".env")}`], "the one file docker-compose may open");
    assert.equal(doc.getElementById("rules-list").hidden, true, "no other group");

    await type("2222");
    assert.deepEqual(drawn(doc), ["rule git.example:2222"], "the connection on that port");
    assert.equal(doc.getElementById("files-group").hidden, true, "Files and folders: no match, not drawn");

    await type("contract-");
    assert.equal(drawn(doc).length, 6);
    assert.equal(doc.getElementById("rules-count").textContent, `6 of ${TOTAL}`);

    await type("stripe-live");
    assert.deepEqual(drawn(doc), []);
    assert.match(doc.getElementById("rules-find-none").textContent, /^No rule mentions “stripe-live”\. Clear$/);

    await type("");
    assert.equal(drawn(doc).length, TOTAL, "an empty box draws every rule");
    assert.deepEqual(asked, [], "typing read nothing");
    assert.ok(!doc.body.textContent.includes(SECRET), "CONFIDENTIALITY VIOLATION: the Rules page shows the value");
  }, { headers: { Cookie: ADMIN_COOKIE } });
});

test("in a real Chromium: the box and the count fit Your rules at 1280 px and at 390 px, beside the heading and under it, and the page shows no value", {
  skip: browser ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-find-cdp-"));
  dirs.push(tmp);
  const { proc, wsUrl } = await tour.startBrowser(browser as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    for (const width of [1280, 390]) {
      const where = `${width}px`;
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
      await send("Page.navigate", { url: base + "/rules" });
      await until(`${where}: Your rules drawn`, `document.getElementById("rules-count")?.textContent === "${TOTAL}"`);
      // Typed as a person types: the box takes the keys.
      await evaluate(`document.getElementById("rules-find").focus(), true`);
      await send("Input.insertText", { text: "api.github.com" });
      await until(`${where}: narrowed`, `document.getElementById("rules-count").textContent === "3 of ${TOTAL}"`);
      const m = await evaluate(`(() => {
        const r = (x) => { const b = x.getBoundingClientRect(); return { left: b.left, right: b.right, top: b.top, bottom: b.bottom, width: b.width }; };
        const card = document.getElementById("rules-block");
        return {
          card: r(card), box: r(document.getElementById("rules-find")), count: r(document.getElementById("rules-count")),
          title: r(document.getElementById("rules-title")), add: r(document.getElementById("rules-add")),
          page: document.documentElement.scrollWidth, view: document.documentElement.clientWidth,
          focused: document.activeElement && document.activeElement.id, text: document.body.innerText,
        };
      })()`);
      assert.ok(m.page <= m.view, `${where}: the page does not scroll sideways (${m.page} > ${m.view})`);
      for (const [name, b] of [["the box", m.box], ["the count", m.count], ["Add a rule", m.add]] as const) {
        assert.ok(b.width > 0, `${where}: ${name} is drawn`);
        assert.ok(b.left >= m.card.left && b.right <= m.card.right + 0.5, `${where}: ${name} fits the card (${b.left}–${b.right} in ${m.card.left}–${m.card.right})`);
      }
      assert.ok(m.box.width >= 160, `${where}: the box is wide enough to type in (${m.box.width})`);
      if (width === 1280) assert.ok(m.box.top < m.title.bottom, `${where}: beside the heading`);
      else assert.ok(m.box.top >= m.title.bottom - 1, `${where}: under the heading`);
      assert.equal(m.focused, "rules-find", `${where}: the focus stays in the box`);
      assert.ok(!m.text.includes(SECRET), `CONFIDENTIALITY VIOLATION: the Rules page at ${where} shows the value`);
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
