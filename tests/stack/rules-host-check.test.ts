/**
 * rules-host-check e2e — Rules › Who may get your secrets › Check a host
 * (dashboard.md §4.25aa *Check a host*) through the PRODUCTION wiring:
 * `makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }))` over a
 * REAL ArbiterServer with a file-backed law (no test bridge, AGENTS.md's
 * parity rule), and a real DashboardServer serving
 * `GET /api/policy/host-check`.
 *
 *   T1  `api.stripe.com` names the labelled `~/app/.env` bound there, and a
 *       secret bound nowhere is held for your OK, which the egress gate
 *       itself agrees with for a real unbound key; an earlier answer is
 *       counted; `pastebin.com` names none, with the same decision; the
 *       JSON never carries the file's value nor a `$MDU:` placeholder; and
 *       the check queues nothing in Approvals (a probe).
 *   T2  the served page (jsdom with the page's CSS at 1280 and 390 px): the
 *       box sends the typed host and draws the answer, its file a button.
 *   T3  a real headless Chromium at 1280 and 390 px: the answer is drawn
 *       inside the screen, with no sideways scroll and no value. Self-SKIPs
 *       without a Chromium (probeBrowser).
 *   T4  a send the real egress gate holds for your answer: the check of its
 *       host says one send waits in Approvals, a link with no search;
 *       answered, the line is gone and the answer is counted instead.
 *   T5  the served page asks again at each Rules read (queue item #218):
 *       checked while the real gate holds a send, the box says it waits;
 *       answered, Approvals and back to Rules by the page's own links, the
 *       box says it was answered, with no Check press; no value, no
 *       placeholder.
 *   T6  the served page follows the questions waiting (queue item #269):
 *       checked with nothing waiting, a send the real gate then holds
 *       shows its waiting line at the next poll, with no Check press, by
 *       one read of Rules and one ask per poll (since queue item #284 that
 *       read redraws the file rows' "Waiting for your answer" line too);
 *       answered Allow once in a second served page (another tab), the
 *       line goes from the first at its next poll; no value, no
 *       placeholder.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
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
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const chromium = tour.probeBrowser({});

const VALUE = `sk_live_hostCheckCanary_${process.pid}_9Qz`;
const OTHER = `other-secret-${process.pid}-never-shown`;

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

let stack: {
  base: string; home: string; envPath: string; gate: ArbiterClient; token: string;
  answer: (id: string, approve: boolean, scope: "once" | "always") => Promise<unknown>;
  /** Another dashboard over the same arbiter, signed in (ADMIN_OPTS): its
   *  page answers a question itself (T6). */
  signedIn: () => Promise<string>;
} | null = null;
async function start() {
  if (stack) return stack;
  const dir = mkdtempSync(join(tmpdir(), "mandu-host-check-"));
  dirs.push(dir);
  const home = join(dir, "home");
  mkdirSync(join(home, "app"), { recursive: true });
  mkdirSync(join(home, "svc"), { recursive: true });
  const envPath = join(home, "app", ".env");
  const otherPath = join(home, "svc", ".env");
  writeFileSync(envPath, `STRIPE_KEY=${VALUE}\n`);
  writeFileSync(otherPath, `TOKEN=${OTHER}\n`);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  // The human socket: Home's answer (the questions waiting, T6) reads it.
  const humanPath = humanSockIn(dir);
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - { path: "${envPath}", level: no-model, recursive: false, bindings: [api.stripe.com] }`,
    "",
  ].join("\n"));
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanPath, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets?.whyHost, "the production wiring forwards whyHost");
  const dashboard = (extra: object = {}) => new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter,
    secretsArbiter: wired.secrets,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    log: () => {},
    ...extra,
  });
  const server = dashboard();
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  closers.push(async () => { await server.close(); wired.close(); gate.close(); await arbiter.close(); });
  const signedIn = async () => {
    const other = dashboard(ADMIN_OPTS);
    const port = await other.listen(0);
    closers.push(() => other.close());
    return `http://127.0.0.1:${port}`;
  };

  // Both files registered, as a launch does: ~/app/.env bound to Stripe's
  // API, ~/svc/.env bound nowhere. A send of the unbound key to
  // api.stripe.com is held, and answered Block: an earlier answer there.
  await gate.registerSecret({ path: envPath, sessionKey: "host-check" });
  const reg = await gate.registerSecret({ path: otherPath, sessionKey: "host-check" });
  const token = /\$MDU:[a-z]+_Read\[[0-9a-f]+\]\.TOKEN/.exec(reg.twin ?? "")?.[0];
  assert.ok(token, `the unbound key has its own placeholder: ${reg.twin}`);
  const held = await gate.desymbolizationDecision({ symbol: token!, boundary: "network", destination: "api.stripe.com", sessionKey: "host-check", scheme: "https" });
  assert.equal(held.allow, false);
  assert.equal("requiresApproval" in held && held.requiresApproval, true, "the egress gate holds an unbound key for your OK");
  const id = "approvalId" in held ? held.approvalId : undefined;
  assert.ok(id, "held in Approvals");
  await wired.arbiter.resolveEgressApproval(id!, false, "always");
  stack = { base, home, envPath, gate, token: token!, answer: (i, approve, scope) => wired.arbiter.resolveEgressApproval(i, approve, scope), signedIn };
  return stack;
}

async function hostCheck(base: string, host: string) {
  const r = await pageFetch(`${base}/api/policy/host-check?host=${encodeURIComponent(host)}`);
  const raw = await r.text();
  assert.ok(!raw.includes(VALUE) && !raw.includes(OTHER), `CONFIDENTIALITY VIOLATION: a value in the answer for ${host}`);
  assert.ok(!raw.includes("$MDU:"), `a placeholder in the answer for ${host}: ${raw}`);
  return { status: r.status, body: JSON.parse(raw) as any };
}

test("T1: over the real arbiter: a bound host names its file, an unbound secret is held for your OK, pastebin.com names none; no value, no placeholder, nothing queued", { timeout: 120_000 }, async () => {
  const { base, gate } = await start();
  const pendingBefore = (await gate.egressApprovals("pending")).length;

  const stripe = await hostCheck(base, "https://API.stripe.com/v1/charges");
  assert.equal(stripe.status, 200);
  assert.equal(stripe.body.check.host, "api.stripe.com");
  const lines = stripe.body.check.lines.map((l: any) => l.text);
  assert.equal(lines[0], "1 of your secrets may be sent there: ~/app/.env.");
  assert.equal(lines[1], "Any other secret sent there: Mandu asks you first.");
  assert.ok(lines.includes("This is Stripe's API host: a Stripe key goes here without asking."), lines.join(" | "));
  assert.ok(lines.includes("You answered 1 earlier send to this host. Find them in Approvals."), lines.join(" | "));
  const bound = stripe.body.check.lines[0];
  assert.deepEqual(bound.files, [{ name: "~/app/.env", rule: stack!.envPath }]);

  const paste = await hostCheck(base, "pastebin.com");
  assert.equal(paste.status, 200);
  assert.deepEqual(paste.body.check.lines.map((l: any) => l.text), [
    "None of your secrets may be sent there.",
    "Any other secret sent there: Mandu asks you first.",
  ]);

  const refused = await pageFetch(`${base}/api/policy/host-check?host=${encodeURIComponent("not a host")}`);
  assert.equal(refused.status, 400);

  const pendingAfter = (await gate.egressApprovals("pending")).length;
  assert.equal(pendingAfter, pendingBefore, "a check queues nothing in Approvals");
});

const sheetsOf = async (base: string) =>
  `${await (await pageFetch(`${base}/mandu.css`)).text()}\n${await (await pageFetch(`${base}/app.css`)).text()}`;

test("T2: the served page at 1280 and 390 px: the box sends the typed host and draws the answer, its file a button", { timeout: 120_000 }, async () => {
  const { base } = await start();
  const sheets = await sheetsOf(base);
  for (const width of [1280, 390]) {
    const where = `the Rules page at ${width}px`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/rules", (doc: any) => !doc.getElementById("by-who-block").hidden && !!doc.querySelector("#files-tree .row.file-rule"), async (doc: any) => {
      const form = doc.getElementById("host-check");
      assert.equal(form.hidden, false, `${where}: the box shows`);
      const box = doc.getElementById("host-check-q");
      box.value = "api.stripe.com";
      box.focus();
      form.requestSubmit();
      await waitWhile(() => !doc.querySelector("#host-check-answer li"));
      const lines = [...doc.querySelectorAll("#host-check-answer li")].map((li: any) => li.textContent);
      assert.equal(lines[0], "1 of your secrets may be sent there: ~/app/.env.", where);
      assert.equal(lines[1], "Any other secret sent there: Mandu asks you first.", where);
      const button = doc.querySelector('#host-check-answer li[data-kind="bound"] button.by-who-link');
      assert.ok(button, `${where}: the file opens its rule`);
      assert.equal(doc.activeElement, box, `${where}: the focus stays in the box`);
      assert.ok(!doc.body.textContent.includes(VALUE) && !doc.body.textContent.includes(OTHER), `CONFIDENTIALITY VIOLATION: ${where} shows a value`);
      assert.ok(!doc.getElementById("host-check-answer").textContent.includes("$MDU:"), `${where}: no placeholder`);
    }, { css: resolveCssVars(stylesAt(sheets, width)) });
  }
});

test("T3: in a real Chromium at 1280 and 390 px: Check draws the answer inside the screen, no sideways scroll, no value", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-host-check-cdp-"));
  dirs.push(tmp);
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
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
    for (const width of [1280, 390]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
      await send("Page.navigate", { url: `${base}/rules` });
      await until(`the card drawn at ${width} px`, `(() => { const f = document.getElementById("host-check"); return !!f && !f.closest("[hidden]") && document.fonts.status === "loaded"; })()`);
      await evaluate(`(() => { const b = document.getElementById("host-check-q"); b.scrollIntoView({ block: "center" }); b.focus(); b.value = "api.stripe.com"; document.getElementById("host-check").requestSubmit(); return true; })()`);
      await until(`the answer drawn at ${width} px`, `document.querySelectorAll("#host-check-answer li").length >= 2`);
      const m = await evaluate(`(() => {
        const box = document.getElementById("host-check-q").getBoundingClientRect();
        const go = document.getElementById("host-check-go").getBoundingClientRect();
        const lis = [...document.querySelectorAll("#host-check-answer li")].map((li) => { const r = li.getBoundingClientRect(); return { left: r.left, right: r.right, h: r.height, text: li.textContent }; });
        return {
          lis, box: { left: box.left, right: box.right, top: box.top, h: box.height }, go: { left: go.left, right: go.right, top: go.top, bottom: go.bottom, h: go.height },
          view: innerWidth, page: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth,
          active: document.activeElement && document.activeElement.id, body: document.body.innerText,
        };
      })()`);
      assert.equal(m.lis[0].text, "1 of your secrets may be sent there: ~/app/.env.", `${width} px`);
      assert.equal(m.lis[1].text, "Any other secret sent there: Mandu asks you first.", `${width} px`);
      for (const li of m.lis) assert.ok(li.h > 0 && li.left >= 0 && li.right <= m.view, `a line inside the screen at ${width} px: ${JSON.stringify(li)}`);
      assert.ok(m.box.h > 0 && m.go.h > 0 && m.go.right <= m.view && m.box.left >= 0, `the box and Check inside the screen at ${width} px (${JSON.stringify([m.box, m.go])})`);
      assert.ok(m.go.top < m.box.top + m.box.h && m.go.bottom > m.box.top, `Check beside the box at ${width} px (${JSON.stringify([m.box, m.go])})`);
      assert.ok(m.page <= m.cw, `no sideways scroll at ${width} px`);
      assert.equal(m.active, "host-check-q", `the focus stays in the box at ${width} px`);
      assert.ok(!m.body.includes(VALUE) && !m.body.includes(OTHER), "CONFIDENTIALITY VIOLATION: the page shows a value");
      assert.ok(!m.body.includes("$MDU:"), "no placeholder on the page");
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});

test("T4: a send waiting for your answer is counted, linked to Approvals; answered, it moves to the answered count; no value, no placeholder", { timeout: 120_000 }, async () => {
  const { base, gate, token, answer } = await start();
  // A host of its own, so the counts are this send's alone.
  const host = "uploads.example.com";
  const before = await hostCheck(base, host);
  assert.ok(!before.body.check.lines.some((l: any) => l.kind === "waiting" || l.kind === "answered"), "nothing asked there yet");

  const held = await gate.desymbolizationDecision({ symbol: token, boundary: "network", destination: host, sessionKey: "host-check", scheme: "https" });
  assert.equal("requiresApproval" in held && held.requiresApproval, true, "the egress gate holds the send for your answer");
  const id = "approvalId" in held ? held.approvalId : undefined;
  assert.ok(id, "held in Approvals");

  const waiting = await hostCheck(base, host);
  assert.equal(waiting.status, 200);
  const line = waiting.body.check.lines.find((l: any) => l.kind === "waiting");
  assert.ok(line, `the waiting line: ${JSON.stringify(waiting.body.check.lines)}`);
  assert.equal(line.text, "1 send to this host waits for your answer in Approvals.");
  assert.deepEqual(line.parts.filter((p: any) => p.kind === "link"), [{ kind: "link", text: "Approvals", to: "approvals" }]);
  assert.ok(!waiting.body.check.lines.some((l: any) => l.kind === "answered"), "a waiting send is not an answer");

  await answer(id!, false, "once");
  const answered = await hostCheck(base, host);
  const kinds = answered.body.check.lines.map((l: any) => l.kind);
  assert.ok(!kinds.includes("waiting"), `answered: no waiting line (${kinds.join(", ")})`);
  assert.equal(answered.body.check.lines.find((l: any) => l.kind === "answered")?.text, "You answered 1 earlier send to this host. Find them in Approvals.");
});

test("T5: the served page: answered in Approvals, back to Rules, the box says what holds now without a Check press; no value, no placeholder", { timeout: 120_000 }, async () => {
  const { base, gate, token, answer } = await start();
  // A host of its own, so the counts are this send's alone.
  const host = "drop.example.com";
  const held = await gate.desymbolizationDecision({ symbol: token, boundary: "network", destination: host, sessionKey: "host-check", scheme: "https" });
  assert.equal("requiresApproval" in held && held.requiresApproval, true, "the egress gate holds the send for your answer");
  const id = "approvalId" in held ? held.approvalId : undefined;
  assert.ok(id, "held in Approvals");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await servedProductPage(base, "/rules", (doc: any) => !doc.getElementById("by-who-block").hidden, async (doc: any) => {
    const w = doc.defaultView;
    const lines = () => [...doc.querySelectorAll("#host-check-answer li")].map((li: any) => li.textContent as string);
    const box = doc.getElementById("host-check-q");
    box.value = host;
    doc.getElementById("host-check").requestSubmit();
    await waitWhile(() => !doc.querySelector('#host-check-answer li[data-kind="waiting"]'));
    assert.equal(doc.querySelector('#host-check-answer li[data-kind="waiting"]')?.textContent, "1 send to this host waits for your answer in Approvals.");

    await answer(id!, false, "once");
    doc.querySelector('#host-check-answer li[data-kind="waiting"] a').click();
    await waitWhile(() => w.location.pathname !== "/approvals");
    assert.equal(w.location.pathname, "/approvals");
    doc.querySelector('a[data-page-link="rules"]').click();
    await waitWhile(() => !lines().some((l) => l.startsWith("You answered")));
    assert.equal(w.location.pathname, "/rules");
    assert.ok(!lines().some((l) => l.includes("waits for your answer")), `no waiting line: ${lines().join(" | ")}`);
    assert.ok(lines().includes("You answered 1 earlier send to this host. Find them in Approvals."), lines().join(" | "));
    assert.equal(box.value, host);
    assert.ok(!doc.body.textContent.includes(VALUE) && !doc.body.textContent.includes(OTHER), "CONFIDENTIALITY VIOLATION: the page shows a value");
    assert.ok(!doc.getElementById("host-check-answer").textContent.includes("$MDU:"), "no placeholder in the answer");
  });
});

test("T6: the served page follows the questions waiting: a send held after the check shows its line at the next poll, and answered Allow once in another tab, it goes; no value, no placeholder", { timeout: 120_000 }, async () => {
  const { gate, token, signedIn } = await start();
  // Both tabs signed in to one dashboard, so the second answers itself.
  const base = await signedIn();
  const tab = { headers: { Cookie: ADMIN_COOKIE } };
  // A host of its own, so the counts are this send's alone.
  const host = "hold.example.com";
  // The page's reads, from its first: those still out, and (once `counting`)
  // the Rules reads and host asks.
  const reads = { out: 0, counting: false, panel: 0, asks: 0 };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const beforeScripts = (w: any) => {
    const pageReads = w.fetch; // the harness's, over pageFetch
    w.fetch = (url: string, init?: object) => {
      if (reads.counting && String(url).endsWith("/api/policy/panel")) reads.panel++;
      if (reads.counting && String(url).includes("/api/policy/host-check?")) reads.asks++;
      reads.out++;
      return pageReads(url, init).finally(() => { reads.out--; });
    };
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await servedProductPage(base, "/rules", (doc: any) => !doc.getElementById("by-who-block").hidden, async (doc: any) => {
    const w = doc.defaultView;
    const lines = () => [...doc.querySelectorAll("#host-check-answer li")].map((li: any) => li.textContent as string);
    const waits = () => lines().includes("1 send to this host waits for your answer in Approvals.");
    const poll = () => doc.dispatchEvent(new w.Event("visibilitychange"));
    const clean = (where: string) => {
      assert.ok(!doc.body.textContent.includes(VALUE) && !doc.body.textContent.includes(OTHER), `CONFIDENTIALITY VIOLATION: ${where} shows a value`);
      assert.ok(!doc.getElementById("host-check-answer").textContent.includes("$MDU:"), `${where}: no placeholder in the answer`);
    };
    const box = doc.getElementById("host-check-q");
    box.value = host;
    doc.getElementById("host-check-go").click();
    await waitWhile(() => lines().length < 2);
    assert.equal(lines()[0], "None of your secrets may be sent there.");
    assert.ok(!waits(), `nothing waits yet: ${lines().join(" | ")}`);
    // Every read the page makes from here on is counted: no Check, and
    // since queue item #284 one Rules read per change of the questions
    // waiting (a file row's "Waiting for your answer" line follows them),
    // which asks the host itself: one ask per poll. Counted once no read of
    // the page's opening is still out: one asked before the send but
    // answered after it would say it waits without any poll.
    await waitWhile(() => reads.out > 0);
    reads.counting = true;

    const held = await gate.desymbolizationDecision({ symbol: token, boundary: "network", destination: host, sessionKey: "host-check", scheme: "https" });
    assert.equal("requiresApproval" in held && held.requiresApproval, true, "the egress gate holds the send for your answer");
    const id = "approvalId" in held ? held.approvalId : undefined;
    assert.ok(id, "held in Approvals");
    poll();
    await waitWhile(() => !waits());
    assert.ok(waits(), `the waiting line, at the next poll: ${lines().join(" | ")}`);
    assert.equal(w.location.pathname, "/rules");
    assert.equal(reads.panel, 1, "one Rules read, for the file rows' waiting line (#284)");
    assert.equal(reads.asks, 1, "the host asked once, by that read");
    clean("the Rules page with a send waiting");

    // Another tab: Approvals, its card answered Allow once.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const card = (other: any) => [...other.querySelectorAll("#approvals-waiting .ask")].find((c: any) => c.dataset.id === id) as any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/approvals", (other: any) => !!card(other), async (other: any) => {
      const once = [...card(other).querySelectorAll(".ask-actions button")].find((b: any) => b.textContent === "Allow once") as any;
      assert.ok(once, "the card offers Allow once");
      once.click();
      await waitWhile(() => !!card(other)?.querySelector(".ask-actions button"));
    }, tab);
    assert.ok(!(await gate.egressApprovals("pending")).some((a) => a.id === id), "answered in the other tab");

    poll();
    await waitWhile(() => waits());
    assert.ok(!waits(), `the waiting line went at the next poll: ${lines().join(" | ")}`);
    assert.ok(lines().includes("You answered 1 earlier send to this host. Find them in Approvals."), lines().join(" | "));
    assert.equal(box.value, host);
    assert.equal(reads.panel, 2, "one more Rules read for the answer, no more");
    assert.equal(reads.asks, 2, "one more ask");
    clean("the Rules page after the answer");
  }, { ...tab, beforeScripts });
});
