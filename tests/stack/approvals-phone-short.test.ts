/**
 * approvals-phone-short e2e — on a phone, a question an agent waits on is a
 * short card on Approvals, its answers right under its line (dashboard.md
 * §4.25 *A waiting question is short on a phone*, #251). Mandu-new.
 *
 * Until 2026-11-02 every live card of Approvals was drawn in full at every
 * width: at 375 px its first answer button sat about 930 px below the card's
 * top, under *Why it stopped*, *What the AI has now* and the *If you click*
 * notes, so three questions put over 3,000 px of cards on a phone. A REAL
 * ArbiterServer (`secrets` axes) holds two questions about a labelled
 * `STRIPE_KEY`, both raised by its own egress gate (`registerSecret` +
 * `desymbolizationDecision`) for a running session. A REAL DashboardServer
 * over the production admin adapter (`makeApprovalsArbiter`) serves the page
 * to a REAL headless Chromium (Playwright's headless shell; none found: the
 * test skips), signed in with the one-time admin link:
 *
 *   P1  at 375 px each card is short: no cells, a What each answer does
 *       button, and the first card's Allow once within 450 px of its top;
 *   P2  at 1280 px the same cards are full, the three cells drawn; the page
 *       drew them again when the width crossed the breakpoint, no reload;
 *   P3  back at 375 px they are short again, and What each answer does opens
 *       the three cells in place;
 *   P4  the oracle: no page drawn (folded or opened, at either width) nor
 *       /api/home or /api/home/agent carries the key's value or a `$MDU`
 *       token;
 *   P5  the session page's Needs your OK follows the same rule (#300): that
 *       running session's page at 375 px draws its first card short, Allow
 *       once within 450 px of its top; at 1280 px full, the three cells,
 *       drawn again with no reload; back at 375 px What each answer does
 *       opens the cells in place. Before, the first card was about
 *       1,060 px tall there, its Allow once about 950 px below its top
 *       (after: about 500 px, Allow once about 390 px).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ChildProcess } from "node:child_process";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const BIN = chromiumBinary();
const SESSION = `1791890000-${process.pid}`;
// Assembled at run time: this file holds no credential-shaped literal.
const KEY_VALUE = `${"sk" + "_live_"}phoneShortKey_${process.pid}_0000`;
const HOSTS = ["uploads.example-storage.net", "paste.example-bin.org"];

/** One card as Chromium lays it out. */
interface Card {
  id: string;
  short: boolean;
  cells: number;
  more: string | null;
  top: number;
  height: number;
  /** Allow once's top, less the card's. */
  allowOnce: number | null;
}

test("on a 375 px phone Approvals and the session's page draw a running agent's questions short, Allow once within 450 px of the card's top, full again at 1280 px, in real Chromium, no value shown (real arbiter, production adapter; secrets axes, explicit)", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 180_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-phone-short-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
  const env = join(home, "shop", ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY_VALUE}\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const admin = new ArbiterClient(adminSock); await admin.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const clean = (body: string, where: string) => {
    assert.ok(!body.includes(KEY_VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the key's value`);
    assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
  };
  const profile = join(tmp, "chrome");
  let chrome: ChildProcess | null = null;
  let page: Awaited<ReturnType<typeof devtools>> | null = null;
  try {
    // ── two questions, raised by the arbiter's own egress gate ───────────────
    await admin.setPathLabel({ path: env, confidentiality: "no-model", bindings: ["api.stripe.com"], recursive: false });
    const ids: string[] = [];
    for (const host of HOSTS) {
      const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
      const sym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
      assert.ok(sym, `the key has its own symbol: ${JSON.stringify(reg)}`);
      const d = await gate.desymbolizationDecision({ symbol: sym!, boundary: "network", destination: host, sessionKey: SESSION, scheme: "https" });
      assert.equal(d.allow, false, `the real gate refuses ${host}`);
      assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "and asks for an OK");
      ids.push(String((d as { approvalId?: string }).approvalId));
    }
    const vm = await (await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } })).json() as { waiting: Array<{ id: string; askerEnded?: boolean }> };
    assert.deepEqual(vm.waiting.map((a) => a.id).sort(), [...ids].sort(), "both wait");
    assert.ok(vm.waiting.every((a) => !a.askerEnded), "an agent waits on each: live cards");

    // ── the served Approvals page in real Chromium ───────────────────────────
    const started = await startChromium(BIN!, profile, `${base}${dashboard.adminLoginPath()}`);
    chrome = started.proc;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let target: any = null;
    for (let i = 0; i < 50 && target === null; i++) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const list = (await (await pageFetch(`http://127.0.0.1:${started.port}/json/list`)).json()) as any[];
      target = list.find((x) => x.type === "page") ?? null;
      if (target === null) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(target, "the page is listed");
    page = await devtools(target.webSocketDebuggerUrl);
    const p = page;
    const evaluate = async (expression: string): Promise<unknown> => (await p.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result?.result?.value;
    const until = async (expression: string, what: string): Promise<void> => {
      for (let i = 0; i < 250; i++) {
        if (await evaluate(expression) === true) return;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.fail(`the page never showed ${what}`);
    };
    const width = (w: number) => p.send("Emulation.setDeviceMetricsOverride", { width: w, height: 800, deviceScaleFactor: 1, mobile: w < 760 });
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    await width(375);
    await p.send("Page.navigate", { url: `${base}/approvals` });
    const list = JSON.stringify(ids);
    const drawn = `${READY} && location.pathname === "/approvals" && ${list}.every((id) => [...document.querySelectorAll("#approvals-waiting .ask")].some((c) => c.dataset.id === id)) && document.fonts.status === "loaded"`;
    await until(drawn, "both questions");
    /** Each card's layout in `list` (Approvals' by default), after two frames. */
    const measure = async (list = "#approvals-waiting"): Promise<Card[]> => JSON.parse(String(await evaluate(`new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(() => {
      const cards = [...document.querySelectorAll("${list} .ask")];
      done(JSON.stringify(cards.map((c) => {
        const r = c.getBoundingClientRect();
        const allow = [...c.querySelectorAll(".ask-actions button")].find((b) => b.textContent === "Allow once");
        const more = c.querySelector(".ask-more");
        return {
          id: c.dataset.id, short: !c.classList.contains("expanded"), cells: c.querySelectorAll(".ask-detail .k").length,
          more: more ? more.textContent : null, top: r.top + scrollY, height: r.height,
          allowOnce: allow ? allow.getBoundingClientRect().top - r.top : null,
        };
      })));
    })))`)));

    // ── P1: short at 375 px ──
    const phone = await measure();
    t.diagnostic(`375 px: ${JSON.stringify(phone)}`);
    assert.equal(phone.length, 2);
    for (const c of phone) {
      assert.ok(c.short, `${c.id}: short at 375 px`);
      assert.equal(c.cells, 0, `${c.id}: no cells`);
      assert.equal(c.more, "What each answer does");
      assert.ok(c.allowOnce !== null && c.allowOnce < 450, `${c.id}: Allow once ${c.allowOnce} px below the card's top, within 450`);
    }
    clean(String(await evaluate("document.documentElement.outerHTML")), "Approvals at 375 px, folded");

    // ── P2: full at 1280 px, drawn again without a reload ──
    await evaluate("window.__sameDoc = true");
    await width(1280);
    await until(`[...document.querySelectorAll("#approvals-waiting .ask")].every((c) => c.classList.contains("expanded"))`, "the cards full at 1280 px");
    const wide = await measure();
    t.diagnostic(`1280 px: ${JSON.stringify(wide)}`);
    for (const c of wide) {
      assert.ok(!c.short, `${c.id}: full at 1280 px`);
      assert.equal(c.cells, 3, `${c.id}: the three cells`);
      assert.equal(c.more, null);
    }
    assert.equal(await evaluate("window.__sameDoc === true"), true, "no reload: the page drew the list again itself");
    clean(String(await evaluate("document.documentElement.outerHTML")), "Approvals at 1280 px");

    // ── P3: short again at 375 px; What each answer does opens the cells ──
    await width(375);
    await until(`[...document.querySelectorAll("#approvals-waiting .ask")].every((c) => !c.classList.contains("expanded"))`, "the cards short again at 375 px");
    await evaluate(`document.querySelector("#approvals-waiting .ask .ask-more").click()`);
    const opened = await measure();
    assert.equal(opened[0]!.cells, 3, "pressed, its cells open in place");
    assert.equal(opened[0]!.more, "Hide");
    assert.equal(opened[1]!.cells, 0, "only the card pressed");
    clean(String(await evaluate("document.documentElement.outerHTML")), "Approvals at 375 px, opened");

    // ── P5: the session page's Needs your OK, short at 375 px ──
    // The session's page needs a record of it: one model call, its message
    // holding nothing secret.
    await human.emit({
      sessionId: SESSION, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      id: "phone-call-1", ts: new Date(Date.now() - 30_000).toISOString(), kind: "tllm_call",
      input: { symbolized: "Upload the shop's config", original: null, differs: false, symbols: [] },
    } as never);
    await p.send("Page.navigate", { url: `${base}/agents/${encodeURIComponent(SESSION)}` });
    const agentPath = JSON.stringify(`/agents/${SESSION}`);
    await until(`${READY} && location.pathname === ${agentPath} && ${list}.every((id) => [...document.querySelectorAll("#agent-waiting .ask")].some((c) => c.dataset.id === id)) && document.fonts.status === "loaded"`, "the session page's questions");
    const agentPhone = await measure("#agent-waiting");
    t.diagnostic(`session page, 375 px: ${JSON.stringify(agentPhone)}`);
    assert.equal(agentPhone.length, 2);
    for (const c of agentPhone) {
      assert.ok(c.short, `${c.id}: short on the session page at 375 px`);
      assert.equal(c.cells, 0, `${c.id}: no cells`);
      assert.equal(c.more, "What each answer does", `${c.id}: What each answer does, not Details in Approvals`);
    }
    const first = agentPhone[0]!;
    assert.ok(first.allowOnce !== null && first.allowOnce < 450, `the first card's Allow once ${first.allowOnce} px below its top, within 450`);
    clean(String(await evaluate("document.documentElement.outerHTML")), "the session page at 375 px, folded");
    await evaluate("window.__sameAgentDoc = true");
    await width(1280);
    await until(`[...document.querySelectorAll("#agent-waiting .ask")].every((c) => c.classList.contains("expanded"))`, "the session page's cards full at 1280 px");
    const agentWide = await measure("#agent-waiting");
    t.diagnostic(`session page, 1280 px: ${JSON.stringify(agentWide)}`);
    for (const c of agentWide) {
      assert.equal(c.cells, 3, `${c.id}: the three cells at 1280 px`);
      assert.equal(c.more, null);
    }
    assert.equal(await evaluate("window.__sameAgentDoc === true"), true, "no reload: the session page drew Needs your OK again itself");
    clean(String(await evaluate("document.documentElement.outerHTML")), "the session page at 1280 px");
    await width(375);
    await until(`[...document.querySelectorAll("#agent-waiting .ask")].every((c) => !c.classList.contains("expanded"))`, "the session page's cards short again at 375 px");
    await evaluate(`document.querySelector("#agent-waiting .ask .ask-more").click()`);
    const agentOpened = await measure("#agent-waiting");
    assert.equal(agentOpened[0]!.cells, 3, "pressed, its cells open in place");
    assert.equal(agentOpened[0]!.more, "Hide");
    assert.equal(agentOpened[1]!.cells, 0, "only the card pressed");
    clean(String(await evaluate("document.documentElement.outerHTML")), "the session page at 375 px, opened");

    // ── P4: the oracle ──
    for (const route of ["/api/home", "/approvals", `/api/home/agent?session=${encodeURIComponent(SESSION)}`, `/agents/${encodeURIComponent(SESSION)}`]) {
      const r = await pageFetch(base + route, { headers: { Cookie: ADMIN_COOKIE } });
      assert.equal(r.status, 200, `${route} is served`);
      clean(await r.text(), route);
    }
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    await dashboard.close();
    wired?.close();
    gate.close(); admin.close(); human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

/** A DevTools client over Node's built-in WebSocket. */
async function devtools(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`no DevTools at ${wsUrl}`)), { once: true });
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const waiting = new Map<number, (m: any) => void>();
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
  });
  let id = 1;
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    send(method: string, params: Record<string, unknown> = {}): Promise<any> {
      const my = id++;
      return new Promise((resolve) => { waiting.set(my, resolve); ws.send(JSON.stringify({ id: my, method, params })); });
    },
    close: () => ws.close(),
  };
}
