/**
 * ask-words-wide e2e — on a wide window a short question card's words use
 * the card's width, with its answers under them (dashboard.md §4.25 *A
 * question's buttons wrap inside its card*, *A short question's words keep
 * 520 px*, #252). Mandu-new.
 *
 * Until 2026-11-02 a short card's words had a 320 px flex basis and its four
 * answers (447 px) never shrank, so at 1280 px the answers took half the
 * card and the words wrapped to ten lines in a 367 px column beside them.
 * A REAL ArbiterServer (`secrets` axes) holds two questions about a labelled
 * `STRIPE_KEY`, both raised by its own egress gate (`registerSecret` +
 * `desymbolizationDecision`). A REAL DashboardServer over the production
 * admin adapter (`makeApprovalsArbiter`) serves Home and Approvals to a REAL
 * headless Chromium (Playwright's headless shell; none found: the test
 * skips), signed in with the one-time admin link:
 *
 *   W1  at 1280, 1024 and 860 px Home's first card has its answers under its
 *       words, and the words are at least 500 px wide;
 *   W2  at every width the icon is beside the words where the card's row is
 *       380 px or wider (the 2026-10-12 fix: no empty band over the words),
 *       and above them only where it is narrower (a phone, as before);
 *   W3  at every width no answer runs past its card, nor the page sideways;
 *   W4  Approvals' short cards (at 700 px, short since #251) draw the same;
 *   W5  the oracle: no page drawn nor /api/home carries the key's value or a
 *       `$MDU` token.
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
const KEY_VALUE = `${"sk" + "_live_"}wordsWideKey_${process.pid}_0000`;
const HOSTS = ["hooks.slack.com", "evil.example"];

interface Box { left: number; right: number; top: number; bottom: number; width: number; height: number }
/** One short card as Chromium lays it out. */
interface Card {
  short: boolean;
  card: Box;
  /** The card's content box's right edge. */
  inner: number;
  row: Box;
  icon: Box;
  words: Box;
  answers: Box;
  sideways: boolean;
}

test("a short question card's words use a wide card's width, its answers under them, its icon still beside its words, in real Chromium, no value shown (real arbiter, production adapter; secrets axes, explicit)", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 180_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-words-wide-"));
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
    const vm = await (await pageFetch(`${base}/api/home`, { headers: { Cookie: ADMIN_COOKIE } })).json() as { waiting: Array<{ id: string }> };
    assert.deepEqual(vm.waiting.map((a) => a.id).sort(), [...ids].sort(), "both wait");

    // ── the served pages in real Chromium ────────────────────────────────────
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
    const width = (w: number) => p.send("Emulation.setDeviceMetricsOverride", { width: w, height: 900, deviceScaleFactor: 1, mobile: w < 760 });
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    const list = JSON.stringify(ids);
    const drawn = (host: string) => `${READY} && ${list}.every((id) => [...document.querySelectorAll("${host} .ask")].some((c) => c.dataset.id === id)) && document.fonts.status === "loaded"`;
    /** Each card's layout under `host`, after two frames. */
    const measure = async (host: string): Promise<Card[]> => JSON.parse(String(await evaluate(`new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(() => {
      const box = (e) => { const r = e.getBoundingClientRect(); return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height }; };
      const sideways = document.documentElement.scrollWidth > innerWidth;
      done(JSON.stringify([...document.querySelectorAll("${host} .ask")].map((c) => {
        const cs = getComputedStyle(c);
        const r = c.getBoundingClientRect();
        return {
          short: !c.classList.contains("expanded"), card: box(c), inner: r.right - parseFloat(cs.borderRightWidth) - parseFloat(cs.paddingRight),
          row: box(c.querySelector(".ask-top")), icon: box(c.querySelector(".ask-icon")), words: box(c.querySelector(".ask-body")),
          answers: box(c.querySelector(".ask-actions")), sideways,
        };
      })));
    })))`)));
    const round = (c: Card) => ({ card: Math.round(c.card.width), words: Math.round(c.words.width), height: Math.round(c.card.height), under: c.answers.top >= c.words.bottom - 0.5 });
    /** W2 and W3 on one card. */
    const shape = (c: Card, where: string) => {
      assert.ok(c.short, `${where}: a short card`);
      if (c.row.width >= 380) {
        assert.ok(c.icon.right <= c.words.left + 0.5, `${where}: the icon beside the words (icon ends ${c.icon.right}, words start ${c.words.left})`);
        assert.ok(c.icon.top >= c.words.top - 0.5 && c.icon.bottom <= c.words.bottom + 0.5, `${where}: on the words' line, no band over them`);
        assert.ok(c.words.top - c.row.top < 0.5, `${where}: the words start the row (no empty band above them: ${c.words.top - c.row.top} px)`);
      } else {
        assert.ok(c.icon.bottom <= c.words.top + 0.5, `${where}: a row under 380 px puts the icon above the words, as before`);
      }
      assert.ok(c.answers.right <= c.inner + 0.5, `${where}: the answers end inside the card (${c.answers.right} > ${c.inner})`);
      assert.equal(c.sideways, false, `${where}: the page does not scroll sideways`);
    };

    // ── W1–W3: Home at each width ──
    await width(1280);
    await until(drawn("#home-waiting"), "both questions on Home");
    for (const w of [1280, 1024, 860, 700, 600, 390]) {
      await width(w);
      const [first] = await measure("#home-waiting");
      assert.ok(first, `${w} px: a card`);
      t.diagnostic(`Home ${w} px: ${JSON.stringify(round(first!))} row ${Math.round(first!.row.width)}`);
      shape(first!, `Home at ${w} px`);
      if (w >= 860) {
        assert.ok(first!.answers.top >= first!.words.bottom - 0.5, `Home at ${w} px: the answers start under the words (answers ${first!.answers.top}, words end ${first!.words.bottom})`);
        assert.ok(first!.words.width >= 500, `Home at ${w} px: the words are ${first!.words.width} px wide, at least 500`);
      }
    }
    clean(String(await evaluate("document.documentElement.outerHTML")), "Home");

    // ── W2 on a one-line question: its words shortened in place at 1280 px
    // (the gate raises only sends, whose line is long), so the row is
    // sized by short words, the case the 2026-10-12 fix was for ──
    await width(1280);
    await evaluate(`(() => {
      const c = document.querySelector("#home-waiting .ask");
      c.querySelector(".ask-sentence").textContent = "Claude Code wants to run curl";
      c.querySelector(".ask-sub").textContent = "Just now.";
    })()`);
    const [one] = await measure("#home-waiting");
    t.diagnostic(`Home 1280 px, one line: ${JSON.stringify(round(one!))} row ${Math.round(one!.row.width)}`);
    shape(one!, "Home at 1280 px, a one-line question");
    assert.ok(one!.answers.top >= one!.words.bottom - 0.5, "a one-line question's answers are under its words too: one shape on a wide card");
    assert.ok(one!.words.height < one!.icon.height + 10, `its words are the line beside the icon (${one!.words.height} px tall)`);

    // ── W4: Approvals' short cards ──
    await width(700);
    await p.send("Page.navigate", { url: `${base}/approvals` });
    await until(`${drawn("#approvals-waiting")} && location.pathname === "/approvals"`, "both questions on Approvals");
    await until(`[...document.querySelectorAll("#approvals-waiting .ask")].every((c) => !c.classList.contains("expanded"))`, "short cards on Approvals at 700 px");
    const cards = await measure("#approvals-waiting");
    assert.equal(cards.length, 2);
    for (const [i, c] of cards.entries()) {
      t.diagnostic(`Approvals 700 px #${i}: ${JSON.stringify(round(c))} row ${Math.round(c.row.width)}`);
      shape(c, `Approvals at 700 px, card ${i}`);
      assert.ok(c.answers.top >= c.words.bottom - 0.5, `Approvals at 700 px, card ${i}: the answers under the words`);
    }
    clean(String(await evaluate("document.documentElement.outerHTML")), "Approvals");

    // ── W5: the oracle ──
    for (const route of ["/api/home", "/", "/approvals"]) {
      const r = await pageFetch(base + route, { headers: { Cookie: ADMIN_COOKIE } });
      assert.equal(r.status, 200, `${route} is served`);
      clean(await r.text(), route);
    }
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    await dashboard.close();
    wired?.close();
    gate.close(); admin.close();
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
