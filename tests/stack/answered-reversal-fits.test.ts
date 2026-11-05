/**
 * answered-reversal-fits e2e — Approvals › Answered earlier: the button that
 * changes an answer is one line, inside its border, at every width
 * (dashboard.md §4.25 *One line in its button*, #258). Mandu-new.
 *
 * Until 2026-11-02 the button's column was a fixed 110 px. #202 made the
 * reversal of a Block read "Always allow instead" and #226 "Allow this
 * session instead" / "Allow once instead", so at 1280 and 900 px the label
 * wrapped in 86 px of text room: "Always allow" inside the border, "instead"
 * across and below its bottom edge. A REAL ArbiterServer holds two
 * questions filed through its own flow, both answered Block over the
 * dashboard's real route on the production admin adapter
 * (`makeApprovalsArbiter`):
 *
 *   - a send of STRIPE_KEY to an upload host: the egress gate asks
 *     (`desymbolizationDecision`), its reversal "Always allow instead";
 *   - a program in a session that read `.env` sends to hooks.slack.com
 *     (`holder-send:` keyed to that session), "Allow this session instead",
 *     the longest label.
 *
 * A REAL headless Chromium (Playwright's headless shell; none found: the
 * test skips), signed in with the one-time admin link, draws Approvals:
 *
 *   R1  at 1280 and 900 px each reversal is one line: its scrollHeight fits
 *       its box, its text one line box inside the button's border, the
 *       button as tall as a one-line `.btn.small`, its right edge inside the
 *       row; the outcome ("✗ Blocked") starts at the same x on both rows;
 *   R2  the words column gives up only what the button's column gained over
 *       its old 110 px, the outcome column keeps its 150 px;
 *   R3  every label the row can carry ("Block instead", "Send as written
 *       instead", "Send masked instead", …), set on the drawn button, is one
 *       line in the same column (a fixture: a held message's row is not
 *       cheap to raise here);
 *   R4  at 375 px the row stacks and each button is one line inside it;
 *   R5  the oracle: no page read, /api/home included, carries a value or a
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";
import { chromiumBinary, READY, startChromium, stopChromium } from "../lib/chromium.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const BIN = chromiumBinary();
const SESSION = `1791880000-${process.pid}`;
// Assembled at run time: this file holds no credential-shaped literal.
const KEY_VALUE = `${"sk" + "_live_"}answeredFitsKey_${process.pid}_0000`;
const FILE_VALUE = `${"sk" + "_live_"}answeredFitsFile_${process.pid}_0000`;
const HOST = "uploads.example-storage.net";
/** Every label the reversal can carry (home.js `drawAnswered`). */
const LABELS = ["Always allow instead", "Allow this session instead", "Allow once instead", "Block instead", "Send as written instead", "Send masked instead"];

/** One drawn row, as Chromium lays it out. */
interface Drawn {
  label: string;
  row: [number, number];
  /** The row's content box: its left and right edges inside its padding. */
  content: [number, number];
  button: { left: number; right: number; top: number; bottom: number; height: number; scrollHeight: number; clientHeight: number };
  /** The label's text: how many line boxes, and their bounds. */
  text: { lines: number; left: number; right: number; top: number; bottom: number };
  outcome: number;
  columns: number[];
}

test("Answered earlier's reversal is one line inside its button at 1280, 900 and 375 px in real Chromium, the longest label too, the words giving up only the difference, no value shown (real arbiter, production adapter; secrets axes, explicit)", { skip: BIN === null ? "no headless Chromium (Playwright's headless shell) on this host" : false, timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-answered-fits-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
  mkdirSync(join(home, "deploy"), { recursive: true });
  const dotenv = join(home, "shop", ".env");
  writeFileSync(dotenv, `STRIPE_KEY=${FILE_VALUE}\n`);
  const keys = join(home, "deploy", "staging.env");
  writeFileSync(keys, `STRIPE_KEY=${KEY_VALUE}\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
    policyDocument: { version: 1, paths: [{ path: dotenv, level: "no-model", readers: ["ssh-add"] }] },
  });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const guard = new ArbiterClient(humanSock); await guard.connect();
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
    for (const v of [KEY_VALUE, FILE_VALUE]) assert.ok(!body.includes(v), `CONFIDENTIALITY VIOLATION: ${where} carries a value`);
    assert.doesNotMatch(body, /\$MDU/, `${where} carries no token`);
  };
  const profile = join(tmp, "chrome");
  let chrome: ChildProcess | null = null;
  let page: Awaited<ReturnType<typeof devtools>> | null = null;
  try {
    // ── two questions, filed through the arbiter's own flow ──────────────────
    const reg = await gate.registerSecret({ path: keys, sessionKey: SESSION });
    const keySym = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
    assert.ok(keySym, `the key has its own symbol: ${JSON.stringify(reg)}`);
    const d = await gate.desymbolizationDecision({ symbol: keySym!, boundary: "network", destination: HOST, sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false, `the real gate refuses ${HOST}`);
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "and asks for an OK");
    const opened = await guard.decideSecretOpen({ path: dotenv, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "a-1", session: SESSION });
    assert.equal(opened.verdict, "raw", JSON.stringify(opened));
    const holder = (await guard.taintedProcessBindings({ procKey: "a-1", session: SESSION, destination: "hooks.slack.com" })).ask!.approvalId;
    const pending = await admin.egressApprovals("pending");
    const send = pending.find((a) => a.id !== holder)?.id;
    assert.ok(send, `the key's send waits: ${JSON.stringify(pending.map((a) => a.id))}`);
    // Answered Block over the dashboard's real route.
    for (const id of [send!, holder]) {
      const r = await pageFetch(`${base}/api/egress/approvals/${id}/deny`, { method: "POST", headers: CSRF_ADMIN });
      assert.equal(r.status, 200, `${id} is answered Block`);
    }
    const expect: Record<string, string> = { [send!]: "Always allow instead", [holder]: "Allow this session instead" };

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
    await until(`${READY} && location.pathname === "/"`, "Home after the sign-in link");
    await p.send("Page.navigate", { url: `${base}/approvals` });
    const ids = JSON.stringify([send!, holder]);
    const sel = `#approvals-answered .row.answered[data-id="ID"] > button.btn`;
    await until(`${READY} && location.pathname === "/approvals" && ${ids}.every((id) => !!document.querySelector(${JSON.stringify(sel)}.replace("ID", id))) && document.fonts.status === "loaded"`, "both answered rows with their buttons");
    assert.equal(await evaluate(`document.fonts.check('500 13px "IBM Plex Sans"')`), true, "the page's own font draws the buttons");

    /** Each row's layout, with `labels[i]` set on its button first when given
     *  (the drawn label put back after). */
    const measure = async (labels: string[] | null): Promise<Drawn[]> => JSON.parse(String(await evaluate(`new Promise((done) => {
      const rows = ${ids}.map((id) => document.querySelector(${JSON.stringify(sel)}.replace("ID", id)).parentElement);
      const kept = rows.map((r) => r.querySelector(":scope > button.btn").textContent);
      const labels = ${JSON.stringify(labels)};
      if (labels) rows.forEach((r, i) => { r.querySelector(":scope > button.btn").textContent = labels[i]; });
      requestAnimationFrame(() => requestAnimationFrame(() => {
        const out = rows.map((row) => {
          const b = row.querySelector(":scope > button.btn"), cs = getComputedStyle(row), rr = row.getBoundingClientRect(), br = b.getBoundingClientRect();
          const range = document.createRange(); range.selectNodeContents(b);
          const lines = [...range.getClientRects()].filter((x) => x.width > 0);
          const tops = new Set(lines.map((x) => Math.round(x.top)));
          return {
            label: b.textContent,
            row: [rr.left, rr.right],
            content: [rr.left + parseFloat(cs.paddingLeft), rr.right - parseFloat(cs.paddingRight)],
            button: { left: br.left, right: br.right, top: br.top, bottom: br.bottom, height: br.height, scrollHeight: b.scrollHeight, clientHeight: b.clientHeight },
            text: { lines: tops.size, left: Math.min(...lines.map((x) => x.left)), right: Math.max(...lines.map((x) => x.right)), top: Math.min(...lines.map((x) => x.top)), bottom: Math.max(...lines.map((x) => x.bottom)) },
            outcome: row.querySelector(".outcome").getBoundingClientRect().left,
            columns: cs.gridTemplateColumns.split(" ").map(parseFloat),
          };
        });
        rows.forEach((r, i) => { r.querySelector(":scope > button.btn").textContent = kept[i]; });
        done(JSON.stringify(out));
      }));
    })`)));
    /** A one-line \`.btn.small\` on the page: the height the reversal keeps. */
    const oneLine = Number(await evaluate(`(() => { const b = document.createElement("button"); b.className = "btn small"; b.textContent = "Undo"; document.getElementById("approvals-answered").after(b); const h = b.getBoundingClientRect().height; b.remove(); return h; })()`));
    assert.ok(oneLine > 20, `a one-line small button is measured: ${oneLine}`);
    const fits = (r: Drawn, say: string) => {
      const why = `${say}, "${r.label}": ${JSON.stringify(r)}`;
      assert.ok(r.button.scrollHeight <= r.button.clientHeight, `${why}: nothing runs below the button's box`);
      assert.equal(r.text.lines, 1, `${why}: the label is one line`);
      assert.ok(Math.abs(r.button.height - oneLine) < 0.5, `${why}: as tall as a one-line small button`);
      assert.ok(r.text.left >= r.button.left - 0.5 && r.text.right <= r.button.right + 0.5, `${why}: the label lies inside the button, side to side`);
      assert.ok(r.text.top >= r.button.top - 0.5 && r.text.bottom <= r.button.bottom + 0.5, `${why}: the label lies inside the button, top to bottom`);
      assert.ok(r.button.left >= r.content[0] - 0.5 && r.button.right <= r.content[1] + 0.5, `${why}: the button lies inside the row`);
    };

    for (const width of [1280, 900, 375]) {
      await p.send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 760 });
      const say = `at ${width} px`;
      // ── R1, R4: the drawn labels ──
      const drawn = await measure(null);
      assert.deepEqual(drawn.map((r) => r.label), [send!, holder].map((id) => expect[id]), `${say}: the rows carry the reversals the arbiter's scopes give`);
      for (const r of drawn) fits(r, say);
      if (width === 375) {
        for (const r of drawn) assert.equal(r.columns.length, 1, `${say}: the row stacks`);
      } else {
        // ── R1, R2: the columns ──
        const [a, b] = drawn as [Drawn, Drawn];
        assert.ok(Math.abs(a.outcome - b.outcome) < 0.5, `${say}: the outcome starts at the same x on both rows (${a.outcome}, ${b.outcome})`);
        for (const r of drawn) {
          assert.equal(r.columns.length, 3, `${say}: words, outcome, button`);
          assert.equal(r.columns[1], 150, `${say}: the outcome keeps its 150 px`);
          const room = r.content[1] - r.content[0];
          const before = room - 150 - 110 - 2 * 16; // the words' column under the old 110 px
          assert.ok(Math.abs(r.columns[0]! - (before - (r.columns[2]! - 110))) < 1, `${say}: the words give up only what the button's column gained: ${JSON.stringify(r.columns)}, room ${room}`);
          assert.ok(r.columns[2]! <= 200, `${say}: the button's column stays near its label, not a share of the row: ${r.columns[2]}`);
        }
        // ── R3: every label the row can carry, in the same column ──
        for (const label of LABELS) {
          const set = await measure([label, label]);
          for (const r of set) {
            fits(r, `${say}, set on the drawn button`);
            assert.ok(Math.abs(r.outcome - a.outcome) < 0.5, `${say}, "${label}": the outcome does not move (${r.outcome} vs ${a.outcome})`);
          }
        }
      }
      clean(String(await evaluate("document.documentElement.outerHTML")), `the Approvals page ${say}`);
    }

    // ── R5: the oracle ──
    for (const route of ["/api/home", "/approvals"]) {
      const r = await pageFetch(base + route, { headers: { Cookie: ADMIN_COOKIE } });
      assert.equal(r.status, 200, `${route} is served`);
      clean(await r.text(), route);
    }
  } finally {
    page?.close();
    await stopChromium(chrome, profile);
    await dashboard.close();
    wired?.close();
    gate.close(); guard.close(); admin.close();
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
