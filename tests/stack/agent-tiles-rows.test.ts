/**
 * agent-tiles-rows — a session's page draws its count tiles in even rows,
 * across the REAL components and the served styles (dashboard.md §4.25 *The
 * tiles fill their rows evenly*). Mandu-new.
 *
 * Until 2026-10-15 the tiles were a plain auto-fit grid of 180 px tiles: a
 * headless Chromium drew the first-session tour's four tiles as 3 + 1 in a
 * 614 to 821 px window ("send with a real value filled in" alone under
 * three), five tiles as 4 + 1 and six as 4 + 2 from 822 px. Here a real
 * ArbiterServer runs at the `secrets` axes, the REAL anthropic-proxy on its
 * production client (`new ArbiterClientAdapter(data, human)`) carries one
 * session that reads `deploy/staging.conf` before it is marked a secret and
 * a `.env` whose key the proxy masks, then the real egress gate refuses the
 * key's send to a host no rule binds it to and asks for an OK (from the
 * human socket, as the real proxies ask). A real DashboardServer over the
 * production adapter (`makeApprovalsArbiter`) serves the session's page,
 * opened with its served stylesheets as each window applies them:
 *
 *   T1  the page draws four tiles (masked, read before marked, blocked,
 *       waiting) and nothing else in the grid; as a 720 px window they are
 *       two by two, as 613 and 822 px windows auto-fit (2 + 2 and one row),
 *       and as 390 and 320 px phones two by two too (the phone minimum,
 *       130 px: 180 px tiles took a whole row each there);
 *   T2  the served stylesheet: for 1 to 6 tiles at every window from 320 to
 *       1600 px, as few rows as auto-fit's and no row two tiles short of
 *       another, the tour's four as 2 + 2 at 320 to 821 px, two to six
 *       tiles two to a row under 614 px, each at least 130 px wide, and one
 *       tile the whole row; on a 390 px phone the four take two rows, half
 *       the four they took (Chromium: the block 381 px tall before, 224
 *       after);
 *   T3  the oracle: the model never got the `.env` value; no page or answer
 *       read here carries it, nor the staging file's token, nor a token
 *       (`$MDU`) on the product side.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON). What is
 * under test is the served page and styles; the stack supplies the real
 * session and the counts the server draws as tiles.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { MAX_TILES, arrangement, even, tilesRows } from "../../dashboard/test/unit/ui/tiles-rows.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

after(() => resetCurrentPolicyForTests("claude-code"));

const SESSION = `1791830000-${process.pid}`;
const VALUE = `sk_live_tilesRowsCanary_${process.pid}_000000`;
const TOKEN = "ghp_FakeTilesRows7Qm2Xw9Kd4Rt6Zp1Vn";
const CONF = `[staging]\nhost = "staging.tiles.example"\ntoken = "${TOKEN}"\n`;
const AUTO = "repeat(auto-fit, minmax(min(180px, 100%), 1fr))";
const PHONE = "repeat(auto-fit, minmax(min(130px, 100%), 1fr))";
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

test("a session's page draws its four tiles two by two in a 720 px window, on the real stack with its served styles, and no value is shown (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-tiles-rows-"));
  const ws = join(tmp, "mandu-try");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const conf = join(ws, "deploy", "staging.conf");
  const env = join(ws, ".env");
  writeFileSync(conf, CONF);
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(tmp, "other.key")}\n    level: no-model\n`);
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
  assert.ok(wired?.secrets?.setPathLabel, "the production wiring offers the Rules page's label");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  // The scripted model: read staging.conf, then the .env, then answer.
  const turns = [
    buildToolUseSse({ id: "toolu_tr_conf", name: "Read", input: { file_path: conf } }),
    buildToolUseSse({ id: "toolu_tr_env", name: "Read", input: { file_path: env } }),
    buildTextSse("Done.", { deltas: 1 }),
  ];
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = turns[Math.min(seen.length - 1, turns.length - 1)]!;
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  type Msg = { role: string; content: unknown };
  const ask = async (messages: Msg[]): Promise<string> => {
    const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    return seen.at(-1)!;
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the .env value`);
    assert.ok(!text.includes(TOKEN), `${where} carries a byte of the staging file`);
  };
  const served = async (f: string): Promise<string> => {
    const r = await pageFetch(base + f);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  const getPage = async (): Promise<{ text: string; vm: AgentPageVM }> => {
    const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}`);
    assert.equal(r.status, 200);
    const text = await r.text();
    return { text, vm: JSON.parse(text) as AgentPageVM };
  };
  try {
    // The session reads staging.conf as it is (nothing marks it yet), then the .env.
    const q: Msg[] = [{ role: "user", content: "What is in deploy/staging.conf and .env?" }];
    await ask(q);
    const t1: Msg[] = [
      ...q,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_tr_conf", name: "Read", input: { file_path: conf } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_tr_conf", content: render(CONF) }] },
    ];
    assert.ok((await ask(t1)).includes(TOKEN), "unmarked, the staging file reaches the model as read");
    const t2: Msg[] = [
      ...t1,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_tr_env", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_tr_env", content: render(`STRIPE_KEY=${VALUE}\n`) }] },
    ];
    const masked = await ask(t2);
    assert.ok(!masked.includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    const symbol = /\$MDU:[A-Za-z]+_Read\[[0-9a-f]+\](?:\.[A-Z_]+)?/.exec(masked)?.[0];
    assert.ok(symbol, "the model got the key's placeholder");
    await new Promise((r) => setTimeout(r, 20)); // the label comes strictly after the read
    // The Rules page marks staging.conf a secret: the AI read it before.
    await wired.secrets!.setPathLabel({ path: conf, confidentiality: "no-model" });
    // The agent's program sends the key to a host no rule binds it to: refused, waiting for an OK.
    const d = await human.desymbolizationDecision({ symbol, boundary: "network", destination: "paste.tiles.example", sessionKey: SESSION, scheme: "https" });
    assert.equal(d.allow, false, "the real gate refuses an unbound send");
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "and asks for an OK");

    let page = await getPage();
    for (let i = 0; i < 200 && !(page.vm.secrets?.counts?.masked === 1 && page.vm.secrets?.counts?.early === 1 && page.vm.waiting.length === 1); i++) {
      await new Promise((r) => setTimeout(r, 25));
      page = await getPage();
    }
    assert.deepEqual(page.vm.secrets.counts, { masked: 1, early: 1 }, "one secret masked, one read before it was marked");
    assert.equal(page.vm.waiting.length, 1, "one send waits for an OK");
    noValue(page.text, "/api/home/agent");
    assert.doesNotMatch(page.text, /\$MDU/, "the product's session page carries no token");
    const sheets = `${await served("/mandu.css")}\n${await served("/app.css")}`;

    // ── T1: the served page, as three windows apply its styles ──
    for (const [width, cols, rows] of [[720, "repeat(2, minmax(0, 1fr))", "2+2"], [613, AUTO, "2+2"], [822, AUTO, "4"], [390, PHONE, "2+2"], [320, PHONE, "2+2"]] as const) {
      await servedProductPage(base, `/agents/${SESSION}`, (doc) => (doc.getElementById("agent-facts")?.children.length ?? 0) === 4, (doc) => {
        const where = `the session page at ${width}px`;
        const box = doc.getElementById("agent-facts");
        const tiles = [...box.children] as El[];
        assert.deepEqual(tiles.map((t) => t.querySelector(".lbl").textContent), [
          "secret masked before the AI saw it",
          "secret the AI read before it was marked a secret",
          "actions blocked",
          "waiting for you",
        ], `${where}: the four tiles, and nothing else in the grid`);
        assert.ok(tiles.every((t) => t.classList.contains("tile")));
        assert.equal(doc.defaultView.getComputedStyle(box).gridTemplateColumns, cols, where);
        assert.equal(arrangement(tilesRows(sheets).at(width, 4)), rows, `${where}: ${rows}`);
        noValue(doc.body.textContent, `the rendered session page at ${width}px`);
        assert.doesNotMatch(doc.body.textContent, /\$MDU/, "the rendered page carries no token");
      }, { css: resolveCssVars(stylesAt(sheets, width)) });
    }

    // ── T2: the served stylesheet, every window and tile count ──
    const model = tilesRows(sheets);
    for (let n = 1; n <= MAX_TILES; n++) {
      for (let w = 320; w <= 1600; w++) {
        const g = model.at(w, n);
        assert.equal(g.rows.length, model.autoFit(w, n).rows.length, `${n} tiles at ${w}px: as few rows as auto-fit's`);
        assert.ok(even(g), `${n} tiles at ${w}px: ${arrangement(g)}`);
      }
    }
    for (let w = 320; w <= 821; w++) assert.equal(arrangement(model.at(w, 4)), "2+2", `four tiles at ${w}px`);
    for (let w = 320; w <= 613; w++) {
      assert.equal(model.at(w, 1).cols, 1, `one tile at ${w}px takes the row`);
      for (let n = 2; n <= MAX_TILES; n++) {
        const g = model.at(w, n);
        assert.equal(g.cols, 2, `${n} tiles at ${w}px: two to a row`);
        assert.ok(g.tile >= 130, `${n} tiles at ${w}px: each ${g.tile.toFixed(1)}px`);
      }
    }
    assert.equal(model.at(390, 4).rows.length, 2, "on a 390 px phone the four tiles take two rows, not four");

    // ── T3: the oracle ──
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    for (const route of ["/api/home", "/api/home/history", `/api/home/agent?session=${SESSION}`]) {
      const text = await (await pageFetch(base + route)).text();
      noValue(text, route);
      assert.doesNotMatch(text, /\$MDU/, `${route} carries no token`);
    }
  } finally {
    await proxy.close();
    await dashboard.close();
    wired?.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
