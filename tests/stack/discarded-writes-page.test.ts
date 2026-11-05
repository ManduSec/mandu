/**
 * discarded-writes-page — a session's page lists the secret files whose
 * masked copy the agent changed (dashboard.md §4.25b, *Changes Mandu did
 * not apply to your files*), across the REAL components:
 *
 *   D1  a real ArbiterServer in `secrets` (confidentiality ON, integrity
 *       OFF), a `.env` holding a fake key registered as a secret, and the
 *       REAL anthropic-proxy in its production wiring (`new
 *       ArbiterClientAdapter(data, human)`) in front of a mock model: one
 *       Read of the `.env`, whose result reaches the model masked;
 *   D2  the launcher's REAL `session_exit` (services/observe.ts
 *       `sessionExitEvent`, `discardedWrites: [<.env>]`), emitted with
 *       `emitLauncherEvent` on the human socket, as run.ts does;
 *   D3  the REAL dashboard over the arbiter (`ArbiterEventSource`): its
 *       page model (`GET /api/home/agent`) lists the file `~/…` under the
 *       dashboard's home, signed in and out; a later exit sent on the DATA
 *       socket, as a program in the agent's tree could, is stored as a claim
 *       and changes nothing;
 *   D4  a second session whose believed exit names no file, then a claimed
 *       one naming the `.env`: no block;
 *   D5  Home's (`/api/home`) and History's (`/api/home/history`) rows, signed
 *       in and out: the first session's carries `notApplied: 1` (the claimed
 *       forged file never raises it), the second's none, neither the path;
 *       History's switch keeps the first (§4.25b *Home and History say so*);
 *   oracle: the model never got the key, and neither the block nor any page
 *       answer holds it. Only the path appears.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const KEY = `sk_live_discardedCanary_${process.pid}_7Hq2Lm9Zx4`;
const SESSION = `discarded-${process.pid}`;
const QUIET = `discarded-quiet-${process.pid}`;
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

test("an ended session's page lists the secret file whose masked copy the agent changed, from a believed exit only, and never the key (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-discarded-page-"));
  const home = join(tmp, "home");
  const ws = join(home, "app");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath); await data.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const seen: string[] = [];
  let calls = 0;
  const upstream: UpstreamFetcher = async (a) => {
    const m = new MockUpstream({ sse: calls++ === 0 ? buildToolUseSse({ id: "toolu_env", name: "Read", input: { file_path: env } }) : buildTextSse("Added STRIPE_WEBHOOK_SECRET to .env.") });
    const res = await m.fetcher(a);
    seen.push(m.requests.at(-1)!.bodyText);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const dashboard = new DashboardServer({ ...ADMIN_OPTS, source: new ArbiterEventSource({ socketPath }), configEnv: { MANDU_HOME: join(tmp, "mandu") }, fileBrowserHome: home, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  type Msg = { role: string; content: unknown };
  const ask = async (session: string, messages: Msg[]) => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  /** Waits until the arbiter holds `n` events of `kind` for `session` (emission is asynchronous). */
  const recorded = async (session: string, kind: string, n: number) => {
    let seenN = 0;
    for (let i = 0; i < 200 && seenN < n; i++) {
      seenN = ((await human.events(session)) as unknown as { kind: string }[]).filter((e) => e.kind === kind).length;
      if (seenN < n) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(seenN >= n, `the arbiter recorded ${n} ${kind} event(s) for ${session} (saw ${seenN})`);
  };
  const pageOf = async (session: string, signedIn = true): Promise<{ vm: AgentPageVM; text: string }> => {
    const r = await fetch(`${base}/api/home/agent?session=${session}`, signedIn ? { headers: { Cookie: ADMIN_COOKIE } } : {});
    assert.equal(r.status, 200);
    const text = await r.text();
    return { vm: JSON.parse(text) as AgentPageVM, text };
  };
  const later = () => new Promise((r) => setTimeout(r, 5)); // a later timestamp than the last event

  try {
    // ── D1: the session reads its .env through the real proxy ──────────────
    const reg = await data.registerSecret({ path: env, sessionKey: SESSION });
    assert.ok(reg.symbol || reg.twin, `the .env is registered: ${JSON.stringify(reg)}`);
    let msgs: Msg[] = [{ role: "user", content: "Add STRIPE_WEBHOOK_SECRET to .env" }];
    await ask(SESSION, msgs);
    msgs = [...msgs,
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_env", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_env", content: render(`STRIPE_KEY=${KEY}\n`) }] },
    ];
    await ask(SESSION, msgs);
    await recorded(SESSION, "tllm_call", 2);
    assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the key");
    assert.equal((await pageOf(SESSION)).vm.discardedWrites, null, "running: no block");

    // ── D2: the launcher records the exit, naming the changed .env ─────────
    await later();
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: SESSION, code: 0, durationMs: 4_000, discardedWrites: [env] }), humanPath), "the launcher's emit lands");
    await recorded(SESSION, "session_exit", 1);

    // ── D3: the page lists it, signed in and out ───────────────────────────
    const ended = await pageOf(SESSION);
    assert.equal(ended.vm.running, false);
    assert.deepEqual(ended.vm.discardedWrites, { files: ["~/app/.env"], more: 0 });
    const out = await pageOf(SESSION, false);
    assert.equal(out.vm.valuesShown, false);
    assert.deepEqual(out.vm.discardedWrites, ended.vm.discardedWrites, "signed out: the same path");
    // A later exit sent on the data socket (a program in the agent's tree
    // could): stored as a claim, it neither replaces nor adds a file.
    await later();
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: SESSION, code: 0, durationMs: 5_000, discardedWrites: [join(home, "forged.txt")] })), "the data socket takes the emit");
    await recorded(SESSION, "session_exit", 2);
    const exits = ((await human.events(SESSION)) as unknown as { kind: string; claimed?: boolean }[]).filter((e) => e.kind === "session_exit");
    assert.deepEqual(exits.map((e) => e.claimed === true), [false, true], "the data socket's exit is stored as a claim");
    assert.deepEqual((await pageOf(SESSION)).vm.discardedWrites, { files: ["~/app/.env"], more: 0 }, "the claim changes nothing");

    // ── D4: a believed exit naming no file, then a claimed one naming it ───
    await ask(QUIET, [{ role: "user", content: "hello" }]);
    await recorded(QUIET, "tllm_call", 1);
    await later();
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: QUIET, code: 0, durationMs: 1_000 }), humanPath));
    await later();
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: QUIET, code: 0, durationMs: 2_000, discardedWrites: [env] })));
    await recorded(QUIET, "session_exit", 2);
    const quiet = await pageOf(QUIET);
    assert.equal(quiet.vm.running, false, "its believed exit ended it");
    assert.equal(quiet.vm.discardedWrites, null, "a claimed exit makes the page list nothing");

    // ── D5: Home's and History's rows carry the count, never the path ──────
    type Row = { id: string; state: string; notApplied?: number };
    const rows = async (path: string, signedIn: boolean): Promise<{ list: Row[]; text: string }> => {
      const r = await fetch(`${base}${path}`, signedIn ? { headers: { Cookie: ADMIN_COOKIE } } : {});
      assert.equal(r.status, 200, path);
      const text = await r.text();
      const body = JSON.parse(text) as { agents?: Row[]; rows?: Row[] };
      return { list: body.agents ?? body.rows ?? [], text };
    };
    const listed: string[] = [];
    for (const path of ["/api/home", "/api/home/history?limit=100"]) for (const signedIn of [true, false]) {
      const { list, text } = await rows(path, signedIn);
      const lost = list.find((a) => a.id === SESSION);
      assert.ok(lost, `${path}: the session is listed`);
      assert.equal(lost.state, "idle", `${path}: ended`);
      assert.equal(lost.notApplied, 1, `${path} (${signedIn ? "signed in" : "signed out"}): one file, from the believed exit only`);
      const q = list.find((a) => a.id === QUIET);
      assert.ok(q && !("notApplied" in q), `${path}: a claimed exit gives none`);
      for (const p of [env, "~/app/.env", "forged.txt"]) assert.ok(!text.includes(p), `${path}: a count, never the path (${p})`);
      listed.push(text);
    }
    const only = await rows("/api/home/history?only=stepped-in&limit=100", false);
    assert.ok(only.list.some((a) => a.id === SESSION), "Only sessions where Mandu stepped in keeps it");

    // ── The oracle: only the path, never the key ───────────────────────────
    assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the key");
    assert.ok(!JSON.stringify(ended.vm.discardedWrites).includes(KEY), "CONFIDENTIALITY VIOLATION: the block holds the key");
    for (const [what, text] of [["signed out", out.text], ["the quiet session", quiet.text], ...listed.map((t, i) => [`a Home or History read #${i}`, t] as const)] as const) {
      assert.ok(!text.includes(KEY), `CONFIDENTIALITY VIOLATION: the page answer (${what}) holds the key`);
    }
    const served = await fetch(`${base}/agents/${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(served.status, 200);
    const html = await served.text();
    assert.ok(!html.includes(KEY), "CONFIDENTIALITY VIOLATION: the served page holds the key");
    assert.match(html, /id="agent-discarded-block"/, "the served page has the block");
  } finally {
    await dashboard.close();
    await proxy.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
