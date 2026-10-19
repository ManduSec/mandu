/**
 * session-exit-not-running — an agent that exited is not "running" on the
 * developer view's session list (dashboard.md §4.10.4, "A recorded exit ends
 * R"), across the REAL components:
 *
 *   L1  a real ArbiterServer in `secrets` (confidentiality ON, integrity
 *       OFF) and the REAL anthropic-proxy in its production wiring (`new
 *       ArbiterClientAdapter(data, human)`), a mock model behind it: one
 *       model call for the session, so its last event is seconds old, well
 *       inside the list's five-minute recency window. The REAL dashboard
 *       over the arbiter (`ArbiterEventSource`, production wiring) lists it
 *       running: the control;
 *   L2  the launcher's REAL `session_exit` (services/observe.ts
 *       `sessionExitEvent`, emitted with `emitLauncherEvent` on the human
 *       socket, as run.ts does when the agent ends);
 *   L3  `/api/sessions`: the row carries `exited`, and neither it nor its
 *       day group is running; Home (`/api/home`) lists it ended, as before;
 *   L4  the agent resumes in the same session (another model call through
 *       the proxy): the row is running again, the exit no longer counts.
 *
 * Before this, the list read only recency: for five minutes after an exit
 * the inspector's row pulsed R ("still running") while the product pages on
 * the same server said it had ended (work-ledger tour item 14).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const SESSION = `${Math.floor(Date.now() / 1000)}-${process.pid}`;

type Row = { id: string; status?: string; exited?: boolean };
type Group = { id: string; status?: string; sessions: Row[] };

test("an agent that exited is not running on the real dashboard's session list, though its last event is seconds old; a resumed one is (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-exit-not-running-"));
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
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream: upstream.fetcher, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath }), configEnv: { MANDU_HOME: join(tmp, "home") }, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;

  /** One model call for the session through the real proxy. */
  const ask = async (text: string) => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 64, messages: [{ role: "user", content: text }] }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  /** Waits until the arbiter holds `n` events of `kind` for the session (emission is asynchronous). */
  const recorded = async (kind: string, n: number) => {
    let seen = 0;
    for (let i = 0; i < 200 && seen < n; i++) {
      seen = ((await human.events(SESSION)) as unknown as { kind: string }[]).filter((e) => e.kind === kind).length;
      if (seen < n) await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(seen >= n, `the arbiter recorded ${n} ${kind} event(s) for the session (saw ${seen})`);
  };
  /** The session's row on the list and the group it is in. */
  const listed = async (): Promise<{ row: Row; group: Group }> => {
    const res = await fetch(`${base}/api/sessions`);
    assert.equal(res.status, 200);
    const { sections } = (await res.json()) as { sections: { live: Group[] } };
    const group = sections.live.find((g) => g.sessions.some((s) => s.id === SESSION));
    assert.ok(group, `the session is listed under Live: ${JSON.stringify(sections.live.map((g) => g.sessions.map((s) => s.id)))}`);
    return { row: group.sessions.find((s) => s.id === SESSION)!, group };
  };

  try {
    // ── L1: a model call, seconds ago: running by recency (the control) ─────
    await ask("What is in .env?");
    await recorded("tllm_call", 1);
    const going = await listed();
    assert.equal(going.row.status, "running", "recent activity, no recorded exit: running");
    assert.equal(going.row.exited, undefined);

    // ── L2: the launcher records the agent's exit ──────────────────────────
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: SESSION, code: 0, durationMs: 4_000 }), humanPath), "the launcher's emit lands");
    await recorded("session_exit", 1);

    // ── L3: the list and Home agree it ended ───────────────────────────────
    const ended = await listed();
    assert.equal(ended.row.exited, true, "the row carries the recorded exit");
    assert.notEqual(ended.row.status, "running", "an exited agent is not running, though its last event is seconds old");
    assert.notEqual(ended.group.status, "running", "nor is its day group");
    const home = (await (await fetch(`${base}/api/home`)).json()) as { agents: { id: string; state: string }[] };
    assert.equal(home.agents.find((a) => a.id === SESSION)?.state, "idle", "Home lists it ended");

    // ── L4: the agent resumes in the same session ──────────────────────────
    await new Promise((r) => setTimeout(r, 5)); // a later timestamp than the exit
    await ask("And DEBUG?");
    await recorded("tllm_call", 2);
    const resumed = await listed();
    assert.equal(resumed.row.status, "running", "activity after the exit: running again");
    assert.equal(resumed.row.exited, undefined, "the exit no longer counts");
  } finally {
    await dashboard.close();
    await proxy.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
