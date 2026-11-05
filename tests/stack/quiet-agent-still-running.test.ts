/**
 * quiet-agent-still-running — an agent quiet for longer than the listing's
 * five-minute recency window stays under Home's Running now while its
 * `mandu` launch is alive (dashboard.md §4.10.4, *A live launch keeps R*),
 * across the REAL components:
 *
 *   Q1  a real ArbiterServer in `secrets` (confidentiality ON, integrity
 *       OFF) and the REAL anthropic-proxy in its production wiring (`new
 *       ArbiterClientAdapter(data, human)`), a mock model behind it: one
 *       model call for the session, whose id is a launch's scope id
 *       (`<epochSec>-<pid>`, this process's pid). The dashboard's Home,
 *       History and session page builders over the REAL `ArbiterEventSource`
 *       read it with a clock 10 minutes after that call, and the REAL probe
 *       (`liveLaunches`) over a runtime base holding the session's launch
 *       dir: it is running (Home's row not idle, History's neither, the page
 *       says it runs);
 *   Q2  the launch dir removed (the launcher's teardown): the five-minute
 *       rule ends it, as before this change;
 *   Q3  the dir back and the launcher's REAL `session_exit`
 *       (services/observe.ts `sessionExitEvent` over the human socket): a
 *       recorded exit outranks a live launch, the session has ended.
 *
 * Before this, Q1 read "idle": an agent waiting on its person for five
 * minutes dropped to Earlier, and its question was reworded as from a
 * session that had ended.
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
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { buildAgentPageFor, buildHistoryFor, buildHome, HomeFacts, type HomeDeps } from "../../dashboard/src/server/home-routes.js";
import { liveLaunches } from "../../dashboard/src/mandu-running.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const SESSION = `${Math.floor(Date.now() / 1000)}-${process.pid}`;

test("a session quiet for 10 minutes stays running while its mandu launch is alive; teardown or a recorded exit ends it (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-quiet-running-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const runtimeBase = join(tmp, "rt");
  const launchDir = join(runtimeBase, SESSION);
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  mkdirSync(join(runtimeBase, "instances"), { recursive: true });
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
  const source = new ArbiterEventSource({ socketPath });
  // Ten minutes after now: the session's last event is past the window.
  const later = Date.now() + 10 * 60_000;
  const deps: HomeDeps = {
    source, facts: new HomeFacts(source, join(tmp, "u")), approvals: undefined, testRuns: [], watchRuns: [],
    env: { MANDU_HOME: join(tmp, "home") }, home: join(tmp, "u"), now: () => later,
    live: () => liveLaunches(runtimeBase),
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
  /** The session's Home row, History row and page, as the product reads them. */
  const read = async () => {
    const home = await buildHome(deps);
    const history = await buildHistoryFor(deps, null, 20);
    const page = await buildAgentPageFor(deps, SESSION);
    return {
      home: home.agents.find((a) => a.id === SESSION)?.state,
      history: history.rows.find((r) => r.id === SESSION)?.state,
      page: page.running,
    };
  };

  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 64, messages: [{ role: "user", content: "What is in .env?" }] }),
    });
    assert.equal(res.status, 200, await res.text());
    await recorded("tllm_call", 1);

    // ── Q1: its launch alive (this process), quiet 10 minutes: running ─────
    mkdirSync(launchDir);
    assert.deepEqual([...liveLaunches(runtimeBase)], [SESSION], "the real probe finds the launch");
    const going = await read();
    assert.equal(going.home, "running", "Home keeps it under Running now");
    assert.notEqual(going.history, "idle", "History lists it running");
    assert.equal(going.page, true, "its page says it runs");

    // ── Q2: teardown removed the launch dir: the recency rule ends it ──────
    rmSync(launchDir, { recursive: true });
    const gone = await read();
    assert.equal(gone.home, "idle", "no live launch, quiet 10 minutes: Earlier");
    assert.equal(gone.history, "idle");
    assert.equal(gone.page, false);

    // ── Q3: the launch alive again, but the agent's exit recorded ──────────
    mkdirSync(launchDir);
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: SESSION, code: 0, durationMs: 4_000 }), humanPath), "the launcher's emit lands");
    await recorded("session_exit", 1);
    const exited = await read();
    assert.equal(exited.home, "idle", "a recorded exit outranks a live launch");
    assert.equal(exited.history, "idle");
    assert.equal(exited.page, false);
  } finally {
    source.close();
    await proxy.close();
    data.close();
    human.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
