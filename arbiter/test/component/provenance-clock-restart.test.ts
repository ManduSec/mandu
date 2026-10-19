/**
 * provenance-clock-restart — plan 13 D7's store clock ACROSS AN ARBITER
 * RESTART, over the real sockets (provenance-store.ts `tick`,
 * `storedClockFloor`). Mandu-new.
 *
 * Arbiter A runs on a wall clock three hours AHEAD (a clock that ran fast and
 * was then corrected, a VM resumed); arbiter B is a fresh ArbiterServer on
 * the same mandu.db with the clock back where it belongs. The guard and the
 * proxy report on the human socket as in production (plan 13 D9).
 *
 * Proves:
 *   - an orphaned subshell of a call bound before the restart that reads a
 *     secret after it folds into that call's tree (`callTaint` no-model);
 *     before, its first sighting sorted before the call's relay and the
 *     call's later result (a background poll) reached the model raw;
 *   - an agent flow opened before the restart masks the agent's receipt of a
 *     call relayed after it (`agentReceiptTaint`); before, the flow's open
 *     sorted after the call's window: raw;
 *   - utility: a call relayed after the restart is not masked by an orphan
 *     seen before it, and a call relayed before the restart binds the shell
 *     reported after it (before: the first was masked, the second unbound).
 *
 * Axes: secrets (stated; the server's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const AHEAD_MS = 3 * 3_600_000;
const shell = (command: string): string[] => ["/bin/bash", "-c", command];
const pause = (): Promise<void> => new Promise((ok) => setTimeout(ok, 5));

test("D7 across an arbiter restart on a clock corrected backward: the orphan's read folds into the call relayed before it, an agent flow opened before masks a later receipt; a later call is not over-masked (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-prov-restart-"));
  const secret = join(dir, "x.txt");
  writeFileSync(secret, "token=RESTART_CLOCK_CANARY_0\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const realNow = Date.now;
  const boot = async () => {
    const s = new ArbiterServer({
      socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
      policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
    });
    await s.listen();
    const guard = new ArbiterClient(join(dir, "human", "h.sock")); await guard.connect();
    const proxy = new ArbiterClient(join(dir, "human", "h.sock")); await proxy.connect();
    return { guard, proxy, close: async () => { guard.close(); proxy.close(); await s.close(); } };
  };
  const session = "restart";
  const BG = "( read -t 2 <&-; mytool ./x.tx? | od -An -tx1 ) &";
  const OLD = "( mytool ./x.tx? ) &";
  const SPAN = "ls /w";
  try {
    // ── Arbiter A, the wall clock three hours ahead. ──
    Date.now = () => realNow() + AHEAD_MS;
    const a = await boot();
    try {
      // A background call, bound at its first ask (its result came back empty).
      await a.proxy.execGate({ command: BG, sessionKey: session, callId: "toolu_bg" });
      await a.guard.recordExecRoot({ procKey: "sh-bg", ancestors: ["agent-0"], argv: shell(BG), session, callRoot: true });
      await pause();
      const first = await a.proxy.callTaint("toolu_bg", { command: BG, session });
      assert.equal(first.level, null, JSON.stringify(first));
      assert.equal(first.root, "sh-bg");
      // An older orphan that read the secret before the restart.
      await a.proxy.execGate({ command: OLD, sessionKey: session, callId: "toolu_old" });
      await a.guard.recordExecRoot({ procKey: "old-mytool", ancestors: ["old-sub"], argv: ["mytool", "./x.txt"], session, orphanRoot: "old-sub" });
      assert.equal((await a.guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "old-mytool", parentKey: "old-sub", ancestorKeys: ["old-sub"], orphanRoot: "old-sub", session })).verdict, "raw");
      // The agent connects to a holder (a local server that read the secret).
      await a.guard.taintProcessSecret({ procKey: "srv-0", path: secret, level: "no-model", app: "mytool", session });
      assert.equal((await a.guard.recordAgentFlow({ channel: "socket:[4242]", flowsFrom: ["srv-0"], session })).recorded, true);
      // A call relayed just before the restart; its shell comes after it.
      await a.proxy.execGate({ command: SPAN, sessionKey: session, callId: "toolu_span" });
    } finally {
      await a.close();
    }

    // ── Arbiter B, the same mandu.db, the clock corrected (3 h back). ──
    Date.now = realNow;
    const b = await boot();
    try {
      // The background call's subshell, orphaned, now reads the secret.
      await b.guard.recordExecRoot({ procKey: "bg-mytool", ancestors: ["bg-sub"], argv: ["mytool", "./x.txt"], session, orphanRoot: "bg-sub" });
      assert.equal((await b.guard.decideSecretOpen({ path: secret, exe: "/usr/bin/mytool", isAgent: false, exeSystem: true, openerEnv: [], procKey: "bg-mytool", parentKey: "bg-sub", ancestorKeys: ["bg-sub"], orphanRoot: "bg-sub", session })).verdict, "raw");
      await pause();
      const bg = await b.proxy.callTaint("toolu_bg", { command: BG, session });
      // MASTER: level null, the poll's output raw
      assert.equal(bg.level, "no-model", `CONFIDENTIALITY: the orphan's read after the restart folds into the call relayed before it: ${JSON.stringify(bg)}`);
      // The agent still holds the connection: a WebFetch relayed now is its receipt.
      await b.proxy.recordCallCommand({ callId: "toolu_fetch", sessionKey: session });
      await pause();
      const receipt = await b.proxy.agentReceiptTaint([{ callId: "toolu_fetch", tool: "WebFetch" }], session);
      // MASTER: level null (the flow's open sorted after the call's window)
      assert.equal(receipt.calls[0]!.level, "no-model", `CONFIDENTIALITY: the agent's receipt over a connection opened before the restart: ${JSON.stringify(receipt)}`);
      // Utility: the call relayed before the restart binds its shell.
      await b.guard.recordExecRoot({ procKey: "sh-span", ancestors: ["agent-0"], argv: shell(SPAN), session, callRoot: true });
      await pause();
      const span = await b.proxy.callTaint("toolu_span", { command: SPAN, session });
      assert.equal(span.root, "sh-span", `MASTER: unbound (an empty window): ${JSON.stringify(span)}`);
      // Utility: a call relayed now is not masked by the orphan seen before the restart.
      await b.guard.recordAgentFlow({ channel: "socket:[4242]", closed: true });
      await b.proxy.execGate({ command: "echo clean-42", sessionKey: session, callId: "toolu_clean" });
      await b.guard.recordExecRoot({ procKey: "sh-clean", ancestors: ["agent-0"], argv: shell("echo clean-42"), session, callRoot: true });
      await pause();
      const clean = await b.proxy.callTaint("toolu_clean", { command: "echo clean-42", session });
      assert.equal(clean.root, "sh-clean");
      assert.equal(clean.level, null, `MASTER: masked by orphans seen before its relay: ${JSON.stringify(clean)}`);
    } finally {
      await b.close();
    }
  } finally {
    Date.now = realNow;
    rmSync(dir, { recursive: true, force: true });
  }
});
