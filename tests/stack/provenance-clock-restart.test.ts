/**
 * provenance-clock-restart — plan 13 D7's store clock across an ARBITER
 * RESTART on a wall clock corrected backward, through the anthropic-proxy's
 * production adapter (`new ArbiterClientAdapter(new ArbiterClient(sock), new
 * ArbiterClient(humanSock))`) and its real request rewrite.
 *
 * Arbiter A runs three hours ahead (a clock that ran fast, a VM resumed): the
 * guard records that the agent itself holds a connection to a local server
 * that read a secret (plan 13 §4.5.1). The arbiter restarts on the same
 * mandu.db with the clock corrected. The agent fetches from that server: the
 * proxy relays the WebFetch call, and the result carries what the server
 * sent. The fetch's result must reach the model masked whole, as before the
 * restart.
 *
 * Before the fix the store's clock restarted at the wall clock, three hours
 * below the flow's open, so the open sorted after the call's window and the
 * canary reached the model raw.
 *
 * Axes stated: `secrets` (confidentiality ON, integrity OFF), pinned on the
 * server too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const CANARY = "devsrv_RESTART_CLOCK_CANARY_7Qp2";
const AHEAD_MS = 3 * 3_600_000;

function fetchCall(id: string, content: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "what does the local server say?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "WebFetch", input: { url: "http://127.0.0.1:8080/status", prompt: "summarize" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
const forwarded = (r: MessagesRequest): string => ((r.messages[2]!.content as any[])[0].content as string);

test("D7 across an arbiter restart on a clock corrected backward: the agent's fetch from a holder it connected to before the restart reaches the model masked (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prov-restart-"));
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const socketPath = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const realNow = Date.now;
  const boot = async () => {
    const server = new ArbiterServer({
      socketPath, humanSocketPath: humanSock, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
      confidentiality: true, integrity: false, // the `secrets` mode axes, stated
    });
    await server.listen();
    const clients: ArbiterClient[] = [];
    const open = async (sock: string): Promise<ArbiterClient> => { const c = new ArbiterClient(sock); await c.connect(); clients.push(c); return c; };
    const guard = await open(humanSock); // the guard reports on the human socket (plan 13 D9)
    const claude = new ArbiterClientAdapter(await open(socketPath), await open(humanSock));
    return { guard, claude, close: async () => { for (const c of clients) c.close(); await server.close(); } };
  };
  const session = "s-prov-restart";
  try {
    // ── Arbiter A, three hours ahead: the agent connects to a holder. ──
    Date.now = () => realNow() + AHEAD_MS;
    const a = await boot();
    try {
      await a.guard.taintProcessSecret({ procKey: "devsrv-0", path: "/w/.env", level: "no-model", app: "python3", session });
      assert.equal((await a.guard.recordAgentFlow({ channel: "socket:[9001]", flowsFrom: ["devsrv-0"], session })).recorded, true);
      // Before the restart, a fetch over it is masked (the baseline).
      assert.equal((await a.claude.recordCallCommand!({ callId: "toolu_before", sessionKey: session })).recorded, true);
      const before = await rewriteRequest(fetchCall("toolu_before", `status ok, key ${CANARY}`), { arbiter: a.claude, sessionKey: session });
      assert.ok(!forwarded(before.request).includes(CANARY), `baseline: masked before the restart: ${forwarded(before.request)}`);
    } finally {
      await a.close();
    }
    // ── Arbiter B, the same mandu.db, the clock corrected. ──
    Date.now = realNow;
    const b = await boot();
    try {
      assert.equal((await b.claude.recordCallCommand!({ callId: "toolu_after", sessionKey: session })).recorded, true);
      const after = await rewriteRequest(fetchCall("toolu_after", `status ok, key ${CANARY}`), { arbiter: b.claude, sessionKey: session });
      const body = forwarded(after.request);
      // MASTER: the canary, raw
      assert.ok(!body.includes(CANARY), `CONFIDENTIALITY VIOLATION: the agent's receipt from a holder reached the model raw after the restart: ${body}`);
      assert.match(body, /\$MDU:/, "masked whole: a symbol");
      assert.match(body, /\[mandu:secret\] masked: python3 read \/w\/\.env/, "with the note naming the holder's read");
    } finally {
      await b.close();
    }
  } finally {
    Date.now = realNow;
    rmSync(tmp, { recursive: true, force: true });
  }
});
