/**
 * fs-view-map-gate.test.ts — LIVE (real-arbiter, real-IPC) e2e for the fs
 * prefix map (P2) and the sensitive-path gate (P3), fs-sync.md §1.3, §1.4.1.
 *
 * Unlike the per-package proxy e2e (which inject a MOCK arbiter in-process),
 * this drives the REAL AnthropicProxy against a REAL ArbiterServer over its
 * REAL Unix-socket IPC — so the P3 gate exercises the arbiter's actual
 * `fsPathDecision` policy AND its persistent egress-approval queue, and the
 * event surface is read back through the real `events()` op. The upstream is a
 * mock (no model/key); the map/gate are pure path logic + real IPC, so no
 * on-disk worktree is needed to prove the cross-process contract.
 *
 * What it proves end-to-end, over real IPC:
 *   P2  a model-emitted HumanView absolute path in a tool_use is forward-mapped
 *       into the AgentView before the agent sees it;
 *   P3  a model-emitted sensitive path (~/.ssh/id_rsa) is DENIED on the wire —
 *       rewritten to the /mandu/denied sentinel — the real arbiter queues a
 *       pending fs approval, and an fs_action event is emitted;
 *   P3  a human approval (resolveEgressApproval) flips the NEXT identical
 *       request to allow — the real, persistent queue round-trips over IPC.
 *
 * Run: npm test (integration) — part of scripts/test-all.sh.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as AnthropicProxyArbiterAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { ViewMap } from "../../interceptors/anthropic-proxy/src/view-map.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../interceptors/anthropic-proxy/src/sse-parser.js";
import { MockUpstream, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

/** Bridge the real ArbiterClient to the proxy adapter's structural client type
 *  (mirrors modelProxyRealClient in full-stack.test.ts, incl. fsPathDecision). */
function proxyClient(client: ArbiterClient): ConstructorParameters<typeof AnthropicProxyArbiterAdapter>[0] {
  return {
    connect: () => client.connect(),
    classify: (req) => client.classify(req as never) as never,
    symbolize: (args) => client.symbolize(args),
    handlingPrompt: (mode?: string, capabilities?: { inspect?: boolean; policyTools?: boolean; exec?: boolean }) =>
      client.handlingPrompt(mode as never, capabilities),
    recordToolCall: (args) => client.recordToolCall(args),
    fsPathDecision: (req) => client.fsPathDecision(req as never) as never,
    // Phase-0 exec gate (exec-routing.md §3): absent = the adapter fails CLOSED
    // and every model-emitted Bash command becomes the block sentinel.
    execGate: (req) => client.execGate(req as never) as never,
    emit: async (event) => ({ seq: await client.emit(event as never) }),
    // the value backstop (a side call's text, the exec legs), as the real client has it
    scanSecretValues: (text) => client.scanSecretValues(text),
    // the prompt filter (confidentiality-plan-15 §3.2), as the real client has it
    filterPrompt: (args: Parameters<ArbiterClient["filterPrompt"]>[0]) => client.filterPrompt(args),
    close: () => client.close(),
  };
}

const HUMAN = "/work/human-repo";
const AGENT = "/work/agent-view";
const SSH_KEY = join(homedir(), ".ssh", "id_rsa"); // real homedir → hits the arbiter's built-in sensitive list

function postMessages(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": "fs-map-gate-1" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function toolUsesOf(sse: string): ReconstructedToolUse[] {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sse);
  p.end();
  return seen;
}

const TURN = JSON.stringify({
  model: "claude-opus-4",
  stream: true,
  messages: [{ role: "user", content: "read the notes and the key" }],
});

test("LIVE (real arbiter/IPC): P2 forward-map + P3 gate deny→sentinel + approval round-trip", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-fsmap-"));
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({ socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {} });
  await arbiter.listen();

  const proxyIpc = new ArbiterClient(socketPath);
  await proxyIpc.connect();
  const readClient = new ArbiterClient(join(tmp, "admin.sock")); // resolveEgressApproval is admin-only
  await readClient.connect();

  const viewMap = new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix" });

  // Turn 1: the model reads a workspace file (forward-map) AND the ssh key (gate).
  const upstream = new MockUpstream({
    sse:
      buildToolUseSse({ id: "tu_ws", name: "Read", input: { file_path: `${HUMAN}/notes.md` }, index: 0 }) +
      buildToolUseSse({ id: "tu_ssh", name: "Read", input: { file_path: SSH_KEY }, index: 1 }),
    chunkInto: 6,
  });
  const proxy = new AnthropicProxy({
    arbiter: new AnthropicProxyArbiterAdapter(proxyClient(proxyIpc)),
    upstream: upstream.fetcher,
    viewMap,
    log: () => {},
  });
  const port = await proxy.listen(0);

  try {
    const res = await postMessages(port, TURN);
    assert.equal(res.status, 200);
    const tus = toolUsesOf(res.body);
    assert.equal(tus.length, 2, "both tool_use blocks reconstructed");

    // P2 (live): the workspace read forward-mapped into the AgentView.
    assert.deepEqual(tus[0].input, { file_path: `${AGENT}/notes.md` });
    assert.ok(!res.body.includes(HUMAN), "HumanView prefix must not reach the agent");

    // P3 (live): the sensitive read DENIED on the wire → the /mandu/denied
    // sentinel, produced by the REAL arbiter fsPathDecision over IPC.
    assert.deepEqual(tus[1].input, { file_path: `/mandu/denied/policy${SSH_KEY}` });

    // The REAL, persistent egress-approval queue holds a pending fs entry.
    const pending = await readClient.egressApprovals("pending");
    const fsEntry = pending.find((a) => a.symbol === "fs:Read:read" && a.destination === SSH_KEY);
    assert.ok(fsEntry, `expected a pending fs approval for ${SSH_KEY}, got ${JSON.stringify(pending)}`);

    // An fs_action event was emitted to the real arbiter.
    let events = await readClient.events("fs-map-gate-1");
    for (let i = 0; i < 40 && !events.some((e) => e.kind === "fs_action"); i++) {
      await new Promise((r) => setTimeout(r, 25));
      events = await readClient.events("fs-map-gate-1");
    }
    assert.ok(events.some((e) => e.kind === "fs_action"), "an fs_action (gate denial) event was emitted");

    // ── P3 round-trip: a human APPROVES → the next identical read is allowed ──
    await readClient.resolveEgressApproval(fsEntry!.id, true);

    const upstream2 = new MockUpstream({
      sse: buildToolUseSse({ id: "tu_ssh2", name: "Read", input: { file_path: SSH_KEY }, index: 0 }),
    });
    const proxy2 = new AnthropicProxy({
      arbiter: new AnthropicProxyArbiterAdapter(proxyClient(proxyIpc)),
      upstream: upstream2.fetcher,
      viewMap,
      log: () => {},
    });
    const port2 = await proxy2.listen(0);
    try {
      const res2 = await postMessages(port2, TURN);
      const tus2 = toolUsesOf(res2.body);
      // Approved → the gate now ALLOWS: the path passes through unchanged (the
      // human vouched for it), no sentinel. Proven over the real, persistent queue.
      assert.deepEqual(tus2[0].input, { file_path: SSH_KEY });
    } finally {
      await proxy2.close();
    }
  } finally {
    await proxy.close();
    proxyIpc.close();
    readClient.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
