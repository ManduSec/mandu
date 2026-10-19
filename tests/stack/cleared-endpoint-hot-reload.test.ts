/**
 * cleared-endpoint-hot-reload.test.ts — plan 11 rung 2 under a policy edit
 * made while the session runs
 * (docs/design/confidentiality/model-endpoints.md §1 D2, D5).
 *
 * inspect-mcp reads the declared endpoints from the arbiter on every call
 * (`modelEndpoints`), and the arbiter re-derives each endpoint's location from
 * the law in force on every `resolve(deep, endpoint)`. So a hand edit of
 * policy.yaml that withdraws `local: true`, or removes the entry, must close
 * the door for a `$MDU:localmodel_…` symbol minted before the edit, with no
 * restart of either side.
 *
 * Wiring is PRODUCTION: a real ArbiterServer reading a policy FILE through its
 * mtime poll (arbiter/policy/policy-document-store.ts), inspect-mcp's adapter
 * over the real client (`new ArbiterClientAdapter(new ArbiterClient(sock))`)
 * and the production endpoint factory against a recording OpenAI-chat server
 * on loopback. The default U-LLM is a recording client.
 *
 * Legs:
 *   1. before the edit, the document reaches the declared local endpoint;
 *   2. an edit sets `local: false`: refused with the by-design text, the
 *      endpoint records no new request, the default U-LLM sees nothing;
 *   3. the entry restored, then removed from `models:`: the same;
 *   4. a stale endpoint list (the list inspect-mcp read a moment before the
 *      edit) still gets nothing: the arbiter refuses the resolve at the
 *      endpoint name, which is the backstop for that race.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { approveHeldDiskChange } from "../../arbiter/test/held-disk.js";
import { inspectSymbol } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { ArbiterClientAdapter as InspectArbiterAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import type { ModelEndpoint } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { createEndpointUllmFactory } from "../../interceptors/inspect-mcp/src/ullm-config.js";
import { MockUllm } from "../../interceptors/inspect-mcp/test/helpers/mock-ullm.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // local-model is a confidentiality level (the default mode's axis)

const CONTRACT = "Board minutes: acquire Initech for 18M. HOT_RELOAD_LOCAL_CANARY";
const CANARY = "HOT_RELOAD_LOCAL_CANARY";
const SUMMARY = "An 18M acquisition.";
const DOC = "/h/notes/minutes.md";

/** The hand-edited file: the `own` entry as local, as not local, or gone. */
function law(url: string, own: "local" | "not-local" | "absent"): string {
  const lines = ["version: 1"];
  if (own !== "absent") {
    lines.push(
      "models:",
      "  - name: own",
      `    url: ${url}`,
      "    wire: openai-chat",
      "    model: llama3.2",
      `    local: ${own === "local"}`,
    );
  }
  lines.push("paths:", `  - path: ${DOC}`, "    level: local-model", "");
  return lines.join("\n");
}

interface Wire { url: string; bodies: string[]; connections: () => number; close: () => Promise<void> }

async function openAiChatServer(): Promise<Wire> {
  const bodies: string[] = [];
  let connections = 0;
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      bodies.push(`${req.method} ${req.url}\n${body}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "llama3.2", choices: [{ message: { role: "assistant", content: SUMMARY } }] }));
    });
  });
  server.on("connection", () => { connections++; });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    bodies,
    connections: () => connections,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

async function waitFor(pred: () => Promise<boolean>, ms: number, what: string): Promise<void> {
  const deadline = Date.now() + ms;
  while (!(await pred())) {
    if (Date.now() > deadline) assert.fail(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

test("hot reload: withdrawing local: true or removing the entry closes rung 2 for a symbol minted before the edit", async () => {
  const own = await openAiChatServer();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cleared-reload-"));
  const file = join(tmp, "policy.yaml");
  writeFileSync(file, law(own.url, "local"));
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
    // The real mtime poll, at a test cadence (production: 2 s).
    policyPath: file, policyPollMs: 40,
  });
  await arbiter.listen();
  const minter = new ArbiterClient(sock);
  await minter.connect();
  const inspectClient = new ArbiterClient(sock);
  await inspectClient.connect();
  // THE production wiring: the adapter over the real client, nothing between.
  const adapter = new InspectArbiterAdapter(inspectClient);
  const outside = new MockUllm({ reply: SUMMARY, model: "claude-haiku-mock" });
  const deps = { arbiter: adapter, ullm: outside, sessionId: "reload-11", endpointUllm: createEndpointUllmFactory({}) };

  /** Write the file and wait until the law in force says what it says. */
  let bump = 0;
  const edit = async (state: "local" | "not-local" | "absent"): Promise<void> => {
    writeFileSync(file, law(own.url, state));
    // Distinct mtime even on a coarse clock, so the poll cannot miss the edit.
    const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
    utimesSync(file, t, t);
    const want = state === "absent" ? [] : [["own", state === "local"]];
    await waitFor(
      // Any `models:` change relaxes the law, so the poll holds it until a
      // human approves it (policy-surface.md §8.4.6); approve as the Inbox would.
      async () => (approveHeldDiskChange(arbiter), JSON.stringify((await minter.modelEndpoints()).map((e) => [e.name, e.local])) === JSON.stringify(want)),
      10_000,
      `the edit to '${state}' was never reloaded`,
    );
  };

  const assertClosed = async (symbol: string, why: string): Promise<void> => {
    const requests = own.bodies.length;
    const conns = own.connections();
    const out = await inspectSymbol(deps, { symbol, instruction: "Summarize." });
    assert.equal(out.ok, false, `${why}: refused`);
    if (out.ok) return;
    assert.match(out.error, /is local-model: this datum is readable only by your own model and none is declared in policy\.yaml `models:`/, why);
    assert.match(out.error, /This is by design, not an error: route the symbol instead, and do not retry\./, why);
    assert.ok(!out.error.includes(CANARY), `${why}: the refusal carries no bytes`);
    assert.equal(own.bodies.length, requests, `${why}: the endpoint received no new request`);
    assert.equal(own.connections(), conns, `${why}: not even a connection`);
    assert.equal(outside.calls.length, 0, `${why}: nothing fell back to the default U-LLM`);
    // The arbiter's own answer at the old name, independent of inspect-mcp.
    assert.equal(await minter.resolve(symbol, { deep: true, endpoint: "own" }), null, `${why}: the arbiter refuses the old endpoint name`);
  };

  try {
    const minted = await minter.symbolizeFull({ tool: "Read", value: CONTRACT, field: "content", origin: DOC });
    assert.match(minted.symbol, /^\$MDU:localmodel_Read\[/);

    // 1. Before the edit: admitted at the declared local endpoint.
    const ok = await inspectSymbol(deps, { symbol: minted.symbol, instruction: "Summarize." });
    assert.equal(ok.ok, true, `routed to the declared local model (${(ok as { error?: string }).error ?? ""})`);
    assert.ok(own.bodies.some((b) => b.includes(CANARY)), "the local model's wire carries the document");
    assert.equal(outside.calls.length, 0);

    // 2. local: true withdrawn.
    await edit("not-local");
    await assertClosed(minted.symbol, "local: false");

    // 3. Restored (the door reopens, so the refusal above was the edit's), then removed.
    await edit("local");
    const again = await inspectSymbol(deps, { symbol: minted.symbol, instruction: "Summarize." });
    assert.equal(again.ok, true, "restoring local: true reopens the door");
    await edit("absent");
    await assertClosed(minted.symbol, "entry removed");

    // 4. The race: inspect-mcp listed the endpoint as local a moment before
    // the edit landed. A stale list in front of the production adapter (only
    // modelEndpoints answers from the past; resolve goes to the real arbiter).
    const staleList: ModelEndpoint[] = [{ name: "own", url: own.url, wire: "openai-chat", model: "llama3.2", local: true }];
    const stale = new Proxy(adapter, {
      get(target, prop, receiver) {
        if (prop === "modelEndpoints") return async () => staleList;
        const v = Reflect.get(target, prop, receiver) as unknown;
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    });
    for (const state of ["not-local", "absent"] as const) {
      await edit(state);
      const requests = own.bodies.length;
      const conns = own.connections();
      const out = await inspectSymbol({ ...deps, arbiter: stale }, { symbol: minted.symbol, instruction: "Summarize." });
      assert.equal(out.ok, false, `stale list, ${state}: refused`);
      if (out.ok) continue;
      assert.match(out.error, /is local-model and the arbiter refused it at your declared model 'own'\. This is by design/, state);
      assert.equal(own.bodies.length, requests, `stale list, ${state}: the endpoint received nothing`);
      assert.equal(own.connections(), conns, `stale list, ${state}: not even a connection`);
      assert.equal(outside.calls.length, 0, `stale list, ${state}: nothing fell back to the default U-LLM`);
    }
    assert.ok(own.bodies.filter((b) => b.includes(CANARY)).length === 2, "the document reached the endpoint only in the two admitted legs");
  } finally {
    inspectClient.close();
    minter.close();
    await arbiter.close();
    await own.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
