/**
 * dashboard-apply-patch-words — a Codex session's `apply_patch` calls name
 * their files on the product's session page and in the inspector's trace
 * (dashboard.md §4.25b "A patch names its files"), over the PRODUCTION
 * wiring: a real ArbiterServer in `secrets`, the REAL openai-proxy on its
 * production client (`new ArbiterClientAdapter(new ArbiterClient(sock), new
 * ArbiterClient(humanSock))`) with its exec gate on (the default), a
 * scripted model making Codex's calls, and the real DashboardServer over
 * `ArbiterEventSource`, read signed out.
 *
 * Before: the openai-proxy recorded nothing for Codex's FREEFORM
 * `apply_patch` (a `custom_tool_call` whose input is the patch text), and the
 * page read no patch, so every patch step read "Edited `a file`". And the
 * stream rewriter read a freeform patch as a code-mode cell: in a HIGH
 * session (a secret's content shown to the model), where the exec gate
 * blocks every command, the whole patch was replaced by the gate's sentinel
 * cell, which is no patch.
 *
 * Proves, end to end:
 *   - the freeform patch reaches Codex as the model wrote it, in a HIGH
 *     session (a secret shown to the model, another masked from it);
 *   - the proxy records it as `apply_patch({"input": <patch>})`, the shape
 *     of its JSON form, with the placeholder the model wrote kept;
 *   - the session page (`/api/home/agent`) words both forms by their files:
 *     "Edited `config.ts`, created `setup.md`, deleted `legacy.ts`" and
 *     "Moved `a.ts` to `b.ts`";
 *   - the inspector's trace (`/api/events`) carries each patch step's files;
 *   - THE ORACLE: the secret the patch's placeholder stands for reaches
 *     neither the model nor any dashboard route.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy, type UpstreamFetcher } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { buildCustomToolCallSse, buildFunctionCallSse, buildTextSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const KEY = `sk_live_fake_Patch${process.pid}_7788`;
const HEAD = "Chunk ID: 7a2c\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 12\nOutput:\n";

interface Part { kind: string; text: string }
interface StepWire { kind: string; sentence?: Part[] }
interface TurnWire { steps: StepWire[] }
interface Step { step: string; tool?: string; patchFiles?: unknown }
const words = (parts: readonly Part[] | undefined): string => (parts ?? []).map((p) => (p.kind === "masked" ? `[${p.text}]` : p.text)).join("");

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** The payload of every event of `type` in an SSE body. */
function eventsOf(sse: string, type: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const block of sse.split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/).find((l) => l.startsWith("data:"));
    if (!data) continue;
    try { const o = JSON.parse(data.slice(5).trim()) as Record<string, unknown>; if (o["type"] === type) out.push(o); } catch { /* not JSON */ }
  }
  return out;
}

test("Codex: a freeform and a JSON apply_patch name their files on the session page and in the trace; the freeform patch reaches Codex whole in a HIGH session; the secret reaches neither the model nor the dashboard (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-apply-patch-words-"));
  dirs.push(tmp);
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  writeFileSync(join(ws, ".env"), `STRIPE_KEY=${KEY}\n`);
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }), log: () => {} });
  const dport = await dashboard.listen(0);
  const get = async (path: string) => {
    const r = await fetch(`http://127.0.0.1:${dport}/api/${path}`);
    const text = await r.text();
    return { status: r.status, text, body: (() => { try { return JSON.parse(text) as Record<string, unknown>; } catch { return {}; } })() };
  };
  const session = `apply-patch-words-${process.pid}`;
  let proxy: OpenAiProxy | null = null;
  try {
    // The session goes HIGH (a model-ok datum read into context): the exec
    // gate then blocks every command it cannot prove stays home, and before
    // 2026-10-09 it read the freeform patch as one.
    const admin = await open(join(tmp, "admin.sock"));
    const contracts = join(tmp, "contracts");
    mkdirSync(contracts);
    await admin.setPathLabel({ path: contracts, confidentiality: "any-model", bindings: ["docs.corp"] });
    const sym = await admin.symbolizeFull({ tool: "read", value: "Acme pays $4,200,000 on 2026-09-30.", field: "content", origin: join(contracts, "c.md"), integrity: "trusted", sessionKey: session });
    assert.equal((await admin.declassifySymbol({ symbol: sym.symbol, sessionKey: session })).allowed, true);
    assert.equal((await admin.sessionState(session)).high, true, "the session is HIGH");

    // The scripted model: the freeform patch writes the placeholder the
    // model got for the key (read off the request it was sent), then the
    // JSON form renames a file, then it answers.
    const seen: string[] = [];
    let freeform = "";
    const json = ["*** Begin Patch", "*** Update File: src/a.ts", "*** Move to: src/b.ts", "@@", "-x", "+y", "*** End Patch"].join("\n");
    const upstream: UpstreamFetcher = async ({ body }) => {
      const text = body.toString("utf8");
      seen.push(text);
      let sse: string;
      if (seen.length === 1) {
        const token = /\$MDU:[a-z_]+\[[0-9a-f]{4,8}\](?:\.[A-Za-z0-9_.]+)?/.exec(text)?.[0];
        assert.ok(token, `the key reached the model as a placeholder: ${text.slice(-600)}`);
        freeform = [
          "*** Begin Patch",
          "*** Update File: src/config.ts",
          "@@",
          '-const key = "";',
          `+const key = "${token}";`,
          "*** Add File: docs/setup.md",
          "+# Setup",
          "+Run `npm start`; it reads the key from src/config.ts.",
          "*** Delete File: old/legacy.ts",
          "*** End Patch",
        ].join("\n");
        sse = buildCustomToolCallSse({ name: "apply_patch", input: freeform, callId: "call_ap1", itemId: "ctc_ap1", inputDeltas: 4 });
      } else if (seen.length === 2) {
        sse = buildFunctionCallSse({ name: "apply_patch", arguments: { input: json }, callId: "call_ap2", itemId: "fc_ap2" });
      } else {
        sse = buildTextSse("Done.");
      }
      return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
    };
    proxy = new OpenAiProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    const post = async (input: unknown[]): Promise<string> => {
      const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
        method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session },
        body: JSON.stringify({ model: "gpt-5.5", stream: true, instructions: "You are Codex.", input }),
      });
      const text = await res.text();
      assert.equal(res.status, 200, text);
      return text;
    };

    // Turn 1: the agent read the .env (the command names it, so its whole
    // output is masked); the model answers with the freeform patch.
    const history: unknown[] = [
      { type: "message", role: "user", content: [{ type: "input_text", text: "Put the Stripe key from .env into the config, add a setup note and drop the legacy file." }] },
      { type: "function_call", call_id: "call_env", name: "exec_command", arguments: JSON.stringify({ cmd: "cat ./.env", workdir: ws }) },
      { type: "function_call_output", call_id: "call_env", output: `${HEAD}STRIPE_KEY=${KEY}\n` },
    ];
    const first = await post(history);
    // The patch reaches Codex whole: a patch is not code, so the gate that
    // holds this HIGH session leaves it alone.
    const done = eventsOf(first, "response.custom_tool_call_input.done");
    assert.equal(done.length, 1);
    assert.equal(done[0]!["input"], freeform, "the freeform patch reaches Codex as the model wrote it");
    assert.doesNotMatch(first, /mandu-exec-gate/);

    // Turn 2: its result; the model answers with the JSON form.
    history.push({ type: "custom_tool_call", call_id: "call_ap1", name: "apply_patch", input: freeform });
    history.push({ type: "custom_tool_call_output", call_id: "call_ap1", output: "Success. Updated the following files:\nM src/config.ts\nA docs/setup.md\nD old/legacy.ts\n" });
    const second = await post(history);
    assert.equal(eventsOf(second, "response.function_call_arguments.done")[0]?.["arguments"], JSON.stringify({ input: json }));

    // Turn 3: its result; the model answers in words.
    history.push({ type: "function_call", call_id: "call_ap2", name: "apply_patch", arguments: JSON.stringify({ input: json }) });
    history.push({ type: "function_call_output", call_id: "call_ap2", output: "Success. Updated the following files:\nM src/b.ts\n" });
    await post(history);

    // The inspector's trace: each patch step carries its files.
    const ev = await waitFor("both patch steps in the trace", async () => {
      const r = await get(`events?session=${encodeURIComponent(session)}`);
      const steps = ((r.body["viewModel"] as { dualLanes?: { steps?: Step[] } } | undefined)?.dualLanes?.steps ?? []).filter((s) => s.step === "tool" && s.tool === "apply_patch");
      return r.status === 200 && steps.length >= 2 && steps.every((s) => s.patchFiles) ? { r, steps } : undefined;
    });
    assert.deepEqual(ev.steps.map((s) => s.patchFiles), [
      [{ kind: "update", path: "src/config.ts" }, { kind: "add", path: "docs/setup.md" }, { kind: "delete", path: "old/legacy.ts" }],
      [{ kind: "move", path: "src/a.ts", to: "src/b.ts" }],
    ]);
    // The freeform call's record is its JSON form's shape, the placeholder kept.
    const uses = ((ev.r.body["events"] ?? []) as Array<{ kind: string; callId?: string; input?: { symbolized?: string } }>).filter((e) => e.kind === "tool_use" && e.callId === "call_ap1");
    assert.equal(uses.length, 1, "the freeform patch is recorded once");
    assert.equal(uses[0]!.input?.symbolized, `apply_patch(${JSON.stringify({ input: freeform })})`);

    // The product's session page: each patch by its files.
    const page = await waitFor("the session page's patch steps", async () => {
      const r = await get(`home/agent?session=${encodeURIComponent(session)}`);
      const said = ((r.body["story"] ?? []) as TurnWire[]).flatMap((t) => t.steps).filter((s) => s.kind === "action").map((s) => words(s.sentence));
      return r.status === 200 && said.filter((w) => /^(Edited|Moved) /.test(w)).length >= 2 ? { r, said } : undefined;
    });
    const patches = page.said.filter((w) => /^(Edited|Moved) /.test(w));
    assert.deepEqual(patches, ["Edited config.ts, created setup.md, deleted legacy.ts", "Moved a.ts to b.ts"]);
    for (const w of page.said) assert.doesNotMatch(w, /a file/, `no step reads as an unnamed file: ${page.said.join(" | ")}`);

    // THE ORACLE: the key reaches neither the model nor any route.
    assert.ok(seen.length >= 3, "the model got every turn");
    for (const body of seen) assert.ok(!body.includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the key");
    for (const text of [ev.r.text, page.r.text, (await get("home")).text, (await get("sessions")).text]) {
      assert.ok(!text.includes(KEY), "CONFIDENTIALITY VIOLATION: the dashboard served the key signed out");
    }
  } finally {
    await proxy?.close().catch(() => {});
    await dashboard.close?.();
    for (const c of clients) c.close();
    await server.close();
  }
});
