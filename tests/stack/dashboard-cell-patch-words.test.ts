/**
 * dashboard-cell-patch-words — a Codex code-mode cell's `tools.apply_patch`
 * calls name their files on the product's session page and in the
 * inspector's trace (dashboard.md §4.25b "A patch in a code cell"), over the
 * PRODUCTION wiring: a real ArbiterServer in `secrets`, the REAL openai-proxy
 * on its production client (`new ArbiterClientAdapter(new ArbiterClient(sock),
 * new ArbiterClient(humanSock))`) with its exec gate on (the default), a
 * scripted model writing code-mode cells the way a live model does, and the
 * real DashboardServer over `ArbiterEventSource`, read signed out.
 *
 * Before: the openai-proxy recorded a cell by its `tools.exec_command`
 * literals only, so a patch inside a cell was no call, and a cell that only
 * patched files read "Ran a command" (its tool, `exec`, taken off the next
 * request's transcript).
 *
 * Proves, end to end:
 *   - a cell that binds its patch to a `const` (the placeholder the model got
 *     for the key in it), applies it and runs a command reads "Ran `npm
 *     test` and edited `config.ts`, created `setup.md`" — the cell's step
 *     keeps the command's name and args, and carries the patch's files;
 *   - a cell of two literal patches (a template literal and a string) and a
 *     computed one reads "Moved `a.ts` to `b.ts`, deleted `legacy.ts`": the
 *     computed patch names nothing;
 *   - the proxy records each literal patch as `apply_patch({"input": …})`
 *     under the cell's call id, the placeholder kept as written, and the
 *     cells' bytes reach Codex with the model's code whole;
 *   - THE ORACLE: the key the placeholder stands for reaches neither the
 *     model nor any dashboard route.
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
import { buildScriptCellSse, buildTextSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const dirs: string[] = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const KEY = `sk_live_fake_CellPatch${process.pid}_4411`;
const HEAD = "Chunk ID: 7a2c\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 12\nOutput:\n";
/** Codex 0.162's battery: the code-mode cell tool, each cell a fresh isolate. */
const BATTERY = {
  type: "additional_tools", role: "developer",
  tools: [{ type: "namespace", name: "functions", tools: [
    { type: "custom", name: "exec", description: "Run JavaScript code\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." },
    { type: "function", name: "wait" },
  ] }],
};

interface Part { kind: string; text: string }
interface StepWire { kind: string; sentence?: Part[] }
interface TurnWire { steps: StepWire[] }
interface Step { step: string; callId?: string; tool?: string; input?: string; patchFiles?: unknown }
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

/** The cell the stream delivered to Codex. */
function deliveredCell(sse: string): string {
  for (const block of sse.split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/).find((l) => l.startsWith("data:"));
    if (!data) continue;
    try {
      const o = JSON.parse(data.slice(5).trim()) as { type?: string; item?: { type?: string; input?: string } };
      if (o.type === "response.output_item.done" && o.item?.type === "custom_tool_call") return String(o.item.input);
    } catch { /* not JSON */ }
  }
  throw new Error("no custom_tool_call in the delivered stream");
}

test("Codex code mode: a cell's literal tools.apply_patch calls name their files on the session page and in the trace, next to the command the cell ran; a computed patch names none; the key reaches neither the model nor the dashboard (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cell-patch-words-"));
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
  const session = `cell-patch-words-${process.pid}`;
  let proxy: OpenAiProxy | null = null;
  try {
    // The scripted model, writing cells as a live model does: the patch
    // bound first, then applied, then a command; next, a cell of patches.
    const seen: string[] = [];
    let cell1 = "";
    let patch1 = "";
    const moved = ["*** Begin Patch", "*** Update File: src/a.ts", "*** Move to: src/b.ts", "@@", "-x", "+y", "*** End Patch"].join("\n");
    const cell2 = [
      `await tools.apply_patch(\`${moved}\`);`,
      `const r = await tools.apply_patch("*** Begin Patch\\n*** Delete File: old/legacy.ts\\n*** End Patch");`,
      `const name = "gen/" + Date.now() + ".ts";`,
      `await tools.apply_patch("*** Begin Patch\\n*** Add File: " + name + "\\n+x\\n*** End Patch");`,
      `text(String(r));`,
    ].join("\n");
    const upstream: UpstreamFetcher = async ({ body }) => {
      const text = body.toString("utf8");
      seen.push(text);
      let sse: string;
      if (seen.length === 1) {
        const token = /\$MDU:[a-z_]+\[[0-9a-f]{4,8}\](?:\.[A-Za-z0-9_.]+)?/.exec(text)?.[0];
        assert.ok(token, `the key reached the model as a placeholder: ${text.slice(-600)}`);
        patch1 = [
          "*** Begin Patch",
          "*** Update File: src/config.ts",
          "@@",
          '-const key = "";',
          `+const key = "${token}";`,
          "*** Add File: docs/setup.md",
          "+# Setup",
          "+Run `npm start`.",
          "*** End Patch",
        ].join("\n");
        cell1 = `const patch = ${JSON.stringify(patch1)};\nconst p = await tools.apply_patch(patch);\nconst r = await tools.exec_command({"cmd":"npm test","workdir":${JSON.stringify(ws)}});\ntext(r.output);\n`;
        sse = buildScriptCellSse({ input: cell1, callId: "call_cell1", itemId: "ctc_cell1", inputDeltas: 5 });
      } else if (seen.length === 2) {
        sse = buildScriptCellSse({ input: cell2, callId: "call_cell2", itemId: "ctc_cell2", inputDeltas: 3 });
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
    // output is masked); the model answers with the patch-and-test cell.
    const history: unknown[] = [
      BATTERY,
      { type: "message", role: "user", content: [{ type: "input_text", text: "Put the Stripe key from .env into the config, add a setup note, run the tests." }] },
      { type: "function_call", call_id: "call_env", name: "exec_command", arguments: JSON.stringify({ cmd: "cat ./.env", workdir: ws }) },
      { type: "function_call_output", call_id: "call_env", output: `${HEAD}STRIPE_KEY=${KEY}\n` },
    ];
    const first = await post(history);
    const delivered1 = deliveredCell(first);
    assert.ok(delivered1.endsWith(cell1), `the model's cell reaches Codex whole (a guard may lead it): ${delivered1.slice(-300)}`);

    // Turn 2: its result; the model answers with the cell of patches.
    history.push({ type: "custom_tool_call", call_id: "call_cell1", name: "exec", input: delivered1 });
    history.push({ type: "custom_tool_call_output", call_id: "call_cell1", output: [{ type: "input_text", text: "Script completed\nOutput:\n" }, { type: "input_text", text: "2 passing\n" }] });
    const second = await post(history);
    const delivered2 = deliveredCell(second);
    assert.ok(delivered2.endsWith(cell2), `the cell of patches reaches Codex whole: ${delivered2.slice(-300)}`);

    // Turn 3: its result; the model answers in words.
    history.push({ type: "custom_tool_call", call_id: "call_cell2", name: "exec", input: delivered2 });
    history.push({ type: "custom_tool_call_output", call_id: "call_cell2", output: [{ type: "input_text", text: "Script completed\nOutput:\n" }, { type: "input_text", text: "Success.\n" }] });
    await post(history);

    // The inspector's trace: each cell's step carries its patches' files.
    const ev = await waitFor("both cell steps in the trace", async () => {
      const r = await get(`events?session=${encodeURIComponent(session)}`);
      const steps = ((r.body["viewModel"] as { dualLanes?: { steps?: Step[] } } | undefined)?.dualLanes?.steps ?? []).filter((s) => s.step === "tool" && (s.callId === "call_cell1" || s.callId === "call_cell2"));
      return r.status === 200 && steps.length === 2 && steps.every((s) => s.patchFiles) ? { r, steps } : undefined;
    });
    const byCall = new Map(ev.steps.map((s) => [s.callId, s]));
    const s1 = byCall.get("call_cell1")!;
    assert.equal(s1.tool, "exec_command", "the cell's step keeps the command it ran");
    assert.deepEqual(JSON.parse(s1.input ?? "{}"), { cmd: "npm test", workdir: ws });
    assert.deepEqual(s1.patchFiles, [{ kind: "update", path: "src/config.ts" }, { kind: "add", path: "docs/setup.md" }]);
    const s2 = byCall.get("call_cell2")!;
    assert.equal(s2.tool, "apply_patch");
    assert.deepEqual(s2.patchFiles, [{ kind: "move", path: "src/a.ts", to: "src/b.ts" }, { kind: "delete", path: "old/legacy.ts" }], "the computed patch names nothing");
    // The records: each literal patch under its cell's id, as the model wrote it.
    const uses = ((ev.r.body["events"] ?? []) as Array<{ kind: string; callId?: string; input?: { symbolized?: string } }>).filter((e) => e.kind === "tool_use");
    const of = (id: string): string[] => uses.filter((e) => e.callId === id).map((e) => e.input?.symbolized ?? "");
    assert.deepEqual(of("call_cell1"), [
      `exec_command(${JSON.stringify({ cmd: "npm test", workdir: ws })})`,
      `apply_patch(${JSON.stringify({ input: patch1 })})`,
    ], "the placeholder stays the placeholder the model wrote");
    assert.deepEqual(of("call_cell2").map((u) => u.slice(0, u.indexOf("("))), ["apply_patch", "apply_patch"]);

    // The product's session page: each cell by what it did.
    const page = await waitFor("the session page's cell steps", async () => {
      const r = await get(`home/agent?session=${encodeURIComponent(session)}`);
      const said = ((r.body["story"] ?? []) as TurnWire[]).flatMap((t) => t.steps).filter((s) => s.kind === "action").map((s) => words(s.sentence));
      return r.status === 200 && said.some((w) => w.startsWith("Ran npm test")) && said.some((w) => w.startsWith("Moved ")) ? { r, said } : undefined;
    });
    assert.ok(page.said.includes("Ran npm test and edited config.ts, created setup.md"), page.said.join(" | "));
    assert.ok(page.said.includes("Moved a.ts to b.ts, deleted legacy.ts"), page.said.join(" | "));
    for (const w of page.said) assert.doesNotMatch(w, /a file|a command|Used exec/, `no cell step reads as an unnamed file, command or tool: ${page.said.join(" | ")}`);

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
