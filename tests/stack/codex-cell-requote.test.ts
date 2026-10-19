/**
 * codex-cell-requote — a Codex code-mode cell's `tools.exec_command` literal
 * is requoted like Codex's `exec_command` function call (confidentiality.md
 * §7, "A placeholder the agent's shell would expand"), over the REAL arbiter
 * and the openai-proxy's PRODUCTION wiring, `secrets` axes.
 *
 * The literal is the same tool run by the same shell, so a secret
 * placeholder the model writes in double quotes or bare inside it reaches
 * the program as `Bearer :nomodel_…` unless it is requoted. The proxy splices
 * the requoted literal back into the cell as JSON, so the inserted `'` and
 * `\` are re-encoded inside the JavaScript string. Proven here by running the
 * DELIVERED cell: it parses as JavaScript, its exec_command receives the
 * requoted command, and that command, run by bash and zsh, prints the
 * placeholder whole; the cell as the model wrote it does not (the control).
 * A hand-written JavaScript literal (`{cmd: '…'}`) is normalized and requoted
 * the same way. The key never reaches a model request; the model reads back
 * its own cell (exec-history.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import vm from "node:vm";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy, type UpstreamFetcher } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { buildScriptCellSse } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SHELLS = ["bash", "zsh"].filter((s) => spawnSync(s, ["-c", "exit 0"], { stdio: "ignore" }).status === 0);
const USER = { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] };
const BATTERY = {
  type: "additional_tools", role: "developer",
  tools: [{ type: "namespace", name: "functions", tools: [
    { type: "custom", name: "exec", description: "Run JavaScript code\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." },
    { type: "function", name: "wait" },
  ] }],
};

/** Run a cell as Codex's code-mode host would: an async module whose
 *  `tools.exec_command` runs `cmd` in `shell`. Returns the commands it ran
 *  and what it printed (`text`). A cell that does not parse throws. */
async function runCell(src: string, shell: string): Promise<{ cmds: string[]; text: string }> {
  const cmds: string[] = [];
  let text = "";
  const tools = {
    exec_command: async (args: { cmd: string }) => {
      cmds.push(args.cmd);
      const r = spawnSync(shell, ["-c", args.cmd], { encoding: "utf8", env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: tmpdir() } });
      return { output: `${r.stdout}${r.stderr}` };
    },
  };
  const ctx = vm.createContext({ tools, text: (s: string) => { text += s; } });
  await (new vm.Script(`(async () => {\n${src}\n})()`).runInContext(ctx) as Promise<void>);
  return { cmds, text };
}

function deliveredCell(sse: string): string {
  for (const block of sse.split("\n\n")) {
    const line = block.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    const obj = JSON.parse(line.slice(5).trim()) as { type?: string; item?: { type?: string; input?: string } };
    if (obj.type === "response.output_item.done" && obj.item?.type === "custom_tool_call") return String(obj.item.input);
  }
  throw new Error("no custom_tool_call in the delivered stream");
}

test("a code cell's exec_command literal is requoted: the delivered cell parses, and its command prints the placeholder whole in bash and zsh (secrets axes, production wiring)", { skip: SHELLS.length === 0 ? "neither bash nor zsh is installed" : false }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cell-requote-"));
  const proj = join(tmp, "proj"); mkdirSync(proj);
  const envFile = join(proj, ".env");
  const KEY = `sk_live_cell_${randomBytes(12).toString("hex")}`;
  writeFileSync(envFile, `STRIPE_KEY=${KEY}\n`);
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    adminPolicyDir: null, packDir: null,
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
    policyDocument: { version: 1, paths: [{ path: envFile, level: "no-model", bindings: ["api.stripe.test"] }] },
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (p: string): Promise<ArbiterClient> => { const c = new ArbiterClient(p); await c.connect(); clients.push(c); return c; };
  const requests: string[] = [];
  let sse = "";
  const upstream: UpstreamFetcher = async ({ body }) => {
    requests.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new OpenAiProxy({
    arbiter: new ArbiterClientAdapter((await open(socketPath)) as unknown as RealArbiterClient, (await open(humanPath)) as never),
    upstream, sessionKey: "codex-cell-requote", log: () => {},
  });
  const port = await proxy.listen(0);
  const post = async (input: unknown[]): Promise<string> => {
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-6.1-sol", stream: true, input }),
    });
    assert.equal(res.status, 200);
    return res.text();
  };
  try {
    const reg = await (await open(socketPath)).registerSecret({ path: envFile });
    assert.ok(reg.twin, reg.reason);
    const P = /STRIPE_KEY='?(\$MDU:[^'\s]+)/.exec(reg.twin!)![1]!;

    const cases: Array<{ id: string; cell: string; requoted: string }> = [
      // the observed shape: a JSON literal, the placeholder in double quotes
      { id: "call_dq", cell: `const r = await tools.exec_command(${JSON.stringify({ cmd: `echo "Bearer ${P}"`, workdir: proj, yield_time_ms: 10000 })});\ntext(r.output);\n`, requoted: `echo "Bearer \\${P}"` },
      // a hand-written JavaScript literal, the placeholder bare
      { id: "call_js", cell: `const r = await tools.exec_command({cmd: 'echo Bearer ${P}', yield_time_ms: 10000});\ntext(r.output);\n`, requoted: `echo Bearer '${P}'` },
    ];
    for (const c of cases) {
      sse = buildScriptCellSse({ input: c.cell, callId: c.id });
      const delivered = deliveredCell(await post([BATTERY, USER]));
      assert.notEqual(delivered, c.cell, `${c.id}: the cell was rewritten`);
      for (const shell of SHELLS) {
        const ran = await runCell(delivered, shell); // throws if the delivered cell does not parse
        assert.deepEqual(ran.cmds, [c.requoted], `${c.id}: the literal's command is the requoted one`);
        assert.equal(ran.text, `Bearer ${P}\n`, `${c.id}/${shell}: the program receives the placeholder whole`);
        const asWritten = await runCell(c.cell, shell);
        assert.notEqual(asWritten.text, `Bearer ${P}\n`, `${c.id}/${shell}: the control loses it as written`);
      }
      // Codex echoes the delivered cell: the model reads back its own
      await post([BATTERY, USER, { type: "custom_tool_call", call_id: c.id, name: "exec", input: delivered },
        { type: "custom_tool_call_output", call_id: c.id, output: [{ type: "input_text", text: "Script completed\nWall time 0.1 seconds\nOutput:\n" }, { type: "input_text", text: "ok\n" }] }]);
      const sent = (JSON.parse(requests[requests.length - 1]!) as { input: Array<Record<string, unknown>> }).input;
      assert.equal(sent.find((i) => i["type"] === "custom_tool_call")!["input"], c.cell, `${c.id}: the model reads back the cell it wrote`);
    }
    for (const r of requests) assert.ok(!r.includes(KEY), "the key never reaches a model request");
  } finally {
    await proxy.close().catch(() => {});
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
