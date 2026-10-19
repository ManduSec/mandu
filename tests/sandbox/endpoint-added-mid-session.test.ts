/**
 * endpoint-added-mid-session.test.ts — a `local: true` model declared in
 * policy.yaml AFTER launch fails closed
 * (docs/design/confidentiality/model-endpoints.md §1 D5, §8 item 5).
 *
 * The launcher reads `models:` once, at launch, and fixes the inspect-mcp
 * network confine's port set from that list (launcher/src/inspect-net-confine.ts,
 * the whole-agent wraps likewise). inspect-mcp re-reads the list per call, so
 * after a hot edit that declares a new local endpoint it routes a
 * `$MDU:localmodel_…` input there, and the kernel refuses the connect. The
 * answer must be a refusal naming the endpoint, with nothing sent to the
 * default U-LLM (external) and nothing reaching the new endpoint.
 *
 * Real components: an ArbiterServer reading a policy FILE (hot reload), the
 * launcher's own `readModelEndpoints` + `planInspectNetConfine` (the real bin
 * resolution and kernel probe), and `inspect_symbol` in production wiring run
 * as a child process under the written prefix
 * (tests/fixtures/inspect-under-confine.fixture.ts). The control runs the same
 * child without the prefix: the call succeeds and the endpoint gets the
 * document, so the refusal is the confine's.
 *
 * Kernel-gated: self-SKIPs without the mandu-landlock-apply bin or Landlock
 * TCP rules (kernel < 6.7), like launcher/test/kernel/inspect-mcp-confine.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { pollDiskApproving } from "../../arbiter/test/held-disk.js";
import { planInspectNetConfine } from "../../launcher/src/inspect-net-confine.js";
import { readModelEndpoints } from "../../launcher/src/model-endpoints.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // local-model is a confidentiality level (the default mode's axis)

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(PKG_ROOT, "fixtures", "inspect-under-confine.fixture.ts");
const DOC = "/h/notes/minutes.md";
const CONTRACT = "Board minutes: acquire Initech for 18M. LATE_ENDPOINT_CANARY";
const CANARY = "LATE_ENDPOINT_CANARY";

const law = (models: string): string => ["version: 1", models, "paths:", `  - { path: ${DOC}, level: local-model }`, ""].join("\n");

interface Wire { url: string; port: number; bodies: string[]; connections: () => number; close: () => Promise<void> }

async function openAiChatServer(): Promise<Wire> {
  const bodies: string[] = [];
  let connections = 0;
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      bodies.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "llama3.2", choices: [{ message: { role: "assistant", content: "An 18M acquisition." } }] }));
    });
  });
  server.on("connection", () => { connections++; });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  return { url: `http://127.0.0.1:${port}`, port, bodies, connections: () => connections, close: () => new Promise<void>((r) => server.close(() => r())) };
}

interface ChildOut { ok: boolean; error?: string; resultSymbol?: string; defaultCalls: number }

/** Run the fixture (async: the arbiter answering it lives in THIS process). */
function inspectInChild(prefix: string[], sock: string, symbol: string): Promise<ChildOut> {
  const argv = [...prefix, process.execPath, "--import", "tsx", FIXTURE];
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0]!, argv.slice(1), {
      cwd: PKG_ROOT,
      // No proxy variables: a fetch through a proxy would hide the connect.
      env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: process.env["HOME"] ?? "/tmp", MANDU_ARBITER_SOCK: sock, INSPECT_SYMBOL: symbol },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr.on("data", (d: Buffer) => (err += d.toString()));
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`fixture timed out; stderr:\n${err}`)); }, 60_000);
    child.on("error", (e) => { clearTimeout(timer); reject(e); });
    child.on("close", (code) => {
      clearTimeout(timer);
      const line = out.trim().split("\n").pop() ?? "";
      if (code !== 0 || line === "") { reject(new Error(`fixture exited ${code}; stderr:\n${err}`)); return; }
      resolve(JSON.parse(line) as ChildOut);
    });
  });
}

test("a local endpoint declared after launch is refused by the launch-time confine; nothing reaches it or the default U-LLM", async (t) => {
  const late = await openAiChatServer();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-late-endpoint-"));
  const file = join(tmp, "policy.yaml");
  writeFileSync(file, law("")); // launched with no models: declared
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: file, policyPollMs: 0,
  });
  await arbiter.listen();
  const c = new ArbiterClient(sock);
  await c.connect();
  try {
    // ── the launch: the launcher's own read and the real confine decision ──
    const read = await readModelEndpoints(sock);
    assert.equal(read.status, "ok");
    assert.deepEqual(read.endpoints, [], "nothing declared at launch");
    const notes: string[] = [];
    const confine = planInspectNetConfine({ modelEndpoints: read.endpoints }, { log: (m) => notes.push(m) });
    if (confine === null) { t.skip(`the inspect-mcp confine degraded on this host: ${notes.join(" | ")}`); return; }
    assert.deepEqual(confine.ports, [443], "the confine holds only the default U-LLM's port");
    const prefix = confine.wrapArgv;

    const minted = await c.symbolizeFull({ tool: "Read", value: CONTRACT, field: "content", origin: DOC });
    assert.match(minted.symbol, /^\$MDU:localmodel_Read\[/);

    // ── mid-session: the user declares their own model ──
    writeFileSync(file, law(`models:\n  - { name: late, url: "${late.url}", wire: openai-chat, model: llama3.2, local: true }`));
    const when = new Date(Date.now() + 5_000);
    utimesSync(file, when, when);
    // Declaring a model relaxes the law, so the edit is held until approved
    // (policy-surface.md §8.4.6); approved here as the Inbox would.
    assert.equal(pollDiskApproving(arbiter), true, "the edit was reloaded");
    assert.deepEqual((await c.modelEndpoints()).map((e) => [e.name, e.local]), [["late", true]], "inspect-mcp will see the new endpoint");

    // ── under the launch-time confine: refused, nothing sent anywhere ──
    const confined = await inspectInChild(prefix, sock, minted.symbol);
    assert.equal(confined.ok, false, "refused");
    assert.match(confined.error ?? "", /your declared model 'late' did not answer \(U-LLM request could not reach the endpoint \(EACCES\)\)/, confined.error);
    assert.match(confined.error ?? "", /it was not sent to any other model\. This is by design/);
    assert.ok(!(confined.error ?? "").includes(CANARY), "the refusal carries no bytes");
    assert.equal(confined.defaultCalls, 0, "nothing fell back to the default U-LLM");
    assert.equal(late.connections(), 0, "the kernel refused the connect: the endpoint saw no connection");
    assert.equal(late.bodies.length, 0);

    // ── control: the same call without the confine reaches the endpoint ──
    const bare = await inspectInChild([], sock, minted.symbol);
    assert.equal(bare.ok, true, `unconfined, the call is admitted (${bare.error ?? ""})`);
    assert.match(bare.resultSymbol ?? "", /^\$MDU:localmodel_/);
    assert.equal(bare.defaultCalls, 0);
    assert.ok(late.bodies.some((b) => b.includes(CANARY)), "so the refusal above was the confine's");
  } finally {
    c.close();
    await arbiter.close();
    await late.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
