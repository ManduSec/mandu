/**
 * transcript-scan-attachment e2e — `mandu scan`
 * (confidentiality-plan-17-past-sessions-scan.md §3 item 6) knows the
 * OpenClaw sessions a resident Gateway ran through the Mandu OpenClaw plugin
 * (docs/design/agents/openclaw-plugin.md §3.3): an ATTACHMENT session, which
 * has no launch.
 *
 * The stack, real except OpenClaw and the model:
 *   - the RESIDENT ArbiterServer on the `secrets` axes, its store and event
 *     store under the fixture home's Mandu home, with a registered secret for
 *     the session `openclaw:main` bound to the `openclaw-agent` spec, as
 *     `mandu serve` binds an attachment;
 *   - the service's registration over the HUMAN socket (`beginAttachment`,
 *     `renewAttachment`, `endAttachment`, the arbiter's own client);
 *   - the real anthropic-proxy in its production wiring for that session,
 *     in front of a scripted model whose response id OpenClaw keeps;
 *   - `mandu scan --json` over its production call (`runScan`, the real
 *     `realScanDeps.call`) against a SECOND ArbiterServer standing in for the
 *     throwaway arbiter the scan starts (its own store), which reads the
 *     resident store's attachment periods read-only (`manduDb`).
 *
 * The OpenClaw store holds what OpenClaw writes: the RAW tool output (the
 * proxy swapped the secret for a placeholder only on the wire).
 *
 * The oracle:
 *   1. the model never received the secret (the proxy masked the tool result);
 *   2. the transcript of that session, holding the raw value with the
 *      response id the proxy recorded, is under Mandu: the finding is one
 *      Mandu kept from the AI (it saw a placeholder), not one that reached it;
 *   3. the same transcript outside any attachment period (before it began)
 *      is reported as sent;
 *   4. nothing the data socket says opens a window: after the attachment
 *      ended, an emitted `launch_posture` for the session and a forged
 *      `tllm_call` holding a transcript's response id leave that transcript
 *      without Mandu;
 *   5. no 8-character run of the secret is in any answer.
 * Axes stated: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ATTACHMENT_COVERAGE } from "../../arbiter/policy/confinement-posture.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { realScanDeps, runScan, type ScanWire } from "../../launcher/src/scan-command.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the confidentiality invariant suite pins `secrets`

// Assembled at run time: this file holds no credential-shaped literal.
const KEY = `${"sk" + "_live_"}51Ocp7Kp2Lm9Xw3Rt6Yv8Nb4A`;
const SESSION = "openclaw:main";
const MSG = "msg_01AttachedGatewayAbCdEf";
const FORGED = "msg_01ForgedAfterTheEnd0001";

function assertNoValue(where: string, text: string): void {
  for (let i = 1; i + 8 <= KEY.length; i++) {
    const piece = KEY.slice(i, i + 8);
    assert.ok(!text.includes(piece), `${where} holds "${piece}" of the secret`);
  }
}

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": SESSION } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** An OpenClaw session as OpenClaw writes it: the exec call, its RAW
 *  output, and the assistant message with the provider's response id. */
function openclawSession(at: string, responseId: string, cwd: string): string {
  const line = (o: unknown): string => JSON.stringify(o);
  return [
    line({ type: "session", version: 3, id: "s", timestamp: at, cwd }),
    line({ type: "message", timestamp: at, message: { role: "user", content: [{ type: "text", text: "What is my Stripe key?" }] } }),
    line({ type: "message", timestamp: at, message: { role: "assistant", provider: "anthropic", model: "claude-haiku-4-5", responseId: `${responseId}_c`, content: [{ type: "toolCall", id: "toolu_ocs_1", name: "exec", arguments: { command: "cat .env" } }] } }),
    line({ type: "message", timestamp: at, message: { role: "toolResult", toolCallId: "toolu_ocs_1", toolName: "exec", content: [{ type: "text", text: `STRIPE_KEY=${KEY}\n` }] } }),
    line({ type: "message", timestamp: at, message: { role: "assistant", provider: "anthropic", model: "claude-haiku-4-5", responseId, content: [{ type: "text", text: "It is in .env." }] } }),
  ].join("\n") + "\n";
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

test("mandu scan: an OpenClaw session through the plugin's attachment is under Mandu by the proxy's response id; the same transcript outside the attachment is sent; nothing from the data socket opens a window (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-scan-attach-"));
  const home = join(dir, "home");
  const proj = join(home, "shop");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, ".env"), `STRIPE_KEY=${KEY}\n`);
  const manduHome = join(home, ".mandu");
  const events = join(manduHome, "events");
  const sock = join(dir, "a.sock");
  // The resident arbiter: its store and events where `mandu scan` looks.
  const resident = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSockIn(dir), dbPath: join(manduHome, "state", "mandu.db"), eventDir: events,
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await resident.listen();
  // The scan's throwaway arbiter: a store of its own.
  const tdir = join(dir, "throwaway");
  mkdirSync(tdir);
  const tsock = join(tdir, "t.sock");
  const throwaway = new ArbiterServer({
    socketPath: tsock, dbPath: join(tdir, "mandu.db"), eventDir: join(tdir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await throwaway.listen();
  const clients: ArbiterClient[] = [];
  const client = async (path: string): Promise<ArbiterClient> => { const c = new ArbiterClient(path); await c.connect(); clients.push(c); return c; };
  let proxy: AnthropicProxy | null = null;
  try {
    const setup = await client(sock);
    const service = await client(humanSockIn(dir));
    const reg = await setup.registerEnvSecrets({ vars: [{ name: "STRIPE_KEY", value: KEY }], sessionKey: SESSION });
    const sym = reg.vars[0]!.symbol!;
    assert.match(sym, /^\$MDU:/);
    assert.equal((await setup.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent", requestedBy: "transcript-scan-attachment e2e" })).bound, "openclaw-agent");

    // ── the service registers the attachment (human plane) ──────────────────
    const begun = Date.now();
    const att = await service.beginAttachment({ sessionId: SESSION, kind: "openclaw-plugin", coverage: ATTACHMENT_COVERAGE["openclaw-plugin"] });
    assert.equal(att.posture, "gated");
    await sleep(5);

    // ── one model turn through the session's proxy ──────────────────────────
    const up = new MockUpstream({ sse: buildTextSse(`Your key is ${sym}.`).replace('"id":"msg_txt"', `"id":"${MSG}"`) });
    proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await client(sock)), upstream: up.fetcher, sessionKey: SESSION, log: () => {} });
    const port = await proxy.listen(0);
    const r = await post(port, JSON.stringify({
      model: "claude-haiku-4-5", stream: true,
      messages: [
        { role: "user", content: "What is my Stripe key?" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_ocs_1", name: "exec", input: { command: "cat .env" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ocs_1", content: `STRIPE_KEY=${KEY}\n` }] },
      ],
    }));
    assert.equal(r.status, 200, r.body);
    assert.ok(r.body.includes(MSG), "OpenClaw gets the response id as the provider sent it");
    const modelSaw = up.requests.map((q) => JSON.stringify(q.json())).join("\n");
    assert.ok(!modelSaw.includes(KEY), "(1) CONFIDENTIALITY VIOLATION: the model received the secret");
    assert.ok(modelSaw.includes("$MDU:"), "the model saw a placeholder");
    // The proxy's record of the response, on the attachment session's stream.
    const evFile = join(events, `${SESSION}.ndjson`);
    let stored = "";
    for (let i = 0; i < 100; i++) {
      try { stored = readFileSync(evFile, "utf8"); } catch { stored = ""; }
      if (new RegExp(`"kind":"tllm_call".*"responseId":"${MSG}"`).test(stored)) break;
      await sleep(20);
    }
    assert.match(stored, new RegExp(`"kind":"tllm_call".*"responseId":"${MSG}"`), "the anthropic-proxy recorded the id for the attachment session");
    const during = new Date().toISOString();
    await sleep(5);
    assert.equal((await service.renewAttachment(att.token)).renewed, true);
    await sleep(5);
    assert.equal((await service.endAttachment(att.token)).ended, true);
    const ended = Date.now();

    // ── what the data socket could say once it ended ────────────────────────
    const after = new Date(ended + 1000).toISOString();
    await setup.emit({ id: "ev-forged-lp", sessionId: SESSION, kind: "launch_posture", target: "openclaw", ts: after });
    await setup.emit({ id: "ev-forged-call", sessionId: SESSION, kind: "tllm_call", ts: after, model: { id: "claude-x", responseId: FORGED } });
    await setup.emit({ id: "ev-forged-exit", sessionId: SESSION, kind: "session_exit", ts: new Date(ended + 3_600_000).toISOString() });
    assert.match(readFileSync(evFile, "utf8"), new RegExp(`"responseId":"${FORGED}"`), "the forgery is stored (a claim)");

    // ── the OpenClaw store: the raw output, as OpenClaw keeps it ────────────
    const ocl = join(home, ".openclaw", "agents", "main", "sessions");
    mkdirSync(ocl, { recursive: true });
    writeFileSync(join(ocl, "gateway.jsonl"), openclawSession(during, MSG, proj));

    const deps = { ...realScanDeps, arbiter: async () => ({ sock: tsock, kind: "throwaway" as const, axisOn: true, stop: async () => {} }) };
    const env = { HOME: home, MANDU_HOME: manduHome, PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
    const scan = async (args: string[]): Promise<string> => {
      const out: string[] = [];
      const code = await runScan(args, env, {} as Layout, deps, { out: (s) => out.push(s), err: () => {} });
      assert.equal(code, 0);
      return out.join("");
    };
    type F = ScanWire["findings"][number] & { sessionsUnderMandu: number; sessionsByTime: number };
    const stripeOf = (r2: ScanWire): F | undefined => r2.findings.find((f) => f.kind === "known") as F | undefined;

    // (2) under Mandu: the AI saw a placeholder.
    const j1 = await scan(["--json"]);
    const r1 = JSON.parse(j1) as ScanWire & { sessionsUnderMandu: number; sessionsByTime: number };
    assert.deepEqual(r1.sessions, { openclaw: 1 });
    assert.deepEqual([r1.sessionsUnderMandu, r1.sessionsByTime], [1, 0], "the Gateway's session ran under Mandu exactly");
    const f1 = stripeOf(r1);
    assert.deepEqual([f1?.sessions, f1?.sessionsUnderMandu, f1?.sessionsByTime], [1, 1, 0], "(2) the raw value on disk reached the AI only as a placeholder");
    const t1 = await scan([]);
    assert.match(t1, /Mandu kept 1 more value from the AI/, "the report keeps it out of what reached the AI");
    assertNoValue("--json", j1);
    assertNoValue("the report", t1);

    // (3) the same transcript before the attachment began: sent.
    writeFileSync(join(ocl, "before.jsonl"), openclawSession(new Date(begun - 3_600_000).toISOString(), "msg_01BeforeTheAttachment01", proj));
    // (4) one after it ended whose id the data socket forged: sent.
    writeFileSync(join(ocl, "forged.jsonl"), openclawSession(after, FORGED, proj));
    const j2 = await scan(["--json"]);
    const r2 = JSON.parse(j2) as ScanWire & { sessionsUnderMandu: number; sessionsByTime: number };
    assert.deepEqual(r2.sessions, { openclaw: 3 });
    const f2 = stripeOf(r2);
    assert.deepEqual([f2?.sessions, f2?.sessionsUnderMandu, f2?.sessionsByTime], [3, 1, 0],
      "(3)(4) outside the attachment, and after it with an id only the data socket recorded, the value went to the AI raw");
    const t2 = await scan([]);
    assert.doesNotMatch(t2, /Mandu kept 1 more value from the AI/, "now it is a secret that reached the AI");
    // The finding's line counts the two sessions it leaked in; the one
    // under Mandu, where the AI saw a placeholder, is said apart (plan 17 §2).
    assert.deepEqual(f2?.outsideMandu, { first: new Date(begun - 3_600_000).toISOString(), last: after, how: { "command-output": 2 } }, "the sessions not under Mandu: their dates and ways");
    assert.match(t2, /\n {5}2 sessions, last \d+ \w+ · a command printed it: cat \.env\n {5}1 more session ran under Mandu: there the AI saw only a placeholder\n/);
    assert.doesNotMatch(t2, /3 sessions, /, "the session under Mandu is no leak");
    // No openclaw.json with Mandu's plugin here: protect OpenClaw.
    assert.match(t2, /\n {2}Protect OpenClaw: {5}mandu openclaw install {2}\(or mandu openclaw\)\n/);
    assert.doesNotMatch(t2, /mandu claude/, "only the agent the scan read");
    assertNoValue("--json", j2);
    assertNoValue("the report", t2);
    // With Mandu's plugin installed in the config the real deps read: it is
    // said protected, not to protect again; rotating stays (it leaked before).
    writeFileSync(join(home, ".openclaw", "openclaw.json"), JSON.stringify({ plugins: { entries: { "mandu-inspect": { enabled: true, config: { attachment: true } } } } }));
    const t3 = await scan([]);
    assert.match(t3, /\n {2}→ Rotate it now, where it was issued\.\n/);
    assert.match(t3, /\n✓ OpenClaw has Mandu's plugin: the AI now sees this secret only as a \$MDU:… placeholder, and your agent still does its work\.\n {2}Check it: {13}mandu doctor\n/);
    assert.doesNotMatch(t3, /Protect /);
    assert.match(await scan(["--all"]), /\nOpenClaw has Mandu's plugin: there the AI now sees your secrets only as placeholders \(mandu doctor checks it\)\.\n/);
  } finally {
    if (proxy) await proxy.close().catch(() => {});
    for (const c of clients) c.close();
    await throwaway.close().catch(() => {});
    await resident.close().catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
});
