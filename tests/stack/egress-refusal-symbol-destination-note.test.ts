/**
 * egress-refusal-symbol-destination-note — confidentiality plan 10 §11.8,
 * "A placeholder as the destination" (2026-10-17), over the REAL
 * components: a program asks the REAL net-proxy to CONNECT to a host that
 * is a Mandu placeholder (the agent wrote `curl https://$MDU:…/`). The proxy
 * refuses it as before (403, no tunnel, nothing dialed) and now reports the
 * refusal on the arbiter's human plane under its own kind,
 * `symbol-destination`: by process when it can tie the connection to one,
 * as unattributed when it cannot. The tool call's result then carries a
 * `refused:` line, through both model proxies in their PRODUCTION wiring,
 * that says the destination was a placeholder and names neither the host
 * nor the symbol. The secret's value reaches no destination and no model.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { connect as netConnect } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import type { ProcHolder } from "../../interceptors/net-proxy/src/conn-attr.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { ArbiterClientAdapter as OpenAiAdapter, type RealArbiterClient as OpenAiRealClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteResponsesRequest } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

function connectThrough(port: number, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(port, "127.0.0.1", () => sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let got = "";
    sock.on("data", (d) => { got += d.toString("utf8"); });
    sock.on("close", () => resolve(got));
    sock.on("error", reject);
  });
}

const WORDS = "its destination was a Mandu placeholder ($MDU:…), and Mandu never turns a placeholder into a host to connect to. Do not retry with a placeholder as the host: write the host itself, and use the placeholder only where the secret's value belongs (a header or the body). If the host itself is the secret, tell the user.";

test("a CONNECT to a placeholder host refused by the real net-proxy: both model proxies say so (attributed and not), naming no host and no symbol", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-egress-refusal-symdest-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  const canary = `symdest-${randomBytes(16).toString("hex")}`;
  writeFileSync(env, `API_HOST=${canary}\n`);
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
  const session = "s-egress-refusal-symdest";
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    reached.push(req.url);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  let holders: ProcHolder[] = [];
  const net = new NetProxy({
    arbiter: new NetProxyAdapter(netData, netHuman as never), forwarder, log: () => {}, sessionId: session,
    attributeHolders: () => holders,
  });
  const netPort = await net.listen(0);
  try {
    const reg = await guard.registerSecret({ path: env, sessionKey: session });
    const symbol = String(reg.symbol);
    assert.match(symbol, /^\$MDU:/, JSON.stringify(reg));

    const cmd = `curl -s https://${symbol}/`;
    const run = async (callId: string, root: string, attributed: boolean): Promise<void> => {
      await guard.recordCallCommand({ callId, command: cmd, sessionKey: session });
      await guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", cmd], session, callRoot: true });
      await guard.recordExecRoot({ procKey: `${root}-curl`, parentKey: root, argv: ["/usr/bin/curl", "-s", `https://${symbol}/`], session });
      holders = attributed ? [{ procKey: `${root}-curl`, ancestors: [root, "agent-0"] }] : [];
      const answer = await connectThrough(netPort, `${symbol}:443`);
      assert.match(answer, /^HTTP\/1\.1 403/, `the real net-proxy refuses the placeholder host: ${answer}`);
    };
    const curlSays = "curl: (56) CONNECT tunnel failed, response 403\n";

    // Claude: the proxy tied the connection to curl.
    await run("toolu_symdest", "bash-a", true);
    const a = await rewriteRequest({
      model: "claude-test",
      messages: [
        { role: "user", content: "fetch it" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_symdest", name: "Bash", input: { command: cmd } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_symdest", content: curlSays }] },
      ],
    } as MessagesRequest, { arbiter: claude, sessionKey: session });
    const ca = String((a.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
    assert.equal(ca, `${curlSays}\n\n[mandu:secret] refused: curl tried to connect out and Mandu refused the connection, nothing was sent: ${WORDS}`);

    // Codex: the proxy could tie it to no process.
    await run("call_symdest", "bash-o", false);
    const o = await rewriteResponsesRequest({
      model: "gpt-test", instructions: "You are Codex.",
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "fetch it" }] },
        { type: "function_call", call_id: "call_symdest", name: "exec_command", arguments: JSON.stringify({ cmd }) },
        { type: "function_call_output", call_id: "call_symdest", output: `Chunk ID: 1a2b\nWall time: 0.2 seconds\nProcess exited with code 56\nOutput:\n${curlSays}` },
      ],
    } as ResponsesRequest, { arbiter: codex, sessionKey: session });
    const co = String((o.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
    assert.ok(co.includes(`[mandu:secret] refused: a connection out was refused while this command ran, and nothing was sent; Mandu could not tell which program opened it, so it may not be this command's: ${WORDS}`), co);

    for (const [who, text] of [["claude", ca], ["codex", co]] as const) {
      const note = text.slice(text.indexOf("[mandu:secret]"));
      assert.ok(!note.includes(symbol) && !/\$MDU:[A-Za-z_]/.test(note), `${who}: the note carries no symbol token`);
      assert.ok(!text.includes(canary), `${who}: no secret`);
    }
    assert.ok(!JSON.stringify(a.request).includes(canary) && !JSON.stringify(o.request).includes(canary), "the secret reaches no model request");
    assert.deepEqual(reached, [], "nothing was dialed");
  } finally {
    await net.close();
    guard.close(); humanA.close(); realA.close(); realO.close(); netHuman.close(); (netData as unknown as ArbiterClient).close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
