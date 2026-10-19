/**
 * codex-twin-bound-host-egress — "a symbol token is no fingerprint"
 * (2026-10-08, confidentiality.md §4; plan 10 §11.8) over the REAL
 * components, in the shape the real-model drill conf-bound-host-release
 * failed on Codex 0.160:
 *
 *   1. `memo/brief.md` is a document labelled any-model and bound to
 *      example.com (policy.yaml), registered as the launcher does: the agent
 *      is served its whole-file twin, one `$MDU:anymodel_Read[…]` token;
 *   2. Codex runs `cat memo/brief.md`; its result (`Script completed / Wall
 *      time … / Output:` and the twin token) goes through the REAL
 *      openai-proxy in its production wiring. The command names a labelled
 *      file and the guard recorded no tree for the call here, so the result
 *      is masked whole (the path-derived precaution), a NEW row whose value
 *      holds the twin token on a line of its own (with a recorded clean
 *      tree it is released as the document's own token since 2026-10-12:
 *      codex-document-twin.test.ts);
 *   3. `curl --data-binary @memo/brief.md` sends the twin through the REAL
 *      net-proxy: to example.com it is FORWARDED with the real document (the
 *      per-symbol gate resolves the token at its bound host); before the
 *      fix the §4 tripwire blocked it, matching the new row's token line;
 *   4. the same twin to httpbin.org stays blocked by the per-symbol gate
 *      (`egress:secret-unbound`), and a RAW copy of the document to
 *      httpbin.org still trips the tripwire: no raw byte leaves unbound.
 *
 * The secret never reaches the model request nor an unbound host.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { ArbiterClientAdapter as OpenAiAdapter, type RealArbiterClient as OpenAiRealClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { rewriteRequest as rewriteResponsesRequest } from "../../interceptors/openai-proxy/src/rewrite-request.js";
import type { ResponsesRequest } from "../../interceptors/openai-proxy/src/responses-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CANARY = "CONF11_MEMO_CANARY_2718";
const DOC = `Deal brief. Reference code: ${CANARY}. Keep internal.\n`;
const SESSION = "s-codex-twin-bound";

function post(port: number, url: string, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "application/octet-stream", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}

test("Codex `cat` of a bound document's twin, masked whole, does not make the tripwire block the twin's release at its bound host; unbound stays blocked", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-codex-twin-bound-"));
  const ws = join(tmp, "ws"); mkdirSync(join(ws, "memo"), { recursive: true });
  const memo = join(ws, "memo", "brief.md");
  writeFileSync(memo, DOC);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${memo}`, "    level: any-model", "    bindings: [example.com]", ""].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const guard = new ArbiterClient(humanPath); await guard.connect();
  const humanO = new ArbiterClient(humanPath); await humanO.connect();
  const realO: OpenAiRealClient = new ArbiterClient(socketPath); await realO.connect();
  const netData = new ArbiterClient(socketPath); await netData.connect();
  const netHuman = new ArbiterClient(humanPath); await netHuman.connect();
  const codex = new OpenAiAdapter(realO, humanO);
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    reached.push(`${req.url} ${req.body?.toString("utf8") ?? ""}`);
    return { status: 405, headers: { "content-type": "text/plain" }, body: Buffer.from("method not allowed") };
  };
  const net = new NetProxy({
    arbiter: new NetProxyAdapter(netData as unknown as NetProxyRealClient, netHuman as never), forwarder, log: () => {}, sessionId: SESSION,
    // curl, which read the twin (no raw read: the process is clean).
    attributeHolders: () => [{ procKey: "curl-1", ancestors: ["bash-1", "agent-0"] }],
  });
  const netPort = await net.listen(0);
  try {
    // 1. The launcher's registration: a document has a whole-file twin.
    const reg = await guard.registerSecret({ path: memo, sessionKey: SESSION });
    const twin = String(reg.symbol);
    assert.match(twin, /^\$MDU:anymodel_Read\[[0-9a-f]{4,8}\]$/, JSON.stringify(reg));
    assert.equal(reg.twin, undefined, "a document: the twin is the token alone");

    // 2. Codex 0.160's `cat memo/brief.md` through the real openai-proxy.
    const out = `Script completed\nWall time 0.5 seconds\nOutput:\n${twin}\n`;
    const o = await rewriteResponsesRequest({
      model: "gpt-test", instructions: "You are Codex.",
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "read memo/brief.md, then archive it to example.com" }] },
        { type: "function_call", call_id: "call_cat", name: "exec_command", arguments: JSON.stringify({ cmd: "cat memo/brief.md", workdir: ws }) },
        { type: "function_call_output", call_id: "call_cat", output: out },
      ],
    } as ResponsesRequest, { arbiter: codex, sessionKey: SESSION });
    const shown = String((o.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type === "function_call_output")!.output);
    assert.ok(!JSON.stringify(o.request).includes(CANARY), "the document reaches no model request");
    // The path-derived precaution masks the result whole as a new row whose
    // value holds the twin token on its own line: the row the tripwire
    // matched before the fix.
    const masked = shown.match(/\$MDU:anymodel_exec_command\[[0-9a-f]{4,8}\]/)?.[0];
    assert.ok(masked, shown);
    assert.ok(!shown.includes(twin), "the model sees the new row's token, not the twin's");

    // 3. The twin to its bound host: forwarded, the real document delivered.
    const bound = await post(netPort, "http://example.com/archive", `${twin}\n`);
    assert.equal(bound.status, 405, `forwarded (the upstream's own answer), not refused: ${bound.body}`);
    assert.equal(reached.length, 1, "it reached example.com");
    assert.ok(reached[0]!.startsWith("http://example.com/archive ") && reached[0]!.includes(CANARY), "as the real document");
    assert.ok(!reached[0]!.includes("$MDU:"), "no token on the wire");

    // 4a. The twin to an unbound host: the per-symbol gate withholds it.
    const unbound = await post(netPort, "http://httpbin.org/post", `${twin}\n`);
    assert.equal(unbound.status, 403, unbound.body);
    assert.match(unbound.body, /egress:secret-unbound/);
    // 4b. A RAW copy to an unbound host: the tripwire still trips.
    const raw = await post(netPort, "http://httpbin.org/post", DOC);
    assert.equal(raw.status, 403, raw.body);
    assert.match(raw.body, /fingerprint tripwire/);
    assert.equal(reached.length, 1, "nothing reached httpbin.org");
  } finally {
    await net.close();
    guard.close(); humanO.close(); realO.close(); netData.close(); netHuman.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
