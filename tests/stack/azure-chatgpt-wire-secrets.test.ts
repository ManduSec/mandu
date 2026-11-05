/**
 * azure-chatgpt-wire-secrets — OpenClaw's `azure-openai-responses` and
 * `openai-chatgpt-responses` apis routed through the model proxy at
 * /_mandu/openai/<id> (model-wires.md §9), over the REAL arbiter, its REAL
 * IPC and the PRODUCTION proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock), humanPlane)`), against a scripted model (no key, no
 * network). `secrets` axes: the product default, stated.
 *
 * THE INVARIANT on the two ingresses: a registered secret in a tool result
 * reaches the model ONLY as its `$MDU:` placeholder:
 *   - Azure: POST …/responses?api-version=v1 with an `api-key`, the body as
 *     OpenClaw's AzureOpenAI client sends it;
 *   - ChatGPT: POST …/codex/responses with the body zstd-compressed, as
 *     OpenClaw's ChatGPT transport sends it for the built-in `openai`
 *     provider (the proxy reads it decoded and sends it decoded);
 * and fail-closed: with the arbiter gone, the proxy answers 502 and the model
 * receives nothing.
 *
 * The mock-arbiter version is
 * interceptors/anthropic-proxy/test/component/azure-chatgpt-route.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as zlib from "node:zlib";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";
import { confCanary, modelSawCanary, secretFileBody } from "../lib/conf-exfil.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

type Json = Record<string, unknown>;

const SYMBOL_RE = /^\$MDU:[a-z]+_[A-Za-z0-9_]+\[[0-9a-f]{4,8}\](?:\.[A-Za-z0-9_]+)*$/;
/** A masked `read` of a no-model file ends with the protected-file note (confidentiality.md §7.1, "A protected file read whole"): the symbol is what comes before it. */
const beforeNote = (s: string): string => {
  const at = s.indexOf("\n\n[mandu:secret] masked: ");
  if (at >= 0) assert.match(s.slice(at), /is a protected file that no AI model may read/, "the note says what the symbol is");
  return at < 0 ? s : s.slice(0, at);
};
const zstd = (zlib as unknown as Record<string, ((b: Buffer) => Buffer) | undefined>)["zstdCompressSync"];
const JWT = `e30.${Buffer.from(JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: "acct-mandu" } })).toString("base64url")}.sig`;

function send(port: number, path: string, body: Buffer, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(body.length), ...headers } },
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

const answer = `data: ${JSON.stringify({ type: "response.created", response: { id: "r1" } })}\n\n`
  + `data: ${JSON.stringify({ type: "response.output_text.delta", item_id: "m", output_index: 0, delta: "ok" })}\n\n`
  + `data: ${JSON.stringify({ type: "response.completed", response: { id: "r1", output: [] } })}\n\n`;

/** One Responses turn: the model called `read`, the tool answered `output`. */
const turn = (path: string, output: string, extra: Json): Json => ({
  input: [
    { role: "user", content: [{ type: "input_text", text: "look at the project" }] },
    { type: "function_call", call_id: "call_r", name: "read", arguments: JSON.stringify({ path }) },
    { type: "function_call_output", call_id: "call_r", output },
  ],
  stream: true,
  store: false,
  tools: [{ type: "function", name: "read", parameters: { type: "object" }, strict: false }],
  ...extra,
});

const forwardedOutput = (up: MockUpstream): string => String(((up.requests[0]!.json() as Json)["input"] as Json[])[2]!["output"]);

test("secrets: a registered secret in a tool result reaches the Azure and the ChatGPT model only as its placeholder (the ChatGPT body zstd-compressed); the arbiter gone, nothing is sent", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-azure-chatgpt-wire-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "vault"), { recursive: true });
  const canary = confCanary("AZCG");
  const vault = join(ws, "vault", "partner.env");
  const fileBody = secretFileBody(canary);
  writeFileSync(vault, fileBody);

  const sock = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: join(ws, "vault"), level: "no-model", recursive: true }] } as never,
  });
  await server.listen();
  const launcher = new ArbiterClient(sock);
  const real = new ArbiterClient(sock);
  const humanPlane = new ArbiterClient(join(tmp, "human", "h.sock"));
  await Promise.all([launcher.connect(), real.connect(), humanPlane.connect()]);
  const sessionKey = `azure-chatgpt-wire-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  const ups: MockUpstream[] = [];
  const through = async (id: string, base: string, path: string, body: Buffer, headers: Record<string, string>): Promise<{ up: MockUpstream; status: number }> => {
    const up = new MockUpstream({ sse: answer });
    ups.push(up);
    const proxy = new AnthropicProxy({
      // THE PRODUCTION WIRING: the adapter over the real clients, no bridge.
      arbiter: new ArbiterClientAdapter(real, humanPlane),
      upstream: async () => { throw new Error("the Anthropic upstream was called"); },
      sessionKey,
      log: () => {},
      openaiUpstreams: { [id]: base },
      openaiFetcher: () => up.fetcher,
    });
    proxies.push(proxy);
    const r = await send(await proxy.listen(0), path, body, headers);
    return { up, status: r.status };
  };
  try {
    const bound = await real.setSessionSpec({ sessionKey, spec: "openclaw-agent", requestedBy: "azure-chatgpt-wire-secrets e2e" });
    assert.equal(bound.bound, "openclaw-agent");
    const reg = await launcher.registerSecret({ path: vault, home, sessionKey });
    assert.ok(typeof (reg.twin ?? reg.symbol) === "string", `registered: ${reg.reason}`);

    // Azure: the AzureOpenAI client's path, query and key header.
    const az = await through("azure", "https://res.openai.azure.com/openai/v1", "/_mandu/openai/azure/responses?api-version=v1",
      Buffer.from(JSON.stringify(turn(vault, fileBody, { model: "gpt-5-deploy", prompt_cache_key: "s" }))), { "api-key": "azure-test-not-real" });
    assert.equal(az.status, 200);
    assert.equal(az.up.requests[0]!.path, "/responses?api-version=v1");
    assert.match(beforeNote(forwardedOutput(az.up)), SYMBOL_RE, `Azure: the read reaches the model as its placeholder: ${forwardedOutput(az.up)}`);

    // ChatGPT: the zstd body to /codex/responses, the OAuth bearer as sent.
    if (zstd) {
      const body = turn(vault, fileBody, { model: "gpt-5.5", instructions: "You are OpenClaw.", include: ["reasoning.encrypted_content"], text: { verbosity: "low" } });
      const cg = await through("openai", "https://chatgpt.com/backend-api/codex", "/_mandu/openai/openai/responses", zstd(Buffer.from(JSON.stringify(body))), {
        "content-encoding": "zstd", authorization: `Bearer ${JWT}`, "chatgpt-account-id": "acct-mandu", originator: "openclaw",
      });
      assert.equal(cg.status, 200);
      assert.equal(cg.up.requests[0]!.path, "/responses", "the SDK transport's /responses below the /codex base");
      assert.equal(cg.up.requests[0]!.headers["content-encoding"], undefined, "sent decoded");
      assert.equal(cg.up.requests[0]!.headers["authorization"], `Bearer ${JWT}`, "the OAuth bearer passes as sent");
      assert.match(beforeNote(forwardedOutput(cg.up)), SYMBOL_RE, `ChatGPT: the read reaches the model as its placeholder: ${forwardedOutput(cg.up)}`);
    }

    // THE ORACLE over every request the models received.
    assert.equal(modelSawCanary(ups.flatMap((u) => u.requests.map((r) => ({ body: r.bodyText }))), canary), false, "no request to either model carries the secret");

    // Fail-closed: the arbiter gone, the proxy refuses and sends nothing.
    real.close();
    humanPlane.close();
    await server.close();
    const d = await through("azure", "https://res.openai.azure.com/openai/v1", "/_mandu/openai/azure/responses?api-version=v1",
      Buffer.from(JSON.stringify(turn(vault, fileBody, { model: "gpt-5-deploy" }))), { "api-key": "azure-test-not-real" });
    assert.equal(d.status, 502, "the arbiter unreachable: 502");
    assert.equal(d.up.requests.length, 0, "INVARIANT: nothing reaches the model when the arbiter is gone");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    for (const cl of [launcher, real, humanPlane]) cl.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
