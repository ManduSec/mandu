/**
 * openclaw-gateway-token-env e2e — OpenClaw's Gateway token under `mandu
 * openclaw`: ONE stable placeholder, over the PRODUCTION wiring (the
 * launcher's applyEnvSecrets and pinRunConfigGatewayCredentials, its socket
 * adapter, a real ArbiterServer, then the real model proxy;
 * confidentiality-plan-10-flow-taint.md §11.4, "OpenClaw's Gateway
 * credentials: one stable placeholder").
 *
 * OPENCLAW_GATEWAY_TOKEN authenticates OpenClaw's processes to each other: a
 * `mandu openclaw agent` client and the `mandu openclaw gateway run` it talks
 * to are two launches, and both must hold the same value. Each launch masks
 * the variable and writes the same placeholder over the token in its run
 * config, so:
 *   - two launches get the SAME placeholder (the arbiter mints an
 *     environment secret once per value, not per session), and so does a
 *     launch after the arbiter restarts (the row is in Mandu's state);
 *   - another value gets another placeholder, and a placeholder says
 *     nothing about its value;
 *   - the raw token is in no launch's environment nor run config;
 *   - it stays registered: a model request carrying it (the agent ran
 *     `env`, or read the user's own openclaw.json) reaches the model only as
 *     that placeholder;
 *   - any other target masks the variable as before.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { applyEnvSecrets, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { pinRunConfigGatewayCredentials } from "../../launcher/src/openclaw-gateway-credentials.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON: the axis this registration serves

const TOKEN = "ocgw-7f3c9a1e5b2d8c4f6a0e9b1d3c5f7a2e";
const OTHER = "ocgw-0d9e8c7b6a5f4e3d2c1b0a9f8e7d6c5b";

function post(port: number, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-api-key": "sk-ant-test" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    r.on("error", reject);
    r.end(body);
  });
}

function arbiter(dir: string): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSockIn(dir),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
}

/** One `mandu openclaw` launch's two steps: the environment mask, then the
 *  run config's credentials. The placeholder in each place. */
async function launch(dir: string, n: string, token: string): Promise<{ env: string | undefined; auth: string; remote: string; config: string }> {
  const sock = join(dir, "a.sock");
  const mut = emptyMutation();
  await applyEnvSecrets({ confidentiality: true, target: "openclaw" } as LaunchPlan, { PATH: process.env["PATH"], OPENCLAW_GATEWAY_TOKEN: token }, mut, {
    arbiter: socketSecretArbiter(sock), log: () => {},
  });
  const config = join(dir, `run-${n}.json`);
  writeFileSync(config, JSON.stringify({ gateway: { port: 18789, auth: { mode: "token", token }, remote: { token } } }), { mode: 0o600 });
  await pinRunConfigGatewayCredentials(config, { arbiter: socketSecretArbiter(sock), log: () => {} });
  const doc = JSON.parse(readFileSync(config, "utf8")) as { gateway: { auth: { token: string }; remote: { token: string } } };
  return { env: mut.env["OPENCLAW_GATEWAY_TOKEN"], auth: doc.gateway.auth.token, remote: doc.gateway.remote.token, config: readFileSync(config, "utf8") };
}

test("under `mandu openclaw` every launch holds ONE stable placeholder for the Gateway token, in its environment and its run config; the raw token is in neither and reaches the model only as that placeholder (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-ocgwtok-"));
  let server = arbiter(dir);
  await server.listen();
  const upstream = await startScriptedAnthropic({ script: [], fallbackText: "OK" });
  let proxy: AnthropicProxy | null = null;
  const clients: ArbiterClient[] = [];
  try {
    // The Gateway's launch and a client's launch.
    const gw = await launch(dir, "gateway", TOKEN);
    const client = await launch(dir, "client", TOKEN);
    assert.match(gw.env ?? "", /^\$MDU:nomodel_Env\[[0-9a-f]+\]\.OPENCLAW_GATEWAY_TOKEN$/, "the environment holds the placeholder");
    for (const l of [gw, client]) {
      assert.equal(l.auth, gw.env, "the run config's gateway.auth.token is the same placeholder");
      assert.equal(l.remote, gw.env, "and gateway.remote.token");
      assert.ok(!l.config.includes(TOKEN), "the raw token is in no run config");
      assert.ok(l.env !== TOKEN);
    }
    assert.equal(client.env, gw.env, "the client's launch holds the Gateway's placeholder: the token check passes");
    // The placeholder says nothing about the value: the arbiter's random
    // symbol name (symbol-table.ts allocateSymbol), the variable's name.
    assert.ok(!gw.env!.includes(TOKEN.slice(5, 13)), "the placeholder carries no piece of the value");
    // Another value, another placeholder.
    const other = await launch(dir, "other", OTHER);
    assert.notEqual(other.env, gw.env);
    // Stable per machine: after the arbiter restarts, the same placeholder.
    await server.close();
    server = arbiter(dir);
    await server.listen();
    const later = await launch(dir, "later", TOKEN);
    assert.equal(later.env, gw.env, "the placeholder is kept in Mandu's state across an arbiter restart");
    assert.equal(later.auth, gw.env);

    // The value stays registered: a model request carrying it (the agent ran
    // `env`) reaches the model only as the placeholder.
    const data = new ArbiterClient(join(dir, "a.sock"));
    const human = new ArbiterClient(humanSockIn(dir));
    clients.push(data, human);
    await data.connect();
    await human.connect();
    assert.equal((await data.setSessionSpec({ sessionKey: "s-ocgw", spec: "openclaw-agent", requestedBy: "openclaw-gateway-token-env e2e" })).bound, "openclaw-agent");
    proxy = new AnthropicProxy({
      arbiter: new ArbiterClientAdapter(data, human), upstreamOrigin: upstream.origin, sessionKey: "s-ocgw",
      identity: { service: "anthropic-proxy", sessionKey: "s-ocgw", arbiterSock: join(dir, "a.sock"), viewMap: [] }, log: () => {},
    });
    const port = await proxy.listen(0);
    const body = JSON.stringify({
      model: "claude-test", stream: true, max_tokens: 64,
      messages: [
        { role: "user", content: "what is in the environment?" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_env", name: "exec", input: { command: "env" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_env", content: `HOME=/home/u\nOPENCLAW_GATEWAY_TOKEN=${TOKEN}\nPATH=/usr/bin\n` }] },
      ],
    });
    assert.equal(await post(port, body), 200);
    const sent = upstream.requests.filter((q) => q.url.includes("/v1/messages")).map((q) => q.body).join("\n");
    assert.ok(sent.length > 0, "the request reached the model");
    assert.ok(!sent.includes(TOKEN), "CONFIDENTIALITY VIOLATION: the Gateway token reached the model");
    assert.ok(sent.includes(`OPENCLAW_GATEWAY_TOKEN=${gw.env}`), "the model saw the same stable placeholder");

    // Any other target: the variable masked as ever.
    const mut = emptyMutation();
    await applyEnvSecrets({ confidentiality: true, target: "opencode" } as LaunchPlan, { OPENCLAW_GATEWAY_TOKEN: TOKEN }, mut, { arbiter: socketSecretArbiter(join(dir, "a.sock")), log: () => {} });
    assert.equal(mut.env["OPENCLAW_GATEWAY_TOKEN"], gw.env);
  } finally {
    await proxy?.close();
    await upstream.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
