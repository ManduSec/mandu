/**
 * model-token-env.test.ts — a declared local model's bearer token
 * (policy.yaml `models[].token_env`, confidentiality-plan-11 D2) reaches that
 * model with its REAL value, while the agent's environment carries it masked.
 *
 * The gap this pins (found 2026-09-28): Claude Code hands its own environment
 * to an MCP server (verified on 2.1.283), and the launcher's env-secret mask
 * replaces a token-shaped variable there with its symbol, so inspect-mcp sent
 * the placeholder and the model server refused every call. The launcher now
 * names the token in the inspect-mcp entry's own env (which Claude Code lays
 * over its environment), and the arbiter registers every declared token as a
 * secret whatever its name, bound to its model's host.
 *
 * PRODUCTION wiring end to end: the launcher's own mask (`applyEnvSecrets`
 * over `socketSecretArbiter`), its endpoint read (`readModelEndpoints`), its
 * MCP entry builder (`inspectMcpConfigDoc`), inspect-mcp's adapter over the
 * real `ArbiterClient` and its production endpoint factory, one real
 * ArbiterServer, and a recording OpenAI-chat server as the local model.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { inspectSymbol } from "../../interceptors/inspect-mcp/src/inspect-symbol.js";
import { ArbiterClientAdapter as InspectArbiterAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { createEndpointUllmFactory } from "../../interceptors/inspect-mcp/src/ullm-config.js";
import { MockUllm } from "../../interceptors/inspect-mcp/test/helpers/mock-ullm.js";
import { applyEnvSecrets, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { localModelTokens, readModelEndpoints } from "../../launcher/src/model-endpoints.js";
import { inspectMcpConfigDoc } from "../../launcher/src/services/mcp.js";
import { Layout } from "../../launcher/src/services/layout.js";
import type { LaunchMutation, LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON (the mask runs), integrity OFF

const REPO = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const TOKEN = "tok-local-model-REAL-7d1e";
const DOC = "Board minutes: acquire Initech for 18M. TOKEN_ENV_CANARY";

interface Wire { url: string; auth: string[]; bodies: string[]; close: () => Promise<void> }

/** An OpenAI-chat server (as Ollama speaks) that answers only the real token. */
async function ownModel(): Promise<Wire> {
  const auth: string[] = [];
  const bodies: string[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      auth.push(String(req.headers["authorization"] ?? ""));
      bodies.push(body);
      if (req.headers["authorization"] !== `Bearer ${TOKEN}`) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ model: "llama3.2", choices: [{ message: { role: "assistant", content: "An 18M acquisition." } }] }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    auth, bodies,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

test("production wiring: the agent's environment carries the token masked, and the declared local model receives the real one", async () => {
  const own = await ownModel();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-token-env-"));
  const sock = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath: sock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: {
      version: 1,
      // OLLAMA_BEARER matches no built-in secret-name shape: only the
      // declaration makes it a secret.
      models: [{ name: "own", url: own.url, wire: "openai-chat", model: "llama3.2", local: true, token_env: "OLLAMA_BEARER" }],
      paths: [{ path: "/h/notes/minutes.md", level: "local-model" }],
    },
  });
  await arbiter.listen();
  const minter = new ArbiterClient(sock);
  await minter.connect();
  const inspectClient = new ArbiterClient(sock);
  await inspectClient.connect();
  try {
    // 1. The launcher's own mask over the launcher's own environment.
    const launcherEnv = { OLLAMA_BEARER: TOKEN, SHELL: "/bin/bash" };
    const mut: LaunchMutation = { env: {}, argvPrefix: [], launchPrefix: [] };
    const plan = { confidentiality: true } as unknown as LaunchPlan;
    const masked = await applyEnvSecrets(plan, launcherEnv, mut, { arbiter: socketSecretArbiter(sock), log: () => {} });
    assert.deepEqual(masked.masked, ["OLLAMA_BEARER"], "the declared token is masked in the agent's environment");
    assert.match(mut.env["OLLAMA_BEARER"]!, /^\$MDU:nomodel_Env\[/);
    assert.ok(!Object.values(mut.env).includes(TOKEN), "the real token is nowhere in the agent's environment");

    // 2. The launcher's endpoint read and MCP entry, as run.ts builds them.
    const read = await readModelEndpoints(sock);
    assert.equal(read.status, "ok");
    const entry = inspectMcpConfigDoc({
      arbiterSock: sock, scopeId: "token-env-e2e",
      ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
      modelEndpoints: read.endpoints,
      modelTokens: localModelTokens(read.endpoints, launcherEnv),
    }, Layout.dev(REPO)).mcpServers["mandu-inspect"]!;
    assert.equal(entry.env["OLLAMA_BEARER"], TOKEN);

    // 3. The server's environment as Claude Code composes it: its own (the
    //    agent's, masked) with the entry's env laid over.
    const agentEnv = { ...launcherEnv, ...mut.env };
    const serverEnv = { ...agentEnv, ...entry.env };
    const deps = (env: Record<string, string>) => ({
      arbiter: new InspectArbiterAdapter(inspectClient),
      ullm: new MockUllm({ reply: "unused", model: "claude-haiku-mock" }),
      sessionId: "token-env-e2e",
      endpointUllm: createEndpointUllmFactory(env),
    });
    const doc = await minter.symbolizeFull({ tool: "Read", value: DOC, field: "content", origin: "/h/notes/minutes.md" });
    assert.match(doc.symbol, /^\$MDU:localmodel_Read\[/);

    const out = await inspectSymbol(deps(serverEnv), { symbol: doc.symbol, instruction: "Summarize." });
    assert.equal(out.ok, true, `the local model answered (${(out as { error?: string }).error ?? ""})`);
    assert.deepEqual(own.auth, [`Bearer ${TOKEN}`], "one call, with the real token");
    assert.ok(own.bodies[0]!.includes("TOKEN_ENV_CANARY"), "and the document");

    // The counterfactual this pins: the agent's environment alone (no entry
    // env) sends the placeholder, and the helper refuses, never falls back.
    const bare = await inspectSymbol(deps(agentEnv), { symbol: doc.symbol, instruction: "Summarize." });
    assert.equal(bare.ok, false, "the masked token is refused by the model");
    assert.match(own.auth[1] ?? "", /^Bearer \$MDU:nomodel_Env\[/, "what the entry's env replaces");
  } finally {
    inspectClient.close();
    minter.close();
    await arbiter.close();
    await own.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
