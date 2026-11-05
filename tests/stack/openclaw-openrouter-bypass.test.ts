/**
 * openclaw-openrouter-bypass — OpenClaw's openrouter bypass under the wrapper
 * (`mandu openclaw`), end to end (supported-agents.md §2.1, "The openrouter
 * bypass"). A SECURITY REGRESSION closed 2026-10-25.
 *
 * THE BYPASS. OpenClaw 2026.3.12 and 2026.3.13 resolve an openrouter model
 * that neither their catalog nor `models.providers.openrouter.models` knows
 * to a model whose baseUrl is `https://openrouter.ai/api/v1`, whatever the
 * provider's baseUrl (measured on 2026.3.12 with a recording proxy: the turn
 * left as `CONNECT openrouter.ai:443` through HTTPS_PROXY; on 2026.9.9 it
 * reached the routed provider). Under the wrapper, whose launch check judged
 * providers and not models, a configured openrouter model OpenClaw does not
 * know sent the whole model request (the conversation, the raw tool results)
 * around Mandu's model proxy.
 *
 * Two legs, over the production code:
 *   the fence  the run config the launcher writes (`writeAgentConfig`, the
 *              user's openclaw.json with such a model as its primary and an
 *              allowlist key of another) for OpenClaw 2026.3.12, resolved by
 *              a transcription of 2026.3.12's resolveModelWithRegistry with
 *              no catalog entry: every model the run can reach (configured,
 *              and every allowlist key a mid-session switch may pick) goes
 *              to the proxy's route; the control (the same config without
 *              the fence, as on 2026.9.9, where it is not needed) goes to
 *              openrouter.ai under the same resolution;
 *   the net    the request that would have gone to openrouter.ai, sent as
 *              OpenClaw sends it (through HTTPS_PROXY, OpenClaw's
 *              EnvHttpProxyAgent), at a REAL NetProxy on its TLS-inspected
 *              leg with the launcher's model-service list, mock-sites routing
 *              openrouter.ai to a loopback HTTPS recorder (the oracle), a
 *              REAL arbiter with a value registered as the launcher
 *              registers it (`applyEnvSecrets`): a tool result carrying the
 *              raw value is refused and nothing reaches openrouter.ai; one
 *              carrying only its placeholder leaves with the placeholder,
 *              never the value. What the egress proxy cannot see is text it
 *              holds no value for (a labelled file's content the model proxy
 *              would have masked): that is why the fence, not the egress
 *              gate, is the guarantee.
 *
 * Made-up secrets. No OpenClaw runs here (the real-OpenClaw leg is the
 * plugin lane's 2026.3.12 test). SKIP without openssl (no session CA).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { applyEnvSecrets, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { PROVIDER_KEY_HOSTS } from "../../launcher/src/agent-key-grant.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import { writeAgentConfig } from "../../launcher/src/services/agent-config.js";
import { Layout } from "../../launcher/src/services/layout.js";
import type { LaunchPlan, Ullm } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the built-in default: confidentiality ON, integrity OFF

type Json = Record<string, any>;

const OPENSSL = opensslAvailable();
const OPENROUTER_BASE = "https://openrouter.ai/api/v1";
const PROXY = { host: "127.0.0.1", port: 48123 };
const ROUTE_URL = `http://${PROXY.host}:${PROXY.port}/_mandu/openai/openrouter`;
const ULLM: Ullm = { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" };
const STRIPE = "sk_" + "live_51OpenrouterBypassValue7Hq2Lm9Zx";

/**
 * Where OpenClaw 2026.3.12 sends a model (resolveModelWithRegistry,
 * pi-embedded-runner/model.ts of the published package), for a model no
 * catalog holds (`modelRegistry.find` misses, no forward-compat template):
 * an inline model of the provider (`models.providers.<p>.models`, with an
 * `api`) carries the provider's baseUrl; else an openrouter model is
 * OpenClaw's own, at openrouter.ai; else the provider's baseUrl.
 */
function openclaw312Destination(doc: Json, ref: string): string | undefined {
  const slash = ref.indexOf("/");
  const provider = ref.slice(0, slash).trim().toLowerCase();
  const raw = ref.slice(slash + 1).trim();
  const modelId = provider === "openrouter" && !raw.includes("/") ? `openrouter/${raw}` : raw;
  const providers: Json = doc["models"]?.["providers"] ?? {};
  const key = Object.keys(providers).find((k) => k.trim().toLowerCase() === provider);
  const cfg: Json | undefined = key !== undefined ? providers[key] : undefined;
  const inline = (cfg?.["models"] ?? []).find((m: Json) => m?.["id"] === modelId);
  if (inline && (inline["api"] ?? cfg?.["api"])) return cfg?.["baseUrl"];
  if (provider === "openrouter") return OPENROUTER_BASE;
  return cfg?.["baseUrl"];
}

/** Every model a run config lets OpenClaw run: its primary and fallbacks,
 *  and every key of its allowlist (selectable mid-session). */
function reachable(doc: Json): string[] {
  const d = doc["agents"]?.["defaults"] ?? {};
  const m = d["model"];
  return [...new Set([
    ...(typeof m === "string" ? [m] : [m?.["primary"], ...(m?.["fallbacks"] ?? [])]).filter((x: unknown) => typeof x === "string"),
    ...Object.keys(d["models"] ?? {}).filter((k) => !k.startsWith("anthropic/")),
  ])];
}

test("the wrapper's run config for OpenClaw 2026.3.12 sends every openrouter model it can reach (configured, or picked mid-session from the allowlist) to the proxy's route; without the fence the same config goes to openrouter.ai", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-or-bypass-cfg-"));
  try {
    const userCfg = join(dir, "openclaw.json");
    writeFileSync(userCfg, JSON.stringify({
      models: { providers: { openrouter: { baseUrl: OPENROUTER_BASE, api: "openai-completions", apiKey: "sk-or-v1-made-up", models: [] } } },
      agents: { defaults: { model: { primary: "openrouter/mandu/unknown-model" }, models: { "openrouter/mandu/other": { alias: "other" } } } },
    }));
    const write = (agentVersion: string, sub: string): Json => {
      const plan = {
        target: "openclaw", argv: ["openclaw", "gateway"], cwd: "/w", scopeId: `sid-or-${sub}`, tenant: "live", proxy: PROXY, writeMcp: false,
        arbiterSock: "/s", ullm: ULLM, agentVersion,
        openaiRoutes: [{ id: "openrouter", api: "openai-completions", upstream: OPENROUTER_BASE }],
      } as unknown as LaunchPlan;
      const out = join(dir, sub);
      return JSON.parse(readFileSync(writeAgentConfig(plan, Layout.dev("/repo"), out, () => {}, { OPENCLAW_CONFIG_PATH: userCfg }).path, "utf8"));
    };
    const fenced = write("2026.3.12", "old");
    const models = reachable(fenced);
    assert.deepEqual(models.sort(), ["openrouter/mandu/other", "openrouter/mandu/unknown-model"], "the allowlist names no openrouter wildcard");
    for (const m of models) {
      assert.equal(openclaw312Destination(fenced, m), ROUTE_URL, `SECURITY: ${m} must go to Mandu's proxy route on OpenClaw 2026.3.12, not around it`);
    }
    // The control: the config the launcher writes where the fence is not
    // needed (2026.9.9 honours the baseUrl) has the bypass shape under
    // 2026.3.12's resolution: the primary and the wildcard go to openrouter.ai.
    const unfenced = write("2026.9.9", "new");
    assert.equal(openclaw312Destination(unfenced, "openrouter/mandu/unknown-model"), OPENROUTER_BASE);
    assert.ok("openrouter/*" in unfenced["agents"].defaults.models);
    assert.equal(openclaw312Destination(unfenced, "openrouter/*"), OPENROUTER_BASE, "on 2026.3.12 an allowlist wildcard is the model `*`");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

interface Got { url: string; headers: IncomingMessage["headers"]; body: string }

async function httpsRecorder(dir: string, host: string, got: Got[]) {
  const ca = ensureCa(join(dir, `ca-${host}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      got.push({ url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"choices":[{"message":{"role":"assistant","content":"ok"}}]}');
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** What OpenClaw's EnvHttpProxyAgent does for https://openrouter.ai: CONNECT
 *  through HTTPS_PROXY, TLS (here trusting the session CA, as the launch's
 *  NODE_EXTRA_CA_CERTS makes OpenClaw do), one POST. */
function postThroughProxy(proxyPort: number, host: string, sessionCa: string, path: string, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      head = Buffer.concat([head, c]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      raw.off("data", onData);
      const status = head.subarray(0, idx).toString("latin1").split("\r\n")[0]!;
      if (!/ 200 /.test(`${status} `)) {
        raw.destroy();
        resolve({ status: Number(/HTTP\/1\.1 (\d{3})/.exec(status)?.[1] ?? 0), body: "" });
        return;
      }
      const tls = tlsConnect({ socket: raw, servername: host, ca: sessionCa }, () => {
        const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join("");
        tls.write(`POST ${path} HTTP/1.1\r\nHost: ${host}\r\n${lines}Content-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      });
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0), body: text });
      });
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("request timed out")), 8000).unref();
  });
}

/** OpenClaw 2026.3.12's Chat Completions request for a turn whose tool ran:
 *  the conversation, the tool call, its result as OpenClaw keeps it. */
function turnBody(toolResult: string): string {
  return JSON.stringify({
    model: "mandu/unknown-model", stream: true,
    messages: [
      { role: "system", content: "You are a personal assistant running inside OpenClaw." },
      { role: "user", content: "read the billing config and tell me the key" },
      { role: "assistant", content: null, tool_calls: [{ id: "call1", type: "function", function: { name: "read", arguments: "{\"path\":\"billing.env\"}" } }] },
      { role: "tool", tool_call_id: "call1", content: toolResult },
    ],
    tools: [{ type: "function", function: { name: "read", parameters: { type: "object" } } }],
  });
}

test("a request that went to openrouter.ai around the model proxy crosses the egress proxy: a raw registered value is refused and nothing reaches openrouter.ai; a placeholder leaves as it is, never the value", { skip: OPENSSL ? false : "openssl unavailable", timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-or-bypass-net-"));
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  await data.connect();
  await human.connect();
  const got: Got[] = [];
  const openrouter = await httpsRecorder(dir, "openrouter.ai", got);
  const sites = MockSites.fromYaml([
    "hosts:",
    "  - host: openrouter.ai", `    to: 127.0.0.1:${openrouter.port}`, `    tls_to: 127.0.0.1:${openrouter.port}`, `    tls_ca: ${JSON.stringify(openrouter.caPath)}`,
    "",
  ].join("\n"));
  // The session's egress proxy as the launcher starts it: TLS inspection on
  // (the default with confidentiality on), the launcher's model-service list
  // (services/net-proxy.ts MANDU_NET_PROXY_MODEL_SERVICES), which names
  // openrouter.ai.
  assert.ok(Object.values(PROVIDER_KEY_HOSTS).includes("openrouter.ai"), "openrouter.ai is one of the launch's model services");
  const proxy = new NetProxy({
    allowThisMachine: true, arbiter: new ArbiterClientAdapter(data as unknown as RealArbiterClient, human as unknown as RealArbiterClient), log: () => {}, sessionId: "s-or-bypass",
    mockSites: sites, mitm: { caDir: join(dir, "mitm") }, modelServices: Object.values(PROVIDER_KEY_HOSTS),
    attributeHolders: () => [{ procKey: "7500-1", ancestors: [] }],
  });
  const port = await proxy.listen(0);
  try {
    // A secret registered as the launcher registers the launch's env.
    const plan = { target: "openclaw", confidentiality: true, noContextProxy: true, arbiterHumanSock: humanSock, scopeId: "s-or-bypass" } as unknown as LaunchPlan;
    const mut = emptyMutation();
    await applyEnvSecrets(plan, { PATH: process.env["PATH"], STRIPE_SECRET_KEY: STRIPE }, mut, { arbiter: socketSecretArbiter(sock), log: () => {} });
    const placeholder = mut.env["STRIPE_SECRET_KEY"]!;
    assert.match(placeholder, /^\$MDU:/, "the value is registered and masked for the launch");

    const ca = readFileSync(join(dir, "mitm", "mandu-egress-ca.pem"), "utf8");
    const auth = { Authorization: "Bearer sk-or-v1-made-up", "HTTP-Referer": "https://openclaw.ai", "X-Title": "OpenClaw" };

    // The bypass as it was: OpenClaw keeps the raw tool result, so the
    // request carries the value itself. Refused before any dial.
    const raw = await postThroughProxy(port, "openrouter.ai", ca, "/api/v1/chat/completions", auth, turnBody(`STRIPE_SECRET_KEY=${STRIPE}\n`));
    assert.equal(raw.status, 403, `SECURITY REGRESSION: a raw registered value reached openrouter.ai past the egress proxy: ${raw.body}`);
    assert.equal(got.length, 0, "nothing reached openrouter.ai");

    // A body holding only the placeholder leaves (a model service reads
    // placeholders as written), and never with the value.
    const masked = await postThroughProxy(port, "openrouter.ai", ca, "/api/v1/chat/completions", auth, turnBody(`STRIPE_SECRET_KEY=${placeholder}\n`));
    assert.equal(masked.status, 200, masked.body);
    assert.equal(got.length, 1);
    assert.equal(got[0]!.url, "/api/v1/chat/completions");
    assert.ok(got[0]!.body.includes(placeholder), "the placeholder left as written");
    for (const g of got) assert.ok(!JSON.stringify(g).includes(STRIPE), "CONFIDENTIALITY VIOLATION: the registered value reached openrouter.ai");
  } finally {
    await proxy.close();
    openrouter.close();
    data.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
