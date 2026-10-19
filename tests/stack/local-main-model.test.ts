/**
 * e2e — plan 11 phase 3 across the real components, in PRODUCTION wiring
 * (docs/design/confidentiality/model-endpoints.md §1.7.1):
 * the launcher's own `bindSessionUpstream` records each session's main model
 * on a real ArbiterServer; the real model proxy (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`, as its server-main builds it) forwards to a declared
 * model served under a base path over a real HTTP socket; inspect-mcp's
 * production adapter asks for the in-context read.
 *
 * What it pins:
 *   - ingress still masks for a LOCAL main model: the labeled document reaches
 *     it only as `$MDU:localmodel_` (phase 3 opens rung 3, nothing else);
 *   - rung 3 hands the bytes back only to the session bound to the declared
 *     local model, and the handling prompt each session receives says which;
 *   - the upstream base path reaches the model server;
 *   - a claim made from inside the agent after the launcher's binding is
 *     refused and changes nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter as ProxyAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { ArbiterClientAdapter as InspectAdapter } from "../../interceptors/inspect-mcp/src/arbiter-client.js";
import { bindSessionUpstream } from "../../launcher/src/model-endpoints.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const BODY = "Board minutes: the Acme deal closes at $4,200,000. MAIN_MODEL_CANARY";
const CANARY = "MAIN_MODEL_CANARY";

interface Captured { path: string; body: string }

/** A model server under a base path: records every request, answers one text turn. */
async function modelServer(): Promise<{ url: string; seen: Captured[]; close: () => Promise<void> }> {
  const seen: Captured[] = [];
  const srv: Server = createServer((req, res) => {
    let b = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      seen.push({ path: req.url ?? "", body: b });
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(buildTextSse("ok", { deltas: 1 }));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/anthropic`;
  return { url, seen, close: () => new Promise<void>((r) => srv.close(() => r())) };
}

function post(port: number, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** The agent Reads the labeled document (the shape the proxy must mask). */
function readTurn(path: string): string {
  return JSON.stringify({
    model: "claude-opus-4",
    stream: true,
    system: "You are Claude Code.",
    tools: [{ name: "mcp__mandu-inspect__inspect_symbol" }, { name: "Read" }],
    messages: [
      { role: "user", content: "Summarize the board minutes." },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_mm1", name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_mm1", content: BODY }] },
    ],
  });
}

function systemText(body: string): string {
  const sys = (JSON.parse(body) as { system?: unknown }).system;
  if (typeof sys === "string") return sys;
  return Array.isArray(sys) ? (sys as Array<{ text?: string }>).map((b) => b.text ?? "").join("\n") : "";
}

test("a declared local main model: masked at ingress, rung 3 opens for its session only, base path reaches the server", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-main-model-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "notes"), { recursive: true });
  const minutes = join(home, "notes", "minutes.md");
  writeFileSync(minutes, BODY + "\n");
  const mine = await modelServer();
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
    policyDocument: {
      version: 1,
      models: [{ name: "mine", url: mine.url, wire: "anthropic", local: true }],
      paths: [{ path: minutes, level: "local-model" }],
    } as never,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const client = async (): Promise<ArbiterClient> => {
    const c = new ArbiterClient(socketPath);
    await c.connect();
    clients.push(c);
    return c;
  };
  const proxies: AnthropicProxy[] = [];
  try {
    // The launcher's own call, before any service starts (run.ts).
    const bLocal = await bindSessionUpstream(socketPath, "s-local", "mine");
    assert.equal(bLocal.status, "ok", JSON.stringify(bLocal));
    assert.equal(bLocal.location, "local");
    const bVendor = await bindSessionUpstream(socketPath, "s-vendor", null);
    assert.equal(bVendor.status, "ok", JSON.stringify(bVendor));
    assert.equal(bVendor.location, "external");

    // One proxy per session, exactly as the launcher starts it: the local
    // session's upstream is the declared URL (base path included).
    const proxyFor = async (sessionKey: string, upstreamOrigin: string): Promise<number> => {
      const p = new AnthropicProxy({ arbiter: new ProxyAdapter(await client()), upstreamOrigin, sessionKey, log: () => {} });
      proxies.push(p);
      return p.listen(0);
    };
    const localPort = await proxyFor("s-local", mine.url);
    assert.equal(await post(localPort, readTurn(minutes)), 200);
    assert.equal(mine.seen.length, 1);
    assert.equal(mine.seen[0]!.path, "/anthropic/v1/messages", "the base path reaches the model server");
    const localBody = mine.seen[0]!.body;
    assert.ok(!localBody.includes(CANARY), "ingress masks for a local main model too: phase 3 opens rung 3, nothing else");
    const minted = localBody.match(/\$MDU:localmodel_Read\[[0-9a-f]+\]/)?.[0];
    assert.ok(minted, "the document reached the model as a localmodel_ token");
    assert.match(systemText(localBody), /`declassify_symbol` works for this level here/);

    const vendorPort = await proxyFor("s-vendor", mine.url);
    assert.equal(await post(vendorPort, readTurn(minutes)), 200);
    const vendorBody = mine.seen[1]!.body;
    assert.ok(!vendorBody.includes(CANARY));
    assert.match(systemText(vendorBody), /`declassify_symbol` is refused\*\* for this level/);

    // Rung 3 through inspect-mcp's production adapter. A TRUSTED datum, so
    // only the level and the session's main model decide.
    const data = await client();
    const inspect = new InspectAdapter(await client());
    const mint = async (sessionKey: string) => (await data.symbolizeFull({
      tool: "Read", value: BODY, field: "content", origin: minutes, integrity: "trusted", sessionKey,
    })).symbol;
    const local = await inspect.declassify({ symbol: await mint("s-local"), sessionKey: "s-local" });
    assert.equal(local.allowed, true, local.reason);
    assert.equal(local.value, BODY);
    const vendor = await inspect.declassify({ symbol: await mint("s-vendor"), sessionKey: "s-vendor" });
    assert.equal(vendor.allowed, false);
    assert.equal(vendor.value, null, "the default vendor's session never gets the bytes");
    assert.match(vendor.reason, /readable only by the user's own model/);

    // A process inside the vendor session claims the local model: refused,
    // through the production client and through the launcher's own function.
    await assert.rejects(data.setSessionUpstream({ sessionKey: "s-vendor", endpoint: "mine", requestedBy: "agent" }), /bind-once/);
    assert.equal((await bindSessionUpstream(socketPath, "s-vendor", "mine")).status, "refused");
    const again = await inspect.declassify({ symbol: await mint("s-vendor"), sessionKey: "s-vendor" });
    assert.equal(again.value, null, "the claim changed nothing");
  } finally {
    for (const p of proxies) await p.close();
    for (const c of clients) c.close();
    await arbiter.close();
    await mine.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
