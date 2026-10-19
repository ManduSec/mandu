/**
 * host-binding-parity — ONE binding rule across the arbiter and the net-proxy
 * (confidentiality.md §2.2, `arbiter/policy/host-bindings.ts`).
 *
 * Until 2026-10-11 four matchers disagreed: the egress gate read
 * `*.amazonaws.com` as a literal name (it released nothing) and ignored
 * ports (`db.internal:5432` released at any port), the holder join read a
 * bare host as that host only, and the net-proxy let `*.x` admit `x`.
 *
 *   1. The net-proxy keeps its own copy (it does not import the arbiter):
 *      the text below the marker is the arbiter's to the character, and one
 *      case table answers the same through both.
 *   2. Over the REAL components (an ArbiterServer reading a policy FILE; the
 *      REAL net-proxy in its production wiring, a recording forwarder as the
 *      oracle), a secret bound to `*.example.test` reaches api.example.test
 *      and never example.test nor evil-example.test; one bound to
 *      `db.example.test:8443` reaches that port only.
 *   3. A raw holder of a file bound to `*.example.test` and one bound to
 *      `example.test` may send under example.test but not to it (the join by
 *      the same rule; it was nowhere before).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import * as arbiterRule from "../../arbiter/policy/host-bindings.js";
import * as proxyRule from "../../interceptors/net-proxy/src/host-bindings.js";
import { hostIsBound } from "../../interceptors/net-proxy/src/egress.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..");
const MARKER = "// ── the rule: identical in both copies below this line";

test("the net-proxy's copy of the rule is the arbiter's, below the marker", () => {
  const body = (rel: string): string => {
    const text = readFileSync(join(ROOT, rel), "utf8");
    const at = text.indexOf(MARKER);
    assert.ok(at >= 0, `${rel} carries the marker`);
    return text.slice(at);
  };
  assert.equal(body("interceptors/net-proxy/src/host-bindings.ts"), body("arbiter/policy/host-bindings.ts"),
    "edit arbiter/policy/host-bindings.ts and copy the text below the marker to the net-proxy's");
});

test("one case table answers the same through both copies and the proxy's hostIsBound", () => {
  const bindings = ["example.test", "*.example.test", "example.test:8443", "*.example.test:8443", "10.1.2.3", "[::1]:443", "10.0.0.0/8", "unix:/run/x", "*", "",
    "[2001:DB8::1]:8443", "[2001:db8:0::1]", "[fe80::1%eth0]"];
  const destinations = ["example.test", "api.example.test", "a.b.example.test", "evil-example.test", "api.example.test:8443", "api.example.test:443",
    "https://api.example.test:8443/x", "10.1.2.3", "10.1.2.3:80", "[::1]:443", "[::1]:80", "EXAMPLE.TEST.", "",
    "[2001:db8::1]", "[2001:db8:0:0::1]:8443", "https://[2001:DB8::1]:8443/simple", "[2001:db8::2]:8443", "[fe80::1%eth0]", "[fe80::1]"];
  for (const b of bindings) {
    for (const d of destinations) {
      const want = arbiterRule.bindingAdmits(d, b);
      assert.equal(proxyRule.bindingAdmits(d, b), want, `${JSON.stringify(b)} admits ${JSON.stringify(d)}`);
      assert.equal(hostIsBound(d, [b]), want, `the proxy's hostIsBound: ${JSON.stringify(b)} admits ${JSON.stringify(d)}`);
    }
    for (const o of bindings) assert.equal(proxyRule.bindingCovers(o, b), arbiterRule.bindingCovers(o, b), `${o} covers ${b}`);
  }
});

/** A plain-HTTP POST through the forward proxy; the status and the proxy's body. */
function post(port: number, url: string, auth: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, authorization: `Bearer ${auth}`, "content-length": 0 } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end();
  });
}

const WILD = "sk_live_fake_HOSTRULE_WILD_51c2e0";
const PORTED = "sk_live_fake_HOSTRULE_PORT_88a1f4";
const APEX = "sk_live_fake_HOSTRULE_APEX_0d93b7";
const SESSION = "s-host-binding-parity";

test("over the real gate and proxy: *.x releases under x only, a :port only there, and a holder's join by the same rule", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-host-rule-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const wild = join(ws, "wild.env");
  const ported = join(ws, "ported.env");
  const apex = join(ws, "apex.env");
  writeFileSync(wild, `WILD_KEY=${WILD}\n`);
  writeFileSync(ported, `PORT_KEY=${PORTED}\n`);
  writeFileSync(apex, `APEX_KEY=${APEX}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, [
    "version: 1",
    "paths:",
    `  - path: ${wild}`,
    "    level: no-model",
    "    readers: [ssh-add]",
    '    bindings: ["*.example.test"]',
    `  - path: ${ported}`,
    "    level: no-model",
    '    bindings: ["db.example.test:8443"]',
    `  - path: ${apex}`,
    "    level: no-model",
    "    readers: [ssh-add]",
    "    bindings: [example.test]",
    "",
  ].join("\n"));
  const sock = join(tmp, "a.sock");
  const humanSock = join(tmp, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const human = new ArbiterClient(humanSock); await human.connect();
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    reached.push(`${req.url} ${JSON.stringify(req.headers)}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  const clients: ArbiterClient[] = [human];
  const proxy = async (procKey: string): Promise<{ net: NetProxy; port: number }> => {
    const data = new ArbiterClient(sock); await data.connect();
    const netHuman = new ArbiterClient(humanSock); await netHuman.connect();
    clients.push(data, netHuman);
    const net = new NetProxy({
      arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, netHuman as never), forwarder, log: () => {}, sessionId: SESSION,
      attributeHolders: () => [{ procKey, ancestors: ["bash-1", "agent-0"] }],
    });
    return { net, port: await net.listen(0) };
  };
  const clean = await proxy("curl-clean");
  const holder = await proxy("holder-both");
  try {
    const wildSym = `${String((await human.registerSecret({ path: wild, sessionKey: SESSION })).symbol)}.WILD_KEY`;
    const portSym = `${String((await human.registerSecret({ path: ported, sessionKey: SESSION })).symbol)}.PORT_KEY`;
    assert.ok((await human.registerSecret({ path: apex, sessionKey: SESSION })).symbol);

    const send = async (port: number, symbol: string, url: string, value: string | null, why: string) => {
      const before = reached.length;
      const r = await post(port, url, symbol);
      if (value !== null) {
        assert.equal(r.status, 200, `${why}: ${r.body}`);
        assert.equal(reached.length, before + 1, `${why}: reached`);
        assert.ok(reached.at(-1)!.includes(value), `${why}: the real value arrived`);
      } else {
        assert.equal(r.status, 403, `${why}: refused (${r.body})`);
        assert.equal(reached.length, before, `${why}: nothing reached the host`);
      }
      for (const s of [WILD, PORTED, APEX]) assert.ok(!r.body.includes(s), `${why}: the answer carries no secret`);
    };

    // 2. `*.example.test`: under it, never it, never a look-alike.
    await send(clean.port, wildSym, "http://api.example.test/v1", WILD, "*.example.test at api.example.test");
    await send(clean.port, wildSym, "http://a.b.example.test/v1", WILD, "*.example.test two labels down");
    await send(clean.port, wildSym, "http://example.test/v1", null, "*.example.test at example.test itself");
    await send(clean.port, wildSym, "http://evil-example.test/v1", null, "*.example.test at a look-alike");
    // `db.example.test:8443`: that port only.
    await send(clean.port, portSym, "http://db.example.test:8443/v1", PORTED, "a :8443 binding at :8443");
    await send(clean.port, portSym, "http://db.example.test:9443/v1", null, "a :8443 binding at another port");
    for (const r of reached) {
      assert.ok(!(r.startsWith("http://db.example.test:9443") && r.includes(PORTED)), "no byte at the wrong port");
      assert.ok(!(r.startsWith("http://example.test/") && r.includes(WILD)), "no byte at the apex");
    }

    // 3. A raw holder of both files: only where both may go, under example.test.
    for (const path of [wild, apex]) {
      assert.equal((await human.decideSecretOpen({ path, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "holder-both", parentKey: "agent-0" })).verdict, "raw");
    }
    assert.deepEqual((await human.taintedProcessBindings({ procKey: "holder-both" })).bindings, ["*.example.test"], "the join keeps what both admit");
    const ok = await post(holder.port, "http://api.example.test/v1", "no-secret-here");
    assert.equal(ok.status, 200, `the holder reaches a host both files allow: ${ok.body}`);
    for (const host of ["example.test", "other.test"]) {
      const before = reached.length;
      const r = await post(holder.port, `http://${host}/v1`, "no-secret-here");
      assert.equal(r.status, 403, `the holder at ${host}: refused (${r.body})`);
      assert.equal(reached.length, before, `nothing reached ${host} from the holder`);
    }
  } finally {
    await clean.net.close();
    await holder.net.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
