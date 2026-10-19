/**
 * bindings-follow-policy — a `bindings:` entry in policy.yaml governs the
 * symbols of a file Mandu registered BEFORE the entry was written, in both
 * directions (confidentiality.md §2.1, 2026-10-05), over the REAL components:
 * an ArbiterServer reading a policy FILE (the hand-edit poll, a loosening
 * approved as the Approvals page does), and the REAL net-proxy in its
 * production wiring (`new ArbiterClientAdapter(new ArbiterClient(data),
 * new ArbiterClient(human))`) with a recording forwarder as the oracle.
 *
 * Test 1, the beta-tutorial flow that was dead (docs/getting-started.md §5-7):
 *   1. `.env` is registered with no binding: a send of its key's placeholder
 *      to api.stripe.com is refused (`egress:secret-unbound`), nothing sent;
 *   2. policy.yaml binds it to api.stripe.com (a loosening, approved): the
 *      SAME placeholder now reaches api.stripe.com as the real value, with no
 *      re-registration; evil.example still gets nothing; `testFlow` (what
 *      `mandu why --to` asks) agrees with the gate;
 *   3. the binding removed (a tightening, in force at once): refused again;
 *   4. the binding re-added while the arbiter is down, and a restart over the
 *      same symbol DB: the old placeholder is released at api.stripe.com;
 *      a new launch's registration reuses the same symbol and keeps it.
 *
 * Test 2, the security direction: a file registered while BOUND (its rows
 * minted with the binding) stops releasing the moment the binding leaves
 * the law: by a hand edit, and by the dashboard's label act (the label
 * store, which wins over the file on the same path).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { pollDiskApproving } from "../../arbiter/test/held-disk.js";
import { NetProxy, type HttpForwarder } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const KEY = "sk_live_fake_BINDFOLLOW_7f3a91";
const SESSION = "s-bindings-follow";

/** A plain-HTTP POST through the forward proxy carrying `auth`; the status
 *  and the proxy's body (a refusal names its rule there). */
function viaProxy(port: number, url: string, auth: string): Promise<{ status: number; body: string }> {
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

interface Stack {
  server: ArbiterServer;
  human: ArbiterClient;
  admin: ArbiterClient;
  port: number;
  close: () => Promise<void>;
}

interface Harness {
  env: string;
  reached: string[];
  /** Write policy.yaml, with or without the binding, at a fresh mtime. */
  writeLaw: (bound: boolean) => void;
  /** Start an arbiter (over the one symbol DB and policy file) and a net-proxy. */
  start: () => Promise<Stack>;
  /** Send the placeholder to `host`; assert the outcome at the destination. */
  send: (s: Stack, symbol: string, host: string, released: boolean, why: string) => Promise<void>;
  /** What `mandu why <file> --to <host>` answers, from the same engine. */
  why: (s: Stack, host: string) => Promise<string | undefined>;
  cleanup: () => void;
}

function harness(): Harness {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-bindings-follow-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\nDEBUG=1\n`);
  const policy = join(tmp, "policy.yaml");
  const dbPath = join(tmp, "symbols.sqlite");
  const reached: string[] = [];
  const forwarder: HttpForwarder = async (req) => {
    reached.push(`${req.url} ${JSON.stringify(req.headers)}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  let bump = 0;
  let starts = 0;
  return {
    env,
    reached,
    writeLaw: (bound) => {
      writeFileSync(policy, ["version: 1", "paths:", `  - path: ${env}`, "    level: no-model", ...(bound ? ["    bindings: [api.stripe.com]"] : []), ""].join("\n"));
      // A distinct mtime even on a coarse clock, so the poll cannot miss it.
      const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
      utimesSync(policy, t, t);
    },
    start: async () => {
      const n = ++starts;
      const sock = join(tmp, `a${n}.sock`);
      const adminSock = join(tmp, `admin${n}.sock`);
      const humanSock = join(tmp, `h${n}`, "h.sock");
      const server = new ArbiterServer({
        socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
        dbPath, eventDir: join(tmp, "events"), log: () => {},
        confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
      });
      await server.listen();
      const human = new ArbiterClient(humanSock); await human.connect();
      const admin = new ArbiterClient(adminSock); await admin.connect();
      const data = new ArbiterClient(sock); await data.connect();
      const netHuman = new ArbiterClient(humanSock); await netHuman.connect();
      const net = new NetProxy({
        arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, netHuman as never), forwarder, log: () => {}, sessionId: SESSION,
        attributeHolders: () => [],
      });
      const port = await net.listen(0);
      return {
        server, human, admin, port,
        close: async () => {
          await net.close();
          human.close(); admin.close(); data.close(); netHuman.close();
          await server.close();
        },
      };
    },
    send: async (s, symbol, host, released, why) => {
      const before = reached.length;
      const r = await viaProxy(s.port, `http://${host}/v1/customers`, symbol);
      if (released) {
        assert.equal(r.status, 200, `${why}: ${r.body}`);
        assert.equal(reached.length, before + 1, `${why}: the request reached ${host}`);
        assert.ok(reached.at(-1)!.includes(KEY), `${why}: ${host} received the real value`);
        assert.ok(!reached.at(-1)!.includes("$MDU:"), `${why}: not the placeholder`);
      } else {
        assert.equal(r.status, 403, `${why}: refused (${r.body})`);
        assert.match(r.body, /egress:secret-unbound/, why);
        assert.equal(reached.length, before, `${why}: nothing reached ${host}`);
      }
      assert.ok(!r.body.includes(KEY), `${why}: the refusal carries no secret`);
    },
    why: async (s, host) =>
      (await s.human.testFlow({ source: { tool: "Read", origin: env }, destination: host })).egress?.decision.ruleRef?.id,
    cleanup: () => rmSync(tmp, { recursive: true, force: true }),
  };
}

test("policy.yaml bindings govern a file's existing symbols: bind after first sight releases, unbind stops at once, a restart keeps the law in force", async () => {
  const h = harness();
  h.writeLaw(false);
  let s = await h.start();
  try {
    // 1. Registered with no binding (a launch's registration).
    const reg = await s.human.registerSecret({ path: h.env, sessionKey: SESSION });
    assert.match(String(reg.symbol), /^\$MDU:nomodel_Read\[/, JSON.stringify(reg));
    const field = `${reg.symbol}.STRIPE_KEY`;
    assert.ok(String(reg.twin).includes(field), "the twin carries the field placeholder");
    await h.send(s, field, "api.stripe.com", false, "before the binding");

    // 2. Bound after first sight: a loosening, approved as the Inbox would.
    h.writeLaw(true);
    assert.equal(pollDiskApproving(s.server), true, "the edit was seen");
    assert.deepEqual((await s.human.pathLevel(h.env)).bindings, ["api.stripe.com"], "the binding is in force");
    assert.equal(await h.why(s, "api.stripe.com"), "egress:secret-bound-trusted", "mandu why: released");
    await h.send(s, field, "api.stripe.com", true, "after the binding, no re-registration");
    await h.send(s, field, "evil.example", false, "an unbound host");
    assert.equal(await h.why(s, "evil.example"), "egress:secret-unbound", "mandu why agrees: held");

    // 3. Unbound: a tightening is in force at once.
    h.writeLaw(false);
    pollDiskApproving(s.server);
    assert.deepEqual((await s.human.pathLevel(h.env)).bindings, [], "the binding is gone");
    await h.send(s, field, "api.stripe.com", false, "after the binding was removed");
    assert.equal(await h.why(s, "api.stripe.com"), "egress:secret-unbound", "mandu why agrees: held");

    // 4. Re-bound while the arbiter is down; restart over the same DB.
    await s.close();
    h.writeLaw(true);
    s = await h.start();
    pollDiskApproving(s.server);
    assert.deepEqual((await s.human.pathLevel(h.env)).bindings, ["api.stripe.com"]);
    await h.send(s, field, "api.stripe.com", true, "after a restart, no re-registration");
    // A new launch registers the file again: the same symbol, still released.
    const again = await s.human.registerSecret({ path: h.env, sessionKey: SESSION });
    assert.equal(again.symbol, reg.symbol, "the same rows, reused");
    await h.send(s, field, "api.stripe.com", true, "after a new launch's registration");
    await h.send(s, field, "evil.example", false, "an unbound host, after the restart");
    assert.ok(h.reached.every((r) => r.startsWith("http://api.stripe.com/")), "only the bound host ever received anything");
  } finally {
    await s.close();
    h.cleanup();
  }
});

test("a file registered while bound stops releasing the moment the binding leaves the law (hand edit, dashboard label act)", async () => {
  const h = harness();
  h.writeLaw(true);
  const s = await h.start();
  try {
    const reg = await s.human.registerSecret({ path: h.env, sessionKey: SESSION });
    const field = `${reg.symbol}.STRIPE_KEY`;
    await h.send(s, field, "api.stripe.com", true, "minted while bound");

    // A hand edit removes the binding: no approval, in force at once.
    h.writeLaw(false);
    pollDiskApproving(s.server);
    await h.send(s, field, "api.stripe.com", false, "the binding removed by a hand edit");

    // Bound again by the file, then the dashboard's label act (the label
    // store wins over the file on the same path) takes it away.
    h.writeLaw(true);
    pollDiskApproving(s.server);
    await h.send(s, field, "api.stripe.com", true, "bound again");
    await s.admin.setPathLabel({ path: h.env, confidentiality: "no-model", bindings: [] });
    await h.send(s, field, "api.stripe.com", false, "the dashboard's label carries no binding");
    assert.equal(await h.why(s, "api.stripe.com"), "egress:secret-unbound", "mandu why agrees");
    // Removing the dashboard label leaves the file's rule, and its binding.
    assert.equal(await s.admin.removePathLabel(h.env), true);
    await h.send(s, field, "api.stripe.com", true, "the file's binding back in force");
    await h.send(s, field, "evil.example", false, "an unbound host");
  } finally {
    await s.close();
    h.cleanup();
  }
});
