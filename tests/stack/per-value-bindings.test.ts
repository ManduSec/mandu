/**
 * per-value-bindings — a structured file's values bound one by one
 * (confidentiality plan 13 §5.2, `values:` in policy.yaml) over the REAL
 * components: an ArbiterServer reading a policy FILE, and the REAL net-proxy
 * in its production wiring (`new ArbiterClientAdapter(new ArbiterClient(data),
 * new ArbiterClient(human))`) with a recording forwarder as the oracle.
 *
 * `.env` holds a Stripe key and two AWS keys; policy.yaml binds STRIPE_KEY to
 * api.stripe.com and `AWS_*` to amazonaws.com, and the file itself nowhere.
 *
 *   1. The STRIPE_KEY placeholder sent to api.stripe.com reaches it as the
 *      real value; the AWS placeholders sent there are refused
 *      (`egress:secret-unbound`) and nothing of them reaches it; the AWS
 *      secret reaches s3.amazonaws.com; the Stripe key does not; the
 *      whole-file placeholder goes nowhere. `mandu why --to` agrees.
 *   2. A process that opened the file RAW holds every value, so it may
 *      connect only where every value may go: here nowhere (api.stripe.com
 *      and s3.amazonaws.com both refused, nothing forwarded). The control: a
 *      holder of a file whose values all share a host reaches that host, so
 *      the refusal above is the intersection, not a holder refused anyway.
 *   3. A binding added to a value is a loosening (held for the human until
 *      approved); approved, the value is released at the new host and the
 *      other values are still not.
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

const STRIPE = "sk_live_fake_PERVALUE_STACK_7f3a91";
const AWS_ID = "AKIAIOSFODNN7PVSTACK";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYPVSTACK01";
const SHARED = "sk_live_fake_PERVALUE_SHARED_0042aa";
const SESSION = "s-per-value-bindings";

/** A plain-HTTP POST through the forward proxy; the status and the proxy's body. */
function post(port: number, url: string, auth: string, body = ""): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, authorization: `Bearer ${auth}`, "content-length": Buffer.byteLength(body) } },
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

test("values: each value is released at its own hosts only, and a raw holder of the file may send nowhere outside the intersection", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-per-value-"));
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${STRIPE}\nAWS_ACCESS_KEY_ID=${AWS_ID}\nAWS_SECRET_ACCESS_KEY=${AWS_SECRET}\nDEBUG=1\n`);
  const shared = join(ws, "shared.env");
  writeFileSync(shared, `SHARED_KEY=${SHARED}\n`);
  const policy = join(tmp, "policy.yaml");
  let bump = 0;
  const writeLaw = (stripeHosts: string[]) => {
    writeFileSync(policy, [
      "version: 1",
      "paths:",
      `  - path: ${env}`,
      "    level: no-model",
      "    readers: [ssh-add]",
      "    values:",
      `      STRIPE_KEY: { bindings: [${stripeHosts.join(", ")}] }`,
      '      "AWS_*": { bindings: [amazonaws.com] }',
      `  - path: ${shared}`,
      "    level: no-model",
      "    readers: [ssh-add]",
      "    bindings: [api.stripe.com]",
      "    values:",
      "      SHARED_KEY: { bindings: [api.stripe.com] }",
      "",
    ].join("\n"));
    const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
    utimesSync(policy, t, t);
  };
  writeLaw(["api.stripe.com"]);
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
    reached.push(`${req.url} ${JSON.stringify(req.headers)} ${req.body?.toString("utf8") ?? ""}`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("ok") };
  };
  const clients: ArbiterClient[] = [human];
  /** A net-proxy whose every connection is the process `procKey`. */
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
  const holder = await proxy("holder-env");
  const control = await proxy("holder-shared");
  try {
    // The launcher's registration: the structured twin's field placeholders.
    const reg = await human.registerSecret({ path: env, sessionKey: SESSION });
    assert.match(String(reg.symbol), /^\$MDU:nomodel_Read\[/, JSON.stringify(reg));
    const whole = String(reg.symbol);
    const stripe = `${whole}.STRIPE_KEY`;
    const awsId = `${whole}.AWS_ACCESS_KEY_ID`;
    const awsSecret = `${whole}.AWS_SECRET_ACCESS_KEY`;
    for (const f of [stripe, awsId, awsSecret]) assert.ok(String(reg.twin).includes(f), `the twin carries ${f}`);
    assert.ok((await human.registerSecret({ path: shared, sessionKey: SESSION })).symbol);

    const send = async (port: number, symbol: string, host: string, released: boolean, why: string, value?: string) => {
      const before = reached.length;
      const r = await post(port, `http://${host}/v1/x`, symbol);
      if (released) {
        assert.equal(r.status, 200, `${why}: ${r.body}`);
        assert.equal(reached.length, before + 1, `${why}: reached ${host}`);
        if (value) assert.ok(reached.at(-1)!.includes(value), `${why}: ${host} received the real value`);
        assert.ok(!reached.at(-1)!.includes("$MDU:"), `${why}: not the placeholder`);
      } else {
        assert.equal(r.status, 403, `${why}: refused (${r.body})`);
        assert.equal(reached.length, before, `${why}: nothing reached ${host}`);
      }
      for (const secret of [STRIPE, AWS_ID, AWS_SECRET, SHARED]) assert.ok(!r.body.includes(secret), `${why}: the answer carries no secret`);
    };

    // 1. Each value at its own hosts, through a clean sender.
    await send(clean.port, stripe, "api.stripe.com", true, "STRIPE_KEY at api.stripe.com", STRIPE);
    await send(clean.port, awsSecret, "api.stripe.com", false, "AWS_SECRET_ACCESS_KEY at api.stripe.com");
    await send(clean.port, awsId, "api.stripe.com", false, "AWS_ACCESS_KEY_ID at api.stripe.com");
    await send(clean.port, awsSecret, "s3.amazonaws.com", true, "AWS_SECRET_ACCESS_KEY at s3.amazonaws.com", AWS_SECRET);
    await send(clean.port, stripe, "s3.amazonaws.com", false, "STRIPE_KEY at s3.amazonaws.com");
    await send(clean.port, whole, "api.stripe.com", false, "the whole file at api.stripe.com");
    await send(clean.port, whole, "s3.amazonaws.com", false, "the whole file at s3.amazonaws.com");
    for (const r of reached) {
      if (r.startsWith("http://api.stripe.com")) assert.ok(!r.includes(AWS_ID) && !r.includes(AWS_SECRET), "no AWS byte reached Stripe");
      if (r.startsWith("http://s3.amazonaws.com")) assert.ok(!r.includes(STRIPE), "no Stripe byte reached AWS");
    }
    const why = async (host: string) => (await human.testFlow({ source: { tool: "Read", origin: env }, destination: host })).egress?.decision.ruleRef?.id;
    assert.equal(await why("api.stripe.com"), "egress:secret-unbound", "mandu why for the whole file: held at Stripe");

    // 2. A raw holder of the file: the intersection over its values, nowhere.
    assert.equal((await human.decideSecretOpen({ path: env, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "holder-env", parentKey: "agent-0" })).verdict, "raw");
    assert.deepEqual((await human.taintedProcessBindings({ procKey: "holder-env" })).bindings, [], "the whole file may go nowhere");
    for (const host of ["api.stripe.com", "s3.amazonaws.com"]) {
      const before = reached.length;
      const r = await post(holder.port, `http://${host}/v1/x`, "no-secret-here");
      assert.equal(r.status, 403, `a holder of every value connecting to ${host}: refused (${r.body})`);
      assert.equal(reached.length, before, `nothing reached ${host} from the holder`);
    }
    // The control: every value of shared.env and the file share api.stripe.com.
    assert.equal((await human.decideSecretOpen({ path: shared, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "holder-shared", parentKey: "agent-0" })).verdict, "raw");
    assert.deepEqual((await human.taintedProcessBindings({ procKey: "holder-shared" })).bindings, ["api.stripe.com"]);
    const ok = await post(control.port, "http://api.stripe.com/v1/x", "no-secret-here");
    assert.equal(ok.status, 200, `the control holder reaches the host every value allows: ${ok.body}`);
    const no = await post(control.port, "http://s3.amazonaws.com/v1/x", "no-secret-here");
    assert.equal(no.status, 403, `the control holder elsewhere: refused (${no.body})`);

    // 3. A binding added to a value: a loosening, in force once approved;
    // the other values stay where they were.
    writeLaw(["api.stripe.com", "hooks.example.com"]);
    assert.equal(pollDiskApproving(server), true, "the loosening was seen (and approved, as the Approvals page does)");
    await send(clean.port, stripe, "hooks.example.com", true, "STRIPE_KEY at its newly bound host", STRIPE);
    await send(clean.port, awsSecret, "hooks.example.com", false, "the AWS key is not");
    assert.deepEqual((await human.taintedProcessBindings({ procKey: "holder-env" })).bindings, [], "the holder of the whole file still nowhere");
  } finally {
    await clean.net.close();
    await holder.net.close();
    await control.net.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
