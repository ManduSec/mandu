/**
 * issuer-bindings-gate — the default catalog's issuer bindings at the REAL
 * egress gate (confidentiality.md §2.3), over the IPC the net-proxy uses:
 *
 *   - a workspace `.env` the catalog labels (no label of the user's, no
 *     binding): its Stripe key's placeholder is released at api.stripe.com
 *     with no card (`egress:secret-issuer`) in the Authorization header over
 *     HTTPS, and asks (`egress:secret-unbound`, a card) for every lookalike
 *     host, in the body, the URL or another header, over plain HTTP;
 *   - the file's other values (a password), its whole-file placeholder and
 *     an old key in a comment line keep asking, at the issuer's host too;
 *   - a key goes only to its OWN issuer (the Notion token at api.stripe.com
 *     asks);
 *   - a masked environment variable holding a key is released the same way;
 *   - the human's answers win: a Block at the host stays a block;
 *   - policy.yaml `issuer_bindings: false`, `issuers_off`, `values_off`
 *     each make the send ask again, at once;
 *   - `mandu why <host>` says the host is an issuer's.
 *
 * Mandu-new test. Axes stated: `secrets` (confidentiality on, integrity off).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const tail = (n: number, seed: number): string => {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let x = seed, out = "";
  while (out.length < n) { x = (Math.imul(x, 1103515245) + 12345) >>> 0; out += abc[(x >>> 16) % abc.length]; }
  return out;
};
const STRIPE = ["sk", "test", `51ISSUERGATE${tail(90, 3)}`].join("_");
const OLD_STRIPE = ["sk", "live", `51ISSUEROLD${tail(90, 5)}`].join("_");
const NOTION = ["ntn", `11235813213ISSUER${tail(29, 9)}`].join("_");
const ENV_STRIPE = ["rk", "live", `51ISSUERENV${tail(90, 11)}`].join("_");
const PASSWORD = "Harbor-Quay-8812-Plum!x";

async function stack() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-issuer-gate-"));
  const ws = join(dir, "ws", "shop-app");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_SECRET_KEY=${STRIPE}\n# STRIPE_SECRET_KEY=${OLD_STRIPE}\nNOTION_TOKEN=${NOTION}\nDB_PASSWORD=${PASSWORD}\n`);
  // A fresh install: a law with no label and no binding.
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(dir, "a.sock");
  const human = join(dir, "human", "h.sock");
  const adminSock = join(dir, "admin.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, adminSocketPath: adminSock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await s.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const h = new ArbiterClient(human); await h.connect();
  const admin = new ArbiterClient(adminSock); await admin.connect();
  const reg = await h.registerSecret({ path: env, home: join(dir, "home") });
  assert.ok(reg.symbol && reg.twin, reg.reason);
  const field = (key: string): string => {
    const m = new RegExp(`^${key}='?(\\$MDU:[^\\s']+)'?$`, "m").exec(reg.twin!);
    assert.ok(m, `${key} has a placeholder in the twin:\n${reg.twin}`);
    return m![1]!;
  };
  const comment = /^# STRIPE_SECRET_KEY='?(\$MDU:[^\s']+)'?$/m.exec(reg.twin!)?.[1];
  assert.ok(comment, `the commented-out key has its placeholder:\n${reg.twin}`);
  return {
    data, h, admin, base: reg.symbol!, stripe: field("STRIPE_SECRET_KEY"), notion: field("NOTION_TOKEN"), password: field("DB_PASSWORD"), comment,
    done: async () => { data.close(); h.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

type K = Awaited<ReturnType<typeof stack>>;
const HEADER = { scheme: "https" as const, positions: ["authorization" as const] };
const send = (k: K, symbol: string, destination: string, extra: Record<string, unknown> = HEADER) =>
  k.h.desymbolizationDecision({ symbol, boundary: "network", destination, asCommand: false, ...extra } as never);

test("a catalog .env's Stripe key: released at api.stripe.com in the header over https, no card; every lookalike asks", async () => {
  const k = await stack();
  try {
    for (const d of ["api.stripe.com", "api.stripe.com:443", "files.stripe.com:443"]) {
      const r = await send(k, k.stripe, d);
      assert.equal(r.allow, true, `${d}: ${r.reason}`);
      assert.equal(r.ruleRef?.id, "egress:secret-issuer", d);
    }
    for (const d of ["api.stripe.com.evil.io", "api-stripe.com", "stripe.com", "x.api.stripe.com", "api.stripe.com:8443", "evil.example"]) {
      const r = await send(k, k.stripe, d);
      assert.equal(r.allow, false, d);
      assert.equal(r.ruleRef?.id, "egress:secret-unbound", `${d}: ${r.reason}`);
      assert.equal((r as { requiresApproval?: boolean }).requiresApproval, true, d);
    }
    for (const extra of [
      { scheme: "https", positions: ["body"] }, { scheme: "https", positions: ["url"] }, { scheme: "https", positions: ["header"] },
      { scheme: "https", positions: ["authorization", "body"] }, { scheme: "http", positions: ["authorization"] }, { positions: ["authorization"] }, {},
    ]) {
      const r = await send(k, k.stripe, "api.stripe.com", extra);
      assert.equal(r.allow, false, JSON.stringify(extra));
      assert.equal(r.ruleRef?.id, "egress:secret-unbound", JSON.stringify(extra));
    }
    // nothing above that released filed a card
    const pending = await k.admin.egressApprovals("pending");
    assert.ok(!pending.some((p) => p.destination === "api.stripe.com" && p.reason.includes("issuer")));
  } finally { await k.done(); }
});

test("only the key's own issuer, only the key: the Notion token, the password, the whole file and an old key in a comment", async () => {
  const k = await stack();
  try {
    assert.equal((await send(k, k.notion, "api.notion.com")).ruleRef?.id, "egress:secret-issuer");
    assert.equal((await send(k, k.notion, "api.stripe.com")).ruleRef?.id, "egress:secret-unbound");
    assert.equal((await send(k, k.stripe, "api.notion.com")).ruleRef?.id, "egress:secret-unbound");
    assert.equal((await send(k, k.password, "api.stripe.com")).ruleRef?.id, "egress:secret-unbound");
    assert.equal((await send(k, k.base, "api.stripe.com")).ruleRef?.id, "egress:secret-unbound", "the whole file is no key");
    assert.equal((await send(k, k.comment!, "api.stripe.com")).ruleRef?.id, "egress:secret-unbound", "a commented-out key goes nowhere");
  } finally { await k.done(); }
});

test("a masked environment variable holding a key is released at its issuer the same way", async () => {
  const k = await stack();
  try {
    const r = await k.h.registerEnvSecrets({ vars: [{ name: "STRIPE_RESTRICTED", value: ENV_STRIPE }] });
    const sym = r.vars[0]!.symbol;
    assert.ok(sym, r.vars[0]!.reason);
    assert.equal((await send(k, sym!, "api.stripe.com")).ruleRef?.id, "egress:secret-issuer");
    assert.equal((await send(k, sym!, "api-stripe.com")).ruleRef?.id, "egress:secret-unbound");
  } finally { await k.done(); }
});

test("the human's Block at the host wins over the default", async () => {
  const k = await stack();
  try {
    // A body send asks: the card the human answers Block.
    const ask = (await send(k, k.stripe, "api.stripe.com", { scheme: "https", positions: ["body"] })) as { approvalId?: string; reason: string };
    assert.ok(ask.approvalId, ask.reason);
    await k.admin.resolveEgressApproval(ask.approvalId!, false, "always");
    const r = await send(k, k.stripe, "api.stripe.com");
    assert.equal(r.allow, false, r.reason);
    assert.equal(r.ruleRef?.source, "verdict");
  } finally { await k.done(); }
});

test("policy.yaml issuer_bindings: off, an issuer off, a value off: the send asks again, at once", async () => {
  const k = await stack();
  try {
    const apply = async (doc: Record<string, unknown>) => {
      const read = await k.admin.policyDocument();
      const r = await k.admin.applyPolicyDocument({ version: 1, ...doc }, "test", read.lawHash!);
      assert.ok((r as { ok?: boolean; applied?: boolean }).ok !== false, JSON.stringify(r));
    };
    assert.equal((await send(k, k.stripe, "api.stripe.com")).ruleRef?.id, "egress:secret-issuer");
    for (const doc of [{ issuer_bindings: false }, { issuer_bindings: { issuers_off: ["stripe"] } }, { issuer_bindings: { values_off: ["STRIPE_*"] } }]) {
      await apply(doc);
      const r = await send(k, k.stripe, "api.stripe.com");
      assert.equal(r.ruleRef?.id, "egress:secret-unbound", JSON.stringify(doc));
    }
    // values_off names STRIPE_*: the Notion token is still released
    assert.equal((await send(k, k.notion, "api.notion.com")).ruleRef?.id, "egress:secret-issuer");
    const why = await k.h.whyHost("api.stripe.com");
    assert.deepEqual(why.issuer && { id: why.issuer.id, on: why.issuer.on }, { id: "stripe", on: true }, "values_off leaves the issuer on");
    await apply({ issuer_bindings: false });
    assert.equal((await k.h.whyHost("api.stripe.com")).issuer?.on, false);
    assert.equal((await k.h.whyHost("api-stripe.com")).issuer, undefined);
  } finally { await k.done(); }
});
