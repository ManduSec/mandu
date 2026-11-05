/**
 * aws-signing-gate — the AWS signing release at the REAL egress gate
 * (aws-signing.ts; docs/design/confidentiality/aws-sigv4-resign.md), over
 * the IPC the net-proxy uses:
 *
 *   - a fresh install's `~/.aws/credentials` (the catalog labels it, nothing
 *     binds it): its secret access key is released at an AWS endpoint over
 *     HTTPS only at position `signature` (`egress:secret-aws-signing`, no
 *     card); in a header, the body or the URL, beside the signature, over
 *     plain HTTP, at a lookalike host, an address or another port it asks
 *     (`egress:secret-unbound`) as before;
 *   - the access key id and the session token only in the credential
 *     headers (`authorization`), never at `signature`;
 *   - the same for masked `AWS_*` environment variables;
 *   - `signingKeys` lists the secret keys' placeholders only (names, no
 *     value; never the id or the token);
 *   - policy.yaml `issuer_bindings: false`, `issuers_off: [aws]` and a
 *     `values_off` name make it ask again, at once; `issuers_off: [aws]`
 *     is a valid law;
 *   - the axis off: `signingKeys` lists nothing.
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
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let x = seed, out = "";
  while (out.length < n) { x = (Math.imul(x, 1103515245) + 12345) >>> 0; out += abc[(x >>> 16) % abc.length]; }
  return out;
};
const ID = `AKIA${tail(16, 3).toUpperCase().replace(/[^A-Z0-9]/g, "Q")}`;
const SECRET = tail(40, 5);
const TOKEN = `IQoJb3JpZ2luX2VjE${tail(120, 7)}`;
const ENV_SECRET = tail(40, 11);

async function stack(opts: { confidentiality?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mandu-aws-gate-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".aws"), { recursive: true });
  const creds = join(home, ".aws", "credentials");
  writeFileSync(creds, `[default]\naws_access_key_id = ${ID}\naws_secret_access_key = ${SECRET}\naws_session_token = ${TOKEN}\nregion = us-west-2\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(dir, "a.sock");
  const human = join(dir, "human", "h.sock");
  const adminSock = join(dir, "admin.sock");
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, adminSocketPath: adminSock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: opts.confidentiality ?? true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await s.listen();
  const data = new ArbiterClient(sock); await data.connect();
  const h = new ArbiterClient(human); await h.connect();
  const admin = new ArbiterClient(adminSock); await admin.connect();
  const reg = await h.registerSecret({ path: creds, home });
  const field = (key: string): string => {
    const m = new RegExp(`^${key} = (\\$MDU:\\S+)$`, "m").exec(reg.twin ?? "");
    assert.ok(m, `${key} has a placeholder in the twin:\n${reg.twin}`);
    return m![1]!;
  };
  return {
    data, h, admin, reg, field,
    done: async () => { data.close(); h.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

type K = Awaited<ReturnType<typeof stack>>;
const send = (k: K, symbol: string, destination: string, positions: string[], scheme: "https" | "http" | "unstated" = "https") =>
  k.data.desymbolizationDecision({ symbol, boundary: "network", destination, asCommand: false, positions, ...(scheme !== "unstated" ? { scheme } : {}) } as never);

test("~/.aws/credentials: the secret key goes to an AWS endpoint only as the signing key; everything else asks", async () => {
  const k = await stack();
  try {
    assert.ok(k.reg.symbol && k.reg.twin, k.reg.reason);
    const secret = k.field("aws_secret_access_key");
    assert.ok(!k.reg.twin!.includes(SECRET) && !k.reg.twin!.includes(ID) && !k.reg.twin!.includes(TOKEN), "the twin holds no value");
    for (const d of ["s3.us-west-2.amazonaws.com:443", "sts.amazonaws.com", "bucket.s3.amazonaws.com:443", "ec2.cn-north-1.amazonaws.com.cn:443", "s3.dualstack.us-east-1.api.aws:443"]) {
      const r = await send(k, secret, d, ["signature"]);
      assert.equal(r.allow, true, `${d}: ${r.reason}`);
      assert.equal(r.ruleRef?.id, "egress:secret-aws-signing", d);
    }
    for (const d of ["amazonaws.com", "amazonaws.com.evil.io:443", "s3-amazonaws.com", "s3.amazonaws.com:8443", "52.95.0.1:443", "evil.example:443"]) {
      const r = await send(k, secret, d, ["signature"]);
      assert.equal(r.allow, false, d);
      assert.equal(r.ruleRef?.id, "egress:secret-unbound", `${d}: ${r.reason}`);
    }
    for (const positions of [["authorization"], ["header"], ["body"], ["url"], ["signature", "header"], []]) {
      const r = await send(k, secret, "s3.us-west-2.amazonaws.com:443", positions);
      assert.equal(r.allow, false, JSON.stringify(positions));
      assert.equal(r.ruleRef?.id, "egress:secret-unbound", JSON.stringify(positions));
    }
    for (const scheme of ["http", "unstated"] as const) {
      const r = await send(k, secret, "s3.us-west-2.amazonaws.com:443", ["signature"], scheme);
      assert.equal(r.ruleRef?.id, "egress:secret-unbound", String(scheme));
    }
  } finally { await k.done(); }
});

test("the access key id and the session token: in the credential headers only, never as a signing key", async () => {
  const k = await stack();
  try {
    for (const key of ["aws_access_key_id", "aws_session_token"]) {
      const sym = k.field(key);
      const ok = await send(k, sym, "sts.amazonaws.com:443", ["authorization"]);
      assert.equal(ok.ruleRef?.id, "egress:secret-aws-signing", `${key}: ${ok.reason}`);
      for (const positions of [["signature"], ["body"], ["header"], ["authorization", "body"]]) {
        assert.equal((await send(k, sym, "sts.amazonaws.com:443", positions)).ruleRef?.id, "egress:secret-unbound", `${key} ${positions}`);
      }
      assert.equal((await send(k, sym, "evil.example:443", ["authorization"])).ruleRef?.id, "egress:secret-unbound", key);
    }
  } finally { await k.done(); }
});

test("signingKeys: the secret keys' placeholders, names only", async () => {
  const k = await stack();
  try {
    const env = await k.h.registerEnvSecrets({ vars: [{ name: "AWS_SECRET_ACCESS_KEY", value: ENV_SECRET }, { name: "AWS_ACCESS_KEY_ID", value: ID }] });
    const envKey = env.vars.find((v) => v.name === "AWS_SECRET_ACCESS_KEY")?.symbol;
    const envId = env.vars.find((v) => v.name === "AWS_ACCESS_KEY_ID")?.symbol;
    assert.ok(envKey && envId);
    const r = await k.data.signingKeys();
    assert.deepEqual(new Set(r.symbols), new Set([k.field("aws_secret_access_key"), envKey]));
    const wire = JSON.stringify(r);
    assert.ok(!wire.includes(SECRET) && !wire.includes(ENV_SECRET) && !wire.includes(ID), "no value crosses");
    // The masked variables release the same way.
    assert.equal((await send(k, envKey!, "s3.amazonaws.com:443", ["signature"])).ruleRef?.id, "egress:secret-aws-signing");
    assert.equal((await send(k, envId!, "s3.amazonaws.com:443", ["authorization"])).ruleRef?.id, "egress:secret-aws-signing");
    assert.equal((await send(k, envKey!, "s3.amazonaws.com:443", ["authorization"])).ruleRef?.id, "egress:secret-unbound");
  } finally { await k.done(); }
});

test("policy.yaml issuer_bindings: false, issuers_off: [aws], a value off: it asks again, at once", async () => {
  const k = await stack();
  try {
    const secret = k.field("aws_secret_access_key");
    const apply = async (doc: Record<string, unknown>) => {
      const read = await k.admin.policyDocument();
      const r = await k.admin.applyPolicyDocument({ version: 1, ...doc }, "test", read.lawHash!);
      assert.ok((r as { ok?: boolean }).ok !== false, JSON.stringify(r));
    };
    assert.equal((await send(k, secret, "s3.amazonaws.com:443", ["signature"])).ruleRef?.id, "egress:secret-aws-signing");
    for (const doc of [{ issuer_bindings: false }, { issuer_bindings: { issuers_off: ["aws"] } }, { issuer_bindings: { values_off: ["*aws_secret_access_key"] } }]) {
      await apply(doc);
      assert.equal((await send(k, secret, "s3.amazonaws.com:443", ["signature"])).ruleRef?.id, "egress:secret-unbound", JSON.stringify(doc));
    }
    await apply({ issuer_bindings: { issuers_off: ["stripe"] } });
    assert.equal((await send(k, secret, "s3.amazonaws.com:443", ["signature"])).ruleRef?.id, "egress:secret-aws-signing", "another issuer off leaves AWS on");
  } finally { await k.done(); }
});

test("the axis off: signingKeys lists nothing", async () => {
  const k = await stack({ confidentiality: false });
  try {
    assert.deepEqual((await k.data.signingKeys()).symbols, []);
  } finally { await k.done(); }
});
