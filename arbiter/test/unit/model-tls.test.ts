/**
 * model-tls.test — plan 12 D3: policy.yaml `models[].tls` is validated at load
 * (files exist and parse, pins are 32-byte SHA-256, the client pair matches,
 * https only), compiled to absolute paths, and the client key is a secret
 * file (no-model) the discovery walks wherever it lives.
 *
 * Certificates are minted per run with the openssl CLI (tls-fixtures.ts);
 * the suite self-SKIPs where openssl is absent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { checkModelTls, compileModelTls, expandTlsPath, isSha256Pin, modelClientKeyPaths } from "../../policy/model-tls.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { applyEdits, evaluateEdits } from "../../policy/policy-edit.js";
import { mintTlsFixtures } from "../helpers/tls-fixtures.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the endpoints serve local-model data (confidentiality); validation reads no axis

const fx = mintTlsFixtures();
const skip = fx === null ? "openssl is not on PATH" : false;
process.on("exit", () => fx?.cleanup());

const entry = (tls: unknown, url = "https://llm.corp.example/v1") => ({ name: "corp", url, wire: "openai-chat", model: "q", local: true, tls });

test("isSha256Pin / expandTlsPath", () => {
  assert.equal(isSha256Pin(Buffer.alloc(32, 7).toString("base64")), true);
  assert.equal(isSha256Pin(Buffer.alloc(31, 7).toString("base64")), false);
  assert.equal(isSha256Pin("not base64 at all, but 44 characters long!!="), false);
  assert.equal(isSha256Pin(42), false);
  assert.equal(expandTlsPath("~/.config/mandu/k.pem", "/home/u"), "/home/u/.config/mandu/k.pem");
  assert.equal(expandTlsPath("/etc/ssl/corp//ca.pem"), "/etc/ssl/corp/ca.pem");
  assert.equal(expandTlsPath("relative/ca.pem"), null);
});

test("a full, valid tls: loads, and compiles to absolute paths", { skip }, () => {
  const tls = { ca_file: fx!.caCert, pin_sha256: [fx!.serverPin, fx!.caPin], client_cert: fx!.clientCert, client_key: fx!.clientKey };
  assert.deepEqual(validatePolicyDocument({ version: 1, models: [entry(tls)] }), []);
  const m = compilePolicy({ specId: "claude-code", document: { version: 1, models: [entry(tls) as never] } }).models[0]!;
  assert.deepEqual(m.tls, { caFile: fx!.caCert, pinSha256: [fx!.serverPin, fx!.caPin], clientCert: fx!.clientCert, clientKey: fx!.clientKey });
  assert.deepEqual(modelClientKeyPaths([m]), [fx!.clientKey]);
  // Any subset alone is fine too; an entry without tls compiles without the field.
  assert.deepEqual(validatePolicyDocument({ version: 1, models: [entry({ pin_sha256: [fx!.serverPin] })] }), []);
  assert.deepEqual(validatePolicyDocument({ version: 1, models: [entry({ ca_file: fx!.caCert })] }), []);
  const bare = compilePolicy({ specId: "claude-code", document: { version: 1, models: [{ name: "o", url: "http://127.0.0.1:11434", local: true }] } }).models[0]!;
  assert.equal("tls" in bare, false);
});

test("tls: refused on http, unknown keys, missing or unparsable files, bad pins, a half pair, a key that does not match", { skip }, () => {
  const probs = (tls: unknown, url?: string): string => validatePolicyDocument({ version: 1, models: [entry(tls, url)] }).join("\n");
  assert.match(probs({ ca_file: fx!.caCert }, "http://127.0.0.1:8000"), /models\[0\]\.tls: the url is plain http, so there is no TLS to check; use an https url or remove tls/);
  assert.match(probs({ ca: fx!.caCert }), /models\[0\]\.tls: unknown key 'ca'/);
  assert.match(probs("yes"), /models\[0\]\.tls: must be a mapping/);
  assert.match(probs({ ca_file: join(fx!.dir, "nope.pem") }), /models\[0\]\.tls\.ca_file: cannot read .*nope\.pem/);
  assert.match(probs({ ca_file: "ca.pem" }), /models\[0\]\.tls\.ca_file: must be an absolute path or start with ~\//);
  const junk = join(fx!.dir, "junk.pem");
  writeFileSync(junk, "hello");
  assert.match(probs({ ca_file: junk }), /models\[0\]\.tls\.ca_file: .*junk\.pem holds no PEM certificate/);
  assert.match(probs({ pin_sha256: [] }), /pin_sha256: must be a non-empty list/);
  assert.match(probs({ pin_sha256: ["abc="] }), /pin_sha256\[0\]: must be the base64 of a 32-byte SHA-256/);
  assert.match(probs({ client_cert: fx!.clientCert }), /models\[0\]\.tls: client_cert and client_key go together/);
  assert.match(probs({ client_key: fx!.clientKey }), /models\[0\]\.tls: client_cert and client_key go together/);
  assert.match(probs({ client_cert: fx!.clientCert, client_key: fx!.strayKey }), /models\[0\]\.tls: client_key does not match client_cert/);
  assert.match(probs({ client_cert: fx!.clientCert, client_key: fx!.clientCert }), /models\[0\]\.tls\.client_key: .* is not a private key/);
  for (const p of [probs({ ca: 1 }), probs({ client_cert: fx!.clientCert, client_key: fx!.strayKey })]) assert.ok(!/ — /.test(p));
});

test("checkModelTls reads through the injected reader, never the network", () => {
  const out: string[] = [];
  const read: string[] = [];
  checkModelTls({ url: "https://x", tls: { ca_file: "/etc/x.pem" } }, "models[0]", out, (p) => { read.push(p); throw new Error("ENOENT"); });
  assert.deepEqual(read, ["/etc/x.pem"]);
  assert.match(out.join(), /cannot read \/etc\/x\.pem/);
});

test("the edit grammar carries tls whole; a change of it is a models relaxation naming the field", { skip }, () => {
  const base = { version: 1, models: [entry({ pin_sha256: [fx!.serverPin] })] } as never;
  const r = applyEdits(base, [{ op: "update-model", ...entry({ pin_sha256: [fx!.caPin] }) } as never]);
  assert.ok(r.ok, r.ok ? "" : r.problems.join("; "));
  if (r.ok) assert.deepEqual((r.document.models![0] as { tls?: unknown }).tls, { pin_sha256: [fx!.caPin] });
  const ev = evaluateEdits({ specId: "claude-code", document: base }, [{ op: "update-model", ...entry({ pin_sha256: [fx!.caPin] }) } as never]);
  assert.ok(ev.ok, ev.ok ? "" : ev.problems.join("; "));
  if (ev.ok) assert.match(ev.delta.relaxations.map((x) => x.detail).join("\n"), /model corp changes \(tls\)/);
});

test("compileModelTls keeps only usable fields: a half pair is dropped, bad pins filtered", () => {
  assert.equal(compileModelTls({}), undefined);
  assert.deepEqual(compileModelTls({ tls: { client_cert: "/a.pem" } } as never), undefined);
  assert.deepEqual(compileModelTls({ tls: { pin_sha256: ["x", Buffer.alloc(32).toString("base64")] } } as never), { pinSha256: [Buffer.alloc(32).toString("base64")] });
});
