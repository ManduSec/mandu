/**
 * sigv4-gate.test — the egress gate's SigV4 re-signing release (src/egress.ts
 * `sigv4Plan` / `resignRequest`; docs/design/confidentiality/aws-sigv4-resign.md).
 *
 * The agent's world signs with placeholders. Pinned, over the mock arbiter:
 *   - a request signed with a signing-key placeholder, carrying the access
 *     key id's and the session token's placeholders, leaves with the real
 *     id, the real token and the signature botocore makes with the real key
 *     (the botocore vectors of sigv4.test.ts: the bytes AWS would accept);
 *   - the signing key is asked at `signature` only, the id and the token at
 *     `authorization` (the token's header counts as the credential header);
 *   - every case it cannot sign is refused with nothing resolved: a
 *     signature no placeholder made, a Host other than the one sent to, a
 *     chunk-signed stream, SigV4a, an arbiter that cannot list keys, a
 *     signing key the arbiter withholds or the human sends without;
 *   - a SigV4 request with no placeholder at all goes as before.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { gateRequest, type GateInput } from "../../src/egress.js";
import { MockArbiter, type DesymbolizationDecision, type DesymbolizationRequest } from "../../src/arbiter-client.js";
import { matchSignature, parseSigV4Authorization, resignedAuthorization, sha256Hex, sigv4Signature } from "../../src/sigv4.js";

const SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const TOKEN = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";
const WHEN = "20261024T121033Z";

const KEY_PH = "$MDU:nomodel_Read[ab12].default.aws_secret_access_key";
const ID_PH = "$MDU:nomodel_Read[ab12].default.aws_access_key_id";
const TOKEN_PH = "$MDU:nomodel_Read[ab12].default.aws_session_token";
const OTHER_KEY_PH = "$MDU:nomodel_Env[cd34].AWS_SECRET_ACCESS_KEY";

/** botocore 1.40.72's Authorization for sts GetCallerIdentity with SECRET
 *  and TOKEN (sigv4.test.ts): what the proxy must send. */
const STS_REAL_AUTH = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=bdca9269a4b1a1c77d43711b923a90bda71751fa8897ce67c9793013bf4a8f57";
/** botocore's S3 virtual-host PUT of "hello" with SECRET and TOKEN. */
const S3_REAL_AUTH = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=0c029be0c86e7655642afe546dff5cca240ae53b20dc9273b75e0c3578afdbac";

const FORM = { uri: "normalized", query: "raw" } as const;

/** A request as the agent's `aws` makes it: placeholders for the id and the
 *  token, signed with `signWith` (a placeholder in the agent's world). */
function agentRequest(o: {
  host: string; method: string; path: string; headers: Record<string, string>; body?: string;
  scope: string; signedHeaders: string; signWith: string; hostHeader?: string;
  /** The form the SDK signs in: botocore's S3 signer keeps the path raw. */
  form?: { uri: "raw" | "encoded" | "normalized"; query: "raw" | "strict" };
}): Pick<GateInput, "method" | "destinationHost" | "url" | "headers" | "bodyText" | "bodyBytes"> {
  const headers: Record<string, string> = { Host: o.hostHeader ?? o.host, ...o.headers, "X-Amz-Date": WHEN };
  const auth0 = `AWS4-HMAC-SHA256 Credential=${ID_PH}/${o.scope}, SignedHeaders=${o.signedHeaders}, Signature=${"0".repeat(64)}`;
  headers.Authorization = auth0;
  const body = Buffer.from(o.body ?? "", "utf8");
  const url = `https://${o.host}${o.path}`;
  const sig = sigv4Signature({ method: o.method, url, headers, body }, parseSigV4Authorization(auth0)!, o.signWith, o.form ?? FORM)!;
  headers.Authorization = resignedAuthorization(auth0, sig);
  return { method: o.method, destinationHost: `${o.host}:443`, url, headers, bodyText: o.body ?? "", bodyBytes: body };
}

const stsRequest = (signWith = KEY_PH, extra: Partial<Parameters<typeof agentRequest>[0]> = {}) => agentRequest({
  host: "sts.amazonaws.com", method: "POST", path: "/",
  headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Amz-Security-Token": TOKEN_PH },
  body: "Action=GetCallerIdentity&Version=2011-06-15",
  scope: "20261024/us-east-1/sts/aws4_request", signedHeaders: "content-type;host;x-amz-date;x-amz-security-token",
  signWith, ...extra,
});

const VALUES = { [KEY_PH]: SECRET, [ID_PH]: "AKIDEXAMPLE", [TOKEN_PH]: TOKEN };
const allowAll = (): DesymbolizationDecision => ({ allow: true, reason: "test: allowed" });

function arbiter(o: { decisionFn?: (r: DesymbolizationRequest) => DesymbolizationDecision; signingKeys?: string[]; failSigningKeys?: boolean } = {}) {
  return new MockArbiter({
    decisionFn: o.decisionFn ?? allowAll,
    values: VALUES,
    ...("signingKeys" in o ? { signingKeys: o.signingKeys } : { signingKeys: [OTHER_KEY_PH, KEY_PH] }),
    ...(o.failSigningKeys ? { failSigningKeys: true } : {}),
  });
}

const gate = (req: ReturnType<typeof agentRequest>, a: MockArbiter, more: Partial<GateInput> = {}) =>
  gateRequest({ ...req, arbiter: a, scheme: "https", hostHeader: new URL(req.url).host, ...more });

const header = (h: Record<string, string | string[] | undefined>, name: string) =>
  Object.entries(h).find(([k]) => k.toLowerCase() === name)?.[1];

test("a placeholder-signed STS call leaves with the real id, token and botocore's real signature", async () => {
  const a = arbiter();
  const r = await gate(stsRequest(), a);
  assert.equal(r.action, "forward");
  assert.ok(r.action === "forward" && r.rewritten);
  assert.equal(header(r.rewritten.headers, "authorization"), STS_REAL_AUTH);
  assert.equal(header(r.rewritten.headers, "x-amz-security-token"), TOKEN);
  assert.equal(r.rewritten.bodyText, "Action=GetCallerIdentity&Version=2011-06-15");
  // Where each placeholder was asked about.
  const at = new Map(a.decisionCalls.map((c) => [c.symbol, c.positions]));
  assert.deepEqual(at.get(KEY_PH), ["signature"]);
  assert.deepEqual(at.get(ID_PH), ["authorization"]);
  assert.deepEqual(at.get(TOKEN_PH), ["authorization"]);
  assert.ok(a.decisionCalls.every((c) => c.destination === "sts.amazonaws.com:443" && c.scheme === "https"));
  // The real key is in no byte of what leaves.
  const sent = JSON.stringify(r.rewritten);
  assert.ok(!sent.includes(SECRET));
});

test("an S3 virtual-host PUT with a hashed payload re-signs to botocore's bytes", async () => {
  const req = agentRequest({
    host: "bucket.s3.us-west-2.amazonaws.com", method: "PUT", path: "/dir/my%20file.txt",
    headers: { "X-Amz-Security-Token": TOKEN_PH, "X-Amz-Content-SHA256": sha256Hex("hello") }, body: "hello",
    scope: "20261024/us-west-2/s3/aws4_request", signedHeaders: "host;x-amz-content-sha256;x-amz-date;x-amz-security-token", signWith: KEY_PH,
    form: { uri: "raw", query: "raw" },
  });
  const r = await gate(req, arbiter());
  assert.ok(r.action === "forward" && r.rewritten);
  assert.equal(header(r.rewritten.headers, "authorization"), S3_REAL_AUTH);
});

test("a binary body with no placeholder in it is signed over its bytes, not their UTF-8 reading", async () => {
  const bytes = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0x41]);
  const req = agentRequest({
    host: "bucket.s3.us-west-2.amazonaws.com", method: "PUT", path: "/blob",
    headers: { "X-Amz-Content-SHA256": "UNSIGNED-PAYLOAD" }, body: "",
    scope: "20261024/us-west-2/s3/aws4_request", signedHeaders: "host;x-amz-content-sha256;x-amz-date", signWith: KEY_PH,
  });
  const r = await gate({ ...req, bodyBytes: bytes, bodyText: bytes.toString("utf8") }, arbiter());
  assert.ok(r.action === "forward" && r.rewritten);
  const out = { method: "PUT", url: r.rewritten.url, headers: r.rewritten.headers, body: bytes };
  assert.ok(matchSignature(out, parseSigV4Authorization(header(r.rewritten.headers, "authorization") as string)!, [SECRET]));
});

test("a released value in a hashed body gets the body's new hash, signed", async () => {
  const BODY_PH = "$MDU:nomodel_Read[ef56].NOTE";
  const req = agentRequest({
    host: "s3.us-west-2.amazonaws.com", method: "PUT", path: "/bucket/note.txt",
    headers: { "X-Amz-Content-SHA256": sha256Hex(`v=${BODY_PH}`) }, body: `v=${BODY_PH}`,
    scope: "20261024/us-west-2/s3/aws4_request", signedHeaders: "host;x-amz-content-sha256;x-amz-date", signWith: KEY_PH,
  });
  const a = new MockArbiter({ decisionFn: allowAll, values: { ...VALUES, [BODY_PH]: "real-note" }, signingKeys: [KEY_PH] });
  const r = await gate(req, a);
  assert.ok(r.action === "forward" && r.rewritten);
  assert.equal(r.rewritten.bodyText, "v=real-note");
  assert.equal(header(r.rewritten.headers, "x-amz-content-sha256"), sha256Hex("v=real-note"));
  const out = { method: "PUT", url: r.rewritten.url, headers: r.rewritten.headers, body: Buffer.from("v=real-note") };
  assert.ok(matchSignature(out, parseSigV4Authorization(header(r.rewritten.headers, "authorization") as string)!, [SECRET]));
});

test("refused, nothing resolved: a signature no listed placeholder made", async () => {
  const a = arbiter({ signingKeys: [OTHER_KEY_PH] });
  const r = await gate(stsRequest(KEY_PH), a);
  assert.equal(r.action, "block");
  assert.match(r.action === "block" ? r.reason : "", /not made with the placeholder/);
  assert.equal(a.decisionCalls.length, 0);
});

test("refused: signed for one Host, sent to another (no replay of a real signature elsewhere)", async () => {
  const req = stsRequest(KEY_PH, { hostHeader: "sts.amazonaws.com" });
  const a = arbiter();
  const r = await gate({ ...req, destinationHost: "attacker.compute-1.amazonaws.com:443" }, a, { hostHeader: "attacker.compute-1.amazonaws.com" });
  assert.equal(r.action, "block");
  assert.match(r.action === "block" ? r.reason : "", /signs Host 'sts\.amazonaws\.com' but is sent to 'attacker/);
  assert.equal(a.decisionCalls.length, 0);
});

test("refused: a chunk-signed aws-chunked stream, SigV4a, an unknown payload mode", async () => {
  for (const mode of ["STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", "nonsense"]) {
    const req = agentRequest({
      host: "s3.us-west-2.amazonaws.com", method: "PUT", path: "/b/k",
      headers: { "X-Amz-Content-SHA256": mode }, body: "x",
      scope: "20261024/us-west-2/s3/aws4_request", signedHeaders: "host;x-amz-content-sha256;x-amz-date", signWith: KEY_PH,
    });
    const r = await gate(req, arbiter());
    assert.equal(r.action, "block", mode);
  }
  const v4a = stsRequest();
  const auth = (v4a.headers.Authorization as string).replace("AWS4-HMAC-SHA256", "AWS4-ECDSA-P256-SHA256");
  const r = await gate({ ...v4a, headers: { ...v4a.headers, Authorization: auth } }, arbiter());
  assert.equal(r.action, "block");
  assert.match(r.action === "block" ? r.reason : "", /SigV4a is not supported/);
});

test("an aws-chunked body with unsigned chunks is re-signed when untouched, refused when a release changes it", async () => {
  const ok = agentRequest({
    host: "s3.us-west-2.amazonaws.com", method: "PUT", path: "/b/k",
    headers: { "X-Amz-Content-SHA256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "Content-Encoding": "aws-chunked" }, body: "5\r\nhello\r\n0\r\n\r\n",
    scope: "20261024/us-west-2/s3/aws4_request", signedHeaders: "content-encoding;host;x-amz-content-sha256;x-amz-date", signWith: KEY_PH,
  });
  assert.equal((await gate(ok, arbiter())).action, "forward");
  const BODY_PH = "$MDU:nomodel_Read[ef56].NOTE";
  const changed = agentRequest({
    host: "s3.us-west-2.amazonaws.com", method: "PUT", path: "/b/k",
    headers: { "X-Amz-Content-SHA256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "Content-Encoding": "aws-chunked" }, body: `5\r\n${BODY_PH}\r\n0\r\n\r\n`,
    scope: "20261024/us-west-2/s3/aws4_request", signedHeaders: "content-encoding;host;x-amz-content-sha256;x-amz-date", signWith: KEY_PH,
  });
  const a = new MockArbiter({ decisionFn: allowAll, values: { ...VALUES, [BODY_PH]: "real" }, signingKeys: [KEY_PH] });
  const r = await gate(changed, a);
  assert.equal(r.action, "block");
  assert.match(r.action === "block" ? r.reason : "", /aws-chunked body that a released value changed/);
});

test("refused: the arbiter cannot list signing keys (absent op, or a throw) while the request carries a placeholder", async () => {
  const absent = new MockArbiter({ decisionFn: allowAll, values: VALUES });
  (absent as { signingKeys?: unknown }).signingKeys = undefined;
  assert.equal((await gate(stsRequest(), absent)).action, "block");
  assert.equal(absent.decisionCalls.length, 0);
  const failing = arbiter({ failSigningKeys: true });
  assert.equal((await gate(stsRequest(), failing)).action, "block");
  assert.equal(failing.decisionCalls.length, 0);
});

test("refused: the arbiter withholds the signing key (an unbound host it asks about)", async () => {
  const a = arbiter({
    decisionFn: (r) => r.symbol === KEY_PH
      ? { allow: false, requiresApproval: true, reason: "secret at an unbound destination" }
      : { allow: true, reason: "ok" },
  });
  const r = await gate(stsRequest(), a);
  assert.equal(r.action, "block");
  assert.ok(r.action === "block" && r.withheld.some((w) => w.symbol === KEY_PH));
});

test("refused: the human chose Send without it for the signing key", async () => {
  const a = arbiter({ decisionFn: (r) => r.symbol === KEY_PH ? { allow: false, requiresApproval: false, reason: "send without", strip: true } : { allow: true, reason: "ok" } });
  const r = await gate(stsRequest(), a);
  assert.equal(r.action, "block");
  assert.match(r.action === "block" ? r.reason : "", /cannot go without its signing key/);
});

test("the signing key's placeholder written into the request too is asked at every place it sits", async () => {
  const req = stsRequest();
  const a = arbiter({ decisionFn: (r) => r.symbol === KEY_PH ? { allow: false, requiresApproval: true, reason: "asks" } : { allow: true, reason: "ok" } });
  // The agent also puts the key's placeholder in a header of its own: not signed, so the signature still matches.
  const r = await gate({ ...req, headers: { ...req.headers, "X-Debug": KEY_PH } }, a);
  assert.equal(r.action, "block");
  assert.deepEqual(a.decisionCalls.find((c) => c.symbol === KEY_PH)?.positions, ["header", "signature"]);
});

test("a SigV4 request with no placeholder, signed by a key Mandu does not hold, goes as before", async () => {
  const real = {
    method: "POST", destinationHost: "sts.amazonaws.com:443", url: "https://sts.amazonaws.com/", bodyText: "Action=GetCallerIdentity&Version=2011-06-15",
    headers: { Host: "sts.amazonaws.com", "Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Amz-Date": WHEN, "X-Amz-Security-Token": TOKEN, Authorization: STS_REAL_AUTH },
  };
  const a = arbiter();
  const r = await gate(real, a);
  assert.equal(r.action, "forward");
  assert.ok(r.action === "forward" && r.rewritten === undefined);
  // And with no signingKeys op at all: still as before (nothing to re-sign).
  const absent = new MockArbiter({ decisionFn: allowAll, values: VALUES });
  (absent as { signingKeys?: unknown }).signingKeys = undefined;
  assert.equal((await gate(real, absent)).action, "forward");
});

test("fail-closed on the scheme: a SigV4 request in a postgres (or any non-HTTP) request is refused, nothing resolved", async () => {
  for (const scheme of ["postgres", "mysql"] as const) {
    const a = arbiter();
    const req = stsRequest(KEY_PH);
    const r = await gate({ ...req, destinationHost: "prod.abc123.us-east-1.rds.amazonaws.com:5432" }, a, { scheme: scheme as never, hostHeader: "prod.abc123.us-east-1.rds.amazonaws.com" });
    assert.equal(r.action, "block", scheme);
    assert.match(r.action === "block" ? r.reason : "", new RegExp(`in a ${scheme} request: only HTTP and HTTPS requests are signed again`));
    assert.equal(a.decisionCalls.length, 0, `${scheme}: nothing asked, nothing resolved`);
  }
  // http and https are judged as before.
  const ok = await gate(stsRequest(KEY_PH), arbiter());
  assert.equal(ok.action, "forward");
});
