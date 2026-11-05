/**
 * sigv4.test — the egress proxy's SigV4 signer (src/sigv4.ts;
 * docs/design/confidentiality/aws-sigv4-resign.md) against signatures it
 * did not make: AWS's published test-suite vector (`get-vanilla`) and
 * requests signed by botocore 1.40.72 (`SigV4Auth`, `S3SigV4Auth`; the
 * script that made them is in the design note, §8). Each must be matched
 * by `matchSignature` from the request as sent, and re-signed to the same
 * bytes with the key that made it.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  awsUriEncode, canonicalRequest, matchSignature, normalHost, parseSigV4Authorization, payloadModeOf,
  rawPathAndQuery, resignedAuthorization, sigv4AuthorizationOf, sigv4Signature, signingKey, type SigV4Request,
} from "../../src/sigv4.js";

const SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const TOKEN = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";
const WHEN = "20261024T121033Z";
const HELLO_SHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

interface Vector { name: string; method: string; url: string; headers: Record<string, string>; body?: string; signature: string }

/** botocore 1.40.72 (and AWS's suite for get-vanilla-2015). */
const VECTORS: Vector[] = [
  {
    // AWS's SigV4 test suite, get-vanilla (the published signature).
    name: "aws-suite get-vanilla", method: "GET", url: "https://example.amazonaws.com/",
    headers: { Host: "example.amazonaws.com", "X-Amz-Date": "20150830T123600Z",
      Authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31" },
    signature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
  },
  {
    name: "botocore get-vanilla", method: "GET", url: "https://example.amazonaws.com/",
    headers: { Host: "example.amazonaws.com", "X-Amz-Date": WHEN,
      Authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=abca31987030a8e6c754843a41a91fa68fad3e95935a9cd56034a89c3d6046da" },
    signature: "abca31987030a8e6c754843a41a91fa68fad3e95935a9cd56034a89c3d6046da",
  },
  {
    name: "botocore iam ListUsers (a query)", method: "GET", url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
    headers: { Host: "iam.amazonaws.com", "Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Amz-Date": WHEN,
      Authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=d1bcf48dbcdf64640813119b14373a9aac651bf235442b77d7ee48d803474fb0" },
    signature: "d1bcf48dbcdf64640813119b14373a9aac651bf235442b77d7ee48d803474fb0",
  },
  {
    name: "botocore sts POST with a session token", method: "POST", url: "https://sts.amazonaws.com/",
    headers: { Host: "sts.amazonaws.com", "Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Amz-Date": WHEN, "X-Amz-Security-Token": TOKEN,
      Authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=bdca9269a4b1a1c77d43711b923a90bda71751fa8897ce67c9793013bf4a8f57" },
    body: "Action=GetCallerIdentity&Version=2011-06-15",
    signature: "bdca9269a4b1a1c77d43711b923a90bda71751fa8897ce67c9793013bf4a8f57",
  },
  {
    name: "botocore path with dot segments, a space and a double slash", method: "GET", url: "https://example.amazonaws.com/a/./b/../c%20d//e",
    headers: { Host: "example.amazonaws.com", "X-Amz-Date": WHEN,
      Authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=fe19f587aed13636d8840d5173a34b4ed78ce7d43fc78408ff95764eb5992223" },
    signature: "fe19f587aed13636d8840d5173a34b4ed78ce7d43fc78408ff95764eb5992223",
  },
  {
    name: "botocore unsorted query, a repeated key, a bare key", method: "GET", url: "https://example.amazonaws.com/?b=2&a=1&a=0&c",
    headers: { Host: "example.amazonaws.com", "X-Amz-Date": WHEN,
      Authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=2b65b25487ec15455a095fb8c09a168a01ea5e42e17ff4ec23e07db79b8fc2fd" },
    signature: "2b65b25487ec15455a095fb8c09a168a01ea5e42e17ff4ec23e07db79b8fc2fd",
  },
  {
    name: "botocore S3 virtual-host PUT with a token (hashed payload)", method: "PUT", url: "https://bucket.s3.us-west-2.amazonaws.com/dir/my%20file.txt",
    headers: { Host: "bucket.s3.us-west-2.amazonaws.com", "X-Amz-Date": WHEN, "X-Amz-Security-Token": TOKEN, "X-Amz-Content-SHA256": HELLO_SHA,
      Authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=0c029be0c86e7655642afe546dff5cca240ae53b20dc9273b75e0c3578afdbac" },
    body: "hello",
    signature: "0c029be0c86e7655642afe546dff5cca240ae53b20dc9273b75e0c3578afdbac",
  },
  {
    name: "botocore S3 path-style PUT, a double slash kept", method: "PUT", url: "https://s3.us-west-2.amazonaws.com/bucket/a//b.txt",
    headers: { Host: "s3.us-west-2.amazonaws.com", "X-Amz-Date": WHEN, "X-Amz-Content-SHA256": HELLO_SHA,
      Authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261024/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=3fb010ccfb1514d4f0afa5f88e592c71fdac118632c05cf5441ed039ff90938a" },
    body: "hello",
    signature: "3fb010ccfb1514d4f0afa5f88e592c71fdac118632c05cf5441ed039ff90938a",
  },
];

const asReq = (v: Vector): SigV4Request => ({ method: v.method, url: v.url, headers: v.headers, body: Buffer.from(v.body ?? "", "utf8") });

for (const v of VECTORS) {
  test(`matches and re-makes a signature it did not make: ${v.name}`, () => {
    const auth = parseSigV4Authorization(v.headers.Authorization!);
    assert.ok(auth, "the Authorization parses");
    assert.equal(auth.accessKey, "AKIDEXAMPLE");
    const hit = matchSignature(asReq(v), auth, ["not-the-key", SECRET]);
    assert.ok(hit, "one canonical form reproduces the SDK's signature");
    assert.equal(hit.secret, SECRET);
    assert.equal(sigv4Signature(asReq(v), auth, SECRET, hit.form), v.signature);
  });
}

test("no candidate matches a request signed with another key, and a changed byte breaks the match", () => {
  const v = VECTORS[3]!;
  const auth = parseSigV4Authorization(v.headers.Authorization!)!;
  assert.equal(matchSignature(asReq(v), auth, ["$MDU:nomodel_Read[ab12].default.aws_secret_access_key"]), null);
  assert.equal(matchSignature({ ...asReq(v), body: Buffer.from("Action=GetCallerIdentity&Version=2011-06-16") }, auth, [SECRET]), null);
  assert.equal(matchSignature({ ...asReq(v), headers: { ...v.headers, Host: "sts.evil.example" } }, auth, [SECRET]), null);
});

test("AWS's documented signing key for the 2015 example", () => {
  // "Calculate the signature": 20150830 / us-east-1 / iam.
  assert.equal(signingKey(SECRET, "20150830", "us-east-1", "iam").toString("hex"), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
});

test("the signature of a placeholder key re-signs to the real key's (what the proxy does)", () => {
  const placeholder = "$MDU:nomodel_Read[ab12].default.aws_secret_access_key";
  const base = VECTORS[1]!;
  const auth0 = parseSigV4Authorization(base.headers.Authorization!)!;
  const form = { uri: "normalized", query: "raw" } as const;
  const agentSig = sigv4Signature(asReq(base), auth0, placeholder, form)!;
  const agentAuth = resignedAuthorization(base.headers.Authorization!, agentSig);
  const agentReq = { ...asReq(base), headers: { ...base.headers, Authorization: agentAuth } };
  const auth = parseSigV4Authorization(agentAuth)!;
  const hit = matchSignature(agentReq, auth, [placeholder]);
  assert.ok(hit);
  const real = sigv4Signature(agentReq, auth, SECRET, hit.form)!;
  assert.equal(resignedAuthorization(agentAuth, real), base.headers.Authorization);
});

test("parse refuses what is not a SigV4 Authorization", () => {
  assert.equal(parseSigV4Authorization("Bearer abc"), null);
  assert.equal(parseSigV4Authorization("AWS4-HMAC-SHA256 Credential=AK/20261024/us-east-1/s3/aws4_request, SignedHeaders=host"), null);
  assert.equal(parseSigV4Authorization("AWS4-HMAC-SHA256 Credential=AK/2026/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=" + "a".repeat(64)), null);
  assert.equal(parseSigV4Authorization("AWS4-HMAC-SHA256 Credential=AK/20261024/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=" + "a".repeat(64) + ", Signature=" + "b".repeat(64)), null);
  const p = parseSigV4Authorization("AWS4-ECDSA-P256-SHA256 Credential=$MDU:nomodel_Env[ab12].AWS_ACCESS_KEY_ID/20261024/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=" + "c".repeat(64));
  assert.ok(p);
  assert.equal(p.algorithm, "AWS4-ECDSA-P256-SHA256");
  assert.equal(p.accessKey, "$MDU:nomodel_Env[ab12].AWS_ACCESS_KEY_ID");
  // A SigV4a request never matches: the release signs HMAC-SHA256 only.
  assert.equal(matchSignature(asReq(VECTORS[1]!), p, [SECRET]), null);
});

test("sigv4AuthorizationOf: one AWS4 Authorization, or ambiguous", () => {
  assert.equal(sigv4AuthorizationOf({ Authorization: "Bearer x" }), null);
  assert.equal(sigv4AuthorizationOf({ authorization: ["AWS4-HMAC-SHA256 x", "Bearer y"] }), "ambiguous");
  const one = sigv4AuthorizationOf({ authorization: VECTORS[1]!.headers.Authorization! });
  assert.ok(one && one !== "ambiguous" && one.parsed);
});

test("payload modes", () => {
  assert.equal(payloadModeOf({}), "absent");
  assert.equal(payloadModeOf({ "x-amz-content-sha256": HELLO_SHA }), "hashed");
  assert.equal(payloadModeOf({ "X-Amz-Content-SHA256": "UNSIGNED-PAYLOAD" }), "unsigned");
  assert.equal(payloadModeOf({ "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER" }), "streaming-unsigned");
  assert.equal(payloadModeOf({ "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" }), "streaming-signed");
  assert.equal(payloadModeOf({ "x-amz-content-sha256": "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER" }), "streaming-signed");
  assert.equal(payloadModeOf({ "x-amz-content-sha256": "nope" }), "other");
});

test("helpers: raw path and query, the encoder, the host compare", () => {
  assert.deepEqual(rawPathAndQuery("https://h.example/a%20b/?x=1&y"), { path: "/a%20b/", query: "x=1&y" });
  assert.deepEqual(rawPathAndQuery("https://h.example"), { path: "/", query: "" });
  assert.deepEqual(rawPathAndQuery("/p?q#frag"), { path: "/p", query: "q" });
  assert.equal(awsUriEncode("/a b%2F~é", true), "/a%20b%252F~%C3%A9");
  assert.equal(normalHost("S3.amazonaws.com:443", "https"), "s3.amazonaws.com");
  assert.equal(normalHost("s3.amazonaws.com:8443", "https"), "s3.amazonaws.com:8443");
  // The canonical request of AWS's 2015 iam example (its documented hash).
  const v: SigV4Request = {
    method: "GET", url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", body: Buffer.alloc(0),
    headers: { Host: "iam.amazonaws.com", "Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Amz-Date": "20150830T123600Z" },
  };
  const auth = parseSigV4Authorization("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=" + "0".repeat(64))!;
  const cr = canonicalRequest(v, auth, { uri: "normalized", query: "raw" })!;
  assert.equal(cr.split("\n").length, 9);
  assert.equal(sigv4Signature(v, auth, SECRET, { uri: "normalized", query: "raw" }), "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
});
