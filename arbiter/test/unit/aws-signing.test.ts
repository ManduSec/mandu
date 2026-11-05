/**
 * aws-signing — the AWS signing release's pure rule (policy/aws-signing.ts;
 * docs/design/confidentiality/aws-sigv4-resign.md): which names are which
 * AWS credential, which hosts are AWS endpoints, and each condition of the
 * release on its own.
 *
 * Mandu-new test. Axes stated: `secrets` (the rule is the confidentiality
 * axis's).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { awsCredentialRole, awsSigningRelease, isAwsEndpoint } from "../../policy/aws-signing.js";
import { DEFAULT_ISSUER_BINDINGS, checkIssuerBindings, compileIssuerBindings } from "../../policy/issuer-bindings.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

test("awsCredentialRole: by the names the CLI and the SDKs read", () => {
  assert.equal(awsCredentialRole(["default.aws_secret_access_key"]), "secret");
  assert.equal(awsCredentialRole(["prod.AWS_SECRET_ACCESS_KEY"]), "secret");
  assert.equal(awsCredentialRole(["AWS_SECRET_ACCESS_KEY"]), "secret");
  assert.equal(awsCredentialRole(["default.aws_access_key_id"]), "id");
  assert.equal(awsCredentialRole(["AWS_SESSION_TOKEN"]), "token");
  assert.equal(awsCredentialRole(["AWS_SECURITY_TOKEN"]), "token");
  for (const n of ["MY_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key_old", "STRIPE_KEY", "default.region", ""]) assert.equal(awsCredentialRole([n]), null, n);
  assert.equal(awsCredentialRole(["AWS_SECRET_ACCESS_KEY", "default.aws_access_key_id"]), null, "two names that disagree");
});

test("isAwsEndpoint: under amazonaws.com, amazonaws.com.cn or api.aws, port 443 or none, never an address", () => {
  for (const d of ["s3.amazonaws.com", "sts.amazonaws.com:443", "bucket.s3.us-west-2.amazonaws.com", "ec2.cn-north-1.amazonaws.com.cn:443", "s3.dualstack.us-east-1.api.aws", "https://iam.amazonaws.com/"]) {
    assert.equal(isAwsEndpoint(d), true, d);
  }
  for (const d of ["amazonaws.com", "api.aws", "amazonaws.com.evil.io", "s3amazonaws.com", "s3.amazonaws.com:8443", "52.95.0.1", "[::1]:443", "http://s3.amazonaws.com/", "*.amazonaws.com", 7, undefined]) {
    assert.equal(isAwsEndpoint(d), false, String(d));
  }
});

test("awsSigningRelease: every condition on its own", () => {
  const on = DEFAULT_ISSUER_BINDINGS;
  const base = { names: ["default.aws_secret_access_key"], destination: "s3.amazonaws.com:443", scheme: "https", positions: ["signature"] };
  assert.deepEqual(awsSigningRelease(base, on), { role: "secret" });
  assert.deepEqual(awsSigningRelease({ ...base, positions: ["authorization"] }, on), { miss: "position" });
  assert.deepEqual(awsSigningRelease({ ...base, positions: ["signature", "body"] }, on), { miss: "position" });
  assert.deepEqual(awsSigningRelease({ ...base, positions: [] }, on), { miss: "position" });
  assert.deepEqual(awsSigningRelease({ ...base, positions: "signature" }, on), { miss: "position" });
  assert.deepEqual(awsSigningRelease({ ...base, scheme: "http" }, on), { miss: "scheme" });
  assert.deepEqual(awsSigningRelease({ ...base, destination: "evil.example" }, on), { miss: "host" });
  assert.deepEqual(awsSigningRelease({ ...base, names: ["STRIPE_KEY"] }, on), { miss: "not-aws" });
  const id = { ...base, names: ["AWS_ACCESS_KEY_ID"] };
  assert.deepEqual(awsSigningRelease({ ...id, positions: ["authorization"] }, on), { role: "id" });
  assert.deepEqual(awsSigningRelease(id, on), { miss: "position" }, "an id is no signing key");
  assert.deepEqual(awsSigningRelease(base, compileIssuerBindings(false)), { miss: "off" });
  assert.deepEqual(awsSigningRelease(base, compileIssuerBindings({ issuers_off: ["aws"] })), { miss: "off" });
  assert.deepEqual(awsSigningRelease(base, compileIssuerBindings({ values_off: ["*aws_secret_access_key"] })), { miss: "value-off" });
  assert.deepEqual(awsSigningRelease(base, compileIssuerBindings({ issuers_off: ["stripe"] })), { role: "secret" });
});

test("issuers_off accepts aws, still refuses an unknown id", () => {
  const ok: string[] = [];
  checkIssuerBindings({ issuers_off: ["aws", "stripe"] }, "issuer_bindings", ok);
  assert.deepEqual(ok, []);
  const bad: string[] = [];
  checkIssuerBindings({ issuers_off: ["amazon"] }, "issuer_bindings", bad);
  assert.equal(bad.length, 1);
  assert.match(bad[0]!, /aws/);
});
