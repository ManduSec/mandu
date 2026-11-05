# AWS: the egress proxy re-signs SigV4 with the real key

Built 2026-10-24. Decision note on [`confidentiality.md`](confidentiality.md)
§2.3 (the issuer bindings, whose "Left out" list named AWS) and on the wire
release of [plan 10](confidentiality-plan-10-flow-taint.md) §11.5.
Mandu-new (no reference origin).

## 1. The gap

In the agent's world `~/.aws/credentials` is a placeholder file: each of
`aws_access_key_id`, `aws_secret_access_key` and `aws_session_token` is a
`$MDU:` placeholder (the INI reading of `secret-extract.ts`), and so are
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` in the
environment (plan 10 §11.4). The wire release puts a placeholder back where
it sits in a request; AWS's Signature Version 4 never sends the secret key.
The client derives a signing key from it and sends an HMAC over the request
(`Authorization: AWS4-HMAC-SHA256 Credential=<id>/<scope>, SignedHeaders=…,
Signature=…`). A program signing with the placeholder makes a signature AWS
rejects, and there was no placeholder in the request to put back. So `aws`
and every SDK failed unless the user listed `aws` as a reader of the file
(`prints: nothing`), and an environment-variable key could not work at all
(plan 10 §11.4, "Stated gap"). This is one of the three gaps that kept
Mandu's "programs can still use it" requirement at Partly.

## 2. The decision

The egress proxy re-signs. On the TLS-inspected leg it reads the decrypted
request (`interceptors/net-proxy/src/egress.ts`, `sigv4Plan` and
`resignRequest`; the algorithm in `src/sigv4.ts`):

1. **Which placeholder signed it.** The arbiter lists the placeholders of
   the session's AWS secret access keys (`signingKeys`, names only). The
   proxy recomputes the request's signature with each, as the key, over the
   request exactly as received. A match is cryptographic proof that this
   placeholder signed these bytes.
2. **The gate decides it where its value goes.** The matched placeholder is
   added to the request's placeholders at a new position, `signature`
   (`RequestPosition`: nowhere in the request; the value is a key the proxy
   signs with). The access key id (in `Credential=`) and the session token
   (in `X-Amz-Security-Token`, which counts as `authorization` in a SigV4
   request) are decided where they sit, like any placeholder. One withheld
   placeholder refuses the whole request, as always.
3. **The released request is signed again.** Every placeholder is put
   back, a body the release changed gets its stated hash recomputed, and
   the proxy signs the request it sends with the real key in the canonical
   form the agent's signature matched. Only the `Signature=` value changes.

The real secret key never enters a request. What leaves is the access key
id, the session token and an HMAC made with the key.

## 3. Who may receive it: the AWS signing release

With nothing else, step 2 asks: nothing binds a fresh install's
`~/.aws/credentials` (`egress:secret-unbound`, an Approvals card per AWS
host, and AWS has one host per service, region and bucket). The default
catalog therefore has an **AWS signing release** beside its issuer table
(`arbiter/policy/aws-signing.ts`, composed in `server.ts` right after the
issuer release; rule `egress:secret-aws-signing`). Every condition is
required:

- the row is one the issuer release may read (`issuerSourceOf`: a
  registered file's own field row, or a masked environment variable, the
  user's own and trusted; never a copy, a derived row, a comment line);
- its name says which credential it is (`awsCredentialRole`, the last
  dotted piece, case folded): `aws_secret_access_key` (the secret),
  `aws_access_key_id` (the id), `aws_session_token` or the older
  `aws_security_token` (the token). So a profile of `~/.aws/credentials`
  or `~/.aws/config`, a masked `AWS_SECRET_ACCESS_KEY`, and the same keys
  in a `.env` a program loads;
- the destination is an AWS endpoint name (`isAwsEndpoint`): under
  `amazonaws.com`, `amazonaws.com.cn` or `api.aws`, port 443 or none,
  never an address;
- HTTPS;
- the positions: the secret **only** at `signature`; the id and the token
  only at `authorization`;
- the switch: `issuer_bindings` on, `aws` not under `issuers_off` (a valid
  id now), the value's name not under `values_off`.

After every standing answer, the lockdown and the human's answer about the
file at that host, as the issuer release.

**Why a suffix, when the issuer table refuses one.** AWS has no fixed list
of API hosts, and anyone can own a name under `amazonaws.com` (an S3
bucket, an EC2 public name, an API Gateway stage). So the release is built
so that what such an owner receives is useless to them:

- the signature is an HMAC under a key derived for one day, region and
  service, over a request that names its Host. **The proxy re-signs only
  when the Host the agent signed is the Host it sends to**
  (`signs Host 'x' but is sent to 'y'` otherwise): a request signed for
  `sts.amazonaws.com` and sent to `attacker.compute-1.amazonaws.com` is
  refused, so no owner of a suffix host ever holds a real signature valid
  at a real endpoint;
- the access key id is an identifier, and the session token signs nothing
  without the secret;
- the secret itself is never released as bytes by this rule: the same
  placeholder in a header, the body or the URL, or beside the signature,
  asks exactly as an unbound secret does (`egress:secret-unbound`).

What the release does not stop, and no release can: a request the agent
chose to make with the user's AWS identity at a real AWS endpoint (an
upload to a bucket it names). That is the user's authority used as the
agent was asked, the same as any bound credential, and the egress
inspection and session trace record it; the secret does not leave.

## 4. What else the leg needed

- **The body's own bytes.** The inspected and plain legs used to forward
  `Buffer.from(rewrittenText, "utf8")` whenever any placeholder was
  released, which rewrites a binary body (an S3 upload) that UTF-8 could
  not read. The gate now gets the bytes (`GateInput.bodyBytes`) and both
  legs forward them unless the release changed the body's text.
- **The path as written.** The inspected leg re-parsed a rewritten URL
  with the WHATWG parser, which resolves `./` and `../` and re-encodes;
  S3 signs the path as sent. `rewrittenPath` keeps the client's path when
  the release left the URL alone and otherwise takes the rewritten text
  after the same authority, unparsed.
- **`Expect: 100-continue`.** The SDKs send it on every S3 upload and wait
  for the 100 before the body; the proxy needs the whole body before the
  gate runs and used to wait for the body until its idle timeout. It now
  answers the 100 itself and drops the header upstream (`readHttpRequest`,
  `reoriginationHead`).

## 5. Canonical forms

AWS's own canonicalization is the service's; the agent's signature covers
the SDK's. The proxy tries each form an SDK uses and re-signs in the one
that matched (`CANONICAL_FORMS`): the URI raw (S3) or normalized and
encoded again (botocore and the JavaScript SDK for the other services; plus
encoded without normalizing), the query as written and sorted (botocore)
or decoded and encoded by RFC 3986 (the JavaScript SDK, the spec). The
payload hash is `x-amz-content-sha256` when sent (S3 signs that header),
else the body's SHA-256.

Payloads: a hashed one (`x-amz-content-sha256` a hex hash) is rehashed if
the release changed the body; `UNSIGNED-PAYLOAD` goes as it is;
`STREAMING-UNSIGNED-PAYLOAD-TRAILER` (aws-chunked with unsigned chunks,
which botocore 1.36 and later use for every PutObject) goes when the
release left the body alone and is refused when it changed it.

## 6. Refused, and still open

Each refusal below is fail-closed and only in a request that carries a
placeholder or was signed by one; a SigV4 request with neither (a key of
the program's own, an allowed reader's real key) goes as before.

- **Chunk-signed streams** (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, with or
  without a trailer): every chunk carries a signature chained from the
  header's. Re-signing them is the same HMAC over each chunk; not built.
- **SigV4a** (`AWS4-ECDSA-P256-SHA256`, multi-region access points): an
  ECDSA key derived from the secret. Not built.
- **Presigned URLs** (`X-Amz-Signature` in the query, `aws s3 presign`):
  the access key id's placeholder in the URL is refused by the position
  rules, and a URL made locally and printed is for someone else, who never
  goes through the proxy. Not built.
- **A signed Host other than the one sent to**, a signature none of the
  listed placeholders made (or made in a form the proxy does not read), an
  arbiter that cannot list the keys, two Authorization headers, a signing
  key the human sends without: refused.
- **Credentials that arrive by the network.** `aws sso login`, `aws sts
  assume-role` and the container and instance credential endpoints return
  temporary credentials in a response, which reaches the agent's program
  raw (the response path does not mask them). Plan 10's flow taint then
  holds that program. Not changed here.
- **`mandu why --to` and Test a flow** read no request and no signature,
  so they keep answering "asks" for an AWS secret at an AWS host.
- **The product page** counts a re-signed request among the "sends with a
  real value filled in" (the access key id and the token were); the
  secret key itself did not leave. Not reworded yet.

## 7. Tests

- `interceptors/net-proxy/test/unit/sigv4.test.ts`: AWS's published
  vectors (the SigV4 test suite's `get-vanilla`, the documented 2015 IAM
  example's signing key and signature) and botocore-made signatures (STS
  with a token, a query, dot segments, S3 virtual-host and path-style),
  each matched from the request as sent and re-made with the key.
- `interceptors/net-proxy/test/unit/sigv4-gate.test.ts`: the gate over the
  mock arbiter: a placeholder-signed request leaves with botocore's exact
  Authorization for the real key; the positions asked; a binary body; a
  rehashed body; every refusal above; a request with no placeholder goes
  as before.
- `arbiter/test/unit/aws-signing.test.ts` (the pure rule) and
  `arbiter/test/component/aws-signing-gate.test.ts` (the real gate over
  IPC: every condition, the masked variables, `signingKeys`, the switch,
  the axis off).
- `tests/stack/aws-sigv4-resign.test.ts`, the oracle: the real arbiter,
  the real proxy in its production wiring and fake AWS endpoints that
  accept only the real key's signature. A placeholder-signed STS call and
  S3 PUT are accepted; the same to a host that is no endpoint, and one
  signed for STS sent to another `amazonaws.com` host, reach nothing;
  with boto3 installed, boto3 itself (STS GetCallerIdentity, S3 PutObject
  aws-chunked) works with the placeholders; the real key reaches no host,
  and no real value is in the twin, the refusals or the events.
- `tests/stack/proxy-real-client-parity.test.ts`: `signingKeys` over the
  production wiring.

## 8. The botocore vectors

Made with botocore 1.40.72 (`SigV4Auth` / `S3SigV4Auth.add_auth` over an
`AWSRequest`, credentials `AKIDEXAMPLE` /
`wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, and the suite's example token
for the token cases); the requests and signatures are the test's table.
