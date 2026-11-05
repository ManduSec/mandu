/**
 * aws-sigv4-resign — `aws` and the AWS SDKs work in the agent's world with
 * the placeholders of `~/.aws/credentials`: the egress proxy re-signs each
 * SigV4 request with the real key (docs/design/confidentiality/aws-sigv4-resign.md),
 * over the REAL components: an ArbiterServer in `secrets` mode with the
 * launch HOME's `~/.aws/credentials` registered as the launcher does (no
 * label of the user's, no binding), the REAL NetProxy with TLS inspection
 * in its production wiring (`new ArbiterClientAdapter(new ArbiterClient(data),
 * new ArbiterClient(human))`), and fake AWS endpoints that accept a request
 * only when its signature is the REAL key's.
 *
 *   1. a request signed with the placeholder key (STS, and an S3 PUT with a
 *      hashed payload) reaches its AWS endpoint with the real access key id,
 *      the real session token and a signature the real key made: accepted;
 *   2. the same placeholder-signed request to a host that is no AWS
 *      endpoint is refused (an ask: nothing binds the key there), and one
 *      signed for an AWS host but sent to another host under amazonaws.com
 *      (anyone can own one) is refused: neither host receives anything;
 *   3. with botocore installed (self-SKIP otherwise): boto3 itself, given
 *      the placeholders, its HTTPS through the proxy and the session CA,
 *      calls STS GetCallerIdentity and S3 PutObject (aws-chunked, the
 *      SDK's own choice) and both are accepted;
 *   4. THE ORACLE: the real secret key never reaches any host (only an
 *      HMAC made with it does), no real value reaches a host the key is
 *      not for, and none is in what the agent's world reads back (the
 *      registration's twin, the proxy's refusals, the session's events).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { matchSignature, parseSigV4Authorization, resignedAuthorization, sha256Hex, sigv4Signature, type CanonicalForm } from "../../interceptors/net-proxy/src/sigv4.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const OPENSSL = opensslAvailable();
const BOTO = spawnSync("python3", ["-I", "-c", "import boto3, botocore"], { stdio: "ignore" }).status === 0;

const ID = "AKIAMANDUSIGV4E2E0001";
const SECRET = "mAnDuSigV4e2eRealSecret/Key+0123456789ab";
const TOKEN = "IQoJb3JpZ2luX2VjEMANDUe2eRealSessionToken//////////wEaCXVzLWVhc3QtMSJHMEUCIQ";

const STS = "sts.us-east-1.amazonaws.com";
const S3 = "bucket.s3.us-west-2.amazonaws.com";
const LOOKALIKE = "attacker.compute-1.amazonaws.com";
const EVIL = "evil.example";

interface Got { site: string; method: string; url: string; headers: Record<string, string | string[] | undefined>; body: Buffer; verified: boolean }

/** A fake AWS endpoint: 200 only for a request the REAL key signed. */
async function awsEndpoint(dir: string, host: string, got: Got[]) {
  const ca = ensureCa(join(dir, `ca-${host.replace(/[^a-z0-9.]/gi, "_")}`));
  const leaf = leafForHost(ca, host);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const headers = req.headers as Record<string, string | string[] | undefined>;
      const auth = typeof headers.authorization === "string" ? parseSigV4Authorization(headers.authorization) : null;
      const verified = auth !== null && auth.accessKey === ID &&
        matchSignature({ method: req.method ?? "GET", url: `https://${host}${req.url}`, headers, body }, auth, [SECRET]) !== null;
      got.push({ site: host, method: req.method ?? "", url: req.url ?? "", headers, body, verified });
      if (!verified) {
        res.writeHead(403, { "content-type": "text/xml" });
        res.end("<Error><Code>SignatureDoesNotMatch</Code></Error>");
        return;
      }
      if (host === STS) {
        res.writeHead(200, { "content-type": "text/xml" });
        res.end('<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>' +
          "<Arn>arn:aws:iam::123456789012:user/mandu-e2e</Arn><UserId>AIDAMANDUE2E</UserId><Account>123456789012</Account>" +
          "</GetCallerIdentityResult><ResponseMetadata><RequestId>e2e-1</RequestId></ResponseMetadata></GetCallerIdentityResponse>");
        return;
      }
      res.writeHead(200, { etag: '"e2e"', "content-length": "0" });
      res.end();
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { host, port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** CONNECT `target` through the proxy, TLS trusting the session CA, send one
 *  request as written; the status. */
function viaConnect(proxyPort: number, target: string, sni: string, sessionCa: string, request: Buffer): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${target}:443 HTTP/1.1\r\nHost: ${target}:443\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      head = Buffer.concat([head, c]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      raw.off("data", onData);
      const line = head.subarray(0, idx).toString("latin1").split("\r\n")[0]!;
      if (!/ 200 /.test(`${line} `)) {
        raw.destroy();
        resolve({ status: Number(/HTTP\/1\.1 (\d{3})/.exec(line)?.[1] ?? 0), text: line });
        return;
      }
      const tls = tlsConnect({ socket: raw, ca: sessionCa, servername: sni }, () => tls.write(request));
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0), text });
      });
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("request timed out")), 15_000).unref();
  });
}

/** A request as an SDK in the agent's world makes it: the placeholders for
 *  the id and the token, signed with the key's placeholder. */
function agentRequest(o: {
  host: string; method: string; path: string; body: string; service: string; region: string;
  extra: Record<string, string>; form: CanonicalForm; ph: { id: string; key: string; token: string };
}): Buffer {
  const amzDate = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const headers: Record<string, string> = {
    Host: o.host, "X-Amz-Date": amzDate, "X-Amz-Security-Token": o.ph.token, ...o.extra,
    "Content-Length": String(Buffer.byteLength(o.body)),
  };
  const signed = ["host", ...Object.keys(o.extra).map((k) => k.toLowerCase()), "x-amz-date", "x-amz-security-token"].sort();
  const auth0 = `AWS4-HMAC-SHA256 Credential=${o.ph.id}/${amzDate.slice(0, 8)}/${o.region}/${o.service}/aws4_request, SignedHeaders=${signed.join(";")}, Signature=${"0".repeat(64)}`;
  headers.Authorization = auth0;
  const sig = sigv4Signature({ method: o.method, url: `https://${o.host}${o.path}`, headers, body: Buffer.from(o.body) }, parseSigV4Authorization(auth0)!, o.ph.key, o.form)!;
  headers.Authorization = resignedAuthorization(auth0, sig);
  const head = [`${o.method} ${o.path} HTTP/1.1`, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), "Connection: close", "", ""].join("\r\n");
  return Buffer.concat([Buffer.from(head, "utf8"), Buffer.from(o.body, "utf8")]);
}

const BOTO_SCRIPT = `
import json, boto3
from botocore.config import Config
cfg = Config(retries={"max_attempts": 1, "mode": "standard"})
out = {}
sts = boto3.client("sts", region_name="us-east-1", endpoint_url="https://${STS}", config=cfg)
out["sts"] = sts.get_caller_identity()["Account"]
s3 = boto3.client("s3", region_name="us-west-2", config=cfg)
r = s3.put_object(Bucket="bucket", Key="notes/today.txt", Body=b"hello from boto3")
out["s3"] = r["ResponseMetadata"]["HTTPStatusCode"]
print(json.dumps(out))
`;

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p));
    else out.push(p);
  }
  return out;
}

test(
  "SigV4 requests signed with the placeholder key reach AWS signed with the real key; nothing reaches another host; no real value reaches the agent's world",
  { skip: !OPENSSL && "openssl unavailable", timeout: 120_000 },
  async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-sigv4-"));
    const home = join(dir, "home");
    mkdirSync(join(home, ".aws"), { recursive: true });
    const creds = join(home, ".aws", "credentials");
    writeFileSync(creds, `[default]\naws_access_key_id = ${ID}\naws_secret_access_key = ${SECRET}\naws_session_token = ${TOKEN}\n`);
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const eventDir = join(dir, "events");
    const server = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: join(dir, "admin.sock"),
      dbPath: join(dir, "mandu.db"), eventDir, log: () => {},
      adminPolicyDir: null, packDir: null, confidentiality: true, integrity: false,
      // A fresh install: no label of the user's, no binding.
      policyDocument: { version: 1 },
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const got: Got[] = [];
    const sites = await Promise.all([STS, S3, LOOKALIKE, EVIL].map((h) => awsEndpoint(dir, h, got)));
    const yaml = ["hosts:", ...sites.flatMap((s) => [`  - host: "${s.host}"`, `    tls_to: 127.0.0.1:${s.port}`, `    tls_ca: ${JSON.stringify(s.caPath)}`]), ""].join("\n");
    const caDir = join(dir, "mitm");
    const proxyLog: string[] = [];
    const proxy = new NetProxy({
      allowThisMachine: true, log: (m: string) => proxyLog.push(m), sessionId: "sess-sigv4", mockSites: MockSites.fromYaml(yaml), mitm: { caDir },
      arbiter: new NetProxyAdapter(data as unknown as NetProxyRealClient, human as never),
      attributeHolders: () => [{ procKey: "8100-1", ancestors: [] }],
    });
    try {
      const port = await proxy.listen(0);
      const caPem = readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8");
      const reg = await human.registerSecret({ path: creds, home, sessionKey: "sess-sigv4" });
      assert.ok(reg.twin, reg.reason);
      const field = (k: string) => new RegExp(`^${k} = (\\$MDU:\\S+)$`, "m").exec(reg.twin!)?.[1];
      const ph = { id: field("aws_access_key_id")!, key: field("aws_secret_access_key")!, token: field("aws_session_token")! };
      assert.ok(ph.id && ph.key && ph.token, reg.twin);
      const seen: string[] = [reg.twin!];

      // 1. STS (a hashed body, botocore's form) and an S3 PUT (a hashed payload, the raw path).
      const sts = agentRequest({
        host: STS, method: "POST", path: "/", body: "Action=GetCallerIdentity&Version=2011-06-15", service: "sts", region: "us-east-1",
        extra: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" }, form: { uri: "normalized", query: "raw" }, ph,
      });
      const r1 = await viaConnect(port, STS, STS, caPem, sts);
      seen.push(r1.text);
      assert.equal(r1.status, 200, r1.text);
      const put = agentRequest({
        host: S3, method: "PUT", path: "/notes/./my%20day.txt", body: "hello", service: "s3", region: "us-west-2",
        extra: { "X-Amz-Content-SHA256": sha256Hex("hello") }, form: { uri: "raw", query: "raw" }, ph,
      });
      const r2 = await viaConnect(port, S3, S3, caPem, put);
      seen.push(r2.text);
      assert.equal(r2.status, 200, r2.text);
      assert.deepEqual(got.map((g) => [g.site, g.verified]), [[STS, true], [S3, true]]);
      assert.equal(got[0]!.headers["x-amz-security-token"], TOKEN, "the real token in place");
      assert.equal(got[1]!.url, "/notes/./my%20day.txt", "the path as signed, never re-parsed");

      // 2. Elsewhere: no AWS endpoint (asks: nothing binds the key there), and
      //    a request signed for STS sent to another amazonaws.com host.
      const evil = agentRequest({
        host: EVIL, method: "POST", path: "/", body: "Action=GetCallerIdentity&Version=2011-06-15", service: "sts", region: "us-east-1",
        extra: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" }, form: { uri: "normalized", query: "raw" }, ph,
      });
      const r3 = await viaConnect(port, EVIL, EVIL, caPem, evil);
      seen.push(r3.text);
      assert.equal(r3.status, 403, r3.text);
      const r4 = await viaConnect(port, LOOKALIKE, LOOKALIKE, caPem, sts);
      seen.push(r4.text);
      assert.equal(r4.status, 403, r4.text);
      assert.match(r4.text, /signs Host/);
      assert.equal(got.length, 2, "neither other host received anything");

      // 3. botocore itself (self-SKIP without it).
      await t.test("boto3: STS GetCallerIdentity and S3 PutObject with the placeholders", { skip: !BOTO && "python3 with boto3 unavailable" }, async () => {
        const script = join(dir, "boto_e2e.py");
        writeFileSync(script, BOTO_SCRIPT);
        const bundle = join(dir, "session-ca.pem");
        writeFileSync(bundle, caPem);
        const env: NodeJS.ProcessEnv = {
          PATH: process.env.PATH, HOME: join(dir, "boto-home"), HTTPS_PROXY: `http://127.0.0.1:${port}`, NO_PROXY: "",
          AWS_CA_BUNDLE: bundle, AWS_ACCESS_KEY_ID: ph.id, AWS_SECRET_ACCESS_KEY: ph.key, AWS_SESSION_TOKEN: ph.token,
          AWS_EC2_METADATA_DISABLED: "true", AWS_CONFIG_FILE: "/dev/null", AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
        };
        const child = spawn("python3", ["-I", script], { env, stdio: ["ignore", "pipe", "pipe"] });
        let out = "", err = "";
        child.stdout.on("data", (d) => (out += d));
        child.stderr.on("data", (d) => (err += d));
        const [code] = await once(child, "exit");
        seen.push(out, err);
        assert.equal(code, 0, `${err.slice(-600)}\nproxy: ${proxyLog.slice(-6).join("\n")}`);
        assert.deepEqual(JSON.parse(out), { sts: "123456789012", s3: 200 });
        const boto = got.slice(2);
        assert.deepEqual(boto.map((g) => [g.site, g.verified]), [[STS, true], [S3, true]]);
        // botocore 1.36+ uploads aws-chunked with unsigned chunks
        // (STREAMING-UNSIGNED-PAYLOAD-TRAILER) after an Expect: 100-continue.
        assert.equal(boto[1]!.headers.expect, undefined, "the proxy answered the 100-continue itself");
      });

      // 4. THE ORACLE.
      for (const g of got) {
        const bytes = JSON.stringify(g.headers) + g.url + g.body.toString("latin1");
        assert.ok(!bytes.includes(SECRET), `the real secret key never reaches ${g.site}`);
        assert.ok(!bytes.includes("$MDU:"), `no placeholder reaches ${g.site}`);
        assert.ok(g.site === STS || g.site === S3, `only AWS endpoints received anything (${g.site})`);
      }
      const events = filesUnder(eventDir).map((f) => readFileSync(f, "utf8")).join("\n");
      for (const [name, value] of [["secret key", SECRET], ["session token", TOKEN], ["access key id", ID]] as const) {
        for (const text of [...seen, events]) assert.ok(!text.includes(value), `the ${name} is nowhere the agent's world reads`);
      }
    } finally {
      await proxy.close();
      for (const s of sites) s.close();
      data.close();
      human.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
