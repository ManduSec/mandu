/**
 * session-page-issuer-send — a key sent to its own company's API says, on
 * the product's session page, why nobody was asked (dashboard.md §4.25b, *A
 * send to its company's own API says why it did not ask*), across the REAL
 * components. Mandu-new.
 *
 * A real ArbiterServer at the `secrets` axes, a REAL NetProxy with TLS
 * inspection through the production adapter, and a real DashboardServer over
 * the production wiring (`makeApprovalsArbiter`, whose `policyDocument` the
 * agent route reads):
 *
 *   G1  a GitHub-format token in a workspace `.env`, its placeholder in the
 *       Authorization header of an HTTPS request to api.github.com, reaches
 *       GitHub as the real token with no Approvals card (the built-in
 *       issuer binding, confidentiality.md §2.3);
 *   G2  the served `/api/home/agent` step "Sent a request to
 *       `api.github.com` …" keeps its note, then says GitHub's keys "may" go
 *       there without asking, linking Rules › Built-in protections; it
 *       never claims to be the reason the send went;
 *   G3  with `issuer_bindings: false` the same send is refused and asks (a
 *       card), and no step carries the sentence;
 *   G4  the oracle: no answer of the dashboard carries the token's value or
 *       a placeholder, and only api.github.com saw the token.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer } from "node:https";
import { type IncomingMessage, type ServerResponse } from "node:http";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect, type AddressInfo } from "node:net";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { MockSites } from "../../interceptors/net-proxy/src/mock-sites.js";
import { ensureCa, leafForHost, opensslAvailable } from "../../interceptors/net-proxy/src/ca.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { AgentPageVM, StoryStep } from "../../dashboard/src/view-model/agent-page.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const OPENSSL = opensslAvailable();
const SESSION = "s-issuer-send";
const HOST = "api.github.com";
const TOKEN = ["ghp", `ISSUERSEND${process.pid}`.padEnd(40, "q7")].join("_");
const NOTE = "The real value left this machine, to a destination allowed to receive it.";
const SENTENCE = `${NOTE} ${HOST} is GitHub's own API: a key GitHub issued may go there without asking you. Built-in protections in Rules lists these, and says how to have them ask.`;

type Got = Array<{ authorization: string | undefined; raw: string }>;

async function githubRecorder(dir: string, got: Got) {
  const ca = ensureCa(join(dir, "ca-github"));
  const leaf = leafForHost(ca, HOST);
  const server = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      got.push({ authorization: req.headers["authorization"], raw: `${req.url} ${JSON.stringify(req.headers)} ${Buffer.concat(chunks).toString("utf8")}` });
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"login":"octocat"}');
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { port: (server.address() as AddressInfo).port, caPath: ca.certPath, close: () => server.close() };
}

/** CONNECT api.github.com:443 through the proxy, TLS trusting the session
 *  CA, one GET with `authorization`; the status (the CONNECT's on a refusal). */
function viaTls(proxyPort: number, sessionCa: string, authorization: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const raw = netConnect(proxyPort, "127.0.0.1", () => raw.write(`CONNECT ${HOST}:443 HTTP/1.1\r\nHost: ${HOST}:443\r\n\r\n`));
    let head = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      head = Buffer.concat([head, c]);
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      raw.off("data", onData);
      const status = head.subarray(0, idx).toString("latin1").split("\r\n")[0]!;
      if (!/ 200 /.test(`${status} `)) {
        raw.destroy();
        resolve(Number(/HTTP\/1\.1 (\d{3})/.exec(status)?.[1] ?? 0));
        return;
      }
      const tls = tlsConnect({ socket: raw, servername: HOST, ca: sessionCa }, () => {
        tls.write(`GET /user HTTP/1.1\r\nHost: ${HOST}\r\nAuthorization: ${authorization}\r\nConnection: close\r\n\r\n`);
      });
      const chunks: Buffer[] = [];
      tls.on("data", (d: Buffer) => chunks.push(d));
      tls.on("end", () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(Buffer.concat(chunks).toString("utf8"))?.[1] ?? 0)));
      tls.on("error", reject);
    };
    raw.on("data", onData);
    raw.on("error", reject);
    setTimeout(() => reject(new Error("request timed out")), 10_000).unref();
  });
}

type Action = Extract<StoryStep, { kind: "action" }>;
const words = (parts: { text: string }[]) => parts.map((p) => p.text).join("");

test(
  "a GitHub token sent to api.github.com with no card: the real session page says GitHub's keys may go there without asking, linking Built-in protections; with issuer_bindings: false it asks and no step says so; no answer carries the token",
  { skip: !OPENSSL && "openssl unavailable", timeout: 120_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mdu-issuer-send-"));
    const home = join(dir, "home");
    const ws = join(home, "ws");
    mkdirSync(ws, { recursive: true });
    const envFile = join(ws, ".env");
    writeFileSync(envFile, `GITHUB_TOKEN=${TOKEN}\n`);
    const policyPath = join(dir, "policy.yaml");
    writeFileSync(policyPath, "version: 1\n"); // a fresh install: no label, no binding
    const sock = join(dir, "arbiter.sock");
    const humanSock = join(dir, "human", "h.sock");
    const adminSock = join(dir, "admin.sock");
    const arbiter = new ArbiterServer({
      socketPath: sock, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
      log: () => {}, adminPolicyDir: null, packDir: null, policyPath, policyPollMs: 0,
      confidentiality: true, integrity: false, // the `secrets` axes, stated
    });
    await arbiter.listen();
    const data = new ArbiterClient(sock);
    const human = new ArbiterClient(humanSock);
    const admin = new ArbiterClient(adminSock);
    await admin.connect();
    const got: Got = [];
    const gh = await githubRecorder(dir, got);
    const sites = MockSites.fromYaml([
      "hosts:",
      `  - host: ${HOST}`, `    to: 127.0.0.1:${gh.port}`, `    tls_to: 127.0.0.1:${gh.port}`, `    tls_ca: ${JSON.stringify(gh.caPath)}`,
      "",
    ].join("\n"));
    const caDir = join(dir, "mitm");
    const proxy = new NetProxy({
      allowThisMachine: true, arbiter: new ArbiterClientAdapter(data as unknown as RealArbiterClient, human as unknown as RealArbiterClient),
      log: () => {}, sessionId: SESSION, mockSites: sites, mitm: { caDir }, attributeHolders: () => [{ procKey: "7000-1", ancestors: [] }],
    });
    const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
    assert.ok(wired?.policyDoc, "the production wiring connects");
    const dashboard = new DashboardServer({
      source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock }),
      approvalsArbiter: wired.arbiter,
      policyDocArbiter: wired.policyDoc,
      fileBrowserHome: home,
      configEnv: { MANDU_HOME: join(dir, "mandu-home"), MANDU_POLICY_FILE: policyPath },
      log: () => {},
      ...ADMIN_OPTS,
    });
    const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
    const bodies: string[] = [];
    /** The served page, signed in, once `ready` holds of its sent steps. */
    const pageUntil = async (ready: (steps: Action[]) => boolean): Promise<Action[]> => {
      let steps: Action[] = [];
      for (let i = 0; i < 100; i++) {
        const r = await pageFetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
        const body = await r.text();
        assert.equal(r.status, 200, body);
        bodies.push(body);
        steps = (JSON.parse(body) as AgentPageVM).story.flatMap((t) => t.steps).filter((s): s is Action => s.kind === "action" && s.icon === "web");
        if (ready(steps)) return steps;
        await new Promise((res) => setTimeout(res, 30));
      }
      return steps;
    };
    try {
      const port = await proxy.listen(0);
      const ca = readFileSync(join(caDir, "mandu-egress-ca.pem"), "utf8");
      // Registered as the launcher registers a workspace credential file.
      const reg = await human.registerSecret({ path: envFile, home, sessionKey: SESSION });
      assert.ok(reg.symbol && reg.twin, reg.reason);
      assert.ok(!reg.twin!.includes(TOKEN), "the twin holds no secret byte");
      const sym = new RegExp(`^GITHUB_TOKEN='?(\\$MDU:[^\\s']+)'?$`, "m").exec(reg.twin!)![1]!;

      // ── G1: GitHub's own host, the Authorization header, HTTPS: no card ──
      assert.equal(await viaTls(port, ca, `Bearer ${sym}`), 200);
      assert.deepEqual(got.map((g) => g.authorization), [`Bearer ${TOKEN}`], "GitHub got the real token");
      assert.equal((await admin.egressApprovals("pending")).length, 0, "no card for GitHub's own host");

      // ── G2: the sent step says why it did not ask ──
      const sent = await pageUntil((steps) => steps.some((s) => s.outcome === "sent"));
      const step = sent.find((s) => s.outcome === "sent");
      assert.ok(step, `the send is a step of the page: ${JSON.stringify(sent)}`);
      assert.match(words(step.sentence), /^Sent a request to api\.github\.com with your secret GITHUB_TOKEN filled in$/);
      assert.equal(step.note, SENTENCE, "the note, then the sentence");
      assert.equal(words(step.noteParts!), SENTENCE);
      assert.deepEqual(step.noteParts!.filter((p) => p.rules), [{ kind: "text", text: "Built-in protections", rules: "built-in" }]);
      assert.doesNotMatch(step.note!, /because|the reason|allowed it/i, "it says what may go, never why this send went");

      // ── G3: the switch off: the send asks, and no step says it may go ──
      const read = await admin.policyDocument();
      await admin.applyPolicyDocument({ version: 1, issuer_bindings: false }, "test", read.lawHash!);
      assert.equal(await viaTls(port, ca, `Bearer ${sym}`), 403, "issuer_bindings: false");
      assert.equal(got.length, 1, "nothing more reached GitHub");
      const asked = (await admin.egressApprovals("pending")).map((p) => p.destination);
      assert.ok(asked.some((d) => d === HOST || d.startsWith(`${HOST}:`)), `a card for ${HOST}: ${asked}`);
      const after = await pageUntil((steps) => steps.some((s) => s.outcome === "blocked" || s.outcome === "waiting"));
      assert.ok(after.some((s) => s.outcome === "blocked" || s.outcome === "waiting"), `the refused send is a step: ${JSON.stringify(after)}`);
      for (const s of after) {
        assert.ok(!(s.note ?? "").includes("without asking you"), `no step says it may go: ${s.note}`);
        assert.ok(!(s.noteParts ?? []).some((p) => p.rules), "no Built-in protections link");
      }
      assert.equal(after.find((s) => s.outcome === "sent")?.note, NOTE, "the earlier send keeps its note alone");

      // ── G4: the oracle ──
      for (const body of bodies) {
        assert.ok(!body.includes(TOKEN), "CONFIDENTIALITY VIOLATION: the session page carries the token's value");
        assert.doesNotMatch(body, /\$MDU:/, "the product page carries no placeholder");
      }
      for (const g of got) assert.ok(!g.raw.replace(JSON.stringify(g.authorization ?? ""), "").includes(TOKEN), "the token only in the Authorization header");
    } finally {
      await dashboard.close();
      wired?.close();
      await proxy.close();
      gh.close();
      data.close();
      human.close();
      admin.close();
      await arbiter.close();
      resetCurrentPolicyForTests();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
