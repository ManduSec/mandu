/**
 * content-tier-config-secret — the default catalog's content tier and the
 * 2026-10-19 path shapes, end to end (secret-discovery.md §2.6): a password
 * saved in a YAML config, a platform CLI's token in its project
 * dot-directory and an HTTP client's private environment reach the model
 * only as placeholders, with no label of the human's.
 *
 * The gap it closes: under Mandu's defaults alone (the `secrets-defaults`
 * battery of 2026-10-18) the power company's password in
 * `accounts/brightgrid.yaml` and the hosting platform's token in
 * `.launchdeck/auth.json` reached the model, since no catalog rule named
 * either file and the launch scan only suggested locking them.
 *
 * Real ArbiterServer, the launch's secret setup as the launcher does it
 * (`discoverSecrets` over HOME and the workspace, `registerSecret` per file
 * found), and the PRODUCTION proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`) in front of a mock upstream: what the upstream
 * receives is what the model would. Asserted, per file: no byte of the
 * value in any model-facing request (a Read of the RAW file, a command that
 * names it, a command that does not), the twin keeps the rest of the file,
 * and the value's placeholder asks before it leaves for any host. Then the
 * negatives (a test fixture, a reference, a human `public` label) and the
 * lifetime (a restarted arbiter still knows the file; a walk that reads it
 * clean drops the label).
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the default mode, the one a fresh install runs

const PW = "Garden-Lamp-QXT4-6180";
const TOKEN = "ldk_7Hq2Lp9Xw3Rt5Vb8Nc1Mz6Ks4Jd0Fg2A";
const ADMIN = "Stg-Admin-7r2Kq9Lm4x";

/** The workspace: the three saved logins, and what must stay public. */
const FILES: Record<string, string> = {
  "accounts/power.yaml": `# PowerCo: my online account\nsite: https://my.powerco.test\nemail: alex@mail.test\npassword: ${PW}\n`,
  ".launchdeck/auth.json": `${JSON.stringify({ token: TOKEN }, null, 2)}\n`,
  "api/http-client.private.env.json": `${JSON.stringify({ staging: { user: "ops-admin", password: ADMIN } }, null, 2)}\n`,
  // a recorded exchange the task re-records: test data, not a config
  "svc/test/fixtures/login.json": `${JSON.stringify({ request: { body: { password: PW } } })}\n`,
  // a reference, no credential
  "config/database.yml": "production:\n  password: ${DB_PASSWORD}\n",
};

function post(port: number, body: string, session: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": session } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/** Claude Code's Read output: numbered lines. */
const claudeRead = (text: string) => text.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");

function turn(input: { file_path: string } | { command: string }, content: string, id: string): string {
  return JSON.stringify({
    model: "claude-sonnet-5",
    stream: true,
    messages: [
      { role: "user", content: "how much is my electricity bill?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "file_path" in input ? "Read" : "Bash", input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

function start(dir: string): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
}

test("a saved password in a YAML config, a CLI's project login and an HTTP client's private environment reach the model only as placeholders, with no label of the human's (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-content-tier-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "proj");
  mkdirSync(home, { recursive: true });
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), text);
  }
  const at = (rel: string): string => join(ws, rel);
  let server = start(dir);
  await server.listen();
  let real = new ArbiterClient(join(dir, "arbiter.sock"));
  await real.connect();
  const sessionKey = `content-tier-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "content-tier e2e" })).bound, "claude-code");

    // The launch's secret setup (launcher/src/secret-setup.ts).
    const report = await real.discoverSecretsReport([home, ws], home);
    assert.ok(![PW, TOKEN, ADMIN].some((v) => JSON.stringify(report).includes(v)), "the walk answers paths and fields, never a value");
    const rules = new Map(report.files.map((f) => [f.path, f.rule]));
    assert.equal(rules.get(at("accounts/power.yaml")), "content:secret-key", "the content tier read the YAML");
    assert.equal(rules.get(at(".launchdeck/auth.json")), "shape:tool-login-file");
    assert.equal(rules.get(at("api/http-client.private.env.json")), "shape:*.private.env.json");
    for (const rel of ["svc/test/fixtures/login.json", "config/database.yml"]) assert.ok(!rules.has(at(rel)), `${rel} is not a secret file`);
    const twins = new Map<string, string>();
    for (const f of report.files) {
      const r = await real.registerSecret({ path: f.path, home });
      assert.ok(r.symbol, `${f.path}: ${r.reason}`);
      if (typeof r.twin === "string") twins.set(f.path, r.twin);
    }

    const forwarded = async (input: { file_path: string } | { command: string }, content: string): Promise<string> => {
      const up = new MockUpstream({ sse: buildTextSse("ok") });
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(real), upstream: up.fetcher, sessionKey, log: () => {} });
      proxies.push(proxy);
      const r = await post(await proxy.listen(0), turn(input, content, `tu_${n++}`), sessionKey);
      assert.equal(r.status, 200, r.body);
      const b: unknown = up.requests[up.requests.length - 1]!.body;
      return Buffer.isBuffer(b) ? b.toString("utf8") : String(b);
    };

    for (const [rel, value, kept] of [
      ["accounts/power.yaml", PW, ["site: https://my.powerco.test", "email: alex@mail.test"]],
      [".launchdeck/auth.json", TOKEN, ['"token": "$MDU:']],
      ["api/http-client.private.env.json", ADMIN, ['"user": "ops-admin"']],
    ] as const) {
      const path = at(rel);
      assert.deepEqual(await real.pathLevel(path), { level: "no-model", bindings: [], axis: true, rule: rules.get(path) }, rel);
      // the copy programs read keeps the file: the rest as written, the value a placeholder
      const twin = twins.get(path)!;
      assert.ok(twin && !twin.includes(value), `${rel}: the structured twin hides the value:\n${twin}`);
      for (const k of kept) assert.ok(twin.includes(k), `${rel}: the twin keeps ${k}:\n${twin}`);
      // what reaches the model: a Read of the RAW file (no guard served the
      // twin), a command that names it, and one that does not
      const raw = FILES[rel]!;
      for (const [input, content] of [
        [{ file_path: path }, claudeRead(raw)],
        [{ command: `cat ${rel}` }, raw],
        [{ command: "cat ./*/p* ./.l*/* ./api/h*" }, raw],
      ] as const) {
        const sent = await forwarded(input, content);
        assert.ok(!sent.includes(value), `CONFIDENTIALITY VIOLATION: ${rel}'s value reached the model through ${JSON.stringify(input)}:\n${sent.slice(0, 2000)}`);
        assert.match(sent, /\$MDU:nomodel_/, `${rel}: the model sees a placeholder:\n${sent.slice(0, 3000)}`);
      }
      // what the agent's Read returns under the guard is the twin: the model
      // reads the rest of the file as written (the site, the email, the
      // user), the value as its placeholder
      const viaTwin = await forwarded({ file_path: path }, claudeRead(twin));
      assert.ok(!viaTwin.includes(value), `CONFIDENTIALITY VIOLATION: ${rel}'s value reached the model through its twin`);
      for (const k of kept.filter((x) => !x.includes("$MDU"))) assert.ok(viaTwin.includes(JSON.stringify(k).slice(1, -1)), `${rel}: the model reads ${k}:\n${viaTwin.slice(0, 1500)}`);
      // the value is a registered one: the backstop knows it, and its
      // placeholder asks before it leaves for any host (no binding)
      const hits = (await real.scanSecretValues(`debug: ${value}\n`)).hits;
      assert.ok(hits.length > 0, `${rel}: the value backstop knows the value`);
      const d = await real.desymbolizationDecision({ symbol: hits[0]!.symbol, boundary: "network", destination: "my.powerco.test" });
      assert.equal(d.allow, false, d.reason);
      assert.equal(d.requiresApproval, true, d.reason);
      assert.equal(d.ruleRef?.id, "egress:secret-unbound", d.reason);
    }

    // the launch scan no longer suggests what is protected
    const sug = await real.suggestPolicy([ws], { home, waitMs: 60_000 });
    const locked = sug.suggestions.flatMap((s) => s.edits.filter((e) => e.op === "lock-path").map((e) => (e as { path: string }).path));
    for (const rel of ["accounts/power.yaml", ".launchdeck/auth.json", "api/http-client.private.env.json"]) assert.ok(!locked.includes(at(rel)), `${rel} is not suggested: ${locked.join(", ")}`);

    // a restarted arbiter still knows the found file (mandu.db)
    for (const p of proxies.splice(0)) await p.close().catch(() => {});
    real.close();
    await server.close();
    server = start(dir);
    await server.listen();
    real = new ArbiterClient(join(dir, "arbiter.sock"));
    await real.connect();
    assert.equal((await real.pathLevel(at("accounts/power.yaml"))).rule, "content:secret-key", "kept across a restart");

    // a walk that reads it clean drops the label (the human took the password out)
    writeFileSync(at("accounts/power.yaml"), "site: https://my.powerco.test\npassword: ${POWERCO_PASSWORD}\n");
    const again = await real.discoverSecretsReport([home, ws], home);
    assert.deepEqual(again.cleared, [at("accounts/power.yaml")]);
    assert.equal((await real.pathLevel(at("accounts/power.yaml"))).level, "public", "a file with no credential in it is a file like any other");
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a human `public` label on a found file decides, as it does over the catalog (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-content-tier-public-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "proj");
  const f = join(ws, "accounts", "power.yaml");
  mkdirSync(home, { recursive: true });
  mkdirSync(dirname(f), { recursive: true });
  writeFileSync(f, FILES["accounts/power.yaml"]!);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
    policyDocument: { paths: [{ path: f, level: "public" }] },
  });
  await server.listen();
  const real = new ArbiterClient(join(dir, "arbiter.sock"));
  await real.connect();
  try {
    const report = await real.discoverSecretsReport([home, ws], home);
    assert.ok(!report.files.some((x) => x.path === f), "a file the human released is not twinned");
    assert.deepEqual(report.found ?? [], [], "nor read: the human's label decides");
    assert.equal((await real.pathLevel(f)).rule, `label:${f}`);
  } finally {
    real.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
