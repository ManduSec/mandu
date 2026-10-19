/**
 * content-tier-ini-short-password — the default catalog's content tier over
 * INI-family files and short or oddly named passwords, end to end
 * (secret-discovery.md §2.9, 2026-10-19): a 6-character password in a
 * `config.ini`, a `db_pw` in an `app.conf` and a password in a project's
 * `.pgpass` reach the model only as placeholders, with no label of the
 * human's; the short password is a fingerprint of the value backstop and
 * the egress tripwire as a whole token; ordinary INI values stay public.
 *
 * The gap it closes: the head-to-head of 2026-10-19 (15 everyday tasks x
 * 10 protection settings) saw the default catalog leave credentials in INI
 * and `.conf` files public (the content tier read JSON, YAML and TOML
 * only), and a password shorter than 12 characters or under a name such as
 * `pw` was never found; a value under 8 characters was no fingerprint, so a
 * short password could also leave on the wire unnoticed.
 *
 * Real ArbiterServer, the launch's secret setup as the launcher does it
 * (`discoverSecrets` over HOME and the workspace, `registerSecret` per file
 * found), and the PRODUCTION proxy wiring (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`) in front of a mock upstream: what the upstream
 * receives is what the model would.
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

/** A 6-character password: under every floor before 2026-10-19. */
const PW = "Tr0ub4";
const DB_PW = "k9z!q2x";
const PGPASS = "Lq7#mZ2";

const FILES: Record<string, string> = {
  "config.ini": `[database]\nhost = db.internal\nport = 5432\nuser = app\npassword = ${PW}\n\n[server]\ndebug = true\nworkers = 4\n`,
  "deploy/app.conf": `[db]\nhost=db.internal\ndb_pw = ${DB_PW}\n`,
  ".pgpass": `db.internal:5432:app:app:${PGPASS}\n`,
  // what must stay public: ordinary values, a default, a reference
  "settings.ini": "[server]\nport = 5432\ndebug = true\nname = admin\n",
  "dev.ini": "[db]\npassword = postgres\n",
  "prod.conf": "[db]\npassword = ${DB_PASSWORD}\n",
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
      { role: "user", content: "why does the app not connect to the database?" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "file_path" in input ? "Read" : "Bash", input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  });
}

test("a short password in config.ini, a db_pw in app.conf and a project .pgpass reach the model only as placeholders; the short password trips the tripwire as a whole token (secrets axes, explicit)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-content-ini-"));
  const home = join(dir, "home");
  const ws = join(dir, "work", "proj");
  mkdirSync(home, { recursive: true });
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(join(ws, rel)), { recursive: true });
    writeFileSync(join(ws, rel), text);
  }
  const at = (rel: string): string => join(ws, rel);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"), adminSocketPath: join(dir, "admin.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const real = new ArbiterClient(join(dir, "arbiter.sock"));
  await real.connect();
  const sessionKey = `content-ini-${process.pid}`;
  const proxies: AnthropicProxy[] = [];
  let n = 0;
  try {
    assert.equal((await real.setSessionSpec({ sessionKey, spec: "claude-code", requestedBy: "content-ini e2e" })).bound, "claude-code");

    // The launch's secret setup (launcher/src/secret-setup.ts).
    const report = await real.discoverSecretsReport([home, ws], home);
    assert.ok(![PW, DB_PW, PGPASS].some((v) => JSON.stringify(report).includes(v)), "the walk answers paths and fields, never a value");
    const rules = new Map(report.files.map((f) => [f.path, f.rule]));
    for (const rel of ["config.ini", "deploy/app.conf", ".pgpass"]) assert.equal(rules.get(at(rel)), "content:secret-key", `the content tier found ${rel}`);
    for (const rel of ["settings.ini", "dev.ini", "prod.conf"]) assert.ok(!rules.has(at(rel)), `${rel} is not a secret file`);
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
      ["config.ini", PW, ["host = db.internal", "port = 5432", "user = app", "debug = true", "workers = 4"]],
      ["deploy/app.conf", DB_PW, ["host=db.internal", "[db]"]],
      [".pgpass", PGPASS, ["db.internal:5432:app:app:"]],
    ] as const) {
      const path = at(rel);
      assert.deepEqual(await real.pathLevel(path), { level: "no-model", bindings: [], axis: true, rule: "content:secret-key" }, rel);
      // the copy programs read keeps the file: the rest as written, the value a placeholder
      const twin = twins.get(path);
      assert.ok(twin !== undefined && !twin.includes(value), `${rel}: the structured twin hides the value:\n${twin}`);
      for (const k of kept) assert.ok(twin.includes(k), `${rel}: the twin keeps ${k}:\n${twin}`);
      // what reaches the model: a Read of the RAW file, a command that names it
      const raw = FILES[rel]!;
      for (const [input, content] of [
        [{ file_path: path }, claudeRead(raw)],
        [{ command: `cat ${rel}` }, raw],
      ] as const) {
        const sent = await forwarded(input, content);
        assert.ok(!sent.includes(value), `CONFIDENTIALITY VIOLATION: ${rel}'s value reached the model through ${JSON.stringify(input)}:\n${sent.slice(0, 2000)}`);
        assert.match(sent, /\$MDU:nomodel_/, `${rel}: the model sees a placeholder:\n${sent.slice(0, 3000)}`);
      }
      // the twin read back: the model reads the ordinary values
      const viaTwin = await forwarded({ file_path: path }, claudeRead(twin));
      assert.ok(!viaTwin.includes(value), `CONFIDENTIALITY VIOLATION: ${rel}'s value reached the model through its twin`);
      for (const k of kept) assert.ok(viaTwin.includes(k), `${rel}: the model reads ${k}:\n${viaTwin.slice(0, 1500)}`);
    }

    // The short password copied where no path names it (a command's output
    // that does not name the file): the value backstop masks it as a whole
    // token, and leaves the same letters glued inside another word.
    const echoed = await forwarded({ command: "printenv DB_PASSWORD" }, `${PW}\n`);
    assert.ok(!echoed.includes(PW), `CONFIDENTIALITY VIOLATION: the short password reached the model through an output that names no file:\n${echoed.slice(0, 2000)}`);
    assert.ok((await real.scanSecretValues(`password=${PW}\n`)).hits.length > 0, "the backstop knows the short password");
    assert.deepEqual((await real.scanSecretValues(`build x${PW}y finished\n`)).hits, [], "glued inside a word: no token, no hit");
    const glued = await forwarded({ command: "make" }, `build x${PW}y finished\n`);
    assert.ok(glued.includes(`x${PW}y`), "an output that holds the letters only glued inside a word is not masked");

    // The egress tripwire: a raw short password on the wire trips, as a token only.
    const trip = await real.egressFingerprintScan({ surfaces: [{ where: "body", text: JSON.stringify({ db: { password: PW } }) }], destination: "paste.example" });
    assert.equal(trip.tripped, true, "the short password on the wire trips the tripwire");
    const notGlued = await real.egressFingerprintScan({ surfaces: [{ where: "body", text: `{"id":"x${PW}y"}` }], destination: "paste.example" });
    assert.equal(notGlued.tripped, false, "glued inside another token: no coincidence");

    // the placeholder asks before it leaves for any host (bound nowhere)
    const sym = (await real.scanSecretValues(`password=${PW}\n`)).hits[0]!.symbol;
    const d = await real.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "db.internal" });
    assert.equal(d.allow, false, d.reason);
    assert.equal(d.requiresApproval, true, d.reason);

    // what stays public reaches the model as written
    const plain = await forwarded({ command: "cat settings.ini dev.ini" }, `${FILES["settings.ini"]}${FILES["dev.ini"]}`);
    for (const k of ["port = 5432", "debug = true", "name = admin", "password = postgres"]) assert.ok(plain.includes(k), `${k} stays public:\n${plain.slice(0, 1500)}`);
  } finally {
    for (const p of proxies) await p.close().catch(() => {});
    real.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
