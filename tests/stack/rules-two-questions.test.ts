/**
 * rules-two-questions e2e — the Rules page's two menus (dashboard.md §4.25p,
 * "Two questions per secret", 2026-10-11) through the PRODUCTION wiring:
 * `makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }))` over a
 * REAL ArbiterServer with a file-backed law, and a real DashboardServer.
 *
 * A label is `Release(d) = Models(level) ∪ Bindings ∪ {human, storage}`
 * (confidentiality plan 13 §4.2). The first menu sets `level`; the second
 * sets `bindings` through the same save route:
 *
 *   1. the panel's row for a bound file carries its level, its hosts and
 *      the "Opens it" words for its readers (plan 13 §5.3), never a value;
 *   2. "Needs your OK" (the same level, no hosts) is a tightening: it applies
 *      at once, policy.yaml loses the host, and the arbiter's egress decision
 *      for the file's secret at that host becomes an ask;
 *   3. "Listed hosts without asking" (a host added) is a loosening: nothing
 *      changes until it is sent back with what was shown, then the host is
 *      bound and the secret is released there, and only there;
 *   4. "Not secret" from the second menu is the level `public`, a loosening
 *      like any other.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const SECRET = "sk-live-TWOQ-NEVER-SHOWN";

test("two questions over the real arbiter: the second menu's choices bind, unbind and declassify through the save route, and egress follows", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-two-questions-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const ws = join(home, "ws");
  mkdirSync(ws, { recursive: true });
  const envPath = join(ws, ".env");
  const notesPath = join(ws, "notes.md");
  writeFileSync(envPath, `STRIPE_KEY=${SECRET}\n`);
  writeFileSync(notesPath, "notes\n");

  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "paths:",
    `  - { path: "${envPath}", level: no-model, recursive: false, bindings: [api.stripe.com], readers: [{ app: deploy, prints: nothing }], others: twin }`,
    `  - { path: "${notesPath}", level: any-model, recursive: false }`,
    "",
  ].join("\n"));
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc);
  const server = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock }),
    approvalsArbiter: wired.arbiter,
    secretsArbiter: wired.secrets,
    policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const save = async (body: unknown) => {
    const r = await fetch(`${base}/api/files/labels`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as any };
  };
  const panelRow = async (path: string) => {
    const r = await fetch(`${base}/api/policy/panel`, { headers: CSRF_ADMIN });
    const raw = await r.text();
    assert.ok(!raw.includes(SECRET), "the panel never carries a value");
    return ((JSON.parse(raw) as any).panel.yourRules as any[]).find((x) => x.id === `lock:${path}`);
  };
  // The file's secret as the AI holds it, and what the egress gate decides
  // for it at a host (the invariant's network half).
  const reg = await gate.registerSecret({ path: envPath, sessionKey: "two-questions" });
  const token = /\$MDU:nomodel_Read\[[0-9a-f]+\]\.STRIPE_KEY/.exec(reg.twin ?? "")?.[0];
  assert.ok(token, `the key has its own symbol: ${JSON.stringify({ ...reg, twin: undefined })}`);
  assert.ok(!(reg.twin ?? "").includes(SECRET), "the twin holds no value");
  const egress = (host: string) => gate.desymbolizationDecision({ symbol: token!, boundary: "network", destination: host, sessionKey: "two-questions", scheme: "https" });

  try {
    // 1. The row: both answers and who may open the file.
    const env = await panelRow(envPath);
    assert.equal(env.level, "no-model");
    assert.deepEqual(env.bindings, ["api.stripe.com"]);
    assert.equal(env.plain.effect, "No AI; may be sent to api.stripe.com");
    assert.equal(env.plain.opens, "deploy (your word) may open the real file. Other programs get a masked copy.");
    assert.equal((await egress("api.stripe.com")).allow, true, "bound: released at its host");
    assert.equal((await egress("paste.example")).allow, false, "anywhere else: not released");

    // 2. Needs your OK: the same level, no hosts. A tightening, applied at once.
    const ask = await save({ changes: [{ path: envPath, level: "no-model", bindings: [], recursive: false }] });
    assert.equal(ask.status, 200, JSON.stringify(ask.body));
    assert.equal(ask.body.applied, true, `removing a host only adds protection: ${JSON.stringify(ask.body)}`);
    assert.doesNotMatch(readFileSync(policyPath, "utf8"), /api\.stripe\.com/);
    assert.deepEqual((await panelRow(envPath)).bindings, []);
    const now = await egress("api.stripe.com");
    assert.equal(now.allow, false, "unbound: the host no longer gets the real value without asking");

    // 3. Listed hosts without asking: a host added is a loosening.
    const more = { changes: [{ path: envPath, level: "no-model", bindings: ["api.stripe.com"], recursive: false }] };
    const before = readFileSync(policyPath, "utf8");
    const confirm = await save(more);
    assert.equal(confirm.body.confirm, true, "adding a host asks first");
    assert.equal(readFileSync(policyPath, "utf8"), before, "asking writes nothing");
    assert.equal((await egress("api.stripe.com")).allow, false);
    const done = await save({ ...more, expected: confirm.body.expected });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.match(readFileSync(policyPath, "utf8"), /api\.stripe\.com/);
    assert.equal((await egress("api.stripe.com")).allow, true, "bound again: released there");
    assert.equal((await egress("paste.example")).allow, false, "and only there");

    // 4. Not secret from the second menu is the level public: a loosening.
    const pub = { changes: [{ path: notesPath, level: "public", recursive: false }] };
    const ask4 = await save(pub);
    assert.equal(ask4.body.confirm, true);
    assert.equal((await gate.pathLevel(notesPath)).level, "any-model", "nothing changes until confirmed");
    await save({ ...pub, expected: ask4.body.expected });
    assert.equal((await gate.pathLevel(notesPath)).level, "public");
    assert.equal((await panelRow(notesPath)).plain.opens, undefined, "Not secret has nothing to open");
  } finally {
    await server.close();
    wired.close();
    gate.close();
    await arbiter.close();
  }
});
