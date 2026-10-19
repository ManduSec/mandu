/**
 * dashboard-file-browser e2e — the Rules page's file browser (dashboard.md
 * §4.25m) through the PRODUCTION wiring: `makeApprovalsArbiter(dataSock,
 * () => ({ socketPath: adminSock }))` over a REAL ArbiterServer with a
 * file-backed law, a real DashboardServer, and a real folder tree.
 *
 *   0. parity: the adapter forwards `pathLevels` (a data-socket read), so
 *      the labels below are the arbiter's own, not a test bridge's;
 *   1. the listing needs the admin session; with it, every entry carries the
 *      label a read would mint with today (checked against `pathLevel` on the
 *      data socket), where it came from, and no file contents;
 *   2. Save of a tightening writes policy.yaml at once, enforced at once
 *      (`pathLevel`), and Undo takes it back;
 *   3. Save of a loosening (a built-in secret made "Not secret") changes
 *      nothing until it is sent back with what was shown; then the file is
 *      public for a read, and the change is recorded;
 *   4. a rule kept in the page's own store (made by the old form) is changed
 *      there, in place: policy.yaml is not touched for it.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

test("file browser over the real arbiter: labels as a read mints them, tighten at once, loosen only when confirmed, page-store rules in place", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-file-browser-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "config"), { recursive: true });
  mkdirSync(join(ws, "docs"));
  mkdirSync(join(home, ".ssh"));
  writeFileSync(join(ws, ".env"), "API_KEY=sk-live-E2E-NEVER-SHOWN\n");
  writeFileSync(join(ws, "config", "db.yaml"), "password: e2e-hunter2\n");
  writeFileSync(join(ws, "docs", "plan.md"), "plan\n");
  writeFileSync(join(ws, "notes.md"), "notes\n");
  writeFileSync(join(home, ".ssh", "id_ed25519"), "-----BEGIN KEY-----\n");

  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - { path: "${join(ws, "config")}", level: no-model }\n`);
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc);
  // 0. Parity: the production adapter forwards the read.
  assert.equal(typeof wired.secrets.pathLevels, "function", "the adapter forwards pathLevels");
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
  const list = async (p: string, headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await fetch(`${base}/api/files/list?path=${encodeURIComponent(p)}`, { headers });
    return { status: r.status, body: (await r.json()) as any, raw: "" };
  };
  const save = async (body: unknown) => {
    const r = await fetch(`${base}/api/files/labels`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as any };
  };
  const at = (b: any, name: string) => b.entries.find((e: any) => e.name === name);

  try {
    // 1. The listing: admin session only; labels as the arbiter mints them.
    assert.equal((await list("~/ws", { "X-Mandu-Control": "1" })).status, 403, "no admin session, no listing");
    const first = await list("~/ws");
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const b = first.body;
    assert.equal(b.labels, "ok");
    assert.equal(b.axis, true);
    for (const e of b.entries) {
      const minted = await gate.pathLevel(e.path);
      assert.equal(e.label.level, minted.level, `${e.name}: the browser shows what a read mints`);
    }
    assert.equal(at(b, "config").label.from, "Your rule");
    assert.equal(at(b, "config").label.store, "policy");
    assert.equal(at(b, ".env").label.from, "Built in: environment files");
    assert.equal(at(b, "notes.md").label.words, "Like any other file");
    assert.equal(at(b, "config").inside, 0);
    const inner = (await list("~/ws/config")).body;
    assert.equal(inner.entries[0].label.from, "From your rule on ~/ws/config");
    const ssh = (await list("~/.ssh")).body;
    assert.equal(ssh.self.source, "builtin", "a built-in folder under the browsed HOME");
    assert.equal(ssh.entries[0].label.level, "no-model");
    const raw = JSON.stringify([b, inner, ssh]);
    for (const s of ["sk-live-E2E-NEVER-SHOWN", "e2e-hunter2", "BEGIN KEY"]) assert.ok(!raw.includes(s), `no contents: ${s}`);

    // 2. A tightening applies at once, is enforced, and can be undone.
    assert.equal((await gate.pathLevel(join(ws, "docs", "plan.md"))).level, "public");
    const tight = await save({ changes: [{ path: "~/ws/docs", level: "no-model", recursive: true }] });
    assert.equal(tight.status, 200, JSON.stringify(tight.body));
    assert.equal(tight.body.applied, true);
    assert.ok(tight.body.changeId);
    assert.match(readFileSync(policyPath, "utf8"), new RegExp(`${join(ws, "docs").replace(/[/.]/g, "\\$&")}`));
    assert.equal((await gate.pathLevel(join(ws, "docs", "plan.md"))).level, "no-model", "enforced for a read");
    assert.equal(at((await list("~/ws")).body, "docs").label.from, "Your rule");
    const undo = await fetch(`${base}/api/policy/changes/${encodeURIComponent(tight.body.changeId)}/undo`, { method: "POST", headers: CSRF_ADMIN });
    assert.equal(undo.status, 200);
    assert.equal((await gate.pathLevel(join(ws, "docs", "plan.md"))).level, "public", "Undo takes it back");

    // 3. A loosening: nothing changes until it comes back with what was shown.
    const before = readFileSync(policyPath, "utf8");
    const change = { changes: [{ path: join(ws, ".env"), level: "public", recursive: false }] };
    const ask = await save(change);
    assert.equal(ask.status, 200);
    assert.equal(ask.body.confirm, true);
    assert.equal(ask.body.loosens[0].subject, "~/ws/.env");
    assert.match(ask.body.loosens[0].detail, /^Becomes Not secret/);
    assert.equal(readFileSync(policyPath, "utf8"), before, "asking writes nothing");
    assert.equal((await gate.pathLevel(join(ws, ".env"))).level, "no-model");
    assert.equal((await save({ ...change, expected: [] })).status, 409);
    assert.equal((await gate.pathLevel(join(ws, ".env"))).level, "no-model", "a confirmation of less changes nothing");
    const done = await save({ ...change, expected: ask.body.expected, reason: "test fixture" });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.equal((await gate.pathLevel(join(ws, ".env"))).level, "public");
    const changes = (await (await fetch(`${base}/api/policy/changes`)).json()) as { changes: Array<{ id: string }> };
    assert.ok(changes.changes.some((c) => c.id === done.body.changeId), "recorded in History");

    // 4. A rule the old form made (the page's store) is changed in place.
    await admin.setPathLabel({ path: join(ws, "notes.md"), confidentiality: "no-model", recursive: false });
    assert.equal(at((await list("~/ws")).body, "notes.md").label.store, "page");
    const lawBefore = readFileSync(policyPath, "utf8");
    const weaker = { changes: [{ path: "~/ws/notes.md", level: "any-model", recursive: false }] };
    const ask2 = await save(weaker);
    assert.equal(ask2.body.confirm, true, "making it weaker asks");
    const done2 = await save({ ...weaker, expected: ask2.body.expected });
    assert.deepEqual(done2.body, { applied: true, changeId: null, page: 1 });
    assert.equal((await gate.pathLevel(join(ws, "notes.md"))).level, "any-model");
    assert.equal(readFileSync(policyPath, "utf8"), lawBefore, "policy.yaml is not touched for it");
    const rm = await save({ changes: [{ path: "~/ws/notes.md", level: null }] });
    assert.equal(rm.body.confirm, true);
    await save({ changes: [{ path: "~/ws/notes.md", level: null }], expected: rm.body.expected });
    assert.equal((await gate.pathLevel(join(ws, "notes.md"))).level, "public", "removed from the page's store");
  } finally {
    await server.close();
    wired.close();
    gate.close();
    admin.close();
    await arbiter.close();
  }
});

test("file browser follow-ups over the real arbiter: symlinks get both rules, impact under the real law, Why, and the move of the page's older rules", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-file-browser-2-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const ws = join(home, "ws");
  mkdirSync(join(ws, "keys"), { recursive: true });
  mkdirSync(join(ws, "proj", "sub"), { recursive: true });
  writeFileSync(join(ws, "keys", "deploy.key"), "k\n");
  writeFileSync(join(ws, "proj", ".env"), "API_KEY=sk-live-E2E2\n");
  writeFileSync(join(ws, "proj", "sub", "notes.md"), "n\n");
  symlinkSync(join(ws, "keys", "deploy.key"), join(ws, "key-link"));

  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, "version: 1\n");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
  });
  await arbiter.listen();
  const gate = new ArbiterClient(dataSock);
  await gate.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc);
  // Parity: the production adapter forwards every op the browser uses.
  assert.equal(typeof wired.secrets.whyPath, "function", "the adapter forwards whyPath");
  assert.equal(typeof wired.policyDoc.movePageLabels, "function", "the adapter forwards movePageLabels");
  const server = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: dataSock }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, log: () => {}, ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const post = async (path: string, body?: unknown) => {
    const r = await fetch(base + path, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json()) as any };
  };
  try {
    // Symlink: a rule chosen for the link is written on its file too, and a
    // read by EITHER spelling is covered.
    const link = await post("/api/files/labels", { changes: [{ path: "~/ws/key-link", level: "no-model", recursive: false }] });
    assert.equal(link.status, 200, JSON.stringify(link.body));
    assert.equal((await gate.pathLevel(join(ws, "key-link"))).level, "no-model");
    assert.equal((await gate.pathLevel(join(ws, "keys", "deploy.key"))).level, "no-model", "the file it points to is covered too");
    const listed = (await (await fetch(`${base}/api/files/list?path=${encodeURIComponent("~/ws")}`, { headers: CSRF_ADMIN })).json()) as any;
    const entry = listed.entries.find((e: any) => e.name === "key-link");
    assert.equal(entry.target, join(ws, "keys", "deploy.key"));
    assert.equal(entry.targetLabel, null, "both spellings agree now");

    // Impact under the real law: a folder made Not secret reaches the built-in .env inside it.
    const imp = await post("/api/files/impact", { changes: [{ path: "~/ws/proj", level: "public", recursive: true }], folder: "~/ws" });
    assert.equal(imp.status, 200, JSON.stringify(imp.body));
    assert.equal(imp.body.impact.scanned, 2);
    assert.equal(imp.body.impact.weaker, 1);
    assert.equal(imp.body.impact.files[0].display, "~/ws/proj/.env");
    assert.equal(imp.body.impact.files[0].after, "Not secret");
    assert.equal((await gate.pathLevel(join(ws, "proj", ".env"))).level, "no-model", "a preview changes nothing");
    const ask = await post("/api/files/labels", { changes: [{ path: "~/ws/proj", level: "public", recursive: true }] });
    assert.equal(ask.body.confirm, true);
    assert.equal(ask.body.impact.files[0].display, "~/ws/proj/.env", "the question names the built-in secret it reaches");

    // Why: the rules' view of one file.
    const why = (await (await fetch(`${base}/api/files/why?path=${encodeURIComponent("~/ws/proj/.env")}`, { headers: CSRF_ADMIN })).json()) as any;
    assert.equal(why.why.label.from, "Built in: environment files");
    assert.ok(why.why.lines.some((l: any) => l.term === "May be sent to" && l.text === "Nowhere without your OK."));
    assert.ok(!JSON.stringify(why).includes("sk-live-E2E2"), "no contents");

    // The page's older rules move into policy.yaml unchanged; Undo refuses the move.
    await admin.setPathLabel({ path: join(ws, "proj", "sub"), confidentiality: "any-model" });
    const before = await gate.pathLevel(join(ws, "proj", "sub", "notes.md"));
    const moved = await post("/api/files/move-page-rules");
    assert.equal(moved.status, 200, JSON.stringify(moved.body));
    assert.equal(moved.body.moved, 1);
    assert.deepEqual(await gate.pathLevel(join(ws, "proj", "sub", "notes.md")), before, "protection does not change");
    assert.match(readFileSync(policyPath, "utf8"), /proj\/sub/);
    const undo = await fetch(`${base}/api/policy/changes/${encodeURIComponent(moved.body.changeId)}/undo`, { method: "POST", headers: CSRF_ADMIN });
    assert.notEqual(undo.status, 200, "the move cannot be undone");
    const listedAfter = (await (await fetch(`${base}/api/files/list?path=${encodeURIComponent("~/ws/proj")}`, { headers: CSRF_ADMIN })).json()) as any;
    assert.equal(listedAfter.entries.find((e: any) => e.name === "sub").label.store, "policy");
  } finally {
    await server.close();
    wired.close();
    gate.close();
    admin.close();
    await arbiter.close();
  }
});
