/**
 * e2e — `pathLevels`, the Rules page file browser's labels (dashboard.md
 * §4.25m), over a REAL arbiter socket. One folder's entries in one round trip:
 * each entry carries the same derivation a read would mint with (`pathLevel`),
 * the deciding rule, and WHERE the deciding human label is kept, so the page
 * can say "your rule" / "from your rule on …" / "built-in" and change the rule
 * in the store that holds it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { PATH_LEVELS_MAX } from "../../ipc/protocol.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

async function withLaw(doc: PolicyFileConfig, confidentiality: boolean, fn: (data: ArbiterClient, admin: ArbiterClient) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pathlevels-e2e-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality, integrity: false, policyDocument: doc, policyPollMs: 0,
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "a.sock"));
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  try {
    await data.connect();
    await admin.connect();
    await fn(data, admin);
  } finally {
    data.close(); admin.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const LAW: PolicyFileConfig = {
  paths: [
    { path: "/srv/proj/config", level: "no-model" },
    { path: "/srv/proj/config/sample.env", level: "public", recursive: false },
    { path: "**/*.pem", level: "any-model", bindings: ["api.example.com"] },
    { path: "/srv/proj/notes.md", level: "local-model", recursive: false },
  ],
};

test("pathLevels: one entry per path, in order, naming the deciding rule and the store that keeps it", async () => {
  await withLaw(LAW, true, async (data, admin) => {
    // A label made on the page before labels moved to policy.yaml: the DB
    // store, which wins over policy.yaml on the same path.
    await admin.setPathLabel({ path: "/srv/proj/notes.md", confidentiality: "any-model", recursive: false });
    const asked = [
      "/srv/proj/config",
      "/srv/proj/config/db.yaml",
      "/srv/proj/config/sample.env",
      "/srv/proj/deploy.pem",
      "/srv/proj/.env",
      "/srv/proj/README.md",
      "/srv/proj/notes.md",
    ];
    const r = await data.pathLevels(asked);
    assert.equal(r.axis, true);
    assert.deepEqual(r.levels.map((l) => l.path), asked, "one entry per path, in the order asked");
    const at = (p: string) => r.levels.find((l) => l.path === p)!;
    assert.deepEqual(at("/srv/proj/config"), { path: "/srv/proj/config", level: "no-model", bindings: [], rule: "label:/srv/proj/config", store: "policy" });
    assert.equal(at("/srv/proj/config/db.yaml").rule, "label:/srv/proj/config", "inherited: the ancestor's rule decides");
    assert.equal(at("/srv/proj/config/db.yaml").level, "no-model");
    assert.equal(at("/srv/proj/config/sample.env").level, "public", "the closer rule wins, and beats the catalog's .env shape");
    assert.equal(at("/srv/proj/config/sample.env").store, "policy");
    assert.deepEqual(at("/srv/proj/deploy.pem"), { path: "/srv/proj/deploy.pem", level: "any-model", bindings: ["api.example.com"], rule: "label:**/*.pem", store: "policy" }, "a pattern is kept in policy.yaml too");
    assert.deepEqual(at("/srv/proj/.env"), { path: "/srv/proj/.env", level: "no-model", bindings: [], rule: "shape:.env*", store: null }, "built-in: no store");
    assert.deepEqual(at("/srv/proj/README.md"), { path: "/srv/proj/README.md", level: "public", bindings: [], rule: null, store: null });
    assert.equal(at("/srv/proj/notes.md").store, "page", "the page's own store wins on the same path");
    assert.equal(at("/srv/proj/notes.md").level, "any-model");

    // The same derivation a read would mint with.
    for (const p of asked) {
      const one = await data.pathLevel(p);
      assert.equal(one.level, at(p).level, `${p}: pathLevels agrees with pathLevel`);
      assert.equal(one.rule, at(p).rule);
    }
  });
});

test("pathLevels: answers with the confidentiality axis OFF (axis:false), unlike pathLevel", async () => {
  await withLaw(LAW, false, async (data) => {
    const r = await data.pathLevels(["/srv/proj/config/db.yaml", "/srv/proj/.env"]);
    assert.equal(r.axis, false, "nothing enforces these now");
    assert.equal(r.levels[0]!.level, "no-model", "…but the page can show what the rules will do");
    assert.equal(r.levels[1]!.rule, "shape:.env*");
    assert.equal((await data.pathLevel("/srv/proj/.env")).level, "public", "pathLevel (the mint) still answers public with the axis off");
  });
});

test("pathLevels: refuses a request over the cap or with a non-string path, and answers an empty list", async () => {
  await withLaw({}, true, async (data) => {
    await assert.rejects(data.pathLevels(Array.from({ length: PATH_LEVELS_MAX + 1 }, (_, i) => `/x/${i}`)), /at most/);
    await assert.rejects(data.pathLevels([42 as unknown as string]), /at most/);
    assert.deepEqual(await data.pathLevels([]), { axis: true, levels: [] });
    // A relative path is not a label path: nothing matches, public, no store.
    assert.deepEqual((await data.pathLevels(["relative/.ssh"])).levels[0]!.store, null);
  });
});

test("pathLevels withEdits: the labels under a proposed change, nothing written, the law in force untouched", async () => {
  await withLaw(LAW, true, async (data) => {
    const edits = [{ op: "lock-path", path: "/srv/proj", level: "public" }];
    const after = await data.pathLevels(["/srv/proj/.env", "/srv/proj/config/db.yaml", "/srv/proj/README.md"], undefined, edits);
    assert.equal(after.levels[0]!.level, "public", "a folder made Not secret covers the built-in .env inside it");
    assert.equal(after.levels[0]!.rule, "label:/srv/proj");
    assert.equal(after.levels[1]!.level, "no-model", "the closer folder rule still decides inside it");
    const now = await data.pathLevels(["/srv/proj/.env"]);
    assert.equal(now.levels[0]!.level, "no-model", "the law in force is untouched afterwards");
    assert.equal((await data.pathLevel("/srv/proj/.env")).level, "no-model");
    await assert.rejects(data.pathLevels(["/x"], undefined, [{ op: "lock-path", path: "", level: "public" }]), /withEdits/);
  });
});

test("movePageLabels: the dashboard's older rules move into policy.yaml unchanged, the rows are gone, enforcement is the same, and Undo refuses the move", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-move-labels-"));
  const policyPath = join(dir, "policy.yaml");
  // A policy.yaml entry the page row shadows on the same path (spelled
  // differently), with an expert field the row does not have.
  writeFileSync(policyPath, `version: 1\npaths:\n  - { path: "/srv/proj/notes.md", level: public, recursive: false, readers: [cat] }\n  - { path: "/srv/proj/config", level: no-model }\n`);
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0,
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "a.sock"));
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  try {
    await data.connect();
    await admin.connect();
    await assert.rejects(data.movePageLabels("x"), /admin-only/, "a human's act: the data socket is refused");
    assert.deepEqual(await admin.movePageLabels("t"), { moved: 0, changeId: null }, "nothing to move");
    await admin.setPathLabel({ path: "/srv/proj/notes.md", confidentiality: "no-model", recursive: false });
    await admin.setPathLabel({ path: "/srv/keys", confidentiality: "any-model", bindings: ["api.example.com"] });
    const probe = ["/srv/proj/notes.md", "/srv/keys/a.pem", "/srv/proj/config/x"];
    const before = await data.pathLevels(probe);
    assert.deepEqual(before.levels.map((l) => l.store), ["page", "page", "policy"]);

    const r = await admin.movePageLabels("human:rules-page");
    assert.equal(r.moved, 2);
    assert.ok(r.changeId);
    const after = await data.pathLevels(probe);
    assert.deepEqual(after.levels.map((l) => [l.level, l.bindings]), before.levels.map((l) => [l.level, l.bindings]), "what is enforced does not change");
    assert.deepEqual(after.levels.map((l) => l.store), ["policy", "policy", "policy"], "every rule now lives in policy.yaml");
    assert.deepEqual((await data.confidentialityState()).labels!.filter((l) => l.source !== "policy-file"), [], "the rows are gone from mandu.db");
    const text = readFileSync(policyPath, "utf8");
    assert.match(text, /\/srv\/keys/);
    assert.doesNotMatch(text, /readers/, "the shadowed entry is replaced by what was in force");
    const change = (await data.policyChanges(5)).changes.find((c) => c.id === r.changeId)!;
    assert.equal(change.via, "move-labels");
    assert.equal(change.undoable, false);
    await assert.rejects(admin.undoPolicyChange(r.changeId!, "human"), /moved rules made on the dashboard/);
  } finally {
    data.close(); admin.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
