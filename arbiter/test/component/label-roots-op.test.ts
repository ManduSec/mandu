/**
 * The guard's view of the human labels (2026-10-17, confidentiality.md §6
 * "Read by a program the launch did not see"), over the REAL ArbiterServer
 * and the REAL ArbiterClient on the human socket, as the guard dials it:
 *
 *   `labelRootsSince` lists where the labels above `public` lie (a literal's
 *   path; a pattern's literal prefix, `/` for none, with its last segment's
 *   literal anchors; a declared client key), answers `unchanged` with no rows
 *   for the key it last gave, and a new key once a label is set;
 *   `labelledLevel` classifies a file under a root as `decideSecretOpen`
 *   would: the folder's level, `public` for a file a pattern does not match
 *   or a nested `public` label covers, the session's launch HOME's catalog;
 *   with the axis OFF there are no roots and every level is `public`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // explicit below: confidentiality ON, integrity OFF; the last test turns the axis OFF by name

async function rig(policyFor: (ws: string) => string, confidentiality = true): Promise<{ dir: string; ws: string; server: ArbiterServer; human: ArbiterClient; close: () => Promise<void> }> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-label-roots-")));
  const ws = join(dir, "ws");
  for (const d of ["vault/open", "notes", "keys"]) mkdirSync(join(ws, d), { recursive: true });
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, policyFor(ws));
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  await human.connect();
  return { dir, ws, server, human, close: async () => { human.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

const LABELS = (ws: string): string => [
  "version: 1",
  "paths:",
  `  - path: ${join(ws, "vault")}`,
  "    level: no-model",
  `  - path: ${join(ws, "vault", "open")}`,
  "    level: public",
  `  - path: ${join(ws, "notes")}/secret-*.md`,
  "    level: local-model",
  "  - path: '**/*.pem'",
  "    level: no-model",
  `  - path: ${join(ws, "keys")}/id_*`,
  "    level: no-model",
  "",
].join("\n");

test("labelRootsSince: a literal's path, a pattern's prefix with its last segment's anchors, never a public label; unchanged answers no rows", async () => {
  const r = await rig(LABELS);
  try {
    const first = await r.human.labelRootsSince({});
    assert.equal(first.unchanged, false);
    assert.ok(first.key.length > 0);
    const byPath = new Map(first.roots.map((x) => [`${x.path}|${JSON.stringify(x.shape ?? null)}`, x]));
    assert.ok(byPath.has(`${join(r.ws, "vault")}|null`), JSON.stringify(first.roots));
    assert.ok(byPath.has(`${join(r.ws, "notes")}|${JSON.stringify({ head: "secret-", tail: ".md", exact: false })}`), JSON.stringify(first.roots));
    assert.ok(byPath.has(`/|${JSON.stringify({ head: "", tail: ".pem", exact: false })}`), "a pattern with no prefix is rooted at /");
    assert.ok(byPath.has(`${join(r.ws, "keys")}|${JSON.stringify({ head: "id_", tail: "", exact: false })}`));
    assert.ok(!first.roots.some((x) => x.path === join(r.ws, "vault", "open")), "a public label is no root");
    for (const d of [".git", "node_modules", "target"]) assert.ok(first.skipDirs.includes(d), `the walk's skipped directory ${d} is shipped`);
    const again = await r.human.labelRootsSince({ key: first.key });
    assert.deepEqual({ ...again, skipDirs: [] }, { key: first.key, unchanged: true, roots: [], skipDirs: [] });
    // A label act changes the list and its key.
    const set = r.server.dispatch({ id: 1, op: "setPathLabel", path: join(r.ws, "late"), confidentiality: "no-model" } as never) as { ok: boolean };
    assert.ok(set.ok);
    const after = await r.human.labelRootsSince({ key: first.key });
    assert.equal(after.unchanged, false);
    assert.notEqual(after.key, first.key);
    assert.ok(after.roots.some((x) => x.path === join(r.ws, "late")));
  } finally {
    await r.close();
  }
});

test("labelledLevel: the label's level under a root, public where a pattern does not match or a nested public label speaks", async () => {
  const r = await rig(LABELS);
  try {
    const level = async (p: string): Promise<string> => (await r.human.labelledLevel({ path: p })).level;
    assert.equal(await level(join(r.ws, "vault", "plan.md")), "no-model");
    assert.equal(await level(join(r.ws, "vault", "a", "b", "c", "d", "e", "deep.md")), "no-model", "any depth below the folder");
    assert.equal(await level(join(r.ws, "vault", "open", "readme.md")), "public", "a nested public label");
    assert.equal(await level(join(r.ws, "notes", "secret-plan.md")), "local-model");
    assert.equal(await level(join(r.ws, "notes", "plan.md")), "public", "a name the pattern does not match");
    assert.equal(await level(join(r.ws, "elsewhere", "server.pem")), "no-model");
    assert.equal(await level("relative/path"), "public", "never a relative path");
    const roots = await r.human.labelRootsSince({});
    assert.equal((await r.human.labelledLevel({ path: join(r.ws, "vault", "plan.md") })).key, roots.key, "decided under the roots' key");
  } finally {
    await r.close();
  }
});

test("axis OFF: no roots, and every level is public", async () => {
  const r = await rig(LABELS, false);
  try {
    const roots = await r.human.labelRootsSince({});
    assert.deepEqual(roots.roots, []);
    assert.equal(roots.catalog, undefined, "nor any catalog prefilter");
    assert.equal((await r.human.labelledLevel({ path: join(r.ws, "vault", "plan.md") })).level, "public");
    assert.equal((await r.human.labelledLevel({ path: join(r.ws, "a", ".env") })).level, "public");
  } finally {
    await r.close();
  }
});

// ── The catalog (2026-10-17): a `.env` or a key the launch did not register ──

test("labelRootsSince ships the catalog: its prefixes as roots for the arbiter's HOME and the session's launch HOME, its name anchors, never an agent's own place", async () => {
  const r = await rig(() => "version: 1\n");
  try {
    const launchHome = join(r.dir, "lhome");
    mkdirSync(launchHome);
    await r.human.beginLaunch({ pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true, sessionId: "cat-s", home: launchHome });
    const withLaunch = await r.human.labelRootsSince({ session: "cat-s" });
    const paths = new Set(withLaunch.roots.filter((x) => x.shape === undefined).map((x) => x.path));
    for (const p of [join(homedir(), ".ssh"), join(launchHome, ".ssh"), join(launchHome, ".aws"), join(launchHome, ".config", "gcloud")]) assert.ok(paths.has(p), `${p} is a root`);
    for (const p of [join(launchHome, ".claude"), join(launchHome, ".codex"), join(homedir(), ".claude.json")]) assert.ok(!paths.has(p), `an agent's own place is no root: ${p}`);
    assert.ok(withLaunch.catalog, "the name prefilter is shipped");
    assert.deepEqual([...withLaunch.catalog!.homes].sort(), [homedir(), launchHome].sort());
    assert.ok(withLaunch.catalog!.names.some((a) => a.exact === ".env") && withLaunch.catalog!.names.some((a) => a.contains === "credentials" && a.ci === true));
    assert.ok(withLaunch.catalog!.skipDirs.includes("site-packages"));
    const own = await r.human.labelRootsSince({});
    assert.notEqual(own.key, withLaunch.key, "the launch HOME's places change the key");
    assert.ok(!own.roots.some((x) => x.path === join(launchHome, ".ssh")), "no session: the arbiter's HOME only");
    const again = await r.human.labelRootsSince({ session: "cat-s", key: withLaunch.key });
    assert.equal(again.unchanged, true);
    assert.equal(again.catalog, undefined, "an unchanged answer keeps the prefilter in force");
  } finally {
    await r.close();
  }
});

test("labelledLevel on a catalog file: the walk's rule (a template is public), its prunes, the launch HOME's places, at any depth", async () => {
  const r = await rig(() => "version: 1\n");
  try {
    const launchHome = join(r.dir, "lhome");
    const put = (p: string): string => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, "x\n"); return p; };
    await r.human.beginLaunch({ pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true, sessionId: "cat-l", home: launchHome });
    const level = async (p: string, session?: string): Promise<string> => (await r.human.labelledLevel({ path: p, ...(session ? { session } : {}) })).level;
    assert.equal(await level(put(join(r.ws, "a", "b", "c", "d", "e", "f", ".env"))), "no-model", "deeper than the walk");
    assert.equal(await level(put(join(r.ws, "keys", "server.key"))), "no-model");
    assert.equal(await level(put(join(r.ws, ".env.example"))), "public", "a template: the walk's rule, no content check");
    assert.equal(await level(put(join(r.ws, "node_modules", "pkg", ".env"))), "public", "the walk never enters node_modules");
    assert.equal(await level(put(join(r.ws, "readme.md"))), "public");
    const tok = put(join(launchHome, ".aws", "sso", "cache", "a", "b", "c", "tok.json"));
    assert.equal(await level(tok, "cat-l"), "no-model", "the launch HOME's catalog place, deeper than the walk");
    assert.equal(await level(tok), "public", "not one of this arbiter's HOME's places");
    assert.equal(await level(put(join(launchHome, ".claude", ".credentials.json")), "cat-l"), "public", "the launched agent's own login");
    // The guard registers what it gated naming no HOME: a file only the
    // launch HOME's catalog names is registered under that HOME (else its
    // twin could not be made and every program got EACCES).
    const sshKey = put(join(launchHome, ".ssh", "deploy_k042"));
    assert.equal(await level(sshKey, "cat-l"), "no-model");
    const reg = await r.human.registerSecret({ path: sshKey });
    assert.ok(reg.symbol, `registered under the launch HOME: ${reg.reason}`);
    // The cost of one classification over the human socket: the guard's one
    // round trip for a name an anchor admits (cached per file state after).
    const p = join(r.ws, "a", "b", "c", "d", "e", "f", ".env");
    const n = 500;
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < n; i++) await level(p, "cat-l");
    const us = Number(process.hrtime.bigint() - t0) / 1000 / n;
    console.log(`labelledLevel round trip: ${us.toFixed(0)} us`);
    assert.ok(us < 20_000, `a classification costs ${us} us`);
  } finally {
    await r.close();
  }
});
