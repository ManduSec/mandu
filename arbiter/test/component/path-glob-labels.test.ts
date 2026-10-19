/**
 * e2e — gitignore-style `policy.yaml paths:` patterns through the REAL arbiter
 * (confidentiality.md §6.1). The invariant half: a file a pattern labels secret
 * mints a SECRET symbol, so its content reaches the model only as an opaque
 * token at the pattern's level; the pattern's bindings ride the symbol; and a
 * pattern can never be used to UNDER-label what a closer label or the catalog
 * (absent any label) says.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

async function withLaw(doc: PolicyFileConfig, fn: (data: ArbiterClient, admin: ArbiterClient) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-glob-e2e-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyDocument: doc, policyPollMs: 0,
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
    // every drill workspace's contracts dir, wherever the run put it
    { path: "**/ws-*/contracts/**", level: "any-model", bindings: ["example.com"] },
    { path: "**/*.pem", level: "no-model" },
    // the fixture override, as a pattern
    { path: "**/test/fixtures/.env", level: "public", recursive: false },
  ],
};

test("a pattern-labeled file mints a SECRET symbol at the pattern's level, with its bindings: the content reaches the model only as that token", async () => {
  await withLaw(LAW, async (data) => {
    const SECRET = "Acme pays 4,200,000 USD on signature.";
    const r = await data.symbolizeFull({ tool: "Read", value: SECRET, field: "content", origin: "/runs/20260920/ws-c4/contracts/acme.md" });
    assert.ok(r.symbol.includes("anymodel_"), `expected a model-ok secret symbol, got ${r.symbol}`);
    assert.ok(!r.symbol.includes("4,200,000"), "the token is opaque");
    assert.equal(r.confidentiality, "any-model");
    const lvl = await data.pathLevel("/runs/20260920/ws-c4/contracts/acme.md");
    assert.deepEqual(lvl, { level: "any-model", bindings: ["example.com"], axis: true, rule: "label:**/ws-*/contracts/**" }, "and the deciding PATTERN is named");

    const pem = await data.symbolizeFull({ tool: "Read", value: "-----BEGIN PRIVATE KEY-----", field: "content", origin: "/srv/app/tls/server.pem" });
    assert.ok(pem.symbol.includes("nomodel_") && !pem.symbol.includes("anymodel_"), `expected a strict symbol, got ${pem.symbol}`);

    // segment-aware: the sibling directory is NOT covered
    const sib = await data.pathLevel("/runs/20260920/ws-c4/contracts-public/acme.md");
    assert.equal(sib.level, "public");
    assert.equal(sib.rule, null);
  });
});

test("a public pattern releases exactly what it names: the fixture .env, not the workspace's real .env (the catalog still fails closed)", async () => {
  await withLaw(LAW, async (data) => {
    assert.deepEqual(await data.pathLevel("/ws/test/fixtures/.env"), { level: "public", bindings: [], axis: true, rule: "label:**/test/fixtures/.env" });
    const real = await data.pathLevel("/ws/.env");
    assert.equal(real.level, "no-model");
    assert.equal(real.rule, "shape:.env*");
    const fixture = await data.symbolizeFull({ tool: "Read", value: "API_KEY=fixture", field: "content", origin: "/ws/test/fixtures/.env" });
    assert.ok(!fixture.symbol.includes("nomodel_"), "no secret marker on the released fixture");
  });
});

test("a dashboard (DB) label composes with the patterns: a closer literal directory label beats a `**` pattern, an exact literal beats everything", async () => {
  await withLaw(LAW, async (data, admin) => {
    await admin.setPathLabel({ path: "/srv/app/tls", confidentiality: "any-model", recursive: true });
    assert.equal((await data.pathLevel("/srv/app/tls/server.pem")).level, "any-model", "the directory label is closer to the file than a pattern with no literal prefix");
    await admin.setPathLabel({ path: "/srv/app/tls/server.pem", confidentiality: "no-model", recursive: false });
    assert.deepEqual(await data.pathLevel("/srv/app/tls/server.pem"), { level: "no-model", bindings: [], axis: true, rule: "label:/srv/app/tls/server.pem" });
    // the standing-release surface lists the patterns AS patterns
    const listed = await admin.pathLabels();
    const pub = listed.find((l) => l.path === "**/test/fixtures/.env");
    assert.equal(pub?.glob, true);
    assert.equal(pub?.declassifies, true, "a public pattern is reported as a declassification");
  });
});

// ── Test a flow: "which rule decided, and why" (policy-surface.md §4) ──

const OUTRANK_LAW: PolicyFileConfig = {
  paths: [
    { path: "/srv/notes", level: "any-model", bindings: ["example.com"] },
    { path: "**/*.pem", level: "no-model" },
    { path: "**/*.md", level: "public" },
  ],
};

test("testFlow on a filesystem path answers the pathLevel derivation and names a STRICTER pattern that lost to a closer directory label, without changing any decision", async () => {
  await withLaw(OUTRANK_LAW, async (data) => {
    const r = await data.testFlow({ source: { tool: "Read", field: "content", origin: "/srv/notes/k.pem" }, destination: "evil.example" });
    const lvl = await data.pathLevel("/srv/notes/k.pem");
    assert.deepEqual(r.pathLabel, {
      path: "/srv/notes/k.pem", ...lvl,
      outranked: [{ pattern: "**/*.pem", level: "no-model" }],
    }, "level / bindings / axis / rule are exactly pathLevel's answer");
    assert.equal(r.pathLabel!.rule, "label:/srv/notes");
    assert.equal(r.pathLabel!.level, "any-model");
    // observability only: the probe runs at the level the real gate derived
    assert.equal(r.probe.level, "any-model");
    assert.ok(r.egress && r.egress.decision.allow === false, "a secret headed for an unbound host is not allowed");
    // and the real mint agrees with what the tester reported
    const minted = await data.symbolizeFull({ tool: "Read", value: "-----BEGIN PRIVATE KEY-----", field: "content", origin: "/srv/notes/k.pem" });
    assert.equal(minted.confidentiality, "any-model");
    assert.ok(!minted.symbol.includes("BEGIN"), "the content reaches the model only as an opaque token");

    // the looser `**/*.md` = public pattern lost too, but is not STRICTER: no note
    assert.deepEqual((await data.testFlow({ source: { tool: "Read", origin: "/srv/notes/a.md" } })).pathLabel?.outranked, []);
    // a pattern that decided: named as the rule, nothing outranked
    const pem = (await data.testFlow({ source: { tool: "Read", origin: "/etc/tls/server.pem" } })).pathLabel!;
    assert.equal(pem.rule, "label:**/*.pem");
    assert.deepEqual(pem.outranked, []);
    // the catalog deciding, and nothing matching
    assert.equal((await data.testFlow({ source: { tool: "Read", origin: "/ws/.env" } })).pathLabel!.rule, "shape:.env*");
    assert.deepEqual((await data.testFlow({ source: { tool: "Read", origin: "/ws/readme.txt" } })).pathLabel,
      { path: "/ws/readme.txt", level: "public", bindings: [], axis: true, rule: null, outranked: [] });
    // a URL source is not a path: no derivation is claimed
    assert.equal((await data.testFlow({ source: { tool: "WebFetch", origin: "https://example.com/k.pem" } })).pathLabel, undefined);
    assert.equal((await data.testFlow({ source: { tool: "WebFetch" } })).pathLabel, undefined);
  });
});

test("testFlow with the confidentiality axis OFF says so instead of reporting a path as public", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-glob-e2e-off-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: false, policyDocument: OUTRANK_LAW, policyPollMs: 0,
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "a.sock"));
  try {
    await data.connect();
    const r = await data.testFlow({ source: { tool: "Read", origin: "/srv/notes/k.pem" } });
    assert.deepEqual(r.pathLabel, { path: "/srv/notes/k.pem", level: "public", bindings: [], axis: false, rule: null, outranked: [] });
  } finally {
    data.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the DECLASSIFIED flag on a below-strict pattern: raised when it AIMS at catalog-secret files, not for a whole-directory pattern (parity with a literal directory label)", async () => {
  await withLaw({
    paths: [
      { path: "**/ws-*/contracts/**", level: "any-model" },   // a directory's contents
      { path: "**/.env*", level: "any-model" },               // aims at the catalog's .env shape
      { path: "~/.ssh/*", level: "any-model" },               // under a catalog prefix
      { path: "**/*credentials*", level: "no-model" },         // strict can weaken nothing
      { path: "/srv/app/*.md", level: "any-model" },          // ordinary names
    ],
  }, async (_data, admin) => {
    const by = new Map((await admin.pathLabels()).map((l) => [l.path, l.declassifies]));
    assert.equal(by.get("**/ws-*/contracts/**"), false);
    assert.equal(by.get("**/.env*"), true, "a model-ok pattern over `.env*` weakens files the catalog calls strict: say so");
    assert.equal([...by].find(([p]) => p.endsWith("/.ssh/*"))?.[1], true);
    assert.equal(by.get("**/*credentials*"), false);
    assert.equal(by.get("/srv/app/*.md"), false);
  });
});
