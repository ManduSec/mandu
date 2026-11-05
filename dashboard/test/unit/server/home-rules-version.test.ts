/**
 * home-rules-version.test — `buildHome` (GET /api/home) carries
 * `rulesVersion`, the opaque version of your rules an open Rules page
 * follows (view-model/home.ts `rulesVersionOf`; dashboard.md §4.25 *Rules
 * follows a change made elsewhere*).
 *
 * Pins:
 * - it changes when the in-force document changes (its `lawHash`, through
 *   the `policy` dep Home already reads), and stays the same otherwise;
 * - it changes when an answer kept in Rules is given, given again or
 *   forgotten, and not for a question waiting or a count of uses;
 * - it is absent with no reader, a read that throws, an older arbiter with
 *   no `lawHash`, or a queue that was not read;
 * - it holds no path, no destination and no rule's words.
 *
 * Axes: the arbiter's posture is the snapshot's own, `secrets` (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildHome, HomeFacts, type HomeDeps } from "../../../src/server/home-routes.js";
import type { EventSource } from "../../../src/event-source.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import type { PolicyDocumentView } from "../../../src/server/policy-doc-routes.js";

const FILE = "/home/u/ws/deploy/staging.tfvars";
const HOST = "paste-canary.example";

function snapshot(verdicts: VerdictEntry[] | undefined): PolicySnapshot {
  return {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, // the `secrets` axes, stated
    usage: { rules: [], sensitivePaths: [] },
    ...(verdicts ? { verdicts } : {}),
  } as unknown as PolicySnapshot;
}
function verdict(id: string, status: VerdictEntry["status"], over: Partial<VerdictEntry> = {}): VerdictEntry {
  return { id, symbol: "$MDU:file:abcdef0123456789", destination: `net:${HOST}`, status, reason: "", count: 1, firstSeen: 1, lastSeen: 2, resolvedAt: status === "pending" ? null : 1000, scope: "always", ...over };
}
function doc(lawHash: string | undefined): PolicyDocumentView {
  return {
    status: { path: "/home/u/.mandu/policy.yaml", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null },
    inForce: { labels: [{ path: FILE, level: "no-model" }] },
    ...(lawHash !== undefined ? { lawHash } : {}),
    onDisk: { text: `labels:\n  - path: ${FILE}\n`, parsed: null, problems: [] },
  };
}

function deps(mandu: string, opts: { policy?: HomeDeps["policy"] | null; verdicts?: VerdictEntry[] | undefined }): HomeDeps {
  const source = {
    listSessions: async () => [],
    policySnapshot: async () => snapshot("verdicts" in opts ? opts.verdicts : []),
  } as unknown as EventSource;
  return {
    source,
    facts: new HomeFacts(source, "/home/u"),
    approvals: undefined,
    ...(opts.policy ? { policy: opts.policy } : {}),
    testRuns: [],
    watchRuns: [],
    env: { MANDU_HOME: mandu },
    home: "/home/u",
  };
}
const at = (hash: string | undefined): HomeDeps["policy"] => ({ policyDocument: async () => doc(hash) });

async function withHome(fn: (mandu: string) => Promise<void>): Promise<void> {
  const mandu = mkdtempSync(join(tmpdir(), "mandu-home-rules-version-"));
  try { await fn(mandu); } finally { rmSync(mandu, { recursive: true, force: true }); }
}

test("rulesVersion moves with the in-force document and holds otherwise", () => withHome(async (mandu) => {
  const a = await buildHome(deps(mandu, { policy: at("law-1") }));
  const again = await buildHome(deps(mandu, { policy: at("law-1") }));
  const b = await buildHome(deps(mandu, { policy: at("law-2") }));
  assert.equal(typeof a.rulesVersion, "string");
  assert.match(a.rulesVersion!, /^[0-9a-f]{32}$/, "an opaque digest");
  assert.equal(again.rulesVersion, a.rulesVersion, "nothing changed: the same version");
  assert.notEqual(b.rulesVersion, a.rulesVersion, "a rule changed: a new version");
  assert.notEqual(a.rulesVersion, "law-1", "not the arbiter's hash as is");
}));

test("rulesVersion moves with an answer kept in Rules, not with a waiting question or a count of uses", () => withHome(async (mandu) => {
  const v = async (verdicts: VerdictEntry[]) => (await buildHome(deps(mandu, { policy: at("law-1"), verdicts }))).rulesVersion;
  const none = await v([]);
  const waiting = await v([verdict("egr-1", "pending")]);
  assert.equal(waiting, none, "a question waiting is no rule");
  const once = await v([verdict("egr-1", "approved", { scope: "once" })]);
  assert.equal(once, none, "Allow once is not kept in Rules");
  const allowed = await v([verdict("egr-1", "approved")]);
  assert.notEqual(allowed, none, "Always allow: a new version");
  assert.equal(await v([verdict("egr-1", "approved", { count: 9, lastSeen: 99 })]), allowed, "asked again: the same rule");
  assert.notEqual(await v([verdict("egr-1", "denied", { resolvedAt: 2000 })]), allowed, "answered again: a new version");
  assert.equal(await v([verdict("egr-2", "pending"), verdict("egr-1", "approved")]), allowed, "order and waiting rows do not matter");
  assert.equal(await v([]), none, "forgotten: back to none");
}));

test("rulesVersion is absent when it cannot be read", () => withHome(async (mandu) => {
  assert.equal((await buildHome(deps(mandu, { policy: null }))).rulesVersion, undefined, "no reader");
  assert.equal((await buildHome(deps(mandu, { policy: { policyDocument: async () => { throw new Error("arbiter down"); } } }))).rulesVersion, undefined, "a read that fails");
  assert.equal((await buildHome(deps(mandu, { policy: at(undefined) }))).rulesVersion, undefined, "an older arbiter, no lawHash");
  assert.equal((await buildHome(deps(mandu, { policy: at("law-1"), verdicts: undefined }))).rulesVersion, undefined, "the answers were not read");
  const down = await buildHome({ ...deps(mandu, { policy: at("law-1") }), source: { listSessions: async () => [], policySnapshot: async () => { throw new Error("down"); } } as unknown as EventSource });
  assert.equal(down.rulesVersion, undefined, "no panel");
}));

test("rulesVersion holds no path, destination or rule's words", () => withHome(async (mandu) => {
  const vm = await buildHome(deps(mandu, { policy: at("law-1"), verdicts: [verdict("egr-1", "approved")] }));
  assert.ok(vm.rulesVersion);
  for (const s of [FILE, "staging", HOST, "egr-1", "no-model", "law-1"]) assert.ok(!vm.rulesVersion!.includes(s), `no ${s}`);
  // The rest of /api/home carries no more of the document than before.
  const body = JSON.stringify(vm);
  assert.ok(!body.includes(FILE) && !body.includes("law-1"), "neither the document's path rule nor its hash reaches /api/home");
}));
