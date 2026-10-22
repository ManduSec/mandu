/**
 * transcript-suggestions — plan 17 §3 item 13's pure parts: the claims'
 * shape (`parseScanFileClaims`), the check of each file against its own
 * content (`verifyScanFile`: only a credential the arbiter's extractor reads
 * under a NAMED key makes a candidate; an agent's own file, Mandu's state, a
 * path outside HOME and an unreadable file never do), the suggestion's
 * project (`claimRepoRoot`: never HOME), and the generator
 * (`suggestPastSessionEdits`: one no-model lock per file, `rotate: true`,
 * covered when the catalog or the law protects it).
 * Axes: none (pure decision logic).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import { claimRepoRoot, parseScanFileClaims, verifyScanFile, type VerifyDeps } from "../../policy/transcript-suggestions.js";
import { pastSessionsFindingKey, suggestPastSessionEdits } from "../../policy/policy-suggestions.js";

stateAxes("secrets");

const TOKEN = `${"gh" + "o_"}Zt4Qm8Lp2Xw7Rk9Vb3Nc6Hj1Df5Gs0Ae2Yu8T`;
const HOME = "/home/u";

function deps(files: Record<string, string>, extra: Partial<VerifyDeps> = {}): VerifyDeps {
  return {
    home: HOME,
    read: (p) => files[p] ?? null,
    agentOwn: (p) => p.startsWith(`${HOME}/.codex/`),
    manduState: (p) => p.startsWith(`${HOME}/.mandu/`),
    ...extra,
  };
}

test("parseScanFileClaims: the shape is checked, names deduplicated, the time re-written", () => {
  const ok = parseScanFileClaims([{ path: "/home/u/a/../b.yml", names: ["token", "token"], sessions: 2, last: "2026-10-19T08:00:00Z" }]);
  assert.ok(Array.isArray(ok));
  assert.deepEqual(ok, [{ path: "/home/u/b.yml", names: ["token"], sessions: 2, last: "2026-10-19T08:00:00.000Z" }]);
  assert.deepEqual(parseScanFileClaims([{ path: "/a", names: ["x"] }]), [{ path: "/a", names: ["x"], sessions: 0, last: null }]);
  for (const bad of [null, {}, [1], [{ path: "a", names: ["x"] }], [{ path: "/a", names: [] }], [{ path: "/a", names: [""] }], [{ path: "/a\0b", names: ["x"] }], [{ path: "/a", names: ["x"], sessions: -1 }], [{ path: "/a", names: ["x"], sessions: 1.5 }], [{ path: "/a", names: ["x"], last: "soon" }]]) {
    assert.ok("error" in (parseScanFileClaims(bad) as object), JSON.stringify(bad));
  }
});

test("verifyScanFile: only a credential under a named key makes a candidate", () => {
  const cfg = `${HOME}/.config/cli/config.yml`;
  const files = { [cfg]: `user: someone\ntoken: ${TOKEN}\nversion: 3.2.1\n` };
  const v = verifyScanFile({ path: cfg, names: ["token", "version"], sessions: 3, last: null }, deps(files));
  assert.deepEqual(v, { ok: true, file: { path: cfg, repoRoot: `${HOME}/.config/cli`, names: ["token"], sessions: 3, last: null } });
  // A name the file does not give a credential: refused.
  assert.deepEqual(verifyScanFile({ path: cfg, names: ["user"], sessions: 1, last: null }, deps(files)), { ok: false, why: "no-credential" });
  // The caller's names are never trusted alone: a file holding none.
  assert.deepEqual(verifyScanFile({ path: `${HOME}/x.yml`, names: ["token"], sessions: 1, last: null }, deps({ [`${HOME}/x.yml`]: "token: changeme\n" })), { ok: false, why: "no-credential" });
});

test("verifyScanFile: outside HOME, an agent's own file, Mandu's state and an unreadable file are refused", () => {
  const body = `token: ${TOKEN}\n`;
  const claim = (path: string) => ({ path, names: ["token"], sessions: 1, last: null });
  assert.deepEqual(verifyScanFile(claim("/etc/cli.yml"), deps({ "/etc/cli.yml": body })), { ok: false, why: "not-under-home" });
  assert.deepEqual(verifyScanFile(claim(`${HOME}`), deps({})), { ok: false, why: "not-under-home" });
  assert.deepEqual(verifyScanFile(claim(`${HOME}/.codex/auth.yml`), deps({ [`${HOME}/.codex/auth.yml`]: body })), { ok: false, why: "agent-own" });
  assert.deepEqual(verifyScanFile(claim(`${HOME}/.mandu/state/x.yml`), deps({ [`${HOME}/.mandu/state/x.yml`]: body })), { ok: false, why: "mandu-state" });
  assert.deepEqual(verifyScanFile(claim(`${HOME}/gone.yml`), deps({})), { ok: false, why: "not-a-file" });
});

test("claimRepoRoot: the nearest work tree below HOME, else the file's folder, never HOME", () => {
  const trees = new Set([`${HOME}/shop`, HOME]);
  const isTree = (d: string) => trees.has(d);
  assert.equal(claimRepoRoot(`${HOME}/shop/deploy/conf.yml`, HOME, isTree), `${HOME}/shop`);
  assert.equal(claimRepoRoot(`${HOME}/.config/cli/config.yml`, HOME, isTree), `${HOME}/.config/cli`);
  assert.equal(claimRepoRoot(`${HOME}/top.yml`, HOME, isTree), HOME, "a file right in HOME has HOME as its folder");
});

test("suggestPastSessionEdits: one no-model lock per file, rotate on, covered when protected", () => {
  const law = { specId: "claude-code" as const, document: { version: 1 }, pathLabels: new Map() } as unknown as Parameters<typeof suggestPastSessionEdits>[1];
  const a = { path: `${HOME}/.config/cli/config.yml`, repoRoot: `${HOME}/.config/cli`, names: ["token"], sessions: 3, last: "2026-10-19T08:00:00.000Z" };
  const b = { path: `${HOME}/shop/.env`, repoRoot: `${HOME}/shop`, names: ["STRIPE_KEY"], sessions: 1, last: null };
  const r = suggestPastSessionEdits([a, b, a], law, { home: HOME, isCovered: (p) => p.endsWith("/.env") });
  assert.equal(r.suggestions.length, 1);
  const s = r.suggestions[0]!;
  assert.equal(s.source, "past-sessions");
  assert.equal(s.findingKey, pastSessionsFindingKey(a.path));
  assert.deepEqual(s.edits, [{ op: "lock-path", path: a.path, level: "no-model" }]);
  assert.equal(s.rotate, true);
  assert.equal(s.sentence, "Make ~/.config/cli/config.yml a secret no AI may read");
  assert.deepEqual(s.evidence.pastSessions, { names: ["token"], sessions: 3, last: "2026-10-19T08:00:00.000Z" });
  assert.deepEqual(s.impact, { historicalVersions: 0, workingTreeChanges: true, files: ["config.yml"] });
  assert.deepEqual(r.covered.map((c) => c.paths), [[".env"]]);
  // A glob character in a name is a literal lock.
  const odd = suggestPastSessionEdits([{ ...a, path: `${HOME}/a[1].yml`, repoRoot: HOME }], law, { home: HOME });
  assert.deepEqual(odd.suggestions[0]!.edits, [{ op: "lock-path", path: `${HOME}/a\\[1\\].yml`, level: "no-model" }]);
});
