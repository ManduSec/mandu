/**
 * Unit: workspaceIdFor / ViewLayout state-dir naming.
 *
 * Locks in the properties the `<basename>-<sha256[:12]>` scheme MUST hold (it
 * replaced `encodeURIComponent(path)`, whose `%2F`-per-slash expansion could blow
 * past NAME_MAX on deep real workspaces — see layout.ts adaptation notes):
 *   - a single filesystem-safe path component (no `/`, no `%2F`);
 *   - bounded length (cannot hit the 255-byte NAME_MAX ceiling);
 *   - deterministic and collision-free across distinct paths (even same basename);
 *   - a human-recognizable basename prefix.
 * Reversibility is intentionally NOT a property: the canonical path lives in
 * workspace.json (metadata.workspacePath), and nothing decodes the dir name.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { ViewLayout, workspaceIdFor } from "../../src/layout.js";

test("workspaceIdFor: single filesystem-safe component (no slashes, no %2F)", () => {
  const id = workspaceIdFor("/tmp/pinchbench/0001/agent_workspace");
  assert.doesNotMatch(id, /\//, "id must not contain a path separator");
  assert.doesNotMatch(id, /%2[Ff]/, "id must not contain a percent-encoded slash");
  assert.match(id, /^[A-Za-z0-9._-]+$/, "id is a safe single path component");
});

test("workspaceIdFor: <basename>-<12 hex sha256> shape, bounded length", () => {
  const id = workspaceIdFor("/tmp/mandu-e2e-fs/live/trusted-and-untrusted/workspace");
  assert.match(id, /^workspace-[0-9a-f]{12}$/, "readable basename + 12-hex hash");
  // basename capped at 40 + '-' + 12 hex ⇒ far under the 255-byte NAME_MAX ceiling
  // the old encodeURIComponent scheme could exceed on deep paths.
  assert.ok(id.length <= 53, `id length ${id.length} stays bounded`);
});

test("workspaceIdFor: deterministic for the same canonical path", () => {
  const a = workspaceIdFor("/tmp/a/b/c");
  const b = workspaceIdFor("/tmp/a/b/c");
  assert.equal(a, b, "same path ⇒ same id");
});

test("workspaceIdFor: distinct paths sharing a basename get distinct ids", () => {
  // Same basename `workspace`, different parents — the hash is over the FULL path,
  // so these must not collide (the basename prefix alone is not identity).
  const one = workspaceIdFor("/tmp/proj-one/workspace");
  const two = workspaceIdFor("/tmp/proj-two/workspace");
  assert.notEqual(one, two, "same basename, different path ⇒ different id");
  assert.ok(one.startsWith("workspace-") && two.startsWith("workspace-"));
});

test("workspaceIdFor: root path degrades to a `root-` prefix, still valid", () => {
  const id = workspaceIdFor("/");
  assert.match(id, /^root-[0-9a-f]{12}$/, "empty basename falls back to `root`");
});

test("workspaceIdFor: GOLDEN cross-language vector (Rust twin: fs-supervisor layout.rs)", () => {
  // These literals are asserted verbatim by the Rust mirror in
  // interceptors/fs-supervisor/src/layout.rs (workspace_id_matches_fs_sync_golden_vector).
  // The LD_PRELOAD/seccomp redirect lands on the worktree fs-sync seeded ONLY if
  // both languages derive the same dir name — a drift here broke the live FS
  // chokepoint once (the interposer redirected reads to a nonexistent dir →
  // ENOENT). Change the scheme ⇒ change both implementations + both tests in the
  // same commit. (Paths are nonexistent, so canonicalization is a pure resolve.)
  assert.equal(workspaceIdFor("/home/u/proj"), "proj-9c09f8055a26");
  assert.equal(workspaceIdFor("/srv/data"), "data-96b53e47e3fc");
  assert.equal(workspaceIdFor("/"), "root-8a5edab28263");
  // Non [A-Za-z0-9._-] basename chars sanitize to '_'; the hash is over the
  // UNsanitized full path.
  assert.equal(workspaceIdFor("/tmp/My Proj!"), "My_Proj_-175f9f42097a");
});

test("ViewLayout: state paths hang off the id; metadata round-trips the real path", () => {
  const layout = new ViewLayout("/tmp/a/b/c", "/state");
  assert.equal(layout.workspaceId, workspaceIdFor("/tmp/a/b/c"));
  assert.equal(layout.workspaceDir, `/state/workspaces/${layout.workspaceId}`);
  assert.equal(layout.agentViewPath, `/state/workspaces/${layout.workspaceId}/agentview`);
  const meta = layout.metadata();
  assert.equal(meta.workspaceId, layout.workspaceId);
  // The canonical HumanView path is what makes the id reversible — recorded here,
  // not decoded from the dir name.
  assert.equal(meta.workspacePath, layout.humanPath);
});
