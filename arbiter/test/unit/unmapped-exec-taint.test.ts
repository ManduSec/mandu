/**
 * unmapped-exec-taint.test.ts — plan 10 §11.12, the store half: the raw
 * secret reads of ONE session (every session with none given), the answer
 * `callTaint` falls back to for an unmapped command tool the guard never
 * tied to a process tree.
 *
 * Mandu-new test. No privilege, a temp SQLite file.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProvenanceStore } from "../../provenance/provenance-store.js";

test("sessionSecretTaint: the strictest level of the session's rows; other sessions never count; none ⇒ null", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-prov-unmapped-"));
  const store = new ProvenanceStore({ dbPath: join(dir, "symbols.db") });
  try {
    assert.deepEqual(store.sessionSecretTaint("s1"), { level: null, rows: [] });
    store.taintProcessSecret({ procKey: "psql-1", path: "/h/.pgpass", level: "any-model", app: "psql", session: "s1" });
    assert.equal(store.sessionSecretTaint("s1").level, "any-model");
    store.taintProcessSecret({ procKey: "gh-2", path: "/h/.config/gh/hosts.yml", level: "no-model", app: "gh", session: "s1" });
    store.taintProcessSecret({ procKey: "aws-3", path: "/h/.aws/credentials", level: "no-model", app: "aws", session: "s2" });
    const s1 = store.sessionSecretTaint("s1");
    assert.equal(s1.level, "no-model");
    assert.deepEqual(s1.rows.map((r) => r.app).sort(), ["gh", "psql"]);
    assert.equal(store.sessionSecretTaint("s3").level, null, "a session with no raw read has nothing");
    assert.equal(store.sessionSecretTaint().rows.length, 3, "no session given: every session (fail-closed)");
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Claude Code's Monitor is a mapped shell: an inbound rule, the exec gate and the exec-output legs", async () => {
  const { inboundSpecNamesInput, getToolInboundSpec } = await import("../../policy/tool-inbound.js");
  const { CLAUDE_CODE_GATE_SURFACE, UNION_GATE_SURFACE } = await import("../../policy/tool-gate-surface.js");
  assert.equal(inboundSpecNamesInput("Monitor"), true);
  assert.deepEqual(getToolInboundSpec("Monitor"), { schema: "UNTRUSTED" });
  assert.equal(CLAUDE_CODE_GATE_SURFACE.exec["Monitor"], "command");
  assert.equal(CLAUDE_CODE_GATE_SURFACE.execOutput["Monitor"], "command");
  assert.equal(UNION_GATE_SURFACE.execOutput["Monitor"], "command");
});
