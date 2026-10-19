/**
 * pathLevels op (dashboard.md §4.25m) through `dispatch`, no socket: the
 * request validation and the per-entry shape. The store precedence over a
 * real policy document and the DB store is pinned in test/component/path-levels.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { PATH_LEVELS_MAX } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

function withServer(fn: (srv: ArbiterServer) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pathlevels-"));
  const srv = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyDocument: {}, policyPollMs: 0,
  });
  try { fn(srv); } finally { srv.close().catch(() => {}); rmSync(dir, { recursive: true, force: true }); }
}

type Res = { ok: boolean; error?: string; result?: { axis: boolean; levels: Array<{ path: string; level: string; rule: string | null; store: string | null; bindings: string[] }> } };

test("pathLevels: catalog entries carry the rule and no store; unmatched paths are public", () => {
  withServer((srv) => {
    const r = srv.dispatch({ id: 1, op: "pathLevels", paths: ["/h/u/.ssh/id_ed25519", "/h/u/a.txt"] }, { channel: "data" }) as Res;
    assert.equal(r.ok, true);
    assert.equal(r.result!.axis, true);
    assert.equal(r.result!.levels[0]!.level, "no-model");
    assert.equal(r.result!.levels[0]!.store, null);
    assert.ok(r.result!.levels[0]!.rule, "the catalog rule is named");
    assert.deepEqual(r.result!.levels[1], { path: "/h/u/a.txt", level: "public", bindings: [], rule: null, store: null });
  });
});

test("pathLevels: rides the data socket (read-only, not admin-only)", () => {
  withServer((srv) => {
    const r = srv.dispatch({ id: 1, op: "pathLevels", paths: [] }, { channel: "data" }) as Res;
    assert.equal(r.ok, true, r.error);
  });
});

test("pathLevels: a malformed request is refused, never half-answered", () => {
  withServer((srv) => {
    for (const paths of [undefined, "/a", [1], Array.from({ length: PATH_LEVELS_MAX + 1 }, () => "/a")]) {
      const r = srv.dispatch({ id: 1, op: "pathLevels", paths } as never, { channel: "data" }) as Res;
      assert.equal(r.ok, false, `refused: ${JSON.stringify(paths)?.slice(0, 40)}`);
      assert.match(r.error!, /at most 1000 strings/);
    }
  });
});
