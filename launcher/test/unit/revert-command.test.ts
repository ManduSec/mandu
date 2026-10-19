/**
 * revert-command — `mandu revert` (comparisons.md §3.8) with the
 * fs-sync CLI faked: list, plan-then-ask, refuse without a terminal or
 * --yes, decline, and revert. The fs-sync side is proven for real in
 * fs-sync/test/integrity/fs-sync-cli.test.ts (history / revert over a real shadow
 * repo).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { plainRevertError, renderHistory, renderPlan, runRevert, type RevertDeps } from "../../src/revert-command.js";

const PLAN = { ok: true as const, reverted: false, to: 1, timestamp: "2026-09-25T10:00:00Z", abandoned: 2, kept: 3, removed: ["second.txt"] };

function fake(over: Partial<RevertDeps> = {}): { deps: RevertDeps; calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    deps: {
      fsCli: (args) => {
        calls.push(args);
        if (args[0] === "history") return { code: 0, stdout: JSON.stringify({ ok: true, cycles: [{ number: 1, timestamp: "2026-09-25T10:00:00Z", files: ["first.txt"], tool: "Write" }] }), stderr: "" };
        const dry = args.includes("--dry-run");
        return { code: 0, stdout: JSON.stringify({ ...PLAN, reverted: !dry }), stderr: "" };
      },
      gitRoot: () => "/ws",
      cwd: () => "/ws/sub",
      isTTY: () => true,
      confirm: async () => true,
      ...over,
    },
  };
}

/** stdout through the `out` sink (patching process.stdout.write would swallow
 *  the test runner's report, which shares the stream); stderr by patching,
 *  which the runner does not use. */
async function quiet<T>(fn: (out: (s: string) => void) => Promise<T>): Promise<{ v: T; out: string; err: string }> {
  const o: string[] = [], e: string[] = [];
  const ew = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: string) => boolean }).write = (s) => { e.push(s); return true; };
  try { return { v: await fn((s) => { o.push(s); }), out: o.join(""), err: e.join("") }; } finally {
    (process.stderr as unknown as { write: typeof ew }).write = ew;
  }
}

test("no --to: lists the writes of the workspace's git root", async () => {
  const f = fake();
  const r = await quiet((out) => runRevert([], {}, {} as never, { ...f.deps, out }));
  assert.equal(r.v, 0);
  assert.deepEqual(f.calls, [["history", "/ws"]]);
  assert.match(r.out, /#1 +2026-09-25 10:00:00  Write +first\.txt/);
});

test("--to N: the dry-run plan first, then the revert once confirmed; no state-base flag (fs-sync takes the home's state/)", async () => {
  const f = fake();
  const r = await quiet((out) => runRevert(["--to", "1"], { MANDU_VIEW_STATE: "/s" }, {} as never, { ...f.deps, out }));
  assert.equal(r.v, 0);
  assert.deepEqual(f.calls, [["revert", "--to", "1", "--dry-run", "/ws"], ["revert", "--to", "1", "/ws"]], "the retired MANDU_VIEW_STATE is not read");
  assert.match(r.out, /2 later writes undone/);
  assert.match(r.out, /removed: second\.txt/);
  assert.match(r.out, /Reverted to write #1/);
});

test("--to N refuses without a terminal unless --yes, and a 'no' changes nothing", async () => {
  let f = fake({ isTTY: () => false });
  let r = await quiet((out) => runRevert(["--to", "1"], {}, {} as never, { ...f.deps, out }));
  assert.equal(r.v, 1);
  assert.match(r.err, /not reverting without --yes/);
  assert.equal(f.calls.length, 1, "only the dry run ran");
  f = fake({ isTTY: () => false });
  r = await quiet((out) => runRevert(["--to", "1", "--yes"], {}, {} as never, { ...f.deps, out }));
  assert.equal(r.v, 0);
  assert.equal(f.calls.length, 2);
  f = fake({ confirm: async () => false });
  r = await quiet((out) => runRevert(["--to", "1"], {}, {} as never, { ...f.deps, out }));
  assert.equal(r.v, 1);
  assert.match(r.out, /Nothing changed/);
  assert.equal(f.calls.length, 1);
});

test("a bad --to is a usage error; a failing fs-sync is reported", async () => {
  assert.equal((await quiet((out) => runRevert(["--to", "0"], {}, {} as never, { ...fake().deps, out }))).v, 2);
  const r = await quiet((out) => runRevert([], {}, {} as never, { ...fake({ fsCli: () => ({ code: 1, stdout: "", stderr: "no Mandu history for /ws" }) }).deps, out }));
  assert.equal(r.v, 1);
  assert.match(r.err, /no Mandu history/);
  assert.match(r.err, /records the agent's writes only in the injection and full modes/);
});

test("fs-sync's failures reach the user without its internal prefix, in plain words (release checklist d5)", () => {
  const none = plainRevertError("[fs-sync-cli] no Mandu history for /ws (it was never opened in a mode that tracks writes: injection or full)\n", 1, "/ws");
  assert.doesNotMatch(none, /fs-sync-cli/);
  assert.match(none, /^no Mandu history for \/ws: .*nothing to undo here$/);
  assert.equal(plainRevertError("[fs-sync-cli] Write #9 not found (3 write cycles exist)", 1, "/ws"), "there is no write #9: 3 writes are recorded (`mandu revert` lists them)");
  assert.equal(plainRevertError("[fs-sync-cli] git reset failed: boom", 1, "/ws"), "git reset failed: boom");
  assert.equal(plainRevertError("", 7, "/ws"), "the history tool stopped with code 7");
});

test("renderers", () => {
  assert.match(renderHistory("/ws", []), /no writes recorded yet/);
  assert.match(renderPlan({ ...PLAN, removed: [] }), /no file is removed/);
});
