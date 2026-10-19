/**
 * backstop-raised-row.test — confidentiality-plan-15-prompt-filter.md §4.1,
 * "What a raised row registers".
 *
 * A tool result the path rules call public but in which the value backstop
 * finds a registered secret is raised to the secret's level and masked whole,
 * and its row is registered. Every long line of that row used to be a piece,
 * so a later unrelated result sharing an ordinary line (a heading, a log
 * line) was masked whole. Now such a row, when the arbiter can tell its level
 * is the backstop's raise alone, keeps only the lines a secret was found in
 * (and its whole value, its credential-shaped spans, any line with one).
 *
 * The oracle half (a later result with the secret is masked, through the real
 * proxy): tests/stack/backstop-raised-row.test.ts.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { RegisteredValueIndex, raisedRowKeptLines, raisedRowPieces } from "../../prompt-filter/registered-values.js";
import { valuePieces } from "../../policy/egress-fingerprint.js";
import { RaisedRowStore } from "../../symbol-table/raised-rows.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/symbol-table.js";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const TOKEN = "sk_live_RaisedRowUnit7Kq2Xr9Lm4Tz8V";
const SECRET_LINE = `STRIPE_SECRET_KEY=${TOKEN}`;
const HEADING = "## Deployment checklist for the release team";
const LOGLINE = "INFO  starting worker pool with 8 workers";
const RAISED = `${HEADING}\n- bump the version\n${SECRET_LINE}\n${LOGLINE}\n`;

test("raisedRowKeptLines: the lines a span touches, a span across a line break keeps both", () => {
  const at = RAISED.indexOf(TOKEN);
  assert.deepEqual([...raisedRowKeptLines(RAISED, [{ start: at, end: at + TOKEN.length }])], [2]);
  const nl = RAISED.indexOf("\n", at);
  assert.deepEqual([...raisedRowKeptLines(RAISED, [{ start: at, end: nl + 3 }])].sort(), [2, 3]);
  assert.deepEqual([...raisedRowKeptLines(RAISED, [{ start: 0, end: 1 }])], [0]);
  assert.equal(raisedRowKeptLines(RAISED, []).size, 0);
  assert.equal(raisedRowKeptLines(RAISED, [{ start: 5, end: 5 }]).size, 0, "an empty span keeps nothing");
});

test("raisedRowPieces: ordinary long lines are dropped; the kept line, a line with a credential shape, the spans and the trimmed value stay", () => {
  const all = valuePieces(RAISED, 0, {}).pieces;
  assert.ok(all.includes(HEADING) && all.includes(LOGLINE) && all.includes(SECRET_LINE), "control: every long line is a piece");
  const kept = raisedRowPieces(RAISED, all, new Set([2]));
  assert.ok(kept.includes(SECRET_LINE), "the line the secret was found in");
  assert.ok(!kept.includes(HEADING) && !kept.includes(LOGLINE), "ordinary lines are no piece");
  assert.ok(kept.includes(RAISED.replace(/\n$/, "")), "the value without its final break stays");
  for (const p of all) if (p !== HEADING && p !== LOGLINE) assert.ok(kept.includes(p), `only the ordinary lines go: ${p}`);
  // a line carrying another credential shape is never dropped as ordinary
  const other = "GITHUB_TOKEN=ghp_Zq8vT3nLk2Wp9Rx4Hb7Mc1Fd6Gs0Jy5Ua8Ee2";
  const v = `${HEADING}\n${other}\n${SECRET_LINE}\n`;
  const p2 = raisedRowPieces(v, valuePieces(v, 0, {}).pieces, new Set([2]));
  assert.ok(p2.includes(other), "a credential-shaped line stays a piece");
  assert.ok(!p2.includes(HEADING));
  // nothing kept: the ordinary lines still go, nothing else does
  assert.deepEqual(raisedRowPieces("short\n", ["short"], new Set()), ["short"]);
});

function row(value: string, extra: Partial<SymbolEntry> = {}): SymbolEntry {
  return {
    value, tool: "Read", field: null, origin: "/ws/notes.md", session_key: "s", call_id: "c", created_at: 0,
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "no-model", bindings: null, integrity: "untrusted", ...extra,
  };
}

test("RegisteredValueIndex: a raised row's ordinary lines are no hit once its kept lines are known; its secret line and whole value are", () => {
  const map: SymbolMap = { symbols: new Map([["$MDU:r[0001]", row(RAISED)]]) };
  const idx = new RegisteredValueIndex();
  idx.sync(map);
  assert.deepEqual(idx.hits(`x\n${HEADING}\n`).map((h) => h.symbol), ["$MDU:r[0001]"], "control: every line counts");
  const keep = new Map([["$MDU:r[0001]", new Set([2])]]);
  idx.sync(map, undefined, 1, undefined, (name) => keep.get(name) ?? null);
  assert.deepEqual(idx.hits(`x\n${HEADING}\n${LOGLINE}\n`), [], "ordinary lines are no hit");
  assert.deepEqual(idx.hits(`later ${SECRET_LINE}`).map((h) => h.symbol), ["$MDU:r[0001]"], "the secret line is");
  assert.deepEqual(idx.hits(`y ${TOKEN} z`).map((h) => h.symbol), ["$MDU:r[0001]"], "the credential span is");
  assert.deepEqual(idx.hits(RAISED).map((h) => h.how), ["value"], "the whole value is");
});

test("RaisedRowStore: a mark is bound to its row's value; a gone row, another value or a broken list is not loaded", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-raised-store-"));
  try {
    const dbPath = join(dir, "db.sqlite");
    const s = new RaisedRowStore({ dbPath });
    s.record("$MDU:r[0001]", RAISED, new Set([2]));
    s.record("$MDU:r[0002]", "old value", new Set([0]));
    s.record("$MDU:r[0003]", RAISED, new Set([1, 2]));
    s.close();
    const again = new RaisedRowStore({ dbPath });
    const map: SymbolMap = { symbols: new Map([["$MDU:r[0001]", row(RAISED)], ["$MDU:r[0002]", row("another value")]]) };
    assert.deepEqual([...again.load(map)].map(([n, k]) => [n, [...k]]), [["$MDU:r[0001]", [2]]]);
    again.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the arbiter narrows a row only when its classify raised a public verdict for the call, the symbolize says so, and the secrets found reach its level; a restart keeps it (real server)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-raised-row-"));
  const opts = {
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: "/ws/vault", level: "no-model", recursive: true }, { path: "/ws/brief", level: "any-model", recursive: true }] } as never,
  };
  const boot = async (): Promise<{ s: ArbiterServer; c: ArbiterClient }> => {
    const s = new ArbiterServer(opts);
    await s.listen();
    const c = new ArbiterClient(join(dir, "human", "h.sock"));
    await c.connect();
    return { s, c };
  };
  let { s, c } = await boot();
  try {
    const hitBy = async (text: string): Promise<string[]> => (await c.scanSecretValues(text)).hits.map((h) => h.symbol);
    // the source: a registered no-model value holding the secret line
    await c.symbolize({ tool: "Read", value: `# billing\n${SECRET_LINE}\nSTRIPE_ACCOUNT=acct_public_example\n`, origin: "/ws/vault/billing.env", sessionKey: "S", callId: "src" });
    const classify = (callId: string, value: string, origin = "/ws/notes.md") =>
      c.classify({ tool: "Read", value, boundary: "model_context", origin, params: { file_path: origin }, sessionKey: "S", callId });
    const symbolize = (callId: string, value: string, extra: Record<string, unknown> = {}) =>
      c.symbolize({ tool: "Read", value, origin: "/ws/notes.md", sessionKey: "S", callId, confidentiality: "no-model", ...extra });

    // 1. raised by the backstop, said so: only the secret line is a piece
    const v1 = RAISED;
    const r1 = await classify("c1", v1);
    assert.equal(r1.confidentiality, "no-model");
    assert.equal((r1 as { raisedBy?: string }).raisedBy, "value-backstop");
    const s1 = await symbolize("c1", v1, { secretBy: "value-backstop" });
    const check = async (when: string): Promise<void> => {
      assert.ok(!(await hitBy(`${HEADING}\n${LOGLINE}\n`)).includes(s1), `${when}: the raised row's ordinary lines are no piece`);
      assert.ok((await hitBy(`later ${SECRET_LINE}`)).includes(s1), `${when}: its secret line is`);
      assert.ok((await hitBy(v1)).includes(s1), `${when}: its whole value is`);
    };
    await check("before the restart");

    // 2. fail-closed: each missing condition keeps every line
    const ordinaryOf = (n: number): string => `## Ordinary heading number ${n} for the team`;
    const vOf = (n: number): string => `${ordinaryOf(n)}\n${SECRET_LINE}\n`;
    // 2a. no `secretBy`
    await classify("c2", vOf(2));
    const s2 = await symbolize("c2", vOf(2));
    // 2b. `secretBy`, but no classify of that call or value raised it
    const s3 = await symbolize("c3", vOf(3), { secretBy: "value-backstop" });
    // 2c. the call's result was secret by policy too (a labelled path)
    await classify("c4", vOf(4), "/ws/vault/copy.env");
    const s4 = await c.symbolize({ tool: "Read", value: vOf(4), origin: "/ws/notes.md", sessionKey: "S", callId: "c4", confidentiality: "no-model", secretBy: "value-backstop" });
    // 2d. the row's own origin is labelled
    await classify("c5", vOf(5));
    const s5 = await c.symbolize({ tool: "Read", value: vOf(5), origin: "/ws/brief/x.md", sessionKey: "S", callId: "c5", confidentiality: "no-model", secretBy: "value-backstop" });
    // 2e. the secrets found do not reach the row's level (any-model source, no-model row)
    await c.symbolize({ tool: "Read", value: `brief: ${"BRIEF_SOURCE_LINE_0123456789_abcdefgh"}\n`, origin: "/ws/brief/b.md", sessionKey: "S", callId: "src2" });
    const v6 = `${ordinaryOf(6)}\nbrief: BRIEF_SOURCE_LINE_0123456789_abcdefgh\n`;
    const r6 = await classify("c6", v6);
    assert.equal(r6.confidentiality, "any-model");
    const s6 = await symbolize("c6", v6, { secretBy: "value-backstop" });
    for (const [n, name, why] of [[2, s2, "no secretBy"], [3, s3, "no classify record"], [4, s4, "secret by policy"], [5, s5, "a labelled origin"], [6, s6, "a level above the secrets found"]] as const) {
      assert.ok((await hitBy(`x ${ordinaryOf(n)} y`)).includes(name), `${why}: the ordinary line stays a piece`);
    }

    c.close();
    await s.close();
    ({ s, c } = await boot());
    await check("after the restart, with no re-send");
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
