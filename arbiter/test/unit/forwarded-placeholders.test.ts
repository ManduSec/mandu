/**
 * forwarded-placeholders.test — the model proxies' placeholder records in
 * mandu.db (confidentiality.md §6, "OpenClaw's history redacts
 * placeholders", *Across a relaunch*; symbol-table/forwarded-placeholders.ts).
 * Mandu-new, no reference origin.
 *
 * A relaunch that resumes an OpenClaw conversation re-sends a history whose
 * results OpenClaw redacted; the proxy rebuilds the text it forwarded from
 * the placeholders it recorded here and checks the digest. The store keeps
 * NOTHING but tokens, offsets and a digest (every placeholder must be
 * exactly one symbol token), survives a restart, is bounded, and its two
 * ops are human plane only.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, humanPlaneOnlyError, type IpcChannel } from "../../ipc/server.js";
import type { ArbiterRequest } from "../../ipc/protocol.js";
import { ForwardedPlaceholderStore, MAX_MAPS_PER_REQUEST, MAX_PLACEHOLDERS, parsePlaceholderMap } from "../../symbol-table/forwarded-placeholders.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); the ops answer the same on any axis

function withDir<T>(fn: (dir: string) => Promise<T> | T): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-fwd-ph-"));
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const TOK = "$MDU:nomodel_Read[e7f3].STRIPE_KEY";
const DIGEST = "a".repeat(64);
const MAP = { callId: "toolu_r1", digest: DIGEST, placeholders: [[12, TOK]] as Array<[number, string]> };

test("parsePlaceholderMap: a call id, a 64-hex digest and increasing [offset, token] pairs whose token is exactly one symbol token", () => {
  assert.deepEqual(parsePlaceholderMap(MAP), MAP);
  assert.deepEqual(parsePlaceholderMap({ ...MAP, placeholders: [[0, "$MDU:Bash[464e]"], [15, TOK]] }), { ...MAP, placeholders: [[0, "$MDU:Bash[464e]"], [15, TOK]] }, "adjacent tokens");
  const bad: Array<[unknown, RegExp]> = [
    [null, /not an object/],
    [{ ...MAP, callId: "has space" }, /callId/],
    [{ ...MAP, digest: "A".repeat(64) }, /digest/],
    [{ ...MAP, digest: "a".repeat(63) }, /digest/],
    [{ ...MAP, placeholders: [] }, /1 to/],
    [{ ...MAP, placeholders: Array.from({ length: MAX_PLACEHOLDERS + 1 }, (_, i) => [i * 40, TOK]) }, /1 to/],
    [{ ...MAP, placeholders: [[0, TOK], [10, TOK]] }, /increase and not overlap/],
    [{ ...MAP, placeholders: [[-1, TOK]] }, /increase/],
    [{ ...MAP, placeholders: [[1.5, TOK]] }, /increase/],
    [{ ...MAP, placeholders: [[0]] }, /pair/],
    // the minimisation: no text but a whole token can be stored
    [{ ...MAP, placeholders: [[0, "STRIPE_KEY=sk_live_raw_value"]] }, /exactly one symbol token/],
    [{ ...MAP, placeholders: [[0, `${TOK} and more text`]] }, /exactly one symbol token/],
    [{ ...MAP, placeholders: [[0, `x${TOK}`]] }, /exactly one symbol token/],
  ];
  for (const [x, why] of bad) {
    const r = parsePlaceholderMap(x);
    assert.equal(typeof r, "string", JSON.stringify(x));
    assert.match(r as string, why);
  }
});

test("ForwardedPlaceholderStore: records, answers in the order asked, a later record of an id replaces it, and survives a reopen (a relaunch)", () =>
  withDir((dir) => {
    const dbPath = join(dir, "mandu.db");
    const s1 = new ForwardedPlaceholderStore({ dbPath });
    assert.equal(s1.record([MAP, { ...MAP, callId: "toolu_r2" }]), 2);
    s1.record([{ ...MAP, callId: "toolu_r2", digest: "b".repeat(64) }]);
    assert.deepEqual(s1.known(["toolu_r2", "toolu_x", "toolu_r1"]).map((m) => [m.callId, m.digest[0]]), [["toolu_r2", "b"], ["toolu_r1", "a"]]);
    s1.close();
    const s2 = new ForwardedPlaceholderStore({ dbPath });
    assert.deepEqual(s2.known(["toolu_r1"]), [MAP]);
    s2.close();
  }));

test("ForwardedPlaceholderStore: past its bound the OLDEST rows go first (only a restore is lost)", () =>
  withDir((dir) => {
    const s = new ForwardedPlaceholderStore({ dbPath: join(dir, "mandu.db"), maxRows: 2 });
    for (const id of ["a", "b", "c"]) s.record([{ ...MAP, callId: id }]);
    assert.deepEqual(s.known(["a", "b", "c"]).map((m) => m.callId), ["b", "c"]);
    s.close();
  }));

test("ForwardedPlaceholderStore: the table holds the id, the digest, the tokens and their offsets, never another byte of the text", () =>
  withDir((dir) => {
    const dbPath = join(dir, "mandu.db");
    const s = new ForwardedPlaceholderStore({ dbPath });
    s.record([MAP]);
    s.close();
    const bytes = readFileSync(dbPath).toString("latin1") + (() => { try { return readFileSync(`${dbPath}-wal`).toString("latin1"); } catch { return ""; } })();
    assert.match(bytes, /CREATE TABLE forwarded_placeholders \(\s*call_id\s+TEXT PRIMARY KEY,\s*digest\s+TEXT NOT NULL,\s*placeholders TEXT NOT NULL,\s*recorded_at\s+INTEGER NOT NULL\s*\)/);
    assert.ok(bytes.includes(TOK) && bytes.includes(DIGEST));
  }));

function server(dir: string): ArbiterServer {
  mkdirSync(join(dir, "human"), { recursive: true, mode: 0o700 });
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
}

type Resp = { ok: boolean; result?: unknown; error?: string };
const call = (s: ArbiterServer, req: Record<string, unknown>, channel: IpcChannel): Resp =>
  s.dispatch({ id: "t", ...req } as ArbiterRequest, { channel }) as Resp;

test("recordForwardedPlaceholders / forwardedPlaceholders: human plane only; malformed maps skipped; a later arbiter over the same mandu.db (a relaunch) answers them", () =>
  withDir(async (dir) => {
    const s1 = server(dir);
    try {
      const refused = [
        call(s1, { op: "recordForwardedPlaceholders", maps: [MAP] }, "data"),
        call(s1, { op: "forwardedPlaceholders", ids: ["toolu_r1"] }, "data"),
      ];
      assert.equal(refused[0]!.error, humanPlaneOnlyError("recordForwardedPlaceholders"));
      assert.equal(refused[1]!.error, humanPlaneOnlyError("forwardedPlaceholders"));
      assert.deepEqual(call(s1, { op: "forwardedPlaceholders", ids: ["toolu_r1"] }, "human").result, { maps: [] }, "the refused record wrote nothing");
      const rec = call(s1, { op: "recordForwardedPlaceholders", maps: [MAP, { ...MAP, callId: "x y" }, { ...MAP, callId: "toolu_raw", placeholders: [[0, "sk_live_raw"]] }, 7] }, "human");
      assert.deepEqual(rec.result, { recorded: 1, skipped: 3 });
    } finally {
      await s1.close();
    }
    const s2 = server(dir);
    try {
      assert.deepEqual(call(s2, { op: "forwardedPlaceholders", ids: ["toolu_raw", "toolu_r1", " "] }, "human").result, { maps: [MAP] });
      assert.deepEqual(call(s2, { op: "forwardedPlaceholders", ids: ["toolu_r1"] }, "admin").result, { maps: [MAP] });
    } finally {
      await s2.close();
    }
  }));

test("recordForwardedPlaceholders / forwardedPlaceholders: a non-array or an over-long list is refused whole", () =>
  withDir(async (dir) => {
    const s = server(dir);
    try {
      assert.match(call(s, { op: "recordForwardedPlaceholders", maps: MAP }, "human").error ?? "", /maps must be an array/);
      assert.match(call(s, { op: "recordForwardedPlaceholders", maps: Array.from({ length: MAX_MAPS_PER_REQUEST + 1 }, () => MAP) }, "human").error ?? "", /at most/);
      assert.match(call(s, { op: "forwardedPlaceholders", ids: "toolu_r1" }, "human").error ?? "", /ids must be an array/);
      assert.deepEqual(call(s, { op: "forwardedPlaceholders", ids: ["toolu_r1"] }, "human").result, { maps: [] });
    } finally {
      await s.close();
    }
  }));
