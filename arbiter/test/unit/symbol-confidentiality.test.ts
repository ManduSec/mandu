import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../../db/sqlite.js";
import {
  loadSymbolMap,
  allocateSymbol,
  allocateDerivedSymbol,
  escalateSymbolConfidentiality,
  getSymbolEntry,
} from "../../symbol-table/symbol-table.js";
import { ArbiterServer } from "../../ipc/server.js";
import type { SymbolizeRequest, SymbolizeResult } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

function tmpDb(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-conf-"));
  return {
    path: join(dir, "symbols.db"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("allocate stores level + bindings, mints a marker name; both survive a reload", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = loadSymbolMap(path);
    const name = allocateSymbol(map, {
      tool: "Read", value: "AKIA...", origin: "~/.aws/credentials",
      confidentiality: "no-model", bindings: ["sts.amazonaws.com"],
    }, path);
    assert.ok(name.startsWith("$MDU:nomodel_Read["), name);
    const re = loadSymbolMap(path).symbols.get(name);
    assert.equal(re?.confidentiality, "no-model");
    assert.deepEqual(re?.bindings, ["sts.amazonaws.com"]);
  } finally {
    cleanup();
  }
});

test("unknown stored level parses fail-closed to no-model on load", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = loadSymbolMap(path);
    const name = allocateSymbol(map, { tool: "Bash", value: "x" }, path);
    // A future build wrote a level this build does not know.
    const db = new Database(path);
    db.prepare("UPDATE symbols SET confidentiality = ? WHERE sym_name = ?")
      .run("secret-compartment-hr", name);
    db.close();
    assert.equal(loadSymbolMap(path).symbols.get(name)?.confidentiality, "no-model");
  } finally {
    cleanup();
  }
});

test("corrupt bindings cell degrades to null (restricts), never kills the load", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = loadSymbolMap(path);
    const name = allocateSymbol(map, { tool: "Bash", value: "y" }, path);
    const db = new Database(path);
    db.prepare("UPDATE symbols SET bindings = ? WHERE sym_name = ?")
      .run("{not json", name);
    db.close();
    assert.equal(loadSymbolMap(path).symbols.get(name)?.bindings, null);
  } finally {
    cleanup();
  }
});

test("derived symbols inherit the parent's level and bindings (§8)", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = loadSymbolMap(path);
    const parent = allocateSymbol(map, {
      tool: "Read", value: "l1\nl2", origin: "~/.ssh/id_rsa",
      confidentiality: "no-model", bindings: ["github.com"],
    }, path);
    const child = allocateDerivedSymbol(map, {
      parentSymName: parent, value: "l1", lineStart: 0, lineEnd: 1, splitIndex: 0,
    }, path);
    assert.ok(child.startsWith("$MDU:nomodel_Read["), child);
    const e = getSymbolEntry(map, child);
    assert.equal(e?.confidentiality, "no-model");
    assert.deepEqual(e?.bindings, ["github.com"]);
    assert.equal(e?.derived_from, parent);
  } finally {
    cleanup();
  }
});

// ── the symbolize IPC op, ON and OFF (dispatch-level; the socket transport is
//    covered by ipc.test.ts / provenance-ipc.test.ts) ─────────────────────────

function makeServer(dir: string, confidentiality: boolean): ArbiterServer {
  return new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality,
  });
}

function symbolizeReq(extra: Partial<SymbolizeRequest>): SymbolizeRequest {
  return { id: "t", op: "symbolize", tool: "Read", value: "v", ...extra };
}

function resultOf(resp: unknown): SymbolizeResult {
  const r = resp as { ok: boolean; result: SymbolizeResult; error?: string };
  assert.equal(r.ok, true, r.error);
  return r.result;
}

test("symbolize ON: server-side derivation from a secret origin, no client level", () => {
  const { path, cleanup } = tmpDb();
  const dir = path.slice(0, path.lastIndexOf("/"));
  const server = makeServer(dir, true);
  try {
    const r = resultOf(server.dispatch(symbolizeReq({
      value: "AKIA...", origin: `${process.env.HOME}/.aws/credentials`,
    })));
    assert.equal(r.confidentiality, "no-model");
    assert.ok(r.symbol.startsWith("$MDU:nomodel_Read["), r.symbol);
  } finally {
    void server.close();
    cleanup();
  }
});

test("symbolize ON: Bash command origin (text scan) and URL origin (exempt)", () => {
  const { path, cleanup } = tmpDb();
  const dir = path.slice(0, path.lastIndexOf("/"));
  const server = makeServer(dir, true);
  try {
    const bash = resultOf(server.dispatch(symbolizeReq({
      tool: "Bash", value: "out", origin: "cat .env | base64",
    })));
    assert.equal(bash.confidentiality, "no-model");

    const web = resultOf(server.dispatch(symbolizeReq({
      tool: "web_fetch", value: "page", origin: "https://x.test/credentials",
    })));
    assert.equal(web.confidentiality, "public");
    assert.ok(web.symbol.startsWith("$MDU:web_fetch["), web.symbol);
  } finally {
    void server.close();
    cleanup();
  }
});

test("symbolize ON: explicit level can only raise; junk fails closed", () => {
  const { path, cleanup } = tmpDb();
  const dir = path.slice(0, path.lastIndexOf("/"));
  const server = makeServer(dir, true);
  try {
    const raised = resultOf(server.dispatch(symbolizeReq({
      value: "x", origin: "notes.txt", confidentiality: "no-model",
    })));
    assert.equal(raised.confidentiality, "no-model");

    const junk = resultOf(server.dispatch(symbolizeReq({
      value: "y", origin: "notes.txt", confidentiality: "bogus-level",
    })));
    assert.equal(junk.confidentiality, "no-model");
  } finally {
    void server.close();
    cleanup();
  }
});

test("symbolize ON: reuse escalates the stored row, keeps the name", () => {
  const { path, cleanup } = tmpDb();
  const dir = path.slice(0, path.lastIndexOf("/"));
  const server = makeServer(dir, true);
  try {
    const key = { value: "same-bytes", origin: "notes.txt", callId: "c1" };
    const first = resultOf(server.dispatch(symbolizeReq(key)));
    assert.equal(first.confidentiality, "public");
    const second = resultOf(server.dispatch(symbolizeReq({
      ...key, confidentiality: "no-model",
    })));
    assert.equal(second.symbol, first.symbol); // stable name across turns
    assert.equal(second.confidentiality, "no-model"); // row escalated
    // and it persisted
    assert.equal(
      loadSymbolMap(path).symbols.get(first.symbol)?.confidentiality,
      "no-model",
    );
  } finally {
    void server.close();
    cleanup();
  }
});

test("symbolize OFF (inertness, matrix fold 2): byte-identical to the pre-axis wire", () => {
  const { path, cleanup } = tmpDb();
  const dir = path.slice(0, path.lastIndexOf("/"));
  const server = makeServer(dir, false);
  try {
    const r = resultOf(server.dispatch(symbolizeReq({
      value: "AKIA...",
      origin: `${process.env.HOME}/.aws/credentials`,
      confidentiality: "no-model", // explicit level is IGNORED — off means off
    })));
    assert.equal("confidentiality" in r, false); // no new wire field
    assert.ok(r.symbol.startsWith("$MDU:Read["), r.symbol); // no marker
    assert.equal(loadSymbolMap(path).symbols.get(r.symbol)?.confidentiality, "public");
  } finally {
    void server.close();
    cleanup();
  }
});

test("integrity column: stored when ON, ignored when OFF, inherited by derived", () => {
  const { path, cleanup } = tmpDb();
  const dir = path.slice(0, path.lastIndexOf("/"));
  // ON: explicit trusted integrity is stored; junk parses untrusted.
  const on = makeServer(dir, true);
  try {
    const r = resultOf(on.dispatch(symbolizeReq({
      value: "KEY", origin: "notes.txt",
      confidentiality: "no-model", integrity: "trusted",
    } as never)));
    const map = loadSymbolMap(path);
    assert.equal(map.symbols.get(r.symbol)?.integrity, "trusted");

    const junk = resultOf(on.dispatch(symbolizeReq({
      value: "K2", origin: "notes.txt", integrity: "very-trusted",
    } as never)));
    assert.equal(loadSymbolMap(path).symbols.get(junk.symbol)?.integrity, "untrusted");
  } finally {
    void on.close();
  }
  // OFF: integrity param ignored — rows stay untrusted (pre-axis invariant).
  const off = makeServer(dir, false);
  try {
    const r = resultOf(off.dispatch(symbolizeReq({
      value: "K3", origin: "notes.txt", integrity: "trusted",
    } as never)));
    assert.equal(loadSymbolMap(path).symbols.get(r.symbol)?.integrity, "untrusted");
  } finally {
    void off.close();
    cleanup();
  }
});

test("derived symbols inherit the parent's integrity", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = loadSymbolMap(path);
    const parent = allocateSymbol(map, {
      tool: "Read", value: "l1\nl2", origin: "~/.ssh/id_rsa",
      confidentiality: "no-model", integrity: "trusted",
    }, path);
    const child = allocateDerivedSymbol(map, {
      parentSymName: parent, value: "l1", lineStart: 0, lineEnd: 1, splitIndex: 0,
    }, path);
    assert.equal(getSymbolEntry(map, child)?.integrity, "trusted");
  } finally {
    cleanup();
  }
});

test("switch ON changes nothing for non-secret data (matrix fold-3 seed)", () => {
  const { path, cleanup } = tmpDb();
  const dir = path.slice(0, path.lastIndexOf("/"));
  const server = makeServer(dir, true);
  try {
    const r = resultOf(server.dispatch(symbolizeReq({
      tool: "web_fetch", value: "page bytes", origin: "https://example.com/page",
    })));
    // Same name shape as an OFF server (no marker), level public — the only
    // difference the axis makes for benign data is the additive result field.
    assert.ok(r.symbol.startsWith("$MDU:web_fetch["), r.symbol);
    assert.equal(r.confidentiality, "public");
    assert.equal(loadSymbolMap(path).symbols.get(r.symbol)?.confidentiality, "public");
  } finally {
    void server.close();
    cleanup();
  }
});

test("escalation is monotone: labels rise, never fall — and persist", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = loadSymbolMap(path);
    const name = allocateSymbol(map, { tool: "Bash", value: "x2" }, path);
    escalateSymbolConfidentiality(map, name, "no-model", path);
    assert.equal(getSymbolEntry(map, name)?.confidentiality, "no-model");
    escalateSymbolConfidentiality(map, name, "public", path); // no-op
    assert.equal(getSymbolEntry(map, name)?.confidentiality, "no-model");
    assert.equal(loadSymbolMap(path).symbols.get(name)?.confidentiality, "no-model");
    // and the NAME kept its original (marker-free) spelling — presentation only
    assert.ok(name.startsWith("$MDU:Bash["), name);
  } finally {
    cleanup();
  }
});
