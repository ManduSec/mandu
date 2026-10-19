/**
 * symbol-reuse.test — findReusableSymbol (symbol-table): the stable-symbol
 * contract behind the arbiter's symbolize op. The stateless Messages API
 * re-sends history every turn; re-symbolizing the identical allocation key
 * must return the FIRST minted live symbol, never an obsoleted one, and never
 * collapse distinct provenance.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  type SymbolMap,
  allocateSymbol,
  findReusableSymbol,
  obsoleteSymbol,
} from "../../symbol-table/index.js";

function emptyMap(): SymbolMap {
  return { symbols: new Map() };
}

const KEY = {
  tool: "Read", field: undefined, value: "raw bytes",
  origin: "/ws/notes.md", sessionKey: "s1", callId: "c1",
};

test("finds the live symbol minted for the identical key; misses on any key difference", () => {
  const map = emptyMap();
  const sym = allocateSymbol(map, KEY);
  assert.equal(findReusableSymbol(map, KEY), sym);
  assert.equal(findReusableSymbol(map, { ...KEY, value: "other" }), null);
  assert.equal(findReusableSymbol(map, { ...KEY, tool: "WebFetch" }), null);
  assert.equal(findReusableSymbol(map, { ...KEY, field: "text" }), null);
  assert.equal(findReusableSymbol(map, { ...KEY, origin: "/ws/other.md" }), null);
  assert.equal(findReusableSymbol(map, { ...KEY, sessionKey: "s2" }), null);
  assert.equal(findReusableSymbol(map, { ...KEY, callId: "c2" }), null);
});

test("an OBSOLETED symbol is never reused (stale data must not resurrect)", () => {
  // obsoleteSymbol always persists, and unlike allocateSymbol it has no
  // in-memory-only mode — an explicit temp path keeps this unit test off the
  // user's real arbiter DB (a bare call would open the default path, and its
  // legacy migration probe refuses while a live arbiter owns the legacy file).
  const dir = mkdtempSync(join(tmpdir(), "mandu-symreuse-"));
  try {
    const map = emptyMap();
    const sym = allocateSymbol(map, KEY);
    const replacement = allocateSymbol(map, { ...KEY, callId: "c-new" });
    obsoleteSymbol(map, sym, replacement, join(dir, "mandu.db"));
    assert.equal(findReusableSymbol(map, KEY), null, "obsoleted → mint fresh");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the FIRST minted symbol wins when duplicates predate the reuse fix", () => {
  const map = emptyMap();
  const first = allocateSymbol(map, KEY);
  allocateSymbol(map, KEY); // a pre-fix duplicate
  assert.equal(findReusableSymbol(map, KEY), first);
});

test("absent optional fields match null-normalized (a bare {tool,value} key round-trips)", () => {
  const map = emptyMap();
  const sym = allocateSymbol(map, { tool: "exec", value: "v" });
  assert.equal(findReusableSymbol(map, { tool: "exec", value: "v" }), sym);
});
