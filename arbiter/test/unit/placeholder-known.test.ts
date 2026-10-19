/**
 * placeholder-known — `placeholderBaseKnown` (symbol-table.ts), the rule
 * behind the `placeholderKnown` op the DevTools relay asks on the key that
 * closes a typed placeholder's code (devtools-relay.md §3.3). Pinned: a base
 * is known by its own row or by a field row beneath it (obsoleted rows too,
 * as `resolve` reads them); a sibling-looking name (`base` + more code
 * digits) is not beneath it; anything but a base answers false; and the
 * SOUNDNESS the relay relies on: whenever the base is unknown, every token
 * the agent could go on to type after it resolves to nothing (the same walk
 * `resolve` and the egress gate use). Secrets axes, explicit (the table only;
 * no axis is read). Mandu-new.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  allocateSymbol, findSymbolByName, loadSymbolMap, obsoleteSymbol, placeholderBaseKnown, resolveSymbol, PLACEHOLDER_BASE_RE,
} from "../../symbol-table/index.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

function table() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ph-known-"));
  const dbPath = join(dir, "symbols.db");
  const map = loadSymbolMap(dbPath);
  // A registered .env: a field row per variable (no row of the base itself).
  const field = allocateSymbol(map, { tool: "Read", field: "CARD_NUMBER", value: "4242424242424242", origin: "/h/.env", confidentiality: "no-model" }, dbPath);
  // An ordinary result: a base row of its own.
  const plain = allocateSymbol(map, { tool: "web_fetch", value: "a page" }, dbPath);
  const gone = allocateSymbol(map, { tool: "Bash", value: "old output" }, dbPath);
  obsoleteSymbol(map, gone, "human", dbPath);
  return { map, dbPath, field, plain, gone, close: () => rmSync(dir, { recursive: true, force: true }) };
}

const baseOf = (name: string): string => name.slice(0, name.indexOf("]") + 1);

test("placeholderBaseKnown: a base is known by its own row or a field row beneath it, obsoleted ones too; a longer code is another base", () => {
  const t = table();
  try {
    assert.equal(placeholderBaseKnown(t.map, baseOf(t.field)), true, "known through its field row");
    assert.equal(placeholderBaseKnown(t.map, t.plain), true, "its own row");
    assert.equal(placeholderBaseKnown(t.map, t.gone), true, "obsoleted: still read by resolve, so still known");
    const code = /\[([0-9a-f]+)\]/.exec(t.plain)![1]!;
    const other = code === "0000" ? "0001" : "0000";
    assert.equal(placeholderBaseKnown(t.map, t.plain.replace(`[${code}]`, `[${other}]`)), false, "a made-up code");
    assert.equal(placeholderBaseKnown(t.map, t.plain.replace("$MDU:web_fetch", "$MDU:web_fetchX")), false, "another kind");
    assert.equal(placeholderBaseKnown(t.map, t.plain.replace(`[${code}]`, `[${code}0]`)), false, "a longer code is not beneath it");
    for (const notBase of [t.field, `${t.plain}.text`, "$MDU:web_fetch[zz]", "$MDU:k[012]", "", "web_fetch"]) {
      assert.equal(PLACEHOLDER_BASE_RE.test(notBase), false, notBase);
      assert.equal(placeholderBaseKnown(t.map, notBase), false, `not a base: ${notBase}`);
    }
  } finally {
    t.close();
  }
});

test("placeholderBaseKnown is sound for the relay: an unknown base means no token typed after it resolves (the walk resolve and the gate use)", () => {
  const t = table();
  try {
    const kinds = ["nomodel_Read", "web_fetch", "Bash", "Read"];
    const tails = ["", ".", ".text", ".CARD_NUMBER", ".CARD_NUMBER.", ".CARD_NUMBER.x", ".a[0]", ".a.b.c"];
    let unknownBases = 0;
    for (const kind of kinds) {
      for (let i = 0; i < 0x200; i++) {
        const base = `$MDU:${kind}[${i.toString(16).padStart(4, "0")}]`;
        if (placeholderBaseKnown(t.map, base)) continue;
        unknownBases++;
        for (const tail of tails) {
          assert.equal(findSymbolByName(t.map, base + tail), null, base + tail);
          assert.equal(resolveSymbol(t.map, base + tail), null, base + tail);
        }
      }
    }
    assert.ok(unknownBases > 0);
    // And the table's own names: each base known, each name resolves.
    for (const name of t.map.symbols.keys()) {
      assert.equal(placeholderBaseKnown(t.map, baseOf(name)), true, name);
      assert.notEqual(findSymbolByName(t.map, name), null, name);
    }
  } finally {
    t.close();
  }
});
