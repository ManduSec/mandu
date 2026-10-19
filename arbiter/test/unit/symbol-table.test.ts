/**
 * symbol-table.test.ts — unit tests for the lifted Mandu symbol table.
 *
 * Mandu-new test (no reference origin). Covers the security-relevant core:
 * symbol generation/format, value matching, and the symbolize↔desymbolize
 * round-trip — including the field-path resolution and human-edit obsolescence
 * paths preserved from the reference. Uses Node's built-in test runner
 * (`node:test`) + `node:assert`, mirroring the reference repo's tsx + assert
 * style with zero extra deps.
 *
 * Run: npm run test:unit   (or: tsx --test test/unit/symbol-table.test.ts)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  MDU_SYM_FORMAT,
  getActiveFormat,
  shortToolTag,
  unescapeSymbols,
  type SymbolMap,
  type SymbolEntry,
  allocateSymbol,
  allocateDerivedSymbol,
  resolveSymbol,
  resolveAllSymbols,
  resolveAllSymbolsDeep,
  findSymbolsByValue,
  findSymbolsByCallId,
  findReusableSymbol,
  hasSymbols,
  obsoleteSymbol,
  isSymbolActive,
  loadSymbolMap,
  getSymbolPattern,
  getSymbolDbPath,
  symbolNameCandidates,
  uniqueFieldExtension,
  nearestSymbolName,
} from "../../symbol-table/index.js";

function emptyMap(): SymbolMap {
  return { symbols: new Map() };
}

function tmpDb(): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-symtab-"));
  const path = join(dir, "symbols.db");
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// ── format: generate / match ─────────────────────────────────────────────────

test("format generates the canonical $MDU: shape", () => {
  const sym = MDU_SYM_FORMAT.generate({ tool: "web_fetch", hash: "a1b2", field: "text" });
  assert.equal(sym, "$MDU:web_fetch[a1b2].text");
  assert.equal(MDU_SYM_FORMAT.extractHash(sym), "a1b2");
  assert.equal(MDU_SYM_FORMAT.extractFieldPath(sym), "text");
});

test("generate embeds a SHORT tool tag for MCP tool names (keeps names readable)", () => {
  // The raw Claude Code MCP name is `mcp__<server>__<tool>` — only the tool
  // segment lands in the name; `inspect_symbol` further aliases to `inspect`.
  const sym = MDU_SYM_FORMAT.generate({
    tool: "mcp__mandu-inspect__inspect_symbol",
    hash: "ee19",
  });
  assert.equal(sym, "$MDU:inspect[ee19]");
  assert.equal(shortToolTag("mcp__some-server__fetch_page"), "fetch_page");
});

test("generate sanitizes tool chars outside the symbol grammar (egress-detectable)", () => {
  // REGRESSION: a hyphenated MCP server name used to be embedded verbatim,
  // producing names like $MDU:mcp__mandu-inspect__inspect_symbol[ee19]
  // that the symbol pattern can NEVER match — invisible to hasSymbols and
  // resolveAllSymbols, so they were never desymbolized at egress.
  for (const tool of ["mcp__mandu-inspect__inspect_symbol", "weird-tool.v2", "1starts_with_digit"]) {
    const sym = MDU_SYM_FORMAT.generate({ tool, hash: "a1b2", field: "text" });
    const pat = getSymbolPattern();
    pat.lastIndex = 0;
    assert.deepEqual(`pre ${sym} post`.match(pat), [sym], `generated name for ${tool} must match the pattern`);
    assert.equal(hasSymbols(sym), true);
  }
});

test("shortToolTag is idempotent and caps the tag length", () => {
  for (const t of ["Read", "web_fetch", "inspect", "mcp__mandu-inspect__inspect_symbol"]) {
    assert.equal(shortToolTag(shortToolTag(t)), shortToolTag(t));
  }
  const long = "a_very_long_tool_name_that_never_ends_really";
  assert.ok(shortToolTag(long).length <= 24);
});

test("allocateSymbol keeps the FULL tool name as provenance while the NAME uses the short tag", () => {
  const map = emptyMap();
  const sym = allocateSymbol(map, {
    tool: "mcp__mandu-inspect__inspect_symbol",
    value: "quarantined output",
  });
  assert.ok(sym.startsWith("$MDU:inspect["), sym);
  assert.equal(map.symbols.get(sym)?.tool, "mcp__mandu-inspect__inspect_symbol");
  // Round-trip still works — the whole point of the sanitization.
  assert.equal(resolveAllSymbols(`out: ${sym}`, map), "out: quarantined output");
});

test("format pattern matches symbols and ignores plain text", () => {
  const pat = getSymbolPattern();
  pat.lastIndex = 0;
  const text = "before $MDU:exec[deadbeef] after $MDU:web_fetch[a1b2].text.title end";
  const found = text.match(pat) ?? [];
  assert.deepEqual(found, [
    "$MDU:exec[deadbeef]",
    "$MDU:web_fetch[a1b2].text.title",
  ]);
  assert.equal(getActiveFormat(), MDU_SYM_FORMAT);
});

test("hasSymbols is a correct fast pre-check", () => {
  assert.equal(hasSymbols("no symbols here"), false);
  assert.equal(hasSymbols("has $MDU:exec[a1b2]"), true);
  // prefix present but not a valid symbol → false
  assert.equal(hasSymbols("the $MDU: prefix alone"), false);
});

test("unescapeSymbols strips Markdown backslash escapes", () => {
  const escaped = "see \\$MDU:exec[a1b2] now";
  assert.equal(unescapeSymbols(escaped), "see $MDU:exec[a1b2] now");
});

// ── allocate / resolve round-trip (in-memory) ────────────────────────────────

test("symbolize → desymbolize round-trips an untrusted value (in-memory)", () => {
  const map = emptyMap();
  const secret = "attacker-controlled IGNORE PREVIOUS INSTRUCTIONS payload";
  const sym = allocateSymbol(map, { tool: "web_fetch", field: "text", value: secret });

  // The symbol is opaque and does not leak the value.
  assert.ok(sym.startsWith("$MDU:web_fetch["));
  assert.ok(!sym.includes(secret));

  // Resolve by name and by full-text replacement.
  assert.equal(resolveSymbol(map, sym), secret);
  const restored = resolveAllSymbols(`model said: ${sym}`, map);
  assert.equal(restored, `model said: ${secret}`);
});

test("findSymbolsByValue and findSymbolsByCallId locate allocations", () => {
  const map = emptyMap();
  const s1 = allocateSymbol(map, { tool: "web_fetch", value: "dup", callId: "call-1" });
  const s2 = allocateSymbol(map, { tool: "exec", value: "dup", callId: "call-1" });
  allocateSymbol(map, { tool: "exec", value: "other", callId: "call-2" });

  assert.deepEqual(findSymbolsByValue(map, "dup").sort(), [s1, s2].sort());
  assert.equal(findSymbolsByCallId(map, "call-1").length, 2);
  assert.equal(findSymbolsByCallId(map, "call-2").length, 1);
});

test("resolveAllSymbols resolves a derived (split) symbol via parent field path", () => {
  const map = emptyMap();
  const parentVal = "line0\nline1\nline2";
  const parent = allocateSymbol(map, { tool: "policy_file", field: "body", value: parentVal });
  const derived = allocateDerivedSymbol(map, {
    parentSymName: parent,
    value: "line1",
    lineStart: 1,
    lineEnd: 2,
    splitIndex: 0,
  });
  assert.equal(resolveSymbol(map, derived), "line1");
  assert.equal(resolveAllSymbols(`x ${derived} y`, map), "x line1 y");
});

// ── human-edit obsolescence ───────────────────────────────────────────────────

test("obsoleteSymbol marks a symbol inactive", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = emptyMap();
    const sym = allocateSymbol(map, { tool: "Read", value: "old content" }, path);
    assert.equal(isSymbolActive(map, sym), true);
    obsoleteSymbol(map, sym, "human", path);
    assert.equal(isSymbolActive(map, sym), false);
  } finally {
    cleanup();
  }
});

// ── persistence (SQLite-backed, race-safe path) ──────────────────────────────

test("allocateSymbol persists to SQLite and survives a reload", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = emptyMap();
    const secret = "persisted untrusted value";
    const sym = allocateSymbol(map, { tool: "web_fetch", field: "text", value: secret }, path);

    // Fresh load from disk must recover the same mapping.
    const reloaded = loadSymbolMap(path);
    assert.equal(resolveSymbol(reloaded, sym), secret);
  } finally {
    cleanup();
  }
});

test("allocateSymbol stores derivedFrom lineage and survives a reload (symbol-lineage.md G2)", () => {
  const { path, cleanup } = tmpDb();
  try {
    const map = emptyMap();
    const parent = allocateSymbol(map, { tool: "web_fetch", field: "text", value: "raw page" }, path);
    const child = allocateSymbol(
      map,
      { tool: "inspect", field: "result", value: "extracted", origin: parent, derivedFrom: parent, lineRange: "0:3" },
      path,
    );
    assert.equal(map.symbols.get(child)?.derived_from, parent);
    assert.equal(map.symbols.get(child)?.line_range, "0:3");

    const reloaded = loadSymbolMap(path);
    assert.equal(reloaded.symbols.get(child)?.derived_from, parent);
    assert.equal(reloaded.symbols.get(child)?.line_range, "0:3");
  } finally {
    cleanup();
  }
});

test("derivedFrom is NOT part of the reuse key — an identical re-send reuses the first mint", () => {
  const map = emptyMap();
  const parent = "$MDU:web_fetch[0001].text";
  const first = allocateSymbol(map, {
    tool: "inspect", field: "result", value: "same bytes", origin: parent, derivedFrom: parent,
  });
  // The stateless re-send arrives WITHOUT derivedFrom (or with it) — either way
  // the reuse key (tool, field, origin, value, session, call) must hit.
  const reused = findReusableSymbol(map, {
    tool: "inspect", field: "result", value: "same bytes", origin: parent,
  });
  assert.equal(reused, first);
  assert.equal(map.symbols.get(first)?.derived_from, parent, "first mint's lineage is kept");
});

test("unknown symbols are left intact by resolveAllSymbols (no accidental leak)", () => {
  const map = emptyMap();
  const text = "unknown $MDU:exec[ffff] stays as-is";
  assert.equal(resolveAllSymbols(text, map), text);
});

// ── model-mutated tokens (the candidate walk) ─────────────────────────────────
// Models hand back real tokens with glue or mutations the table never minted
// (both seen live 2026-07-16): an INVENTED extra field suffix
// ($MDU:Read[6819].content for the real $MDU:Read[6819]) and a trailing
// sentence dot the scanner grammar swallows ($MDU:…result. ending a sentence).

test("symbolNameCandidates: exact first, then dot-trimmed, then shorter field paths to the base", () => {
  assert.deepEqual(symbolNameCandidates("$MDU:Read[6819]"), ["$MDU:Read[6819]"]);
  assert.deepEqual(symbolNameCandidates("$MDU:Read[6819].content"), [
    "$MDU:Read[6819].content",
    "$MDU:Read[6819]",
  ]);
  assert.deepEqual(symbolNameCandidates("$MDU:inspect[8a52].result."), [
    "$MDU:inspect[8a52].result.",
    "$MDU:inspect[8a52].result",
    "$MDU:inspect[8a52]",
  ]);
  assert.deepEqual(symbolNameCandidates("$MDU:Read[3088].notes.md.extra"), [
    "$MDU:Read[3088].notes.md.extra",
    "$MDU:Read[3088].notes.md",
    "$MDU:Read[3088].notes",
    "$MDU:Read[3088]",
  ]);
  // Not token-shaped: only the exact string is probed.
  assert.deepEqual(symbolNameCandidates("not-a-token"), ["not-a-token"]);
});

test("a mutated token with an invented field suffix resolves like the real name (the opus .content shape)", () => {
  const map = emptyMap();
  const real = allocateSymbol(map, { tool: "Read", value: "poisoned notes", origin: "notes.md" });
  assert.equal(resolveSymbol(map, `${real}.content`), "poisoned notes");
  assert.equal(nearestSymbolName(map, `${real}.content`), real);
  assert.equal(
    resolveAllSymbols(`Here are the contents:\n\n${real}.content`, map),
    "Here are the contents:\n\npoisoned notes",
  );
});

test("an invented suffix on a FIELD-FUL name resolves too (the one-level fallback's blind spot)", () => {
  const map = emptyMap();
  const real = allocateSymbol(map, { tool: "inspect", field: "result", value: "a summary" });
  assert.match(real, /\.result$/);
  assert.equal(resolveSymbol(map, `${real}.text`), "a summary");
});

test("a glued sentence dot resolves and the punctuation survives", () => {
  const map = emptyMap();
  const real = allocateSymbol(map, { tool: "inspect", field: "result", value: "a summary" });
  assert.equal(
    resolveAllSymbols(`The file says: ${real}.`, map),
    "The file says: a summary.",
  );
  // Invented suffix AND sentence dot: the fiction drops, the period stays.
  assert.equal(
    resolveAllSymbols(`It is ${real}.text.`, map),
    "It is a summary.",
  );
});

test("mutation lookups never invent matches: a token with an unknown base stays literal", () => {
  const map = emptyMap();
  allocateSymbol(map, { tool: "Read", value: "x" });
  const ghost = "$MDU:Read[ffff].content";
  assert.equal(resolveSymbol(map, ghost), null);
  assert.equal(nearestSymbolName(map, ghost), null);
  assert.equal(resolveAllSymbols(`keep ${ghost} verbatim`, map), `keep ${ghost} verbatim`);
});

// ── the ALIAS TIER (uniqueFieldExtension): the base↔field SSE seam ───────────
// Models stream a token's base and its `.field` tail in separate deltas; a TUI
// frame interposed between them strands the BARE BASE ($MDU:inspect[c72f]) —
// a name the table never minted, which the shortening walk cannot recover.
// Third live hit 2026-07-19 (pipeline 6420 interactive-inspect-extract): the
// human terminal showed the raw token for the whole session.

test("a stranded bare base resolves to its ONE allocated field extension (the SSE-seam shape)", () => {
  const map = emptyMap();
  const real = allocateSymbol(map, { tool: "inspect", field: "result", value: "SA-2026-0777" });
  const base = real.replace(/\.result$/, "");
  assert.notEqual(base, real, "the allocated name carries the .result field");
  assert.equal(resolveSymbol(map, base), "SA-2026-0777");
  assert.equal(nearestSymbolName(map, base), real, "the alias reports the REAL allocated name");
  assert.equal(
    resolveAllSymbols(`advisory:${base}`, map),
    "advisory:SA-2026-0777",
    "the text scanner resolves the stranded base too (the reply-filter's server-side path)",
  );
});

test("sibling extensions refuse the alias: never guess between different values", () => {
  const map = emptyMap();
  const entry = (value: string, field: string): SymbolEntry => ({
    value, tool: "Bash", field, origin: null, session_key: null,
    call_id: null, created_at: Date.now(), obsoleted_at: null,
    obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "public", bindings: null, integrity: "untrusted",
  });
  map.symbols.set("$MDU:Bash[ab12].stdout", entry("out", "stdout"));
  map.symbols.set("$MDU:Bash[ab12].stderr", entry("err", "stderr"));
  assert.equal(resolveSymbol(map, "$MDU:Bash[ab12]"), null);
  assert.equal(resolveAllSymbols("x $MDU:Bash[ab12] y", map), "x $MDU:Bash[ab12] y");
});

test("a split family aliases to its common ancestor (the .__mdu_split shape)", () => {
  const map = emptyMap();
  const real = allocateSymbol(map, { tool: "inspect", field: "result", value: "line1\nline2" });
  allocateDerivedSymbol(map, {
    parentSymName: real, value: "line1\n", lineStart: 0, lineEnd: 1, splitIndex: 0,
  });
  const base = real.replace(/\.result$/, "");
  assert.equal(
    resolveSymbol(map, base),
    "line1\nline2",
    "the ancestor (.result) wins — its value is what the full token resolves to",
  );
});

test("an allocated base always wins over the alias tier (specificity)", () => {
  const map = emptyMap();
  const entry = (value: string, field: string | null): SymbolEntry => ({
    value, tool: "Read", field, origin: null, session_key: null,
    call_id: null, created_at: Date.now(), obsoleted_at: null,
    obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "public", bindings: null, integrity: "untrusted",
  });
  map.symbols.set("$MDU:Read[3088]", entry("base value", null));
  map.symbols.set("$MDU:Read[3088].notes", entry("field value", "notes"));
  assert.equal(resolveSymbol(map, "$MDU:Read[3088]"), "base value");
});

test("uniqueFieldExtension grammar bounds: mid-segment prefixes and fragments never alias", () => {
  const names = ["$MDU:inspect[c72f].result"];
  // Mid-segment prefix: the boundary check refuses (.res is not a field cut).
  assert.equal(uniqueFieldExtension("$MDU:inspect[c72f].res", names), null);
  // Mid-hash fragment: not grammar-complete.
  assert.equal(uniqueFieldExtension("$MDU:inspect[c7", names), null);
  // Prose is not a token.
  assert.equal(uniqueFieldExtension("not-a-token", names), null);
  // The seam shape itself, with a glued sentence dot trimmed.
  assert.equal(uniqueFieldExtension("$MDU:inspect[c72f].", names), "$MDU:inspect[c72f].result");
  assert.equal(uniqueFieldExtension("$MDU:inspect[c72f]", names), "$MDU:inspect[c72f].result");
});

test("the exact name always wins over a stripped candidate (specificity order)", () => {
  const map = emptyMap();
  const entry = (value: string): SymbolEntry => ({
    value, tool: "Read", field: null, origin: null, session_key: null,
    call_id: null, created_at: Date.now(), obsoleted_at: null,
    obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "public", bindings: null, integrity: "untrusted",
  });
  map.symbols.set("$MDU:Read[3088]", entry("base value"));
  map.symbols.set("$MDU:Read[3088].notes.md", entry("field value"));
  assert.equal(resolveSymbol(map, "$MDU:Read[3088].notes.md"), "field value");
  assert.equal(resolveSymbol(map, "$MDU:Read[3088].notes.md.x"), "field value");
  assert.equal(resolveSymbol(map, "$MDU:Read[3088].other"), "base value");
});

// ── deep (fixpoint) resolution — NESTED symbolization ────────────────────────
// Nesting is real in Mandu: the fs-sync AgentView twin of an untrusted file
// is ALREADY a `$MDU:Read[..].<file>` on disk; when the agent Reads it,
// the proxy re-symbolizes the tool_result — a symbol whose value is a symbol.
// Full-fidelity surfaces (HumanView writes, the quarantined U-LLM) must peel
// the whole chain; the gated egress paths keep the single-pass primitive.

/** Hand-build a SymbolEntry (for cases allocateSymbol can't construct, e.g.
 *  cycles — a name isn't known before its own allocation). */
function entryOf(value: string): SymbolEntry {
  return {
    value, tool: "exec", field: null, origin: null, session_key: null,
    call_id: null, created_at: Date.now(), obsoleted_at: null,
    obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "public", bindings: null, integrity: "untrusted",
  };
}

test("resolveAllSymbolsDeep collapses the fs-sync twin double-symbolization to raw", () => {
  const map = emptyMap();
  const rawNotes = "# Project notes\n\nTODO: ship the proxy.\nINJECTION LINE\nMore notes.";
  // Level 1: the on-disk AgentView twin symbol (field-path tail `.notes.md`,
  // exactly the twin spelling fs-sync writes).
  const inner = allocateSymbol(map, { tool: "Read", field: "notes.md", value: rawNotes });
  assert.match(inner, /^\$MDU:Read\[[0-9a-f]{4,8}\]\.notes\.md$/);
  // Level 2: the proxy re-symbolizes the Read tool_result of the twin (the
  // cat -n-style body the agent actually read).
  const outer = allocateSymbol(map, { tool: "Read", value: `1\t${inner}\n2\t` });

  // Single-pass resolution peels ONE layer — the inner symbol survives.
  assert.ok(resolveAllSymbols(outer, map).includes(inner));
  // Deep resolution reaches the raw original; no symbol survives.
  const deep = resolveAllSymbolsDeep(outer, map);
  assert.ok(deep.includes(rawNotes), deep);
  assert.equal(hasSymbols(deep), false);
});

test("resolveAllSymbolsDeep leaves UNKNOWN nested symbols literal (fail-closed) and terminates", () => {
  const map = emptyMap();
  const outer = allocateSymbol(map, { tool: "Read", value: "sees $MDU:exec[ffff] inside" });
  const deep = resolveAllSymbolsDeep(`x ${outer} y`, map);
  assert.equal(deep, "x sees $MDU:exec[ffff] inside y");
});

test("resolveAllSymbolsDeep terminates on a symbol cycle (depth cap, no throw)", () => {
  const map = emptyMap();
  const a = "$MDU:exec[aaaa]";
  const b = "$MDU:exec[bbbb]";
  map.symbols.set(a, entryOf(`a sees ${b}`));
  map.symbols.set(b, entryOf(`b sees ${a}`));
  const out = resolveAllSymbolsDeep(`start ${a}`, map);
  // A cycle can never fully resolve — it must terminate with a symbol left
  // opaque rather than loop or throw.
  assert.ok(hasSymbols(out));
  assert.ok(out.startsWith("start a sees b sees"));
});

test("resolveAllSymbolsDeep honors an explicit maxDepth", () => {
  const map = emptyMap();
  const s1 = allocateSymbol(map, { tool: "exec", value: "RAW" });
  const s2 = allocateSymbol(map, { tool: "exec", value: `wraps ${s1}` });
  const s3 = allocateSymbol(map, { tool: "exec", value: `wraps ${s2}` });
  // 3-deep chain: depth 2 stops one short, depth 3 reaches the raw value.
  assert.ok(hasSymbols(resolveAllSymbolsDeep(s3, map, 2)));
  assert.equal(resolveAllSymbolsDeep(s3, map, 3), "wraps wraps RAW");
});

test("getSymbolDbPath is the path table's symbol-db: ${MANDU_HOME:-~/.mandu}/state/mandu.db; the retired MANDU_SYMBOL_DB moves nothing", () => {
  assert.equal(getSymbolDbPath({ MANDU_SYMBOL_DB: "/pinned/x.db" }, "/home/u"), "/home/u/.mandu/state/mandu.db");
  assert.equal(getSymbolDbPath({ MANDU_SYMBOL_DB: "/pinned/x.db", MANDU_HOME: "/mh" }, "/home/u"), "/mh/state/mandu.db");
  assert.equal(getSymbolDbPath({}, "/home/u"), "/home/u/.mandu/state/mandu.db");
  assert.equal(getSymbolDbPath({}, "/home/u/"), "/home/u/.mandu/state/mandu.db");
  assert.equal(getSymbolDbPath({ MANDU_HOME: "/mh" }, "/home/u"), "/mh/state/mandu.db");
  // An empty MANDU_HOME counts as unset.
  assert.equal(getSymbolDbPath({ MANDU_HOME: "" }, "/home/u"), "/home/u/.mandu/state/mandu.db");
});
