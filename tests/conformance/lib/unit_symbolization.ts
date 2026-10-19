/**
 * unit_symbolization — topic unit suite for the Mandu symbolization primitives.
 *
 * Mirrors the breadth of adfi-openclaw/test/unit/unit_injection.ts (+
 * unit_policy.ts): bold-cyan section headers + many small `test(...)` cases over
 * the PRIMITIVES, here driven against a REAL booted arbiter over its IPC socket
 * (the symbol table + data-trust classify) rather than the in-process plugin.
 *
 * Run: tsx lib/unit_symbolization.ts
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { test, header, summary, printTapFooter } from "./harness.js";
import { evaluateFieldMatcher } from "./assertions.js";

const SYMBOL_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/;

async function main(): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-conf-unitsym-"));
  const socketPath = join(tmp, "arbiter.sock");
  // The human plane (arbiter-human-plane.md): resolve/desymbolize return
  // originals and are served only on this socket.
  const humanSocketPath = join(tmp, "human", "h.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    humanSocketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"),
    // The conformance corpus is the paper's defense: integrity ON, confidentiality
    // OFF, STATED (protection-modes.md §4), never the built-in default.
    integrity: true,
    confidentiality: false,
    log: () => {},
  });
  await arbiter.listen();
  const c = new ArbiterClient(socketPath);
  await c.connect();
  const h = new ArbiterClient(humanSocketPath);
  await h.connect();

  // Pre-mint a few symbols the synchronous tests assert over.
  const readSym = await c.symbolize({ tool: "Read", value: "SECRET file body", origin: "/x/notes.md" });
  const readSymAgain = await c.symbolize({ tool: "Read", value: "SECRET file body", origin: "/x/notes.md" });
  const readSymAgainResolved = await h.resolve(readSymAgain);
  const bashSym = await c.symbolize({ tool: "Bash", value: "stdout blob", origin: "ls" });
  const readResolved = await h.resolve(readSym);
  const unknownResolved = await h.resolve("$MDU:Read[dead]");
  const desym = await h.desymbolize(`prefix ${readSym} suffix`);
  // …and the data socket refuses exactly those reads.
  const dataDesymRefused = await c.desymbolize(`prefix ${readSym} suffix`).then(() => false, (e: Error) => /human-plane/.test(e.message));
  const dataResolveRefused = await c.resolve(readSym).then(() => false, (e: Error) => /human-plane/.test(e.message));

  // The classify verdicts (per the Claude Code data-trust spec).
  const bashV = await c.classify({ tool: "Bash", value: "x", boundary: "model_context", origin: "ls", params: { command: "ls" } });
  const writeV = await c.classify({ tool: "Write", value: "x", boundary: "model_context", params: { file_path: "/a" } });
  const webStatusV = await c.classify({
    tool: "WebFetch", field: "status", value: "200", boundary: "model_context",
    origin: "https://evil.example/x", params: { url: "https://evil.example/x" },
  });
  const webContentV = await c.classify({
    tool: "WebFetch", field: "content", value: "body", boundary: "model_context",
    origin: "https://evil.example/x", params: { url: "https://evil.example/x" },
  });
  const unknownToolV = await c.classify({ tool: "DefinitelyNotARealTool", value: "x", boundary: "model_context" });

  // ── FieldMatcher (adfi DSL parity) ──────────────────────────────────────
  header("FieldMatcher (adfi-parity matcher primitives)");

  test("equals: exact match passes, mismatch fails", () => {
    assert.equal(evaluateFieldMatcher("200", { equals: "200" })[0], true);
    assert.equal(evaluateFieldMatcher("200", { equals: "404" })[0], false);
  });
  test("contains / not_contains", () => {
    assert.equal(evaluateFieldMatcher("hello world", { contains: "world" })[0], true);
    assert.equal(evaluateFieldMatcher("hello world", { not_contains: "evil" })[0], true);
    assert.equal(evaluateFieldMatcher("hello evil", { not_contains: "evil" })[0], false);
  });
  test("matches (regex) + min_length", () => {
    assert.equal(evaluateFieldMatcher("abc123", { matches: "^[a-z]+\\d+$" })[0], true);
    assert.equal(evaluateFieldMatcher("short", { min_length: 10 })[0], false);
    assert.equal(evaluateFieldMatcher("long enough string", { min_length: 10 })[0], true);
  });
  test("bare value shorthand → equals", () => {
    assert.equal(evaluateFieldMatcher("200", "200")[0], true);
    assert.equal(evaluateFieldMatcher(200, 200)[0], true);
  });

  // ── symbolize → resolve round-trip (the arbiter is the symbol authority) ──
  header("symbolize → resolve (arbiter symbol-table round-trip)");

  test("symbolize mints a well-formed $MDU:<tool>[hash] token", () => {
    assert.match(readSym, SYMBOL_RE);
    assert.ok(readSym.includes("Read"), "symbol carries the originating tool name");
  });
  test("distinct tools / values mint distinct symbols", () => {
    assert.notEqual(readSym, bashSym);
  });
  test("resolve returns the EXACT original bytes", () => {
    assert.equal(readResolved, "SECRET file body");
  });
  test("resolve of an unknown symbol returns null (nothing to leak)", () => {
    assert.equal(unknownResolved, null);
  });
  test("desymbolize substitutes a symbol embedded in surrounding text", () => {
    assert.equal(desym, "prefix SECRET file body suffix");
  });
  test("the data socket refuses desymbolize and the shallow resolve (human plane only)", () => {
    assert.equal(dataDesymRefused, true);
    assert.equal(dataResolveRefused, true);
  });
  test("re-symbolizing the same bytes both resolve back to the original", () => {
    // The arbiter allocates a fresh per-call symbol; the SECURITY-load-bearing
    // property is that every minted symbol round-trips to the exact original.
    assert.equal(readSymAgainResolved, "SECRET file body");
  });

  // ── data-trust classify (the ingress symbolization decision) ─────────────
  header("classify (data-trust policy: what gets symbolized)");

  test("Bash stdout is UNTRUSTED (attacker-reachable) → symbolize", () => {
    assert.equal(bashV.trust, "UNTRUSTED");
  });
  test("Write result is TRUSTED (agent-authored) → passthrough", () => {
    assert.equal(writeV.trust, "TRUSTED");
  });
  test("WebFetch.status metadata is TRUSTED (no over-symbolization)", () => {
    assert.equal(webStatusV.trust, "TRUSTED");
  });
  test("WebFetch.content from a non-allowlisted URL is UNTRUSTED → symbolize", () => {
    assert.equal(webContentV.trust, "UNTRUSTED");
  });
  test("an unknown tool is fail-closed UNTRUSTED (over-symbolize when unsure)", () => {
    assert.equal(unknownToolV.trust, "UNTRUSTED");
  });

  c.close();
  h.close();
  await arbiter.close();
  rmSync(tmp, { recursive: true, force: true });

  const { passed, failed } = summary();
  console.log(`\n  ${failed === 0 ? "\x1b[32m" : "\x1b[31m"}${passed} passed, ${failed} failed\x1b[0m\n`);
  printTapFooter(passed, failed);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
