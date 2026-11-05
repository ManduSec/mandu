/**
 * twin-write-note.test.ts — the `copy:` line's pieces (plan 10 §4.1, "The
 * model is told at the call", 2026-10-27): which of the arbiter's
 * `twinWrites` the line may name (only the call's own tokens, verbatim), and
 * its words, singular and plural. Each proxy's own wiring is pinned in its
 * `twin-write-copy-line.test.ts`.
 *
 * One suite, two copies (both model proxies); the source is
 * interceptors/anthropic-proxy/test/unit/twin-write-note.test.ts.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { twinWriteLine, twinWriteTokens } from "../../src/twin-write-note.js";

const HEREDOC = "cat > orders-app/.env << 'EOF'\nORDERHUB_PASSWORD='$MDU:nomodel_Read[a169].ORDERHUB_PASSPHRASE'\nEOF\n";

test("twinWriteTokens: only tokens a top-level string of the call's own input holds verbatim, at most 3, one short line each", () => {
  assert.deepEqual(twinWriteTokens(["orders-app/.env"], { command: HEREDOC, description: "Write the corrected .env file" }), ["orders-app/.env"]);
  assert.deepEqual(twinWriteTokens(["/w/orders-app/.env"], { file_path: "/w/orders-app/.env", old_string: "a", new_string: "b" }), ["/w/orders-app/.env"]);
  // a spelling the model never wrote (a resolved path) is dropped
  assert.deepEqual(twinWriteTokens(["/home/u/w/orders-app/.env"], { command: HEREDOC }), []);
  // nested values are not the call's own top-level fields
  assert.deepEqual(twinWriteTokens([".env"], { edits: [{ file_path: ".env" }] }), []);
  assert.deepEqual(twinWriteTokens(["a", "b", "c", "d", "a"], { cmd: "tee a b c d" }), ["a", "b", "c"]);
  assert.deepEqual(twinWriteTokens(["a\nb", "", "x".repeat(201), 7, null], { command: `cat > a\nb ${"x".repeat(201)}` }), []);
  assert.deepEqual(twinWriteTokens(undefined, { command: HEREDOC }), []);
  assert.deepEqual(twinWriteTokens("orders-app/.env", { command: HEREDOC }), []);
  assert.deepEqual(twinWriteTokens(["orders-app/.env"], null), []);
});

test("twinWriteLine: says the change stays in the copy, the real file is unchanged, not to claim it is fixed, and the way out; plural form", () => {
  const one = twinWriteLine(["orders-app/.env"]);
  assert.ok(one.startsWith("copy: orders-app/.env is a protected file: you and the programs you run see and change only its placeholder copy, never the user's real file."), one);
  for (const piece of [
    "A change written into it stays in that copy",
    "replacing the file (sed -i, mv onto it, a file tool's or an editor's save) is refused",
    "a run here may work after the change, but the copy never reaches the user's real file",
    "the user's real orders-app/.env is unchanged",
    "Do not tell the user it is fixed or saved.",
    "Make the change where it is not secret instead (for example in the code or script that reads the file)",
    "or tell the user exactly what to change in orders-app/.env themselves.",
  ]) assert.ok(one.includes(piece), `missing: ${piece}\n${one}`);
  assert.ok(!/\$MDU/.test(one), "no placeholder in the line");
  const two = twinWriteLine([".env", "conf/.env"]);
  assert.ok(two.startsWith("copy: .env, conf/.env are protected files: you and the programs you run see and change only their placeholder copies"), two);
  assert.ok(two.includes("the user's real .env, conf/.env are unchanged") && two.includes("Do not tell the user it is fixed or saved."), two);
});
