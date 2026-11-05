/**
 * locked-object-note-text.test.ts — the `[mandu:locked]` note's words
 * (confidentiality.md §7.1, "git's report on a history rewrite"): what it
 * names (object ids, plain paths; at most eight) and the advice it gives,
 * each claim pinned on real git by the stack test git-locked-object-report.
 * Each proxy's own wiring is pinned in its `locked-object-note.test.ts`.
 *
 * One suite, two copies (both model proxies); the source is
 * interceptors/anthropic-proxy/test/unit/locked-object-note-text.test.ts.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { LOCKED_NOTE_MARKER, lockedObjectNote, protectedCopyNote } from "../../src/locked-object-note.js";

const LOCKED = "7c72b0c959f112730dc47da675a590979839a25e";

test("lockedObjectNote names the ids, at most eight, and nothing that is not an object id", () => {
  const note = lockedObjectNote([LOCKED])!;
  assert.ok(note.startsWith(`${LOCKED_NOTE_MARKER} git could not read 7c72b0c959f1: Mandu keeps the stored versions of protected secret files unreadable in this session, and this object is one.`), note);
  assert.ok(!note.includes(LOCKED), "only the 12-digit form");
  assert.match(lockedObjectNote([LOCKED, "a".repeat(64)])!, /these objects are such versions/);
  assert.equal(lockedObjectNote([]), null);
  assert.equal(lockedObjectNote(["not-an-id", "sk_live_x", LOCKED.slice(0, 39), LOCKED.toUpperCase()]), null, "only full lowercase object ids are named");
  const many = Array.from({ length: 12 }, (_, i) => i.toString(16).padStart(40, "a"));
  assert.equal((lockedObjectNote(many)!.match(/[0-9a-f]{12}/g) ?? []).length, 8);
  assert.equal(lockedObjectNote([LOCKED, LOCKED]), note, "an id named twice is named once");
});

// live 2026-10-27 (demo-git-history-scrub on Codex): one filter-repo pass with
// --replace-text and --invert-paths failed on the locked version; the model
// took the repository for broken, tried chmod and mv on the object, and then
// replaced the history with one new root commit, dropping every commit.
test("lockedObjectNote: the repository is not damaged and is not to be re-created or flattened", () => {
  const note = lockedObjectNote([LOCKED])!;
  assert.match(note, /The repository is not damaged: do not chmod or move the object, re-clone or re-create the repository, or replace its history with a new root commit \(that drops every commit\)\./);
});

test("lockedObjectNote: filter-repo in two passes, --invert-paths first and --replace-text after; filter-branch's index filter", () => {
  const note = lockedObjectNote([LOCKED])!;
  assert.match(note, /run two passes: first --path <file> --invert-paths alone \(it reads no file content\), then --replace-text on what is left; one pass with both reads every version and fails\./);
  assert.match(note, /git filter-branch --index-filter 'git rm -q --cached --ignore-unmatch <file>' also works/);
});

// live 2026-10-26 (demo-git-history-scrub, OpenClaw): told only to remove the
// versions, the model removed checkout.js from every commit and its rewrite
// dropped the commits that only changed it.
test("lockedObjectNote: a clean blob in place of a locked one keeps the file", () => {
  const note = lockedObjectNote([LOCKED])!;
  assert.match(note, /git update-index --cacheinfo 100644,<clean blob id>,<path> where git ls-files -s <path> shows the locked id/);
});

test("lockedObjectNote: check with log --name-status or log -- <path>, never --stat (it reads the version)", () => {
  const note = lockedObjectNote([LOCKED])!;
  assert.match(note, /git show, log -p, log --stat and a tree filter fail on a locked version, so check a rewrite with git log --all --name-status or git log --all -- <path>\.$/);
  assert.ok(!/check[^.]*with[^.]*--stat/.test(note), "--stat is never the advice");
});

test("protectedCopyNote: the paths as shown and static text; index-filter, not a tree filter, reset or checkout over it", () => {
  const note = protectedCopyNote([".env"])!;
  assert.ok(note.startsWith(`${LOCKED_NOTE_MARKER} git could not remove '.env': when that is a protected secret file, Mandu keeps it in your working tree as a read-only copy`), note);
  assert.match(note, /the repository is not damaged and needs no re-creating/);
  assert.match(note, /--index-filter 'git rm -q --cached --ignore-unmatch <path>' \(not --tree-filter\)/);
  assert.match(note, /do not git reset --hard, git checkout or git rm \(without --cached\) over that path/);
  assert.equal(protectedCopyNote([]), null);
  assert.equal(protectedCopyNote(["a'b", "x\ny", "", "p".repeat(257)]), null, "nothing that is not a plain path");
  assert.equal((protectedCopyNote(Array.from({ length: 12 }, (_, i) => `f${i}`))!.match(/'f\d+'/g) ?? []).length, 8);
});

test("both notes stay short", () => {
  assert.ok(lockedObjectNote([LOCKED])!.length < 1400, `${lockedObjectNote([LOCKED])!.length} characters`);
  assert.ok(protectedCopyNote([".env"])!.length < 700);
});
