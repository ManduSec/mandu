/**
 * named-twins — the twin each secret file a shell command names would give a
 * read of it on its own (confidentiality.md §7.1, "the path-derived note",
 * 2026-10-19): the shell glob reader, the token's files, and the answer per
 * twin kind, with the cases that must get NO answer (a mixed glob, a secret
 * file with no twin, a token with no known place).
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { NAMED_TWIN_LIMITS, globSegmentMatches, namedFiles, namedTwinsFor, type NamedTwinFs, type NamedTwinKind } from "../../policy/named-twins.js";

/** An in-memory tree: every path a file, its parents directories. */
function memFs(files: readonly string[]): NamedTwinFs {
  const dirs = new Map<string, Set<string>>();
  for (const f of files) {
    const parts = f.split("/").filter(Boolean);
    for (let i = 0; i < parts.length; i++) {
      const dir = `/${parts.slice(0, i).join("/")}`;
      if (!dirs.has(dir)) dirs.set(dir, new Set());
      dirs.get(dir)!.add(parts[i]!);
    }
  }
  const set = new Set(files);
  return {
    kind: (p) => (set.has(p) ? "file" : dirs.has(p) ? "dir" : null),
    list: (d) => (dirs.has(d) ? [...dirs.get(d)!] : null),
  };
}

const WS = "/home/u/papers";
const TAX = `${WS}/taxes/2025/return-summary.txt`;
const NOTES = `${WS}/taxes/2025/notes.txt`;
const ENV = `${WS}/.env`;
const DIARY = `${WS}/private/diary.txt`;
const SSH = "/home/u/.ssh/config";
const UNREG = `${WS}/vault/key.txt`;
const FILES = [TAX, NOTES, ENV, DIARY, SSH, UNREG, `${WS}/taxes/2024/return-summary.txt`, `${WS}/mixed/a.env`, `${WS}/mixed/b.txt`];
const KINDS: Record<string, NamedTwinKind | null> = {
  [TAX]: "lines", [`${WS}/taxes/2024/return-summary.txt`]: "lines",
  [ENV]: "fields", [DIARY]: "whole", [SSH]: "text", [UNREG]: null,
  [`${WS}/mixed/a.env`]: "fields", [`${WS}/mixed/b.txt`]: "whole",
};
const opts = (over: Partial<Parameters<typeof namedTwinsFor>[1]> = {}): Parameters<typeof namedTwinsFor>[1] => ({
  base: WS,
  home: "/home/u",
  fs: memFs(FILES),
  isSecretFile: (p) => p in KINDS,
  twinKindOf: (p) => KINDS[p] ?? null,
  ...over,
});

test("the glob reader takes the shell's segment syntax: * ? [set] [!set], a leading dot only by a dot", () => {
  const yes: Array<[string, string]> = [
    ["*", "return-summary.txt"], ["*.txt", "notes.txt"], ["re?urn*", "return-summary.txt"], ["[a-c]*", "b.txt"],
    ["[!a]*", "b.txt"], ["[^a]*", "b.txt"], ["*.[et]*", "a.env"], [".*", ".env"], [".e*", ".env"], ["**", "x"], ["a*b*c", "aXbYc"],
  ];
  const no: Array<[string, string]> = [
    ["*", ".env"], ["?env", ".env"], ["*.md", "notes.txt"], ["[a-c]*", "d.txt"], ["[!b]*", "b.txt"], ["a?", "a"], ["a*b*c", "aXbY"],
  ];
  for (const [p, n] of yes) assert.equal(globSegmentMatches(p, n), true, `${p} ~ ${n}`);
  for (const [p, n] of no) assert.equal(globSegmentMatches(p, n), false, `${p} !~ ${n}`);
  assert.equal(globSegmentMatches("[abc", "a"), null, "an unterminated set is not read");
  assert.equal(globSegmentMatches("a\\*", "a*"), null, "an escape is not read");
});

test("a token's files: a plain file, a glob's matches in order, ~/, and none for a directory, a missing path or no place", () => {
  const fs = memFs(FILES);
  assert.deepEqual(namedFiles("taxes/2025/return-summary.txt", WS, "/home/u", fs), [TAX]);
  assert.deepEqual(namedFiles("taxes/2025/*", WS, "/home/u", fs), [NOTES, TAX]);
  assert.deepEqual(namedFiles("taxes/*/return-summary.txt", WS, "/home/u", fs), [`${WS}/taxes/2024/return-summary.txt`, TAX]);
  assert.deepEqual(namedFiles(`${WS}/.env`, undefined, undefined, fs), [ENV]);
  assert.deepEqual(namedFiles("~/.ssh/config", WS, "/home/u", fs), [SSH]);
  assert.deepEqual(namedFiles("./taxes/../.env", WS, "/home/u", fs), [ENV]);
  assert.equal(namedFiles("taxes/", WS, "/home/u", fs), null, "a directory names no file");
  assert.equal(namedFiles("taxes/2026/*", WS, "/home/u", fs), null);
  assert.equal(namedFiles("taxes/2025/*", undefined, "/home/u", fs), null, "a relative token with no base has no place");
  assert.equal(namedFiles("~/.ssh/config", WS, undefined, fs), null);
  assert.equal(namedFiles("~bob/.ssh/config", WS, "/home/u", fs), null);
  assert.equal(namedFiles("taxes/{2024,2025}/*", WS, "/home/u", fs), null, "a brace is not expanded");
  assert.equal(namedFiles("$HOME/.ssh/config", WS, "/home/u", fs), null, "an expansion is not read");
  assert.equal(namedFiles("'taxes/2025/notes.txt'", WS, "/home/u", fs), null, "a quoted token is not read");
});

test("each named token gets the twin kind its secret files share: lines, fields, whole, text", () => {
  const got = namedTwinsFor(["taxes/2025/*", ".env", "private/diary.txt", "~/.ssh/config"], opts());
  assert.deepEqual(got, [
    { path: "taxes/2025/*", twin: "lines" },
    { path: ".env", twin: "fields" },
    { path: "private/diary.txt", twin: "whole" },
    { path: "~/.ssh/config", twin: "text" },
  ]);
});

test("no answer where the claim would not hold: a mixed glob, a secret file with no twin, no secret file, no place, past the token bound", () => {
  assert.deepEqual(namedTwinsFor(["mixed/*"], opts()), [], "two kinds under one token");
  assert.deepEqual(namedTwinsFor(["vault/key.txt"], opts()), [], "a secret file Mandu serves no twin of");
  assert.deepEqual(namedTwinsFor(["taxes/2025/notes.txt"], opts()), [], "a file that is not secret");
  assert.deepEqual(namedTwinsFor(["taxes/2025/*"], opts({ base: undefined })), [], "a relative token read nowhere");
  assert.deepEqual(namedTwinsFor(undefined, opts()), []);
  assert.deepEqual(namedTwinsFor([".env", ".env"], opts()), [{ path: ".env", twin: "fields" }], "a token once");
  const many = [...Array.from({ length: NAMED_TWIN_LIMITS.tokens }, (_, i) => `nothing-${i}`), ".env"];
  assert.deepEqual(namedTwinsFor(many, opts()), [], "tokens past the bound are not looked at");
  // the non-secret files a glob also matches do not count against it
  assert.deepEqual(namedTwinsFor(["taxes/2025/*.txt"], opts()), [{ path: "taxes/2025/*.txt", twin: "lines" }]);
});

test("a glob over a directory past the entry bound gets no answer", () => {
  const big = Array.from({ length: NAMED_TWIN_LIMITS.dirEntries + 1 }, (_, i) => `${WS}/big/f${i}.txt`);
  const fs = memFs([...big, TAX]);
  assert.equal(namedFiles("big/*", WS, "/home/u", fs), null);
  assert.deepEqual(namedTwinsFor(["big/*"], opts({ fs, isSecretFile: () => true, twinKindOf: () => "whole" })), []);
});

test("the real file system: a glob follows a link to a file, as the shell's cat does", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-named-twins-"));
  try {
    mkdirSync(join(dir, "taxes", "2025"), { recursive: true });
    writeFileSync(join(dir, "taxes", "2025", "return-summary.txt"), "x\n");
    symlinkSync(join(dir, "taxes", "2025", "return-summary.txt"), join(dir, "taxes", "2025", "latest.txt"));
    const fs: NamedTwinFs = {
      kind: (p) => { try { const s = statSync(p); return s.isFile() ? "file" : s.isDirectory() ? "dir" : null; } catch { return null; } },
      list: (d) => { try { return readdirSync(d); } catch { return null; } },
    };
    assert.deepEqual(namedFiles("taxes/2025/*", dir, undefined, fs), [join(dir, "taxes", "2025", "latest.txt"), join(dir, "taxes", "2025", "return-summary.txt")]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
