/**
 * apply-patch — the port of OpenClaw's apply_patch parser that finds a
 * patch's target paths (src/apply-patch.ts; arbiter tool-gate-surface.ts
 * PatchToolFields). The proxy gates exactly the headers this returns, so it
 * must read the same headers OpenClaw applies, and reject (so the proxy
 * refuses) every patch OpenClaw's parser throws on.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { parseApplyPatch, patchWrites, rewritePatchPaths, type PatchPath } from "../../src/apply-patch.js";

const paths = (input: string): Array<[PatchPath["kind"], string]> => {
  const r = parseApplyPatch(input);
  assert.ok(r.ok, `parses: ${r.ok ? "" : r.error}`);
  return r.paths.map((p) => [p.kind, p.path]);
};
const error = (input: unknown): string => {
  const r = parseApplyPatch(input);
  assert.equal(r.ok, false, `rejects: ${JSON.stringify(input)}`);
  return r.ok ? "" : r.error;
};

test("add, delete, update and move headers each name their path", () => {
  assert.deepEqual(paths("*** Begin Patch\n*** Add File: notes/new.md\n+hello\n+world\n*** End Patch"), [["add", "notes/new.md"]]);
  assert.deepEqual(paths("*** Begin Patch\n*** Delete File: /home/u/.ssh/id_rsa\n*** End Patch"), [["delete", "/home/u/.ssh/id_rsa"]]);
  assert.deepEqual(paths("*** Begin Patch\n*** Update File: src/a.ts\n@@\n-old\n+new\n*** End Patch"), [["update", "src/a.ts"]]);
  assert.deepEqual(
    paths("*** Begin Patch\n*** Update File: src/a.ts\n*** Move to: /home/u/.aws/credentials\n@@ fn\n-old\n+new\n*** End Patch"),
    [["update", "src/a.ts"], ["move", "/home/u/.aws/credentials"]],
  );
});

test("several files in one patch, in order, with their original line numbers", () => {
  const input = [
    "*** Begin Patch",
    "*** Add File: a.txt",
    "+one",
    "*** Update File: b.txt",
    "@@",
    " keep",
    "-drop",
    "+add",
    "",
    "@@ second",
    "+more",
    "*** End of File",
    "*** Delete File: c.txt",
    "*** Update File: d.txt",
    "*** Move to: e.txt",
    "+x",
    "*** End Patch",
  ].join("\n");
  const r = parseApplyPatch(input);
  assert.ok(r.ok);
  assert.deepEqual(r.paths.map((p) => [p.kind, p.path, p.line]), [
    ["add", "a.txt", 1],
    ["update", "b.txt", 3],
    ["delete", "c.txt", 12],
    ["update", "d.txt", 13],
    ["move", "e.txt", 14],
  ]);
  assert.deepEqual(r.paths.map((p) => patchWrites(p.kind)), [true, true, false, true, true], "a delete writes nothing");
});

test("a content line that LOOKS like a header is content, as OpenClaw reads it: only real headers are paths", () => {
  // `+*** Delete File: …` is an added line; ` *** Update File: …` a context line
  const input = "*** Begin Patch\n*** Add File: doc.md\n+*** Delete File: /etc/passwd\n*** Update File: guide.md\n@@\n *** Update File: /etc/shadow\n+ok\n*** End Patch";
  assert.deepEqual(paths(input), [["add", "doc.md"], ["update", "guide.md"]]);
});

test("OpenClaw's leniency is mirrored: surrounding whitespace, CRLF, indented headers, the <<EOF heredoc wrapper", () => {
  assert.deepEqual(paths("\n\n  *** Begin Patch\r\n   *** Delete File: x.txt  \r\n*** End Patch\n\n"), [["delete", "x.txt"]]);
  assert.deepEqual(paths("<<'EOF'\n*** Begin Patch\n*** Delete File: y.txt\n*** End Patch\nEOF"), [["delete", "y.txt"]]);
  const r = parseApplyPatch("\n\n<<EOF\n*** Begin Patch\n*** Delete File: z.txt\n*** End Patch\nEOF");
  assert.ok(r.ok);
  assert.equal(r.paths[0]!.line, 4, "the line counts the trimmed lead and the heredoc opener");
  assert.deepEqual(paths("*** Begin Patch\n*** End Patch"), [], "an empty patch names nothing (OpenClaw then refuses: no files were modified)");
});

test("malformed input is rejected with OpenClaw's own message (the proxy refuses the call whole)", () => {
  assert.match(error(""), /input is empty/);
  assert.match(error("   \n "), /input is empty/);
  assert.match(error(42), /not a string/);
  assert.match(error(undefined), /not a string/);
  assert.match(error("*** Add File: a\n+x\n*** End Patch"), /first line of the patch must be/);
  assert.match(error("*** Begin Patch\n*** Add File: a\n+x"), /last line of the patch must be/);
  assert.match(error("*** Begin Patch\n*** Rename File: a\n*** End Patch"), /is not a valid hunk header/);
  assert.match(error("*** Begin Patch\n*** Update File: a\n*** End Patch"), /Update file hunk for path 'a' is empty/);
  assert.match(error("*** Begin Patch\n*** Update File: a\n@@\n*** End Patch"), /Update hunk does not contain any lines/);
  assert.match(error("*** Begin Patch\n*** Update File: a\n@@\n+x\n@@\n~bad\n*** End Patch"), /Unexpected line found in update hunk/);
  assert.match(error("*** Begin Patch\n*** Update File: a\n+x\nnot a hunk line\n*** End Patch"), /Expected update hunk to start with a @@ context marker/);
  assert.match(error("<<EOF\n*** Begin Patch\n*** Delete File: a\nEOF"), /last line of the patch must be/, "a heredoc around a broken patch");
  assert.match(error("*** Begin Patch\n*** Add File: a\nplain\n*** End Patch"), /is not a valid hunk header/, "an add body line without +");
});

test("rewritePatchPaths moves only the named headers' paths; every other byte stays", () => {
  const input = "  *** Begin Patch\r\n*** Update File: /h/src/a.ts\r\n*** Move to: /h/src/b.ts\r\n@@\r\n-/h/src/a.ts\r\n+/h/src/b.ts\r\n*** End Patch\r\n";
  const r = parseApplyPatch(input);
  assert.ok(r.ok);
  const out = rewritePatchPaths(input, r.paths, new Map([[0, "/a/src/a.ts"], [1, "/a/src/b.ts"]]));
  assert.equal(out, input.replace("Update File: /h/src/a.ts", "Update File: /a/src/a.ts").replace("Move to: /h/src/b.ts", "Move to: /a/src/b.ts"));
  assert.ok(out.includes("-/h/src/a.ts\r\n+/h/src/b.ts"), "content lines naming the paths are untouched");
  assert.equal(rewritePatchPaths(input, r.paths, new Map()), input);
});
