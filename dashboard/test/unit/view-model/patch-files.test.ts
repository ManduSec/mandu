/**
 * patch-files.test — the files an `apply_patch` call touches, read off its
 * patch's headers (view-model/patch-files.ts; dashboard.md §4.25b "A patch
 * names its files"), for every form the call is recorded in: Codex's JSON
 * tool and OpenClaw's (`{"input": …}`), Codex's freeform tool as the
 * openai-proxy records it (the same), OpenCode's `{"patchText": …}`, the
 * request transcript's bare JSON string, and the patch text itself.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { isPatchTool, patchFiles, patchText } from "../../../src/view-model/patch-files.js";

const PATCH = [
  "*** Begin Patch",
  "*** Update File: src/app.ts",
  "@@ function main",
  "-  old();",
  "+  next();",
  " *** Add File: not/a/header.ts",
  "*** Add File: docs/setup.md",
  "+# Setup",
  "+*** Delete File: also/not/a/header.ts",
  "*** Delete File: old/legacy.ts",
  "*** Update File: src/a.ts",
  "*** Move to: src/b.ts",
  "@@",
  "-x",
  "+y",
  "*** End Patch",
].join("\n");

const WANT = [
  { kind: "update", path: "src/app.ts" },
  { kind: "add", path: "docs/setup.md" },
  { kind: "delete", path: "old/legacy.ts" },
  { kind: "move", path: "src/a.ts", to: "src/b.ts" },
];

test("every recorded form of the call yields the same files, in the patch's order; a content line that holds a header's text is not one", () => {
  for (const [form, input] of [
    ["the JSON form (Codex's function tool, OpenClaw's, Codex's freeform as recorded)", JSON.stringify({ input: PATCH })],
    ["OpenCode's patchText", JSON.stringify({ patchText: PATCH })],
    ["the transcript's bare string", JSON.stringify(PATCH)],
    ["the patch text itself", PATCH],
    ["CRLF line ends", PATCH.replace(/\n/g, "\r\n")],
    ["the heredoc wrapper", `<<'EOF'\n${PATCH}\nEOF`],
  ] as const) {
    assert.deepEqual(patchFiles(input), WANT, form);
  }
});

test("a file named twice the same way is listed once; a header with no path, and an input with no patch, name none", () => {
  const twice = ["*** Begin Patch", "*** Update File: a.ts", "@@", "-a", "+b", "*** Update File: a.ts", "@@", "-c", "+d", "*** End Patch"].join("\n");
  assert.deepEqual(patchFiles(JSON.stringify({ input: twice })), [{ kind: "update", path: "a.ts" }]);
  assert.deepEqual(patchFiles("*** Begin Patch\n*** Add File: \n*** End Patch"), []);
  for (const none of [null, undefined, "", "  ", "{}", JSON.stringify({ input: 3 }), JSON.stringify([PATCH]), "not a patch"]) {
    assert.deepEqual(patchFiles(none), [], String(none));
  }
  // A header's path keeps its inner spaces and loses the trailing ones.
  assert.deepEqual(patchFiles("*** Add File: My Notes/to do.md  \n+x"), [{ kind: "add", path: "My Notes/to do.md" }]);
  // A placeholder in a path is kept as the AI wrote it (the page draws it as a chip).
  assert.deepEqual(patchFiles(JSON.stringify({ input: "*** Delete File: $MDU:nomodel_Read[3fa9].DIR/k.pem" })), [{ kind: "delete", path: "$MDU:nomodel_Read[3fa9].DIR/k.pem" }]);
});

test("patchText reads the patch out of each argument shape; isPatchTool names apply_patch in any case", () => {
  assert.equal(patchText(JSON.stringify({ input: "P" })), "P");
  assert.equal(patchText(JSON.stringify({ patchText: "P" })), "P");
  assert.equal(patchText(JSON.stringify({ patch: "P" })), "P");
  assert.equal(patchText(JSON.stringify({ input: "", patchText: "Q" })), "Q", "an empty field is skipped");
  assert.equal(patchText(JSON.stringify("P")), "P");
  assert.equal(patchText("*** Begin Patch"), "*** Begin Patch");
  assert.equal(patchText(JSON.stringify({ path: "a.ts" })), null);
  assert.ok(isPatchTool("apply_patch"));
  assert.ok(isPatchTool("Apply_Patch"));
  for (const no of ["edit", "Edit", "write", "patch", "exec"]) assert.ok(!isPatchTool(no), no);
});
