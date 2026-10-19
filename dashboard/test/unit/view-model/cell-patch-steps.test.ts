/**
 * cell-patch-steps.test — a Codex code-mode cell's patches on its step
 * (dashboard.md §4.25b "A patch in a code cell"). The openai-proxy records a
 * cell's `tools.exec_command` literals, then each literal `tools.apply_patch`
 * as `apply_patch({"input": …})`, all under the cell's one call id:
 *
 *   - extractToolUses: the last record names the call, but a patch never
 *     renames a call another tool named; every patch's args are kept;
 *   - toDualLanes: the step keeps the exec's name and args and carries the
 *     files of every patch (`patchFiles`), in order, each once; a cell of
 *     patches only is a patch step with all their files;
 *   - actionSentence: "Ran `npm test` and edited `a.ts`", "Edited `a.ts`,
 *     created `b.md`"; a masked item in a path is a chip, never its token;
 *   - patchFilesOf: several patches' files, each once.
 *
 * Pure view-model: no axis is read (the events are what the proxy recorded).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { extractToolUses } from "../../../src/view-model/tool-calls.js";
import { toDualLanes } from "../../../src/view-model/dual-lanes.js";
import type { DualToolStep } from "../../../src/view-model/dual-lanes-types.js";
import { actionSentence } from "../../../src/view-model/agent-page.js";
import { patchFilesOf } from "../../../src/view-model/patch-files.js";
import { ev, repr } from "./dual-lanes-fixtures.js";

const patch = (...headers: string[]): string => ["*** Begin Patch", ...headers, "*** End Patch"].join("\n");
const P1 = patch("*** Update File: src/a.ts", "@@", "-x", "+y");
const P2 = patch("*** Add File: docs/b.md", "+hi", "*** Update File: src/a.ts", "@@", "-y", "+z");
const use = (callId: string, name: string, args: unknown) =>
  ev({ kind: "tool_use", callId, emitter: "openai-proxy", input: repr(`${name}(${JSON.stringify(args)})`) });
const result = (callId: string, text: string) =>
  ev({ kind: "tool_result", callId, emitter: "openai-proxy", output: repr(text, text) });
const text = (parts: ReadonlyArray<{ kind: string; text: string }>): string => parts.map((p) => (p.kind === "masked" ? `[${p.text}]` : p.text)).join("");
const toolStep = (events: Parameters<typeof toDualLanes>[0], callId: string): DualToolStep =>
  toDualLanes(events).steps.find((s) => s.step === "tool" && (s as DualToolStep).callId === callId) as DualToolStep;

test("extractToolUses: a patch never renames a call another tool named; every patch is kept", () => {
  const events = [
    use("call_cell", "exec_command", { cmd: "npm test" }),
    use("call_cell", "apply_patch", { input: P1 }),
    use("call_cell", "apply_patch", { input: P2 }),
    use("call_only", "apply_patch", { input: P1 }),
    use("call_only", "apply_patch", { input: P2 }),
    use("call_bash", "exec_command", { cmd: "ls" }),
    use("call_bash", "exec_command", { cmd: "pwd" }),
  ];
  const tu = extractToolUses(events);
  assert.deepEqual(tu.get("call_cell"), { tool: "exec_command", input: JSON.stringify({ cmd: "npm test" }), patches: [JSON.stringify({ input: P1 }), JSON.stringify({ input: P2 })] });
  assert.deepEqual(tu.get("call_only"), { tool: "apply_patch", input: JSON.stringify({ input: P2 }), patches: [JSON.stringify({ input: P1 }), JSON.stringify({ input: P2 })] });
  // Control: no patch, the last record names the call, as before.
  assert.deepEqual(tu.get("call_bash"), { tool: "exec_command", input: JSON.stringify({ cmd: "pwd" }) });
});

test("toDualLanes: a cell that ran a command and patched keeps the command's name and args, and carries every patch's files", () => {
  const events = [
    use("call_cell", "exec_command", { cmd: "npm test" }),
    use("call_cell", "apply_patch", { input: P1 }),
    use("call_cell", "apply_patch", { input: P2 }),
    result("call_cell", "ok"),
  ];
  const step = toolStep(events, "call_cell");
  assert.equal(step.tool, "exec_command");
  assert.equal(step.input, JSON.stringify({ cmd: "npm test" }));
  assert.deepEqual(step.patchFiles, [{ kind: "update", path: "src/a.ts" }, { kind: "add", path: "docs/b.md" }]);
  assert.equal(text(actionSentence(step).sentence), "Ran npm test and edited a.ts, created b.md");
  assert.equal(actionSentence(step).icon, "run");
});

test("toDualLanes: a cell of patches only is a patch step naming every patch's files", () => {
  const events = [use("call_only", "apply_patch", { input: P1 }), use("call_only", "apply_patch", { input: P2 }), result("call_only", "Success.")];
  const step = toolStep(events, "call_only");
  assert.equal(step.tool, "apply_patch");
  assert.deepEqual(step.patchFiles, [{ kind: "update", path: "src/a.ts" }, { kind: "add", path: "docs/b.md" }]);
  const said = actionSentence(step);
  assert.equal(text(said.sentence), "Edited a.ts, created b.md");
  assert.equal(said.icon, "edit");
});

test("a cell with no patch reads as before; a cell whose patch names no file adds nothing", () => {
  const plain = toolStep([use("call_x", "exec_command", { cmd: "ls" }), result("call_x", "a")], "call_x");
  assert.equal(plain.patchFiles, undefined);
  assert.equal(text(actionSentence(plain).sentence), "Ran ls");
  const empty = toolStep([use("call_y", "exec_command", { cmd: "ls" }), use("call_y", "apply_patch", { input: "*** Begin Patch\n*** End Patch" })], "call_y");
  assert.equal(empty.patchFiles, undefined);
  assert.equal(text(actionSentence(empty).sentence), "Ran ls");
});

test("a masked item in a cell patch's path is a chip on the page, the token as written in the trace", () => {
  const sym = "$MDU:nomodel_exec_command[3fa9]";
  const step = toolStep([
    use("call_m", "exec_command", { cmd: "npm test" }),
    use("call_m", "apply_patch", { input: patch(`*** Delete File: /w/${sym}`) }),
  ], "call_m");
  assert.deepEqual(step.patchFiles, [{ kind: "delete", path: `/w/${sym}` }], "the trace keeps what the AI wrote");
  const said = actionSentence(step).sentence;
  assert.equal(text(said), "Ran npm test and deleted [secret]");
  assert.doesNotMatch(JSON.stringify(said), /\$MDU:|3fa9/);
});

test("patchFilesOf: several patches' files in order, each once", () => {
  assert.deepEqual(patchFilesOf([JSON.stringify({ input: P1 }), null, JSON.stringify({ input: P2 })]), [{ kind: "update", path: "src/a.ts" }, { kind: "add", path: "docs/b.md" }]);
  assert.deepEqual(patchFilesOf([]), []);
});
