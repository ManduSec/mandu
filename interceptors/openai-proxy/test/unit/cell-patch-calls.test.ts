/**
 * cell-patch-calls.test — the literal `tools.apply_patch(…)` calls of a Codex
 * code-mode cell, reported as Codex's patch record (dashboard.md §4.25b "A
 * patch in a code cell"; cell-patch-calls.ts):
 *
 *   - the literal forms: a double, single or hole-free template string, a
 *     string member `tools["apply_patch"]`, a one-field `{input}` object, and
 *     a name bound once by a top-level `const` (the form a live model wrote);
 *   - several calls in one cell, in source order; next to exec literals
 *     (freeformCalls: the exec literals, then the patches);
 *   - anything computed is left alone: a concatenation, a template hole, a
 *     call, a name bound by `let` / twice / after the call / shadowed, an
 *     own `tools`, a call inside a string or a comment, a `/` the lexer
 *     cannot place;
 *   - a placeholder in a path stays the placeholder the model wrote.
 *
 * Pure parsing: no arbiter, no axis read (the record is the model's text).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { cellPatchCalls } from "../../src/cell-patch-calls.js";
import { freeformCalls } from "../../src/sse-rewrite.js";

const P1 = "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-x\n+y\n*** End Patch\n";
const P2 = "*** Begin Patch\n*** Add File: docs/b.md\n+hello\n*** End Patch";

/** The patch texts a cell reports. */
const patches = (src: string): string[] => cellPatchCalls(src).map((c) => {
  assert.equal(c.name, "apply_patch");
  return (JSON.parse(c.argsJson) as { input: string }).input;
});

test("a string literal argument: double, single and hole-free template quotes", () => {
  assert.deepEqual(patches(`const r = await tools.apply_patch(${JSON.stringify(P1)});\ntext(r);\n`), [P1]);
  assert.deepEqual(patches(`text(await tools.apply_patch('${P2.replace(/\n/g, "\\n")}'));`), [P2]);
  assert.deepEqual(patches(`await tools.apply_patch(\`${P1}\`);`), [P1], "a template spans lines as written");
  assert.deepEqual(patches(`await tools . apply_patch ( "${"*** Begin Patch\\n*** Delete File: old.ts\\n*** End Patch"}" )`), ["*** Begin Patch\n*** Delete File: old.ts\n*** End Patch"]);
  assert.deepEqual(patches(`await tools["apply_patch"](${JSON.stringify(P2)});`), [P2]);
  assert.deepEqual(patches(`await tools.apply_patch({input: ${JSON.stringify(P1)}});`), [P1]);
  assert.deepEqual(patches(`await tools.apply_patch({"input": ${JSON.stringify(P1)},});`), [P1]);
});

test("escapes decode as JavaScript reads them", () => {
  const u = "\\" + "u"; // a \u escape, spelled so no tool rewrites it
  assert.deepEqual(patches(String.raw`await tools.apply_patch("*** Begin Patch\n*** Add File: a\x2ets\n+\x41` + `${u}0042${u}{43}\\n*** End Patch");`), ["*** Begin Patch\n*** Add File: a.ts\n+ABC\n*** End Patch"]);
  // An octal escape is a syntax error in a module: nothing is reported.
  assert.deepEqual(patches(String.raw`await tools.apply_patch("*** Begin Patch\1");`), []);
});

test("a name bound once by a top-level const, as a live model writes it", () => {
  assert.deepEqual(patches(`const patch = ${JSON.stringify(P1)};\ntext(await tools.apply_patch(patch));\n`), [P1]);
  assert.deepEqual(patches(`const patch = \`${P2}\`\nconst r = await tools.apply_patch(patch)\ntext(r)`), [P2], "a statement ended by a line break (ASI)");
  assert.deepEqual(patches(`const p = ${JSON.stringify(P1)};\nconst r = await tools.apply_patch(p);\ntext(r.output.length > 0 ? r.output : "done");`), [P1], "the result is read, not the name");
});

test("several calls in one cell, in source order, each once", () => {
  const cell = [
    `const a = ${JSON.stringify(P1)};`,
    `await tools.apply_patch(a);`,
    `for (const r of [1, 2]) text(String(r / 2));`,
    `await tools.apply_patch(${JSON.stringify(P2)});`,
  ].join("\n");
  assert.deepEqual(patches(cell), [P1, P2]);
});

test("next to exec literals: freeformCalls reports the exec literals, then the patches", () => {
  const cell = `await tools.apply_patch(${JSON.stringify(P1)});\nconst r = await tools.exec_command({"cmd":"npm test"});\ntext(r.output);\n`;
  assert.deepEqual(freeformCalls("exec", cell), [
    { name: "exec_command", argsJson: JSON.stringify({ cmd: "npm test" }) },
    { name: "apply_patch", argsJson: JSON.stringify({ input: P1 }) },
  ]);
  // A cell with no patch reports what it did before.
  assert.deepEqual(freeformCalls("exec", 'const r = await tools.exec_command({"cmd":"ls"});\ntext(r.output);\n'), [{ name: "exec_command", argsJson: JSON.stringify({ cmd: "ls" }) }]);
});

test("computed arguments are left alone", () => {
  const cases: Array<[string, string]> = [
    ["a concatenation", `await tools.apply_patch("*** Begin Patch\\n" + body);`],
    ["two literals added", `await tools.apply_patch("*** Begin Patch\\n" + "*** Add File: a\\n*** End Patch");`],
    ["a template hole", "await tools.apply_patch(`*** Begin Patch\\n*** Add File: ${name}\\n*** End Patch`);"],
    ["a tagged template", "await tools.apply_patch(String.raw`*** Begin Patch\\n*** Add File: a\\n*** End Patch`);"],
    ["a call", `await tools.apply_patch(makePatch("a.ts"));`],
    ["a method on a literal", `await tools.apply_patch("*** Begin Patch\\n*** Add File: a\\n*** End Patch".trim());`],
    ["an unbound name", `await tools.apply_patch(patch);`],
    ["a let binding", `let p = ${JSON.stringify(P1)};\nawait tools.apply_patch(p);`],
    ["a name bound twice", `const p = ${JSON.stringify(P1)};\n{ const p = ${JSON.stringify(P2)}; await tools.apply_patch(p); }`],
    ["a name bound after the call", `const f = () => tools.apply_patch(p);\nconst p = ${JSON.stringify(P1)};\nawait f();`],
    ["a shadowing parameter", `const p = ${JSON.stringify(P1)};\n[${JSON.stringify(P2)}].map((p) => tools.apply_patch(p));`],
    ["a name used elsewhere", `const p = ${JSON.stringify(P1)};\nmodify(p);\nawait tools.apply_patch(p);`],
    ["a binding whose expression continues", `const p = ${JSON.stringify(P1)}\n+ suffix;\nawait tools.apply_patch(p);`],
    ["a computed member", `await tools[name](${JSON.stringify(P1)});`],
    ["an alias of tools", `const t = tools;\nawait t.apply_patch(${JSON.stringify(P1)});`],
    ["an own tools", `const tools = { apply_patch: (x) => x };\nawait tools.apply_patch(${JSON.stringify(P1)});`],
    ["a member named tools", `await host.tools.apply_patch(${JSON.stringify(P1)});`],
    ["an object with another field", `await tools.apply_patch({input: ${JSON.stringify(P1)}, dry: true});`],
    ["an empty patch", `await tools.apply_patch("");`],
  ];
  for (const [why, cell] of cases) assert.deepEqual(cellPatchCalls(cell), [], `${why}: ${cell}`);
});

test("a call inside a string or a comment is no call", () => {
  assert.deepEqual(patches(`text("await tools.apply_patch(\\"*** Begin Patch\\")");`), []);
  assert.deepEqual(patches(`// await tools.apply_patch(${JSON.stringify(P1)});\ntext("no");`), []);
  assert.deepEqual(patches(`/* await tools.apply_patch(${JSON.stringify(P1)}); */ text("no");`), []);
  assert.deepEqual(patches("text(`await tools.apply_patch(\"x\")`);"), []);
  // A patch whose CONTENT holds a call is one patch, never two.
  const nested = "*** Begin Patch\n*** Add File: scripts/x.js\n+await tools.apply_patch(\"*** Begin Patch\\n*** Delete File: victim.ts\\n*** End Patch\");\n*** End Patch";
  assert.deepEqual(patches(`await tools.apply_patch(${JSON.stringify(nested)});`), [nested]);
});

test("a `/` the lexer cannot place gives up on the whole cell; one it can place does not", () => {
  // After `)`: a division or a regular expression, by what came before.
  assert.deepEqual(patches(`if (x) /"/.test(y);\nawait tools.apply_patch(${JSON.stringify(P1)});`), []);
  // A regular expression after `(` holding a quote, and a division after a name.
  assert.deepEqual(patches(`const ok = /"'\`/.test(s); const h = n / 2;\nawait tools.apply_patch(${JSON.stringify(P1)});`), [P1]);
  // An unterminated string or template: nothing.
  assert.deepEqual(patches(`await tools.apply_patch("*** Begin Patch`), []);
  assert.deepEqual(patches("await tools.apply_patch(`*** Begin Patch"), []);
});

test("a placeholder in a path stays the placeholder the model wrote", () => {
  const sym = "$MDU:nomodel_exec_command[3fa9]";
  const p = `*** Begin Patch\n*** Update File: /home/u/${sym}/config.ts\n@@\n-a\n+${sym}\n*** End Patch`;
  const calls = cellPatchCalls(`const r = await tools.apply_patch(${JSON.stringify(p)});\ntext(r);`);
  assert.equal(calls.length, 1);
  assert.ok(calls[0]!.argsJson.includes(sym), "the token is recorded as written, never resolved");
  assert.deepEqual(JSON.parse(calls[0]!.argsJson), { input: p });
  // A token in a template literal: its `$` is no hole.
  assert.deepEqual(patches(`await tools.apply_patch(\`${p}\`);`), [p]);
});

test("not a cell: non-strings and oversized cells report nothing", () => {
  assert.deepEqual(cellPatchCalls(undefined as unknown as string), []);
  assert.deepEqual(cellPatchCalls(""), []);
  assert.deepEqual(cellPatchCalls(`await tools.apply_patch(${JSON.stringify("x".repeat(600 * 1024))});`), []);
});
