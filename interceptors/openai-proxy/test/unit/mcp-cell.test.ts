/**
 * mcp-cell — the allow-list grammar of plan 10 §11.13 (a Codex `exec` cell
 * that is nothing but ONE literal MCP call, or a bare `ALL_TOOLS` listing).
 *
 * Pins: the qualifying shapes and what they parse to (the tool identifier and
 * the literal's object, exactly the namespaced call's name and arguments); the
 * two listing forms; and a corpus of adversarial cells, each of which must be
 * REFUSED (null), so it keeps the fail-closed handling: dynamic or computed
 * tool names, aliasing, other globals (`load`, `exec_command`, `eval`,
 * `Function`, `globalThis`), calls on values, prototype walks, string-built
 * code, operators, templates, escapes in names, non-ASCII line terminators,
 * two calls, a call beside a listing, and statements with no separator.
 *
 * Axes: none. A pure parser; no arbiter, no classification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { cellCallsIdentified, cellsAreIsolated, exactExecCall, isMcpToolIdentifier, parseMcpCell, qualifyMcpCell } from "../../src/mcp-cell.js";

const READ = "mcp__mandu_policy__mandu_policy_read";

test("one literal MCP call, in each spelling the grammar takes, is that tool with the literal's object", () => {
  const cases: Array<[string, Record<string, unknown>]> = [
    [`text(await tools.${READ}({}));`, {}],
    [`text(await tools.${READ}({}))`, {}],
    [`const r = await tools.${READ}({});\ntext(r);`, {}],
    [`const r = await tools.${READ}({})\ntext(JSON.stringify(r))`, {}],
    [`const r = await tools.${READ}({});\ntext(JSON.stringify(r, null, 2));`, {}],
    [`const res = await tools.${READ}({});\ntext(res.content[0].text);`, {}],
    [`const res = await tools.${READ}({});\ntext(res?.content?.[0]?.text);`, {}],
    [`await tools.${READ}({});`, {}],
    [`text(await tools["${READ}"]({}));`, {}],
    [`text(await tools['${READ}']({}));`, {}],
    [`// @exec: {"yield_time_ms": 10000}\ntext(await tools.${READ}({}));`, {}],
    [`/* look up the rules */ text(await tools.${READ}({})); // done`, {}],
    [`;;text(await tools.${READ}({}));;`, {}],
  ];
  for (const [src, args] of cases) {
    assert.deepEqual(qualifyMcpCell(src), { kind: "mcp", name: READ, args }, src);
  }
});

test("the argument literal parses to the object V8 would build (JSON and the hand-written subset)", () => {
  const src = `text(await tools.mcp__mandu_policy__mandu_policy_propose({edits: [{op: "lock-path", path: '.env', level: "no-model",},], reason: "keys \\u0041\\x42\\n", n: -1.5e2, ok: true, none: null, "quoted key": 0}));`;
  assert.deepEqual(qualifyMcpCell(src), {
    kind: "mcp",
    name: "mcp__mandu_policy__mandu_policy_propose",
    args: { edits: [{ op: "lock-path", path: ".env", level: "no-model" }], reason: "keys AB\n", n: -150, ok: true, none: null, "quoted key": 0 },
  });
  // a secret symbol in an argument is just a string the tool receives
  assert.deepEqual(qualifyMcpCell(`text(await tools.mcp__mandu_inspect__inspect_symbol({symbol: "$MDU:nomodel_ab12", question: "what is it?"}))`), {
    kind: "mcp", name: "mcp__mandu_inspect__inspect_symbol", args: { symbol: "$MDU:nomodel_ab12", question: "what is it?" },
  });
  // a third-party tool qualifies too: it is then classified as that tool
  assert.deepEqual(qualifyMcpCell(`text(await tools.mcp__box__run_command({command: "psql -c 'select 1'"}))`), {
    kind: "mcp", name: "mcp__box__run_command", args: { command: "psql -c 'select 1'" },
  });
});

test("ALL_TOOLS: the bare listing forms qualify, as a listing", () => {
  for (const src of [
    "text(ALL_TOOLS);",
    "text(ALL_TOOLS)",
    "text(JSON.stringify(ALL_TOOLS));",
    "text(JSON.stringify(ALL_TOOLS, null, 2));",
    "// what can I call?\ntext(ALL_TOOLS);\ntext(JSON.stringify(ALL_TOOLS));",
  ]) {
    assert.deepEqual(qualifyMcpCell(src), { kind: "listing" }, src);
  }
  for (const src of [
    "text(JSON.stringify(ALL_TOOLS, (k, v) => v));",
    "text(JSON.stringify(ALL_TOOLS, [\"name\"]));",
    `text(ALL_TOOLS);\ntext(await tools.${READ}({}));`,
    "ALL_TOOLS;",
  ]) {
    assert.equal(qualifyMcpCell(src), null, src);
  }
});

// codex-cli 0.160 leaves deferred MCP tools out of the `exec` description and
// says "To find one, filter `ALL_TOOLS` by `name` and `description`": the
// search is a filtered listing (plan 10 §11.13, "the filtered listing").
test("ALL_TOOLS: a filtered, mapped or sliced listing qualifies, as a listing", () => {
  for (const src of [
    "text(ALL_TOOLS.filter(t => /policy/.test(t.name)));",
    "text(JSON.stringify(ALL_TOOLS.filter(t => /mandu|policy/i.test(t.name + \" \" + t.description))));",
    "text(JSON.stringify(ALL_TOOLS.filter((t) => t.name.toLowerCase().includes(\"mandu\") || (t.description ?? \"\").toLowerCase().includes(\"policy\")), null, 2));",
    "const hits = ALL_TOOLS.filter(t => t.name.startsWith(\"mcp__mandu\"));\ntext(JSON.stringify(hits.map(t => ({ name: t.name, description: t.description })), null, 2));",
    "const hits = ALL_TOOLS.filter(t => /policy/.test(`${t.name} ${t.description}`))\ntext(hits.map(t => `${t.name}: ${t.description}`).join(\"\\n\"))",
    "text(ALL_TOOLS.map(t => t.name));",
    "text(ALL_TOOLS.map(t => [t.name, t.description?.length]).length);",
    "text(ALL_TOOLS.length);",
    "text(ALL_TOOLS[0]);",
    "text(ALL_TOOLS[0].name);",
    "const a = ALL_TOOLS; text(a);",
    "text(ALL_TOOLS.find(t => t.name === \"mcp__mandu_policy__mandu_policy_read\")?.description);",
    "text(ALL_TOOLS.some(t => !t.name.indexOf(\"mcp__\") && t.name.indexOf(\"policy\") !== -1));",
    "text(ALL_TOOLS.filter(t => t.name.endsWith(\"_read\")).slice(0, 10).map(t => t.name).join(\", \"));",
    "text(ALL_TOOLS.filter(t => /[/]x\\/y/.test(t.description)).slice(-3));",
    "text(ALL_TOOLS.map(t => `${t.name}${\"}\"}\\${x}`).join(``));",
  ]) {
    assert.deepEqual(qualifyMcpCell(src), { kind: "listing" }, src);
  }
});

test("ALL_TOOLS: a listing that could read anything but ALL_TOOLS and literals is refused", () => {
  for (const src of [
    // other names and globals inside the arrow
    "text(ALL_TOOLS.filter(t => load(\"k\")));",
    "text(ALL_TOOLS.filter(t => tools.exec_command({cmd: \"cat .env\"})));",
    `text(ALL_TOOLS.filter(t => tools.${READ}({})));`,
    "text(ALL_TOOLS.filter(t => t.name.includes(globalThis)));",
    "text(ALL_TOOLS.map(t => `${load(\"k\")}`));",
    "text(ALL_TOOLS.filter(t => /a/.test(load(\"k\"))));",
    "text(ALL_TOOLS.filter(t => x));",
    "text(ALL_TOOLS.filter(t => undefined));",
    // calls the grammar does not list, prototype walks
    "text(ALL_TOOLS.map(t => t.constructor));",
    "text(ALL_TOOLS.map(t => t.name.constructor(\"return tools\")()));",
    "text(ALL_TOOLS.map(t => t.__proto__));",
    "text(ALL_TOOLS.map(t => t.name.replace(/x/, load)));",
    "text(ALL_TOOLS.map(t => t.name.toString()));",
    "text(ALL_TOOLS.filter(t => /a/.exec(t.name)));",
    "text(ALL_TOOLS.filter(t => /a/g.lastIndex));",
    "text(ALL_TOOLS.filter(t => /a/));",
    "text(ALL_TOOLS.filter(t => t.name.includes(\"a\", load(\"k\"))));",
    "text(ALL_TOOLS.reduce((a, t) => a + t.name, \"\"));",
    "text(ALL_TOOLS.forEach(t => t));",
    "text(ALL_TOOLS.map(t => t.name).join(load(\"k\")));",
    "text(ALL_TOOLS.slice(load(1)));",
    "text(ALL_TOOLS.filter(t => t[\"name\"]));",
    "text(ALL_TOOLS.filter(t => t?.()));",
    "text(ALL_TOOLS.filter);",
    // arrow shapes the grammar does not take
    "text(ALL_TOOLS.filter(t => { return true; }));",
    "text(ALL_TOOLS.filter(function (t) { return true; }));",
    "text(ALL_TOOLS.filter((t, i) => i < 3));",
    "text(ALL_TOOLS.filter(({ name }) => name));",
    "text(ALL_TOOLS.filter(async t => true));",
    "text(ALL_TOOLS.filter(text => true));",
    "text(ALL_TOOLS.filter(ALL_TOOLS => true));",
    "const t = ALL_TOOLS; text(t.filter(t => t.name));",
    "text(ALL_TOOLS.filter(t => t.map(u => u)));",
    // operators and assignments
    "text(ALL_TOOLS.filter(t => t.name = \"x\"));",
    "text(ALL_TOOLS.filter(t => t.name += \"x\"));",
    "text(ALL_TOOLS.filter(t => t.n++));",
    "text(ALL_TOOLS.filter(t => t.name / 2));",
    "text(ALL_TOOLS.filter(t => t.name ? 1 : 2));",
    "text(ALL_TOOLS.filter(t => t.name ??= 1));",
    "text(ALL_TOOLS.filter(t => t.name || (t.name = 1)));",
    "text(ALL_TOOLS.filter(t => t.a & 1));",
    "text(ALL_TOOLS.filter(t => t.name > \"a\"));",
    "text(ALL_TOOLS.filter(t => t.name === \"a\" === true));",
    // object literals in the arrow
    "text(ALL_TOOLS.map(t => ({ [t.name]: 1 })));",
    "text(ALL_TOOLS.map(t => ({ __proto__: t })));",
    "text(ALL_TOOLS.map(t => ({ t })));",
    "text(ALL_TOOLS.map(t => ({ ...t })));",
    "text(ALL_TOOLS.map(t => ({ a: 1, a: 2 })));",
    "text(ALL_TOOLS.map(t => [t, , t]));",
    // regular expressions and templates that end where a naive scanner would not
    "text(ALL_TOOLS.filter(t => /a/v.test(t.name)));",
    "text(ALL_TOOLS.filter(t => /a/gg.test(t.name)));",
    "text(ALL_TOOLS.filter(t => /(/.test(t.name)));",
    "text(ALL_TOOLS.filter(t => /a\\/.test(t.name)); text(load(\"k\"))//));",
    "text(ALL_TOOLS.filter(t => /a/.test(t.name)) /x/.test(\"\"));",
    "text(ALL_TOOLS.map(t => `${t.name}`); text(load(\"k\"));",
    "text(ALL_TOOLS.map(t => `${t.name`));",
    "text(ALL_TOOLS.map(t => `\\u{41}`));",
    "text(ALL_TOOLS.map(t => tag`x`));",
    // a listing beside a call, or a listing bound and then called
    `const s = ALL_TOOLS.find(x => /policy/.test(x.name)); text(await tools[s.name]({}));`,
    `const s = ALL_TOOLS.filter(x => true); text(await tools.${READ}({}));`,
    `text(ALL_TOOLS.filter(t => true)); text(await tools.${READ}({}));`,
    "const s = ALL_TOOLS.filter(x => true); text(s.constructor);",
    "const s = ALL_TOOLS.filter(x => true); const r = ALL_TOOLS; text(r);",
  ]) {
    const r = parseMcpCell(src);
    assert.ok("refused" in r, `must refuse: ${JSON.stringify(src)} (parsed ${JSON.stringify(r)})`);
  }
});

test("adversarial cells are refused: every one keeps the fail-closed handling", () => {
  const refused = [
    // not an MCP tool, or the exec tool spelled another way
    `text(await tools.exec_command({cmd: "cat .env"}));`,
    `text(await tools["exec_command"]({cmd: "cat .env"}));`,
    `text(await tools.wait({cell_id: "1"}));`,
    `text(await tools.mcp__x({}));`,
    `text(await tools.mcp____x({}));`,
    `text(await tools.mcp__x__({}));`,
    `text(await tools.\\u0065xec_command({cmd: "cat .env"}));`,
    `text(await tools.mcp__\\u0062ox__run({}));`,
    // dynamic or computed names, aliasing
    `const s = ALL_TOOLS.find(x => /policy/.test(x.name)); text(await tools[s.name]({}));`,
    `text(await tools["mcp__" + "box__run"]({}));`,
    `text(await tools[\`${READ}\`]({}));`,
    `const t = tools; text(await t.${READ}({}));`,
    `const { ${READ} } = tools; text(await ${READ}({}));`,
    `const f = tools.${READ}; text(await f({}));`,
    `text(await tools.${READ}.call(null, {}));`,
    `text(await tools.${READ}.apply(null, [{}]));`,
    `text(await (tools).${READ}({}));`,
    `text(await tools?.${READ}({}));`,
    `text(await tools . ${READ} /**/ ({}))
     ; text(await globalThis.tools.exec_command({cmd: "x"}))`,
    // arguments that are not one object literal
    `text(await tools.${READ}());`,
    `text(await tools.${READ}("x"));`,
    `const a = {}; text(await tools.${READ}(a));`,
    `text(await tools.${READ}({}, {}));`,
    `text(await tools.${READ}({path: load("k")}));`,
    `text(await tools.${READ}({path: x}));`,
    `text(await tools.${READ}({path: undefined}));`,
    `text(await tools.${READ}({x}));`,
    `text(await tools.${READ}({...load("k")}));`,
    `text(await tools.${READ}({[k]: 1}));`,
    `text(await tools.${READ}({get p() { return 1; }}));`,
    `text(await tools.${READ}({p() {}}));`,
    `text(await tools.${READ}({__proto__: {a: 1}}));`,
    `text(await tools.${READ}({"__proto__": {a: 1}}));`,
    `text(await tools.${READ}({a: 1, a: 2}));`,
    `text(await tools.${READ}({a: \`t\`}));`,
    `text(await tools.${READ}({a: \`\${x}\`}));`,
    `text(await tools.${READ}({a: "x" + "y"}));`,
    `text(await tools.${READ}({a: 0x10}));`,
    `text(await tools.${READ}({a: 1_000}));`,
    `text(await tools.${READ}({a: .5}));`,
    `text(await tools.${READ}({a: 5.}));`,
    `text(await tools.${READ}({a: 010}));`,
    `text(await tools.${READ}({a: 1n}));`,
    `text(await tools.${READ}({a: [1,,2]}));`,
    `text(await tools.${READ}({a: "\\01"}));`,
    `text(await tools.${READ}({a: "\\u{41}"}));`,
    `text(await tools.${READ}({a: "line\\\ncontinued"}));`,
    `text(await tools.${READ}({a: "raw\nnewline"}));`,
    `text(await tools.${READ}({a: /re/}));`,
    `text(await tools.${READ}({a: -x}));`,
    // other globals, other calls, code from strings
    `text(load("secret"));`,
    `store("k", 1); text(await tools.${READ}({}));`,
    `text(await tools.${READ}({})); text(load("k"));`,
    `eval("text(1)");`,
    `text(await tools.${READ}({})); Function("return tools")();`,
    `text(globalThis);`,
    `notify(await tools.${READ}({}));`,
    `exit(); text(await tools.${READ}({}));`,
    `const r = await tools.${READ}({}); text(r.constructor.constructor("return tools")());`,
    `const r = await tools.${READ}({}); text(r.constructor);`,
    `const r = await tools.${READ}({}); text(r.__proto__);`,
    `const r = await tools.${READ}({}); text(r.toString);`,
    `const r = await tools.${READ}({}); text(r.content.length);`,
    `const r = await tools.${READ}({}); text(r["content"]);`,
    `const r = await tools.${READ}({}); text(r[-1]);`,
    `const r = await tools.${READ}({}); text(r.content.map(x => x));`,
    `const r = await tools.${READ}({}); text(r.content[0].text());`,
    `const r = await tools.${READ}({}); text(r ?? "none");`,
    `const r = await tools.${READ}({}); text(r || "none");`,
    `const r = await tools.${READ}({}); text(r?.5:1);`,
    `const r = await tools.${READ}({}); text(r, r);`,
    `const r = await tools.${READ}({}); text(r,);`,
    `const r = await tools.${READ}({}); text(JSON.stringify(r,));`,
    `const r = await tools.${READ}({}); text(JSON.stringify(r, null, 99));`,
    `const r = await tools.${READ}({}); text(JSON.parse(r));`,
    `const r = await tools.${READ}({}); text(String(r));`,
    `text("a literal");`,
    `text(1);`,
    // bindings: shadowing, rebinding, use before bind, other declarations
    `const text = await tools.${READ}({}); text(1);`,
    `const JSON = await tools.${READ}({}); text(JSON.stringify(1));`,
    `const tools = await tools.${READ}({});`,
    `const undefined = await tools.${READ}({}); text(undefined);`,
    `let r = await tools.${READ}({}); text(r);`,
    `var r = await tools.${READ}({}); text(r);`,
    `r = await tools.${READ}({}); text(r);`,
    `text(r); const r = await tools.${READ}({});`,
    `const r = await tools.${READ}({}), s = 1; text(r);`,
    `const r = await tools.${READ}({}); const s = await tools.${READ}({}); text(s);`,
    // two calls, or a call that is not awaited, or none at all
    `text(await tools.${READ}({})); text(await tools.mcp__box__run_command({command: "id"}));`,
    `text(await tools.${READ}({})); text(await tools.${READ}({}));`,
    `text(tools.${READ}({}));`,
    `const p = tools.${READ}({}); text(await p);`,
    `text(await Promise.all([tools.${READ}({})]));`,
    `if (true) { text(await tools.${READ}({})); }`,
    `(async () => text(await tools.${READ}({})))();`,
    `for (const x of [1]) text(await tools.${READ}({}));`,
    ``,
    `   `,
    `// only a comment`,
    // separators, ASI, and line terminators V8 sees but a naive scanner would not
    `text(await tools.${READ}({})) text(1)`,
    `const r = await tools.${READ}({})\n[0]`,
    `const r = await tools.${READ}({})\n(text(r))`,
    `await tools.${READ}({})\n.then(text)`,
    `text(await tools.${READ}({})); // hidden\u2028text(load("k"))`,
    `text(await tools.${READ}({})); // hidden\u2029text(load("k"))`,
    `text(await tools.${READ}({})); /* unterminated`,
    `#!/usr/bin/env node\ntext(await tools.${READ}({}));`,
    `<!-- html\ntext(await tools.${READ}({}));`,
    `--> html\ntext(await tools.${READ}({}));`,
    `text(await tools.${READ}({}))\u00a0;`,
    `text(await tools.${READ}({}))\v;`,
    `text(await tools.${READ}({a: "x"}).a);`,
    `text(await tools.${READ}({}) == 1);`,
    `text(await tools.${READ}({}) => 1);`,
  ];
  for (const src of refused) {
    const r = parseMcpCell(src);
    assert.ok("refused" in r, `must refuse: ${JSON.stringify(src)} (parsed ${JSON.stringify(r)})`);
  }
  assert.ok("refused" in parseMcpCell(undefined));
  assert.ok("refused" in parseMcpCell({}));
  assert.ok("refused" in parseMcpCell("text(await tools." + READ + "({a:\"" + "x".repeat(70_000) + "\"}))"), "past the size bound");
  let deep = "1";
  for (let i = 0; i < 40; i++) deep = `[${deep}]`;
  assert.ok("refused" in parseMcpCell(`text(await tools.${READ}({a: ${deep}}))`), "past the depth bound");
});

test("isMcpToolIdentifier: mcp__<server>__<tool>, both parts present, identifier characters only", () => {
  for (const ok of [READ, "mcp__box__run_command", "mcp__a__b", "mcp__ologs__get_profile"]) assert.equal(isMcpToolIdentifier(ok), true, ok);
  for (const bad of ["exec_command", "mcp__x", "mcp____x", "mcp__x__", "mcp__-x__y", "MCP__a__b", "mcp__a__b c", ""]) assert.equal(isMcpToolIdentifier(bad), false, bad);
});

test("cellsAreIsolated: only the custom `exec` tool whose description says each cell is a fresh isolate", () => {
  const exec = (description: unknown) => ({ type: "custom", name: "exec", description });
  assert.equal(cellsAreIsolated([exec("Run JavaScript code\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module.")]), true);
  assert.equal(cellsAreIsolated([exec("Run JavaScript code in a persistent REPL")]), false, "a codex that keeps state across cells");
  assert.equal(cellsAreIsolated([exec(undefined)]), false);
  assert.equal(cellsAreIsolated([{ type: "function", name: "exec", description: "fresh V8 isolate" }]), false, "not the custom tool");
  assert.equal(cellsAreIsolated([{ type: "custom", name: "js_repl", description: "fresh V8 isolate" }]), false, "another custom tool");
  assert.equal(cellsAreIsolated([]), false);
  assert.equal(cellsAreIsolated(undefined as never), false);
});

// ── §11.13 path (a): which exec cells are identified exactly ────────────────

test("exactExecCall: the ONE identified tools.exec_command call of a cell, in the shapes codex's model writes", () => {
  const args = { cmd: "cat notes.md", workdir: "/w", yield_time_ms: 10000, max_output_tokens: 2000 };
  const lit = JSON.stringify(args);
  for (const src of [
    `const r = await tools.exec_command(${lit});\ntext(r.output);\n`,
    `const r = await tools.exec_command(${lit})\ntext(r.output)`,
    `text((await tools.exec_command(${lit})).output);`,
    `// @exec: {"yield_time_ms": 10000}\nconst r = await tools.exec_command(${lit});\ntext(JSON.stringify(r));`,
    `await tools.exec_command(${lit});`,
  ]) {
    assert.deepEqual(exactExecCall(src), args, src);
    assert.equal(cellCallsIdentified(src), true, src);
  }
  // the block sentinel cell is itself exact
  assert.deepEqual(exactExecCall(`const r = await tools.exec_command({"cmd":"echo 'blocked' 1>&2; exit 77","yield_time_ms":10000,"max_output_tokens":2000});\ntext(r.output);\n`), { cmd: "echo 'blocked' 1>&2; exit 77", yield_time_ms: 10000, max_output_tokens: 2000 });
});

test("exactExecCall / cellCallsIdentified: a second exec, a hidden exec, or anything the grammar refuses is not exact", () => {
  const lit = `{"cmd":"ls"}`;
  const notExact: Array<[string, boolean]> = [
    // [cell, are all its calls still identified?]
    [`await tools.exec_command(${lit}); await tools.exec_command({"cmd":"psql -c 'select 1'"});`, true],
    [`await tools.exec_command(${lit}); text(await tools.mcp__box__get({}));`, true],
    [`await tools.exec_command(${lit}); text(ALL_TOOLS);`, true],
    [`await tools.exec_command(${lit}); text(ALL_TOOLS.filter(t => /x/.test(t.name)));`, true],
    [`await tools.exec_command(${lit}); text(ALL_TOOLS.filter(t => load("k")));`, false],
    [`await tools.exec_command(${lit}); await tools["exec_command"]({"cmd":"psql"});`, false],
    [`await tools["exec_command"](${lit});`, false],
    [`await tools.exec_command(${lit}); const t = tools; await t.exec_command({"cmd":"psql"});`, false],
    [`await tools.exec_command(${lit}); await tools.\\u0065xec_command({"cmd":"psql"});`, false],
    [`await tools.exec_command(${lit}); await globalThis.tools.exec_command({"cmd":"psql"});`, false],
    [`await tools.exec_command(${lit}); eval("tools.exec_command({cmd:'psql'})");`, false],
    [`const c = "psql"; await tools.exec_command({cmd: c});`, false],
    [`await tools.exec_command({cmd: "ls " + "x"});`, false],
    [`for (const c of ["ls", "psql"]) await tools.exec_command({cmd: c});`, false],
    [`const r = await tools.exec_command(${lit}); text(r.output.split("\\n"));`, false],
    [`const r = await tools.exec_command(${lit}); text(load("k"));`, false],
  ];
  for (const [src, identified] of notExact) {
    assert.equal(exactExecCall(src), null, src);
    assert.equal(cellCallsIdentified(src), identified, src);
  }
  // an MCP-only cell never counts as an exec cell
  assert.equal(exactExecCall(`text(await tools.mcp__mandu_policy__mandu_policy_read({}));`), null);
});
