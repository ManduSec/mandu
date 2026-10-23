/**
 * opencode2-inbound — the OpenCode trust spec (policy/opencode-inbound.ts) on
 * OpenCode 2's tool surface, held to the tools[] and the tool results captured
 * from real 2.0.23 requests (test/fixtures/opencode2-tool-surface-2026-10-05.json;
 * supported-agents.md §2.3). One spec, `opencode`, serves both generations.
 *
 *   - every 2.x tool but `execute` (code mode, refused by the proxy) is mapped,
 *     each renamed tool with its 1.x twin's posture (shell = bash, subagent =
 *     task);
 *   - 2.x's `read` frame (`Read file <path>, lines A-B`, then `n: <line>`) is
 *     read back to the file's lines (opencode2ReadFrameText) exactly where the
 *     frame is whole, and nowhere else (the captured cut, empty, directory and
 *     error results are not);
 *   - the structured read-twin rule takes 2.x's `read{path}` as it takes
 *     1.x's `read{filePath}`; anything else keeps the file's label.
 *
 * Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { OPENCODE_INBOUND_SPEC, opencode2ReadFrameText, opencodeReadRenderingText } from "../../policy/opencode-inbound.js";
import { bindSessionSpec, getToolInboundSpec, unknownToolNames } from "../../policy/tool-inbound.js";
import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { destinationKind } from "../../policy/tool-outbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality verdict of the read-twin rule is asserted; integrity OFF

const capture = JSON.parse(readFileSync(new URL("../fixtures/opencode2-tool-surface-2026-10-05.json", import.meta.url), "utf8")) as Record<string, unknown>;
const SURFACE = Object.keys(capture["2.0.23"] as Record<string, string[]>);
type Captured = { tool: string; input?: Record<string, unknown>; is_error?: boolean; content: unknown };
const RESULTS = capture["__results__"] as Captured[];

bindSessionSpec("oc2-in", "opencode");

const schemaOf = (t: string): unknown => (OPENCODE_INBOUND_SPEC[t] as { schema?: unknown } | undefined)?.schema;

test("the 2.0.23 surface: every tool is mapped but `execute`, which the session-health list names (the proxy refuses it)", () => {
  assert.deepEqual(unknownToolNames(SURFACE, "oc2-in"), ["execute"]);
  for (const t of SURFACE) if (t !== "execute") assert.ok(getToolInboundSpec(t, "oc2-in"), t);
  // the 1.x names stay mapped (one spec for both generations)
  assert.deepEqual(unknownToolNames(["bash", "read", "write", "edit", "glob", "grep", "webfetch", "task", "todowrite", "skill"], "oc2-in"), []);
});

test("postures: the renamed tools keep their 1.x twin's (shell = bash, subagent = task); file content and fetched pages are untrusted, the agent's own echoes trusted", () => {
  assert.equal(schemaOf("shell"), schemaOf("bash"));
  assert.equal(schemaOf("shell"), "UNTRUSTED");
  assert.equal(schemaOf("subagent"), schemaOf("task"));
  assert.equal(schemaOf("subagent"), "UNTRUSTED");
  for (const t of ["grep", "skill"]) assert.equal(schemaOf(t), "UNTRUSTED", t);
  for (const t of ["write", "edit", "glob", "question"]) assert.equal(schemaOf(t), "TRUSTED", t);
  // read: the per-field schema keys both spellings; no whole-result rule (fail-closed)
  const read = OPENCODE_INBOUND_SPEC["read"] as { paramsKeys?: Record<string, unknown>; wholeResult?: unknown };
  assert.ok(read.paramsKeys?.["filePath"] && read.paramsKeys?.["path"]);
  assert.equal(read.wholeResult, undefined);
});

test("outbound: shell's command resolves (a HumanShell egress the egress gate checks); read/write/edit `path` stays symbolic", () => {
  assert.equal(destinationKind("shell", "command", "oc2-in"), "resolve");
  assert.equal(destinationKind("shell", "workdir", "oc2-in"), "resolve");
  for (const [tool, field] of [["read", "path"], ["write", "path"], ["write", "content"], ["edit", "path"], ["subagent", "prompt"], ["execute", "code"]] as const) {
    assert.equal(destinationKind(tool, field, "oc2-in"), "not_resolve", `${tool}.${field}`);
  }
});

// ── the 2.x read frame ─────────────────────────────────────────────────────

test("the read frame: every whole captured read gives back exactly the file's lines (no final newline)", () => {
  const want: Record<string, string> = {
    "/PROJ/notes.txt": "hello world\nsecond line",
    "one.txt": "only line",
    "nl.txt": "",
    "blank.txt": "a\n\n\nb",
    "crlf.txt": "a\r\nb\r",
    "tabs.txt": "\tindented\n  spaced  \ntrailing   ",
    "./sub/../blank.txt": "a\n\n\nb",
  };
  for (const [path, text] of Object.entries(want)) {
    const r = RESULTS.find((x) => x.tool === "read" && x.input?.["path"] === path && !x.input?.["offset"] && typeof x.content === "string");
    assert.ok(r, path);
    assert.equal(opencode2ReadFrameText(String(r!.content), [path]), text, path);
    assert.equal(opencodeReadRenderingText(String(r!.content), [path]), text, `${path}: the shared entry point dispatches on the frame`);
  }
  const offset = RESULTS.find((x) => x.tool === "read" && x.input?.["offset"] === 2)!;
  assert.equal(opencode2ReadFrameText(String(offset.content), ["notes.txt"]), "second line", "an offset read starts at its own line number");
});

test("the read frame: anything not exactly a whole frame is null (the caller keeps the wire bytes): the captured cut, empty, directory and error results, a foreign header, a gap, an extra line", () => {
  const nulls = RESULTS.filter((x) => x.tool === "read" && (x.is_error || typeof x.content !== "string" || /^Read (directory|file [^\n]*, 0 lines)/.test(String(x.content))));
  assert.ok(nulls.length >= 4, "the capture has error, empty, directory and long reads");
  for (const r of nulls) {
    const v = typeof r.content === "string" ? r.content : JSON.stringify(r.content);
    assert.equal(opencode2ReadFrameText(v, [String(r.input?.["path"])]), null, v.slice(0, 80));
  }
  const frame = "Read file a.txt, lines 1-2\n1: x\n2: y";
  assert.equal(opencode2ReadFrameText(frame, ["a.txt"]), "x\ny");
  assert.equal(opencode2ReadFrameText(frame, ["b.txt"]), null, "a header naming a path the call did not name");
  assert.equal(opencode2ReadFrameText(frame, []), null);
  assert.equal(opencode2ReadFrameText(frame, [""]), null);
  assert.equal(opencode2ReadFrameText("Read file a.txt, lines 1-3\n1: x\n2: y", ["a.txt"]), null, "fewer lines than the header says");
  assert.equal(opencode2ReadFrameText(`${frame}\n[Output truncated. Continue reading with offset: 3]`, ["a.txt"]), null, "a cut read");
  assert.equal(opencode2ReadFrameText(`${frame}\n<system-reminder>\nfrom AGENTS.md\n</system-reminder>`, ["a.txt"]), null, "a trailing reminder");
  assert.equal(opencode2ReadFrameText("Read file a.txt, lines 1-2\n1: x\n3: y", ["a.txt"]), null, "a gap in the numbering");
  assert.equal(opencode2ReadFrameText("Read file a.txt, lines 0-0\n0: x", ["a.txt"]), null, "line numbers start at 1");
  assert.equal(opencode2ReadFrameText(`Read file a.txt, lines 1-1\n1: ${"x".repeat(2000)}... (line truncated to 2000 chars)`, ["a.txt"]), null, "a cut line is not the file's line");
  assert.equal(opencode2ReadFrameText("Read file a.txt, lines 1-1", ["a.txt"]), null, "no body");
  assert.equal(opencode2ReadFrameText(42 as unknown as string, ["a.txt"]), null);
});

// ── the structured read-twin rule on 2.x's read{path} ──────────────────────

const TWIN = "# app\nPORT=3000\nSTRIPE_KEY=$MDU:nomodel_Read[9bbd].STRIPE_KEY\n";
const ALLOC = new Set(["$MDU:nomodel_Read[9bbd]", "$MDU:nomodel_Read[9bbd].STRIPE_KEY"]);
const ENV = "/ws/.env";
const frame2 = (lines: string[], path = ENV, from = 1): string =>
  [`Read file ${path}, lines ${from}-${from + lines.length - 1}`, ...lines.map((l, i) => `${from + i}: ${l}`)].join("\n");
const TWIN_LINES = TWIN.replace(/\n$/, "").split("\n");

function twinPolicy() {
  return createEngineBackedPolicy({
    policyFileOverride: {},
    confidentiality: true,
    integrity: false,
    symbolAllocated: (t: string) => ALLOC.has(t),
    twinRendering: (path: string) => (path === ENV ? TWIN : null),
  });
}
const read2 = (value: string, path = ENV) =>
  twinPolicy().classify({ tool: "read", value, boundary: "model_context", origin: path, params: { path }, sessionKey: "oc2-in" });

test("read-twin: 2.x's frame around the twin (whole, or an offset piece) passes public, as 1.x's envelope does", () => {
  assert.equal(read2(frame2(TWIN_LINES)).confidentiality, "public");
  assert.equal(read2(frame2(TWIN_LINES.slice(2, 3), ENV, 3)).confidentiality, "public");
});

test("read-twin: a raw value, a foreign header, a trailing reminder or a relative path keeps the label", () => {
  for (const v of [
    frame2(["STRIPE_KEY=sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"]),
    frame2(TWIN_LINES, "/etc/passwd"),
    `${frame2(TWIN_LINES)}\n<system-reminder>\nSTRIPE_KEY=sk_${""}live_4eC39HqLyjWDarjtT1zdp7dc\n</system-reminder>`,
    frame2(TWIN_LINES).replace("3: STRIPE", "4: STRIPE"),
  ]) {
    assert.equal(read2(v).confidentiality, "no-model", v);
  }
  assert.equal(read2(frame2(TWIN_LINES, ".env"), ".env").confidentiality, "no-model", "a relative path is not looked up");
});
