/**
 * unmapped-upload — the local files a tool NO gate table names may send off
 * this computer (guarantees.md §3; supported-agents.md §2, "The unmapped
 * upload leg"). Before 2026-10-17 such a tool was not judged on the wire at
 * all: an MCP server's `upload_file{path: "/ws/app/.env"}` went to the agent
 * unchanged. Pinned here, pure and over a fake arbiter:
 *   - which strings are local paths (absolute, `~/`, `file://`; a relative
 *     one only under a path-like key, against the launch directory) and
 *     which are not (URLs, `//host`, prose, a remote API's path is one but
 *     the arbiter finds nothing there);
 *   - every path goes to the arbiter in the UNMAPPED form, with no host;
 *     a held one becomes a path under the denied namespace, every other
 *     argument as the model wrote it, and the notice says ask the user;
 *   - the window: a path judged by its bytes after a possible writer of the
 *     same turn is withheld; an exempt tool's (mapped, guard-confined) is not;
 *   - fail-closed: no op, a throw, a hang, too many paths withhold every path;
 *   - which tools are unmapped (surfaceNamesTool) and which may write
 *     (possibleWriter).
 *
 * Axes: `secrets`, stated through the fake arbiter (the upload gate's
 * answers are the confidentiality axis's).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  gateUnmappedUploadToolUse,
  localPathOf,
  possibleWriter,
  replaceAtLocs,
  surfaceNamesTool,
  uploadPathCandidates,
  withheldPath,
  UPLOAD_DENIED_ROOT,
  UNMAPPED_UPLOAD_MAX_DEPTH,
  UNMAPPED_UPLOAD_MAX_PATHS,
  type UnmappedUploadOptions,
} from "../../src/unmapped-upload.js";
import { CLAUDE_CODE_GATE_SURFACE, UNION_GATE_SURFACE } from "../../src/gate-surface.js";
import { DENIED_NAMESPACE } from "../../src/fs-gate.js";
import type { FileUploadDecision, FileUploadDecisionRequest } from "../../src/arbiter-client.js";

const HOME = "/home/u";
const SECRET = "/ws/app/.env";

const HELD: FileUploadDecision = {
  allow: false, requiresApproval: true,
  reason: `'${SECRET}' is a secret file (no-model) and no rule lets it go to an unnamed destination`,
  ruleRef: { source: "rule", id: "fs:upload-secret-file" }, approvalId: "egr-9",
};
const answer = (id: string): FileUploadDecision => ({ allow: true, reason: id, ruleRef: { source: "rule", id } });

function fake(calls: FileUploadDecisionRequest[] = [], decide?: (r: FileUploadDecisionRequest) => FileUploadDecision): UnmappedUploadOptions["arbiter"] {
  return {
    fileUploadDecision: async (req: FileUploadDecisionRequest) => {
      calls.push(req);
      if (decide) return decide(req);
      return req.path === SECRET ? HELD : req.path.startsWith("/ws/") ? answer("fs:upload-clean") : answer("fs:upload-no-file");
    },
  };
}

const opts = (arbiter = fake(), over: Partial<UnmappedUploadOptions> = {}): UnmappedUploadOptions =>
  ({ arbiter, sessionKey: "s1", home: HOME, launchDir: "/ws/app", ...over });

// ── which strings are local paths ───────────────────────────────────────────

test("localPathOf: absolute, ~/ and file:// name a local path; URLs, //host, prose and multi-line text do not", () => {
  assert.equal(localPathOf("/ws/app/.env", null, HOME), "/ws/app/.env");
  assert.equal(localPathOf("  /ws/app/./x/../.env ", null, HOME), "/ws/app/.env");
  assert.equal(localPathOf("~/.aws/credentials", null, HOME), "/home/u/.aws/credentials");
  assert.equal(localPathOf("file:///ws/app/a%20b.txt", null, HOME), "/ws/app/a b.txt");
  assert.equal(localPathOf("file://localhost/ws/app/x", null, HOME), "/ws/app/x");
  for (const s of ["https://example.com/a", "//cdn.example.com/x.js", "file://host/x", "hello world", "/a\n/b", "", "   ", "x".repeat(5000)]) {
    assert.equal(localPathOf(s, "path", HOME, "/ws/app"), null, JSON.stringify(s.slice(0, 40)));
  }
});

test("localPathOf: a relative string is a path only under a path-like key and with a launch directory to place it", () => {
  assert.equal(localPathOf(".env", "file_path", HOME, "/ws/app"), "/ws/app/.env");
  assert.equal(localPathOf("docs/a.md", "attachments", HOME, "/ws/app"), "/ws/app/docs/a.md");
  assert.equal(localPathOf(".env", "file_path", HOME), null, "no launch directory: not placed");
  assert.equal(localPathOf(".env", "query", HOME, "/ws/app"), null, "not a path-like key");
  for (const s of ["two words", "mailto:x@y.z", "-rf"]) assert.equal(localPathOf(s, "path", HOME, "/ws/app"), null, s);
});

test("uploadPathCandidates: every path at any depth, with where it sits; replaceAtLocs rewrites exactly those", () => {
  const input = { title: "report", paths: ["/ws/app/a.html", "https://x.test/y"], meta: { attach: [{ src: "~/notes.txt" }] }, n: 3 };
  const c = uploadPathCandidates(input, { home: HOME });
  assert.deepEqual(c.map((x) => [x.loc, x.path]), [[["paths", 0], "/ws/app/a.html"], [["meta", "attach", 0, "src"], "/home/u/notes.txt"]]);
  const out = replaceAtLocs(input, [{ loc: ["meta", "attach", 0, "src"], value: "X" }]) as typeof input;
  assert.equal(out.meta.attach[0]!.src, "X");
  assert.equal(input.meta.attach[0]!.src, "~/notes.txt", "the original is not mutated");
  assert.deepEqual(out.paths, input.paths);
});

// ── the leg ──────────────────────────────────────────────────────────────────

test("an unmapped upload tool naming a secret file: the path is withheld (names no file), the rest of the call kept; asked in the unmapped form with no host", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const input = { path: SECRET, remote_name: "env.txt", public: true };
  const r = await gateUnmappedUploadToolUse("mcp__drive__upload_file", input, opts(fake(calls)));
  assert.equal(r.outcome?.decision, "block");
  assert.deepEqual(r.input, { path: withheldPath(SECRET), remote_name: "env.txt", public: true });
  assert.equal(withheldPath(SECRET), "/mandu/denied/upload/ws/app/.env");
  assert.deepEqual(calls.map((c) => [c.tool, c.path, c.destination, c.unmapped, c.sessionKey]), [["mcp__drive__upload_file", SECRET, "", true, "s1"]]);
  assert.equal(r.outcome?.withheld[0]?.approvalId, "egr-9");
  assert.match(r.outcome!.notice!, /mcp__drive__upload_file was not given the file \/ws\/app\/\.env/);
  assert.match(r.outcome!.notice!, /Approvals page/);
  assert.match(r.outcome!.notice!, /rule: fs:upload-secret-file/);
  assert.ok(!JSON.stringify(r.input).includes(`"${SECRET}"`));
});

test("a clean file, nothing at a path (a remote API's /v1/items), a mapped tool: unchanged, no block", async () => {
  for (const input of [{ path: "/ws/app/report.html" }, { endpoint: "/v1/items", body: "{}" }, { query: "no paths here" }]) {
    const r = await gateUnmappedUploadToolUse("mcp__x__send", input, opts());
    assert.equal(r.input, input);
    assert.notEqual(r.outcome?.decision, "block");
  }
  // no path at all: nothing asked
  const calls: FileUploadDecisionRequest[] = [];
  assert.equal((await gateUnmappedUploadToolUse("mcp__x__send", { q: "hi" }, opts(fake(calls)))).outcome, undefined);
  assert.equal(calls.length, 0);
});

test("one ask per distinct path; every held path withheld, the first held one names the notice", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const decide = (r: FileUploadDecisionRequest): FileUploadDecision => (r.path.endsWith(".env") || r.path.endsWith("id_rsa") ? { ...HELD, approvalId: `egr-${r.path.length}` } : answer("fs:upload-clean"));
  const input = { files: ["/ws/app/a.html", SECRET, SECRET, "~/.ssh/id_rsa"] };
  const r = await gateUnmappedUploadToolUse("mcp__chrome__file_upload", input, opts(fake(calls, decide)));
  assert.deepEqual(calls.map((c) => c.path), ["/ws/app/a.html", SECRET, "/home/u/.ssh/id_rsa"]);
  assert.deepEqual((r.input as { files: string[] }).files, ["/ws/app/a.html", withheldPath(SECRET), withheldPath(SECRET), withheldPath("/home/u/.ssh/id_rsa")]);
  assert.equal(r.outcome?.withheld.length, 3);
});

test("THE WINDOW: after a possible writer of the same turn, a path judged by its bytes (clean or nothing there) is withheld; an exempt tool's is not", async () => {
  const input = { path: "/ws/app/report.html", also: "/tmp/new.txt" };
  const r = await gateUnmappedUploadToolUse("mcp__drive__upload_file", input, opts(fake(), { priorWriter: "Bash" }));
  assert.equal(r.outcome?.decision, "block");
  assert.deepEqual(r.input, { path: withheldPath("/ws/app/report.html"), also: withheldPath("/tmp/new.txt") });
  assert.match(r.outcome!.notice!, /earlier call of this turn \(Bash\)/);
  assert.match(r.outcome!.notice!, /rule: proxy:upload-after-write/);
  for (const id of ["fs:upload-mapped-tool", "fs:upload-confined-server"]) {
    const ok = await gateUnmappedUploadToolUse("mcp__fs__read_file", input, opts(fake([], () => answer(id)), { priorWriter: "Bash" }));
    assert.equal(ok.input, input, `${id}: exempt from the window rule`);
  }
  // a held file still names the notice before the window rule
  const held = await gateUnmappedUploadToolUse("mcp__drive__upload_file", { a: "/ws/app/report.html", b: SECRET }, opts(fake(), { priorWriter: "Bash" }));
  assert.match(held.outcome!.notice!, /rule: fs:upload-secret-file/);
});

test("FAIL-CLOSED: an arbiter without the op, one that throws, one that hangs, too many paths: every path withheld", async () => {
  const input = { path: "/ws/app/report.html", other: SECRET };
  const every = { path: withheldPath("/ws/app/report.html"), other: withheldPath(SECRET) };
  for (const arbiter of [
    {} as UnmappedUploadOptions["arbiter"],
    { fileUploadDecision: async () => { throw new Error("socket closed"); } },
    { fileUploadDecision: () => new Promise<FileUploadDecision>(() => {}) },
  ]) {
    const r = await gateUnmappedUploadToolUse("mcp__x__up", input, opts(arbiter, { timeoutMs: 50 }));
    assert.equal(r.outcome?.decision, "block");
    assert.deepEqual(r.input, every);
    assert.match(r.outcome!.notice!, /Mandu could not check the file/);
  }
  const many = { files: Array.from({ length: UNMAPPED_UPLOAD_MAX_PATHS + 5 }, (_, i) => `/ws/app/f${i}.txt`) };
  const r = await gateUnmappedUploadToolUse("mcp__x__up", many, opts());
  assert.equal(r.outcome?.decision, "block");
  assert.ok((r.input as { files: string[] }).files.every((f) => f.startsWith("/mandu/denied/upload/")), "past the bound too");
});

test("FAIL-CLOSED: a value nested past the depth bound is withheld whole (a path hidden below it would go unchecked)", async () => {
  let deep: Record<string, unknown> = { path: SECRET };
  for (let i = 0; i < UNMAPPED_UPLOAD_MAX_DEPTH + 2; i++) deep = { inner: deep };
  const input = { note: "x", payload: deep, clean: "/ws/app/report.html" };
  const calls: FileUploadDecisionRequest[] = [];
  const r = await gateUnmappedUploadToolUse("mcp__x__up", input, opts(fake(calls)));
  assert.equal(r.outcome?.decision, "block");
  assert.ok(!JSON.stringify(r.input).includes(SECRET), "the secret path below the bound is gone");
  assert.equal((r.input as typeof input).clean, "/ws/app/report.html", "a checked clean path stays");
  assert.deepEqual(calls.map((c) => c.path), ["/ws/app/report.html"], "the deep value is not asked about, it is withheld");
  assert.match(r.outcome!.notice!, /could not read the call well enough/);
});

test("not an object: untouched, no outcome", async () => {
  for (const input of [null, "x", ["/ws/app/.env"], 3]) assert.equal((await gateUnmappedUploadToolUse("mcp__x__up", input, opts())).outcome, undefined);
});

// ── which tools ──────────────────────────────────────────────────────────────

test("surfaceNamesTool: every table names its tools (the upload table too); an MCP tool or a new built-in is unmapped", () => {
  for (const t of ["Bash", "Read", "Write", "WebFetch", "DesignSync", "Artifact", "BashOutput"]) assert.equal(surfaceNamesTool(CLAUDE_CODE_GATE_SURFACE, t), true, t);
  for (const t of ["mcp__drive__upload_file", "mcp__claude-in-chrome__file_upload", "Attach", "TodoWrite"]) assert.equal(surfaceNamesTool(CLAUDE_CODE_GATE_SURFACE, t), false, t);
  assert.equal(surfaceNamesTool(UNION_GATE_SURFACE, "apply_patch"), true);
});

test("possibleWriter: shells, write tools, patches, dispatchers and unmapped tools may write; read tools, fetches and bookkeeping do not", () => {
  for (const t of ["Bash", "Monitor", "Write", "Edit", "NotebookEdit", "Task", "Agent", "mcp__fs__write_file", "Artifact", "ArtifactData"]) assert.equal(possibleWriter(t, CLAUDE_CODE_GATE_SURFACE), true, t);
  for (const t of ["Read", "Glob", "Grep", "LS", "WebFetch", "WebSearch", "TodoWrite", "ToolSearch", "AskUserQuestion", "DesignSync", "ArtifactComments"]) assert.equal(possibleWriter(t, CLAUDE_CODE_GATE_SURFACE), false, t);
  assert.equal(possibleWriter("apply_patch", UNION_GATE_SURFACE), true);
  assert.equal(possibleWriter("tool_call", UNION_GATE_SURFACE), true);
});

test("the shared core's withheld spelling sits under this proxy's denied namespace (unmapped-upload-core.ts names no fs-gate.ts of its own)", () => {
  assert.equal(UPLOAD_DENIED_ROOT, `${DENIED_NAMESPACE}/upload`);
  assert.equal(withheldPath("/ws/app/.env"), `${DENIED_NAMESPACE}/upload/ws/app/.env`);
});
