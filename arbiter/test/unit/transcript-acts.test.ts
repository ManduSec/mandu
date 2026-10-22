/**
 * transcript-acts.test — what a past session did, for the scan's riskier
 * sessions (arbiter/policy/transcript-acts.ts; plan 17 §3 item 10):
 *
 * - the call readers against the record shapes of real transcripts
 *   (test/fixtures/transcripts) and against hand-made records: each call
 *   with how it ended (failed, refused, stopped by Mandu), and the session's
 *   permission prompts;
 * - the shell commands of each agent's shell tools, the pipelines of a
 *   command, and which commands print the whole environment;
 * - the scanner's counts of the riskier sessions, a subagent counted with
 *   its parent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { claudeCodeActs, codexActs, isEnvDump, pipelineCommands, shellCommandsOf, shellPipelines, type ToolCall } from "../../policy/transcript-acts.js";
import { TranscriptScanner } from "../../policy/transcript-scan.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const FIXTURES = join(import.meta.dirname, "..", "fixtures", "transcripts");
const load = (name: string): unknown[] => readFileSync(join(FIXTURES, name), "utf8").split("\n").filter((l) => l !== "").map((l) => JSON.parse(l) as unknown);

const bash = (command: string, end?: ToolCall["end"]): ToolCall => ({ tool: "Bash", input: { command }, ...(end ? { end } : {}) });

test("the readers over the real record shapes: every call with its tool, and the fixtures' prompts were on", () => {
  const cc = claudeCodeActs(load("claude-code-2.1.305.jsonl"));
  assert.ok(cc.calls.length > 0);
  assert.ok(cc.calls.every((c) => typeof c.tool === "string" && c.tool !== ""));
  assert.equal(cc.skippedPrompts, false); // the fixture's modes are `auto` and `default`
  const cx = codexActs(load("codex-0.160.jsonl"));
  assert.ok(cx.calls.some((c) => c.tool === "exec"));
  assert.equal(cx.skippedPrompts, false); // read-only sandbox
});

test("claudeCodeActs: how each call ended, and bypassPermissions as prompts off", () => {
  const recs = [
    { type: "user", permissionMode: "bypassPermissions", message: { content: "go" } },
    { type: "assistant", timestamp: "2026-10-01T00:00:00Z", message: { content: [
      { type: "tool_use", id: "a", name: "Bash", input: { command: "ls" } },
      { type: "tool_use", id: "b", name: "Bash", input: { command: "false" } },
      { type: "tool_use", id: "c", name: "Bash", input: { command: "rm -rf build" } },
      { type: "tool_use", id: "d", name: "Bash", input: { command: "deploy" } },
      { type: "tool_use", id: "e", name: "Read", input: { file_path: "/x" } },
    ] } },
    { type: "user", message: { content: [
      { type: "tool_result", tool_use_id: "a", content: "ok" },
      { type: "tool_result", tool_use_id: "b", is_error: true, content: "Exit code 1" },
      { type: "tool_result", tool_use_id: "c", is_error: true, content: "The user doesn't want to proceed with this tool use." },
      { type: "tool_result", tool_use_id: "d", content: [{ type: "text", text: "{\"error\":{\"type\":\"mandu_fail_closed\"}}" }] },
    ] } },
  ];
  const acts = claudeCodeActs(recs);
  assert.equal(acts.skippedPrompts, true);
  assert.deepEqual(acts.calls.map((c) => [c.tool, c.end]), [["Bash", undefined], ["Bash", "failed"], ["Bash", "refused"], ["Bash", "stopped-by-mandu"], ["Read", undefined]]);
  assert.equal(acts.calls[0]!.at, "2026-10-01T00:00:00Z");
  assert.equal(claudeCodeActs([{ type: "user", permissionMode: "auto" }]).skippedPrompts, false);
});

test("codexActs: exit codes in Codex's forms, and approvals never with no sandbox as prompts off", () => {
  const call = (id: string, name: string, input: unknown) => ({ type: "response_item", payload: { type: "custom_tool_call", call_id: id, name, input } });
  const out = (id: string, output: unknown) => ({ type: "response_item", payload: { type: "custom_tool_call_output", call_id: id, output } });
  const recs = [
    { type: "turn_context", payload: { approval_policy: "never", sandbox_policy: { type: "danger-full-access" } } },
    call("1", "exec", "x"), out("1", [{ type: "input_text", text: "Script completed\nOutput:\n" }, { type: "input_text", text: "{\"exit_code\":0,\"output\":\"ok\"}" }]),
    call("2", "exec", "y"), out("2", "{\"exit_code\":2,\"output\":\"\"}"),
    call("3", "exec", "z"), out("3", "Process exited with code 1"),
    call("4", "exec", "w"), out("4", "{\"error\":{\"type\":\"mandu_fail_closed\"}}"),
  ];
  const acts = codexActs(recs);
  assert.equal(acts.skippedPrompts, true);
  assert.deepEqual(acts.calls.map((c) => c.end), [undefined, "failed", "failed", "stopped-by-mandu"]);
  assert.equal(codexActs([{ type: "turn_context", payload: { approval_policy: "never", sandbox_policy: { type: "read-only" } } }]).skippedPrompts, false);
  assert.equal(codexActs([{ type: "turn_context", payload: { approval_policy: "on-request", sandbox_policy: { type: "danger-full-access" } } }]).skippedPrompts, false);
});

test("shellCommandsOf: each agent's shell tools, and null for a tool that is not one", () => {
  assert.deepEqual(shellCommandsOf(bash("ls -la")), ["ls -la"]);
  assert.deepEqual(shellCommandsOf({ tool: "shell", input: JSON.stringify({ command: ["bash", "-lc", "env | sort"] }) }), ["env | sort"]);
  assert.deepEqual(shellCommandsOf({ tool: "local_shell", input: { type: "exec", command: ["printenv"] } }), ["printenv"]);
  assert.deepEqual(shellCommandsOf({ tool: "exec_command", input: { cmd: "pwd" } }), ["pwd"]);
  const code = 'const r = await tools.exec_command({cmd:"printf \\"%s\\" a; env","workdir":"/w"});\ntext(r.output);';
  assert.deepEqual(shellCommandsOf({ tool: "exec", input: code }), ['printf "%s" a; env']);
  assert.deepEqual(shellCommandsOf({ tool: "exec", input: "text('no command here')" }), []);
  assert.equal(shellCommandsOf({ tool: "Read", input: { file_path: "/x" } }), null);
});

test("shellPipelines and pipelineCommands: split where the shell splits, not inside quotes, $(…) or a here-document", () => {
  assert.deepEqual(shellPipelines("a; b && c || d & e\nf"), ["a", "b", "c", "d", "e", "f"]);
  assert.deepEqual(shellPipelines("echo 'a; b' \"c && d\" $(x; y)"), ["echo 'a; b' \"c && d\" $(x; y)"]);
  assert.deepEqual(shellPipelines("cat > f <<'EOF'\nenv\nset\nEOF\nls"), ["cat > f <<'EOF'\nenv\nset\nEOF", "ls"]);
  assert.deepEqual(shellPipelines("echo hi 2>&1 >/dev/null"), ["echo hi 2>&1 >/dev/null"]);
  assert.deepEqual(pipelineCommands("env | grep -i 'api key' | sort"), [["env"], ["grep", "-i", "api key"], ["sort"]]);
});

test("isEnvDump: a command that prints every variable, unless a filter narrows it to something else or it did not run", () => {
  for (const c of ["env", "printenv", "env | sort", "sudo env", "export -p", "export", "set", "declare -x", "cat /proc/self/environ", "cd /x && env", "env | grep -i token", "printenv | rg KEY"]) {
    assert.equal(isEnvDump(bash(c)), true, c);
  }
  for (const c of ["env FOO=1 make", "printenv HOME", "export PATH=/x:$PATH", "set -euo pipefail", "declare -A m", "env | grep PATH", "env | wc -l", "echo env", "cat > f <<EOF\nenv\nEOF"]) {
    assert.equal(isEnvDump(bash(c)), false, c);
  }
  assert.equal(isEnvDump(bash("env", "failed")), false);
  assert.equal(isEnvDump(bash("env", "refused")), false);
  assert.equal(isEnvDump({ tool: "Read", input: { file_path: "env" } }), false);
});

test("the scanner counts the riskier sessions once each, a subagent with its parent", () => {
  const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
  const s = new TranscriptScanner({ known: [{ value: STRIPE, path: "~/shop/.env", name: "STRIPE_KEY" }] });
  const skipped = { calls: [], skippedPrompts: true };
  s.addSession("claude-code", "p.jsonl", [{ how: "read-file", text: `STRIPE_KEY=${STRIPE}` }], {}, skipped);
  s.addSession("claude-code", "p.jsonl", [], {}, { calls: [bash("env")], skippedPrompts: true }); // its subagent
  s.addSession("claude-code", "q.jsonl", [], {}, skipped);
  s.addSession("codex", "r.jsonl", [], {}, { calls: [bash("printenv")], skippedPrompts: false });
  s.addSession("codex", "t.jsonl", [], {});
  assert.deepEqual(s.result().risk, { skippedPrompts: 2, skippedWithSecret: 1, envDumps: 2 });
});
