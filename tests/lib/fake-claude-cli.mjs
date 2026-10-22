#!/usr/bin/env node
/**
 * fake-claude-cli — a stand-in `claude` executable for the suites that run a
 * launch headless (`mandu claude -p …`) where no real Claude Code is
 * installed (GitHub's runners, a contributor's machine): the GitHub Action's
 * end-to-end test (tests/stack/github-action.test.ts).
 *
 * It speaks the one thing of Claude Code's that Mandu's model proxy reads: the
 * Anthropic Messages wire, streamed, to `$ANTHROPIC_BASE_URL/v1/messages`,
 * with a `Bash` tool. The scripted model decides every step (a `tool_use`
 * names the command); this program runs each command with `sh -c` in its own
 * working directory, as Claude Code's Bash tool does, sends the output back as
 * the `tool_result`, and stops at the first turn with no tool call, printing
 * that turn's text on stdout (the `-p` result).
 *
 *   --version     prints a version inside Mandu's tested range
 *   -p <prompt>   the prompt (every other argument is ignored, as the
 *                 launcher adds its own: --permission-mode, --mcp-config, …)
 *
 * No dependency, no network but the base URL. Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";

/** A trace of each step, for a red run's diagnostics (`MDU_FAKE_CLAUDE_LOG`). */
const trace = (line) => {
  const f = process.env.MDU_FAKE_CLAUDE_LOG;
  if (f) { try { appendFileSync(f, `${new Date().toISOString()} ${line}\n`); } catch { /* best effort */ } }
};

const argv = process.argv.slice(2);
if (argv[0] === "--version") {
  process.stdout.write("2.1.295 (Claude Code)\n");
  process.exit(0);
}
const pi = argv.findIndex((a) => a === "-p" || a === "--print");
const prompt = pi >= 0 ? argv[pi + 1] ?? "" : "";
const base = (process.env.ANTHROPIC_BASE_URL ?? "").replace(/\/+$/, "");
if (!base) {
  process.stderr.write("fake-claude: ANTHROPIC_BASE_URL is not set\n");
  process.exit(3);
}

const tools = [{
  name: "Bash",
  description: "Run a shell command.",
  input_schema: { type: "object", properties: { command: { type: "string" } }, required: ["command"] },
}];
const messages = [{ role: "user", content: [{ type: "text", text: prompt }] }];

/** One streamed /v1/messages turn: its text and its tool calls. */
async function turn() {
  trace(`turn: ${messages.length} message(s)`);
  const res = await fetch(`${base}/v1/messages`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "anthropic-version": "2023-06-01",
      "x-api-key": process.env.ANTHROPIC_API_KEY ?? "",
      "user-agent": "claude-cli/2.1.295 (external, cli)",
    },
    body: JSON.stringify({ model: "claude-fake", max_tokens: 1024, stream: true, tools, messages }),
  });
  if (!res.ok) throw new Error(`model answered ${res.status}: ${await res.text()}`);
  const text = await res.text();
  const blocks = [];
  for (const chunk of text.split("\n\n")) {
    const data = chunk.split("\n").find((l) => l.startsWith("data: "));
    if (!data) continue;
    const ev = JSON.parse(data.slice(6));
    if (ev.type === "content_block_start") blocks[ev.index] = { ...ev.content_block, json: "" };
    else if (ev.type === "content_block_delta") {
      const b = blocks[ev.index];
      if (ev.delta.type === "text_delta") b.text = (b.text ?? "") + ev.delta.text;
      else if (ev.delta.type === "input_json_delta") b.json += ev.delta.partial_json;
    }
  }
  return blocks.filter(Boolean).map((b) => (b.type === "tool_use"
    ? { type: "tool_use", id: b.id, name: b.name, input: b.json ? JSON.parse(b.json) : {} }
    : { type: "text", text: b.text ?? "" }));
}

for (let i = 0; i < 16; i++) {
  const content = await turn();
  messages.push({ role: "assistant", content });
  const calls = content.filter((b) => b.type === "tool_use");
  if (calls.length === 0) {
    process.stdout.write(content.filter((b) => b.type === "text").map((b) => b.text).join("") + "\n");
    process.exit(0);
  }
  const results = calls.map((c) => {
    trace(`run: ${String(c.input.command ?? "")}`);
    const r = spawnSync("sh", ["-c", String(c.input.command ?? "")], { encoding: "utf8", timeout: 60_000 });
    trace(`exit: ${r.status} ${r.error ? r.error.message : ""}`);
    return { type: "tool_result", tool_use_id: c.id, content: `${r.stdout ?? ""}${r.stderr ?? ""}`.trimEnd() || "(no output)" };
  });
  messages.push({ role: "user", content: results });
}
process.stderr.write("fake-claude: too many turns\n");
process.exit(4);
