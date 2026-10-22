/**
 * transcript-unwrapped.test — the readers of the agents Mandu does not run
 * (arbiter/policy/transcript-unwrapped.ts;
 * docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §3 item 3, §4 phase 3):
 *
 * - against the record shapes of each agent's store with every value
 *   removed (test/fixtures/transcripts/gemini-0.65.0, gemini-0.29.7,
 *   copilot-1.0.101, made by scripts/transcript-shapes.mjs from stores
 *   written in each agent's own record shapes): every string field is
 *   marked, laid out where the agent keeps it, read through the store
 *   layer, and the fields a reader yields must be the ones the agent puts
 *   in its requests, never a local-only one (Gemini CLI's
 *   `displayContent`, `resultDisplay`, notices; Copilot CLI's
 *   `detailedContent`, its permission and info events);
 * - how each text got there, with literal records (an `@file`'s content,
 *   the session context, a person's own `!` command left out);
 * - each session's tool calls, how each ended, whether prompts were off;
 * - Cursor's chats counted, never read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  copilotActs, copilotSentTexts, countCursorChats, geminiActs, geminiSentTexts, isUnwrappedStoreFile, unwrappedItems, type UnwrappedKind,
} from "../../policy/transcript-unwrapped.js";
import { httpRequestsOf, isEnvDump, shellCommandsOf } from "../../policy/transcript-acts.js";
import { sqliteUriFilenames } from "../../policy/transcript-stores.js";
import { transcriptSources, type SentText, type SessionMeta, type TranscriptAgent } from "../../policy/transcript-scan.js";
import { SCAN_ONLY_AGENTS } from "../../src/generated/agents.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const FIXTURES = join(import.meta.dirname, "..", "fixtures", "transcripts");

function fixture(name: string): Array<Record<string, unknown>> {
  return readFileSync(join(FIXTURES, name), "utf8").split("\n").filter((l) => l !== "").map((l) => JSON.parse(l) as Record<string, unknown>);
}

/** A record's kind: its `type` (Gemini's message type, Copilot's event type). */
const kindOf = (r: Record<string, unknown>): string => (typeof r["type"] === "string" ? r["type"] : "");

/** Every "<text>" leaf replaced by a unique marker; `paths` maps each
 *  marker to its field's path, prefixed by the record's kind. */
function mark(records: Array<Record<string, unknown>>): { records: Array<Record<string, unknown>>; paths: Map<string, string> } {
  const paths = new Map<string, string>();
  let n = 0;
  const walk = (v: unknown, path: string): unknown => {
    if (Array.isArray(v)) return v.map((x) => walk(x, `${path}[]`));
    if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x, `${path}.${k}`)]));
    if (v !== "<text>") return v;
    const m = `MARK${++n}Z`;
    paths.set(m, path);
    return m;
  };
  return { records: records.map((r) => walk(r, kindOf(r)) as Record<string, unknown>), paths };
}

/** The texts the store layer yields for `records` laid out as `kind`
 *  keeps them (`legacy`: Gemini CLI's whole-file `.json`). */
async function readStore(kind: UnwrappedKind, agent: TranscriptAgent, records: Array<Record<string, unknown>>, legacy = false): Promise<SentText[]> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-unw-"));
  try {
    let root: string;
    if (kind === "gemini-chats") {
      root = join(dir, "tmp");
      mkdirSync(join(root, "shop", "chats"), { recursive: true });
      if (legacy) {
        const [header, ...messages] = records;
        writeFileSync(join(root, "shop", "chats", "session-2026-02-20T10-00-9d8c7b6a.json"), JSON.stringify({ ...header, messages }, null, 2));
      } else writeFileSync(join(root, "shop", "chats", "session-2026-10-20T09-00-3f2a9c1e.jsonl"), records.map((r) => JSON.stringify(r)).join("\n"));
    } else {
      root = join(dir, "session-state");
      mkdirSync(join(root, "s1"), { recursive: true });
      writeFileSync(join(root, "s1", "events.jsonl"), records.map((r) => JSON.stringify(r)).join("\n"));
    }
    const items = unwrappedItems({ agent, kind, root }, 1000, { n: 0 });
    assert.equal(items.length, 1, "the fixture is one session");
    return [...(await items[0]!.read()).texts];
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function reach(kind: UnwrappedKind, agent: TranscriptAgent, name: string, legacy = false): Promise<{ sent: Set<string>; unsent: Set<string> }> {
  const { records, paths } = mark(fixture(name));
  const yielded = (await readStore(kind, agent, records, legacy)).map((t) => t.text).join("\n");
  const sent = new Set<string>();
  const all = new Set<string>();
  for (const [m, p] of paths) {
    all.add(p);
    if (yielded.includes(m)) sent.add(p);
  }
  return { sent, unsent: new Set([...all].filter((p) => !sent.has(p))) };
}

const only = (sent: Set<string>, allowed: RegExp[], what: string): void => {
  for (const p of sent) assert.ok(allowed.some((re) => re.test(p)), `${what} yielded a field it does not send: ${p}`);
};

test("Gemini CLI 0.65 reader: only the fields Gemini CLI sends, over its chat file's record shapes", async () => {
  const { sent, unsent } = await reach("gemini-chats", "gemini", "gemini-0.65.0.jsonl");
  only(sent, [
    /^user\.content(?:\[\]\.text)?$/,
    /^user\.content\[\]\.functionResponse\.response\./,
    /^gemini\.content(?:\[\]\.text)?$/,
    /^gemini\.content\[\]\.functionCall\.args\./,
    /^gemini\.thoughts\[\]\.(?:subject|description)$/,
    /^gemini\.toolCalls\[\]\.args\./,
    /^gemini\.toolCalls\[\]\.result\[\]\.functionResponse\.response\./,
    /^\.\$patch\.updates\[\]\.content\[\]\.functionResponse\.response\./,
    /^\.\$set\.messages\[\]\.content\[\]\.text$/,
  ], "the Gemini CLI reader");
  for (const p of ["user.content[].text", "user.content[].functionResponse.response.output", "gemini.thoughts[].subject", "gemini.toolCalls[].args.command",
    "gemini.toolCalls[].result[].functionResponse.response.output", "gemini.content[].text", ".$patch.updates[].content[].functionResponse.response.output", ".$set.messages[].content[].text"]) {
    assert.ok(sent.has(p), `sent: ${p}`);
  }
  for (const p of ["user.displayContent[].text", "gemini.toolCalls[].resultDisplay", "gemini.toolCalls[].resultDisplay.originalContent", "gemini.toolCalls[].resultDisplay.newContent",
    "gemini.toolCalls[].description", "gemini.toolCalls[].displayName", "gemini.model", "info.content", "warning.content", "error.content", ".$set.summary", ".$set.memoryScratchpad.workflowSummary"]) {
    assert.ok(unsent.has(p), `local only, never read as sent: ${p}`);
  }
});

test("Gemini CLI 0.29 reader: the older whole-file chat, its messages inside", async () => {
  const { sent, unsent } = await reach("gemini-chats", "gemini", "gemini-0.29.7.jsonl", true);
  only(sent, [/^user\.content\[\]\.text$/, /^gemini\.content$/, /^gemini\.toolCalls\[\]\.args\./, /^gemini\.toolCalls\[\]\.result\[\]\.functionResponse\.response\./], "the Gemini CLI reader");
  for (const p of ["user.content[].text", "gemini.toolCalls[].result[].functionResponse.response.output", "gemini.content"]) assert.ok(sent.has(p), `sent: ${p}`);
  for (const p of ["gemini.toolCalls[].description", "gemini.toolCalls[].displayName", "info.content"]) assert.ok(unsent.has(p), `local only: ${p}`);
});

test("Copilot CLI reader: only the fields Copilot CLI sends, over its events' record shapes", async () => {
  const { sent, unsent } = await reach("copilot-events", "copilot", "copilot-1.0.101.jsonl");
  only(sent, [
    /^user\.message\.data\.(?:transformedContent|content)$/,
    /^assistant\.message\.data\.(?:content|reasoningText)$/,
    /^assistant\.message\.data\.toolRequests\[\]\.arguments\./,
    /^assistant\.reasoning\.data\.content$/,
    /^tool\.execution_complete\.data\.(?:result\.content|error\.message)$/,
    /^(?:system\.message|system\.notification|skill\.invoked)\.data\.content$/,
    /^session\.compaction_complete\.data\.summaryContent$/,
    /^session\.handoff\.data\.context$/,
  ], "the Copilot CLI reader");
  for (const p of ["user.message.data.transformedContent", "assistant.message.data.content", "assistant.message.data.toolRequests[].arguments.command", "tool.execution_complete.data.result.content",
    "tool.execution_complete.data.error.message", "system.message.data.content", "session.compaction_complete.data.summaryContent"]) assert.ok(sent.has(p), `sent: ${p}`);
  for (const p of ["tool.execution_complete.data.result.detailedContent", "tool.execution_complete.data.result.contents[].text", "assistant.message.data.reasoningOpaque", "assistant.message.data.encryptedContent",
    "assistant.message.data.toolRequests[].intentionSummary", "tool.execution_start.data.arguments.command", "tool.user_requested.data.arguments.command", "permission.requested.data.permissionRequest.fullCommandText",
    "session.info.data.message", "session.warning.data.message", "session.error.data.message", "hook.start.data.input", "session.handoff.data.summary", "user.message.data.attachments[].taggedFilesEntry"]) {
    assert.ok(unsent.has(p), `local only, never read as sent: ${p}`);
  }
});

test("Gemini CLI: how each text got there, an @file's content with its path, the session context, the provider and the project", () => {
  const meta: SessionMeta = {};
  const id = "run_shell_command__run_shell_command_1_0";
  const texts = [...geminiSentTexts([
    { sessionId: "s", projectHash: "h", startTime: "2026-10-20T09:00:00Z", kind: "subagent", directories: ["/home/u/shop"] },
    { id: "c", type: "user", timestamp: "2026-10-20T09:00:00Z", content: [{ text: "<session_context>\nok\n</session_context>" }] },
    { id: "u", type: "user", timestamp: "2026-10-20T09:00:01Z", content: [{ text: "look at @.env" }, { text: "\n--- Content from referenced files ---" }, { text: "\nContent from @/home/u/shop/.env:\n" }, { text: "KEY=attached" }, { text: "\n--- End of content ---" }], displayContent: "look at @.env (shown)" },
    { id: "g", type: "gemini", timestamp: "2026-10-20T09:00:02Z", model: "gemini-2.5-pro", content: "", toolCalls: [{ id, name: "run_shell_command", args: { command: "cat .env" }, status: "success", result: [{ functionResponse: { id: "run_shell_command_1_0", name: "run_shell_command", response: { output: "Output: KEY=printed" } } }], resultDisplay: "KEY=display-only" }] },
    { id: "u2", type: "user", timestamp: "2026-10-20T09:00:03Z", content: [{ functionResponse: { id: "run_shell_command_1_0", name: "run_shell_command", response: { output: "Output: KEY=again" } } }] },
    { id: "i", type: "info", content: "KEY=notice" },
  ], meta)];
  const by = (s: string): SentText | undefined => texts.find((t) => t.text.includes(s));
  assert.equal(by("<session_context>")?.how, "context");
  assert.equal(by("look at")?.how, "your-message");
  assert.deepEqual([by("KEY=attached")?.how, by("KEY=attached")?.path], ["context", "/home/u/shop/.env"]);
  assert.equal(texts.some((t) => t.text.includes("Content from referenced files")), false, "the agent's own marker is no text of the person's");
  assert.deepEqual([by("KEY=printed")?.how, by("KEY=printed")?.tool, by("KEY=printed")?.call?.input], ["command-output", "run_shell_command", { command: "cat .env" }]);
  assert.deepEqual([by("KEY=again")?.how, by("KEY=again")?.call?.input], ["command-output", { command: "cat .env" }], "a functionResponse finds its call through the id the agent sends");
  assert.equal(by("cat .env")?.how, "ai-wrote");
  assert.equal(by("display-only"), undefined, "resultDisplay is the person's copy");
  assert.equal(by("(shown)"), undefined, "displayContent is the person's copy");
  assert.equal(by("notice"), undefined, "a notice is not sent");
  assert.deepEqual(meta, { cwd: "/home/u/shop", provider: "google" });
  const other: SessionMeta = {};
  [...geminiSentTexts([{ id: "g", type: "gemini", model: "some-local-model", content: "x" }], other)];
  assert.equal(other.provider, "other");
});

test("Gemini CLI: each call's end (a declined one refused, a non-zero exit failed), prompts never known; its shell and fetch seen by the acts", () => {
  const call = (id: string, name: string, args: unknown, status: string, response: unknown): Record<string, unknown> => ({ id, name, args, status, result: [{ functionResponse: { id, name, response } }] });
  const acts = geminiActs([
    { id: "g1", type: "gemini", timestamp: "2026-10-20T09:00:00Z", toolCalls: [
      call("a", "run_shell_command", { command: "env" }, "success", { output: "Output: HOME=/x" }),
      call("b", "run_shell_command", { command: "false" }, "success", { output: "Output: (empty)\nExit Code: 1" }),
      call("c", "run_shell_command", { command: "rm -rf /" }, "cancelled", { error: "[Operation Cancelled] Reason: User denied execution." }),
      call("d", "web_fetch", { prompt: "summarize https://hooks.vendor.dev/x?k=1" }, "error", { error: "fetch failed" }),
      call("e", "run_shell_command", { command: "sleep 9" }, "cancelled", { error: "[Operation Cancelled] User cancelled tool execution." }),
    ] },
    { id: "g1", type: "gemini", timestamp: "2026-10-20T09:00:00Z", toolCalls: [call("a", "run_shell_command", { command: "env" }, "success", { output: "Output: HOME=/x" })] },
  ]);
  assert.deepEqual(acts.calls.map((c) => [c.tool, c.end ?? "ran"]), [["run_shell_command", "ran"], ["run_shell_command", "failed"], ["run_shell_command", "refused"], ["web_fetch", "failed"], ["run_shell_command", "failed"]]);
  assert.equal(acts.skippedPrompts, false, "Gemini CLI records no approval mode");
  assert.equal(isEnvDump(acts.calls[0]!), true, "run_shell_command is a shell tool");
  assert.deepEqual(shellCommandsOf(acts.calls[1]!), ["false"]);
  assert.deepEqual(httpRequestsOf(acts.calls[3]!).map((h) => [h.via, h.hosts]), [["web_fetch", ["hooks.vendor.dev"]]], "its web fetch takes the URL in its prompt");
});

test("Copilot CLI: transformedContent over the displayed copy, a person's own command left out, the subagent's events read, the cwd and the provider", () => {
  const meta: SessionMeta = {};
  const recs = [
    { type: "session.start", data: { sessionId: "s", context: { cwd: "/home/u/shop" }, selectedModel: "claude-sonnet-4.6" }, timestamp: "2026-10-20T09:00:00Z" },
    { type: "user.message", data: { content: "KEY=displayed", transformedContent: "<date/> KEY=transformed" }, timestamp: "2026-10-20T09:00:01Z" },
    { type: "assistant.message", data: { content: "ok", toolRequests: [{ toolCallId: "c1", name: "bash", arguments: { command: "cat .env" } }, { toolCallId: "c2", name: "view", arguments: { path: "/home/u/shop/.env" } }] }, timestamp: "2026-10-20T09:00:02Z" },
    { type: "tool.execution_complete", data: { toolCallId: "c1", success: true, result: { content: "KEY=printed\n<exited with exit code 0>", detailedContent: "KEY=detailed" } }, timestamp: "2026-10-20T09:00:03Z" },
    { type: "tool.execution_complete", data: { toolCallId: "c2", success: true, result: { content: "KEY=viewed" } }, timestamp: "2026-10-20T09:00:04Z" },
    { type: "tool.execution_complete", data: { toolCallId: "u1", success: true, isUserRequested: true, result: { content: "KEY=own-command" } } },
    { type: "assistant.message", agentId: "sub", data: { content: "KEY=subagent", parentToolCallId: "c1" } },
    { type: "session.info", data: { message: "KEY=info" } },
  ];
  const texts = [...copilotSentTexts(recs, meta)];
  const by = (s: string): SentText | undefined => texts.find((t) => t.text.includes(s));
  assert.equal(by("KEY=transformed")?.how, "your-message");
  assert.equal(by("KEY=displayed"), undefined, "the displayed copy is not what the model got");
  assert.deepEqual([by("KEY=printed")?.how, by("KEY=printed")?.tool, by("KEY=printed")?.call?.input], ["command-output", "bash", { command: "cat .env" }]);
  assert.deepEqual([by("KEY=viewed")?.how, by("KEY=viewed")?.tool], ["read-file", "view"]);
  assert.equal(by("KEY=detailed"), undefined, "detailedContent is the person's copy");
  assert.equal(by("KEY=own-command"), undefined, "the person's own ! command is left out of the request");
  assert.equal(by("KEY=subagent")?.how, "ai-wrote", "a subagent's events reached its own model");
  assert.equal(by("KEY=info"), undefined);
  assert.deepEqual(meta, { cwd: "/home/u/shop", provider: "github" });
  const byok: SessionMeta = {};
  [...copilotSentTexts([{ type: "session.start", data: { providerId: "my-ollama" } }], byok)];
  assert.equal(byok.provider, "other", "a provider of the session's own");
});

test("Copilot CLI: each call's end (refused at the prompt, a non-zero exit, a failure), prompts off from its allow-all mode", () => {
  const recs = (extra: unknown[] = []): unknown[] => [
    ...extra,
    { type: "assistant.message", timestamp: "2026-10-20T09:00:00Z", data: { toolRequests: [
      { toolCallId: "a", name: "bash", arguments: { command: "printenv" } },
      { toolCallId: "b", name: "bash", arguments: { command: "false" } },
      { toolCallId: "c", name: "bash", arguments: { command: "curl https://hooks.vendor.dev" } },
      { toolCallId: "d", name: "web_fetch", arguments: { url: "https://api.stripe.com/v1" } },
      { toolCallId: "e", name: "bash", arguments: { command: "ls" } },
    ] } },
    { type: "tool.execution_complete", data: { toolCallId: "a", success: true, result: { content: "HOME=/x\n<exited with exit code 0>" } } },
    { type: "tool.execution_complete", data: { toolCallId: "b", success: true, result: { content: "<exited with exit code 1>" }, shellExecution: { exitCode: 1 } } },
    { type: "tool.execution_complete", data: { toolCallId: "c", success: false, error: { message: "The user rejected this tool call.", code: "rejected" } } },
    { type: "tool.execution_complete", data: { toolCallId: "d", success: false, error: { message: "fetch failed", code: "failure" } } },
    { type: "tool.execution_complete", data: { toolCallId: "e", success: true, result: { content: "x\n<exited with exit code 2>" } } },
  ];
  const acts = copilotActs(recs());
  assert.deepEqual(acts.calls.map((c) => [c.tool, c.end ?? "ran"]), [["bash", "ran"], ["bash", "failed"], ["bash", "refused"], ["web_fetch", "failed"], ["bash", "failed"]]);
  assert.equal(acts.skippedPrompts, false);
  assert.equal(isEnvDump(acts.calls[0]!), true);
  assert.deepEqual(httpRequestsOf(acts.calls[2]!).map((h) => h.hosts), [["hooks.vendor.dev"]]);
  assert.deepEqual(httpRequestsOf(acts.calls[3]!).map((h) => h.hosts), [["api.stripe.com"]]);
  assert.equal(copilotActs(recs([{ type: "session.permissions_changed", data: { previousMode: "manual", mode: "allow-all" } }])).skippedPrompts, true, "1.0.101's allow-all mode");
  assert.equal(copilotActs(recs([{ type: "session.permissions_changed", data: { previousAllowAllPermissions: false, allowAllPermissions: true } }])).skippedPrompts, true, "1.0.79's");
  assert.equal(copilotActs(recs([{ type: "session.permissions_changed", data: { mode: "assisted" } }])).skippedPrompts, false);
});

test("the stores: each where the agent's own variables put it; a Gemini subagent with its parent; Copilot's linked older folder read once", async () => {
  const roots = (env: Record<string, string>): string[] => transcriptSources("/home/u", env).filter((s) => (SCAN_ONLY_AGENTS as readonly string[]).includes(s.agent)).map((s) => `${s.kind} ${s.root}`);
  assert.deepEqual(roots({}), [
    "gemini-chats /home/u/.gemini/tmp",
    "copilot-events /home/u/.copilot/session-state",
    "cursor-editor /home/u/.config/Cursor/User/globalStorage/state.vscdb",
    "cursor-editor /home/u/.config/cursor/User/globalStorage/state.vscdb",
    "cursor-editor /home/u/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
    "cursor-cli /home/u/.cursor/chats",
  ]);
  assert.deepEqual(roots({ GEMINI_CLI_HOME: "/g", COPILOT_HOME: "/c", XDG_STATE_HOME: "/s", XDG_CONFIG_HOME: "/x", CURSOR_CONFIG_DIR: "/cc" }), [
    "gemini-chats /g/.gemini/tmp",
    "copilot-events /c/session-state",
    "copilot-events /s/.copilot/session-state",
    "cursor-editor /x/Cursor/User/globalStorage/state.vscdb",
    "cursor-editor /x/cursor/User/globalStorage/state.vscdb",
    "cursor-editor /home/u/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
    "cursor-cli /cc/chats",
  ]);
  assert.equal(roots({ XDG_CONFIG_HOME: "/x" }).at(-1), "cursor-cli /x/cursor/chats");
  assert.equal(roots({ GEMINI_CLI_HOME: "relative" })[0], "gemini-chats /home/u/.gemini/tmp", "a relative variable is ignored");
  assert.ok(isUnwrappedStoreFile("gemini-chats", "/g/tmp", "/g/tmp/shop/chats/session-1.jsonl"));
  assert.ok(isUnwrappedStoreFile("gemini-chats", "/g/tmp", "/g/tmp/shop/chats/9d8c7b6a-1/sub.jsonl"));
  assert.ok(!isUnwrappedStoreFile("gemini-chats", "/g/tmp", "/g/tmp/shop/logs.json"));
  assert.ok(isUnwrappedStoreFile("copilot-events", "/c/s", "/c/s/abc/events.jsonl") && isUnwrappedStoreFile("copilot-events", "/c/s", "/c/s/abc.jsonl"));
  assert.ok(isUnwrappedStoreFile("cursor-cli", "/c/chats", "/c/chats/h/id/store.db") && !isUnwrappedStoreFile("cursor-cli", "/c/chats", "/c/chats/h/id/meta.json"));

  const dir = mkdtempSync(join(tmpdir(), "mdu-unw-st-"));
  try {
    // Gemini CLI: two projects, one by its marker, one an older hash folder
    // named in projects.json; a subagent's chat under its parent's id.
    const tmp = join(dir, ".gemini", "tmp");
    mkdirSync(join(tmp, "shop", "chats", "9d8c7b6a-1111-4222-8333-444455556666"), { recursive: true });
    writeFileSync(join(tmp, "shop", ".project_root"), "/home/u/shop\n");
    writeFileSync(join(tmp, "shop", "chats", "session-2026-10-20T09-00-9d8c7b6a.jsonl"), `${JSON.stringify({ sessionId: "9d8c7b6a-1111-4222-8333-444455556666", projectHash: "h" })}\n`);
    writeFileSync(join(tmp, "shop", "chats", "9d8c7b6a-1111-4222-8333-444455556666", "sub-1.jsonl"), `${JSON.stringify({ sessionId: "sub-1", projectHash: "h", kind: "subagent" })}\n`);
    writeFileSync(join(tmp, "shop", "logs.json"), "[]");
    const hash = createHash("sha256").update("/home/u/old").digest("hex");
    mkdirSync(join(tmp, hash, "chats"), { recursive: true });
    writeFileSync(join(tmp, hash, "chats", "session-2026-01-01T09-00-aaaaaaaa.json"), JSON.stringify({ sessionId: "a", messages: [] }));
    writeFileSync(join(dir, ".gemini", "projects.json"), JSON.stringify({ projects: { "/home/u/shop": "shop", "/home/u/old": "old" } }));
    const g = unwrappedItems({ agent: "gemini", kind: "gemini-chats", root: tmp }, 100, { n: 0 });
    assert.equal(g.length, 3, "two chats and a subagent's, never logs.json");
    assert.equal(new Set(g.map((i) => i.session)).size, 2, "the subagent counts with its parent");
    const cwds = await Promise.all(g.map(async (i) => (await i.read()).meta.cwd));
    assert.deepEqual([...new Set(cwds)].sort(), ["/home/u/old", "/home/u/shop"], "the project from its marker, or the path whose hash names the folder");
    // Copilot CLI: a session folder, an older flat file, and the older XDG folder linked to the new one.
    const cs = join(dir, ".copilot", "session-state");
    mkdirSync(join(cs, "s1"), { recursive: true });
    writeFileSync(join(cs, "s1", "events.jsonl"), "{}\n");
    writeFileSync(join(cs, "s0.jsonl"), "{}\n");
    writeFileSync(join(cs, "s1", "workspace.yaml"), "cwd: /x\n");
    mkdirSync(join(dir, "state", ".copilot"), { recursive: true });
    symlinkSync(cs, join(dir, "state", ".copilot", "session-state"));
    assert.equal(unwrappedItems({ agent: "copilot", kind: "copilot-events", root: cs }, 100, { n: 0 }).length, 2);
    assert.equal(unwrappedItems({ agent: "copilot", kind: "copilot-events", root: join(dir, "state", ".copilot", "session-state") }, 100, { n: 0 }).length, 0, "a linked folder is read once, as the other source");
    const over = { n: 0 };
    assert.equal(unwrappedItems({ agent: "copilot", kind: "copilot-events", root: cs }, 1, over).length, 1);
    assert.equal(over.n, 1, "past the cap: counted");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Cursor: its chats counted, never read: the editor's composerData keys (no value), the CLI's store files; nothing changed", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-unw-cur-"));
  try {
    // A running editor's database: WAL in use, the writer open (every Node the scan supports reads it).
    const vscdb = join(dir, "state.vscdb");
    const db = new DatabaseSync(vscdb);
    db.exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;");
    db.exec("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB); CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);");
    const put = db.prepare("INSERT INTO cursorDiskKV VALUES (?, ?)");
    for (const k of ["composerData:a", "composerData:b", "composerData:c", "bubbleId:a:1", "composerDataX", "composerdata:z", "agentKv:q"]) put.run(k, Buffer.from("{}"));
    const before = [readFileSync(vscdb), readFileSync(`${vscdb}-wal`)];
    assert.equal(countCursorChats("cursor-editor", vscdb), 3, "the exact composerData: prefix");
    assert.deepEqual([readFileSync(vscdb), readFileSync(`${vscdb}-wal`)], before, "the database and its WAL are as they were");
    db.close();
    // A stopped editor's: read immutable where this Node can (22.15 and later), else said unreadable.
    assert.equal(countCursorChats("cursor-editor", vscdb), sqliteUriFilenames() ? 3 : null);
    assert.equal(countCursorChats("cursor-editor", join(dir, "none.vscdb")), 0);
    writeFileSync(join(dir, "bad.vscdb"), "not a database");
    assert.equal(countCursorChats("cursor-editor", join(dir, "bad.vscdb")), null, "one that cannot be read is said");
    const chats = join(dir, "chats");
    for (const [h, c] of [["h1", "c1"], ["h1", "c2"], ["h2", "c3"]] as const) {
      mkdirSync(join(chats, h, c), { recursive: true });
      const s = new DatabaseSync(join(chats, h, c, "store.db"));
      s.exec("CREATE TABLE blobs (id TEXT PRIMARY KEY, data BLOB); CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);");
      s.close();
    }
    mkdirSync(join(chats, "h2", "empty"), { recursive: true });
    assert.equal(countCursorChats("cursor-cli", chats), 3);
    assert.equal(countCursorChats("cursor-cli", join(dir, "nochats")), 0);
    assert.deepEqual(unwrappedItems({ agent: "cursor", kind: "cursor-cli", root: chats }, 100, { n: 0 }), [], "no Cursor session is ever read");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
