/**
 * path-denial-notice.test.ts (e2e) — a Read the sensitive-path gate denied
 * explains itself to the model, through the REAL proxy data path
 * (confidentiality plan 10 §11.8, "Path denials"; fs-sync.md §1.4.1).
 *
 * Turn 1: the model reads ~/.ssh/id_rsa and a workspace file; the key's path
 * becomes the /mandu/denied sentinel. Turn 2: Claude Code's error for the
 * sentinel (carrying a stand-in for program bytes) and the workspace file's
 * content come back. The denied call's result is REPLACED by Mandu's notice;
 * the allowed call's result takes the classify path as before. The mock
 * classify calls everything `no-model`, as the real path scan calls a
 * sentinel ending in `id_rsa`.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AnthropicProxy } from "../../src/proxy.js";
import { ViewMap } from "../../src/view-map.js";
import { DENIED_NAMESPACE } from "../../src/fs-gate.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../src/sse-parser.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildToolUseSse } from "../helpers/mock-upstream.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";
const SSH_KEY = "/home/u/.ssh/id_rsa";
/** A test-only stand-in for bytes a tool might add (not a real credential). */
const PROGRAM_BYTES = "FIXTURE-PROGRAM-OUTPUT-7f3a";

const secretEverything = (): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "integrity axis OFF — trust classification disabled", confidentiality: "no-model",
});

async function post(port: number, messages: unknown[]): Promise<string> {
  const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "claude-opus-4", stream: true, messages }),
  });
  assert.equal(res.status, 200);
  return res.text();
}

test("a Read whose path the fs gate denied: the model reads Mandu's notice in place of the tool's error; an allowed Read is classified as before", async () => {
  const arbiter = new MockArbiter({
    classifyFn: secretEverything,
    scanSecretValuesFn: () => ({ hits: [] }),
    fsPathDecisionFn: (req) =>
      req.workspaceRoots.some((r) => req.path.startsWith(r + "/"))
        ? { allow: true, reason: "inside workspace root" }
        : { allow: false, requiresApproval: false, reason: "sensitive path: ~/.ssh is never read by an agent", ruleRef: { source: "rule", id: "fs:sensitive" } },
  });
  const upstream = new MockUpstream({
    sse:
      buildToolUseSse({ id: "tu_ws", name: "Read", input: { file_path: `${HUMAN}/notes.md` }, index: 0 }) +
      buildToolUseSse({ id: "tu_ssh", name: "Read", input: { file_path: SSH_KEY }, index: 1 }),
  });
  const viewMap = new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, viewMap, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const seen: ReconstructedToolUse[] = [];
    const p = new SseToolUseParser((tu) => seen.push(tu));
    p.feed(await post(port, [{ role: "user", content: "read the key and the notes" }]));
    p.end();
    const delivered = new Map(seen.map((t) => [t.id, t.input as { file_path: string }]));
    assert.equal(delivered.get("tu_ssh")!.file_path, `${DENIED_NAMESPACE}/policy${SSH_KEY}`);

    await post(port, [
      { role: "user", content: "read the key and the notes" },
      { role: "assistant", content: [
        { type: "tool_use", id: "tu_ws", name: "Read", input: delivered.get("tu_ws") },
        { type: "tool_use", id: "tu_ssh", name: "Read", input: delivered.get("tu_ssh") },
      ] },
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "tu_ws", content: "     1\tthe notes\n" },
        { type: "tool_result", tool_use_id: "tu_ssh", content: `<tool_use_error>File does not exist. ${PROGRAM_BYTES}</tool_use_error>`, is_error: true },
      ] },
    ]);
    const body = upstream.requests[1]!.json() as { messages: Array<{ content: unknown }> };
    const results = new Map((body.messages[2]!.content as Array<{ tool_use_id: string; content: unknown }>).map((b) => [b.tool_use_id, String(b.content)]));
    const denied = results.get("tu_ssh")!;
    assert.match(denied, /^mandu-fs-gate: denied, nothing was read or written: Mandu rules do not allow this tool to use this path/);
    assert.ok(denied.includes(`path: ${SSH_KEY} (Read.file_path)`), denied);
    assert.ok(denied.includes("detail: sensitive path: ~/.ssh is never read by an agent"));
    assert.ok(!denied.includes(PROGRAM_BYTES) && !denied.includes("File does not exist"), "no byte of the tool's output is forwarded");
    assert.ok(!upstream.requests[1]!.bodyText.includes(PROGRAM_BYTES), "nowhere on the wire");
    assert.match(results.get("tu_ws")!, /^\$MDU:/, "the allowed Read takes the classify path, as before");
  } finally {
    await proxy.close();
  }
});
