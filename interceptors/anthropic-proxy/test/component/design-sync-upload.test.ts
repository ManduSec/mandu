/**
 * design-sync-upload (proxy e2e) — Claude Code 2.1.292's DesignSync uploads
 * local files to claude.ai by `localPath`, their bytes never entering the
 * model context (supported-agents.md §2). Through the REAL AnthropicProxy
 * with a mock upstream replaying DesignSync tool_use blocks in the captured
 * 2.1.292 shape and a mock arbiter answering Claude Code's gate surface:
 *
 *   plan        finalize_plan with an absolute localDir reaches the agent
 *               unchanged; without one (or relative) the agent receives a
 *               refusal DesignSync's schema rejects;
 *   upload      write_files whose `localPath` (relative to the plan) names a
 *               file the arbiter holds reaches the agent as the refusal: no
 *               `files`, no `localPath`, nothing for the tool to read or
 *               send; the fs_action event names the rule and the Approvals
 *               row; next turn the model reads its own call back and the
 *               gate's notice in place of the tool's validation error;
 *   ordinary    a clean file passes unchanged;
 *   fail-closed an arbiter that cannot judge an upload refuses it;
 *   control     a surface whose upload table is empty does not refuse the
 *               call whole (the table entry is what does), but since
 *               2026-10-17 the unmapped leg (unmapped-upload.ts) still
 *               withholds the secret path; before, it went out unchanged.
 *   window      an upload after a Bash call of the same turn is refused
 *               (the Bash runs first and may change the file judged).
 *
 * The interactive Artifact tools (2026-10-09, supported-agents.md §2,
 * "Claude Code 2.1.295"), the same way: an Artifact publish naming a held
 * supporting file is refused whole and the model reads the notice next
 * turn; a page path relative to the working directory is refused with how
 * to call it; an ArtifactData batch from a held local JSON file is refused;
 * an ordinary publish and a comment reply pass; fail-closed and control.
 *
 * The real-arbiter versions (a registered .env, the real upload gate) are
 * tests/stack/design-sync-upload.test.ts and tests/stack/artifact-upload.test.ts.
 *
 * Axes: `secrets`, stated through the mock (the upload gate's answers are
 * the confidentiality axis's).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy, type UpstreamFetcher } from "../../src/proxy.js";
import { REFUSED_ID_PREFIX } from "../../src/dispatch.js";
import { CLAUDE_CODE_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../src/sse-parser.js";
import type { FileUploadDecision, FileUploadDecisionRequest } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildToolUseSse, buildTextSse, sseEvent } from "../helpers/mock-upstream.js";

const CLAUDE: GateSurface = { ...CLAUDE_CODE_GATE_SURFACE };
const NO_UPLOAD: GateSurface = { ...CLAUDE_CODE_GATE_SURFACE, upload: {} };
const BUNDLE = "/ws/app/ds-bundle";
const SECRET = "/ws/app/.env";

const HOLD = (req: FileUploadDecisionRequest): FileUploadDecision =>
  req.path === SECRET
    ? { allow: false, requiresApproval: true, reason: `'${SECRET}' is a secret file (no-model) and no rule lets it go to claude.ai`, ruleRef: { source: "rule", id: "fs:upload-secret-file" }, approvalId: "egr-3" }
    : { allow: true, reason: "clean", ruleRef: { source: "rule", id: "fs:upload-clean" } };

function post(port: number, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": "ds-1" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve(buf));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function toolUsesOf(sse: string): ReconstructedToolUse[] {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sse);
  p.end();
  return seen;
}

/** One proxy, the upstream answering each request with the next body. */
async function session(
  surface: GateSurface,
  bodies: string[],
  run: (send: (messages: unknown[]) => Promise<ReconstructedToolUse[]>, arbiter: MockArbiter, upstream: MockUpstream[]) => Promise<void>,
  decide: ((r: FileUploadDecisionRequest) => FileUploadDecision) | null = HOLD,
): Promise<void> {
  const arbiter = new MockArbiter({
    gateSurfaceFn: () => surface,
    // integrity OFF (secrets): a tool result is not masked for its trust
    classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" }),
    ...(decide ? { fileUploadDecisionFn: decide } : {}),
  });
  // the value backstop a notice passes before it replaces a result
  (arbiter as unknown as { scanSecretValues: unknown }).scanSecretValues = async () => ({ hits: [] });
  const ups = bodies.map((sse) => new MockUpstream({ sse }));
  let i = 0;
  const fetcher: UpstreamFetcher = (args) => ups[Math.min(i++, ups.length - 1)]!.fetcher(args);
  const proxy = new AnthropicProxy({ arbiter, upstream: fetcher, sessionKey: "ds-1", log: () => {} });
  const port = await proxy.listen(0);
  try {
    await run(async (messages) => toolUsesOf(await post(port, JSON.stringify({ model: "m", stream: true, messages }))), arbiter, ups);
  } finally {
    await proxy.close();
  }
}

const finalize = (localDir?: string) => ({
  method: "finalize_plan", projectId: "proj-1", writes: ["components/**"], ...(localDir !== undefined ? { localDir } : {}),
});
const writeFiles = (files: unknown[]) => ({ method: "write_files", projectId: "proj-1", planId: "plan-9", files });
const refused = (input: Record<string, unknown>): boolean =>
  Object.keys(input).length === 1 && String(input["action"]).startsWith(REFUSED_ID_PREFIX);

const GO = [{ role: "user", content: "/design-sync push the button component" }];

test("plan then upload: a secret localPath relative to the plan is refused whole; the event names the rule and the Approvals row", async () => {
  const plan = finalize(BUNDLE);
  const upload = writeFiles([
    { path: "components/button/index.html", localPath: "button/index.html" },
    { path: "components/button/env.txt", localPath: "../.env" },
  ]);
  await session(CLAUDE, [buildToolUseSse({ id: "tu_plan", name: "DesignSync", input: plan }), buildToolUseSse({ id: "tu_up", name: "DesignSync", input: upload })], async (send, arbiter) => {
    const [p] = await send(GO);
    assert.deepEqual(p!.input, plan, "an absolute plan reaches the agent unchanged");
    const history = [
      ...GO,
      { role: "assistant", content: [{ type: "tool_use", id: "tu_plan", name: "DesignSync", input: plan }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_plan", content: '{"planId":"plan-9"}' }] },
    ];
    const [u] = await send(history);
    const got = u!.input as Record<string, unknown>;
    assert.ok(refused(got), `refused whole: ${JSON.stringify(got)}`);
    assert.ok(!JSON.stringify(got).includes("localPath"), "no path is left for the tool to read");
    assert.match(String(got["action"]), /mandu-upload-gate: upload refused, nothing was sent/);
    assert.deepEqual(arbiter.fileUploadDecisionCalls.map((c) => [c.path, c.destination, c.tool]), [
      [`${BUNDLE}/button/index.html`, "claude.ai", "DesignSync"],
      [SECRET, "claude.ai", "DesignSync"],
    ]);
    const ev = arbiter.emittedEvents.find((e) => e.kind === "fs_action" && e.callId === "tu_up");
    assert.ok(ev, "an fs_action event for the held upload");
    const pol = (ev as unknown as { policy: { usage: string; ruleRef?: { id: string }; approvalId?: string } }).policy;
    assert.equal(pol.usage, "needs_approval");
    assert.equal(pol.ruleRef?.id, "fs:upload-secret-file");
    assert.equal(pol.approvalId, "egr-3");
  });
});

test("next turn: the model reads its own call back and the gate's notice in place of the tool's validation error", async () => {
  const plan = finalize(BUNDLE);
  const upload = writeFiles([{ path: "components/env.txt", localPath: "../.env" }]);
  await session(CLAUDE, [
    buildToolUseSse({ id: "tu_plan", name: "DesignSync", input: plan }),
    buildToolUseSse({ id: "tu_up", name: "DesignSync", input: upload }),
    buildTextSse("ok"),
  ], async (send, _arbiter, ups) => {
    await send(GO);
    const h1 = [
      ...GO,
      { role: "assistant", content: [{ type: "tool_use", id: "tu_plan", name: "DesignSync", input: plan }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_plan", content: '{"planId":"plan-9"}' }] },
    ];
    const [u] = await send(h1);
    // Claude Code echoes the call it received and its schema's rejection
    await send([
      ...h1,
      { role: "assistant", content: [{ type: "tool_use", id: "tu_up", name: "DesignSync", input: u!.input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_up", is_error: true, content: "<tool_use_error>InputValidationError: DesignSync failed: unrecognized key 'action'; required: method</tool_use_error>" }] },
    ]);
    const seen = ups[2]!.requests[0]!.bodyText;
    assert.match(seen, /mandu-upload-gate: upload refused, nothing was sent/, "the notice replaces the result");
    assert.ok(!seen.includes("InputValidationError"), "the tool's own error is not forwarded");
    assert.ok(seen.includes("../.env"), "the model's own call is restored in its history");
    assert.ok(!seen.includes(REFUSED_ID_PREFIX + "mandu-upload-gate"), "not the refusal it never wrote");
  });
});

test("a plan without an absolute localDir is refused, with how to call it; the upload that follows (no plan seen) is refused too", async () => {
  await session(CLAUDE, [
    buildToolUseSse({ id: "tu_p", name: "DesignSync", input: finalize() }),
    buildToolUseSse({ id: "tu_r", name: "DesignSync", input: finalize("ds-bundle") }),
    buildToolUseSse({ id: "tu_u", name: "DesignSync", input: writeFiles([{ path: "a.html", localPath: "a.html" }]) }),
  ], async (send, arbiter) => {
    for (let k = 0; k < 2; k++) {
      const [p] = await send(GO);
      assert.ok(refused(p!.input as Record<string, unknown>));
      assert.match(String((p!.input as Record<string, unknown>)["action"]), /localDir set to the absolute path/);
    }
    const [u] = await send(GO);
    assert.ok(refused(u!.input as Record<string, unknown>));
    assert.match(String((u!.input as Record<string, unknown>)["action"]), /finalize_plan again/);
    assert.equal(arbiter.fileUploadDecisionCalls.length, 0, "nothing could be placed, nothing was asked");
  });
});

test("an ordinary file passes unchanged; the read methods pass", async () => {
  const upload = writeFiles([{ path: "components/button/index.html", localPath: "/ws/app/ds-bundle/button/index.html" }, { path: "readme.md", data: "# Buttons" }]);
  await session(CLAUDE, [
    buildToolUseSse({ id: "tu_u", name: "DesignSync", input: upload }),
    buildToolUseSse({ id: "tu_l", name: "DesignSync", input: { method: "list_files", projectId: "proj-1" } }),
  ], async (send) => {
    const [u] = await send(GO);
    assert.deepEqual(u!.input, upload);
    const [l] = await send(GO);
    assert.deepEqual(l!.input, { method: "list_files", projectId: "proj-1" });
  });
});

test("FAIL-CLOSED: an arbiter that cannot judge an upload refuses it", async () => {
  const upload = writeFiles([{ path: "a.html", localPath: "/ws/app/ds-bundle/a.html" }]);
  await session(CLAUDE, [buildToolUseSse({ id: "tu_u", name: "DesignSync", input: upload })], async (send) => {
    const [u] = await send(GO);
    assert.ok(refused(u!.input as Record<string, unknown>));
    assert.match(String((u!.input as Record<string, unknown>)["action"]), /could not check the file/);
  }, null);
});

test("CONTROL: with no upload table the unmapped leg still withholds the secret path (before 2026-10-17 the call went out unchanged)", async () => {
  const upload = writeFiles([{ path: "env.txt", localPath: SECRET }]);
  await session(NO_UPLOAD, [buildToolUseSse({ id: "tu_u", name: "DesignSync", input: upload })], async (send, arbiter) => {
    const [u] = await send(GO);
    const got = u!.input as { files: Array<{ path: string; localPath: string }> };
    // the table entry is what refuses the call WHOLE; without it the unmapped
    // leg (unmapped-upload.ts) asks in the unmapped form, with no host, and
    // the held path becomes one that names no file
    assert.ok(!refused(got as unknown as Record<string, unknown>), "not the mapped leg's whole refusal");
    assert.equal(got.files[0]!.localPath, `/mandu/denied/upload${SECRET}`);
    assert.ok(!JSON.stringify(got).includes(`"${SECRET}"`), "the secret path is gone");
    assert.deepEqual(arbiter.fileUploadDecisionCalls.map((c) => [c.path, c.destination, c.unmapped]), [[SECRET, "", true]]);
  });
});

// ── the interactive Artifact tools (supported-agents.md §2, "Claude Code
//    2.1.295"; the captured shapes: arbiter/test/fixtures/
//    claude-artifact-tools-2026-10-09.json) ──────────────────────────────────

const PUBLISH = [{ role: "user", content: "publish the report as an artifact" }];

test("Artifact publish: a secret supporting file refuses the whole call (event, Approvals row); the model reads the notice next turn", async () => {
  const call = { file_path: "/ws/app/report.html", root: "/ws/app", files: { "data/env.txt": ".env", "app.js": "app.js" }, icon: "chart" };
  await session(CLAUDE, [buildToolUseSse({ id: "tu_a", name: "Artifact", input: call }), buildTextSse("ok")], async (send, arbiter, ups) => {
    const [a] = await send(PUBLISH);
    const got = a!.input as Record<string, unknown>;
    assert.ok(refused(got), `refused whole: ${JSON.stringify(got)}`);
    assert.ok(!("file_path" in got) && !("files" in got), "no path is left for the tool to read");
    assert.deepEqual(arbiter.fileUploadDecisionCalls.map((c) => [c.path, c.destination, c.tool]), [
      ["/ws/app/report.html", "claude.ai", "Artifact"],
      [SECRET, "claude.ai", "Artifact"],
      ["/ws/app/app.js", "claude.ai", "Artifact"],
    ]);
    const ev = arbiter.emittedEvents.find((e) => e.kind === "fs_action" && e.callId === "tu_a");
    const pol = (ev as unknown as { policy: { usage: string; ruleRef?: { id: string }; approvalId?: string } }).policy;
    assert.equal(pol.usage, "needs_approval");
    assert.equal(pol.ruleRef?.id, "fs:upload-secret-file");
    assert.equal(pol.approvalId, "egr-3");
    // Claude Code echoes the refused call and its schema's rejection (action is an enum)
    await send([
      ...PUBLISH,
      { role: "assistant", content: [{ type: "tool_use", id: "tu_a", name: "Artifact", input: got }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_a", is_error: true, content: "<tool_use_error>InputValidationError: Artifact failed: action: Invalid enum value</tool_use_error>" }] },
    ]);
    const seen = ups[1]!.requests[0]!.bodyText;
    assert.match(seen, /mandu-upload-gate: upload refused, nothing was sent/, "the notice replaces the result");
    assert.ok(!seen.includes("InputValidationError"));
    assert.ok(seen.includes("report.html"), "the model's own call is restored in its history");
  });
});

test("Artifact: a page path relative to the working directory is refused with how to call it; nothing is asked", async () => {
  await session(CLAUDE, [buildToolUseSse({ id: "tu_r", name: "Artifact", input: { file_path: "report.html", icon: "doc" } })], async (send, arbiter) => {
    const [a] = await send(PUBLISH);
    const got = a!.input as Record<string, unknown>;
    assert.ok(refused(got));
    assert.match(String(got["action"]), /Call Artifact again with the absolute path of the file\. \(rule: proxy:upload-relative-path\)/);
    assert.equal(arbiter.fileUploadDecisionCalls.length, 0);
  });
});

test("ArtifactData: a batch write from a secret local JSON file is refused; an ordinary publish and a comment reply pass unchanged", async () => {
  const batch = { action: "batch", url: "https://claude.ai/artifact/a1", writes: [{ op: "set", collection: "rows", doc_id: "r1", file_path: SECRET }] };
  const page = { file_path: "/ws/app/report.html", icon: "chart" };
  const reply = { action: "reply", url: "https://claude.ai/artifact/a1", thread_id: "t1", text: "Done: the totals are fixed." };
  await session(CLAUDE, [
    buildToolUseSse({ id: "tu_b", name: "ArtifactData", input: batch }),
    buildToolUseSse({ id: "tu_p", name: "Artifact", input: page }),
    buildToolUseSse({ id: "tu_c", name: "ArtifactComments", input: reply }),
  ], async (send) => {
    const [b] = await send(PUBLISH);
    assert.ok(refused(b!.input as Record<string, unknown>));
    const [p] = await send(PUBLISH);
    assert.deepEqual(p!.input, page);
    const [c] = await send(PUBLISH);
    assert.deepEqual(c!.input, reply);
  });
});

test("FAIL-CLOSED / CONTROL: Artifact with an arbiter that cannot judge is refused; with no upload table the unmapped leg withholds the secret page", async () => {
  const call = { file_path: SECRET };
  await session(CLAUDE, [buildToolUseSse({ id: "tu_f", name: "Artifact", input: call })], async (send) => {
    const [a] = await send(PUBLISH);
    assert.ok(refused(a!.input as Record<string, unknown>));
  }, null);
  await session(NO_UPLOAD, [buildToolUseSse({ id: "tu_n", name: "Artifact", input: call })], async (send, arbiter) => {
    const [a] = await send(PUBLISH);
    assert.deepEqual(a!.input, { file_path: `/mandu/denied/upload${SECRET}` }, "before 2026-10-17 it went out unchanged");
    assert.deepEqual(arbiter.fileUploadDecisionCalls.map((c) => [c.path, c.unmapped]), [[SECRET, true]]);
  });
  // and an unmapped tool with no arbiter answer withholds every path (fail-closed)
  await session(NO_UPLOAD, [buildToolUseSse({ id: "tu_x", name: "Artifact", input: call })], async (send) => {
    const [a] = await send(PUBLISH);
    assert.deepEqual(a!.input, { file_path: `/mandu/denied/upload${SECRET}` });
  }, () => { throw new Error("mock arbiter: the service is down"); });
});

// ── THE WINDOW (2026-10-17; upload-gate.ts priorWriter): the agent runs a
//    turn's calls in order, so a Bash before the upload in the SAME message
//    runs first and can put a secret into the file the gate judged clean
//    (`cp ~/notes.txt report.html`, then the publish). Refused, nothing asked.

/** One assistant message with several tool_use blocks, in order. */
function callsSse(calls: Array<{ id: string; name: string; input: Record<string, unknown> }>): string {
  let out = sseEvent("message_start", { type: "message_start", message: { id: "msg_w", role: "assistant", content: [] } });
  calls.forEach((c, index) => {
    out += sseEvent("content_block_start", { type: "content_block_start", index, content_block: { type: "tool_use", id: c.id, name: c.name, input: {} } });
    out += sseEvent("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(c.input) } });
    out += sseEvent("content_block_stop", { type: "content_block_stop", index });
  });
  out += sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } });
  out += sseEvent("message_stop", { type: "message_stop" });
  return out;
}

test("WINDOW: an upload after a Bash of the same turn is refused (nothing asked); after a Read it is judged as usual; alone, next turn, it goes", async () => {
  const page = { file_path: "/ws/app/report.html", icon: "chart" };
  const bash = { command: "cp ~/notes.txt /ws/app/report.html" };
  await session(CLAUDE, [
    callsSse([{ id: "tu_b", name: "Bash", input: bash }, { id: "tu_p", name: "Artifact", input: page }]),
    callsSse([{ id: "tu_r", name: "Read", input: { file_path: "/ws/app/notes.md" } }, { id: "tu_q", name: "Artifact", input: page }]),
    callsSse([{ id: "tu_s", name: "Artifact", input: page }]),
  ], async (send, arbiter) => {
    const [, p] = await send(PUBLISH);
    assert.equal(p!.name, "Artifact");
    const got = p!.input as Record<string, unknown>;
    assert.ok(refused(got), `refused whole: ${JSON.stringify(got)}`);
    assert.match(String(got["action"]), /rule: proxy:upload-after-write/);
    assert.match(String(got["action"]), /Bash/);
    assert.equal(arbiter.fileUploadDecisionCalls.length, 0, "refused before anything is asked");
    const [, q] = await send(PUBLISH);
    assert.deepEqual(q!.input, page, "a Read writes nothing: the upload is judged as usual");
    assert.equal(arbiter.fileUploadDecisionCalls.length, 1);
    const [s] = await send(PUBLISH);
    assert.deepEqual(s!.input, page, "on its own, the next turn, it goes");
  });
});
