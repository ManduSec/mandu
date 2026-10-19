/**
 * reply-media — OpenClaw attaches the files a `MEDIA:` line of the model's
 * own reply names (reply-media.ts; supported-agents.md §2.1, "Files named in
 * the reply"). Pure and over a fake arbiter:
 *   - the grammar: every reference OpenClaw 2026.7.1 or 2026.9.9 reads off a
 *     directive line is among the references judged (the fixture's cases,
 *     read from both dists); a line start that may still become a directive;
 *   - the plan: a canonical line is judged, every other place a directive
 *     could form after OpenClaw's sanitizers is neutralized (its colon);
 *   - the judgment: a held file replaces the line with a notice and is asked
 *     with no host; a clean one passes; a relative path without a base, the
 *     media store, a response that also calls a tool, an arbiter that throws
 *     or lacks the op hold (fail-closed);
 *   - the stream (reply-media-stream.ts): a directive split across deltas is
 *     never half out, text before it streams, the held rest is rewritten as
 *     one delta, and a reply with no directive is relayed byte for byte.
 *
 * Axes: `secrets`, stated through the fake arbiter (the upload gate's
 * answers are the confidentiality axis's).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  gateReplyTexts,
  judgeMediaLine,
  mediaLineState,
  openclawMediaRefs,
  placeReplyRef,
  planReplyMedia,
  MEDIA_COLON_NEUTRAL,
  REPLY_MEDIA_MARKER,
  REPLY_MEDIA_TOOL,
  type ReplyMediaOptions,
} from "../../src/reply-media.js";
import {
  ANTHROPIC_WIRE,
  CHAT_WIRE,
  RESPONSES_WIRE,
  ReplyMediaFilter,
  gateChatJsonReply,
  gateMessagesJsonReply,
  gateResponsesJsonReply,
} from "../../src/reply-media-stream.js";
import type { FileUploadDecision, FileUploadDecisionRequest } from "../../src/arbiter-client.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(readFileSync(join(here, "..", "..", "..", "..", "arbiter", "test", "fixtures", "openclaw-media-lines-2026-10-17.json"), "utf8")) as {
  builds: string[];
  cases: Array<{ text: string; attaches: Record<string, string[]>; formsAfterSanitizing?: boolean }>;
};

const HOME = "/home/u";
const WS = "/home/u/ws";
const SECRET = "/home/u/.env";
const HELD: FileUploadDecision = {
  allow: false, requiresApproval: true,
  reason: "'/home/u/.env' is a secret file (registry) and no rule lets it go to an unnamed destination",
  ruleRef: { source: "rule", id: "fs:upload-secret-file" }, approvalId: "egr-1",
};

function fake(calls: FileUploadDecisionRequest[] = [], over: Partial<ReplyMediaOptions["arbiter"]> = {}): ReplyMediaOptions["arbiter"] {
  return {
    fileUploadDecision: async (req: FileUploadDecisionRequest) => {
      calls.push(req);
      return req.path === SECRET || req.path.endsWith("/secret.txt") ? HELD : { allow: true, reason: "clean", ruleRef: { source: "rule", id: "fs:upload-clean" } };
    },
    sessionEgressDecision: async () => ({ allow: true, reason: "ok" }) as never,
    desymbolizationDecision: async () => ({ allow: true, reason: "ok" }) as never,
    ...over,
  };
}
const opts = (calls: FileUploadDecisionRequest[] = [], over: Partial<ReplyMediaOptions["arbiter"]> = {}): ReplyMediaOptions =>
  ({ arbiter: fake(calls, over), home: HOME, launchDir: WS, sessionKey: "s" });

// ── the grammar ─────────────────────────────────────────────────────────────

test("the fixture's directive lines: every reference either build attaches is among the references judged; every text that attaches anything is flagged", () => {
  assert.deepEqual(FIXTURE.builds, ["2026.7.1", "2026.9.9"]);
  for (const c of FIXTURE.cases) {
    const attached = [...new Set(Object.values(c.attaches).flat())];
    const plan = planReplyMedia(c.text);
    if (attached.length > 0) assert.ok(plan.canonical.length + plan.neutral.length > 0, `not flagged: ${JSON.stringify(c.text)}`);
    if (c.formsAfterSanitizing) {
      assert.equal(plan.canonical.length, 0, `${JSON.stringify(c.text)}: forms only after OpenClaw's sanitizers, so it is neutralized, not judged`);
      continue;
    }
    for (const line of c.text.split("\n")) {
      if (mediaLineState(line) !== "yes") continue;
      const refs = openclawMediaRefs(line);
      assert.ok(refs, line);
      for (const a of attached.filter((x) => line.includes(x.replace(/^~\//, "")))) {
        assert.ok(refs.includes(a) || refs.includes(`file://${a}`) || refs.includes(`file:///${a.replace(/^\//, "")}`), `${JSON.stringify(line)}: ${a} not read (read ${JSON.stringify(refs)})`);
      }
    }
  }
});

test("a line start that may still become a directive is 'maybe'; a decided one is yes or no", () => {
  for (const s of ["", "  ", "M", "me", "MED", "  MEDI", "MEDIA"]) assert.equal(mediaLineState(s), "maybe", JSON.stringify(s));
  for (const s of ["MEDIA:", "media: x", "\tMEDIA:/x", "﻿MEDIA: x"]) assert.equal(mediaLineState(s), "yes", JSON.stringify(s));
  for (const s of ["Hello", "MEDIUM", "x MEDIA: /y", "MEDIA :"]) assert.equal(mediaLineState(s), "no", JSON.stringify(s));
});

test("a reference is placed as OpenClaw's reply loader reads it: file: decoded, ~/ the home, a relative one in the workspace; the store, a URL and data: apart", () => {
  assert.deepEqual(placeReplyRef("/home/u/../u/.env", HOME, WS), { kind: "local", path: SECRET });
  assert.deepEqual(placeReplyRef("file:///home/u/%2Eenv", HOME, WS), { kind: "local", path: SECRET });
  assert.deepEqual(placeReplyRef("~/.env", HOME, WS), { kind: "local", path: SECRET });
  assert.deepEqual(placeReplyRef("out/a.png", HOME, WS), { kind: "local", path: "/home/u/ws/out/a.png" });
  assert.deepEqual(placeReplyRef("@/tmp/a.png", HOME, WS), { kind: "local", path: "/home/u/ws/@/tmp/a.png" }, "no `@` strip: a directive does not take one");
  assert.deepEqual(placeReplyRef("out/a.png", HOME), { kind: "relative" });
  assert.deepEqual(placeReplyRef("media://inbound/x.png", HOME, WS), { kind: "store" });
  assert.equal(placeReplyRef("https://e.com/a.png", HOME, WS).kind, "remote");
  assert.deepEqual(placeReplyRef("data:image/png;base64,AA", HOME, WS), { kind: "none" });
});

// ── the plan ────────────────────────────────────────────────────────────────

test("plan: a canonical line is judged; a directive that forms only after OpenClaw strips markup, or one with markup in it, is neutralized; prose with 'media:' too", () => {
  const p1 = planReplyMedia("Here it is:\nMEDIA: /tmp/chart.png\nEnjoy");
  assert.deepEqual(p1.canonical.map((c) => c.line), ["MEDIA: /tmp/chart.png"]);
  assert.deepEqual(p1.neutral, []);
  for (const t of ["ME<think>\n</think>DIA: /x", "<think>x</think>MEDIA: /x", "<final>MEDIA: /x</final>", "MEDIA: <b>/x</b>", "ME[x]DIA: /x", "M]<]minimax[>[EDIA: /x", "Social media: twitter"]) {
    const p = planReplyMedia(t);
    assert.equal(p.canonical.length, 0, t);
    assert.ok(p.neutral.length > 0, t);
  }
  assert.deepEqual(planReplyMedia("MEDIA: /a.png MEDIA: /b.png").canonical, [], "two directives on one line: neutralized");
  assert.deepEqual(planReplyMedia("no directive at all: a colon, a <tag>, [x]"), { canonical: [], neutral: [] });
});

// ── the judgment ────────────────────────────────────────────────────────────

test("a secret file named on a MEDIA line: the line becomes a notice, asked with no host as tool MEDIA; a clean file passes untouched", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const text = "Here is the config\nMEDIA: /home/u/.env\nand the chart\nMEDIA: ./chart.png";
  const r = await gateReplyTexts([text], undefined, opts(calls));
  const [out] = r.texts;
  assert.ok(!out!.includes("MEDIA: /home/u/.env"), out);
  assert.match(out!, /^\[mandu\] attachment not sent, nothing was uploaded: \/home\/u\/\.env is a secret file/m);
  assert.match(out!, /Approvals page/);
  assert.match(out!, /rule: fs:upload-secret-file/);
  assert.ok(out!.includes("\nMEDIA: ./chart.png"), "the clean line stays");
  assert.deepEqual(calls.map((c) => [c.tool, c.path, c.destination]), [[REPLY_MEDIA_TOOL, SECRET, ""], [REPLY_MEDIA_TOOL, "/home/u/ws/chart.png", ""]]);
  assert.equal(r.withheld.length, 1);
  assert.equal(r.withheld[0]!.approvalId, "egr-1");
  assert.ok(out!.split("\n").every((l) => mediaLineState(l) !== "yes" || !l.includes(".env")));
});

test("every spelling of the secret is held: file://, ~/, quoted with spaces, a second reference on the line, a relative one in the workspace", async () => {
  for (const line of ["MEDIA: file:///home/u/.env", "MEDIA: ~/.env", "MEDIA: `/home/u/.env`", "MEDIA: /tmp/ok.png /home/u/.env", "  media:   /home/u/.env", "MEDIA: ws/secret.txt", "MEDIA: secret.txt"]) {
    const r = await gateReplyTexts([line], undefined, opts());
    assert.ok(r.texts[0]!.startsWith(REPLY_MEDIA_MARKER), `${line} → ${r.texts[0]}`);
  }
  const quoted = await gateReplyTexts(['MEDIA: "/home/u/ws/secret.txt"'], undefined, opts());
  assert.ok(quoted.texts[0]!.startsWith(REPLY_MEDIA_MARKER));
  // OpenClaw refuses a `..` reference itself (both builds), so there is nothing to judge
  assert.deepEqual(openclawMediaRefs("MEDIA: ../.env"), []);
});

test("fail-closed: no base for a relative path, OpenClaw's media store, an arbiter that throws, one without the op, a line past the grammar's bound", async () => {
  const noBase = await gateReplyTexts(["MEDIA: out/chart.png"], undefined, { arbiter: fake(), home: HOME });
  assert.match(noBase.texts[0]!, /relative path.*rule: proxy:reply-media-relative/);
  // a `media://` reference spells a second `media:` on the line, so the plan
  // neutralizes the line; judged directly, the store is held
  const store = await gateReplyTexts(["MEDIA: media://inbound/x.png"], undefined, opts());
  assert.equal(store.texts[0], `MEDIA${MEDIA_COLON_NEUTRAL} media${MEDIA_COLON_NEUTRAL}//inbound/x.png`);
  const judged = await judgeMediaLine("MEDIA: media://inbound/x.png", undefined, opts());
  assert.match(judged.replacement!, /media store.*rule: proxy:reply-media-store/);
  const throws = await gateReplyTexts(["MEDIA: /tmp/ok.png"], undefined, opts([], { fileUploadDecision: async () => { throw new Error("socket closed"); } }));
  assert.match(throws.texts[0]!, /could not check the file \/tmp\/ok\.png .*socket closed.*rule: proxy:arbiter-unreachable/);
  const noOp = await gateReplyTexts(["MEDIA: /tmp/ok.png"], undefined, opts([], { fileUploadDecision: undefined }));
  assert.match(noOp.texts[0]!, /rule: proxy:arbiter-unreachable/);
  const many = "MEDIA: " + Array.from({ length: 8 }, (_, i) => `https://e${i}.example.com/a.png`).join(" ");
  const bound = await gateReplyTexts([many], undefined, opts());
  assert.match(bound.texts[0]!, /rule: proxy:reply-media-unreadable/);
});

test("the window: a response that also calls a tool holds every local reference, before anything is asked", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const r = await gateReplyTexts(["Done.\nMEDIA: /tmp/ok.png"], "exec", opts(calls));
  assert.match(r.texts[0]!, /also calls exec.*final reply.*rule: proxy:reply-media-with-call/);
  assert.equal(calls.length, 0);
});

test("a remote reference goes to the net legs: a held host replaces the line, an allowed one passes", async () => {
  const blocked = await gateReplyTexts(["MEDIA: https://e.example.com/a.png"], undefined, opts([], {
    sessionEgressDecision: async () => ({ allow: false, requiresApproval: true, reason: "a secret session may not reach e.example.com", ruleRef: { source: "rule", id: "net:session-watermark" } }) as never,
  }));
  assert.match(blocked.texts[0]!, /did not let OpenClaw fetch https:\/\/e\.example\.com\/a\.png/);
  const ok = await gateReplyTexts(["MEDIA: https://e.example.com/a.png"], undefined, opts());
  assert.equal(ok.texts[0], "MEDIA: https://e.example.com/a.png");
});

test("a directive that forms after OpenClaw's sanitizers gets its colon neutralized (no arbiter ask); prose keeps every other byte", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const r = await gateReplyTexts(["ME<think>\n</think>DIA: /home/u/.env", "Social media: 3 posts"], undefined, opts(calls));
  assert.equal(r.texts[0], `ME<think>\n</think>DIA${MEDIA_COLON_NEUTRAL} /home/u/.env`);
  assert.equal(r.texts[1], `Social media${MEDIA_COLON_NEUTRAL} 3 posts`);
  assert.equal(calls.length, 0);
  assert.equal(r.neutralized, 2);
  const clean = await gateReplyTexts(["No directive: just text."], undefined, opts());
  assert.equal(clean.changed, false);
});

test("blocks are read joined by a newline, as OpenClaw joins them: markup split across two blocks is still seen", async () => {
  const r = await gateReplyTexts(["ME<think>", "</think>DIA: /home/u/.env"], undefined, opts());
  assert.deepEqual(r.texts, ["ME<think>", `</think>DIA${MEDIA_COLON_NEUTRAL} /home/u/.env`]);
});

// ── the stream ──────────────────────────────────────────────────────────────

const ev = (event: string, data: unknown): string => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
function anthropicSse(pieces: string[], withToolUse = false): string {
  let s = ev("message_start", { type: "message_start", message: { id: "m", role: "assistant", content: [] } });
  s += ev("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
  for (const p of pieces) s += ev("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: p } });
  s += ev("content_block_stop", { type: "content_block_stop", index: 0 });
  if (withToolUse) {
    s += ev("content_block_start", { type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "tu_1", name: "exec", input: {} } });
    s += ev("content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: "{\"command\":\"ls\"}" } });
    s += ev("content_block_stop", { type: "content_block_stop", index: 1 });
  }
  s += ev("message_delta", { type: "message_delta", delta: { stop_reason: withToolUse ? "tool_use" : "end_turn" } });
  s += ev("message_stop", { type: "message_stop" });
  return s;
}
function anthropicText(sse: string): string {
  let t = "";
  for (const raw of sse.split("\n\n")) {
    const line = raw.split("\n").find((l) => l.startsWith("data: "));
    if (!line) continue;
    const d = JSON.parse(line.slice(6)) as { type: string; delta?: { type: string; text?: string } };
    if (d.type === "content_block_delta" && d.delta?.type === "text_delta") t += d.delta.text;
  }
  return t;
}

test("stream: a MEDIA line split one character per delta is never half out; the text before it streams; the held rest goes out rewritten at the end", async () => {
  const text = "Your file:\nMEDIA: /home/u/.env\n";
  const f = new ReplyMediaFilter(ANTHROPIC_WIRE, opts());
  const sse = anthropicSse([...text]);
  let early = "";
  // feed one SSE event at a time
  for (const raw of sse.split(/(?<=\n\n)/)) early += f.feed(raw);
  assert.equal(anthropicText(early), "Your file:\n", "what streamed before the end is the text before the directive");
  const all = early + (await f.end());
  const got = anthropicText(all);
  assert.ok(!got.includes(".env\n") || got.startsWith("Your file:\n[mandu]"), got);
  assert.match(got, /^Your file:\n\[mandu\] attachment not sent/);
  assert.ok(all.includes("event: message_stop"), "every non-text event still goes out");
});

test("stream: a reply with no directive is relayed byte for byte, as it comes (only a possible line start waits for its next delta)", async () => {
  const sse = anthropicSse(["Hello", " world.\n", "Mean", "while: done"]);
  const f = new ReplyMediaFilter(ANTHROPIC_WIRE, opts());
  let out = "";
  for (const raw of sse.split(/(?<=\n\n)/)) out += f.feed(raw);
  out += await f.end();
  assert.equal(anthropicText(out), "Hello world.\nMeanwhile: done");
  const plain = anthropicSse(["Just", " text"]);
  const g = new ReplyMediaFilter(ANTHROPIC_WIRE, opts());
  assert.equal(g.feed(plain) + (await g.end()), plain, "byte-identical");
});

test("stream: a tool_use in the same response holds the reference (the window)", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const f = new ReplyMediaFilter(ANTHROPIC_WIRE, opts(calls));
  const out = f.feed(anthropicSse(["Report:\nMEDIA: /tmp/ok.png\n"], true)) + (await f.end());
  assert.match(anthropicText(out), /rule: proxy:reply-media-with-call/);
  assert.ok(out.includes("\"name\":\"exec\""), "the call itself passes");
  assert.equal(calls.length, 0);
});

test("stream: Chat Completions and Responses deltas and every complete text an event carries are rewritten alike", async () => {
  const text = "ok\nMEDIA: /home/u/.env";
  const pieces = ["ok\nME", "DI", "A: /home", "/u/.env"];
  let chat = `data: ${JSON.stringify({ id: "c", choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] })}\n\n`;
  for (const p of pieces) chat += `data: ${JSON.stringify({ id: "c", choices: [{ index: 0, delta: { content: p }, finish_reason: null }] })}\n\n`;
  chat += `data: ${JSON.stringify({ id: "c", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`;
  const fc = new ReplyMediaFilter(CHAT_WIRE, opts());
  const outC = fc.feed(chat) + (await fc.end());
  let gotC = "";
  for (const raw of outC.split("\n\n")) {
    if (!raw.startsWith("data: {")) continue;
    gotC += (JSON.parse(raw.slice(6)) as { choices: Array<{ delta: { content?: string } }> }).choices[0]!.delta.content ?? "";
  }
  assert.match(gotC, /^ok\n\[mandu\] attachment not sent/);
  assert.ok(outC.includes("\"role\":\"assistant\""), "the role chunk stays");
  assert.ok(outC.endsWith("data: [DONE]\n\n"));

  let resp = "";
  for (const p of pieces) resp += ev("response.output_text.delta", { type: "response.output_text.delta", item_id: "i", output_index: 0, content_index: 0, delta: p });
  resp += ev("response.output_text.done", { type: "response.output_text.done", item_id: "i", output_index: 0, content_index: 0, text });
  resp += ev("response.completed", { type: "response.completed", response: { output: [{ type: "message", content: [{ type: "output_text", text }] }] } });
  const fr = new ReplyMediaFilter(RESPONSES_WIRE, opts());
  const outR = fr.feed(resp) + (await fr.end());
  assert.ok(!outR.includes("MEDIA: /home/u/.env"), "no event of the answer still names the file");
  assert.equal(outR.match(/\[mandu\] attachment not sent/g)?.length, 3, "the delta, the .done text and response.completed");
});

test("buffered answers: Messages, Chat Completions and Responses JSON", async () => {
  const msg = { content: [{ type: "text", text: "MEDIA: /home/u/.env" }] };
  assert.equal(await gateMessagesJsonReply(msg, opts()), true);
  assert.match(msg.content[0]!.text, /^\[mandu\]/);
  const chat = { choices: [{ message: { role: "assistant", content: "x\nMEDIA: /home/u/.env" } }] };
  assert.equal(await gateChatJsonReply(chat, opts()), true);
  assert.match(chat.choices[0]!.message.content, /^x\n\[mandu\]/);
  const resp = { output: [{ type: "message", content: [{ type: "output_text", text: "MEDIA: /tmp/ok.png" }] }, { type: "function_call", name: "exec", arguments: "{}" }] };
  assert.equal(await gateResponsesJsonReply(resp, opts()), true);
  assert.match(resp.output[0]!.content![0]!.text, /also calls exec/);
  const clean = { content: [{ type: "text", text: "nothing to attach" }] };
  assert.equal(await gateMessagesJsonReply(clean, opts()), false);
});
