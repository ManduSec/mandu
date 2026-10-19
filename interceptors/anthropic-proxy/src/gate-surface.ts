/**
 * gate-surface — the per-agent tool surface the model-context gates read
 * (agent-e2e-harness.md §7.7; the authoritative tables live in the arbiter,
 * arbiter/policy/tool-gate-surface.ts, next to each agent's inbound spec).
 *
 * The proxy asks the arbiter once per session (`gateSurface` op, cached a short
 * while) which tool is the shell and which field carries its command, which
 * tools reach the network and through which field, and which fields are paths.
 * Before 2026-09-27 those were Claude Code constants here, so under `mandu
 * opencode` / `mandu openclaw` the exec, net and sensitive-path gates never
 * fired (a live opencode drill sent `bash -c "$MDU:bash[…]"` ungated).
 *
 * FALLBACK = the UNION of every agent's table (UNION_GATE_SURFACE, a mirror of
 * the arbiter's; a parity test pins the two). It applies when the arbiter
 * predates the op, answers a malformed shape, or does not answer in time, so an
 * OpenCode / OpenClaw session keeps its gates exactly when the arbiter
 * misbehaves. For a Claude Code session the union is a no-op: the extra names
 * are lowercase / snake_case and never appear on its wire. A failed fetch is
 * NOT cached, so the next request asks again. The arbiter's own default for a
 * spec without a table is the same union.
 */

import type { Arbiter } from "./arbiter-client.js";

export interface NetToolFields {
  /** The field naming the destination host; null = the tool names none. */
  destination: string | null;
  /** The field whose bytes reach the destination (scanned for symbols). */
  symbols: string;
  /** More fields naming where the call goes, each a URL string or an array
   *  of them (arbiter tool-gate-surface.ts NetToolFields; net-gate.ts checks
   *  every host and scans every string, and blocks a value it cannot read). */
  alsoDestinations?: readonly string[];
  /** `"refuse"`: a blocked call's WHOLE input becomes `{action:
   *  "mandu-refused: <why>"}` (net-gate.ts); absent: the destination field
   *  (or a `query` key) is rewritten. */
  block?: "refuse";
}

/** A form of a tool that is refused (arbiter tool-gate-surface.ts
 *  RefuseArgRule; dispatch.ts refusedArg applies it). */
export interface RefuseArgRule {
  field: string;
  allow: readonly string[];
  reason: string;
}

/** How a tool types into a running process (arbiter StdinKind;
 *  stdin-gate.ts reads it). */
export type StdinKind = "openclaw-process";

export interface PathToolFields {
  /** Each field holds a path or an array of paths (fs-gate.ts gates every
   *  string element; fs-label.ts reads string fields only). */
  fields: readonly string[];
  mode: "read" | "write";
  /** `"media"`: media references (`@path`, `file://`; an http(s) or data:
   *  URL is no path). fs-gate.ts mediaRefPath. */
  refs?: "media";
}

/** A tool whose target paths live inside a patch text (arbiter
 *  tool-gate-surface.ts PatchToolFields; apply-patch.ts parses it, proxy.ts
 *  gates it, view-map.ts maps its headers). */
export interface PatchToolFields {
  field: string;
  format: "apply-patch";
}

/** How a tool dispatches another tool (arbiter tool-gate-surface.ts
 *  DispatchKind; dispatch.ts applies it). */
export type DispatchKind = "openclaw-tool-call" | "refuse";

/** A tool that uploads local files off the machine by path (arbiter
 *  tool-gate-surface.ts UploadKind; upload-gate.ts applies it). */
export type UploadKind =
  | "claude-design-sync" | "claude-artifact" | "claude-artifact-data" | "claude-artifact-comments"
  | "openclaw-message" | "openclaw-media" | "openclaw-browser-upload";

/** Every UploadKind this proxy reads (the arbiter's answer is checked
 *  against it; an unknown kind rejects the whole answer). */
export const UPLOAD_KINDS: readonly UploadKind[] = [
  "claude-design-sync", "claude-artifact", "claude-artifact-data", "claude-artifact-comments",
  "openclaw-message", "openclaw-media", "openclaw-browser-upload",
];

/** How an agent attaches files its model names in the REPLY TEXT (arbiter
 *  tool-gate-surface.ts ReplyMediaKind; reply-media.ts applies it). */
export type ReplyMediaKind = "openclaw-media-lines";

/** OpenClaw's tools that send a local file by path (arbiter
 *  tool-gate-surface.ts OPENCLAW_GATE_SURFACE `upload`, mirrored). */
const OPENCLAW_UPLOAD: Readonly<Record<string, UploadKind>> = {
  message: "openclaw-message",
  view_image: "openclaw-media",
  image: "openclaw-media",
  pdf: "openclaw-media",
  image_generate: "openclaw-media",
  music_generate: "openclaw-media",
  video_generate: "openclaw-media",
  browser: "openclaw-browser-upload",
};

/** Claude Code's upload tools (DesignSync; the interactive Artifact tools). */
const CLAUDE_CODE_UPLOAD: Readonly<Record<string, UploadKind>> = {
  DesignSync: "claude-design-sync",
  Artifact: "claude-artifact",
  ArtifactData: "claude-artifact-data",
  ArtifactComments: "claude-artifact-comments",
};

export interface GateSurface {
  spec: string;
  /** tool → the field carrying its shell command (exec gate, view-map text). */
  exec: Readonly<Record<string, string>>;
  /** tool → the command field of a call whose RESULT is a process tree's
   *  output (callTaint, the symbol-twin note). */
  execOutput: Readonly<Record<string, string>>;
  net: Readonly<Record<string, NetToolFields>>;
  paths: Readonly<Record<string, PathToolFields>>;
  /** Dispatcher tools: tool → how it names the tool it runs (dispatch.ts). */
  dispatch: Readonly<Record<string, DispatchKind>>;
  /** Tools refused on every call: tool → why (arbiter tool-gate-surface.ts
   *  RefuseTable; dispatch.ts refuseTool applies it). */
  refuse: Readonly<Record<string, string>>;
  /** Tools refused in some forms: tool → rules (dispatch.ts refusedArg). */
  refuseArgs: Readonly<Record<string, readonly RefuseArgRule[]>>;
  /** Tools that type into a running process (stdin-gate.ts). */
  stdin: Readonly<Record<string, StdinKind>>;
  /** Tools whose target paths live inside a patch text (PatchToolFields).
   *  Optional in a hand-built surface; parseGateSurface always fills it. */
  patch?: Readonly<Record<string, PatchToolFields>>;
  /** Tools that upload local files by path, their bytes never entering the
   *  model context (UploadKind; upload-gate.ts). Optional in a hand-built
   *  surface; parseGateSurface always fills it. */
  upload?: Readonly<Record<string, UploadKind>>;
  /** The agent attaches files named in the model's reply text (`MEDIA:`
   *  lines; reply-media.ts). Absent or null: it does not. parseGateSurface
   *  fills it from an arbiter that predates the field with the union's. */
  replyMedia?: ReplyMediaKind | null;
  /** `"launch"`: the agent resolves a relative path in a gated field against
   *  the directory it was started in (arbiter tool-gate-surface.ts
   *  relativeBase; OpenCode). fs-gate.ts / fs-label.ts then resolve it
   *  against the proxy's `agentCwd`. Absent: the base is unknown, and a
   *  relative path escaping it with `..` is denied. */
  relativeBase?: "launch";
}

/** Claude Code's surface: the constants this proxy applied to every session
 *  before the table moved to the arbiter. The per-gate DEFAULT for a caller
 *  that passes no surface (net-gate.ts, rewrite-request.ts); NOT the cache's
 *  fallback (that is the union below). A parity test pins it to the arbiter's
 *  claude-code entry. */
export const CLAUDE_CODE_GATE_SURFACE: GateSurface = {
  spec: "claude-code",
  exec: { Bash: "command", Monitor: "command" },
  execOutput: { Bash: "command", BashOutput: "command", TaskOutput: "command", Monitor: "command" },
  net: {
    WebFetch: { destination: "url", symbols: "url" },
    WebSearch: { destination: null, symbols: "query" },
  },
  paths: {
    Read: { fields: ["file_path"], mode: "read" },
    Glob: { fields: ["path"], mode: "read" },
    Grep: { fields: ["path"], mode: "read" },
    LS: { fields: ["path"], mode: "read" },
    Write: { fields: ["file_path"], mode: "write" },
    Edit: { fields: ["file_path"], mode: "write" },
    MultiEdit: { fields: ["file_path"], mode: "write" },
    NotebookEdit: { fields: ["notebook_path"], mode: "write" },
  },
  dispatch: {},
  refuse: {},
  refuseArgs: {},
  stdin: {},
  patch: {},
  upload: { ...CLAUDE_CODE_UPLOAD },
};

/** Why OpenClaw's Code Mode `exec{code}` is refused (the arbiter's
 *  tool-gate-surface.ts OPENCLAW_CODE_MODE_REFUSAL, mirrored). */
const OPENCLAW_CODE_MODE_REFUSAL =
  "exec{code} is OpenClaw Code Mode: JavaScript that calls tools inside OpenClaw, where Mandu cannot check which tool gets which input; Code Mode is off under Mandu, call each tool directly (shell commands go in exec{command})";

/** Every agent's names at once: Claude Code + OpenCode + OpenClaw + Goose. A MIRROR of
 *  arbiter/policy/tool-gate-surface.ts UNION_GATE_SURFACE (this package takes
 *  no arbiter import; tests/stack agent-gate-surface.test.ts pins the
 *  two equal). The cache's fallback when the arbiter cannot say. */
export const UNION_GATE_SURFACE: GateSurface = {
  spec: "union",
  exec: { Bash: "command", Monitor: "command", bash: "command", exec: "command", shell: "command" },
  execOutput: { Bash: "command", BashOutput: "command", TaskOutput: "command", Monitor: "command", bash: "command", exec: "command", process: "command", shell: "command" },
  net: {
    WebFetch: { destination: "url", symbols: "url" },
    WebSearch: { destination: null, symbols: "query" },
    webfetch: { destination: "url", symbols: "url" },
    websearch: { destination: null, symbols: "query" },
    web_fetch: { destination: "url", symbols: "url" },
    web_search: { destination: null, symbols: "query" },
    conversations_send: { destination: null, symbols: "message" },
    conversations_turn: { destination: null, symbols: "message" },
    message: { destination: null, symbols: "message", block: "refuse" },
    show_widget: { destination: null, symbols: "widget_code", block: "refuse" },
    x_search: { destination: null, symbols: "query", block: "refuse" },
    code_execution: { destination: null, symbols: "task", block: "refuse" },
    image_generate: { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" },
    music_generate: { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" },
    video_generate: {
      destination: null, symbols: "prompt",
      alsoDestinations: ["image", "images", "video", "videos", "audioRef", "audioRefs"], block: "refuse",
    },
    tts: { destination: null, symbols: "text", block: "refuse" },
    pdf: { destination: null, symbols: "prompt", alsoDestinations: ["pdf", "pdfs"], block: "refuse" },
    browser: { destination: "targetUrl", symbols: "targetUrl", alsoDestinations: ["url"], block: "refuse" },
    image: { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" },
    view_image: { destination: null, symbols: "prompt", alsoDestinations: ["path", "paths"], block: "refuse" },
    read_image: { destination: "source", symbols: "source" },
  },
  paths: {
    Read: { fields: ["file_path"], mode: "read" },
    Glob: { fields: ["path"], mode: "read" },
    Grep: { fields: ["path"], mode: "read" },
    LS: { fields: ["path"], mode: "read" },
    Write: { fields: ["file_path"], mode: "write" },
    Edit: { fields: ["file_path"], mode: "write" },
    MultiEdit: { fields: ["file_path"], mode: "write" },
    NotebookEdit: { fields: ["notebook_path"], mode: "write" },
    read: { fields: ["filePath", "path", "file_path"], mode: "read" },
    glob: { fields: ["path"], mode: "read" },
    grep: { fields: ["path"], mode: "read" },
    write: { fields: ["filePath", "path", "file_path"], mode: "write" },
    edit: { fields: ["filePath", "path", "file_path"], mode: "write" },
    bash: { fields: ["workdir"], mode: "read" },
    shell: { fields: ["workdir"], mode: "read" },
    exec: { fields: ["workdir"], mode: "read" },
    ls: { fields: ["path"], mode: "read" },
    view_image: { fields: ["path", "paths"], mode: "read", refs: "media" },
    image: { fields: ["image", "images"], mode: "read", refs: "media" },
    message: { fields: ["media"], mode: "read" },
    pdf: { fields: ["pdf", "pdfs"], mode: "read", refs: "media" },
    image_generate: { fields: ["image", "images"], mode: "read", refs: "media" },
    music_generate: { fields: ["image", "images"], mode: "read", refs: "media" },
    video_generate: { fields: ["image", "images", "video", "videos", "audioRef", "audioRefs"], mode: "read", refs: "media" },
    browser: { fields: ["path", "paths"], mode: "write" },
    tree: { fields: ["path"], mode: "read" },
    analyze: { fields: ["path"], mode: "read" },
    read_image: { fields: ["source"], mode: "read", refs: "media" },
    delegate: { fields: ["working_dir"], mode: "read" },
    computercontroller__docx_tool: { fields: ["path"], mode: "write" },
    computercontroller__xlsx_tool: { fields: ["path"], mode: "write" },
    computercontroller__pdf_tool: { fields: ["path"], mode: "read" },
    summarize__summarize: { fields: ["paths"], mode: "read" },
  },
  dispatch: { execute: "refuse", tool_call: "openclaw-tool-call", tool_search_code: "refuse", execute_typescript: "refuse" },
  refuse: {
    terminal:
      "terminal types into a shell the operator opened in OpenClaw's Control UI, which runs in the gateway outside Mandu's sandbox; run commands with exec instead",
    automations:
      "automations schedules agent runs that fire later in the OpenClaw gateway, outside this session and outside Mandu's protection",
    cron:
      "cron schedules agent runs that fire later in the OpenClaw gateway, outside this session and outside Mandu's protection",
    gateway:
      "gateway reads the gateway's configuration and runs OpenClaw's self-update, which Mandu cannot check",
    plugins:
      "plugins installs and loads executable plugins, code Mandu never sees",
    secrets:
      "secrets asks for a credential and binds it to hosts the agent names, outside Mandu's secret handling; add secrets in Mandu's policy instead",
    portal:
      "portal exposes a local server through a gateway route, a channel no Mandu gate checks",
    nodes:
      "nodes runs commands and reads data on paired devices, outside Mandu's sandbox",
    sessions_send:
      "sessions_send hands text to another OpenClaw session, which an OpenClaw gateway outside Mandu may run; do the work in this session instead",
    sessions_spawn:
      "sessions_spawn starts a session in an OpenClaw gateway (or an ACP agent on the host) outside Mandu's protection; do the work in this session instead",
    computer:
      "computer controls the gateway's desktop or a paired computer, outside Mandu's sandbox",
    mobile_ui:
      "mobile_ui controls a paired Android device, outside Mandu's sandbox",
    canvas:
      "canvas drives the widget panel on a paired macOS node, outside Mandu's sandbox",
    openclaw:
      "the openclaw tool delegates setup and repair to a separate model turn that changes the gateway's configuration, plugins and credentials outside Mandu",
    github_publish:
      "github_publish has the OpenClaw gateway push this session's workspace to GitHub with credentials Mandu never sees; push with exec (git push, gh pr create) instead, which Mandu checks",
    wait:
      "wait resumes an OpenClaw Code Mode run (model-written JavaScript that calls tools inside OpenClaw, where Mandu cannot check them); Code Mode is off under Mandu, call each tool directly instead",
    extensionmanager__manage_extensions:
      "manage_extensions enables Goose extensions, which starts their servers as programs Mandu never checked; start goose with the extension instead",
    apps__create_app:
      "Goose apps are HTML and JavaScript the Goose desktop runs later in its own window, outside this session and outside Mandu's protection",
    apps__iterate_app:
      "Goose apps are HTML and JavaScript the Goose desktop runs later in its own window, outside this session and outside Mandu's protection",
    apps__delete_app:
      "Goose apps belong to the Goose desktop, outside this session; delete an app from the desktop instead",
    scheduler__manage_schedule:
      "scheduled Goose jobs run later in another Goose process (the desktop's goose serve), outside this session and outside Mandu's protection",
    orchestrator__start_agent:
      "start_agent starts a Goose agent outside this session, which Mandu does not protect; do the work in this session or with delegate",
    orchestrator__send_message:
      "send_message hands text to another Goose session, which may run outside Mandu's protection; do the work in this session instead",
    orchestrator__interrupt_agent:
      "interrupt_agent acts on another Goose session, outside this session",
    computercontroller__computer_control:
      "computer_control automates the desktop, outside Mandu's sandbox",
  },
  refuseArgs: {
    shell: [{
      field: "background",
      allow: ["", "false"],
      reason: "a background shell returns its output later as a message no Mandu check reads; run the command in the foreground (without background)",
    }],
    subagent: [
      {
        field: "model",
        allow: [""],
        reason: "a subagent on a model of its own may call a provider Mandu does not route; call subagent without model (it runs on this session's model)",
      },
      {
        field: "background",
        allow: ["", "false"],
        reason: "a background subagent returns its result later as a message no Mandu check reads; run it in the foreground (without background)",
      },
    ],
    delegate: [
      {
        field: "provider",
        allow: [""],
        reason: "a delegate with its own provider calls a model Mandu does not route, outside its protection; delegate without provider",
      },
      {
        field: "source",
        allow: [""],
        reason: "a delegate that runs a recipe or agent by source can pin a model Mandu does not route; delegate with instructions instead",
      },
    ],
    exec: [{
      field: "host",
      allow: ["", "auto", "sandbox", "gateway"],
      reason: "exec host=node runs the command on a paired device through the OpenClaw gateway, outside Mandu's sandbox; run it here, without host",
    }, {
      field: "code",
      allow: [],
      reason: OPENCLAW_CODE_MODE_REFUSAL,
    }, {
      field: "language",
      allow: [],
      reason: OPENCLAW_CODE_MODE_REFUSAL,
    }],
    browser: [{
      field: "target",
      allow: ["", "sandbox", "host"],
      reason: "browser target=node drives a paired device's browser, outside Mandu's sandbox",
    }],
  },
  stdin: { process: "openclaw-process" },
  patch: { apply_patch: { field: "input", format: "apply-patch" } },
  upload: { ...CLAUDE_CODE_UPLOAD, ...OPENCLAW_UPLOAD },
  replyMedia: "openclaw-media-lines",
};

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function stringMap(v: unknown): Record<string, string> | null {
  if (!isObj(v)) return null;
  const out: Record<string, string> = {};
  for (const [k, f] of Object.entries(v)) {
    if (typeof f !== "string" || f === "") return null;
    out[k] = f;
  }
  return out;
}

/** Validate an arbiter answer. Any malformed part rejects the whole answer
 *  (null ⇒ the caller keeps the fallback): a half-read table could silently
 *  drop a gate. Pure. */
export function parseGateSurface(w: unknown): GateSurface | null {
  if (!isObj(w) || typeof w["spec"] !== "string") return null;
  const exec = stringMap(w["exec"]);
  const execOutput = stringMap(w["execOutput"]);
  if (!exec || !execOutput || !isObj(w["net"]) || !isObj(w["paths"])) return null;
  const net: Record<string, NetToolFields> = {};
  for (const [k, v] of Object.entries(w["net"])) {
    if (!isObj(v) || typeof v["symbols"] !== "string") return null;
    const d = v["destination"];
    if (d !== null && typeof d !== "string") return null;
    if (v["block"] !== undefined && v["block"] !== "refuse") return null;
    const also = v["alsoDestinations"];
    if (also !== undefined && (!Array.isArray(also) || !also.every((f) => typeof f === "string" && f !== ""))) return null;
    net[k] = {
      destination: d,
      symbols: v["symbols"],
      ...(Array.isArray(also) && also.length > 0 ? { alsoDestinations: also as string[] } : {}),
      ...(v["block"] === "refuse" ? { block: "refuse" as const } : {}),
    };
  }
  const paths: Record<string, PathToolFields> = {};
  for (const [k, v] of Object.entries(w["paths"])) {
    if (!isObj(v) || !Array.isArray(v["fields"]) || !v["fields"].every((f) => typeof f === "string" && f !== "")) return null;
    if (v["mode"] !== "read" && v["mode"] !== "write") return null;
    if (v["refs"] !== undefined && v["refs"] !== "media") return null;
    paths[k] = { fields: v["fields"] as string[], mode: v["mode"], ...(v["refs"] === "media" ? { refs: "media" as const } : {}) };
  }
  // An arbiter that predates the dispatch table answers none: the union's
  // dispatchers then apply (over-gating a name is safe; a missed dispatcher
  // is the tool_call bypass, supported-agents.md §2.1). Present but malformed
  // rejects the whole answer like every other part.
  let dispatch: Record<string, DispatchKind> = { ...UNION_GATE_SURFACE.dispatch };
  if (w["dispatch"] !== undefined) {
    if (!isObj(w["dispatch"])) return null;
    dispatch = {};
    for (const [k, v] of Object.entries(w["dispatch"])) {
      if (v !== "openclaw-tool-call" && v !== "refuse") return null;
      dispatch[k] = v;
    }
  }
  // The refuse table follows the dispatch rule: absent (an older arbiter) ⇒
  // the union's refusals apply; present but malformed ⇒ the whole answer is
  // rejected.
  let refuse: Record<string, string> = { ...UNION_GATE_SURFACE.refuse };
  if (w["refuse"] !== undefined) {
    const r = stringMap(w["refuse"]);
    if (!r) return null;
    refuse = r;
  }
  // refuseArgs and stdin follow the same rule: absent (an older arbiter) ⇒
  // the union's apply; present but malformed ⇒ the whole answer is rejected.
  let refuseArgs: Record<string, RefuseArgRule[]> = Object.fromEntries(
    Object.entries(UNION_GATE_SURFACE.refuseArgs).map(([k, v]) => [k, [...v]]),
  );
  if (w["refuseArgs"] !== undefined) {
    if (!isObj(w["refuseArgs"])) return null;
    refuseArgs = {};
    for (const [k, rules] of Object.entries(w["refuseArgs"])) {
      if (!Array.isArray(rules)) return null;
      const out: RefuseArgRule[] = [];
      for (const r of rules) {
        if (!isObj(r) || typeof r["field"] !== "string" || r["field"] === "" || typeof r["reason"] !== "string") return null;
        if (!Array.isArray(r["allow"]) || !r["allow"].every((a) => typeof a === "string")) return null;
        out.push({ field: r["field"], allow: r["allow"] as string[], reason: r["reason"] });
      }
      refuseArgs[k] = out;
    }
  }
  let stdin: Record<string, StdinKind> = { ...UNION_GATE_SURFACE.stdin };
  if (w["stdin"] !== undefined) {
    if (!isObj(w["stdin"])) return null;
    stdin = {};
    for (const [k, v] of Object.entries(w["stdin"])) {
      if (v !== "openclaw-process") return null;
      stdin[k] = v;
    }
  }
  // The patch table follows the same rule: an arbiter that predates it
  // answers none, and the union's patch tools (apply_patch) are gated anyway.
  let patch: Record<string, PatchToolFields> = { ...UNION_GATE_SURFACE.patch };
  if (w["patch"] !== undefined) {
    if (!isObj(w["patch"])) return null;
    patch = {};
    for (const [k, v] of Object.entries(w["patch"])) {
      if (!isObj(v) || typeof v["field"] !== "string" || v["field"] === "" || v["format"] !== "apply-patch") return null;
      patch[k] = { field: v["field"], format: "apply-patch" };
    }
  }
  // The upload table follows the same rule: an arbiter that predates it
  // answers none, and the union's upload tools (DesignSync, the Artifact
  // tools) are gated anyway.
  let upload: Record<string, UploadKind> = { ...UNION_GATE_SURFACE.upload };
  if (w["upload"] !== undefined) {
    if (!isObj(w["upload"])) return null;
    upload = {};
    for (const [k, v] of Object.entries(w["upload"])) {
      if (!UPLOAD_KINDS.includes(v as UploadKind)) return null;
      upload[k] = v as UploadKind;
    }
  }
  // The relative base: absent means unknown (the conservative reading); any
  // other value than "launch" rejects the whole answer.
  if (w["relativeBase"] !== undefined && w["relativeBase"] !== "launch") return null;
  // The reply-media reading: an arbiter that predates it answers none (not
  // null), and the union's applies (a reply is read for attachments); null
  // is "this agent attaches none"; anything else rejects the whole answer.
  const rm = w["replyMedia"];
  if (rm !== undefined && rm !== null && rm !== "openclaw-media-lines") return null;
  const replyMedia: ReplyMediaKind | null = rm === undefined ? UNION_GATE_SURFACE.replyMedia ?? null : rm;
  return {
    spec: w["spec"], exec, execOutput, net, paths, dispatch, refuse, refuseArgs, stdin, patch, upload, replyMedia,
    ...(w["relativeBase"] === "launch" ? { relativeBase: "launch" as const } : {}),
  };
}

export const GATE_SURFACE_TTL_MS = 30_000;
export const GATE_SURFACE_TIMEOUT_MS = 3000;

/** Per-session surface cache over the arbiter op. */
export class GateSurfaceCache {
  private readonly cache = new Map<string, { surface: GateSurface; at: number }>();
  private warned = false;
  /** Failure messages already logged: a failed fetch is retried on the next
   *  request, and an arbiter that lacks the op fails every time. */
  private readonly logged = new Set<string>();

  constructor(
    private readonly arbiter: Pick<Arbiter, "gateSurface">,
    private readonly opts: { log?: (m: string) => void; ttlMs?: number; timeoutMs?: number; now?: () => number } = {},
  ) {}

  /** The surface for `sessionKey`; the union fallback when the arbiter cannot
   *  say. Never throws. */
  async get(sessionKey: string | undefined): Promise<GateSurface> {
    const now = this.opts.now ?? Date.now;
    const key = sessionKey ?? "";
    const hit = this.cache.get(key);
    if (hit && now() - hit.at < (this.opts.ttlMs ?? GATE_SURFACE_TTL_MS)) return hit.surface;
    if (!this.arbiter.gateSurface) {
      if (!this.warned) {
        this.warned = true;
        this.opts.log?.("gate-surface: the arbiter predates the gateSurface op; every agent's gate table (the union) applies to every session");
      }
      return UNION_GATE_SURFACE;
    }
    const timeoutMs = this.opts.timeoutMs ?? GATE_SURFACE_TIMEOUT_MS;
    let timer: NodeJS.Timeout | undefined;
    try {
      const wire = await Promise.race([
        this.arbiter.gateSurface(sessionKey !== undefined ? { sessionKey } : {}),
        new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error(`timed out after ${timeoutMs}ms`)), timeoutMs); }),
      ]);
      const surface = parseGateSurface(wire);
      if (!surface) {
        this.opts.log?.("gate-surface: malformed answer from the arbiter; every agent's gate table (the union) applies to this request");
        return UNION_GATE_SURFACE;
      }
      this.cache.set(key, { surface, at: now() });
      return surface;
    } catch (err) {
      const msg = (err as Error).message;
      if (!this.logged.has(msg)) {
        this.logged.add(msg);
        this.opts.log?.(`gate-surface: ${msg}; every agent's gate table (the union) applies until the arbiter answers`);
      }
      return UNION_GATE_SURFACE;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
