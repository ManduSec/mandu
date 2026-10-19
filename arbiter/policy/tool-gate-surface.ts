/**
 * tool-gate-surface — which of an agent's tools each model-context gate reads,
 * and from which input field (agent-e2e-harness.md §7.7).
 *
 * Mandu-new. The model-API proxy gates tool_use inputs on the wire: the exec
 * gate reads a shell command, the net gate a URL, the sensitive-path gate and
 * the derived on-disk label typed path fields, and the exec-output legs
 * (callTaint, the symbol-twin note) the command behind a shell result. Until
 * 2026-09-27 the proxy keyed all of these on Claude Code's tool names only
 * (`Bash.command`, `WebFetch.url`, `Read.file_path`), so under `mandu opencode`
 * (`bash`, `webfetch`, `read.filePath`) and `mandu openclaw` (`exec`,
 * `web_fetch`, `read.path`) NONE of them fired: a live opencode drill sent
 * `bash -c "$MDU:bash[…]"` and no exec gate saw it. The inbound trust spec was
 * already per agent (tool-inbound.ts, session-keyed via `setSessionSpec`); this
 * table puts the GATE surface next to it, keyed by the same InboundSpecId, and
 * the proxy asks the arbiter for it per session (`gateSurface` IPC op) instead
 * of hard-coding one agent's names.
 *
 * TOOL NAMES AND FIELDS ARE READ OFF THE WIRE, not from docs: captured
 * 2026-09-27 from the `tools[]` of a real request on opencode 1.18.32 and
 * openclaw 2026.6.35 (arbiter/test/fixtures/agent-tool-schemas-2026-09-27.json;
 * a unit test pins every field below against it). Later captures pin the
 * later tables the same way: OpenClaw 2026.7.1 / 2026.9.6, Goose 1.53.0,
 * OpenCode 2.0.23 (the fixtures named at each table).
 *
 * FAIL-CLOSED DEFAULT. A session bound to a spec with no table here (the
 * AgentDojo eval specs, "fail-closed", an id minted later) gets the UNION of
 * every agent table: at least as much gating as the Claude Code table the proxy
 * applied to every session before this module existed, never less. Over-gating
 * a tool name is safe (a gate verdict, not a silent pass); a missed name is the
 * regression class this module closes.
 */

import { processSessionSpecs, resolveInboundSpecId, type InboundSpecId, type SessionSpecLookup } from "./tool-inbound.js";
import type { WorkdirShape, WorkdirTools } from "./secret-catalog.js";

/** A network-reaching tool: the field naming its destination host (`null` = the
 *  tool egresses but names no checkable destination, e.g. a search query that
 *  goes to the provider; a high session fails closed on it) and the field
 *  whose bytes reach the destination (scanned for symbols). */
export interface NetToolFields {
  destination: string | null;
  symbols: string;
  /** More fields that name where the call goes, each a URL string or an
   *  array of URL strings: an alias the tool reads when `destination` is
   *  absent (OpenClaw browser `url`), or the media references a tool loads
   *  (OpenClaw image `image` / `images`). The session leg checks every host
   *  they name, the per-symbol leg scans every string in them, and a value
   *  the gate cannot read (neither a string nor an array) blocks the call. A
   *  value with no host (a local path, a `data:` URL) is no network
   *  destination; the path gate reads it. */
  alsoDestinations?: readonly string[];
  /** How a BLOCKED call is neutralized. Absent: the destination field becomes
   *  the sentinel URL (a tool with no destination field gets a `query` key
   *  naming the block, which is its payload field or a key its schema
   *  rejects). `"refuse"`: the WHOLE input becomes `{action: "mandu-refused:
   *  <why>"}`, for a tool whose other fields would still act on a block (a
   *  browser that types, a message with attachments, a generator that
   *  uploads reference files) and whose schema rejects that input (each is
   *  noted where it is mapped). */
  block?: "refuse";
}

/** A filesystem tool: its path-typed input fields and what it does to them
 *  (the `mode` the sensitive-path gate reports; the derived label runs on
 *  `write` only). */
export interface PathToolFields {
  /** Each field holds a path, or an array of paths: every string element is
   *  gated. The derived label reads string fields only; no tool writes
   *  through an array field. */
  fields: readonly string[];
  mode: "read" | "write";
  /** `"media"`: the values are media references as OpenClaw's media loader
   *  reads them. A leading `@` is dropped, a `file://` URL names a local
   *  path, and an `http(s):` or `data:` URL is no path (the net gate reads
   *  it). Without it `@/home/u/.ssh/id_rsa` would read as a relative path
   *  and skip the gate. */
  refs?: "media";
}

/** A tool whose target paths live INSIDE a text field: the `*** Begin Patch`
 *  format of OpenClaw's `apply_patch{input}` (Codex's apply_patch format).
 *  The proxy parses the file headers (`*** Add File:`, `*** Delete File:`,
 *  `*** Update File:`, `*** Move to:`) with a port of OpenClaw's own parser
 *  (apply-patch.ts), puts every path to the sensitive-path gate as a write,
 *  records the derived label on every path the patch writes, and maps the
 *  header paths between the views. A patch it cannot parse, or one that
 *  touches a denied path, is refused whole: nothing is applied. */
export interface PatchToolFields {
  field: string;
  format: "apply-patch";
}

/** How a tool DISPATCHES another tool (a Tool Search style indirection):
 *  - `openclaw-tool-call`: OpenClaw's `tool_call{id, args}` runs the catalog
 *    tool named by `id` with `args` as its input. The proxy gates the INNER
 *    tool (its exec / net / path fields, the exec-output legs) and refuses a
 *    call it cannot parse to exactly one inner tool.
 *  - `refuse`: the tool runs code that calls tools (`tool_search_code`), so no
 *    gate can read which tool gets which input. The proxy refuses every call,
 *    the way the openai-proxy refuses an unparseable Codex JS cell. */
export type DispatchKind = "openclaw-tool-call" | "refuse";

/** A tool Mandu refuses outright: tool → the reason the model reads. For a
 *  tool whose effect happens OUTSIDE every chokepoint Mandu has (a shell in
 *  the OpenClaw gateway's Control UI, a scheduled run that fires later in the
 *  gateway, an executable plugin install, a credential bound to hosts the
 *  agent names). No field of its input can be gated into safety, so the proxy
 *  replaces the call's input with one the tool's own schema rejects
 *  (`{action: "mandu-refused: <why>"}`; every refused tool takes a required
 *  `action` enum) and nothing runs. A dispatched call to it is refused the
 *  dispatcher's way (dispatch.ts). */
export type RefuseTable = Readonly<Record<string, string>>;

/** A tool refused only in some FORMS: a call whose `field` is present with a
 *  value outside `allow` (compared trimmed and lowercased, as OpenClaw
 *  normalizes an exec host; a boolean compares as "true" / "false", any
 *  other type is outside every list) is refused. For a tool that is safe in the box
 *  but can be pointed OUTSIDE it by one input field (OpenClaw's
 *  `exec{host: "node"}` runs on a paired device, `browser{target: "node"}`
 *  drives a paired device's browser). The proxy replaces the field's value
 *  with "mandu-refused: <why>", a value the tool rejects, so nothing runs
 *  (and a shell tool's command becomes the exec gate's block sentinel too). */
export interface RefuseArgRule {
  field: string;
  /** The values that keep the call inside Mandu's box ("" = the field set
   *  to an empty string, which the tool reads as absent). */
  allow: readonly string[];
  reason: string;
}

/** A tool that TYPES into a process an earlier shell call started: how the
 *  proxy reads the text it types.
 *  - `openclaw-process`: OpenClaw's `process` (`write{data}`,
 *    `paste{text}`, `send-keys{literal, hex, keys}`), which writes into a
 *    background `exec` session's stdin. That process is often a shell, so
 *    each typed stream is exec-gated like a command, and a blocked call's
 *    input becomes `{action: "mandu-refused: <why>"}`. */
export type StdinKind = "openclaw-process";

/** A tool that UPLOADS local files off the machine by path, their bytes never
 *  entering the model context: how the proxy reads which files go where.
 *  - `claude-design-sync`: Claude Code's `DesignSync` (2.1.292), which syncs
 *    the user's claude.ai/design projects. Its `write_files{planId, files:
 *    [{path, localPath | data, …}]}` reads each `localPath` (relative to the
 *    `localDir` its earlier `finalize_plan` call named; the working
 *    directory when absent) and uploads the bytes to claude.ai. The proxy
 *    (upload-gate.ts) refuses a `finalize_plan` whose `localDir` is not an
 *    absolute path, places every `localPath` against the plans it relayed,
 *    puts each file to the arbiter's `fileUploadDecision` (its label, its
 *    registration, the registered secret values in its bytes), and runs the
 *    net gate's session and per-symbol legs over every string the call sends
 *    to claude.ai (inline `data`, names, paths). Any block, an unplaceable
 *    path or an arbiter that does not answer refuses the WHOLE call
 *    (`{action: "mandu-refused: …"}`: the schema requires `method` and
 *    rejects unknown keys, so nothing is sent). Captured from the 2.1.292
 *    wire (test/fixtures/claude-design-sync-tool-2026-10-07.json).
 *  - `claude-artifact`: Claude Code's `Artifact` (interactive sessions,
 *    2.1.290 to 2.1.295 at least), which publishes web pages to claude.ai.
 *    Its `publish` (the default `action`) reads the local page `file_path`,
 *    every `files` source (an array of `{path}` or a map of published path
 *    to a source path or `{from}`, relative to `root` or the working
 *    directory) and, in later releases, `file_paths`, and uploads the bytes.
 *    The proxy places each path (absolute as written; relative only against
 *    an absolute `root`: the working directory follows the shell's `cd`, so a
 *    path relative to it is refused with how to call it) and puts each to
 *    `fileUploadDecision`; the net legs run over every string. Every other
 *    action sends only model-written text (the net legs alone).
 *  - `claude-artifact-data`: Claude Code's `ArtifactData`, a published
 *    page's shared database. `set` / `update` take a local JSON file by
 *    `file_path`, `batch` one per `writes[].file_path`, whose object is sent
 *    as the document: placed (absolute only) and judged the same way; the
 *    net legs over every string (inline `data`, `str_replace` text).
 *  - `claude-artifact-comments`: Claude Code's `ArtifactComments`: no local
 *    file, but its `reply` text goes to claude.ai, so the net legs.
 *  Every Artifact tool takes `action` from an enum, so the refusal
 *  `{action: "mandu-refused: …"}` is rejected by its schema and nothing is
 *  sent. Captured from the interactive wire
 *  (test/fixtures/claude-artifact-tools-2026-10-09.json).
 *  "To claude.ai" is the service each tool presents as: the bytes go to
 *  api.anthropic.com (2026-10-17, test/fixtures/claude-upload-hosts-
 *  2026-10-17.json), and the proxy judges every host (upload-gate.ts
 *  UPLOAD_HOSTS). A tool no table names is the proxy's unmapped upload
 *  leg's (unmapped-upload.ts).
 *
 *  OpenClaw's tools that send a LOCAL FILE's bytes somewhere by naming its
 *  path (2026-10-17; read from the openclaw 2026.7.1 and 2026.9.9 dist,
 *  supported-agents.md §2.1, "Tools that send a local file"). OpenClaw
 *  reads the file in its own process and sends it on, so the bytes never
 *  enter the model context and only the path is on the wire:
 *  - `openclaw-message`: `message` attaches media to a chat channel send
 *    (any action; `send`, `broadcast`, `sendAttachment`, `upload-file`,
 *    `setGroupIcon`, … each hydrate the same params). OpenClaw reads its
 *    media sources from `media`, `path`, `filePath`, `mediaUrl`, `fileUrl`,
 *    `image` (and their snake_case spellings), the `mediaUrls` list, every
 *    `attachments[]` entry's `media`, `mediaUrl`, `path`, `filePath`,
 *    `fileUrl` or `url`, and a channel plugin's own params (Matrix
 *    `avatarPath` / `avatarUrl`), each a media reference (a path, `~`,
 *    `file://`, `MEDIA:`; an http(s) URL is fetched). The DESTINATION is
 *    the channel, which the proxy cannot name as a host: OpenClaw delivers
 *    from its own process or through a gateway to a channel API whose root
 *    is configurable (Telegram `apiRoot`) or a plugin's own transport. So
 *    no binding can release a secret file to it: a secret one is held for
 *    the person's OK (fileUploadDecision with no host).
 *  - `openclaw-media`: `view_image`, `image`, `pdf` and the media
 *    generators load each reference named in their path entry's fields
 *    (`refs: "media"`) and send the bytes to a MODEL: the session's own
 *    (view_image on a vision model returns the image as the result), or an
 *    image, PDF or generation model OpenClaw picks, which the proxy cannot
 *    name. Judged as an upload to a model (`toModel`): a file at
 *    `any-model` may go (its level admits every model), a `local-model` or
 *    `no-model` one is held.
 *  - `openclaw-browser-upload`: `browser{action: "upload", paths}` puts the
 *    local files into the page's file chooser, for the page to send where
 *    it likes. No host is known; judged as `openclaw-message`.
 */
export type UploadKind =
  | "claude-design-sync" | "claude-artifact" | "claude-artifact-data" | "claude-artifact-comments"
  | "openclaw-message" | "openclaw-media" | "openclaw-browser-upload";

/** How an agent attaches files its model names in the REPLY TEXT, with no
 *  tool call (2026-10-17; supported-agents.md §2.1, "Files named in the
 *  reply"; test/fixtures/openclaw-media-lines-2026-10-17.json):
 *  - `openclaw-media-lines`: OpenClaw delivers a reply to a chat channel
 *    with every file a `MEDIA:` line names attached (parseReplyDirectives →
 *    splitMediaFromOutput), read in its own process. The proxy reads the
 *    reply text on the response (anthropic-proxy reply-media.ts): each
 *    local file goes to fileUploadDecision with no host, as `message`'s
 *    attachments, and every other place a directive could form is
 *    neutralized. */
export type ReplyMediaKind = "openclaw-media-lines";

export interface GateSurface {
  /** The spec the surface was resolved from (observability). */
  spec: InboundSpecId;
  /** Tools whose input carries a shell command STRING: tool → command field.
   *  The exec gate reads it; the view map substitutes paths inside it. */
  exec: Readonly<Record<string, string>>;
  /** Tools whose RESULT is a process tree's output: tool → the command field
   *  of the call (callTaint, the symbol-twin note). */
  execOutput: Readonly<Record<string, string>>;
  net: Readonly<Record<string, NetToolFields>>;
  paths: Readonly<Record<string, PathToolFields>>;
  /** Dispatcher tools: tool → how it names the tool it runs. */
  dispatch: Readonly<Record<string, DispatchKind>>;
  /** Tools refused on every call: tool → why (RefuseTable). */
  refuse: RefuseTable;
  /** Tools refused in some forms: tool → the rules (RefuseArgRule). */
  refuseArgs: Readonly<Record<string, readonly RefuseArgRule[]>>;
  /** Tools that type into a running process: tool → how (StdinKind). */
  stdin: Readonly<Record<string, StdinKind>>;
  /** Tools whose target paths live inside a patch text (PatchToolFields). */
  patch: Readonly<Record<string, PatchToolFields>>;
  /** Tools that upload local files by path (UploadKind). Optional in a
   *  hand-built table; every agent table below names its own. */
  upload?: Readonly<Record<string, UploadKind>>;
  /** The agent attaches files named in the model's reply text
   *  (ReplyMediaKind). A table leaves it out when its agent does not; a
   *  resolved surface (gateSurfaceForSpec) always says, null for none, so
   *  the proxy can tell "none" from an arbiter that predates the field. */
  replyMedia?: ReplyMediaKind | null;
  /** Where the agent resolves a RELATIVE path in a gated field (fs-portable-
   *  core.md §4.1, "Relative paths"). `"launch"`: against the directory the
   *  agent was started in, fixed for the session (OpenCode: every file tool
   *  and `bash.workdir` join `ctx.directory`), so the proxy resolves it
   *  against the launch directory the launcher names (MANDU_AGENT_CWD) and
   *  gates the absolute path (OpenClaw too: its workspace, which the
   *  launcher pins to the launch directory for the local shapes). Absent:
   *  the base is not known to the proxy (Claude Code's follows the shell's
   *  `cd`), and a relative path that escapes it with `..` is denied. The
   *  launcher names no directory where it cannot vouch for it, and then an
   *  agent that claims a base is treated as unknown too. */
  relativeBase?: "launch";
  /** Tools whose `workdir` input the agent HONOURS: the command runs in the
   *  directory it names (tool → `WorkdirShape`; secret-catalog.ts
   *  `callWorkdir`). The confidentiality derivation reads a call's relative
   *  path tokens there, so a human label on that path decides them. A
   *  `workdir` on any other tool, or on a call without the entry's shape, is
   *  the model's claim, which the agent never acts on: it is ignored, and
   *  the directory the kernel says the call's shell started in is read
   *  instead (2026-10-11: Goose's `shell` has no `workdir`, yet shares
   *  Codex's tool name, and a forged one used to be believed; confidentiality.md
   *  §6). Absent: none. A tool goes here only when its captured schema has
   *  the field AND the agent always runs the command there (OpenClaw's
   *  `exec.workdir` does not: it falls back to the workspace or home when the
   *  directory is missing, so it stays out and its calls take the kernel's
   *  directory). */
  workdir?: WorkdirTools;
}

type SurfaceTable = Omit<GateSurface, "spec">;

/** Codex's tools whose `workdir` it honours (GateSurface `workdir`):
 *  `exec_command{cmd, workdir}` (unified exec) and the classic
 *  `shell{command: string[], workdir}`, each a fresh process started in its
 *  `workdir`. `shell` only with an argv `command`: a string one is Goose's
 *  `shell` (no `workdir`) or OpenCode 2's, in a session that lost its
 *  binding. Codex has no session spec of its own (the openai-proxy binds
 *  none), so a Codex session resolves to the boot spec, Claude Code's by
 *  default, and this table rides in Claude Code's (claude-code-inbound.ts
 *  carries Codex's result shapes for the same reason). */
export const CODEX_WORKDIR_TOOLS: WorkdirTools = { exec_command: "always", shell: "argv" };

/** Claude Code — exactly the constants the proxy hard-coded before this table
 *  (exec-gate.ts EXEC_COMMAND_FIELDS, net-gate.ts NET_TOOLS/NET_SYMBOL_FIELDS,
 *  view-map.ts CLAUDE_CODE_PATH_FIELDS/FS_MODE_BY_TOOL, rewrite-request.ts's
 *  Bash/BashOutput exec-output check). Behavior for Claude sessions is
 *  unchanged by construction; a parity test pins it. */
export const CLAUDE_CODE_GATE_SURFACE: SurfaceTable = {
  // `Monitor{command}` (2.1.28x) runs a shell command in the background and
  // streams its stdout back: a shell to the exec gate and the exec-output
  // legs alike (plan 10 §11.12). Its `ws{url}` form names no top-level field
  // the net gate reads; the connect guard still holds the connection.
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
  // 2.1.292: DesignSync uploads local files to claude.ai by `localPath`
  // (UploadKind; supported-agents.md §2, "Claude Code 2.1.292"). The
  // interactive Artifact tools (2026-10-09; "Claude Code 2.1.295"): Artifact
  // and ArtifactData upload local files by path, ArtifactComments sends text.
  upload: {
    DesignSync: "claude-design-sync",
    Artifact: "claude-artifact",
    ArtifactData: "claude-artifact-data",
    ArtifactComments: "claude-artifact-comments",
  },
  // Claude Code's `Bash` names no directory; these are Codex's tools
  // (CODEX_WORKDIR_TOOLS).
  workdir: CODEX_WORKDIR_TOOLS,
};

/** OpenCode, ONE table for both generations (the session spec `opencode`
 *  serves both; a name only one of them sends is simply never on the other's
 *  wire, and over-gating is safe where a missed name is not).
 *
 *  OpenCode 1 (opencode 1.18.32 wire): `bash{command,timeout,workdir}`,
 *  `read{filePath,offset,limit}`, `write{content,filePath}`,
 *  `edit{filePath,oldString,newString,replaceAll}`, `glob{pattern,path}`,
 *  `grep{pattern,path,include}`, `webfetch{url,format,timeout}`.
 *  `websearch{query,numResults,livecrawl,type,contextMaxCharacters}` is
 *  registry-conditional (off in the captured build: on only for the
 *  `opencode` provider or with OPENCODE_ENABLE_EXA / _PARALLEL set), so its
 *  shape is read statically from the 1.18.13 binary instead
 *  (test/fixtures/opencode-websearch-2026-10-17.json: the query goes to
 *  mcp.exa.ai or search.parallel.ai, picked per session; no field names a
 *  destination, so `destination: null`). `bash`'s
 *  `workdir` is the directory the shell runs in: a path read, and a denied
 *  one blocks the command (proxy.ts), the same as OpenClaw's `exec`.
 *
 *  OpenCode 2 (npm `@opencode/cli` 2.0.23 wire, captured 2026-10-05:
 *  test/fixtures/opencode2-tool-surface-2026-10-05.json; supported-agents.md
 *  §2.3): `shell{command,workdir,timeout,background}` (bash renamed),
 *  `read{path,offset,limit}`, `write{path,content}`,
 *  `edit{path,oldString,newString,replaceAll}` (`path`, not `filePath`),
 *  `glob{pattern,path,hidden,limit}`, `grep{pattern,path,include,…}`,
 *  `webfetch{url,format,timeout}`, `websearch{query}` (advertised by
 *  default), `subagent{agent,description,prompt,model,sessionID,background}`
 *  (task renamed), `question{questions}`, `skill{id}` and
 *  `execute{code}`. Every schema has additionalProperties false and OpenCode
 *  validates a call before it runs, so a refused field's string value (or
 *  `{action: …}`) fails the call ("Invalid arguments for tool").
 *
 *  - `execute` is CODE MODE (decision D4, §5.3.4): JavaScript that calls
 *    tools in process (a catalog reachable only there: `opencode.models`,
 *    `session_move`, `session_rename`, the MCP resource readers) and has
 *    `fetch`. No gate can read which tool runs with which input, or which
 *    host the code fetches, so every call is refused the dispatcher way
 *    (`{code: "throw new Error(…)"}`; probed on 2.0.23: the code throws,
 *    nothing else runs).
 *  - `background: true` on `shell` or `subagent` is refused: the work then
 *    ends in a USER TEXT (`<shell id=… state="completed">output</shell>`,
 *    `<subagent …>result</subagent>`), not a tool_result, so its output
 *    would pass every tool_result leg (callTaint, the value backstop, the
 *    inbound spec) unread (probed on 2.0.23). A foreground call is the same
 *    work with its output in the tool_result.
 *  - `subagent.model` is refused: the child session runs on the model it
 *    names. Today the provider fence (`enabled_providers`, which 2.x
 *    normalizes into `experimental.policies`) refuses an unrouted provider
 *    ("Model … is not available", probed), but a model the agent picks is
 *    not one Mandu checked at launch (agent-model-route.ts); without it the
 *    child runs on the session's own model, through the proxy, under the
 *    same session (probed: same session header, same gates).
 *  - `question` and `skill` read no path, URL or command a gate could check:
 *    their results are classified by the inbound spec (opencode-inbound.ts).
 */
export const OPENCODE_GATE_SURFACE: SurfaceTable = {
  exec: { bash: "command", shell: "command" },
  execOutput: { bash: "command", shell: "command" },
  net: {
    webfetch: { destination: "url", symbols: "url" },
    websearch: { destination: null, symbols: "query" },
  },
  paths: {
    read: { fields: ["filePath", "path"], mode: "read" },
    glob: { fields: ["path"], mode: "read" },
    grep: { fields: ["path"], mode: "read" },
    write: { fields: ["filePath", "path"], mode: "write" },
    edit: { fields: ["filePath", "path"], mode: "write" },
    bash: { fields: ["workdir"], mode: "read" },
    shell: { fields: ["workdir"], mode: "read" },
  },
  dispatch: { execute: "refuse" },
  // OpenCode 1's `bash{command, workdir}` and OpenCode 2's `shell{command,
  // workdir}` run the command in `workdir` (resolved against the launch
  // directory when relative; only an absolute one is a base here).
  workdir: { bash: "always", shell: "always" },
  refuse: {},
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
  },
  stdin: {},
  patch: {},
  // Every relative path joins the instance directory (read/write/edit
  // `path.join(ctx.directory, filePath)`, glob/grep `path.resolve(…)`, bash's
  // workdir resolved against it; opencode 1.18.32), which is the directory
  // opencode started in unless its argv names another (`opencode <project>`,
  // `--dir`), and then the launcher names no base (launcher agentStartDir).
  // OpenCode 2.0.23 the same: a relative `read{path}`, `write{path}` and
  // `shell{workdir}` resolved in the launch directory (probed). Code mode's
  // `session_move` would move it, and is refused with `execute`.
  relativeBase: "launch",
};

/** Why OpenClaw's Code Mode `exec` (JavaScript that calls tools) is refused. */
const OPENCLAW_CODE_MODE_REFUSAL =
  "exec{code} is OpenClaw Code Mode: JavaScript that calls tools inside OpenClaw, where Mandu cannot check which tool gets which input; Code Mode is off under Mandu, call each tool directly (shell commands go in exec{command})";

/** OpenClaw (openclaw 2026.6.35 wire, `tools.profile: "coding"`):
 *  `exec{command,workdir,env,…}`, `process{action,sessionId,…}` (polls a
 *  background exec session: the same output class, no command field),
 *  `read{path,offset,limit}`, `write{path,content}`, `edit{path,edits}`,
 *  `web_fetch{url,extractMode,maxChars}`, `web_search{query,…}`,
 *  `apply_patch{input}`, `image{prompt,image,images,model,…}`. `read` also
 *  accepts the `file_path` alias (openclaw-inbound.ts header), so both
 *  spellings are gated.
 *
 *  The gate-surface residue closed 2026-09-29 (supported-agents.md §5.5 item 4),
 *  each read from openclaw 2026.6.35's dist:
 *  - `exec.workdir` is the directory the command runs in (a path read). A
 *    denied one blocks the command too: OpenClaw falls back to its own cwd,
 *    or the home directory, when the workdir does not exist
 *    (resolveWorkdir), so a sentinel path alone would still run it.
 *  - `apply_patch.input` names its target paths in file headers (`patch`
 *    table, PatchToolFields).
 *  - `image.image` / `image.images` are media references: a local path
 *    (`~`, `@path`, `file://`), a `data:` URL, or an http(s) URL the tool
 *    fetches; the image then goes to the configured image model. Net: the
 *    provider leg names no destination (as `pdf`), the URLs are checked;
 *    paths: the local references. `view_image{path,paths}` (2026.9.x)
 *    replaces it (openclaw-inbound.ts) and is gated the same way (read from
 *    the 2026.9.9 dist on 2026-10-17: the image goes to the session's own
 *    model when it has vision, else to an image model; both are model
 *    destinations, the `upload` table's `openclaw-media` kind).
 *  - `browser` reads `url` when `targetUrl` is absent (readTargetUrlParam),
 *    and `upload` sends the local files in `paths`. */
export const OPENCLAW_GATE_SURFACE: SurfaceTable = {
  exec: { exec: "command" },
  execOutput: { exec: "command", process: "command" },
  net: {
    web_fetch: { destination: "url", symbols: "url" },
    web_search: { destination: null, symbols: "query" },
    // 2026.9.x: send to an external channel conversation through the gateway
    // (`{conversationRef, message}`, additionalProperties false). No
    // destination a gate can check: the ref is opaque and the gateway does
    // the delivery. The session leg blocks it in a high session, the symbol
    // leg on any symbol in `message`; the block adds a `query` key the
    // schema rejects, so a blocked call sends nothing.
    conversations_send: { destination: null, symbols: "message" },
    conversations_turn: { destination: null, symbols: "message" },
    // Tools outside the `coding` profile's captured surface (the `full` and
    // `messaging` profiles, provider plugins), read from 2026.9.6's source.
    // Each sends its input to a service outside Mandu's model route and names
    // no destination a gate can check, so a high session blocks it, and so
    // does a symbol in its payload field. A block replaces the WHOLE input
    // (`block: "refuse"`): the other fields would still act. Why each schema
    // rejects `{action: "mandu-refused: …"}` is noted per tool.
    //   message{action (enum), message, media, …}: a chat channel send.
    message: { destination: null, symbols: "message", block: "refuse" },
    //   show_widget{title (required), widget_code}: HTML whose scripts load
    //   from CDNs and whose pinned widgets may fetch declared origins.
    show_widget: { destination: null, symbols: "widget_code", block: "refuse" },
    //   x_search{query (required)}, code_execution{task (required)}: xAI.
    x_search: { destination: null, symbols: "query", block: "refuse" },
    code_execution: { destination: null, symbols: "task", block: "refuse" },
    //   The media providers: image/music/video_generate{prompt, image, …}
    //   (an unknown `action` throws "action must be generate, status, or
    //   list"), tts{text (required)}, pdf{prompt, pdf, …} (no pdf, nothing
    //   to send). Their reference fields (a string and its array twin:
    //   `pdf`/`pdfs`, `image`/`images`, `video`/`videos`, `audioRef`/
    //   `audioRefs`) are media references, fetched when an http(s) URL
    //   (loadReferenceImages / loadReferenceAssets / the pdf loader in
    //   2026.6.35), so each host is a further destination, as for `image`.
    image_generate: { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" },
    music_generate: { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" },
    video_generate: {
      destination: null, symbols: "prompt",
      alsoDestinations: ["image", "images", "video", "videos", "audioRef", "audioRefs"], block: "refuse",
    },
    tts: { destination: null, symbols: "text", block: "refuse" },
    pdf: { destination: null, symbols: "prompt", alsoDestinations: ["pdf", "pdfs"], block: "refuse" },
    //   browser{action (enum), targetUrl, url, …}: navigates, types, uploads
    //   and runs page JavaScript; the destination is checked where the call
    //   names one, in `targetUrl` or the `url` it falls back to.
    browser: { destination: "targetUrl", symbols: "targetUrl", alsoDestinations: ["url"], block: "refuse" },
    //   image{prompt, image, images, …} (coding profile, 2026.6.35 and
    //   2026.7.1) and view_image{prompt, path, paths, …} (2026.9.x): load
    //   each reference (an http(s) URL is fetched) and send the image to an
    //   image model. No destination names the provider, the references'
    //   hosts are checked. A block refuses the whole input: with no
    //   reference left nothing is loaded or sent (image throws "image
    //   required" in 2026.6.35).
    image: { destination: null, symbols: "prompt", alsoDestinations: ["image", "images"], block: "refuse" },
    view_image: { destination: null, symbols: "prompt", alsoDestinations: ["path", "paths"], block: "refuse" },
  },
  paths: {
    read: { fields: ["path", "file_path"], mode: "read" },
    write: { fields: ["path", "file_path"], mode: "write" },
    edit: { fields: ["path", "file_path"], mode: "write" },
    // The shell's working directory (header): a denied one blocks the command.
    exec: { fields: ["workdir"], mode: "read" },
    // 2026.9.x (openclaw-tool-surface-2026-09-27.json): `ls{path,limit,after}`,
    // `view_image{path,paths,…}`. The image tools' references are media
    // references (`@path`, `file://`; a URL is the net gate's).
    ls: { fields: ["path"], mode: "read" },
    view_image: { fields: ["path", "paths"], mode: "read", refs: "media" },
    image: { fields: ["image", "images"], mode: "read", refs: "media" },
    // Local files a provider tool uploads, each a media reference in a string
    // field and its array twin (2026-09-29: the arrays too, now that a path
    // field may hold one; these tools also stay out of the inbound spec, so
    // the unmapped-input scan still raises their result's level for every
    // labeled path they name), and the browser's output path (screenshot,
    // pdf, download) and the local files its `upload` sends (`paths`;
    // reported as a write, the tool's stricter mode). message's `media` is a
    // path or URL it attaches.
    message: { fields: ["media"], mode: "read" },
    pdf: { fields: ["pdf", "pdfs"], mode: "read", refs: "media" },
    image_generate: { fields: ["image", "images"], mode: "read", refs: "media" },
    music_generate: { fields: ["image", "images"], mode: "read", refs: "media" },
    video_generate: { fields: ["image", "images", "video", "videos", "audioRef", "audioRefs"], mode: "read", refs: "media" },
    browser: { fields: ["path", "paths"], mode: "write" },
  },
  // The Tool Search dispatcher (on by default from 2026.9.x; opt-in on
  // 2026.6.35 and 2026.7.1 through `tools.toolSearch`). `tool_call{id, args}`
  // runs the catalog tool `id` (a name, or `<source>:<plugin>:<name>`), so
  // every gate above applies to the inner tool; `tool_search_code` runs
  // JavaScript that calls tools, which no gate can read, so it is refused.
  // `tool_search` / `tool_describe` only read the catalog (their results are
  // UNTRUSTED, openclaw-inbound.ts). supported-agents.md §2.1.
  dispatch: { tool_call: "openclaw-tool-call", tool_search_code: "refuse" },
  // Tools whose effect lands outside every Mandu chokepoint (read from each
  // tool's source in 2026.9.6; `cron` and `nodes` in 2026.7.1 too). OpenClaw
  // itself denies most of them over its HTTP tool surface and limits them to
  // the owner (src/security/dangerous-tools.ts). supported-agents.md §2.1.
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
    // Session hand-offs: the work runs in whichever OpenClaw gateway serves
    // the call. Under `mandu openclaw chat` / `agent --local` there is no
    // in-process gateway, so OpenClaw calls the configured one (a gateway
    // daemon, or a remote one), which runs outside Mandu. The proxy cannot
    // tell the launch shapes apart, so both are refused on every shape.
    // Schemas: sessions_send requires `message`, sessions_spawn `task`.
    sessions_send:
      "sessions_send hands text to another OpenClaw session, which an OpenClaw gateway outside Mandu may run; do the work in this session instead",
    sessions_spawn:
      "sessions_spawn starts a session in an OpenClaw gateway (or an ACP agent on the host) outside Mandu's protection; do the work in this session instead",
    // `full`-profile tools that act on another machine or on the gateway
    // itself. Schemas: computer, mobile_ui and canvas take an `action` enum,
    // openclaw requires `message`, github_publish rejects unknown keys.
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
    // Code Mode (`tools.codeMode`, 2026.5.18 and later; 2026.9.x reads an
    // absent setting as "auto"): the model sees `exec{code}` and
    // `wait{runId}` in place of the tools, and its JavaScript calls them
    // inside OpenClaw, where no wire gate reads which tool gets which input
    // (the decision taken for `tool_search_code` and for Goose's and
    // OpenCode 2's code mode, supported-agents.md §5.3.4). `wait` resumes a
    // suspended Code Mode run; its schema requires `runId`, so `{action: …}`
    // fails validation. Code Mode's `exec` is refused by form (refuseArgs
    // below), and the launcher turns Code Mode off (agent-config.ts
    // fenceOpenclawCodeMode).
    wait:
      "wait resumes an OpenClaw Code Mode run (model-written JavaScript that calls tools inside OpenClaw, where Mandu cannot check them); Code Mode is off under Mandu, call each tool directly instead",
  },
  // Tools refused only in some forms (RefuseArgRule). OpenClaw normalizes an
  // exec host trimmed and lowercased (requireValidExecTarget, 2026.7.1 and
  // 2026.9.6); `auto` resolves to the sandbox or the gateway host, both this
  // process under `mandu openclaw` (the agent loop runs in-process).
  //
  // Code Mode's `exec` shares the shell tool's name: `exec{code}` (2026.9.x
  // `{title, code, restartSafe}`, `code` required; 2026.5.18 to 2026.7.x
  // `{code, command, language}`) runs JavaScript that calls tools inside
  // OpenClaw. The shell `exec` has neither `code` nor `language`, so either
  // field, with any value (an empty `allow`), marks the Code Mode form and
  // refuses the call: `code` becomes "mandu-refused: <why>", which is not
  // JavaScript (a SyntaxError before anything runs), a `command` beside it
  // the block sentinel (2026.9.x then rejects the call: "code and command
  // must match"), and a `language` a value its enum rejects.
  refuseArgs: {
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
  // `process{action: write|paste|send-keys}` types into a background exec
  // session's stdin (bash-tools.ts, both versions); the exec gate reads that
  // text as a command, since the process is often a shell.
  stdin: { process: "openclaw-process" },
  // `apply_patch{input}` (coding profile, every captured build) writes,
  // deletes and moves the files its headers name (header; PatchToolFields).
  patch: { apply_patch: { field: "input", format: "apply-patch" } },
  // Tools that send a local file's bytes by path (UploadKind; 2026-10-17):
  // a chat attachment, a reference loaded into a model, a browser upload.
  // Before, `message.media` was only a read path (the sensitive-path gate,
  // with the view map only) and `attachments` was read by nothing, so a
  // secret file went to a chat channel as a file.
  upload: {
    message: "openclaw-message",
    view_image: "openclaw-media",
    image: "openclaw-media",
    pdf: "openclaw-media",
    image_generate: "openclaw-media",
    music_generate: "openclaw-media",
    video_generate: "openclaw-media",
    browser: "openclaw-browser-upload",
  },
  // A `MEDIA:` line in the reply text attaches the file it names when the
  // reply goes to a channel (ReplyMediaKind; 2026-10-17).
  replyMedia: "openclaw-media-lines",
  // read/write/edit/apply_patch resolve a relative path against the
  // workspace root, and exec's workdir against the process cwd the embedded
  // runner chdir()s to that workspace (2026.6.35). The launcher pins the
  // workspace to the launch directory for the local shapes (agent-config.ts
  // fenceOpenclawWorkspace) and names that directory only then, and only
  // without `--agent` (launcher agentStartDir); otherwise the proxy has no
  // base and treats it as unknown.
  relativeBase: "launch",
};

/** Goose (goose 1.53.0 wire, captured 2026-10-05:
 *  test/fixtures/goose-tool-surface-2026-10-05.json). The default surface of
 *  `goose run` / `goose session`: `shell{command,timeout_secs}` (`bash -c` in
 *  the launch directory, stdin /dev/null), `write{path,content}`,
 *  `edit{path,before,after}`, `tree{path,depth}`, `analyze{path,…}`,
 *  `read_image{source,crop}` (a local path or an http(s) URL),
 *  `delegate{instructions,source,provider,model,working_dir,…}`,
 *  `load{source,…}`, `load_skill{name,args}`, `apps__*`,
 *  `extensionmanager__*`. The opt-in builtins' tools are read from the same
 *  capture's `--with-builtin` entry. supported-agents.md §5.6 has the build
 *  and what the capture found.
 *
 *  - Goose has NO file-read tool: a file is read through `shell` (`cat`), so
 *    the exec gate and the exec-output legs carry file ingress.
 *  - `read_image` fetches its `source` when it is a URL (a net tool whose
 *    destination is that field) and reads it when it is a path (a media path
 *    read); the image then goes back to this same model, through the proxy.
 *  - `delegate` builds its subagent's provider from, in order, a recipe's
 *    settings, env GOOSE_SUBAGENT_PROVIDER, the call's `provider`, the
 *    config, the session (summon.rs resolve_provider). A model-written
 *    `provider` reached an unrouted provider in process (probed: it dialed
 *    OPENAI_HOST), and a `source` names a recipe whose settings can pin one
 *    (a recipe the agent can `write` itself). Both forms are refused; the
 *    launcher also pins GOOSE_SUBAGENT_PROVIDER to the routed provider.
 *    `working_dir` is a path the subagent runs in (a read).
 *  - Code mode (`--with-builtin code_execution`) replaces every non-developer
 *    tool with `execute_typescript{code, tool_graph}`, which runs TypeScript
 *    that calls tools in process: refused (decision D4). The dispatcher
 *    refusal's input (`{code: "throw …"}`) runs and fails, nothing else runs
 *    (probed on 1.53.0).
 *  - Refused outright, each because its effect lands outside every Mandu
 *    chokepoint: enabling an extension (a stdio server, an executable
 *    install), a Goose app (HTML/JS the desktop runs later, outside the
 *    launch; `delete_app` too since 2026-10-09: it removes a file of the
 *    desktop's app store, named by no gated field, and the model is the
 *    only one who asked), the scheduler (jobs fire in whichever process runs
 *    `--enable-scheduler`, normally the desktop's `goose serve`), the
 *    orchestrator's agent control (other sessions, possibly in `serve`),
 *    and macOS desktop automation. Every refusal input
 *    `{action: "mandu-refused: …"}` fails the tool's own parameter check
 *    (probed: "Missing or invalid 'prd'", "unknown variant", …). */
export const GOOSE_GATE_SURFACE: SurfaceTable = {
  exec: { shell: "command" },
  execOutput: { shell: "command" },
  net: {
    read_image: { destination: "source", symbols: "source" },
  },
  paths: {
    write: { fields: ["path"], mode: "write" },
    edit: { fields: ["path"], mode: "write" },
    tree: { fields: ["path"], mode: "read" },
    analyze: { fields: ["path"], mode: "read" },
    // a path, or an http(s) URL the net gate reads (`refs: "media"`)
    read_image: { fields: ["source"], mode: "read", refs: "media" },
    delegate: { fields: ["working_dir"], mode: "read" },
    // opt-in builtins: `docx_tool` and `xlsx_tool` write as well as read
    // (operations update_doc / update_cell), `pdf_tool` reads,
    // `summarize` reads every path in `paths`
    computercontroller__docx_tool: { fields: ["path"], mode: "write" },
    computercontroller__xlsx_tool: { fields: ["path"], mode: "write" },
    computercontroller__pdf_tool: { fields: ["path"], mode: "read" },
    summarize__summarize: { fields: ["paths"], mode: "read" },
  },
  dispatch: { execute_typescript: "refuse" },
  // NONE: `shell{command, timeout_secs}` has no `workdir` (captured), and
  // Goose runs every call in the launch directory whatever else the input
  // holds. A `workdir` the model writes there is a claim nothing acts on;
  // the call is read where the kernel says its shell started (2026-10-11).
  workdir: {},
  refuse: {
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
  },
  stdin: {},
  patch: {},
  // `shell` runs in the launch directory and `write` / `edit` resolve a
  // relative `path` there (probed on 1.53.0); the launcher names that
  // directory for every goose launch shape it allows.
  relativeBase: "launch",
};

/** Merge tables: a tool present in several keeps every field any of them names;
 *  a mode conflict resolves to `write` (the stricter one, as fs-gate does for an
 *  unknown mode). Pure. */
export function unionSurfaces(...tables: SurfaceTable[]): SurfaceTable {
  const exec: Record<string, string> = {};
  const execOutput: Record<string, string> = {};
  const net: Record<string, NetToolFields> = {};
  const paths: Record<string, PathToolFields> = {};
  const dispatch: Record<string, DispatchKind> = {};
  const refuse: Record<string, string> = {};
  const refuseArgs: Record<string, RefuseArgRule[]> = {};
  const stdin: Record<string, StdinKind> = {};
  const patch: Record<string, PatchToolFields> = {};
  const upload: Record<string, UploadKind> = {};
  // A `workdir` is believed only where EVERY merged agent honours it, at the
  // strictest shape any of them names (`argv` over `always`): a session with
  // no table of its own may be any of them, and Goose's `shell` honours none.
  const workdir: Record<string, WorkdirShape> = {};
  for (const [k, v] of Object.entries(tables[0]?.workdir ?? {})) {
    const all = tables.map((t) => (t.workdir !== undefined && Object.prototype.hasOwnProperty.call(t.workdir, k) ? t.workdir[k] : undefined));
    if (all.every((x) => x !== undefined)) workdir[k] = all.includes("argv") ? "argv" : v;
  }
  for (const t of tables) {
    for (const [k, v] of Object.entries(t.exec)) exec[k] ??= v;
    for (const [k, v] of Object.entries(t.execOutput)) execOutput[k] ??= v;
    for (const [k, v] of Object.entries(t.net)) {
      const prev = net[k];
      // a checkable destination beats none: the gate then checks the host;
      // a whole-input refusal on a block beats a field rewrite
      // and every further destination field either names is checked
      const also = [...new Set([...(prev?.alsoDestinations ?? []), ...(v.alsoDestinations ?? [])])];
      net[k] = prev
        ? {
            destination: prev.destination ?? v.destination,
            symbols: prev.symbols,
            ...(also.length > 0 ? { alsoDestinations: also } : {}),
            ...(prev.block ?? v.block ? { block: "refuse" as const } : {}),
          }
        : v;
    }
    for (const [k, v] of Object.entries(t.paths)) {
      const prev = paths[k];
      // media references read wherever any agent reads them (stripping `@` /
      // `file://` only gates more)
      const refs = prev?.refs ?? v.refs;
      paths[k] = prev
        ? { fields: [...new Set([...prev.fields, ...v.fields])], mode: prev.mode === "write" || v.mode === "write" ? "write" : "read", ...(refs ? { refs } : {}) }
        : { fields: [...v.fields], mode: v.mode, ...(refs ? { refs } : {}) };
    }
    // a name two agents dispatch differently resolves to `refuse`
    for (const [k, v] of Object.entries(t.dispatch)) dispatch[k] = dispatch[k] === undefined || dispatch[k] === v ? v : "refuse";
    // a name any agent refuses is refused
    for (const [k, v] of Object.entries(t.refuse)) refuse[k] ??= v;
    // every agent's rules apply (a value two rules disagree on is refused)
    for (const [k, v] of Object.entries(t.refuseArgs)) refuseArgs[k] = [...(refuseArgs[k] ?? []), ...v];
    for (const [k, v] of Object.entries(t.stdin)) stdin[k] ??= v;
    for (const [k, v] of Object.entries(t.patch)) patch[k] ??= v;
    for (const [k, v] of Object.entries(t.upload ?? {})) upload[k] ??= v;
  }
  // A relative base is known only when EVERY merged agent resolves against
  // its launch directory (a session with no table of its own is none of them).
  const relativeBase = tables.length > 0 && tables.every((t) => t.relativeBase === "launch") ? "launch" as const : undefined;
  // A reply is read for attachments when ANY merged agent attaches them.
  const replyMedia = tables.find((t) => t.replyMedia)?.replyMedia;
  return {
    exec, execOutput, net, paths, dispatch, refuse, refuseArgs, stdin, patch, upload, workdir,
    ...(replyMedia ? { replyMedia } : {}),
    ...(relativeBase ? { relativeBase } : {}),
  };
}

/** The table for an unbound-to-any-known-agent session: every agent's names. */
export const UNION_GATE_SURFACE: SurfaceTable = unionSurfaces(
  CLAUDE_CODE_GATE_SURFACE,
  OPENCODE_GATE_SURFACE,
  OPENCLAW_GATE_SURFACE,
  GOOSE_GATE_SURFACE,
);

const SURFACES: Partial<Record<InboundSpecId, SurfaceTable>> = {
  "claude-code": CLAUDE_CODE_GATE_SURFACE,
  opencode: OPENCODE_GATE_SURFACE,
  "openclaw-agent": OPENCLAW_GATE_SURFACE,
  // the lifted reference spec names the same OpenClaw tools
  openclaw: OPENCLAW_GATE_SURFACE,
  goose: GOOSE_GATE_SURFACE,
};

/** The gate surface for a spec id; the union for a spec with no table. Pure. */
export function gateSurfaceForSpec(spec: InboundSpecId): GateSurface {
  return { spec, replyMedia: null, ...(SURFACES[spec] ?? UNION_GATE_SURFACE) };
}

/** The gate surface for a session: its bound spec, else the process-global
 *  spec (the same resolution classification uses, so the gates and the trust
 *  spec can never disagree on which agent a session is). An arbiter passes
 *  its own `specs`, the same registry its engine classifies with. */
export function gateSurfaceFor(sessionKey?: string, specs: SessionSpecLookup = processSessionSpecs): GateSurface {
  return gateSurfaceForSpec(resolveInboundSpecId(sessionKey, specs));
}
