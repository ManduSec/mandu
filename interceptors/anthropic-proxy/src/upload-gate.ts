/**
 * upload-gate — a tool that UPLOADS LOCAL FILES off the machine by path,
 * gated on the wire (supported-agents.md §2, "Claude Code 2.1.292";
 * confidentiality.md §7, "A tool that uploads a local file").
 *
 * Mandu-new (no reference origin). Claude Code 2.1.292's `DesignSync` syncs
 * the user's claude.ai/design projects. Its `write_files` takes, per file, a
 * `localPath` the tool itself reads, encodes and uploads to claude.ai: "the
 * contents never enter your context" (its own description). So the bytes
 * never reach a `tool_result` this proxy symbolizes, and the only trace of
 * them on the wire is the PATH the model wrote. Before this module the proxy
 * did not gate DesignSync at all (it was in no gate table), and only the OS
 * layer (the secret twins, the macOS read block) kept a secret file's bytes
 * home; where that confinement is unavailable, nothing did.
 *
 * THE TOOL (captured from the 2.1.292 wire,
 * arbiter/test/fixtures/claude-design-sync-tool-2026-10-07.json): one tool
 * dispatching on `method`. `finalize_plan{projectId, writes, deletes,
 * localDir}` locks the paths a plan may write and the directory uploads read
 * from (`localDir`, the working directory when absent) and returns a
 * `planId`; `write_files{projectId, planId, files: [{path, localPath | data,
 * encoding, mimeType}]}` uploads, each `localPath` relative to that
 * `localDir` (and confined to it by the tool). Every other method sends only
 * model-written text (names, paths, globs, counts) to claude.ai.
 *
 * WHAT THIS GATE DOES (kind `claude-design-sync`), in order:
 *   1. The NET LEGS over every string the call sends (net-gate.ts, reused):
 *      the session watermark at every upload host (a high session's upload
 *      of a paraphrase needs a binding or approval) and the per-symbol leg
 *      (a `$MDU:*` token in inline `data`, a name or a path is judged by the
 *      egress gate at each host, and even an allowed one cannot be put back
 *      inside the tool's own HTTPS request, which goes to a model API host
 *      the net proxy never carries: refused).
 *   2. `finalize_plan`: `localDir` must be an ABSOLUTE path. Absent, the
 *      tool reads from its working directory, which follows the shell's `cd`
 *      and is not known to this proxy (gate-surface.ts `relativeBase`), so the
 *      files a later upload reads could not be placed: refused, with a
 *      notice that says how to call it. An allowed plan's directory is
 *      remembered for the session (UploadPlans).
 *   3. `write_files`: every `localPath` is placed (an absolute one as is, a
 *      relative one against EVERY directory a plan of this session named:
 *      over-gating is safe where a wrong base is not; `~/` also as the home)
 *      and each spelling is put to the arbiter's `fileUploadDecision` (its
 *      label, its registration, a symlink's real path, the registered secret
 *      values in its bytes), on the human plane. A path it cannot place (no
 *      plan seen, a proxy restarted since) is refused with a notice that
 *      says to finalize the plan again.
 * ANY block refuses the WHOLE call: its input becomes `{action:
 * "mandu-refused: <why>"}`, which DesignSync's schema rejects (`method` is
 * required and unknown keys are not allowed), so nothing is uploaded. The
 * model reads the notice in place of the tool's validation error.
 *
 * FAIL-CLOSED: an arbiter without the op, one that throws or does not answer
 * in time, an input the gate cannot read (no `method`, `files` not a list
 * of objects, a `localPath` that is not a string), or more files than the
 * gate's bound refuse the call.
 *
 * THE ARTIFACT TOOLS (2026-10-09; supported-agents.md §2, "Claude Code
 * 2.1.295"; captured from the interactive wire of 2.1.290 to 2.1.295,
 * arbiter/test/fixtures/claude-artifact-tools-2026-10-09.json). Claude
 * Code's interactive sessions can advertise three tools that send to
 * claude.ai, each taking `action` from an enum (the refusal above is
 * rejected by each schema):
 *   - `Artifact` (kind `claude-artifact`): `publish` (the default action)
 *     uploads the local page `file_path`, every `files` source (an array of
 *     `{path}`, or a map of published path → source path | `{from}` |
 *     null, relative to `root` or the working directory) and `file_paths`
 *     (later releases' asset upload). Each path is placed ABSOLUTE only: as
 *     written, or a `files` source against an absolute `root`. The working
 *     directory follows the shell's `cd` and is not known here, so a path
 *     relative to it (or a relative `root`) refuses the call with how to
 *     call it (`proxy:upload-relative-path`). A `files` entry naming another
 *     artifact's file (`{artifact, path}`) is a server-side copy: no local
 *     byte. Every other action sends only model-written text.
 *   - `ArtifactData` (kind `claude-artifact-data`): the local JSON file of
 *     `file_path` and of each `writes[].file_path`, placed the same way
 *     (absolute only), whatever the action (over-gating is safe).
 *   - `ArtifactComments` (kind `claude-artifact-comments`): no local file;
 *     its `reply` text goes to claude.ai, so the net legs alone.
 * Every placed file goes to `fileUploadDecision` exactly as for DesignSync
 * (step 3), and the net legs (step 1) run over every string of every call.
 *
 * THE HOSTS (2026-10-17, UPLOAD_HOSTS): every step above judges against
 * claude.ai AND api.anthropic.com, where the 2.1.302 binary sends the
 * bytes; a binding must name each, and no TLS-inspection release applies.
 *
 * THE WINDOW (2026-10-17, `priorWriter`): an upload of a local file after a
 * call of the same model turn that may write files is refused whole before
 * anything is asked (`proxy:upload-after-write`): the agent runs that call
 * first, and the file judged now may not be the one the tool reads.
 *
 * OPENCLAW'S TOOLS (2026-10-17; supported-agents.md §2.1, "Tools that send
 * a local file"; read from the openclaw 2026.7.1 and 2026.9.9 dist). Three
 * kinds, each reading the file in OpenClaw's own process:
 *   - `openclaw-message`: `message` attaches media to a chat channel send.
 *     Every media source OpenClaw reads (openclawUploadRefs: the six source
 *     params and their snake_case spellings, `mediaUrls`, each
 *     `attachments[]` entry's six, and any other param a channel plugin
 *     adds whose name looks like a path and whose value names a local file)
 *     is read as OpenClaw's media loader reads it (placeMediaRef). A local
 *     file goes to `fileUploadDecision` with NO host: the channel is no host
 *     this proxy can name (tool-gate-surface.ts UploadKind), so no binding
 *     releases a secret file to it; the person's OK does. An http(s) source
 *     is a URL OpenClaw fetches: the net legs judge its host and symbols.
 *   - `openclaw-media`: `view_image`, `image`, `pdf` and the media
 *     generators load each reference in their path entry's fields and send
 *     the bytes to a model: judged `toModel` (a file at `any-model` may go).
 *     Their URLs are their net entries' further destinations already.
 *   - `openclaw-browser-upload`: `browser{action: "upload", paths}` puts the
 *     files into the page's file chooser; judged as a message attachment.
 * A relative reference is placed against the launch directory where the
 * agent resolves it there and the launcher named it (OpenClaw's workspace,
 * gate-surface.ts `relativeBase`; never for the browser, which reads it
 * under its own uploads directory); without a base, and for a `media://`
 * reference into OpenClaw's own media store, the call is refused with how
 * to call it. A block refuses the WHOLE call as above (`message` and
 * `browser` take an `action` enum; the media tools then name no reference,
 * so nothing is loaded or sent).
 *
 * NOT HERE: a tool outside every gate table that may upload a local path (a
 * future built-in before it is mapped, an MCP server's upload tool) is
 * unmapped-upload.ts's (supported-agents.md §2, "The upload residuals").
 */

import path from "node:path";
import { homedir } from "node:os";

import { fileURLToPath } from "node:url";

import type { Arbiter, FileUploadDecision, RuleRef } from "./arbiter-client.js";
import { UPLOAD_KINDS, type NetToolFields, type PathToolFields, type UploadKind } from "./gate-surface.js";
import { gateNetToolUse, hostOf, type NetGateOutcome } from "./net-gate.js";
import { refusedToolInput } from "./dispatch.js";
import { uploadHeldWords } from "./unmapped-upload-core.js";

// Why a file was held, in the model's words: shared with the unmapped leg
// (unmapped-upload-core.ts), re-exported for this module's callers.
export { uploadHeldWords };

/** The service every upload kind presents as: DesignSync the user's
 *  claude.ai/design projects, the Artifact tools pages "hosted on claude.ai"
 *  (their own descriptions), through the user's claude.ai login. The host
 *  the gate's events name. */
export const UPLOAD_HOST = "claude.ai";

/** DesignSync's host (UPLOAD_HOST; the name the 2.1.292 gate shipped with). */
export const DESIGN_SYNC_HOST = UPLOAD_HOST;

/**
 * EVERY host an upload kind's bytes may reach, observed, not assumed
 * (2026-10-17; read off the Claude Code 2.1.302 binary, the excerpts pinned
 * in arbiter/test/fixtures/claude-upload-hosts-2026-10-17.json): DesignSync
 * posts its MCP calls, `write_files` included, to `${BASE_API_URL}/v1/design/mcp`
 * ("Claude Design is only reachable from api.anthropic.com"), and the
 * Artifact tools' "file inputs" PUT each file's bytes to an upload URL whose
 * origin must be the OAuth API host's (`api.anthropic.com`, or its staging
 * twin) while the tools present as claude.ai. So the session and per-symbol
 * legs ask about each host, and a file counts as bound only where its
 * bindings name each (`destinations`; file-upload.ts DESTINATIONS).
 *
 * `api.anthropic.com` is a model API host: the egress proxy did not carry it
 * (net-proxy egress.ts MODEL_HOST_SUFFIXES, the launch's NO_PROXY), so no
 * network layer saw these uploads. Under the model-host deny (since
 * 2026-10-18, with the confidentiality axis on; net-proxy
 * model-host-paths.ts) they ride the egress proxy's inspected leg, on paths
 * its list names for these tools, where its gate and tripwire see the
 * bytes too; this gate stays the decision. Either way a placeholder the
 * policy would put back is not: the per-symbol leg runs without the
 * TLS-inspection release (`tlsInspected` is never passed for an upload).
 */
export const UPLOAD_HOSTS: readonly string[] = [UPLOAD_HOST, "api.anthropic.com"];

/** Fail-closed ceiling for one arbiter fileUploadDecision: the arbiter
 *  client's whole-call bound for the op (arbiter client.ts
 *  FILE_UPLOAD_TIMEOUT_MS, 60 s), since the arbiter scans a large file in
 *  chunks (confidentiality.md §7, STREAMED). An arbiter that stops answering
 *  still fails closed at the client's 5 s idle timeout (its progress frames
 *  re-arm it only while it works). */
export const DEFAULT_UPLOAD_GATE_TIMEOUT_MS = 60_000;

/** Bound on the file spellings one call may put to the arbiter (DesignSync
 *  takes at most 256 files per call; each relative one is placed against
 *  every plan directory). A call needing more is refused. */
export const UPLOAD_GATE_MAX_PATHS = 1024;

/** Plan directories remembered per session (oldest out). */
export const UPLOAD_PLANS_MAX = 64;

const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** The upload directory of every DesignSync plan this proxy relayed, per
 *  session. In memory only: a restarted proxy knows none, and a relative
 *  `localPath` is then refused until the model finalizes the plan again. */
export class UploadPlans {
  private readonly bases = new Map<string, string[]>();

  remember(session: string, dir: string): void {
    const list = (this.bases.get(session) ?? []).filter((d) => d !== dir);
    list.push(dir);
    while (list.length > UPLOAD_PLANS_MAX) list.shift();
    this.bases.set(session, list);
  }

  of(session: string): readonly string[] {
    return this.bases.get(session) ?? [];
  }
}

export interface UploadGateOutcome {
  decision: "allow" | "block";
  reason: string;
  /** What the model reads in place of the call's result, when blocked. */
  notice?: string;
  ruleRef?: RuleRef;
  /** The first file the arbiter held: its field key and the path judged. */
  field?: string;
  path?: string;
  requiresApproval?: boolean;
  /** The Approvals row of the first held file. */
  approvalId?: string;
  /** Set when the net legs decided (session watermark or a symbol). */
  net?: NetGateOutcome;
  /** Every file the arbiter allowed, for observability. */
  allowed?: Array<{ field: string; path: string; ruleRef?: RuleRef }>;
}

export interface UploadGateResult {
  /** The input the agent receives: unchanged, or the refusal on a block. */
  input: unknown;
  /** Absent: the tool is not an upload tool. */
  outcome?: UploadGateOutcome;
}

export interface UploadGateOptions {
  uploadTools: Readonly<Record<string, UploadKind>>;
  arbiter: Pick<Arbiter, "fileUploadDecision" | "sessionEgressDecision" | "desymbolizationDecision">;
  /** The watermark session (the net legs) and the approval row's session. */
  sessionKey?: string;
  plans: UploadPlans;
  log?: (m: string) => void;
  timeoutMs?: number;
  /** The net proxy TLS-inspects non-model HTTPS (net-gate.ts). Read and
   *  IGNORED: an upload's bytes reach a model API host the net proxy never
   *  carries (UPLOAD_HOSTS), so nothing can be put back on the way. */
  tlsInspected?: boolean;
  /** Home for a `~/` local path (tests). */
  home?: string;
  /** The session agent's path fields (gate-surface.ts GateSurface.paths):
   *  where an `openclaw-media` tool names its references. */
  pathTools?: Readonly<Record<string, PathToolFields>>;
  /** The absolute directory the agent resolves a relative reference in,
   *  when the surface says it is the launch directory and the launcher
   *  named it (proxy.ts relativeBaseFor). Absent: a relative reference of
   *  an OpenClaw kind is refused. */
  launchDir?: string;
  /** An earlier call of the SAME model turn that may write files (the
   *  proxy's `possibleWriter`; the agent runs it first): a call that uploads
   *  a local file is refused, since the file the gate reads now may not be
   *  the one the tool reads after it (`proxy:upload-after-write`). */
  priorWriter?: string;
}

/** The refusal of an upload that follows a possible writer in the same
 *  turn (UploadGateOptions.priorWriter). Shared with unmapped-upload.ts. */
export function afterWriteNotice(name: string, writer: string): string {
  return `mandu-upload-gate: upload refused, nothing was sent: an earlier call of this turn (${writer}) runs first and may change the files ${name} names, and Mandu checks a file before the call runs, not when the tool reads it. Call ${name} again on its own, in a later turn, once the other calls have finished. (rule: proxy:upload-after-write)`;
}

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e as Error); },
    );
  });
}

/** Every string in a value (object values and array elements, depth-first).
 *  Pure. */
export function stringsIn(v: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 16) return out;
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const el of v) stringsIn(el, out, depth + 1);
  else if (isObj(v)) for (const el of Object.values(v)) stringsIn(el, out, depth + 1);
  return out;
}

/** An absolute directory a plan names, normalized; null when it is not one
 *  the gate can place (absent, relative, `~`). Pure. */
export function planDir(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (!s.startsWith("/")) return null;
  return path.posix.resolve(s);
}

/** Where a `localPath` may land: absolute as is; relative against every
 *  plan directory; `~/x` also as the home's `x` (the tool would not expand
 *  it, the gate checks it anyway). `null` when a relative path has no base.
 *  Pure. */
export function placeLocalPath(raw: string, bases: readonly string[], home: string): string[] | null {
  const s = raw.trim();
  if (s === "") return null;
  if (s.startsWith("/")) return [path.posix.resolve(s)];
  const out = new Set<string>();
  if (s === "~" || s.startsWith("~/")) out.add(path.posix.resolve(home, s.slice(2)));
  for (const b of bases) out.add(path.posix.resolve(b, s));
  return out.size > 0 ? [...out] : null;
}

/** What an Artifact-tool call uploads from this machine. */
export interface ArtifactUploadTargets {
  /** Every local file the call names, placed absolute. */
  targets: UploadTarget[];
  /** Set when the input cannot be read: the call is refused. */
  unreadable?: string;
  /** Set when a path is relative to the working directory (or `root` is
   *  relative): the call is refused with how to call it. */
  relative?: { field: string; shown: string };
}

/**
 * The local files an Artifact-tool call uploads (the module header, "THE
 * ARTIFACT TOOLS"): Artifact's `publish` (the default action) `file_path`,
 * `files` sources (against an absolute `root`) and `file_paths`; every
 * `file_path` of ArtifactData, top level and in `writes`; nothing for
 * ArtifactComments or a non-publish Artifact action. Absolute paths only
 * (`~/` as the home); the first path it cannot place is `relative`. Pure.
 */
export function artifactUploadTargets(kind: UploadKind, input: Record<string, unknown>, home: string): ArtifactUploadTargets {
  const targets: UploadTarget[] = [];
  const fail = (unreadable: string): ArtifactUploadTargets => ({ targets: [], unreadable });
  /** null when placed (pushed), else the refusal. */
  const place = (field: string, raw: unknown, base: string | null): ArtifactUploadTargets | null => {
    if (typeof raw !== "string") return fail(`${field} is not a string`);
    if (raw.trim() === "") return fail(`${field} is empty`);
    const placed = placeLocalPath(raw, base !== null ? [base] : [], home);
    if (placed === null) return { targets: [], relative: { field, shown: raw } };
    for (const p of placed) targets.push({ field, shown: raw, path: p });
    return null;
  };
  if (kind === "claude-artifact-comments" || kind === "claude-design-sync") return { targets };

  if (kind === "claude-artifact-data") {
    if (input["file_path"] !== undefined) {
      const r = place("file_path", input["file_path"], null);
      if (r) return r;
    }
    const writes = input["writes"];
    if (writes !== undefined) {
      if (!Array.isArray(writes)) return fail("writes is not a list");
      for (let i = 0; i < writes.length; i++) {
        const w = writes[i];
        if (!isObj(w)) return fail(`writes[${i}] is not an object`);
        if (w["file_path"] === undefined) continue; // inline `data`: through the net legs
        const r = place(`writes[${i}].file_path`, w["file_path"], null);
        if (r) return r;
      }
    }
    return { targets };
  }

  // claude-artifact: only a publish reads local files (list, read, delete,
  // pin, unpin send the model's own text, which the net legs saw).
  if ((input["action"] ?? "publish") !== "publish") return { targets };
  let root: string | null = null;
  if (input["root"] !== undefined) {
    if (typeof input["root"] !== "string") return fail("root is not a string");
    root = planDir(input["root"]);
    if (root === null) return { targets: [], relative: { field: "root", shown: input["root"] } };
  }
  if (input["file_path"] !== undefined) {
    const r = place("file_path", input["file_path"], null);
    if (r) return r;
  }
  const files = input["files"];
  if (Array.isArray(files)) {
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      if (!isObj(f)) return fail(`files[${i}] is not an object`);
      const r = place(`files[${i}].path`, f["path"], root);
      if (r) return r;
    }
  } else if (isObj(files)) {
    for (const [published, src] of Object.entries(files)) {
      const field = `files[${JSON.stringify(published)}]`;
      if (src === null) continue; // removes a published path
      let r: ArtifactUploadTargets | null;
      if (typeof src === "string") r = place(field, src, root);
      else if (isObj(src) && own(src, "from")) r = place(`${field}.from`, src["from"], root);
      else if (isObj(src) && own(src, "artifact")) continue; // another artifact's file, copied server side: no local byte
      else return fail(`${field} is not a source path`);
      if (r) return r;
    }
  } else if (files !== undefined) {
    return fail("files is neither a list nor a map");
  }
  const filePaths = input["file_paths"];
  if (filePaths !== undefined) {
    if (!Array.isArray(filePaths)) return fail("file_paths is not a list");
    for (let i = 0; i < filePaths.length; i++) {
      const r = place(`file_paths[${i}]`, filePaths[i], null);
      if (r) return r;
    }
  }
  return { targets };
}

const APPROVALS_HINT =
  " The user can allow it on the Mandu dashboard's Approvals page (mandu dashboard): tell them, and do not retry before they answer.";

/** What the model reads when a held file refused the call. Names the file
 *  the model itself wrote and the rule; never what the file holds. */
export function uploadBlockNotice(shown: string, d: FileUploadDecision | null, failure?: string): string {
  const { plain, id, asks } = uploadHeldWords(shown, d, failure);
  return `mandu-upload-gate: upload refused, nothing was sent: ${plain}.${asks ? APPROVALS_HINT : ""} (rule: ${id})`;
}

function refuse(
  reason: string,
  notice: string,
  extra: Partial<UploadGateOutcome> = {},
): UploadGateResult {
  return { input: refusedToolInput(notice), outcome: { decision: "block", reason, notice, ...extra } };
}

/**
 * Gate one call of an upload tool. NEVER THROWS: an arbiter that errors or
 * does not answer refuses the call. Absent outcome ⇒ not an upload tool.
 */
export async function gateUploadToolUse(name: string, input: unknown, opts: UploadGateOptions): Promise<UploadGateResult> {
  if (!own(opts.uploadTools, name)) return { input };
  const kind = opts.uploadTools[name];
  if (kind === undefined || !UPLOAD_KINDS.includes(kind)) {
    return refuse(`${name}: upload kind ${String(kind)} is not one this proxy reads — fail closed`,
      `mandu-upload-gate: upload refused, nothing was sent: Mandu could not read this call (rule: proxy:upload-unreadable)`,
      { ruleRef: { source: "fail-closed", id: "proxy:upload-unreadable" } });
  }
  const unreadable = (why: string): UploadGateResult => {
    opts.log?.(`upload-gate: ${name} → REFUSED (${why})`);
    return refuse(`${why} — fail closed`,
      `mandu-upload-gate: upload refused, nothing was sent: Mandu could not read this call (${why}) (rule: proxy:upload-unreadable)`,
      { ruleRef: { source: "fail-closed", id: "proxy:upload-unreadable" } });
  };
  if (!isObj(input)) return unreadable("the input is not an object");
  if (kind === "openclaw-message" || kind === "openclaw-media" || kind === "openclaw-browser-upload") {
    return gateOpenclawUpload(name, kind, input, opts, unreadable);
  }
  // DesignSync dispatches on `method`; the Artifact tools on `action`
  // (Artifact's may be absent: a publish).
  const method = kind === "claude-design-sync" ? input["method"] : input["action"];
  if (kind === "claude-design-sync" && typeof method !== "string") return unreadable("no method");
  if (kind !== "claude-design-sync" && typeof method !== "string" && !(kind === "claude-artifact" && method === undefined)) {
    return unreadable("no action");
  }

  // 1. The net legs over every string the call sends, at EVERY host it may
  //    reach (UPLOAD_HOSTS), strictest first-block; no TLS-inspection
  //    release (the model API host never passes the net proxy).
  const spec: NetToolFields = { destination: "url", symbols: "payload" };
  const payload = stringsIn(input).join("\n");
  for (const host of UPLOAD_HOSTS) {
    const ng = await gateNetToolUse(name, { url: `https://${host}/`, payload }, {
      arbiter: opts.arbiter as Arbiter,
      ...(opts.sessionKey ? { sessionKey: opts.sessionKey } : {}),
      ...(opts.log ? { log: opts.log } : {}),
      ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
      netTools: { [name]: spec },
    });
    if (ng.outcome?.decision === "block") {
      const notice = ng.outcome.notice ?? "mandu-net-gate: network use blocked, nothing was sent";
      return refuse(ng.outcome.reason, notice, { net: ng.outcome, ...(ng.outcome.ruleRef ? { ruleRef: ng.outcome.ruleRef } : {}) });
    }
  }

  // 2'. The Artifact tools: every local file the call names, placed absolute.
  if (kind !== "claude-design-sync") {
    const what = `${String(method ?? "publish")}`;
    const r = artifactUploadTargets(kind, input, opts.home ?? homedir());
    if (r.unreadable !== undefined) return unreadable(r.unreadable);
    if (r.relative !== undefined) {
      const { field, shown } = r.relative;
      const why = `${field} '${shown}' is a relative path, and the working directory it is relative to follows the shell's cd, which Mandu cannot see`;
      const how = field === "root" || field.startsWith("files")
        ? "with absolute paths (or root set to an absolute directory)"
        : "with the absolute path of the file";
      opts.log?.(`upload-gate: ${name}.${what} → REFUSED (${why})`);
      return refuse(why,
        `mandu-upload-gate: upload refused, nothing was sent: ${why}, so it cannot check the file. Call ${name} again ${how}. (rule: proxy:upload-relative-path)`,
        { ruleRef: { source: "fail-closed", id: "proxy:upload-relative-path" }, field });
    }
    return judgeUploadTargets(name, input, r.targets, `${name}.${what}`, opts, unreadable);
  }

  const session = opts.sessionKey ?? "";
  // 2. A plan names the directory uploads read from: it must be absolute.
  if (method === "finalize_plan") {
    const dir = planDir(input["localDir"]);
    if (dir === null) {
      const why = input["localDir"] === undefined
        ? "finalize_plan names no localDir, so the files its uploads read would come from a working directory Mandu cannot see"
        : "finalize_plan's localDir is not an absolute path, so Mandu cannot place the files its uploads read";
      opts.log?.(`upload-gate: ${name}.finalize_plan → REFUSED (${why})`);
      return refuse(why,
        `mandu-upload-gate: plan refused, nothing was sent: ${why}. Call DesignSync finalize_plan again with localDir set to the absolute path of the directory the bundle was built into. (rule: proxy:upload-plan-dir)`,
        { ruleRef: { source: "fail-closed", id: "proxy:upload-plan-dir" } });
    }
    opts.plans.remember(session, dir);
    return { input, outcome: { decision: "allow", reason: `plan reads from ${dir}` } };
  }
  if (method !== "write_files") return { input, outcome: { decision: "allow", reason: `${method} uploads no local file` } };

  // 3. Every local file the call uploads, placed and put to the arbiter.
  const files = input["files"];
  if (files === undefined) return { input, outcome: { decision: "allow", reason: "write_files names no file" } };
  if (!Array.isArray(files)) return unreadable("files is not a list");
  const home = opts.home ?? homedir();
  const bases = opts.plans.of(session);
  const targets: UploadTarget[] = [];
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    if (!isObj(f)) return unreadable(`files[${i}] is not an object`);
    const lp = f["localPath"];
    if (lp === undefined) continue; // inline `data`: its text went through the net legs
    if (typeof lp !== "string") return unreadable(`files[${i}].localPath is not a string`);
    const placed = placeLocalPath(lp, bases, home);
    if (placed === null) {
      const why = lp.trim() === ""
        ? `files[${i}].localPath is empty`
        : `files[${i}].localPath '${lp}' is relative and Mandu has not seen this session finalize a plan with an absolute localDir`;
      opts.log?.(`upload-gate: ${name}.write_files → REFUSED (${why})`);
      return refuse(why,
        `mandu-upload-gate: upload refused, nothing was sent: ${why}, so it cannot check the file. Call DesignSync finalize_plan again with localDir set to the absolute path of the bundle's directory, then write_files with the new planId. (rule: proxy:upload-plan-dir)`,
        { ruleRef: { source: "fail-closed", id: "proxy:upload-plan-dir" }, field: `files[${i}].localPath` });
    }
    for (const p of placed) targets.push({ field: `files[${i}].localPath`, shown: lp, path: p });
  }
  return judgeUploadTargets(name, input, targets, "write_files", opts, unreadable);
}

/** One local file a call uploads: the field that names it, the spelling the
 *  model wrote (for the notice), and a placed absolute path. */
interface UploadTarget { field: string; shown: string; path: string }

/** Where a kind's bytes go, as `fileUploadDecision` is asked. */
interface UploadDestination { destination: string; destinations: readonly string[]; toModel: boolean }

/** Claude Code's upload tools: claude.ai and the API host (UPLOAD_HOSTS). */
const CLAUDE_UPLOAD_DESTINATION: UploadDestination = {
  destination: UPLOAD_HOST, destinations: UPLOAD_HOSTS.filter((h) => h !== UPLOAD_HOST), toModel: false,
};

// ── OpenClaw (module header, "OPENCLAW'S TOOLS") ─────────────────────────────

/** `message`'s top-level media source params (openclaw 2026.7.1 and 2026.9.9
 *  message-action-params.ts BASE_ACTION_MEDIA_SOURCE_PARAM_KEYS), with the
 *  snake_case spellings OpenClaw also reads (resolveSnakeCaseParamKey). */
export const OPENCLAW_MESSAGE_SOURCE_KEYS: readonly string[] = [
  "media", "path", "filePath", "mediaUrl", "fileUrl", "image", "file_path", "media_url", "file_url",
];
/** `message`'s list of media sources. */
export const OPENCLAW_MESSAGE_LIST_KEYS: readonly string[] = ["mediaUrls", "media_urls"];
/** The source params of one `attachments[]` entry
 *  (STRUCTURED_ATTACHMENT_MEDIA_SOURCE_PARAM_KEYS, snake_case too). */
export const OPENCLAW_ATTACHMENT_SOURCE_KEYS: readonly string[] = [
  "media", "mediaUrl", "path", "filePath", "fileUrl", "url", "media_url", "file_path", "file_url",
];
/** A param name a channel plugin may read a media source from (its own
 *  `mediaSourceParams`, e.g. Matrix `avatarPath` / `avatarUrl`): judged when
 *  its value names a LOCAL file by an absolute, `~` or `file:` spelling. */
const OPENCLAW_EXTRA_SOURCE_KEY_RE = /path|file|media|image|avatar|icon|attach|url|src|source/i;

/** What one media reference names, read the way OpenClaw's media loader
 *  reads it (web-media.ts loadWebMediaInternal; view_image's own `@` strip):
 *  a leading `@` and a `MEDIA:` prefix dropped, a `file:` URL decoded, `~`
 *  as the home, a relative path against `base`. */
export type MediaRef =
  | { kind: "local"; path: string }
  | { kind: "remote"; url: string; host: string | null }
  /** a `data:` URL (inline bytes the model wrote) or nothing at all */
  | { kind: "none" }
  /** relative, and no base to place it against */
  | { kind: "relative" }
  /** `media://`: OpenClaw's own media store, which the proxy cannot place */
  | { kind: "store" };

/** Place one media reference (MediaRef). Pure. */
export function placeMediaRef(raw: string, home: string, base?: string): MediaRef {
  let s = raw.trim();
  if (s.startsWith("@")) s = s.slice(1).trim();
  if (!/^media:\/\//i.test(s)) s = s.replace(/^\s*MEDIA\s*:\s*/i, "").trim();
  if (s === "") return { kind: "none" };
  if (/^https?:\/\//i.test(s)) return { kind: "remote", url: s, host: hostOf(s) };
  if (/^data:/i.test(s)) return { kind: "none" };
  if (/^media:\/\//i.test(s)) return { kind: "store" };
  if (/^file:/i.test(s)) {
    let p: string;
    try { p = fileURLToPath(s); } catch { p = s.replace(/^file:(\/\/)?/i, ""); }
    s = p;
  }
  if (s.startsWith("/")) return { kind: "local", path: path.posix.resolve(s) };
  if (s === "~" || s.startsWith("~/")) return { kind: "local", path: path.posix.resolve(home, s.slice(2)) };
  if (base !== undefined && base.startsWith("/")) return { kind: "local", path: path.posix.resolve(base, s) };
  return { kind: "relative" };
}

/** Does `raw` name a local file by a spelling that needs no base (absolute,
 *  `~`, `file:`, after the `@` / `MEDIA:` prefixes)? Pure. */
function localSpelling(raw: string): boolean {
  const s = raw.trim().replace(/^@/, "").replace(/^\s*MEDIA\s*:\s*/i, "").trim();
  return s.startsWith("/") || s === "~" || s.startsWith("~/") || /^file:/i.test(s);
}

/** One media reference of an OpenClaw call: the field that holds it (for
 *  the notice and the event) and the string as the model wrote it. */
export interface OpenclawRef { field: string; shown: string }

/** The OpenClaw upload kinds (module header). */
export type OpenclawUploadKind = "openclaw-message" | "openclaw-media" | "openclaw-browser-upload";

/** Every media reference an OpenClaw upload-kind call names (module header),
 *  or the first field the gate cannot read. `fields`: an `openclaw-media`
 *  tool's reference fields. Pure. */
export function openclawUploadRefs(
  kind: OpenclawUploadKind,
  input: Record<string, unknown>,
  fields: readonly string[] = [],
): { refs: OpenclawRef[]; unreadable?: string } {
  const refs: OpenclawRef[] = [];
  const one = (field: string, v: unknown): string | null => {
    if (v === undefined || v === null) return null;
    if (typeof v !== "string") return `${field} is not a string`;
    if (v.trim() !== "") refs.push({ field, shown: v });
    return null;
  };
  /** A string or a list of strings (a non-string element is skipped, as
   *  OpenClaw's own list readers skip it). */
  const many = (field: string, v: unknown): string | null => {
    if (v === undefined || v === null) return null;
    if (typeof v === "string") return one(field, v);
    if (!Array.isArray(v)) return `${field} is neither a string nor a list`;
    v.forEach((el, i) => { if (typeof el === "string" && el.trim() !== "") refs.push({ field: `${field}[${i}]`, shown: el }); });
    return null;
  };
  const fail = (why: string): { refs: OpenclawRef[]; unreadable: string } => ({ refs: [], unreadable: why });

  if (kind === "openclaw-media") {
    for (const f of fields) {
      const bad = many(f, input[f]);
      if (bad) return fail(bad);
    }
    return { refs };
  }
  if (kind === "openclaw-browser-upload") {
    if (input["action"] !== "upload") return { refs };
    const bad = many("paths", input["paths"]);
    return bad ? fail(bad) : { refs };
  }
  // openclaw-message: every action (each hydrates the same params)
  for (const [k, v] of Object.entries(input)) {
    if (OPENCLAW_MESSAGE_SOURCE_KEYS.includes(k)) {
      const bad = one(k, v);
      if (bad) return fail(bad);
    } else if (OPENCLAW_MESSAGE_LIST_KEYS.includes(k)) {
      const bad = many(k, v);
      if (bad) return fail(bad);
    } else if (k === "attachments") {
      if (v === undefined || v === null) continue;
      if (!Array.isArray(v)) return fail("attachments is not a list");
      for (let i = 0; i < v.length; i++) {
        const a: unknown = v[i];
        if (!isObj(a)) continue; // OpenClaw skips a non-object entry
        for (const [ak, av] of Object.entries(a)) {
          const field = `attachments[${i}].${ak}`;
          if (OPENCLAW_ATTACHMENT_SOURCE_KEYS.includes(ak)) {
            const bad = one(field, av);
            if (bad) return fail(bad);
          } else if (OPENCLAW_EXTRA_SOURCE_KEY_RE.test(ak) && typeof av === "string" && localSpelling(av)) {
            refs.push({ field, shown: av });
          }
        }
      }
    } else if (OPENCLAW_EXTRA_SOURCE_KEY_RE.test(k) && typeof v === "string" && localSpelling(v)) {
      refs.push({ field: k, shown: v });
    }
  }
  return { refs };
}

/** Gate one call of an OpenClaw upload kind (module header). NEVER THROWS. */
async function gateOpenclawUpload(
  name: string,
  kind: OpenclawUploadKind,
  input: Record<string, unknown>,
  opts: UploadGateOptions,
  unreadable: (why: string) => UploadGateResult,
): Promise<UploadGateResult> {
  const fields = kind === "openclaw-media" ? opts.pathTools?.[name]?.fields : [];
  if (fields === undefined) return unreadable(`${name} names no reference field this proxy knows`);
  const r = openclawUploadRefs(kind, input, fields);
  if (r.unreadable !== undefined) return unreadable(r.unreadable);
  const home = opts.home ?? homedir();
  // the browser reads a relative path under its own uploads directory
  const base = kind === "openclaw-browser-upload" ? undefined : opts.launchDir;
  const targets: UploadTarget[] = [];
  const remote: Array<{ field: string; url: string; host: string | null }> = [];
  for (const ref of r.refs) {
    const m = placeMediaRef(ref.shown, home, base);
    if (m.kind === "local") targets.push({ field: ref.field, shown: ref.shown, path: m.path });
    else if (m.kind === "remote") remote.push({ field: ref.field, url: m.url, host: m.host });
    else if (m.kind === "relative" || m.kind === "store") {
      const why = m.kind === "store"
        ? `${ref.field} '${ref.shown}' names OpenClaw's own media store, where Mandu cannot tell which file it is`
        : `${ref.field} '${ref.shown}' is a relative path, and Mandu does not know the directory OpenClaw reads it in for this launch`;
      opts.log?.(`upload-gate: ${name} → REFUSED (${why})`);
      return refuse(why,
        `mandu-upload-gate: refused, nothing was sent: ${why}, so it cannot check the file. Call ${name} again with the absolute path of the file. (rule: proxy:upload-relative-path)`,
        { ruleRef: { source: "fail-closed", id: "proxy:upload-relative-path" }, field: ref.field });
    }
  }
  // An http(s) source of a message is a URL OpenClaw fetches: its host and
  // its symbols are judged as any fetch's (the media tools' URLs are their
  // net entries' further destinations already).
  if (kind === "openclaw-message") {
    const seen = new Set<string>();
    for (const u of remote) {
      if (seen.has(u.url)) continue;
      seen.add(u.url);
      if (u.host === null) return unreadable(`${u.field} is a URL with no host the gate can read`);
      const ng = await gateNetToolUse(name, { url: u.url }, {
        arbiter: opts.arbiter as Arbiter,
        ...(opts.sessionKey ? { sessionKey: opts.sessionKey } : {}),
        ...(opts.log ? { log: opts.log } : {}),
        ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
        ...(opts.tlsInspected ? { tlsInspected: true } : {}),
        netTools: { [name]: { destination: "url", symbols: "url" } },
      });
      if (ng.outcome?.decision === "block") {
        const notice = ng.outcome.notice ?? "mandu-net-gate: network use blocked, nothing was sent";
        return refuse(ng.outcome.reason, notice, { net: ng.outcome, ...(ng.outcome.ruleRef ? { ruleRef: ng.outcome.ruleRef } : {}), field: u.field });
      }
    }
  }
  const what = kind === "openclaw-browser-upload" ? `${name}.upload`
    : kind === "openclaw-message" ? `${name}.${typeof input["action"] === "string" ? input["action"] : "send"}`
    : name;
  return judgeUploadTargets(name, input, targets, what, opts, unreadable, {
    destination: "", destinations: [], toModel: kind === "openclaw-media",
  });
}


/** Step 3, shared by every kind: put each placed file to the arbiter's
 *  `fileUploadDecision`; one held file refuses the WHOLE call. */
async function judgeUploadTargets(
  name: string,
  input: Record<string, unknown>,
  targets: readonly UploadTarget[],
  what: string,
  opts: UploadGateOptions,
  unreadable: (why: string) => UploadGateResult,
  to: UploadDestination = CLAUDE_UPLOAD_DESTINATION,
): Promise<UploadGateResult> {
  if (targets.length > UPLOAD_GATE_MAX_PATHS) {
    return unreadable(`${targets.length} file paths in one call exceeds the gate's bound (${UPLOAD_GATE_MAX_PATHS})`);
  }
  if (targets.length === 0) return { input, outcome: { decision: "allow", reason: `${what} uploads no local file` } };
  // THE WINDOW (file-upload.ts): an earlier call of this turn runs first and
  // may write the very file judged now (`cp ~/notes.txt bundle/a.html` then
  // the upload of a.html, in one message). Refused before anything is asked.
  if (opts.priorWriter !== undefined) {
    const why = `${opts.priorWriter} runs before ${name} in the same turn and may change the files it uploads`;
    opts.log?.(`upload-gate: ${what} → REFUSED (${why})`);
    return refuse(why, afterWriteNotice(name, opts.priorWriter),
      { ruleRef: { source: "fail-closed", id: "proxy:upload-after-write" }, field: targets[0]!.field, path: targets[0]!.path });
  }

  const decide = opts.arbiter.fileUploadDecision?.bind(opts.arbiter);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_UPLOAD_GATE_TIMEOUT_MS;
  const allowed: NonNullable<UploadGateOutcome["allowed"]> = [];
  let held: { t: (typeof targets)[number]; d: FileUploadDecision } | null = null;
  const asked = new Set<string>();
  for (const t of targets) {
    if (asked.has(t.path)) continue;
    asked.add(t.path);
    let d: FileUploadDecision;
    try {
      if (!decide) throw new Error("this arbiter cannot judge an upload");
      d = await withTimeout(
        decide({
          tool: name, path: t.path, destination: to.destination,
          ...(to.destinations.length > 0 ? { destinations: to.destinations } : {}),
          ...(to.toModel ? { toModel: true } : {}),
          ...(opts.sessionKey ? { sessionKey: opts.sessionKey } : {}),
        }),
        timeoutMs,
        `arbiter fileUploadDecision timed out after ${timeoutMs}ms`,
      );
    } catch (err) {
      const msg = (err as Error).message;
      opts.log?.(`upload-gate: ${name}.${t.field} → REFUSED (arbiter: ${msg})`);
      return refuse(`arbiter unreachable — fail closed: ${msg}`, uploadBlockNotice(t.shown, null, msg), {
        ruleRef: { source: "fail-closed", id: "proxy:arbiter-unreachable" }, field: t.field, path: t.path, requiresApproval: false,
      });
    }
    if (d.allow) { allowed.push({ field: t.field, path: t.path, ...(d.ruleRef ? { ruleRef: d.ruleRef } : {}) }); continue; }
    opts.log?.(`upload-gate: ${name}.${t.field} → ${t.path} HELD (${d.reason})`);
    // keep asking: every held file queues its own Approvals row at once
    held ??= { t, d };
  }
  if (held) {
    const { t, d } = held;
    const requiresApproval = d.allow === false && d.requiresApproval;
    return refuse(d.reason, uploadBlockNotice(t.shown, d), {
      ...(d.ruleRef ? { ruleRef: d.ruleRef } : {}),
      field: t.field, path: t.path, requiresApproval,
      ...(d.allow === false && d.approvalId ? { approvalId: d.approvalId } : {}),
      allowed,
    });
  }
  return { input, outcome: { decision: "allow", reason: `${allowed.length} local file(s) checked`, allowed } };
}
