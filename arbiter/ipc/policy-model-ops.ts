/**
 * policy-model-ops — the arbiter side of the policy model of
 * confidentiality-plan-14-policy-suggestions.md §14.2-§14.5: the names-only
 * tier T1 (step 4b) and the contents tier T2 (step 4c, §14.11).
 * Mandu-new (no reference origin).
 *
 * TWO OPS, BOTH DATA PLANE (§14.2), consent bound to the exact bytes:
 *
 *   modelSuggestPreview {tier, endpoint?, roots, home?, includeHome?}
 *     walks the roots (the workspace scan's walk, names listed), builds the
 *     tier's payload, gates it (policy-model.ts), renders the request texts
 *     and KEEPS them in memory for PREVIEW_TTL_MS under their digest; answers
 *     the digest, the destination, the counts and, for T1, every line to be
 *     sent; for T2, the files and their byte counts (never their text).
 *     T2 goes ONLY to a declared `local: true` entry that passes
 *     `resolveLocalEndpoint` (the named one, or the only one declared): any
 *     other is refused before anything is walked, read or sent.
 *   modelSuggest {digest, waitMs?}
 *     sends exactly the kept texts, once per digest, through the classifier
 *     (a child process: inspect-mcp classify-main.ts), in the background
 *     like `suggestPolicy` (`waitMs` → `running: true`, call again to
 *     poll). The answer is re-validated against the kept payload, turned
 *     into suggestions (`source: "model-names"`) and filed as the scans'
 *     are. A digest no longer held is refused ("look again").
 *
 * THE CLASSIFIER is started per run from the command the arbiter was
 * launched with (`--classifier`, server-args.ts); without one both ops
 * answer "not available in this install". Its stdin is one JSON request, its
 * stdout one JSON answer; its stderr is discarded (a model's text must never
 * reach a log). Under `mandu-landlock-apply --net-only` with only the
 * endpoint's port when the applier and the kernel allow it (probe-gated, one
 * note on degrade, as inspect-mcp's confine: launcher inspect-net-confine.ts).
 * Its environment is an allowlist: the helper's transport selection, the
 * client keys, and the declared entry's token variable.
 *
 * NOTHING THE MODEL WRITES IS KEPT: the classifier keeps an id and two enums
 * per rule; this module re-validates them (policy-model.ts
 * `parseClassifierAnswer`) and builds every sentence and path from its own
 * candidate list. The `policy_model_call` event carries counts only.
 */
import { spawn, spawnSync } from "node:child_process";
import { tmpdir, userInfo } from "node:os";
import { isAbsolute } from "node:path";
import type { ModelEndpoint } from "../policy/compiled-policy.js";
import { isCloudBackedModel } from "../policy/cloud-model.js";
import {
  PREVIEW_TTL_MS, T1_PROMPT_VERSION, T1_REQUEST_TIMEOUT_MS, T1_RUN_TIMEOUT_MS,
  T2_HEAD_BYTES, T2_OFFICE_RUN_BYTES, T2_PROMPT_VERSION, T2_REQUEST_TIMEOUT_MS, T2_RUN_TIMEOUT_MS,
  batchCandidateIds, buildContentsPayload, buildNamesView, contentsCandidates, contentsToSuggestions, declaredDestination, isOfficeDocument, itemLine, officeTextHead,
  modelPayloadGate, parseClassifierAnswer, parseContentsClassifierAnswer, resolveLocalEndpoint,
  T1_BATCHES_MAX, payloadDigest, renderNamesBatches, rulesToSuggestions, withoutOrphanFolders,
  type ContentsCandidate, type ContentsVerdict, type ModelDestination, type ModelRule, type NamesView,
} from "../policy/policy-model.js";
import type { SuggestLaw } from "../policy/policy-suggestions.js";
import { detectSecretShapes } from "../policy/secret-detectors.js";
import { HISTORY_ROOTS_MAX } from "../policy/secret-history-scan.js";
import { readFileHead, readOfficeFileText, type SecretWorkspaceScan, type WorkspaceHeadRead, type WorkspaceOfficeTextRead } from "../policy/secret-workspace-scan.js";
import type { PolicySuggestionOps } from "./policy-suggestion-ops.js";
import type { ModelSuggestPreviewResult, ModelSuggestResult, SuggestionView } from "./protocol.js";

/** How the arbiter starts the classifier (server-args.ts `--classifier`,
 *  `--landlock-apply`). */
export interface ClassifierSpec {
  /** The command: argv[0] and its arguments (the entry script last). */
  argv: string[];
  /** `mandu-landlock-apply`'s absolute path, or null/absent (no confine). */
  landlockApply?: string | null;
}

/** What the `policy_model_call` event says (§14.5): counts only. */
export interface PolicyModelCallEvent {
  tier: "names" | "contents";
  endpoint: string;
  location: string;
  placement: string;
  items: number;
  bytes: number;
  requests: number;
  ms: number;
  kept: number;
  dropped: number;
  filed: number;
  failed: number;
}

/** One run of the classifier: `input` on stdin, stdout back. Never rejects:
 *  a failure is `{code: null|n, stdout}` with what came out. */
export type ClassifierRunner = (argv: readonly string[], input: string, opts: { env: NodeJS.ProcessEnv; timeoutMs: number }) => Promise<{ code: number | null; stdout: string; timedOut: boolean }>;

export interface PolicyModelOpsDeps {
  classifier: ClassifierSpec | null;
  /** The workspace walk with `list: true` under the one-scan-at-a-time
   *  flag; rejects "busy" when a scan runs. `documents` (T2): the home tier
   *  reads the document files too, so the detectors run over them. */
  walk: (roots: string[], home: string | undefined, includeHome: boolean, opts?: { documents?: boolean }) => Promise<SecretWorkspaceScan>;
  /** T2: a document's head, with the scan's safe open. Default
   *  `readFileHead`. */
  readHead?: (absPath: string, max: number) => Promise<WorkspaceHeadRead>;
  /** T2: an Office document's extracted text (§14.13), with the scan's safe
   *  open, at most `totalLeft` bytes read. Default `readOfficeFileText`. */
  readOfficeText?: (absPath: string, caps: { totalLeft: number }) => Promise<WorkspaceOfficeTextRead>;
  /** A human label above `public` at this path (a folder or a file). */
  labelledAbovePublic: (absPath: string, home: string) => boolean;
  /** The registered-value backstop over a text (secretValueHits). */
  registeredValueHit: (text: string) => boolean;
  /** The law in force: the declared models and the judge's law. */
  models: () => readonly ModelEndpoint[];
  law: () => SuggestLaw;
  suggestions: PolicySuggestionOps;
  emitCall: (e: PolicyModelCallEvent) => void;
  log: (m: string) => void;
  /** Test seams. */
  run?: ClassifierRunner;
  probeLandlock?: (applier: string) => boolean;
  /** The host's platform (default `process.platform`): the confine is
   *  Landlock, a Linux kernel guard. */
  platform?: string;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  userName?: string;
}

/** The environment the classifier gets (§14.3: the helper's transport
 *  selection and the client keys, nothing else), plus `tokenEnv`. Pure. */
export const CLASSIFIER_ENV_KEYS = [
  "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
  "CLAUDE_CONFIG_DIR", "CODEX_HOME",
  "MANDU_ULLM_MODE", "MANDU_ULLM_BINARY", "MANDU_ULLM_MODEL",
  "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "MANDU_ULLM_FORWARDER", "MANDU_MODEL_PROXY_URL", "MANDU_MODEL_CLIENT_KEYS",
  "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "NODE_EXTRA_CA_CERTS",
] as const;

export function classifierEnv(env: NodeJS.ProcessEnv, tokenEnv?: string): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const k of CLASSIFIER_ENV_KEYS) if (typeof env[k] === "string") out[k] = env[k];
  if (tokenEnv && /^[A-Za-z_][A-Za-z0-9_]*$/.test(tokenEnv) && typeof env[tokenEnv] === "string") out[tokenEnv] = env[tokenEnv];
  return out;
}

/** The TCP port a URL dials (explicit, else by scheme). Pure. */
export function urlPort(url: string): number | null {
  try {
    const u = new URL(url);
    if (u.port !== "") return Number(u.port);
    return u.protocol === "https:" ? 443 : u.protocol === "http:" ? 80 : null;
  } catch {
    return null;
  }
}

/** The confine's wrap argv (launcher landlock-net.ts `planLandlockNet`'s
 *  shape). Pure. */
export function landlockWrap(applier: string, ports: readonly number[]): string[] {
  const p = [...new Set(ports)].sort((a, b) => a - b).flatMap((n) => ["--allow-tcp-port", String(n)]);
  return [applier, "--net-only", ...p, "--skip-unsupported", "--"];
}

/** Why the classifier runs without its network confine, or undefined when
 *  the confine can be live. The confine is Landlock, a Linux kernel guard:
 *  on macOS there is none, whatever bin resolves (plan 14 §11.3). Pure but
 *  for `landlockNet`, asked only on Linux with an applier. */
export function confineDegradeNote(o: { platform: string; applier: string | null; landlockNet: (applier: string) => boolean }): string | undefined {
  if (o.platform !== "linux") {
    return `the classifier's network is not confined on ${o.platform === "darwin" ? "macOS" : "this system"}: its confine is Landlock, a Linux kernel guard`;
  }
  if (!o.applier) return "the classifier's network confine is unavailable: this install passed no mandu-landlock-apply; the classifier reaches the network like the helper without it";
  if (!o.landlockNet(o.applier)) return "the classifier's network confine is unavailable: this kernel has no Landlock TCP rules (needs 6.7)";
  return undefined;
}

/** The applier's own answer: does it confine TCP on this kernel? */
export function probeLandlockNet(applier: string): boolean {
  try {
    return spawnSync(applier, ["--allow-tcp-port", "1", "--net-only", "--", "true"], { stdio: "ignore", timeout: 5000 }).status === 0;
  } catch {
    return false;
  }
}

/** The production runner: spawn, write stdin, read at most 1 MiB of
 *  stdout, discard stderr, kill the process group at the deadline. */
export const spawnClassifier: ClassifierRunner = (argv, input, opts) => new Promise((resolve) => {
  let stdout = "";
  let timedOut = false;
  let settled = false;
  const child = spawn(argv[0]!, argv.slice(1), { stdio: ["pipe", "pipe", "ignore"], env: opts.env, cwd: tmpdir(), detached: true });
  const kill = (): void => { try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch { /* gone */ } } };
  const timer = setTimeout(() => { timedOut = true; kill(); }, opts.timeoutMs);
  timer.unref?.();
  child.stdout!.setEncoding("utf8");
  child.stdout!.on("data", (c: string) => {
    stdout += c;
    if (stdout.length > 1024 * 1024) { stdout = ""; kill(); }
  });
  const done = (code: number | null): void => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    resolve({ code, stdout, timedOut });
  };
  child.on("error", () => done(null));
  child.on("close", (code) => done(code));
  child.stdin!.on("error", () => { /* the child exited early */ });
  child.stdin!.end(input);
});

interface HeldPreview {
  digest: string;
  tier: "names" | "contents";
  destination: ModelDestination;
  /** The declared entry (and the list, for the guard), or the default. */
  endpoint: { kind: "declared"; entry: ModelEndpoint; all: ModelEndpoint[] } | { kind: "default"; expect: { mode: string; binary?: string } };
  batches: string[];
  batchIds: Array<Set<string>>;
  view: NamesView;
  /** T2: the candidate each request is about (by request index), and the
   *  candidates by id. */
  contents: { ids: string[]; candidates: Map<string, ContentsCandidate> } | null;
  items: number;
  bytes: number;
  wrap: string[];
  home: string | undefined;
  expiresAt: number;
  run: { promise: Promise<ModelSuggestResult>; result: ModelSuggestResult | null } | null;
}

/** At most this many previews are held (the oldest goes first). */
const HELD_MAX = 8;

export class PolicyModelOps {
  private readonly held = new Map<string, HeldPreview>();
  private running = false;
  private probed: boolean | null = null;
  private notedDegrade = false;
  private readonly now: () => number;
  private readonly run: ClassifierRunner;
  private readonly env: NodeJS.ProcessEnv;

  constructor(private readonly deps: PolicyModelOpsDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.run = deps.run ?? spawnClassifier;
    this.env = deps.env ?? process.env;
  }

  private sweep(): void {
    const t = this.now();
    for (const [k, v] of this.held) if (v.expiresAt <= t && (v.run === null || v.run.result !== null)) this.held.delete(k);
  }

  /** The confine's argv for these ports, or [] with one note (once). */
  private confine(ports: number[]): { wrap: string[]; live: boolean; note?: string } {
    const applier = this.deps.classifier?.landlockApply ?? null;
    const note = confineDegradeNote({
      platform: this.deps.platform ?? process.platform,
      applier,
      landlockNet: (a) => {
        if (this.probed === null) this.probed = (this.deps.probeLandlock ?? probeLandlockNet)(a);
        return this.probed;
      },
    });
    if (note !== undefined) {
      if (!this.notedDegrade) { this.notedDegrade = true; this.deps.log(`policy model: ${note}`); }
      return { wrap: [], live: false, note };
    }
    return { wrap: landlockWrap(applier!, ports), live: true };
  }

  /** Ask the classifier what the default helper would use (no request to
   *  any model). */
  private async describeDefault(): Promise<{ destination: ModelDestination; expect: { mode: string; binary?: string }; port: number }> {
    const spec = this.deps.classifier!;
    const r = await this.run(spec.argv, JSON.stringify({ v: 1, op: "describe" }) + "\n", { env: classifierEnv(this.env), timeoutMs: 20_000 });
    let v: Record<string, unknown> | null = null;
    try { v = JSON.parse(r.stdout) as Record<string, unknown>; } catch { v = null; }
    if (!v || v["ok"] !== true || v["destination"] === null || typeof v["destination"] !== "object") {
      const why = v && typeof v["error"] === "string" ? v["error"].replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, 300) : "the classifier did not answer";
      throw new Error(`the default helper model cannot be used: ${why}`);
    }
    const d = v["destination"] as Record<string, unknown>;
    const word = (x: unknown, dflt: string): string => (typeof x === "string" && /^[A-Za-z0-9][A-Za-z0-9 ._:()/@-]{0,79}$/.test(x) ? x : dflt);
    const port = typeof d["port"] === "number" && Number.isInteger(d["port"]) && d["port"] > 0 && d["port"] < 65536 ? d["port"] : 443;
    const mode = word(d["mode"], "api");
    const binary = typeof d["binary"] === "string" ? word(d["binary"], "claude") : undefined;
    return {
      destination: { kind: "default", name: word(d["name"], "the helper's default model"), location: "external", placement: "network", vendor: word(d["vendor"], "Anthropic") },
      expect: { mode, ...(binary ? { binary } : {}) },
      port,
    };
  }

  /** `modelSuggestPreview` (§14.2). Throws a plain-words refusal. */
  async preview(req: { tier?: unknown; endpoint?: unknown; roots?: unknown; home?: unknown; includeHome?: unknown }): Promise<ModelSuggestPreviewResult> {
    this.sweep();
    if (req.tier !== "names" && req.tier !== "contents") throw new Error('tier must be "names" or "contents"');
    const roots = Array.isArray(req.roots) && req.roots.every((r) => typeof r === "string" && isAbsolute(r)) ? (req.roots as string[]).slice(0, HISTORY_ROOTS_MAX) : null;
    if (roots === null || roots.length === 0) throw new Error("roots must be a non-empty list of absolute paths");
    if (req.includeHome !== undefined && typeof req.includeHome !== "boolean") throw new Error("includeHome must be a boolean");
    const home = typeof req.home === "string" && req.home.startsWith("/") ? req.home.replace(/\/+$/, "") || "/" : undefined;
    if (req.includeHome === true && home === undefined) throw new Error("includeHome needs home (an absolute path)");
    if (req.endpoint !== undefined && (typeof req.endpoint !== "string" || req.endpoint === "")) throw new Error("endpoint must be a declared model's name");
    if (this.deps.classifier === null) throw new Error("the model tier is not available in this install (the arbiter was started without a classifier)");
    if (req.tier === "contents") return this.previewContents(roots, home, req.includeHome === true, req.endpoint as string | undefined);

    // The destination, before anything is walked.
    let destination: ModelDestination;
    let endpoint: HeldPreview["endpoint"];
    let port: number;
    if (typeof req.endpoint === "string") {
      const all = [...this.deps.models()];
      const entry = all.find((m) => m.name === req.endpoint);
      if (!entry) throw new Error(`no model named '${req.endpoint}' is declared in policy.yaml models:`);
      destination = declaredDestination(entry);
      endpoint = { kind: "declared", entry: { ...entry }, all: all.map((m) => ({ ...m })) };
      port = urlPort(entry.url) ?? 443;
    } else {
      const d = await this.describeDefault();
      destination = d.destination;
      endpoint = { kind: "default", expect: d.expect };
      port = d.port;
    }

    const scan = await this.deps.walk(roots, home, req.includeHome === true);
    const walked = scan.roots.filter((r) => r.reason === undefined).map((r) => r.root);
    const view = buildNamesView({
      listed: scan.listed ?? [],
      roots: walked,
      labelledAbovePublic: (p) => this.deps.labelledAbovePublic(p, home ?? ""),
      home: home ?? "",
      userName: this.deps.userName ?? safeUserName(),
    });
    const gated = modelPayloadGate("names", destination, view.items, { registeredValueHit: this.deps.registeredValueHit });
    let kept = withoutOrphanFolders(gated.kept);
    let batches = renderNamesBatches(kept, walked.length);
    if (batches.length > T1_BATCHES_MAX) {
      // Never more requests than the classifier takes: the rest is not sent.
      const sendable = new Set(batches.slice(0, T1_BATCHES_MAX).flatMap((b) => [...batchCandidateIds(b)]));
      view.left.overCap += kept.filter((it) => it.kind === "file" && !sendable.has(it.id)).length;
      kept = kept.filter((it) => sendable.has(it.id));
      batches = batches.slice(0, T1_BATCHES_MAX);
    }
    // The whole payload once more: a hit here (across lines) sends nothing.
    const whole = batches.join("\n");
    if (batches.length > 0 && (detectSecretShapes(whole, { maxHits: 1 }).length > 0 || this.deps.registeredValueHit(whole))) {
      batches = [];
      gated.dropped.detector += kept.length;
      kept = [];
    }
    const bytes = batches.reduce((n, b) => n + Buffer.byteLength(b, "utf8"), 0);
    const confine = this.confine([port]);
    const result: ModelSuggestPreviewResult = {
      axis: true,
      tier: "names",
      digest: "",
      destination,
      roots: view.roots.map((r) => ({ index: r.index, root: r.root, files: r.files })),
      items: kept.length,
      bytes,
      requests: batches.length,
      names: kept.map(itemLine),
      files: [],
      left: { ...view.left, detector: gated.dropped.detector, registered: gated.dropped.registered, flagged: 0, unread: 0 },
      promptVersion: T1_PROMPT_VERSION,
      confine: { live: confine.live, ...(confine.note ? { note: confine.note } : {}) },
      expiresAt: 0,
      walk: { examined: scan.counts.examined, covered: scan.counts.covered, capped: scan.capped.lines },
    };
    if (batches.length === 0) return result;
    const digest = payloadDigest({ tier: "names", destination, promptVersion: T1_PROMPT_VERSION, batches });
    const expiresAt = this.hold({
      digest, tier: "names", destination, endpoint, batches, batchIds: batches.map(batchCandidateIds), view, contents: null,
      items: kept.length, bytes, wrap: confine.wrap, home, expiresAt: 0, run: null,
    });
    return { ...result, digest, expiresAt };
  }

  /** Keep a payload under its digest (a preview of the same bytes renews
   *  it); at most HELD_MAX, the oldest idle one going first. Returns when it
   *  is forgotten. */
  private hold(h: HeldPreview): number {
    const expiresAt = this.now() + PREVIEW_TTL_MS;
    const prior = this.held.get(h.digest);
    if (!prior || prior.run === null) this.held.set(h.digest, { ...h, expiresAt });
    else prior.expiresAt = expiresAt;
    while (this.held.size > HELD_MAX) {
      const oldest = [...this.held.values()].filter((x) => x.run === null || x.run.result !== null).sort((a, b) => a.expiresAt - b.expiresAt)[0];
      if (!oldest) break;
      this.held.delete(oldest.digest);
    }
    return expiresAt;
  }

  /**
   * T2's preview (§14.2, §14.4, §14.11): the endpoint first (a declared
   * `local: true` entry that passes `resolveLocalEndpoint`, else refused
   * before anything is walked), then the walk with the home tier reading
   * documents, the candidates, each one's head (16 KiB, the scan's safe
   * open), the builder (which takes only the `LocalModelEndpoint` brand) and
   * its gate (the detectors and the registered values over each head's exact
   * text). What the preview shows is the files and their byte counts, never
   * their text. An Office document (§14.13) is read by `readOfficeFileText`
   * instead of its head (a file with any enabled sensitivity label is left
   * out, labelled), its WHOLE extracted text goes through the detectors and
   * the registered values (`officeTextHead`), and only then its first 16 KiB
   * joins the builder like any head; its raw zip bytes are never a head.
   */
  private async previewContents(roots: string[], home: string | undefined, includeHome: boolean, name: string | undefined): Promise<ModelSuggestPreviewResult> {
    const all = [...this.deps.models()];
    let pick = name;
    if (pick === undefined) {
      const locals = all.filter((m) => m.local && !(m.model !== undefined && isCloudBackedModel(m.model)));
      if (locals.length === 0) {
        throw new Error("no model of your own is declared: file contents go only to a model declared local: true in policy.yaml models:");
      }
      if (locals.length > 1) throw new Error(`more than one model of your own is declared (${locals.map((m) => m.name).join(", ")}): name the one to use`);
      pick = locals[0]!.name;
    }
    const resolved = resolveLocalEndpoint(pick, all);
    if (!resolved.ok) throw new Error(`file contents go only to your own model: ${resolved.why}`);
    const local = resolved.endpoint;
    const destination = declaredDestination(local);
    const endpoint: HeldPreview["endpoint"] = { kind: "declared", entry: { ...local }, all: all.map((m) => ({ ...m })) };

    const scan = await this.deps.walk(roots, home, includeHome, { documents: true });
    const walked = scan.roots.filter((r) => r.reason === undefined).map((r) => r.root);
    const view = contentsCandidates({
      listed: scan.listed ?? [],
      roots: walked,
      labelledAbovePublic: (p) => this.deps.labelledAbovePublic(p, home ?? ""),
    });
    const readHead = this.deps.readHead ?? readFileHead;
    const readOffice = this.deps.readOfficeText ?? readOfficeFileText;
    const gateDeps = { registeredValueHit: this.deps.registeredValueHit };
    const heads = new Map<string, { head: Buffer; size: number }>();
    // Office documents (§14.13): the extracted text, checked whole, under
    // one byte budget per preview; left out are counted as text documents'.
    const office = { labelled: 0, unread: 0, detector: 0, registered: 0 };
    let officeLeft = T2_OFFICE_RUN_BYTES;
    const sendable: ContentsCandidate[] = [];
    for (const c of view.candidates) {
      if (isOfficeDocument(c.path)) {
        const r = officeLeft > 0 ? await readOffice(c.path, { totalLeft: officeLeft }) : null;
        if (r !== null && r.kind === "read") officeLeft -= r.result.bytes;
        const h = r === null ? { left: "unread" as const } : officeTextHead(r.kind === "read" ? r.result : { kind: "unreadable" }, gateDeps);
        if ("left" in h) { office[h.left]++; continue; }
        heads.set(c.id, h);
        sendable.push(c);
        continue;
      }
      const r = await readHead(c.path, T2_HEAD_BYTES);
      if (r.kind === "read") heads.set(c.id, { head: r.head, size: r.size });
      sendable.push(c);
    }
    const payload = buildContentsPayload(local, sendable, heads, gateDeps);
    heads.clear();
    const byId = new Map(view.candidates.map((c) => [c.id, c]));
    const bytes = payload.requests.reduce((n, b) => n + Buffer.byteLength(b, "utf8"), 0);
    const confine = this.confine([urlPort(local.url) ?? 443]);
    const result: ModelSuggestPreviewResult = {
      axis: true,
      tier: "contents",
      digest: "",
      destination,
      roots: view.roots.map((r) => ({ index: r.index, root: r.root, files: r.files })),
      items: payload.items.length,
      bytes,
      requests: payload.requests.length,
      names: [],
      files: payload.items.map((it) => {
        const c = byId.get(it.id)!;
        return { root: c.rootIndex, name: c.rel, bytes: it.bytes, truncated: it.truncated };
      }),
      left: {
        covered: view.left.covered, labelled: view.left.labelled + office.labelled, tooLong: 0, personal: 0, overCap: view.left.overCap,
        detector: payload.dropped.detector + office.detector, registered: payload.dropped.registered + office.registered,
        flagged: view.left.flagged, unread: view.left.unread + payload.dropped.unread + office.unread,
      },
      promptVersion: T2_PROMPT_VERSION,
      confine: { live: confine.live, ...(confine.note ? { note: confine.note } : {}) },
      expiresAt: 0,
      walk: { examined: scan.counts.examined, covered: scan.counts.covered, capped: scan.capped.lines },
    };
    if (payload.requests.length === 0) return result;
    const digest = payloadDigest({ tier: "contents", destination, promptVersion: T2_PROMPT_VERSION, batches: payload.requests });
    const expiresAt = this.hold({
      digest, tier: "contents", destination, endpoint, batches: payload.requests, batchIds: [],
      view: { roots: view.roots, items: [], candidates: new Map(), left: { covered: 0, labelled: 0, tooLong: 0, personal: 0, overCap: 0 } },
      contents: { ids: payload.items.map((it) => it.id), candidates: byId },
      items: payload.items.length, bytes, wrap: confine.wrap, home, expiresAt: 0, run: null,
    });
    return { ...result, digest, expiresAt };
  }

  /** `modelSuggest` (§14.2): send the kept bytes once, in the background. */
  async send(req: { digest?: unknown; waitMs?: unknown }): Promise<ModelSuggestResult> {
    this.sweep();
    const digest = typeof req.digest === "string" ? req.digest : "";
    const h = /^[0-9a-f]{64}$/.test(digest) ? this.held.get(digest) : undefined;
    if (!h || (h.run === null && h.expiresAt <= this.now())) {
      throw new Error("this preview is no longer held (it is kept 15 minutes, and not across a restart): look again");
    }
    const waitMs = typeof req.waitMs === "number" && Number.isFinite(req.waitMs) && req.waitMs >= 0 ? req.waitMs : null;
    if (h.run === null) {
      if (this.running) throw new Error("another model run is in progress; try again when it ends");
      this.running = true;
      const promise = this.execute(h).finally(() => { this.running = false; });
      h.run = { promise, result: null };
      promise.then((r) => { if (h.run) h.run.result = r; }, () => { /* execute never rejects */ });
    }
    const run = h.run;
    if (run.result !== null) return run.result;
    if (waitMs === null) return run.promise;
    let timer: NodeJS.Timeout | undefined;
    const late = new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), waitMs); timer.unref?.(); });
    const first = await Promise.race([run.promise, late]);
    if (timer) clearTimeout(timer);
    return first ?? this.runningAnswer(h);
  }

  private runningAnswer(h: HeldPreview): ModelSuggestResult {
    return {
      axis: true, running: true, digest: h.digest, destination: h.destination,
      sent: { requests: 0, items: h.items, bytes: h.bytes },
      counts: emptyModelCounts(), filed: [], suggestions: [], error: null, ms: 0,
    };
  }

  /** One run: the classifier, the re-validation, the filing. Never rejects. */
  private async execute(h: HeldPreview): Promise<ModelSuggestResult> {
    if (h.tier === "contents") return this.executeContents(h);
    const t0 = this.now();
    const counts = emptyModelCounts();
    let error: string | null = null;
    let filed: string[] = [];
    let suggestions: SuggestionView[] = [];
    let requests = 0;
    try {
      const request = {
        v: 1, op: "classify", tier: "names", promptVersion: T1_PROMPT_VERSION,
        endpoint: h.endpoint.kind === "declared" ? { kind: "declared", entry: h.endpoint.entry, all: h.endpoint.all } : { kind: "default", expect: h.endpoint.expect },
        batches: h.batches,
        requestTimeoutMs: T1_REQUEST_TIMEOUT_MS,
        runTimeoutMs: T1_RUN_TIMEOUT_MS,
      };
      const tokenEnv = h.endpoint.kind === "declared" ? h.endpoint.entry.tokenEnv : undefined;
      const argv = [...h.wrap, ...this.deps.classifier!.argv];
      const r = await this.run(argv, JSON.stringify(request) + "\n", { env: classifierEnv(this.env, tokenEnv), timeoutMs: T1_RUN_TIMEOUT_MS + 15_000 });
      const answer = r.timedOut
        ? { ok: false as const, answers: [], dropped: 0, error: "the model run took longer than 5 minutes and was stopped" }
        : parseClassifierAnswer(r.stdout, h.batchIds);
      if (!answer.ok) error = answer.error ?? "the classifier refused";
      const rules: ModelRule[] = [];
      for (const a of answer.answers) {
        if ("failed" in a) { counts.failedRequests++; requests++; continue; }
        requests++;
        rules.push(...a.rules);
      }
      counts.rules = rules.length;
      counts.dropped = answer.dropped;
      const pending = this.deps.suggestions.pending();
      const gen = rulesToSuggestions(rules, h.view, this.deps.law(), {
        destination: h.destination, pending: pending.map((p) => ({ id: p.id, source: p.source, edits: p.edits })), ...(h.home ? { home: h.home } : {}), now: this.now(),
      });
      counts.merged = gen.counts.merged;
      counts.tooBroad = gen.counts.tooBroad;
      counts.covered = gen.counts.covered;
      counts.dropped += gen.counts.dropped;
      counts.kept = gen.suggestions.length;
      const f = this.deps.suggestions.fileModelSuggestions(gen.suggestions);
      filed = f.filed;
      counts.filed = f.counts.filed;
      counts.alreadyPending = f.counts.alreadyPending;
      counts.dismissed = f.counts.dismissed;
      counts.overCap = f.counts.overCap;
      const mine = new Set(filed);
      suggestions = this.deps.suggestions.pending().filter((v) => v.source === "model-names" && (mine.has(v.id) || gen.suggestions.some((s) => s.findingKey === v.findingKey)));
    } catch (e) {
      error = `the model run failed: ${(e as Error).message}`;
    }
    const ms = this.now() - t0;
    this.deps.log(`policy model: names-only run to ${h.destination.name} (${h.destination.location}, ${h.destination.placement}): ${h.items} name(s) in ${h.batches.length} request(s), ${counts.rules} rule(s), ${counts.kept} kept, ${counts.filed} filed, ${counts.dropped} dropped, ${counts.failedRequests} request(s) failed, in ${ms} ms${error ? ` (${error})` : ""}`);
    try {
      this.deps.emitCall({
        tier: "names", endpoint: h.destination.name, location: h.destination.location, placement: h.destination.placement,
        items: h.items, bytes: h.bytes, requests, ms, kept: counts.kept, dropped: counts.dropped + counts.tooBroad, filed: counts.filed, failed: counts.failedRequests,
      });
    } catch { /* best-effort */ }
    return {
      axis: true, running: false, digest: h.digest, destination: h.destination,
      sent: { requests, items: h.items, bytes: h.bytes },
      counts, filed, suggestions, error, ms,
    };
  }

  /**
   * One T2 run (§14.11): the kept request texts to the declared local entry
   * the preview resolved, one request per document; each verdict
   * re-validated (`parseContentsClassifierAnswer`: an index the payload
   * holds, the two enums), then `contentsToSuggestions` (a `no-model`
   * answer the ordinary tightening, a lower one `humanOnly`) and the shared
   * filing. Never rejects.
   */
  private async executeContents(h: HeldPreview): Promise<ModelSuggestResult> {
    const t0 = this.now();
    const counts = emptyModelCounts();
    let error: string | null = null;
    let filed: string[] = [];
    let suggestions: SuggestionView[] = [];
    let requests = 0;
    try {
      if (h.endpoint.kind !== "declared" || h.contents === null) throw new Error("the contents tier needs your own declared model");
      const request = {
        v: 1, op: "classify", tier: "contents", promptVersion: T2_PROMPT_VERSION,
        endpoint: { kind: "declared", entry: h.endpoint.entry, all: h.endpoint.all },
        batches: h.batches,
        requestTimeoutMs: T2_REQUEST_TIMEOUT_MS,
        runTimeoutMs: T2_RUN_TIMEOUT_MS,
      };
      const argv = [...h.wrap, ...this.deps.classifier!.argv];
      const r = await this.run(argv, JSON.stringify(request) + "\n", { env: classifierEnv(this.env, h.endpoint.entry.tokenEnv), timeoutMs: T2_RUN_TIMEOUT_MS + 15_000 });
      const answer = r.timedOut
        ? { ok: false as const, answers: [], dropped: 0, error: `the model run took longer than ${Math.round(T2_RUN_TIMEOUT_MS / 60_000)} minutes and was stopped` }
        : parseContentsClassifierAnswer(r.stdout, h.batches.length);
      if (!answer.ok) error = answer.error ?? "the classifier refused";
      const verdicts: Array<{ id: string; verdict: ContentsVerdict }> = [];
      for (const a of answer.answers) {
        requests++;
        if ("failed" in a) { counts.failedRequests++; continue; }
        if (a.verdict === null) continue;
        verdicts.push({ id: h.contents.ids[a.batch]!, verdict: a.verdict });
      }
      counts.rules = verdicts.length;
      counts.dropped = answer.dropped;
      const gen = contentsToSuggestions(verdicts, h.contents.candidates, this.deps.law(), {
        destination: h.destination, ...(h.home ? { home: h.home } : {}), now: this.now(),
      });
      counts.public = gen.counts.public;
      counts.covered = gen.counts.covered;
      counts.dropped += gen.counts.dropped;
      counts.kept = gen.suggestions.length;
      const f = this.deps.suggestions.fileModelSuggestions(gen.suggestions);
      filed = f.filed;
      counts.filed = f.counts.filed;
      counts.alreadyPending = f.counts.alreadyPending;
      counts.dismissed = f.counts.dismissed;
      counts.overCap = f.counts.overCap;
      const mine = new Set(filed);
      suggestions = this.deps.suggestions.pending().filter((v) => v.source === "model-contents" && (mine.has(v.id) || gen.suggestions.some((s) => s.findingKey === v.findingKey)));
    } catch (e) {
      error = `the model run failed: ${(e as Error).message}`;
    }
    const ms = this.now() - t0;
    this.deps.log(`policy model: contents run to ${h.destination.name} (${h.destination.location}, ${h.destination.placement}): ${h.items} document(s) in ${h.batches.length} request(s), ${counts.rules} answer(s), ${counts.public} public, ${counts.kept} kept, ${counts.filed} filed, ${counts.dropped} dropped, ${counts.failedRequests} request(s) failed, in ${ms} ms${error ? ` (${error})` : ""}`);
    try {
      this.deps.emitCall({
        tier: "contents", endpoint: h.destination.name, location: h.destination.location, placement: h.destination.placement,
        items: h.items, bytes: h.bytes, requests, ms, kept: counts.kept, dropped: counts.dropped, filed: counts.filed, failed: counts.failedRequests,
      });
    } catch { /* best-effort */ }
    return {
      axis: true, running: false, digest: h.digest, destination: h.destination,
      sent: { requests, items: h.items, bytes: h.bytes },
      counts, filed, suggestions, error, ms,
    };
  }
}

export function emptyModelCounts(): ModelSuggestResult["counts"] {
  return { rules: 0, kept: 0, dropped: 0, merged: 0, tooBroad: 0, covered: 0, filed: 0, alreadyPending: 0, dismissed: 0, overCap: 0, failedRequests: 0, public: 0 };
}

function safeUserName(): string | undefined {
  try { return userInfo().username; } catch { return undefined; }
}
