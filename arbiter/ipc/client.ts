/**
 * client — thin Mandu arbiter IPC client (Mandu-new, no reference origin).
 *
 * A small promise-based client other components (Track A model proxy, tests)
 * use to call the arbiter over its Unix socket using the NDJSON protocol in
 * ./protocol.ts. It maintains a single connection, frames requests/responses by
 * newline, and correlates replies by `id`.
 *
 * The Rust interceptors will reimplement this same wire protocol natively; this
 * TS client exists for TS callers and the test suite.
 */

import { connect, Socket } from "node:net";
import { dirname, isAbsolute, resolve as resolvePath } from "node:path";
import { NdjsonLineSplitter } from "./ndjson-lines.js";
import { assertSocketPathFits, socketPathProblem } from "./socket-path.js";

import type {
  ArbiterResponse,
  SymbolizeResult,
  DesymbolizeResult,
  ResolveResult,
  SymbolProvenanceResult,
  ClassifyOpResult,
  HelloResult,
  PingResult,
  HandlingPromptResult,
  RecordToolCallResult,
  DesymbolizationDecisionOpResult,
  FsPathDecisionOpResult,
  FileUploadDecisionOpResult,
  ClassifyExecOpResult,
  ResolveExecArgvOpResult,
  ExecGateOpResult,
  ExecDecisionForOpResult,
  EscalateExecOpResult,
  ReportExecCleanVerdictOpResult,
  ClaimCleanReporterResult,
  ExecCleanVerdictForOpResult,
  ReportExecTwinsOpResult,
  ExecTwinsForOpResult,
  PathLevelOpResult,
  PathLevelsOpResult,
  MovePageLabelsResult,
  WhyPathOpResult,
  WhyHostOpResult,
  ReaderProgramOpResult,
  WhySymbolOpResult,
  PolicySnapshotOpResult,
  EgressApprovalsResult,
  ResolveEgressApprovalResult,
  ForgetEgressApprovalResult,
  SetSessionPostureResult,
  SetSessionSpecResult,
  SymbolShapeResult,
  SessionRelayMode,
  ReplyLayoutRule,
  ReplyTabOrigin,
  SetSessionRelayResult,
  SessionRelayWire,
  ReserveBlockWire,
  RecordForwardedClearResult,
  ForwardedClearResult,
  ForwardedPlaceholderMapWire,
  RecordForwardedPlaceholdersResult,
  ForwardedPlaceholdersResult,
  SessionUpstreamResult,
  GateSurfaceResult,
  EmitResult,
  EventsResult,
  SessionsResult,
  DeleteSessionResult,
  SubscribeEventFrame,
  IsProcessTaintedResult,
  FileTrustResult,
  ConfidentialityStateResultWire,
  DeclassifySymbolResultWire,
  SessionEgressDecisionResultWire,
  SessionExecRootResultWire,
  GuardAttachResultWire,
  EgressFingerprintScanResultWire,
  StrippedPlaceholdersResultWire,
  TakeRelayNoticesResultWire,
  PlaceholderKnownResultWire,
  SessionLoginsWire,
  SessionStateResultWire,
  SetPathLabelResultWire,
  RemovePathLabelResultWire,
  PathLabelsResultWire,
  PolicyDocumentResult,
  NetConnectAllowResult,
  ModelEndpointWire,
  ModelEndpointsResult,
  TestFlowOpRequest,
  TestFlowResult,
  ApplyPolicyDocumentResult,
  MintUserRuleOpRequest,
  MintUserRuleResult,
  PolicyItemVersionWire,
  HolderSourceBindingResultWire,
  PolicyProposeResult,
  PolicyProposalsOpRequest,
  PolicyProposalsResult,
  PolicyChangesResult,
  ResolvePolicyProposalResult,
  UndoPolicyChangeResult,
  PolicyExplainResult,
  PolicySchemaResult,
  PolicyPreviewResult,
  ExportDbLabelsResult,
  PathLabelWire,
  LabelWrittenPathResultWire,
  RemoveDerivedLabelResultWire,
  DerivedLabelsSinceResultWire,
  LabelRootsSinceResultWire,
  LabelledLevelResultWire,
  SessionPathLabelResultWire,
  ClearSessionPathLabelsResultWire,
  FilterPromptResultWire,
  PromptFiltersResultWire,
  PromptFilterPacksResultWire,
  PromptExceptionsResultWire,
  PromptHoldsResultWire,
  PromptPackEditResultWire,
  FollowDerivedLabelResultWire,
  DiscoverSecretsResultWire,
  ScanSecretHistoryResultWire,
  SuggestPolicyResult,
  ModelSuggestPreviewResult,
  ModelSuggestResult,
  PolicySuggestionsResult,
  ApplySuggestionResult,
  DismissSuggestionResult,
  GuardSettingsResult,
  GitHistoryLocksResult,
  RegisterRepositoryResult,
  CacheSealsResult,
  SealCacheEntriesResult,
  BeginLaunchResult,
  EndLaunchResult,
  HumanPlaneStatusResult,
  AgentReceiptTaintResultWire,
  SuggestFromScanOpRequest,
  SuggestFromScanResultWire,
} from "./protocol.js";
import type {
  ArbiterEvent,
  StoredEvent,
  SessionSummary,
} from "../events/event-store.js";
import type {
  ClassifyRequest,
  DesymbolizationRequest,
} from "../policy/policy-interface.js";
import type { RelayNoticeWire } from "./relay-notices.js";
import type { ExecShell } from "../policy/exec-classify.js";
import type { ExecCleanVerdictReport } from "../policy/exec-clean-verdicts.js";
import type { ExecTwinReport } from "../policy/exec-twin-store.js";
import type { FsPathDecisionRequest } from "../policy/fs-outbound.js";
import type { FileUploadDecisionRequest } from "../policy/file-upload.js";
import type {
  EgressApproval,
  ApprovalStatus,
  ApprovalScope,
} from "../policy/egress-approvals.js";

/** Handle to an open subscription. Call close() to end the dedicated stream
 * connection; the arbiter stops fan-out when the socket closes. */
export interface SubscriptionHandle {
  close: () => void;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  /** A progress frame arrived (`{id, progress: true}`): the op is at work. */
  progress?: () => void;
}

/** Per-call deadline for every one-shot op. Matches the gates' existing
 *  convention (anthropic-proxy fs-gate/exec-gate `DEFAULT_GATE_TIMEOUT_MS`),
 *  which is the fail-closed bound this generalizes. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 5000;
/** `filterPrompt`'s longest wait (plan 15 §4.3, §13.5 item 11): above the
 *  longest plugin deadline (30 s) and the confinement probe, reached only
 *  while the arbiter keeps sending progress frames; the proxy fails closed
 *  after. */
export const FILTER_PROMPT_TIMEOUT_MS = 60_000;
/** `fileUploadDecision`'s longest wait (confidentiality.md §7, STREAMED):
 *  above the arbiter's scan deadline (server.ts FILE_UPLOAD_SCAN_DEADLINE_MS,
 *  45 s), so the arbiter's own hold answers first; reached only while the
 *  arbiter keeps sending progress frames. The proxies' upload gates wait
 *  this long too (their DEFAULT_*UPLOAD*_TIMEOUT_MS). */
export const FILE_UPLOAD_TIMEOUT_MS = 60_000;

/** `discoverSecrets` walks HOME + the workspace roots (depth- and count-capped,
 *  but still real filesystem I/O over a cold cache), so it is the one op whose
 *  honest worst case exceeds the 5s bound. It runs once at launch, off the
 *  per-turn hot path. */
const DISCOVER_SECRETS_TIMEOUT_MS = 30_000;

/** `scanSecretHistory` runs git over a whole history under its own deadline
 *  (60 s by default); the client waits past it by a margin. */
export const SCAN_SECRET_HISTORY_TIMEOUT_MS = 180_000;

export interface ArbiterClientOptions {
  /** Override the per-call deadline (ms). */
  requestTimeoutMs?: number;
  /** PATH mode only: where the endpoint went when dialing the current path
   *  finds no listener (ENOENT / ECONNREFUSED / ENOTSOCK). Returns the path
   *  to dial instead, or null. Asked with backoff (REDISCOVER_MIN_MS doubling
   *  to REDISCOVER_MAX_MS while it finds nothing, reset on a connect); a
   *  rediscovery that rejects with a dead-endpoint error (the arbiter is down)
   *  grows no backoff, so the first dial after it is back re-learns. The human-plane
   *  clients use {@link humanPlaneRediscovery} (arbiter-human-plane.md §5.1):
   *  an arbiter restarted under a live session listens on a NEW human socket. */
  rediscoverPath?: (stale: string) => Promise<string | null>;
}

/** The first wait between two rediscoveries, and the longest. */
export const REDISCOVER_MIN_MS = 250;
export const REDISCOVER_MAX_MS = 30_000;

/** Dial errors that mean "nothing listens at this path any more". */
const DEAD_ENDPOINT_CODES = new Set(["ENOENT", "ECONNREFUSED", "ENOTSOCK"]);

/** One `hello` on `sock`, on a client of its own, closed after. */
async function helloAt(sock: string, timeoutMs: number): Promise<{ humanSock?: unknown; instanceId?: unknown; channel?: unknown }> {
  const c = new ArbiterClient(sock, { requestTimeoutMs: timeoutMs });
  try {
    return (await c.hello()) as unknown as { humanSock?: unknown; instanceId?: unknown; channel?: unknown };
  } finally {
    c.close();
  }
}

/**
 * The rediscovery for a HUMAN-PLANE client (arbiter-human-plane.md §5.1): ask
 * the arbiter on the DATA socket (`dataSock`: the launcher's spelling, which
 * follows a restart: `current/arbiter.sock`, or the pinned path the new
 * instance binds) for its human socket, the way the launcher learned it
 * (`hello().humanSock`), and accept the answer only when:
 *   - it is an absolute `.sock` path in the SAME directory as the stale one
 *     (the walled `human/` directory, which the agent world cannot reach),
 *     and is not the data socket: a human-plane op never goes to the data
 *     socket ({@link acceptableHumanSock});
 *   - the socket at that path answers `hello` as the `human` channel, with
 *     the instance id the data socket reported (the same arbiter, not a
 *     leftover, and never a data socket under another name).
 * Anything else → null, and the caller's request fails as it would have
 * (the reply filter passes the token through; an enforcement path fails
 * closed).
 */
export function humanPlaneRediscovery(
  dataSock: string,
  opts: { timeoutMs?: number } = {},
): (stale: string) => Promise<string | null> {
  const timeoutMs = opts.timeoutMs ?? 3000;
  return async (stale: string): Promise<string | null> => {
    let hello: { humanSock?: unknown; instanceId?: unknown };
    try {
      hello = await helloAt(dataSock, timeoutMs);
    } catch (e) {
      // Nothing listens on the data socket either (the arbiter is down):
      // say so, so the caller grows no backoff (ArbiterClient dial).
      if (DEAD_ENDPOINT_CODES.has((e as NodeJS.ErrnoException).code ?? "")) throw e;
      return null;
    }
    const cand = typeof hello.humanSock === "string" ? hello.humanSock : "";
    if (!acceptableHumanSock(cand, stale, dataSock)) return null;
    let confirm: { instanceId?: unknown; channel?: unknown };
    try {
      confirm = await helloAt(cand, timeoutMs);
    } catch {
      return null;
    }
    // The arbiter says which channel answered: only its human channel will do.
    if (confirm.channel !== "human") return null;
    if (typeof hello.instanceId === "string" && confirm.instanceId !== hello.instanceId) return null;
    return cand;
  };
}

/** The checks {@link humanPlaneRediscovery} puts a reported path through:
 *  absolute, `.sock`, in the stale path's directory, not the data socket,
 *  and short enough to dial as written. */
export function acceptableHumanSock(cand: string, stale: string, dataSock: string): boolean {
  if (cand === "" || !isAbsolute(cand) || !cand.endsWith(".sock")) return false;
  if (!isAbsolute(stale) || dirname(resolvePath(cand)) !== dirname(resolvePath(stale))) return false;
  if (resolvePath(cand) === resolvePath(dataSock)) return false;
  return socketPathProblem(cand) === null;
}

/**
 * Where a client connects (policy-surface.md §2.6):
 *   - a Unix-socket PATH — the data socket every interceptor dials;
 *   - `{ fd }` — an already-open channel this process INHERITED at spawn (the
 *     arbiter's admin channel, one end of the supervisor's socketpair);
 *   - `{ socket }` — a live Socket the caller already holds (the supervisor's
 *     own end of that pair, `child.stdio[n]`).
 * A pre-opened channel is adopted, never dialed, and never re-dialed: once it
 * closes the client is closed (fail-closed — there is nothing to reconnect to).
 */
export type ArbiterClientTarget = string | { fd: number } | { socket: Socket };

export class ArbiterClient {
  /** The dial target in PATH mode; undefined for a pre-opened channel.
   *  Replaced only by a rediscovery (ArbiterClientOptions.rediscoverPath). */
  private socketPath: string | undefined;
  private readonly rediscoverPath?: (stale: string) => Promise<string | null>;
  /** Rediscovery backoff: the earliest time the next one may run, and the
   *  wait that one sets. Reset by a successful dial. */
  private rediscoverAt = 0;
  private rediscoverDelay = REDISCOVER_MIN_MS;
  /** How many times this client moved to a rediscovered path. */
  rediscoveries = 0;
  private readonly fd?: number;
  private presetSocket?: Socket;
  private readonly requestTimeoutMs: number;
  private sock?: Socket;
  /** The socket of an IN-FLIGHT connect (not yet "connect"-ed), so close()
   *  can destroy it instead of letting it land on a closed client. */
  private connectingSock?: Socket;
  private lines = new NdjsonLineSplitter();
  private nextId = 1;
  private readonly pending = new Map<string | number, Pending>();
  private connectPromise?: Promise<void>;
  /** close() is TERMINAL: a straggler request after close() must reject, not
   *  silently re-connect. The old behavior (request → connect() → fresh
   *  socket on a closed client) leaked ownerless long-lived connections —
   *  e.g. a proxy's late best-effort emit re-opening its already-closed
   *  client, whose socket then held the process's event loop open (found
   *  live 2026-07-11 by the integration exit-guard). */
  private closed = false;
  /** unref() was requested — re-applied to each socket as it is created, so a
   *  reconnect cannot silently start holding the host's event loop open again. */
  private unrefRequested = false;

  constructor(target: ArbiterClientTarget, opts: ArbiterClientOptions = {}) {
    if (typeof target === "string") {
      this.socketPath = target;
    } else if ("fd" in target) {
      this.socketPath = undefined;
      this.fd = target.fd;
    } else {
      this.socketPath = undefined;
      this.presetSocket = target.socket;
    }
    this.requestTimeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (opts.rediscoverPath && typeof target === "string") this.rediscoverPath = opts.rediscoverPath;
  }

  /** A HUMAN-PLANE client (arbiter-human-plane.md §5.1) that follows the
   *  arbiter across a restart: given `dataSock` (the launcher's
   *  MANDU_ARBITER_SOCK) it re-learns the human socket there when its own
   *  stops answering ({@link humanPlaneRediscovery}); without it, a plain
   *  client. A human-plane op is never sent to the data socket. */
  static humanPlane(humanSock: string, dataSock?: string | null, opts: ArbiterClientOptions = {}): ArbiterClient {
    return new ArbiterClient(humanSock, {
      ...opts,
      ...(dataSock ? { rediscoverPath: humanPlaneRediscovery(dataSock) } : {}),
    });
  }

  /** The path this client dials now (PATH mode), or undefined. */
  get path(): string | undefined {
    return this.socketPath;
  }

  /** A client over an inherited fd (the arbiter side of the admin channel). */
  static overFd(fd: number, opts: ArbiterClientOptions = {}): ArbiterClient {
    return new ArbiterClient({ fd }, opts);
  }

  /** A client over a Socket the caller already holds (the supervisor side). */
  static overSocket(socket: Socket, opts: ArbiterClientOptions = {}): ArbiterClient {
    return new ArbiterClient({ socket }, opts);
  }

  /** True for a pre-opened (fd / socket) channel — no path to dial. */
  get isPreOpened(): boolean {
    return this.socketPath === undefined;
  }

  /** Establish (or reuse) the connection to the arbiter socket. Rejects after
   *  close() — a closed client never reconnects (see `closed`). */
  async connect(): Promise<void> {
    if (this.closed) throw new Error("arbiter client is closed");
    if (this.sock && !this.sock.destroyed) return;
    if (this.connectPromise) return this.connectPromise;
    if (this.socketPath === undefined) {
      // Pre-opened channel: adopt it — no dial, no "connect" event. Adopted
      // exactly once; when it closes, the client is closed for good (there is
      // no path to re-dial, and silently re-wrapping a dead fd would be a hang).
      let sock: Socket;
      if (this.presetSocket) {
        sock = this.presetSocket;
        this.presetSocket = undefined;
      } else if (this.fd !== undefined) {
        sock = new Socket({ fd: this.fd, readable: true, writable: true });
      } else {
        throw new Error("arbiter client: pre-opened channel already consumed");
      }
      if (this.unrefRequested) sock.unref();
      sock.setEncoding("utf8");
      sock.on("data", (chunk: string) => this.onData(chunk));
      sock.on("error", () => { /* the close handler runs the teardown */ });
      sock.on("close", () => {
        this.closed = true;
        this.onClose();
      });
      this.sock = sock;
      this.connectPromise = Promise.resolve();
      return this.connectPromise;
    }
    const attempt = this.dialWithRediscovery(this.socketPath);
    this.connectPromise = attempt;
    attempt.catch(() => {
      if (this.connectPromise === attempt) this.connectPromise = undefined;
    });
    return attempt;
  }

  /** Dial `socketPath`; when nothing listens there and a rediscovery is
   *  configured (and its backoff allows), dial the path it names instead. */
  private async dialWithRediscovery(socketPath: string): Promise<void> {
    try {
      await this.dial(socketPath);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? "";
      if (!this.rediscoverPath || !DEAD_ENDPOINT_CODES.has(code) || this.closed) throw err;
      const now = Date.now();
      if (now < this.rediscoverAt) throw err;
      // The backoff grows only when the arbiter answered and named nothing
      // usable. A rediscovery that throws a dead-endpoint error (the data
      // socket does not answer: the arbiter is down) costs one failed
      // connect, like the dial, and leaves no window to wait out once the
      // arbiter is back.
      let next: string | null = null;
      let down = false;
      try {
        next = await this.rediscoverPath(socketPath);
      } catch (e) {
        down = DEAD_ENDPOINT_CODES.has((e as NodeJS.ErrnoException).code ?? "");
        next = null;
      }
      if (next === null && !down) {
        this.rediscoverAt = now + this.rediscoverDelay;
        this.rediscoverDelay = Math.min(this.rediscoverDelay * 2, REDISCOVER_MAX_MS);
      }
      if (next === null || next === socketPath || this.closed) throw err;
      await this.dial(next);
      this.socketPath = next;
      this.rediscoveries += 1;
    }
    this.rediscoverAt = 0;
    this.rediscoverDelay = REDISCOVER_MIN_MS;
  }

  private dial(socketPath: string): Promise<void> {
    // A path the kernel would shorten dials whatever sits at the shorter name.
    assertSocketPathFits(socketPath, "arbiter client");
    return new Promise<void>((resolve, reject) => {
      const sock = connect(socketPath);
      this.connectingSock = sock;
      if (this.unrefRequested) sock.unref();
      sock.setEncoding("utf8");
      sock.once("connect", () => {
        this.connectingSock = undefined;
        if (this.closed) {
          // close() raced the dial: never adopt the socket.
          sock.destroy();
          reject(new Error("arbiter client is closed"));
          return;
        }
        this.sock = sock;
        resolve();
      });
      sock.once("error", (err) => {
        this.connectingSock = undefined;
        reject(err);
      });
      sock.on("data", (chunk: string) => this.onData(chunk));
      // Only the adopted connection's close tears the client down: a dial
      // that failed (before a rediscovery's second dial) never connected,
      // and must not clear the attempt still in flight.
      sock.on("close", () => {
        if (this.sock === sock) this.onClose();
      });
    });
  }

  private onData(chunk: string): void {
    // Linear framing (ndjson-lines.ts): a multi-MB single-line reply (`events`
    // for a long session) must not re-scan the whole buffer per chunk.
    for (const line of this.lines.push(chunk)) {
      if (line.trim() === "") continue;
      let resp: ArbiterResponse<unknown>;
      try {
        resp = JSON.parse(line) as ArbiterResponse<unknown>;
      } catch {
        continue; // ignore unparseable line
      }
      const p = this.pending.get(resp.id);
      if (!p) continue;
      // An interim frame (filterPrompt's, when asked): not the answer.
      if ((resp as { progress?: unknown }).progress === true && !("ok" in resp)) { p.progress?.(); continue; }
      this.pending.delete(resp.id);
      if (resp.ok) p.resolve(resp.result);
      else p.reject(new Error(resp.error));
    }
  }

  private onClose(): void {
    for (const p of this.pending.values()) {
      p.reject(new Error("arbiter connection closed"));
    }
    this.pending.clear();
    this.sock = undefined;
    this.connectPromise = undefined;
    this.lines = new NdjsonLineSplitter(); // a torn fragment never bleeds into a reconnect
  }

  /** Low-level request: send {id, op, ...args}, resolve with `result`.
   *
   *  BOUNDED BY A DEADLINE, and that is a security property, not a nicety. A
   *  reply is the ONLY thing that settles a request: an arbiter that is
   *  alive-but-unresponsive (SIGSTOPped, blocked on disk I/O, wedged on a
   *  poison row) holds its socket open, so `close` never fires and the awaited
   *  verdict never arrives. Un-bounded, that hangs the caller FOREVER — and a
   *  caller that never returns never reaches its fail-closed `catch`. A dead
   *  arbiter failed closed; a wedged one wedged the model turn. The gates
   *  (fs-gate, exec-gate) already bound their own awaits for exactly this
   *  reason; the bound belongs HERE, where it covers every op of every adapter
   *  — classify/symbolize on the proxies' ingress path, exec-wrap's
   *  classifyExec, net-proxy, fs-sync, inspect-mcp, reply-filter.
   *
   *  The deadline spans connect + write + reply (a wedged peer can stall the
   *  dial too), and rejects — which every caller already turns into its
   *  fail-closed answer (RewriteRefusal, a block sentinel, a denied path).
   *
   *  On expiry we drop the pending entry but deliberately do NOT destroy the
   *  socket: a late reply then lands on no pending entry and is ignored
   *  (harmless), whereas destroying would reject every CONCURRENT in-flight
   *  request on the shared connection — collateral failure of healthy calls to
   *  punish one slow one. */
  private async request<T>(
    op: string,
    args: Record<string, unknown>,
    timeoutMs: number = this.requestTimeoutMs,
    opts: { maxMs?: number } = {},
  ): Promise<T> {
    let id: number | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let maxTimer: ReturnType<typeof setTimeout> | undefined;
    let progress: (() => void) | undefined;

    // NOT unref'd: this is the fail-closed safety valve and must be able to
    // fire even if it is momentarily the only thing on the loop. `finally`
    // disarms it on every settle path, so it never holds the loop open past
    // the call (close() → onClose → reject → finally → clearTimeout).
    // With `maxMs`, the arbiter's progress frames re-arm the idle deadline,
    // never past `maxMs` in all.
    const deadline = new Promise<never>((_, reject) => {
      const expire = (ms: number): void => {
        if (id !== undefined) this.pending.delete(id);
        reject(new Error(`arbiter ${op} timed out after ${ms}ms — fail closed`));
      };
      timer = setTimeout(() => expire(timeoutMs), timeoutMs);
      if (opts.maxMs !== undefined) {
        const maxMs = opts.maxMs;
        maxTimer = setTimeout(() => expire(maxMs), maxMs);
        progress = () => {
          if (timer !== undefined) clearTimeout(timer);
          timer = setTimeout(() => expire(timeoutMs), timeoutMs);
        };
      }
    });

    const call = (async (): Promise<T> => {
      await this.connect();
      const rid = this.nextId++;
      id = rid;
      const payload = JSON.stringify({ id: rid, op, ...args }) + "\n";
      return new Promise<T>((resolve, reject) => {
        this.pending.set(rid, { resolve: resolve as (v: unknown) => void, reject, ...(progress ? { progress } : {}) });
        this.sock!.write(payload, (err) => {
          if (err) {
            this.pending.delete(rid);
            // A socket the arbiter closed between connect() and this write
            // ("Cannot call write after a stream was destroyed"): the same
            // closed connection the onClose sweep reports, in its words, so a
            // caller that tells a stopped arbiter apart (the dashboard's
            // isArbiterUnreachable) sees one. Still a rejection: fail closed.
            reject(new Error(`arbiter connection closed (${err.message})`, { cause: err }));
          }
        });
      });
    })();

    try {
      // race() attaches a handler to `call`, so a rejection arriving AFTER the
      // deadline won (e.g. the eventual onClose sweep) is handled, not unhandled.
      return await Promise.race([call, deadline]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (maxTimer !== undefined) clearTimeout(maxTimer);
    }
  }

  // ── Typed operations ──────────────────────────────────────────────────────

  async symbolize(args: {
    tool: string;
    value: string;
    field?: string;
    origin?: string;
    /** The origin in the arbiter's world (HumanView) when the caller runs a view
     *  map — the LEVEL is derived from this (Plan 9). See SymbolizeRequest. */
    originHuman?: string;
    /** The launch directory a relative typed-path origin was read in
     *  (SymbolizeRequest.relativeBase). */
    relativeBase?: string;
    sessionKey?: string;
    callId?: string;
    /** Requested confidentiality level — the server can only RAISE it via the
     * default-secret catalog; ignored while the axis is OFF (SymbolizeRequest). */
    confidentiality?: string;
    /** Per-datum bound destinations (confidentiality.md §2). */
    bindings?: string[];
    /** Integrity half of the label; only "trusted" counts (fail-closed). */
    integrity?: string;
    /** Parent symbol name for a derived value (symbol-lineage.md G2). */
    derivedFrom?: string;
    /** Line span within the parent value, end-exclusive `start:end`. */
    lineRange?: string;
    /** The value is an agent's whole result led by its runtime's own head
     *  (SymbolizeRequest.resultHead, plan 10 §11.14). */
    resultHead?: string;
    /** The level is the classify backstop raise alone (SymbolizeRequest.secretBy, plan 15 §4.1). */
    secretBy?: string;
  }): Promise<string> {
    const r = await this.symbolizeFull(args);
    return r.symbol;
  }

  async symbolizeDerived(args: Parameters<ArbiterClient["symbolize"]>[0] & { sourceSymbols: string[] }): Promise<string> {
    const result = await this.request<SymbolizeResult>("symbolizeDerived", args);
    return result.symbol;
  }

  /** As {@link symbolize}, but returns the whole result — including the level the
   *  ARBITER derived (which may exceed what the caller asked for: the server
   *  composes the request, the default-secret catalog, and the user labels, so no
   *  client can under-label by omission). Callers that only need the name use
   *  `symbolize`. */
  async symbolizeFull(args: {
    tool: string;
    value: string;
    field?: string;
    origin?: string;
    originHuman?: string;
    relativeBase?: string;
    sessionKey?: string;
    callId?: string;
    confidentiality?: string;
    bindings?: string[];
    integrity?: string;
    derivedFrom?: string;
    lineRange?: string;
    resultHead?: string;
    secretBy?: string;
  }): Promise<SymbolizeResult> {
    return this.request<SymbolizeResult>("symbolize", args);
  }

  /** Pre-symbolize a secret file (confidentiality.md §7.2): the ARBITER reads
   * it, so secret bytes never enter this process. Returns null when the path is
   * not a catalog secret, is unreadable, or the axis is OFF. */
  async registerSecret(args: { path: string; sessionKey?: string; home?: string; loginEnv?: Record<string, string> }): Promise<{
    symbol: string | null;
    reason: string;
    twin?: string;
    shape?: string;
    fields?: number;
    terminator?: "" | "\n" | "\r\n";
  }> {
    return this.request("registerSecret", args);
  }

  /** Mask the secret-shaped variables of an environment (plan 10 §11.4): the
   * arbiter registers each secret value and returns what the agent's
   * environment should carry instead. */
  async registerEnvSecrets(args: { vars: Array<{ name: string; value: string; agentKey?: boolean }>; sessionKey?: string }): Promise<{
    vars: Array<{ name: string; symbol: string | null; twin?: string; reason: string }>;
  }> {
    return this.request("registerEnvSecrets", args);
  }

  /** The confidentiality axis's state: the switch + the standing release
   * surface (§6). Never returns secret values. */
  async confidentialityState(): Promise<ConfidentialityStateResultWire> {
    return this.request<ConfidentialityStateResultWire>("confidentialityState", {});
  }

  /** Every registered secret ({path, symbol}) — the launcher's twin set. */
  async secretRegistry(): Promise<Array<{ path: string; symbol: string }>> {
    const r = await this.request<{ entries: Array<{ path: string; symbol: string }> }>(
      "secretRegistry", {},
    );
    return r.entries;
  }

  /** Which catalog secret files exist under `roots` (no secret bytes are read). */
  async discoverSecrets(roots: string[], home?: string, opts?: { stateBase?: string; cacheEnv?: Record<string, string>; target?: string; ullmBinary?: string; loginEnv?: Record<string, string> }): Promise<Array<{ path: string; level: string; rule: string }>> {
    return (await this.discoverSecretsReport(roots, home, opts)).files;
  }

  /** The reachable git history of each root's work tree, scanned for
   *  secret-shaped blobs (secret-discovery.md §3). Findings carry no value. */
  async scanSecretHistory(roots: string[], home?: string): Promise<ScanSecretHistoryResultWire> {
    return this.request<ScanSecretHistoryResultWire>(
      "scanSecretHistory", { roots, ...(home ? { home } : {}) },
      // The scan has its own deadline (MANDU_HISTORY_SCAN_TIMEOUT_S, 60 s by
      // default); this bound only catches a wedged arbiter.
      SCAN_SECRET_HISTORY_TIMEOUT_MS,
    );
  }

  /** Scan `roots` (the repositories holding them, and the files under them:
   *  `sources`, both by default) and file what the law does not cover as
   *  suggestions (confidentiality-plan-14 §5, §13). `includeHome` also walks
   *  `home` as a home (name hints). With `waitMs` the arbiter answers when
   *  that budget ends and finishes the scans itself. */
  async suggestPolicy(
    roots: string[],
    opts: { home?: string; waitMs?: number; sources?: Array<"git-history" | "workspace" | "sensitivity-label">; includeHome?: boolean; countLabels?: boolean; answerFromEarlier?: boolean } = {},
  ): Promise<SuggestPolicyResult> {
    return this.request<SuggestPolicyResult>(
      "suggestPolicy",
      {
        roots,
        ...(opts.home ? { home: opts.home } : {}),
        ...(opts.waitMs !== undefined ? { waitMs: opts.waitMs } : {}),
        ...(opts.sources !== undefined ? { sources: opts.sources } : {}),
        ...(opts.includeHome !== undefined ? { includeHome: opts.includeHome } : {}),
        ...(opts.countLabels !== undefined ? { countLabels: opts.countLabels } : {}),
        ...(opts.answerFromEarlier !== undefined ? { answerFromEarlier: opts.answerFromEarlier } : {}),
      },
      // Both scans have their own deadlines (60 s + 30 s by default); this
      // bound only catches a wedged arbiter.
      opts.waitMs !== undefined ? opts.waitMs + 30_000 : SCAN_SECRET_HISTORY_TIMEOUT_MS,
    );
  }

  /** The scan's suggestions, newest first. */
  async policySuggestions(status?: "pending" | "approved" | "denied" | "superseded"): Promise<PolicySuggestionsResult> {
    return this.request<PolicySuggestionsResult>("policySuggestions", status ? { status } : {});
  }

  /** Plan 17 §3 item 13: name the files `mandu scan`'s secrets came from
   *  (paths and key names, never a value); each one no rule covers, once the
   *  arbiter has checked it, becomes a suggestion. */
  async suggestFromScan(home: string, files: SuggestFromScanOpRequest["files"]): Promise<SuggestFromScanResultWire> {
    return this.request<SuggestFromScanResultWire>("suggestFromScan", { home, files });
  }

  /** Apply one suggestion if it is still a pure tightening (data plane). */
  async applySuggestion(suggestionId: string, requestedBy?: string): Promise<ApplySuggestionResult> {
    return this.request<ApplySuggestionResult>("applySuggestion", { suggestionId, ...(requestedBy ? { requestedBy } : {}) });
  }

  /** Build, gate and keep a names-only model payload (confidentiality-plan-14
   *  §14.2): the answer carries every line to be sent and the digest that
   *  `modelSuggest` sends. `endpoint` names a declared model; absent, the
   *  helper's default. The walk has the workspace scan's deadline. */
  async modelSuggestPreview(
    roots: string[],
    opts: { tier?: "names" | "contents"; endpoint?: string; home?: string; includeHome?: boolean } = {},
  ): Promise<ModelSuggestPreviewResult> {
    return this.request<ModelSuggestPreviewResult>(
      "modelSuggestPreview",
      {
        tier: opts.tier ?? "names",
        roots,
        ...(opts.endpoint !== undefined ? { endpoint: opts.endpoint } : {}),
        ...(opts.home ? { home: opts.home } : {}),
        ...(opts.includeHome !== undefined ? { includeHome: opts.includeHome } : {}),
      },
      SCAN_SECRET_HISTORY_TIMEOUT_MS,
    );
  }

  /** Send a kept payload once and file what the model suggests (§14.2).
   *  With `waitMs` the answer comes then at the latest (`running: true`); call
   *  again with the same digest to poll. */
  async modelSuggest(digest: string, opts: { waitMs?: number } = {}): Promise<ModelSuggestResult> {
    return this.request<ModelSuggestResult>(
      "modelSuggest",
      { digest, ...(opts.waitMs !== undefined ? { waitMs: opts.waitMs } : {}) },
      // A run is bounded at 5 minutes (plus the kill margin) by the arbiter.
      opts.waitMs !== undefined ? opts.waitMs + 30_000 : 6 * 60_000,
    );
  }

  /** ADMIN-ONLY: "Not a secret"; the finding is never filed again. */
  async dismissSuggestion(suggestionId: string, requestedBy?: string): Promise<DismissSuggestionResult> {
    return this.request<DismissSuggestionResult>("dismissSuggestion", { suggestionId, ...(requestedBy ? { requestedBy } : {}) });
  }

  /** Which of these env var NAMES a launch would mask (values unseen; the
   *  dry run's inventory, plan 10 §11.4). */
  async envSecretNames(names: string[]): Promise<string[]> {
    const r = await this.request<{ matched: string[] }>("envSecretNames", { names });
    return r.matched;
  }

  /** The same walk with its "not covered" ledger (skipped candidates, counts,
   *  caps, truncation) — secret-discovery.md §1.3. */
  async discoverSecretsReport(roots: string[], home?: string, opts?: { stateBase?: string; cacheEnv?: Record<string, string>; target?: string; ullmBinary?: string; loginEnv?: Record<string, string> }): Promise<DiscoverSecretsResultWire> {
    return this.request<DiscoverSecretsResultWire>(
      "discoverSecrets", {
        roots, ...(home ? { home } : {}), ...(opts?.stateBase ? { stateBase: opts.stateBase } : {}),
        ...(opts?.cacheEnv && Object.keys(opts.cacheEnv).length > 0 ? { cacheEnv: opts.cacheEnv } : {}),
        // The launch's agent and its login variables (secret-discovery.md §1.10).
        ...(opts?.target ? { target: opts.target } : {}),
        ...(opts?.ullmBinary ? { ullmBinary: opts.ullmBinary } : {}),
        ...(opts?.loginEnv && Object.keys(opts.loginEnv).length > 0 ? { loginEnv: opts.loginEnv } : {}),
      },
      // The one op whose honest worst case exceeds the default bound — it is a
      // real filesystem walk, not a SQLite lookup. Still bounded: unbounded here
      // would hang the LAUNCH, which is exactly the wedge this fix is about.
      DISCOVER_SECRETS_TIMEOUT_MS,
    );
  }

  /** THE LABELING ACT (confidentiality.md §6, Plan 6) — the only way to mint
   *  `any-model`, and the only way to declassify a catalog secret.
   *  Rejects (throws) an invalid level or a relative path rather than coercing. */
  async setPathLabel(args: {
    path: string;
    confidentiality: string;
    bindings?: string[];
    recursive?: boolean;
  }): Promise<SetPathLabelResultWire> {
    return this.request<SetPathLabelResultWire>("setPathLabel", { ...args });
  }

  async removePathLabel(path: string): Promise<boolean> {
    const r = await this.request<RemovePathLabelResultWire>("removePathLabel", { path });
    return r.removed;
  }

  /** Every user label — the standing release surface the dashboard renders. */
  async pathLabels(): Promise<PathLabelWire[]> {
    const r = await this.request<PathLabelsResultWire>("pathLabels", {});
    return r.labels;
  }

  // ── policy document (policy-surface.md §2.1, stage 5a; ADMIN-ONLY writes) ──

  async policyDocument(): Promise<PolicyDocumentResult> {
    return this.request<PolicyDocumentResult>("policyDocument", {});
  }

  /** The declared model endpoints of the law in force (plan 11 D5). */
  async modelEndpoints(): Promise<ModelEndpointWire[]> {
    const r = await this.request<ModelEndpointsResult>("modelEndpoints", {});
    return r.endpoints;
  }

  /** The law's connect-guard allowances (§2.3, 4b) — `proto:host:port` specs. */
  async netConnectAllow(): Promise<NetConnectAllowResult> {
    return this.request<NetConnectAllowResult>("netConnectAllow", {});
  }

  /** Test a flow (§4/§5): what the real gates would decide, nothing recorded. */
  async testFlow(req: Omit<TestFlowOpRequest, "id" | "op">): Promise<TestFlowResult> {
    return this.request<TestFlowResult>("testFlow", req);
  }

  /** Replace the user's policy document. `lawHash` is the `lawHash` of the
   *  `policyDocument` read the document was built from: the apply is refused
   *  as stale when the law moved since (policy-surface.md §8.4.6). */
  async applyPolicyDocument(document: unknown, requestedBy: string | undefined, lawHash: string): Promise<ApplyPolicyDocumentResult> {
    return this.request<ApplyPolicyDocumentResult>("applyPolicyDocument", { document, requestedBy, lawHash });
  }

  async mintUserRule(rule: MintUserRuleOpRequest["rule"], requestedBy?: string): Promise<MintUserRuleResult> {
    return this.request<MintUserRuleResult>("mintUserRule", { rule, requestedBy });
  }

  // ── policy agent surface (policy-surface.md §8.4.2) ──

  /** Tighten at once, or file a proposal a human decides (data plane). */
  async policyPropose(req: { edits: unknown; reason?: string; sessionKey?: string; requestedBy?: string; basedOn?: PolicyItemVersionWire[] }): Promise<PolicyProposeResult> {
    return this.request<PolicyProposeResult>("policyPropose", req);
  }

  async policyProposals(status?: PolicyProposalsOpRequest["status"]): Promise<PolicyProposalsResult> {
    return this.request<PolicyProposalsResult>("policyProposals", status ? { status } : {});
  }

  async policyChanges(limit?: number): Promise<PolicyChangesResult> {
    return this.request<PolicyChangesResult>("policyChanges", limit !== undefined ? { limit } : {});
  }

  /** ADMIN-ONLY: a human approves or denies a proposal. */
  async resolvePolicyProposal(proposalId: string, verdict: "approved" | "denied", requestedBy?: string): Promise<ResolvePolicyProposalResult> {
    return this.request<ResolvePolicyProposalResult>("resolvePolicyProposal", { proposalId, verdict, requestedBy });
  }

  /** ADMIN-ONLY: a human reverts one recorded change. */
  async undoPolicyChange(changeId: string, requestedBy?: string): Promise<UndoPolicyChangeResult> {
    return this.request<UndoPolicyChangeResult>("undoPolicyChange", { changeId, requestedBy });
  }

  /** What an edit list would do, nothing written (§5.2). */
  async policyPreview(edits: unknown): Promise<PolicyPreviewResult> {
    return this.request<PolicyPreviewResult>("policyPreview", { edits });
  }

  /** The JSON Schema of a PolicyEdit list (§4.3). */
  async policySchema(): Promise<PolicySchemaResult> {
    return this.request<PolicySchemaResult>("policySchema", {});
  }

  /** The law as structured fields only (§4.4), safe for a configuring model. */
  async policyExplain(args: { audience?: "agent" | "assistant"; sessionKey?: string } = {}): Promise<PolicyExplainResult> {
    return this.request<PolicyExplainResult>("policyExplain", args);
  }

  async exportDbLabels(requestedBy?: string): Promise<ExportDbLabelsResult> {
    return this.request<ExportDbLabelsResult>("exportDbLabels", { requestedBy });
  }

  /** A session is WRITING a file: record the on-disk label if that session is
   *  HIGH (Plan 9, §4/§8). This is what makes the watermark survive the session —
   *  without it the next session reads the derived file, the catalog finds no
   *  match, and it classifies PUBLIC. Inert for a public session / an OFF axis.
   *  A THROW means the arbiter is unreachable: the CALLER fails closed (denies the
   *  write), because "we could not check" must never mean "write it unlabeled". */
  async labelWrittenPath(args: {
    sessionKey?: string;
    path: string;
    tool?: string;
  }): Promise<LabelWrittenPathResultWire> {
    return this.request<LabelWrittenPathResultWire>("labelWrittenPath", { ...args });
  }

  /** Clear a derived taint record (§8's declassification, the blunt form). */
  async removeDerivedLabel(path: string): Promise<boolean> {
    const r = await this.request<RemoveDerivedLabelResultWire>("removeDerivedLabel", { path });
    return r.removed;
  }

  /** §3.3 RUNG 3 — the IN-CONTEXT READ (Plan 8). Raw content enters T-LLM's
   *  context only because the model ASKED and the arbiter ALLOWED, and every
   *  allowed read HIGH-WATERMARKS the session. Refused outright for an
   *  untrusted datum (the one invariant) or a strict one (the residency claim);
   *  approval-gated in an untrusted-tainted session (§9 rule 2). */
  async declassifySymbol(args: {
    symbol: string;
    sessionKey?: string;
    reason?: string;
  }): Promise<DeclassifySymbolResultWire> {
    return this.request<DeclassifySymbolResultWire>("declassifySymbol", { ...args });
  }

  /** What a HIGH session may still do (§4) — consulted IN ADDITION to the
   *  per-symbol egress gate, because a paraphrase carries no symbol. */
  async sessionEgressDecision(args: {
    sessionKey?: string;
    boundary: "network" | "shell" | "filesystem";
    destination?: string;
    netEnabled?: boolean;
  }): Promise<SessionEgressDecisionResultWire> {
    return this.request<SessionEgressDecisionResultWire>("sessionEgressDecision", { ...args });
  }

  /** confidentiality.md §4: the guard's question at a call root's exec (a
   *  HIGH session's command holds what the session read). */
  async sessionExecRoot(args: { procKey: string; session?: string }): Promise<SessionExecRootResultWire> {
    return this.request<SessionExecRootResultWire>("sessionExecRoot", { ...args });
  }

  /** confidentiality.md §4: the session's guard announces itself. */
  async guardAttach(args: { sessionKey: string }): Promise<GuardAttachResultWire> {
    return this.request<GuardAttachResultWire>("guardAttach", { ...args });
  }

  /** Which of these `$MDU:` names (rebuilt by the net-proxy from text whose
   *  `$MDU` a shell expanded to nothing) are secret-labelled rows
   *  (confidentiality.md §7). Names only, never a value. */
  async strippedPlaceholders(args: { candidates: string[]; sessionKey?: string }): Promise<StrippedPlaceholdersResultWire> {
    return this.request<StrippedPlaceholdersResultWire>("strippedPlaceholders", { ...args });
  }

  /** Report a refusal of the DevTools relay's, for the browser agent's next
   *  model call (relay-notices.ts; devtools-relay.md §3.4). Names only. */
  async relayNotice(args: { notice: RelayNoticeWire; sessionKey?: string }): Promise<{ queued: true }> {
    return this.request<{ queued: true }>("relayNotice", { ...args });
  }

  /** Whether a placeholder's base (`$MDU:kind[code]`) names a row, its own or
   *  a field's (devtools-relay.md §3.3). Names only. Human plane only. */
  async placeholderKnown(args: { base: string }): Promise<PlaceholderKnownResultWire> {
    return this.request<PlaceholderKnownResultWire>("placeholderKnown", { ...args });
  }

  /** The session's pending relay refusals, cleared by this take. */
  async takeRelayNotices(args: { sessionKey?: string } = {}): Promise<TakeRelayNoticesResultWire> {
    return this.request<TakeRelayNoticesResultWire>("takeRelayNotices", { ...args });
  }

  /** The §4 verbatim-leak TRIPWIRE — scan outbound surfaces against the
   *  arbiter's known secret VALUES. Backs the symbol gates (defense-in-depth);
   *  trips only on a positive verbatim match at a non-released destination. */
  async egressFingerprintScan(args: {
    surfaces: { where: string; text: string }[];
    destination: string;
    /** The asking session's logins (secret-discovery.md §1.10). */
    sessionLogins?: SessionLoginsWire;
  }): Promise<EgressFingerprintScanResultWire> {
    return this.request<EgressFingerprintScanResultWire>("egressFingerprintScan", { ...args });
  }

  /** The session's floating label (the watermark + the untrusted-taint bit). */
  async sessionState(sessionKey?: string): Promise<SessionStateResultWire> {
    return this.request<SessionStateResultWire>("sessionState", { sessionKey });
  }

  /** Deep (fixpoint) text desymbolization — nested chains collapse to raw.
   * For full-fidelity HumanView surfaces; see DesymbolizeRequest. */
  async desymbolize(text: string): Promise<string> {
    const r = await this.request<DesymbolizeResult>("desymbolize", { text });
    return r.text;
  }

  /** The line count of ONE symbol token's deep-resolved value (one trailing
   * line break dropped), or null when the token is not a known symbol. Never
   * the value (reply-row-reservation.md §3.3). With `opts.width` (20..1000)
   * the result also carries `rows`, the screen rows the value wraps to, the
   * first row `opts.first` wide (0, or ⌈width/2⌉..width; default `width`) —
   * §11.5; `opts.rule`, the TUI's wrap rule (§17, default `ink`);
   * `opts.indent`, the content area's terminal column a TAB's stop counts
   * from (§11.2, default 0). Human plane only: the data socket refuses it. */
  async symbolShape(
    token: string, opts?: { width?: number; first?: number; rule?: ReplyLayoutRule; indent?: number },
  ): Promise<SymbolShapeResult | null> {
    return this.request<SymbolShapeResult | null>("symbolShape", {
      token,
      ...(opts?.width !== undefined ? { width: opts.width } : {}),
      ...(opts?.first !== undefined ? { first: opts.first } : {}),
      ...(opts?.rule !== undefined ? { rule: opts.rule } : {}),
      ...(opts?.indent !== undefined ? { indent: opts.indent } : {}),
    });
  }

  /** Report the reply filter's relay mode for a session (and again on resize) —
   * reply-row-reservation.md §3.6, §11.5 (`wrap`: it paints v2 heads; `tabs`,
   * §19.7: where the TUI counts a TAB's stops from). Human
   * plane only: the data socket refuses it. */
  async setSessionRelay(args: {
    sessionKey: string;
    mode: SessionRelayMode;
    reserve: boolean;
    cols?: number;
    rows?: number;
    wrap?: boolean;
    rule?: ReplyLayoutRule;
    tabs?: ReplyTabOrigin;
  }): Promise<void> {
    await this.request<SetSessionRelayResult>("setSessionRelay", args);
  }

  /** A session's last reported relay state, or null when never reported.
   * Human plane only: the data socket refuses it. */
  async sessionRelay(sessionKey: string): Promise<SessionRelayWire | null> {
    return this.request<SessionRelayWire | null>("sessionRelay", { sessionKey });
  }

  /** Record a reserve block the proxy expanded: the head's token, its N, and
   * for a v2 head `width`/`first` (reply-row-reservation.md §3.8). Human
   * plane only: the data socket refuses it. */
  async noteReserveBlock(args: {
    sessionKey: string;
    token: string;
    n: number;
    width?: number;
    first?: number;
  }): Promise<void> {
    await this.request<{ ok: true }>("noteReserveBlock", args);
  }

  /** The block noted for `hash` in the session, or null. Human plane only. */
  async reserveBlock(sessionKey: string, hash: string): Promise<ReserveBlockWire | null> {
    return this.request<ReserveBlockWire | null>("reserveBlock", { sessionKey, hash });
  }

  /** Record the tool-call ids whose result body a model proxy forwarded in
   * clear (confidentiality.md §7.1, "Masked after the fact"). Ids only,
   * durable. Human plane only: the data socket refuses it. */
  async recordForwardedClear(ids: string[]): Promise<RecordForwardedClearResult> {
    return this.request<RecordForwardedClearResult>("recordForwardedClear", { ids });
  }

  /** Which of `ids` were recorded by {@link recordForwardedClear}, in the
   * order asked. Human plane only: the data socket refuses it. */
  async forwardedClear(ids: string[]): Promise<string[]> {
    return (await this.request<ForwardedClearResult>("forwardedClear", { ids })).ids;
  }

  /** {@link forwardedClear} with the store's generation, and, given the
   * generation of an earlier answer (`since`), the ids recorded after it
   * (confidentiality.md §7.1, "Two launches at once"). Human plane only. */
  async forwardedClearSince(ids: string[], since?: number): Promise<ForwardedClearResult> {
    return this.request<ForwardedClearResult>("forwardedClear", { ids, ...(since !== undefined ? { since } : {}) });
  }

  /** Record, for results a model proxy forwarded in clear in an OpenClaw
   * session, where Mandu's placeholders sat and the text's digest
   * (confidentiality.md §6, *Across a relaunch*). Tokens, offsets and a
   * digest only, durable. Human plane only: the data socket refuses it. */
  async recordForwardedPlaceholders(maps: ForwardedPlaceholderMapWire[]): Promise<RecordForwardedPlaceholdersResult> {
    return this.request<RecordForwardedPlaceholdersResult>("recordForwardedPlaceholders", { maps });
  }

  /** The maps {@link recordForwardedPlaceholders} recorded for `ids`, in the
   * order asked. Human plane only: the data socket refuses it. */
  async forwardedPlaceholders(ids: string[]): Promise<ForwardedPlaceholderMapWire[]> {
    return (await this.request<ForwardedPlaceholdersResult>("forwardedPlaceholders", { ids })).maps;
  }

  /** Resolve one symbol (null if unknown). `deep` expands symbols nested in
   * the value to fixpoint — ungated full-fidelity consumers only (see
   * ResolveRequest); gated egress callers must stay shallow. */
  async resolve(symbol: string, opts?: { deep?: boolean; endpoint?: string }): Promise<string | null> {
    const r = await this.resolveFull(symbol, opts);
    return r.value;
  }

  /** As {@link resolve}, but returns the whole result — including the resolved
   *  symbol's LEVEL on a `deep` resolve (Plan 7), which the U-LLM quarantine
   *  inherits onto its re-symbolized answer. Advisory: `symbolize` derives the
   *  same inheritance server-side from the origin symbol, so a caller that
   *  ignores this still cannot launder the label. */
  async resolveFull(symbol: string, opts?: { deep?: boolean; endpoint?: string }): Promise<ResolveResult> {
    return this.request<ResolveResult>("resolve", {
      symbol,
      ...(opts?.deep ? { deep: true } : {}),
      ...(opts?.deep && typeof opts.endpoint === "string" ? { endpoint: opts.endpoint } : {}),
    });
  }

  /** Original field metadata and the tool call that produced a symbol's value.
   * Tool-call linkage is best-effort (symbol-quality.md §4.1 v2). Consumers
   * requiring a field for derived provenance must distinguish explicit null
   * from absent metadata; see mandu.md §9. */
  async symbolProvenance(symbol: string): Promise<SymbolProvenanceResult> {
    return this.request<SymbolProvenanceResult>("symbolProvenance", { symbol });
  }

  async classify(request: ClassifyRequest): Promise<ClassifyOpResult> {
    return this.request<ClassifyOpResult>("classify", { request });
  }

  /** Data-usage / egress gate: may this symbol be resolved on egress, or does
   * it require human approval? */
  async desymbolizationDecision(
    request: DesymbolizationRequest,
  ): Promise<DesymbolizationDecisionOpResult> {
    return this.request<DesymbolizationDecisionOpResult>(
      "desymbolizationDecision",
      { request },
    );
  }

  /** Sensitive-path gate (fs data-usage policy): may this tool touch this
   * absolute path? Wrapped by the interactive approval queue (entries keyed
   * `fs:<tool>:<mode>` × path); a human approve/deny short-circuits repeats. */
  async fsPathDecision(request: FsPathDecisionRequest): Promise<FsPathDecisionOpResult> {
    return this.request<FsPathDecisionOpResult>("fsPathDecision", { request });
  }

  /** The local-file upload gate (file-upload.ts): may this tool send this
   * file's bytes to this host? Approval-wrapped (`fs:<tool>:upload` × path);
   * answered by reading the file only on the human plane. The arbiter
   * scans a large file in chunks (upload-scan.ts): its progress frames keep
   * the call alive past the idle timeout, up to FILE_UPLOAD_TIMEOUT_MS in
   * all; an arbiter that never answers still fails closed at the idle one. */
  async fileUploadDecision(request: FileUploadDecisionRequest): Promise<FileUploadDecisionOpResult> {
    return this.request<FileUploadDecisionOpResult>("fileUploadDecision", { request, progress: true }, this.requestTimeoutMs, { maxMs: FILE_UPLOAD_TIMEOUT_MS });
  }

  /** Select AgentShell vs HumanShell for a command argv; reports the command's
   * canonical identity + reason. */
  async classifyExec(args: {
    argv: string[];
    cwd?: string;
    needsNetwork?: boolean;
    needsOriginalFs?: boolean;
    params?: Record<string, unknown>;
  }): Promise<ClassifyExecOpResult> {
    return this.request<ClassifyExecOpResult>("classifyExec", args);
  }

  /** Desymbolize an argv for a chosen shell AFTER the data-usage check +
   * command rewriting. Returns the argv to run plus any required approvals. */
  async resolveExecArgv(args: {
    argv: string[];
    shell: ExecShell;
    params?: Record<string, unknown>;
  }): Promise<ResolveExecArgvOpResult> {
    return this.request<ResolveExecArgvOpResult>("resolveExecArgv", args);
  }

  /** Model-context-layer exec gate (exec-routing.md §3): classify a raw shell
   * command string and decide allow/block (blocks only an untrusted symbol in
   * command/execution position). Reports classification + evasion signals. The
   * arbiter also records the verdict by signature for later correlation. */
  async execGate(args: { command: string; cwd?: string; sessionKey?: string; callId?: string }): Promise<ExecGateOpResult> {
    return this.request<ExecGateOpResult>("execGate", args);
  }

  /** Correlation lookup (exec-routing.md §4 step 1): the proxy's recorded
   * execGate decision for a command (by signature), or null on a miss. */
  async execDecisionFor(args: { command?: string; argv?: string[] }): Promise<ExecDecisionForOpResult> {
    return this.request<ExecDecisionForOpResult>("execDecisionFor", args);
  }

  /** Report one finished boxed invocation's CLEAN verdict (exec-routing.md §8
   * §4 rung 2 / §5). The server resolves it through the fail-closed gate chain
   * (boxed, AgentShell, its OWN lineage-taint re-check, output hash) and
   * records it by callId; the returned verdict says what it resolved to. */
  async reportExecCleanVerdict(
    report: ExecCleanVerdictReport,
    reporterToken?: string,
  ): Promise<ReportExecCleanVerdictOpResult> {
    return this.request<ReportExecCleanVerdictOpResult>(
      "reportExecCleanVerdict",
      reporterToken === undefined ? { report } : { report, reporterToken },
    );
  }

  /** The session guard's one claim of its clean-verdict reporter token
   * (exec-routing.md §8.5.3). A refusal REJECTS. */
  async claimCleanReporter(sessionKey: string): Promise<ClaimCleanReporterResult> {
    return this.request<ClaimCleanReporterResult>("claimCleanReporter", { sessionKey });
  }

  /** The resolved clean verdict for a callId, or null on a miss (observability
   * / tests / the supervisor double-checking its report). */
  async execCleanVerdictFor(callId: string): Promise<ExecCleanVerdictForOpResult> {
    return this.request<ExecCleanVerdictForOpResult>("execCleanVerdictFor", { callId });
  }

  /** The exec box's symbol-twin hint for one AgentShell leaf it is about to
   * run (symbol-twin-shell-blindness.md §4.1 v2). Utility-only. */
  async reportExecTwins(report: ExecTwinReport): Promise<ReportExecTwinsOpResult> {
    return this.request<ReportExecTwinsOpResult>("reportExecTwins", { report });
  }

  /** The recent boxed leaves' symbolic-twin candidates for a model-authored
   * command (the proxy re-verifies each under its own roots). */
  async execTwinsFor(command: string): Promise<ExecTwinsForOpResult> {
    return this.request<ExecTwinsForOpResult>("execTwinsFor", { command });
  }

  /** The level a value read from `path` would mint with today (user labels +
   * catalog, HumanView spelling) — fs-sync's relabel guard on the re-launch
   * fast path. `axis: false` when confidentiality is OFF. */
  async pathLevel(path: string): Promise<PathLevelOpResult> {
    return this.request<PathLevelOpResult>("pathLevel", { path });
  }

  /** The file browser's labels (dashboard.md §4.25m): `pathLevel` for many
   * paths at once, plus where each deciding human label is kept. */
  async pathLevels(paths: string[], home?: string, withEdits?: unknown): Promise<PathLevelsOpResult> {
    return this.request<PathLevelsOpResult>("pathLevels", { paths, ...(home ? { home } : {}), ...(withEdits !== undefined ? { withEdits } : {}) });
  }

  /** ADMIN: move the dashboard's older rules (mandu.db) into policy.yaml. */
  async movePageLabels(requestedBy?: string): Promise<MovePageLabelsResult> {
    return this.request<MovePageLabelsResult>("movePageLabels", { requestedBy });
  }

  /** `mandu why <path>`: the law's view of one file, read-only. */
  async whyPath(path: string, home?: string, loginEnv?: Record<string, string>, session?: string): Promise<WhyPathOpResult> {
    return this.request<WhyPathOpResult>("whyPath", { path, ...(home ? { home } : {}), ...(loginEnv && Object.keys(loginEnv).length > 0 ? { loginEnv } : {}), ...(session ? { session } : {}) });
  }

  /** policy.yaml env.sources: what a launch should fetch (never a value). */
  async envSources(): Promise<{ sources: Array<{ name: string; source: string; bindings: string[] }> }> {
    return this.request("envSources", {});
  }

  /** A session log's hash chain: intact, or the first seq that does not link. */
  async verifyEvents(sessionId: string): Promise<{ ok: boolean; chained: number; unchained: number; brokenAt?: number; head: string | null }> {
    return this.request("verifyEvents", { sessionId });
  }

  /** The signed consumer packs in force, and the ones refused. */
  async consumerPacks(): Promise<{ packs: Array<{ name: string; version: string; keyId: string; consumers: number }>; refused: string[] }> {
    return this.request("consumerPacks", {});
  }

  /** policy.yaml protect: paths no program in the agent's tree may delete. */
  async protectPaths(): Promise<{ paths: string[] }> {
    return this.request("protectPaths", {});
  }

  /** policy.yaml `unix_sockets:` / `write_protect:` (guard-settings.ts). */
  async guardSettings(): Promise<GuardSettingsResult> {
    return this.request("guardSettings", {});
  }

  /** The blob locks and human labels the launcher's object twins hide
   *  (confidentiality-plan-14 §8.1, §8.2). */
  async gitHistoryLocks(roots?: string[]): Promise<GitHistoryLocksResult> {
    return this.request("gitHistoryLocks", roots !== undefined && roots.length > 0 ? { roots } : {});
  }

  /** Add a work tree to the known-repository registry (plan 14 §11.1 R1):
   *  add-only, validated by the arbiter's hardened git, capped. */
  async registerRepository(root: string): Promise<RegisterRepositoryResult> {
    return this.request("registerRepository", { root });
  }

  /** Plan 14 §11.2 (HUMAN PLANE): the current epoch's seals for these cache
   *  entries; none while no seal is honoured. */
  async cacheSeals(kind: string, keys: string[]): Promise<CacheSealsResult> {
    return this.request("cacheSeals", { kind, keys });
  }

  /** Plan 14 §11.2 (HUMAN PLANE): seal cache entries just written or
   *  verified; report the ones not used (an event, no content). */
  async sealCacheEntries(
    entries: Array<{ kind: string; key: string; sha256: string; size: number }>,
    rejected: Array<{ kind: string; key: string; reason: "unsealed" | "mismatch" }> = [],
  ): Promise<SealCacheEntriesResult> {
    return this.request("sealCacheEntries", { entries, ...(rejected.length > 0 ? { rejected } : {}) });
  }

  /** Plan 14 §11.2 (HUMAN PLANE): a launch starts; the arbiter classifies it. */
  async beginLaunch(args: { pid: number; mode: string; posture: string; writeProtect: boolean; homeSealed?: boolean; humanPlaneWalled?: boolean; sessionId?: string; home?: string; workspace?: string }): Promise<BeginLaunchResult> {
    return this.request("beginLaunch", args);
  }

  /** HUMAN PLANE (arbiter-human-plane.md §10.1.1): whether a launch with no
   *  wall is live now, and which. Read-only. */
  async humanPlaneStatus(): Promise<HumanPlaneStatusResult> {
    return this.request("humanPlaneStatus", {});
  }

  /** Plan 14 §11.2 (HUMAN PLANE): a launch ended. */
  async endLaunch(token: string): Promise<EndLaunchResult> {
    return this.request("endLaunch", { token });
  }

  /** Plan 13 D8: what the arbiter knows a binary to be (a printer, a
   *  program that runs code, a renamed copy of an installed one). */
  async readerProgram(exe: string, sha256?: string): Promise<ReaderProgramOpResult> {
    return this.request<ReaderProgramOpResult>("readerProgram", { exe, ...(sha256 !== undefined ? { sha256 } : {}) });
  }

  /** policy.yaml ssh_agent.readers (null = the agent socket is ungated). */
  async sshAgentPolicy(): Promise<{ readers: unknown[] | null }> {
    return this.request("sshAgentPolicy", {});
  }

  /** `mandu why <host>`: bound secrets, release decisions, destinations. */
  async whyHost(host: string): Promise<WhyHostOpResult> {
    return this.request<WhyHostOpResult>("whyHost", { host });
  }

  /** HUMAN PLANE: `mandu why <symbol>` (plan 15 §13.8): where a placeholder
   *  came from; for a prompt finding, its filter, category, action, hold,
   *  session and turn, the verdicts on file and the policy now. No value. */
  async whySymbol(symbol: string, session?: string): Promise<WhySymbolOpResult> {
    return this.request<WhySymbolOpResult>("whySymbol", { symbol, ...(session ? { session } : {}) });
  }

  /** Exec escalation gate (exec-routing.md §5): may an AgentShell command that
   * needs `resource` escalate to HumanShell? Approved → HumanShell; otherwise
   * stay AgentShell (a pending approval is queued). */
  async escalateExec(args: {
    argv: string[];
    cwd?: string;
    resource: "network" | "original-fs";
    sessionKey?: string;
  }): Promise<EscalateExecOpResult> {
    return this.request<EscalateExecOpResult>("escalateExec", args);
  }

  /** Fetch the active inbound/outbound/origin policy rules for the dashboard's
   * per-tool-call policy modal. OBSERVABILITY ONLY — mirrors the enforced specs,
   * decides nothing. */
  async policySnapshot(): Promise<PolicySnapshotOpResult> {
    return this.request<PolicySnapshotOpResult>("policySnapshot", {});
  }

  // ── Egress-approval queue ─────────────────────────────────────────────────

  /** List queued egress-approval entries (optionally filtered by status),
   * newest-resolved first by lastSeen. A NETWORK desymbolizationDecision that
   * requires approval upserts a PENDING entry the dashboard reads here. */
  async egressApprovals(status?: ApprovalStatus): Promise<EgressApproval[]> {
    const r = await this.request<EgressApprovalsResult>(
      "egressApprovals",
      status === undefined ? {} : { status },
    );
    return r.approvals;
  }

  /** Apply a human verdict to a queued entry by id: `approve:true` → approved,
   * `false` → denied. A SUBSEQUENT desymbolizationDecision for the same
   * {symbol, destination} then short-circuits to allow (approved) /
   * deny-without-approval (denied). `scope` defaults to "always" (standing);
   * "once" spends the verdict on its first satisfying decision, after which
   * the pair re-queues on its next attempt. `opts.strip` (with `approve:
   * false`) answers "Send without it" (confidentiality.md §4): a one-shot
   * denial whose use sends the next such request with a marker in the
   * symbol's place; the arbiter refuses it on a row that does not take it.
   * Rejects if `id` is unknown. */
  async resolveEgressApproval(
    id: string,
    approve: boolean,
    scope?: ApprovalScope,
    opts?: { strip?: boolean },
  ): Promise<EgressApproval> {
    // The entry id is sent as `approvalId` (NOT `id`, which is the reserved wire
    // correlation field — naming it `id` would clobber the correlation id).
    const r = await this.request<ResolveEgressApprovalResult>(
      "resolveEgressApproval",
      { approvalId: id, approve, ...(scope !== undefined ? { scope } : {}), ...(opts?.strip === true ? { strip: true } : {}) },
    );
    return r.approval;
  }

  /** Forget a human verdict (admin channel only): the entry is deleted and
   * the pair's next attempt asks again. Rejects for an unknown or pending id. */
  async forgetEgressApproval(id: string): Promise<EgressApproval> {
    const r = await this.request<ForgetEgressApprovalResult>("forgetEgressApproval", { approvalId: id });
    return r.approval;
  }

  /** Set the arbiter's GLOBAL egress posture (siem-integration.md §4.3 scenario
   * D; policy-surface.md §9.8.6). TIGHTEN-ONLY BY DEFAULT — a `normal` request
   * is a refused no-op unless `allowRelax` is set (the explicit human-driven
   * flag, e.g. the dashboard's ▶ Resume), in which case the loosen applies and
   * is audited exactly like a tighten. GLOBAL-scoped (omit `sessionId`, or pass
   * `*`). `requestedBy` is free-text audit provenance (e.g. the Wazuh rule id,
   * or "dashboard"). Returns the posture after the request — `applied` is false
   * when the guard refused. */
  async setSessionPosture(args: {
    posture: "normal" | "lockdown";
    sessionId?: string;
    requestedBy?: string;
    allowRelax?: boolean;
  }): Promise<SetSessionPostureResult> {
    return this.request<SetSessionPostureResult>("setSessionPosture", args);
  }

  /** Bind a SESSION to an inbound/outbound trust spec (agent-e2e-harness.md
   * §7.1 — one arbiter serving mixed agents). `sessionKey` must be the same
   * identity later `classify` calls carry (MANDU_SESSION_KEY / scopeId).
   * FAIL-CLOSED: an unknown `spec` binds "fail-closed" (every tool UNTRUSTED)
   * — check `applied` to detect it. */
  async setSessionSpec(args: {
    sessionKey: string;
    spec: string;
    requestedBy?: string;
  }): Promise<SetSessionSpecResult> {
    return this.request<SetSessionSpecResult>("setSessionSpec", args);
  }

  /** Record which `models:` entry the session's main conversation goes to
   *  (plan 11 phase 3; null = the default vendor). Bind-once, and refused
   *  once the session has carried traffic: a refusal REJECTS. */
  async setSessionUpstream(args: {
    sessionKey: string;
    endpoint: string | null;
    requestedBy?: string;
    cleanReporter?: boolean;
  }): Promise<SessionUpstreamResult> {
    return this.request<SessionUpstreamResult>("setSessionUpstream", args);
  }

  /** The session's main-model binding and its live location. */
  async sessionUpstream(sessionKey: string): Promise<SessionUpstreamResult> {
    return this.request<SessionUpstreamResult>("sessionUpstream", { sessionKey });
  }

  async ping(): Promise<PingResult> {
    return this.request<PingResult>("ping", {});
  }

  /** Identity handshake: WHO answers this socket (pid, git rev, start time,
   * instance id, durable-state paths) — runtime-instances.md. */
  async hello(): Promise<HelloResult> {
    return this.request<HelloResult>("hello", {});
  }

  /** Fetch the T-LLM symbol system prompt the proxy injects so the model knows
   * how to treat symbols. `mode` defaults to "full" on the arbiter side.
   * `capabilities` reports what the requesting agent's tool battery can do so
   * the arbiter drops sections about tools that don't exist; absent (or absent
   * fields) = present = full prompt. */
  /** Session-health (dashboard.md §4.21): which of the agent's advertised tool
   *  names have no inbound spec for this session (their outputs fail closed). */
  async toolSurface(names: string[], sessionKey?: string): Promise<string[]> {
    const r = await this.request<{ unknown: string[] }>("toolSurface", {
      names,
      ...(sessionKey ? { sessionKey } : {}),
    });
    return r.unknown;
  }

  /** Which of the session's agent tools each model-context gate reads, and
   *  from which field (policy/tool-gate-surface.ts). */
  async gateSurface(sessionKey?: string): Promise<GateSurfaceResult> {
    return this.request<GateSurfaceResult>("gateSurface", sessionKey ? { sessionKey } : {});
  }

  async handlingPrompt(
    mode?: "full" | "dual-only",
    capabilities?: {
      inspect?: boolean;
      policyTools?: boolean;
      exec?: boolean;
      execEnv?: boolean;
      fsView?: boolean;
      /** `read-blocked` on macOS (handling-prompt.md §2). */
      secretPosture?: string;
      /** A browser agent's model (handling-prompt.md §11). */
      browser?: boolean;
    },
    sessionKey?: string,
  ): Promise<string> {
    const r = await this.request<HandlingPromptResult>("handlingPrompt", {
      ...(mode === undefined ? {} : { mode }),
      ...(capabilities === undefined ? {} : { capabilities }),
      // Plan 11 phase 3: the arbiter reads this session's main-model binding.
      ...(sessionKey ? { sessionKey } : {}),
    });
    return r.prompt;
  }

  /** Record a tool_use decision so later OS interceptors can correlate a
   * syscall to a known tool decision. In-memory / non-persistent on the arbiter
   * for now. Resolves to `{ ok: true }`. */
  async recordToolCall(args: {
    toolUseId: string;
    name: string;
    input: unknown;
    sessionKey?: string;
  }): Promise<RecordToolCallResult> {
    return this.request<RecordToolCallResult>("recordToolCall", args);
  }

  // ── Observability event stream ────────────────────────────────────────────

  /** Append one opaque observability event. `event.sessionId` and `event.id`
   * are REQUIRED; the arbiter assigns the per-session monotonic `seq` and returns
   * it. FIRE-AND-FORGET observability: never gate a security decision on this —
   * a rejected promise means the emit was not persisted, nothing more. */
  async emit(event: ArbiterEvent): Promise<number> {
    const r = await this.request<EmitResult>("emit", { event });
    return r.seq;
  }

  /** Read persisted events for a session with seq > sinceSeq (default 0), in
   * seq order. */
  async events(sessionId: string, sinceSeq = 0): Promise<StoredEvent[]> {
    const r = await this.request<EventsResult>("events", { sessionId, sinceSeq });
    return r.events;
  }

  /** List known sessions with counts + ts bounds. */
  async sessions(): Promise<SessionSummary[]> {
    const r = await this.request<SessionsResult>("sessions", {});
    return r.sessions;
  }

  /** Delete ONE session's event log (+ its in-memory state and any live
   * subscribe streams) — observability only; any session, live or test.
   * Rejects for an unknown session. */
  async deleteSession(sessionId: string): Promise<void> {
    await this.request<DeleteSessionResult>("deleteSession", { sessionId });
  }

  /**
   * Subscribe to a session's live event feed on a DEDICATED connection.
   *
   * Opens a fresh socket (separate from this client's shared request
   * connection so the one-req-one-res ops keep working), sends one `subscribe`
   * request, and invokes `onEvent` for each frame: first the backlog (events
   * with seq > sinceSeq, in seq order), then each newly-emitted event as it
   * arrives. Resolves once the backlog has been requested and the stream is
   * live; the returned handle's close() ends the stream (the arbiter stops
   * fan-out when the socket closes).
   */
  subscribe(
    sessionId: string,
    sinceSeq: number,
    onEvent: (event: StoredEvent) => void,
    /** Called once when the arbiter refuses the stream AFTER the promise has
     *  resolved (an error frame — e.g. a `subscribe` sent to the data socket,
     *  which is human-plane only: arbiter-human-plane.md). The stream is
     *  closed; nothing more will arrive. */
    onError?: (err: Error) => void,
  ): Promise<SubscriptionHandle> {
    return new Promise<SubscriptionHandle>((resolve, reject) => {
      if (this.closed) {
        reject(new Error("arbiter client is closed"));
        return;
      }
      if (this.socketPath === undefined) {
        reject(new Error("subscribe needs a dialable socket path — not available on a pre-opened (admin) channel"));
        return;
      }
      const tooLong = socketPathProblem(this.socketPath);
      if (tooLong !== null) {
        reject(new Error(`arbiter client: ${tooLong}`));
        return;
      }
      const sock = connect(this.socketPath);
      const lines = new NdjsonLineSplitter();
      let settled = false;
      sock.setEncoding("utf8");

      const handle: SubscriptionHandle = {
        close: () => {
          sock.end();
          sock.destroy();
        },
      };

      sock.once("connect", () => {
        const payload = JSON.stringify({ id: "sub", op: "subscribe", sessionId, sinceSeq }) + "\n";
        sock.write(payload, (err) => {
          if (err && !settled) {
            settled = true;
            reject(err);
            return;
          }
          // The stream is live as soon as the subscribe request is on the wire;
          // backlog frames arrive on subsequent "data" events.
          if (!settled) {
            settled = true;
            resolve(handle);
          }
        });
      });

      sock.on("data", (chunk: string) => {
        for (const line of lines.push(chunk)) {
          if (line.trim() === "") continue;
          let resp: ArbiterResponse<SubscribeEventFrame>;
          try {
            resp = JSON.parse(line) as ArbiterResponse<SubscribeEventFrame>;
          } catch {
            continue; // ignore unparseable frame
          }
          if (resp.ok) {
            const result = resp.result;
            if (result && result.type === "event") onEvent(result.event);
          } else {
            // A bad subscribe (e.g. invalid sessionId, or the wrong channel)
            // returns one error frame.
            if (!settled) {
              settled = true;
              reject(new Error(resp.error));
            } else {
              handle.close();
              onError?.(new Error(resp.error));
            }
          }
        }
      });

      sock.once("error", (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      });
    });
  }

  // ── Provenance (taint) registry ───────────────────────────────────────────

  /** Mark a process as tainted by untrusted network input. */
  async taintProcess(args: {
    procKey: string;
    originHost: string;
    session?: string;
  }): Promise<void> {
    await this.request<{ ok: true }>("taintProcess", args);
  }

  /** Record a parent→child process lineage edge. */
  async processLineage(args: {
    childKey: string;
    parentKey: string;
    session?: string;
  }): Promise<void> {
    await this.request<{ ok: true }>("processLineage", args);
  }

  /** Confidentiality plan 13 §9 R1: `procKey` holds what `flowsFrom` hold,
   *  through a descriptor (the guard's record; a claim from the data socket). */
  async recordProcessFlow(args: {
    procKey: string;
    flowsFrom: string[];
    session?: string;
  }): Promise<void> {
    await this.request<{ ok: true }>("recordProcessFlow", args);
  }

  /** Confidentiality plan 13 §4.5.1: the agent process itself holds
   *  `channel`, whose other end the holders `flowsFrom` write into (the
   *  guard's record; `closed` when the agent no longer holds it). */
  async recordAgentFlow(args: { channel: string; flowsFrom?: string[]; closed?: boolean; session?: string }): Promise<{ recorded: boolean; reason?: string }> {
    return this.request("recordAgentFlow", args);
  }

  /** Confidentiality plan 13 §4.5.1: per tool result, the level the agent's
   *  own connections to a holder mask it at (the model proxies' ask; its
   *  first ask of a call, on the human socket, ends the call's window). */
  async agentReceiptTaint(calls: Array<{ callId: string; tool: string }>, session?: string): Promise<AgentReceiptTaintResultWire> {
    return this.request("agentReceiptTaint", { calls, ...(session ? { session } : {}) });
  }

  /** Query whether a process (or any ancestor) is network-tainted. */
  async isProcessTainted(procKey: string): Promise<IsProcessTaintedResult> {
    return this.request<IsProcessTaintedResult>("isProcessTainted", { procKey });
  }

  // ── Plan 10: confidentiality taint ──────────────────────────────────────
  async taintProcessSecret(args: { procKey: string; path: string; level: string; app: string; session?: string }): Promise<void> {
    await this.request("taintProcessSecret", args);
  }
  async processSecretTaint(procKey: string): Promise<{ level: string | null; rows: Array<{ procKey: string; path: string; level: string; app: string }> }> {
    return this.request("processSecretTaint", { procKey });
  }
  async recordCallRoot(args: { callId: string; procKey: string; session?: string }): Promise<void> {
    await this.request("recordCallRoot", args);
  }
  /** Plan 10 §4.1: what an open of a registered secret by this process becomes. */
  async decideSecretOpen(args: { path: string; exe: string; sha256?: string; isAgent: boolean; procKey: string; parentKey?: string; ancestorKeys?: string[]; ancestorExes?: string[]; ancestorTrusted?: boolean[]; exeSystem?: boolean; openerEnv?: string[]; script?: { path: string; sha256?: string; system: boolean; isolated: boolean; traced: boolean }; scriptProblem?: string; orphanRoot?: string; session?: string; ask?: string; heldMs?: number }): Promise<{
    verdict: "raw" | "twin" | "deny" | "ask"; app: string; level: string; reason: string; pinNeeded: boolean; approvalId?: string;
  }> {
    return this.request("decideSecretOpen", args);
  }
  /** Finding 6: a change under an `ask` write-protect entry (allow | deny | ask).
   *  The writer's identity facts as for an open (the D8 follow-up), and for
   *  an interpreter the script it runs (plan 13 §8 decision (c)). */
  async decideProtectedWrite(args: { path: string; exe: string; sha256?: string; exeSystem?: boolean; openerEnv?: string[]; script?: { path: string; sha256?: string; system: boolean; isolated: boolean; traced: boolean }; scriptProblem?: string; procKey: string; label?: string; session?: string; heldMs?: number }): Promise<{
    verdict: "allow" | "deny" | "ask"; reason: string; approvalId?: string;
  }> {
    return this.request("decideProtectedWrite", args);
  }
  /** Plan 13 D9 follow-up: the command the model proxy delivered to the agent
   *  for a call (believed only on the human socket). */
  async recordCallCommand(args: { callId: string; command?: string; sessionKey?: string }): Promise<{ recorded: boolean; reason?: string }> {
    return this.request("recordCallCommand", args);
  }
  /** Plan 10 §11.8, "Refused connections" (an attested report: the human
   *  socket). */
  async recordEgressRefusal(args: { procKeys: string[]; kind: string; sessionKey?: string; unattributed?: boolean }): Promise<{ recorded: boolean; reason?: string }> {
    return this.request("recordEgressRefusal", args);
  }
  async callTaint(callId: string, opts: { command?: string; session?: string; output?: string; codexHead?: boolean; unmappedTool?: string; builtin?: boolean; forPoll?: string } = {}): Promise<{
    level: string | null; files: string[]; apps: string[]; rule: "secret" | "clear" | "mask"; mask: string[]; root: string | null;
    denied: Array<{ path: string; app: string; reason: string }>; twinOf?: string[]; twinWhole?: true; twinKeys?: true; dirListing?: true; evidence?: "tree" | "session" | "unmapped"; why?: string;
    refusedEgress?: Array<{ app: string; kind: string; unattributed?: true }>;
    blockedExec?: Array<{ app: string; kind: string }>;
  }> {
    return this.request("callTaint", { callId, ...opts });
  }
  /** Plan 10 §11.13 (HUMAN PLANE): the agent's stdio MCP servers, as the
   *  launcher read them from its config. */
  async registerMcpServers(sessionKey: string, servers: Array<{ name: string; command: string; args: string[] }>, sources?: Array<{ path: string; stamp: string }>): Promise<{ registered: number }> {
    return this.request("registerMcpServers", { sessionKey, servers, ...(sources ? { sources } : {}) });
  }
  /** Plan 10 §11.13.1 (HUMAN PLANE): this session's egress proxy inspects
   *  TLS, so npm may be served the `.npmrc` twin. */
  async registerWireRelease(sessionKey: string, inspecting: boolean, direct?: string[], opts: { pid?: number } = {}): Promise<{ inspecting: boolean }> {
    return this.request("registerWireRelease", { sessionKey, inspecting, ...(direct ? { direct } : {}), ...(opts.pid !== undefined ? { pid: opts.pid } : {}) });
  }
  /** Agent-sign-in.md §3 (HUMAN PLANE): a field of the agent's own key file
   *  authenticates to `host` (the provider the launch routes). */
  async registerAuthGrant(path: string, grants: Array<{ field: string; host: string; https: boolean }>, opts: { pid?: number } = {}): Promise<{ granted: number }> {
    return this.request("registerAuthGrant", { path, grants, ...(opts.pid !== undefined ? { pid: opts.pid } : {}) });
  }
  /** Agent-sign-in.md §3.8 (HUMAN PLANE): the agent's key in the environment
   *  variable `name` authenticates to `host`. */
  async registerEnvAuthGrant(name: string, grants: Array<{ field: string; host: string; https: boolean }>, opts: { pid?: number } = {}): Promise<{ granted: number }> {
    return this.request("registerAuthGrant", { env: name, grants, ...(opts.pid !== undefined ? { pid: opts.pid } : {}) });
  }
  /** Plan 10 §11.13: is the MCP server behind `tool` tainted, clean, or unmapped? */
  async mcpServerTaint(tool: string, sessionKey?: string): Promise<{
    verdict: "tainted" | "clean" | "unmapped" | "own"; server?: string; candidates: number; level: string | null; files: string[]; apps: string[]; configChanged?: boolean;
  }> {
    return this.request("mcpServerTaint", { tool, ...(sessionKey ? { sessionKey } : {}) });
  }
  async recordExecRoot(args: { procKey: string; parentKey?: string; ancestors?: string[]; argv: string[]; session?: string; callRoot?: boolean; cwd?: string; orphanRoot?: string }): Promise<void> {
    await this.request("recordExecRoot", args);
  }
  /** `destination` (plan 13 §5.4): the send the caller is about to refuse;
   *  on an attested channel the answer then carries the human's verdict or
   *  the question filed (`ask`). */
  async taintedProcessBindings(args: { procKey: string; ancestors?: string[]; session?: string; flowsFrom?: string[]; destination?: string; sessionAskOnly?: boolean }): Promise<{
    tainted: boolean; level: string | null; files: string[]; bindings: string[];
    ask?: { approvalId: string; status: "pending" | "approved" | "denied"; scope?: "once" | "always"; question?: "session" | "holder" };
  }> {
    return this.request("taintedProcessBindings", args);
  }
  /** Plan 13 §5.4, §9 R2: the policy edit an *Always* on one file of a
   *  holder's send question files (a read; the caller applies it on the
   *  admin channel). */
  async holderSourceBinding(approvalId: string, path: string): Promise<HolderSourceBindingResultWire> {
    return this.request("holderSourceBinding", { approvalId, path });
  }
  /** Plan 13 D6: does any process of the session hold a secret? */
  async sessionSecretTaint(args: { session?: string } = {}): Promise<{ tainted: boolean; level: string | null; files: string[] }> {
    return this.request("sessionSecretTaint", args);
  }
  /** Plan 13 D6, a blind tunnel's chunks: every process key the store
   *  would answer tainted (raw-read rows, closed forward over lineage,
   *  claims and flows). */
  async secretTaintedProcesses(): Promise<{ procKeys: string[] }> {
    return this.request("secretTaintedProcesses", {});
  }
  async labelWrittenPathTainted(args: { path: string; procKey: string; ancestors?: string[]; session?: string; flowsFrom?: string[] }): Promise<{ labeled: boolean; level: string; reason: string }> {
    return this.request("labelWrittenPathTainted", args);
  }
  /** Confidentiality plan 13 D4: the derived labels changed after `since` in
   *  `epoch` (every one for another epoch or none given). */
  async derivedLabelsSince(args: { epoch?: string; since?: number }): Promise<DerivedLabelsSinceResultWire> {
    return this.request<DerivedLabelsSinceResultWire>("derivedLabelsSince", args);
  }
  /** Where the human labels above `public` lie (the guard's gate of a
   *  labelled file the launch did not register, 2026-10-17). */
  async labelRootsSince(args: { key?: string; session?: string } = {}): Promise<LabelRootsSinceResultWire> {
    return this.request<LabelRootsSinceResultWire>("labelRootsSince", args);
  }

  /** The level a path classifies at now (`labelledLevel`). */
  async labelledLevel(args: { path: string; session?: string; agentOpen?: boolean }): Promise<LabelledLevelResultWire> {
    return this.request<LabelledLevelResultWire>("labelledLevel", args);
  }

  /** A session's machine label on one exact path: `no-model`, in memory,
   *  raise-only (session-path-labels.ts). */
  async sessionPathLabel(args: { path: string; sessionKey: string; reason?: string }): Promise<SessionPathLabelResultWire> {
    return this.request<SessionPathLabelResultWire>("sessionPathLabel", args);
  }
  /** Drop a session's path labels (human plane: it lowers protection). */
  async clearSessionPathLabels(args: { sessionKey: string }): Promise<ClearSessionPathLabelsResultWire> {
    return this.request<ClearSessionPathLabelsResultWire>("clearSessionPathLabels", args);
  }
  /** Confidentiality plan 13 D4: the derived label of `from` follows its file to `to`. */
  async followDerivedLabel(args: { from: string; to: string; how: "rename" | "link" | "identity"; session?: string }): Promise<FollowDerivedLabelResultWire> {
    return this.request<FollowDerivedLabelResultWire>("followDerivedLabel", args);
  }
  /** Secret-discovery.md §2.8: the text a PDF `document` block of a tool
   *  result is forwarded as (null: none; the proxy masks it whole). */
  async documentText(args: { data: string; mediaType: string; origin?: string; sessionKey?: string }): Promise<{ text: string | null; twinOf?: string; reason: string }> {
    return this.request("documentText", { data: args.data, mediaType: args.mediaType, ...(args.origin ? { origin: args.origin } : {}), ...(args.sessionKey ? { sessionKey: args.sessionKey } : {}) });
  }

  async scanSecretValues(text: string): Promise<{ hits: Array<{ symbol: string; level: string }> }> {
    return this.request("scanSecretValues", { text });
  }
  /** Confidentiality plan 15 §3.2: the prompt filter over a request's
   *  user-role segments. `dryRun` is accepted only on the human socket. */
  async filterPrompt(args: {
    session?: string;
    agent: string;
    segments: Array<{ id: string; origin: "human" | "harness" | "side-call"; text: string }>;
    dryRun?: boolean;
    /** Phase 3: the caller waits on a `hold` and asks again. */
    holds?: boolean;
    /** Phase 3: the last ask of a held request (its deadline passed). */
    heldMs?: number;
  }): Promise<FilterPromptResultWire> {
    // Plan 15 §4.3, §13.5 item 11: a plugin may take up to its deadline (at
    // most 30 s), longer than the request timeout; the arbiter's progress
    // frames keep the call alive while it works, up to FILTER_PROMPT_TIMEOUT_MS
    // in all. An arbiter that never answers still fails closed at the
    // ordinary timeout.
    return this.request<FilterPromptResultWire>("filterPrompt", { ...args, progress: true }, this.requestTimeoutMs, { maxMs: FILTER_PROMPT_TIMEOUT_MS });
  }
  /** Plan 15 §7: the human's answer to a held prompt. Admin channel only. */
  async resolvePromptHold(args: { approvalId: string; answer: "send" | "mask" | "cancel"; scope?: "once" | "session" }): Promise<{ approval: EgressApproval; answer: string; scope: string }> {
    return this.request("resolvePromptHold", args);
  }
  /** Plan 15 §7: let one past prompt finding through as written. Admin channel only. */
  async letPromptFindingThrough(args: { session: string; category: string; ref: string; turn?: string; scope: "once" | "session" }): Promise<{ approval: EgressApproval }> {
    return this.request("letPromptFindingThrough", args);
  }
  /** Plan 15 §7: the pending prompt holds with their found text. Human plane only. */
  async promptHolds(): Promise<PromptHoldsResultWire> {
    return this.request<PromptHoldsResultWire>("promptHolds", {});
  }
  /** Plan 15 §8.1: the prompt filters, who set them, the actions, the
   *  exceptions (no pattern) and the packs (counts only). */
  async promptFilters(): Promise<PromptFiltersResultWire> {
    return this.request<PromptFiltersResultWire>("promptFilters", {});
  }
  /** Plan 15 §13.7 item 4: the exceptions with their patterns. Human plane only. */
  async promptExceptions(): Promise<PromptExceptionsResultWire> {
    return this.request<PromptExceptionsResultWire>("promptExceptions", {});
  }
  /** Plan 15 §8.1: every pack in full. Human plane only. */
  async promptFilterPacks(): Promise<PromptFilterPacksResultWire> {
    return this.request<PromptFilterPacksResultWire>("promptFilterPacks", {});
  }
  /** Plan 15 §8.1: typed edits to one of the person's packs. Admin channel only. */
  async promptPackEdit(args: { edits: unknown; dryRun?: boolean; sample?: string; requestedBy?: string }): Promise<PromptPackEditResultWire> {
    return this.request<PromptPackEditResultWire>("promptPackEdit", args);
  }

  /** Mark a file (by content hash + path) as written by a tainted process. */
  async taintFile(args: {
    contentHash: string;
    path: string;
    originHost: string;
    writerProc?: string;
    session?: string;
  }): Promise<void> {
    await this.request<{ ok: true }>("taintFile", args);
  }

  /** Query whether a file (by content hash or path) is tainted. */
  async fileTrust(args: { contentHash?: string; path?: string }): Promise<FileTrustResult> {
    return this.request<FileTrustResult>("fileTrust", args);
  }

  /** Close the connection — TERMINAL. Any in-flight dial is destroyed and any
   *  later connect()/request rejects ("arbiter client is closed"): for
   *  security ops that is fail-closed, for best-effort emits a swallowed
   *  rejection — never a silent ownerless reconnect. */
  close(): void {
    this.closed = true;
    // destroy(err) so the in-flight dial's "error" handler REJECTS the pending
    // connect() promise — a bare destroy() emits only "close" and would leave
    // that promise (and its awaiting request) pending forever.
    this.connectingSock?.destroy(new Error("arbiter client is closed"));
    this.connectingSock = undefined;
    this.sock?.end();
    this.sock?.destroy();
    this.onClose();
  }

  /**
   * Stop this client's socket from holding the process's event loop open.
   *
   * FOR CLIENTS EMBEDDED IN A HOST WE DO NOT OWN. A long-lived connection is a
   * live libuv handle, so node will not exit while it is open — which for a
   * daemon is exactly right, and for an in-process guest is a lifecycle change
   * the host never asked for. The OpenClaw inspect PLUGIN hit precisely this:
   * `openclaw agent --local` completed its turn, printed its result, and then
   * hung forever, because the plugin's arbiter connection kept the loop alive
   * (found 2026-08-06 — the run only ended when the harness's wall-clock
   * SIGKILLed the process group). Same family as the stranded-client hang the
   * integration exit-guard was built for.
   *
   * The connection stays fully usable: `unref` affects only whether the handle
   * COUNTS toward keeping the loop alive. A call in flight is not protected —
   * if the host has nothing else pending it may exit mid-request — which is the
   * correct trade for a guest: the host's lifetime wins. Idempotent, and safe
   * to call before connect (it re-applies on the next connect).
   */
  unref(): void {
    this.unrefRequested = true;
    this.sock?.unref();
    this.connectingSock?.unref();
  }
}
