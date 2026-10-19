/**
 * proxy — the Mandu egress data-usage gate (a COOPERATIVE forward HTTP(S) proxy).
 *
 * The agent points HTTP_PROXY / HTTPS_PROXY at this server. It is a FORWARD proxy
 * (dynamic destinations, not a fixed upstream). It is the network "exfiltration
 * kill-switch": a request carrying an untrusted `$MDU:*` symbol is gated by
 * the arbiter's data-usage policy (sending a symbol to an untrusted destination,
 * or using a symbol AS the destination, requires approval → fail-closed BLOCK).
 * Symbol-free requests pass through unchanged. Model-API hosts are EXCLUDED (the
 * anthropic-proxy / openai-proxy own them under a different policy).
 *
 * Two request shapes a forward proxy receives:
 *   - HTTP  (plaintext): the client sends an absolute-form request line
 *     (`GET http://host/path`). We read the body, run `gateRequest` (egress gate),
 *     forward the possibly-rewritten request to the real destination, then run
 *     `observeResponse` (Plan 7: returns RAW body + best-effort taints the process;
 *     was `symbolizeResponse` pre-Plan-7). Block → 403. Arbiter/infra error →
 *     fail-closed (403/502).
 *   - CONNECT (HTTPS): the client asks to tunnel to `host:port`. If the host
 *     string carries a symbol → 403 (symbol-as-destination). Otherwise establish
 *     a plain TCP tunnel (net.connect, pipe both ways). The encrypted body is NOT
 *     inspectable without MITM — DOCUMENTED LIMITATION: the symbol-in-body gate
 *     cannot apply to HTTPS. We emit a `net_action(tunneled)` event noting the
 *     body is opaque. With TLS inspection on (the default whenever the
 *     confidentiality axis is), a non-model CONNECT is terminated instead
 *     (mitm.ts) and each decrypted request runs the same gate.
 *
 * THE SENDER, ON EVERY LEG (plan 13 D6, 2026-10-02): the guard lets a process
 * holding a secret reach this proxy's port only because the proxy judges the
 * process again. Every leg resolves every process holding the client's socket
 * (conn-attr.ts) and runs egress.ts `secretTaintVerdict`: per plain-HTTP
 * request, per decrypted request (the holders at the CONNECT and those now),
 * and for a blind tunnel at the CONNECT (refused unless the destination is
 * bound for every holder) and again before each chunk the client sends (the
 * holders at the CONNECT and every process holding the socket now that holds
 * a secret, found among the processes the arbiter lists: `chunkHolders`). A
 * connection that cannot be attributed is refused while any process of the
 * session holds a secret.
 *
 * FAIL-CLOSED (mandu.md invariant): if the gate denies / the arbiter is
 * unreachable / the destination forward fails, we NEVER forward raw symbol data;
 * we block (403) or 502. Every `emit` is best-effort and OFF the security path.
 */

import {
  BlockedDestinationError,
  dialHostOf,
  dialRefusal,
  guardDial,
  isBlockedDestinationError,
  type DialPolicy,
} from "./blocked-destinations.js";
import { deniedHost, denyHostReason, denyHostsForIdentity, type DenyHostRule } from "./deny-hosts.js";
import { MODEL_HOST_NAMES, modelHostRule, modelHostTunnelReason, modelPathDecision, type ModelPathDecision } from "./model-host-paths.js";
import { BROWSER_NOTE_CAPABILITIES, editModelCall, type ModelCallEdit, type ModelNoteKind } from "./model-note.js";
import type { SessionLogins } from "./session-logins.js";
import { createServer, request as httpRequest, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { connect as netConnect, isIP, type Socket } from "node:net";
import { Duplex as DuplexStream, type Duplex } from "node:stream";

import type { Arbiter, ArbiterEvent, EgressRefusalKind } from "./arbiter-client.js";
import type { MockSites } from "./mock-sites.js";
import { gateRequest, observeResponse, isModelHost, isModelService, findSymbols, withheldPolicy, agentWithheld, heldForEvent, secretTaintVerdict, refusalKindOf, EGRESS_HOLD_MAX_MS, type SecretTaintVerdict } from "./egress.js";
import { MitmEngine, type MitmConfig } from "./mitm.js";
import { forwardDestination, statedDestination } from "./destination.js";
import { attributeHolders as liveAttributeHolders, holdersAmong, holdersOfInode, socketInodeFor, type Endpoint, type ProcHolder } from "./conn-attr.js";

export interface NetProxyOptions {
  arbiter: Arbiter;
  /** Extra model-API hosts to exclude (e.g. a local inference server). */
  modelHosts?: string[];
  /** Logger; defaults to console.error. Set to a no-op in tests. */
  log?: (msg: string) => void;
  /** Max request/response body bytes buffered for inspection. */
  maxBodyBytes?: number;
  /**
   * Forwarder for plaintext HTTP requests to the real destination. Injectable so
   * tests drive a mock destination / model-host passthrough with no network.
   * Defaults to a real node:http forwarder.
   */
  forwarder?: HttpForwarder;
  /** Session id threaded into emitted events. */
  sessionId?: string;
  /** Tenant stamp for every event this proxy emits (policy-surface.md
   *  §2.7); server-main passes MANDU_TENANT. Absent → events stay unstamped. */
  tenant?: string;
  /**
   * OPTIONAL offline web mock. When set, a request whose URL matches a configured
   * site is served the canned response instead of being forwarded (the response
   * still flows through ingress symbolization). For deterministic agent loops /
   * demos without touching the internet. Absent → normal forwarding only.
   */
  mockSites?: MockSites;
  /**
   * OPT-IN, DEFAULT OFF: terminate TLS for non-model HTTPS hosts so the egress
   * gate can inspect decrypted request BODIES (otherwise CONNECT is blind-
   * tunneled and an HTTPS-body symbol is invisible). When set, a session-local CA
   * under `caDir` mints per-host leaf certs (the agent must trust the CA via
   * NODE_EXTRA_CA_CERTS / CURL_CA_BUNDLE). Absent → today's behavior unchanged.
   * Model-API hosts stay blind-tunnel passthrough, except under the model-host
   * deny (`modelHostDeny`), where they are terminated and judged by path.
   */
  mitm?: MitmConfig;
  /**
   * Resolve the connecting process's proc key from (clientSrc, proxyAddr).
   * Injectable so tests drive a known pid / a forced miss with no real /proc.
   * Used only when `attributeHolders` is not given: its key is then the one
   * holder (no ancestors). Returning undefined = unattributed. NEVER
   * fabricates a wrong key.
   */
  attributeConnection?: (clientSrc: Endpoint, proxyAddr: Endpoint) => string | undefined;
  /**
   * Plan 13 D6: EVERY process holding the client's end of a connection, with
   * its ancestor chain (`[]` = unattributed). Injectable for tests; defaults
   * to the live /proc scan (conn-attr.ts `attributeHolders`). Asked on every
   * leg: per plain-HTTP request, at a CONNECT, and again per decrypted
   * request on the TLS-inspected leg (a holder forked after the CONNECT is
   * judged too).
   */
  attributeHolders?: (clientSrc: Endpoint, proxyAddr: Endpoint) => ProcHolder[];
  /**
   * A blind tunnel's chunks (plan 13 D6, 2026-10-07): the holders of the
   * client's end that are, or descend from, a process in `tainted` (the
   * arbiter's `secretTaintedProcesses`), or null when they cannot be told
   * apart (then every holder is rescanned). Injectable for tests; defaults
   * to the live narrowed scan (conn-attr.ts `holdersAmong`), or, when
   * `attributeHolders` / `attributeConnection` is injected, to that
   * attribution filtered by `tainted` over each holder and its ancestors.
   */
  attributeTaintedHolders?: (clientSrc: Endpoint, proxyAddr: Endpoint, tainted: ReadonlySet<string>) => ProcHolder[] | null;
  /**
   * Self-describing identity served at `GET /_mandu/identity` so a launcher
   * can verify a listening net-proxy is THIS session's before adopting it (the
   * start-or-reuse safety check — mirror of the anthropic-proxy endpoint).
   * Carries the security-relevant routing the reuse decision keys on — the
   * arbiter socket (wrong one = wrong egress policy + symbol table, approvals
   * and events in the wrong session). Absent → the endpoint reports
   * `{ mandu:false }` and a launcher refuses to adopt this proxy.
   */
  identity?: NetProxyIdentity;
  /**
   * Skip the always-denied destination check (cloud metadata, link-local;
   * blocked-destinations.ts). server-main sets it from
   * MANDU_NET_ALLOW_METADATA=1. Default false: those destinations are refused
   * with 403 in every mode.
   */
  allowMetadata?: boolean;
  /**
   * TEST ONLY (in-process tests whose upstream servers listen on loopback):
   * skip the this-machine check (blocked-destinations.ts), so the proxy
   * relays to loopback and this machine's own addresses. server-main never
   * sets it and no environment variable reaches it: a launched net-proxy
   * always refuses this machine, except a mock-sites host route's own dial.
   * Default false.
   */
  allowThisMachine?: boolean;
  /**
   * The agent's upload hosts (deny-hosts.ts; launcher upload-deny.ts), from
   * MANDU_NET_PROXY_DENY_HOSTS: a CONNECT or plain-HTTP request to one is
   * refused with 403 before anything is dialed, in every mode. Published in
   * the identity (`denyHosts`), so a launch never adopts a proxy that denies
   * another set.
   */
  denyHosts?: readonly DenyHostRule[];
  /**
   * The AI agents' login files this proxy's session leaves raw
   * (session-logins.ts), from MANDU_NET_PROXY_SESSION_LOGINS: sent with each
   * tripwire scan, so another session's registration of them does not
   * refuse this session's own agent its own login (secret-discovery.md
   * §1.10). Published in the identity (`sessionLogins`). Absent: nothing is
   * exempt.
   */
  sessionLogins?: SessionLogins;
  /**
   * Confidentiality.md §4, "A held request": how long (ms) a request whose
   * only obstacle is an unanswered per-symbol card is held while the human
   * answers it (egress.ts `EgressHold`), on the plain and the TLS-inspected
   * legs. server-main sets it from MANDU_EGRESS_HOLD_MS. Default 0: no
   * hold, the request is refused at once (as before).
   */
  egressHoldMs?: number;
  /**
   * Model services a program in the session calls itself
   * (MANDU_NET_PROXY_MODEL_SERVICES; egress.ts GateInput.modelService): a
   * placeholder in a request to one leaves as it is, outside the
   * Authorization header. Default none.
   */
  modelServices?: string[];
  /**
   * The handling note for a browser agent's own model calls (model-note.ts;
   * MANDU_NET_PROXY_MODEL_NOTE, the launcher's when it runs a DevTools
   * relay): a Chat Completions request to a model service, on the
   * TLS-inspected leg, gets Mandu's note as its first system message.
   * Default none: every request leaves as written.
   */
  modelNote?: ModelNoteKind | null;
  /**
   * The model-host deny (model-host-paths.ts; agent-sdks.md §4, "The
   * model-host deny"): a request to a model vendor's host is let through
   * only when its path is on that host's list, on the plain leg and, with
   * TLS inspection on, on the inspected leg (a model host is then
   * terminated like any other host); with TLS inspection off a CONNECT to
   * one is refused whole. server-main sets it from
   * MANDU_NET_PROXY_MODEL_HOST_DENY=1 (the launcher's, whenever the
   * confidentiality axis is on). Published in the identity
   * (`modelHostDeny`). Default false: model hosts pass as before (a blind
   * tunnel, the plain leg's passthrough).
   */
  modelHostDeny?: boolean;
}

/** The identity a net-proxy publishes at `/_mandu/identity` (see NetProxyOptions). */
export interface NetProxyIdentity {
  /** Always "net-proxy" — must match the service the launcher wants. */
  service: "net-proxy";
  /** The per-session scope id (informational; NOT part of the reuse key). */
  sessionKey?: string;
  /** The arbiter Unix socket this proxy gates against (reuse key). */
  arbiterSock?: string;
}

/** The path the identity endpoint answers on (loopback admin, never forwarded). */
export const IDENTITY_PATH = "/_mandu/identity";

/** A buffered upstream HTTP response. */
export interface ForwardedResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

/** Forward one plaintext HTTP request to the real destination. `dial`, when
 *  set, is where to connect instead of the URL's host (a mock-sites host
 *  route, always loopback); the request keeps the URL's Host header. */
export type HttpForwarder = (args: {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  dial?: { host: string; port: number };
}) => Promise<ForwardedResponse>;

const DEFAULT_MAX_BODY = 64 * 1024 * 1024; // 64 MiB

/** The bound on noteRefusal's report (it delays the 403 at most this long). */
const REFUSAL_NOTE_TIMEOUT_MS = 1000;


/** Content types we treat as text and run symbolization over on the response. */
function isTextResponse(headers: Record<string, string | string[] | undefined>): boolean {
  const ct = headerValue(headers, "content-type") ?? "";
  return (
    ct.includes("text/") ||
    ct.includes("json") ||
    ct.includes("xml") ||
    ct.includes("javascript") ||
    ct.includes("html") ||
    ct === ""
  );
}

function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const lname = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lname) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

export class NetProxy {
  private readonly arbiter: Arbiter;
  private readonly modelHosts: string[];
  private readonly log: (msg: string) => void;
  private readonly maxBodyBytes: number;
  private readonly forward: HttpForwarder;
  private readonly sessionId: string;
  /** Tenant stamp for emitted events (policy-surface.md §2.7), or null. */
  private readonly tenant: "live" | "test" | null;
  /** Optional offline web mock (undefined → forward everything). */
  private readonly mockSites?: MockSites;
  private server?: Server;
  /** This proxy's own listen address, learned in listen(). Used by the self-loop
   *  guard so a request whose destination IS this proxy is refused, not forwarded
   *  to itself (which recurses via the Host-header fallback until ports exhaust). */
  private listenHost = "";
  private listenPort = 0;
  /** Active CONNECT tunnel sockets, so close() can tear them down. */
  private readonly tunnels = new Set<Duplex>();
  /** In-flight best-effort emits, drained at close(). */
  private readonly pendingEmits = new Set<Promise<void>>();
  /** OPT-IN MITM engine (TLS termination). Undefined → blind-tunnel (default). */
  private readonly mitm?: MitmEngine;
  /** The connection-attribution function: every holder of the client's end
   *  (injectable for tests; default: live /proc). */
  private readonly attributeAll: (clientSrc: Endpoint, proxyAddr: Endpoint) => ProcHolder[];
  /** Attribution reads live /proc (nothing injected): `resolveHolders`
   *  keeps each connection's client inode in `clientInodes`. */
  private readonly liveAttribution: boolean;
  /** A connection's socket object → the client end's socket inode (fixed
   *  for the connection's life; see resolveHolders). Weak: it goes with
   *  the connection. */
  private readonly clientInodes = new WeakMap<object, number>();
  /** A blind tunnel's per-chunk holder lookup: a factory per tunnel (the
   *  live form keeps the socket's inode), see NetProxyOptions. */
  private readonly taintedHoldersFor: () => (clientSrc: Endpoint, proxyAddr: Endpoint, tainted: ReadonlySet<string>) => ProcHolder[] | null;
  /** Proc keys of processes found gone by the narrowed scan (a
   *  `${pid}-${starttime}` key never comes back), across tunnels. */
  private readonly goneKeys = new Set<string>();
  /** Self-describing identity for the launcher's reuse safety check, or null. */
  private readonly identity: NetProxyIdentity | null;
  /** Opt-out of the always-denied destination check (see NetProxyOptions). */
  private readonly allowMetadata: boolean;
  /** What every dial of this proxy refuses (blocked-destinations.ts). */
  private readonly dialPolicy: DialPolicy;
  /** The agent's upload hosts, refused before any dial (see NetProxyOptions). */
  private readonly denyHosts: readonly DenyHostRule[];
  /** The logins this session leaves raw (see NetProxyOptions). */
  private readonly sessionLogins: SessionLogins | null;
  /** How long a request may be held for the human's answer (ms; 0 = none). */
  private readonly egressHoldMs: number;
  /** The model-host deny (see NetProxyOptions). */
  private readonly modelHostDeny: boolean;
  /** Model services (see NetProxyOptions). */
  private readonly modelServices: readonly string[];
  /** The handling note's kind for model-service calls (see NetProxyOptions). */
  private readonly modelNote: ModelNoteKind | null;

  constructor(opts: NetProxyOptions) {
    this.arbiter = opts.arbiter;
    this.modelHosts = opts.modelHosts ?? [];
    this.modelServices = opts.modelServices ?? [];
    this.modelNote = opts.modelNote ?? null;
    this.log = opts.log ?? ((m) => console.error(`[net-proxy] ${m}`));
    this.maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;
    this.allowMetadata = opts.allowMetadata === true;
    this.dialPolicy = { allowMetadata: this.allowMetadata, allowThisMachine: opts.allowThisMachine === true };
    this.denyHosts = opts.denyHosts ?? [];
    this.sessionLogins = opts.sessionLogins ?? null;
    this.modelHostDeny = opts.modelHostDeny === true;
    const holdMs = opts.egressHoldMs ?? 0;
    this.egressHoldMs = Number.isFinite(holdMs) && holdMs > 0 ? Math.min(Math.floor(holdMs), EGRESS_HOLD_MAX_MS) : 0;
    this.forward = opts.forwarder ?? makeHttpForwarder(this.maxBodyBytes, this.dialPolicy);
    const one = opts.attributeConnection;
    this.attributeAll = opts.attributeHolders
      ?? (one
        ? (c, p) => {
            const k = one(c, p);
            return k === undefined ? [] : [{ procKey: k, ancestors: [] }];
          }
        : liveAttributeHolders);
    this.liveAttribution = !opts.attributeHolders && !one;
    const injectedTainted = opts.attributeTaintedHolders;
    if (injectedTainted) {
      this.taintedHoldersFor = () => injectedTainted;
    } else if (opts.attributeHolders || one) {
      // An injected attribution (tests): the same holders, narrowed by the
      // same rule the live scan applies (a holder of a secret, or one below).
      this.taintedHoldersFor = () => (c, p, tainted) =>
        this.attributeAll(c, p).filter((h) => tainted.has(h.procKey) || h.ancestors.some((a) => tainted.has(a)));
    } else {
      this.taintedHoldersFor = () => {
        let inode: number | null = null;
        return (c, p, tainted) => {
          inode ??= socketInodeFor(c, p);
          if (inode === null) return null;
          if (this.goneKeys.size > 100_000) this.goneKeys.clear(); // only a cache
          return holdersAmong(inode, tainted, this.goneKeys);
        };
      };
    }
    this.identity = opts.identity ?? null;
    this.tenant = opts.tenant === "live" || opts.tenant === "test" ? opts.tenant : null;
    this.sessionId = opts.sessionId ?? `eg_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
    this.mockSites = opts.mockSites;
    if (opts.mitm) {
      // Construct the engine eagerly so a missing openssl / unwritable CA dir
      // throws HERE (the caller — server-main — then degrades to non-MITM) rather
      // than mid-connection. Throws propagate out of the constructor by design.
      this.mitm = new MitmEngine({
        ...opts.mitm,
        allowMetadata: opts.mitm.allowMetadata ?? this.allowMetadata,
        allowThisMachine: opts.mitm.allowThisMachine ?? this.dialPolicy.allowThisMachine,
      }, {
        arbiter: this.arbiter,
        log: this.log,
        maxBodyBytes: this.maxBodyBytes,
        // Attribution-only: MITM-path gate requests carry the same session id
        // the events are filed under.
        sessionKey: this.sessionId,
        egressHoldMs: this.egressHoldMs,
        modelServices: this.modelServices,
        ...(this.modelNote ? { modelNote: (bodyText: string, headers: NodeJS.Dict<string | string[]>) => this.noteBody(bodyText, headers) } : {}),
        emit: (action, fields) => this.safeEmit(action, fields),
        // The §4 verbatim tripwire over the decrypted request, as on the
        // plain leg (defense-in-depth; fail-open on error).
        tripwire: (surfaces, destination, opts) => this.fingerprintTripwire(surfaces, destination, opts),
        // A model host (terminated only under the model-host deny) is routed
        // only by a route naming it, never by the `*` catch-all.
        route: (host) => (isModelHost(host, this.modelHosts) ? this.mockSites?.routeOf(host) : this.mockSites?.route(host))?.tls,
        noteRefusal: (holders, kind) => this.noteRefusal(holders, kind),
        ...(this.modelHostDeny ? { modelPath: (host: string, method: string, target: string) => this.modelPathOf(host, method, target) } : {}),
        track: (s) => this.tunnels.add(s),
        untrack: (s) => this.tunnels.delete(s),
      });
    }
  }

  /** The body of a model-service Chat Completions call with Mandu's
   *  handling note added and the DevTools relay's pending refusals last, or
   *  why it leaves as written (model-note.ts `editModelCall`): the arbiter's
   *  note for a browser agent's model, asked per request (the axes may
   *  change mid-session), and this session's refusals, taken (each told
   *  once); never a reason to refuse. */
  private async noteBody(bodyText: string, headers: NodeJS.Dict<string | string[]>): Promise<ModelCallEdit> {
    const arbiter = this.arbiter;
    return editModelCall(bodyText, headers, {
      ...(arbiter.handlingPrompt ? { note: () => arbiter.handlingPrompt!({ capabilities: BROWSER_NOTE_CAPABILITIES, sessionKey: this.sessionId }) } : {}),
      ...(arbiter.takeRelayNotices ? { relayNotices: () => arbiter.takeRelayNotices!({ sessionKey: this.sessionId }) } : {}),
    });
  }

  /** The session CA cert path when MITM is enabled (else undefined). The launcher
   * logs this so the user/agent can trust it. */
  get mitmCaCertPath(): string | undefined {
    return this.mitm?.caCertPath;
  }

  async listen(port: number, host = "127.0.0.1"): Promise<number> {
    const server = createServer((req, res) => {
      this.onRequest(req, res).catch((err) => {
        this.log(`unhandled error: ${(err as Error).message}`);
        this.refuse(res, 502, `internal proxy error: ${(err as Error).message}`);
      });
    });
    // Nagle off on every accepted connection, said here rather than left
    // to the server's default: the answers written back, a CONNECT's
    // tunnel and the TLS-inspected leg's records must not wait on the
    // client's delayed ACK (plan 13 D6, "The kept-alive floor").
    server.on("connection", (sock: Socket) => sock.setNoDelay(true));
    // CONNECT is delivered on a dedicated event, not the request handler.
    server.on("connect", (req, clientSocket, head) => {
      this.onConnect(req, clientSocket, head);
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.off("error", reject);
        resolve();
      });
    });
    const addr = server.address();
    const boundPort = typeof addr === "object" && addr ? addr.port : port;
    // Remember our own address so the self-loop guard (onRequest) can refuse a
    // request that would forward back into this same listener.
    this.listenHost = host;
    this.listenPort = boundPort;
    this.log(`listening (forward proxy) on http://${host}:${boundPort}`);
    return boundPort;
  }

  async close(): Promise<void> {
    for (const t of this.tunnels) t.destroy();
    this.tunnels.clear();
    if (this.server) {
      await new Promise<void>((resolve) => this.server!.close(() => resolve()));
      this.server = undefined;
    }
    await Promise.allSettled([...this.pendingEmits]);
  }

  // ── observability (BEST-EFFORT, OFF the security path) ──────────────────────

  /** Fire a `net_action` event at the arbiter, best-effort. Failures swallowed. */
  private safeEmit(action: string, fields: Record<string, unknown>): void {
    const now = Date.now();
    const event: ArbiterEvent = {
      kind: "net_action",
      sessionId: this.sessionId,
      ...(this.tenant ? { tenant: this.tenant } : {}),
      id: `${this.sessionId}:${now.toString(36)}:${Math.floor(Math.random() * 1e6).toString(36)}`,
      // Canonical ManduEvent shape (dashboard/src/event-model.ts): an ISO-8601
      // `ts` and the cross-cutting fields the dashboard renders, so net traces are
      // not silently dropped by the event consumer. A net_action is observability,
      // not a model-context ingress, so the §9 invariant trivially holds (false).
      // (The arbiter stamps `seq` on emit.)
      ts: new Date(now).toISOString(),
      turn: 0,
      callId: null,
      parentId: null,
      view: "AgentView",
      boundary: "network",
      emitter: "net-supervisor",
      input: null,
      output: null,
      invariant: { violatedInvariant: false },
      action,
      ...fields,
    };
    const p = (async () => {
      try {
        await this.arbiter.emit(event);
      } catch (err) {
        this.log(`emit failed (non-fatal, off security path): ${(err as Error).message}`);
      }
    })().finally(() => {
      this.pendingEmits.delete(p);
    });
    this.pendingEmits.add(p);
  }

  /**
   * The §4 verbatim-leak tripwire over one request's ORIGINAL surfaces. Returns
   * a block reason + the tripped SYMBOL names on a positive hit, else null.
   * Fail-OPEN (returns null) on any error or an arbiter without the op — this is
   * defense-in-depth behind the per-symbol gate, never the guarantee, so it must
   * not fail a benign request. The reason NAMES symbols only, never values.
   */
  private async fingerprintTripwire(
    surfaces: { url: string; headers: NodeJS.Dict<string | string[]>; bodyText: string },
    destination: string,
    opts: { strict?: boolean } = {},
  ): Promise<{ reason: string; symbols: string[] } | null> {
    // STRICT ("Send without it", confidentiality.md §4): the request goes
    // only because the human chose to send it without the secret, so the
    // scan that says no secret value is left in it must run and find
    // nothing. An arbiter without the op, or a failed scan, blocks
    // (fail-closed) instead of being a no-op.
    const unchecked = (why: string): { reason: string; symbols: string[] } | null =>
      opts.strict
        ? { reason: `the request you chose to send without the secret could not be checked for secret values (${why}), so it was not sent (fail-closed)`, symbols: [] }
        : null;
    if (!this.arbiter.egressFingerprintScan) return unchecked("the Mandu service cannot check");
    try {
      const headerText = Object.entries(surfaces.headers)
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v ?? ""}`)
        .join("\n");
      const res = await this.arbiter.egressFingerprintScan({
        surfaces: [
          { where: "url", text: surfaces.url },
          { where: "header", text: headerText },
          { where: "body", text: surfaces.bodyText },
        ],
        destination,
        // The logins this session runs on: their registered rows are not
        // scanned for it (session-logins.ts, secret-discovery.md §1.10).
        ...(this.sessionLogins ? { sessionLogins: this.sessionLogins } : {}),
      });
      if (!res.tripped || res.hits.length === 0) return null;
      const symbols = res.hits.map((h) => h.symbol);
      return {
        reason:
          `§4 fingerprint tripwire: ${res.hits.length} secret value(s) appeared VERBATIM in the ` +
          `request to '${destination}' with no symbol — a raw-secret leak the per-symbol gate cannot see ` +
          `(${res.hits.map((h) => `${h.symbol}@${h.where}`).join(", ")}). Blocked.`,
        symbols,
      };
    } catch (err) {
      // Defense-in-depth: an error here is a NO-OP, never a block of a benign
      // request — the guarantee is the per-symbol gate, which already ran.
      this.log(`fingerprint tripwire error (${opts.strict ? "strict: blocks" : "non-fatal, defense-in-depth"}): ${(err as Error).message}`);
      return unchecked("the check failed");
    }
  }

  // ── process attribution (ON the security path since plan 13 D6) ─────────────

  /**
   * Every process holding the client's end of THIS connection (the agent's
   * client, e.g. curl via HTTP(S)_PROXY, and any process that inherited the
   * descriptor), each with its ancestors. The accepted socket gives the
   * client's source endpoint (remoteAddress:remotePort) and this proxy's
   * accept endpoint (localAddress:localPort); conn-attr matches the client's
   * /proc/net/tcp row (local==clientSrc, rem==proxyAddr). `[]` on ANY
   * miss/error = unattributed, which the secret-taint verdict refuses while
   * the session holds a secret (egress.ts `secretTaintVerdict`). NEVER a
   * wrong key.
   *
   * The live form keeps one thing per connection: the client end's socket
   * inode, found once in /proc/net/tcp (`clientInodes`, keyed by this
   * connection's own socket object). It is fixed for the connection's life
   * (the kernel never hands an open 4-tuple to another socket, and a new
   * connection is a new socket object here), so a request on a kept-alive
   * or TLS-inspected connection reads only the descriptor tables. Who holds
   * that inode is read again on every call (`holdersOfInode`): no process,
   * pid or proc key is kept, so a holder that appeared since, or a pid that
   * now names another process, is judged as it is now (plan 13 D6, "the
   * full scan's cost").
   */
  private resolveHolders(sock: { remoteAddress?: string; localAddress?: string; remotePort?: number; localPort?: number }): ProcHolder[] {
    try {
      if (this.liveAttribution) {
        const kept = this.clientInodes.get(sock);
        if (kept !== undefined) return holdersOfInode(kept);
      }
      const clientIp = normalizeIp(sock.remoteAddress);
      const proxyIp = normalizeIp(sock.localAddress);
      const clientPort = sock.remotePort;
      const proxyPort = sock.localPort;
      if (!clientIp || !proxyIp || clientPort == null || proxyPort == null) return [];
      if (this.liveAttribution) {
        const inode = socketInodeFor({ ip: clientIp, port: clientPort }, { ip: proxyIp, port: proxyPort });
        if (inode === null) return []; // no row (yet): asked again next time
        this.clientInodes.set(sock, inode);
        return holdersOfInode(inode);
      }
      return this.attributeAll({ ip: clientIp, port: clientPort }, { ip: proxyIp, port: proxyPort });
    } catch {
      return []; // unattributed; never a wrong key
    }
  }

  /**
   * A blind tunnel, before each chunk (plan 13 D6; the P0 triage's 2a,
   * 2026-10-07): the processes holding the client's end now that could
   * change the verdict, i.e. those the arbiter would answer tainted. The
   * arbiter lists every process key it holds taint for
   * (`secretTaintedProcesses`); `narrow` finds which of those, or of their
   * live descendants, hold this socket, reading only their descriptor
   * tables. An empty list: no process holds a secret, so no holder can be
   * refused, and nothing is scanned. FAIL-CLOSED: an arbiter without the
   * op, one that fails it or answers malformed, or a narrowing that cannot
   * answer, gets the full rescan of every holder (the MITM leg's per
   * request), never the CONNECT's holders alone.
   */
  private async chunkHolders(
    sock: { remoteAddress?: string; localAddress?: string; remotePort?: number; localPort?: number },
    narrow: (clientSrc: Endpoint, proxyAddr: Endpoint, tainted: ReadonlySet<string>) => ProcHolder[] | null,
  ): Promise<ProcHolder[]> {
    let tainted: string[] | null = null;
    if (this.arbiter.secretTaintedProcesses) {
      try {
        const r = await this.arbiter.secretTaintedProcesses();
        if (Array.isArray(r?.procKeys) && r.procKeys.every((k) => typeof k === "string")) tainted = r.procKeys;
      } catch {
        tainted = null;
      }
    }
    if (tainted === null) return this.resolveHolders(sock);
    if (tainted.length === 0) return [];
    const clientIp = normalizeIp(sock.remoteAddress);
    const proxyIp = normalizeIp(sock.localAddress);
    if (!clientIp || !proxyIp || sock.remotePort == null || sock.localPort == null) return this.resolveHolders(sock);
    let found: ProcHolder[] | null;
    try {
      found = narrow({ ip: clientIp, port: sock.remotePort }, { ip: proxyIp, port: sock.localPort }, new Set(tainted));
    } catch {
      found = null;
    }
    return found ?? this.resolveHolders(sock);
  }

  /** The secret-taint verdict for `holders` at `host` (egress.ts), with
   *  this proxy's session for the unattributed case. */
  private taintVerdict(holders: readonly ProcHolder[], host: string, granted?: Set<string>): Promise<SecretTaintVerdict> {
    return secretTaintVerdict({ arbiter: this.arbiter, holders, destinationHost: host, sessionKey: this.sessionId, ...(granted ? { granted } : {}) });
  }

  /** Plan 10 §11.8, "Refused connections": tell the arbiter (human plane)
   *  that a connection from `holders` was refused, so the tool call whose
   *  tree holds one says so in its result. Awaited (bounded) before the 403
   *  goes out, so the record exists by the time the program's result reaches
   *  the model proxy; a failure or a timeout changes nothing (the refusal
   *  stands, only the note is lost). A kind, never the host.
   *
   *  "A refusal no process is tied to" (2026-10-17): with no holder the
   *  report says so (`procKeys: []`, `unattributed: true`) instead of being
   *  dropped; the arbiter ties it to the session's calls running then,
   *  never to a guessed process, and keeps one per (session, kind) per call. */
  private async noteRefusal(holders: readonly ProcHolder[], kind: EgressRefusalKind): Promise<void> {
    const procKeys = [...new Set(holders.map((h) => h.procKey).filter((k) => k !== ""))];
    if (!this.arbiter.recordEgressRefusal) return;
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        this.arbiter.recordEgressRefusal({
          procKeys, kind, ...(procKeys.length === 0 ? { unattributed: true } : {}), ...(this.sessionId ? { sessionKey: this.sessionId } : {}),
        }),
        new Promise<void>((resolve) => { timer = setTimeout(resolve, REFUSAL_NOTE_TIMEOUT_MS); }),
      ]);
    } catch (err) {
      this.log(`recordEgressRefusal failed: ${(err as Error).message} (the refusal stands; its note is lost)`);
    } finally {
      clearTimeout(timer);
    }
  }

  /** A 403 written on a raw CONNECT socket, then the socket closed. */
  private refuseConnect(clientSocket: Duplex, message: string): void {
    try {
      clientSocket.write(
        "HTTP/1.1 403 Forbidden\r\n" +
          "Content-Type: application/json\r\n" +
          "Connection: close\r\n\r\n" +
          JSON.stringify({ error: { type: "mandu_fail_closed", message } }),
      );
    } catch {
      /* client already gone */
    }
    clientSocket.destroy();
  }

  // ── forward HTTP (plaintext) ────────────────────────────────────────────────

  private async onRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const rawUrl = req.url ?? "/";

    // Local admin: the launcher's start-or-reuse identity probe. Answered here
    // (never forwarded) so a listening net-proxy can be checked as THIS
    // session's before it is adopted. ORIGIN-FORM only (`GET /_mandu/identity`,
    // as probeIdentity sends it) — a proxied ABSOLUTE-form URL that happens to
    // end in this path is normal egress and falls through to the gate. Checked
    // BEFORE destination parsing: the probe's Host header is our own address,
    // which the self-loop guard below would otherwise refuse with a 508.
    if (method === "GET" && (rawUrl.split("?")[0] ?? "") === IDENTITY_PATH) {
      this.serveIdentity(res);
      return;
    }

    // Symbol-as-destination over plain HTTP (plan 10 §11.8, "A placeholder
    // as the destination", 2026-10-17): a $MDU placeholder in the host part
    // of the request line or in the Host header is refused, as the CONNECT
    // leg refuses it, and noted. Before parsing: such a host is no valid URL
    // host, and the parse failure's 400 used to answer it with no note.
    const authority = destinationAuthority(rawUrl, req.headers.host);
    if (findSymbols(authority).length > 0) {
      this.safeEmit("blocked", { method, destination: authority, reason: SYMBOL_DESTINATION_REASON });
      this.log(`BLOCK ${method}: symbol used as destination`);
      await this.noteRefusal(this.resolveHolders(req.socket), "symbol-destination");
      this.refuse(res, 403, SYMBOL_DESTINATION_REASON);
      return;
    }

    // Parse the destination. A forward proxy receives an absolute-form request
    // line (`http://host/path`); fall back to the Host header otherwise.
    const dest = parseForwardTarget(rawUrl, req.headers.host);
    if (!dest) {
      this.refuse(res, 400, `cannot determine destination from request line: ${rawUrl}`);
      return;
    }
    // The deny sentinel over plain HTTP: same final answer (see onConnect).
    if (isDenySentinel(dest.host)) {
      const why = denySentinelReason(dest.host);
      this.safeEmit("blocked", { method, destination: dest.host, reason: why });
      this.refuse(res, 403, why);
      return;
    }

    // SELF-LOOP GUARD: a request whose destination IS this proxy's own listen
    // address must NEVER be forwarded — forwarding re-enters this same listener
    // (the upstream request is origin-form with Host = our address, which
    // parseForwardTarget resolves back to us), recursing without bound until
    // ephemeral ports exhaust. A single such request once produced 35,723
    // net_action events in ~21s. Refuse with 508 Loop Detected, off the gate.
    if (isSelfDestination(dest.host, this.listenHost, this.listenPort)) {
      this.safeEmit("loop_detected", {
        method,
        destination: dest.host,
        reason: "destination is the proxy's own address → refusing to forward (loop)",
      });
      this.log(`LOOP ${method} ${dest.host}: destination is the proxy itself — refused (508)`);
      this.refuse(res, 508, `destination ${dest.host} is the egress proxy itself → refusing to forward (loop)`);
      return;
    }

    // ALWAYS-DENIED destinations (cloud metadata, link-local) and THIS
    // MACHINE (loopback, the unspecified address, `localhost`, this machine's
    // own interface addresses, an address its routing tables deliver to
    // itself), in every mode: this proxy dials from outside
    // the connect guard, so it must refuse them itself. The host as written
    // here; the host actually dialed is checked again at the dial, a name on
    // the address it resolves to (blocked-destinations.ts).
    const blocked = this.blockedTarget(dest.absoluteUrl, dest.host);
    if (blocked) {
      this.safeEmit("blocked", { method, destination: dest.host, reason: blocked.message });
      this.log(`BLOCK ${method} ${dest.host}: ${blocked.reason}`);
      await this.noteRefusal(this.resolveHolders(req.socket), blocked.refusalKind);
      this.refuse(res, 403, blocked.message);
      return;
    }

    // The agent's UPLOAD HOSTS (deny-hosts.ts; supported-agents.md §5.3.4
    // rule 1): refused before any gate or dial, in every mode, model hosts
    // included. The reason names the host, never the request.
    const denied = this.deniedTarget(dest.absoluteUrl);
    if (denied) {
      this.safeEmit("blocked", { method, destination: dest.host, reason: denied });
      this.log(`BLOCK ${method} ${dest.host}: upload host denied`);
      await this.noteRefusal(this.resolveHolders(req.socket), "blocked-destination");
      this.refuse(res, 403, denied);
      return;
    }

    // THE MODEL-HOST DENY (model-host-paths.ts): a model vendor's host takes
    // only the paths on its list; an allowed one then runs the gate below
    // like any other request. The target as the client sent it, never the
    // parsed URL (which would resolve a dot segment or an escape first).
    const modelPath = this.modelPathOf(dest.host, method, rawUrl);
    if (modelPath && !modelPath.allowed) {
      this.safeEmit("blocked", { method, destination: dest.host, reason: modelPath.reason, modelHost: true });
      this.log(`BLOCK ${dest.host}: model host path refused: ${modelPath.reason}`);
      await this.noteRefusal(this.resolveHolders(req.socket), "blocked-destination");
      this.refuse(res, 403, modelPath.reason);
      return;
    }
    if (modelPath) this.log(`model host ${dest.host}: ${method} ${modelPath.path} allowed (${modelPath.pattern})`);

    // EXCLUSION: model-API hosts are owned by the anthropic-proxy/openai-proxy. We
    // pass them through verbatim — no gate, no symbolization. Under the
    // model-host deny an allowed path is gated instead (above).
    if (!modelPath && isModelHost(dest.host, this.modelHosts)) {
      await this.passthrough(method, dest, req, res);
      return;
    }

    const body = await this.readBody(req, res);
    if (body == null) return; // readBody already responded (e.g. 413)

    // Resolve the sending processes: every holder of the client's socket (plan
    // 13 D6), judged by the secret-taint leg; `[]` = unattributed, refused
    // while the session holds a secret. The first holder's key also lights
    // the (frozen) integrity branch in gateRequest and the observe-and-tag in
    // observeResponse, exactly as before (Plan 6.5, Plan 7).
    const holders = this.resolveHolders(req.socket);
    const procKey = holders[0]?.procKey;

    // The destination every release and binding decision is asked for: the
    // host and the port this request goes to, the scheme's default when the
    // URL names none (destination.ts; plan 10 §11.13.1, 2026-10-17).
    const decideAt = forwardDestination(dest);

    // ── EGRESS gate (security-critical, fail-closed). ──
    const gate = await gateRequest({
      method,
      destinationHost: decideAt,
      url: dest.absoluteUrl,
      headers: req.headers,
      bodyText: body.toString("utf8"),
      arbiter: this.arbiter,
      procKey, // the integrity leg (frozen); undefined → that branch skipped
      holders, // the secret-taint leg (plan 13 D6)
      // Attribution-only: the same session the net_action events are filed
      // under, so an approval-queue row joins to this session's trace.
      sessionKey: this.sessionId,
      // The plain leg: the request reached us in clear text, so it is
      // `http` even for an absolute-form `https://` URL. A wire-twin
      // credential declared for https is not put back here (plan 10
      // §11.13.1, 2026-10-03).
      scheme: "http",
      modelService: isModelService(decideAt, this.modelServices),
    }, this.egressHoldMs > 0 ? {
      // Confidentiality.md §4, "A held request": wait for the human's
      // answer to the card; a client gone meanwhile is sent nothing.
      ms: this.egressHoldMs,
      aborted: () => req.socket.destroyed || res.destroyed,
      log: this.log,
    } : undefined);

    if (gate.action === "block") {
      this.safeEmit("blocked", {
        method,
        destination: dest.host,
        reason: gate.reason,
        withheld: gate.withheld.map((w) => w.symbol),
        // WHICH rule withheld it (egress.ts withheldPolicy): the trace can then
        // tell a one-time approval at a BOUND host from an unbound host.
        ...(withheldPolicy(gate.withheld) ? { policy: withheldPolicy(gate.withheld) } : {}),
        ...(gate.held ? { heldMs: gate.held.ms } : {}),
        // The cards it waited on and the rule that filed each: the answer's
        // decision names only the verdict (egress-hold.md, "The trace").
        ...(heldForEvent(gate.held) ? { heldFor: heldForEvent(gate.held) } : {}),
      });
      this.log(`BLOCK ${method} ${dest.host}: ${gate.reason}`);
      await this.noteRefusal(holders, refusalKindOf(gate.reason));
      this.refuse(res, 403, gate.reason, { withheld: agentWithheld(gate.withheld) });
      return;
    }

    // ── §4 verbatim-leak TRIPWIRE (defense-in-depth, NOT the guarantee). ──
    // Scan the ORIGINAL agent-sent surfaces — a symbol there is still an opaque
    // token, so this cannot false-positive on a legitimately-resolved secret
    // (resolution happens below). It catches only a RAW secret value the per-
    // symbol gate never saw (a never-symbolized/mislabeled secret, a verbatim
    // copy). Fail-OPEN on error: the per-symbol gate above is the guarantee and
    // already failed closed; this only ever ADDS a block on a positive hit.
    // "Send without it" (confidentiality.md §4): the scan runs over the
    // request with the markers in, STRICT (it must run and find nothing).
    const trip = gate.sentWithoutView
      ? await this.fingerprintTripwire(gate.sentWithoutView, decideAt, { strict: true })
      : await this.fingerprintTripwire(
          { url: dest.absoluteUrl, headers: req.headers, bodyText: body.toString("utf8") },
          decideAt,
        );
    if (trip) {
      this.safeEmit("blocked", {
        method,
        destination: dest.host,
        reason: trip.reason,
        withheld: trip.symbols,
        fingerprintTripwire: true,
      });
      this.log(`BLOCK ${method} ${dest.host}: ${trip.reason}`);
      await this.noteRefusal(holders, "fingerprint");
      this.refuse(res, 403, trip.reason, { withheld: trip.symbols.map((symbol) => ({ symbol, requiresApproval: false, reason: trip.reason })) });
      return;
    }

    // Forward the (possibly rewritten) request to the real destination.
    const fwdUrl = gate.rewritten?.url ?? dest.absoluteUrl;
    const fwdHeaders = sanitizeForwardHeaders(gate.rewritten?.headers ?? req.headers);
    const fwdBody = gate.rewritten ? Buffer.from(gate.rewritten.bodyText, "utf8") : body;
    // The model-host deny judges the URL that is SENT: a value the gate put
    // back into it could make its path another one (fail-closed).
    if (modelPath && gate.rewritten && gate.rewritten.url !== dest.absoluteUrl) {
      const again = this.modelPathOf(dest.host, method, fwdUrl);
      if (!again || !again.allowed) {
        const reason = again && !again.allowed ? again.reason : `model host ${dest.host}: the URL changed and could not be judged again (fail-closed)`;
        this.safeEmit("blocked", { method, destination: dest.host, reason, modelHost: true });
        this.log(`BLOCK ${dest.host}: model host path refused after the release: ${reason}`);
        await this.noteRefusal(holders, "blocked-destination");
        this.refuse(res, 403, reason);
        return;
      }
    }

    // OFFLINE WEB MOCK: if a mock site is configured for this URL, serve its canned
    // response AS the upstream — no real network — and let the SAME ingress
    // symbolization below run over it (so the defense is exercised on mock content
    // exactly as on real content). Lets a REAL agent run a deterministic loop.
    const mock = this.mockSites?.match(fwdUrl);
    // A mock-sites HOST ROUTE (test infrastructure, mock-sites.ts): the
    // request the gate let out goes to a loopback test listener instead of
    // the internet. The gate above is unchanged; only the dial differs.
    // A model host (gated here only under the model-host deny) is routed
    // only by a route naming it, never by the `*` catch-all.
    const route = mock
      ? undefined
      : (isModelHost(dest.host, this.modelHosts) ? this.mockSites?.routeOf(dest.host) : this.mockSites?.route(dest.host))?.http;
    let upstream: ForwardedResponse;
    if (mock) {
      upstream = mock;
    } else {
      try {
        upstream = await this.forward({ method, url: fwdUrl, headers: fwdHeaders, body: fwdBody, ...(route ? { dial: route } : {}) });
      } catch (err) {
        if (isBlockedDestinationError(err)) {
          // Refused at the dial: a name that resolved to a refused address,
          // or a host the gate's rewrite produced.
          this.safeEmit("blocked", { method, destination: dest.host, reason: err.message });
          this.log(`BLOCK ${method} ${dest.host}: ${err.reason} (at the dial)`);
          await this.noteRefusal(holders, err.refusalKind);
          this.refuse(res, 403, err.message);
          return;
        }
        // Forward failed → fail-closed (never leave the client hanging with raw
        // symbol data half-sent; nothing untrusted reached the agent yet).
        this.log(`forward error: ${(err as Error).message}`);
        this.safeEmit("forward_error", { method, destination: dest.host, reason: (err as Error).message });
        this.refuse(res, 502, `forward to destination failed: ${(err as Error).message}`);
        return;
      }
    }

    // ── INGRESS observe-and-tag of the plaintext response body (Plan 7). ──
    // Post-Plan-7: the body is returned RAW for untrusted origins (no longer symbolized
    // at the net layer). `observeResponse` still classifies + best-effort taints the
    // connecting process. The T-LLM invariant rests solely on the model-API proxy.
    let outBody = upstream.body;
    let symbolized = false; // repurposed: now means "untrusted-by-origin (tagged)", NOT body-symbolized
    if (isTextResponse(upstream.headers)) {
      // procKey resolved by Plan 6.5; undefined → no-op (fail-soft)
      const r = await observeResponse(upstream.body, { arbiter: this.arbiter, origin: dest.host, procKey });
      outBody = r.body; // RAW for untrusted (was the symbol pre-Plan-7)
      // `symbolized` is repurposed to mean "untrusted-by-origin (tagged, not body-symbolized)"
      // for backward-compat with the dashboard's `responseSymbolized` field. See Task 2 Step 5.
      symbolized = r.meta.trust === "UNTRUSTED";
    }

    this.safeEmit("forwarded", {
      method,
      destination: dest.host,
      status: upstream.status,
      resolved: gate.resolved ?? [],
      // "Send without it": the symbols sent as the marker (names only).
      ...(gate.sentWithout?.length ? { sentWithout: gate.sentWithout } : {}),
      // A model service (egress.ts modelService): placeholders sent as they are.
      ...(gate.keptOpaque?.length ? { keptOpaque: gate.keptOpaque } : {}),
      // A held request (confidentiality.md §4): how long it waited.
      ...(gate.held ? { heldMs: gate.held.ms } : {}),
      ...(heldForEvent(gate.held) ? { heldFor: heldForEvent(gate.held) } : {}),
      // `responseSymbolized` is now "untrusted-by-origin (observe-and-tag)" NOT "body was symbolized"
      // (Plan 7 minimal rename: keep the field name for dashboard backward-compat; see Step 5).
      responseSymbolized: symbolized,
      ...(mock ? { mock: true } : {}),
      ...(route ? { mockRoute: `${route.host}:${route.port}` } : {}),
    });

    const outHeaders = responseHeaders(upstream.headers, outBody.length);
    res.writeHead(upstream.status, outHeaders);
    res.end(outBody);
  }

  /** Pass a model-API host request through verbatim (no gate, no symbolization). */
  private async passthrough(
    method: string,
    dest: ForwardTarget,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const body = await this.readBody(req, res);
    if (body == null) return;
    // A model host is excluded from the symbol gate (its proxy owns it), not
    // from the network exit of a process holding a secret (plan 13 D6): the
    // agent never holds one (it reads twins), so its own traffic is untouched.
    const passHolders = this.resolveHolders(req.socket);
    const taint = await this.taintVerdict(passHolders, forwardDestination(dest));
    if (taint.action === "block") {
      this.safeEmit("blocked", { method, destination: dest.host, reason: taint.reason, withheld: taint.withheld.map((w) => w.symbol) });
      this.log(`BLOCK ${method} ${dest.host}: ${taint.reason}`);
      await this.noteRefusal(passHolders, refusalKindOf(taint.reason));
      this.refuse(res, 403, taint.reason, { withheld: agentWithheld(taint.withheld) });
      return;
    }
    this.safeEmit("passthrough", { method, destination: dest.host, note: "model-API host excluded" });
    let upstream: ForwardedResponse;
    try {
      upstream = await this.forward({
        method,
        url: dest.absoluteUrl,
        headers: sanitizeForwardHeaders(req.headers),
        body,
      });
    } catch (err) {
      if (isBlockedDestinationError(err)) {
        this.safeEmit("blocked", { method, destination: dest.host, reason: err.message });
        this.log(`BLOCK ${method} ${dest.host}: ${err.reason} (at the dial)`);
        await this.noteRefusal(passHolders, err.refusalKind);
        this.refuse(res, 403, err.message);
        return;
      }
      this.refuse(res, 502, `passthrough forward failed: ${(err as Error).message}`);
      return;
    }
    res.writeHead(upstream.status, responseHeaders(upstream.headers, upstream.body.length));
    res.end(upstream.body);
  }

  // ── CONNECT (HTTPS) tunnel ──────────────────────────────────────────────────

  private onConnect(req: IncomingMessage, clientSocket: Duplex, head: Buffer): void {
    const target = req.url ?? "";
    const { host, port } = parseConnectTarget(target);

    // The Mandu DENY SENTINEL (anthropic-proxy net-gate.ts DENIED_HOST): a
    // URL the model-context gate already refused was rewritten to this host,
    // so the decision is made — answer 403 NOW. Dialing a `.invalid` name
    // fails DNS and used to surface as a 502, which clients treat as
    // TRANSIENT: Claude Code's WebFetch retried a HIGH-session denial for two
    // minutes before reporting it (watch C7, 2026-09-19), blowing the turn.
    if (isDenySentinel(host)) {
      // The asked sentinel (a refusal that filed an Approvals row) invites a
      // retry after the user's answer; every other one is final.
      const why = denySentinelReason(host);
      this.safeEmit("blocked", { method: "CONNECT", destination: host, reason: why });
      clientSocket.write(
        "HTTP/1.1 403 Forbidden\r\n" +
          "Content-Type: application/json\r\n" +
          "Connection: close\r\n\r\n" +
          JSON.stringify({ error: { type: "mandu_denied", message: why } }),
      );
      clientSocket.destroy();
      return;
    }

    // ALWAYS-DENIED destinations (cloud metadata, link-local) and THIS
    // MACHINE: refused before any tunnel or MITM, in every mode. The host as
    // written; the host dialed is checked again at the dial (a name on the
    // address it resolves to). A mock-sites host route dials its own
    // loopback listener instead, so a routed host skips the this-machine
    // check (mock-sites.ts).
    const blocked = this.refusedHost(host, port);
    if (blocked) {
      this.safeEmit("blocked", { method: "CONNECT", destination: `${host}:${port}`, reason: blocked.message });
      this.log(`BLOCK CONNECT ${host}:${port}: ${blocked.reason}`);
      const answer = (): void => this.refuseConnect(clientSocket, blocked.message);
      clientSocket.on("error", () => clientSocket.destroy());
      void this.noteRefusal(this.resolveHolders(req.socket), blocked.refusalKind).then(answer, answer);
      return;
    }

    // The agent's UPLOAD HOSTS (deny-hosts.ts): refused before any tunnel or
    // MITM, in every mode. The refusal is noted for the connecting process
    // (bounded), then answered.
    if (deniedHost(host, port, this.denyHosts)) {
      const message = denyHostReason(host);
      this.safeEmit("blocked", { method: "CONNECT", destination: `${host}:${port}`, reason: message });
      this.log(`BLOCK CONNECT ${host}:${port}: upload host denied`);
      const answer = (): void => {
        clientSocket.write(
          "HTTP/1.1 403 Forbidden\r\n" +
            "Content-Type: application/json\r\n" +
            "Connection: close\r\n\r\n" +
            JSON.stringify({ error: { type: "mandu_fail_closed", message } }),
        );
        clientSocket.destroy();
      };
      void this.noteRefusal(this.resolveHolders(req.socket), "blocked-destination").then(answer, answer);
      return;
    }

    // Symbol-as-destination: a symbol in the host string is an attempt to
    // exfiltrate by using the secret AS the destination. Block.
    // Noted like every other refusal (plan 10 §11.8, "A placeholder as the
    // destination", 2026-10-17): its own kind, never the host or the symbol.
    if (findSymbols(target).length > 0) {
      this.safeEmit("blocked", { method: "CONNECT", destination: host, reason: SYMBOL_DESTINATION_REASON });
      this.log(`BLOCK CONNECT ${target}: symbol used as destination`);
      const answer = (): void => {
        clientSocket.write(
          "HTTP/1.1 403 Forbidden\r\n" +
            "Content-Type: application/json\r\n" +
            "Connection: close\r\n\r\n" +
            JSON.stringify({ error: { type: "mandu_fail_closed", message: SYMBOL_DESTINATION_REASON } }),
        );
        clientSocket.destroy();
      };
      clientSocket.on("error", () => clientSocket.destroy());
      void this.noteRefusal(this.resolveHolders(req.socket), "symbol-destination").then(answer, answer);
      return;
    }

    const model = isModelHost(host, this.modelHosts);
    // THE MODEL-HOST DENY (model-host-paths.ts): a vendor's model host is
    // judged per request on the TLS-inspected leg; without TLS inspection
    // no path can be read, so the host is refused whole (fail-closed).
    const modelDeny = this.modelHostDeny && modelHostRule(host) !== null;
    if (modelDeny && !this.mitm) {
      const message = modelHostTunnelReason(host);
      this.safeEmit("blocked", { method: "CONNECT", destination: `${host}:${port}`, reason: message, modelHost: true });
      this.log(`BLOCK CONNECT ${host}:${port}: model host, TLS inspection off`);
      const answer = (): void => this.refuseConnect(clientSocket, message);
      clientSocket.on("error", () => clientSocket.destroy());
      void this.noteRefusal(this.resolveHolders(req.socket), "blocked-destination").then(answer, answer);
      return;
    }

    // Plan 13 D6: the sending process, resolved on this leg too. The client
    // is connected and waiting for our answer, so its socket is in /proc now.
    // A blocking /proc scan, like the plain leg's.
    const sock = req.socket;
    const holders = this.resolveHolders(sock);

    // OPT-IN MITM: if enabled AND this is NOT a model host, terminate TLS so the
    // egress gate can inspect the decrypted request body (the new capability a
    // blind tunnel cannot provide). A model-API host (owned by the anthropic-proxy /
    // openai-proxy) falls through to the blind tunnel, except under the model-host
    // deny, where it is terminated too and each request judged by its path.
    // FAIL-CLOSED: a MITM setup error closes the connection (handled in mitm.ts).
    // Every decrypted request is judged against the taint of the holders
    // found here AND of those holding the socket at that request (a child
    // forked after the CONNECT, or a holder tainted since, is judged).
    //
    // A tunnel may carry PLAIN HTTP instead of TLS: a client that tunnels an
    // http:// URL (OpenClaw's guarded fetch through an env proxy sends
    // `CONNECT host:80`, measured on 2026.7.1-2 and 2026.9.9). TLS termination
    // would fail on it, so the first byte decides (a TLS record starts with
    // 0x16, a handshake): plain HTTP is served by this proxy's own plaintext
    // leg (`servePlainTunnel`), request by request, under the same gate.
    if (this.mitm && (!model || modelDeny)) {
      const mitm = this.mitm;
      const attribution = { holders, current: () => this.resolveHolders(sock) };
      this.sniffTunnel(clientSocket, head, (first, stream, rest) => {
        if (first === TLS_HANDSHAKE_RECORD) mitm.handleConnect(host, port, stream, rest, attribution, { established: true });
        else this.servePlainTunnel(rest.length > 0 ? prependChunk(stream, rest) : stream, `${host}:${port}`);
      });
      return;
    }

    // Default (MITM off) OR a model host: plain TCP tunnel. For a model host this
    // is the intended passthrough. For a non-model host the encrypted body is NOT
    // inspectable without MITM — DOCUMENTED LIMITATION: the symbol-in-body gate
    // cannot apply to HTTPS. We still tunnel (so the agent works) but emit a
    // `tunneled` event noting the body is opaque to the gate.
    // A mock-sites host route (test infrastructure) points the tunnel at a
    // loopback test listener. Under MITM (the branch above) the route is the
    // re-origination's dial instead, after the body gate. A model host is
    // never routed.
    const route = model ? undefined : this.mockSites?.route(host)?.tls;
    void this.blindConnect(host, port, clientSocket, head, model, holders, sock, route);
  }

  /**
   * Answer the CONNECT, then wait for the client's first byte. `decide` gets
   * it and the stream to read the tunnel from: a byte read off the socket
   * cannot be put back where a native TLS or HTTP parser reads it, so a chunk
   * read here rides in front of the socket in a wrapper (`prependChunk`).
   * `rest`: bytes that came with the CONNECT line (the TLS leg puts them in
   * itself, as before). A client that closes first is just closed; nothing
   * is dialed.
   */
  private sniffTunnel(clientSocket: Duplex, head: Buffer, decide: (first: number, stream: Duplex, rest: Buffer) => void): void {
    const onError = (): void => { clientSocket.destroy(); };
    clientSocket.on("error", onError);
    try {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    } catch {
      clientSocket.destroy();
      return;
    }
    if (head && head.length > 0) {
      clientSocket.off("error", onError);
      decide(head[0]!, clientSocket, head);
      return;
    }
    const onData = (chunk: Buffer): void => {
      clientSocket.off("data", onData);
      clientSocket.off("end", onEnd);
      clientSocket.off("error", onError);
      clientSocket.pause();
      decide(chunk[0]!, prependChunk(clientSocket, chunk), Buffer.alloc(0));
    };
    const onEnd = (): void => { clientSocket.off("data", onData); clientSocket.destroy(); };
    clientSocket.on("data", onData);
    clientSocket.once("end", onEnd);
  }

  /**
   * Serve a CONNECT tunnel that carries plain HTTP with this proxy's own
   * plaintext leg: the stream is handed to the HTTP server as a new
   * connection. Each request arrives in origin form with its Host header,
   * which `onRequest` resolves (parseForwardTarget) and judges like any
   * proxied plain-HTTP request: the deny sentinel, the always-denied hosts,
   * the per-symbol gate, the verbatim tripwire, the sender's taint (the
   * wrapper answers the socket's addresses, so the sender is found as on any
   * request). The Host header, not the CONNECT line, is where the request is
   * forwarded, so it is what the gate judges.
   */
  private servePlainTunnel(stream: Duplex, target: string): void {
    const server = this.server;
    if (!server) { stream.destroy(); return; }
    this.safeEmit("tunnel_plain_http", { method: "CONNECT", destination: target, reason: "the tunnel carries plain HTTP: each request goes through the plaintext leg's gate" });
    server.emit("connection", stream);
  }

  /**
   * A tunnel the proxy cannot read (MITM off, or a model host). Plan 13 D6:
   * the proxy cannot see what a process holding a secret sends in it, so
   * such a CONNECT is refused unless the destination is bound for every
   * secret the holders hold (the answer the guard gives the same process's
   * direct connect: content-agnostic, so readable or not makes no
   * difference). An unattributed CONNECT is refused while the session holds
   * a secret. Once open, every chunk the client sends is held until the
   * holders are judged again: those of the CONNECT, and any process holding
   * the socket now that holds a secret (`chunkHolders`), so neither a holder
   * that reads a secret after the CONNECT nor a child forked after it that
   * does sends anything more to an unbound host.
   */
  private async blindConnect(
    host: string,
    port: number,
    clientSocket: Duplex,
    head: Buffer,
    model: boolean,
    holders: ProcHolder[],
    sock: { remoteAddress?: string; localAddress?: string; remotePort?: number; localPort?: number },
    route?: { host: string; port: number },
  ): Promise<void> {
    // The client may reset while the verdict is pending: never an unhandled
    // 'error' (establishTunnel adds its own cleanup once the tunnel exists).
    clientSocket.on("error", () => clientSocket.destroy());
    // Plan 13 §5.4: the file sets a human's answer let through at the
    // CONNECT, so the tunnel's chunks are not asked again for them.
    const granted = new Set<string>();
    let v: SecretTaintVerdict;
    try {
      v = await this.taintVerdict(holders, statedDestination(host, port), granted);
    } catch (err) {
      v = { action: "block", reason: `taint check failed: ${(err as Error).message} → block (fail-closed)`, withheld: [] };
    }
    if (v.action === "block") {
      this.safeEmit("blocked", {
        method: "CONNECT",
        destination: `${host}:${port}`,
        reason: v.reason,
        withheld: v.withheld.map((w) => w.symbol),
        note: "a tunnel the proxy cannot read, for a process holding a secret (plan 13 D6)",
      });
      this.log(`BLOCK CONNECT ${host}:${port}: ${v.reason}`);
      await this.noteRefusal(holders, refusalKindOf(v.reason));
      this.refuseConnect(clientSocket, v.reason);
      return;
    }
    if (clientSocket.destroyed) return;
    // Before each chunk: the CONNECT's holders (tainted since?) and every
    // process holding the socket now that holds a secret (a child forked
    // after the CONNECT that read one: the P0 triage's 2a), as the MITM leg
    // judges each request. A holder's chain is sent the first time it is
    // asked about (its lineage edges are recorded then); later asks go
    // without it (no write per chunk).
    const keys: ProcHolder[] = holders.map((h) => ({ procKey: h.procKey, ancestors: [] }));
    const chained = new Set(holders.map((h) => h.procKey));
    const narrow = this.taintedHoldersFor();
    const recheck = async (): Promise<SecretTaintVerdict> => {
      const ask = [...keys];
      for (const h of await this.chunkHolders(sock, narrow)) {
        if (ask.some((a) => a.procKey === h.procKey)) continue;
        ask.push(chained.has(h.procKey) ? { procKey: h.procKey, ancestors: [] } : h);
        chained.add(h.procKey);
      }
      return this.taintVerdict(ask, statedDestination(host, port), granted);
    };
    this.establishTunnel(host, port, clientSocket, head, model, holders, route, recheck);
  }

  private establishTunnel(
    host: string,
    port: number,
    clientSocket: Duplex,
    head: Buffer,
    model: boolean,
    holders: readonly ProcHolder[],
    route?: { host: string; port: number },
    recheck?: () => Promise<SecretTaintVerdict>,
  ): void {
    // Dial only an address that passed the always-denied and this-machine
    // checks: a literal here, a name in the lookup on the address it resolves
    // to. A mock-sites route's own loopback dial skips the this-machine check.
    const dialHost = route?.host ?? host;
    const dialPort = route?.port ?? port;
    let dialOpts: ReturnType<typeof guardDial>;
    try {
      dialOpts = guardDial(dialHost, dialPort, route ? { ...this.dialPolicy, allowThisMachine: true } : this.dialPolicy);
    } catch (err) {
      const message = (err as Error).message;
      this.safeEmit("blocked", { method: "CONNECT", destination: `${host}:${port}`, reason: message });
      this.log(`BLOCK CONNECT ${host}:${port}: ${message}`);
      const answer = (): void => this.refuseConnect(clientSocket, message);
      if (isBlockedDestinationError(err)) void this.noteRefusal(holders, err.refusalKind).then(answer, answer);
      else answer();
      return;
    }
    // Nagle off on the relay's far side too (the client side is the
    // server's, `noDelay` in listen): a relay forwards each chunk as it
    // comes, and a small one must not wait on the previous one's ACK
    // (plan 13 D6, "The kept-alive floor").
    const upstream = netConnect({ port: dialPort, host: dialHostOf(dialHost), ...dialOpts }, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      // `head` was sent before the CONNECT was answered: judged by the
      // verdict that opened the tunnel.
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      if (!recheck) {
        clientSocket.pipe(upstream);
        return;
      }
      // Each chunk waits for a fresh verdict (plan 13 D6): a holder tainted
      // since the CONNECT, at a destination its secrets are not bound to,
      // closes the tunnel before the chunk is written.
      clientSocket.on("data", (chunk: Buffer) => {
        clientSocket.pause();
        recheck().then(
          (v) => {
            if (v.action === "block") {
              this.safeEmit("blocked", {
                method: "CONNECT",
                destination: `${host}:${port}`,
                reason: v.reason,
                withheld: v.withheld.map((w) => w.symbol),
                note: "tunnel closed: a holder now holds a secret not bound here (plan 13 D6)",
              });
              this.log(`BLOCK tunnel ${host}:${port}: ${v.reason}`);
              cleanup();
              return;
            }
            if (upstream.destroyed) return;
            if (upstream.write(chunk)) clientSocket.resume();
            else upstream.once("drain", () => clientSocket.resume());
          },
          () => cleanup(),
        );
      });
      clientSocket.on("end", () => upstream.end());
    });

    upstream.setNoDelay(true); // applied at the connect
    this.tunnels.add(upstream);
    this.tunnels.add(clientSocket);

    this.safeEmit(model ? "passthrough" : "tunneled", {
      method: "CONNECT",
      destination: `${host}:${port}`,
      note: model
        ? "model-API host excluded (tunnel)"
        : "HTTPS body OPAQUE to the gate (no MITM) — symbol-in-body gate cannot apply (documented limitation)",
      ...(route ? { mockRoute: `${route.host}:${route.port}` } : {}),
    });

    // Set while a refusal is being noted: the upstream's close must not tear
    // the client down before its 403 is written.
    let refusing = false;
    const cleanup = (): void => {
      this.tunnels.delete(upstream);
      upstream.destroy();
      if (refusing) return;
      this.tunnels.delete(clientSocket);
      clientSocket.destroy();
    };
    upstream.on("error", (err) => {
      this.log(`tunnel upstream error (${host}:${port}): ${err.message}`);
      if (isBlockedDestinationError(err)) {
        // Refused in the lookup: a name that resolved to a refused address.
        // Noted (bounded) before the 403, like every refusal.
        this.safeEmit("blocked", { method: "CONNECT", destination: `${host}:${port}`, reason: err.message });
        refusing = true;
        cleanup();
        const answer = (): void => {
          this.tunnels.delete(clientSocket);
          if (!clientSocket.destroyed) this.refuseConnect(clientSocket, err.message);
        };
        void this.noteRefusal(holders, err.refusalKind).then(answer, answer);
        return;
      }
      if (!clientSocket.destroyed) {
        try {
          clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        } catch {
          /* client already gone */
        }
      }
      cleanup();
    });
    clientSocket.on("error", cleanup);
    upstream.on("close", cleanup);
    clientSocket.on("close", cleanup);
  }

  // ── helpers ─────────────────────────────────────────────────────────────────

  /** Read the full request body, enforcing the max-size cap. */
  private readBody(req: IncomingMessage, res: ServerResponse): Promise<Buffer | null> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let aborted = false;
      req.on("data", (c: Buffer) => {
        if (aborted) return;
        size += c.length;
        if (size > this.maxBodyBytes) {
          aborted = true;
          this.refuse(res, 413, `request body exceeds ${this.maxBodyBytes} bytes`);
          resolve(null);
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => {
        if (!aborted) resolve(Buffer.concat(chunks));
      });
      req.on("error", () => {
        if (!aborted) {
          aborted = true;
          this.refuse(res, 400, "error reading request body");
          resolve(null);
        }
      });
    });
  }

  /** The model-host deny's decision for one request (model-host-paths.ts),
   *  or null when the deny is off or `host` is no model vendor's host. */
  private modelPathOf(host: string, method: string, target: string): ModelPathDecision | null {
    if (!this.modelHostDeny) return null;
    const rule = modelHostRule(host);
    return rule ? modelPathDecision(rule, method, target) : null;
  }

  /** The refusal when an absolute URL targets an always-denied destination
   *  or this machine as written (a literal IP, a metadata or `localhost`
   *  name), else null. The WHATWG parser has already normalized
   *  `http://2852039166/`, `http://0x7f.1/` and friends to dotted form. A
   *  name that resolves there is caught by the dial's lookup. A URL a mock
   *  site serves, or a host a mock-sites route sends to its own loopback
   *  listener, is not dialed as written, so it skips the this-machine check
   *  (the forwarder still checks whatever it does dial). */
  private blockedTarget(absoluteUrl: string, routedHost: string): BlockedDestinationError | null {
    let u: URL;
    try {
      u = new URL(absoluteUrl);
    } catch {
      return null; // unparseable → the forwarder fails it
    }
    const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
    const mocked = this.mockSites !== undefined && !isModelHost(routedHost, this.modelHosts) &&
      (this.mockSites.has(absoluteUrl) || this.mockSites.route(routedHost)?.http !== undefined);
    const r = dialRefusal(u.hostname, port, mocked ? { ...this.dialPolicy, allowThisMachine: true } : this.dialPolicy);
    return r ? BlockedDestinationError.of(u.hostname, r) : null;
  }

  /** The refusal of a CONNECT target as written (see blockedTarget), else
   *  null. A host a mock-sites route tunnels to its own loopback listener
   *  skips the this-machine check. Not a model host: a model host is never
   *  routed. */
  private refusedHost(host: string, port: number): BlockedDestinationError | null {
    const routed = !isModelHost(host, this.modelHosts) && this.mockSites?.route(host)?.tls !== undefined;
    const r = dialRefusal(host, port, routed ? { ...this.dialPolicy, allowThisMachine: true } : this.dialPolicy);
    return r ? BlockedDestinationError.of(host, r) : null;
  }

  /** The refusal message when an absolute URL's host is one of the agent's
   *  upload hosts (deny-hosts.ts), else null. */
  private deniedTarget(absoluteUrl: string): string | null {
    if (this.denyHosts.length === 0) return null;
    let u: URL;
    try {
      u = new URL(absoluteUrl);
    } catch {
      return null; // unparseable → the forwarder fails it
    }
    const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
    return deniedHost(u.hostname, port, this.denyHosts) ? denyHostReason(u.hostname) : null;
  }

  private refuse(res: ServerResponse, status: number, message: string, extra?: Record<string, unknown>): void {
    if (res.headersSent || res.writableEnded) return;
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { type: "mandu_fail_closed", message, ...extra } }));
  }

  /** Answer the launcher's start-or-reuse identity probe (mirror of the
   *  anthropic-proxy endpoint). No identity configured → `{ mandu:false }`,
   *  which a launcher refuses to adopt. */
  private serveIdentity(res: ServerResponse): void {
    const body = this.identity
      ? {
        mandu: true, ...this.identity, ...(this.denyHosts.length > 0 ? { denyHosts: denyHostsForIdentity(this.denyHosts) } : {}),
        ...(this.modelHostDeny ? { modelHostDeny: [...MODEL_HOST_NAMES] } : {}),
        ...(this.sessionLogins ? { sessionLogins: this.sessionLogins } : {}),
      }
      : { mandu: false };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  }
}

// ── pure URL/header helpers ────────────────────────────────────────────────────

interface ForwardTarget {
  host: string; // host[:port]
  absoluteUrl: string; // http://host/path
}

/**
 * Parse the forward-proxy target from the request line + Host header. A forward
 * proxy receives an absolute-form request URI (`http://host/path`). If the URL is
 * origin-form (`/path`), reconstruct it from the Host header.
 */
/** Hosts under this suffix are Mandu's own refusal sentinels (RFC 6761
 *  `.invalid` never resolves). A twin of the anthropic-proxy's DENIED_HOST
 *  (`blocked.mandu.invalid`, net-gate.ts) — the packages install
 *  independently; KEEP IN SYNC. */
export const MANDU_SENTINEL_SUFFIX = ".mandu.invalid";
/** The first byte of a TLS handshake record (a ClientHello opens every TLS
 *  stream); anything else in a CONNECT tunnel is served as plain HTTP. */
export const TLS_HANDSHAKE_RECORD = 0x16;
export const DENY_SENTINEL_REASON =
  "blocked by Mandu: this request was refused at the model-context gate — do not retry";
/** The sentinel a refusal that ASKED the user is rewritten to (the
 *  anthropic-proxy's `ASKED_HOST`, net-gate.ts; confidentiality.md §4, "How
 *  a watermark denial reaches the client"); KEEP IN SYNC. A retry after the
 *  user's answer is the intended flow, so its 403 says so instead of "do
 *  not retry". */
export const ASKED_SENTINEL_HOST = "asked.mandu.invalid";
export const ASKED_SENTINEL_REASON =
  "stopped by Mandu: the user was asked on Mandu's Approvals page (mandu dashboard) — make this request again after they answer";
/** The 403 body's reason for a sentinel host: the asked one, or final. */
export function denySentinelReason(host: string): string {
  const h = (host ?? "").toLowerCase().replace(/:\d+$/, "");
  return h === ASKED_SENTINEL_HOST ? ASKED_SENTINEL_REASON : DENY_SENTINEL_REASON;
}
export function isDenySentinel(host: string): boolean {
  const h = (host ?? "").toLowerCase().replace(/:\d+$/, "");
  return h === MANDU_SENTINEL_SUFFIX.slice(1) || h.endsWith(MANDU_SENTINEL_SUFFIX);
}

/**
 * A duplex over `sock` that first yields `first` (bytes already read off it),
 * then everything `sock` yields; writes, end and destroy go to `sock`. It
 * answers `sock`'s addresses, which the sender attribution reads.
 */
export function prependChunk(sock: Duplex, first: Buffer): Duplex {
  const out = new DuplexStream({
    read() { sock.resume(); },
    write(chunk, encoding, cb) { sock.write(chunk, encoding, cb); },
    final(cb) { sock.end(); cb(); },
    destroy(err, cb) { sock.destroy(err ?? undefined); cb(err); },
  });
  out.push(first);
  sock.on("data", (c: Buffer) => { if (!out.push(c)) sock.pause(); });
  sock.once("end", () => out.push(null));
  sock.on("error", (e) => out.destroy(e));
  sock.once("close", () => { if (!out.destroyed) out.destroy(); });
  for (const key of ["remoteAddress", "remotePort", "remoteFamily", "localAddress", "localPort"] as const) {
    Object.defineProperty(out, key, { get: () => (sock as unknown as Record<string, unknown>)[key], enumerable: true });
  }
  // the HTTP server sets timeouts and keep-alive on its connections
  (out as unknown as { setTimeout: (ms: number, cb?: () => void) => unknown }).setTimeout = (ms, cb) => {
    (sock as unknown as { setTimeout?: (ms: number, cb?: () => void) => unknown }).setTimeout?.(ms, cb);
    return out;
  };
  (out as unknown as { setNoDelay: () => unknown }).setNoDelay = () => out;
  (out as unknown as { setKeepAlive: () => unknown }).setKeepAlive = () => out;
  sock.resume();
  return out;
}

/** The 403 reason of a symbol-as-destination refusal (both legs). */
export const SYMBOL_DESTINATION_REASON = "symbol used as destination → block";

/** The destination part of a proxied request as the client wrote it: the
 *  host and port of an absolute-form request line (between `://` and the
 *  first `/`, `?` or `#`, after any `user:password@`: a placeholder there is
 *  a credential, which the gate judges, not a destination), else the Host
 *  header; "" when neither. Raw text, no URL parse (a host holding a `$MDU`
 *  placeholder is no valid URL host), for the symbol-as-destination check
 *  only. Pure. */
export function destinationAuthority(rawUrl: string, hostHeader?: string | string[]): string {
  const m = /^https?:\/\/([^/?#]*)/i.exec(rawUrl);
  if (m) {
    const authority = m[1] ?? "";
    const at = authority.lastIndexOf("@");
    return at >= 0 ? authority.slice(at + 1) : authority;
  }
  const h = Array.isArray(hostHeader) ? hostHeader.join(",") : hostHeader;
  return typeof h === "string" ? h : "";
}

export function parseForwardTarget(rawUrl: string, hostHeader?: string): ForwardTarget | null {
  if (/^https?:\/\//i.test(rawUrl)) {
    try {
      const u = new URL(rawUrl);
      return { host: u.host, absoluteUrl: u.toString() };
    } catch {
      return null;
    }
  }
  // Origin-form: need the Host header.
  if (hostHeader) {
    const host = hostHeader.trim();
    const path = rawUrl.startsWith("/") ? rawUrl : `/${rawUrl}`;
    return { host, absoluteUrl: `http://${host}${path}` };
  }
  return null;
}

/** Normalize a Node socket address: strip the IPv6-mapped-IPv4 prefix
 * (`::ffff:127.0.0.1` → `127.0.0.1`). conn-attr compares addresses by
 * `addressKey`, so either form matches a client's /proc/net/tcp row (an
 * AF_INET socket) or its v4-mapped tcp6 row (an AF_INET6 one).
 * Returns undefined for an empty/missing address. */
export function normalizeIp(addr: string | undefined): string | undefined {
  if (!addr) return undefined;
  const m = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(addr);
  return m ? m[1] : addr;
}

/** Loopback host literals that all address the local machine. A 127.x.x.x match
 *  is checked separately (the whole 127/8 block is loopback). */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "0.0.0.0", "::"]);

function isLoopbackHost(host: string): boolean {
  return LOOPBACK_HOSTS.has(host) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * True if `destHost` (host or host:port) resolves to THIS proxy's own listen
 * address — i.e. forwarding it would loop straight back into the proxy. The port
 * must match (a request to a different port can't be our listener); the hostname
 * matches either exactly or, when the proxy listens on a loopback / all-interfaces
 * address, via any loopback alias (127.0.0.1 / localhost / ::1). A destination
 * with no explicit port is treated as the HTTP default (80), matching how the
 * forwarder dials (`parsed.port || 80`).
 */
export function isSelfDestination(destHost: string, listenHost: string, listenPort: number): boolean {
  let hostname: string;
  let port: number;
  try {
    const u = new URL(`http://${destHost}`);
    hostname = u.hostname.replace(/^\[|\]$/g, ""); // unwrap an IPv6 literal's [brackets]
    port = u.port ? Number(u.port) : 80;
  } catch {
    return false; // unparseable host → let the normal path handle/refuse it
  }
  if (port !== listenPort) return false;
  const lh = listenHost.replace(/^\[|\]$/g, "");
  if (hostname === lh) return true;
  // Loopback aliases are interchangeable when we bind loopback / all interfaces.
  return isLoopbackHost(lh) && isLoopbackHost(hostname);
}

/** Parse a CONNECT target `host:port` (default port 443). An IPv6 literal
 *  (`[2001:DB8:0::1]:8443`) comes back bracketed in its canonical text
 *  (`[2001:db8::1]`), the form the gate, the leaf certificate and the dial
 *  all use (plan 10 §11.13.1, 2026-10-17); one that does not parse (a zone
 *  id included) is returned as written, which no binding admits. */
export function parseConnectTarget(target: string): { host: string; port: number } {
  const v6 = /^\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?$/.exec(target);
  if (v6 && isIP(v6[1]!) === 6) {
    try {
      return { host: new URL(`http://[${v6[1]!}]/`).hostname, port: Number(v6[2] ?? "") || 443 };
    } catch {
      /* not an address: as written below */
    }
  }
  const idx = target.lastIndexOf(":");
  if (idx === -1) return { host: target, port: 443 };
  const host = target.slice(0, idx);
  const port = Number(target.slice(idx + 1)) || 443;
  return { host, port };
}

/** Strip hop-by-hop / proxy / length headers we re-derive when forwarding. */
function sanitizeForwardHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string | string[] | undefined> {
  const out: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (
      lk === "proxy-connection" ||
      lk === "proxy-authorization" ||
      lk === "connection" ||
      lk === "transfer-encoding" ||
      lk === "content-length" ||
      lk === "accept-encoding"
    ) {
      continue;
    }
    out[k] = v;
  }
  // Force identity so the response body we symbolize is plaintext.
  out["accept-encoding"] = "identity";
  return out;
}

/** Build response headers for the client, fixing content-length + dropping
 * hop-by-hop/encoding headers (the body may have been rewritten/symbolized). */
function responseHeaders(
  headers: Record<string, string | string[] | undefined>,
  contentLength: number,
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v == null) continue;
    const lk = k.toLowerCase();
    if (lk === "connection" || lk === "transfer-encoding" || lk === "content-length" || lk === "content-encoding") {
      continue;
    }
    out[k] = v;
  }
  out["content-length"] = String(contentLength);
  return out;
}

/** The default real forwarder: a node:http request to the absolute URL. */
function makeHttpForwarder(maxBodyBytes: number, policy: DialPolicy): HttpForwarder {
  return ({ method, url, headers, body, dial }) =>
    new Promise<ForwardedResponse>((resolve, reject) => {
      let parsed: URL;
      let dialOpts: ReturnType<typeof guardDial>;
      try {
        parsed = new URL(url);
        // Dial only an address that passed the always-denied and
        // this-machine checks (blocked-destinations.ts), on the host actually
        // dialed: the gate's rewrite may have changed it, and a literal IP
        // never reaches the lookup. A mock-sites route's own loopback dial
        // skips the this-machine check.
        dialOpts = guardDial(
          dial?.host ?? parsed.hostname,
          dial?.port ?? (Number(parsed.port) || 80),
          dial ? { ...policy, allowThisMachine: true } : policy,
        );
      } catch (err) {
        reject(err as Error);
        return;
      }
      const r = httpRequest(
        {
          protocol: parsed.protocol,
          // An IPv6 literal's URL hostname keeps its brackets: dialed bare.
          hostname: dialHostOf(dial?.host ?? parsed.hostname),
          port: dial?.port ?? (parsed.port || 80),
          ...dialOpts,
          method,
          path: parsed.pathname + parsed.search,
          headers: { ...headers, host: parsed.host },
        },
        (upRes) => {
          const chunks: Buffer[] = [];
          let size = 0;
          let aborted = false;
          upRes.on("data", (c: Buffer) => {
            if (aborted) return;
            size += c.length;
            if (size > maxBodyBytes) {
              aborted = true;
              upRes.destroy();
              reject(new Error(`upstream response exceeds ${maxBodyBytes} bytes`));
              return;
            }
            chunks.push(c);
          });
          upRes.on("end", () => {
            if (!aborted) {
              resolve({
                status: upRes.statusCode ?? 502,
                headers: upRes.headers,
                body: Buffer.concat(chunks),
              });
            }
          });
          upRes.on("error", (err) => {
            if (!aborted) reject(err);
          });
        },
      );
      r.on("error", reject);
      r.end(body);
    });
}
