/**
 * mitm — the OPT-IN, default-OFF TLS-termination path for the egress proxy.
 *
 * Today an HTTPS CONNECT is blind-tunneled (proxy.ts establishTunnel): the
 * encrypted body is opaque, so a `$MDU:*` smuggled in an HTTPS BODY can't be
 * gated. This module closes that gap WHEN MITM is explicitly enabled: it
 * terminates TLS with the session-local CA (ca.ts), parses the decrypted inner
 * HTTP request, runs the SAME egress gate (egress.ts `gateRequest`) on the
 * plaintext body, and either:
 *   - block  → respond HTTP 403 (JSON reason) over the terminated TLS socket;
 *              the request is NEVER forwarded (dest receives NOTHING); or
 *   - forward → re-originate to the REAL upstream over TLS (normal system-CA
 *              verification, unless explicitly disabled for tests), read the
 *              response, run `observeResponse` on a text body (Plan 7: returns RAW
 *              body + observe-and-tag; was `symbolizeResponse`), and write it back
 *              over the terminated TLS socket.
 *
 * FAIL-CLOSED (mandu.md invariant): any MITM setup/parse error closes the
 * connection (or 502) rather than leaking. A model-API host reaches this leg only
 * under the model-host deny (proxy.ts; model-host-paths.ts), where each request
 * is first judged by its path (`modelPath`); otherwise it stays a blind tunnel.
 *
 * KEEP-ALIVE (HTTP/1.1 persistent): after serving a request on the terminated TLS
 * socket we LOOP to read the next request on the SAME connection — each request is
 * independently gated/forwarded — until the client sends `Connection: close`, an
 * idle read timeout fires, the request was malformed, or the socket ends. A gate
 * BLOCK responds 403 and CLOSES the connection (`Connection: close`): the safe,
 * spec-correct choice — once we've decided the client is exfiltrating we do not
 * keep serving it, and closing avoids any ambiguity about a half-consumed body on
 * the persistent stream. Benign requests keep the connection open for the next.
 *
 * UPSTREAM REUSE: we keep ONE pooled upstream TLS connection and reuse it while the
 * host:port is unchanged AND the upstream kept it alive (no `Connection: close`,
 * socket still writable). On any mismatch / closed upstream we dial a fresh one
 * (correctness over reuse). Each forwarded request is sent over the pooled (or
 * fresh) upstream as the client wrote it, apart from the few headers the
 * proxy owns (`reoriginationHead`: one Host, the real Content-Length,
 * identity encoding, no hop-by-hop headers).
 *
 * REQUEST BODIES: both `Content-Length` and `Transfer-Encoding: chunked` request
 * bodies are decoded to a full in-memory buffer BEFORE the gate runs, so a symbol
 * smuggled in a chunked HTTPS upload is now gated (was previously treated as an
 * empty body and bypassed). Bodies are re-originated with a computed Content-Length
 * (identity), never re-chunked.
 */

import { dialHostOf, guardDial, isBlockedDestinationError, type DialPolicy } from "./blocked-destinations.js";
import { TLSSocket, checkServerIdentity, connect as tlsConnect, createSecureContext, type SecureContext } from "node:tls";
import { isIP } from "node:net";
import type { Duplex } from "node:stream";

import type { Arbiter, ArbiterEvent, EgressRefusalKind } from "./arbiter-client.js";
import { gateRequest, observeResponse, withheldPolicy, agentWithheld, heldForEvent, refusalKindOf, isModelService } from "./egress.js";
import { ensureCa, leafForHost, type CaMaterial } from "./ca.js";
import { statedDestination } from "./destination.js";
import type { ProcHolder } from "./conn-attr.js";
import type { ModelPathDecision } from "./model-host-paths.js";
import { isChatCompletionsCall, type ModelCallEdit } from "./model-note.js";

/** MITM runtime config, threaded from server-main via the proxy constructor. */
export interface MitmConfig {
  /** Directory holding the session CA + per-host leaf cache. */
  caDir: string;
  /**
   * TEST ONLY: skip UPSTREAM TLS verification when re-originating. Default false
   * (verify against the system CA store). Loudly documented; never default-on.
   */
  insecureUpstream?: boolean;
  /** Skip the always-denied destination check on the upstream dial
   *  (blocked-destinations.ts; MANDU_NET_ALLOW_METADATA=1). Default false. */
  allowMetadata?: boolean;
  /** TEST ONLY: skip the this-machine check on the upstream dial
   *  (blocked-destinations.ts; proxy.ts `allowThisMachine`). No environment
   *  variable reaches it. Default false. */
  allowThisMachine?: boolean;
  /** How long a client may take to finish the TLS handshake before the
   *  connection is reported (`tls_rejected`) and closed. Default 10 s. */
  handshakeTimeoutMs?: number;
}

/** Everything the MITM handler needs from the proxy (kept narrow for testing). */
export interface MitmDeps {
  arbiter: Arbiter;
  log: (msg: string) => void;
  maxBodyBytes: number;
  /** ATTRIBUTION-ONLY session key threaded onto each gate request (never a
   * decision input) — the proxy's sessionId, so approval-queue rows created by
   * a MITM-path deny attribute to the same session as the emitted events. */
  sessionKey?: string;
  /** Confidentiality.md §4, "A held request": how long (ms) a decrypted
   *  request whose only obstacle is an unanswered per-symbol card is held
   *  for the human's answer (proxy.ts `egressHoldMs`). 0 / absent: none. */
  egressHoldMs?: number;
  /** Model services (proxy.ts NetProxyOptions.modelServices; egress.ts
   *  GateInput.modelService). Absent: none. */
  modelServices?: readonly string[];
  /** The handling note for a model-service Chat Completions call
   *  (model-note.ts; proxy.ts `noteBody`), with the relay's pending
   *  refusals last (relay-notice.ts): the body to send, or why it is
   *  sent as written. Absent: no note (the launch runs no DevTools relay). */
  modelNote?: (bodyText: string, headers: NodeJS.Dict<string | string[]>) => Promise<ModelCallEdit>;
  /** Best-effort net_action emit (off the security path). */
  emit: (action: string, fields: Record<string, unknown>) => void;
  /** The §4 verbatim-leak tripwire over a decrypted request's original
   *  surfaces (proxy.ts `fingerprintTripwire`): a block reason on a hit, else
   *  null. Defense-in-depth behind the gates; absent → not run. */
  tripwire?: (
    surfaces: { url: string; headers: NodeJS.Dict<string | string[]>; bodyText: string },
    destination: string,
    /** `strict` ("Send without it"): a scan that cannot run blocks. */
    opts?: { strict?: boolean },
  ) => Promise<{ reason: string; symbols: string[] } | null>;
  /** A mock-sites host route for the re-origination (test infrastructure,
   *  mock-sites.ts): dial this loopback listener instead of the host, still
   *  over verified TLS (against the route's own `ca`, servername the host).
   *  Absent, or undefined for a host: the real upstream. */
  route?: (host: string) => { host: string; port: number; ca?: string } | undefined;
  /** Plan 10 §11.8, "Refused connections": report a refusal for these
   *  holders, `[]` when none was found (proxy.ts noteRefusal; bounded,
   *  never throws). Absent: none. */
  noteRefusal?: (holders: readonly ProcHolder[], kind: EgressRefusalKind) => Promise<void>;
  /** The model-host deny (model-host-paths.ts): the decision for a request
   *  to a model vendor's host, or null for any other host. Checked first,
   *  before the gate: a refused path is answered 403 and nothing is dialed.
   *  Absent: the deny is off (a model host never reaches this leg then). */
  modelPath?: (host: string, method: string, target: string) => ModelPathDecision | null;
  /** Track sockets so the proxy's close() can tear them down. */
  track: (s: Duplex) => void;
  untrack: (s: Duplex) => void;
}

/** Idle read timeout on a terminated TLS socket between persistent requests. A
 * client that holds the connection open without sending the next request is torn
 * down after this many ms (keep-alive must not leak fds). */
const KEEPALIVE_IDLE_MS = 30_000;

/** A client that has not finished the handshake by now has given up on it
 *  (typically it rejected the leaf and its process exited without our side
 *  seeing the close). Reported and torn down instead of held forever. */
const HANDSHAKE_TIMEOUT_MS = 10_000;

/** Who sends on one terminated connection (plan 13 D6): the processes that
 *  held the client's socket at the CONNECT, and a way to read who holds it
 *  now. Each decrypted request is judged against both (proxy.ts). */
export interface ConnAttribution {
  holders: readonly ProcHolder[];
  current: () => ProcHolder[];
}

/** The holders a decrypted request is judged against: those at the CONNECT
 *  and those holding the socket now, each once. Empty only when neither
 *  found one (unattributed). */
export function requestHolders(a: ConnAttribution): ProcHolder[] {
  const out: ProcHolder[] = [];
  let now: ProcHolder[] = [];
  try {
    now = a.current();
  } catch {
    now = [];
  }
  for (const h of [...a.holders, ...now]) if (!out.some((o) => o.procKey === h.procKey)) out.push(h);
  return out;
}

/** A pooled upstream TLS connection, reused across requests on one client
 * connection while the host:port matches and the upstream keeps it alive. */
interface PooledUpstream {
  host: string;
  port: number;
  sock: TLSSocket;
}

/** The materialized MITM engine: CA loaded once, per-host SecureContext cached. */
export class MitmEngine {
  private readonly ca: CaMaterial;
  private readonly secureContexts = new Map<string, SecureContext>();

  constructor(
    private readonly cfg: MitmConfig,
    private readonly deps: MitmDeps,
  ) {
    // Load (or mint) the CA up front so a missing openssl fails FAST at setup,
    // not mid-connection. Throws if openssl is unavailable → caller degrades.
    this.ca = ensureCa(cfg.caDir);
  }

  /** The CA cert path (the launcher logs this so the user/agent can trust it). */
  get caCertPath(): string {
    return this.ca.certPath;
  }

  /** Per-host SecureContext (leaf cert), minted once and cached. The chain
   *  served is the leaf and the session CA: a Chrome that `mandu --browser`
   *  starts trusts the CA by its key pin (`--ignore-certificate-errors-spki-list`,
   *  devtools-relay.md §6.4), which Chrome matches only against certificates
   *  the server sends. A client that trusts the CA anyway ignores the copy. */
  private contextForHost(host: string): SecureContext {
    let ctx = this.secureContexts.get(host);
    if (!ctx) {
      const leaf = leafForHost(this.ca, host);
      ctx = createSecureContext({ key: leaf.keyPem, cert: `${leaf.certPem.trimEnd()}\n${this.ca.certPem}` });
      this.secureContexts.set(host, ctx);
    }
    return ctx;
  }

  /**
   * Terminate TLS on `clientSocket` (the accepted CONNECT socket), gate the inner
   * request, and re-originate to `host:port`. FAIL-CLOSED on any error.
   */
  handleConnect(
    host: string, port: number, clientSocket: Duplex, head: Buffer, attribution?: ConnAttribution,
    opts: { established?: boolean } = {},
  ): void {
    // Tell the client the tunnel is up; the TLS ClientHello follows on this
    // socket. `established`: the caller already did (proxy.ts sniffs the
    // first byte to tell TLS from plain HTTP in the tunnel).
    if (!opts.established) {
      try {
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      } catch {
        clientSocket.destroy();
        return;
      }
    }

    let tls: TLSSocket;
    try {
      tls = new TLSSocket(clientSocket as unknown as import("node:net").Socket, {
        isServer: true,
        // SNICallback presents the right per-host leaf. We always know `host` from
        // the CONNECT line, but SNI lets us match the client's intended name too.
        SNICallback: (servername, cb) => {
          try {
            cb(null, this.contextForHost(servername || host));
          } catch (err) {
            this.deps.log(`MITM SNI leaf mint failed for ${servername || host}: ${(err as Error).message}`);
            // Fail closed: no context → the TLS handshake aborts → connection dies.
            cb(err as Error);
          }
        },
        // Default context (used if the client sends no SNI).
        ...((): { secureContext?: SecureContext } => {
          try {
            return { secureContext: this.contextForHost(host) };
          } catch {
            return {};
          }
        })(),
      });
    } catch (err) {
      this.deps.log(`MITM TLS termination setup failed for ${host}:${port}: ${(err as Error).message}`);
      this.deps.emit("mitm_error", { destination: `${host}:${port}`, reason: (err as Error).message });
      clientSocket.destroy();
      return;
    }

    this.deps.track(tls);
    if (head && head.length) {
      // Any bytes read past the CONNECT line belong to the TLS stream.
      tls.unshift(head);
    }

    // One pooled upstream per CLIENT connection, reused across persistent requests
    // while the host:port matches and the upstream stays alive (see serveConnection).
    const pool: { current?: PooledUpstream } = {};

    // A handshake that never completes is, almost always, a client that does
    // not trust the session CA (it ignores the CA variables, or pins its own
    // CA); a rejecting client often just closes, with no error on our side.
    // Say so on the trace, once: otherwise the tool fails and nothing names
    // the reason (docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §10).
    let secured = false;
    let reported = false;
    const report = (detail: string): void => {
      if (reported) return;
      reported = true;
      this.deps.emit("tls_rejected", {
        destination: `${host}:${port}`,
        reason:
          `the TLS handshake with the program for ${host} did not complete (${detail}); most often it does not trust the session CA. ` +
          "Make the program a reader of its secret, or exclude the host from inspection",
      });
    };
    const unfinished = (detail: string): void => {
      if (!secured) report(detail);
    };
    tls.on("error", (err) => {
      this.deps.log(`MITM TLS socket error (${host}:${port}): ${err.message}`);
      unfinished(err.message);
      this.cleanup(tls, clientSocket, pool);
    });
    // TLS 1.3: the server's handshake completes before the client checks the
    // certificate, so a client that rejects it closes after "secure" having
    // sent no request at all.
    const stats = { served: 0 };
    tls.on("close", () => {
      unfinished("the program closed the connection");
      if (secured && stats.served === 0) report("the program closed the connection right after the handshake without a request");
      this.cleanup(tls, clientSocket, pool);
    });
    clientSocket.on("error", () => this.cleanup(tls, clientSocket, pool));

    // serveConnection re-arms this as the keep-alive idle timeout once secure.
    tls.setTimeout(this.cfg.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS, () => {
      if (secured) return;
      unfinished("no completed handshake before the deadline");
      this.cleanup(tls, clientSocket, pool);
    });
    tls.once("secure", () => {
      secured = true;
      this.serveConnection(host, port, tls, pool, stats, attribution).catch((err) => {
        this.deps.log(`MITM serve error (${host}:${port}): ${(err as Error).message}`);
        this.respond(tls, 502, "mandu_mitm_error", `MITM serve failed: ${(err as Error).message}`);
        this.cleanup(tls, clientSocket, pool);
      });
    });
  }

  private cleanup(tls: TLSSocket, clientSocket: Duplex, pool?: { current?: PooledUpstream }): void {
    this.deps.untrack(tls);
    if (pool?.current && !pool.current.sock.destroyed) pool.current.sock.destroy();
    if (pool) pool.current = undefined;
    if (!tls.destroyed) tls.destroy();
    if (!clientSocket.destroyed) clientSocket.destroy();
  }

  /**
   * KEEP-ALIVE loop: read decrypted HTTP/1.1 requests off `tls` one at a time and
   * serve each (independently gated + forwarded) until the client asks to close,
   * an idle read timeout fires, a request is malformed, or the socket ends.
   */
  private async serveConnection(
    host: string,
    port: number,
    tls: TLSSocket,
    pool: { current?: PooledUpstream },
    stats: { served: number } = { served: 0 },
    attribution?: ConnAttribution,
  ): Promise<void> {
    // Idle read timeout between persistent requests: a client holding the socket
    // open without sending the next request is torn down (keep-alive must not leak
    // fds). The timeout is rearmed by readHttpRequest on every byte received.
    tls.setTimeout(KEEPALIVE_IDLE_MS, () => {
      this.deps.log(`MITM keep-alive idle timeout (${host}:${port}) → close`);
      tls.destroy();
    });

    for (;;) {
      if (tls.destroyed) return;
      const parsed = await readHttpRequest(tls, this.deps.maxBodyBytes);
      if (parsed === null) {
        // Clean EOF between requests: the persistent connection ended → stop.
        if (!tls.destroyed) tls.end();
        return;
      }
      if (parsed.bad) {
        // Malformed / oversized / truncated request → fail closed (400) + close.
        this.respond(tls, 400, "mandu_mitm_bad_request", "could not parse the decrypted HTTPS request");
        tls.end();
        return;
      }

      stats.served += 1;
      const keepAlive = await this.handleRequest(host, port, tls, parsed, pool, attribution);
      if (!keepAlive) {
        // BLOCK, error, or `Connection: close` → stop serving this connection. We
        // tear down any pooled upstream so it isn't reused after we've closed.
        if (pool.current && !pool.current.sock.destroyed) pool.current.sock.destroy();
        pool.current = undefined;
        if (!tls.destroyed) tls.end();
        return;
      }
    }
  }

  /**
   * Serve ONE decrypted request: gate it, forward-or-block, write the response.
   * Returns whether the client connection may be KEPT for the next request
   * (true = keep-alive, false = close). A gate BLOCK / upstream error / explicit
   * `Connection: close` returns false (the connection is closed by the loop).
   */
  private async handleRequest(
    host: string,
    port: number,
    tls: TLSSocket,
    parsed: ParsedRequest,
    pool: { current?: PooledUpstream },
    attribution?: ConnAttribution,
  ): Promise<boolean> {
    const { method, path, headers, body } = parsed;
    const absoluteUrl = `https://${connectAuthority(host, port)}${path}`;
    // The CONNECT target's host AND port (destination.ts, 2026-10-17): the
    // gate and the tripwire judge `host:8443` or `host:443`, never the host
    // alone (which the binding rule reads as "no port said", so a credential
    // bound or granted to `host:8443` was also put back at `host:443`).
    const decideAt = statedDestination(host, port);
    const clientWantsClose = wantsClose(headers);

    // ── THE MODEL-HOST DENY (model-host-paths.ts), before anything else: a
    //    model vendor's host takes only the paths on its list. The target as
    //    the client sent it. A refusal closes the connection, as a block does.
    const modelPath = this.deps.modelPath?.(host, method, path) ?? null;
    if (modelPath && !modelPath.allowed) {
      this.deps.emit("blocked", { method, destination: host, scheme: "https", reason: modelPath.reason, modelHost: true });
      // The reason names the method and the path (no query): the log is
      // where a needed path that was refused is found.
      this.deps.log(`MITM BLOCK https://${host}: model host path refused: ${modelPath.reason}`);
      if (this.deps.noteRefusal) await this.deps.noteRefusal(attribution ? requestHolders(attribution) : [], "blocked-destination");
      this.respond(tls, 403, "mandu_fail_closed", modelPath.reason);
      return false;
    }
    if (modelPath) this.deps.log(`MITM model host ${host}: ${method} ${modelPath.path} allowed (${modelPath.pattern})`);

    // ── EGRESS gate on the DECRYPTED request (the new capability). ──
    // A held request (confidentiality.md §4) waits with no bytes on the
    // client's socket: the keep-alive idle timeout is off meanwhile, and a
    // client gone is sent nothing.
    const holdMs = this.deps.egressHoldMs ?? 0;
    if (holdMs > 0) tls.setTimeout(0);
    const gate = await gateRequest({
      method,
      destinationHost: decideAt,
      url: absoluteUrl,
      headers,
      bodyText: body.toString("utf8"),
      arbiter: this.deps.arbiter,
      // The scheme the value would travel in (plan 10 §11.13.1): decrypted
      // here, so HTTPS on both sides.
      scheme: "https",
      modelService: isModelService(decideAt, this.deps.modelServices ?? []),
      // Attribution-only — same session as the proxy's emitted events.
      ...(this.deps.sessionKey !== undefined ? { sessionKey: this.deps.sessionKey } : {}),
      // Plan 13 D6: the secret-taint leg, judged per request against every
      // process that held the socket at the CONNECT or holds it now. No
      // `procKey`: the integrity leg is frozen and stays plain-HTTP only.
      ...(attribution ? { holders: requestHolders(attribution) } : {}),
    }, holdMs > 0 ? { ms: holdMs, aborted: () => tls.destroyed, log: this.deps.log } : undefined);
    if (holdMs > 0 && !tls.destroyed) tls.setTimeout(KEEPALIVE_IDLE_MS);

    if (gate.action === "block") {
      this.deps.emit("blocked", {
        method,
        destination: host,
        scheme: "https",
        reason: gate.reason,
        withheld: gate.withheld.map((w) => w.symbol),
        // WHICH rule withheld it (egress.ts withheldPolicy): the trace can then
        // tell a one-time approval at a BOUND host from an unbound host.
        ...(withheldPolicy(gate.withheld) ? { policy: withheldPolicy(gate.withheld) } : {}),
        ...(gate.held ? { heldMs: gate.held.ms } : {}),
        // The cards it waited on and the rule that filed each (egress-hold.md).
        ...(heldForEvent(gate.held) ? { heldFor: heldForEvent(gate.held) } : {}),
        note: "HTTPS body gated via MITM termination",
      });
      this.deps.log(`MITM BLOCK ${method} https://${host}${path}: ${gate.reason}`);
      if (this.deps.noteRefusal) await this.deps.noteRefusal(attribution ? requestHolders(attribution) : [], refusalKindOf(gate.reason));
      this.respond(tls, 403, "mandu_fail_closed", gate.reason, { withheld: agentWithheld(gate.withheld) });
      // FAIL-CLOSED: a block CLOSES the connection (Connection: close). Once a
      // client is exfiltrating we stop serving it; closing also avoids ambiguity
      // about a half-consumed body on the persistent stream. NEVER forwarded →
      // upstream/dest receives NOTHING.
      return false;
    }

    // ── §4 verbatim-leak TRIPWIRE over the decrypted request (defense-in-
    //    depth, as on the plain leg; fail-open on error, only ADDS blocks). ──
    // "Send without it" (confidentiality.md §4): over the request with the
    // markers in, STRICT; with no scan at all it is not sent (fail-closed).
    const trip = gate.action === "forward" && gate.sentWithoutView
      ? this.deps.tripwire
        ? await this.deps.tripwire(gate.sentWithoutView, decideAt, { strict: true })
        : { reason: "the request you chose to send without the secret could not be checked for secret values (no check here), so it was not sent (fail-closed)", symbols: [] }
      : this.deps.tripwire
        ? await this.deps.tripwire({ url: absoluteUrl, headers, bodyText: body.toString("utf8") }, decideAt)
        : null;
    if (trip) {
      this.deps.emit("blocked", {
        method,
        destination: host,
        scheme: "https",
        reason: trip.reason,
        withheld: trip.symbols,
        fingerprintTripwire: true,
        note: "HTTPS body gated via MITM termination",
      });
      this.deps.log(`MITM BLOCK ${method} https://${host}${path}: ${trip.reason}`);
      if (this.deps.noteRefusal) await this.deps.noteRefusal(attribution ? requestHolders(attribution) : [], "fingerprint");
      this.respond(tls, 403, "mandu_fail_closed", trip.reason, {
        withheld: trip.symbols.map((symbol) => ({ symbol, requiresApproval: false, reason: trip.reason })),
      });
      return false;
    }

    // Forward the (possibly rewritten) request to the REAL upstream over TLS,
    // as the client wrote it (reoriginationHead: its header order and case,
    // ONE Host naming the CONNECT target).
    const fwdPath = gate.rewritten ? rewrittenPath(gate.rewritten.url, path) : path;
    const fwdBody = gate.rewritten ? Buffer.from(gate.rewritten.bodyText, "utf8") : body;
    // The model-host deny judges the path that is SENT: a value the gate put
    // back into the path could make it another one (fail-closed).
    if (modelPath && fwdPath !== path) {
      const again = this.deps.modelPath?.(host, method, fwdPath) ?? null;
      if (!again || !again.allowed) {
        const reason = again && !again.allowed ? again.reason : `model host ${host}: the path changed and could not be judged again (fail-closed)`;
        this.deps.emit("blocked", { method, destination: host, scheme: "https", reason, modelHost: true });
        this.deps.log(`MITM BLOCK https://${host}: model host path refused after the release: ${reason}`);
        if (this.deps.noteRefusal) await this.deps.noteRefusal(attribution ? requestHolders(attribution) : [], "blocked-destination");
        this.respond(tls, 403, "mandu_fail_closed", reason);
        return false;
      }
    }

    // ── THE HANDLING NOTE (model-note.ts): a browser agent's own Chat
    //    Completions call to a model service gets Mandu's note as its first
    //    system message, once the gate and the tripwire passed the request
    //    as the client wrote it, and the DevTools relay's pending refusals
    //    as its last message (relay-notice.ts). Anything the note step
    //    cannot read leaves as written (utility only).
    let sendBody = fwdBody;
    let modelNote: string | undefined;
    let relayNotices = 0;
    if (this.deps.modelNote && isModelService(decideAt, this.deps.modelServices ?? []) && isChatCompletionsCall(method, fwdPath)) {
      const r = await this.deps.modelNote(fwdBody.toString("utf8"), gate.rewritten?.headers ?? headers);
      if (r.bodyText !== undefined) sendBody = Buffer.from(r.bodyText, "utf8");
      modelNote = r.note;
      relayNotices = r.relayNotices;
      if (modelNote !== "added") this.deps.log(`MITM model service ${host}: handling note ${modelNote}`);
      if (relayNotices > 0) this.deps.log(`MITM model service ${host}: told the model ${relayNotices} relay refusal(s)`);
    }

    let upstream: { status: number; headers: Record<string, string | string[] | undefined>; body: Buffer; upstreamClose: boolean };
    try {
      // A header the substitution left unsendable (a line break in a resolved
      // value) throws here: 502, nothing sent (fail-closed).
      const head = reoriginationHead(method, fwdPath, gate.rewritten?.headers ?? headers, connectAuthority(host, port), sendBody.length);
      upstream = await this.originate(host, port, head, sendBody, pool);
    } catch (err) {
      if (isBlockedDestinationError(err)) {
        this.deps.emit("blocked", { method, destination: host, scheme: "https", reason: err.message });
        if (this.deps.noteRefusal) await this.deps.noteRefusal(attribution ? requestHolders(attribution) : [], err.refusalKind);
        this.respond(tls, 403, "mandu_fail_closed", err.message);
        return false;
      }
      this.deps.log(`MITM upstream error (${host}:${port}): ${(err as Error).message}`);
      this.deps.emit("forward_error", { method, destination: host, scheme: "https", reason: (err as Error).message });
      this.respond(tls, 502, "mandu_mitm_upstream_error", `re-originate to ${host} failed: ${(err as Error).message}`);
      return false; // upstream failure closes the connection
    }

    // ── INGRESS observe-and-tag of the decrypted response body (Plan 7). ──
    // Post-Plan-7: the body is returned RAW for untrusted origins (no longer symbolized
    // at the net layer). `observeResponse` classifies + best-effort taints the process.
    let outBody = upstream.body;
    let symbolized = false; // repurposed: "untrusted-by-origin (tagged)", NOT body-symbolized
    if (isTextResponse(upstream.headers)) {
      const r = await observeResponse(upstream.body, { arbiter: this.deps.arbiter, origin: host });
      outBody = r.body; // RAW for untrusted (was the symbol pre-Plan-7)
      symbolized = r.meta.trust === "UNTRUSTED";
    }

    const routed = this.deps.route?.(host);
    this.deps.emit("forwarded", {
      method,
      destination: host,
      scheme: "https",
      status: upstream.status,
      resolved: gate.resolved ?? [],
      ...(gate.sentWithout?.length ? { sentWithout: gate.sentWithout } : {}),
      // A model service (egress.ts modelService): placeholders sent as they are.
      ...(gate.keptOpaque?.length ? { keptOpaque: gate.keptOpaque } : {}),
      // The handling note (model-note.ts): added, or why not.
      ...(modelNote ? { modelNote } : {}),
      // The relay's refusals told to the model (relay-notice.ts).
      ...(relayNotices > 0 ? { relayNotices } : {}),
      ...(gate.action === "forward" && gate.held ? { heldMs: gate.held.ms } : {}),
      ...(gate.action === "forward" && heldForEvent(gate.held) ? { heldFor: heldForEvent(gate.held) } : {}),
      responseSymbolized: symbolized,
      note: "HTTPS gated + re-originated via MITM termination",
      ...(routed ? { mockRoute: `${routed.host}:${routed.port}` } : {}),
    });

    // Keep the CLIENT connection alive unless the client asked to close. We always
    // advertise the chosen disposition in the written response (writeResponse).
    const keepAlive = !clientWantsClose && !tls.destroyed;
    this.writeResponse(tls, upstream.status, upstream.headers, outBody, keepAlive);
    return keepAlive;
  }

  /**
   * Re-originate the request to the real upstream over TLS. Reuses the pooled
   * upstream socket when host:port is unchanged and it is still alive; otherwise
   * dials a fresh one (correctness over reuse). On success, the pool is updated to
   * the live socket iff the upstream kept the connection alive.
   */
  private originate(
    host: string,
    port: number,
    head: string,
    body: Buffer,
    pool: { current?: PooledUpstream },
  ): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: Buffer; upstreamClose: boolean }> {
    return new Promise((resolve, reject) => {
      // Reuse the pooled upstream iff it targets the same host:port and is still
      // writable; else discard it and dial fresh.
      let reused: TLSSocket | undefined;
      if (pool.current && pool.current.host === host && pool.current.port === port && !pool.current.sock.destroyed && pool.current.sock.writable) {
        reused = pool.current.sock;
      } else if (pool.current && !pool.current.sock.destroyed) {
        pool.current.sock.destroy();
        pool.current = undefined;
      }

      const sendRequest = (sock: TLSSocket): void => {
        // The head reoriginationHead built. HTTP/1.1 is persistent by default,
        // so the pool can reuse the connection for the next request. One
        // flush (writeMessage), on a socket with Nagle off (below).
        writeMessage(sock, head, body);
      };

      // Per-request response reader. Reads until the response is complete (honoring
      // Content-Length / chunked / connection-close framing), resolves, and decides
      // whether the socket can be pooled for reuse.
      const attachReader = (sock: TLSSocket): void => {
        readHttpResponse(sock, this.deps.maxBodyBytes)
          .then((res) => {
            if (!res) {
              sock.destroy();
              if (pool.current?.sock === sock) pool.current = undefined;
              reject(new Error("could not parse the upstream HTTPS response"));
              return;
            }
            if (res.upstreamClose) {
              // Upstream won't keep the connection → don't pool it.
              if (pool.current?.sock === sock) pool.current = undefined;
              if (!sock.destroyed) sock.destroy();
            } else {
              // Upstream kept it alive → pool for the next request on this client.
              pool.current = { host, port, sock };
            }
            resolve({ status: res.status, headers: res.headers, body: res.body, upstreamClose: res.upstreamClose });
          })
          .catch((err) => {
            sock.destroy();
            if (pool.current?.sock === sock) pool.current = undefined;
            reject(err);
          });
      };

      if (reused) {
        // Reused socket: errors here (e.g. upstream closed the idle conn) bubble to
        // the reader's catch → the caller fails closed for this request.
        sendRequest(reused);
        attachReader(reused);
        return;
      }

      // A mock-sites host route (test infrastructure): the same verified TLS,
      // to a loopback listener, trusting the route's own CA for `host`.
      const route = this.deps.route?.(host);
      // Dial only an address that passed the always-denied and this-machine
      // checks (blocked-destinations.ts): a literal here (throws → the
      // promise rejects, nothing dialed), a name in the lookup. A route's own
      // loopback dial skips the this-machine check.
      const policy: DialPolicy = {
        allowMetadata: this.cfg.allowMetadata === true,
        allowThisMachine: route !== undefined || this.cfg.allowThisMachine === true,
      };
      const dialOpts = guardDial(route?.host ?? host, route?.port ?? port, policy);
      // An IPv6 literal (`[2001:db8::1]`, the CONNECT target) is dialed bare,
      // sends no SNI (RFC 6066 has none for an address) and is verified
      // against the certificate's IP entry for that address, a route's
      // loopback dial included.
      const bare = dialHostOf(host);
      const literal = isIP(bare) !== 0;
      const sock = tlsConnect(
        {
          host: dialHostOf(route?.host ?? host),
          port: route?.port ?? port,
          ...(literal ? { checkServerIdentity: (_name: string, cert: import("node:tls").PeerCertificate) => checkServerIdentity(bare, cert) } : { servername: host }),
          ...(route?.ca ? { ca: route.ca } : {}),
          ...dialOpts,
          // UPSTREAM verification: default ON (system CA store). Only the TEST-ONLY
          // insecureUpstream flag disables it — never default-on (documented loudly
          // in server-main + README).
          rejectUnauthorized: this.cfg.insecureUpstream ? false : true,
        },
        () => {
          sendRequest(sock);
          attachReader(sock);
        },
      );
      // Nagle off: on a pooled (kept-alive) connection a request's last
      // small segment otherwise waits for the ACK of the one before it,
      // which the server delays (~40 ms) while it waits for the rest of
      // the request (plan 13 D6, "The kept-alive floor").
      sock.setNoDelay(true);
      sock.setTimeout(30000, () => {
        sock.destroy(new Error("upstream TLS timeout"));
      });
      sock.on("error", reject);
    });
  }

  /** Write a buffered upstream response back over the terminated TLS socket. We
   * always send a computed Content-Length (identity framing) and advertise the
   * keep-alive disposition so the client knows whether to reuse the connection. */
  private writeResponse(
    tls: TLSSocket,
    status: number,
    headers: Record<string, string | string[] | undefined>,
    body: Buffer,
    keepAlive: boolean,
  ): void {
    const lines = [`HTTP/1.1 ${status} ${statusText(status)}`];
    for (const [k, v] of Object.entries(headers)) {
      if (v == null) continue;
      const lk = k.toLowerCase();
      if (lk === "connection" || lk === "transfer-encoding" || lk === "content-length" || lk === "content-encoding") {
        continue;
      }
      for (const one of Array.isArray(v) ? v : [v]) lines.push(`${k}: ${one}`);
    }
    lines.push(`Content-Length: ${body.length}`);
    lines.push(keepAlive ? "Connection: keep-alive" : "Connection: close");
    try {
      writeMessage(tls, lines.join("\r\n") + "\r\n\r\n", body);
    } catch (err) {
      this.deps.log(`MITM write-back failed: ${(err as Error).message}`);
    }
  }

  /** Send a small JSON error response (block / fail-closed) over the TLS socket. */
  private respond(
    tls: TLSSocket,
    status: number,
    type: string,
    message: string,
    extra?: Record<string, unknown>,
  ): void {
    if (tls.destroyed) return;
    const payload = JSON.stringify({ error: { type, message, ...extra } });
    const buf = Buffer.from(payload, "utf8");
    try {
      writeMessage(
        tls,
        `HTTP/1.1 ${status} ${statusText(status)}\r\n` +
          "Content-Type: application/json\r\n" +
          `Content-Length: ${buf.length}\r\n` +
          "Connection: close\r\n\r\n",
        buf,
      );
    } catch (err) {
      this.deps.log(`MITM error-response write failed: ${(err as Error).message}`);
    }
  }
}

// ── pure HTTP parse/serialize helpers (no node:http server needed) ─────────────

interface ParsedRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  /** Set when the request was MALFORMED / oversized (vs a clean EOF, which yields
   * null). Lets the keep-alive loop answer 400 only for a real bad request. */
  bad?: boolean;
}

/**
 * A minimal buffering reader over a Duplex stream. It accumulates incoming bytes
 * in an internal buffer so successive `readHttpRequest` calls on a PERSISTENT
 * (keep-alive) connection never drop bytes that arrived early (e.g. a pipelined or
 * fast-following next request). One reader is created per request via a tiny
 * WeakMap cache keyed on the socket, so the buffer survives across loop iterations.
 */
class StreamReader {
  buf: Buffer = Buffer.alloc(0);
  ended = false;
  errored = false;
  private waiter?: () => void;

  constructor(private readonly stream: Duplex) {
    stream.on("data", (chunk: Buffer) => {
      this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
      this.wake();
    });
    stream.on("end", () => {
      this.ended = true;
      this.wake();
    });
    stream.on("error", () => {
      this.errored = true;
      this.ended = true;
      this.wake();
    });
  }

  private wake(): void {
    const w = this.waiter;
    this.waiter = undefined;
    if (w) w();
  }

  /** Resolve once more bytes are available OR the stream ended/errored. */
  wait(): Promise<void> {
    if (this.ended || this.errored) return Promise.resolve();
    return new Promise((resolve) => {
      this.waiter = resolve;
    });
  }

  consume(n: number): Buffer {
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }
}

const readers = new WeakMap<Duplex, StreamReader>();
function readerFor(stream: Duplex): StreamReader {
  let r = readers.get(stream);
  if (!r) {
    r = new StreamReader(stream);
    readers.set(stream, r);
  }
  return r;
}

/**
 * Read and parse ONE HTTP/1.1 request off a decrypted duplex stream. Reads the
 * head (request line + headers) up to CRLFCRLF, then the body honoring EITHER
 * `Content-Length` OR `Transfer-Encoding: chunked` (the chunked body is decoded —
 * chunk-ext stripped, trailing/trailer headers consumed — and reassembled, so a
 * symbol smuggled in a chunked upload is gated rather than treated as empty).
 *
 * Returns:
 *   - a ParsedRequest on success;
 *   - `null` on a CLEAN connection end (no bytes / EOF between requests — the
 *     persistent connection simply ended);
 *   - a ParsedRequest with `bad:true` on a MALFORMED / oversized / truncated
 *     request (the caller answers 400 and closes — fail closed).
 */
async function readHttpRequest(stream: Duplex, maxBodyBytes: number): Promise<ParsedRequest | null> {
  const r = readerFor(stream);

  // ── 1. read the head (up to CRLFCRLF) ──
  let headEnd = -1;
  for (;;) {
    headEnd = r.buf.indexOf("\r\n\r\n");
    if (headEnd !== -1) break;
    if (r.buf.length > 256 * 1024) return { ...EMPTY_REQ, bad: true }; // runaway head
    if (r.ended) {
      // Clean EOF with no (partial) request pending → the connection ended.
      if (r.buf.length === 0) return null;
      return { ...EMPTY_REQ, bad: true }; // truncated head
    }
    await r.wait();
  }

  const headText = r.buf.subarray(0, headEnd).toString("utf8");
  r.consume(headEnd + 4);
  const lines = headText.split("\r\n");
  const reqLine = lines.shift() ?? "";
  const m = reqLine.match(/^(\S+)\s+(\S+)\s+HTTP\/\d\.\d$/);
  if (!m) return { ...EMPTY_REQ, bad: true };
  const method = m[1]!;
  const path = m[2]!;

  const headers: Record<string, string | string[] | undefined> = {};
  let contentLength = -1;
  let chunked = false;
  for (const line of lines) {
    const ci = line.indexOf(":");
    if (ci === -1) continue;
    const k = line.slice(0, ci).trim();
    const v = line.slice(ci + 1).trim();
    const lk = k.toLowerCase();
    const existing = headers[k];
    if (existing == null) headers[k] = v;
    else if (Array.isArray(existing)) existing.push(v);
    else headers[k] = [existing, v];
    if (lk === "content-length") contentLength = Number(v) || 0;
    if (lk === "transfer-encoding" && /chunked/i.test(v)) chunked = true;
  }

  // ── 2. read the body ──
  // Per RFC 7230 §3.3.3: Transfer-Encoding chunked takes precedence over a
  // Content-Length (and a chunked request has no usable Content-Length).
  if (chunked) {
    const body = await readChunkedBody(r, maxBodyBytes);
    if (body == null) return { method, path, headers, body: Buffer.alloc(0), bad: true };
    // Re-originate as identity: strip the chunked markers (writer recomputes C-L).
    delete headers["Transfer-Encoding"];
    delete headers["transfer-encoding"];
    return { method, path, headers, body };
  }

  const len = contentLength < 0 ? 0 : contentLength;
  if (len > maxBodyBytes) return { method, path, headers, body: Buffer.alloc(0), bad: true };
  while (r.buf.length < len) {
    if (r.ended) return { method, path, headers, body: Buffer.alloc(0), bad: true }; // truncated body
    await r.wait();
  }
  const body = r.consume(len);
  return { method, path, headers, body };
}

const EMPTY_REQ: ParsedRequest = { method: "GET", path: "/", headers: {}, body: Buffer.alloc(0) };

/**
 * Decode a `Transfer-Encoding: chunked` request body off the buffering reader:
 * read `<size-hex>[;chunk-ext]CRLF <data> CRLF` chunks until the 0-size terminator,
 * then consume optional trailer headers up to the final CRLF. chunk-extensions are
 * stripped; trailers are dropped (minimal handling). Returns the reassembled body,
 * or null on a malformed / oversized / truncated chunked stream (caller → 400).
 */
async function readChunkedBody(r: StreamReader, maxBodyBytes: number): Promise<Buffer | null> {
  const out: Buffer[] = [];
  let total = 0;

  const readLine = async (): Promise<string | null> => {
    for (;;) {
      const nl = r.buf.indexOf("\r\n");
      if (nl !== -1) {
        const line = r.buf.subarray(0, nl).toString("ascii");
        r.consume(nl + 2);
        return line;
      }
      if (r.buf.length > 64 * 1024) return null; // runaway chunk-size/trailer line
      if (r.ended) return null;
      await r.wait();
    }
  };

  for (;;) {
    const sizeLine = await readLine();
    if (sizeLine == null) return null;
    const sizeHex = sizeLine.trim().split(";")[0]!.trim(); // strip chunk-ext
    const size = parseInt(sizeHex, 16);
    if (Number.isNaN(size) || size < 0) return null;
    if (size === 0) {
      // Last chunk: consume trailer headers until the terminating empty line.
      for (;;) {
        const trailer = await readLine();
        if (trailer == null) return null;
        if (trailer.length === 0) break;
      }
      break;
    }
    total += size;
    if (total > maxBodyBytes) return null;
    // Read `size` data bytes + the trailing CRLF.
    while (r.buf.length < size + 2) {
      if (r.ended) return null; // truncated mid-chunk
      await r.wait();
    }
    out.push(r.consume(size));
    const crlf = r.consume(2);
    if (crlf.length !== 2 || crlf[0] !== 0x0d || crlf[1] !== 0x0a) return null; // bad framing
  }

  return out.length ? Buffer.concat(out) : Buffer.alloc(0);
}

/**
 * Read ONE complete HTTP/1.1 response off an upstream TLS socket using the same
 * buffering reader, honoring framing so we can REUSE the socket for the next
 * request: chunked → decode to the 0-chunk; Content-Length → that many bytes;
 * otherwise read to connection close. Returns `upstreamClose` when the response
 * framing requires closing (no C-L + not chunked, or `Connection: close`), which
 * tells the pool not to reuse this socket.
 */
async function readHttpResponse(
  stream: Duplex,
  maxBodyBytes: number,
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: Buffer; upstreamClose: boolean } | null> {
  const r = readerFor(stream);

  let headEnd = -1;
  for (;;) {
    headEnd = r.buf.indexOf("\r\n\r\n");
    if (headEnd !== -1) break;
    if (r.buf.length > 256 * 1024) return null;
    if (r.ended) return null;
    await r.wait();
  }

  const headText = r.buf.subarray(0, headEnd).toString("utf8");
  r.consume(headEnd + 4);
  const lines = headText.split("\r\n");
  const statusLine = lines.shift() ?? "";
  const m = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})/);
  if (!m) return null;
  const status = Number(m[1]);

  const headers: Record<string, string | string[] | undefined> = {};
  let chunked = false;
  let contentLength = -1;
  let connClose = false;
  for (const line of lines) {
    const ci = line.indexOf(":");
    if (ci === -1) continue;
    const k = line.slice(0, ci).trim();
    const v = line.slice(ci + 1).trim();
    const lk = k.toLowerCase();
    if (lk === "transfer-encoding" && /chunked/i.test(v)) chunked = true;
    if (lk === "content-length") contentLength = Number(v) || 0;
    if (lk === "connection" && /close/i.test(v)) connClose = true;
    const existing = headers[k];
    if (existing == null) headers[k] = v;
    else if (Array.isArray(existing)) existing.push(v);
    else headers[k] = [existing, v];
  }

  // Responses with no body by definition (204/304/1xx) — frame as empty.
  const bodyless = status === 204 || status === 304 || (status >= 100 && status < 200);

  if (bodyless) {
    return { status, headers, body: Buffer.alloc(0), upstreamClose: connClose };
  }
  if (chunked) {
    const body = await readChunkedBody(r, maxBodyBytes);
    if (body == null) return null;
    return { status, headers, body, upstreamClose: connClose };
  }
  if (contentLength >= 0) {
    if (contentLength > maxBodyBytes) return null;
    while (r.buf.length < contentLength) {
      if (r.ended) return null;
      await r.wait();
    }
    return { status, headers, body: r.consume(contentLength), upstreamClose: connClose };
  }
  // No framing → read until close (RFC 7230 §3.3.3 case 7). The socket cannot be
  // reused (the body is delimited by EOF).
  while (!r.ended) {
    if (r.buf.length > maxBodyBytes) return null;
    await r.wait();
  }
  return { status, headers, body: r.consume(r.buf.length), upstreamClose: true };
}

/** True iff the request asked the proxy to close the connection after responding. */
function wantsClose(headers: Record<string, string | string[] | undefined>): boolean {
  const v = headerValue(headers, "connection");
  return v != null && /close/i.test(v);
}

/** Map the rewritten absolute URL back to an origin-form path for re-origination. */
function rewrittenPath(rewrittenUrl: string, fallback: string): string {
  try {
    const u = new URL(rewrittenUrl);
    return u.pathname + u.search;
  } catch {
    return fallback;
  }
}

/** Content types we treat as text and run symbolization over. Mirrors proxy.ts. */
function isTextResponse(headers: Record<string, string | string[] | undefined>): boolean {
  const ct = headerValue(headers, "content-type") ?? "";
  return ct.includes("text/") || ct.includes("json") || ct.includes("xml") || ct.includes("javascript") || ct.includes("html") || ct === "";
}

function headerValue(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const lname = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lname) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

/** The authority the re-originated request names in its Host header: the
 *  CONNECT target the gate judged, with the port unless it is HTTPS's 443
 *  (what curl and every HTTP client write for that URL). */
export function connectAuthority(host: string, port: number): string {
  const h = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  return port === 443 ? h : `${h}:${port}`;
}

/** Headers of the client's own hop to the proxy, never forwarded: the
 *  upstream leg is the proxy's. */
const HOP_BY_HOP = new Set(["proxy-connection", "proxy-authorization", "connection", "keep-alive", "transfer-encoding"]);

/**
 * The HTTP/1.1 request head the TLS-inspected leg re-originates (request line
 * through the blank line): what the client sent, in its header order and
 * case, apart from
 *
 *   - Host: exactly ONE, at the client's position and in its case, naming the
 *     CONNECT target (`authority`), the destination the gate judged; a second
 *     Host is dropped. (Until 2026-10-05 a lowercase `host` was appended
 *     after the client's own `Host:`, and nginx answers a request with two
 *     Host headers with a plain 400: every inspected request to
 *     api.stripe.com failed, the released key included. Lenient test
 *     listeners accepted it.)
 *   - Content-Length: the body's real length, at the client's position; added
 *     at the end only for a body the client framed chunked. A body-less
 *     request sent without one gets none (no `Content-Length: 0` on a GET).
 *   - Accept-Encoding: `identity`, at the client's position, else appended
 *     (the one line a client that sent none sees added): the response the
 *     proxy observes and writes back is then plaintext.
 *   - the hop-by-hop headers (HOP_BY_HOP) are dropped.
 *
 * The header values are the gate's (a released secret already substituted).
 * One holding CR, LF or NUL would split the head (a resolved value is
 * arbitrary text): it throws, and the caller sends nothing (fail-closed).
 * Pure.
 */
export function reoriginationHead(
  method: string,
  path: string,
  headers: Record<string, string | string[] | undefined>,
  authority: string,
  bodyLength: number,
): string {
  const lines = [`${method} ${path} HTTP/1.1`];
  let host = false;
  let length = false;
  let encoding = false;
  for (const [k, v] of Object.entries(headers)) {
    if (v == null) continue;
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (lk === "host") {
      if (!host) lines.push(`${k}: ${authority}`);
      host = true;
    } else if (lk === "content-length") {
      if (!length) lines.push(`${k}: ${bodyLength}`);
      length = true;
    } else if (lk === "accept-encoding") {
      if (!encoding) lines.push(`${k}: identity`);
      encoding = true;
    } else {
      for (const one of Array.isArray(v) ? v : [v]) {
        if (/[\r\n\0]/.test(one) || /[\r\n\0:]/.test(k)) {
          throw new Error(`header ${JSON.stringify(k)} cannot be sent: it holds a line break (fail-closed)`);
        }
        lines.push(`${k}: ${one}`);
      }
    }
  }
  if (!host) lines.splice(1, 0, `Host: ${authority}`);
  if (!length && bodyLength > 0) lines.push(`Content-Length: ${bodyLength}`);
  if (!encoding) lines.push("Accept-Encoding: identity");
  return `${lines.join("\r\n")}\r\n\r\n`;
}

/**
 * Write an HTTP message (its head, then its body) as ONE flush: corked, so
 * a TLS socket seals head and body into one record (a small body into the
 * head's segment), never a head segment and then a body segment that
 * Nagle would hold until the peer's (delayed) ACK. The order and the bytes
 * are the two writes' own.
 */
export function writeMessage(sock: Pick<Duplex, "cork" | "uncork" | "write">, head: string, body: Buffer): void {
  sock.cork();
  try {
    sock.write(head);
    if (body.length) sock.write(body);
  } finally {
    sock.uncork();
  }
}

function statusText(status: number): string {
  const map: Record<number, string> = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    502: "Bad Gateway",
  };
  return map[status] ?? "Status";
}
