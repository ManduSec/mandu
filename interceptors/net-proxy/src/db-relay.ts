/**
 * db-relay — the database login release (docs/design/confidentiality/
 * db-login-release.md): one loopback listener per database the launch's
 * secrets name, through which a client in the agent's tree logs in with the
 * placeholder its password file or variable holds, and the relay answers the
 * server's password challenge with the real password.
 *
 * How a connection gets here: the connect guard (mandu-net-guard
 * `--redirect`) performs the agent tree's connect to the database's
 * address and port on the relay's loopback port instead, so `psql -h
 * db.internal` and any driver reach the relay without knowing it. Each relay
 * serves exactly one database (`DbRelayTarget`), so the destination is never
 * read from the client.
 *
 * The login, Postgres (protocol 3):
 *   1. the client's SSLRequest is answered `S` with the session CA's leaf for
 *      the database's name when there is one, else `N`; a GSSENCRequest `N`;
 *      a CancelRequest is passed to the server on a connection of its own;
 *   2. the relay dials the server (the always-denied set refused; this
 *      machine allowed, the target being fixed at launch from the user's own
 *      files), asks it for TLS, and sends the client's StartupMessage as is;
 *   3. AuthenticationOk (a trust login) goes to the client; a password
 *      request (md5, SCRAM-SHA-256, or cleartext over verified TLS) makes the
 *      relay ask the CLIENT for its password in cleartext (on loopback, or
 *      inside the client's TLS), run it through the egress gate as the
 *      login's credential (`authorization` position) at `host:port`, and
 *      answer the server's method with the value the gate put back;
 *   4. SCRAM's server signature is checked: a server that cannot prove it
 *      knows the password gets nothing more and the client an error;
 *   5. after AuthenticationOk the relay copies bytes both ways, each chunk
 *      the client sends judged again by the holders' secret taint, as a
 *      blind tunnel's (plan 13 D6).
 *
 * The login, MySQL (protocol 10; the server speaks first):
 *   1. the relay dials the server, reads its handshake, and gives the client
 *      the server's own handshake with the relay's scramble, plugin
 *      `caching_sha2_password`, and TLS offered when there is a session CA;
 *   2. it asks the client for the full path of `caching_sha2_password`
 *      (switching a client that answered with another plugin), so the
 *      client sends its password in cleartext inside TLS, or RSA-encrypted
 *      under the relay's own key when the client asks for it;
 *   3. the password goes through the same gate; the relay answers the
 *      server's `mysql_native_password` or `caching_sha2_password` (fast
 *      scramble; the full path only over TLS it verified) with the value put
 *      back, follows an auth switch, and gives the client the server's OK or
 *      ERR, then copies bytes both ways as for Postgres.
 *
 * FAIL-CLOSED: a refusal at any step (the gate, the tripwire, an unknown
 * method, a malformed or oversized message, a server that will not do TLS
 * when the client asked for it, a bad SCRAM signature, the arbiter
 * unreachable) closes both sides with an ErrorResponse naming the reason;
 * the real password is never sent to anything but the server's method, and
 * never to the client.
 *
 * Mandu-new (no reference origin).
 */

import { connect as netConnect, createServer, isIP, type Server, type Socket } from "node:net";
import { checkServerIdentity, connect as tlsConnect, TLSSocket, type SecureContext } from "node:tls";
import type { Duplex } from "node:stream";

import type { Arbiter, EgressRefusalKind } from "./arbiter-client.js";
import type { ProcHolder } from "./conn-attr.js";
import { statedDestination } from "./destination.js";
import { dialHostOf, guardDial, isBlockedDestinationError, thisMachineAddressReason } from "./blocked-destinations.js";
import { prependChunk } from "./proxy.js";
import { gateRequest, refusalKindOf, secretTaintVerdict, withheldPolicy, type SecretTaintVerdict } from "./egress.js";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import {
  CACHING_SHA2, CAP, CLEAR, MyReader, NATIVE, authSwitch, cachingSha2Password, cleartextOf, clientResponse, errPacket,
  errText, nativePassword, packet, parseAuthSwitch, parseClientResponse, parseServerHandshake, rsaPasswordOf,
  serverHandshake, sslRequest as mysqlSslRequest, type ClientResponse,
} from "./mysql-wire.js";
import {
  AUTH, PgReader, ScramClient, authRequest, errorResponse, errorText, md5Password, parseAuth, parseStartupPacket,
  passwordMessage, passwordOf, saslInitialResponse, saslMechanisms, saslResponse, sslRequest, type PgMessage,
} from "./pg-wire.js";

/** The variable naming the relays the net-proxy opens (server-main): a JSON
 *  list of `{ protocol, host, port }`. */
export const DB_RELAYS_ENV = "MANDU_NET_PROXY_DB_RELAYS";
/** Where server-main publishes each relay's bound port (JSON, atomic). */
export const DB_RELAY_PORT_FILE_ENV = "MANDU_DB_RELAY_PORT_FILE";

/** The protocols a relay speaks. */
export type DbProtocol = "postgres" | "mysql";

/** One database a relay serves. */
export interface DbRelayTarget {
  protocol: DbProtocol;
  host: string;
  port: number;
}

/** A relay as published: its target and the loopback port it listens on. */
export interface DbRelayBound extends DbRelayTarget {
  listen: number;
}

/** Parse `MANDU_NET_PROXY_DB_RELAYS`. Entries that are not a known protocol,
 *  a host and a port are dropped (and named in `dropped`). */
export function parseDbRelays(raw: string | undefined): { targets: DbRelayTarget[]; dropped: string[] } {
  if (!raw || raw.trim() === "") return { targets: [], dropped: [] };
  let list: unknown;
  try {
    list = JSON.parse(raw);
  } catch {
    return { targets: [], dropped: [raw] };
  }
  if (!Array.isArray(list)) return { targets: [], dropped: [raw] };
  const targets: DbRelayTarget[] = [];
  const dropped: string[] = [];
  for (const e of list) {
    const o = e as { protocol?: unknown; host?: unknown; port?: unknown };
    const ok = o && (o.protocol === "postgres" || o.protocol === "mysql") && typeof o.host === "string" && /^[A-Za-z0-9._:-]+$/.test(o.host) &&
      typeof o.port === "number" && Number.isInteger(o.port) && o.port > 0 && o.port < 65536;
    if (!ok) { dropped.push(JSON.stringify(e)); continue; }
    if (!targets.some((t) => t.host === o.host && t.port === o.port)) targets.push({ protocol: o.protocol as DbProtocol, host: o.host as string, port: o.port as number });
  }
  return { targets, dropped };
}

export interface DbRelayDeps {
  arbiter: Arbiter;
  log: (msg: string) => void;
  /** A `net_action` event (NetProxy.safeEmit): best-effort, off the path. */
  emit: (action: string, fields: Record<string, unknown>) => void;
  /** Attribution-only session key on each gate request. */
  sessionKey?: string;
  /** Every process holding the client's end now (NetProxy.resolveHolders). */
  holders: (sock: Socket) => ProcHolder[];
  /** After the login: a check run before each chunk the client sends (the
   *  blind tunnel's, NetProxy). Absent: none. */
  recheck?: (sock: Socket, holders: readonly ProcHolder[], destination: string) => () => Promise<SecretTaintVerdict>;
  /** The §4 verbatim tripwire over the login's credential (NetProxy). */
  tripwire?: (surfaces: { url: string; headers: NodeJS.Dict<string | string[]>; bodyText: string }, destination: string) => Promise<{ reason: string; symbols: string[] } | null>;
  /** The refusal note (NetProxy.noteRefusal). */
  noteRefusal?: (holders: readonly ProcHolder[], kind: EgressRefusalKind) => Promise<void>;
  /** How long a login waiting on an unanswered card is held (ms). */
  egressHoldMs?: number;
  /** The client-side TLS context for a host (the session CA's leaf), or
   *  null/absent: the client's SSLRequest is answered `N`. */
  clientTls?: (host: string) => SecureContext | null;
  /** The CA the server's certificate must chain to (the user's own
   *  `PGSSLROOTCERT` / `~/.postgresql/root.crt`, as their psql would read it),
   *  checked with the host name; `system`: the system's store (libpq's
   *  `sslrootcert=system`; for MySQL, never). Absent: the server's TLS is not verified
   *  (libpq's default without a root certificate), and a cleartext password
   *  request is refused. */
  upstreamCa?: string;
  /** The user's own libpq settings the relay holds itself to (the launch
   *  environment's `PGSSLMODE`, `PGREQUIREAUTH`, `PGCHANNELBINDING`). */
  pgSettings?: { sslmode?: string; requireAuth?: string; channelBinding?: string };
  /** For a target on this machine: is the listening end a process of this
   *  session (`session`, refused: a program the agent runs could stand in
   *  for the database and collect the password's proof), another user's or
   *  one outside the session (`other`), or not known (`unknown`, refused)?
   *  Absent: every local target is refused. */
  localServer?: (sock: Socket) => "session" | "other" | "unknown";
  /** Skip the always-denied set (MANDU_NET_ALLOW_METADATA). */
  allowMetadata?: boolean;
  /** TEST ONLY: dial this address in place of the target's (the target's
   *  name still drives TLS and the gate). */
  route?: { host: string; port: number };
  /** The login's deadline (ms), the hold excluded. Default 30 s. */
  loginTimeoutMs?: number;
}

/** A refusal: the SQLSTATE the client sees and the reason. */
class Refusal extends Error {
  constructor(readonly sqlstate: string, message: string, readonly kind: EgressRefusalKind = "fail-closed") {
    super(message);
  }

  /** The MySQL error number for it (access denied, a lost connection,
   *  a bad handshake, a plugin not loaded). */
  get mysqlCode(): number {
    return this.sqlstate === AUTH_REFUSED ? 1045 : this.sqlstate === CONNECTION_FAILURE ? 2013 : this.sqlstate === PROTOCOL_VIOLATION ? 1043 : 1524;
  }
}

/** SQLSTATEs: invalid_authorization_specification, connection_failure,
 *  protocol_violation, feature_not_supported. */
const AUTH_REFUSED = "28000";
const CONNECTION_FAILURE = "08006";
const PROTOCOL_VIOLATION = "08P01";
const NOT_SUPPORTED = "0A000";

/** What a Feed cuts its bytes with (pg-wire's PgReader, mysql-wire's
 *  MyReader). */
interface Cutter {
  feed(chunk: Buffer): void;
  rest(): Buffer;
}

/** A socket read as a stream of startup packets / messages / single bytes. */
class Feed<R extends Cutter = PgReader> {
  readonly reader: R;
  private waiter: (() => void) | null = null;
  private failed: Error | null = null;
  private readonly onData = (c: Buffer): void => { this.reader.feed(c); this.wake(); };
  private readonly onEnd = (): void => { this.failed ??= new Error("the connection closed"); this.wake(); };
  private readonly onError = (e: Error): void => { this.failed ??= e; this.wake(); };

  constructor(private readonly sock: Duplex, reader?: R) {
    this.reader = reader ?? (new PgReader() as unknown as R);
    sock.on("data", this.onData);
    sock.on("end", this.onEnd);
    sock.on("close", this.onEnd);
    sock.on("error", this.onError);
  }

  private wake(): void {
    const w = this.waiter;
    this.waiter = null;
    w?.();
  }

  async take<T>(f: (r: R) => T | null): Promise<T> {
    for (;;) {
      const t = f(this.reader);
      if (t !== null) return t;
      if (this.failed) throw this.failed;
      await new Promise<void>((resolve) => { this.waiter = resolve; });
    }
  }

  /** One raw byte (the answer to an SSLRequest). */
  byte(): Promise<number> {
    return this.take((r) => {
      const b = r.rest();
      if (b.length === 0) return null;
      if (b.length > 1) r.feed(b.subarray(1));
      return b[0]!;
    });
  }

  /** Stop reading; the bytes read and not taken. */
  detach(): Buffer {
    this.sock.off("data", this.onData);
    this.sock.off("end", this.onEnd);
    this.sock.off("close", this.onEnd);
    this.sock.off("error", this.onError);
    this.wake();
    return this.reader.rest();
  }
}

export class DbRelay {
  private server?: Server;
  private readonly open = new Set<Duplex>();

  constructor(readonly target: DbRelayTarget, private readonly deps: DbRelayDeps) {}

  /** `host:port` as the gate and the bindings read it. */
  get destination(): string {
    return statedDestination(this.target.host, this.target.port);
  }

  async listen(port = 0, host = "127.0.0.1"): Promise<number> {
    const server = createServer((sock) => {
      sock.setNoDelay(true);
      this.open.add(sock);
      sock.on("close", () => this.open.delete(sock));
      sock.on("error", () => sock.destroy());
      this.serve(sock).catch((err) => {
        this.deps.log(`db-relay ${this.destination}: ${(err as Error).message}`);
        sock.destroy();
      });
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => { server.off("error", reject); resolve(); });
    });
    const addr = server.address();
    return typeof addr === "object" && addr ? addr.port : port;
  }

  async close(): Promise<void> {
    for (const s of this.open) s.destroy();
    this.open.clear();
    if (this.server) {
      await new Promise<void>((resolve) => this.server!.close(() => resolve()));
      this.server = undefined;
    }
  }

  /** One client connection, by the relay's protocol. */
  private serve(raw: Socket): Promise<void> {
    return this.target.protocol === "mysql" ? this.serveMysql(raw) : this.servePostgres(raw);
  }

  /** One Postgres client connection, from its first byte to the copy. */
  private async servePostgres(raw: Socket): Promise<void> {
    let client: Duplex = raw;
    let feed = new Feed(raw);
    let upstream: Duplex | null = null;
    let clientTls = false;
    const loginTimeout = (this.deps.loginTimeoutMs ?? 30_000) + (this.deps.egressHoldMs ?? 0);
    const timer = setTimeout(() => { client.destroy(); upstream?.destroy(); }, loginTimeout);
    timer.unref();
    try {
      // 1. The client's startup: TLS / GSS requests first, then the startup.
      let startup: Extract<ReturnType<typeof parseStartupPacket>, { kind: "startup" }> | null = null;
      while (startup === null) {
        const pkt = parseStartupPacket(await feed.take((r) => r.takeStartup()));
        if (pkt.kind === "ssl") {
          const ctx = clientTls ? null : this.deps.clientTls?.(this.target.host) ?? null;
          if (!ctx) { client.write("N"); continue; }
          // Bytes sent before the TLS handshake would be read as if inside
          // it (CVE-2021-23214's shape): refused.
          if (feed.detach().length > 0) throw new Refusal(PROTOCOL_VIOLATION, "the client sent data before the TLS handshake");
          client.write("S");
          const tls = new TLSSocket(raw, { isServer: true, secureContext: ctx });
          tls.on("error", () => tls.destroy());
          client = tls;
          feed = new Feed(tls);
          clientTls = true;
          this.open.add(tls);
          continue;
        }
        if (pkt.kind === "gssenc") { client.write("N"); continue; }
        if (pkt.kind === "invalid") throw new Refusal(PROTOCOL_VIOLATION, `mandu: ${pkt.reason}`);
        // Nothing the client wrote reaches the server before its holders
        // are judged here (plan 13 D6): a startup's parameters and a cancel's
        // key are bytes a process holding a secret could fill.
        await this.judgeHolders(raw, pkt.kind === "startup" ? [...pkt.params].map(([k, v]) => `${k}=${v}`).join("\n") : "");
        if (pkt.kind === "cancel") { await this.passCancel(pkt.raw); client.end(); return; }
        startup = pkt;
      }
      const user = startup.params.get("user")!;

      // 2. The server: dialed, asked for TLS, sent the startup as written.
      const verify = this.pgVerifyRequirement(clientTls);
      upstream = await this.dialServer(verify.tls);
      if (verify.verified && !this.upstreamVerified(upstream)) {
        throw new Refusal(CONNECTION_FAILURE, `mandu: your PGSSLMODE=${this.deps.pgSettings?.sslmode} asks for a verified server, and there is no root certificate to verify ${this.destination} against (set PGSSLROOTCERT)`);
      }
      upstream.write(startup.raw);
      const up = new Feed(upstream);

      // 3–4. The login.
      let scram: { client: ScramClient; verified: boolean } | null = null;
      let methodSeen = false;
      let released: { value: string; resolved: string[] } | null = null;
      const real = async (): Promise<string> => {
        released ??= await this.releasedPassword(raw, client, feed);
        return released.value;
      };
      for (;;) {
        const msg: PgMessage = await up.take((r) => r.takeMessage());
        if (msg.type === "E") {
          // The server's own refusal (a wrong password, no such database):
          // passed to the client as the server wrote it.
          this.deps.log(`db-relay ${this.destination}: the server refused the login: ${errorText(msg.body)}`);
          client.end(msg.raw);
          upstream.end();
          return;
        }
        if (msg.type === "v") { client.write(msg.raw); continue; } // NegotiateProtocolVersion
        if (msg.type !== "R") throw new Refusal(PROTOCOL_VIOLATION, `mandu: the server sent '${msg.type}' during the login`);
        const auth = parseAuth(msg.body);
        if (!auth) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a malformed authentication request from the server");
        // The user's PGREQUIREAUTH: the first request names the method
        // (AuthenticationOk first: none).
        if (!methodSeen) { this.pgAllowedMethod(auth.code); methodSeen = true; }
        if (auth.code === AUTH.ok) {
          if (scram !== null && !scram.verified) throw new Refusal(AUTH_REFUSED, "mandu: the server did not prove it knows the password (SCRAM), so the login was stopped");
          client.write(msg.raw);
          break;
        }
        if (auth.code === AUTH.md5) {
          if (auth.data.length !== 4) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a malformed md5 salt");
          // md5's answer is crackable offline by whoever receives it, so it
          // goes only where the user's own psql would send it: the target is
          // fixed at launch, a local listener is checked (dialTcp), and the
          // user's PGSSLMODE / PGREQUIREAUTH are held to (db-login-release.md
          // §3.5).
          upstream.write(passwordMessage(md5Password(user, await real(), auth.data)));
          continue;
        }
        if (auth.code === AUTH.sasl) {
          const mechs = saslMechanisms(auth.data);
          if (!mechs.includes("SCRAM-SHA-256")) throw new Refusal(NOT_SUPPORTED, `mandu: the server offers only ${mechs.join(", ") || "no"} SASL mechanism(s); Mandu logs in with SCRAM-SHA-256`);
          scram = { client: new ScramClient(await real()), verified: false };
          upstream.write(saslInitialResponse("SCRAM-SHA-256", scram.client.first()));
          continue;
        }
        if (auth.code === AUTH.saslContinue) {
          if (scram === null) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a SASL continuation with no exchange");
          let reply: string;
          try { reply = scram.client.final(auth.data.toString("utf8")); } catch (err) { throw new Refusal(AUTH_REFUSED, `mandu: ${(err as Error).message}`); }
          upstream.write(saslResponse(reply));
          continue;
        }
        if (auth.code === AUTH.saslFinal) {
          if (scram === null || !scram.client.verify(auth.data.toString("utf8"))) {
            throw new Refusal(AUTH_REFUSED, "mandu: the server did not prove it knows the password (SCRAM), so the login was stopped");
          }
          scram.verified = true;
          continue;
        }
        if (auth.code === AUTH.cleartext) {
          // The password itself on the wire: only to a server whose TLS
          // certificate was verified.
          if (!this.upstreamVerified(upstream)) {
            throw new Refusal(AUTH_REFUSED, "mandu: the server asks for the password in cleartext, and Mandu sends it only over TLS to a server whose certificate it verified (set PGSSLROOTCERT, or use scram-sha-256)");
          }
          upstream.write(passwordMessage(await real()));
          continue;
        }
        throw new Refusal(NOT_SUPPORTED, `mandu: the server asks for an authentication method Mandu does not answer (code ${auth.code}); only md5 and scram-sha-256 are put through`);
      }

      // 5. The copy.
      clearTimeout(timer);
      const fromServer = up.detach();
      if (fromServer.length) client.write(fromServer);
      const fromClient = feed.detach();
      this.deps.emit("forwarded", {
        method: "LOGIN",
        destination: this.destination,
        scheme: this.target.protocol,
        resolved: (released as { resolved: string[] } | null)?.resolved ?? [],
        note: "database login: the password put back in the server's own method (db-relay)",
      });
      this.splice(raw, client, upstream, fromClient);
    } catch (err) {
      clearTimeout(timer);
      const r = err instanceof Refusal ? err : new Refusal(CONNECTION_FAILURE, `mandu: ${(err as Error).message}`);
      this.deps.log(`db-relay ${this.destination}: refused: ${r.message}`);
      if (!client.destroyed && client.writable) client.end(errorResponse(r.sqlstate, r.message));
      upstream?.destroy();
    }
  }

  /** The relay's own RSA key for a MySQL client that asks for the
   *  server's public key (the full path without TLS), made on first use. */
  private rsaKey: { publicKey: string; privateKey: string } | null = null;

  /** One MySQL client connection, from the server's handshake to the copy. */
  private async serveMysql(raw: Socket): Promise<void> {
    let client: Duplex = raw;
    let feed = new Feed(raw, new MyReader());
    let upstream: Duplex | null = null;
    // The sequence id of the client's last packet: the relay's next one to
    // the client is one more (-1: nothing yet, the handshake goes as 0).
    let clientSeq = -1;
    const loginTimeout = (this.deps.loginTimeoutMs ?? 30_000) + (this.deps.egressHoldMs ?? 0);
    const timer = setTimeout(() => { client.destroy(); upstream?.destroy(); }, loginTimeout);
    timer.unref();
    try {
      // The server speaks first, so the holders are judged before it is
      // dialed: nothing of the client's reaches it otherwise.
      await this.judgeHolders(raw, "");
      const sock = await this.dialTcp();
      upstream = sock;
      let up = new Feed(sock, new MyReader());
      const first = await up.take((r) => r.take());
      if (first.payload[0] === 0xff) {
        // The server refused the connection (too many, a blocked host).
        this.deps.log(`db-relay ${this.destination}: the server refused the connection: ${errText(first.payload)}`);
        client.end(packet(0, first.payload));
        sock.destroy();
        return;
      }
      const h = parseServerHandshake(first.payload);
      if (!h) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a server handshake Mandu does not read (protocol 10 only)");
      const needed = CAP.PROTOCOL_41 | CAP.SECURE_CONNECTION | CAP.PLUGIN_AUTH;
      if ((h.capabilities & needed) !== needed) throw new Refusal(NOT_SUPPORTED, "mandu: the server predates the 4.1 protocol with authentication plugins");
      let serverSeq = first.seq;

      // 1. The client: the server's handshake, the relay's scramble and plugin.
      const scramble = relayScramble();
      const ctx = this.deps.clientTls?.(this.target.host) ?? null;
      const offered = ((h.capabilities & ~CAP.SSL) | (ctx ? CAP.SSL : 0)) >>> 0;
      client.write(packet(0, serverHandshake({ ...h, scramble, capabilities: offered, plugin: CACHING_SHA2 })));
      clientSeq = 0;
      let pk = await feed.take((r) => r.take());
      clientSeq = pk.seq;
      let resp = parseClientResponse(pk.payload);
      if (!resp) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a client handshake Mandu does not read (protocol 4.1 only)");
      let clientTls = false;
      if (resp.ssl) {
        if (!ctx) throw new Refusal(PROTOCOL_VIOLATION, "mandu: the client asked for TLS, which was not offered");
        // MySQL's SSLRequest has no answer: the client's TLS hello may
        // already be read behind it, so it rides in front of the socket.
        raw.pause();
        const tls = new TLSSocket(prependChunk(raw, feed.detach()), { isServer: true, secureContext: ctx });
        tls.on("error", () => tls.destroy());
        this.open.add(tls);
        client = tls;
        feed = new Feed(tls, new MyReader());
        clientTls = true;
        pk = await feed.take((r) => r.take());
        clientSeq = pk.seq;
        resp = parseClientResponse(pk.payload);
        if (!resp || resp.ssl) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a client handshake Mandu does not read inside TLS");
      }
      // The connect attributes too: bytes a holder of a secret could fill.
      await this.tripStartup(raw, [`user=${resp.user}`, `database=${resp.database ?? ""}`, ...(resp.attrs ? [`attrs=${resp.attrs.toString("utf8")}`] : [])].join("\n"));

      // 2. The client's password, by the full path, then the gate.
      const asked = await this.mysqlClientPassword(client, feed, resp, scramble, clientTls, clientSeq);
      clientSeq = asked.seq;
      const released = await this.gatePassword(raw, client, asked.password);
      const real = released.value;

      // 3. The server: TLS when it offers it (required when the client
      //    asked), the client's own choices, the password's answer.
      let verified = false;
      let caps = ((resp.capabilities & h.capabilities) | needed) >>> 0;
      caps = (caps & ~CAP.SSL) >>> 0;
      if (!(h.capabilities & CAP.PLUGIN_AUTH_LENENC_CLIENT_DATA)) caps = (caps & ~CAP.PLUGIN_AUTH_LENENC_CLIENT_DATA) >>> 0;
      if (!(h.capabilities & CAP.CONNECT_ATTRS) || resp.attrs === null) caps = (caps & ~CAP.CONNECT_ATTRS) >>> 0;
      if (h.capabilities & CAP.SSL) {
        caps = (caps | CAP.SSL) >>> 0;
        serverSeq += 1;
        sock.write(packet(serverSeq, mysqlSslRequest(caps, resp.maxPacket, resp.charset)));
        if (up.detach().length > 0) throw new Refusal(PROTOCOL_VIOLATION, "mandu: the server sent data before the TLS handshake");
        const tls = await this.tlsToServer(sock);
        upstream = tls;
        up = new Feed(tls, new MyReader());
        verified = this.deps.upstreamCa !== undefined;
      } else if (clientTls || this.deps.upstreamCa !== undefined) {
        // An ssl-ca of yours means TLS to the server, verified (security
        // review 2026-10-24): a server with its SSL flag stripped is refused,
        // never answered in plaintext.
        throw new Refusal(CONNECTION_FAILURE, `mandu: ${this.destination} does not offer TLS, and ${clientTls ? "the client asked for it" : "your ~/.my.cnf names an ssl-ca for it"}`);
      }
      let plugin = h.plugin === NATIVE || h.plugin === CACHING_SHA2 ? h.plugin : CACHING_SHA2;
      let serverScramble = h.scramble;
      const answer = (name: string, data: Buffer): Buffer => {
        if (name === NATIVE) return nativePassword(real, data);
        if (name === CACHING_SHA2) return cachingSha2Password(real, data);
        if (name === CLEAR) {
          if (!verified) throw new Refusal(AUTH_REFUSED, "mandu: the server asks for the password in cleartext, and Mandu sends it only over TLS to a server whose certificate it verified (set ssl-ca in ~/.my.cnf)");
          return Buffer.from(`${real}\0`, "utf8");
        }
        throw new Refusal(NOT_SUPPORTED, `mandu: the server asks for an authentication plugin Mandu does not answer (${name}); only mysql_native_password and caching_sha2_password are put through`);
      };
      serverSeq += 1;
      upstream.write(packet(serverSeq, clientResponse({
        capabilities: caps, maxPacket: resp.maxPacket, charset: resp.charset, user: resp.user,
        authResponse: answer(plugin, serverScramble), database: resp.database, plugin, attrs: resp.attrs,
      })));
      for (;;) {
        const p = await up.take((r) => r.take());
        serverSeq = p.seq;
        const kind = p.payload[0];
        if (kind === 0x00) {
          client.write(packet(clientSeq + 1, p.payload));
          break;
        }
        if (kind === 0xff) {
          this.deps.log(`db-relay ${this.destination}: the server refused the login: ${errText(p.payload)}`);
          client.end(packet(clientSeq + 1, p.payload));
          upstream.end();
          return;
        }
        if (kind === 0xfe) {
          const sw = parseAuthSwitch(p.payload);
          if (!sw) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a malformed authentication switch from the server");
          plugin = sw.plugin;
          serverScramble = sw.data;
          serverSeq += 1;
          upstream.write(packet(serverSeq, answer(plugin, serverScramble)));
          continue;
        }
        if (kind === 0x01 && plugin === CACHING_SHA2 && p.payload.length === 2 && p.payload[1] === 0x03) continue; // the fast path worked
        if (kind === 0x01 && plugin === CACHING_SHA2 && p.payload.length === 2 && p.payload[1] === 0x04) {
          // The full path: the password itself, only over TLS it verified.
          if (!verified) throw new Refusal(AUTH_REFUSED, `mandu: ${this.destination} needs the password itself (caching_sha2_password's full authentication), and Mandu sends it only over TLS to a server whose certificate it verified (set ssl-ca in ~/.my.cnf); a login that worked once is then served from the server's cache`);
          serverSeq += 1;
          upstream.write(packet(serverSeq, Buffer.from(`${real}\0`, "utf8")));
          continue;
        }
        throw new Refusal(PROTOCOL_VIOLATION, "mandu: an authentication packet from the server Mandu does not read");
      }

      // 4. The copy.
      clearTimeout(timer);
      const fromServer = up.detach();
      if (fromServer.length) client.write(fromServer);
      const fromClient = feed.detach();
      this.deps.emit("forwarded", {
        method: "LOGIN",
        destination: this.destination,
        scheme: "mysql",
        resolved: released.resolved,
        note: "database login: the password put back in the server's own method (db-relay)",
      });
      this.splice(raw, client, upstream, fromClient);
    } catch (err) {
      clearTimeout(timer);
      const r = err instanceof Refusal ? err : new Refusal(CONNECTION_FAILURE, `mandu: ${(err as Error).message}`);
      this.deps.log(`db-relay ${this.destination}: refused: ${r.message}`);
      if (!client.destroyed && client.writable) client.end(packet(clientSeq + 1, errPacket(r.message, r.mysqlCode, r.sqlstate)));
      upstream?.destroy();
    }
  }

  /**
   * The MySQL client's password: a client that answered with another
   * plugin is switched to `caching_sha2_password`, then asked for the full
   * path, so it sends the password in cleartext inside TLS, or encrypted
   * under the relay's RSA key when it asks for it. An empty answer is an
   * empty password. With the sequence id of the client's last packet.
   */
  private async mysqlClientPassword(
    client: Duplex, feed: Feed<MyReader>, resp: ClientResponse, scramble: Buffer, clientTls: boolean, lastSeq: number,
  ): Promise<{ password: string; seq: number }> {
    let seq = lastSeq;
    let data = resp.authResponse;
    if (resp.plugin !== CACHING_SHA2) {
      client.write(packet(seq + 1, authSwitch(CACHING_SHA2, Buffer.concat([scramble, Buffer.from([0])]))));
      const p = await feed.take((r) => r.take());
      seq = p.seq;
      data = p.payload;
    }
    if (data.length === 0) return { password: "", seq };
    client.write(packet(seq + 1, Buffer.from([0x01, 0x04])));
    let p = await feed.take((r) => r.take());
    seq = p.seq;
    if (clientTls) {
      const pw = cleartextOf(p.payload);
      if (pw === null) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a malformed password from the client");
      return { password: pw, seq };
    }
    if (p.payload.length === 1 && p.payload[0] === 0x02) {
      this.rsaKey ??= generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
      client.write(packet(seq + 1, Buffer.concat([Buffer.from([0x01]), Buffer.from(this.rsaKey.publicKey)])));
      p = await feed.take((r) => r.take());
      seq = p.seq;
      const pw = rsaPasswordOf(p.payload, scramble, this.rsaKey.privateKey);
      if (pw === null) throw new Refusal(PROTOCOL_VIOLATION, "mandu: the client's encrypted password could not be read");
      return { password: pw, seq };
    }
    throw new Refusal(AUTH_REFUSED, "mandu: the client must use TLS (ssl-mode PREFERRED or REQUIRED) or ask for the server's public key (--get-server-public-key) to log in through Mandu's relay");
  }

  /** Is the server leg TLS whose certificate was verified? */
  private upstreamVerified(upstream: Duplex): boolean {
    return upstream instanceof TLSSocket && this.deps.upstreamCa !== undefined;
  }

  /** What the user's own `PGSSLMODE` asks of the server leg: TLS
   *  (`require` and up, or the client asked the relay for it) and a verified
   *  certificate (`verify-ca`, `verify-full`). A `PGCHANNELBINDING=require`
   *  is refused (the relay's leg binds no channel). */
  private pgVerifyRequirement(clientTls: boolean): { tls: boolean; verified: boolean } {
    const s = this.deps.pgSettings ?? {};
    if (s.channelBinding === "require") throw new Refusal(NOT_SUPPORTED, "mandu: your PGCHANNELBINDING=require cannot be met through Mandu's relay (it binds no channel to the server)");
    const mode = (s.sslmode ?? "").toLowerCase();
    return { tls: clientTls || mode === "require" || mode === "verify-ca" || mode === "verify-full", verified: mode === "verify-ca" || mode === "verify-full" };
  }

  /** The user's own `PGREQUIREAUTH` (a comma list of `none`, `password`,
   *  `md5`, `scram-sha-256`, or each with `!` to forbid it): a server
   *  asking for a method it rules out is refused. */
  private pgAllowedMethod(code: number): void {
    const raw = (this.deps.pgSettings?.requireAuth ?? "").trim();
    if (raw === "") return;
    const name = code === AUTH.md5 ? "md5" : code === AUTH.sasl ? "scram-sha-256" : code === AUTH.cleartext ? "password" : code === AUTH.ok ? "none" : null;
    if (name === null || code === AUTH.saslContinue || code === AUTH.saslFinal) return;
    const items = raw.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
    const neg = items.filter((x) => x.startsWith("!")).map((x) => x.slice(1));
    const pos = items.filter((x) => !x.startsWith("!"));
    if (neg.includes(name) || (pos.length > 0 && !pos.includes(name))) {
      throw new Refusal(AUTH_REFUSED, `mandu: ${this.destination} asks for ${name}, which your PGREQUIREAUTH=${raw} rules out`);
    }
  }

  /**
   * Before anything the client wrote is sent on: the processes holding its
   * socket, judged at this database by their secret taint (an unbound
   * destination for a secret one holds refuses), and the §4 tripwire over
   * the startup's parameters (`text`). A Refusal, or nothing.
   */
  private async judgeHolders(raw: Socket, text: string): Promise<void> {
    const destination = this.destination;
    const holders = this.deps.holders(raw);
    let v: SecretTaintVerdict;
    try {
      v = await secretTaintVerdict({ arbiter: this.deps.arbiter, holders, destinationHost: destination, ...(this.deps.sessionKey !== undefined ? { sessionKey: this.deps.sessionKey } : {}) });
    } catch (err) {
      v = { action: "block", reason: `taint check failed: ${(err as Error).message} → block (fail-closed)`, withheld: [] };
    }
    if (v.action === "block") {
      this.deps.emit("blocked", { method: "LOGIN", destination, scheme: this.target.protocol, reason: v.reason, withheld: v.withheld.map((w) => w.symbol), note: "database connection refused before the startup (db-relay)" });
      await this.deps.noteRefusal?.(holders, refusalKindOf(v.reason));
      throw new Refusal(AUTH_REFUSED, `mandu: the connection to ${destination} was refused: ${v.reason}`);
    }
    await this.tripStartup(raw, text, holders);
  }

  /** The §4 tripwire over what the client's startup names (`text`: user,
   *  database, parameters). A Refusal, or nothing. */
  private async tripStartup(raw: Socket, text: string, holders: readonly ProcHolder[] = this.deps.holders(raw)): Promise<void> {
    const destination = this.destination;
    const trip = text !== "" && this.deps.tripwire ? await this.deps.tripwire({ url: `${this.target.protocol}://${destination}/`, headers: {}, bodyText: text }, destination) : null;
    if (trip) {
      this.deps.emit("blocked", { method: "LOGIN", destination, scheme: this.target.protocol, reason: trip.reason, withheld: trip.symbols, fingerprintTripwire: true, note: "database startup refused (db-relay)" });
      await this.deps.noteRefusal?.(holders, "fingerprint");
      throw new Refusal(AUTH_REFUSED, trip.reason);
    }
  }

  /**
   * Ask the client for its password (a cleartext request, answered inside
   * the client's own connection), and run it through the egress gate as
   * this login's credential. The value the gate put back, or a Refusal.
   */
  private async releasedPassword(raw: Socket, client: Duplex, feed: Feed): Promise<{ value: string; resolved: string[] }> {
    client.write(authRequest(AUTH.cleartext));
    const msg = await feed.take((r) => r.takeMessage());
    if (msg.type !== "p") throw new Refusal(PROTOCOL_VIOLATION, "mandu: the client did not send a password");
    const sent = passwordOf(msg.body);
    if (sent === null) throw new Refusal(PROTOCOL_VIOLATION, "mandu: a malformed password message");
    return this.gatePassword(raw, client, sent);
  }

  /** The password a client sent, through the egress gate as this login's
   *  credential: the value the gate put back, or a Refusal. */
  private async gatePassword(raw: Socket, client: Duplex, sent: string): Promise<{ value: string; resolved: string[] }> {
    const destination = this.destination;
    const holders = this.deps.holders(raw);
    const url = `${this.target.protocol}://${destination}/`;
    // The password is the login's credential: the gate's `authorization`
    // position (a wire-granted secret is put back only there).
    const headers = { authorization: sent };
    const hold = this.deps.egressHoldMs ?? 0;
    const gate = await gateRequest({
      method: "LOGIN",
      destinationHost: destination,
      url,
      headers,
      bodyText: "",
      arbiter: this.deps.arbiter,
      holders,
      // The relay's login: the one scheme a password file's wire grant is
      // put back in (the arbiter's egress:secret-db-login-only).
      scheme: this.target.protocol,
      ...(this.deps.sessionKey !== undefined ? { sessionKey: this.deps.sessionKey } : {}),
    }, hold > 0 ? { ms: hold, aborted: () => client.destroyed, log: this.deps.log } : undefined);
    if (gate.action === "block") {
      this.deps.emit("blocked", {
        method: "LOGIN", destination, scheme: this.target.protocol, reason: gate.reason,
        withheld: gate.withheld.map((w) => w.symbol),
        ...(withheldPolicy(gate.withheld) ? { policy: withheldPolicy(gate.withheld) } : {}),
        note: "database login refused (db-relay)",
      });
      await this.deps.noteRefusal?.(holders, refusalKindOf(gate.reason));
      // The reason, and each withheld placeholder's own (an approval asked
      // for, an unbound host): never a value.
      const why = [...new Set(gate.withheld.map((w) => w.reason))].join("; ");
      throw new Refusal(AUTH_REFUSED, `mandu: the password for ${destination} was not put back: ${gate.reason}${why ? ` (${why})` : ""}`);
    }
    if (gate.sentWithout?.length) {
      throw new Refusal(AUTH_REFUSED, `mandu: a login cannot be sent without its password (${destination})`);
    }
    const trip = this.deps.tripwire ? await this.deps.tripwire({ url, headers, bodyText: "" }, destination) : null;
    if (trip) {
      this.deps.emit("blocked", { method: "LOGIN", destination, scheme: this.target.protocol, reason: trip.reason, withheld: trip.symbols, fingerprintTripwire: true, note: "database login refused (db-relay)" });
      await this.deps.noteRefusal?.(holders, "fingerprint");
      throw new Refusal(AUTH_REFUSED, trip.reason);
    }
    const put = gate.rewritten?.headers["authorization"];
    return { value: typeof put === "string" ? put : sent, resolved: gate.resolved ?? [] };
  }

  /** Dial the server and ask it for TLS (`clientAskedTls`: the client asked
   *  the relay for it, so the server must do it too). */
  private async dialServer(clientAskedTls: boolean): Promise<Duplex> {
    const sock = await this.dialTcp();
    sock.write(sslRequest());
    const feed = new Feed(sock);
    const answer = await feed.byte().catch(() => { throw new Refusal(CONNECTION_FAILURE, `mandu: ${this.destination} closed the connection`); });
    const extra = feed.detach();
    if (answer === 0x4e /* N */) {
      if (extra.length > 0) throw new Refusal(PROTOCOL_VIOLATION, "mandu: the server sent data after refusing TLS");
      if (clientAskedTls) throw new Refusal(CONNECTION_FAILURE, `mandu: ${this.destination} does not offer TLS, and the client asked for it`);
      return sock;
    }
    if (answer !== 0x53 /* S */) throw new Refusal(PROTOCOL_VIOLATION, "mandu: the server answered the TLS request with neither S nor N");
    // Bytes after `S` and before the handshake would be read as if the
    // server sent them inside TLS (CVE-2021-23222's shape): refused.
    if (extra.length > 0) throw new Refusal(PROTOCOL_VIOLATION, "mandu: the server sent data before the TLS handshake");
    return this.tlsToServer(sock);
  }

  /** The server's address, dialed (the always-denied set refused). */
  private async dialTcp(): Promise<Socket> {
    const { host, port } = this.target;
    const dialHost = this.deps.route?.host ?? host;
    const dialPort = this.deps.route?.port ?? port;
    let opts: ReturnType<typeof guardDial>;
    try {
      // The target is fixed at launch from the user's own files: this
      // machine is allowed (a local database), the always-denied set is not.
      opts = guardDial(dialHost, dialPort, { allowMetadata: this.deps.allowMetadata === true, allowThisMachine: true });
    } catch (err) {
      throw new Refusal(CONNECTION_FAILURE, `mandu: ${(err as Error).message}`, isBlockedDestinationError(err) ? err.refusalKind : "fail-closed");
    }
    const sock = await new Promise<Socket>((resolve, reject) => {
      const s = netConnect({ host: dialHostOf(dialHost), port: dialPort, ...opts }, () => { s.off("error", reject); resolve(s); });
      s.once("error", reject);
    }).catch((err: Error) => { throw new Refusal(CONNECTION_FAILURE, `mandu: could not reach ${this.destination}: ${err.message}`); });
    sock.setNoDelay(true);
    this.open.add(sock);
    sock.on("close", () => this.open.delete(sock));
    // A database on this machine: the listening end must not be a program
    // of this session (security review 2026-10-24), which could stand in
    // for the database and collect what the relay sends it.
    if (thisMachineAddressReason(sock.remoteAddress ?? "") !== null) {
      const who = this.deps.localServer?.(sock) ?? "unknown";
      if (who !== "other") {
        sock.destroy();
        throw new Refusal(CONNECTION_FAILURE, who === "session"
          ? `mandu: the server listening at ${this.destination} is a program of this session, not your database: refused`
          : `mandu: Mandu could not tell who listens at ${this.destination} on this machine (a program it cannot read): refused`);
      }
    }
    return sock;
  }

  /** TLS to the server on `sock`: verified, with the target's name, against
   *  `upstreamCa` when there is one, else not verified. */
  private async tlsToServer(sock: Socket): Promise<TLSSocket> {
    const { host } = this.target;
    const ca = this.deps.upstreamCa;
    const tls = await new Promise<TLSSocket>((resolve, reject) => {
      const t = tlsConnect({
        socket: sock,
        ...(isIP(host) === 0 ? { servername: host } : {}),
        // `system`: Node's own store (libpq's sslrootcert=system).
        ...(ca === "system" ? { rejectUnauthorized: true } : ca !== undefined ? { ca, rejectUnauthorized: true } : { rejectUnauthorized: false }),
        // The name checked is the target's, whatever address was dialed.
        checkServerIdentity: ca !== undefined ? (_name, cert) => checkServerIdentity(host, cert) : () => undefined,
      }, () => { t.off("error", reject); resolve(t); });
      t.once("error", reject);
    }).catch((err: Error) => { throw new Refusal(CONNECTION_FAILURE, `mandu: TLS to ${this.destination} failed: ${err.message}`); });
    this.open.add(tls);
    tls.on("close", () => this.open.delete(tls));
    return tls;
  }

  /** A CancelRequest, passed to the server on a connection of its own (it
   *  carries a process id and a key, no secret). */
  private async passCancel(raw: Buffer): Promise<void> {
    const dialHost = this.deps.route?.host ?? this.target.host;
    const dialPort = this.deps.route?.port ?? this.target.port;
    let opts: ReturnType<typeof guardDial>;
    try { opts = guardDial(dialHost, dialPort, { allowMetadata: this.deps.allowMetadata === true, allowThisMachine: true }); } catch { return; }
    await new Promise<void>((resolve) => {
      const s = netConnect({ host: dialHostOf(dialHost), port: dialPort, ...opts }, () => s.end(raw));
      s.on("close", () => resolve());
      s.on("error", () => resolve());
      s.setTimeout(10_000, () => s.destroy());
    });
  }

  /** Copy both ways; each client chunk judged again first (recheck). */
  private splice(raw: Socket, client: Duplex, upstream: Duplex, pending: Buffer): void {
    const cleanup = (): void => { client.destroy(); upstream.destroy(); };
    client.on("error", cleanup);
    upstream.on("error", cleanup);
    client.on("close", cleanup);
    upstream.on("close", cleanup);
    upstream.pipe(client);
    const recheck = this.deps.recheck?.(raw, this.deps.holders(raw), this.destination);
    if (!recheck) {
      if (pending.length) upstream.write(pending);
      client.pipe(upstream);
      return;
    }
    const send = (chunk: Buffer): void => {
      client.pause();
      recheck().then((v) => {
        if (v.action === "block") {
          this.deps.emit("blocked", { method: "LOGIN", destination: this.destination, scheme: this.target.protocol, reason: v.reason, withheld: v.withheld.map((w) => w.symbol), note: "database connection closed: a holder now holds a secret not bound here (plan 13 D6)" });
          this.deps.log(`db-relay ${this.destination}: closed: ${v.reason}`);
          cleanup();
          return;
        }
        if (upstream.destroyed) return;
        if (upstream.write(chunk)) client.resume();
        else upstream.once("drain", () => client.resume());
      }, cleanup);
    };
    if (pending.length) send(pending);
    client.on("data", send);
    client.on("end", () => upstream.end());
  }
}

/** A MySQL scramble: 20 bytes, none a NUL (the handshake ends it with one). */
function relayScramble(): Buffer {
  const b = randomBytes(20);
  for (let i = 0; i < b.length; i++) b[i] = (b[i]! % 0x7e) + 1;
  return b;
}
