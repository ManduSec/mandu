/**
 * fake-postgres — a Postgres server and client small enough to read, for the
 * database login release's tests (db-relay.ts). Shared by the package's
 * component test and the stack e2e (tests/stack/db-login-release.test.ts).
 *
 * The server speaks protocol 3's login with one method (trust, cleartext,
 * md5 or SCRAM-SHA-256, the server side of RFC 5802 written out here), an
 * optional TLS answer to SSLRequest, and then a simple query whose
 * CommandComplete tag echoes the query. It records every byte it receives
 * (the oracle: what reached the database) and each login's outcome.
 *
 * The client is what `psql` does for a cleartext request: the startup, the
 * password when asked, then one query.
 */
import { createServer, connect as netConnect, type AddressInfo, type Server, type Socket } from "node:net";
import { connect as tlsConnect, TLSSocket, createSecureContext } from "node:tls";
import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import type { Duplex } from "node:stream";

import {
  AUTH, PgReader, authRequest, message, md5Password, parseAuth, parseStartupPacket, passwordMessage, passwordOf, saslPrep,
  saslMechanisms, sslRequest,
} from "../src/pg-wire.js";

export type FakeMethod = "trust" | "password" | "md5" | "scram" | "gss";

export interface FakePostgresOptions {
  method: FakeMethod;
  user: string;
  password: string;
  /** Answer SSLRequest with S and this certificate; absent: N. */
  tls?: { key: string; cert: string };
  /** SCRAM: send a server signature that does not match (a server that does
   *  not know the password). */
  badSignature?: boolean;
  /** SCRAM: the iteration count asked for (default 4096). */
  iterations?: number;
  /** The address and port to listen on (default 127.0.0.1, a free port): the
   *  live database suite puts a decoy on "the other machine". */
  host?: string;
  port?: number;
}

export interface FakeLogin {
  user: string;
  ok: boolean;
  tls: boolean;
}

export interface FakePostgres {
  port: number;
  logins: FakeLogin[];
  /** Every byte the server received, all connections, in order. */
  received: () => Buffer;
  /** Connections accepted. */
  connections: () => number;
  close: () => Promise<void>;
}

class Feed {
  readonly r = new PgReader();
  private wake: (() => void) | null = null;
  private dead = false;
  constructor(private s: Duplex, onBytes: (b: Buffer) => void) {
    s.on("data", (c: Buffer) => { onBytes(c); this.r.feed(c); this.wake?.(); });
    s.on("close", () => { this.dead = true; this.wake?.(); });
    s.on("error", () => { this.dead = true; this.wake?.(); });
  }
  async take<T>(f: (r: PgReader) => T | null): Promise<T> {
    for (;;) {
      const t = f(this.r);
      if (t !== null) return t;
      if (this.dead) throw new Error("closed");
      await new Promise<void>((res) => { this.wake = res; });
    }
  }
  detach(): void { this.s.removeAllListeners("data"); }
}

const hmac = (k: Buffer, d: string): Buffer => createHmac("sha256", k).update(d).digest();
const sha256 = (d: Buffer): Buffer => createHash("sha256").update(d).digest();

function ready(sock: Duplex): void {
  const key = Buffer.alloc(8);
  key.writeInt32BE(4242, 0);
  key.writeInt32BE(7, 4);
  sock.write(Buffer.concat([authRequest(AUTH.ok), message("K", key), message("Z", Buffer.from("I"))]));
}

function fatal(sock: Duplex, code: string, text: string): void {
  const f = (k: string, v: string) => Buffer.concat([Buffer.from(k), Buffer.from(v), Buffer.from([0])]);
  sock.end(message("E", Buffer.concat([f("S", "FATAL"), f("C", code), f("M", text), Buffer.from([0])])));
}

export async function startFakePostgres(opts: FakePostgresOptions): Promise<FakePostgres> {
  const chunks: Buffer[] = [];
  const logins: FakeLogin[] = [];
  let connections = 0;
  const live = new Set<Duplex>();
  const server: Server = createServer((sock: Socket) => {
    connections++;
    live.add(sock);
    sock.on("close", () => live.delete(sock));
    void serve(sock).catch(() => sock.destroy());
  });

  async function serve(raw: Socket): Promise<void> {
    let sock: Duplex = raw;
    let feed = new Feed(raw, (b) => chunks.push(b));
    let tls = false;
    let params: Map<string, string> | null = null;
    while (params === null) {
      const pkt = parseStartupPacket(await feed.take((r) => r.takeStartup()));
      if (pkt.kind === "ssl") {
        if (!opts.tls) { sock.write("N"); continue; }
        feed.detach();
        sock.write("S");
        const t = new TLSSocket(raw, { isServer: true, secureContext: createSecureContext(opts.tls) });
        live.add(t);
        sock = t;
        feed = new Feed(t, (b) => chunks.push(b));
        tls = true;
        continue;
      }
      if (pkt.kind === "cancel") { raw.end(); return; }
      if (pkt.kind !== "startup") { raw.destroy(); return; }
      params = pkt.params;
    }
    const user = params.get("user")!;
    const login = (ok: boolean) => logins.push({ user, ok, tls });
    if (user !== opts.user) { login(false); fatal(sock, "28000", `role "${user}" does not exist`); return; }
    if (opts.method === "trust") {
      login(true);
    } else if (opts.method === "gss") {
      sock.write(authRequest(AUTH.gss));
      await feed.take((r) => r.takeMessage());
      login(false);
      fatal(sock, "28000", "GSS is not set up here");
      return;
    } else if (opts.method === "password" || opts.method === "md5") {
      const salt = randomBytes(4);
      sock.write(opts.method === "md5" ? authRequest(AUTH.md5, salt) : authRequest(AUTH.cleartext));
      const msg = await feed.take((r) => r.takeMessage());
      const got = msg.type === "p" ? passwordOf(msg.body) : null;
      const want = opts.method === "md5" ? md5Password(user, opts.password, salt) : opts.password;
      if (got !== want) { login(false); fatal(sock, "28P01", `password authentication failed for user "${user}"`); return; }
      login(true);
    } else {
      const mechs = Buffer.concat([Buffer.from("SCRAM-SHA-256\0"), Buffer.from([0])]);
      sock.write(authRequest(AUTH.sasl, mechs));
      const init = await feed.take((r) => r.takeMessage());
      const mechEnd = init.body.indexOf(0);
      const mech = init.body.toString("utf8", 0, mechEnd);
      const len = init.body.readInt32BE(mechEnd + 1);
      const clientFirst = init.body.toString("utf8", mechEnd + 5, mechEnd + 5 + len);
      if (mech !== "SCRAM-SHA-256" || !clientFirst.startsWith("n,,")) { login(false); fatal(sock, "28000", "bad SCRAM start"); return; }
      const clientFirstBare = clientFirst.slice(3);
      const cnonce = /(?:^|,)r=([^,]+)/.exec(clientFirstBare)?.[1] ?? "";
      const salt = randomBytes(16);
      const iters = opts.iterations ?? 4096;
      const nonce = cnonce + randomBytes(12).toString("base64");
      const serverFirst = `r=${nonce},s=${salt.toString("base64")},i=${iters}`;
      sock.write(authRequest(AUTH.saslContinue, Buffer.from(serverFirst)));
      const fin = await feed.take((r) => r.takeMessage());
      const clientFinal = fin.body.toString("utf8");
      const withoutProof = clientFinal.replace(/,p=[^,]*$/, "");
      const proof = Buffer.from(/,p=([^,]*)$/.exec(clientFinal)?.[1] ?? "", "base64");
      const salted = pbkdf2Sync(saslPrep(opts.password), salt, iters, 32, "sha256");
      const clientKey = hmac(salted, "Client Key");
      const storedKey = sha256(clientKey);
      const authMessage = `${clientFirstBare},${serverFirst},${withoutProof}`;
      const sig = hmac(storedKey, authMessage);
      const recovered = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) recovered[i] = (proof[i] ?? 0) ^ sig[i]!;
      const ok = proof.length === 32 && timingSafeEqual(sha256(recovered), storedKey) && withoutProof === `c=biws,r=${nonce}`;
      if (!ok) { login(false); fatal(sock, "28P01", `password authentication failed for user "${user}"`); return; }
      const serverSig = opts.badSignature ? randomBytes(32) : hmac(hmac(salted, "Server Key"), authMessage);
      sock.write(authRequest(AUTH.saslFinal, Buffer.from(`v=${serverSig.toString("base64")}`)));
      login(true);
    }
    ready(sock);
    for (;;) {
      const msg = await feed.take((r) => r.takeMessage(1 << 20));
      if (msg.type === "X") { sock.end(); return; }
      if (msg.type === "Q") {
        const q = msg.body.toString("utf8", 0, msg.body.length - 1);
        sock.write(Buffer.concat([message("C", Buffer.from(`ECHO ${q}\0`)), message("Z", Buffer.from("I"))]));
      }
    }
  }

  server.listen(opts.port ?? 0, opts.host ?? "127.0.0.1");
  await once(server, "listening");
  return {
    port: (server.address() as AddressInfo).port,
    logins,
    received: () => Buffer.concat(chunks),
    connections: () => connections,
    close: async () => {
      for (const s of live) s.destroy();
      await new Promise<void>((res) => server.close(() => res()));
    },
  };
}

export interface ClientResult {
  ok: boolean;
  /** The CommandComplete tag of the query, when the login worked. */
  tag?: string;
  /** The ErrorResponse's message, when it did not. */
  error?: string;
  /** Every byte the client received (the oracle: what reached the agent). */
  received: Buffer;
}

/**
 * Log in as `user` with `password` (answering a cleartext request, as psql
 * does for the relay), run `SELECT 1`, and terminate. `tls`: send
 * SSLRequest first and require `S` (sslmode=require), checking the server's
 * certificate against `ca` when given.
 */
export async function pgLogin(port: number, args: { user: string; password: string; database?: string; tls?: { ca?: string; servername?: string } }): Promise<ClientResult> {
  const raw = netConnect(port, "127.0.0.1");
  await once(raw, "connect");
  const got: Buffer[] = [];
  let sock: Duplex = raw;
  const done = (r: Omit<ClientResult, "received">): ClientResult => { sock.destroy(); raw.destroy(); return { ...r, received: Buffer.concat(got) }; };
  try {
    if (args.tls) {
      raw.write(sslRequest());
      const b = await new Promise<Buffer>((res, rej) => { raw.once("data", res); raw.once("error", rej); raw.once("close", () => rej(new Error("closed"))); });
      got.push(b);
      if (b.toString("latin1") !== "S") return done({ ok: false, error: `the server answered ${JSON.stringify(b.toString("latin1"))} to SSLRequest` });
      const t = tlsConnect({ socket: raw, ...(args.tls.ca ? { ca: args.tls.ca, servername: args.tls.servername } : { rejectUnauthorized: false }) });
      await once(t, "secureConnect");
      sock = t;
    }
    const feed = new Feed(sock, (c) => got.push(c));
    const kv = Buffer.from(`user\0${args.user}\0database\0${args.database ?? args.user}\0\0`);
    const head = Buffer.alloc(8);
    head.writeInt32BE(8 + kv.length, 0);
    head.writeInt32BE(196608, 4);
    sock.write(Buffer.concat([head, kv]));
    for (;;) {
      const msg = await feed.take((r) => r.takeMessage(1 << 20));
      if (msg.type === "E") return done({ ok: false, error: errorMessage(msg.body) });
      if (msg.type === "R") {
        const a = parseAuth(msg.body)!;
        if (a.code === AUTH.ok) continue;
        if (a.code === AUTH.cleartext) { sock.write(passwordMessage(args.password)); continue; }
        if (a.code === AUTH.md5) { sock.write(passwordMessage(md5Password(args.user, args.password, a.data))); continue; }
        return done({ ok: false, error: `the client does not answer auth code ${a.code} (${saslMechanisms(a.data).join(",")})` });
      }
      if (msg.type === "Z") break;
    }
    sock.write(message("Q", Buffer.from("SELECT 1\0")));
    let tag = "";
    for (;;) {
      const msg = await feed.take((r) => r.takeMessage(1 << 20));
      if (msg.type === "C") tag = msg.body.toString("utf8", 0, msg.body.length - 1);
      if (msg.type === "E") return done({ ok: false, error: errorMessage(msg.body) });
      if (msg.type === "Z") break;
    }
    sock.write(message("X", Buffer.alloc(0)));
    return done({ ok: true, tag });
  } catch (err) {
    return done({ ok: false, error: (err as Error).message });
  }
}

function errorMessage(body: Buffer): string {
  const field = body.toString("utf8").split("\0").find((f) => f.startsWith("M"));
  return field ? field.slice(1) : body.toString("utf8");
}
