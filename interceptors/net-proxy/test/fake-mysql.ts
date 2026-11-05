/**
 * fake-mysql — a MySQL server and client small enough to read, for the
 * database login release's tests (db-relay.ts). Shared by the package's
 * component test and the stack e2e (tests/stack/db-login-release.test.ts).
 *
 * The server speaks protocol 10's login with one plugin
 * (`mysql_native_password`, or `caching_sha2_password` with its fast path
 * once a login has filled its cache and its full path before, over TLS or
 * with its RSA key), optional TLS, an optional auth switch, and then
 * COM_QUERY, answered with an OK whose info echoes the query. It records
 * every byte it receives and each login's outcome.
 *
 * The client is what `mysql` does: `caching_sha2_password` first, following
 * a switch, the full path in cleartext inside TLS or under the server's RSA
 * key when it asks for it.
 */
import { createServer, connect as netConnect, type AddressInfo, type Socket } from "node:net";
import { connect as tlsConnect, TLSSocket, createSecureContext } from "node:tls";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { once } from "node:events";
import type { Duplex } from "node:stream";

import {
  CACHING_SHA2, CAP, MyReader, NATIVE, authSwitch, cachingSha2Password, cleartextOf, clientResponse, errPacket, lenencInt, nativePassword,
  packet, parseAuthSwitch, parseClientResponse, parseServerHandshake, rsaPassword, rsaPasswordOf, serverHandshake, sslRequest,
} from "../src/mysql-wire.js";
import { prependChunk } from "../src/proxy.js";

export interface FakeMysqlOptions {
  plugin: "native" | "caching_sha2";
  user: string;
  password: string;
  tls?: { key: string; cert: string };
  /** caching_sha2: the cache already holds this user (the fast path works). */
  cached?: boolean;
  /** After the response, switch the client to mysql_native_password. */
  switchToNative?: boolean;
  /** The address and port to listen on (default 127.0.0.1, a free port): the
   *  live database suite puts a decoy on "the other machine". */
  host?: string;
  port?: number;
}

export interface FakeMysql {
  port: number;
  logins: Array<{ user: string; ok: boolean; tls: boolean; path: string }>;
  received: () => Buffer;
  connections: () => number;
  close: () => Promise<void>;
}

class Feed {
  readonly r = new MyReader();
  private wake: (() => void) | null = null;
  private dead = false;
  constructor(private s: Duplex, onBytes: (b: Buffer) => void) {
    s.on("data", (c: Buffer) => { onBytes(c); this.r.feed(c); this.wake?.(); });
    s.on("close", () => { this.dead = true; this.wake?.(); });
    s.on("error", () => { this.dead = true; this.wake?.(); });
  }
  async take(): Promise<{ seq: number; payload: Buffer }> {
    for (;;) {
      const t = this.r.take(1 << 20);
      if (t !== null) return t;
      if (this.dead) throw new Error("closed");
      await new Promise<void>((res) => { this.wake = res; });
    }
  }
  detach(): void { this.s.removeAllListeners("data"); }
}

const scrambleBytes = (): Buffer => { const b = randomBytes(20); for (let i = 0; i < 20; i++) b[i] = (b[i]! % 0x7e) + 1; return b; };
const okPacket = (info = ""): Buffer => Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]), Buffer.from(info, "utf8")]);

export async function startFakeMysql(opts: FakeMysqlOptions): Promise<FakeMysql> {
  const chunks: Buffer[] = [];
  const logins: FakeMysql["logins"] = [];
  let connections = 0;
  let cached = opts.cached === true;
  const keys = generateKeyPairSync("rsa", { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const live = new Set<Duplex>();
  const server = createServer((sock: Socket) => {
    connections++;
    live.add(sock);
    sock.on("close", () => live.delete(sock));
    void serve(sock).catch(() => sock.destroy());
  });

  async function serve(raw: Socket): Promise<void> {
    let sock: Duplex = raw;
    let feed = new Feed(raw, (b) => chunks.push(b));
    const scramble = scrambleBytes();
    const caps = (CAP.PROTOCOL_41 | CAP.SECURE_CONNECTION | CAP.PLUGIN_AUTH | CAP.PLUGIN_AUTH_LENENC_CLIENT_DATA | CAP.CONNECT_WITH_DB | CAP.CONNECT_ATTRS | (opts.tls ? CAP.SSL : 0)) >>> 0;
    const plugin = opts.plugin === "native" ? NATIVE : CACHING_SHA2;
    sock.write(packet(0, serverHandshake({ serverVersion: "8.4.3-fake", connectionId: 9, scramble, capabilities: caps, charset: 255, status: 2, plugin })));
    let p = await feed.take();
    let resp = parseClientResponse(p.payload);
    let tls = false;
    if (resp?.ssl) {
      // No answer to an SSLRequest: the client's TLS hello may be read already.
      raw.pause();
      feed.detach();
      const t = new TLSSocket(prependChunk(raw, feed.r.rest()), { isServer: true, secureContext: createSecureContext(opts.tls!) });
      live.add(t);
      sock = t;
      feed = new Feed(t, (b) => chunks.push(b));
      tls = true;
      p = await feed.take();
      resp = parseClientResponse(p.payload);
    }
    if (!resp) { raw.destroy(); return; }
    let seq = p.seq;
    const fail = (path: string): void => {
      logins.push({ user: resp!.user, ok: false, tls, path });
      sock.end(packet(seq + 1, errPacket(`Access denied for user '${resp!.user}'`)));
    };
    if (resp.user !== opts.user) return fail("user");
    let usedPlugin = resp.plugin ?? NATIVE;
    let data = resp.authResponse;
    let sc = scramble;
    if (opts.switchToNative) {
      sc = scrambleBytes();
      sock.write(packet(seq + 1, authSwitch(NATIVE, Buffer.concat([sc, Buffer.from([0])]))));
      const q = await feed.take();
      seq = q.seq;
      data = q.payload;
      usedPlugin = NATIVE;
    }
    if (usedPlugin === NATIVE) {
      if (!nativePassword(opts.password, sc).equals(data)) return fail("native");
      logins.push({ user: resp.user, ok: true, tls, path: "native" });
    } else {
      if (!cachingSha2Password(opts.password, sc).equals(data)) return fail("sha2-scramble");
      if (cached) {
        sock.write(packet(++seq, Buffer.from([0x01, 0x03])));
        logins.push({ user: resp.user, ok: true, tls, path: "fast" });
      } else {
        sock.write(packet(++seq, Buffer.from([0x01, 0x04])));
        let q = await feed.take();
        seq = q.seq;
        let pw: string | null;
        if (tls) {
          pw = cleartextOf(q.payload);
        } else if (q.payload.length === 1 && q.payload[0] === 0x02) {
          sock.write(packet(++seq, Buffer.concat([Buffer.from([0x01]), Buffer.from(keys.publicKey)])));
          q = await feed.take();
          seq = q.seq;
          pw = rsaPasswordOf(q.payload, sc, keys.privateKey);
        } else {
          pw = null;
        }
        if (pw !== opts.password) return fail("full");
        cached = true;
        logins.push({ user: resp.user, ok: true, tls, path: "full" });
      }
    }
    sock.write(packet(seq + 1, okPacket()));
    for (;;) {
      const q = await feed.take();
      if (q.payload[0] === 0x01) { sock.end(); return; }
      if (q.payload[0] === 0x03) sock.write(packet(1, okPacket(`ECHO ${q.payload.toString("utf8", 1)}`)));
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

export interface MysqlResult {
  ok: boolean;
  info?: string;
  error?: string;
  received: Buffer;
}

/** Log in as `user` with `password`, run one query, quit. `tls`: ask for
 *  TLS (the client's ssl-mode REQUIRED), checking the certificate against
 *  `ca` when given. `publicKey`: ask for the server's RSA key on the full
 *  path without TLS (--get-server-public-key). */
export async function mysqlLogin(port: number, args: { user: string; password: string; database?: string; tls?: { ca?: string; servername?: string }; publicKey?: boolean; clientPlugin?: "native"; attr?: string }): Promise<MysqlResult> {
  const raw = netConnect(port, "127.0.0.1");
  await once(raw, "connect");
  const got: Buffer[] = [];
  let sock: Duplex = raw;
  let feed = new Feed(raw, (c) => got.push(c));
  const done = (r: Omit<MysqlResult, "received">): MysqlResult => { sock.destroy(); raw.destroy(); return { ...r, received: Buffer.concat(got) }; };
  try {
    const first = await feed.take();
    if (first.payload[0] === 0xff) return done({ ok: false, error: first.payload.toString("utf8", 9) });
    const h = parseServerHandshake(first.payload)!;
    const caps = (CAP.PROTOCOL_41 | CAP.SECURE_CONNECTION | CAP.PLUGIN_AUTH | CAP.PLUGIN_AUTH_LENENC_CLIENT_DATA | CAP.CONNECT_WITH_DB | CAP.LONG_PASSWORD | (args.attr ? CAP.CONNECT_ATTRS : 0)) >>> 0;
    // One connect attribute, `program_name` = args.attr.
    const attrs = args.attr ? (() => {
      const kv = Buffer.concat([lenencInt(12), Buffer.from("program_name"), lenencInt(Buffer.byteLength(args.attr!)), Buffer.from(args.attr!)]);
      return Buffer.concat([lenencInt(kv.length), kv]);
    })() : null;
    let seq = 0;
    let tls = false;
    if (args.tls) {
      if (!(h.capabilities & CAP.SSL)) return done({ ok: false, error: "the server does not offer TLS" });
      sock.write(packet(++seq, sslRequest(caps, 1 << 24, 45)));
      feed.detach();
      const t = tlsConnect({ socket: raw, ...(args.tls.ca ? { ca: args.tls.ca, servername: args.tls.servername } : { rejectUnauthorized: false }) });
      await once(t, "secureConnect");
      sock = t;
      feed = new Feed(t, (c) => got.push(c));
      tls = true;
    }
    let plugin = args.clientPlugin === "native" ? NATIVE : h.plugin;
    let sc = h.scramble;
    const answer = (name: string, data: Buffer): Buffer => (name === NATIVE ? nativePassword(args.password, data) : cachingSha2Password(args.password, data));
    sock.write(packet(++seq, clientResponse({ capabilities: tls ? (caps | CAP.SSL) >>> 0 : caps, maxPacket: 1 << 24, charset: 45, user: args.user, authResponse: answer(plugin, sc), database: args.database ?? "app", plugin, attrs })));
    for (;;) {
      const p = await feed.take();
      seq = p.seq;
      if (p.payload[0] === 0x00) break;
      if (p.payload[0] === 0xff) return done({ ok: false, error: p.payload.toString("utf8", 9) });
      if (p.payload[0] === 0xfe) {
        const sw = parseAuthSwitch(p.payload)!;
        plugin = sw.plugin;
        sc = sw.data;
        sock.write(packet(++seq, answer(plugin, sc)));
        continue;
      }
      if (p.payload[0] === 0x01 && p.payload[1] === 0x03) continue;
      if (p.payload[0] === 0x01 && p.payload[1] === 0x04) {
        if (tls) { sock.write(packet(++seq, Buffer.from(`${args.password}\0`))); continue; }
        if (!args.publicKey) return done({ ok: false, error: "Authentication requires secure connection." });
        sock.write(packet(++seq, Buffer.from([0x02])));
        const k = await feed.take();
        seq = k.seq;
        sock.write(packet(++seq, rsaPassword(args.password, sc, k.payload.toString("utf8", 1))));
        continue;
      }
      return done({ ok: false, error: `an auth packet the client does not read (${p.payload[0]})` });
    }
    sock.write(packet(0, Buffer.concat([Buffer.from([0x03]), Buffer.from("SELECT 1")])));
    const r = await feed.take();
    if (r.payload[0] === 0xff) return done({ ok: false, error: r.payload.toString("utf8", 9) });
    sock.write(packet(0, Buffer.from([0x01])));
    return done({ ok: true, info: r.payload.toString("utf8", 7) });
  } catch (err) {
    return done({ ok: false, error: (err as Error).message });
  }
}
