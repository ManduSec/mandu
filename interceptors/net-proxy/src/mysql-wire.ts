/**
 * mysql-wire — the PURE pieces of the MySQL client/server protocol the
 * database login release needs (db-relay.ts, db-login-release.md §8): packet
 * framing, the initial handshake, the client's handshake response, the
 * authentication packets, and the client side of the two password methods,
 * `mysql_native_password` and `caching_sha2_password` (its fast path's
 * scramble and its full path's RSA answer).
 *
 * Only the login is parsed. Once the server says OK the relay copies bytes
 * both ways and reads nothing.
 *
 * Pure: no socket. `MyReader` buffers bytes it is fed.
 *
 * Mandu-new (no reference origin).
 */

import { createHash, publicEncrypt, privateDecrypt, constants as cryptoConstants } from "node:crypto";

/** Capability flags (include/mysql_com.h). */
export const CAP = {
  LONG_PASSWORD: 0x1,
  CONNECT_WITH_DB: 0x8,
  COMPRESS: 0x20,
  PROTOCOL_41: 0x200,
  SSL: 0x800,
  SECURE_CONNECTION: 0x8000,
  PLUGIN_AUTH: 0x80000,
  CONNECT_ATTRS: 0x100000,
  PLUGIN_AUTH_LENENC_CLIENT_DATA: 0x200000,
  ZSTD_COMPRESSION: 0x4000000,
  /** `CLIENT_QUERY_ATTRIBUTES` and the rest are passed through as negotiated. */
} as const;

export const NATIVE = "mysql_native_password";
export const CACHING_SHA2 = "caching_sha2_password";
export const CLEAR = "mysql_clear_password";

/** The largest packet read during the login. */
export const MAX_LOGIN_PACKET = 64 * 1024;

export interface MyPacket {
  seq: number;
  payload: Buffer;
}

/** Buffers bytes and cuts them into packets (3-byte length, 1-byte
 *  sequence id). A length over `max` is an error (the caller refuses). */
export class MyReader {
  private buf: Buffer = Buffer.alloc(0);

  feed(chunk: Buffer): void {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
  }

  take(max = MAX_LOGIN_PACKET): MyPacket | null {
    if (this.buf.length < 4) return null;
    const len = this.buf.readUIntLE(0, 3);
    if (len > max) throw new Error(`a packet of ${len} bytes`);
    if (this.buf.length < 4 + len) return null;
    const seq = this.buf[3]!;
    const payload = Buffer.from(this.buf.subarray(4, 4 + len));
    this.buf = this.buf.subarray(4 + len);
    return { seq, payload };
  }

  rest(): Buffer {
    const r = this.buf;
    this.buf = Buffer.alloc(0);
    return r;
  }
}

/** One packet on the wire. */
export function packet(seq: number, payload: Buffer): Buffer {
  const head = Buffer.alloc(4);
  head.writeUIntLE(payload.length, 0, 3);
  head[3] = seq & 0xff;
  return Buffer.concat([head, payload]);
}

function cstringAt(buf: Buffer, at: number): { text: string; next: number } | null {
  const end = buf.indexOf(0, at);
  if (end < 0) return null;
  return { text: buf.toString("utf8", at, end), next: end + 1 };
}

/** A length-encoded integer at `at`, and the offset after it. */
export function lenencIntAt(buf: Buffer, at: number): { value: number; next: number } | null {
  const b = buf[at];
  if (b === undefined) return null;
  if (b < 0xfb) return { value: b, next: at + 1 };
  if (b === 0xfc) return at + 3 <= buf.length ? { value: buf.readUInt16LE(at + 1), next: at + 3 } : null;
  if (b === 0xfd) return at + 4 <= buf.length ? { value: buf.readUIntLE(at + 1, 3), next: at + 4 } : null;
  if (b === 0xfe) {
    if (at + 9 > buf.length) return null;
    const v = Number(buf.readBigUInt64LE(at + 1));
    return Number.isSafeInteger(v) ? { value: v, next: at + 9 } : null;
  }
  return null;
}

export function lenencInt(n: number): Buffer {
  if (n < 0xfb) return Buffer.from([n]);
  if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = 0xfc; b.writeUInt16LE(n, 1); return b; }
  if (n < 0x1000000) { const b = Buffer.alloc(4); b[0] = 0xfd; b.writeUIntLE(n, 1, 3); return b; }
  const b = Buffer.alloc(9); b[0] = 0xfe; b.writeBigUInt64LE(BigInt(n), 1); return b;
}

/** The server's initial handshake (protocol 10). */
export interface ServerHandshake {
  serverVersion: string;
  connectionId: number;
  /** The auth plugin data (the scramble), part 1 and 2 joined, NUL dropped. */
  scramble: Buffer;
  capabilities: number;
  charset: number;
  status: number;
  plugin: string;
}

export function parseServerHandshake(p: Buffer): ServerHandshake | null {
  if (p.length < 1 || p[0] !== 10) return null;
  const v = cstringAt(p, 1);
  if (!v) return null;
  let at = v.next;
  if (at + 4 + 8 + 1 + 2 > p.length) return null;
  const connectionId = p.readUInt32LE(at); at += 4;
  const part1 = p.subarray(at, at + 8); at += 8;
  at += 1; // filler
  let capabilities = p.readUInt16LE(at); at += 2;
  let charset = 0, status = 0, dataLen = 0;
  let part2: Buffer = Buffer.alloc(0);
  let plugin = NATIVE;
  if (at < p.length) {
    if (at + 1 + 2 + 2 + 1 + 10 > p.length) return null;
    charset = p[at]!; at += 1;
    status = p.readUInt16LE(at); at += 2;
    capabilities |= p.readUInt16LE(at) << 16; at += 2;
    capabilities >>>= 0;
    dataLen = p[at]!; at += 1;
    at += 10; // reserved
    if (capabilities & CAP.SECURE_CONNECTION) {
      const n = Math.max(13, dataLen - 8);
      if (at + n > p.length) return null;
      part2 = p.subarray(at, at + n); at += n;
    }
    if (capabilities & CAP.PLUGIN_AUTH) {
      const name = cstringAt(p, at) ?? { text: p.toString("utf8", at), next: p.length };
      plugin = name.text;
    }
  }
  let scramble = Buffer.concat([part1, part2]);
  if (scramble.length > 0 && scramble[scramble.length - 1] === 0) scramble = scramble.subarray(0, scramble.length - 1);
  return { serverVersion: v.text, connectionId, scramble, capabilities, charset, status, plugin };
}

/** The initial handshake the relay sends the client: the server's own
 *  values, the relay's scramble and plugin, the capabilities given. */
export function serverHandshake(h: ServerHandshake): Buffer {
  const scramble = h.scramble;
  const part1 = scramble.subarray(0, 8);
  const part2 = Buffer.concat([scramble.subarray(8), Buffer.from([0])]);
  const caps = Buffer.alloc(4);
  caps.writeUInt32LE(h.capabilities >>> 0, 0);
  const id = Buffer.alloc(4);
  id.writeUInt32LE(h.connectionId >>> 0, 0);
  const status = Buffer.alloc(2);
  status.writeUInt16LE(h.status, 0);
  return Buffer.concat([
    Buffer.from([10]), Buffer.from(`${h.serverVersion}\0`, "utf8"), id, part1, Buffer.from([0]),
    caps.subarray(0, 2), Buffer.from([h.charset]), status, caps.subarray(2, 4),
    Buffer.from([scramble.length + 1]), Buffer.alloc(10), part2, Buffer.from(`${h.plugin}\0`, "utf8"),
  ]);
}

/** The client's HandshakeResponse41 (or, 32 bytes long, its SSLRequest). */
export interface ClientResponse {
  capabilities: number;
  maxPacket: number;
  charset: number;
  /** An SSLRequest: the handshake response follows inside TLS. */
  ssl: boolean;
  user: string;
  authResponse: Buffer;
  database: string | null;
  plugin: string | null;
  /** The connect attributes as written (lenenc block), or null. */
  attrs: Buffer | null;
}

export function parseClientResponse(p: Buffer): ClientResponse | null {
  if (p.length < 32) return null;
  const capabilities = p.readUInt32LE(0) >>> 0;
  if (!(capabilities & CAP.PROTOCOL_41)) return null;
  const maxPacket = p.readUInt32LE(4);
  const charset = p[8]!;
  if (p.length === 32) {
    return (capabilities & CAP.SSL) ? { capabilities, maxPacket, charset, ssl: true, user: "", authResponse: Buffer.alloc(0), database: null, plugin: null, attrs: null } : null;
  }
  let at = 32;
  const user = cstringAt(p, at);
  if (!user) return null;
  at = user.next;
  let authResponse: Buffer;
  if (capabilities & CAP.PLUGIN_AUTH_LENENC_CLIENT_DATA) {
    const n = lenencIntAt(p, at);
    if (!n || n.next + n.value > p.length) return null;
    authResponse = p.subarray(n.next, n.next + n.value); at = n.next + n.value;
  } else if (capabilities & CAP.SECURE_CONNECTION) {
    const n = p[at];
    if (n === undefined || at + 1 + n > p.length) return null;
    authResponse = p.subarray(at + 1, at + 1 + n); at += 1 + n;
  } else {
    const s = cstringAt(p, at);
    if (!s) return null;
    authResponse = p.subarray(at, s.next - 1); at = s.next;
  }
  let database: string | null = null;
  if (capabilities & CAP.CONNECT_WITH_DB && at < p.length) {
    const s = cstringAt(p, at);
    if (!s) return null;
    database = s.text; at = s.next;
  }
  let plugin: string | null = null;
  if (capabilities & CAP.PLUGIN_AUTH && at < p.length) {
    const s = cstringAt(p, at) ?? { text: p.toString("utf8", at), next: p.length };
    plugin = s.text; at = s.next;
  }
  let attrs: Buffer | null = null;
  if (capabilities & CAP.CONNECT_ATTRS && at < p.length) {
    const n = lenencIntAt(p, at);
    if (!n || n.next + n.value > p.length) return null;
    attrs = p.subarray(at, n.next + n.value); at = n.next + n.value;
  }
  return { capabilities, maxPacket, charset, ssl: false, user: user.text, authResponse: Buffer.from(authResponse), database, plugin, attrs };
}

function head32(caps: number, maxPacket: number, charset: number): Buffer {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(caps >>> 0, 0);
  b.writeUInt32LE(maxPacket >>> 0, 4);
  b[8] = charset;
  return b;
}

/** The SSLRequest the relay sends the server. */
export function sslRequest(caps: number, maxPacket: number, charset: number): Buffer {
  return head32(caps | CAP.SSL, maxPacket, charset);
}

/** The HandshakeResponse41 the relay sends the server. */
export function clientResponse(r: Omit<ClientResponse, "ssl">): Buffer {
  const parts = [head32(r.capabilities, r.maxPacket, r.charset), Buffer.from(`${r.user}\0`, "utf8")];
  if (r.capabilities & CAP.PLUGIN_AUTH_LENENC_CLIENT_DATA) parts.push(lenencInt(r.authResponse.length), r.authResponse);
  else parts.push(Buffer.from([r.authResponse.length]), r.authResponse);
  if (r.capabilities & CAP.CONNECT_WITH_DB) parts.push(Buffer.from(`${r.database ?? ""}\0`, "utf8"));
  if (r.capabilities & CAP.PLUGIN_AUTH) parts.push(Buffer.from(`${r.plugin ?? ""}\0`, "utf8"));
  if (r.capabilities & CAP.CONNECT_ATTRS) parts.push(r.attrs ?? lenencInt(0));
  return Buffer.concat(parts);
}

/** An ERR packet's message, for the log. */
export function errText(p: Buffer): string {
  if (p[0] !== 0xff || p.length < 3) return "(no message)";
  let at = 3;
  if (p[at] === 0x23) at += 6; // '#' + sqlstate
  return p.toString("utf8", at);
}

/** An ERR packet (code 1045, access denied, unless given). */
export function errPacket(text: string, code = 1045, sqlstate = "28000"): Buffer {
  const c = Buffer.alloc(2);
  c.writeUInt16LE(code, 0);
  return Buffer.concat([Buffer.from([0xff]), c, Buffer.from(`#${sqlstate}`, "latin1"), Buffer.from(text, "utf8")]);
}

/** An AuthSwitchRequest: the plugin to use and its data. */
export function authSwitch(plugin: string, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0xfe]), Buffer.from(`${plugin}\0`, "utf8"), data]);
}

export function parseAuthSwitch(p: Buffer): { plugin: string; data: Buffer } | null {
  if (p[0] !== 0xfe || p.length < 2) return null;
  const s = cstringAt(p, 1);
  if (!s) return null;
  let data = p.subarray(s.next);
  if (data.length > 0 && data[data.length - 1] === 0) data = data.subarray(0, data.length - 1);
  return { plugin: s.text, data: Buffer.from(data) };
}

const sha1 = (...b: Buffer[]): Buffer => { const h = createHash("sha1"); for (const x of b) h.update(x); return h.digest(); };
const sha256 = (...b: Buffer[]): Buffer => { const h = createHash("sha256"); for (const x of b) h.update(x); return h.digest(); };

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i % b.length]!;
  return out;
}

/** `mysql_native_password`: SHA1(pw) XOR SHA1(scramble ‖ SHA1(SHA1(pw))).
 *  An empty password answers nothing. */
export function nativePassword(password: string, scramble: Buffer): Buffer {
  if (password === "") return Buffer.alloc(0);
  const s1 = sha1(Buffer.from(password, "utf8"));
  return xor(s1, sha1(scramble.subarray(0, 20), sha1(s1)));
}

/** `caching_sha2_password`'s fast answer: SHA256(pw) XOR
 *  SHA256(SHA256(SHA256(pw)) ‖ scramble). */
export function cachingSha2Password(password: string, scramble: Buffer): Buffer {
  if (password === "") return Buffer.alloc(0);
  const m1 = sha256(Buffer.from(password, "utf8"));
  return xor(m1, sha256(sha256(m1), scramble.subarray(0, 20)));
}

/** The full path's RSA answer: (pw ‖ NUL) XOR scramble, RSA-OAEP under the
 *  server's public key. */
export function rsaPassword(password: string, scramble: Buffer, publicKeyPem: string): Buffer {
  const plain = xor(Buffer.from(`${password}\0`, "utf8"), scramble.subarray(0, 20));
  return publicEncrypt({ key: publicKeyPem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING }, plain);
}

/** The inverse, for the relay's own key (the client's side of the full
 *  path when there is no TLS): the password, or null. */
export function rsaPasswordOf(encrypted: Buffer, scramble: Buffer, privateKeyPem: string): string | null {
  let plain: Buffer;
  try {
    plain = privateDecrypt({ key: privateKeyPem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING }, encrypted);
  } catch {
    return null;
  }
  const pw = xor(plain, scramble.subarray(0, 20));
  const nul = pw.indexOf(0);
  return pw.toString("utf8", 0, nul < 0 ? pw.length : nul);
}

/** A cleartext password answer (the full path over TLS, or
 *  `mysql_clear_password`): the password up to its NUL, or null. */
export function cleartextOf(p: Buffer): string | null {
  const nul = p.indexOf(0);
  if (nul !== p.length - 1) return null;
  return p.toString("utf8", 0, nul);
}
