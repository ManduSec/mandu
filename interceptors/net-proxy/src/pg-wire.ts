/**
 * pg-wire — the PURE pieces of the Postgres frontend/backend protocol (v3)
 * the database login release needs (db-relay.ts; docs/design/confidentiality/
 * db-login-release.md): the startup packets, message framing, the
 * authentication messages, and the client side of the two password methods,
 * md5 and SCRAM-SHA-256 (RFC 5802 / RFC 7677).
 *
 * Only the login is parsed. Once the server says AuthenticationOk the relay
 * copies bytes both ways and reads nothing.
 *
 * Pure: no socket, no clock. `PgReader` buffers bytes it is fed; the relay
 * feeds it from a socket.
 *
 * Mandu-new (no reference origin).
 */

import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";

/** The startup packet codes (protocol.html, "Message Formats"). */
export const SSL_REQUEST_CODE = 80877103;
export const GSSENC_REQUEST_CODE = 80877104;
export const CANCEL_REQUEST_CODE = 80877102;
/** Protocol major version 3, in the startup packet's high 16 bits. */
export const PROTOCOL_MAJOR = 3;

/** A startup packet larger than this is no client's (libpq's own limit is
 *  10 000): refused before it is buffered. */
export const MAX_STARTUP_BYTES = 10_000;
/** The largest message read during the login (an ErrorResponse, a SASL
 *  exchange). After the login nothing is parsed. */
export const MAX_LOGIN_MESSAGE_BYTES = 64 * 1024;

/** The authentication request codes ('R' messages) the relay meets. */
export const AUTH = {
  ok: 0,
  kerberosV5: 2,
  cleartext: 3,
  md5: 5,
  gss: 7,
  gssContinue: 8,
  sspi: 9,
  sasl: 10,
  saslContinue: 11,
  saslFinal: 12,
} as const;

export type StartupPacket =
  | { kind: "ssl" }
  | { kind: "gssenc" }
  | { kind: "cancel"; raw: Buffer }
  | { kind: "startup"; major: number; minor: number; params: Map<string, string>; raw: Buffer }
  | { kind: "invalid"; reason: string };

/** Parse one whole startup packet (its length word included). Pure. */
export function parseStartupPacket(raw: Buffer): StartupPacket {
  if (raw.length < 8) return { kind: "invalid", reason: "a startup packet shorter than 8 bytes" };
  const len = raw.readInt32BE(0);
  if (len !== raw.length) return { kind: "invalid", reason: "a startup packet whose length word does not match" };
  const code = raw.readInt32BE(4);
  if (code === SSL_REQUEST_CODE && len === 8) return { kind: "ssl" };
  if (code === GSSENC_REQUEST_CODE && len === 8) return { kind: "gssenc" };
  if (code === CANCEL_REQUEST_CODE && len === 16) return { kind: "cancel", raw };
  const major = code >>> 16;
  const minor = code & 0xffff;
  if (major !== PROTOCOL_MAJOR) return { kind: "invalid", reason: `protocol version ${major}.${minor} (only 3.x is spoken)` };
  const params = new Map<string, string>();
  let at = 8;
  while (at < raw.length) {
    if (raw[at] === 0) {
      if (at !== raw.length - 1) return { kind: "invalid", reason: "bytes after the startup packet's terminator" };
      return params.has("user") ? { kind: "startup", major, minor, params, raw } : { kind: "invalid", reason: "a startup packet with no user" };
    }
    const k = cstring(raw, at);
    if (!k) return { kind: "invalid", reason: "an unterminated startup parameter" };
    const v = cstring(raw, k.next);
    if (!v) return { kind: "invalid", reason: "an unterminated startup parameter" };
    params.set(k.text, v.text);
    at = v.next;
  }
  return { kind: "invalid", reason: "a startup packet with no terminator" };
}

/** A NUL-terminated UTF-8 string at `at`, and the offset after its NUL. */
function cstring(buf: Buffer, at: number): { text: string; next: number } | null {
  const end = buf.indexOf(0, at);
  if (end < 0) return null;
  return { text: buf.toString("utf8", at, end), next: end + 1 };
}

/** One backend or frontend message after the startup: its type byte, its
 *  body, and the whole message as it was on the wire. */
export interface PgMessage {
  type: string;
  body: Buffer;
  raw: Buffer;
}

/**
 * Buffers bytes and cuts them into startup packets or typed messages. A
 * length out of bounds is an error (the caller refuses the connection);
 * nothing is ever read past what was fed.
 */
export class PgReader {
  private buf: Buffer = Buffer.alloc(0);

  feed(chunk: Buffer): void {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
  }

  /** A whole startup packet, or null until it has arrived. Throws on a
   *  length out of bounds. */
  takeStartup(): Buffer | null {
    if (this.buf.length < 4) return null;
    const len = this.buf.readInt32BE(0);
    if (len < 8 || len > MAX_STARTUP_BYTES) throw new Error(`a startup packet of ${len} bytes`);
    if (this.buf.length < len) return null;
    const raw = this.buf.subarray(0, len);
    this.buf = this.buf.subarray(len);
    return Buffer.from(raw);
  }

  /** A whole typed message, or null until it has arrived. Throws on a
   *  length out of bounds. */
  takeMessage(max = MAX_LOGIN_MESSAGE_BYTES): PgMessage | null {
    if (this.buf.length < 5) return null;
    const len = this.buf.readInt32BE(1);
    if (len < 4 || len > max) throw new Error(`a message of ${len} bytes`);
    if (this.buf.length < len + 1) return null;
    const raw = Buffer.from(this.buf.subarray(0, len + 1));
    this.buf = this.buf.subarray(len + 1);
    return { type: String.fromCharCode(raw[0]!), body: raw.subarray(5), raw };
  }

  /** The bytes fed and not taken (handed on when the relay starts copying). */
  rest(): Buffer {
    const r = this.buf;
    this.buf = Buffer.alloc(0);
    return r;
  }
}

/** A typed message: type byte, length word (itself included), body. */
export function message(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head.write(type, 0, "latin1");
  head.writeInt32BE(body.length + 4, 1);
  return Buffer.concat([head, body]);
}

function int32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeInt32BE(n, 0);
  return b;
}

function cstr(s: string): Buffer {
  return Buffer.concat([Buffer.from(s, "utf8"), Buffer.from([0])]);
}

/** The SSLRequest a client (here, the relay toward the server) sends. */
export function sslRequest(): Buffer {
  return Buffer.concat([int32(8), int32(SSL_REQUEST_CODE)]);
}

/** An authentication request ('R') with its code and any extra bytes. */
export function authRequest(code: number, extra: Buffer = Buffer.alloc(0)): Buffer {
  return message("R", Buffer.concat([int32(code), extra]));
}

/** A PasswordMessage ('p') carrying a NUL-terminated password (cleartext
 *  or md5). */
export function passwordMessage(password: string): Buffer {
  return message("p", cstr(password));
}

/** SASLInitialResponse ('p'): the mechanism and the client-first-message. */
export function saslInitialResponse(mechanism: string, data: string): Buffer {
  const d = Buffer.from(data, "utf8");
  return message("p", Buffer.concat([cstr(mechanism), int32(d.length), d]));
}

/** SASLResponse ('p'): the client-final-message. */
export function saslResponse(data: string): Buffer {
  return message("p", Buffer.from(data, "utf8"));
}

/**
 * An ErrorResponse ('E') with severity FATAL, the SQLSTATE `code` and a
 * message. Every refusal the relay makes reaches the client as one, so
 * `psql` prints the reason (`psql: error: … FATAL: mandu: …`).
 */
export function errorResponse(code: string, text: string): Buffer {
  return message("E", Buffer.concat([
    Buffer.from("S"), cstr("FATAL"),
    Buffer.from("V"), cstr("FATAL"),
    Buffer.from("C"), cstr(code),
    Buffer.from("M"), cstr(text),
    Buffer.from([0]),
  ]));
}

/** An 'R' message's code and the bytes after it. Null when too short. */
export function parseAuth(body: Buffer): { code: number; data: Buffer } | null {
  if (body.length < 4) return null;
  return { code: body.readInt32BE(0), data: body.subarray(4) };
}

/** The mechanisms an AuthenticationSASL lists. */
export function saslMechanisms(data: Buffer): string[] {
  const out: string[] = [];
  let at = 0;
  while (at < data.length && data[at] !== 0) {
    const s = cstring(data, at);
    if (!s) break;
    out.push(s.text);
    at = s.next;
  }
  return out;
}

/** The password a client's PasswordMessage carries (the reply to a
 *  cleartext request), or null when the body is no NUL-terminated string. */
export function passwordOf(body: Buffer): string | null {
  if (body.length === 0 || body[body.length - 1] !== 0) return null;
  const s = body.toString("utf8", 0, body.length - 1);
  return s.includes("\u0000") ? null : s;
}

/** An ErrorResponse's message field (`M`), for the log. */
export function errorText(body: Buffer): string {
  let at = 0;
  while (at < body.length && body[at] !== 0) {
    const field = String.fromCharCode(body[at]!);
    const s = cstring(body, at + 1);
    if (!s) break;
    if (field === "M") return s.text;
    at = s.next;
  }
  return "(no message)";
}

// ── md5 (AuthenticationMD5Password) ─────────────────────────────────────────

const md5hex = (b: Buffer | string): string => createHash("md5").update(b).digest("hex");

/** The md5 method's answer: `md5` + md5(md5(password ‖ user) ‖ salt). */
export function md5Password(user: string, password: string, salt: Buffer): string {
  const inner = md5hex(Buffer.from(password + user, "utf8"));
  return `md5${md5hex(Buffer.concat([Buffer.from(inner, "latin1"), salt]))}`;
}

// ── SCRAM-SHA-256 (RFC 5802, RFC 7677) ──────────────────────────────────────

/**
 * The password as SCRAM hashes it. libpq runs SASLprep (RFC 4013) and uses
 * the password as it is when SASLprep fails. Here: an ASCII password is
 * used as it is (SASLprep leaves printable ASCII unchanged); any other is
 * NFKC-normalized with the non-ASCII spaces mapped to a space and the
 * "commonly mapped to nothing" characters dropped, SASLprep's steps for
 * the passwords people type. A password SASLprep would reject (a control
 * or unassigned character) is used as it is, as libpq does.
 */
export function saslPrep(password: string): string {
  if (/^[\x20-\x7e]*$/.test(password)) return password;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(password)) return password;
  const mapped = password
    .replace(/[   -​  　]/g, " ")
    .replace(/[­͏᠆᠋-᠍‌‍⁠︀-️﻿]/g, "");
  return mapped.normalize("NFKC");
}

const hmac = (key: Buffer, data: string | Buffer): Buffer => createHmac("sha256", key).update(data).digest();
const sha256 = (data: Buffer): Buffer => createHash("sha256").update(data).digest();

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/** The fields of a SCRAM message (`k=v,k=v`). */
function scramFields(msg: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of msg.split(",")) {
    const eq = part.indexOf("=");
    if (eq !== 1) continue;
    if (!out.has(part[0]!)) out.set(part[0]!, part.slice(2));
  }
  return out;
}

/** The highest iteration count accepted from a server (Postgres uses 4096;
 *  a hostile server's huge count would hold the relay's CPU). */
export const SCRAM_MAX_ITERATIONS = 1_000_000;
/** The lowest: Postgres's own default. A server asking for fewer makes the
 *  client proof cheap to attack offline (security review 2026-10-24). */
export const SCRAM_MIN_ITERATIONS = 4096;

/**
 * The client side of SCRAM-SHA-256, without channel binding (gs2 header
 * `n,,`). `first()` → client-first-message; `final(serverFirst)` →
 * client-final-message (throws when the server's message is malformed or
 * its nonce does not extend ours); `verify(serverFinal)` → whether the
 * server proved it knows the password (the relay refuses the connection
 * when it did not).
 *
 * `user` is the SCRAM user name: Postgres ignores it (the startup packet's
 * user counts) and libpq sends it empty.
 */
export class ScramClient {
  private readonly nonce: string;
  private readonly user: string;
  private clientFirstBare = "";
  private serverSignature: Buffer | null = null;

  constructor(private readonly password: string, opts: { nonce?: string; user?: string } = {}) {
    this.nonce = opts.nonce ?? randomBytes(18).toString("base64");
    this.user = opts.user ?? "";
  }

  first(): string {
    const name = this.user.replace(/=/g, "=3D").replace(/,/g, "=2C");
    this.clientFirstBare = `n=${name},r=${this.nonce}`;
    return `n,,${this.clientFirstBare}`;
  }

  final(serverFirst: string): string {
    const f = scramFields(serverFirst);
    const r = f.get("r");
    const s = f.get("s");
    const i = Number(f.get("i"));
    if (f.has("e")) throw new Error(`the server refused SCRAM: ${f.get("e")}`);
    if (!r || !s || !Number.isInteger(i)) throw new Error("a malformed SCRAM server-first-message");
    if (!r.startsWith(this.nonce) || r.length <= this.nonce.length) throw new Error("the server's SCRAM nonce does not extend the client's");
    if (i < SCRAM_MIN_ITERATIONS || i > SCRAM_MAX_ITERATIONS) throw new Error(`a SCRAM iteration count of ${i} (Mandu accepts ${SCRAM_MIN_ITERATIONS} to ${SCRAM_MAX_ITERATIONS})`);
    const salt = Buffer.from(s, "base64");
    if (salt.length === 0) throw new Error("an empty SCRAM salt");
    const salted = pbkdf2Sync(saslPrep(this.password), salt, i, 32, "sha256");
    const clientKey = hmac(salted, "Client Key");
    const storedKey = sha256(clientKey);
    const withoutProof = `c=biws,r=${r}`;
    const authMessage = `${this.clientFirstBare},${serverFirst},${withoutProof}`;
    const clientSignature = hmac(storedKey, authMessage);
    const proof = xor(clientKey, clientSignature).toString("base64");
    const serverKey = hmac(salted, "Server Key");
    this.serverSignature = hmac(serverKey, authMessage);
    return `${withoutProof},p=${proof}`;
  }

  verify(serverFinal: string): boolean {
    if (this.serverSignature === null) return false;
    const f = scramFields(serverFinal);
    const v = f.get("v");
    if (f.has("e") || !v) return false;
    const got = Buffer.from(v, "base64");
    return got.length === this.serverSignature.length && timingSafeEqual(got, this.serverSignature);
  }
}
