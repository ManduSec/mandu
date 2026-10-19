/**
 * pdf-text — the text layer of a PDF, in reading order, for the content
 * tier's personal documents (2026-10-19, docs/design/confidentiality/
 * secret-discovery.md §2.8). Pure over a byte buffer: it opens no file
 * (document-text.ts reads one safely), keeps nothing and sends nothing.
 *
 * WHAT IT READS. Every object of the file in order (`n g obj … endobj`, so
 * a broken or missing cross-reference table does not matter), the objects
 * inside object streams, the trailer (`trailer` or a cross-reference
 * stream's dictionary). The page tree from the catalog, each page's content
 * streams and the Form XObjects they draw (depth 6), and the filled-in
 * values of the form's fields (`/AcroForm`, `TU` or `T`: `V`), after the
 * pages. Filters: Flate (with PNG and TIFF predictors), ASCIIHex, ASCII85,
 * LZW, RunLength; an image filter (DCT, JPX, CCITT, JBIG2) is an image,
 * never text.
 *
 * THE TEXT. Each shown string (`Tj`, `TJ`, `'`, `"`) is decoded through its
 * font: a `ToUnicode` CMap first (code-space ranges, `bfchar`, `bfrange`),
 * else a simple font's encoding (WinAnsi, MacRoman, Standard, with
 * `Differences` by glyph name); a composite font with no `ToUnicode` gives no
 * text (its codes are glyph ids). Each string becomes a chunk placed by the
 * text and current transformation matrices (and the page's `/Rotate`); a
 * page's chunks are grouped into lines by baseline, ordered top to bottom
 * and left to right, joined with a blank where the gap is a word space, and
 * split into CELLS where it is wider than a column gap (1.2 em). A line of
 * cells is rendered as document-text.ts `renderRow` renders a table row
 * (`Label: value`, or cells joined by ` | `), so a statement's
 * `Account number      0042-118833-77` reads `Account number: 0042-118833-77`.
 *
 * ENCRYPTION. The standard security handler with an EMPTY user password
 * (a bank's statement is often "encrypted" only to restrict printing): RC4
 * 40 and 128 (R2-R4), AES-128 (V4 AESV2), AES-256 (R5, R6). A file that
 * needs a password is `encrypted`, never read; so is another handler.
 *
 * WHAT IS NOT TEXT. A scanned page (an image, no text layer) gives none:
 * `no-text`. Text drawn as vector outlines, a Type3 font with no encoding,
 * a composite font with no `ToUnicode`: none. Annotations' appearance
 * streams other than a field's value are not read.
 *
 * THE BOUNDS. The caller caps the file (document-text.ts). Here: each
 * stream inflates to at most 8 MiB and all of them to 32 MiB, at most
 * 200,000 objects, 1,000 pages, 2,000,000 content operators, 200,000
 * chunks, 2,000 form fields; the text at most `textMax` UTF-8 bytes (past
 * it, `too-long`). Never throws: what cannot be read is `unreadable` with a
 * short reason (no file text in it).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin). The R6 key derivation follows ISO 32000-2 §7.6.4.3.4
 * (Algorithm 2.B); the encodings are the tables of ISO 32000-1 Annex D.
 */
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { constants as zlibConstants, inflateRawSync, inflateSync } from "node:zlib";

/** The bounds (see the module comment). */
export const PDF_TEXT_LIMITS = {
  streamOutMax: 8 * 1024 * 1024,
  totalOutMax: 32 * 1024 * 1024,
  objectsMax: 200_000,
  pagesMax: 1_000,
  opsMax: 2_000_000,
  chunksMax: 200_000,
  fieldsMax: 2_000,
  formDepthMax: 6,
} as const;

export type PdfTextRead =
  | { kind: "text"; text: string; pages: number }
  /** No text layer (a scanned document), or too little text to read. */
  | { kind: "no-text"; pages: number }
  /** A password is needed (or a security handler other than the standard
   *  one): not read. */
  | { kind: "encrypted" }
  | { kind: "too-long" }
  | { kind: "unreadable"; reason: string };

// ── Values ───────────────────────────────────────────────────────────────────

class PName { constructor(readonly n: string) {} }
/** A string's bytes, one character per byte (latin1). */
class PStr { constructor(readonly b: string) {} }
class PRef { constructor(readonly num: number, readonly gen: number) {} }
class POp { constructor(readonly op: string) {} }
type PDict = Map<string, PVal>;
type PVal = null | boolean | number | PName | PStr | PRef | PVal[] | PDict | PStream;
interface PStream { dict: PDict; start: number; end: number; num: number; gen: number; inStm: false }
type PObj = { val: PVal; pos: number; num: number; gen: number; inStm: boolean };

const isDict = (v: unknown): v is PDict => v instanceof Map;
const isStream = (v: unknown): v is PStream => typeof v === "object" && v !== null && !(v instanceof Map) && !Array.isArray(v) && "dict" in (v as object) && "start" in (v as object);
const nameOf = (v: unknown): string | null => (v instanceof PName ? v.n : null);
const numOf = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

class TooLong extends Error {}
class Bad extends Error {}

// ── The lexer (objects and content streams share it) ────────────────────────

const WS = new Set([0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20]);
const DELIM = new Set([0x28, 0x29, 0x3c, 0x3e, 0x5b, 0x5d, 0x7b, 0x7d, 0x2f, 0x25]);

class Lexer {
  pos: number;
  constructor(readonly s: string, pos = 0, readonly end = s.length) { this.pos = pos; }

  skipWs(): void {
    const s = this.s;
    while (this.pos < this.end) {
      const c = s.charCodeAt(this.pos);
      if (WS.has(c)) { this.pos++; continue; }
      if (c === 0x25) { // comment
        while (this.pos < this.end && s.charCodeAt(this.pos) !== 0x0a && s.charCodeAt(this.pos) !== 0x0d) this.pos++;
        continue;
      }
      break;
    }
  }

  /** The next regular-character run (a number, a keyword, an operator). */
  word(): string {
    const st = this.pos;
    while (this.pos < this.end) {
      const c = this.s.charCodeAt(this.pos);
      if (WS.has(c) || DELIM.has(c)) break;
      this.pos++;
    }
    return this.s.slice(st, this.pos);
  }

  literal(): PStr {
    // at `(`
    const s = this.s;
    this.pos++;
    let depth = 1;
    let out = "";
    while (this.pos < this.end) {
      const c = s[this.pos++]!;
      if (c === "\\") {
        const n = s[this.pos++];
        if (n === undefined) break;
        switch (n) {
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "\r": if (s[this.pos] === "\n") this.pos++; break;
          case "\n": break;
          default:
            if (n >= "0" && n <= "7") {
              let o = n;
              for (let k = 0; k < 2 && s[this.pos]! >= "0" && s[this.pos]! <= "7"; k++) o += s[this.pos++];
              out += String.fromCharCode(parseInt(o, 8) & 0xff);
            } else out += n;
        }
        continue;
      }
      if (c === "(") depth++;
      else if (c === ")") { if (--depth === 0) break; }
      out += c;
    }
    return new PStr(out);
  }

  hex(): PStr {
    // at `<` (not `<<`)
    this.pos++;
    const close = this.s.indexOf(">", this.pos);
    const stop = close < 0 || close > this.end ? this.end : close;
    const h = this.s.slice(this.pos, stop).replace(/[^0-9A-Fa-f]/g, "");
    this.pos = stop + 1;
    let out = "";
    for (let i = 0; i < h.length; i += 2) out += String.fromCharCode(parseInt(h.slice(i, i + 2).padEnd(2, "0"), 16));
    return new PStr(out);
  }

  name(): PName {
    this.pos++;
    const w = this.word();
    return new PName(w.includes("#") ? w.replace(/#([0-9A-Fa-f]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16))) : w);
  }

  /** One object value (`refs`: `n g R` is a reference; off in content
   *  streams). Undefined at the end, at a stray delimiter (consumed), or at
   *  a keyword (consumed; `this.lastWord` names it). */
  lastWord = "";
  value(refs: boolean, depth = 0): PVal | undefined {
    if (depth > 64) throw new Bad("nesting too deep");
    this.lastWord = "";
    this.skipWs();
    if (this.pos >= this.end) return undefined;
    const s = this.s;
    const c = s[this.pos]!;
    if (c === "/") return this.name();
    if (c === "(") return this.literal();
    if (c === "<") {
      if (s[this.pos + 1] === "<") {
        this.pos += 2;
        const d: PDict = new Map();
        for (;;) {
          this.skipWs();
          if (this.pos >= this.end) break;
          if (s[this.pos] === ">" && s[this.pos + 1] === ">") { this.pos += 2; break; }
          if (s[this.pos] !== "/") { // junk: skip one value (a keyword is consumed)
            this.value(refs, depth + 1);
            continue;
          }
          const k = this.name().n;
          const v = this.value(refs, depth + 1);
          if (v === undefined) continue;
          d.set(k, v);
        }
        return d;
      }
      return this.hex();
    }
    if (c === "[") {
      this.pos++;
      const a: PVal[] = [];
      for (;;) {
        this.skipWs();
        if (this.pos >= this.end) break;
        if (s[this.pos] === "]") { this.pos++; break; }
        const v = this.value(refs, depth + 1);
        if (v === undefined) continue;
        a.push(v);
        if (a.length > 1_000_000) throw new Bad("array too long");
      }
      return a;
    }
    if (c === ")" || c === ">" || c === "]" || c === "{" || c === "}") { this.pos++; return undefined; }
    const w = this.word();
    if (w === "") { this.pos++; return undefined; }
    if (/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(w)) {
      const n = Number(w);
      if (refs && /^\d+$/.test(w)) {
        // `n g R`?
        const save = this.pos;
        this.skipWs();
        const g = this.word();
        if (/^\d+$/.test(g)) {
          this.skipWs();
          if (this.s[this.pos] === "R" && (this.pos + 1 >= this.end || WS.has(this.s.charCodeAt(this.pos + 1)) || DELIM.has(this.s.charCodeAt(this.pos + 1)))) {
            this.pos++;
            return new PRef(n, Number(g));
          }
        }
        this.pos = save;
      }
      return n;
    }
    if (w === "true") return true;
    if (w === "false") return false;
    if (w === "null") return null;
    this.lastWord = w;
    return undefined;
  }
}

// ── Filters ──────────────────────────────────────────────────────────────────

class Budget {
  out = 0;
  take(n: number): void {
    this.out += n;
    if (this.out > PDF_TEXT_LIMITS.totalOutMax) throw new Bad("streams inflate past the limit");
  }
}

function flate(b: Buffer): Buffer {
  const opts = { maxOutputLength: PDF_TEXT_LIMITS.streamOutMax, finishFlush: zlibConstants.Z_SYNC_FLUSH };
  try {
    return inflateSync(b, opts);
  } catch (err) {
    if ((err as { code?: string }).code === "ERR_BUFFER_TOO_LARGE") throw new Bad("a stream inflates past its limit");
    try { return inflateRawSync(b, opts); } catch { throw new Bad("a stream cannot be inflated"); }
  }
}

function asciiHex(b: Buffer): Buffer {
  const h = b.toString("latin1").split(">")[0]!.replace(/[^0-9A-Fa-f]/g, "");
  return Buffer.from(h.length % 2 ? `${h}0` : h, "hex");
}

function ascii85(b: Buffer): Buffer {
  let s = b.toString("latin1").replace(/\s+/g, "");
  if (s.startsWith("<~")) s = s.slice(2);
  const end = s.indexOf("~>");
  if (end >= 0) s = s.slice(0, end);
  const out: number[] = [];
  let tuple: number[] = [];
  for (const ch of s) {
    if (ch === "z" && tuple.length === 0) { out.push(0, 0, 0, 0); continue; }
    const c = ch.charCodeAt(0) - 33;
    if (c < 0 || c > 84) continue;
    tuple.push(c);
    if (tuple.length === 5) {
      let v = 0;
      for (const t of tuple) v = v * 85 + t;
      out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
      tuple = [];
    }
  }
  if (tuple.length > 1) {
    const n = tuple.length;
    while (tuple.length < 5) tuple.push(84);
    let v = 0;
    for (const t of tuple) v = v * 85 + t;
    const bytes = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
    out.push(...bytes.slice(0, n - 1));
  }
  return Buffer.from(out);
}

function lzw(b: Buffer, early: number): Buffer {
  const out: number[] = [];
  let dict: number[][] = [];
  const reset = (): void => { dict = []; for (let i = 0; i < 256; i++) dict.push([i]); dict.push([], []); };
  reset();
  let bits = 9;
  let buf = 0;
  let nbits = 0;
  let prev: number[] | null = null;
  for (let i = 0; i < b.length; i++) {
    buf = (buf << 8) | b[i]!;
    nbits += 8;
    while (nbits >= bits) {
      const code = (buf >>> (nbits - bits)) & ((1 << bits) - 1);
      nbits -= bits;
      buf &= (1 << nbits) - 1;
      if (code === 256) { reset(); bits = 9; prev = null; continue; }
      if (code === 257) return Buffer.from(out);
      let entry: number[];
      if (code < dict.length && dict[code]!.length > 0) entry = dict[code]!;
      else if (prev !== null && code === dict.length) entry = [...prev, prev[0]!];
      else return Buffer.from(out);
      out.push(...entry);
      if (out.length > PDF_TEXT_LIMITS.streamOutMax) throw new Bad("a stream inflates past its limit");
      if (prev !== null) dict.push([...prev, entry[0]!]);
      prev = entry;
      if (dict.length + early >= 1 << bits && bits < 12) bits++;
    }
  }
  return Buffer.from(out);
}

function runLength(b: Buffer): Buffer {
  const out: number[] = [];
  for (let i = 0; i < b.length;) {
    const n = b[i++]!;
    if (n === 128) break;
    if (n < 128) { for (let k = 0; k <= n && i < b.length; k++) out.push(b[i++]!); }
    else { const v = b[i++] ?? 0; for (let k = 0; k < 257 - n; k++) out.push(v); }
    if (out.length > PDF_TEXT_LIMITS.streamOutMax) throw new Bad("a stream inflates past its limit");
  }
  return Buffer.from(out);
}

function predict(b: Buffer, parms: PDict | null): Buffer {
  const pred = numOf(parms?.get("Predictor")) ?? 1;
  if (pred < 2) return b;
  const colors = numOf(parms?.get("Colors")) ?? 1;
  const bpc = numOf(parms?.get("BitsPerComponent")) ?? 8;
  const columns = numOf(parms?.get("Columns")) ?? 1;
  const bpp = Math.max(1, Math.ceil((colors * bpc) / 8));
  const rowLen = Math.ceil((colors * bpc * columns) / 8);
  if (rowLen <= 0 || rowLen > 1 << 20) return b;
  if (pred === 2) {
    if (bpc !== 8) return b;
    const out = Buffer.from(b);
    for (let r = 0; r + rowLen <= out.length; r += rowLen) for (let i = bpp; i < rowLen; i++) out[r + i] = (out[r + i]! + out[r + i - bpp]!) & 255;
    return out;
  }
  const out = Buffer.alloc(Math.floor(b.length / (rowLen + 1)) * rowLen);
  let prev = Buffer.alloc(rowLen);
  let o = 0;
  for (let r = 0; r + rowLen + 1 <= b.length; r += rowLen + 1) {
    const type = b[r]!;
    const row = Buffer.from(b.subarray(r + 1, r + 1 + rowLen));
    for (let i = 0; i < rowLen; i++) {
      const left = i >= bpp ? row[i - bpp]! : 0;
      const up = prev[i]!;
      const ul = i >= bpp ? prev[i - bpp]! : 0;
      let add = 0;
      if (type === 1) add = left;
      else if (type === 2) add = up;
      else if (type === 3) add = (left + up) >> 1;
      else if (type === 4) { const p = left + up - ul; const pa = Math.abs(p - left), pb = Math.abs(p - up), pc = Math.abs(p - ul); add = pa <= pb && pa <= pc ? left : pb <= pc ? up : ul; }
      row[i] = (row[i]! + add) & 255;
    }
    row.copy(out, o);
    o += rowLen;
    prev = row;
  }
  return out;
}

const IMAGE_FILTERS = new Set(["DCTDecode", "DCT", "JPXDecode", "CCITTFaxDecode", "CCF", "JBIG2Decode"]);

// ── Encryption (the standard security handler, empty user password) ─────────

const PAD = Buffer.from("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A", "hex");

function rc4(key: Buffer, data: Buffer): Buffer {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + S[i]! + key[i % key.length]!) & 255;
    const t = S[i]!; S[i] = S[j]!; S[j] = t;
  }
  const out = Buffer.alloc(data.length);
  for (let k = 0, i = 0, j = 0; k < data.length; k++) {
    i = (i + 1) & 255;
    j = (j + S[i]!) & 255;
    const t = S[i]!; S[i] = S[j]!; S[j] = t;
    out[k] = data[k]! ^ S[(S[i]! + S[j]!) & 255]!;
  }
  return out;
}

const md5 = (...parts: Buffer[]): Buffer => { const h = createHash("md5"); for (const p of parts) h.update(p); return h.digest(); };

type CryptMethod = "rc4" | "aes128" | "aes256" | "identity";
interface Crypt { stm: CryptMethod; str: CryptMethod; key: Buffer }

/** Algorithm 2.B (ISO 32000-2 §7.6.4.3.4), the R6 hash. */
function hash2B(pw: Buffer, salt: Buffer, udata: Buffer): Buffer {
  let k = createHash("sha256").update(Buffer.concat([pw, salt, udata])).digest();
  let e: Buffer = Buffer.alloc(0);
  for (let i = 0; i < 64 || e[e.length - 1]! > i - 32; i++) {
    if (i > 2048) break;
    const k1 = Buffer.concat(Array(64).fill(Buffer.concat([pw, k, udata])) as Buffer[]);
    const c = createCipheriv("aes-128-cbc", k.subarray(0, 16), k.subarray(16, 32));
    c.setAutoPadding(false);
    e = Buffer.concat([c.update(k1), c.final()]);
    let sum = 0;
    for (let j = 0; j < 16; j++) sum += e[j]!;
    k = createHash(["sha256", "sha384", "sha512"][sum % 3]!).update(e).digest();
  }
  return k.subarray(0, 32);
}

/** The keys of an encrypted document opened with the empty user password,
 *  or a reason it cannot be: `password` (one is needed), `unsupported`. */
function openEncryption(enc: PDict, id0: Buffer, resolve: (v: PVal) => PVal): Crypt | "password" | "unsupported" {
  if (nameOf(resolve(enc.get("Filter") ?? null)) !== "Standard") return "unsupported";
  const V = numOf(resolve(enc.get("V") ?? null)) ?? 0;
  const R = numOf(resolve(enc.get("R") ?? null)) ?? 0;
  const strOf = (k: string): Buffer => { const v = resolve(enc.get(k) ?? null); return v instanceof PStr ? Buffer.from(v.b, "latin1") : Buffer.alloc(0); };
  const O = strOf("O");
  const U = strOf("U");
  const P = numOf(resolve(enc.get("P") ?? null)) ?? 0;
  let stm: CryptMethod = "rc4";
  let str: CryptMethod = "rc4";
  let length = numOf(resolve(enc.get("Length") ?? null)) ?? 40;
  if (V === 4 || V === 5) {
    const cf = resolve(enc.get("CF") ?? null);
    const method = (name: string | null): CryptMethod | null => {
      if (name === null || name === "Identity") return "identity";
      const f = isDict(cf) ? resolve(cf.get(name) ?? null) : null;
      const cfm = isDict(f) ? nameOf(resolve(f.get("CFM") ?? null)) : null;
      if (cfm === "V2") return "rc4";
      if (cfm === "AESV2") return "aes128";
      if (cfm === "AESV3") return "aes256";
      if (cfm === "None" || cfm === null) return "identity";
      return null;
    };
    const s1 = method(nameOf(resolve(enc.get("StmF") ?? null)));
    const s2 = method(nameOf(resolve(enc.get("StrF") ?? null)));
    if (s1 === null || s2 === null) return "unsupported";
    stm = s1;
    str = s2;
    if (V === 4) {
      const f = isDict(cf) ? resolve(cf.get(nameOf(resolve(enc.get("StmF") ?? null)) ?? "") ?? null) : null;
      const l = isDict(f) ? numOf(resolve(f.get("Length") ?? null)) : null;
      if (l !== null) length = l <= 32 ? l * 8 : l;
      if (stm === "aes128" || str === "aes128") length = 128;
    }
  } else if (V !== 1 && V !== 2) {
    return "unsupported";
  }
  if (R >= 5) {
    if (U.length < 48) return "unsupported";
    const pw = Buffer.alloc(0);
    const check = R === 5 ? createHash("sha256").update(Buffer.concat([pw, U.subarray(32, 40)])).digest() : hash2B(pw, U.subarray(32, 40), Buffer.alloc(0));
    if (!check.equals(U.subarray(0, 32))) return "password";
    const ik = R === 5 ? createHash("sha256").update(Buffer.concat([pw, U.subarray(40, 48)])).digest() : hash2B(pw, U.subarray(40, 48), Buffer.alloc(0));
    const UE = strOf("UE");
    if (UE.length < 32) return "unsupported";
    const d = createDecipheriv("aes-256-cbc", ik, Buffer.alloc(16));
    d.setAutoPadding(false);
    const key = Buffer.concat([d.update(UE.subarray(0, 32)), d.final()]);
    return { stm, str, key };
  }
  if (R < 2 || R > 4) return "unsupported";
  const n = R === 2 ? 5 : Math.max(5, Math.min(16, Math.floor(length / 8)));
  const p = Buffer.alloc(4);
  p.writeInt32LE(P | 0, 0);
  const meta = resolve(enc.get("EncryptMetadata") ?? null);
  let key = md5(PAD, O.subarray(0, 32), p, id0, R >= 4 && meta === false ? Buffer.from([255, 255, 255, 255]) : Buffer.alloc(0)).subarray(0, n);
  if (R >= 3) for (let i = 0; i < 50; i++) key = md5(key.subarray(0, n)).subarray(0, n);
  // The empty user password must open it (Algorithms 4 and 5).
  if (R === 2) {
    if (!rc4(key, PAD).equals(U.subarray(0, 32))) return "password";
  } else {
    let x = rc4(key, md5(PAD, id0));
    for (let i = 1; i <= 19; i++) x = rc4(Buffer.from(key.map((b) => b ^ i)), x);
    if (!x.subarray(0, 16).equals(U.subarray(0, 16))) return "password";
  }
  return { stm, str, key };
}

function decryptWith(c: Crypt, method: CryptMethod, num: number, gen: number, data: Buffer): Buffer {
  if (method === "identity") return data;
  if (method === "aes256") return aesDecrypt("aes-256-cbc", c.key, data);
  const ext = Buffer.from([num & 255, (num >> 8) & 255, (num >> 16) & 255, gen & 255, (gen >> 8) & 255]);
  const k = md5(c.key, ext, method === "aes128" ? Buffer.from("sAlT", "latin1") : Buffer.alloc(0)).subarray(0, Math.min(16, c.key.length + 5));
  return method === "rc4" ? rc4(k, data) : aesDecrypt("aes-128-cbc", k, data);
}

function aesDecrypt(alg: "aes-128-cbc" | "aes-256-cbc", key: Buffer, data: Buffer): Buffer {
  if (data.length < 32 || data.length % 16 !== 0) return Buffer.alloc(0);
  const iv = data.subarray(0, 16);
  const body = data.subarray(16);
  try {
    const d = createDecipheriv(alg, key, iv);
    return Buffer.concat([d.update(body), d.final()]);
  } catch {
    const d = createDecipheriv(alg, key, iv);
    d.setAutoPadding(false);
    return Buffer.concat([d.update(body), d.final()]);
  }
}

// ── The document ─────────────────────────────────────────────────────────────

const OBJ_RE = /(\d{1,10})[ \t\r\n\f\0]+(\d{1,5})[ \t\r\n\f\0]+obj\b/g;

class PdfDoc {
  readonly objs = new Map<number, PObj>();
  trailer: PDict = new Map();
  crypt: Crypt | null = null;
  readonly budget = new Budget();

  constructor(readonly s: string) {}

  load(): void {
    const s = this.s;
    const trailers: Array<{ pos: number; dict: PDict }> = [];
    OBJ_RE.lastIndex = 0;
    let count = 0;
    for (let m = OBJ_RE.exec(s); m !== null; m = OBJ_RE.exec(s)) {
      if (++count > PDF_TEXT_LIMITS.objectsMax) throw new Bad("too many objects");
      // `12 0 obj` must start a token
      if (m.index > 0 && !WS.has(s.charCodeAt(m.index - 1)) && !DELIM.has(s.charCodeAt(m.index - 1))) { OBJ_RE.lastIndex = m.index + 1; continue; }
      const num = Number(m[1]);
      const gen = Number(m[2]);
      const lx = new Lexer(s, m.index + m[0].length);
      let val: PVal | undefined;
      try { val = lx.value(true); } catch { val = undefined; }
      if (val === undefined) { OBJ_RE.lastIndex = Math.max(lx.pos, m.index + m[0].length); continue; }
      lx.skipWs();
      if (isDict(val) && s.startsWith("stream", lx.pos)) {
        let st = lx.pos + 6;
        if (s[st] === "\r") st++;
        if (s[st] === "\n") st++;
        const len = numOf(val.get("Length"));
        let end = -1;
        if (len !== null && len >= 0 && st + len <= s.length) {
          const after = new Lexer(s, st + len);
          after.skipWs();
          if (s.startsWith("endstream", after.pos)) end = st + len;
        }
        if (end < 0) {
          const e = s.indexOf("endstream", st);
          end = e < 0 ? s.length : e;
          if (s[end - 1] === "\n") end--;
          if (s[end - 1] === "\r") end--;
        }
        const stream: PStream = { dict: val, start: st, end: Math.max(st, end), num, gen, inStm: false };
        this.objs.set(num, { val: stream, pos: m.index, num, gen, inStm: false });
        if (nameOf(val.get("Type")) === "XRef") trailers.push({ pos: m.index, dict: val });
        const e = s.indexOf("endstream", end);
        OBJ_RE.lastIndex = e < 0 ? s.length : e + 9;
      } else {
        this.objs.set(num, { val, pos: m.index, num, gen, inStm: false });
        OBJ_RE.lastIndex = lx.pos;
      }
    }
    for (let i = s.indexOf("trailer"); i >= 0; i = s.indexOf("trailer", i + 7)) {
      const lx = new Lexer(s, i + 7);
      try {
        const d = lx.value(true);
        if (isDict(d)) trailers.push({ pos: i, dict: d });
      } catch { /* not a trailer */ }
    }
    trailers.sort((a, b) => a.pos - b.pos);
    for (const t of trailers) for (const [k, v] of t.dict) if (["Root", "Encrypt", "ID", "Info"].includes(k)) this.trailer.set(k, v);

    const enc = this.trailer.get("Encrypt");
    if (enc !== undefined && enc !== null) {
      const encDict = this.resolve(enc);
      if (!isDict(encDict)) throw new Bad("an unreadable encryption dictionary");
      const ids = this.resolve(this.trailer.get("ID") ?? null);
      const id0 = Array.isArray(ids) && ids[0] instanceof PStr ? Buffer.from(ids[0].b, "latin1") : Buffer.alloc(0);
      const c = openEncryption(encDict, id0, (v) => this.resolve(v));
      if (c === "password" || c === "unsupported") throw new EncryptedError();
      this.crypt = c;
    }

    // Object streams: their members, unless a later object redefines them.
    const objstms = [...this.objs.values()].filter((o) => isStream(o.val) && nameOf(o.val.dict.get("Type")) === "ObjStm").sort((a, b) => a.pos - b.pos);
    for (const o of objstms) {
      const st = o.val as PStream;
      let data: string;
      try { data = this.streamData(st); } catch { continue; }
      const n = numOf(this.resolve(st.dict.get("N") ?? null)) ?? 0;
      const first = numOf(this.resolve(st.dict.get("First") ?? null)) ?? 0;
      const head = new Lexer(data, 0, Math.min(first, data.length));
      const pairs: Array<[number, number]> = [];
      for (let i = 0; i < n && i < 100_000; i++) {
        const a = head.value(false);
        const b = head.value(false);
        if (typeof a !== "number" || typeof b !== "number") break;
        pairs.push([a, b]);
      }
      for (const [num, off] of pairs) {
        if (this.objs.size > PDF_TEXT_LIMITS.objectsMax) throw new Bad("too many objects");
        const prev = this.objs.get(num);
        if (prev !== undefined && prev.pos > o.pos) continue;
        const lx = new Lexer(data, first + off);
        let val: PVal | undefined;
        try { val = lx.value(true); } catch { continue; }
        if (val === undefined) continue;
        this.objs.set(num, { val, pos: o.pos, num, gen: 0, inStm: true });
      }
    }
  }

  resolve(v: PVal | undefined): PVal {
    let cur: PVal | undefined = v;
    for (let i = 0; cur instanceof PRef && i < 32; i++) cur = this.objs.get(cur.num)?.val ?? null;
    if (cur instanceof PRef) return null;
    return cur ?? null;
  }

  /** The object a reference names, with its number (strings in an
   *  encrypted file's objects are decrypted with it). */
  objOf(v: PVal | undefined): PObj | null {
    let cur: PVal | undefined = v;
    let o: PObj | null = null;
    for (let i = 0; cur instanceof PRef && i < 32; i++) { o = this.objs.get(cur.num) ?? null; cur = o?.val; }
    return o;
  }

  get(d: PDict | null | undefined, k: string): PVal {
    return d ? this.resolve(d.get(k) ?? null) : null;
  }

  /** A text string of the object `owner` (a field's `TU`, `V`): decrypted
   *  when the file is, then PDFDocEncoding or UTF-16 with its BOM. */
  textString(v: PVal, owner: PObj | null): string {
    if (v instanceof PName) return v.n;
    if (!(v instanceof PStr)) return "";
    let b: Buffer = Buffer.from(v.b, "latin1");
    if (this.crypt && owner && !owner.inStm) b = decryptWith(this.crypt, this.crypt.str, owner.num, owner.gen, b);
    if (b[0] === 0xfe && b[1] === 0xff) return utf16be(b.subarray(2));
    if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return b.subarray(3).toString("utf8");
    let out = "";
    for (const c of b) out += c >= 0x80 && c <= 0x9f ? WIN_ANSI_HIGH[c - 0x80] ?? "" : String.fromCharCode(c);
    return out;
  }

  /** A stream's decoded bytes (latin1); null for an image. */
  streamData(st: PStream): string {
    let b: Buffer = Buffer.from(this.s.slice(st.start, st.end), "latin1");
    if (this.crypt && nameOf(st.dict.get("Type")) !== "XRef") b = decryptWith(this.crypt, this.crypt.stm, st.num, st.gen, b);
    const f = this.resolve(st.dict.get("Filter") ?? null);
    const p = this.resolve(st.dict.get("DecodeParms") ?? null);
    const filters = Array.isArray(f) ? f.map((x) => nameOf(this.resolve(x))) : f === null ? [] : [nameOf(f)];
    const parms = Array.isArray(p) ? p.map((x) => this.resolve(x)) : [p];
    filters.forEach((name, i) => {
      const parm = parms[i];
      const dict = isDict(parm) ? parm : null;
      if (name === "FlateDecode" || name === "Fl") b = predict(flate(b), dict);
      else if (name === "ASCIIHexDecode" || name === "AHx") b = asciiHex(b);
      else if (name === "ASCII85Decode" || name === "A85") b = ascii85(b);
      else if (name === "LZWDecode" || name === "LZW") b = predict(lzw(b, numOf(dict?.get("EarlyChange")) ?? 1), dict);
      else if (name === "RunLengthDecode" || name === "RL") b = runLength(b);
      else if (name !== null && IMAGE_FILTERS.has(name)) throw new Bad("an image stream");
      else if (name === "Crypt") { /* identity in practice */ }
      else throw new Bad(`an unknown filter`);
      this.budget.take(b.length);
    });
    return b.toString("latin1");
  }
}

class EncryptedError extends Error {}

function utf16be(b: Buffer): string {
  let out = "";
  for (let i = 0; i + 1 < b.length; i += 2) out += String.fromCharCode((b[i]! << 8) | b[i + 1]!);
  return out;
}

// ── Encodings ────────────────────────────────────────────────────────────────

/** WinAnsiEncoding 0x80-0x9F (the rest is Latin-1). */
export const WIN_ANSI_HIGH: readonly string[] = [
  "€", "", "‚", "ƒ", "„", "…", "†", "‡", "ˆ", "‰", "Š", "‹", "Œ", "", "Ž", "",
  "", "‘", "’", "“", "”", "•", "–", "—", "˜", "™", "š", "›", "œ", "", "ž", "Ÿ",
];

function winAnsi(code: number): string {
  if (code >= 0x80 && code <= 0x9f) return WIN_ANSI_HIGH[code - 0x80]!;
  if (code === 0x7f || code < 0x20) return code === 0x09 ? "\t" : "";
  return String.fromCharCode(code);
}

/** MacRomanEncoding 0x80-0xFF. */
const MAC_ROMAN_HIGH = "ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ";

function macRoman(code: number): string {
  if (code >= 0x80) return MAC_ROMAN_HIGH[code - 0x80] ?? "";
  return code < 0x20 || code === 0x7f ? "" : String.fromCharCode(code);
}

/** StandardEncoding: ASCII but for the quotes; the high half by name in
 *  the glyph list (only the common ones). */
function standard(code: number): string {
  if (code === 0x27) return "’";
  if (code === 0x60) return "‘";
  if (code < 0x20 || code >= 0x7f) return "";
  return String.fromCharCode(code);
}

/** The glyph names `Differences` uses most, to Unicode (Adobe Glyph List,
 *  the Latin subset); `uniXXXX`, `uXXXX[XX]` and single letters are read
 *  by rule. */
const GLYPHS: Readonly<Record<string, string>> = {
  space: " ", exclam: "!", quotedbl: "\"", numbersign: "#", dollar: "$", percent: "%", ampersand: "&", quotesingle: "'",
  quoteright: "’", quoteleft: "‘", parenleft: "(", parenright: ")", asterisk: "*", plus: "+", comma: ",", hyphen: "-",
  minus: "−", period: ".", slash: "/", zero: "0", one: "1", two: "2", three: "3", four: "4", five: "5", six: "6",
  seven: "7", eight: "8", nine: "9", colon: ":", semicolon: ";", less: "<", equal: "=", greater: ">", question: "?",
  at: "@", bracketleft: "[", backslash: "\\", bracketright: "]", asciicircum: "^", underscore: "_", grave: "`",
  braceleft: "{", bar: "|", braceright: "}", asciitilde: "~", bullet: "•", endash: "–", emdash: "—",
  quotedblleft: "“", quotedblright: "”", quotesinglbase: "‚", quotedblbase: "„", ellipsis: "…", Euro: "€",
  sterling: "£", yen: "¥", cent: "¢", section: "§", paragraph: "¶", degree: "°", copyright: "©", registered: "®",
  trademark: "™", nbspace: " ", periodcentered: "·", multiply: "×", divide: "÷", plusminus: "±", mu: "µ",
  fi: "fi", fl: "fl", ff: "ff", ffi: "ffi", ffl: "ffl", dagger: "†", daggerdbl: "‡", perthousand: "‰",
  guilsinglleft: "‹", guilsinglright: "›", guillemotleft: "«", guillemotright: "»", exclamdown: "¡", questiondown: "¿",
  Aacute: "Á", aacute: "á", Agrave: "À", agrave: "à", Acircumflex: "Â", acircumflex: "â", Adieresis: "Ä", adieresis: "ä",
  Atilde: "Ã", atilde: "ã", Aring: "Å", aring: "å", AE: "Æ", ae: "æ", Ccedilla: "Ç", ccedilla: "ç", Eacute: "É",
  eacute: "é", Egrave: "È", egrave: "è", Ecircumflex: "Ê", ecircumflex: "ê", Edieresis: "Ë", edieresis: "ë",
  Iacute: "Í", iacute: "í", Igrave: "Ì", igrave: "ì", Icircumflex: "Î", icircumflex: "î", Idieresis: "Ï", idieresis: "ï",
  Ntilde: "Ñ", ntilde: "ñ", Oacute: "Ó", oacute: "ó", Ograve: "Ò", ograve: "ò", Ocircumflex: "Ô", ocircumflex: "ô",
  Odieresis: "Ö", odieresis: "ö", Otilde: "Õ", otilde: "õ", Oslash: "Ø", oslash: "ø", OE: "Œ", oe: "œ",
  Scaron: "Š", scaron: "š", germandbls: "ß", Uacute: "Ú", uacute: "ú", Ugrave: "Ù", ugrave: "ù", Ucircumflex: "Û",
  ucircumflex: "û", Udieresis: "Ü", udieresis: "ü", Yacute: "Ý", yacute: "ý", ydieresis: "ÿ", Ydieresis: "Ÿ",
  Zcaron: "Ž", zcaron: "ž", dotlessi: "ı", onehalf: "½", onequarter: "¼", threequarters: "¾",
};

function glyphToUnicode(name: string): string | null {
  if (GLYPHS[name] !== undefined) return GLYPHS[name]!;
  if (/^[A-Za-z]$/.test(name)) return name;
  let m = /^uni([0-9A-Fa-f]{4})+$/.exec(name);
  if (m) {
    let out = "";
    for (let i = 3; i + 4 <= name.length; i += 4) out += String.fromCharCode(parseInt(name.slice(i, i + 4), 16));
    return out;
  }
  m = /^u([0-9A-Fa-f]{4,6})$/.exec(name);
  if (m) { const cp = parseInt(m[1]!, 16); return cp <= 0x10ffff ? String.fromCodePoint(cp) : null; }
  const base = name.split(/[._]/)[0]!;
  if (base !== name && base !== "") return glyphToUnicode(base);
  return null;
}

/** Helvetica's and Times-Roman's widths for 32-126 (the standard 14
 *  fonts' metrics; Courier is 600 throughout). */
const HELVETICA_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];
const TIMES_W = [250, 333, 408, 500, 500, 833, 778, 180, 333, 333, 500, 564, 250, 333, 250, 278, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 278, 278, 564, 564, 564, 444, 921, 722, 667, 667, 722, 611, 556, 722, 722, 333, 389, 722, 611, 889, 722, 722, 556, 722, 667, 556, 611, 722, 722, 944, 722, 722, 611, 333, 278, 333, 469, 500, 333, 444, 500, 444, 500, 444, 333, 500, 500, 278, 278, 500, 278, 778, 500, 500, 500, 500, 333, 389, 278, 500, 500, 722, 500, 500, 444, 480, 200, 480, 541];

// ── Fonts ────────────────────────────────────────────────────────────────────

interface Font {
  /** The codes of a string, by the code-space ranges. */
  codes(b: string): number[];
  /** A code's text ("" when unknown). */
  text(code: number): string;
  /** A code's advance, in thousandths of the size. */
  width(code: number): number;
  /** Single-byte code 32 takes word spacing. */
  oneByte: boolean;
  /** 1000 / the font matrix scale (Type3 glyph space). */
  scale: number;
}

interface CMap { ranges: Array<{ len: number; lo: number; hi: number }>; map: Map<number, string> }

function hexNum(s: string): number { return s.length === 0 ? 0 : parseInt(s.slice(0, 8), 16); }

function hexText(h: string): string {
  const b = Buffer.from(h.length % 2 ? `${h}0` : h, "hex");
  return utf16be(b);
}

/** A `ToUnicode` CMap (or an embedded encoding CMap's code spaces). */
function parseCMap(text: string): CMap {
  const cm: CMap = { ranges: [], map: new Map() };
  const hexes = (s: string): string[] => [...s.matchAll(/<([0-9A-Fa-f\s]*)>/g)].map((m) => m[1]!.replace(/\s+/g, ""));
  for (const blk of text.matchAll(/begincodespacerange([\s\S]*?)endcodespacerange/g)) {
    const h = hexes(blk[1]!);
    for (let i = 0; i + 1 < h.length && cm.ranges.length < 64; i += 2) cm.ranges.push({ len: Math.max(1, Math.ceil(h[i]!.length / 2)), lo: hexNum(h[i]!), hi: hexNum(h[i + 1]!) });
  }
  for (const blk of text.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    const h = hexes(blk[1]!);
    for (let i = 0; i + 1 < h.length; i += 2) {
      if (cm.map.size > 200_000) break;
      cm.map.set(hexNum(h[i]!), hexText(h[i + 1]!));
    }
  }
  for (const blk of text.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    const body = blk[1]!;
    const re = /<([0-9A-Fa-f\s]*)>\s*<([0-9A-Fa-f\s]*)>\s*(?:<([0-9A-Fa-f\s]*)>|\[([^\]]*)\])/g;
    for (const m of body.matchAll(re)) {
      const lo = hexNum(m[1]!.replace(/\s+/g, ""));
      const hi = hexNum(m[2]!.replace(/\s+/g, ""));
      if (hi < lo || hi - lo > 65535 || cm.map.size > 200_000) continue;
      if (m[3] !== undefined) {
        const dst = m[3].replace(/\s+/g, "");
        const units: number[] = [];
        for (let i = 0; i + 4 <= dst.length; i += 4) units.push(parseInt(dst.slice(i, i + 4), 16));
        if (units.length === 0) continue;
        for (let c = lo; c <= hi; c++) {
          const u = [...units];
          u[u.length - 1] = (u[u.length - 1]! + (c - lo)) & 0xffff;
          cm.map.set(c, String.fromCharCode(...u));
        }
      } else {
        const list = hexes(m[4]!);
        for (let c = lo; c <= hi && c - lo < list.length; c++) cm.map.set(c, hexText(list[c - lo]!));
      }
    }
  }
  return cm;
}

function codesBy(ranges: CMap["ranges"], fallbackLen: number, b: string): number[] {
  const out: number[] = [];
  let i = 0;
  while (i < b.length) {
    let taken = 0;
    if (ranges.length > 0) {
      for (let len = 1; len <= 4 && i + len <= b.length && taken === 0; len++) {
        let v = 0;
        for (let k = 0; k < len; k++) v = v * 256 + b.charCodeAt(i + k);
        if (ranges.some((r) => r.len === len && v >= r.lo && v <= r.hi)) { out.push(v); taken = len; }
      }
    }
    if (taken === 0) {
      const len = Math.min(fallbackLen, b.length - i);
      let v = 0;
      for (let k = 0; k < len; k++) v = v * 256 + b.charCodeAt(i + k);
      out.push(v);
      taken = len;
    }
    i += taken;
  }
  return out;
}

function buildFont(doc: PdfDoc, fd: PDict): Font {
  const subtype = nameOf(doc.get(fd, "Subtype"));
  const base = nameOf(doc.get(fd, "BaseFont")) ?? "";
  const tu = doc.get(fd, "ToUnicode");
  let cmap: CMap | null = null;
  if (isStream(tu)) { try { cmap = parseCMap(doc.streamData(tu)); } catch { cmap = null; } }

  if (subtype === "Type0") {
    const desc = doc.get(fd, "DescendantFonts");
    const cid = Array.isArray(desc) ? doc.resolve(desc[0]) : null;
    const cidDict = isDict(cid) ? cid : null;
    const dw = numOf(doc.get(cidDict, "DW")) ?? 1000;
    const widths = new Map<number, number>();
    const w = doc.get(cidDict, "W");
    if (Array.isArray(w)) {
      for (let i = 0; i < w.length && widths.size < 200_000;) {
        const first = numOf(doc.resolve(w[i]));
        const next = doc.resolve(w[i + 1]);
        if (first === null) break;
        if (Array.isArray(next)) {
          next.forEach((x, k) => { const v = numOf(doc.resolve(x)); if (v !== null) widths.set(first + k, v); });
          i += 2;
        } else {
          const last = numOf(next);
          const v = numOf(doc.resolve(w[i + 2]));
          if (last === null || v === null) break;
          for (let c = first; c <= last && c - first <= 65535; c++) widths.set(c, v);
          i += 3;
        }
      }
    }
    const enc = doc.get(fd, "Encoding");
    let ranges = cmap?.ranges ?? [];
    if (isStream(enc)) { try { ranges = parseCMap(doc.streamData(enc)).ranges; } catch { /* the default */ } }
    else if (nameOf(enc) !== null && !/^Identity-[HV]$/.test(nameOf(enc)!)) ranges = cmap?.ranges ?? [];
    if (ranges.length === 0) ranges = [{ len: 2, lo: 0, hi: 0xffff }];
    return {
      codes: (b) => codesBy(ranges, 2, b),
      text: (c) => cmap?.map.get(c) ?? "",
      width: (c) => widths.get(c) ?? dw,
      oneByte: false,
      scale: 1,
    };
  }

  // A simple font: 1-byte codes.
  const table: string[] = new Array(256).fill("");
  const encV = doc.get(fd, "Encoding");
  const encName = nameOf(encV) ?? (isDict(encV) ? nameOf(doc.get(encV, "BaseEncoding")) : null);
  const symbolic = /Symbol|Dingbats/i.test(base);
  const baseFn = encName === "MacRomanEncoding" ? macRoman : encName === "WinAnsiEncoding" ? winAnsi : encName === "StandardEncoding" ? standard
    : subtype === "TrueType" ? winAnsi : standard;
  for (let c = 0; c < 256; c++) table[c] = symbolic && !cmap ? "" : baseFn(c);
  if (isDict(encV)) {
    const diffs = doc.get(encV, "Differences");
    if (Array.isArray(diffs)) {
      let code = 0;
      for (const d of diffs) {
        const v = doc.resolve(d);
        if (typeof v === "number") code = v;
        else if (v instanceof PName) { if (code >= 0 && code < 256) table[code] = glyphToUnicode(v.n) ?? ""; code++; }
      }
    }
  }
  const first = numOf(doc.get(fd, "FirstChar")) ?? 0;
  const wArr = doc.get(fd, "Widths");
  const desc = doc.get(fd, "FontDescriptor");
  const missing = numOf(doc.get(isDict(desc) ? desc : null, "MissingWidth")) ?? 0;
  const std = /Courier/i.test(base) ? null : /Times|Serif/i.test(base) ? TIMES_W : HELVETICA_W;
  let scale = 1;
  if (subtype === "Type3") {
    const fm = doc.get(fd, "FontMatrix");
    const a = Array.isArray(fm) ? numOf(doc.resolve(fm[0])) : null;
    if (a !== null && a > 0) scale = a * 1000;
  }
  const widths = Array.isArray(wArr) ? wArr.map((x) => numOf(doc.resolve(x)) ?? 0) : null;
  return {
    codes: (b) => (cmap && cmap.ranges.length > 0 && cmap.ranges.some((r) => r.len > 1) ? codesBy(cmap.ranges, 1, b) : [...b].map((ch) => ch.charCodeAt(0))),
    text: (c) => cmap?.map.get(c) ?? table[c] ?? "",
    width: (c) => {
      if (widths) { const w = widths[c - first]; if (w !== undefined) return w * scale; return (missing || 500) * scale; }
      if (std === null) return 600;
      return c >= 32 && c <= 126 ? std[c - 32]! : 500;
    },
    oneByte: true,
    scale,
  };
}

// ── Content streams ──────────────────────────────────────────────────────────

type M6 = [number, number, number, number, number, number];
const ID6: M6 = [1, 0, 0, 1, 0, 0];
function mul(a: M6, b: M6): M6 {
  return [
    a[0] * b[0] + a[1] * b[2], a[0] * b[1] + a[1] * b[3],
    a[2] * b[0] + a[3] * b[2], a[2] * b[1] + a[3] * b[3],
    a[4] * b[0] + a[5] * b[2] + b[4], a[4] * b[1] + a[5] * b[3] + b[5],
  ];
}

/** One shown string, placed on the displayed page (`y` grows downward). */
interface Chunk { x: number; y: number; endX: number; size: number; text: string; seq: number }

interface Gs { ctm: M6; font: Font | null; size: number; tc: number; tw: number; th: number; tl: number }

class PageReader {
  readonly chunks: Chunk[] = [];
  private ops = 0;
  private seq = 0;
  private readonly fontCache = new Map<unknown, Font | null>();

  constructor(private readonly doc: PdfDoc, private readonly rotate: number, private readonly opsLeft: () => number, private readonly spend: (n: number) => void) {}

  private display(x: number, y: number): [number, number] {
    switch (this.rotate) {
      case 90: return [y, x];
      case 180: return [-x, y];
      case 270: return [-y, -x];
      default: return [x, -y];
    }
  }

  private fontOf(res: PDict | null, name: string): Font | null {
    const fonts = this.doc.get(res, "Font");
    const ref = isDict(fonts) ? fonts.get(name) : undefined;
    if (ref === undefined) return null;
    const key = ref instanceof PRef ? ref.num : ref;
    if (this.fontCache.has(key)) return this.fontCache.get(key)!;
    const fd = this.doc.resolve(ref);
    let f: Font | null = null;
    if (isDict(fd)) { try { f = buildFont(this.doc, fd); } catch { f = null; } }
    this.fontCache.set(key, f);
    return f;
  }

  run(content: string, res: PDict | null, ctm: M6, depth: number): void {
    const lx = new Lexer(content);
    const stack: Gs[] = [];
    let gs: Gs = { ctm, font: null, size: 0, tc: 0, tw: 0, th: 1, tl: 0 };
    let tm: M6 = ID6;
    let tlm: M6 = ID6;
    let operands: PVal[] = [];
    const n = (i: number): number => numOf(operands[i]) ?? 0;

    const show = (str: PStr): void => {
      const f = gs.font;
      if (!f) return;
      let text = "";
      const trm0 = mul([gs.size * gs.th, 0, 0, gs.size, 0, 0], mul(tm, gs.ctm));
      const [x0, y0] = this.display(trm0[4], trm0[5]);
      const size = Math.hypot(trm0[2], trm0[3]) || Math.abs(gs.size);
      for (const code of f.codes(str.b)) {
        text += f.text(code);
        const w0 = f.width(code) / 1000;
        const tx = (w0 * gs.size + gs.tc + (f.oneByte && code === 32 ? gs.tw : 0)) * gs.th;
        tm = mul([1, 0, 0, 1, tx, 0], tm);
      }
      const trm1 = mul([gs.size * gs.th, 0, 0, gs.size, 0, 0], mul(tm, gs.ctm));
      const [x1] = this.display(trm1[4], trm1[5]);
      if (text === "") return;
      if (this.chunks.length >= PDF_TEXT_LIMITS.chunksMax) throw new Bad("too many text chunks");
      this.chunks.push({ x: Math.min(x0, x1), y: y0, endX: Math.max(x0, x1), size, text, seq: this.seq++ });
    };
    const nextLine = (): void => { tlm = mul([1, 0, 0, 1, 0, -gs.tl], tlm); tm = tlm; };

    for (;;) {
      if (++this.ops > 1000) { this.spend(this.ops); this.ops = 0; if (this.opsLeft() <= 0) throw new Bad("too many content operators"); }
      const v = lx.value(false);
      if (v !== undefined) { operands.push(v); if (operands.length > 64) operands.shift(); continue; }
      const op = lx.lastWord;
      if (op === "") { if (lx.pos >= lx.end) break; operands = []; continue; }
      switch (op) {
        case "q": if (stack.length < 64) stack.push({ ...gs }); break;
        case "Q": gs = stack.pop() ?? gs; break;
        case "cm": if (operands.length >= 6) gs.ctm = mul([n(operands.length - 6), n(operands.length - 5), n(operands.length - 4), n(operands.length - 3), n(operands.length - 2), n(operands.length - 1)], gs.ctm); break;
        case "BT": tm = ID6; tlm = ID6; break;
        case "Tf": {
          const name = nameOf(operands[operands.length - 2]);
          gs.font = name !== null ? this.fontOf(res, name) : null;
          gs.size = numOf(operands[operands.length - 1]) ?? 0;
          break;
        }
        case "Tc": gs.tc = n(operands.length - 1); break;
        case "Tw": gs.tw = n(operands.length - 1); break;
        case "Tz": gs.th = n(operands.length - 1) / 100; break;
        case "TL": gs.tl = n(operands.length - 1); break;
        case "Td": tlm = mul([1, 0, 0, 1, n(operands.length - 2), n(operands.length - 1)], tlm); tm = tlm; break;
        case "TD": gs.tl = -n(operands.length - 1); tlm = mul([1, 0, 0, 1, n(operands.length - 2), n(operands.length - 1)], tlm); tm = tlm; break;
        case "Tm": if (operands.length >= 6) { const l = operands.length; tlm = [n(l - 6), n(l - 5), n(l - 4), n(l - 3), n(l - 2), n(l - 1)]; tm = tlm; } break;
        case "T*": nextLine(); break;
        case "Tj": { const s = operands[operands.length - 1]; if (s instanceof PStr) show(s); break; }
        case "'": { nextLine(); const s = operands[operands.length - 1]; if (s instanceof PStr) show(s); break; }
        case "\"": { gs.tw = n(operands.length - 3); gs.tc = n(operands.length - 2); nextLine(); const s = operands[operands.length - 1]; if (s instanceof PStr) show(s); break; }
        case "TJ": {
          const arr = operands[operands.length - 1];
          if (Array.isArray(arr)) {
            for (const e of arr) {
              if (e instanceof PStr) show(e);
              else if (typeof e === "number") tm = mul([1, 0, 0, 1, (-e / 1000) * gs.size * gs.th, 0], tm);
            }
          }
          break;
        }
        case "Do": {
          const name = nameOf(operands[operands.length - 1]);
          if (name === null || depth >= PDF_TEXT_LIMITS.formDepthMax) break;
          const xo = this.doc.get(res, "XObject");
          const x = isDict(xo) ? this.doc.resolve(xo.get(name) ?? null) : null;
          if (!isStream(x) || nameOf(this.doc.get(x.dict, "Subtype")) !== "Form") break;
          let data: string;
          try { data = this.doc.streamData(x); } catch { break; }
          const m = this.doc.get(x.dict, "Matrix");
          const mm: M6 = Array.isArray(m) && m.length === 6 ? m.map((e) => numOf(this.doc.resolve(e)) ?? 0) as M6 : ID6;
          const r = this.doc.get(x.dict, "Resources");
          this.run(data, isDict(r) ? r : res, mul(mm, gs.ctm), depth + 1);
          break;
        }
        case "BI": {
          // an inline image: skip to `EI` after its data
          const id = content.indexOf("ID", lx.pos);
          if (id < 0) { lx.pos = lx.end; break; }
          const re = /[\s\0]EI(?=[\s\0]|$)/g;
          re.lastIndex = id + 3;
          const m = re.exec(content);
          lx.pos = m ? m.index + m[0].length : lx.end;
          break;
        }
        default: break;
      }
      operands = [];
    }
    this.spend(this.ops);
    this.ops = 0;
  }
}

// ── Lines ────────────────────────────────────────────────────────────────────

/** A page's chunks as lines of cells (top to bottom, left to right). */
export function chunksToLines(chunks: readonly Chunk[], renderRow: (cells: readonly string[]) => string): string[] {
  const sorted = [...chunks].sort((a, b) => a.y - b.y || a.x - b.x || a.seq - b.seq);
  const lines: Chunk[][] = [];
  for (const c of sorted) {
    const cur = lines[lines.length - 1];
    if (cur && Math.abs(c.y - cur[0]!.y) <= Math.max(1, 0.4 * Math.min(c.size, cur[0]!.size))) cur.push(c);
    else lines.push([c]);
  }
  const out: string[] = [];
  for (const line of lines) {
    line.sort((a, b) => a.x - b.x || a.seq - b.seq);
    const cells: string[] = [];
    let cell = "";
    let prevEnd: number | null = null;
    for (const c of line) {
      if (prevEnd !== null) {
        const gap = c.x - prevEnd;
        const em = Math.max(1, c.size);
        if (gap > 1.2 * em) { cells.push(cell); cell = ""; }
        else if (gap > 0.15 * em && !/\s$/.test(cell) && !/^\s/.test(c.text)) cell += " ";
      }
      cell += c.text;
      prevEnd = prevEnd === null ? c.endX : Math.max(prevEnd, c.endX);
    }
    cells.push(cell);
    out.push(renderRow(cells));
  }
  return out;
}

// ── The entry point ──────────────────────────────────────────────────────────

/**
 * The text layer of the PDF in `bytes` (module comment). `renderRow` is
 * document-text.ts's row rendering; `textMax` caps the text (UTF-8 bytes).
 * Never throws.
 */
export function readPdfText(bytes: Buffer, opts: { renderRow: (cells: readonly string[]) => string; textMax: number }): PdfTextRead {
  const head = bytes.subarray(0, 1024).toString("latin1");
  if (!head.includes("%PDF-")) return { kind: "unreadable", reason: "not a PDF" };
  const doc = new PdfDoc(bytes.toString("latin1"));
  try {
    doc.load();
  } catch (err) {
    if (err instanceof EncryptedError) return { kind: "encrypted" };
    return { kind: "unreadable", reason: err instanceof Bad ? err.message : "the file could not be read" };
  }
  const out: string[] = [];
  let bytesOut = 0;
  const push = (line: string): void => {
    bytesOut += Buffer.byteLength(line, "utf8") + 1;
    if (bytesOut > opts.textMax) throw new TooLong();
    out.push(line);
  };
  let opsLeft = PDF_TEXT_LIMITS.opsMax;
  let pages = 0;
  try {
    for (const page of pageList(doc)) {
      if (++pages > PDF_TEXT_LIMITS.pagesMax) throw new TooLong();
      const reader = new PageReader(doc, page.rotate, () => opsLeft, (n) => { opsLeft -= n; });
      for (const content of page.contents) {
        let data: string;
        try { data = doc.streamData(content); } catch (err) { if (err instanceof Bad && /past/.test(err.message)) throw err; continue; }
        reader.run(data, page.resources, ID6, 0);
      }
      const lines = chunksToLines(reader.chunks, opts.renderRow).map((l) => clean(l)).filter((l, i, a) => l !== "" || (i > 0 && a[i - 1] !== ""));
      if (lines.length === 0) continue;
      if (out.length > 0) push("");
      for (const l of lines) push(l);
    }
    const fields = fieldLines(doc).map(clean).filter((l) => l !== "");
    if (fields.length > 0) {
      if (out.length > 0) push("");
      for (const l of fields) push(opts.renderRow(l.split("\u0000")));
    }
  } catch (err) {
    if (err instanceof TooLong) return { kind: "too-long" };
    return { kind: "unreadable", reason: err instanceof Bad ? err.message : "the file could not be read" };
  }
  const text = out.join("\n").replace(/\n{3,}/g, "\n\n").trim();
  if ((text.match(/[\p{L}\p{N}]/gu) ?? []).length < 16) return { kind: "no-text", pages };
  return { kind: "text", text, pages };
}

/** Control characters (but tab), the replacement character and NUL out;
 *  blanks at the ends trimmed. */
function clean(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0001-\u0008\u000a-\u001f\u007f�﻿]/g, "").replace(/[ \t]+$/, "").replace(/^[ \t]+/, "");
}

interface PageRef { contents: PStream[]; resources: PDict | null; rotate: number }

function pageList(doc: PdfDoc): PageRef[] {
  const out: PageRef[] = [];
  const seen = new Set<unknown>();
  const visit = (node: PVal, inherited: { res: PDict | null; rotate: number }, depth: number): void => {
    if (depth > 64 || out.length > PDF_TEXT_LIMITS.pagesMax) return;
    const key = node instanceof PRef ? node.num : node;
    if (seen.has(key)) return;
    seen.add(key);
    const d = doc.resolve(node);
    if (!isDict(d)) return;
    const r = doc.get(d, "Resources");
    const rot = numOf(doc.get(d, "Rotate"));
    const here = { res: isDict(r) ? r : inherited.res, rotate: rot !== null ? ((rot % 360) + 360) % 360 : inherited.rotate };
    const kids = doc.get(d, "Kids");
    if (Array.isArray(kids) && nameOf(doc.get(d, "Type")) !== "Page") {
      for (const k of kids) visit(k, here, depth + 1);
      return;
    }
    out.push({ contents: contentsOf(doc, d), resources: here.res, rotate: here.rotate });
  };
  const root = doc.resolve(doc.trailer.get("Root") ?? null);
  if (isDict(root)) visit(root.get("Pages") ?? null, { res: null, rotate: 0 }, 0);
  if (out.length === 0) {
    // No page tree: every page object, by number.
    const pages = [...doc.objs.values()].filter((o) => isDict(o.val) && nameOf(o.val.get("Type")) === "Page").sort((a, b) => a.num - b.num);
    for (const p of pages) {
      const d = p.val as PDict;
      const r = doc.get(d, "Resources");
      out.push({ contents: contentsOf(doc, d), resources: isDict(r) ? r : null, rotate: 0 });
      if (out.length > PDF_TEXT_LIMITS.pagesMax) break;
    }
  }
  return out;
}

function contentsOf(doc: PdfDoc, page: PDict): PStream[] {
  const c = doc.get(page, "Contents");
  if (isStream(c)) return [c];
  if (Array.isArray(c)) return c.map((x) => doc.resolve(x)).filter(isStream);
  return [];
}

/** The filled-in form fields (`TU` or `T`, then `V`), joined by NUL for
 *  the row rendering. */
function fieldLines(doc: PdfDoc): string[] {
  const root = doc.resolve(doc.trailer.get("Root") ?? null);
  const form = isDict(root) ? doc.get(root, "AcroForm") : null;
  const fields = isDict(form) ? doc.get(form, "Fields") : null;
  if (!Array.isArray(fields)) return [];
  const out: string[] = [];
  const seen = new Set<number>();
  const visit = (ref: PVal, parentName: string, depth: number): void => {
    if (depth > 32 || out.length >= PDF_TEXT_LIMITS.fieldsMax) return;
    if (ref instanceof PRef) { if (seen.has(ref.num)) return; seen.add(ref.num); }
    const owner = doc.objOf(ref);
    const d = doc.resolve(ref);
    if (!isDict(d)) return;
    const tu = doc.textString(doc.get(d, "TU"), owner);
    const t = doc.textString(doc.get(d, "T"), owner);
    const name = tu || t || parentName;
    const kids = doc.get(d, "Kids");
    const v = doc.get(d, "V");
    if (v !== null) {
      const val = Array.isArray(v) ? v.map((x) => doc.textString(doc.resolve(x), owner)).join(", ") : doc.textString(v, owner);
      if (val !== "" && val !== "Off") out.push(`${name}\u0000${val}`);
    }
    if (Array.isArray(kids)) for (const k of kids) visit(k, name, depth + 1);
  };
  for (const f of fields) visit(f, "", 0);
  return out;
}
