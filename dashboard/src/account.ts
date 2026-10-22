/**
 * account — the one Mandu dashboard account (dashboard.md §6.z,
 * policy-surface.md §2.6 "Signing in"): a username and a salted scrypt hash
 * of its password, in the path table's `dashboard-account` file
 * (`~/.mandu/state/dashboard-account.json`, mode 0600).
 *
 * Mandu-new (no reference origin). The launcher writes the same file
 * (`mandu dashboard --set-password`, launcher/src/dashboard-account.ts, a
 * mirror the launcher ships standalone with; tests/stack
 * dashboard-account-parity proves the two agree byte for byte on the
 * format). This module also writes it once, when a dashboard started with
 * DASHBOARD_BASIC_AUTH finds no account (the migration, server-main.ts).
 *
 * What is on disk: the username, the scrypt parameters, a per-account random
 * salt and the derived key. Never the password, in any form a person could
 * read back.
 *
 * The file is a same-uid file (the threat model, dashboard.md §6.z): a
 * program the agent runs under Mandu cannot reach it (the whole Mandu home
 * is hidden and write-protected for a confined launch, on-disk-layout.md
 * §4), a program of this user outside Mandu can. So a file that is not this
 * user's own regular file, mode 0600 at most, with one link, is REFUSED
 * (`unsafe`): the dashboard signs nobody in until the person writes it again.
 */

import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, renameSync, rmSync, writeSync } from "node:fs";
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from "node:crypto";
import { dirname, join } from "node:path";

/** The record's version; a file of another version is `unsafe`. */
export const ACCOUNT_VERSION = 1;
/** scrypt cost. N = 2^15, r = 8: 32 MiB and ~50 ms a check on a laptop. */
export const SCRYPT_N = 32768;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
export const KEY_LENGTH = 32;
export const SALT_BYTES = 16;
/** A password shorter than this is refused when set (not when checked). */
export const MIN_PASSWORD_LENGTH = 8;
/** The longest username / password accepted (a form field, a header). */
export const MAX_FIELD_LENGTH = 1024;
/** The largest account file read. */
const MAX_FILE_BYTES = 8192;

/** The account record, as stored. */
export interface AccountRecord {
  version: number;
  user: string;
  kdf: "scrypt";
  N: number;
  r: number;
  p: number;
  keyLength: number;
  /** base64 */
  salt: string;
  /** base64 */
  hash: string;
  /** When it was set (ISO 8601), for the person; not trusted for anything. */
  setAt: string;
}

/** What reading the file found. `fingerprint`: a digest of its bytes, so a
 *  change of the file is seen (the dashboard logs it and ends every session). */
export type AccountRead =
  | { kind: "none" }
  | { kind: "ok"; account: AccountRecord; fingerprint: string }
  | { kind: "unsafe"; why: string };

function scrypt(password: string, salt: Buffer, keyLength: number, opts: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password, salt, keyLength, opts, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

/** scrypt's memory ceiling for the parameters (128 * N * r, with room). */
function maxmem(N: number, r: number): number {
  return 128 * N * r * 2 + 1024 * 1024;
}

/** Is `user` a username the account can have? Non-empty, no control
 *  characters, no ':' (a Basic header splits there, RFC 7617). */
export function usernameProblem(user: string): string | null {
  if (user === "") return "the username is empty";
  if (user.length > MAX_FIELD_LENGTH) return "the username is too long";
  if (user.includes(":")) return "the username cannot contain ':'";
  if (/[\u0000-\u001f\u007f]/.test(user)) return "the username cannot contain control characters";
  if (user.trim() !== user) return "the username cannot start or end with a space";
  return null;
}

/** Is `password` one the account may be set to? */
export function passwordProblem(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `the password needs at least ${MIN_PASSWORD_LENGTH} characters`;
  if (password.length > MAX_FIELD_LENGTH) return "the password is too long";
  return null;
}

/** Hash a new account. Throws on a username or password the account may not
 *  have (the caller's words say why). */
export async function makeAccount(user: string, password: string, now: Date = new Date(), opts: { minPassword?: boolean } = {}): Promise<AccountRecord> {
  const u = usernameProblem(user);
  if (u) throw new Error(u);
  // The migration hashes whatever DASHBOARD_BASIC_AUTH held (it already
  // signed in with it); a new password set by hand meets the minimum.
  const p = opts.minPassword === false ? (password === "" ? "the password is empty" : null) : passwordProblem(password);
  if (p) throw new Error(p);
  const salt = randomBytes(SALT_BYTES);
  const key = await scrypt(password, salt, KEY_LENGTH, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: maxmem(SCRYPT_N, SCRYPT_R) });
  return {
    version: ACCOUNT_VERSION, user, kdf: "scrypt", N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, keyLength: KEY_LENGTH,
    salt: salt.toString("base64"), hash: key.toString("base64"), setAt: now.toISOString(),
  };
}

/** The record's own problems (a hand-edited or planted file), null when it
 *  is one this module would write. Parameter bounds keep a planted file
 *  from making each check cost seconds. */
function recordProblem(r: unknown): string | null {
  if (r === null || typeof r !== "object" || Array.isArray(r)) return "not an account record";
  const a = r as Partial<AccountRecord>;
  if (a.version !== ACCOUNT_VERSION) return "an account record of another version";
  if (a.kdf !== "scrypt") return "an unknown password hash";
  if (typeof a.user !== "string" || usernameProblem(a.user) !== null) return "no valid username";
  const pow2 = (n: unknown): boolean => typeof n === "number" && Number.isInteger(n) && n >= 2 ** 14 && n <= 2 ** 20 && (n & (n - 1)) === 0;
  if (!pow2(a.N)) return "scrypt N out of range";
  if (a.r !== 8) return "scrypt r out of range";
  if (typeof a.p !== "number" || !Number.isInteger(a.p) || a.p < 1 || a.p > 4) return "scrypt p out of range";
  if (typeof a.keyLength !== "number" || !Number.isInteger(a.keyLength) || a.keyLength < 32 || a.keyLength > 64) return "key length out of range";
  if (typeof a.salt !== "string" || Buffer.from(a.salt, "base64").length < SALT_BYTES) return "no salt";
  if (typeof a.hash !== "string" || Buffer.from(a.hash, "base64").length !== a.keyLength) return "no password hash";
  return null;
}

const digest = (s: string): Buffer => createHash("sha256").update(s, "utf8").digest();

/** Do `user` and `password` match the account? scrypt runs whatever the
 *  username, and both comparisons are constant-time. */
export async function verifyAccount(account: AccountRecord, user: string, password: string): Promise<boolean> {
  if (user.length > MAX_FIELD_LENGTH || password.length > MAX_FIELD_LENGTH) return false;
  const want = Buffer.from(account.hash, "base64");
  const got = await scrypt(password, Buffer.from(account.salt, "base64"), account.keyLength, {
    N: account.N, r: account.r, p: account.p, maxmem: maxmem(account.N, account.r),
  });
  const userOk = timingSafeEqual(digest(user), digest(account.user));
  const passOk = got.length === want.length && timingSafeEqual(got, want);
  return userOk && passOk;
}

/** The current user's uid; undefined where there is none (Windows). */
function myUid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

/**
 * Read the account file. Opened without following a link; then the open
 * file itself is checked (a regular file, this user's, one link, no group
 * or other bits). Never throws.
 */
export function readAccount(path: string, uid: number | undefined = myUid()): AccountRead {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { kind: "none" };
    if (code === "ELOOP") return { kind: "unsafe", why: "the account file is a symbolic link" };
    return { kind: "unsafe", why: `the account file cannot be read (${code ?? (e as Error).message})` };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { kind: "unsafe", why: "the account file is not a regular file" };
    if (uid !== undefined && st.uid !== uid) return { kind: "unsafe", why: "the account file belongs to another user" };
    if ((st.mode & 0o077) !== 0) return { kind: "unsafe", why: `the account file is readable or writable by others (mode ${(st.mode & 0o777).toString(8)}; it must be 600)` };
    if (st.nlink !== 1) return { kind: "unsafe", why: "the account file has another name (a hard link)" };
    if (st.size > MAX_FILE_BYTES) return { kind: "unsafe", why: "the account file is too large" };
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    const text = buf.subarray(0, off).toString("utf8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return { kind: "unsafe", why: "the account file is not a Mandu account record" };
    }
    const problem = recordProblem(parsed);
    if (problem) return { kind: "unsafe", why: `the account file holds ${problem}` };
    return { kind: "ok", account: parsed as AccountRecord, fingerprint: createHash("sha256").update(buf.subarray(0, off)).digest("hex") };
  } catch (e) {
    return { kind: "unsafe", why: `the account file cannot be read (${(e as Error).message})` };
  } finally {
    closeSync(fd);
  }
}

/** The directory the file goes in must be this user's real directory, not
 *  writable by others; made 0700 when missing. Throws to refuse. */
function ensureAccountDir(dir: string, uid: number | undefined): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`${dir} is not a directory`);
  if (uid !== undefined && st.uid !== uid) throw new Error(`${dir} belongs to another user`);
  if ((st.mode & 0o022) !== 0) throw new Error(`${dir} is writable by others`);
}

/**
 * Write the account file whole: a fresh 0600 file beside it, synced, then
 * renamed over it (a reader sees the old record or the new one). A link at
 * the path is replaced, never followed. Throws to refuse.
 */
export function writeAccount(path: string, record: AccountRecord, uid: number | undefined = myUid()): void {
  const problem = recordProblem(record);
  if (problem) throw new Error(`refusing to write ${problem}`);
  const dir = dirname(path);
  ensureAccountDir(dir, uid);
  const tmp = join(dir, `.dashboard-account.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeSync(fd, JSON.stringify(record, null, 2) + "\n");
    fsyncSync(fd);
  } catch (e) {
    closeSync(fd);
    rmSync(tmp, { force: true });
    throw e;
  }
  closeSync(fd);
  try {
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

/**
 * The account as the dashboard reads it: the file read again only when its
 * metadata changed (one lstat a request), and whether it changed while this
 * dashboard ran (a change is logged and shown on Home, and ends every
 * session, dashboard.md §6.z). The first read is the baseline, not a change.
 */
export class AccountFile {
  private key: string | null = null;
  private last: AccountRead = { kind: "none" };
  private fingerprint: string | null | undefined = undefined;
  private changed: Date | null = null;
  private onChange: ((why: string) => void) | undefined;

  constructor(
    readonly path: string,
    opts: { onChange?: (why: string) => void; now?: () => Date; uid?: number } = {},
  ) {
    this.onChange = opts.onChange;
    this.now = opts.now ?? (() => new Date());
    this.uid = opts.uid ?? myUid();
  }
  private readonly now: () => Date;
  private readonly uid: number | undefined;

  /** The account now. Never throws. */
  read(): AccountRead {
    let key: string;
    try {
      const st = lstatSync(this.path);
      key = `${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}:${st.mode}:${st.uid}:${st.nlink}`;
    } catch {
      key = "absent";
    }
    if (key !== this.key) {
      this.key = key;
      this.last = readAccount(this.path, this.uid);
      const fp = this.last.kind === "ok" ? this.last.fingerprint : this.last.kind === "none" ? null : `unsafe:${this.last.why}`;
      if (this.fingerprint !== undefined && fp !== this.fingerprint) {
        this.changed = this.now();
        const what = this.last.kind === "ok" ? `now for user ${this.last.account.user}` : this.last.kind === "none" ? "removed" : `now refused: ${this.last.why}`;
        this.onChange?.(what);
      }
      this.fingerprint = fp;
    }
    return this.last;
  }

  /** When the file last changed while this dashboard ran; null: it did not. */
  changedAt(): Date | null {
    return this.changed;
  }
}
