/**
 * dashboard-account — `mandu dashboard --set-password`: the one Mandu
 * dashboard account (dashboard.md §6.z, policy-surface.md §2.6 "Signing
 * in"), asked for in the person's own terminal and stored as a salted scrypt
 * hash in the path table's `dashboard-account` file.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code. The record's
 * format, the hash and the safe write MIRROR dashboard/src/account.ts (the
 * launcher ships standalone, so it cannot import the dashboard's source);
 * tests/stack/dashboard-account-parity.test.ts proves a record either one
 * writes is one the other reads and verifies.
 *
 * Asked only on a terminal: the password is read with echo off, twice, and
 * never printed, logged, put in an argument or the environment.
 */

import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, renameSync, rmSync, writeSync } from "node:fs";
import { randomBytes, scrypt as scryptCb, type ScryptOptions } from "node:crypto";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

import { manduPath } from "./generated/mandu-paths.js";

type Env = Record<string, string | undefined>;

// ── the record (mirror of dashboard/src/account.ts) ───────────────────────────

export const ACCOUNT_VERSION = 1;
export const SCRYPT_N = 32768;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
export const KEY_LENGTH = 32;
export const SALT_BYTES = 16;
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_FIELD_LENGTH = 1024;

export interface AccountRecord {
  version: number;
  user: string;
  kdf: "scrypt";
  N: number;
  r: number;
  p: number;
  keyLength: number;
  salt: string;
  hash: string;
  setAt: string;
}

function scrypt(password: string, salt: Buffer, keyLength: number, opts: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password, salt, keyLength, opts, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

export function usernameProblem(user: string): string | null {
  if (user === "") return "the username is empty";
  if (user.length > MAX_FIELD_LENGTH) return "the username is too long";
  if (user.includes(":")) return "the username cannot contain ':'";
  if (/[\u0000-\u001f\u007f]/.test(user)) return "the username cannot contain control characters";
  if (user.trim() !== user) return "the username cannot start or end with a space";
  return null;
}

export function passwordProblem(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `the password needs at least ${MIN_PASSWORD_LENGTH} characters`;
  if (password.length > MAX_FIELD_LENGTH) return "the password is too long";
  return null;
}

export async function makeAccount(user: string, password: string, now: Date = new Date()): Promise<AccountRecord> {
  const u = usernameProblem(user);
  if (u) throw new Error(u);
  const p = passwordProblem(password);
  if (p) throw new Error(p);
  const salt = randomBytes(SALT_BYTES);
  const key = await scrypt(password, salt, KEY_LENGTH, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 128 * SCRYPT_N * SCRYPT_R * 2 + 1024 * 1024 });
  return {
    version: ACCOUNT_VERSION, user, kdf: "scrypt", N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, keyLength: KEY_LENGTH,
    salt: salt.toString("base64"), hash: key.toString("base64"), setAt: now.toISOString(),
  };
}

const myUid = (): number | undefined => (typeof process.getuid === "function" ? process.getuid() : undefined);

/** The account's user when a usable file is there; `unsafe` with why; null
 *  when there is none. Opened without following a link, checked as the
 *  dashboard checks it. */
export function accountState(path: string, uid: number | undefined = myUid()): { user: string } | { unsafe: string } | null {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    return { unsafe: code === "ELOOP" ? "the account file is a symbolic link" : `the account file cannot be read (${code ?? (e as Error).message})` };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { unsafe: "the account file is not a regular file" };
    if (uid !== undefined && st.uid !== uid) return { unsafe: "the account file belongs to another user" };
    if ((st.mode & 0o077) !== 0) return { unsafe: "the account file is readable or writable by others" };
    if (st.nlink !== 1) return { unsafe: "the account file has another name (a hard link)" };
    const buf = Buffer.alloc(Math.min(st.size, 8192));
    const n = readSync(fd, buf, 0, buf.length, 0);
    const rec = JSON.parse(buf.subarray(0, n).toString("utf8")) as Partial<AccountRecord>;
    return typeof rec.user === "string" && rec.kdf === "scrypt" ? { user: rec.user } : { unsafe: "the account file is not a Mandu account record" };
  } catch {
    return { unsafe: "the account file is not a Mandu account record" };
  } finally {
    closeSync(fd);
  }
}

/** Write the record whole: a fresh 0600 file beside it, synced, renamed over
 *  the path (a link there is replaced, never followed); the directory made
 *  0700 and checked to be this user's own. Throws to refuse. */
export function writeAccount(path: string, record: AccountRecord, uid: number | undefined = myUid()): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`${dir} is not a directory`);
  if (uid !== undefined && st.uid !== uid) throw new Error(`${dir} belongs to another user`);
  if ((st.mode & 0o022) !== 0) throw new Error(`${dir} is writable by others`);
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

/** The account file of this Mandu home (the path table's `dashboard-account`). */
export function accountPath(env: Env): string {
  return manduPath("dashboard-account", env, env["HOME"] || homedir());
}

// ── the command ──────────────────────────────────────────────────────────────

/** Injectable terminal I/O for `--set-password` (tests never read a TTY). */
export interface SetPasswordDeps {
  /** Both stdin and stdout are a terminal. */
  isTTY: boolean;
  /** Ask a line, echoed (the username). null: input ended. */
  askLine: (prompt: string) => Promise<string | null>;
  /** Ask a line with echo off (the password). null: input ended. */
  askSecret: (prompt: string) => Promise<string | null>;
  out: (s: string) => void;
  err: (s: string) => void;
  /** The account file (default: the Mandu home's). */
  path: string;
  now?: () => Date;
}

/**
 * `mandu dashboard --set-password`: ask a username (the current one is the
 * default) and a password twice, then write the hash. Exit 0 when written,
 * 1 when it could not be, 2 when not on a terminal or the input ended.
 */
export async function runSetPassword(deps: SetPasswordDeps): Promise<number> {
  if (!deps.isTTY) {
    deps.err("mandu: --set-password asks for the password in a terminal; run it in your own terminal (the password is never taken from an argument or the environment).\n");
    return 2;
  }
  const state = accountState(deps.path);
  const current = state !== null && "user" in state ? state.user : null;
  if (state !== null && "unsafe" in state) deps.out(`The account file cannot be used now (${state.unsafe}); this writes it again.\n`);
  deps.out(current !== null
    ? `Set a new password for your Mandu dashboard account (user ${current}).\n`
    : "Make your Mandu dashboard account: the username and password every dashboard page asks for.\n");
  let user = "";
  for (;;) {
    const got = await deps.askLine(current !== null ? `Username [${current}]: ` : "Username: ");
    if (got === null) return 2;
    user = got.trim() === "" && current !== null ? current : got.trim();
    const problem = usernameProblem(user);
    if (!problem) break;
    deps.err(`mandu: ${problem}; try again.\n`);
  }
  let password = "";
  for (;;) {
    const first = await deps.askSecret("Password: ");
    if (first === null) return 2;
    const problem = passwordProblem(first);
    if (problem) { deps.err(`mandu: ${problem}; try again.\n`); continue; }
    const again = await deps.askSecret("Password again: ");
    if (again === null) return 2;
    if (again !== first) { deps.err("mandu: the two passwords differ; try again.\n"); continue; }
    password = first;
    break;
  }
  try {
    writeAccount(deps.path, await makeAccount(user, password, deps.now?.() ?? new Date()));
  } catch (e) {
    deps.err(`mandu: could not write the dashboard account at ${deps.path}: ${(e as Error).message}\n`);
    return 1;
  }
  deps.out(
    `Saved your dashboard account (user ${user}) in ${deps.path}: only a scrambled form of the password (a scrypt hash), never the password.\n` +
    "A running dashboard uses it now, and every browser signed in before signs in again. Sign in on the dashboard's page with this username and password.\n",
  );
  return 0;
}

/** Read one line from the terminal; with `hidden`, echo off (raw mode,
 *  '*' never shown either). Backspace edits, Ctrl-C and Ctrl-D end it. */
export function terminalLine(prompt: string, hidden: boolean): Promise<string | null> {
  const stdin = process.stdin;
  process.stdout.write(prompt);
  return new Promise((resolve) => {
    let buf = "";
    const wasRaw = stdin.isRaw === true;
    const done = (v: string | null): void => {
      stdin.off("data", onData);
      try { stdin.setRawMode?.(wasRaw); } catch { /* not a terminal any more */ }
      stdin.pause();
      process.stdout.write("\n");
      resolve(v);
    };
    const onData = (d: Buffer | string): void => {
      for (const ch of typeof d === "string" ? d : d.toString("utf8")) {
        if (ch === "\r" || ch === "\n") return done(buf);
        if (ch === "\u0003" || ch === "\u0004") return done(null);
        if (ch === "\u007f" || ch === "\b") {
          if (buf.length > 0) {
            buf = buf.slice(0, -1);
            if (!hidden) process.stdout.write("\b \b");
          }
          continue;
        }
        if (ch < " ") continue;
        buf += ch;
        if (!hidden) process.stdout.write(ch);
      }
    };
    try { stdin.setRawMode?.(true); } catch { /* line mode */ }
    stdin.on("data", onData);
    stdin.resume();
  });
}

export function realSetPasswordDeps(env: Env): SetPasswordDeps {
  return {
    isTTY: process.stdin.isTTY === true && process.stdout.isTTY === true,
    askLine: (p) => terminalLine(p, false),
    askSecret: (p) => terminalLine(p, true),
    out: (s) => { process.stdout.write(s); },
    err: (s) => { process.stderr.write(s); },
    path: accountPath(env),
  };
}
