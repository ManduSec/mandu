/**
 * transcript-suggestions — the files `mandu scan` found a key of in the
 * agents' past sessions, made into plan 14 suggestions in the RUNNING
 * arbiter (confidentiality-plan-17-past-sessions-scan.md §3 item 13).
 *
 * The scan runs in a throwaway arbiter (plan 17 §3 item 7) and forgets its
 * values; the launcher then names to the running arbiter only the FILES and
 * the key NAMES its "your secrets" findings came from (`suggestFromScan`).
 * A caller's claim is never believed as it is: this module checks each file
 * itself before anything is filed. The file must be a regular file under
 * HOME (not a link), not an agent's own login or data, not Mandu's own
 * state, and the arbiter's own extractor must read in it a credential
 * (`knownIsCredential`) under one of the names the caller gave. Only then is
 * it a candidate, and the generator (policy-suggestions.ts
 * `suggestPastSessionEdits`) still drops a file the law covers. So the op
 * files nothing the workspace scan could not file from a root the caller
 * names, and everything it files is a tightening the person still applies.
 * No value leaves this module: it answers names and paths.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { dirname, isAbsolute, normalize } from "node:path";
import { extractSecretSpans } from "./secret-extract.js";
import { knownIsCredential } from "./transcript-scan.js";
import type { PastSessionsFile } from "./policy-suggestions.js";

/** At most this many files in one call (a scan lists a handful). */
export const SCAN_CLAIMS_MAX = 64;
/** A file over this is not read (the scan's own reader stops at 4 MiB). */
export const SCAN_CLAIM_FILE_MAX = 4 * 1024 * 1024;

/** One file as the caller names it: no value, only the path and names. */
export interface ScanFileClaim {
  path: string;
  names: string[];
  sessions: number;
  last: string | null;
}

/** Why a named file was not made a candidate. */
export type ScanClaimRefusal = "not-under-home" | "not-a-file" | "agent-own" | "mandu-state" | "no-credential";

/** The request's `files`, checked for shape; an error string otherwise. */
export function parseScanFileClaims(raw: unknown): ScanFileClaim[] | { error: string } {
  if (!Array.isArray(raw)) return { error: "files must be a list" };
  if (raw.length > SCAN_CLAIMS_MAX) return { error: `at most ${SCAN_CLAIMS_MAX} files` };
  const out: ScanFileClaim[] = [];
  for (const f of raw) {
    if (f === null || typeof f !== "object") return { error: "each file must be an object" };
    const o = f as Record<string, unknown>;
    if (typeof o["path"] !== "string" || !isAbsolute(o["path"]) || o["path"].length > 4096 || o["path"].includes("\0")) {
      return { error: "each file's path must be an absolute path" };
    }
    const names = o["names"];
    if (!Array.isArray(names) || names.length === 0 || names.length > 32 || !names.every((n) => typeof n === "string" && n.length > 0 && n.length <= 256)) {
      return { error: "each file's names must be 1 to 32 key names" };
    }
    const sessions = o["sessions"] === undefined ? 0 : o["sessions"];
    if (typeof sessions !== "number" || !Number.isInteger(sessions) || sessions < 0 || sessions > 10_000_000) {
      return { error: "each file's sessions must be a count" };
    }
    const last = o["last"] === undefined || o["last"] === null ? null : o["last"];
    if (last !== null && (typeof last !== "string" || last.length > 40 || Number.isNaN(Date.parse(last)))) {
      return { error: "each file's last must be a time" };
    }
    out.push({ path: normalize(o["path"]), names: [...new Set(names as string[])], sessions, last: last === null ? null : new Date(last).toISOString() });
  }
  return out;
}

/** Read a regular file without following a link or blocking on a FIFO, up
 *  to the cap; null when it is anything else or too big. The workspace
 *  scan's rule (plan 14 §13.1). */
export function readRegularFile(path: string, max = SCAN_CLAIM_FILE_MAX): string | null {
  try {
    const st = lstatSync(path);
    if (!st.isFile() || st.size > max) return null;
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
    try {
      const fst = fstatSync(fd);
      if (!fst.isFile() || fst.size > max) return null;
      const buf = Buffer.alloc(Math.min(fst.size, max) + 1);
      let n = 0;
      for (;;) {
        const r = readSync(fd, buf, n, buf.length - n, null);
        if (r <= 0) break;
        n += r;
        if (n >= buf.length) return null;
      }
      return buf.subarray(0, n).toString("utf8");
    } finally {
      closeSync(fd);
    }
  } catch {
    return null;
  }
}

export interface VerifyDeps {
  home: string;
  /** The file's text, or null (not a regular file, too big, unreadable). */
  read: (path: string) => string | null;
  /** An agent's own login or data (`agentFileOf`): a lock would break the
   *  agent, and a launch keeps them raw on purpose. */
  agentOwn: (path: string) => boolean;
  /** Mandu's own state (its home, its state base). */
  manduState: (path: string) => boolean;
  /** Does this folder hold a `.git` entry (a work tree's top)? */
  isWorkTree?: (dir: string) => boolean;
}

/** The nearest folder above `path` and below HOME that holds `.git`, else
 *  the file's own folder: the suggestion's `repoRoot`, which the launch's
 *  "in this project" count groups by. Never HOME itself (a key in
 *  `~/.config` is no project's). */
export function claimRepoRoot(path: string, home: string, isWorkTree: (dir: string) => boolean = () => false): string {
  const own = dirname(path);
  for (let d = own; d !== home && d.startsWith(home + "/"); d = dirname(d)) {
    if (isWorkTree(d)) return d;
  }
  return own;
}

/** One claim checked against the file itself. */
export function verifyScanFile(claim: ScanFileClaim, deps: VerifyDeps): { ok: true; file: PastSessionsFile } | { ok: false; why: ScanClaimRefusal } {
  const home = deps.home.replace(/\/+$/, "");
  if (!claim.path.startsWith(home + "/")) return { ok: false, why: "not-under-home" };
  if (deps.manduState(claim.path)) return { ok: false, why: "mandu-state" };
  if (deps.agentOwn(claim.path)) return { ok: false, why: "agent-own" };
  const text = deps.read(claim.path);
  if (text === null) return { ok: false, why: "not-a-file" };
  const wanted = new Set(claim.names);
  const names = new Set<string>();
  for (const sp of extractSecretSpans(claim.path, text).spans) {
    if (!wanted.has(sp.key)) continue;
    if (knownIsCredential({ value: sp.value, path: claim.path, name: sp.key })) names.add(sp.key);
  }
  if (names.size === 0) return { ok: false, why: "no-credential" };
  return {
    ok: true,
    file: {
      path: claim.path,
      repoRoot: claimRepoRoot(claim.path, home, deps.isWorkTree),
      names: [...names].sort(),
      sessions: claim.sessions,
      last: claim.last,
    },
  };
}
