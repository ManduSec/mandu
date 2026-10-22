/**
 * sign-in — the dashboard's human-plane socket (policy-surface.md §2.6
 * "Signing in"; dashboard.md §6.x, §6.z). Mandu-new (no reference origin).
 *
 * The dashboard serves a second listener: a Unix socket in the arbiter's
 * HUMAN-PLANE directory, `<runtime>/human/dashboard-<pid>.sock`. Every wall
 * the launcher builds around that directory (the guard's always-deny entry,
 * the secret-twins `--tmpfs`, Seatbelt, the Unix allow-list and Claude Code's
 * `allowUnixSockets` filter; arbiter-human-plane.md §6) covers this socket
 * too, so a program of a walled agent cannot connect to it.
 *
 * Until 2026-10-22 it minted one-time sign-in links. A person now signs in
 * with the Mandu dashboard account (dashboard.md §6.z), so the socket's
 * `signInLink` op only says HOW this dashboard signs a person in (the
 * account, no account yet, an account that cannot be used, or an in-memory
 * username and password): the launcher's dashboard line and `mandu
 * dashboard` say it in words. No link is minted any more; the op keeps its
 * name so an older launcher still gets an answer it reads.
 *
 * The same socket answers `sessionKept` (2026-10-21, dashboard.md §4.25ah):
 * the launcher, after its agent exits, asks what Mandu kept from the AI in
 * that session and prints the answer's line in the human's terminal. It
 * carries names, paths, hosts and counts, never a value.
 */

import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, unlinkSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";

import type { SessionKept } from "./view-model/session-kept.js";

/** The op the sign-in socket answers. */
export const SIGN_IN_OP = "signInLink";
/** The socket's second op: what Mandu kept from the AI in one session, for
 *  the line the launcher prints when that session ends (dashboard.md
 *  §4.25ah). Names, paths, hosts and counts, never a value and never a
 *  credential, so it needs no exposure check: a program of an agent with no
 *  wall can read the same facts from Home. */
export const SESSION_KEPT_OP = "sessionKept";
/** How long a `sessionKept` answer may take (the session's record is read
 *  and modeled once); the sign-in op keeps the 2 s limit. */
export const SESSION_KEPT_DEADLINE_MS = 8_000;
/** A session id the op accepts: the launcher's scope ids and named ids. */
const SESSION_ID_RE = /^[A-Za-z0-9._:@-]{1,200}$/;
/** The human-plane directory under the runtime base (arbiter/ipc/instance.ts
 *  HUMAN_DIR; duplicated so this package stays standalone). */
export const HUMAN_DIR = "human";

/** The one sentence every refusal of an admin action ends with: what to do. */
export const SIGN_IN_REMEDY =
  "sign in with your Mandu dashboard account (no account yet: run `mandu dashboard --set-password` in your own terminal)";

/** How this dashboard signs a person in (server.ts `signInMode`). */
export type SignInMode = "account" | "no-account" | "account-unusable" | "basic-auth" | "none";

/** What the sign-in socket answers to `signInLink`: never a link now, the
 *  way this dashboard signs a person in. */
export type SignInAnswer = {
  ok: false;
  reason: "account" | "no-account" | "account-unusable" | "basic-auth" | "bad-request";
  error: string;
};

export interface SignInDeps {
  /** How this dashboard signs a person in. */
  mode: () => SignInMode;
  /** What Mandu kept from the AI in a session (server.ts `sessionKept`).
   *  Absent: the socket answers `sessionKept` with `found: false`. */
  sessionKept?: (id: string) => Promise<{ kept: SessionKept; line: string } | null>;
}

/** What the socket answers to `sessionKept`. */
export type SessionKeptAnswer =
  | { ok: true; found: true; line: string; kept: SessionKept }
  | { ok: true; found: false }
  | { ok: false; reason: "bad-request" | "unknown"; error: string };

/** Decide one `sessionKept` request. Pure but for the deps. A failure to
 *  read the record is `unknown`; the launcher then prints nothing. */
export async function answerSessionKept(req: unknown, deps: SignInDeps): Promise<SessionKeptAnswer> {
  const session = (req as { session?: unknown } | null)?.session;
  if (typeof session !== "string" || !SESSION_ID_RE.test(session)) {
    return { ok: false, reason: "bad-request", error: "sessionKept needs a session id" };
  }
  if (!deps.sessionKept) return { ok: true, found: false };
  let got: { kept: SessionKept; line: string } | null;
  try {
    got = await deps.sessionKept(session);
  } catch (e) {
    return { ok: false, reason: "unknown", error: `could not read the session's record (${(e as Error).message})` };
  }
  return got ? { ok: true, found: true, line: got.line, kept: got.kept } : { ok: true, found: false };
}

/** The production wiring (server-main.ts): the server's mode and its
 *  `sessionKept`. */
export function signInDepsFor(
  server: { signInMode(): SignInMode; sessionKept?: (id: string) => Promise<{ kept: SessionKept; line: string } | null> },
): SignInDeps {
  const kept = typeof server.sessionKept === "function" ? { sessionKept: (id: string) => server.sessionKept!(id) } : {};
  return { mode: () => server.signInMode(), ...kept };
}

/** Decide one `signInLink` request: how this dashboard signs a person in.
 *  Pure but for the deps. */
export async function answerSignIn(req: unknown, deps: SignInDeps): Promise<SignInAnswer> {
  const op = (req as { op?: unknown } | null)?.op;
  if (op !== SIGN_IN_OP) {
    return { ok: false, reason: "bad-request", error: `unknown op (this socket answers only '${SIGN_IN_OP}' and '${SESSION_KEPT_OP}')` };
  }
  switch (deps.mode()) {
    case "basic-auth":
      return { ok: false, reason: "basic-auth", error: "this dashboard signs in with its username and password (DASHBOARD_BASIC_AUTH, held in memory)" };
    case "account":
      return { ok: false, reason: "account", error: "this dashboard signs in with your Mandu dashboard account" };
    case "account-unusable":
      return { ok: false, reason: "account-unusable", error: "this dashboard's account cannot be used; run `mandu dashboard --set-password` to set it again" };
    default:
      return { ok: false, reason: "no-account", error: "this dashboard has no account yet; run `mandu dashboard --set-password` to make one" };
  }
}

/** `<runtimeBase>/human/dashboard-<pid>.sock`. */
export function signInSockPath(runtimeBase: string, pid: number = process.pid): string {
  return join(runtimeBase, HUMAN_DIR, `dashboard-${pid}.sock`);
}

/**
 * Create `dir` (0700) when absent, then verify it: a real directory, ours,
 * no group or other bits (mirror of arbiter/ipc/instance.ts
 * ensurePrivateDir, which the arbiter applies to the same directory). Throws
 * otherwise: the sign-in socket is not served from a directory someone else
 * controls.
 */
export function ensurePrivateDir(dir: string): void {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { chmodSync(dir, 0o700); } catch { /* verified below */ }
  }
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`${dir} is not a real directory`);
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    throw new Error(`${dir} is owned by uid ${st.uid}, not ${process.getuid()}`);
  }
  if ((st.mode & 0o077) !== 0) throw new Error(`${dir} has mode ${(st.mode & 0o777).toString(8)}, not 700 (fix: chmod 700 ${dir})`);
}

/** Remove `dashboard-<pid>.sock` files of dead dashboards (a SIGKILL leaves
 *  them). Never touches the arbiter's sockets. Returns the removed names. */
export function sweepDeadSignInSocks(dir: string, pidAlive: (pid: number) => boolean): string[] {
  try { lstatSync(dir); } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw e;
  }
  ensurePrivateDir(dir);
  let names: string[] = [];
  try { names = readdirSync(dir); } catch { return []; }
  const removed: string[] = [];
  for (const name of names) {
    const m = /^dashboard-(\d+)\.sock$/.exec(name);
    if (!m || pidAlive(Number(m[1]))) continue;
    try { unlinkSync(join(dir, name)); removed.push(name); } catch { /* raced */ }
  }
  return removed;
}

/**
 * Serve the sign-in socket at `path`: one NDJSON request per connection, one
 * answer, then close. A request larger than 4 KiB or slower than 2 s is
 * dropped; a `sessionKept` answer may take SESSION_KEPT_DEADLINE_MS. The socket is created 0600 inside a 0700 directory, but the walls
 * are what keep the agent out (a mode means nothing to the same uid).
 */
export async function serveSignInChannel(path: string, deps: SignInDeps): Promise<{ path: string; close: () => Promise<void> }> {
  const dir = path.slice(0, path.lastIndexOf("/"));
  ensurePrivateDir(dir);
  try { unlinkSync(path); } catch { /* none */ }
  const server: Server = createServer((sock: Socket) => {
    let buf = "";
    let done = false;
    const timer = setTimeout(() => sock.destroy(), 2_000);
    sock.setEncoding("utf8");
    sock.on("error", () => { /* the peer went away */ });
    sock.on("close", () => clearTimeout(timer));
    sock.on("data", (chunk: string) => {
      if (done) return;
      buf += chunk;
      if (buf.length > 4096) { done = true; sock.destroy(); return; }
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      done = true;
      let req: unknown = null;
      try { req = JSON.parse(buf.slice(0, nl)); } catch { req = null; }
      if ((req as { op?: unknown } | null)?.op === SESSION_KEPT_OP) {
        // The session's record is read and modeled: a longer deadline.
        clearTimeout(timer);
        const slow = setTimeout(() => sock.destroy(), SESSION_KEPT_DEADLINE_MS);
        sock.on("close", () => clearTimeout(slow));
        void answerSessionKept(req, deps).then(
          (answer) => { sock.end(JSON.stringify(answer) + "\n"); },
          () => { sock.end(JSON.stringify({ ok: false, reason: "unknown", error: "internal error" }) + "\n"); },
        );
        return;
      }
      void answerSignIn(req, deps).then(
        (answer) => { sock.end(JSON.stringify(answer) + "\n"); },
        () => { sock.end(JSON.stringify({ ok: false, reason: "unknown", error: "internal error" }) + "\n"); },
      );
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, () => { server.off("error", reject); resolve(); });
  });
  try { chmodSync(path, 0o600); } catch { /* best-effort; the walls are the boundary */ }
  return {
    path,
    close: () => new Promise<void>((resolve) => {
      server.close(() => resolve());
      try { unlinkSync(path); } catch { /* gone */ }
    }),
  };
}
