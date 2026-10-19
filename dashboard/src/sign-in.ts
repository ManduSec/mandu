/**
 * sign-in — one-time sign-in links for the human, handed out on a channel the
 * agent's world cannot reach (policy-surface.md §2.6 "Signing in";
 * dashboard.md §6.x). Mandu-new (no reference origin).
 *
 * The dashboard's mutating routes need an admin session, and without a
 * password that session used to be earned only through a per-boot link the
 * dashboard printed to its own stderr on a TTY. In the default flow the
 * dashboard is a background daemon (the launcher's stack autostart, `mandu
 * dashboard`), its stderr is a log, so nobody ever saw the link and every
 * approval timed out (2026-10-05).
 *
 * Now the dashboard serves a second listener: a Unix socket in the arbiter's
 * HUMAN-PLANE directory, `<runtime>/human/dashboard-<pid>.sock`. Every wall
 * the launcher builds around that directory (the guard's always-deny entry,
 * the secret-twins `--tmpfs`, Seatbelt, the Unix allow-list and Claude Code's
 * `allowUnixSockets` filter; arbiter-human-plane.md §6) covers this socket
 * too, so a program of a walled agent cannot connect to it. The human's own
 * terminal can: the launcher asks it for a link before the agent starts and
 * prints it on its dashboard line, and `mandu dashboard` asks it on request.
 *
 * A link carries a TICKET: 128 random bits, good for ONE sign-in, and only
 * for `ttlMs` (12 h by default, a working day: the launch line is printed
 * long before the first approval arrives). Redeeming it sets the dashboard's
 * ordinary admin-session cookie. A used ticket in the browser's history, or
 * an unused one past its time in a terminal's scrollback, signs nobody in.
 *
 * Fail closed: while a launch whose agent can reach the human-plane directory
 * is live (the arbiter's `humanPlaneStatus`, arbiter-human-plane.md §10.1),
 * or whenever that cannot be checked, no link is minted, and the answer says
 * why and what to do. A password or Basic-auth dashboard mints none: its
 * credentials are the session.
 */

import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, unlinkSync } from "node:fs";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";

import type { HumanPlaneStatus } from "./event-source/contract.js";

/** A ticket's default life: a working day (see the header). */
export const SIGN_IN_TTL_MS = 12 * 60 * 60 * 1000;
/** Outstanding tickets kept at most; the oldest is dropped past it (each
 *  launch mints one, and most are never used once a browser is signed in). */
export const SIGN_IN_MAX_TICKETS = 64;
/** The op the sign-in socket answers. */
export const SIGN_IN_OP = "signInLink";
/** The human-plane directory under the runtime base (arbiter/ipc/instance.ts
 *  HUMAN_DIR; duplicated so this package stays standalone). */
export const HUMAN_DIR = "human";

/** The one sentence every refusal of an admin action ends with: what to run. */
export const SIGN_IN_REMEDY =
  "run `mandu dashboard` in your own terminal and open the sign-in link it prints";

/**
 * One-time sign-in tickets, held in this process's memory only. A ticket is
 * stored by its SHA-256, so the map's lookup never compares the secret
 * itself byte by byte.
 */
export class SignInTickets {
  private readonly byHash = new Map<string, number>();
  private readonly ttlMs: number;
  private readonly max: number;
  private readonly now: () => number;
  private readonly random: () => string;

  constructor(opts: { ttlMs?: number; max?: number; now?: () => number; random?: () => string } = {}) {
    this.ttlMs = opts.ttlMs ?? SIGN_IN_TTL_MS;
    this.max = opts.max ?? SIGN_IN_MAX_TICKETS;
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? (() => randomBytes(16).toString("hex"));
  }

  /** A fresh ticket and when it stops working. */
  mint(): { ticket: string; expiresAt: number } {
    this.prune();
    while (this.byHash.size >= this.max) {
      const oldest = this.byHash.keys().next().value;
      if (oldest === undefined) break;
      this.byHash.delete(oldest);
    }
    const ticket = this.random();
    const expiresAt = this.now() + this.ttlMs;
    this.byHash.set(hashOf(ticket), expiresAt);
    return { ticket, expiresAt };
  }

  /** True once for a live ticket; it is spent either way it is presented
   *  after that (a second redeem, an expired one, a guess: false). */
  redeem(ticket: string): boolean {
    if (typeof ticket !== "string" || ticket.length === 0 || ticket.length > 256) return false;
    const h = hashOf(ticket);
    const expiresAt = this.byHash.get(h);
    if (expiresAt === undefined) return false;
    this.byHash.delete(h);
    return this.now() < expiresAt;
  }

  /** Outstanding (unspent, unexpired) tickets. */
  size(): number {
    this.prune();
    return this.byHash.size;
  }

  private prune(): void {
    const t = this.now();
    for (const [h, exp] of this.byHash) if (exp <= t) this.byHash.delete(h);
  }
}

function hashOf(ticket: string): string {
  return createHash("sha256").update(ticket).digest("hex");
}

/** What the sign-in socket answers. `path` is the login path under the
 *  dashboard's base path; the caller puts its own `http://host:port` before it. */
export type SignInAnswer =
  | { ok: true; path: string; expiresAt: number }
  | { ok: false; reason: "password" | "basic-auth" | "exposed" | "unknown" | "bad-request"; error: string };

export interface SignInDeps {
  /** How this dashboard signs a human in: tickets (no password), or its
   *  password / Basic-auth credentials (then no link is minted). */
  mode: () => "tickets" | "password" | "basic-auth";
  /** Mint one ticket's login path (`<base>/login?ticket=…`). */
  mintPath: () => { path: string; expiresAt: number };
  /** The arbiter's `humanPlaneStatus` (its human socket). Absent or failing
   *  = cannot tell = no link. */
  humanPlaneStatus?: () => Promise<HumanPlaneStatus>;
}

/**
 * The production wiring (server-main.ts): the server's mode and minting, and
 * the exposure read of EVERY arbiter whose human socket lives in `humanDir`
 * (the directory the sign-in socket shares; every arbiter under this runtime
 * base puts its human socket there, the test tenant's included, and a launch
 * records its exposure only with its own arbiter), plus the dashboard's own
 * event source (its human-plane client, which may live elsewhere). A source
 * without `humanPlaneStatus` (the file source of a demo) adds nothing; when
 * nothing answers at all, the check is unanswerable and no link is minted.
 */
export function signInDepsFor(
  server: { signInMode(): "tickets" | "password" | "basic-auth"; mintSignInPath(): { path: string; expiresAt: number } },
  source: { humanPlaneStatus?: () => Promise<HumanPlaneStatus> },
  humanDir?: string,
  ask: (sock: string) => Promise<HumanPlaneStatus> = askHumanPlaneStatus,
): SignInDeps {
  const own = typeof source.humanPlaneStatus === "function" ? () => source.humanPlaneStatus!() : null;
  if (own === null && humanDir === undefined) {
    return { mode: () => server.signInMode(), mintPath: () => server.mintSignInPath() };
  }
  return {
    mode: () => server.signInMode(),
    mintPath: () => server.mintSignInPath(),
    humanPlaneStatus: () => combinedHumanPlaneStatus(own, humanDir, ask),
  };
}

/** The arbiter sockets in a human-plane directory: every `*.sock` but the
 *  dashboards' sign-in sockets. */
export function arbiterHumanSocks(dir: string): string[] {
  let names: string[] = [];
  try { names = readdirSync(dir); } catch { return []; }
  return names.filter((n) => n.endsWith(".sock") && !/^dashboard-\d+\.sock$/.test(n)).sort().map((n) => join(dir, n));
}

/**
 * One exposure answer for all of them. An arbiter socket nobody listens on
 * (a dead arbiter's leftover: ECONNREFUSED, ENOENT) is skipped; any other
 * failure (a timeout, an older arbiter without the op) makes the whole answer
 * unknown, which mints nothing. Nothing answering at all is unknown too.
 */
export async function combinedHumanPlaneStatus(
  own: (() => Promise<HumanPlaneStatus>) | null,
  humanDir: string | undefined,
  ask: (sock: string) => Promise<HumanPlaneStatus> = askHumanPlaneStatus,
): Promise<HumanPlaneStatus> {
  const answers: HumanPlaneStatus[] = [];
  const asks: Promise<void>[] = [];
  if (own) asks.push(own().then((s) => { answers.push(s); }));
  for (const sock of humanDir ? arbiterHumanSocks(humanDir) : []) {
    asks.push(ask(sock).then(
      (s) => { answers.push(s); },
      (e: NodeJS.ErrnoException) => {
        if (e?.code === "ECONNREFUSED" || e?.code === "ENOENT") return; // a dead arbiter's socket file
        throw e;
      },
    ));
  }
  await Promise.all(asks);
  if (answers.length === 0) throw new Error("no protection service answered");
  for (const a of answers) {
    if (a === null || typeof a !== "object" || typeof a.exposed !== "boolean") throw new Error("a malformed answer");
  }
  const exposed = answers.filter((a) => a.exposed);
  if (exposed.length === 0) return { exposed: false, since: null, launches: [] };
  const seen = new Set<string>();
  const launches = exposed.flatMap((a) => a.launches ?? []).filter((l) => {
    const k = `${l.pid}/${l.session ?? ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const since = Math.min(...exposed.map((a) => a.since ?? Number.POSITIVE_INFINITY));
  return { exposed: true, since: Number.isFinite(since) ? since : null, launches };
}

/** `humanPlaneStatus` on one arbiter human socket: one NDJSON round trip
 *  (the arbiter's protocol, `{id, op}` → `{ok, result}`), 2 s deadline. */
export function askHumanPlaneStatus(sock: string, timeoutMs = 2_000): Promise<HumanPlaneStatus> {
  return new Promise((resolve, reject) => {
    const c = createConnection(sock);
    let buf = "";
    let settled = false;
    const done = (err: Error | null, val?: HumanPlaneStatus): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      c.destroy();
      if (err) reject(err); else resolve(val!);
    };
    const timer = setTimeout(() => done(new Error(`${sock}: no answer within ${timeoutMs} ms`)), timeoutMs);
    c.setEncoding("utf8");
    c.on("error", (e) => done(e));
    c.on("connect", () => c.write(JSON.stringify({ id: 1, op: "humanPlaneStatus" }) + "\n"));
    c.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const r = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; result?: HumanPlaneStatus; error?: string };
        if (r.ok === true) done(null, r.result);
        else done(new Error(`${sock}: ${r.error ?? "refused"}`));
      } catch (e) {
        done(e as Error);
      }
    });
  });
}

/**
 * Decide one request. Pure but for the deps. The exposure check is the
 * security half: the socket's walls hold only for a walled launch, so while
 * any launch runs without them, a program of that agent could be the caller.
 */
export async function answerSignIn(req: unknown, deps: SignInDeps): Promise<SignInAnswer> {
  const op = (req as { op?: unknown } | null)?.op;
  if (op !== SIGN_IN_OP) {
    return { ok: false, reason: "bad-request", error: `unknown op (this socket answers only '${SIGN_IN_OP}')` };
  }
  const mode = deps.mode();
  if (mode === "password") {
    return { ok: false, reason: "password", error: "this dashboard signs in with its password (DASHBOARD_PASSWORD)" };
  }
  if (mode === "basic-auth") {
    return { ok: false, reason: "basic-auth", error: "this dashboard signs in with its HTTP Basic credentials (DASHBOARD_BASIC_AUTH)" };
  }
  let status: HumanPlaneStatus | null = null;
  try {
    status = deps.humanPlaneStatus ? await deps.humanPlaneStatus() : null;
  } catch {
    status = null;
  }
  if (status === null || typeof status !== "object" || typeof status.exposed !== "boolean") {
    return {
      ok: false,
      reason: "unknown",
      error:
        "the dashboard could not ask the protection service whether an agent can reach Mandu's own controls, " +
        "so it hands out no sign-in link; start a session (`mandu claude`) or restart the stack (`mandu stop`), then try again",
    };
  }
  if (status.exposed) {
    const who = (status.launches ?? [])
      .map((l) => `pid ${l.pid}${l.session ? ` (session ${l.session})` : ""}`)
      .join(", ");
    return {
      ok: false,
      reason: "exposed",
      error:
        `an agent that can reach Mandu's own controls is running (${who || "a launch with no wall"}), ` +
        "so no sign-in link is handed out while it runs: a program of that agent could ask for one; " +
        "quit it (or start it again with its file guard on, not `--mode off` and not `--no-net-guard`), " +
        "or set DASHBOARD_PASSWORD",
    };
  }
  const minted = deps.mintPath();
  return { ok: true, path: minted.path, expiresAt: minted.expiresAt };
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
 * dropped. The socket is created 0600 inside a 0700 directory, but the walls
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
