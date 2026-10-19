/**
 * human-plane — the launcher's half of the arbiter's human plane
 * (docs/design/architecture/arbiter-human-plane.md). Mandu-new (no reference origin).
 *
 * The arbiter serves the ops that return ORIGINALS (desymbolize, shallow
 * resolve, events / subscribe / sessions / verifyEvents) only on a second
 * socket, `<runtime>/human/<instance>.sock`. The launcher:
 *
 *   1. learns its path from the arbiter's `hello` (`humanSock`) — never
 *      guessed, and never replaced by the data socket when absent;
 *   2. hands it to the HUMAN-FACING children only (the reply filter, fs-sync,
 *      net-proxy, and the context proxies, which read only row counts and the
 *      relay over it: reply-row-reservation.md §11.5) as
 *      `MANDU_ARBITER_HUMAN_SOCK`, and strips that variable
 *      from everything the agent inherits;
 *   3. walls the agent world off from the whole `human/` directory: the
 *      guard's always-deny `unixDeny` entry (applies with or without the
 *      Unix allow-list, `MANDU_UNIX_POLICY=0` included), a `--tmpfs` over it
 *      in the secret-twins bwrap, a Seatbelt deny on macOS, and no allow-list
 *      entry (policy.yaml, MANDU_UNIX_ALLOW, Claude Code's
 *      sandbox.network.allowUnixSockets) that equals, contains or lies in it.
 *
 * Pure except `readArbiterHumanSock` (one `hello` round trip) and
 * `applyHumanPlaneDeny` (the guard policy file).
 */
import { existsSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { mergeGuardPolicy, type GuardPolicyDeps } from "./guard-policy-file.js";
import { ndjsonCall } from "./secret-setup.js";

/** The variable naming the human-plane socket (arbiter/ipc/instance.ts
 *  HUMAN_SOCK_ENV). Human-facing children only; never the agent's. */
export const HUMAN_SOCK_ENV = "MANDU_ARBITER_HUMAN_SOCK";
/** The directory under the runtime base that holds the human sockets
 *  (arbiter/ipc/instance.ts HUMAN_DIR). */
export const HUMAN_DIR = "human";

/** `${runtimeBase}/human`. */
export function humanPlaneDir(runtimeBase: string): string {
  return join(runtimeBase.replace(/\/+$/, ""), HUMAN_DIR);
}

/**
 * The human socket the arbiter at `sock` reports (`hello().humanSock`), or
 * null: an arbiter older than the human plane, one serving none, or no
 * answer. Null means the human-facing children get NO human socket and
 * degrade by their own rules (the reply filter passes tokens through,
 * fs-sync and the egress paths refuse); the data socket is never offered in
 * its place.
 */
export async function readArbiterHumanSock(
  sock: string,
  call: (sock: string, op: string) => Promise<unknown> = (s, op) => ndjsonCall(s, op, {}, 5_000),
): Promise<string | null> {
  try {
    const r = (await call(sock, "hello")) as { humanSock?: unknown } | null;
    const h = r?.humanSock;
    return typeof h === "string" && h.startsWith("/") ? h : null;
  } catch {
    return null;
  }
}

/** The directories the agent world is walled off from: the reported human
 *  socket's directory and this launch's `${runtimeBase}/human` (the same
 *  directory in every normal deployment; both when a pinned arbiter runs
 *  under another runtime base). Deduplicated, in that order. */
export function humanPlaneDirs(humanSock: string | null | undefined, runtimeBase: string): string[] {
  const out: string[] = [];
  for (const d of [humanSock ? dirname(humanSock) : null, humanPlaneDir(runtimeBase)]) {
    if (d && d !== "/" && !out.includes(d)) out.push(d);
  }
  return out;
}

const norm = (p: string): string => (p.length > 1 ? p.replace(/\/+$/, "") : p);

/** Does `p` equal, contain or lie inside one of `dirs`? (An allow-list
 *  entry that does would reopen the human plane: an ancestor directory entry
 *  allows every socket below it.) Lexical, on absolute paths. */
export function touchesHumanPlane(p: string, dirs: readonly string[]): boolean {
  const q = norm(p);
  if (!q.startsWith("/")) return false;
  return dirs.some((raw) => {
    const d = norm(raw);
    return q === d || q.startsWith(d + "/") || d.startsWith(q === "/" ? "/" : q + "/");
  });
}

/** `env` without the human-socket variable: what the agent may inherit. */
export function withoutHumanSock<T extends Record<string, string | undefined>>(env: T): T {
  if (!(HUMAN_SOCK_ENV in env)) return env;
  const out = { ...env };
  delete out[HUMAN_SOCK_ENV];
  return out;
}

/** The env entry a HUMAN-FACING child gets: the human socket when the
 *  arbiter reported one, else an explicit unset (a stale ambient value must
 *  not point a child at some other arbiter's human plane). */
export function humanSockEnv(humanSock: string | null | undefined): Record<string, string | undefined> {
  return { [HUMAN_SOCK_ENV]: humanSock ?? undefined };
}

/**
 * Write the guard's always-deny Unix-connect list (`unixDeny`, read by
 * mandu-net-guard: net-supervisor secret_open.rs `unix_denied`). Applied
 * whenever the guard runs in a protecting mode, independently of the Unix
 * allow-list and its `MANDU_UNIX_POLICY=0` opt-out.
 */
export function applyHumanPlaneDeny(dirs: readonly string[], mutEnv: Record<string, string>, deps: GuardPolicyDeps & { log: (m: string) => void }): void {
  if (dirs.length === 0) return;
  mergeGuardPolicy(mutEnv, deps, { unixDeny: [...dirs] });
  deps.log(`mandu: human plane — the agent's programs cannot connect to Mandu's human-plane sockets (${dirs.join(", ")}); only the reply filter, fs-sync and the network proxy hold that channel`);
}

/**
 * Is this launch's agent world walled off from the human-plane socket
 * (confidentiality plan 13 D9 leftovers; arbiter-human-plane.md §8)? The
 * arbiter believes the guard's and the proxies' records on that socket only
 * while no launch whose agent can reach it is live, so every launch tells it
 * (`beginLaunch`'s `humanPlaneWalled`). Walled when the guard carries the
 * always-deny entry (`guardDeny`: applyHumanPlaneDeny ran), or, on Linux,
 * when the wrap puts a `--tmpfs` over every human-plane directory (each must
 * exist: one created after the launch would not be masked), or, on macOS,
 * when the applied Seatbelt profile carries the human-directory deny. No human directory known, or none of these: not walled
 * (fail closed). Pure but for the two filesystem seams.
 */
export function humanPlaneWalled(o: {
  dirs: readonly string[];
  guardDeny: boolean;
  launchPrefix: readonly string[];
  platform: string;
  /** The whole-agent profile was applied with every human directory denied. */
  seatbeltHumanDenied?: boolean;
  exists?: (p: string) => boolean;
  realpath?: (p: string) => string;
}): boolean {
  if (o.dirs.length === 0) return false;
  if (o.guardDeny) return true;
  if (o.platform === "darwin") return o.seatbeltHumanDenied === true;
  const exists = o.exists ?? existsSync;
  const real = o.realpath ?? ((p: string): string => { try { return realpathSync(p); } catch { return p; } });
  const masked = new Set<string>();
  for (let i = 0; i + 1 < o.launchPrefix.length; i++) {
    if (o.launchPrefix[i] === "--tmpfs") masked.add(norm(o.launchPrefix[i + 1]!));
  }
  return o.dirs.every((d) => exists(d) && (masked.has(norm(d)) || masked.has(norm(real(d)))));
}
