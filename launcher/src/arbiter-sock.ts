/**
 * arbiter-sock — client-side arbiter socket resolution for the launcher
 * (runtime-instances.md §3, §5).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): mirrors arbiter/ipc/instance.ts
 * `runtimeBase()`/`resolveArbiterSock()` — each package stays standalone (the
 * same rule as the dashboard/src/server-main.ts and integration
 * live-shared.ts mirrors). Keep the resolution order in sync:
 *
 *   1. $MANDU_ARBITER_SOCK ($MANDU_ARBITER_SOCKET legacy alias) verbatim
 *      → "pinned": the caller owns the path; an autostart binds THERE.
 *   2. ${base}/current/arbiter.sock when it resolves — the promoted instance.
 *   3. ${base}/arbiter.sock when it exists — the legacy fixed path (compat).
 *   4. Nothing live → the `current` spelling anyway ("autostart"): the
 *      instance-mode autostart (MANDU_PROMOTE=1) is about to create that
 *      rendezvous. Every consumer keeps the SPELLING, not the resolved
 *      target, so later reconnects follow newer promotions automatically.
 *
 * Before this module the launcher pinned the legacy fixed path while the
 * dashboard stack promoted instances — a bare launch next to a promoted
 * stack would silently start a SECOND resident arbiter on the same symbol
 * DB (the split-brain runtime-instances.md §1 exists to prevent).
 */
import { existsSync, lstatSync } from "node:fs";
import {
  assertTrustedIfPresent, defaultRuntimeBaseOf, legacyTmpdirBase, resolveRuntimeBase,
  type PrivateDirDeps, type RuntimeBaseOptions,
} from "./runtime-base.js";

type Env = Record<string, string | undefined>;

/** How the socket path was chosen — "autostart" tells run.ts to start the
 *  arbiter in instance mode (promote) rather than pinned at the path. */
export type ArbiterSockMode = "pinned" | "current" | "legacy" | "autostart";

export interface ResolvedArbiterSock {
  sock: string;
  mode: ArbiterSockMode;
  /** The runtime base (`…/mandu`, or the `/tmp/mandu-<uid>` fallback) the
   *  instances/ registry lives under. */
  base: string;
}

/** The runtime base dir (mirror of instance.ts runtimeBase; the rule is
 *  runtime-base.ts resolveRuntimeBase, runtime-instances.md §3b): the path
 *  table's `runtime-dir` (MANDU_RUNTIME_DIR, else `mandu` under
 *  XDG_RUNTIME_DIR → TMPDIR → /tmp; on-disk-layout.md §5), except that a
 *  TMPDIR too long for an instance socket gives the private /tmp/mandu-<uid>.
 *  The runtime chain never reads HOME. */
export function runtimeBase(env: Env, opts: RuntimeBaseOptions = {}): string {
  return resolveRuntimeBase(env, opts).base;
}

/** THROW when the runtime base exists but someone else could control it
 *  (runtime-instances.md §3b): the shared-/tmp fallback that is not a private
 *  dir of this uid, or a base directly in a shared sticky dir (`$TMPDIR/mandu-<uid>` on
 *  Linux without XDG_RUNTIME_DIR) that is not ours or that other accounts can
 *  write. A `current` socket, a registry entry or a manifest there could be
 *  anyone's, so nothing under it is trusted. Read-only — an absent dir passes
 *  (the autostart creates it 0700). Every reader of the base calls this first. */
export function assertRuntimeBaseTrusted(
  env: Env,
  opts: RuntimeBaseOptions = {},
  deps: PrivateDirDeps = {},
): void {
  try {
    assertTrustedIfPresent(runtimeBase(env, opts), env, opts, deps);
  } catch (err) {
    throw new Error(`mandu: ${(err as Error).message}`);
  }
}

/**
 * One line for a launch whose DEFAULT base moved off the shared name
 * `$TMPDIR/mandu` (`/tmp/mandu` without TMPDIR) while an arbiter of this
 * user still answers there. Every version before 2026-10-09 put the base
 * there on a host without XDG_RUNTIME_DIR; since then rule 3 is per-user
 * (`$TMPDIR/mandu-<uid>`), and since 2026-09-29 a TMPDIR too long for an
 * instance socket gives the /tmp/mandu-<uid> fallback (runtime-instances.md
 * §3b). The old stack is invisible to this launch's `mandu status`/`stop`/
 * `reap`, and its arbiter still holds the symbol DB, so the autostart beside
 * it can fail. Names the old base and how to stop it. null otherwise
 * (MANDU_RUNTIME_DIR or XDG_RUNTIME_DIR decides the base, the base did not
 * move, nothing live, or the old dir is not this user's: another account's
 * `/tmp/mandu` is not our stack). `exists` follows the `current` link, so a
 * dangling one is not "live".
 */
export function movedBaseHint(
  env: Env,
  opts: RuntimeBaseOptions = {},
  exists: (p: string) => boolean = existsSync,
  ownedByMe: (p: string) => boolean = ownedByThisUid,
): string | null {
  if (env["MANDU_RUNTIME_DIR"]) return null;
  const def = defaultRuntimeBaseOf(env, opts);
  if (def.source === "xdg" || def.source === "explicit") return null;
  const old = legacyTmpdirBase(env);
  if (old === def.base || !exists(`${old}/current/arbiter.sock`) || !ownedByMe(old)) return null;
  return (
    `mandu: a Mandu stack is still running under ${old}, where older versions kept it; this launch uses ` +
    `${def.base}. Stop the old one: MANDU_RUNTIME_DIR=${old} mandu stop --all`
  );
}

/** Is `p` a real directory owned by this uid? */
function ownedByThisUid(p: string): boolean {
  try {
    const st = lstatSync(p);
    return st.isDirectory() && !st.isSymbolicLink() && (typeof process.getuid !== "function" || st.uid === process.getuid());
  } catch {
    return false;
  }
}

/** Resolve the arbiter rendezvous this deployment uses (order above).
 *  THROWS on an untrusted base (assertRuntimeBaseTrusted) — even for a pinned
 *  socket, since the instance registry still lives under the base. */
export function resolveArbiterSock(
  env: Env,
  opts: RuntimeBaseOptions = {},
  deps: PrivateDirDeps = {},
): ResolvedArbiterSock {
  const base = runtimeBase(env, opts);
  assertRuntimeBaseTrusted(env, opts, deps);
  const pinned = env["MANDU_ARBITER_SOCK"] || env["MANDU_ARBITER_SOCKET"];
  if (pinned) return { sock: pinned, mode: "pinned", base };
  const current = `${base}/current/arbiter.sock`;
  if (existsSync(current)) return { sock: current, mode: "current", base };
  const legacy = `${base}/arbiter.sock`;
  if (existsSync(legacy)) return { sock: legacy, mode: "legacy", base };
  return { sock: current, mode: "autostart", base };
}
