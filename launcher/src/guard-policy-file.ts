/**
 * guard-policy-file — add fields to the whole-agent guard's policy file
 * (`MANDU_NET_GUARD_SECRETS`, read by mandu-net-guard at start). The secret
 * setup writes it when the confidentiality axis is on; the write-protect list
 * and the Unix socket allow-list join it, or start one of their own when the
 * launch has none yet (sandbox-security-review-2026-09-28). A policy file
 * also makes the guard trap the open family.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ndjsonCall } from "./secret-setup.js";
import { publishFile } from "./safe-file.js";

export interface GuardPolicyDeps {
  scopeRunDir: string;
  agentExe: string;
  session: string;
  askTimeoutMs?: number;
}

/** policy.yaml `unix_sockets:` / `write_protect:` / `remote_mounts:` as the
 *  arbiter compiled them (arbiter/policy/guard-settings.ts), `~` not yet
 *  expanded. */
export interface GuardSettings {
  unixAllow: string[];
  writeProtect: { deny: string[]; ask: string[]; unprotect: string[] };
  /** `remote_mounts.trust_lookups` (remote-mounts.ts). */
  trustLookups: { mount: string; type: string }[];
}

export const NO_GUARD_SETTINGS: GuardSettings = { unixAllow: [], writeProtect: { deny: [], ask: [], unprotect: [] }, trustLookups: [] };

/** `~` / `~/…` against the launching user's HOME; anything else as is. */
export function expandHome(p: string, home: string | undefined): string | null {
  if (p === "~" || p.startsWith("~/")) return home ? (p === "~" ? home : join(home, p.slice(2))) : null;
  return p;
}

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function trustList(v: unknown): { mount: string; type: string }[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((x): x is { mount: string; type: string } => typeof x === "object" && x !== null && typeof (x as { mount?: unknown }).mount === "string" && typeof (x as { type?: unknown }).type === "string")
    .map((x) => ({ mount: x.mount, type: x.type }));
}

/**
 * Read the three keys from the arbiter (`guardSettings`, the data socket).
 * A failed read (an older arbiter, a timeout) gives none of them and says
 * so: the built-in lists still apply, the opt-outs, the socket extras and
 * the mounts trusted for lookups are then absent (tighter), and only the
 * ADDED deny / ask paths are lost for this launch (an added guard, like
 * `protect:`).
 */
export async function readGuardSettings(
  sock: string,
  log: (m: string) => void,
  call: (sock: string, op: string) => Promise<unknown> = (s, op) => ndjsonCall(s, op, {}, 5_000),
): Promise<GuardSettings> {
  try {
    const r = (await call(sock, "guardSettings")) as { unixAllow?: unknown; writeProtect?: { deny?: unknown; ask?: unknown; unprotect?: unknown }; trustLookups?: unknown };
    return {
      unixAllow: stringList(r?.unixAllow),
      writeProtect: { deny: stringList(r?.writeProtect?.deny), ask: stringList(r?.writeProtect?.ask), unprotect: stringList(r?.writeProtect?.unprotect) },
      trustLookups: trustList(r?.trustLookups),
    };
  } catch (e) {
    log(`WARNING: mandu: policy.yaml unix_sockets: / write_protect: / remote_mounts: not read (${(e as Error).message}); the built-in lists apply, without your additions or opt-outs`);
    return NO_GUARD_SETTINGS;
  }
}

/** A fresh guard policy file's fields, before any merge: the agent's
 *  executable (the one program that always reads the twin), the session its
 *  reports are filed under, the reader-ask timeout, no secret yet. Pure;
 *  `mandu demo` builds its guard's policy from it too (demo/guard.ts). */
export function guardPolicyBase(deps: Pick<GuardPolicyDeps, "agentExe" | "session" | "askTimeoutMs">): Record<string, unknown> {
  return { agentExe: deps.agentExe, session: deps.session, askTimeoutMs: deps.askTimeoutMs ?? 60_000, secrets: [] };
}

/** Merge `fields` into the launch's guard policy file (created in the scope
 *  run dir when absent) and point MANDU_NET_GUARD_SECRETS at it. */
export function mergeGuardPolicy(mutEnv: Record<string, string>, deps: GuardPolicyDeps, fields: Record<string, unknown>): string {
  const existing = mutEnv["MANDU_NET_GUARD_SECRETS"];
  let policy: Record<string, unknown>;
  let path: string;
  if (existing) {
    path = existing;
    policy = JSON.parse(readFileSync(existing, "utf8")) as Record<string, unknown>;
  } else {
    path = join(deps.scopeRunDir, "guard-policy.json");
    policy = guardPolicyBase(deps);
  }
  Object.assign(policy, fields);
  // Never through a link planted in the scope dir (safe-file.ts).
  publishFile(path, JSON.stringify(policy, null, 2), { mode: 0o600 });
  mutEnv["MANDU_NET_GUARD_SECRETS"] = path;
  return path;
}
