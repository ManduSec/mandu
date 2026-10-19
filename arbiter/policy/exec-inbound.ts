/**
 * exec-inbound — per-command inbound classification for the exec tool.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/exec-inbound.ts
 *   Purpose: refine the blanket `exec` / `Bash` "stdout is UNTRUSTED" baseline
 *   for commands whose stdout is a well-known JSON shape. When the canonical
 *   ExecCommandId matches an entry, the exec output is walked with a per-field
 *   SchemaNode instead of blanket-symbolizing the whole output. If the id is
 *   unknown OR stdout fails to parse, the blanket-UNTRUSTED baseline applies —
 *   fail-closed by construction. Also exposes `mergeCommandOverrides`, the
 *   COMMAND-category merge wired back into createPolicyEngine (the branch that
 *   sub-step 1 had stripped).
 *
 *   Adaptation for Mandu — FLAGGED:
 *     - Log prefixes re-tagged [Mandu] → [Mandu-policy].
 *     - `CommandEntryConfig` now imports from the lifted load-policy.ts (the
 *       inbound.command shape + getExplicitUntrustedDirPolicyPaths were restored
 *       there). No other OpenClaw runtime coupling exists in this module — it is
 *       a pure data table + classifier over a command string.
 *     - This is technically an INBOUND (exec-output trust) classifier, but it is
 *       part of the exec policy family that sub-step 1 deferred, so it is lifted
 *       here alongside the data-usage / exec work and re-wired into the engine.
 *     - Claude Code surface note (2026-07-16): this table refines the blanket
 *       `Bash` / `BashOutput` → UNTRUSTED baseline in claude-code-inbound.ts.
 *       It ships EMPTY on purpose (see the Library comment below) — per-command
 *       stdout trust is an operator opt-in via YAML `inbound.command`, never a
 *       built-in grant.
 */

import type { SchemaNode } from "./schema-types.js";
import { isSymbolicExec, normalizeExecCommand } from "./exec-identifier.js";
import type { CommandEntryConfig } from "./load-policy.js";
// The law in force (compiled-policy.ts) — a function-time-only cycle, safe.
import { getCurrentPolicy, resetCurrentPolicyForTests } from "./compiled-policy.js";

export interface ExecOutputSpec {
  /** Alternative canonical ids that resolve to this spec. */
  aliases?: readonly string[];
  /**
   * Per-field schema applied to parsed JSON stdout. "TRUSTED" leaves pass raw;
   * "UNTRUSTED" leaves and any string fields not listed are symbolized
   * (deny-by-default for unlisted string fields). Mutually exclusive with
   * `subcommands`.
   */
  schema?: SchemaNode;
  /** Treat error outputs as TRUSTED (non-zero exit code, JSON `error` envelope)
   * so the agent can read them to fix the command. */
  trustErrors?: boolean;
  /** Treat non-JSON plain text (e.g. --help) as TRUSTED. */
  trustHelp?: boolean;
  /** Per-subcommand dispatch for multi-modal CLIs. Keys are space-joined arg
   * prefixes; longest matching prefix wins. */
  subcommands?: Record<string, ExecSubcommandSpec>;
}

export interface ExecSubcommandSpec extends ExecOutputSpec {
  /** Flags allowed after the subcommand prefix. Any flag not in this set
   * rejects the match. Flag values are always allowed. */
  allowedFlags?: readonly string[];
}

// ─── Library ────────────────────────────────────────────────────────────────
//
// Mandu ships the table EMPTY by default: no exec command is pre-classified
// as having a trusted-shaped stdout. The blanket-UNTRUSTED baseline therefore
// applies to every command unless an operator registers an entry via YAML
// (inbound.command → mergeCommandOverrides). This is the fail-closed posture:
// raw exec stdout is symbolized unless explicitly pinned. The reference shipped
// verified reddit-readonly / gws schemas; those are skill-specific to OpenClaw
// and are intentionally NOT carried over — Mandu operators add their own.

export const EXEC_RESULT_TRUST_ENTRIES: Record<string, ExecOutputSpec> = {};

/**
 * Build a reverse index: canonical id AND every alias map to the owning spec.
 * Throws on collision.
 */
function buildIndex(entries: Record<string, ExecOutputSpec>): Record<string, ExecOutputSpec> {
  const idx: Record<string, ExecOutputSpec> = {};
  for (const [canonical, spec] of Object.entries(entries)) {
    if (canonical in idx) {
      throw new Error(`[exec-inbound] duplicate canonical id: ${canonical}`);
    }
    idx[canonical] = spec;
    for (const alias of spec.aliases ?? []) {
      if (alias in idx) {
        throw new Error(
          `[exec-inbound] alias collision: ${alias} (from ${canonical}) already indexed`,
        );
      }
      idx[alias] = spec;
    }
  }
  return idx;
}

/** The PRISTINE built-in entries — input to `compilePolicy` (compiled-policy.ts).
 *  Never mutated: command overrides apply to a copy; the classifier reads the
 *  index in the law in force. */
export const BUILTIN_EXEC_RESULT_TRUST_ENTRIES: Readonly<Record<string, ExecOutputSpec>> = EXEC_RESULT_TRUST_ENTRIES;

/** The exec-output trust index in the law in force. */
function currentExecIndex(): Readonly<Record<string, ExecOutputSpec>> {
  return getCurrentPolicy().execIndex;
}

/** @internal Reverse index — exported for tests only. */
export function _execResultTrustIndexForTests(): Readonly<Record<string, ExecOutputSpec>> {
  return currentExecIndex();
}

// ─── YAML override merge ────────────────────────────────────────────────────

interface MergeLogger {
  info(msg: string): void;
  warn(msg: string): void;
}

/** Collect leaf trust values as a flat map: dotted path -> trust. */
function collectLeafPaths(node: SchemaNode, prefix = ""): Map<string, string> {
  const result = new Map<string, string>();
  if (node === "TRUSTED" || node === "UNTRUSTED") {
    result.set(prefix || "_root", node);
    return result;
  }
  if (typeof node === "object" && node !== null) {
    if ("__items" in node) {
      for (const [k, v] of collectLeafPaths((node as { __items: SchemaNode }).__items, prefix + "[]")) {
        result.set(k, v);
      }
    } else if (!("role" in node)) {
      for (const [key, val] of Object.entries(node as Record<string, SchemaNode>)) {
        for (const [k, v] of collectLeafPaths(val, prefix ? `${prefix}.${key}` : key)) {
          result.set(k, v);
        }
      }
    }
  }
  return result;
}

/**
 * Check if an override schema is more permissive than the existing one (marks
 * any field TRUSTED that was UNTRUSTED in the original).
 */
function isMorePermissive(
  original: SchemaNode | undefined,
  override: SchemaNode,
): boolean {
  if (!original) return false;
  const origPaths = collectLeafPaths(original);
  const overPaths = collectLeafPaths(override);
  for (const [path, trust] of overPaths) {
    if (trust === "TRUSTED" && origPaths.get(path) === "UNTRUSTED") return true;
  }
  return false;
}

/**
 * Merge YAML command overrides into the static exec spec library. Operator YAML
 * wins over static entries. Logs audit warnings when overrides loosen trust.
 * Called from createPolicyEngine after YAML parsing.
 */
/**
 * PURE (policy-surface.md §2.2): the built-in entries plus the
 * document's command overrides, as a fresh alias-expanded index. `base` is
 * never modified; `compilePolicy` calls this and freezes the result.
 */
export function applyCommandOverrides(
  base: Readonly<Record<string, ExecOutputSpec>>,
  overrides: readonly CommandEntryConfig[],
  log: MergeLogger,
): Record<string, ExecOutputSpec> {
  const entries: Record<string, ExecOutputSpec> = { ...base };
  for (const entry of overrides) {
    if (!entry.id) {
      log.warn(`[Mandu-policy] skipping command override with empty id`);
      continue;
    }
    if (entry.id === "*") {
      log.warn(
        `[Mandu-policy] wildcard command entry "*" registered — ` +
        `trustErrors=${entry.trustErrors ?? false}, trustHelp=${entry.trustHelp ?? false} ` +
        `apply to every exec command not otherwise classified. ` +
        `schema/subcommands on the wildcard are ignored.`,
      );
    }
    const existing = entries[entry.id];

    if (existing && entry.schema) {
      if (isMorePermissive(existing.schema, entry.schema as SchemaNode)) {
        log.warn(
          `[Mandu-policy] command override for "${entry.id}" is more permissive than built-in ` +
          `(marks UNTRUSTED fields as TRUSTED)`,
        );
      }
    }

    const spec: ExecOutputSpec = {
      ...(entry.aliases ? { aliases: entry.aliases } : {}),
      ...(entry.schema ? { schema: entry.schema as SchemaNode } : {}),
      ...(entry.trustErrors !== undefined ? { trustErrors: entry.trustErrors } : {}),
      ...(entry.trustHelp !== undefined ? { trustHelp: entry.trustHelp } : {}),
    };

    if (entry.subcommands) {
      const subs: Record<string, ExecSubcommandSpec> = {};
      for (const [prefix, sub] of Object.entries(entry.subcommands)) {
        subs[prefix] = {
          schema: sub.schema as SchemaNode,
          ...(sub.allowedFlags ? { allowedFlags: sub.allowedFlags } : {}),
          ...(sub.trustErrors !== undefined ? { trustErrors: sub.trustErrors } : {}),
          ...(sub.trustHelp !== undefined ? { trustHelp: sub.trustHelp } : {}),
        };
      }
      spec.subcommands = subs;
    }

    entries[entry.id] = spec;
    log.info(`[Mandu-policy] command override registered for "${entry.id}"`);
  }

  return buildIndex(entries);
}

/**
 * Back to the built-in exec specs (the law in force is recompiled without a
 * document). @internal Used by tests to restore state between runs.
 */
export function _resetExecSpecsForTests(): void {
  resetCurrentPolicyForTests();
}

export interface ExecClassifyResult {
  /** Matched spec with schema, or null if no match. */
  spec: ExecOutputSpec | null;
  /** When non-null, the command matched a known entry but was rejected (e.g.
   * shell operators present). The caller should return this as a TRUSTED error
   * message instead of running the command's output through classification. */
  rejection: string | null;
  /** When true, non-zero exit-code outputs should be treated as TRUSTED. */
  trustErrors: boolean;
  trustHelp: boolean;
}

/**
 * Classify an exec invocation by its command string.
 *
 * - `spec` is the matching ExecOutputSpec when all conditions are met.
 * - `rejection` is a TRUSTED error string when a known command was rejected
 *   (shell operators, unknown flags).
 * - Both null: no match, fall through to blanket UNTRUSTED.
 */
export function classifyExecOutput(
  command: string | undefined,
  params: Record<string, unknown> | undefined,
): ExecClassifyResult {
  const none: ExecClassifyResult = { spec: null, rejection: null, trustErrors: false, trustHelp: false };
  if (typeof command !== "string") return none;
  if (isSymbolicExec(params)) return none;
  const normalized = normalizeExecCommand(command);
  // When normalization can't identify a script/binary (inline code), structured
  // classification is impossible, but the wildcard fallback may still promote
  // exit-code output to TRUSTED. Pass empty args so trustHelp cannot falsely
  // fire — we can't inspect flags of code the agent inlined.
  if (!normalized) return applyWildcard([]);
  // "*" is reserved for the wildcard fallback — never match it as a canonical id.
  const spec = normalized.id === "*" ? null : (currentExecIndex()[normalized.id] ?? null);
  if (!spec) return applyWildcard(normalized.args);
  const te = spec.trustErrors ?? false;
  const th = (spec.trustHelp ?? false) && normalized.args.some(a => a === "--help" || a === "-h");
  if (!spec.subcommands) {
    const w = applyWildcard(normalized.args);
    return { spec, rejection: null, trustErrors: te || w.trustErrors, trustHelp: th || w.trustHelp };
  }
  const result = resolveSubcommand(spec.subcommands, normalized.args);
  const w = applyWildcard(normalized.args);
  return {
    ...result,
    trustErrors: result.trustErrors || te || w.trustErrors,
    trustHelp: result.trustHelp || th || w.trustHelp,
  };
}

/**
 * Wildcard "*" entry fallback. When a "*" entry is registered, its
 * trustErrors/trustHelp flags apply to every exec command. `schema` and
 * `subcommands` on a wildcard entry are ignored.
 */
function applyWildcard(args: string[]): ExecClassifyResult {
  const wildcard = currentExecIndex()["*"];
  if (!wildcard) return { spec: null, rejection: null, trustErrors: false, trustHelp: false };
  return {
    spec: null,
    rejection: null,
    trustErrors: wildcard.trustErrors ?? false,
    trustHelp: (wildcard.trustHelp ?? false) && args.some(a => a === "--help" || a === "-h"),
  };
}

/** Shell operators that indicate command chaining -- reject the match. */
const SHELL_OPERATORS = new Set(["&&", "||", "|", ";"]);

function containsShellOperator(token: string): boolean {
  if (SHELL_OPERATORS.has(token)) return true;
  if (token.endsWith(";")) return true;
  if (token.includes("&&") || token.includes("||") || token.includes("|")) return true;
  return false;
}

/**
 * Longest-prefix match against a subcommands map with strict validation.
 */
function resolveSubcommand(
  subcommands: Record<string, ExecSubcommandSpec>,
  args: string[],
): ExecClassifyResult {
  const none: ExecClassifyResult = { spec: null, rejection: null, trustErrors: false, trustHelp: false };

  for (let len = args.length; len > 0; len--) {
    const prefix = args.slice(0, len).join(" ");
    const match = subcommands[prefix];
    if (!match) continue;

    // Shell operators in args: reject with trusted error.
    for (const token of args) {
      if (containsShellOperator(token)) {
        return {
          spec: null,
          rejection: `[Mandu-policy] Shell operators (&&, ||, |, ;) are not allowed in classified exec commands. Run each command separately.`,
          trustErrors: false,
          trustHelp: false,
        };
      }
    }

    const rest = args.slice(len);
    if (match.allowedFlags && !validateFlags(rest, match.allowedFlags)) continue;

    return { spec: match, rejection: null, trustErrors: match.trustErrors ?? false, trustHelp: match.trustHelp ?? false };
  }
  return none;
}

/**
 * Validate that remaining args after a subcommand prefix contain only allowed
 * flags and their values.
 */
function validateFlags(
  rest: string[],
  allowedFlags: readonly string[],
): boolean {
  const allowed = new Set(allowedFlags);
  let i = 0;
  while (i < rest.length) {
    const token = rest[i];
    if (token.startsWith("-")) {
      const flagName = token.includes("=") ? token.slice(0, token.indexOf("=")) : token;
      if (!allowed.has(flagName)) return false;
      if (!token.includes("=") && i + 1 < rest.length && !rest[i + 1].startsWith("-")) {
        i += 2;
      } else {
        i += 1;
      }
    } else {
      return false;
    }
  }
  return true;
}

/**
 * Look up the canonical id for a command without returning the spec. Useful for
 * audit logging. Returns the id produced by `normalizeExecCommand`.
 */
export function execCommandId(
  command: string | undefined,
  params: Record<string, unknown> | undefined,
): string | null {
  if (typeof command !== "string") return null;
  if (isSymbolicExec(params)) return null;
  const normalized = normalizeExecCommand(command);
  return normalized?.id ?? null;
}
