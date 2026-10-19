/**
 * exec-outbound — per-command outbound (data-usage) policy for exec.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/exec-outbound.ts
 *   Purpose: refine the blanket `TOOL_INPUT_RESOLVE.exec = true` baseline with
 *   per-argv-position resolve decisions. Argv positions are SCRIPT-RELATIVE —
 *   they count from the first argument to the script (interpreter stripped),
 *   matching the `args` produced by `normalizeExecCommand`. Prevents
 *   agent-symbolized tokens (potentially carrying tainted data) from being
 *   silently resolved into arguments passed to an external API — e.g.
 *   `node reddit-readonly.mjs search all $MDU:q…` keeps the query token
 *   symbolic rather than leaking its resolved value into the HTTP request.
 *
 *   Adaptation for Mandu: NONE of substance — pure data + lookup helpers, no
 *   OpenClaw runtime coupling. The `InputFieldPolicy` type now imports from the
 *   lifted tool-outbound.ts. Lifted verbatim aside from this header.
 */

import type { InputFieldPolicy } from "./tool-outbound.js";
import { isSymbolicExec, normalizeExecCommand } from "./exec-identifier.js";

/**
 * Per-position resolve policy for the arguments of an exec command.
 *
 * Numeric keys are script-relative argv positions (0 = first argument to the
 * script after interpreter stripping). `rest` covers every position beyond the
 * largest numbered entry. Absent positions fall back to the tool-level default
 * ("resolve" for exec).
 */
export interface ExecArgsPolicy {
  [position: number]: InputFieldPolicy;
  rest?: InputFieldPolicy;
}

export interface ExecInputSpec {
  /** Alternative canonical ids that resolve to this spec. */
  aliases?: readonly string[];
  args: ExecArgsPolicy;
}

/**
 * Primary library: canonical ExecCommandId -> ExecInputSpec. Each entry is keyed
 * by the canonical script basename and MUST be derived from observed skill
 * source. Kept in sync with EXEC_RESULT_TRUST_ENTRIES (exec-inbound.ts).
 */
export const EXEC_INPUT_RESOLVE_ENTRIES: Record<string, ExecInputSpec> = {
  // ClawHub reddit-readonly skill. argv[0] is the subcommand (a fixed enum
  // chosen by the agent, safe to resolve); everything after may be a subreddit
  // name, post id, or freeform query the agent symbolized — keep symbolic so it
  // never enters the outbound HTTP request.
  "reddit-readonly.mjs": {
    args: {
      0: "resolve",
      rest: "not_resolve",
    },
  },
};

/**
 * Reverse index built at module load: canonical id AND every alias map to the
 * owning spec. Throws on collision so the library can't silently have two
 * entries for the same id.
 */
const EXEC_INPUT_RESOLVE_INDEX: Record<string, ExecInputSpec> = (() => {
  const idx: Record<string, ExecInputSpec> = {};
  for (const [canonical, spec] of Object.entries(EXEC_INPUT_RESOLVE_ENTRIES)) {
    if (canonical in idx) {
      throw new Error(`[exec-outbound] duplicate canonical id: ${canonical}`);
    }
    idx[canonical] = spec;
    for (const alias of spec.aliases ?? []) {
      if (alias in idx) {
        throw new Error(
          `[exec-outbound] alias collision: ${alias} (from ${canonical}) already indexed`,
        );
      }
      idx[alias] = spec;
    }
  }
  return idx;
})();

/** @internal Reverse index — exported for tests only. */
export function _execInputResolveIndexForTests(): Readonly<Record<string, ExecInputSpec>> {
  return EXEC_INPUT_RESOLVE_INDEX;
}

/**
 * Return the per-position policy for a given exec invocation, or null if:
 *   - the call is running in symbolic-exec (AgentShell) mode, OR
 *   - the command can't be normalized (e.g. inline code), OR
 *   - no entry matches the canonical identifier.
 *
 * When null is returned the tool-level default applies to every position.
 */
export function classifyExecInput(
  command: string | undefined,
  params: Record<string, unknown> | undefined,
): ExecInputSpec | null {
  if (typeof command !== "string") return null;
  if (isSymbolicExec(params)) return null;
  const normalized = normalizeExecCommand(command);
  if (!normalized) return null;
  return EXEC_INPUT_RESOLVE_INDEX[normalized.id] ?? null;
}

/**
 * Resolve the effective policy for a single argv position using script-relative
 * indexing.
 *
 * Rules (in order):
 *   1. If the position has an explicit numeric entry, return it.
 *   2. If `rest` is set AND the position is beyond the largest numeric key,
 *      return `rest`.
 *   3. Otherwise return undefined (caller applies tool-level default).
 */
export function resolvePositionPolicy(
  spec: ExecInputSpec,
  position: number,
): InputFieldPolicy | undefined {
  if (position < 0) return undefined;
  const explicit = spec.args[position];
  if (explicit !== undefined) return explicit;
  if (spec.args.rest === undefined) return undefined;
  // `rest` only applies beyond the largest numeric key.
  let maxNumeric = -1;
  for (const key of Object.keys(spec.args)) {
    const n = Number(key);
    if (Number.isInteger(n) && n > maxNumeric) maxNumeric = n;
  }
  return position > maxNumeric ? spec.args.rest : undefined;
}
