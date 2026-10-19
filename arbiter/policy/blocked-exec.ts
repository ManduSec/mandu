/**
 * blocked-exec — plan 10 §11.8, "Blocked commands" (2026-10-07): which
 * commands the exec-wrap shim refused in a tool call's process tree, and why,
 * recomputed by the arbiter from the guard's argv records (never from the
 * shim's word: the shim runs in the agent's world).
 *
 * The shim (interceptors/exec-wrap gate.ts `decideExec`) asks this arbiter
 * `classifyExec(argv, needsNetwork: true)` and then
 * `resolveExecArgv(argv, shell)`, and refuses the command when the answer
 * carries an approval item. Both are pure over the argv and the symbol table,
 * so the same two calls over the command line the guard saw the shim run with
 * (`shimInvocationArgv`) give the shim's verdict. A command the shim refused
 * for another reason (the service unreachable, the real program not on PATH)
 * is not recomputable and is not named, with one exception: a run under
 * Codex's own command sandbox with its network off (`codexSandboxShims`,
 * found by the arbiter from the guard's argv record of that sandbox's
 * helper, provenance-store.ts `codexSandboxNetworkOff`). That sandbox's
 * seccomp filter refuses every `connect`, the shim's dial to this arbiter
 * included, so the shim refused the command without asking: its kind is
 * `codex_sandbox`, and no verdict is recomputed for it.
 *
 * What it yields is for the model's note only (the proxies' `blocked:` line):
 * the program's NAME and a KIND from a fixed set. Never an argument (an
 * argument may hold a secret's value or a placeholder), and the name only
 * when it is a plain program name that holds no registered secret value
 * (argv[0] is the agent's to choose), else "a program". It never lowers a
 * mask. Pure over its inputs.
 */
import type { SymbolMap } from "../symbol-table/index.js";
import { classifyExec, resolveExecArgv } from "./exec-classify.js";

/** Why the shim refused, as the approval item's kind (exec-classify.ts). */
export const BLOCKED_EXEC_KINDS = ["symbol_as_command", "unsupported_command", "secret_symbol", "codex_sandbox", "other"] as const;
export type BlockedExecKind = (typeof BLOCKED_EXEC_KINDS)[number];

export interface BlockedExec {
  app: string;
  kind: BlockedExecKind;
}

const PLAIN_PROGRAM = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,39}$/;

/** The name a note may carry for `argv0`: its basename when that is a plain
 *  program name holding no placeholder and no registered secret value, else
 *  "a program". */
export function blockedProgramName(argv0: string, holdsSecret: (text: string) => boolean = () => false): string {
  const name = argv0.split("/").pop() ?? "";
  if (!PLAIN_PROGRAM.test(name) || name.includes("MDU") || holdsSecret(name)) return "a program";
  return name;
}

/** The shim's verdict over each command line, folded to one entry per
 *  (program, kind). A command line in `opts.codexSandbox` (the shim ran it
 *  under Codex's sandbox with its network off) is `codex_sandbox`: the shim
 *  could not reach the arbiter there, so it refused without a verdict. */
export function blockedExecFold(
  argvs: readonly (readonly string[])[],
  symbols: SymbolMap,
  opts: { holdsSecret?: (text: string) => boolean; codexSandbox?: readonly (readonly string[])[] } = {},
): BlockedExec[] {
  const out: BlockedExec[] = [];
  const sandboxed = new Set((opts.codexSandbox ?? []).map((a) => JSON.stringify(a)));
  for (const raw of argvs) {
    const argv = [...raw];
    if (argv.length === 0) continue;
    let kind: BlockedExecKind | null;
    if (sandboxed.has(JSON.stringify(argv))) {
      kind = "codex_sandbox";
    } else {
      try {
        const { shell } = classifyExec({ argv, needsNetwork: true });
        const r = resolveExecArgv({ argv, shell }, symbols);
        const first = r.approvals[0];
        kind = first === undefined ? null : (BLOCKED_EXEC_KINDS as readonly string[]).includes(first.kind) ? (first.kind as BlockedExecKind) : "other";
      } catch {
        // The shim fails closed on an arbiter error: it refused this too.
        kind = "other";
      }
    }
    if (kind === null) continue;
    const app = blockedProgramName(argv[0]!, opts.holdsSecret);
    if (!out.some((x) => x.app === app && x.kind === kind)) out.push({ app, kind });
  }
  return out;
}
