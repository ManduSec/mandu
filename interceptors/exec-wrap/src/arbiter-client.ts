/**
 * arbiter-client — the arbiter dependency the exec-wrap chokepoint speaks to.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. Pattern mirrored from
 *     fs-sync/src/arbiter-client.ts  /  interceptors/anthropic-proxy/src/arbiter-client.ts
 *   (narrow interface + adapter over the real arbiter IPC client + a mock for
 *   tests). No reference-source origin — the exec supervisor is Mandu-new.
 *
 * The op shapes mirror arbiter/ipc/protocol.ts + arbiter/ipc/client.ts exactly:
 *   - classifyExec({argv, cwd?, needsNetwork?, needsOriginalFs?, params?})
 *        -> { shell, identifier, reason }                  (ExecClassifyDecision)
 *   - resolveExecArgv({argv, shell, params?})
 *        -> { argv, approvals, reason }                    (ResolveExecArgvResult)
 *
 * SECURITY-INVARIANT NOTE: this is the channel by which the exec chokepoint asks
 * the arbiter's data-usage policy whether a shadowed command's argv carries an
 * untrusted symbol used as a command/arg. If a arbiter op fails (or is
 * unreachable) the caller FAILS CLOSED — it must REFUSE the exec rather than run
 * the raw command with un-vetted argv.
 */

/** Which view a command runs in. Mirrors arbiter/policy/exec-classify.ts ExecShell. */
export type ExecShell = "AgentShell" | "HumanShell";

/** Mirrors arbiter/policy/exec-classify.ts ExecClassifyDecision. */
export interface ExecClassifyDecision {
  shell: ExecShell;
  /** Canonical command identity (script/binary basename), or null. */
  identifier: string | null;
  reason: string;
}

/** Mirrors arbiter/policy/exec-classify.ts ExecApprovalKind. */
export type ExecApprovalKind = "symbol_as_command" | "unsupported_command";

/** Mirrors arbiter/policy/exec-classify.ts ExecApprovalItem. */
export interface ExecApprovalItem {
  kind: ExecApprovalKind;
  /** The symbols implicated (empty for unsupported_command). */
  symbols: string[];
  /** Short evidence/reason string. */
  reason: string;
}

/** Mirrors arbiter/policy/exec-classify.ts ResolveExecArgvResult. */
export interface ResolveExecArgvResult {
  /** The argv to run. Symbols in command/code positions are LEFT SYMBOLIC and
   * surfaced in `approvals`; data-position symbols are resolved in-slot. */
  argv: string[];
  /** Items requiring human approval before they may be desymbolized. Non-empty
   * means the egress gate withheld at least one resolution (fail-closed). */
  approvals: ExecApprovalItem[];
  reason: string;
}

export interface ClassifyExecArgs {
  argv: string[];
  cwd?: string;
  needsNetwork?: boolean;
  needsOriginalFs?: boolean;
  params?: Record<string, unknown>;
}

export interface ResolveExecArgvArgs {
  argv: string[];
  shell: ExecShell;
  params?: Record<string, unknown>;
}

/**
 * The narrow arbiter surface the exec chokepoint depends on. Anything that
 * satisfies this — the real adapter or a mock — can drive the gate. Deliberately
 * a SUBSET of the full arbiter client (only the two exec ops + provenance).
 */
export interface ExecArbiter {
  /** Select AgentShell vs HumanShell for a command argv. */
  classifyExec(args: ClassifyExecArgs): Promise<ExecClassifyDecision>;
  /** Desymbolize an argv for a chosen shell after the data-usage check; returns
   * the argv to run plus any required approvals. */
  resolveExecArgv(args: ResolveExecArgvArgs): Promise<ResolveExecArgvResult>;
  /**
   * Provenance (Plan 1 `processLineage`): record a parent→child spawn edge so the
   * arbiter's transitive-ancestor taint walk knows the lineage (design §3.2). Emitted
   * by the shim as a BEST-EFFORT, off-the-security-path event — a failure must never
   * block or alter the exec gate. Mirrors arbiter/ipc/client.ts exactly.
   */
  processLineage(args: { childKey: string; parentKey: string; session?: string }): Promise<void>;
}

/**
 * Structural shape of the real arbiter IPC client (arbiter/ipc/client.ts). We
 * declare it here rather than importing so this package typechecks standalone
 * (the arbiter is a sibling package owned by another sub-agent). The two exec ops
 * landed with the exec policy and are stable.
 */
export interface RealArbiterClient {
  connect(): Promise<void>;
  classifyExec(args: ClassifyExecArgs): Promise<ExecClassifyDecision>;
  resolveExecArgv(args: ResolveExecArgvArgs): Promise<ResolveExecArgvResult>;
  processLineage(args: { childKey: string; parentKey: string; session?: string }): Promise<void>;
  close(): void;
}

/** Adapter: present the real arbiter IPC client as an `ExecArbiter`. */
export class ArbiterClientAdapter implements ExecArbiter {
  constructor(private readonly client: RealArbiterClient) {}

  classifyExec(args: ClassifyExecArgs): Promise<ExecClassifyDecision> {
    return this.client.classifyExec(args);
  }

  resolveExecArgv(args: ResolveExecArgvArgs): Promise<ResolveExecArgvResult> {
    return this.client.resolveExecArgv(args);
  }

  processLineage(args: { childKey: string; parentKey: string; session?: string }): Promise<void> {
    return this.client.processLineage(args);
  }
}
