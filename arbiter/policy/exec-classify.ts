/**
 * exec-classify — AgentShell vs HumanShell selection + safe argv desymbolization.
 *
 * Mandu-new (no single reference file): this is the arbiter-side orchestration
 * the future exec-supervisor (Wave 4) calls. It composes the lifted exec policy
 * modules into the two contracts the exec ops expose:
 *
 *   classifyExec(argv, cwd?, opts?)  → which shell view a command runs in, the
 *                                      command's canonical identity, and why.
 *   resolveExecArgv(argv, shell, …)  → the argv to actually run, with symbols
 *                                      desymbolized ONLY after the data-usage
 *                                      check + command-rewriting rule, plus the
 *                                      list of items that require human approval.
 *
 * SECURITY MODEL (design §4):
 *   - AgentShell (default): net egress disabled, FS = AgentView. Symbols stay
 *     symbolic — the output is already symbolic and safe. No desymbolization, so
 *     no data-usage decision is needed.
 *   - HumanShell: network enabled, FS = HumanView, argv desymbolized — but ONLY
 *     after (a) the data-usage policy check (an untrusted symbol used as
 *     command/code, or flowing to an untrusted destination, requires approval)
 *     and (b) the command-rewriting rule (`python fix.py` → `python -c <file>`),
 *     so the symbol-as-command detector sees the actual code that will run.
 *
 * FAIL-CLOSED: when a command's symbol(s) cannot be safely desymbolized without
 * approval, resolveExecArgv returns those items in `approvals` and leaves them
 * SYMBOLIC in the returned argv. It never silently resolves an untrusted symbol
 * into a command/code position.
 *
 * The lifted shell tokenizers (exec-argv-mode) preserve argv boundaries and
 * quoting context, so a resolved value can never become shell syntax.
 */

import type { SymbolEntry, SymbolMap } from "../symbol-table/index.js";
import { findByCandidates } from "../symbol-table/symbol-format.js";
import {
  isSecret,
  parseConfidentialityLevel,
} from "../symbol-table/confidentiality.js";
import { normalizeExecCommand, isSymbolicExec } from "./exec-identifier.js";
import {
  prepareExecArgvSymbolResolution,
  commandContainsMduSymbol,
  findSymbolMatches,
  type ExecArgvSymbolResolution,
} from "./exec-argv-mode.js";
import {
  detectUntrustedCommandExecutionPatterns,
  detectUntrustedCommandExecutionPatternsFromExecArgvResolution,
  type UntrustedCommandExecutionMatch,
} from "./untrusted-command-execution.js";

/** Which view a command runs in. */
export type ExecShell = "AgentShell" | "HumanShell";

export interface ExecClassifyRequest {
  /** The command argv (argv[0] is the program). The arbiter joins it back into a
   * command string for the lifted tokenizers, which is lossless for the cases
   * we care about (the supervisor passes argv exactly as observed at execve). */
  argv: string[];
  /** Working directory the command runs in (for script-file resolution). */
  cwd?: string;
  /**
   * Caller-supplied resource hints. The arbiter cannot infer at the policy layer
   * whether a command genuinely needs real network or the original (HumanView)
   * filesystem — that is the supervisor's runtime observation. When either is
   * set true, the command is routed to HumanShell. Absent → AgentShell default.
   */
  needsNetwork?: boolean;
  needsOriginalFs?: boolean;
  /** Exec params (e.g. { env: { RESTRICTED: "1" } }) — RESTRICTED=1 pins
   * AgentShell explicitly (the symbolic-exec path). */
  params?: Record<string, unknown>;
}

export interface ExecClassifyDecision {
  shell: ExecShell;
  /** Canonical command identity (script/binary basename), or null when the
   * command is inline code / unidentifiable. */
  identifier: string | null;
  reason: string;
}

/** Join an argv back into a single command string for the lifted tokenizers. */
function argvToCommand(argv: string[]): string {
  return argv.join(" ");
}

/**
 * Select AgentShell vs HumanShell for a command and report its canonical
 * identity.
 *
 * Default is AgentShell (safe: AgentView FS, no egress). HumanShell is selected
 * only when the caller signals the command needs real network or the original
 * filesystem. RESTRICTED=1 pins AgentShell regardless.
 */
export function classifyExec(req: ExecClassifyRequest): ExecClassifyDecision {
  const command = argvToCommand(req.argv);
  const normalized = normalizeExecCommand(command);
  const identifier = normalized?.id ?? null;

  if (isSymbolicExec(req.params)) {
    return {
      shell: "AgentShell",
      identifier,
      reason: "RESTRICTED=1 → AgentShell (symbolic exec; AgentView FS, egress disabled)",
    };
  }

  if (req.needsNetwork || req.needsOriginalFs) {
    const needs = [
      req.needsNetwork ? "network" : null,
      req.needsOriginalFs ? "original-FS" : null,
    ].filter(Boolean).join(" + ");
    return {
      shell: "HumanShell",
      identifier,
      reason: `HumanShell: command requires ${needs} (HumanView); argv desymbolized only after the data-usage check`,
    };
  }

  return {
    shell: "AgentShell",
    identifier,
    reason: "AgentShell (default): AgentView FS, egress disabled, output already symbolic",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// resolveExecArgv: desymbolize argv only after the data-usage check.
// ─────────────────────────────────────────────────────────────────────────────

export type ExecApprovalKind =
  | "symbol_as_command"    // an untrusted symbol sits in command/code position
  | "unsupported_command"  // the command shape can't be safely lowered to argv
  | "secret_symbol";       // a secret-labeled symbol in a net-enabled HumanShell argv (confidentiality §7.1)

export interface ExecApprovalItem {
  kind: ExecApprovalKind;
  /** The symbols implicated (empty for unsupported_command). */
  symbols: string[];
  /** Short evidence/reason string. */
  reason: string;
}

export interface ResolveExecArgvRequest {
  argv: string[];
  shell: ExecShell;
  params?: Record<string, unknown>;
}

export interface ResolveExecArgvResult {
  /** The argv to run. In AgentShell this is the symbolic argv unchanged. In
   * HumanShell, symbols in ordinary data positions are resolved (safely, inside
   * their argv slot); symbols in command/code positions are LEFT SYMBOLIC and
   * surfaced in `approvals`. */
  argv: string[];
  /** Items requiring human approval before they may be desymbolized. Non-empty
   * means the egress gate withheld at least one resolution (fail-closed). */
  approvals: ExecApprovalItem[];
  /** Audit reason. */
  reason: string;
}

/**
 * Build the argv to actually run, applying the data-usage policy.
 *
 * AgentShell: symbols stay symbolic — return argv unchanged, no approvals.
 *
 * HumanShell: scan the command for symbol-as-command/code patterns (the
 * data-usage policy's "untrusted symbol used as a command" case). Any matched
 * symbol is left symbolic and added to `approvals`. Remaining symbols sitting in
 * ordinary data argv slots are resolved in-place via the safe argv lowering
 * (exec-argv-mode), which keeps shell metacharacters inert. Unknown symbols are
 * preserved as-is. If the command shape cannot be lowered (pipes, redirects,
 * substitutions, a symbol in command position), nothing is resolved and an
 * `unsupported_command` approval is returned (fail-closed).
 */
/** Options beyond the classic two arguments. */
export interface ResolveExecArgvOptions {
  /** The confidentiality-axis kill switch (confidentiality.md §11). Since
   * 2026-09-30 it no longer gates the secret-withholding branch
   * (arbiter-human-plane.md §4): this op answers on the data socket the
   * agent's world reaches, and a secret-labelled row minted while the axis was
   * on outlives a restart with it off. An unlabelled row parses `public`, so
   * an axis-off stack with no secret rows resolves exactly as before. Kept for
   * callers that still pass it. */
  confidentiality?: boolean;
}

/** Entry lookup via the shared candidate walk (symbol-format, pure grammar —
 * this policy module keeps its type-only dep on the DB-bearing symbol-table
 * module). Replaces a local bracket-cut base fallback so the exec gate's
 * notion of "known" matches resolution's everywhere — the alias tier
 * (stream-stranded base → its one field extension) included. */
function entryForSymbolName(symbols: SymbolMap, name: string): SymbolEntry | undefined {
  return findByCandidates(name, (n) => symbols.symbols.get(n), () => symbols.symbols.keys())?.hit;
}

export function resolveExecArgv(
  req: ResolveExecArgvRequest,
  symbols: SymbolMap,
  opts?: ResolveExecArgvOptions,
): ResolveExecArgvResult {
  const command = argvToCommand(req.argv);

  // AgentShell never desymbolizes — the AgentView is symbolic by design.
  if (req.shell === "AgentShell") {
    return {
      argv: req.argv,
      approvals: [],
      reason: "AgentShell: symbols preserved (AgentView); no desymbolization",
    };
  }

  // HumanShell. No symbols → nothing to gate, run as-is.
  if (!commandContainsMduSymbol(command)) {
    return {
      argv: req.argv,
      approvals: [],
      reason: "HumanShell: no symbols in argv; run as-is",
    };
  }

  // Confidentiality (confidentiality.md §7.1): a SECRET-labelled symbol is
  // never resolved here. HumanShell is a NET-ENABLED world, so a secret's
  // real value must never enter its argv; the placeholder stays in the argv
  // as written and the command runs. The value goes in only at the NETWORK
  // chokepoint (net-proxy / net-supervisor), after the binding check:
  // released in a request to a bound host, held for the human anywhere else.
  // Applied WHATEVER the axis says (see ResolveExecArgvOptions.confidentiality):
  // this op answers on the data socket the agent's world reaches. Until
  // 2026-10-05 the whole command was withheld instead (`secret_symbol`), which
  // refused §7.1's own example (`curl -H "Authorization: $KEY"`) while a curl
  // config file carrying the same placeholder ran and was gated on the wire.
  void opts;
  const secretSymbols = secretSymbolsIn(command, symbols);
  const resolvable = secretSymbols.size > 0 ? resolvableRows(command, symbols) : symbols.symbols;
  const onlySecretSymbols = secretSymbols.size > 0
    && findSymbolMatches(command).every((m) => secretSymbols.has(m.symbol));

  // 1) Data-usage check: detect symbol-as-command/code patterns on the raw
  //    command (whole-command symbol, sh -c <sym>, python -c <sym>, heredoc).
  const cmdPatterns = detectUntrustedCommandExecutionPatterns(command, { action: "block" });

  // 2) Lower to template argv (BEFORE substituting values) so we can both detect
  //    code-position flow on the template and resolve only data slots. Secret
  //    rows are left out of the map, so their symbols stay as written.
  const resolution = prepareExecArgvSymbolResolution(command, resolvable, {
    resolveSymbols: true,
  });

  if (!resolution) {
    // No symbols after all (shouldn't happen given the guard above) — run as-is.
    return { argv: req.argv, approvals: [], reason: "HumanShell: no symbols to resolve" };
  }

  // Unsupported command shape (pipe/redirect/substitution/symbol-in-command):
  // fail-closed — do not resolve anything; require approval. Unless nothing
  // would be resolved anyway: when every symbol is a secret placeholder that
  // stays as written, no value can turn into syntax (the argv is exec'd as an
  // array, never re-parsed by a shell), so the argv runs as given, provided
  // no placeholder sits where code runs.
  if (resolution.program.kind !== "program") {
    if (onlySecretSymbols && collectCodeFlowSymbols(cmdPatterns).size === 0) {
      return secretPlaceholdersLeft(req.argv, secretSymbols);
    }
    const approvals: ExecApprovalItem[] = [{
      kind: "unsupported_command",
      symbols: [],
      reason: `command shape not safely lowerable to argv: ${resolution.program.reason} (${resolution.program.evidence})`,
    }];
    return {
      argv: req.argv,
      approvals,
      reason: "HumanShell: unsupported command shape → withhold desymbolization (fail-closed)",
    };
  }

  // Also scan the lowered template for code-position symbol flow.
  const templatePatterns = detectUntrustedCommandExecutionPatternsFromExecArgvResolution(
    resolution,
    { action: "block" },
  );

  const codeFlowSymbols = collectCodeFlowSymbols([...cmdPatterns, ...templatePatterns]);

  // If any symbol is in command/code position, the data-usage policy requires
  // approval. We DO NOT resolve those — leave the original symbolic argv intact
  // and surface them. (The supervisor blocks until approved.)
  if (codeFlowSymbols.size > 0) {
    return {
      argv: req.argv,
      approvals: [{
        kind: "symbol_as_command",
        symbols: [...codeFlowSymbols],
        reason: "untrusted symbol used as command/code → human approval required (data usage policy)",
      }],
      reason: "HumanShell: symbol-as-command detected → withhold desymbolization (fail-closed)",
    };
  }

  // Defense in depth: no secret row may come back resolved (the lookup above
  // never sees one; this re-checks every resolved slot against the FULL map).
  // Should it ever happen, withhold the whole command (fail-closed).
  const resolvedSecrets = resolution.decisions
    .filter((d) => d.action === "resolved" && isSecretEntry(entryForSymbolName(symbols, d.symbol)))
    .map((d) => d.symbol);
  if (resolvedSecrets.length > 0) {
    return {
      argv: req.argv,
      approvals: [{
        kind: "secret_symbol",
        symbols: [...new Set(resolvedSecrets)],
        reason: "secret-labeled symbol would be resolved into a net-enabled HumanShell argv → withhold; release only via the network egress gate (confidentiality §7.1)",
      }],
      reason: "HumanShell: secret symbol(s) withheld from argv (confidentiality)",
    };
  }

  // Only secret placeholders, nothing resolved: run the argv exactly as given
  // (the lowering round-trip is not lossless for an argument holding a space,
  // such as `-H "Authorization: Bearer …"`).
  if (secretSymbols.size > 0 && !resolution.decisions.some((d) => d.action === "resolved")) {
    return secretPlaceholdersLeft(req.argv, secretSymbols);
  }

  // No code-position flow: symbols are ordinary data arguments. The lowering
  // already resolved them safely inside their argv slots. Build the flat argv to
  // run from the (single) first command step; multi-step programs join with
  // their operator so the supervisor can re-shell them if needed.
  const argv = flattenResolvedProgram(resolution);
  return {
    argv,
    approvals: [],
    reason: secretSymbols.size > 0
      ? `HumanShell: data-position symbols resolved in-slot; ${SECRET_PLACEHOLDER_REASON} [${[...secretSymbols].join(", ")}]`
      : "HumanShell: data-position symbols resolved in-slot (safe argv lowering)",
  };
}

/** The audit reason for a secret placeholder left in a HumanShell argv. */
const SECRET_PLACEHOLDER_REASON =
  "secret placeholder(s) left as written; the real value goes in only at the network egress gate, after the binding check (confidentiality §7.1)";

function secretPlaceholdersLeft(argv: string[], secretSymbols: Set<string>): ResolveExecArgvResult {
  return {
    argv,
    approvals: [],
    reason: `HumanShell: ${SECRET_PLACEHOLDER_REASON} [${[...secretSymbols].join(", ")}]`,
  };
}

function isSecretEntry(entry: SymbolEntry | undefined): boolean {
  return entry !== undefined && isSecret(parseConfidentialityLevel(entry.confidentiality));
}

/** The symbols in `command` whose row is secret-labelled. */
function secretSymbolsIn(command: string, symbols: SymbolMap): Set<string> {
  const out = new Set<string>();
  for (const m of findSymbolMatches(command)) {
    if (isSecretEntry(entryForSymbolName(symbols, m.symbol))) out.add(m.symbol);
  }
  return out;
}

/** The rows HumanShell may resolve for `command`: each of its symbols' own
 *  row, unless secret-labelled. Built from the command's symbols rather than
 *  by copying the whole table, which is in memory and large. */
function resolvableRows(command: string, symbols: SymbolMap): Map<string, SymbolEntry> {
  const out = new Map<string, SymbolEntry>();
  for (const m of findSymbolMatches(command)) {
    const r = findByCandidates(m.symbol, (n) => symbols.symbols.get(n), () => symbols.symbols.keys());
    if (r && !isSecretEntry(r.hit)) out.set(r.name, r.hit);
  }
  return out;
}

/** Collect the symbols implicated in any command/code-position match. */
function collectCodeFlowSymbols(matches: UntrustedCommandExecutionMatch[]): Set<string> {
  const out = new Set<string>();
  for (const m of matches) {
    for (const s of m.symbols) out.add(s);
  }
  return out;
}

/**
 * Flatten a resolved exec program back to a single argv. For a single-step
 * command this is just that step's argv. For multi-step (&&/||) programs we
 * keep the operators as their own argv tokens so the supervisor preserves the
 * agent's control flow when re-assembling the command line.
 */
function flattenResolvedProgram(resolution: ExecArgvSymbolResolution): string[] {
  if (resolution.program.kind !== "program") return resolution.argv;
  const steps = resolution.program.steps;
  if (steps.length <= 1) return steps[0]?.argv ?? resolution.argv;
  const out: string[] = [];
  for (let i = 0; i < steps.length; i++) {
    if (i > 0 && steps[i].op) out.push(steps[i].op!);
    out.push(...steps[i].argv);
  }
  return out;
}

// Re-export so the IPC layer / supervisor can introspect a SymbolEntry shape if
// it builds a SymbolMap directly.
export type { SymbolEntry };
