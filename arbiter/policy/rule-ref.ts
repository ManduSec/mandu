/**
 * rule-ref — structured decision provenance for the data-USAGE gates
 * (docs/design/ui/policy-surface.md §9.3).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 *
 * Every usage decision (fs sensitive-path gate, egress desymbolization gate,
 * exec escalation) carries a `RuleRef` naming WHICH standing thing decided it:
 * a policy rule branch, a persisted human verdict, or a fail-closed default.
 * The prose `reason` stays the human-readable half; the ruleRef is the
 * machine-readable join key the dashboard uses to link a trace event back to
 * the Policy panel (and to count, per rule, what it decided).
 *
 * THE CATALOG IS THE SINGLE SOURCE OF TRUTH. Gates build refs via
 * `ruleRef(id)` where `id` is `keyof typeof RULES` — an id absent from the
 * catalog does not compile — so the policySnapshot op can ship this catalog
 * knowing enforcement uses exactly these ids (the same cannot-drift property
 * policy-snapshot.ts established for the trust rules). When you add a gate
 * branch, add its catalog row in the SAME change; the compiler holds the door.
 */

/** Who decided: a policy rule, a standing human verdict, or a fail-closed
 * default (nothing matched / out-of-contract input — kept distinct so the
 * dashboard can render "denied by default" differently from "a rule matched"). */
export interface RuleRef {
  source: "rule" | "verdict" | "fail-closed";
  id: string;
}

/** One catalog row: how a rule id renders in the Policy panel. */
export interface UsageRule {
  id: string;
  source: "rule" | "fail-closed";
  /** Which chokepoint asks the question. */
  boundary: "filesystem" | "network" | "shell" | "model_context" | "any";
  /** What the branch does when it fires. */
  outcome: "allow" | "deny" | "deny+approval";
  /** One-line human description (the Rules tab row). */
  summary: string;
  /** The owning gate (GATES key = the id's prefix before ":"). The panel
   * groups rules by gate — within a gate, catalog order IS evaluation order,
   * which grouping by boundary would interleave across unrelated gates. */
  gate: GateId;
}

/** One gate: the deciding function a family of rule ids belongs to. This is
 * the "where is this rule specified" answer the panel's per-row detail shows,
 * shipped FROM the enforcing code (the same cannot-drift property as RULES —
 * a dashboard-side copy of these strings would rot). */
export interface UsageGate {
  id: string;
  /** Plain-register display name ("filesystem path gate"). */
  title: string;
  /** Where the deciding code lives (repo path + function). */
  definedIn: string;
  /** The design doc that specifies it. */
  doc: string;
  /** How rules combine inside this gate (the precedence sentence). */
  evaluation: string;
}

/** The gate catalog, keyed by rule-id prefix. */
export const GATES = {
  fs: {
    title: "filesystem path gate",
    definedIn: "arbiter/policy/fs-outbound.ts (decideFsPath) + file-upload.ts (decideFileUpload, the upload rules)",
    doc: "docs/design/integrity/fs-sync.md §1.4.1 + docs/design/agents/supported-agents.md §2 (uploads)",
    evaluation:
      "checked top to bottom per path; first match wins — sensitive prefixes win even inside a workspace root",
  },
  egress: {
    title: "egress desymbolization gate",
    definedIn: "arbiter/policy/policy-interface.ts (decideDesymbolization)",
    doc: "docs/design/architecture/mandu.md §4 + confidentiality.md §3.2",
    evaluation:
      "checked top to bottom per symbol×destination; first matching branch decides",
  },
  exec: {
    title: "exec gate",
    definedIn: "arbiter/policy/exec-gate.ts (execGate) + exec-program-text.ts (provenance) + ipc/server.ts (escalation wrap)",
    doc: "docs/design/integrity/exec-routing.md §3, §5 + exec-routing.md §8.7a",
    evaluation:
      "applies at exec time: commands run in AgentShell by default (network off, AgentView files); symbolic commands are rewritten on the wire; HumanShell needs an approved escalation",
  },
  session: {
    title: "session watermark gate",
    definedIn: "arbiter/policy/session-egress.ts (decideSessionEgress)",
    doc: "docs/design/confidentiality/confidentiality.md §4",
    evaluation:
      "applies AFTER the per-symbol gate, keyed on what this session has read — a paraphrase can carry a secret no symbol tracks",
  },
  proxy: {
    title: "interceptor fail-closed",
    definedIn: "each interceptor's arbiter client (proxy/fs/net/exec)",
    doc: "docs/design/architecture/mandu.md (the fail-closed invariant)",
    evaluation:
      "enforced interceptor-side: when the arbiter is unreachable, every chokepoint denies rather than falling through to raw",
  },
} as const satisfies Record<string, Omit<UsageGate, "id">>;

export type GateId = keyof typeof GATES;

/** The gate owning a rule id (its prefix before ":"). Total by construction:
 * the RULES literal is typed so every id's prefix is a GATES key. */
export function gateOf(ruleId: `${GateId}:${string}`): GateId {
  return ruleId.slice(0, ruleId.indexOf(":")) as GateId;
}

/** The usage-gate rule catalog. Ids are grouped by gate:
 *  `fs:*` = decideFsPath (fs-outbound.ts, rule order per its header);
 *  `egress:*` = decideDesymbolization (policy-interface.ts);
 *  `exec:*` = decideExecEscalation (ipc/server.ts §5 wrap). */
export const RULES = {
  // ── fs sensitive-path gate (fs-sync.md §1.4.1; deny-precedence order) ──
  "fs:invalid-path": {
    source: "fail-closed", boundary: "filesystem", outcome: "deny+approval",
    summary: "empty or unparseable target path — never guess about the target",
  },
  "fs:relative-path": {
    source: "fail-closed", boundary: "filesystem", outcome: "deny+approval",
    summary: "relative path reached the gate (out of contract — the proxy gates absolute paths only)",
  },
  "fs:sensitive-path": {
    source: "rule", boundary: "filesystem", outcome: "deny+approval",
    summary: "built-in sensitive prefix (~/.ssh, ~/.aws, agent credentials, …) — wins even inside a workspace root",
  },
  "fs:workspace-root": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "inside a vouched workspace root (HumanView or AgentView)",
  },
  "fs:dir-allowlist": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "DIR trust-category allowlist (policy file)",
  },
  "fs:default-deny": {
    source: "fail-closed", boundary: "filesystem", outcome: "deny+approval",
    summary: "out-of-workspace path, no rule matched — fail-closed default",
  },
  // ── the local-file UPLOAD gate (file-upload.ts decideFileUpload; a tool that
  //    sends a local file's bytes off the machine without the model reading
  //    them, Claude Code's DesignSync write_files; supported-agents.md §2) ──
  "fs:upload-invalid-path": {
    source: "fail-closed", boundary: "filesystem", outcome: "deny+approval",
    summary: "upload of an empty or relative path — never guess which file leaves",
  },
  "fs:upload-unattested": {
    source: "fail-closed", boundary: "filesystem", outcome: "deny",
    summary: "upload check asked on the data socket — only the model proxy's human-plane client may make the arbiter read a file",
  },
  "fs:upload-secret-file": {
    source: "rule", boundary: "filesystem", outcome: "deny+approval",
    summary: "upload of a file labelled above public (or a registered secret file) to a destination none of its bindings names",
  },
  "fs:upload-secret-value": {
    source: "rule", boundary: "filesystem", outcome: "deny+approval",
    summary: "upload of a file whose bytes hold a registered secret value not bound to the destination",
  },
  "fs:upload-unreadable": {
    source: "fail-closed", boundary: "filesystem", outcome: "deny+approval",
    summary: "upload of a file the arbiter could not read whole (missing, not a regular file, too large) — its bytes cannot be checked",
  },
  "fs:upload-bound": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "upload of a secret file to a destination every one of its labels and values is bound to",
  },
  "fs:upload-clean": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "upload of a file with no secret label and no registered secret value in it",
  },
  "fs:upload-process-file": {
    source: "fail-closed", boundary: "filesystem", outcome: "deny+approval",
    summary: "upload of a file of a running process or of the kernel (/proc, /sys, /dev/fd) — the arbiter would read its own, not the tool's",
  },
  // The unmapped form (2026-10-17): a local path in the input of a tool no
  // gate table names (an MCP server's tool, a new agent release's tool).
  "fs:upload-mapped-tool": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "a path in a tool Mandu maps: its own checks judge it, nothing is read",
  },
  "fs:upload-confined-server": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "a path in a tool of a registered local MCP server, in a session the file guard confines",
  },
  "fs:upload-no-file": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "a path in an unmapped tool's input that names no stored bytes (nothing there, a device, a pipe)",
  },
  "fs:upload-folder": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "a folder in an unmapped tool's input with no secret label and outside the sensitive paths (its files are not looked into)",
  },

  // ── egress desymbolization gate (data-usage policy) ─────────────────────────
  "egress:invalid-symbol": {
    source: "fail-closed", boundary: "any", outcome: "deny+approval",
    summary: "empty/garbage symbol in the request",
  },
  "egress:unknown-symbol": {
    source: "rule", boundary: "any", outcome: "allow",
    summary: "symbol unknown to the table — nothing to leak, resolution is a no-op",
  },
  "egress:obsolete-symbol": {
    source: "fail-closed", boundary: "any", outcome: "deny+approval",
    summary: "symbol superseded (human edit) — the resolved value may not be the intended one",
  },
  "egress:siem-lockdown": {
    source: "rule", boundary: "network", outcome: "deny+approval",
    summary: "SIEM-triggered lockdown (siem-integration.md §4.3) — every network egress requires human approval",
  },
  "egress:secret-model-context": {
    source: "rule", boundary: "model_context", outcome: "deny",
    summary: "secret symbol must never enter model context (confidentiality §3.2) — no approval override",
  },
  "egress:secret-filesystem": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "secret to the HumanView filesystem — the human owns their own disk",
  },
  "egress:secret-unknown-destination": {
    source: "fail-closed", boundary: "network", outcome: "deny+approval",
    summary: "secret symbol with no destination to check bindings against",
  },
  "egress:secret-bound-trusted": {
    source: "rule", boundary: "network", outcome: "allow",
    summary: "trusted-integrity secret at its BOUND destination (confidentiality §3.2 carve-out)",
  },
  "egress:secret-bound-approval": {
    source: "rule", boundary: "network", outcome: "deny+approval",
    summary: "untrusted-influenced secret at a bound destination — one-time human approval (§9b)",
  },
  "egress:secret-unbound": {
    source: "rule", boundary: "network", outcome: "deny+approval",
    summary: "secret at an unbound destination — human declassification required (§3.2)",
  },
  "egress:secret-issuer": {
    source: "rule", boundary: "network", outcome: "allow",
    summary: "a trusted secret whose own format names its issuer, at that issuer's exact API host, in the Authorization header over HTTPS (the default catalog's issuer bindings, confidentiality §2.3; policy.yaml issuer_bindings)",
  },
  "egress:secret-https-only": {
    source: "rule", boundary: "network", outcome: "deny",
    summary: "a wire-twin credential declared for https is never put back in a plain-HTTP request (plan 10 §11.13.1)",
  },
  "egress:secret-wire-position": {
    source: "rule", boundary: "network", outcome: "deny",
    summary: "a credential bound only by its own config file or an auth grant is put back only in the request's Authorization header, never in its URL, body or another header (plan 10 §11.13.1)",
  },
  "egress:shell-expanded-placeholder": {
    source: "rule", boundary: "network", outcome: "deny",
    summary: "a request carries a secret's placeholder whose $MDU a shell expanded to nothing (net-proxy + ipc/server.ts strippedPlaceholders): it holds neither the value nor the placeholder, so it is refused with how to quote it, never filled in (confidentiality.md §7)",
  },
  "egress:symbol-as-command": {
    source: "rule", boundary: "shell", outcome: "deny+approval",
    summary: "untrusted symbol in command/code position — always requires human approval",
  },
  "egress:unknown-destination": {
    source: "fail-closed", boundary: "network", outcome: "deny+approval",
    summary: "network egress with no destination — possible exfil",
  },
  "egress:trusted-destination": {
    source: "rule", boundary: "network", outcome: "allow",
    summary: "destination in the TRUSTED URL category",
  },
  "egress:untrusted-destination": {
    source: "rule", boundary: "network", outcome: "deny+approval",
    summary: "untrusted symbol bound for an untrusted destination",
  },
  // ── operator law from policy.yaml (policy-surface.md §2.4, §2.5) ──
  // Consulted by the server AFTER a standing verdict and BEFORE the built-in
  // branches: Block beats Allow among matching user rules; a disposition
  // turns a built-in ask into a deny.
  "egress:user-rule-block": {
    source: "rule", boundary: "network", outcome: "deny",
    summary: "a user rule (policy.yaml user_rules, mode block) forbids releasing data from this origin to this destination — nothing is queued",
  },
  "egress:user-rule-allow": {
    source: "rule", boundary: "network", outcome: "allow",
    summary: "a user rule (policy.yaml user_rules, mode allow) releases untrusted data from this origin to this destination — a RELAXATION, listed as such",
  },
  "egress:disposition-block": {
    source: "rule", boundary: "network", outcome: "deny",
    summary: "a built-in rule that asks by default was set to Block by the operator (policy.yaml rules:) — denied, nothing queued",
  },
  "egress:shell-boundary": {
    source: "fail-closed", boundary: "shell", outcome: "deny+approval",
    summary: "bare shell-boundary request — must go through the per-command argv gate (resolveExecArgv)",
  },
  "egress:filesystem-humanview": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "local human-facing sink — the dual-view sync re-symbolizes on disk",
  },
  "egress:user-facing-output": {
    source: "rule", boundary: "model_context", outcome: "allow",
    summary: "user-facing reply — the human may see the original value (HumanView)",
  },
  "egress:unknown-boundary": {
    source: "fail-closed", boundary: "any", outcome: "deny+approval",
    summary: "unrecognized egress boundary (out of contract)",
  },

  // ── exec wire gate (Phase 0, exec-routing.md §3) + escalation (§5 wrap) ─────
  "exec:symbol-in-command": {
    source: "rule", boundary: "shell", outcome: "deny",
    summary: "untrusted symbol in command/execution position — rewritten to the exit-77 sentinel on the wire",
  },
  "exec:no-symbol-in-command": {
    source: "rule", boundary: "shell", outcome: "allow",
    summary: "no symbol in command position — allowed (evasion signals recorded, not blocking)",
  },
  "exec:escalation-approval": {
    source: "rule", boundary: "shell", outcome: "deny+approval",
    summary: "AgentShell command needs a restricted resource — HumanShell only behind a human approval (fail-safe: queue + stay AgentShell)",
  },
  "exec:tainted-program-text": {
    source: "rule", boundary: "shell", outcome: "deny+approval",
    summary: "the program text is net-fetched code (a file curl/wget wrote, or a `curl | bash` pipe) — executing untrusted-by-origin code needs a human approval; unknown/pre-existing scripts are not gated",
  },

  // ── session watermark gate (Plan 8 §4 — the paraphrase chokepoint) ──────────
  "session:not-high": {
    source: "rule", boundary: "any", outcome: "allow",
    summary: "session has read no secret into context — the watermark gate is inert",
  },
  "session:high-fs-labeled": {
    source: "rule", boundary: "filesystem", outcome: "allow",
    summary: "high session's writes are LABELED on disk at the watermark, not blocked",
  },
  "session:agentshell-no-net": {
    source: "rule", boundary: "shell", outcome: "allow",
    summary: "AgentShell with net off — not an egress; the exec valve already confines it",
  },
  "session:high-tainted-bound": {
    source: "rule", boundary: "network", outcome: "deny+approval",
    summary: "HIGH + untrusted-tainted session at a bound destination — the standing release is suspended (§9 rule 1b)",
  },
  "session:high-bound-release": {
    source: "rule", boundary: "network", outcome: "allow",
    summary: "high session to a BOUND destination — the read data's own standing release",
  },
  "session:high-unbound": {
    source: "rule", boundary: "network", outcome: "deny+approval",
    summary: "high session to an unbound destination — a paraphrase may carry the secret, human approval required",
  },
  "session:high-shell": {
    source: "rule", boundary: "shell", outcome: "deny+approval",
    summary: "high session runs a command no gate can prove net-less — a paraphrase may ride its arguments, human approval required (Allow once: that exact command, once)",
  },

  // ── interceptor fail-closed (enforced proxy-side, part of the standing law) ─
  "proxy:arbiter-unreachable": {
    source: "fail-closed", boundary: "any", outcome: "deny",
    summary: "arbiter unreachable or timed out — interceptors fail closed (deny/sentinel), never fall through to raw",
  },
} as const satisfies Record<`${GateId}:${string}`, Omit<UsageRule, "id" | "gate">>;
// The key template ties every rule id to a GATES prefix at compile time —
// `gate` is derived (gateOf), never hand-duplicated per row.

export type RuleId = keyof typeof RULES;

/** Build the ref for a catalog rule id (compile-time-checked). */
export function ruleRef(id: RuleId): RuleRef {
  return { source: RULES[id].source, id };
}

/** Build the ref for a standing human verdict (an approval-queue row). */
export function verdictRef(entryId: string): RuleRef {
  return { source: "verdict", id: `verdict:${entryId}` };
}

/** The catalog as a list, for the policySnapshot op / the Rules tab. */
export function listUsageRules(): UsageRule[] {
  return Object.entries(RULES).map(([id, r]) => ({
    id,
    ...r,
    gate: gateOf(id as RuleId),
  }));
}

/** The gate catalog as a list, for the policySnapshot op (panel row detail). */
export function listUsageGates(): UsageGate[] {
  return Object.entries(GATES).map(([id, g]) => ({ id, ...g }));
}
