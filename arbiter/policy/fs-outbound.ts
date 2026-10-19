/**
 * fs-outbound — the sensitive-path gate's pure decision (data-usage policy,
 * filesystem boundary). P3 of the portable fs core: fs-sync.md §1.4.1.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code — the reference
 * implementation had no fs gate (OpenClaw tools were workspace-scoped by the
 * host). Shape mirrors decideDesymbolization (policy-interface.ts): a PURE
 * function (request + lookups → decision) unit-tested as an oracle; the
 * stateful approval queue wraps it in ipc/server.ts, never here.
 *
 * The question: may tool T touch absolute path P (mode read|write)?
 * Rule order, with DENY-PRECEDENCE (fs-sync.md §1.4.1):
 *   1. built-in sensitive list → deny + requiresApproval. Wins even over a
 *      workspace match: a workspace rooted at `~` must still gate `~/.ssh`.
 *   2. inside a workspace root (HumanView or AgentView) → allow.
 *   3. DIR trust-category allowlist (policy file) → allow.
 *   4. DEFAULT: out-of-workspace → deny + requiresApproval (FAIL-CLOSED).
 *
 * Matching is lexical (normalize + segment-aware prefix), never resolves the
 * filesystem — symlink aliasing is gap class 3, absorbed by fs-sync/kernel
 * tiers, not here.
 */

import { homedir } from "node:os";
import path from "node:path";
import { ruleRef, type RuleRef } from "./rule-ref.js";

/** May tool `tool` touch `path` in `mode`? Asked by the context proxy at the
 *  response-side tool_use hook (the same hook as the P2 prefix map). */
export interface FsPathDecisionRequest {
  /** The tool about to act (e.g. "Read", "Write"). Recorded in the queue key. */
  tool: string;
  /** The ABSOLUTE target path, as the agent would receive it. */
  path: string;
  /** What the tool does to the path (Read/Glob/Grep/LS = read; Write/Edit/… = write). */
  mode: "read" | "write";
  /** Workspace roots the caller vouches for (HumanView + AgentView roots —
   * the proxy's view-map pairs). Paths inside any of them are allowed. */
  workspaceRoots: string[];
  /** Requesting session key — attribution ONLY, never a decision input (the
   * pure gate ignores it). Rides to the approval-queue row
   * (EgressApproval.sessions) via the server wrap. */
  sessionKey?: string;
}

export type FsPathDecision =
  | { allow: true; reason: string; ruleRef?: RuleRef }
  | {
      allow: false;
      requiresApproval: boolean;
      reason: string;
      ruleRef?: RuleRef;
      /** The approval-queue entry this deny created/bumped (`egr-<n>`), stamped
       * by the server wrap when requiresApproval queued a pending row — the
       * event-side join back to the Pending tab (policy-surface.md §9.5).
       * Absent from the pure gate. */
      approvalId?: string;
    };

export interface FsPathDecisionOptions {
  /** DIR trust-category allowlist check (policy file), like the URL check the
   * egress gate threads. Absent → nothing outside the workspace is allowed. */
  isDirTrusted?: (path: string) => boolean;
  /** Home dir for expanding the built-in `~/…` sensitive entries (tests). */
  home?: string;
}

/**
 * Built-in sensitive prefixes, home-relative (`~/…`) or absolute. Deny-listed
 * with approval REGARDLESS of workspace membership. Curated for credential /
 * key / agent-config material — the exfil-staging set, not a general blocklist
 * (everything else out-of-workspace is already deny-by-default).
 */
export const SENSITIVE_PATHS: readonly string[] = [
  // key material + credential stores
  "~/.ssh",
  "~/.gnupg",
  "~/.aws",
  "~/.kube",
  "~/.docker/config.json",
  "~/.netrc",
  "~/.git-credentials",
  "~/.config/gh",
  "~/.config/gcloud",
  // agent credentials/config (an injected agent must not read its own keys)
  "~/.claude",
  "~/.claude.json",
  "~/.codex",
  "~/.anthropic",
  "~/.openai",
  // OpenCode's own data (2026-10-05, supported-agents.md §2.3 item 10): the
  // provider keys (auth.json), the session store with every tool output
  // (opencode.db, both generations), and OpenCode 2's kept shell output
  // files (shell/<hash>/sh_<id>.out). The same posture as ~/.claude and
  // ~/.codex, which hold Claude Code's and Codex's transcripts: a tool's
  // read asks, the catalog labels it no-model, discovery never twins it.
  "~/.local/share/opencode",
  // Goose's own key file (2026-10-06, supported-agents.md §5.6.1): what
  // `goose configure` saves when the keyring is off or out of reach. A
  // tool's read asks; the launcher registers it and, under `mandu goose`
  // only, leaves it readable to Goose (its login); under every other agent
  // it is twinned like any catalog secret.
  "~/.config/goose/secrets.yaml",
  // Goose's own data and state (2026-10-07, supported-agents.md §5.6.2):
  // the session store (sessions/sessions.db, every message and tool output
  // as Goose built it) and the request log (logs/llm_request.*.jsonl, the
  // last ten requests whole, written BEFORE the model proxy symbolizes
  // them), the prompt history and the CLI logs. The same posture as
  // ~/.local/share/opencode: a tool's read asks, the catalog labels it
  // no-model, discovery never twins it (Goose keeps writing it raw). Any
  // XDG or GOOSE_PATH_ROOT spelling: secret-catalog.ts GOOSE_DATA_SHAPE_RE.
  "~/.local/share/goose",
  "~/.local/state/goose",
  // system credential/privilege files
  "/etc/shadow",
  "/etc/gshadow",
  "/etc/sudoers",
  "/etc/sudoers.d",
];

/** Lexically normalize for matching: expand ~, resolve ./.., collapse //. */
function normalize(p: string, home: string): string {
  let s = p.trim();
  if (s === "~") s = home;
  else if (s.startsWith("~/")) s = path.posix.join(home, s.slice(2));
  let norm = path.posix.normalize(s);
  if (norm.length > 1 && norm.endsWith("/")) norm = norm.slice(0, -1);
  return norm;
}

/**
 * Canonicalize an fs path for STABLE keying — the SAME normalization
 * `decideFsPath` applies internally (expand `~`, resolve `./..`, collapse `//`,
 * strip a trailing `/`). Exposed so the approval queue keys every spelling of
 * one target to a SINGLE entry: without it, a human "deny" pinned only the exact
 * spelling and `/x//y`, `/x/./y`, `~/y` each re-queued and escaped the verdict.
 * `home` defaults to `homedir()`, matching what the pure gate uses.
 */
export function normalizeFsPath(p: string, home: string = homedir()): string {
  if (typeof p !== "string" || p.trim() === "") return "";
  return normalize(p, home);
}

/** Segment-aware: is `p` equal to `root` or below it? */
function underRoot(p: string, root: string): boolean {
  return p === root || p.startsWith(root + "/");
}

/** The pure sensitive-path gate. See the module header for the rule order. */
export function decideFsPath(
  req: FsPathDecisionRequest,
  opts: FsPathDecisionOptions = {},
): FsPathDecision {
  const home = opts.home ?? homedir();

  // Malformed request → fail-closed (never guess about an unparseable target).
  if (typeof req.path !== "string" || req.path.trim() === "") {
    return {
      allow: false, requiresApproval: true,
      reason: "fail-closed: empty/invalid path",
      ruleRef: ruleRef("fs:invalid-path"),
    };
  }
  const p = normalize(req.path, home);
  if (!path.posix.isAbsolute(p)) {
    // The proxy only gates absolute paths (relative = CWD scoping's job); a
    // relative path reaching the op anyway is out-of-contract → fail-closed.
    return {
      allow: false,
      requiresApproval: true,
      reason: "fail-closed: fsPathDecision expects an absolute path",
      ruleRef: ruleRef("fs:relative-path"),
    };
  }

  // 1. Sensitive built-ins — deny-precedence over everything.
  for (const entry of SENSITIVE_PATHS) {
    const s = normalize(entry, home);
    if (underRoot(p, s)) {
      return {
        allow: false,
        requiresApproval: true,
        reason: `sensitive path (${entry}): ${req.mode} by '${req.tool}' requires approval`,
        ruleRef: ruleRef("fs:sensitive-path"),
      };
    }
  }

  // 2. Workspace roots (HumanView / AgentView) — the caller vouches for these.
  for (const root of req.workspaceRoots ?? []) {
    if (typeof root !== "string" || root === "") continue;
    const r = normalize(root, home);
    if (path.posix.isAbsolute(r) && underRoot(p, r)) {
      return {
        allow: true,
        reason: `inside workspace root ${root}`,
        ruleRef: ruleRef("fs:workspace-root"),
      };
    }
  }

  // 3. DIR trust-category allowlist (policy file).
  if (opts.isDirTrusted?.(p)) {
    return {
      allow: true,
      reason: "DIR trust category: path allowlisted",
      ruleRef: ruleRef("fs:dir-allowlist"),
    };
  }

  // 4. Default: out-of-workspace → fail-closed deny/approve.
  return {
    allow: false,
    requiresApproval: true,
    reason: `fail-closed: out-of-workspace ${req.mode} of '${p}' by '${req.tool}' requires approval`,
    ruleRef: ruleRef("fs:default-deny"),
  };
}
