/**
 * view-sync — the view-sync lifecycle orchestrator (HumanView <-> AgentView).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   The sync path is lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-filecommit-worktree.ts
 *     (and the on-demand twin adfi-filecommit-ondemand.ts).
 *   Purpose: the two-stage commit that reconciles the AgentView (symbolized)
 *   worktree into the HumanView (raw on-disk files):
 *     1. commit [MDU-TRUSTED] on the mdu-trusted branch (AgentView snapshot)
 *     2. sync this call's changed paths into the HumanView (R2 race guard)
 *     3. commit [MDU-TRUSTED] on the shadow main line (blame-visible trusted parent)
 *     4. desymbolize the synced files in the HumanView
 *     5. commit [MDU-UNTRUSTED] on the shadow main line (raw content)
 *   Design: docs/adfi-reference/design/fs-level-tracking.md; the substrate is
 *   the SHADOW repo (repo.git over the workspace, fs-sync.md §3) —
 *   the user's own .git is never written.
 *
 * Adaptation for Mandu (OpenClaw coupling stripped + arbiter routing):
 *   - The reference was an `after_tool_call` HOOK FACTORY taking an OpenClaw
 *     event. Mandu has no tool hook at the FS layer (the seccomp openat
 *     rewrite triggers this), so this is a plain class driven by a workspace dir
 *     + a git worktree. The OpenClaw `event`/`ctx` params are replaced by an
 *     explicit `{ toolName, callId, runId }` provenance struct.
 *   - Step 4 desymbolization called `resolveAllSymbols` over the in-process
 *     symbol map; it now calls `arbiter.desymbolize(text)` (the arbiter is the
 *     single symbol owner — fs-sync never opens the DB).
 *   - `initialize()` / `readForAgent()` / `captureAgentWrite()` are the
 *     Mandu-shaped surface the Rust fs-supervisor will call on init / openat
 *     (read) / write. They wrap the lifted worktree + symbolize primitives.
 *   - Fixed/on-demand branching collapsed to ONE layout (the supervisor targets
 *     a specific tracked root).
 *
 * SECURITY INVARIANT: `readForAgent` only ever returns AgentView content. If a
 * HumanView file is untrusted and not yet symbolized, it is symbolized through
 * the arbiter FIRST (fail-closed: a arbiter error aborts the read rather than
 * exposing raw bytes). The AgentView worktree therefore never holds
 * un-symbolized untrusted content.
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import type { SymbolArbiter } from "./arbiter-client.js";
import { extractSymbols, hasSymbols, levelOfSymbolName } from "./arbiter-client.js";
import {
  acquireLock,
  mduCommit,
  getChangedFiles,
  getTrackedFiles,
  getWorktreePath,
  type GitCtx,
  gitExecSync,
  initWorktree,
  isSymlink,
  isWorktreeInitialized,
  migrateLegacyWorkspace,
  releaseLock,
  removeWorktree,
  shadowCtx,
  stageFiles,
  writeConflictLog,
} from "./git.js";
import { ViewLayout, defaultStateBase } from "./layout.js";
import { reconcileHumanEdits, type ReconcileResult } from "./human-edit.js";
import {
  DEFAULT_IGNORED_LIMITS,
  type IgnoredLimits,
  type IgnoredSkip,
  humanIgnoredSet,
  listAgentViewIgnored,
  listIgnoredFiles,
  loadIgnoredManifest,
  pathCrossesSymlink,
  saveIgnoredManifest,
  sha256,
  skipCounts,
} from "./ignored.js";
import {
  desymbolizeContent,
  symbolizeContent,
  type SymbolizeContentOptions,
} from "./symbolize.js";

export interface Logger {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
}

const NOOP_LOG: Logger = { info: () => {}, warn: () => {}, error: () => {} };

/** Re-launch fast path (seedAgentView): the AgentView twin's text when it is
 *  a regular file (never a symlink, P5) that already carries a symbol, else
 *  null. Any read failure counts as "not current" so the file is re-seeded
 *  (fail-closed). */
function symbolicTwinText(agent: string): string | null {
  try {
    if (!existsSync(agent) || isSymlink(agent) || !statSync(agent).isFile()) return null;
    const text = readFileSync(agent, "utf8");
    return hasSymbols(text) ? text : null;
  } catch {
    return null;
  }
}

/** How many twins the seed checks against the arbiter at once. The checks
 *  are independent reads (resolve, pathLevel) over one pipelined client:
 *  asked one at a time they were ~4,400 sequential round trips on a
 *  1,700-twin workspace, ~2 s of every launch (fs-sync.md §3). */
export const SEED_CHECK_CONCURRENCY = 32;

/** `fn` over `items` with at most `limit` in flight; results in input order. */
export async function mapPool<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** Provenance for a sync/commit (replaces the OpenClaw tool-call event). */
export interface WriteProvenance {
  toolName: string;
  callId?: string;
  runId?: string;
}

export interface ViewSyncOptions {
  /** HumanView path: the user's real workspace dir. Need NOT be a git repo —
   *  the substrate is the state dir's shadow repo (fs-sync.md §3);
   *  a workspace .git, if present, is never touched. */
  workspacePath: string;
  /** The narrow arbiter surface (symbolize/desymbolize/resolve). */
  arbiter: SymbolArbiter;
  /** view state base (default: `defaultStateBase()`, the path table). Tests pass a temp dir. */
  stateBase?: string;
  /** Session the mints (and their birth events, symbol-lineage.md G1) are
   *  filed under. The launcher/e2e pass their scope id; absent, mints still
   *  succeed but births are not emitted (the event log is per-session). */
  sessionKey?: string;
  log?: Logger;
  auditWrite?: (entry: object) => void;
  /** The `.gitignore`d files brought into the AgentView as symbolized twins
   *  (ignored.ts; fs-sync.md §3.4.1). Absent = the defaults;
   *  `false` = off (the pre-2026-09-28 behavior: ignored files are absent
   *  from the AgentView). */
  ignored?: IgnoredLimits | false;
}

/** What the last ignored-file pass did (fs-sync-cli `init` prints it). */
export interface IgnoredStatus {
  enabled: boolean;
  /** Paths with a twin in the AgentView. */
  included: number;
  minted: number;
  reused: number;
  removed: number;
  skipped: IgnoredSkip[];
}

function collectFilePathsUnder(dirPath: string, relPath: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    // Symlinks never sync (P5, gap class 3): copying one would materialize its
    // TARGET's bytes (copyFileSync follows links) — a path-aliasing escape.
    if (entry.isSymbolicLink()) continue;
    const childRel = relPath ? `${relPath}/${entry.name}` : entry.name;
    const childAbs = join(dirPath, entry.name);
    if (entry.isDirectory()) results.push(...collectFilePathsUnder(childAbs, childRel));
    else if (entry.isFile()) results.push(childRel);
  }
  return results;
}

/**
 * The regular file that stands in for a symlink in the AgentView. Deliberately
 * carries NO attacker bytes (not even the link target — a target string is
 * repo-controlled data and could smuggle an injection as "trusted" text).
 */
export const SYMLINK_MARKER =
  "[mandu] symbolic link not materialized in the AgentView (fs-sync.md gap class 3)\n";

function expandChangedPaths(trustedPath: string, filePaths: string[]): string[] {
  const expanded = new Set<string>();
  for (const filePath of filePaths) {
    const cleanPath = filePath.replace(/\/+$/, "");
    const trustedFilePath = join(trustedPath, cleanPath);
    if (!existsSync(trustedFilePath)) {
      expanded.add(cleanPath);
      continue;
    }
    if (statSync(trustedFilePath).isDirectory()) {
      for (const nested of collectFilePathsUnder(trustedFilePath, cleanPath)) expanded.add(nested);
    } else {
      expanded.add(cleanPath);
    }
  }
  return [...expanded].sort();
}

export class ViewSync {
  readonly layout: ViewLayout;
  private readonly arbiter: SymbolArbiter;
  private readonly sessionKey?: string;
  private readonly log: Logger;
  private readonly auditWrite?: (entry: object) => void;
  private readonly ignoredLimits: IgnoredLimits | null;
  private lastIgnored: IgnoredStatus | null = null;

  constructor(opts: ViewSyncOptions) {
    this.layout = new ViewLayout(opts.workspacePath, opts.stateBase ?? defaultStateBase());
    this.arbiter = opts.arbiter;
    this.sessionKey = opts.sessionKey;
    this.log = opts.log ?? NOOP_LOG;
    this.auditWrite = opts.auditWrite;
    this.ignoredLimits = opts.ignored === false ? null : (opts.ignored ?? DEFAULT_IGNORED_LIMITS);
  }

  get humanPath(): string {
    return this.layout.humanPath;
  }

  /** The AgentView worktree path the agent's reads/writes are rewritten to. */
  get agentViewPath(): string {
    return getWorktreePath(this.layout);
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Initialize the dual-view: ensure the SHADOW substrate repo exists
   * (fs-sync.md §3.2 — the workspace's own `.git`, if any, is never
   * touched), create the mdu-trusted branch + AgentView worktree off it, and
   * seed every existing HumanView file into the AgentView as symbolized
   * content. A workspace still on the legacy in-user-repo substrate is
   * migrated first (§6). Idempotent.
   */
  async initialize(): Promise<void> {
    const migrated = migrateLegacyWorkspace(this.layout);
    if (migrated) {
      this.log.warn(
        `[fs-sync] migrated off the legacy in-user-repo substrate (removed ${
          migrated.removedBranches.join("+") || "no branches"
        } + the worktree registration from the user's repo` +
          (migrated.backedUp.length > 0
            ? `; ${migrated.backedUp.length} unsynced AgentView file(s) backed up to ${migrated.backupDir}`
            : "") +
          `)`,
      );
    }

    // initWorktree ensures the shadow repo + its baseline snapshot first.
    this.materializeWorktree();

    // Seed: symbolize each existing (untrusted-by-default) HumanView file into
    // the AgentView. Fail-closed via symbolizeContent.
    await this.seedAgentView();

    // …and the `.gitignore`d files, as twins OUTSIDE git (fs-sync.md §3
    // §4.1). Same fail-closed mint; a failure aborts the launch like the seed's.
    await this.syncIgnoredFromHuman();
  }

  /**
   * Create the AgentView worktree AND immediately neutralize the symlinks its
   * checkout materialized. These two steps MUST stay together (P5): the git
   * checkout materializes any symlink the repo TRACKS, and a link can alias
   * paths outside both views (gap class 3), so each is replaced with an inert
   * marker BEFORE the agent can read through it. Both materialization sites —
   * initialize() and syncToHuman()'s lazy re-init — go through here so neither
   * can drop the neutralization pass.
   */
  private materializeWorktree(): void {
    initWorktree(this.layout);
    this.neutralizeAgentViewSymlinks();
  }

  /**
   * Replace every symlink in the AgentView worktree with the inert
   * SYMLINK_MARKER regular file. The HumanView keeps its links untouched
   * (syncToHuman refuses to touch symlink paths in either view, so the marker
   * never propagates back). Idempotent; returns the neutralized rel paths.
   */
  private neutralizeAgentViewSymlinks(): string[] {
    const root = this.agentViewPath;
    const neutralized: string[] = [];
    const walk = (dir: string, rel: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === ".git") continue;
        const childAbs = join(dir, entry.name);
        const childRel = rel ? `${rel}/${entry.name}` : entry.name;
        if (entry.isSymbolicLink()) {
          rmSync(childAbs); // removes the LINK, never the target
          writeFileSync(childAbs, SYMLINK_MARKER);
          neutralized.push(childRel);
        } else if (entry.isDirectory()) {
          walk(childAbs, childRel);
        }
      }
    };
    walk(root, "");
    if (neutralized.length > 0) {
      this.log.warn(
        `[fs-sync] neutralized ${neutralized.length} symlink(s) in the AgentView (gap class 3): ${neutralized.join(", ")}`,
      );
    }
    return neutralized;
  }

  /** Whether the dual-view is initialized (AgentView worktree present). */
  isInitialized(): boolean {
    return isWorktreeInitialized(this.layout);
  }

  /** Tear down the AgentView worktree (HumanView untouched). */
  teardown(): void {
    removeWorktree(this.layout);
  }

  /**
   * Symbolize every tracked HumanView file into the AgentView and commit the
   * symbolized snapshot on mdu-trusted. This is the first ingress: it ensures
   * the AgentView contains only symbols for untrusted content before any agent
   * read.
   *
   * Idempotent on RE-LAUNCH (fs-sync.md §3.2 "Re-launch fast path"):
   * a twin that already holds a symbol for a HumanView file that has NOT
   * diverged from the shadow HEAD is current, so nothing is minted for it.
   * Before this rule every `mandu` launch re-symbolized the whole workspace
   * through the arbiter: symbolize + birth emit = two IPC round trips and a
   * fresh session-keyed symbol row per file, ~9 ms/file, 11 s of launch time
   * on the 1.1k-file mandu repo, and the symbol DB grew by the workspace's
   * text on every launch (9901 of 10275 rows were re-seeds, 729 per launch).
   * The invariant still wins over the fast path: a diverged HumanView file, a
   * missing twin, or a twin holding raw bytes is (re-)seeded exactly as before.
   */
  /** Re-launch fast-path guard: does the arbiter still resolve EVERY token the
   *  twin holds? A whole-file twin holds one; a human-edited twin holds its
   *  split parts. Any unknown/obsoleted token, or any IPC error, answers false
   *  so the file is re-seeded from its HumanView original (never a leak: the
   *  re-seed re-symbolizes; the only cost is the mint). */
  private async twinTokensResolve(agent: string, text?: string): Promise<string[] | null> {
    try {
      const tokens = extractSymbols(text ?? readFileSync(agent, "utf8"));
      if (tokens.length === 0) return null;
      const known = await Promise.all(tokens.map((sym) => this.arbiter.resolve(sym)));
      return known.every((v) => v !== null) ? tokens : null;
    } catch {
      return null;
    }
  }

  /** The seed's verdict on one symbolic twin (its text already read): still
   *  current (every token resolves AND carries today's level for the
   *  HumanView path), relabeled, or dangling. The two arbiter reads go out
   *  together; the verdict is the one the sequential checks gave. */
  private async seedTwinVerdict(agent: string, text: string, human: string): Promise<"current" | "relabeled" | "dangling"> {
    const [tokens, level] = await Promise.all([
      this.twinTokensResolve(agent, text),
      this.twinLevelCurrent(extractSymbols(text), human),
    ]);
    if (tokens === null) return "dangling";
    return level ? "current" : "relabeled";
  }

  /** Relabel guard: does every token's marker level equal the level the
   *  arbiter would mint for the HumanView path today? Axis OFF, or an arbiter
   *  without `pathLevel`, answers true (nothing to compare); an IPC error
   *  answers false (re-seed — never a leak, one mint). */
  private async twinLevelCurrent(tokens: string[], human: string): Promise<boolean> {
    if (!this.arbiter.pathLevel) return true;
    try {
      const now = await this.arbiter.pathLevel(human);
      if (!now.axis) return true;
      return tokens.every((sym) => levelOfSymbolName(sym) === now.level);
    } catch {
      return false;
    }
  }

  private async seedAgentView(): Promise<void> {
    const trustedPath = this.agentViewPath;
    const files = getTrackedFiles({ cwd: trustedPath });
    // HumanView files that moved since the shadow HEAD (the last state fs-sync
    // recorded) — the same divergence notion reconcileHumanEdits uses.
    const diverged = new Set(getChangedFiles(shadowCtx(this.layout)).map((f) => f.path));
    let changed = false;
    let reused = 0;
    let minted = 0;
    let dangling = 0;
    let relabeled = 0;
    // Diverged files this seed ingested (whole-file re-symbolization). Their
    // HumanView state is RECORDED on the shadow main line afterwards so the
    // next launch sees them as current: without that record the same files
    // re-seeded on every launch forever (254 files on the mandu workspace,
    // whose shadow HEAD had not moved since 2026-07-20, ~2.5 s per launch).
    const ingested: string[] = [];

    acquireLock(this.layout);
    try {
      // 1. Which files the seed considers, and which of those already hold a
      //    symbolic twin (cheap local reads, as before).
      const candidates: Array<{ rel: string; human: string; agent: string; twin: string | null }> = [];
      for (const rel of files) {
        const human = join(this.humanPath, rel);
        const agent = join(trustedPath, rel);
        if (!existsSync(human)) continue;
        // Never read THROUGH a HumanView symlink (its target may live outside
        // the workspace) and never write THROUGH an AgentView one (P5).
        if (isSymlink(human) || isSymlink(agent)) continue;
        if (statSync(human).isDirectory()) continue;
        candidates.push({ rel, human, agent, twin: diverged.has(rel) ? null : symbolicTwinText(agent) });
      }
      // 2. Is each symbolic twin still current? A symbolic twin is current
      //    ONLY if the arbiter still knows its tokens. After a symbol-DB swap
      //    (mandu-db-no-backcompat: the file is deleted and re-created, never
      //    migrated) every existing twin holds a token that resolves to
      //    nothing — the AgentView is still safe (opaque), but every Read →
      //    inspect_symbol of that file is blind, and a multi-file inspect
      //    hands the U-LLM the bare tokens to invent from
      //    (watch-20260918T194546 U6: `RC-0657-2168` built from two token
      //    hashes). …and its tokens must still carry the level a read of the
      //    HumanView path would mint TODAY: a label added, changed or removed
      //    after the seed (policy.yaml, the dashboard's lock) must reach the
      //    AgentView (a `.env` fixture labeled public after a strict seed
      //    stays uninspectable forever, watch-20260918T214500 C11; a path
      //    labeled STRICTER after a public seed keeps a twin the quarantine
      //    would still open, the security-relevant direction). A null or an
      //    error re-seeds (fail toward re-minting). The checks are
      //    independent reads, so they run SEED_CHECK_CONCURRENCY at a time.
      const verdicts = await mapPool(candidates, SEED_CHECK_CONCURRENCY, async (c) =>
        c.twin === null ? "absent" as const : this.seedTwinVerdict(c.agent, c.twin, c.human));
      // 3. Mint what is not current, one file at a time, in tracked order.
      for (let i = 0; i < candidates.length; i++) {
        const { rel, human, agent } = candidates[i]!;
        const verdict = verdicts[i]!;
        if (verdict === "current") {
          reused++;
          continue;
        }
        if (verdict === "relabeled") relabeled++;
        if (verdict === "dangling") dangling++;
        const raw = readFileSync(human);
        if (diverged.has(rel)) ingested.push(rel);
        const { content, symbol } = await symbolizeContent(this.arbiter, raw, {
          tool: "Read",
          origin: human,
          field: rel,
          sessionKey: this.sessionKey,
        });
        if (symbol == null) continue; // binary / empty / already symbolic
        mkdirSync(dirname(agent), { recursive: true });
        writeFileSync(agent, content);
        changed = true;
        minted++;
      }

      if (reused > 0 || dangling > 0 || relabeled > 0) {
        this.log.info(
          `[fs-sync] seed: ${reused} twin(s) already current (skipped), ${minted} symbolized` +
            (dangling > 0 ? ` (${dangling} re-seeded: their symbols no longer resolve — symbol DB replaced?)` : "") +
            (relabeled > 0 ? ` (${relabeled} re-seeded: their confidentiality label changed since the seed)` : ""),
        );
      }
      if (changed) {
        const trustedCtx: GitCtx = { cwd: trustedPath };
        const dirty = this.withoutIgnored(getChangedFiles(trustedCtx).map((f) => f.path));
        stageFiles(trustedCtx, dirty);
        mduCommit(trustedCtx, { trusted: true, toolName: "seed", files: dirty });
        this.log.info(`[fs-sync] seeded ${dirty.length} symbolized file(s) into AgentView`);
      }
      if (ingested.length > 0) {
        // Record the ingested HumanView state on the shadow main line as an
        // [MDU-TRUSTED] tool=seed commit (the tag syncToHuman uses for a
        // recorded state; NOT [MDU-HUMAN], whose blame would later read these
        // symbolized-as-untrusted lines as human-authored trusted text). Revert
        // walks only [MDU-UNTRUSTED] main commits, so its index pairing is
        // untouched (fs-sync.md §3.5).
        const mainCtx = shadowCtx(this.layout);
        stageFiles(mainCtx, ingested);
        mduCommit(mainCtx, { trusted: true, toolName: "seed", files: ingested });
        this.log.info(`[fs-sync] seed: recorded ${ingested.length} diverged HumanView file(s) on the shadow main line`);
      }
    } finally {
      releaseLock(this.layout);
    }
  }

  // ── Agent read / write ──────────────────────────────────────────────────

  /**
   * Serve an agent read: return the AgentView (symbolized) content for a path
   * relative to the HumanView root. If the AgentView twin is missing or stale
   * (HumanView file exists but no symbolized twin), symbolize on demand FIRST.
   *
   * SECURITY: the returned bytes are always AgentView content. Untrusted raw
   * content is never returned — it is symbolized through the arbiter (fail-closed).
   */
  async readForAgent(relPath: string, opts: SymbolizeContentOptions = {}): Promise<Buffer> {
    const agentFile = join(this.agentViewPath, relPath);
    const humanFile = join(this.humanPath, relPath);
    // FAIL-CLOSED (P5, gap class 3): never read THROUGH an AgentView symlink —
    // it serves bytes from wherever it points, potentially outside both views.
    // (A HumanView link whose AgentView twin is a neutralized regular marker is
    // fine: the marker is served, the link is never followed — see below.)
    if (isSymlink(agentFile)) {
      throw new Error(
        `fs-sync.readForAgent: ${relPath} is a symbolic link — refusing to read through it (gap class 3)`,
      );
    }
    if (existsSync(agentFile)) {
      const buf = readFileSync(agentFile);
      const text = buf.toString("utf8");
      // Already symbolic → serve as-is (the common, fast case).
      if (hasSymbols(text)) return buf;
      // Raw bytes in the AgentView: a tainted child may have written them
      // directly (design §4.1). Consult the provenance registry. Fail-closed:
      // a arbiter error → treat as untrusted and symbolize.
      let untrusted: boolean;
      try {
        // Path-only lookup is intentional for now; once the kernel write-path taintFile
        // producer lands (spec §4.3 dual-keyed), pass contentHash too so AgentView-only files match.
        const verdict = await this.arbiter.fileTrust({ path: humanFile });
        untrusted = verdict.untrusted;
      } catch (err) {
        this.log.warn(`[fs-sync] fileTrust failed for ${relPath}: ${(err as Error).message} → fail-closed UNTRUSTED`);
        untrusted = true;
      }
      if (!untrusted) return buf; // trusted raw (agent-authored) → serve as-is
      // Untrusted raw → symbolize inline + persist back into AgentView, then serve.
      const { content } = await symbolizeContent(this.arbiter, buf, {
        tool: opts.tool ?? "Read",
        origin: opts.origin ?? humanFile,
        field: opts.field ?? relPath,
        sessionKey: opts.sessionKey ?? this.sessionKey,
        callId: opts.callId,
      });
      writeFileSync(agentFile, content);
      return content;
    }
    // No AgentView twin yet — symbolize the HumanView source on demand.
    if (isSymlink(humanFile)) {
      // Same refusal on the human side: on-demand symbolization must not
      // follow a link out of the workspace (P5, gap class 3).
      throw new Error(
        `fs-sync.readForAgent: ${relPath} is a symbolic link — refusing to read through it (gap class 3)`,
      );
    }
    if (!existsSync(humanFile)) {
      throw new Error(`fs-sync.readForAgent: no such file in either view: ${relPath}`);
    }
    const raw = readFileSync(humanFile);
    const { content } = await symbolizeContent(this.arbiter, raw, {
      tool: opts.tool ?? "Read",
      origin: opts.origin ?? humanFile,
      field: opts.field ?? relPath,
      sessionKey: opts.sessionKey ?? this.sessionKey,
      callId: opts.callId,
    });
    mkdirSync(dirname(agentFile), { recursive: true });
    writeFileSync(agentFile, content);
    return content;
  }

  /**
   * Capture an agent write into the AgentView worktree. The agent writes
   * symbolized content (it only ever saw symbols); we persist it to the
   * AgentView. Call `syncToHuman` afterward to propagate to the HumanView.
   */
  captureAgentWrite(relPath: string, content: Buffer | string): void {
    const agentFile = join(this.agentViewPath, relPath);
    // FAIL-CLOSED (P5): writeFileSync follows links — a planted symlink would
    // route this write to wherever it points, outside the AgentView.
    if (isSymlink(agentFile)) {
      throw new Error(
        `fs-sync.captureAgentWrite: ${relPath} is a symbolic link — refusing to write through it (gap class 3)`,
      );
    }
    mkdirSync(dirname(agentFile), { recursive: true });
    writeFileSync(agentFile, content);
  }

  // ── Sync AgentView -> HumanView (two-stage commit) ─────────────────────────

  /**
   * Reconcile the AgentView worktree into the HumanView. Lifted two-stage commit
   * from adfi-filecommit-worktree.ts. Returns the synced file list.
   */
  async syncToHuman(prov: WriteProvenance): Promise<string[]> {
    const tracked = await this.syncTrackedToHuman(prov);
    const ignored = await this.syncIgnoredToHuman(prov);
    return [...tracked, ...ignored];
  }

  /** The tracked half of {@link syncToHuman}: the two-stage commit. */
  private async syncTrackedToHuman(prov: WriteProvenance): Promise<string[]> {
    const trustedPath = this.agentViewPath;
    const gitRoot = this.humanPath;
    const trustedCtx: GitCtx = { cwd: trustedPath };
    // The shadow substrate context — every "main branch" op below addresses
    // <state>/repo.git over the workspace, NEVER the user's own .git.
    const mainCtx = shadowCtx(this.layout);

    if (!isWorktreeInitialized(this.layout)) {
      try {
        // Re-materialize via the shared helper so this lazy path ALSO runs the
        // P5 symlink neutralization — a checkout here materializes tracked
        // symlinks just like initialize(), and skipping the neutralization
        // would reopen gap class 3 on exactly the secret the P5 change closed.
        this.materializeWorktree();
      } catch (initErr) {
        this.log.warn(`[fs-sync] late initWorktree failed: ${(initErr as Error).message}`);
        return [];
      }
    }

    // Ignored paths are syncIgnoredToHuman's and are never committed: the
    // worktree's `.gitignore` is a symbol, so every twin and every agent write
    // to an ignored path shows up here as a plain untracked file.
    const all = getChangedFiles(trustedCtx);
    const kept = new Set(this.withoutIgnored(all.map((f) => f.path)));
    const changed = all.filter((f) => kept.has(f.path));
    if (changed.length === 0) return [];

    acquireLock(this.layout);
    try {
      const filePaths = changed.map((f) => f.path);

      // 0. Re-symbolize any tainted-raw AgentView file (design §4.2 step 2):
      //    a tainted child may have written raw bytes directly into AgentView.
      //    Symbolize them IN PLACE so the [MDU-TRUSTED] commit captures the
      //    symbol, never raw. Fail-closed: a arbiter error → symbolize.
      for (const filePath of filePaths) {
        const agentFilePath = join(trustedPath, filePath);
        if (!existsSync(agentFilePath)) continue; // deletion — nothing to symbolize
        // An agent-created symlink: never read (its TARGET's bytes) or write
        // (through it) here — step 2 below refuses to sync it at all (P5).
        if (isSymlink(agentFilePath)) continue;
        const buf = readFileSync(agentFilePath);
        if (buf.subarray(0, 8192).includes(0)) continue; // binary
        const text = buf.toString("utf8");
        if (hasSymbols(text)) continue; // already symbolic
        let untrusted: boolean;
        try {
          const verdict = await this.arbiter.fileTrust({ path: join(gitRoot, filePath) });
          untrusted = verdict.untrusted;
        } catch (err) {
          this.log.warn(`[fs-sync] fileTrust failed for ${filePath} at sync: ${(err as Error).message} → fail-closed UNTRUSTED`);
          untrusted = true;
        }
        if (!untrusted) continue; // trusted raw (agent-authored) → leave as-is
        const { content } = await symbolizeContent(this.arbiter, buf, {
          tool: prov.toolName,
          origin: join(gitRoot, filePath),
          field: filePath,
          callId: prov.callId,
          sessionKey: prov.runId,
        });
        writeFileSync(agentFilePath, content);
      }

      // 1. Commit the AgentView snapshot on mdu-trusted.
      stageFiles(trustedCtx, filePaths);
      mduCommit(trustedCtx, {
        trusted: true,
        toolName: prov.toolName,
        callId: prov.callId,
        runId: prov.runId,
        files: filePaths,
      });

      // 2. Sync changed paths into the HumanView (R2 race guard). "Dirty" =
      // diverged from the SHADOW HEAD — the last state fs-sync recorded —
      // which survives the human committing in their own repo (§4 win).
      const syncedPaths = expandChangedPaths(trustedPath, filePaths);
      const mainDirty = new Set(getChangedFiles(mainCtx).map((f) => f.path));
      const safeSyncedPaths: string[] = [];
      const skippedPaths: string[] = [];

      for (const filePath of syncedPaths) {
        if (mainDirty.has(filePath)) {
          skippedPaths.push(filePath);
          writeConflictLog(this.layout, {
            race: "R2",
            source: "ViewSync.syncToHuman",
            target: filePath,
            reason: "HumanView has uncommitted edits; refusing to overwrite",
            extra: { toolName: prov.toolName, callId: prov.callId, runId: prov.runId },
          });
          this.log.warn(`[fs-sync] R2 race: skipping ${filePath} (HumanView dirty)`);
          continue;
        }

        const trustedFilePath = join(trustedPath, filePath);
        const mainFilePath = join(gitRoot, filePath);

        // P5 (gap class 3): symlinks never sync, in EITHER direction. Copying
        // an AgentView link would materialize its TARGET's bytes into the
        // HumanView (copyFileSync follows links); touching a HumanView link
        // (overwrite or `git rm`) would destroy/alias the human's own link.
        if (isSymlink(trustedFilePath) || isSymlink(mainFilePath)) {
          skippedPaths.push(filePath);
          writeConflictLog(this.layout, {
            race: "SYMLINK",
            source: "ViewSync.syncToHuman",
            target: filePath,
            reason: "path is a symbolic link in one of the views; refusing to sync through it",
            extra: { toolName: prov.toolName, callId: prov.callId, runId: prov.runId },
          });
          this.log.warn(`[fs-sync] SYMLINK: skipping ${filePath} (refusing to sync a symbolic link)`);
          continue;
        }

        if (!existsSync(trustedFilePath)) {
          gitExecSync(["rm", "-f", "--ignore-unmatch", "--", filePath], mainCtx);
          safeSyncedPaths.push(filePath);
          continue;
        }

        const mainDir = dirname(mainFilePath);
        if (!existsSync(mainDir)) mkdirSync(mainDir, { recursive: true });
        copyFileSync(trustedFilePath, mainFilePath);
        safeSyncedPaths.push(filePath);
      }

      if (safeSyncedPaths.length === 0) {
        this.log.warn(
          `[fs-sync] all ${syncedPaths.length} path(s) skipped (R2 race); mdu-trusted moved, HumanView untouched`,
        );
        return [];
      }

      // 3. Commit the trusted twin on the shadow main line (blame parent of U).
      stageFiles(mainCtx, safeSyncedPaths);
      mduCommit(mainCtx, {
        trusted: true,
        toolName: prov.toolName,
        callId: prov.callId,
        runId: prov.runId,
        files: filePaths,
      });

      // 4. Desymbolize synced files in the HumanView (via the arbiter).
      for (const filePath of safeSyncedPaths) {
        const mainFilePath = join(gitRoot, filePath);
        if (!existsSync(mainFilePath)) continue;
        if (isSymlink(mainFilePath)) continue; // defensive: step 2 never syncs links
        const raw = readFileSync(mainFilePath);
        const resolved = await desymbolizeContent(this.arbiter, raw);
        if (!resolved.equals(raw)) writeFileSync(mainFilePath, resolved);
      }

      // 5. Commit the raw/untrusted version on the shadow main line.
      const mainChanged = getChangedFiles(mainCtx);
      if (mainChanged.length > 0) stageFiles(mainCtx, safeSyncedPaths);
      mduCommit(mainCtx, {
        trusted: false,
        toolName: prov.toolName,
        callId: prov.callId,
        runId: prov.runId,
        files: filePaths,
      });

      if (this.auditWrite) {
        this.auditWrite({
          hook: "view_sync_to_human",
          toolName: prov.toolName,
          callId: prov.callId,
          runId: prov.runId,
          trustedFiles: filePaths,
          syncedFiles: safeSyncedPaths,
          skippedDirtyFiles: skippedPaths,
        });
      }

      this.log.info(
        `[fs-sync] synced ${safeSyncedPaths.length} file(s) AgentView -> HumanView (T+U committed)`,
      );
      return safeSyncedPaths;
    } finally {
      releaseLock(this.layout);
    }
  }

  // ── Human-edit reconciliation + revert (delegate to lifted modules) ─────────

  /**
   * Detect + reconcile human edits in the HumanView, re-symbolizing edited
   * regions of untrusted blocks via the line map + symbol splitting. Triggered
   * before an agent FS action (the design's `before_tool_call` analog).
   */
  async reconcileHumanEdits(): Promise<ReconcileResult | null> {
    const result = await reconcileHumanEdits({
      layout: this.layout,
      arbiter: this.arbiter,
      log: this.log,
      auditWrite: this.auditWrite,
      sessionKey: this.sessionKey,
    });
    // Ignored files have no history to blame: a changed one is re-minted
    // whole, a new one seeded, a deleted one's twin removed.
    if (this.isInitialized()) await this.syncIgnoredFromHuman();
    return result;
  }

  // ── Ignored files (fs-sync.md §3.4.1) ───────────────────────────

  /** The paths that currently have an ignored-file twin (manifest keys). */
  private ignoredPaths(): Set<string> {
    if (this.ignoredLimits === null) return new Set();
    return new Set(Object.keys(loadIgnoredManifest(this.layout.ignoredManifestPath).entries));
  }

  /** Drop from a tracked commit list every path the ignored-file handling
   *  owns: the manifest's twins and anything the HumanView's rules ignore
   *  (an agent write to `.env`, `notes/x.md`, `node_modules/…`). Off when
   *  inclusion is off (the pre-2026-09-28 behavior: such writes took the
   *  tracked two-stage commit). */
  private withoutIgnored(paths: string[]): string[] {
    if (this.ignoredLimits === null || paths.length === 0) return paths;
    const twins = this.ignoredPaths();
    const ruled = humanIgnoredSet(shadowCtx(this.layout), paths);
    return paths.filter((p) => !twins.has(p) && !ruled.has(p));
  }

  /** What the last ignored-file pass did, or null before the first one. */
  ignoredStatus(): IgnoredStatus | null {
    return this.lastIgnored;
  }

  /**
   * HumanView -> AgentView for the `.gitignore`d files: every listed file gets
   * a WHOLE-FILE symbolized twin at its path in the worktree, minted through
   * the arbiter (level from the path's label or the catalog), never raw bytes.
   *
   * A registered secret (a `.env`) gets the whole-file symbol too, NOT the
   * arbiter's structured twin: that twin keeps the file's non-secret bytes
   * (keys, comments) raw, which is right with the integrity axis OFF (secrets
   * mode, no AgentView) but would put untrusted HumanView text in front of
   * the model here, where integrity is ON. A tracked `.env` is seeded the same
   * way.
   *
   * Fast path: a twin whose HumanView bytes and twin bytes both match the
   * manifest, whose tokens still resolve and whose level is still current is
   * kept (no mint). A twin the AGENT changed since (agentSha differs) is left
   * for syncIgnoredToHuman; if the human changed the same file too, the
   * agent's version stays in the AgentView and the conflict is logged (R1).
   * FAILS CLOSED: a mint failure throws before that file is written.
   */
  async syncIgnoredFromHuman(): Promise<IgnoredStatus> {
    if (this.ignoredLimits === null) {
      return (this.lastIgnored = { enabled: false, included: 0, minted: 0, reused: 0, removed: 0, skipped: [] });
    }
    const limits = this.ignoredLimits;
    const av = this.agentViewPath;
    acquireLock(this.layout);
    try {
      const manifest = loadIgnoredManifest(this.layout.ignoredManifestPath);
      const listing = listIgnoredFiles(shadowCtx(this.layout), this.humanPath, limits);
      const skipped: IgnoredSkip[] = [...listing.skipped];
      const present = new Set<string>();
      let minted = 0;
      let reused = 0;
      let removed = 0;

      try {
        for (const { rel } of listing.files) {
          const human = join(this.humanPath, rel);
          const agent = join(av, rel);
          if (pathCrossesSymlink(this.humanPath, rel) || pathCrossesSymlink(av, rel)) {
            skipped.push({ rel, reason: "symlink" });
            continue;
          }
          let raw: Buffer;
          try {
            raw = readFileSync(human);
          } catch {
            skipped.push({ rel, reason: "unreadable" });
            continue;
          }
          if (raw.subarray(0, 8192).includes(0)) {
            skipped.push({ rel, reason: "binary" });
            continue;
          }
          present.add(rel);
          const humanSha = sha256(raw);
          const entry = manifest.entries[rel];
          const agentBuf = existsSync(agent) ? readFileSync(agent) : null;
          const agentSha = agentBuf === null ? null : sha256(agentBuf);

          if (entry && agentSha !== null && agentSha !== entry.agentSha) {
            // The agent wrote this twin and it is not written back yet.
            if (humanSha !== entry.humanSha) {
              writeConflictLog(this.layout, {
                race: "R1",
                source: "ViewSync.syncIgnoredFromHuman",
                target: rel,
                reason:
                  "ignored file changed in both views; the AgentView keeps the agent's version, the HumanView keeps the human's",
              });
              this.log.warn(`[fs-sync] R1: ${rel} (ignored) changed in both views; not re-seeded`);
            }
            continue;
          }
          if (!entry && agentBuf !== null) {
            // A file fs-sync has no record of already sits there: a twin whose
            // manifest was lost (adopt it when its one token stands for exactly
            // this HumanView file), or an agent write not synced yet (keep it;
            // the sync decides). Never overwritten blind.
            const tokens = extractSymbols(agentBuf.toString("utf8"));
            const whole =
              tokens.length === 1 && agentBuf.toString("utf8").trim() === tokens[0]
                ? await this.arbiter.resolve(tokens[0]!).catch(() => null)
                : null;
            if (whole === raw.toString("utf8") && (await this.twinLevelCurrent(tokens, human))) {
              manifest.entries[rel] = { humanSha, agentSha: agentSha! };
              reused++;
              continue;
            }
            writeConflictLog(this.layout, {
              race: "R1",
              source: "ViewSync.syncIgnoredFromHuman",
              target: rel,
              reason: "an unrecorded file already sits at this ignored path in the AgentView; it is kept, not re-seeded",
            });
            this.log.warn(`[fs-sync] R1: ${rel} (ignored) already present in the AgentView; not re-seeded`);
            continue;
          }
          if (entry && agentBuf !== null && entry.humanSha === humanSha && agentSha === entry.agentSha) {
            if (raw.toString("utf8").trim() === "") {
              reused++; // nothing to symbolize: the twin is the (blank) file
              continue;
            }
            const tokens = await this.twinTokensResolve(agent);
            if (tokens && (await this.twinLevelCurrent(tokens, human))) {
              reused++;
              continue;
            }
          }
          const { content } = await symbolizeContent(this.arbiter, raw, {
            tool: "Read",
            origin: human,
            field: rel,
            sessionKey: this.sessionKey,
            force: true,
          });
          mkdirSync(dirname(agent), { recursive: true });
          if (pathCrossesSymlink(av, rel)) {
            // Re-checked after mkdir: a link planted in between is never written through.
            skipped.push({ rel, reason: "symlink" });
            present.delete(rel);
            continue;
          }
          writeFileSync(agent, content);
          manifest.entries[rel] = { humanSha, agentSha: sha256(content) };
          minted++;
        }
      } finally {
        // Persist what was minted even when a later mint threw (fail-closed:
        // the throw propagates, the twins already written are symbolic).
        saveIgnoredManifest(this.layout.ignoredManifestPath, manifest);
      }

      // Entries no longer listed (deleted, un-ignored, over a cap now): remove
      // the twin fs-sync wrote, never one the agent changed since.
      for (const [rel, entry] of Object.entries(manifest.entries)) {
        if (present.has(rel)) continue;
        const agent = join(av, rel);
        if (!pathCrossesSymlink(av, rel) && existsSync(agent) && sha256(readFileSync(agent)) === entry.agentSha) {
          rmSync(agent, { force: true });
          removed++;
        }
        delete manifest.entries[rel];
      }

      manifest.skipped = skipped;
      saveIgnoredManifest(this.layout.ignoredManifestPath, manifest);
      if (minted > 0 || removed > 0) {
        this.log.info(
          `[fs-sync] ignored files: ${minted} symbolized, ${reused} current, ${removed} removed from the AgentView`,
        );
      }
      if (skipped.length > 0) {
        const counts = Object.entries(skipCounts(skipped))
          .map(([k, v]) => `${v} ${k}`)
          .join(", ");
        this.log.warn(
          `[fs-sync] ignored files NOT in the AgentView: ${counts} (${skipped
            .slice(0, 5)
            .map((x) => x.rel)
            .join(", ")}${skipped.length > 5 ? ", ..." : ""}); the full list is in ${this.layout.ignoredManifestPath}`,
        );
      }
      return (this.lastIgnored = {
        enabled: true,
        included: Object.keys(manifest.entries).length,
        minted,
        reused,
        removed,
        skipped,
      });
    } finally {
      releaseLock(this.layout);
    }
  }

  /**
   * AgentView -> HumanView for the ignored paths: an agent write (a twin whose
   * bytes differ from the manifest, or a new ignored file) is re-symbolized
   * first when it is untrusted raw text (step 0 of the tracked sync,
   * fail-closed UNTRUSTED), then desymbolized into the HumanView. R2 guard:
   * the HumanView file must still hold the bytes the manifest recorded (absent
   * for a new file), else the write is refused and logged. A twin the agent
   * deleted is deleted in the HumanView under the same guard. There is no T/U
   * commit pair for these paths, so `revert` does not cover them.
   */
  private async syncIgnoredToHuman(prov: WriteProvenance): Promise<string[]> {
    if (this.ignoredLimits === null || !this.isInitialized()) return [];
    const av = this.agentViewPath;
    const gitRoot = this.humanPath;
    acquireLock(this.layout);
    try {
      const manifest = loadIgnoredManifest(this.layout.ignoredManifestPath);
      // Judged by the HUMANVIEW's rules: the worktree's own `.gitignore` is a
      // symbol and ignores nothing (listAgentViewIgnored).
      const listing = listAgentViewIgnored(av, shadowCtx(this.layout), this.ignoredLimits);
      const synced: string[] = [];
      const seen = new Set<string>();
      const logged = new Set(manifest.notSynced);
      const extra = { toolName: prov.toolName, callId: prov.callId, runId: prov.runId };
      const r2 = (rel: string, reason: string): void => {
        writeConflictLog(this.layout, { race: "R2", source: "ViewSync.syncToHuman", target: rel, reason, extra });
        this.log.warn(`[fs-sync] R2 race: skipping ${rel} (ignored; ${reason})`);
      };

      for (const { rel } of listing.files) {
        seen.add(rel);
        const agent = join(av, rel);
        const human = join(gitRoot, rel);
        if (pathCrossesSymlink(av, rel) || pathCrossesSymlink(gitRoot, rel)) {
          writeConflictLog(this.layout, {
            race: "SYMLINK",
            source: "ViewSync.syncToHuman",
            target: rel,
            reason: "ignored path crosses a symbolic link in one of the views; refusing to sync through it",
            extra,
          });
          continue;
        }
        let buf: Buffer = readFileSync(agent);
        const entry = manifest.entries[rel];
        if (entry && sha256(buf) === entry.agentSha) continue; // unchanged twin

        // Step 0: untrusted raw text becomes a symbol in place first.
        const binary = buf.subarray(0, 8192).includes(0);
        const text = buf.toString("utf8");
        if (!binary && !hasSymbols(text) && text.trim() !== "") {
          let untrusted: boolean;
          try {
            untrusted = (await this.arbiter.fileTrust({ path: human })).untrusted;
          } catch (err) {
            this.log.warn(
              `[fs-sync] fileTrust failed for ${rel} at sync: ${(err as Error).message} → fail-closed UNTRUSTED`,
            );
            untrusted = true;
          }
          if (untrusted) {
            const { content } = await symbolizeContent(this.arbiter, buf, {
              tool: prov.toolName,
              origin: human,
              field: rel,
              callId: prov.callId,
              sessionKey: prov.runId,
            });
            writeFileSync(agent, content);
            buf = content;
          }
        }

        // R2: the HumanView must still hold what the manifest recorded.
        const humanNow = existsSync(human) ? sha256(readFileSync(human)) : null;
        const expected = entry ? entry.humanSha : null;
        if (humanNow !== expected) {
          r2(rel, expected === null ? "the HumanView already has a file there" : "the HumanView file changed since the twin was made");
          continue;
        }
        const resolved = binary ? buf : await desymbolizeContent(this.arbiter, buf);
        mkdirSync(dirname(human), { recursive: true });
        if (pathCrossesSymlink(gitRoot, rel)) continue;
        writeFileSync(human, resolved);
        manifest.entries[rel] = { humanSha: sha256(resolved), agentSha: sha256(buf) };
        synced.push(rel);
      }

      // Agent writes fs-sync leaves in the AgentView: said once per path.
      for (const s of listing.skipped) {
        if (manifest.entries[s.rel] || logged.has(s.rel)) continue;
        logged.add(s.rel);
        writeConflictLog(this.layout, {
          race: "IGNORED-NOT-SYNCED",
          source: "ViewSync.syncToHuman",
          target: s.rel,
          reason: `an ignored path in the AgentView is not written back to the HumanView (${s.reason})`,
          extra,
        });
        this.log.warn(`[fs-sync] IGNORED-NOT-SYNCED: ${s.rel} (${s.reason})`);
      }

      // Twins the agent deleted.
      for (const [rel, entry] of Object.entries(manifest.entries)) {
        if (seen.has(rel)) continue;
        if (existsSync(join(av, rel))) continue; // still there, just not listed now (a cap)
        const human = join(gitRoot, rel);
        if (pathCrossesSymlink(gitRoot, rel)) continue;
        const humanNow = existsSync(human) ? sha256(readFileSync(human)) : null;
        if (humanNow !== null && humanNow !== entry.humanSha) {
          r2(rel, "deleted in the AgentView but changed in the HumanView");
        } else if (humanNow !== null) {
          rmSync(human, { force: true });
          synced.push(rel);
        }
        delete manifest.entries[rel];
      }

      manifest.notSynced = [...logged];
      saveIgnoredManifest(this.layout.ignoredManifestPath, manifest);
      if (synced.length > 0) {
        this.auditWrite?.({ hook: "view_sync_ignored_to_human", ...extra, syncedFiles: synced });
        this.log.info(`[fs-sync] synced ${synced.length} ignored file(s) AgentView -> HumanView (outside git, no commit)`);
      }
      return synced;
    } finally {
      releaseLock(this.layout);
    }
  }

  /** True if any HumanView file is currently un-symbolized untrusted content
   * appearing in the AgentView — i.e. a security-invariant violation. Returns
   * the offending relative paths (empty == invariant holds). Audit helper. */
  agentViewLeaks(): string[] {
    const trustedPath = this.agentViewPath;
    // Tracked files AND the ignored-file twins (a twin is a plain file outside
    // git, so ls-files alone would never look at it).
    const files = [...new Set([...getTrackedFiles({ cwd: trustedPath }), ...this.ignoredPaths()])];
    const leaks: string[] = [];
    for (const rel of files) {
      const agent = join(trustedPath, rel);
      const human = join(this.humanPath, rel);
      if (!existsSync(agent) || !existsSync(human)) continue;
      if (isSymlink(agent) || isSymlink(human)) continue; // never read through links
      const agentBuf = readFileSync(agent);
      if (agentBuf.subarray(0, 8192).includes(0)) continue; // binary
      const humanBuf = readFileSync(human);
      if (humanBuf.subarray(0, 8192).includes(0)) continue;
      const agentText = agentBuf.toString("utf8");
      const humanText = humanBuf.toString("utf8");
      // If the views are byte-identical AND the human content carries no
      // symbols, the AgentView holds raw (possibly untrusted) content. That is
      // only safe when the content is trusted (human/agent-authored). We cannot
      // prove trust here, so we report identity-without-symbols as a candidate
      // leak for the caller / e2e oracle to assert against a known payload.
      if (agentText === humanText && !hasSymbols(agentText)) leaks.push(rel);
    }
    return leaks;
  }
}
