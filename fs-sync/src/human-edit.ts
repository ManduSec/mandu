/**
 * human-edit — reconcile manual human edits in the HumanView via git blame +
 * line-map symbol splitting, then re-symbolize the changed regions.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/dualview-human-edit.ts
 *   Purpose: detect uncommitted HumanView edits, build the trusted<->human line
 *   map, classify changed lines (trusted edit vs trust promotion), split
 *   multi-line symbols around the edited region, rewrite the AgentView file, and
 *   commit both views as [ADFI-HUMAN]. Design: docs/adfi-reference/design/
 *   human-edit-policy.md.
 *
 * Adaptation for Mandu (OpenClaw coupling stripped + arbiter routing):
 *   - The reference loaded the symbol table in-process (loadSymbolMap) and
 *     mutated it (obsoleteSymbol / allocateDerivedSymbol). The arbiter is the
 *     single symbol owner in Mandu, so:
 *       * symbol VALUE lookups (line-map building, edit detection) go through
 *         arbiter.resolve(symbol);
 *       * derived symbols for untouched split ranges are minted via
 *         arbiter.symbolize({...}) (the arbiter allocates + persists). The parent
 *         symbol is simply no longer referenced in the AgentView; the arbiter's
 *         own obsolescence column is its concern, not ours — fs-sync never
 *         writes the DB.
 *   - On-demand/fixed dual-pathing collapsed: Mandu fs-sync drives ONE
 *     ViewLayout (the seccomp openat rewrite targets a specific tracked
 *     root). The fixed-vs-ondemand `buildGitContext` branch is gone.
 *   - `git blame` is now used to FIND changed lines (the design names blame
 *     explicitly); the resolved-value comparison from the reference is retained
 *     as the symbol-range edit detector.
 *   - The R1 race re-hash guard is preserved.
 */

import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import type { SymbolArbiter } from "./arbiter-client.js";
import { hasSymbols, SYMBOL_PATTERN } from "./arbiter-client.js";
import { emitBirth } from "./events.js";
import { symbolizeContent } from "./symbolize.js";
import {
  acquireLock,
  mduHumanCommit,
  blameFile,
  type ChangedFile,
  getChangedFiles,
  getWorktreePath,
  type GitCtx,
  isSymlink,
  releaseLock,
  shadowCtx,
  stageFiles,
  writeConflictLog,
} from "./git.js";
import type { ViewLayout } from "./layout.js";

interface Logger {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
}

function hashBuffer(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

// ── Line map ──────────────────────────────────────────────────────────────

/** A segment in the AgentView (trusted) file. */
export interface LineMapSegment {
  type: "literal" | "symbol";
  symName?: string;
  /** AgentView line number (1-indexed). */
  trustedLine: number;
  /** HumanView line range start (1-indexed, inclusive). */
  humanStart: number;
  /** HumanView line range end (1-indexed, inclusive). */
  humanEnd: number;
}

/**
 * Build a line-number map between the AgentView (trusted) file and the
 * HumanView. A symbol occupies one AgentView line; its resolved value may span
 * N HumanView lines. Resolution goes through the arbiter.
 */
export async function buildLineMap(
  arbiter: SymbolArbiter,
  trustedContent: string,
): Promise<LineMapSegment[]> {
  const trustedLines = trustedContent.split("\n");
  const segments: LineMapSegment[] = [];
  let humanLine = 1;

  for (let i = 0; i < trustedLines.length; i++) {
    const line = trustedLines[i]!;
    SYMBOL_PATTERN.lastIndex = 0;
    const match = SYMBOL_PATTERN.exec(line);

    // Line is purely a symbol (modulo surrounding whitespace).
    if (match && line.trim() === match[0]) {
      const symName = match[0];
      const value = await arbiter.resolve(symName);
      if (value != null) {
        const valueLineCount = value.split("\n").length;
        segments.push({
          type: "symbol",
          symName,
          trustedLine: i + 1,
          humanStart: humanLine,
          humanEnd: humanLine + valueLineCount - 1,
        });
        humanLine += valueLineCount;
        continue;
      }
    }

    segments.push({
      type: "literal",
      trustedLine: i + 1,
      humanStart: humanLine,
      humanEnd: humanLine,
    });
    humanLine += 1;
  }

  return segments;
}

// ── Symbol splitting ────────────────────────────────────────────────────────

export interface SplitPiece {
  type: "symbol" | "literal";
  /** For type=symbol: the newly minted derived symbol name. */
  symName?: string;
  /** For type=literal: the human-authored text lines. */
  lines?: string[];
}

export interface EditRange {
  /** 0-indexed start line within the symbol's value. */
  start: number;
  /** 0-indexed end line (inclusive) within the symbol's value. */
  end: number;
  /** The human's replacement lines for this range. */
  humanLines: string[];
}

const SPLIT_FIELD_SEGMENT = "__mdu_split";

function appendSplitFieldSegment(field: string | undefined, splitIndex: number): string {
  const suffix = `${SPLIT_FIELD_SEGMENT}[${splitIndex}]`;
  return field ? `${field}.${suffix}` : suffix;
}

/** Pull the field-path tail off a symbol name (after the `[hash]`). */
function fieldPathOf(symName: string): string | undefined {
  const m = symName.match(/^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]\.?(.*)$/);
  return m && m[1] ? m[1] : undefined;
}

async function originalFieldOf(arbiter: SymbolArbiter, symName: string): Promise<string | undefined> {
  // The arbiter owns naming: never decode a canonical suffix into provenance.
  // null explicitly means no field; an omitted property supports older servers.
  const provenance = await arbiter.symbolProvenance?.(symName);
  if (provenance?.field !== undefined) return provenance.field ?? undefined;
  const legacyField = fieldPathOf(symName);
  if (legacyField?.startsWith("__mdu_field_")) {
    throw new Error("Cannot split encoded symbol without original field provenance");
  }
  return legacyField;
}

/** Pull the tool segment off a symbol name. */
function toolOf(symName: string): string {
  const m = symName.match(/^\$MDU:([a-zA-Z_][a-zA-Z0-9_]*)\[/);
  return m ? m[1]! : "human_split";
}

/**
 * Split a symbol around human-edited ranges. Untouched portions become NEW
 * derived symbols minted by the arbiter (their `field` carries the
 * `.__mdu_split[n]` provenance segment, mirroring the reference). The original
 * symbol is dropped from the AgentView text (the arbiter owns obsolescence).
 */
export async function splitSymbol(
  arbiter: SymbolArbiter,
  symName: string,
  value: string,
  editRanges: EditRange[],
  ctx: { origin?: string; sessionKey?: string; callId?: string } = {},
): Promise<SplitPiece[]> {
  const valueLines = value.split("\n");
  const pieces: SplitPiece[] = [];
  let cursor = 0;
  let derivedIndex = 0;
  const tool = toolOf(symName);
  const parentField = await originalFieldOf(arbiter, symName);

  // Derived-mint lineage (symbol-lineage.md G2): each untouched piece names
  // its parent symbol and its end-exclusive `start:end` span within the
  // parent value — the same format allocateDerivedSymbol stores — and emits
  // its birth event (G1, best-effort) like every other fs-sync mint.
  const mintDerived = async (lines: string[], lineStart: number, lineEnd: number): Promise<string> => {
    const field = appendSplitFieldSegment(parentField, derivedIndex++);
    const lineRange = `${lineStart}:${lineEnd}`;
    const value = lines.join("\n");
    const sym = await arbiter.symbolize({
      tool,
      value,
      field,
      origin: ctx.origin,
      sessionKey: ctx.sessionKey,
      callId: ctx.callId,
      derivedFrom: symName,
      lineRange,
    });
    await emitBirth(arbiter, {
      sessionKey: ctx.sessionKey,
      symbol: sym,
      original: value,
      tool,
      field,
      origin: ctx.origin,
      callId: ctx.callId,
      derivedFrom: symName,
      lineRange,
    });
    return sym;
  };

  const sorted = [...editRanges].sort((a, b) => a.start - b.start);

  for (const edit of sorted) {
    if (cursor < edit.start) {
      const sym = await mintDerived(valueLines.slice(cursor, edit.start), cursor, edit.start);
      pieces.push({ type: "symbol", symName: sym });
    }
    pieces.push({ type: "literal", lines: edit.humanLines });
    cursor = edit.end + 1;
  }

  if (cursor < valueLines.length) {
    const sym = await mintDerived(valueLines.slice(cursor), cursor, valueLines.length);
    pieces.push({ type: "symbol", symName: sym });
  }

  return pieces;
}

// ── Reconciliation ──────────────────────────────────────────────────────────

export interface ReconcileResult {
  files: string[];
  /** Symbols obsoleted (split or fully promoted) by this human edit. */
  promotedSymbols: string[];
  committed: boolean;
}

export interface ReconcileOptions {
  layout: ViewLayout;
  arbiter: SymbolArbiter;
  log?: Logger;
  auditWrite?: (entry: object) => void;
  /** Session attribution for symbols minted when a changed file turns out to
   *  be untrusted-by-origin (see reconcileChangedFile). */
  sessionKey?: string;
}

/**
 * Detect and reconcile human edits in the HumanView. Returns null if no human
 * edits are detected.
 */
export async function reconcileHumanEdits(
  opts: ReconcileOptions,
): Promise<ReconcileResult | null> {
  const { layout, arbiter, log, auditWrite } = opts;
  const humanPath = layout.humanPath;
  const trustedPath = getWorktreePath(layout);
  // "Uncommitted HumanView change" = diverged from the SHADOW HEAD (the last
  // state fs-sync recorded) — so a human edit stays detectable even after the
  // human commits it in their OWN repo (fs-sync.md §3.4).
  const humanGit: GitCtx = shadowCtx(layout);
  const trustedGit: GitCtx = { cwd: trustedPath };

  const changed = getChangedFiles(humanGit);
  if (changed.length === 0) return null;
  if (!existsSync(trustedPath)) return null;

  if (log) log.info(`[fs-sync/human-edit] ${changed.length} uncommitted HumanView change(s)`);

  acquireLock(layout);
  try {
    const reconciledFiles: string[] = [];
    const allPromoted: string[] = [];
    const preHashes = new Map<string, string | null>();

    // BOTH SIDES CHANGED (fs-sync.md §2.5a): a file whose AgentView twin
    // carries uncommitted AGENT work is not reconciled — rewriting the twin
    // from the human's text would silently discard what the agent wrote. It
    // stays an R2 refusal on the sync side (HumanView dirty ⇒ never
    // overwritten), is logged, and is picked up once the agent's side commits.
    const agentDirty = new Set(getChangedFiles(trustedGit).map((f) => f.path));

    for (const file of changed) {
      if (agentDirty.has(file.path)) {
        writeConflictLog(layout, {
          race: "R2",
          source: "reconcileHumanEdits",
          target: file.path,
          reason: "both views changed: the AgentView twin has uncommitted agent work — human edit not reconciled yet",
        });
        log?.warn(`[fs-sync/human-edit] both sides changed: leaving ${file.path} for the next pass`);
        continue;
      }
      const result = await reconcileChangedFile(arbiter, humanPath, humanGit, trustedPath, file, log, opts.sessionKey);
      if (!result) continue;
      reconciledFiles.push(file.path);
      preHashes.set(file.path, result.preHash);
      allPromoted.push(...result.promoted);
    }

    // R1 race guard: re-hash every file we're about to stage; drop any whose
    // on-disk content shifted during the reconcile window.
    const safeFiles: string[] = [];
    for (const path of reconciledFiles) {
      const expected = preHashes.get(path) ?? null;
      const onDisk = existsSync(join(humanPath, path))
        ? hashBuffer(readFileSync(join(humanPath, path)))
        : null;
      if (expected === onDisk) {
        safeFiles.push(path);
        continue;
      }
      writeConflictLog(layout, {
        race: "R1",
        source: "reconcileHumanEdits",
        target: path,
        reason: "HumanView content changed during reconcile window",
        extra: { expectedHash: expected, observedHash: onDisk },
      });
      if (log) {
        log.warn(
          `[fs-sync/human-edit] R1 race: dropping ${path} (pre=${expected ?? "absent"} post=${onDisk ?? "absent"})`,
        );
      }
    }

    if (safeFiles.length === 0) return null;

    // Commit HumanView as [MDU-HUMAN] — on the SHADOW main line.
    stageFiles(humanGit, safeFiles);
    mduHumanCommit(humanGit, { files: safeFiles, promotedSymbols: allPromoted });

    // Commit AgentView worktree.
    const trustedChanged = getChangedFiles(trustedGit);
    if (trustedChanged.length > 0) {
      stageFiles(trustedGit, trustedChanged.map((f) => f.path));
      mduHumanCommit(trustedGit, { files: safeFiles, promotedSymbols: allPromoted });
    }

    if (log) {
      log.info(
        `[fs-sync/human-edit] Reconciled ${safeFiles.length} file(s), promoted ${allPromoted.length} symbol(s)`,
      );
    }
    if (auditWrite) {
      auditWrite({ hook: "human_edit_reconcile", files: safeFiles, promotedSymbols: allPromoted });
    }

    return { files: safeFiles, promotedSymbols: allPromoted, committed: true };
  } finally {
    releaseLock(layout);
  }
}

interface PerFileResult {
  preHash: string | null;
  promoted: string[];
}

async function reconcileChangedFile(
  arbiter: SymbolArbiter,
  humanPath: string,
  humanGit: GitCtx,
  trustedPath: string,
  file: ChangedFile,
  log?: Logger,
  sessionKey?: string,
): Promise<PerFileResult | null> {
  if (file.status === "D") {
    const trustedFile = join(trustedPath, file.path);
    if (existsSync(trustedFile)) {
      // Mirror deletion into the AgentView worktree.
      const { gitExecSync } = await import("./git.js");
      gitExecSync(["rm", "-f", "--", file.path], { cwd: trustedPath });
      return { preHash: null, promoted: [] };
    }
    return null;
  }

  const humanFilePath = join(humanPath, file.path);
  const trustedFilePath = join(trustedPath, file.path);
  if (!existsSync(humanFilePath)) return null;
  // P5 (gap class 3): a symlink here would make readFileSync serve its
  // TARGET's bytes — which would then land in the AgentView as "trusted,
  // human-authored" RAW text below, a symbolization bypass by aliasing. And a
  // trusted-side link must never be written THROUGH. Refuse both.
  if (isSymlink(humanFilePath) || isSymlink(trustedFilePath)) {
    log?.warn(`[fs-sync] SYMLINK: skipping ${file.path} in human-edit reconcile (refusing to follow)`);
    return null;
  }
  if (statSync(humanFilePath).isDirectory()) return null;

  const humanContent = readFileSync(humanFilePath);
  const preHash = hashBuffer(humanContent);

  // WHO CHANGED IT? (2026-09-21, fs-sync.md §2.5a.) "Dirty against the
  // shadow HEAD" means "not written by fs-sync" — which is the human, but ALSO
  // any non-agent program with the HumanView as its filesystem (a HumanShell
  // `curl -o`, a `git pull`). Under the reference's hook-time trigger that was
  // an accepted blur; under a CONTINUOUS trigger it would import fetched bytes
  // into the AgentView as trusted, human-authored literal text. So the
  // provenance registry is asked first, exactly as readForAgent / syncToHuman
  // step 0 do: untrusted-by-origin (or an arbiter that cannot answer —
  // fail-closed) ⇒ the file is symbolized WHOLE, like the seed would, and no
  // byte of it is promoted.
  let untrusted: boolean;
  try {
    // Path-keyed, like the two sibling call sites in view-sync.ts.
    untrusted = (await arbiter.fileTrust({ path: humanFilePath })).untrusted;
  } catch (err) {
    log?.warn(`[fs-sync/human-edit] fileTrust failed for ${file.path}: ${(err as Error).message} → fail-closed UNTRUSTED`);
    untrusted = true;
  }
  if (untrusted) {
    const { content } = await symbolizeContent(arbiter, humanContent, {
      tool: "Read",
      origin: humanFilePath,
      field: file.path,
      sessionKey,
    });
    mkdirSync(dirname(trustedFilePath), { recursive: true });
    writeFileSync(trustedFilePath, content);
    log?.info(`[fs-sync/human-edit] ${file.path} is untrusted-by-origin: symbolized whole, nothing promoted`);
    return { preHash, promoted: [] };
  }

  // New file, or no AgentView twin yet: copy as-is (trusted, human-authored).
  if (file.status === "??" || file.status === "A" || !existsSync(trustedFilePath)) {
    mkdirSync(dirname(trustedFilePath), { recursive: true });
    writeFileSync(trustedFilePath, humanContent);
    return { preHash, promoted: [] };
  }

  // Skip binary files.
  if (humanContent.subarray(0, 8192).includes(0)) return null;

  const trustedContent = readFileSync(trustedFilePath, "utf8");

  // AgentView twin has no symbols: literal-vs-literal, just copy the human text.
  if (!hasSymbols(trustedContent)) {
    writeFileSync(trustedFilePath, humanContent);
    return { preHash, promoted: [] };
  }

  const promoted = await reconcileFile(
    arbiter,
    trustedContent,
    humanContent.toString("utf8"),
    trustedFilePath,
    humanGit,
    file.path,
    log,
  );
  return { preHash, promoted };
}

/**
 * Reconcile a single file: build the line map, find which lines the human
 * changed (git blame: lines attributed to a non-Mandu / dirty commit), split or
 * promote the affected symbols, and rewrite the AgentView file.
 *
 * Returns the list of obsoleted (promoted) symbol names.
 */
async function reconcileFile(
  arbiter: SymbolArbiter,
  trustedContent: string,
  humanContent: string,
  trustedFilePath: string,
  humanGit: GitCtx,
  relPath: string,
  log?: Logger,
): Promise<string[]> {
  const segments = await buildLineMap(arbiter, trustedContent);
  const humanLines = humanContent.split("\n");
  const trustedLines = trustedContent.split("\n");
  const promoted: string[] = [];
  const newTrustedLines: string[] = [];

  // git blame attributes each final HumanView line to a commit. Lines whose
  // attributing commit is NOT a Mandu commit (or is the uncommitted/"Not
  // Committed Yet" working-tree state) were touched by the human. We compute
  // the set here for completeness/auditing; the actual edit detection below
  // compares against the symbol's resolved value, which is exact even when
  // blame is unavailable (untracked file). See human-edit-policy.md.
  const blame = blameFile(humanGit, relPath);
  const humanTouched = new Set<number>();
  for (const b of blame) {
    // "Not Committed Yet" is git's synthetic summary for uncommitted lines.
    if (b.summary === "Not Committed Yet" || b.commit === "0".repeat(40)) {
      humanTouched.add(b.line);
    }
  }

  for (const seg of segments) {
    if (seg.type === "literal") {
      const humanIdx = seg.humanStart - 1;
      newTrustedLines.push(
        humanIdx < humanLines.length ? humanLines[humanIdx]! : trustedLines[seg.trustedLine - 1]!,
      );
      continue;
    }

    const symName = seg.symName!;
    const resolved = await arbiter.resolve(symName);
    if (resolved == null) {
      // Unknown/obsoleted symbol — keep the line as-is.
      newTrustedLines.push(trustedLines[seg.trustedLine - 1]!);
      continue;
    }

    const resolvedLines = resolved.split("\n");
    const humanSlice = humanLines.slice(seg.humanStart - 1, seg.humanEnd);

    if (linesEqual(resolvedLines, humanSlice)) {
      // Unchanged untrusted block: keep the symbol.
      newTrustedLines.push(trustedLines[seg.trustedLine - 1]!);
      continue;
    }

    const editRanges = findEditRanges(resolvedLines, humanSlice);
    if (editRanges.length === 0) {
      newTrustedLines.push(trustedLines[seg.trustedLine - 1]!);
      continue;
    }

    const totalEdited = editRanges.reduce((sum, r) => sum + (r.end - r.start + 1), 0);
    if (totalEdited >= resolvedLines.length) {
      // Full promotion: replace the symbol with the human's literal lines.
      for (const line of humanSlice) newTrustedLines.push(line);
      promoted.push(symName);
      if (log) log.info(`[fs-sync/human-edit] Full promotion: ${symName}`);
      continue;
    }

    // Partial edit: split the symbol (mint derived symbols for untouched ranges).
    const pieces = await splitSymbol(arbiter, symName, resolved, editRanges);
    promoted.push(symName);
    for (const piece of pieces) {
      if (piece.type === "symbol") newTrustedLines.push(piece.symName!);
      else if (piece.lines) for (const line of piece.lines) newTrustedLines.push(line);
    }
    if (log) log.info(`[fs-sync/human-edit] Split ${symName} into ${pieces.length} piece(s)`);
  }

  writeFileSync(trustedFilePath, newTrustedLines.join("\n"));
  return promoted;
}

function linesEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Find edit ranges by comparing the original resolved lines to the human's
 * version. Returns 0-indexed ranges within the original value that differ.
 * Different line counts (insert/delete) → treat the whole block as edited.
 */
function findEditRanges(resolvedLines: string[], humanLines: string[]): EditRange[] {
  if (resolvedLines.length === humanLines.length) {
    return findEditRangesSameLength(resolvedLines, humanLines);
  }
  return [{ start: 0, end: resolvedLines.length - 1, humanLines: [...humanLines] }];
}

function findEditRangesSameLength(resolvedLines: string[], humanLines: string[]): EditRange[] {
  const ranges: EditRange[] = [];
  let rangeStart: number | null = null;
  for (let i = 0; i < resolvedLines.length; i++) {
    if (resolvedLines[i] !== humanLines[i]) {
      if (rangeStart === null) rangeStart = i;
    } else if (rangeStart !== null) {
      ranges.push({ start: rangeStart, end: i - 1, humanLines: humanLines.slice(rangeStart, i) });
      rangeStart = null;
    }
  }
  if (rangeStart !== null) {
    ranges.push({
      start: rangeStart,
      end: resolvedLines.length - 1,
      humanLines: humanLines.slice(rangeStart),
    });
  }
  return ranges;
}
