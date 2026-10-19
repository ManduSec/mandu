/**
 * fs-sync — public surface of the Mandu git-worktree dual-view sync (Track B,
 * userspace half). Re-exports the ViewSync orchestrator + the lifted primitives
 * the Rust fs-supervisor (Wave 4) and the arbiter integration will call.
 *
 * PROVENANCE: see per-module headers. The view-sync machinery is lifted from
 * adfi-openclaw (adfi-git / adfi-filecommit-* / adfi-human-edit / adfi-revert);
 * the arbiter-client + symbolize ingress are Mandu-new (the arbiter is the
 * single symbol owner, replacing adfi-openclaw's in-process symbol table).
 */

export {
  ViewSync,
  type ViewSyncOptions,
  type WriteProvenance,
  type Logger,
} from "./view-sync.js";

export {
  ViewLayout,
  defaultStateBase,
  canonicalWorkspacePath,
  workspaceIdFor,
  VIEW_SCHEMA_VERSION,
  type ViewWorkspaceMetadata,
} from "./layout.js";

export {
  type SymbolArbiter,
  type SymbolizeArgs,
  type RealArbiterClient,
  type StoredEventLike,
  type EventStreamHandle,
  type EventStreamArbiter,
  ArbiterClientAdapter,
  ArbiterEventStreamAdapter,
  hasSymbols,
  extractSymbols,
  SYMBOL_PATTERN,
  SYMBOL_PREFIX,
} from "./arbiter-client.js";

export {
  DEFAULT_IGNORED_DENY_DIRS,
  DEFAULT_IGNORED_LIMITS,
  applyIgnoredCaps,
  listIgnoredFiles,
  loadIgnoredManifest,
  ignoredLimitsFromEnv,
  ignoredInclusionEnabled,
  type IgnoredLimits,
  type IgnoredListing,
  type IgnoredManifest,
  type IgnoredSkip,
  type IgnoredSkipReason,
} from "./ignored.js";

export {
  EagerSync,
  type EagerSyncTarget,
  type EagerSyncOptions,
} from "./eager-sync.js";

export {
  symbolizeContent,
  desymbolizeContent,
  isBinary,
  type SymbolizeContentOptions,
} from "./symbolize.js";

export {
  reconcileHumanEdits,
  buildLineMap,
  splitSymbol,
  type ReconcileResult,
  type ReconcileOptions,
  type LineMapSegment,
  type SplitPiece,
  type EditRange,
} from "./human-edit.js";

export {
  listWriteCycles,
  findWriteCycleByNumber,
  planRevert,
  revertToWriteCycle,
  type WriteCycle,
  type RevertPlan,
} from "./revert.js";

export {
  initWorktree,
  isWorktreeInitialized,
  removeWorktree,
  getWorktreePath,
  rewriteToWorktree,
  parseMduCommitMessage,
  blameFile,
  findGitRoot,
  // The SHADOW substrate surface (fs-sync.md §3): the git context
  // addressing <state>/repo.git over the workspace, its lifecycle, and the
  // legacy in-user-repo migration.
  type GitCtx,
  shadowCtx,
  initShadowRepo,
  isShadowRepoInitialized,
  migrateLegacyWorkspace,
  legacyWorktreeAdminDir,
  SHADOW_MAIN_REF,
  type LegacyMigrationResult,
  type ParsedMduCommit,
  type ChangedFile,
  type BlameLine,
} from "./git.js";
