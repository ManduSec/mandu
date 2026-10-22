/**
 * server — Mandu arbiter IPC server (Mandu-new, no reference origin).
 *
 * A Unix-domain-socket server that owns the lifted Mandu symbol table and the
 * (stubbed) policy engine, and exposes them over the NDJSON protocol in
 * ./protocol.ts. This is the daemon promotion called for in plan §3/§8: the
 * symbol table moves from an in-process singleton to a single-writer daemon all
 * interceptors query.
 *
 * Concurrency model: Node is single-threaded for JS, so request handling is
 * effectively serialized per event-loop tick. The in-memory SymbolMap is the
 * authoritative view; allocations also persist to SQLite via the lifted
 * race-safe path so a restart (or a second arbiter-adjacent allocator) recovers
 * state. The DB path is fixed at construction.
 */

import type { PathLabelEntry } from "../policy/load-policy.js";
import { PROTECTED_WRITE_LABELS } from "../policy/write-protect.js";
import { binaryVetted, entryReadsTwin, entryVouches, trustVerdictSubject, unvettedOpenVerdict } from "../policy/flow-taint.js";
import { argsCodeProblem, basenameOf, consumerWireRelease, decideOpen, entryAdmitsNothing, openerPrints, foldRules, heldTimeoutReason, inlineCodeProblem, intersectBindings, knownConsumers, loaderEnvProblem, binaryVerdictParts, matchReader, mootQuestionReason, binaryPrints, verdictNoLongerApplies, binaryRunsCode, printerOpenVerdict, readerPrints, readerRunsCode, renamedCopyOf, runtimeOf, openVerdictSubject, parseScriptFacts, readerOutputRule, scriptFactsProblem, setPackConsumers, staleInterpreterVerdict, verdictProgramOf, withPinnedReader, writeVerdictSubject } from "../policy/flow-taint.js";
import { holderFileBindings, valueRulesToDocument, wholeFileBindings } from "../policy/value-bindings.js";
import { defaultPackDirs, loadConsumerPacks, type LoadedPack } from "../policy/consumer-packs.js";
import { refreshProgramHashes } from "../policy/program-hashes.js";
import { createServer, connect, Socket, type Server } from "node:net";
import { ensurePrivateDir } from "./instance.js";
import { releaseVersion } from "./release-version.js";
import { arbiterBuild, type BuildIdentity } from "./build-identity.js";
import { chmodSync, existsSync, lstatSync, readdirSync, unlinkSync, mkdirSync, statSync, renameSync, writeFileSync, readFileSync, realpathSync, openSync, fstatSync, readSync, closeSync, constants as fsConstants } from "node:fs";
import { manduPath } from "../src/generated/mandu-paths.js";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { assertSocketPathFits } from "./socket-path.js";
import { installAdminLayer, layerProblems, loadPolicyFileStrict, policyWarnings, readAdminLayer } from "../policy/policy-file-validate.js";
import { ADMIN_POLICY_DIR, AdminLayerError, adminLayerSignature, adminLayerView, getAdminLayer, setAdminLayer } from "../policy/admin-layer.js";
import { documentPatterns, redactChange, redactPolicyDocumentResult, redactProposal } from "../policy/prompt-pattern-redact.js";

import {
  type SymbolMap,
  loadSymbolMap,
  allocateSymbol,
  findReusableSymbol,
  findAllocationMatches,
  findSymbolByName,
  resolveSymbol,
  getSymbolEntry,
  placeholderBaseKnown,
  PLACEHOLDER_BASE_RE,
  resolveAllSymbolsDeep,
  buildSymbolSystemPrompt,
  getActiveFormat,
  unescapeSymbols,
  getSymbolDbPath,
  ownDbDirs,
  escalateSymbolConfidentiality,
  admits,
  isSecret,
  maxConfidentiality,
  parseConfidentialityLevel,
  type ConfidentialityLevel,
  parseIntegrityLabel,
} from "../symbol-table/index.js";
import { sourceLabel } from "../symbol-table/source-label.js";
import { acquireSymbolDbOwner, type SymbolDbOwner } from "../symbol-table/db-owner.js";
import {
  createEngineBackedPolicy,
  type ClassifyRequest,
  type PolicyEngine,
  type DesymbolizationRequest,
  type DesymbolizationDecision,
  destinationMatchesBindings,
  relativePathBase,
  wireSchemeRefusal,
  wirePositionRefusal,
} from "../policy/policy-interface.js";
import {
  type FsPathDecisionRequest,
  type FsPathDecision,
  normalizeFsPath,
  SENSITIVE_PATHS,
} from "../policy/fs-outbound.js";
import {
  decideFileUpload,
  decideFileUploadByPath,
  isUploadExempt,
  type FileUploadDecision,
  type FileUploadDecisionRequest,
  type FileUploadFacts,
  type UploadContentFact,
  type UploadLabelFact,
  type UploadPresence,
} from "../policy/file-upload.js";
import {
  classifyExec,
  resolveExecArgv,
} from "../policy/exec-classify.js";
import { blockedExecFold } from "../policy/blocked-exec.js";
import { execGate, type ExecGateResult } from "../policy/exec-gate.js";
import { declaredNetWrites, programTextPaths, stdinPrograms } from "../policy/exec-program-text.js";
import { execSignature, execSignatureForArgv, rootSignaturesOfArgv } from "../policy/exec-signature.js";
import { ExecDecisionStore } from "../policy/exec-decision-store.js";
import { ExecCleanVerdictStore } from "../policy/exec-clean-verdicts.js";
import { CleanReporters } from "../policy/clean-reporters.js";
import { ExecTwinStore } from "../policy/exec-twin-store.js";
import { EgressApprovalStore, type EgressApproval } from "../policy/egress-approvals.js";
import { SessionPostureStore, parsePosture, type PostureChange } from "../policy/session-posture.js";
import { inboundSpecNamesInput, isInboundSpecId, resolveInboundSpecId, SessionSpecs, unknownToolNames } from "../policy/tool-inbound.js";
import { gateSurfaceFor, type GateSurface } from "../policy/tool-gate-surface.js";
import { maskedByDecision, requiresGuard, toolMapping, unguardedToolWhy, unmappedToolWhy, type ToolMapping } from "../policy/mapped-tools.js";
import { isAgentFileTool, isAgentReceiptTool } from "../policy/agent-receipt.js";
import { KEY_LISTING_OUTPUT_MAX, commandDirsReached, keyListingCandidates, ownTextTwinExecOutputPath, structuredTwinExecOutputPath, structuredTwinKeyListingPath, wholeFileTwinExecOutputPath, withoutHarnessBudgetTail, type KeyListingTwin } from "../policy/claude-code-inbound.js";
import { compoundListingPaths, compoundLsCommand, compoundWithoutLs, hostListingFs, isLsArgv, lsArgvMatches, plainLsListingPaths } from "../policy/dir-listing.js";
import { createHash, randomBytes } from "node:crypto";
import { listUsageRules, listUsageGates, ruleRef, verdictRef, type RuleRef } from "../policy/rule-ref.js";
import { describeLawSource, type PolicyFileConfig, type PolicyLawSource } from "../policy/load-policy.js";
import { RuleHitStore } from "../policy/rule-hits.js";
import { parseEnforcedAtStart, PolicyDocumentStore, StalePolicyError, type PolicyChange } from "../policy/policy-document-store.js";
import { reconcilePolicyFileAtStart } from "../policy/policy-restore.js";
import { guardSettingsOf } from "../policy/guard-settings.js";
import { OUTSIDE_VIAS, PolicyProposalStore } from "../policy/policy-proposals.js";
import { policyDelta } from "../policy/policy-delta.js";
import { OpError, PolicyAgentOps } from "./policy-agent-ops.js";
import { PolicySuggestionOps, emptyCounts, type SuggestionEvent } from "./policy-suggestion-ops.js";
import { PolicyModelOps, type ClassifierSpec, type PolicyModelCallEvent, type PolicyModelOpsDeps } from "./policy-model-ops.js";
import { documentExtension } from "../policy/policy-model.js";
import { policyAgentEditSchema } from "../policy/policy-edit-schema.js";
import { GLOB_KEY_PREFIX, compilePolicy, connectAllowSpecs, getCurrentPolicy, matchUserRules, modelLocation, modelTokenBindings, originHostOf, relaxationsOf, swapCurrentPolicy } from "../policy/compiled-policy.js";
import { canonicalJson, diffItems, evaluateEdits, pathIdentity } from "../policy/policy-edit.js";
import { recordWireGrant, symbolMapGeneration, type SymbolEntry } from "../symbol-table/symbol-table.js";
import type { DesymStage, PathLevelsEntry, PathLevelsOpResult, SessionUpstreamResult, TestFlowOpRequest, TestFlowPathLabel, TestFlowResult, WhyPathOpResult, WhyHostOpResult, WhyPendingChange, CallTaintResultWire, AgentReceiptTaintResultWire, McpServerTaintResultWire, DecideProtectedWriteResultWire, DecideSecretOpenResultWire, ScanSecretValuesResultWire, FilterPromptResultWire, DocumentTextResultWire, PromptHoldsResultWire, PromptFiltersResultWire, PromptFilterPacksResultWire, PromptExceptionsResultWire, PromptPackEditOpRequest, PromptPackEditResultWire, TaintedProcessBindingsResultWire, HolderSourceBindingResultWire, SessionExecRootResultWire, GuardAttachResultWire, SessionSecretTaintResultWire, SecretTaintedProcessesResultWire, LabelWrittenPathTaintedResultWire, DerivedLabelsSinceResultWire, LabelRootsSinceResultWire, LabelledLevelResultWire, GuardCatalogWire, SessionPathLabelResultWire, ClearSessionPathLabelsResultWire, FollowDerivedLabelResultWire, GuardSettingsResult, SuggestPolicyResult, GitHistoryLocksResult, RegisterRepositoryResult, CacheSealsResult, SealCacheEntriesResult, BeginLaunchResult, EndLaunchResult, HumanPlaneStatusResult, ReaderProgramOpResult, SuggestFromScanResultWire } from "./protocol.js";
import { EGRESS_REFUSAL_KINDS, PATH_LEVELS_MAX, STRIPPED_PLACEHOLDERS_MAX } from "./protocol.js";
import { RelayNoticeQueue, parseRelayNotice } from "./relay-notices.js";

/** The Test-a-flow probe's symbol name: never minted, never resolvable — the
 *  probe entry is handed to the gate directly (decideDesym probe mode). */
const TEST_FLOW_PROBE_SYMBOL = "$MDU:Probe[test].flow";

/** The upload gate scans at most this many bytes of a file for registered
 *  secret values (file-upload.ts rule 6; confidentiality.md §7): a larger
 *  file fails closed, held for the person, rather than be sent half-checked.
 *  The scan is STREAMED (upload-scan.ts: chunk by chunk, never the whole
 *  file in memory, the event loop free between chunks), so the bound is
 *  about time, not memory: 256 MiB of binary scans in about 6 s on the
 *  development host (confidentiality.md §7 has the measurement), inside
 *  FILE_UPLOAD_SCAN_DEADLINE_MS. Was 8 MiB, read whole, until 2026-10-17. */
export const FILE_UPLOAD_MAX_BYTES = 256 * 1024 * 1024;
/** Bytes per read of the upload scan: one decode-and-match stall of the
 *  event loop each, about 10 ms on the development host and in the CI guest
 *  (35 MiB/s either way; 1 MiB reads stalled about 40 ms for no more
 *  throughput, and a loaded host multiplies the stall: every other client
 *  of the arbiter waits it out). */
export const FILE_UPLOAD_SCAN_CHUNK_BYTES = 256 * 1024;
/** How often a running upload scan tells a client that asked
 *  (`progress: true`) that it is at work: the first frame when the scan
 *  starts, then at most this often, from a timer and from each chunk (so a
 *  timer delayed by a busy loop still gets a frame out), well under the
 *  client's 5 s idle timeout (DEFAULT_REQUEST_TIMEOUT_MS). */
export const FILE_UPLOAD_PROGRESS_MS = 1000;
/** The upload scan's deadline: past it the file is held (rule 6, "the
 *  check did not finish in time"). Under the client's whole-call bound for
 *  the op (client.ts FILE_UPLOAD_TIMEOUT_MS), so the arbiter's hold, with
 *  its Approvals row, answers before any client gives up. */
export const FILE_UPLOAD_SCAN_DEADLINE_MS = 45_000;
import type { PathLabel } from "../policy/path-labels.js";
import { modelClientKeyPaths } from "../policy/model-tls.js";
import {
  EventStore,
  type StoredEvent,
  type Tenant,
  tenantFromEnv,
} from "../events/event-store.js";
import { EmitCoalescer } from "../events/coalescer.js";
import { ProvenanceStore, bindingDetermined, lineageChain, strictestLevel, type AgentReceiptOpts, type SecretTaintRow } from "../provenance/provenance-store.js";
import { resolveConfidentialityEnabled } from "../policy/confidentiality-flag.js";
import { sendWithoutRefusal } from "../policy/send-without.js";
import { resolveIntegrityEnabled } from "../policy/integrity-flag.js";
import {
  catalogNameAnchors,
  confidentialityForOrigin,
  directoryMayChange,
  leadingCdDir,
  unresolvedDirChange,
  pathConfidentiality,
  patternTargetsCatalogSecret,
  resolveTypedPathOrigin,
  secretPathConfidentiality,
  type LabelLookup,
  type SecretCatalogMatch,
} from "../policy/secret-catalog.js";
import { compilePathGlob, pathGlobLastSegmentMatches } from "../policy/path-glob.js";
import { namedTwinsFor, type NamedTwin, type NamedTwinKind } from "../policy/named-twins.js";
import { DOCUMENT_TWIN_EXTRACT } from "../policy/personal-documents.js";
import { PathLabelStore, normalizeLabelPath, outrankedStricterPatterns, resolvePathLabel } from "../policy/path-labels.js";
import { SessionLabelStore, type SessionLabel } from "../policy/session-labels.js";
import { SymbolSourceStore } from "../symbol-table/symbol-sources.js";
import { ForwardedClearStore, isCallId, MAX_IDS_PER_REQUEST as FORWARDED_CLEAR_MAX_IDS } from "../symbol-table/forwarded-clear.js";
import { ForwardedPlaceholderStore, parsePlaceholderMap, MAX_IDS_PER_REQUEST as FORWARDED_PLACEHOLDERS_MAX_IDS, MAX_MAPS_PER_REQUEST as FORWARDED_PLACEHOLDERS_MAX_MAPS, type PlaceholderMap } from "../symbol-table/forwarded-placeholders.js";
import { ResultHeadStore } from "../symbol-table/result-heads.js";
import { RaisedRowStore } from "../symbol-table/raised-rows.js";
import { SessionUpstreamStore } from "../policy/session-upstreams.js";
import {
  ReserveBlockStore, SessionRelayStore, parseReserveBlock, parseSessionRelay, parseShapeLayout, relaySessionKeyProblem,
  shapeLines, shapeRowsLast,
} from "./reply-reservation.js";
import { isManduDeclassifyTool, isManduInspectTool, isManduQuarantineTool } from "../policy/inspect-tool.js";
import { isManduPolicyTool } from "../policy/policy-tool.js";

/** The approval key of a rung-3 read: the fs-gate's precedent of a synthetic
 *  destination naming the ACT (`fs:<tool>:<mode>`), not a host. */
const IN_CONTEXT_READ = "model_context:in-context-read";
/** The reason a "Send without it" answer carries on its one decision
 *  (confidentiality.md §4 "Send without it"): the request goes, the secret stays. */
const SEND_WITHOUT_REASON = "the user chose Send without it: this request goes with a marker where the secret's placeholder was, and the secret is not sent";
/** How many of a HIGH session's reads its Approvals card names (the rest
 *  are counted, `sessionReadsMore`). */
const SESSION_READS_SHOWN = 8;
/** The path of a HIGH session's taint row for a datum with no file
 *  (`sessionSourceRows`): bound where its symbol is bound. */
const SESSION_SYMBOL_ROW_PREFIX = "symbol:";
/** How many sessions' guard announcements (`guardAttach`) are kept. */
const GUARDED_SESSIONS_MAX = 1024;
import { DerivedLabelStore, holderMayReadDerived, resolveDerivedLabel } from "../policy/derived-labels.js";
import { SessionPathLabelStore } from "../policy/session-path-labels.js";
import { FoundLabelStore } from "../policy/found-labels.js";
import { composedLabel, guardLabelRoots, labelRootKeys, labelWalkRoots, withLabelRoots, type GuardLabelRoot, type LabelSnapshot } from "../policy/label-lookup.js";
import { holderBindEdit, holderSendReleased, holderSendSubject, holderSources, hostIsBound as holderHostIsBound, parseHolderSendSubject, type HolderSource } from "../policy/holder-send-ask.js";
import { decideDeclassify } from "../policy/declassify.js";
import { decideSessionEgress, type SessionEgressBoundary, type SessionEgressDecision } from "../policy/session-egress.js";
import {
  composeSessionApproval, heldRefusalKind, heldSessionOf, isSessionApprovalSubject, isSessionHeldReason,
  approvalDestination, parseSessionApprovalSubject, sessionApprovalSubject, sessionExecTarget, sessionHeldNetReason, sessionNetTarget,
} from "../policy/session-approvals.js";
import { DEFAULT_PIECE_LIMITS, MIN_FINGERPRINT_LEN, MIN_LINE_FINGERPRINT_LEN, type PieceLimits, type SecretFingerprint } from "../policy/egress-fingerprint.js";
import { RegisteredValueIndex, indexableRow, raisedRowKeptLines, scanEgressFingerprintIndexed, type ValueHow } from "../prompt-filter/registered-values.js";
import { scanFileForValues } from "../policy/upload-scan.js";
import { RESIDUE_MIN_LEN, ResidueScanner, VALUE_ONLY_MAX_CHARS, planValueOnly, residueCheckText, type ValueOnlySpan } from "../policy/value-only-release.js";
import { PATH_RELEASE_TOOLS, blankSpans, callHoldsPlaceholder, commandWords, counterfactualLookup, messageSpans, pathReleaseContentProblem, wordDirectories } from "../policy/clean-tree-release.js";
import { withoutGrepExclusions } from "../policy/exclusion-flags.js";
import { looksLikeSecretValue } from "../policy/secret-detectors.js";
import { isWholeWriteNotice, parseResultHead, resultHeadLength, writeNoticeRow, type ResultHeadKind } from "../policy/agent-result-head.js";
import { RegisteredValueFilter } from "../prompt-filter/registered-value-filter.js";
import { parseSegments, PromptFilterEngine, type PromptPolicyInput, type SessionOwnWrites } from "../prompt-filter/engine.js";
import { DEFAULT_PROMPT_HOLD_MS, PROMPT_SUBJECT_PREFIX, PromptHolds, parsePromptRow } from "../prompt-filter/holds.js";
import { KeyShapesFilter } from "../prompt-filter/key-shapes-filter.js";
import { effectivePromptConfig, promptLockProblems } from "../prompt-filter/policy.js";
import { WHY_SYMBOL_RE, whySymbol, whySymbolSessions } from "../prompt-filter/why-symbol.js";
import {
  ADMIN_PROMPT_PACK_DIR,
  loadPromptPacks,
  PackFilter,
  packDirsSignature,
  packToYaml,
  patternMatchCounts,
  type LoadedPacks,
} from "../prompt-filter/packs.js";
import { applyPackEdits } from "../prompt-filter/pack-edit.js";
import { PluginFilter, type PluginProcessRunner, type PluginStats } from "../prompt-filter/plugin-filter.js";
import { PluginPins } from "../prompt-filter/plugin-pin.js";
import { memoProbe } from "../prompt-filter/plugin-probe.js";
import type { ConfineLegs, ConfineTools } from "../prompt-filter/plugin-confine.js";
import type { PromptFilter } from "../prompt-filter/filter.js";

/** The tools whose symbols hold a COMMAND'S OUTPUT, across the agents the
 *  proxies serve. Such a row is masked either for EVIDENCE (plan 10 rule (i):
 *  a process in the call's tree held a secret, so the output may be the
 *  secret's bytes) or as a PRECAUTION (the path-derived level, a fail-closed
 *  unknown taint: the text is whatever the command printed, usually its own
 *  failure line). `scanSecretValues` fingerprints an exec-output row only
 *  when the arbiter's provenance store shows its call's tree held a secret
 *  (§11.8); a precautionary row would otherwise match its own text forever. */
/** The tools whose result the value-only release may take
 *  (backstop-value-only.md A1): a file read and a command's output, the
 *  agents' own names for them. Never an agent's or subagent's answer, an MCP
 *  tool, a fetch or a background poll: those are masked whole as before. */
const VALUE_ONLY_TOOLS = new Set(["Read", "read", "view", "Bash", "bash", "shell", "exec_command", "local_shell", "exec"]);
const EXEC_OUTPUT_TOOLS = new Set(["Bash", "BashOutput", "exec_command", "shell", "local_shell", "exec", "bash"]);
/** How many registered files' twins one output row takes its twin lines
 *  from at most (`outputRowTwin`): an output naming more keeps the rest of
 *  its lines as pieces (fail-closed). */
const OUTPUT_TWIN_MAX_FILES = 16;
/** How long a *once* spent by one request still answers that request's
 *  other asks (egress-hold.md "One card per file"): the longest hold
 *  (net-proxy EGRESS_HOLD_MAX_MS, 300 s) and a minute to spare. */
const ONCE_REQUEST_WINDOW_MS = 360_000;
/** How many of a request's placeholders (`requestSymbols`) the file-card
 *  test reads at most: past it, a placeholder may keep its own card. */
const REQUEST_SYMBOLS_MAX = 512;
import { agentFileOf, isAgentAuthPath, agentLoginConfidentiality, CATALOG_GATE_SKIP_DIRS, catalogGateRoots, gateVerdict, MAX_LABEL_FILES, originUnder, SKIP_DIRS, parseSessionLogins, pickLoginEnv, pickPackageCacheEnv, sessionLoginPaths, type SecretDiscoveryReport } from "../policy/secret-discovery.js";
import { DiscoveryWorker, runDiscoveryJob, type DiscoveryJob } from "../policy/secret-discovery-thread.js";
import { historyLimitsFromEnv, scanSecretHistory, DEFAULT_HISTORY_LIMITS, type HistoryScanOptions, type SecretHistoryScan } from "../policy/secret-history-scan.js";
import { scanSecretWorkspace, workspaceLimitsFromEnv, WorkspaceScanCache, type LabelCacheEntry, type SecretWorkspaceScan, type WorkspaceScanOptions } from "../policy/secret-workspace-scan.js";
import { effectiveLabelMapping, mapLabel, type LabelMappingEntry, type LabelScanLimits } from "../policy/sensitivity-labels.js";
import { LockResolver, type ResolverGit, type ResolverLimits, type ResolverSchedule } from "../policy/lock-resolution.js";
import type { RegistryLimits, RepoWalkLimits } from "../policy/known-repos.js";
import { defaultHistoryCacheDir, fileHistoryScanCache, type HistoryScanCache } from "../policy/secret-history-cache.js";
import { CacheSealStore, sealGate, type CacheSealRejection, type LiveLaunch } from "../policy/cache-seals.js";
import { PreparedCopies, type PrepGit, type PrepLimits } from "../policy/prepared-copies.js";
import { envSecretNameMatches, envSecretSpan, extractSecretSpans, secretFileShape } from "../policy/secret-extract.js";
import { knownSecretsOf, SCAN_MAX_FILES, transcriptKnownFiles } from "../policy/transcript-known.js";
import { isTranscriptStorePath, manduWindowsFrom, scanAgentTranscripts, transcriptSources, type KnownSecret, type TranscriptScanLimits, type TranscriptSource } from "../policy/transcript-scan.js";
import { codexDirOf, projectProviderReader, providerSettingsOf } from "../policy/transcript-providers.js";
import { parseScanFileClaims, readRegularFile as readTranscriptClaimFile, verifyScanFile } from "../policy/transcript-suggestions.js";
import type { PastSessionsFile } from "../policy/policy-suggestions.js";
import { AuthGrantStore, isGrantOrigin, parseAuthGrants } from "../secret-registry/auth-grants.js";
import { WireReleaseStore, parseDirectHosts } from "../secret-registry/wire-release-sessions.js";
import { documentBlockText } from "../policy/document-blocks.js";
import { documentNameRows, envRowVariable, isOwnTextRow, isRegisteredFileRow, ownTextTwinFor, registerSecret, registeredDocumentText, registeredDocumentTwin, twinMatchOf, fileRegisteredAsIs, listSecretRegistry, registerEnvSecret, registeredFileSymbols, registeredFilePaths, registeredFileTwin, structuredTwinFor, structuredTwinWithSecretsFor, structuredTwinOfField, wholeFileTwinFor, wholeFileTwinOfBase, wireServableTwin, wireReleaseScheme, type RegisteredTwin } from "../secret-registry/registry.js";
import { WhyPreview } from "./why-preview.js";
import { declaredBindingsReader, issuerSourceOf, ownWireHost, releaseRestsOnWireGrant, syncCurrentBindings, syncEnvBindings, syncRegisteredBindings } from "../secret-registry/current-bindings.js";
import { mcpConfigLike } from "../policy/mcp-config.js";
import { issuerOfHost, issuerRelease, type Issuer } from "../policy/issuer-bindings.js";
import { siblingDeclaredBindings, valueSourceLevel, valueSourceView, type ValueSourceOptions } from "../secret-registry/value-sources.js";
import {
  PROTOCOL_VERSION,
  type ArbiterRequest,
  type ArbiterResponse,
  type PolicySnapshotOpResult,
  type SubscribeRequest,
  type SymbolShapeResult,
} from "./protocol.js";

/** A recorded tool_use decision. Stored in-memory keyed by toolUseId so later
 * OS interceptors can correlate an observed syscall to a known tool decision.
 * NON-PERSISTENT for now — cleared on arbiter restart (see recordToolCall). */
export interface ToolCallRecord {
  toolUseId: string;
  name: string;
  input: unknown;
  sessionKey?: string;
  /** Epoch millis when the record was created. */
  recordedAt: number;
  /** Sent where the agent's programs reach (the data socket, or the human
   *  socket while an unwalled launch is live): a CLAIM. Never overwrites a
   *  believed record, and `symbolProvenance` does not answer it
   *  (arbiter-human-plane.md §10.2). */
  claimed?: true;
}

/** A live subscriber, registered while a `subscribe` connection is open. `push`
 * is invoked by `emit` to fan out a newly-stored event; `end` closes the
 * underlying stream socket — used by `deleteSession` so a stream on a deleted
 * session terminates instead of lingering silently. */
/** Plan 15 §4.1 and §13.12: what this arbiter's classify said of one call's
 *  result (`ArbiterServer.backstopCalls`). */
interface BackstopCallRecord {
  raised: boolean;
  policySecret: boolean;
  /** A policy-secret classify that was not the path rule's with every
   *  secret reading placed on a file: no path record, for good. */
  pathMixed: boolean;
  /** The files the path rule's readings were placed on (their union). */
  pathFiles?: string[];
  /** The highest level the path rule gave the result. */
  pathLevel?: ConfidentialityLevel;
  /** Every file the call's plain path tokens name, whatever its label
   *  (`ClassifyResult.placedFiles`, their union). */
  pathPlaced?: string[];
  /** Plan 15 §13.12, "A cd that fails": the same two lists placed where the
   *  command started, for a command that opens with a `cd` to `dir`
   *  (`ClassifyResult.ifCdFailed`, their union); null once a classify of
   *  the call offered none, or another folder (no such placement, for good). */
  pathIfCdFailed?: { dir: string; files: string[]; placed: string[] } | null;
}

interface Subscriber {
  push: (event: StoredEvent) => void;
  end: () => void;
}

/** The workspace scan's test seams (the filesystem, limits, clock, yield),
 *  and the label read's budgets (plan 14 §14.1). What the scan reads and its
 *  coverage check are the server's. */
export type WorkspaceScanSeams = Omit<WorkspaceScanOptions, "home" | "includeHome" | "isCovered" | "cache" | "readText" | "sensitivityLabels"> & {
  labelLimits?: Partial<LabelScanLimits>;
};

export interface ArbiterServerOptions {
  /** Unix-domain socket path to listen on. */
  socketPath: string;
  /** Plan 10 §11.18: the bound on one registered value's piece extraction
   *  (`DEFAULT_PIECE_LIMITS`; a test lowers it). `scanChars` is also the
   *  largest file a guard-reported raw read registers. */
  pieceLimits?: Partial<PieceLimits>;
  /** SQLite symbol DB path. Defaults to the lifted getSymbolDbPath();
   *  server-main passes its `--symbol-db` flag or that default. */
  dbPath?: string;
  /** Observability event directory (one NDJSON file per session). REQUIRED
   * (2026-09-05): server-main resolves it (its `--event-dir` flag, else the
   * on-disk `${MANDU_HOME:-~/.mandu}/events`, on-disk-layout.md §3) and
   * passes it explicitly; every other constructor — which in practice means a test — names its own temp
   * dir. It used to default silently, and for months a handful of unit tests
   * that forgot it wrote their approval fixtures into the DEVELOPER's live
   * shared event store (56 `evil.example/collect` audit rows in the resident
   * stack's `arbiter-admin` stream); on the on-disk default that pollution
   * would also have blocked the legacy carry-over. A required field makes
   * the omission a compile error instead of a quiet leak. */
  eventDir: string;
  /** Observability-only retention (runtime-instances.md §12): a session whose
   * event log has not been appended for longer than this is removed — file,
   * in-memory seq state, live subscribe streams, coalescer state: exactly the
   * `deleteSession` path — once at listen() and then every
   * `eventRetentionSweepMs`. Omitted / 0 → never prune (every test that does
   * not opt in keeps today's behavior). The reserved `arbiter-admin` audit
   * stream is always exempt. server-main derives this from
   * $MANDU_EVENT_RETENTION_DAYS (default 90; 0 disables). */
  eventRetentionMs?: number;
  /** Sweep cadence for eventRetentionMs (default 1 h; tests shorten it). */
  eventRetentionSweepMs?: number;
  /** Policy engine. Defaults to the lifted engine-backed data-trust policy
   * (built-in TOOL_INBOUND_SPEC + intrinsic category defaults; classify is
   * fail-closed for any unmapped tool/field). Pass a custom engine — e.g. one
   * built from a YAML policy file — to override. An injected engine resolves
   * session specs against the registry it was built with: pass that same
   * registry as `sessionSpecs` below, or its classify never sees this
   * server's `setSessionSpec` bindings (it then falls back to the boot spec). */
  policy?: PolicyEngine;
  /** The session→spec registry this server's `setSessionSpec` binds in
   *  (tool-inbound.ts SessionSpecs). Default: a fresh one of its own, which
   *  is what scopes the bindings to this server. Embedders and tests that
   *  inject `policy` pass the registry that engine was built with. Cleared on
   *  close. */
  sessionSpecs?: SessionSpecs;
  /** Optional YAML data-trust policy file (origin lists + tool overrides),
   * consumed only when `policy` is not supplied. */
  policyPath?: string;
  /** An in-memory policy DOCUMENT (tests / embedders): compiled as the law in
   * force instead of loading `policyPath`. `null` = built-ins only. */
  policyDocument?: PolicyFileConfig | null;
  /** Plan 12 D5: the administrator's layer directory. Absent = the built-in
   *  `/etc/mandu/policy.d`; null = no layer; a path = that directory
   *  (tests). A constructor option, never an environment variable: a session
   *  cannot point the arbiter at a layer of its own. */
  adminPolicyDir?: string | null;
  /** Signed consumer packs (consumer-packs.ts): the pack directory and the
   *  trusted-keys directory. Default the path table's `packs` and
   *  `pack-keys` (`<home>/packs`, `<home>/pack-keys`); `null` loads none
   *  (tests, embedders). */
  packDir?: string | null;
  packKeysDir?: string;
  /** Confidentiality plan 15 §4.2: the person's prompt filter packs. Default
   *  the path table's `prompt-filters` (`<home>/prompt-filters`); null loads
   *  none and refuses pack edits (tests, embedders). */
  promptPackDir?: string | null;
  /**
   * Plan 15 §4.3 (phase 3): the prompt filter plugins' confinement tools
   * (server-main sets them from `--net-guard`, `--landlock-apply` and the
   * installed bubblewrap) and the arbiter's private directory for their
   * pinned copies and scratch directories (default `prompt-plugins` beside
   * the symbol DB, in the state directory). Without `netGuard` no plugin
   * runs (its `on_error` applies). `probe` and `run` are test seams.
   */
  promptPlugins?: {
    netGuard?: string | null;
    landlockApply?: string | null;
    bwrap?: string | null;
    dir?: string;
    probe?: () => Promise<ConfineLegs>;
    run?: PluginProcessRunner;
  };
  /** The administrator's packs. Absent = the built-in
   *  `/etc/mandu/prompt-filters.d`; null = none; a path (tests). A
   *  constructor option, never an environment variable. */
  adminPromptPackDir?: string | null;
  /** Plan 15 §7: how long a prompt `ask` holds the model request before its
   *  default applies (ms). Default 30 000, or MANDU_PROMPT_HOLD_MS. */
  promptHoldMs?: number;
  /** Hand-edit pickup interval for the policy file (ms; default 2000; 0 = no
   * watcher). Tests shorten or disable it. */
  policyPollMs?: number;
  /** The upload scan's pacing (confidentiality.md §7, STREAMED): a test
   *  knob. Unset: FILE_UPLOAD_SCAN_DEADLINE_MS and
   *  FILE_UPLOAD_PROGRESS_MS. The size bound and the chunk size are fixed. */
  uploadScan?: { deadlineMs?: number; progressMs?: number };
  /** Optional logger; defaults to console. Set to a no-op in tests. */
  log?: (msg: string) => void;
  /** Start the `discoverSecrets` thread at listen, so a launch's first walk
   *  does not pay its start (runtime-instances.md §14.2 item 7). The daemon sets it;
   *  otherwise the thread starts on the first walk. */
  warmDiscoveryWorker?: boolean;
  /** `scanSecretHistory`'s seams (git runner, blob reader, limits, clock):
   *  a test knob. Unset: real git, limits from MANDU_HISTORY_SCAN_*. */
  historyScan?: HistoryScanOptions;
  /** Where the history scan keeps what it knows per repository
   *  (secret-history-cache.ts; secret-discovery.md §3.2 item 8). Default: the
   *  path table's `object-walks` + `/history-scan` under MANDU_HOME; `null`:
   *  no cache (every scan reads the whole history). */
  historyScanCacheDir?: string | null;
  /** The workspace scan's seams (plan 14 §13: the filesystem, limits, clock,
   *  yield): a test knob. Unset: the real filesystem, limits from
   *  MANDU_WORKSPACE_SCAN_*. Its cache is the server's, in memory. */
  workspaceScan?: WorkspaceScanSeams;
  /**
   * Plan 14 §14.3: how to start the policy classifier (inspect-mcp
   * `classify-main.ts`) for a names-only model run, and the Landlock applier
   * that confines its network. server-main sets it from `--classifier` /
   * `--landlock-apply` (server-args.ts), which only Mandu's own spawners
   * pass. Unset or null: `modelSuggestPreview` / `modelSuggest` answer "not
   * available in this install".
   */
  policyClassifier?: ClassifierSpec | null;
  /** Test seams of the model ops (the classifier runner, the Landlock probe,
   *  the environment the classifier's is drawn from, the user name). */
  policyModel?: Pick<PolicyModelOpsDeps, "run" | "probeLandlock" | "env" | "userName" | "now">;
  /**
   * Plan 14 §11.1 R1/R2: the known-repository registry and the background
   * resolution of every path label into blob ids (lock-resolution.ts),
   * answered through `gitHistoryLocks`. Unset: it runs ON DEMAND only (a
   * `gitHistoryLocks` root, `registerRepository`, a scanned root, a label
   * change seen by an answer), with no HOME walk and no timer, so an
   * embedder or a test never walks the real HOME. The daemon passes
   * `{ schedule: DAEMON_SCHEDULE }`. `null`: off (answers carry no
   * resolution). Confidentiality axis OFF: never constructed.
   */
  lockResolution?: {
    schedule?: ResolverSchedule;
    /** The HOME walked (default $HOME). */
    home?: string;
    git?: ResolverGit;
    limits?: Partial<ResolverLimits>;
    walkLimits?: Partial<RepoWalkLimits>;
    registryLimits?: Partial<RegistryLimits>;
    selfDir?: string | null;
    /** The platform the HOME walk's macOS prune keys on (default this
     *  process's); a test knob. */
    platform?: NodeJS.Platform;
  } | null;
  /**
   * Plan 14 §11.1 R3: sanitized copies of every known repository's packs
   * that hold a locked object, prepared in the background after each lock
   * resolution cycle (policy/prepared-copies.ts) into `cacheDir`, the
   * launcher's object-twin cache, and sealed in the current epoch. Unset or
   * `null`: off (an embedder or a test never writes a cache it did not
   * name). The daemon passes the path table's `object-twins` and the caps
   * from MANDU_GIT_PREP_CYCLE_MB / MANDU_GIT_PREP_TOTAL_MB. Needs the lock
   * resolution (off with it, or with the confidentiality axis OFF).
   */
  preparedCopies?: {
    cacheDir: string;
    limits?: Partial<PrepLimits>;
    git?: PrepGit;
  } | null;
  /**
   * ADMIN CHANNEL (policy-surface.md §2.6): a file descriptor this
   * process INHERITED at spawn — one end of a socketpair the supervisor that
   * started us holds the other end of. Every op is accepted on it; the
   * human-decision ops in {@link ADMIN_ONLY_OPS} are accepted ONLY on it. The
   * point of an inherited fd is that it has no filesystem name: a same-uid
   * process (the agent, its shims, an MCP child) cannot connect to it, while a
   * second socket PATH would be reachable by anyone who can reach the data
   * socket. server-main reads it from $MANDU_ADMIN_FD.
   */
  adminFd?: number;
  /**
   * DEV/TEST ONLY: also serve the admin channel on a Unix-socket PATH. A path is
   * NOT a boundary against same-uid processes, so this exists for in-process
   * tests and `scripts/dev-arbiter.sh` rigs; the daemon logs a warning when it
   * is set. Never set it on a stack an agent runs against.
   */
  adminSocketPath?: string;
  /**
   * HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): the Unix-socket path of
   * the human channel. The ops in {@link HUMAN_PLANE_OPS}, which return
   * originals (or, like `symbolShape` and the relay ops, must stay out of the
   * agent's reach), are accepted here and refused on the data socket. Its parent
   * directory must be owned by this uid and mode 0700 (created so when
   * absent; any other state refuses the start — fail closed). The agent world
   * is walled off from it by the launcher (net-guard's always-deny entry, the
   * secret-twins tmpfs, the Seatbelt rule), never by a secret in the path.
   * server-main binds it at `<runtime>/human/<instanceId>.sock`. Absent → no
   * human channel: the human-plane ops are reachable only in-process and over
   * the admin channel.
   */
  humanSocketPath?: string;
  /**
   * TENANT (policy-surface.md §2.7): `live` or `test`. An explicitly
   * tenanted arbiter REFUSES `emit`s stamped for the other tenant (so a
   * misconfigured harness cannot pollute the live store) and stamps its own
   * tenant onto unstamped events it persists. Undefined (the default, from an
   * unset MANDU_TENANT) = untenanted, legacy: accepts everything, stamps
   * nothing. Tests that emit `tenant:"test"` events must construct a test or
   * untenanted server.
   */
  tenant?: Tenant;
  /** Coalesce runaway bursts of identical observability events before persisting
   *  (defense-in-depth backstop; see events/coalescer.ts). Default ON. Set false
   *  to persist every emit verbatim (e.g. a test asserting raw event counts). */
  coalesceEvents?: boolean;
  /** Runtime identity reported by the `hello` op (runtime-instances.md):
   *  instance id + code rev, set by server-main. Absent (tests / embedded
   *  servers) → hello still answers with pid/startedAt and nogit identity. */
  identity?: {
    instanceId: string | null;
    gitRev: string;
    gitDirty: boolean;
    /** The release version hello reports (runtime-instances.md §4.1).
     *  Absent → this code's own (`releaseVersion()`); null → hello reports
     *  none, as an arbiter from before the version check did (tests that
     *  stand in for such a release). */
    version?: string | null;
    /** The build identity hello reports (build-identity.ts, runtime-
     *  instances.md §4.1). Absent → this code's own (`arbiterBuild(gitRev)`);
     *  null → hello reports none, as an arbiter from before 2026-10-17 did. */
    build?: BuildIdentity | null;
  };
  /** The confidentiality-axis kill switch (confidentiality.md §11): the ONE
   * flag for the whole second lattice. Defaults from MANDU_CONFIDENTIALITY
   * (default OFF). OFF is byte-identical to the integrity-only system — no
   * level derivation, no wire markers/fields, no enforcement. */
  confidentiality?: boolean;
  /** The integrity-axis switch (policy/integrity-flag.ts): the classic IPI
   * defense's trust classification. Defaults from MANDU_INTEGRITY (default
   * ON — opt-OUT, the inverse of confidentiality). OFF ⇒ every classify is
   * TRUSTED, no untrusted symbols are minted, the untrusted handling-prompt
   * sections are dropped; the confidentiality axis is independent and
   * unaffected. */
  integrity?: boolean;
}

/** The reserved arbiter-global audit stream (approval_resolved /
 *  posture_change / config_change land here — see emitAdmin* below). Never
 *  pruned by the retention sweep: it is the audit trail, not a session. */
export const ADMIN_SESSION_ID = "arbiter-admin";

/** Which channel a request arrived on (docs/design/architecture/arbiter-human-plane.md §2).
 *  `data` = the named Unix socket every interceptor (and therefore every
 *  same-uid process, the agent included) can reach; `human` = the HUMAN-PLANE
 *  socket (`<runtime>/human/<instance>.sock`) the human-facing consumers dial
 *  and the agent world is walled off from (net-guard deny, the secret-twins
 *  tmpfs, Seatbelt); `admin` = the inherited-fd channel only the supervisor
 *  holds, or an in-process call (a caller holding the server object is
 *  trusted by construction). The channels nest: admin ⊇ human ⊇ data. */
export type IpcChannel = "data" | "human" | "admin";

export interface DispatchContext {
  channel: IpcChannel;
  /** Write one interim frame on the requester's connection (the socket
   *  path only): `filterPrompt`'s progress frames (plan 15 §13.5 item 11). */
  notify?: (frame: Record<string, unknown>) => void;
}

/** Plan 15 §13.10: the agents' whole-content write tools (gate-surface.ts):
 *  Claude Code's `Write`, OpenCode's and OpenClaw's `write`. A file one of
 *  them created holds exactly the tool's input. */
const OWN_WRITE_TOOLS: ReadonlySet<string> = new Set(["Write", "write"]);
/** Plan 15 §13.10: the bounds on `ownWriteHashes` (oldest dropped first:
 *  a forgotten write only brings the mask back). */
const OWN_WRITE_SESSIONS_CAP = 256;
const OWN_WRITE_PATHS_CAP = 1024;
const OWN_WRITE_HASHES_CAP = 16;
const sha256Hex = (s: string): string => createHash("sha256").update(s).digest("hex");

/** How often a running `filterPrompt` tells a client that asked
 *  (`progress: true`) that it is still at work: well under the client's
 *  idle timeout (DEFAULT_REQUEST_TIMEOUT_MS). */
export const FILTER_PROMPT_PROGRESS_MS = 1000;

/**
 * Ops that enact a HUMAN decision — accepted only on the admin channel
 * (policy-surface.md §2.6, finding F5). Everything else is the data
 * plane and stays open to every client: the interceptors need symbolize /
 * classify / decisions / emit; `registerSecret` and `labelWrittenPath` only
 * ADD protection; `declassifySymbol` is the MCP inspect child's quarantined
 * read (policy-decided, not a human verdict); `setSessionSpec` is data-plane
 * but bind-once (see its handler). An admin-only op arriving on the data
 * socket is refused with {@link adminOnlyError} — the same shape as any
 * other refused request, so a client that was never meant to call it sees a
 * clean error rather than a hang.
 */
export const ADMIN_ONLY_OPS: ReadonlySet<string> = new Set([
  "resolveEgressApproval",
  "forgetEgressApproval",
  "setPathLabel",
  "removePathLabel",
  "removeDerivedLabel",
  "setSessionPosture",
  "deleteSession",
  // The policy document writers (stage 5a): the law on disk is a human's.
  "applyPolicyDocument",
  "mintUserRule",
  "exportDbLabels",
  "movePageLabels",
  // The policy agent surface (policy-surface.md §8.4.2): the data plane may
  // PROPOSE (and apply a proven tightening); approving a relaxation and undoing
  // a change are a human's.
  "resolvePolicyProposal",
  "undoPolicyChange",
  // Plan 14 §5.2: "Not a secret" withholds protection (a relaxation under the
  // monotonic split); from the data socket the agent could make its own
  // findings disappear. Applying a suggestion (a tightening) is data plane.
  "dismissSuggestion",
  // Plan 15 §8.1: a pack edit writes the person's own pattern pack; removing
  // or editing a pattern lets findings through (a relaxation), so only the
  // human's channel may.
  "promptPackEdit",
  // Plan 15 §7 (phase 3): the answer to a held prompt and the per-finding
  // "let it through" send the human's text as written: only the human.
  "resolvePromptHold",
  "letPromptFindingThrough",
]);

/** `scanAgentTranscripts`' caps from the arbiter's environment
 *  (`MANDU_TRANSCRIPT_SCAN_TIMEOUT_S`, `MANDU_TRANSCRIPT_SCAN_MAX_MB`);
 *  anything else keeps the defaults. Pure. */
export function transcriptLimitsFromEnv(env: Record<string, string | undefined>): Partial<TranscriptScanLimits> {
  const out: Partial<TranscriptScanLimits> = {};
  const s = Number(env["MANDU_TRANSCRIPT_SCAN_TIMEOUT_S"]);
  if (Number.isFinite(s) && s > 0) out.deadlineMs = s * 1000;
  const mb = Number(env["MANDU_TRANSCRIPT_SCAN_MAX_MB"]);
  if (Number.isFinite(mb) && mb > 0) out.maxBytes = mb * 1024 * 1024;
  return out;
}

export function adminOnlyError(op: string): string {
  return `admin-only: '${op}' enacts a human decision and is accepted only on the admin channel (the inherited fd held by the supervisor), never on the data socket`;
}

/**
 * Ops that hand back ORIGINALS — accepted only on the human plane (the human
 * socket or the admin channel), never on the data socket
 * (docs/design/architecture/arbiter-human-plane.md). The data socket is reachable from
 * every process the agent's tools start, so an original-returning op there is
 * a same-uid read of every secret the symbol table holds, the `no-model`
 * ones included:
 *   - `desymbolize` — the deep, label-unrestricted HumanView rewrite (fs-sync,
 *     the reply filter);
 *   - `resolve` SHALLOW (`deep !== true`) — the gated egress paths' per-symbol
 *     lookup (net-proxy, net-supervisor) after `desymbolizationDecision`;
 *   - `events` / `subscribe` / `sessions` / `verifyEvents` — the observability
 *     store, whose `DualRepr.original` fields carry originals (reply-filter,
 *     proxy and fs-sync events).
 * `resolve` with `deep: true` stays on the data plane: it is the quarantined
 * U-LLM's read (inspect-mcp), and its level gate — `admits(location, level)`
 * — refuses a `no-model` row whatever the confidentiality axis says.
 * `subscribe` is handled at the connection layer, so onConnection checks it
 * there too, before a stream is started.
 *
 * Reply row reservation adds three ops that return no original but must not
 * be reachable from the agent's world either (reply-row-reservation.md §5.3,
 * §11.5):
 *   - `symbolShape` — a value's line and row counts, derived from an original;
 *   - `setSessionRelay` / `sessionRelay` — the relay state; its `cols` sets
 *     the wrap width the proxy asks `symbolShape` for, and an agent that
 *     chose it could replay one secret at widths of its choosing and learn
 *     its line lengths from the row counts. The reply filter reports and the
 *     proxy reads over the human socket.
 */
export const HUMAN_PLANE_OPS: ReadonlySet<string> = new Set([
  "desymbolize",
  "resolve",
  "events",
  "subscribe",
  "sessions",
  "verifyEvents",
  // Not an original, but derived from one (a value's line/row count): it
  // follows desymbolize's restriction (reply-row-reservation.md §5.3).
  "symbolShape",
  // The terminal layout the counts are taken at (§11.5).
  "setSessionRelay",
  "sessionRelay",
  // Which token a block's continuation rows stand for, and its N/W/F
  // (§3.8): the counts again, so they stay where the counts stay.
  "noteReserveBlock",
  "reserveBlock",
  // Which tool calls' results went to the model in clear (confidentiality.md
  // §7.1, "Masked after the fact"): from the data socket the agent world
  // could name a call whose result it never showed the model, and Mandu's
  // system note would then vouch, in Mandu's voice, that the model read it.
  "recordForwardedClear",
  "forwardedClear",
  // Where Mandu's placeholders sat in a result forwarded in clear, and its
  // digest (confidentiality.md §6, *Across a relaunch*): from the data socket
  // the agent world could record a map that rebuilds a text of its choosing
  // (the digest it would supply too), which a proxy would then put back in
  // an OpenClaw history as what Mandu sent.
  "recordForwardedPlaceholders",
  "forwardedPlaceholders",
  // The enforcement caches' seals and epochs (confidentiality-plan-14
  // §11.2): from the data socket a confined agent could re-seal a cache file
  // planted during an earlier unconfined period, or hold every seal void
  // with a fake live launch (policy/cache-seals.ts, "who may record").
  "cacheSeals",
  "sealCacheEntries",
  "beginLaunch",
  "endLaunch",
  // A session's machine path labels end with it (session-path-labels.ts):
  // from the data socket the agent world could drop the label on its own
  // background output file and read the file raw.
  "clearSessionPathLabels",
  // Which launches hold the human plane exposed, by pid and session
  // (arbiter-human-plane.md §10.1.1): the sessions are human-plane facts
  // (`sessions` is here too), so the answer stays here.
  "humanPlaneStatus",
  // Which process is an MCP server (plan 10 §11.13): from the data socket the
  // agent world could name a clean process of its choosing as the server
  // whose results a session's taint would otherwise mask.
  "registerMcpServers",
  // Whether a session's egress proxy inspects TLS (plan 10 §11.13.1): it
  // decides whether npm is served the `.npmrc` twin, so only the launcher,
  // which started that proxy, may say it.
  "registerWireRelease",
  // Which host an agent's own key authenticates to (agent-sign-in.md §3): a
  // binding, so a release; from the data socket the agent could bind its
  // key to a host of its own.
  "registerAuthGrant",
  // Plan 15 §8.1: the packs in full (an organization's regexes, a person's
  // plain keywords): from the data socket the agent would learn exactly
  // what to rephrase around.
  "promptFilterPacks",
  // Plan 15 §13.7 item 4: the exceptions' patterns (a pattern may hold the
  // person's own words, and names what the filter lets through as written).
  "promptExceptions",
  // Plan 15 §7: the pending prompt holds carry the human's own found text
  // (a code name, a card number) for the Inbox card.
  "promptHolds",
  // Plan 15 §13.8 (`mandu why <symbol>`): which session and message a
  // placeholder came from, read from the session events (`events` is here
  // too). No value; from the data socket `symbolProvenance` stays the answer.
  "whySymbol",
  // Whether a typed placeholder's base names a row (devtools-relay.md §3.3):
  // the DevTools relay's own question, asked beside its release gate and its
  // values. No value, and nothing the data socket does not answer already
  // (the egress decision's unknown-symbol allow); kept off it so the agent
  // world gets no new lookup.
  "placeholderKnown",
]);

/**
 * The ATTESTED records (confidentiality plan 13 §3 D9, exec-routing.md §7.5
 * "Authenticated reports", arbiter-human-plane.md §3): what the session's
 * guard (`mandu-net-guard`) reports about the agent's processes, and what the
 * model proxies record about a tool call's tree. They are believed only from
 * a channel the agent's process tree cannot reach: the human socket (the
 * guard and the proxies run outside the agent world and dial it) or the admin
 * channel. From the DATA socket each is a CLAIM: it may add taint (a claimed
 * lineage edge or taint row only widens a fold, which is anyone's to do), and
 * it never lowers a mask or a taint, pins a reader, consults or spends a human
 * verdict, files an Inbox row, binds a tool call to a tree, or answers raw.
 * An older guard or proxy that still reports on the data socket therefore
 * fails closed: its opens are twins, its protected writes refused, its calls
 * masked at the session's level while the session holds a raw read.
 *
 *   - `recordExecRoot`: data ⇒ its chain is recorded as claimed edges only (no
 *     exec signature, argv or call-root candidate);
 *   - `processLineage`: data ⇒ a claimed edge;
 *   - `taintProcessSecret`: data ⇒ a claimed row (folds `secret`, never held
 *     raw);
 *   - `decideSecretOpen`: data ⇒ its chain claimed, answered `twin`;
 *   - `decideProtectedWrite`: data ⇒ `deny`, no row;
 *   - `taintedProcessBindings`, `labelWrittenPathTainted`: data ⇒ their
 *     `ancestors` are claimed edges (the answer, a tightening, is unchanged;
 *     `flowsFrom` only adds taint); a `taintedProcessBindings` that names a
 *     `destination` (plan 13 §5.4) consults no verdict and files no row;
 *   - `execGate`: data ⇒ the call's gate time (`call_pending`) and command
 *     (`call_commands`) are not recorded;
 *   - `recordEgressRefusal` (plan 10 §11.8): data ⇒ nothing recorded (a
 *     forged refusal would put a false "refused" line beside a result);
 *   - `recordCallCommand`: data ⇒ nothing recorded (the command the proxy
 *     delivered to the agent, which callTaint binds the call by);
 *   - `callTaint`: data ⇒ read-only (no first ask, no binding, no guess);
 *   - `recordProcessFlow` (plan 13 §9 R1): data ⇒ a claimed flow (it only
 *     adds taint, and is never read where more taint buys a raw read);
 *   - `recordAgentFlow` (plan 13 §4.5.1): data ⇒ an open is a claimed flow
 *     (it only adds masking), a close is not recorded;
 *   - `agentReceiptTaint` (plan 13 §4.5.1): data ⇒ read-only (no first ask,
 *     so no call's window is ended early).
 * `recordCallRoot` is a claim on every channel (no production caller).
 * The gates that consult a human verdict and answer every channel
 * (`desymbolizationDecision`, `fsPathDecision`, `escalateExec`, `execGate`'s
 * program-text gate) are not in this set, but from the data socket they
 * neither spend nor grant a human's *Allow once* either
 * (`consultPriorVerdict`, arbiter-human-plane.md §10.3); `declassifySymbol`,
 * whose caller is in the agent's tree by design, still spends one.
 */
export const ATTESTED_REPORT_OPS: ReadonlySet<string> = new Set([
  "recordExecRoot",
  "processLineage",
  "recordProcessFlow",
  "recordAgentFlow",
  "agentReceiptTaint",
  "taintProcessSecret",
  "decideSecretOpen",
  "decideProtectedWrite",
  "taintedProcessBindings",
  "labelWrittenPathTainted",
  "execGate",
  "recordCallCommand",
  "recordEgressRefusal",
  "callTaint",
]);

/** Is a request on `channel` an attested report (plan 13 D9)? Every channel
 *  but the data socket: the human socket and the admin channel are out of the
 *  agent world's reach, and an in-process dispatch defaults to admin. The
 *  server narrows it further while the human plane is EXPOSED (an unwalled
 *  launch is live: `ArbiterServer.attested`, plan 13 D9 leftovers); this is
 *  the rule for the channel alone. */
export function attestedChannel(channel: IpcChannel): boolean {
  return channel !== "data";
}

/** May a gate's ask spend a human's *once* (arbiter-human-plane.md §10.3)?
 *  `true` spends it; `false` (the data socket, the Test-a-flow probe) reads
 *  it, a denial answering and an approval being no verdict; `"preflight"`
 *  (an attested pre-check whose release is judged again downstream) reads
 *  an approval unspent and spends a denial. */
export type VerdictSpend = boolean | "preflight";

/**
 * The egress gate's decision from a human's answer (`consultPriorVerdict`'s
 * result), or null when there is none. An approval allows. A denial refuses
 * with no further approval; "Send without it" (confidentiality.md §4) is
 * still a denial (the value is never released), and the ask that spends it
 * is told to send the request with a marker where the symbol is. A pre-check
 * reads it unspent and lets the call go on to the send (`allow`: nothing is
 * released there, net-gate.ts); an ask that cannot spend it (the data
 * socket, a probe) reads a plain denial. Pure.
 */
export function verdictDecisionOf(
  prior: Pick<EgressApproval, "id" | "status" | "strip"> | undefined,
  mode: { kind: "live"; spends: VerdictSpend } | { kind: "probe" },
): DesymbolizationDecision | null {
  if (prior?.status === "approved") return { allow: true, reason: "human-approved", ruleRef: verdictRef(prior.id) };
  if (prior?.status !== "denied") return null;
  if (prior.strip === true && mode.kind === "live" && mode.spends === true) {
    return { allow: false, requiresApproval: false, strip: true, reason: SEND_WITHOUT_REASON, ruleRef: verdictRef(prior.id) };
  }
  if (prior.strip === true && mode.kind === "live" && mode.spends === "preflight") {
    return { allow: true, strip: true, reason: SEND_WITHOUT_REASON, ruleRef: verdictRef(prior.id) };
  }
  return { allow: false, requiresApproval: false, reason: "human-denied", ruleRef: verdictRef(prior.id) };
}

/** The reason a human-socket report is answered as a claim: an unwalled
 *  launch is live, so its agent's programs reach the human socket too. */
export function exposedHumanPlaneReason(op: string, launches: readonly LiveLaunch[]): string {
  const who = launches.slice(0, 3).map((l) => `pid ${l.pid}, ${l.mode}/${l.posture}`).join("; ");
  return `an unauthenticated report: '${op}' from the human socket while a launch whose agent can reach the human plane is live (${who || "unknown"}), so it is a claim, as from the data socket; it is believed again once that launch ends`;
}

/** How long the human plane's exposure answer is reused (ms). */
const EXPOSURE_MEMO_MS = 250;

/** A launch set's identity, for telling a change once. */
function exposureKey(launches: readonly LiveLaunch[]): string {
  return launches.map((l) => `${l.pid}/${l.session ?? ""}/${l.mode}/${l.posture}`).sort().join(",");
}

/** The reason a data-socket report is answered as a claim. */
export function unattestedReason(op: string): string {
  return `an unauthenticated report: '${op}' from the data socket, which the agent's processes reach, is a claim; only the session's guard and the model proxies, on the human socket, are believed`;
}

/** The human-plane ops that return no original: their refusal says why they
 *  are walled off instead ("returns originals" would be false). */
const HUMAN_PLANE_REASON: ReadonlyMap<string, string> = new Map([
  ["symbolShape", "derives a count from an original"],
  ["setSessionRelay", "sets the terminal layout symbol shapes are counted at"],
  ["sessionRelay", "reads the terminal layout symbol shapes are counted at"],
  ["noteReserveBlock", "records a reserve block's token and row count"],
  ["reserveBlock", "reads a reserve block's token and row count"],
  ["recordForwardedClear", "records which tool results the model read in clear, which Mandu's after-the-fact note vouches for"],
  ["forwardedClear", "reads which tool results the model read in clear"],
  ["recordForwardedPlaceholders", "records what a model proxy forwarded in clear, which the proxy puts back as Mandu's own text"],
  ["forwardedPlaceholders", "reads what a model proxy forwarded in clear"],
  ["cacheSeals", "reads the seals the enforcement caches are trusted by"],
  ["sealCacheEntries", "records the seals the enforcement caches are trusted by"],
  ["beginLaunch", "records a launch whose posture decides whether the enforcement caches are trusted"],
  ["endLaunch", "ends a launch whose posture decides whether the enforcement caches are trusted"],
  ["humanPlaneStatus", "names the live launches (pid and session) whose agent can reach the human plane"],
  ["registerMcpServers", "names the processes whose taint decides whether an MCP server's results are masked"],
  ["registerWireRelease", "says whether a session's egress proxy puts registry tokens back, which decides whether npm reads a credential raw"],
  ["registerAuthGrant", "binds an agent's own key to the host it authenticates to, which releases the key there"],
  ["filterPrompt", "with dryRun: true tests text against the registered values without minting or a trace (the dashboard's test bench)"],
  ["promptFilterPacks", "reads the prompt filter's patterns and keywords"],
  ["promptExceptions", "reads the prompt filter's exceptions with their patterns"],
  ["promptHolds", "reads the human's own text a prompt hold found"],
  ["whySymbol", "reads the session events that name a placeholder (which message of which session it came from)"],
  ["placeholderKnown", "is the DevTools relay's lookup of a typed placeholder, asked beside its release gate"],
]);

export function humanPlaneOnlyError(op: string): string {
  const why = HUMAN_PLANE_REASON.get(op) ?? "returns originals";
  return `human-plane: '${op}' ${why} and is accepted only on the human socket (or the admin channel), never on the data socket`;
}

/** Plan 10 §11.13: the tool-name prefixes an MCP server's tools carry, in
 *  each agent's spelling: as configured, Claude Code's (every character
 *  outside `[A-Za-z0-9_-]` to `_`) and Codex's (also `-` to `_`). */
export function mcpToolPrefixes(server: string): string[] {
  return [...new Set([server, server.replace(/[^A-Za-z0-9_-]/g, "_"), server.replace(/[^A-Za-z0-9_]/g, "_")])].map((n) => `mcp__${n}__`);
}

/** Plan 10 §11.18: does any table of a gate surface name `tool`? Pure. */
export function surfaceNamesTool(surface: GateSurface, tool: string): boolean {
  const own = (o: object | undefined): boolean => !!o && Object.prototype.hasOwnProperty.call(o, tool);
  return own(surface.exec) || own(surface.execOutput) || own(surface.net) || own(surface.paths) || own(surface.dispatch)
    || own(surface.refuse) || own(surface.refuseArgs) || own(surface.stdin) || own(surface.patch);
}

/** Plan 10 §11.17: a config file's stamp, as the launcher records it when
 *  it reads the file (launcher/src/mcp-server-config.ts mirrors it; the stack
 *  test pins the two to one answer): `<dev>:<ino>:<size>:<mtime ns>:<ctime
 *  ns>` of what the path names (links followed), `absent` when nothing is
 *  there, `unreadable` on any other error. Any write moves it (a rename-write
 *  changes the inode, an in-place write the times). Never throws. */
export function mcpSourceStamp(path: string): string {
  try {
    const st = statSync(path, { bigint: true });
    return `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return code === "ENOENT" || code === "ENOTDIR" ? "absent" : "unreadable";
  }
}

/** The argv a stdio server's process is exec'd with: `[command, ...args]`,
 *  and with the command's basename when the config gives a path (a spawn
 *  may pass either as argv[0]). Exact matches only. */
export function mcpArgvSpellings(command: string, args: readonly string[]): string[][] {
  const out: string[][] = [[command, ...args]];
  const base = command.includes("/") ? command.slice(command.lastIndexOf("/") + 1) : "";
  if (base !== "" && base !== command) out.push([base, ...args]);
  return out;
}

/** True when `req` is a human-plane request: an op in {@link HUMAN_PLANE_OPS},
 *  except a DEEP `resolve` (the quarantined U-LLM's level-gated read), and a
 *  `filterPrompt` DRY RUN (confidentiality-plan-15 §8.1). The live
 *  `filterPrompt` is a proxy op on the data plane: it is how the proxies mask
 *  a prompt. A dry run mints nothing, caches nothing and leaves no event, so
 *  on the data socket it would let any process of the agent's test guesses
 *  against the registered values (and, in phase 2, an organization's hashed
 *  keywords) faster than `scanSecretValues` and without a trace. Any value
 *  but `false`/absent counts as a dry run here, so a truthy non-boolean is
 *  refused rather than run live. */
export function isHumanPlaneRequest(req: { op?: unknown; deep?: unknown; dryRun?: unknown }): boolean {
  if (req.op === "filterPrompt") return req.dryRun !== undefined && req.dryRun !== false;
  if (typeof req.op !== "string" || !HUMAN_PLANE_OPS.has(req.op)) return false;
  if (req.op === "resolve" && req.deep === true) return false;
  return true;
}

/** The refusal a request earns on `channel`, or null when the channel accepts
 *  it. One place for the whole matrix: admin accepts everything; human accepts
 *  the data-plane and human-plane ops but no admin-only op; data accepts
 *  neither. */
export function channelRefusal(req: { op?: unknown; deep?: unknown; dryRun?: unknown }, channel: IpcChannel): string | null {
  if (channel === "admin") return null;
  const op = typeof req.op === "string" ? req.op : "";
  if (ADMIN_ONLY_OPS.has(op)) return adminOnlyError(op);
  if (channel === "data" && isHumanPlaneRequest(req)) return humanPlaneOnlyError(op);
  return null;
}

/** The host part of an egress destination as the gate sees it — a bare host,
 *  `host:port`, or a URL — lower-cased, for user-rule matching. */
export function hostOfDestination(destination: string): string {
  const s = destination.trim().toLowerCase();
  // An IPv6 literal (`[2001:db8::1]:443`, the net-proxy's stated form): the
  // address inside the brackets (it read `2001` until 2026-10-17).
  const v6 = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^@/?#]*@)?\[([0-9a-f:.]+)\]/.exec(s);
  if (v6) return v6[1]!;
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?\[?([^/:?#\]]+)\]?/.exec(s);
  return m?.[1] ?? s;
}

export function tenantMismatchError(arbiterTenant: Tenant, eventTenant: unknown): string {
  return (
    `tenant mismatch: this arbiter is the '${arbiterTenant}' tenant and refuses events stamped ` +
    `'${String(eventTenant)}' — run tests against a test-tenant arbiter (MANDU_TENANT=test), never the live one`
  );
}

/** A pack problem without the fragment of a regex the RE2 engine quotes
 *  (between backticks): what the data plane and a block reason may carry
 *  (plan 15 §8.1; the whole message is promptFilterPacks', human plane). */
export function packProblemOutline(problem: string): string {
  return problem.replace(/`[^`]*`/g, "`…`");
}

/** The scans `suggestPolicy` can run (plan 14 §13.5, §14.1). */
export type SuggestSource = "git-history" | "workspace" | "sensitivity-label";
const SUGGEST_SOURCES: readonly SuggestSource[] = ["git-history", "workspace", "sensitivity-label"];

/** `suggestPolicy`'s `sources` (plan 14 §13.5, §14.1): absent = all three;
 *  otherwise a non-empty list of known sources, each once. Null = refused. */
export function parseSuggestSources(raw: unknown): Set<SuggestSource> | null {
  if (raw === undefined) return new Set(SUGGEST_SOURCES);
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > SUGGEST_SOURCES.length) return null;
  const out = new Set<SuggestSource>();
  for (const s of raw) {
    if (!(SUGGEST_SOURCES as readonly unknown[]).includes(s)) return null;
    if (out.has(s as SuggestSource)) return null;
    out.add(s as SuggestSource);
  }
  return out;
}

/** Plan 14 §5.5: when a finished scan (every source) last covered all of
 *  `roots`, each root being a recorded root or lying under one (a sibling
 *  with a common prefix does not count); null when some root has none. The
 *  oldest of the roots' times, so the answer never claims more than the
 *  stalest root's. Pure. */
export function earlierScanAt(finished: ReadonlyMap<string, number>, roots: readonly string[]): number | null {
  if (roots.length === 0) return null;
  let oldest: number | null = null;
  for (const root of roots) {
    let best: number | null = null;
    for (const [done, at] of finished) {
      const holds = root === done || root.startsWith(done.endsWith("/") ? done : done + "/");
      if (holds && (best === null || at > best)) best = at;
    }
    if (best === null) return null;
    if (oldest === null || best < oldest) oldest = best;
  }
  return oldest;
}

/** `keptMcpValues` when the session keeps no MCP config. */
const EMPTY_KEPT_VALUES: ReadonlyMap<string, string | null> = new Map();

/** `discoverSecrets` with the confidentiality axis OFF: nothing to twin. */
const EMPTY_DISCOVERY: SecretDiscoveryReport = {
  files: [], skipped: [], counts: {} as SecretDiscoveryReport["counts"], limits: { maxDepth: 0, maxFiles: 0 }, truncated: false, depthAreas: [],
};

/** Plan 13 D2: a request's `flowsFrom`, validated (strings only, bounded:
 *  a malformed list is no flow, which only narrows what a holder may do,
 *  never widens it, since the guard decides who holds). */
function flowsFromOf(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((k): k is string => typeof k === "string" && k.length > 0 && k.length <= 64).slice(0, 256);
}

/** Plan 15 §13.12, "A cd that fails": could a shell `cd` into `dir` now?
 *  False only when the kernel says nothing is there (`ENOENT`, `ENOTDIR`)
 *  or what is there is not a directory (a `cd` to it fails); any other
 *  answer (a directory, a symlink to one, an error such as `EACCES`) is
 *  true, so the folder's own placement stands (fail-closed: its files are
 *  read there, and narrow nothing unless registered there). */
export function isDirectoryNow(dir: string): boolean {
  try {
    return statSync(dir).isDirectory();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code !== "ENOENT" && code !== "ENOTDIR";
  }
}

/** Plan 10 §11.13 (2026-10-17): of a path's match under the arbiter's own
 *  HOME (`own`) and under a launch's (`launch`), the stricter; `own` on a
 *  tie or with no launch match, so a launch HOME only ever adds places.
 *  Pure. */
export function stricterMatch<M extends { level: ConfidentialityLevel }>(own: M, launch: M | null): M {
  if (launch === null) return own;
  return maxConfidentiality(own.level, launch.level) !== own.level ? launch : own;
}

/** A HOME the human plane names (a launch's, a registration's): an
 *  absolute, normalized path of at most 4096 bytes, no control character,
 *  not `/` itself. Else null. Pure. */
export function attestedHomeOf(v: unknown): string | null {
  if (typeof v !== "string" || !v.startsWith("/") || v === "/" || Buffer.byteLength(v) > 4096) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) return null;
  const n = v.replace(/\/+$/, "");
  return n === "" || n.split("/").some((s, i) => i > 0 && (s === "" || s === "." || s === "..")) ? null : n;
}


/** The value-only release the classify op offers (backstop-value-only.md). */
type ArbiterServerValueOnly = { text: string; spans: ValueOnlySpan[] };

export class ArbiterServer {
  private readonly server: Server;
  private readonly socketPath: string;
  /** Admin channel state (see ArbiterServerOptions.adminFd / adminSocketPath). */
  private readonly adminFd?: number;
  private readonly adminSocketPath?: string;
  /** Human-plane channel (see ArbiterServerOptions.humanSocketPath). */
  private readonly humanSocketPath?: string;
  private humanServer: Server | null = null;
  private humanBoundInode: number | null = null;
  private adminSock: Socket | null = null;
  private adminServer: Server | null = null;
  /** Sessions that have classified at least once — `setSessionSpec` is
   *  bind-once and refuses to (re)bind a session past its first classify, so
   *  an agent cannot move its own live session onto a laxer spec. */
  private readonly classifiedSessions = new Set<string>();
  /** This server's session→spec bindings (`setSessionSpec`; tool-inbound.ts
   *  SessionSpecs): bind-once for the server's life, handed to every engine
   *  it builds (a policy reload keeps them) and to each session-keyed lookup
   *  it makes, cleared on close. Never the module's process registry, so two
   *  arbiters in one process cannot see or block each other's bindings. In
   *  memory, as before: a restart forgets them (the fallback over-symbolizes). */
  private readonly sessionSpecs: SessionSpecs;
  /** Rung 3 releases, per session: symbol → the value handed over. Read by
   *  {@link declassifyResultTrusted}. In memory: after a restart the tool
   *  result is masked again (utility lost, nothing leaked). */
  private readonly declassifyGrants = new Map<string, Map<string, string>>();
  /** The DevTools relay's refusals, per session, until the browser agent's
   *  next model call takes them (relay-notices.ts; devtools-relay.md §3.4).
   *  In memory: a restart loses a hint, nothing else. */
  private readonly relayNotices = new RelayNoticeQueue();
  /** The active secret rows as one matcher (confidentiality-plan-15 §4.1):
   *  the value backstop, the egress tripwire and the prompt filter all read
   *  it; it rebuilds itself when the symbol table changes. */
  private readonly valueIndex: RegisteredValueIndex;
  /** The upload scan's deadline and progress cadence (ms; `uploadScan`). */
  private readonly uploadScanPace: { deadlineMs: number; progressMs: number };
  /** The value-only release's residue scan, by the hash of its values. */
  private residue: { key: string; scanner: ResidueScanner } | null = null;
  /** folder-listing-compound.md L9: the (call, result hash) pairs a compound
   *  listing was offered for; a later classify of the same result is not
   *  compared with the folders again. Bounded: oldest first out. */
  private readonly compoundListings = new Set<string>();
  /** `sessionLoginExemptions`' answers by the session's wire value (a few
   *  sessions at a time; each asks with the same value on every scan). */
  private readonly sessionLoginMemo = new Map<string, readonly string[]>();
  /** `keptRowWireHost`'s answers by symbol name. */
  private readonly keptWireHostMemo = new Map<string, string | null>();
  /** `keptMcpValues`' last answer. */
  private keptMcpValuesMemo: { key: string; values: ReadonlyMap<string, string | null> } | null = null;
  /** Plan 10 §11.18: the bound on one value's pieces (`pieceLimits`). */
  private readonly pieceLimits: PieceLimits;
  /** Plan 10 §11.18: the labelled files a guard-reported raw read could not
   *  register because they are over the bound (`pieceLimits.scanChars`), by
   *  path, with the stamp (size, mtime, inode) they were seen at. Their
   *  pieces are unknown: the arbiter fails closed on them (`fileUnpieced`). */
  private readonly unpiecedFiles = new Map<string, string>();
  /** Plan 10 §11.14: the rows a symbolize named as an agent's whole result
   *  led by its runtime's own head (`resultHead`), by kind, whose head lines
   *  the value index does not fingerprint. Durable since 2026-10-09
   *  (`resultHeadStore`, bound to each row's value): loaded at start, so a
   *  restart keeps them. `resultHeadsVersion` moves when one is learned, so
   *  the index rebuilds. */
  private readonly headedRows: Map<string, ResultHeadKind>;
  private readonly resultHeadStore: ResultHeadStore;
  /** Plan 10 §11.15, case 2: the files registered on a guard-reported raw
   *  read, by path, with the size, mtime and inode last registered. */
  private readonly selfRegistered = new Map<string, string>();
  private resultHeadsVersion = 0;
  /** Plan 15 §4.1, "What a raised row registers": the rows secret only
   *  because the value backstop found a registered secret in them, by name,
   *  with the lines that held one (`learnRaisedRow`). The value index keeps
   *  only those of the row's long lines. Durable (`raisedRowStore`, bound to
   *  each row's value). `raisedRowsVersion` moves when one is learned. */
  private readonly raisedRows: Map<string, ReadonlySet<number>>;
  private readonly raisedRowStore: RaisedRowStore;
  /** Plan 15 §13.12: the durable marks of the path rows (`learnPathRow`). */
  private readonly pathRowStore: RaisedRowStore;
  private raisedRowsVersion = 0;
  /** Plan 15 §4.1: per call (`<session>\0<callId>`), what this arbiter's
   *  classify said of its result: `raised` when the value backstop raised a
   *  public verdict, `policySecret` when the policy itself called a result of
   *  the call secret (sticky). A symbolize narrows a row only for a call with
   *  `raised` and not `policySecret`. Memory only, bounded: a re-sent result
   *  is classified again before it is symbolized.
   *
   *  Plan 15 §13.12: `pathFiles` is set while every policy-secret classify of
   *  the call was the path rule's with each secret reading placed on a file
   *  (`ClassifyResult.namedFiles`, their union), and `pathLevel` is the
   *  highest such level; one classify secret by policy for any other reason
   *  (or with a reading not placed) clears it for good (`pathMixed`). */
  private readonly backstopCalls = new Map<string, BackstopCallRecord>();
  /** The `filterPrompt` op (plan 15 §3.2): filters, the phase-1 policy, the
   *  per-segment cache. Built in the constructor (it mints through dispatch). */
  private readonly promptFilter: PromptFilterEngine;
  /** Plan 15 §7 (phase 3): the Inbox hold and "let it through" over the
   *  engine's answer (holds.ts); rows live in `egressApprovals`. */
  private readonly promptHolds: PromptHolds;
  /** Plan 15 §4.2: the pack directories and keys, and what was loaded. */
  private readonly promptPackDirs: { user: string | null; admin: string | null; keys: string | null };
  private promptPacks: { sig: string; checkedAt: number; loaded: LoadedPacks; filters: Map<string, PromptFilter> } | null = null;
  /** Plan 15 §4.3: the plugins' pins, confinement and stats (kept across
   *  pack reloads, keyed by pack id). */
  private readonly plugins: {
    tools: ConfineTools;
    dir: string;
    pins: PluginPins;
    legs: () => Promise<ConfineLegs>;
    legsKnown: ConfineLegs | null;
    stats: Map<string, PluginStats>;
    run?: PluginProcessRunner;
  };
  private promptPolicyMemo: { doc: unknown; admin: unknown; packs: unknown; input: PromptPolicyInput } | null = null;
  private readonly twinPieceRowCache = new Map<string, boolean>();
  /** `outputRowTwin`'s memo: per output row, the registered files whose
   *  field placeholders its value carries (the length guards a value
   *  replaced under the same name). Bounded. */
  private readonly outputTwinPaths = new Map<string, { len: number; paths: string[] }>();
  /** egress-hold.md "One card per file": which request spent each *once*
   *  answer, and when (its `consumedAt`), so that request's other asks read
   *  it too. In memory: after a restart the request's next ask finds it
   *  spent and the card asks again (fail-closed). Bounded. */
  private readonly onceSpentBy = new Map<string, { requestId: string; consumedAt: number; at: number }>();
  /** Plan 10 §11.8, "A key listing": the registered files' paths
   *  (registry.ts `registeredFilePaths`), rebuilt when the symbol table
   *  changes; computed only for a result that already reads as a listing. */
  private keyListingPaths: { map: unknown; gen: number; size: number; paths: string[] } | null = null;
  /** `registeredTwinOfPath`'s memo (plan 10 §11.8, review of !1604). */
  private twinByPath: { map: unknown; gen: number; size: number; policy: unknown; labels: number; derived: number; homes: string; paths: Set<string>; twins: Map<string, { text: string; secrets: string[] } | null>; kinds: Map<string, NamedTwinKind | null> } | null = null;
  /** This arbiter's tenant (see ArbiterServerOptions.tenant); undefined = untenanted. */
  readonly tenant: Tenant | undefined;
  /** Sessions whose mismatched-tenant emits were already logged (one line per
   *  session, not one per event — a chatty harness must not flood the log). */
  private readonly tenantRefusalsLogged = new Set<string>();
  private readonly dbPath?: string;
  /** The engine-backed policy — REBUILT (not mutated) when the policy document
   *  changes (policy-document-store.ts → rebuildPolicy). */
  private policy: PolicyEngine;
  /** The policy file's store: reads, validated writes, hand-edit pickup (stage 5a). */
  private readonly policyDocs: PolicyDocumentStore;
  private readonly policyPathOpt?: string;
  /** Where the active policy came from (policy-surface.md §9.8 "law source") —
   * computed once at construction (policy load is once-at-start) and reported
   * verbatim by the policySnapshot op. Observability only. */
  private lawSource: PolicyLawSource;
  private readonly log: (msg: string) => void;
  /** Authoritative in-memory symbol table (backed by SQLite). */
  private symbolMap: SymbolMap;
  /** In-memory tool_use decisions, keyed by toolUseId. Recorded via the
   * recordToolCall op so OS interceptors can later correlate a syscall to a
   * known tool decision. NON-PERSISTENT: lost on restart (M-level scaffold). */
  private readonly toolCalls = new Map<string, ToolCallRecord>();
  /** Plan 15 §13.10: session → path → SHA-256 of each believed whole-content
   *  write's `content` (noteOwnWrite). */
  private readonly ownWriteHashes = new Map<string, Map<string, Set<string>>>();
  /** Append-only per-session observability event store + seq counter. */
  private readonly events: EventStore;
  private consumerPacks: LoadedPack[] = [];
  private consumerPackErrors: string[] = [];
  /** Retention sweep (ArbiterServerOptions.eventRetentionMs); 0 = off. */
  private readonly eventRetentionMs: number;
  private readonly eventRetentionSweepMs: number;
  private retentionTimer: NodeJS.Timeout | null = null;
  /** Plan 12 D5: the administrator's directory, its last signature, the
   *  re-read poll, and the problems of a re-read that was refused. */
  private readonly adminDir: string | null;
  private adminSig = "";
  private adminTimer: NodeJS.Timeout | null = null;
  private adminRefused: string[] = [];
  /** An engine passed in (`opts.policy`): nothing of the law is rebuilt here. */
  private readonly injectedPolicy: boolean;
  /** Backstop that collapses runaway identical-event bursts before they reach the
   *  store (undefined when coalesceEvents is false). */
  private readonly coalescer?: EmitCoalescer;
  /** Interactive egress-approval queue: NETWORK egress decisions that require
   * human approval upsert a PENDING entry here; a human verdict (approve/deny)
   * is consulted on the next attempt for the same {symbol, destination}.
   * SQLite-backed (the arbiter's symbol DB) so the queue — the arbiter's only
   * human-decision state — survives a restart. Constructed in the ctor body
   * because it needs the resolved dbPath. */
  private readonly egressApprovals: EgressApprovalStore;
  /** Pending questions this process retired because no answer could make
   *  them take effect (`retireMootQuestions`), id → the reason, so an answer
   *  from a stale page is refused with it rather than "unknown id". In
   *  memory only: after a restart the id is unknown, and never reused
   *  (egress-approvals.ts, IDS ARE NEVER REUSED). */
  private readonly retiredQuestions = new Map<string, string>();
  /** Proposals + the change log of the policy agent surface (same DB file). */
  private readonly policyProposals: PolicyProposalStore;
  private readonly policyAgent: PolicyAgentOps;
  /** Plan 14's suggestions (policy-suggestion-ops.ts): rows of the same
   *  proposals table, filed only by this arbiter's own scan. */
  private readonly policySuggestions: PolicySuggestionOps;
  /** Plan 14 §14.2-§14.4: the names-only model's preview and send. */
  private readonly policyModel: PolicyModelOps;
  /** SIEM-triggered lockdown posture (siem-integration.md §4.3, scenario D). A
   *  Wazuh active-response callback can TIGHTEN this (via `setSessionPosture`),
   *  and the human-driven dashboard route can RELAX it (same op with the explicit
   *  `allowRelax` flag — policy-surface.md §9.8.6); the egress gate consults it
   *  to force every network egress to human approval. In memory — a fresh arbiter
   *  starts at `normal` (documented; persistence is a follow-up). */
  private readonly sessionPosture = new SessionPostureStore();

  /** Proxy↔execve correlation memory (exec-routing.md §4 step 1): the model
   * proxy's execGate verdict, keyed by command signature, for the exec supervisor
   * to consult. In-memory + bounded (a within-run best-effort hint). */
  private readonly execDecisions = new ExecDecisionStore();
  /** Per-invocation exec CLEAN verdicts (exec-routing.md §8.4 rung 2 / §5),
   * keyed by tool_use callId; the classify op consumes them hash-bound. The
   * taint oracle is the arbiter's OWN provenance registry (deferred closure —
   * `provenance` is assigned in the constructor), so a supervisor can never
   * vouch for its parent's lineage. */
  private readonly execCleanVerdicts = new ExecCleanVerdictStore({
    isProcessTainted: (procKey) => this.provenance.isProcessTainted(procKey).tainted,
  });
  /** Who may report a CLEAN verdict (exec-routing.md §8.5.3): the session's
   * guard, by the token it claimed before its agent started. In memory only. */
  private readonly cleanReporters = new CleanReporters();
  /** Box→proxy symbol-twin hints (symbol-twin-shell-blindness.md §4.1 v2):
   * the paths a boxed AgentShell leaf named whose AgentView twin is solely
   * symbol tokens, signature-keyed + recency-bounded. A HINT the proxy
   * re-verifies under its own roots — never a verdict. */
  private readonly execTwins = new ExecTwinStore();
  /** Provenance/taint registry — tracks process and file taint, lives in the
   * same SQLite DB file as symbols. */
  private readonly provenance: ProvenanceStore;
  /** Plan 10 §11.13: per session, the stdio MCP servers the launcher read
   *  from the agent's config (registerMcpServers, human plane). In memory: an
   *  arbiter restart forgets them, and every server is then unmapped. */
  private readonly mcpServersBySession = new Map<string, Array<{ name: string; command: string; args: string[] }>>();
  /** Plan 10 §11.17: per session, the config files the launcher's latest
   *  read consulted and the stamp each had then (registerMcpServers
   *  `sources`). A file whose stamp moved since keeps every server of the
   *  session from `clean` until the launcher's re-read lands. */
  private readonly mcpSourcesBySession = new Map<string, Array<{ path: string; stamp: string }>>();
  /** mapped-tools.ts GUARD_MAPPED_TOOLS: the launches (beginLaunch token →
   *  session) that claimed posture `confined` on an attested channel. In
   *  memory: after an arbiter restart no session is guarded until its next
   *  launch (fail-closed: the guard-only tools are masked). */
  private readonly guardedLaunches = new Map<string, string>();
  /** Sessions any launch claimed WITHOUT the guard (or on an unattested
   *  channel): never guarded again in this arbiter's run. */
  private readonly unguardedSessions = new Set<string>();
  /** Plan 10 §11.13 (2026-10-17): each live launch's HOME (beginLaunch
   *  token → its session and HOME), recorded only from an attested
   *  `beginLaunch`. `decideSecretOpen` judges an open of that session
   *  against the catalog's `~` places of this HOME as well as the arbiter's
   *  own; never from the data socket. In memory: after a restart a session
   *  is judged by the arbiter's HOME alone until its next launch (the twin
   *  for a file only the launch HOME's catalog names: fail-safe). */
  private readonly launchHomes = new Map<string, { session: string; home: string }>();
  /** Plan 10 §11.13 (2026-10-17): the HOMEs a registration on the human
   *  plane named (`registerSecret.home`: the launcher's), bounded. With the
   *  live launches' HOMEs they are the places whose catalog may vouch for a
   *  config's own text (registry.ts `isOwnTextTwin`). */
  private readonly registrationHomes = new Set<string>();
  /** `isOwnTextRow`'s memo (the value backstop), until the symbol table,
   *  the label law or the named HOMEs change. */
  private ownTextRowCache: { key: string; policy: unknown; rows: Map<string, boolean> } | null = null;
  /** `documentNameRows`' memo (secret-discovery.md §2.7, "A person's
   *  name"), until the symbol table, the label law or the labels change. */
  private documentNameRowCache: { key: string; policy: unknown; rows: Set<string> } | null = null;

  /** Does the file guard confine `session`'s agent? Only on an attested
   *  `confined` launch record of that session, none without the guard, and
   *  the human plane not exposed now (an unwalled launch's programs could
   *  forge a record). Anything else, including no session: false. */
  private sessionGuarded(session: string | undefined): boolean {
    if (session === undefined || session === "" || this.unguardedSessions.has(session)) return false;
    if (![...this.guardedLaunches.values()].includes(session)) return false;
    return this.humanPlaneExposure().length === 0;
  }

  /** Plan 10 §11.18: why `tool` has a mapping in `session`, or null when it
   *  has none (its result is then masked whole). */
  private toolMappingFor(tool: string, session: string | undefined): ToolMapping | null {
    const specId = resolveInboundSpecId(session, this.sessionSpecs);
    return toolMapping(tool, {
      specNames: (t) => inboundSpecNamesInput(t, session, this.sessionSpecs),
      specId,
      surfaceNames: (t) => surfaceNamesTool(gateSurfaceFor(session, this.sessionSpecs), t),
      registeredMcp: (t) => session !== undefined && (this.mcpServersBySession.get(session) ?? []).some((sv) => mcpToolPrefixes(sv.name).some((p) => t.startsWith(p))),
      mappedTools: getCurrentPolicy().mappedTools,
      // asked only for a guard-only tool (the exposure check reaps launches)
      guarded: requiresGuard(tool, specId) && this.sessionGuarded(session),
    });
  }
  /** Plan 10 §11.13.1: the sessions whose egress proxy inspects TLS
   *  (registerWireRelease, human plane). In memory, and in mandu.db for the
   *  launcher that said it: a restart takes back the sessions whose launcher
   *  still runs (wire-release-sessions.ts), never an ended launch's.
   *  Constructed in the ctor body (it needs the resolved dbPath). */
  private readonly wireReleaseSessions: WireReleaseStore;
  /** Agent-sign-in.md §3: which field of an agent's own key file
   *  authenticates to which host (registerAuthGrant, human plane). In
   *  memory, and in mandu.db for the launcher that made it: a restart takes
   *  back the grants of the launchers still alive (auth-grants.ts), never
   *  those of an ended launch (fail-closed). Constructed in the ctor body
   *  (it needs the resolved dbPath). */
  private readonly authGrants: AuthGrantStore;
  private readonly fieldGrants = (origin: string, field: string): string[] => this.authGrants.hosts(origin, field);
  /** The SESSION high-watermark + untrusted-taint (Plan 8, §4/§9 rule 2). The
   * only enforceable meaning of `model-ok` AFTER an in-context read: a paraphrase
   * carries no symbol, so the per-symbol egress gate is blind to it and only
   * session confinement can catch it. */
  private readonly sessionLabels: SessionLabelStore;
  /** Sessions whose kernel guard announced itself (`guardAttach`, human
   *  plane): a HIGH session's allowed command runs held there
   *  (confidentiality.md §4). Memory only: a restart forgets, and a card then
   *  understates the confinement, never overstates it. */
  private readonly guardedSessions = new Set<string>();
  /** The sources of each multi-input derived row (symbol-sources.ts), read
   *  by the bindings sync (current-bindings.ts rule 2). */
  private readonly symbolSources: SymbolSourceStore;
  /** The tool-call ids whose result body a model proxy forwarded in clear
   *  (forwarded-clear.ts): the after-the-fact note across a resume
   *  (confidentiality.md §7.1). */
  private readonly forwardedClear: ForwardedClearStore;
  private readonly forwardedPlaceholders: ForwardedPlaceholderStore;
  /** The wire host each masked environment variable's own value named at
   *  its DATA-plane registration in this process (registry.ts `wireHost`):
   *  the row keeps no URL, and the bindings sync (rule 3) keeps this host.
   *  A human-plane registration records it in `wire_grants` instead, which
   *  survives a restart (confidentiality.md §2.1). */
  private readonly envWireHosts = new Map<string, string>();
  /** Each session's main-model binding (plan 11 phase 3); same DB file. */
  private readonly sessionUpstreams: SessionUpstreamStore;
  /** Each session's reply-filter relay state (reply-row-reservation.md §3.6).
   *  In memory: after a restart it reads null ⇒ no expansion until the filter
   *  reports again. */
  private readonly sessionRelays = new SessionRelayStore();
  /** Reserve blocks the proxy expanded, per session (reply-row-reservation.md §3.8). */
  private readonly reserveBlocks = new ReserveBlockStore();
  /** The USER labeling store (Plan 6, confidentiality.md §6) — the ONLY producer
   * of `any-model` in the system. The default-secret catalog yields just
   * public/strict by design, so without this a `model-ok` datum cannot exist.
   * Lives in the same SQLite DB file as symbols. */
  private readonly pathLabels: PathLabelStore;
  /** The machine-minted taint records: files a HIGH session wrote (Plan 9, §8). */
  private readonly derivedLabels: DerivedLabelStore;
  /** A live session's machine labels on exact paths (session-path-labels.ts):
   *  `no-model`, in memory only, listed in the derived index's sequence. */
  private readonly sessionPathLabels = new SessionPathLabelStore();
  /** The catalog's content tier (found-labels.ts, secret-discovery.md
   *  §2.6): config files a walk read and found a credential in. */
  private readonly foundLabels: FoundLabelStore;
  /** The `discoverSecrets` thread (runtime-instances.md §14.2 item 7); `close` stops it. */
  private readonly discoveryWorker = new DiscoveryWorker({
    onFallback: (why) => this.log(`discoverSecrets: ${why}; walking in-process`),
  });
  private readonly warmDiscoveryWorker: boolean;
  /** `scanSecretHistory` (secret-discovery.md §3): the seams a test injects,
   *  and whether a scan runs now (one at a time). */
  private readonly historyScanOpts: HistoryScanOptions;
  private readonly historyScanCache: HistoryScanCache | undefined;
  private historyScanRunning = false;
  /** `scanAgentTranscripts`: one scan at a time (plan 17). */
  private transcriptScanRunning = false;
  /** The workspace scan (plan 14 §13): its seams, and what it read, in
   *  memory only (never on disk; at most WORKSPACE_CACHE_MAX files). It runs
   *  under `historyScanRunning` too: one scan job at a time. */
  private readonly workspaceScanOpts: WorkspaceScanSeams;
  private readonly workspaceScanCache = new WorkspaceScanCache();
  /** Plan 14 §14.1: the label read's cache (in memory; label ids only). */
  private readonly labelScanCache = new WorkspaceScanCache<LabelCacheEntry>();
  /** Plan 14 §11.1: the known-repository registry and the background lock
   *  resolution; null with the axis OFF or `lockResolution: null`. */
  private readonly lockResolver: LockResolver | null;
  /** Plan 14 §11.1 R3: the copies prepared ahead of time; null when off. */
  private readonly preparedCopies: PreparedCopies | null;
  /** Plan 14 §11.2: the seals every enforcement cache is trusted by, the
   *  epoch that voids them, and the unconfined launches that hold them void
   *  (policy/cache-seals.ts). Same DB file. */
  private readonly cacheSeals: CacheSealStore;
  /** {@link humanPlaneExposure}'s memo (`at` 0: stale, re-read on the next
   *  ask; the launches stay, so a change is still told once). */
  private exposureMemo: { at: number; launches: LiveLaunch[] } | null = null;
  /** When the current exposure was first seen (ms); null while walled. */
  private exposedSince: number | null = null;
  /** While exposed, re-reads the exposure each second so its end (a launcher
   *  found gone) is told even when nobody asks. Unref'd. */
  private exposureTimer: ReturnType<typeof setInterval> | null = null;
  /** listen() was refused (another arbiter owns the DB, or the start
   *  failed): close() then records no clean shutdown for the owner's run. */
  private startRefused = false;
  /** Live subscribers per session: sessionId → set of push callbacks. Populated
   * by `subscribe` connections, drained on their socket close, invoked by
   * `emit`. The fan-out is best-effort: a throwing subscriber is dropped. */
  private readonly subscribers = new Map<string, Set<Subscriber>>();
  /** Inode of the socket file we bound in listen(); close() only unlinks the
   *  path while it is STILL this inode, so a dying instance never deletes a
   *  successor arbiter's socket (which would `connect ENOENT` every client). */
  private boundInode: number | null = null;
  /** Single-writer ownership of the symbol DB (db-owner.ts) — acquired in
   *  listen() (an ACTIVE writer, not a mere construction), released in
   *  close(). A second arbiter on the same DB refuses loudly at startup
   *  instead of silently interleaving writes. */
  private dbOwner: SymbolDbOwner | null = null;
  /** Every ESTABLISHED connection. Node's `Server.close()` stops the listener
   *  but resolves only once every open connection has ended on its own — so a
   *  single live client (a proxy's ArbiterClient, a dashboard subscribe stream)
   *  makes `await close()` hang forever, never releasing the DB handles or
   *  unlinking the socket. We track the sockets so close() can END them. */
  private readonly conns = new Set<Socket>();
  /** Runtime identity for the `hello` handshake (nogit defaults for tests). */
  private readonly identity: { instanceId: string | null; gitRev: string; gitDirty: boolean; version?: string | null; build?: BuildIdentity | null };
  /** ISO start time reported by `hello`. */
  private readonly startedAt = new Date().toISOString();
  /** Confidentiality-axis switch (confidentiality.md §11). Read once at
   * construction; every confidentiality behavior in this server guards on it. */
  private readonly confidentiality: boolean;
  /** Integrity-axis switch (policy/integrity-flag.ts). Read once at
   * construction; threaded to the policy engine (the classify collapse point)
   * and the handling-prompt builder. Default ON. */
  private readonly integrity: boolean;

  constructor(opts: ArbiterServerOptions) {
    this.socketPath = opts.socketPath;
    this.sessionSpecs = opts.sessionSpecs ?? new SessionSpecs();
    this.pieceLimits = { ...DEFAULT_PIECE_LIMITS, ...(opts.pieceLimits ?? {}) };
    this.valueIndex = new RegisteredValueIndex({ pieceLimits: this.pieceLimits });
    this.uploadScanPace = {
      deadlineMs: opts.uploadScan?.deadlineMs ?? FILE_UPLOAD_SCAN_DEADLINE_MS,
      progressMs: opts.uploadScan?.progressMs ?? FILE_UPLOAD_PROGRESS_MS,
    };
    this.adminFd = opts.adminFd;
    this.adminSocketPath = opts.adminSocketPath;
    this.humanSocketPath = opts.humanSocketPath;
    this.tenant = opts.tenant ?? tenantFromEnv();
    this.dbPath = opts.dbPath;
    this.confidentiality = opts.confidentiality ?? resolveConfidentialityEnabled();
    this.integrity = opts.integrity ?? resolveIntegrityEnabled();
    this.identity = opts.identity ?? { instanceId: null, gitRev: "nogit", gitDirty: false };
    this.events = new EventStore(opts.eventDir);
    this.eventRetentionMs = opts.eventRetentionMs && opts.eventRetentionMs > 0 ? opts.eventRetentionMs : 0;
    this.eventRetentionSweepMs = opts.eventRetentionSweepMs ?? 60 * 60 * 1000;
    this.coalescer = (opts.coalesceEvents ?? true) ? new EmitCoalescer() : undefined;
    this.log = opts.log ?? ((m) => console.error(`[arbiter] ${m}`));
    this.warmDiscoveryWorker = opts.warmDiscoveryWorker ?? false;
    this.historyScanOpts = opts.historyScan ?? { limits: historyLimitsFromEnv(process.env) };
    this.workspaceScanOpts = opts.workspaceScan ?? { limits: workspaceLimitsFromEnv(process.env) };
    // Plan 14 §11.2: the enforcement caches' seals and epochs, in mandu.db.
    // Opened (the start-time rules) at listen, or lazily by the first use.
    this.cacheSeals = new CacheSealStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
      confidentiality: this.confidentiality,
      onRotate: (e) => {
        if (e.reason !== "first start") this.emitCacheSealEvent("rotated", e.reason, []);
        // Plan 14 §11.1 R3: the prepared copies' seals are void; they are
        // sealed again (or rebuilt) once no unconfined period is live.
        this.preparedCopies?.voided();
      },
    });
    {
      const dir = opts.historyScanCacheDir === undefined
        ? defaultHistoryCacheDir(process.env, process.env.HOME || homedir())
        : opts.historyScanCacheDir;
      this.historyScanCache = dir === null ? undefined : fileHistoryScanCache(dir, {
        seals: sealGate(this.cacheSeals, (r) => this.emitCacheSealEvent("rejected", "a cache entry did not match a seal of the current epoch", [r])),
      });
    }
    // Signed consumer packs (comparisons.md §3.3): only from the user's
    // config directory (the path table's `packs` and `pack-keys`), only under
    // a trusted key; a pack adds rows, never overrides a built-in one.
    {
      const dflt = defaultPackDirs(process.env, process.env.HOME || homedir());
      const packDir = opts.packDir === undefined ? dflt.packDir : opts.packDir;
      const { packs, errors } = packDir === null ? { packs: [], errors: [] } : loadConsumerPacks(packDir, opts.packKeysDir ?? dflt.keysDir);
      this.consumerPacks = packs;
      this.consumerPackErrors = errors;
      setPackConsumers(packs.flatMap((p) => p.consumers));
      for (const p of packs) this.log(`consumer pack: ${p.name} ${p.version} (key ${p.keyId}, ${p.consumers.length} consumer${p.consumers.length === 1 ? "" : "s"})`);
      for (const e of errors) this.log(`consumer pack REFUSED: ${e}`);
    }
    // Plan 13 D8, the !437 leftover (2): the hashes of this host's printers
    // and code-running programs, so a copy of one under another name is one
    // (`hashPrints`, `hashRunsCode`).
    refreshProgramHashes({ minIntervalMs: 0 });
    // Hydrate the symbol table from disk so a restart keeps prior symbols.
    // Loaded BEFORE the policy so the egress gate's symbolLookup can close over
    // the live in-memory SymbolMap (it follows allocations made after startup).
    this.symbolMap = loadSymbolMap(this.dbPath);
    // Egress-approval queue persists to the SAME file as the symbol table (the
    // arbiter is single-writer). Resolve the default path explicitly so the store
    // always has a concrete file, matching what loadSymbolMap/allocateSymbol use.
    this.egressApprovals = new EgressApprovalStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    // The !437 leftover (4), made durable: a pending question an older
    // arbiter filed that no answer can make take effect leaves the store
    // now (the host's printers were hashed above), not only every listing.
    this.retireMootQuestions();
    // Provenance/taint registry — tables live in the same DB file as symbols.
    this.provenance = new ProvenanceStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    // User labels — same DB file. Constructed BEFORE the policy so the
    // confidentiality derivation can close over the live store.
    this.pathLabels = new PathLabelStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    this.sessionLabels = new SessionLabelStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    this.symbolSources = new SymbolSourceStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    this.forwardedClear = new ForwardedClearStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    this.forwardedPlaceholders = new ForwardedPlaceholderStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    // Plan 10 §11.14: the result-head marks, kept across a restart.
    this.resultHeadStore = new ResultHeadStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    this.headedRows = this.resultHeadStore.load(this.symbolMap);
    this.raisedRowStore = new RaisedRowStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    this.raisedRows = this.raisedRowStore.load(this.symbolMap);
    // Plan 15 §13.12: the path rows' marks, in the same map (a row is one
    // kind or the other: each learner returns on a row already marked).
    this.pathRowStore = new RaisedRowStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
      kind: "path",
    });
    for (const [n, keep] of this.pathRowStore.load(this.symbolMap)) if (!this.raisedRows.has(n)) this.raisedRows.set(n, keep);
    this.sessionUpstreams = new SessionUpstreamStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    // Agent-sign-in.md §3.2 item 4: the auth grants of live launchers,
    // taken back across a restart (the first bindings sync applies them).
    this.authGrants = new AuthGrantStore({ dbPath: this.dbPath ?? getSymbolDbPath() });
    if (this.authGrants.restored > 0) this.log(`auth grants: ${this.authGrants.restored} taken back from live launches (agent-sign-in.md §3.2)`);
    // Plan 10 §11.13.1: the sessions whose proxy inspects TLS, of live launchers.
    this.wireReleaseSessions = new WireReleaseStore({ dbPath: this.dbPath ?? getSymbolDbPath() });
    if (this.wireReleaseSessions.restored > 0) this.log(`wire release: ${this.wireReleaseSessions.restored} session(s) taken back from live launches (plan 10 §11.13.1)`);
    // Derived labels (Plan 9) — the files a HIGH session wrote. Same DB file, and
    // constructed here for the same reason: the confidentiality derivation closes
    // over the live store.
    this.derivedLabels = new DerivedLabelStore({
      dbPath: this.dbPath ?? getSymbolDbPath(),
    });
    // The content tier's found labels (found-labels.ts): the same DB file,
    // so a restart keeps a found config file labelled.
    this.foundLabels = new FoundLabelStore({ dbPath: this.dbPath ?? getSymbolDbPath() });
    // Plan 12 D5: the administrator's layer is in force before the user's
    // document is read or compiled (a layer that cannot be used throws: no start).
    this.injectedPolicy = !!opts.policy;
    this.adminDir = opts.adminPolicyDir === undefined ? ADMIN_POLICY_DIR : opts.adminPolicyDir;
    this.adminSig = adminLayerSignature(this.adminDir);
    installAdminLayer(this.adminDir);
    this.ruleHits = new RuleHitStore({ dbPath: this.dbPath ?? getSymbolDbPath() });
    this.policyProposals = new PolicyProposalStore({ dbPath: this.dbPath ?? getSymbolDbPath() });
    this.policyPathOpt = opts.policyPath;
    // The policy FILE store (stage 5a): the dashboard's writes and hand edits
    // both flow through it into rebuildPolicy. An injected engine or an
    // in-memory document has no file → reads work, writes are refused.
    const fileBacked = !opts.policy && opts.policyDocument === undefined && !!opts.policyPath;
    // policy-restore.ts: before the file is loaded as the law, content a human
    // DECLINED is written back to the content in force (persisted in
    // mandu.db), and content still waiting for a human stays held (the
    // persisted content is the law until they decide).
    const atStart = fileBacked
      ? reconcilePolicyFileAtStart({
        path: opts.policyPath as string,
        enforced: this.policyProposals.enforcedPolicy(opts.policyPath as string),
        diskRows: this.policyProposals.listProposals(),
      })
      : null;
    if (atStart?.note) this.log(atStart.note);
    // The file that is the law at start must validate here too, not only in
    // server-main: an embedder that skipped that check could hold a law no
    // daemon would start with (a `local: true` entry naming a cloud model),
    // and every edit judged against it would then fail validation, so every
    // policy suggestion was dropped as invalid (plan 14 §14.12).
    if (fileBacked && !atStart?.inForce) loadPolicyFileStrict(opts.policyPath as string);
    const startLaw = atStart?.inForce ? parseEnforcedAtStart(opts.policyPath as string, atStart.inForce) : undefined;
    this.policy = opts.policy ?? this.buildPolicy(startLaw !== undefined ? startLaw : opts.policyDocument);
    // An INJECTED engine is one the server did not load — vouch for nothing
    // beyond "custom"; otherwise describe the same policyPath the engine-backed
    // policy consumed (basePath mirrors createEngineBackedPolicy's cwd default).
    this.lawSource = opts.policy
      ? { kind: "custom" }
      : opts.policyDocument !== undefined
        ? { kind: "custom" }
        : describeLawSource(opts.policyPath, process.cwd());
    this.policyDocs = new PolicyDocumentStore(
      {
        path: fileBacked ? (opts.policyPath as string) : null,
        rebuild: (doc) => this.rebuildPolicy(doc),
        audit: (change, docs) => {
          this.emitPolicyChange(change);
          this.recordOutsideChange(change, docs);
        },
        log: (m) => this.log(m),
        pollMs: fileBacked ? (opts.policyPollMs ?? 2000) : 0,
        persistEnforced: (e) => this.policyProposals.recordEnforced(opts.policyPath as string, e),
      },
      {
        document: getCurrentPolicy().document,
        found: atStart?.inForce ? atStart.inForce.text !== null : this.lawSource.kind === "file",
        inForce: atStart?.inForce ?? null,
        declined: atStart?.declined ?? [],
      },
    );
    if (atStart?.restored) {
      this.emitPolicyChange({ via: "restore", requestedBy: "arbiter", summary: atStart.note ?? "policy.yaml was restored to the law in force at start" });
    }
    // Plan 12 D5: name the user's entries the administrator's layer keeps out
    // of force, and re-read the layer when a file in it changes (the policy
    // file's own interval; an injected engine has no document to rebuild).
    this.logAdminConflicts();
    const adminPollMs = opts.policy ? 0 : (opts.policyPollMs ?? 2000);
    if (adminPollMs > 0 && this.adminDir !== null) {
      this.adminTimer = setInterval(() => this.pollAdminLayer(), adminPollMs);
      this.adminTimer.unref();
    }
    {
      const dflt = defaultPackDirs(process.env, process.env.HOME || homedir());
      this.promptPackDirs = {
        user: opts.promptPackDir === undefined ? manduPath("prompt-filters", process.env, process.env.HOME || homedir()) : opts.promptPackDir,
        admin: opts.adminPromptPackDir === undefined ? ADMIN_PROMPT_PACK_DIR : opts.adminPromptPackDir,
        keys: opts.packKeysDir ?? dflt.keysDir,
      };
    }
    {
      const pp = opts.promptPlugins ?? {};
      const tools: ConfineTools = { netGuard: pp.netGuard ?? null, landlockApply: pp.landlockApply ?? null, bwrap: pp.bwrap ?? null };
      const dir = pp.dir ?? join(dirname(this.dbPath ?? getSymbolDbPath()), "prompt-plugins");
      const probe = pp.probe ?? memoProbe(tools, dir);
      const plugins: ArbiterServer["plugins"] = {
        tools, dir, pins: new PluginPins(join(dir, "pinned")), legsKnown: null, stats: new Map(),
        legs: async () => {
          mkdirSync(dir, { recursive: true, mode: 0o700 });
          const l = await probe();
          if (plugins.legsKnown === null) for (const n of l.notes) this.log(`prompt filter plugins: ${n}`);
          plugins.legsKnown = l;
          return l;
        },
        ...(pp.run ? { run: pp.run } : {}),
      };
      this.plugins = plugins;
    }
    this.promptFilter = new PromptFilterEngine({
      filters: [new RegisteredValueFilter({
        index: () => this.syncedValueIndex(),
        rowLevel: (symbol) => this.backstopRowLevel(symbol, new Map()),
      }), new KeyShapesFilter()],
      policy: () => this.promptPolicyInput(),
      enforcing: () => this.confidentiality,
      mint: (value, level, origin, session) => this.mintPromptSymbol(value, level, origin, session),
      values: () => {
        const idx = this.syncedValueIndex();
        return { version: idx.contentVersion, digest: idx.digest };
      },
      ownWrites: (session) => this.promptOwnWrites(session),
    });
    {
      const env = Number(process.env["MANDU_PROMPT_HOLD_MS"]);
      this.promptHolds = new PromptHolds({
        approvals: this.egressApprovals,
        dbPath: this.dbPath ?? getSymbolDbPath(),
        timeoutMs: opts.promptHoldMs ?? (Number.isFinite(env) && env > 0 ? env : DEFAULT_PROMPT_HOLD_MS),
        log: (m) => this.log(m),
      });
    }
    this.policySuggestions = new PolicySuggestionOps({
      docs: this.policyDocs,
      proposals: this.policyProposals,
      // The labels in force, mandu.db's included: a path labelled only
      // there is covered, never suggested again.
      pathLabels: () => this.humanLabels(),
      emit: (e) => this.emitSuggestionEvent(e),
      // Plan 14 §14.1: the walk's coverage check, again at apply time for a
      // label lock below no-model (it must not override a protection).
      protectedNow: (p) => {
        const m = pathConfidentiality(p, undefined, this.labelLookup);
        return m.rule !== null && isSecret(m.level);
      },
    });
    this.policyModel = new PolicyModelOps({
      classifier: opts.policyClassifier ?? null,
      ...(opts.policyModel ?? {}),
      walk: (roots, home, includeHome, o) => this.runModelWalk(roots, home, includeHome, o?.documents === true),
      labelledAbovePublic: (p, home) => {
        const l = resolvePathLabel(p, this.humanLabels(), home || undefined);
        return l !== null && l.level !== "public";
      },
      registeredValueHit: (text) => this.secretValueHits(text).length > 0,
      models: () => getCurrentPolicy().models,
      law: () => ({ specId: getCurrentPolicy().specId, document: this.policyDocs.document, pathLabels: this.humanLabels() }),
      suggestions: this.policySuggestions,
      emitCall: (e) => this.emitPolicyModelCall(e),
      log: (m) => this.log(m),
    });
    this.policyAgent = new PolicyAgentOps({
      docs: this.policyDocs,
      proposals: this.policyProposals,
      resolveSuggestion: (id, verdict, by) => this.policySuggestions.resolve(id, verdict, by),
      // A prompt hold (plan 15 §7) is no network destination.
      pendingAsks: () => this.listApprovals({ status: "pending" }).filter((a) => !a.symbol.startsWith("prompt:")).map((a) => ({ destination: a.destination, count: a.count })),
      dbLabels: () => this.pathLabels.list(),
      ruleHits: () => this.ruleHits.all(),
      hostOf: hostOfDestination,
    });
    // Secret-file labels that live ONLY in the DB (dashboard acts) are still
    // effective (the lookup composes both), but the DB is disposable by
    // decision (mandu.db, no back-compat) — say so once at boot so the
    // operator moves them into policy.yaml `paths:` (the `exportDbLabels`
    // admin op does it on request).
    const documentPaths = getCurrentPolicy().pathLabels;
    const dbOnly = this.pathLabels.list().filter((l) => !documentPaths.has(l.path));
    if (dbOnly.length > 0) {
      this.log(
        `${dbOnly.length} secret-file label(s) live only in mandu.db (${dbOnly.slice(0, 5).map((l) => l.path).join(", ")}` +
          `${dbOnly.length > 5 ? ", …" : ""}) — declare them under policy.yaml \`paths:\` to keep them across a DB reset`,
      );
    }
    // Plan 14 §11.1: the registry and the resolver share mandu.db. Its
    // labels are the ones `gitHistoryLocks` answers, so the launcher and the
    // resolver key a walk alike.
    const lr = opts.lockResolution;
    this.lockResolver = this.confidentiality && lr !== null
      ? new LockResolver({
        labels: () => this.historyLabelsWire(),
        blobLocks: () => this.blobLocksAbovePublic(),
        dbPath: this.dbPath ?? getSymbolDbPath(),
        home: lr?.home ?? (process.env.HOME || homedir()),
        log: (m) => this.log(m),
        ...(lr?.schedule ? { schedule: lr.schedule } : {}),
        ...(lr?.git ? { git: lr.git } : {}),
        ...(lr?.limits ? { limits: lr.limits } : {}),
        ...(lr?.walkLimits ? { walkLimits: lr.walkLimits } : {}),
        ...(lr?.registryLimits ? { registryLimits: lr.registryLimits } : {}),
        ...(lr?.selfDir !== undefined ? { selfDir: lr.selfDir } : {}),
        ...(lr?.platform !== undefined ? { platform: lr.platform } : {}),
        // Plan 14 §11.2: a row read back from mandu.db is used only under a
        // seal of the current epoch.
        seals: sealGate(this.cacheSeals, (r) => this.emitCacheSealEvent("rejected", "a lock resolution row did not match a seal of the current epoch", [r])),
        // Plan 14 §11.1 R3: the prepared copies follow every cycle.
        onCycle: () => this.preparedCopies?.kick(),
      })
      : null;
    const pc = opts.preparedCopies;
    this.preparedCopies = this.lockResolver !== null && pc !== undefined && pc !== null
      ? new PreparedCopies({
        cacheDir: pc.cacheDir,
        repos: () => this.lockResolver!.registry.list().map((r) => r.root),
        lockedSet: () => this.lockResolver!.snapshot().lockedSet,
        seals: this.cacheSeals,
        log: (m) => this.log(m),
        ...(pc.limits ? { limits: pc.limits } : {}),
        ...(pc.git ? { git: pc.git } : {}),
      })
      : null;
    this.server = createServer((sock) => this.onConnection(sock, "data"));
    // The label set the launches' walks already cover (D, 2026-10-17): only a
    // label added or raised from here on makes this arbiter walk its place.
    this.labelRootsSeen = this.confidentiality ? labelRootKeys(this.humanLabels()) : null;
  }

  /** The human labels as `gitHistoryLocks` answers them (plan 14 §8.3):
   *  every level, a pattern as compiled. */
  private historyLabelsWire(): GitHistoryLocksResult["labels"] {
    return [...this.humanLabels().values()].map((l) => ({
      path: l.path, level: l.confidentiality, recursive: l.recursive, ...(l.glob ? { glob: true as const } : {}),
    }));
  }

  /** policy.yaml `blobs:` above `public`, as ids. */
  private blobLocksAbovePublic(): string[] {
    return [...getCurrentPolicy().blobLocks.values()].filter((b) => b.level !== "public").map((b) => b.id);
  }

  /** Plan 14 §11.1, a test and in-process aid: run a resolution cycle now
   *  and wait for it (no-op when the resolver is off). */
  async resolveLocksNow(): Promise<void> {
    await this.lockResolver?.runCycle();
    await this.lockResolver?.idle();
  }

  /** Plan 14 §11.1 R3, a test and in-process aid: resolve, then prepare
   *  the copies, and wait for both (no-op when off). */
  async prepareCopiesNow(): Promise<void> {
    await this.resolveLocksNow();
    await this.preparedCopies?.runCycle();
    await this.preparedCopies?.idle();
  }

  /**
   * Bring up the admin channel(s) after the data socket is listening. The
   * inherited fd is wrapped as an already-connected socket (no dial); a
   * malformed fd is a deployment error and fails the start loudly rather than
   * leaving the human-decision ops unreachable in silence. The dev-only path
   * variant warns on every start.
   */
  private async attachAdminChannels(): Promise<void> {
    if (this.adminFd !== undefined) {
      let sock: Socket;
      try {
        sock = new Socket({ fd: this.adminFd, readable: true, writable: true });
      } catch (err) {
        throw new Error(`admin channel: fd ${this.adminFd} is not a usable socket (${(err as Error).message})`);
      }
      this.adminSock = sock;
      this.onConnection(sock, "admin");
      this.log(`admin channel: inherited fd ${this.adminFd}`);
    }
    if (this.adminSocketPath) {
      const path = this.adminSocketPath;
      assertSocketPathFits(path, "arbiter admin socket");
      const dir = dirname(path);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      if (existsSync(path)) {
        try { unlinkSync(path); } catch { /* ignore */ }
      }
      const srv = createServer((sock) => this.onConnection(sock, "admin"));
      await new Promise<void>((resolve, reject) => {
        srv.once("error", reject);
        srv.listen(path, () => {
          srv.off("error", reject);
          resolve();
        });
      });
      this.adminServer = srv;
      this.log(
        `admin channel: DEV-ONLY socket path ${path} — a path is reachable by every same-uid process; ` +
          `never run an agent against this stack`,
      );
    }
  }

  /**
   * Bring up the human-plane socket (docs/design/architecture/arbiter-human-plane.md §3).
   * Its directory is the boundary's anchor, so it is checked, never trusted:
   * created 0700 when absent, and a directory that is a symlink, not ours, or
   * group/other-accessible refuses the start (fail closed — a human channel in
   * a directory someone else controls is not one). A LIVE listener at the
   * path is never stolen; a stale file is reclaimed.
   */
  private async attachHumanChannel(): Promise<void> {
    if (!this.humanSocketPath) return;
    const path = this.humanSocketPath;
    assertSocketPathFits(path, "arbiter human socket");
    ensurePrivateDir(dirname(path));
    if (existsSync(path)) {
      if (await socketIsLive(path)) {
        throw new Error(`a arbiter is already listening on the human socket ${path}; refusing to start a second instance`);
      }
      try { unlinkSync(path); } catch { /* ignore */ }
    }
    const srv = createServer((sock) => this.onConnection(sock, "human"));
    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(path, () => {
        srv.off("error", reject);
        resolve();
      });
    });
    try { chmodSync(path, 0o600); } catch { /* the 0700 dir is the boundary */ }
    try { this.humanBoundInode = statSync(path).ino; } catch { this.humanBoundInode = null; }
    this.humanServer = srv;
    this.log(`human channel: ${path}`);
  }

  /** Start listening. Removes a STALE socket file (no listener) first, but
   *  REFUSES to clobber a LIVE one — stealing the path would orphan the arbiter
   *  that is actually serving there and split clients across two instances. */
  async listen(): Promise<void> {
    // Before anything else: a path the kernel would shorten binds a name no
    // client looks for (socket-path.ts).
    assertSocketPathFits(this.socketPath, "arbiter socket");
    // Claim single-writer ownership of the symbol DB BEFORE binding: a second
    // arbiter on the same DB must refuse here, loudly, not serve half a stack.
    try {
      this.dbOwner = acquireSymbolDbOwner(this.dbPath ?? getSymbolDbPath());
    } catch (e) {
      this.startRefused = true;
      throw e;
    }
    try {
      // Plan 14 §11.2: the start-time epoch rules, once this arbiter owns
      // the DB (an unclean last shutdown voids every seal).
      this.cacheSeals.open();
      const dir = dirname(this.socketPath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      if (existsSync(this.socketPath)) {
        if (await socketIsLive(this.socketPath)) {
          throw new Error(
            `a arbiter is already listening on ${this.socketPath}; ` +
              `refusing to start a second instance (stop the running one first)`,
          );
        }
        // Stale socket from a crashed prior run (nothing is listening) → reclaim it.
        try { unlinkSync(this.socketPath); } catch { /* ignore */ }
      }
      // The human plane BEFORE the data socket: a client that waits for the
      // data socket and then asks `hello` must find `humanSock` already
      // answered (a launcher that read null would start its human-facing
      // children without it), and a human channel that cannot start refuses
      // the start before anything is served.
      await this.attachHumanChannel();
      await new Promise<void>((resolve, reject) => {
        this.server.once("error", reject);
        this.server.listen(this.socketPath, () => {
          this.server.off("error", reject);
          // Record the inode we bound so close() never unlinks a successor's socket.
          try { this.boundInode = statSync(this.socketPath).ino; } catch { this.boundInode = null; }
          this.log(`listening on ${this.socketPath}`);
          resolve();
        });
      });
      await this.attachAdminChannels();
      this.startRetentionSweep();
      if (this.warmDiscoveryWorker && this.confidentiality) this.discoveryWorker.warm();
      this.lockResolver?.start();
    } catch (e) {
      this.startRefused = true;
      // Never hold DB ownership without a serving socket: a failed bind must
      // leave the lock free for whoever IS serving (or the next attempt).
      this.dbOwner.release();
      this.dbOwner = null;
      // A later step (the admin or human channel) failed after the data
      // socket bound: stop serving it too, so a refused start never leaves a
      // half-stack (a data socket with no human plane) behind an embedder
      // that ignores the rejection.
      if (this.server.listening) {
        await new Promise<void>((resolve) => this.server.close(() => resolve()));
        if (this.boundInode !== null && existsSync(this.socketPath)) {
          try {
            if (statSync(this.socketPath).ino === this.boundInode) unlinkSync(this.socketPath);
          } catch { /* ignore */ }
        }
        this.boundInode = null;
      }
      if (this.humanServer) {
        const hs = this.humanServer;
        this.humanServer = null;
        await new Promise<void>((resolve) => hs.close(() => resolve()));
        if (this.humanSocketPath && this.humanBoundInode !== null && existsSync(this.humanSocketPath)) {
          try {
            if (statSync(this.humanSocketPath).ino === this.humanBoundInode) unlinkSync(this.humanSocketPath);
          } catch { /* ignore */ }
        }
        this.humanBoundInode = null;
      }
      throw e;
    }
  }

  /** Arm the observability retention sweep (no-op when retention is off):
   *  one pass now — a daemon that was down for weeks catches up at boot — and
   *  then every eventRetentionSweepMs. unref'd so it never holds the process
   *  open; close() clears it. */
  private startRetentionSweep(): void {
    if (this.eventRetentionMs <= 0 || this.retentionTimer) return;
    this.pruneStaleSessions();
    this.retentionTimer = setInterval(() => this.pruneStaleSessions(), this.eventRetentionSweepMs);
    this.retentionTimer.unref();
  }

  /**
   * Remove every session whose event log has been idle longer than the
   * configured retention (EventStore.staleSessions, by file mtime), through
   * the same removal path as the `deleteSession` op — so live subscribe
   * streams end with the file and a reused id starts fresh. OBSERVABILITY
   * ONLY: touches nothing on the security path (symbol table / policy /
   * approvals). Returns the removed ids; logs one line per sweep that
   * removed anything. Safe to call when retention is off (returns []).
   */
  pruneStaleSessions(now: number = Date.now()): string[] {
    if (this.eventRetentionMs <= 0) return [];
    const stale = this.events.staleSessions(this.eventRetentionMs, now, new Set([ADMIN_SESSION_ID]));
    const removed: string[] = [];
    for (const id of stale) {
      try {
        if (this.removeSession(id)) removed.push(id);
      } catch {
        // A traversal-shaped name on disk is not a session id; skip it.
      }
    }
    if (removed.length) {
      const days = Math.round(this.eventRetentionMs / 86_400_000);
      this.log(`retention: removed ${removed.length} session(s) idle > ${days}d: ${removed.join(", ")}`);
    }
    return removed;
  }

  /** The one removal path (the `deleteSession` op + the retention sweep):
   *  NDJSON file + store seq state (EventStore.delete), then any live subscribe
   *  streams on the id (their close handlers drain the map), the
   *  coalescer's run state and the relay state, so no in-memory tail lingers and a reused id
   *  starts completely fresh. false = no such session file. */
  private removeSession(sessionId: string): boolean {
    if (!this.events.delete(sessionId)) return false;
    const subs = this.subscribers.get(sessionId);
    if (subs) {
      for (const sub of [...subs]) {
        try { sub.end(); } catch { /* best-effort */ }
      }
      this.subscribers.delete(sessionId);
    }
    this.coalescer?.drop(sessionId);
    // Per-session relay state (reply-row-reservation.md §3.6): a reused id
    // starts with no relay report ⇒ no expansion until the filter reports.
    this.sessionRelays.delete(sessionId);
    this.reserveBlocks.delete(sessionId);
    return true;
  }

  /** Stop listening and remove the socket file — but ONLY if it is still the
   *  inode we bound. A newer arbiter may have replaced this path (rm + rebind);
   *  unlinking then would delete the LIVE successor's socket and `connect ENOENT`
   *  every client. */
  async close(): Promise<void> {
    this.closing = true;
    if (this.retentionTimer) {
      clearInterval(this.retentionTimer);
      this.retentionTimer = null;
    }
    if (this.adminTimer) {
      clearInterval(this.adminTimer);
      this.adminTimer = null;
    }
    this.stopExposureWatch();
    // Stop accepting FIRST, then tear down what is already established: with a
    // live connection open, server.close()'s callback would otherwise never
    // fire (see `conns`). Destroying the socket makes each client's `close`
    // handler reject its in-flight requests — which is the fail-closed answer,
    // the same one they get from a dead arbiter.
    const stopped = new Promise<void>((resolve) => this.server.close(() => resolve()));
    const adminStopped = this.adminServer
      ? new Promise<void>((resolve) => this.adminServer!.close(() => resolve()))
      : Promise.resolve();
    const humanStopped = this.humanServer
      ? new Promise<void>((resolve) => this.humanServer!.close(() => resolve()))
      : Promise.resolve();
    for (const sock of this.conns) {
      try { sock.destroy(); } catch { /* already gone */ }
    }
    this.conns.clear();
    // A label registration pass already walking ends first (bounded: one
    // label pass); one still queued sees `closing` and does nothing.
    try { await this.labelSync; } catch { /* logged where it failed */ }
    this.discoveryWorker.stop();
    try { await this.preparedCopies?.stop(); } catch { /* best effort */ }
    try { await this.lockResolver?.stop(); } catch { /* best effort */ }
    try { this.adminSock?.destroy(); } catch { /* already gone */ }
    this.adminSock = null;
    await stopped;
    await adminStopped;
    this.adminServer = null;
    await humanStopped;
    this.humanServer = null;
    // Same rule as the data socket: unlink only the inode WE bound.
    if (this.humanSocketPath && this.humanBoundInode !== null && existsSync(this.humanSocketPath)) {
      try {
        if (statSync(this.humanSocketPath).ino === this.humanBoundInode) unlinkSync(this.humanSocketPath);
      } catch { /* ignore */ }
    }
    this.humanBoundInode = null;
    if (this.adminSocketPath && existsSync(this.adminSocketPath)) {
      try { unlinkSync(this.adminSocketPath); } catch { /* ignore */ }
    }
    // Release the egress-approval queue's DB handle (its own WAL connection to
    // the arbiter DB file). Best-effort: a double-close must not throw.
    try { this.egressApprovals.close(); } catch { /* ignore */ }
    // Plan 14 §11.2: clean only with the axis on and no unconfined launch live.
    try { this.cacheSeals.markShutdown(!this.startRefused); } catch { /* ignore */ }
    try { this.provenance.close(); } catch { /* ignore */ }
    try { this.pathLabels.close(); } catch { /* ignore */ }
    try { this.sessionLabels.close(); } catch { /* ignore */ }
    try { this.symbolSources.close(); } catch { /* ignore */ }
    try { this.forwardedClear.close(); } catch { /* ignore */ }
    try { this.forwardedPlaceholders.close(); } catch { /* ignore */ }
    try { this.resultHeadStore.close(); } catch { /* ignore */ }
    try { this.raisedRowStore.close(); } catch { /* ignore */ }
    try { this.pathRowStore.close(); } catch { /* ignore */ }
    try { this.sessionUpstreams.close(); } catch { /* ignore */ }
    try { this.authGrants.close(); } catch { /* ignore */ }
    try { this.wireReleaseSessions.close(); } catch { /* ignore */ }
    try { this.derivedLabels.close(); } catch { /* ignore */ }
    try { this.foundLabels.close(); } catch { /* ignore */ }
    try { this.ruleHits.close(); } catch { /* ignore */ }
    try { this.policyProposals.close(); } catch { /* ignore */ }
    try { this.policyDocs.close(); } catch { /* ignore */ }
    // Release this server's session→spec bindings: they die with it (a fresh
    // arbiter, in this process or another, binds its sessions from scratch).
    this.sessionSpecs.clear();
    if (this.boundInode !== null && existsSync(this.socketPath)) {
      try {
        if (statSync(this.socketPath).ino === this.boundInode) unlinkSync(this.socketPath);
      } catch { /* ignore */ }
    }
    this.boundInode = null;
    // Hand back single-writer ownership of the symbol DB (release() is
    // pid-guarded, so a successor that stole a stale lock keeps it).
    this.dbOwner?.release();
    this.dbOwner = null;
  }

  /** `whyPath`'s reads of real files (why-preview.ts, 2026-10-10): at
   *  most WHY_MAX_BYTES, remembered, and on the data socket (which the
   *  agent's programs reach) within a byte budget per window. The human
   *  plane (the dashboard) has its own, with no budget the agent can spend. */
  private readonly whyPreview = new WhyPreview();
  private readonly whyPreviewHuman = new WhyPreview({ budgetBytes: Infinity });
  /**
   * The label lookup handed to every confidentiality derivation — the ONE place
   * the two stores compose (Plan 9):
   *
   *   a HUMAN label overrides the catalog in either direction (§6);
   *   a DERIVED label RAISES whatever that yields, and never lowers it (§8) —
   *   except where an EXACT human label speaks about the artifact, which is the
   *   §8 release act and wins.
   *
   * Every classify/symbolize/discovery path already funnels through here, so a
   * file a high session wrote is classified at its watermark by a FUTURE session
   * with no client remembering to ask.
   */
  private readonly labelLookup: LabelLookup = withLabelRoots((p) => {
    // Plan 13 §4.6: a derived copy's destinations are its sources' (label
    // and registry rows, as `taintedProcessBindings` counts a held file);
    // the registry is listed only when a copy with known sources is met.
    let registry: ReturnType<typeof listSecretRegistry> | null = null;
    const sourceBindings = (src: string): string[] => {
      registry ??= listSecretRegistry(this.symbolMap);
      return registry.filter((e) => e.path === src).flatMap((e) => e.bindings);
    };
    return composedLabel(p, this.labelSnapshot(), { sourceBindings });
  }, () => this.labelSnapshot()); // roots: where the labels lie, for a token the text scan cannot place (secret-catalog.ts findSecretPathsInText)

  /** A protected file's own level (2026-10-16, `followDerivedLabel` for a
   *  file moved with its folder): its label or catalog rule when above
   *  public, else the secret registry's level for exactly that path; null
   *  for any other path. */
  private protectedLevelOf(path: string): ConfidentialityLevel | null {
    const m = pathConfidentiality(path, undefined, this.labelLookup);
    if (m.rule !== null && isSecret(m.level)) return m.level;
    const reg = listSecretRegistry(this.symbolMap).filter((e) => e.path === path && isSecret(e.level as ConfidentialityLevel));
    if (reg.length === 0) return null;
    return reg.map((e) => e.level as ConfidentialityLevel).reduce((a, b) => maxConfidentiality(a, b));
  }

  /** The label stores as they stand (label-lookup.ts): the live lookup's
   *  input, and what the discovery worker gets a structured clone of. The
   *  declared model client keys (plan 12 D3) are read from the law in force. */
  private labelSnapshot(): LabelSnapshot {
    return {
      human: this.humanLabels(),
      derived: this.derivedLabels.map(),
      clientKeys: modelClientKeyPaths(getCurrentPolicy().models),
      session: this.sessionPathLabels.map(),
      found: this.foundLabels.map(),
    };
  }

  /** Rule hit counts (policy-surface.md §2.4): machine state in the
   *  symbol DB, one row per deciding rule id. */
  private readonly ruleHits: RuleHitStore;

  /**
   * The HUMAN labels the confidentiality derivation consults: the document's
   * `paths:` (policy.yaml, source "policy-file") composed with the DB rows
   * (dashboard acts). Both are deliberate human acts, so they merge into one
   * map; on the same path the DB row wins — it is the more recent act (a
   * dashboard label changes the running law until the file catches up). The
   * memo is keyed on the compiled policy object + the DB store's version, so a
   * policy swap or a label act invalidates it and steady-state lookups cost a
   * map read.
   */
  /** Where a session's main model runs (plan 11 phase 3): the launcher's
   *  binding, looked up by name in the law IN FORCE. Unbound, bound to the
   *  default vendor, or bound to a name no longer declared local: external. */
  private tllmLocationOf(sessionKey: string | undefined): "local" | "external" {
    const endpoint = this.sessionUpstreams.get(sessionKey)?.endpoint;
    return modelLocation(getCurrentPolicy().models, endpoint ?? undefined);
  }

  private sessionUpstreamOf(sessionKey: string): SessionUpstreamResult {
    const b = this.sessionUpstreams.get(sessionKey);
    return {
      sessionKey,
      endpoint: b?.endpoint ?? null,
      location: this.tllmLocationOf(sessionKey),
      bound: b !== undefined,
      // Present only when offered: older callers see the shape they knew.
      ...(this.cleanReporters.offered(sessionKey) ? { cleanReporter: true } : {}),
    };
  }

  /**
   * The label law the symbol rows' bindings were last brought up to
   * (current-bindings.ts, confidentiality.md §2.1): the compiled policy
   * object, the label store's version, the derived-label generation and
   * the found labels' (the content tier, found-labels.ts).
   * Null at start, so the first request after a restart syncs.
   */
  private bindingsEpoch: { policy: unknown; labels: number; derived: number; found: number } | null = null;

  /**
   * Bring every symbol row's bindings to the label law in force, when that
   * law changed since the last sync (a policy swap, an approved hand edit, a
   * label act, a derived-label write, a restart). Called before every
   * request is answered, so no decision reads a binding the law no longer
   * grants, nor misses one it now grants. Steady state: three comparisons.
   */
  private syncSymbolBindings(): void {
    if (!this.confidentiality) return;
    const policy = getCurrentPolicy();
    const labels = this.pathLabels.version;
    const derived = this.derivedLabels.generation();
    const found = this.foundLabels.generation();
    const e = this.bindingsEpoch;
    if (e && e.policy === policy && e.labels === labels && e.derived === derived && e.found === found) return;
    this.bindingsEpoch = { policy, labels, derived, found };
    try {
      const changed = syncCurrentBindings(this.symbolMap, {
        resolveLabel: this.labelLookup,
        envBindings: (name) => this.envLawBindings(name),
        envWire: (symbol) => this.envWireHosts.get(symbol),
        sourcesOf: (symbol) => this.symbolSources.get(symbol),
        fieldGrants: this.fieldGrants,
      }, this.dbPath ?? getSymbolDbPath());
      if (changed.length > 0) {
        this.log(`bindings: ${changed.length} symbol row(s) brought to the label law in force`);
      }
      // Then every high session's release surface, from the rows it read
      // as they now stand (session-labels.ts `rederive`, §4): a binding the
      // law no longer grants stops releasing a session's paraphrases too.
      const sessions = this.sessionLabels.rederive((symbol) => {
        const e = getSymbolEntry(this.symbolMap, symbol);
        return e && e.obsoleted_at === null ? (e.bindings ?? []) : null;
      });
      if (sessions.length > 0) {
        this.log(`bindings: ${sessions.length} high session(s) brought to the label law in force`);
      }
    } catch (err) {
      // Never leave a stale release standing: retry on the next request.
      this.bindingsEpoch = null;
      this.log(`bindings sync failed (retried next request): ${(err as Error).message}`);
    }
  }

  /** The hosts the law in force binds a masked environment variable to: its
   *  `env.sources` entry's bindings and the host of every declared model
   *  whose `token_env` it is (plan 10 §11.4, plan 11 D2). */
  private envLawBindings(name: string): string[] {
    const law = getCurrentPolicy();
    const source = law.envSources.find((e) => e.name === name);
    return [...new Set([...(source?.bindings ?? []), ...(modelTokenBindings(law.models).get(name) ?? [])])];
  }

  /** What a value's other sources DECLARE for it (value-sources.ts,
   *  confidentiality.md §2.1 "One value, several sources"): a registered
   *  file row's label bindings, an env row's `env.sources` hosts. */
  private valueSourceOpts(): ValueSourceOptions {
    const fileDeclared = declaredBindingsReader(this.symbolMap, this.labelLookup);
    return {
      declared: (name, e) => {
        const variable = envRowVariable(e);
        return variable !== null ? this.envLawBindings(variable) : fileDeclared(name, e);
      },
    };
  }

  /** The row a release decision judges (value-sources.ts): the stored row,
   *  or, when other labelled sources hold the same value, a copy with the
   *  strictest of their levels and the union of their declared bindings. */
  private releaseView(entry: SymbolEntry): SymbolEntry {
    return valueSourceView(this.symbolMap, entry, this.valueSourceOpts());
  }

  /** Does another labelled source of `symbol`'s value declare `destination`
   *  (value-sources.ts)? Then a release there is a binding of the user's,
   *  not one resting on a wire grant alone. */
  private siblingDeclares(symbol: string, destination: string): boolean {
    const hit = findSymbolByName(this.symbolMap, symbol);
    if (!hit) return false;
    return destinationMatchesBindings(destination, siblingDeclaredBindings(this.symbolMap, hit.entry, this.valueSourceOpts()));
  }

  private humanLabelsMemo: { policy: unknown; dbVersion: number; map: Map<string, PathLabel> } | null = null;
  private humanLabels(): ReadonlyMap<string, PathLabel> {
    const policy = getCurrentPolicy();
    const dbVersion = this.pathLabels.version;
    if (this.humanLabelsMemo && this.humanLabelsMemo.policy === policy && this.humanLabelsMemo.dbVersion === dbVersion) {
      return this.humanLabelsMemo.map;
    }
    const map = new Map<string, PathLabel>(policy.pathLabels);
    for (const [p, l] of this.pathLabels.map()) map.set(p, l);
    this.humanLabelsMemo = { policy, dbVersion, map };
    // The label set changed (a policy swap or a label act): the files
    // already under a new label are registered (`syncLabelRegistrations`).
    if (this.labelRootsSeen !== null) queueMicrotask(() => this.syncLabelRegistrations());
    return map;
  }

  /** The human label roots above public (label-lookup.ts `labelRootKeys`)
   *  whose files this arbiter has registered or the launches' walks cover;
   *  null while the confidentiality axis is OFF. */
  private labelRootsSeen: Set<string> | null = null;
  /** The registration pass in flight, chained (`labelRegistrationsSettled`). */
  private labelSync: Promise<void> = Promise.resolve();
  /** Set by `close`: a registration pass still queued registers nothing. */
  private closing = false;

  /**
   * D (2026-10-17, confidentiality.md §6 "Read by a program the launch did
   * not see"): a label set mid-session (a dashboard act, a policy.yaml edit)
   * registers the files already under it, as the launch's walk does for the
   * labels it starts with (`discoveryJob`'s label roots), so the value
   * backstop knows their values when a program the guard does not gate
   * prints them (no guard, `--no-net-guard`, macOS, a recursive read before
   * the guard learns the label). Walked like the launch's label pass (from
   * the label's top, MAX_DEPTH, MAX_LABEL_FILES) on the discovery thread;
   * each file registered as the guard's raw-read report registers one
   * (`registerReadFile`). Only a label added or raised: a lowered or removed
   * one registers nothing (the rows stay, a known secret stays known).
   * Never throws.
   */
  private syncLabelRegistrations(): void {
    if (!this.confidentiality || this.labelRootsSeen === null) return;
    const human = this.humanLabels();
    const now = labelRootKeys(human);
    const before = this.labelRootsSeen;
    this.labelRootsSeen = now;
    const added = [...new Set([...now].filter((k) => !before.has(k)).map((k) => k.slice(k.indexOf(" ") + 1)))];
    if (added.length === 0) return;
    const labels = this.labelSnapshot();
    const job: DiscoveryJob = { roots: [], opts: { labelRoots: added, labelPaths: [...labels.human.keys()] }, labels };
    this.labelSync = this.labelSync.then(async () => {
      if (this.closing) return;
      const report = await this.discoveryWorker.run(job);
      if (this.closing) return;
      for (const f of report.files) this.registerReadFile(f.path, "a label set in this session");
      this.log(`label roots ${added.join(", ")}: ${report.files.length} file(s) under them registered${report.truncated ? ` (the walk stopped at its ${MAX_LABEL_FILES}-file budget)` : ""}`);
    }).catch((err: unknown) => {
      this.log(`label roots ${added.join(", ")}: registration failed (ignored): ${(err as Error).message}`);
    });
  }

  /** The guard's label roots (`labelRootsSince`) and their key, memoized
   *  on the label set (the composed human labels and the client keys). */
  private guardRootsMemo: { labels: ReadonlyMap<string, PathLabel>; keys: string; found: number; key: string; roots: GuardLabelRoot[] } | null = null;
  private guardLabelRootsNow(): { key: string; roots: GuardLabelRoot[] } {
    const labels = this.humanLabels();
    const clientKeys = modelClientKeyPaths(getCurrentPolicy().models);
    const keys = clientKeys.join("\0");
    const found = this.foundLabels.generation();
    const m = this.guardRootsMemo;
    if (m !== null && m.labels === labels && m.keys === keys && m.found === found) return m;
    // The found labels' files too (found-labels.ts): gated at the open
    // wherever the launch did not twin them.
    const roots = guardLabelRoots(labels, clientKeys, undefined, this.foundLabels.map().keys());
    const memo = { labels, keys, found, key: sha256Hex(JSON.stringify(roots)).slice(0, 16), roots };
    this.guardRootsMemo = memo;
    return memo;
  }

  /** The guard's roots for one session (`labelRootsSince`): the label roots
   *  above, the catalog's prefixes for the arbiter's HOME and the session's
   *  launch HOME (`catalogGateRoots`), and the catalog's name prefilter
   *  (2026-10-17); keyed over all of it, memoized per HOME set. */
  private guardCatalogMemo = new Map<string, { base: string; key: string; roots: GuardLabelRoot[]; catalog: GuardCatalogWire }>();
  private guardRoots(session?: unknown): { key: string; roots: GuardLabelRoot[]; catalog?: GuardCatalogWire } {
    if (!this.confidentiality) return { key: "off", roots: [] };
    const base = this.guardLabelRootsNow();
    const homes = this.gateHomes(session);
    const hk = homes.join("\0");
    const m = this.guardCatalogMemo.get(hk);
    if (m !== undefined && m.base === base.key) return m;
    const byPath = new Map<string, GuardLabelRoot>();
    for (const r of base.roots) byPath.set(`${r.path}\0${JSON.stringify(r.shape ?? null)}`, r);
    for (const p of catalogGateRoots(homes)) if (!byPath.has(`${p}\0null`)) byPath.set(`${p}\0null`, { path: p });
    const roots = [...byPath.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    const catalog: GuardCatalogWire = { names: catalogNameAnchors(), homes, skipDirs: [...CATALOG_GATE_SKIP_DIRS] };
    const memo = { base: base.key, key: sha256Hex(JSON.stringify({ roots, catalog })).slice(0, 16), roots, catalog };
    if (this.guardCatalogMemo.size >= 64) this.guardCatalogMemo.clear();
    this.guardCatalogMemo.set(hk, memo);
    return memo;
  }

  /** The live launch HOME holding `path` whose catalog calls it a secret
   *  when this arbiter's own HOME does not (`registerSecret` from the guard,
   *  2026-10-17), else null. */
  private launchHomeJudging(path: unknown): string | null {
    if (typeof path !== "string" || !path.startsWith("/")) return null;
    if (isSecret(pathConfidentiality(path, undefined, this.labelLookup).level)) return null;
    for (const l of this.launchHomes.values()) {
      if (path.startsWith(l.home + "/") && isSecret(pathConfidentiality(path, l.home, this.labelLookup).level)) return l.home;
    }
    return null;
  }

  /** The HOMEs the guard's catalog gate reads the catalog's `~` places in:
   *  this arbiter's and the session's launch HOME (`sessionHome`), sorted. */
  private gateHomes(session?: unknown): string[] {
    const launchHome = this.sessionHome(session);
    return [...new Set([homedir(), ...(launchHome !== null ? [launchHome] : [])])].sort();
  }

  /** Resolves once every registration pass started so far has ended (a
   *  test's wait; `syncLabelRegistrations`). */
  async labelRegistrationsSettled(): Promise<void> {
    this.syncLabelRegistrations();
    await new Promise<void>((r) => queueMicrotask(r));
    await this.labelSync;
  }

  /**
   * Where a symbolize's RELATIVE typed-path origin was read (2026-10-10,
   * confidentiality.md §6): `<relativeBase>/<origin>` when the request's
   * `relativeBase` applies exactly as it does on the classify of the same
   * result (`relativePathBase`: this arbiter's own copy of the session's gate
   * surface says `launch` and lists the tool) and the origin is a value the
   * agent's tool reads there (`resolveTypedPathOrigin`); else undefined (the
   * origin is stored as sent). Never with an `originHuman` (a view map
   * translated the origin, so it was not the relative value) nor with the
   * confidentiality axis OFF (the stored row stays byte-identical).
   */
  private placedTypedOrigin(req: { tool: string; origin?: string; originHuman?: string; relativeBase?: string; sessionKey?: string }): string | undefined {
    if (!this.confidentiality || typeof req.origin !== "string" || req.originHuman !== undefined) return undefined;
    const base = relativePathBase({ tool: req.tool, relativeBase: req.relativeBase, sessionKey: req.sessionKey }, this.sessionSpecs);
    return base === undefined ? undefined : resolveTypedPathOrigin(req.origin, base.dir);
  }

  /** Bindings a label/catalog rule grants an origin, when the client sent none.
   *  A binding is a STANDING RELEASE RULE (§2) — it must not depend on a client
   *  remembering to forward it. */
  private bindingsForOrigin(origin: string | undefined): string[] | undefined {
    const b = confidentialityForOrigin(origin, undefined, this.labelLookup).bindings;
    return b.length > 0 ? b : undefined;
  }

  /**
   * The label of an ORIGIN that is itself a SYMBOL NAME — the derived-symbol
   * inheritance rule (Plan 7, confidentiality.md §8).
   *
   * THIS IS WHAT MAKES LAUNDERING STRUCTURALLY IMPOSSIBLE, and it is subtler
   * than it looks. A derived symbol — above all the U-LLM quarantine's
   * re-symbolized result (`inspect_symbol`) — passes the SOURCE SYMBOL as its
   * origin. `confidentialityForOrigin` cannot see that: it looks for filesystem
   * paths, and `$MDU:anymodel_Read[3fa9]` is not one, so its term is `public`.
   * Without this third term the entire label would rest on the CLIENT
   * remembering to send `confidentiality` — and a client that forgets (a bug, a
   * refactor, a new caller) mints `public`, laundering a secret through the
   * quarantine in exactly one hop. Deriving it server-side keeps the promise the
   * rest of this handler makes: no client can under-label by omission.
   *
   * It also generalizes past the quarantine: ANY symbol derived from a secret
   * symbol is secret, which is §8's derived-data rule enforced where it is
   * cheapest. (`allocateDerivedSymbol` already does this for the SPLIT path;
   * this gives the symbolize path the same guarantee.)
   */
  private originSymbolLabel(
    origin: string | undefined,
  ): { level: ConfidentialityLevel; bindings?: string[] } {
    if (!origin) return { level: "public" };
    // getSymbolEntry resolves field-path tails too (`$MDU:x[ab].field`).
    const e = getSymbolEntry(this.symbolMap, origin);
    if (!e) return { level: "public" };
    return {
      level: parseConfidentialityLevel(e.confidentiality),
      bindings: e.bindings && e.bindings.length > 0 ? e.bindings : undefined,
    };
  }

  /** Is a user label WEAKER than the catalog's verdict for the same path? That
   *  is a declassification — a standing rule that a file the catalog calls a
   *  credential may now flow freely — and §6 requires the surface show it.
   *  Computed against the CATALOG ALONE (no label lookup), or it would compare
   *  the label to itself. */
  private declassifies(path: string, level: ConfidentialityLevel, glob?: boolean): boolean {
    // A PATTERN names a class of files, so the catalog has no single verdict to
    // compare with. A `public` pattern is reported as a declassification
    // outright (it releases whatever catalog-secret file it matches). A
    // `any-model` pattern RAISES every ordinary file it matches, so it
    // is flagged only when it AIMS at catalog-secret files: under a catalog
    // prefix, or a file-name segment that matches a catalog-shaped name
    // (`patternTargetsCatalogSecret`; a whole-directory pattern is judged like
    // a literal directory label, confidentiality.md §6.1).
    if (glob) {
      if (level === "public") return true;
      if (level === "no-model") return false;
      const r = compilePathGlob(path);
      return "glob" in r && patternTargetsCatalogSecret(r.glob, (n) => pathGlobLastSegmentMatches(r.glob, n));
    }
    const catalog = secretPathConfidentiality(path).level;
    // Weaker ⇔ the catalog's level dominates and they differ.
    return level !== catalog && maxConfidentiality(level, catalog) === catalog;
  }

  private onConnection(sock: Socket, channel: IpcChannel): void {
    this.conns.add(sock);
    const ctx: DispatchContext = {
      channel,
      notify: (frame) => { if (!sock.destroyed) sock.write(JSON.stringify(frame) + "\n"); },
    };
    let buf = "";
    // Once a `subscribe` request lands, this connection becomes a DEDICATED
    // streaming connection: we register a subscriber, replay the backlog, and
    // ignore any further request lines on it (subscribe monopolizes its
    // connection — the one-req-one-res ops are unaffected on other connections).
    let streaming = false;
    let unsubscribe: (() => void) | undefined;

    sock.setEncoding("utf8");
    sock.on("data", (chunk: string) => {
      if (streaming) return; // dedicated stream — ignore further input.
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;

        // Peek for the streaming `subscribe` op before the one-shot dispatch.
        const sub = this.parseSubscribe(line);
        if (sub) {
          // The stream carries originals (DualRepr.original): human plane
          // only. Refused with one error line in the shape of any other
          // refusal, then the connection is ended: a subscribe always owns a
          // dedicated connection, and its client must see the refusal (the
          // error frame, then EOF) rather than wait on a stream that never
          // starts.
          const refused = channelRefusal(sub, channel);
          if (refused !== null) {
            this.log(`refused on ${channel} channel: subscribe`);
            streaming = true; // ignore anything else on this connection
            sock.end(JSON.stringify({ id: sub.id, ok: false, error: refused }) + "\n");
            return;
          }
          streaming = true;
          unsubscribe = this.startSubscription(sock, sub);
          return; // stop consuming request lines on this connection.
        }

        const response = this.handleLine(line, ctx);
        if (response instanceof Promise) {
          // Answered when the worker is done; the client matches replies by
          // id, so later requests on this connection are not held behind it.
          void response.then((r) => { if (!sock.destroyed) sock.write(JSON.stringify(r) + "\n"); });
        } else {
          sock.write(JSON.stringify(response) + "\n");
        }
      }
    });
    const teardown = (): void => {
      this.conns.delete(sock);
      if (unsubscribe) {
        unsubscribe();
        unsubscribe = undefined;
      }
    };
    sock.on("close", teardown);
    sock.on("error", (err) => {
      this.log(`socket error: ${err.message}`);
      teardown();
    });
  }

  /** If `line` is a well-formed `subscribe` request, return it; else null (so the
   * caller falls through to the normal one-req-one-res dispatch). */
  private parseSubscribe(line: string): SubscribeRequest | null {
    let req: { op?: string };
    try {
      req = JSON.parse(line) as { op?: string };
    } catch {
      return null;
    }
    if (req && typeof req === "object" && req.op === "subscribe") {
      return req as SubscribeRequest;
    }
    return null;
  }

  /** Turn `sock` into a dedicated subscription stream: replay the backlog as
   * event frames, then register a live push callback. Returns an unsubscribe fn
   * the connection's close/error handler invokes. */
  private startSubscription(sock: Socket, req: SubscribeRequest): () => void {
    const writeFrame = (event: StoredEvent): void => {
      // Each frame is a normal OkResponse with result.type === "event".
      try {
        sock.write(JSON.stringify({ id: req.id, ok: true, result: { type: "event", event } }) + "\n");
      } catch {
        // Best-effort: a write failure means the peer is gone; the close/error
        // handler will run teardown.
      }
    };

    // Validate the sessionId the same way the store does; on a bad request emit
    // one error response and let the client close.
    let backlog: StoredEvent[];
    try {
      backlog = this.events.since(req.sessionId, req.sinceSeq ?? 0);
    } catch (err) {
      sock.write(JSON.stringify({ id: req.id, ok: false, error: (err as Error).message }) + "\n");
      return () => {};
    }

    // 1) Replay backlog frames (events since sinceSeq), in seq order.
    for (const e of backlog) writeFrame(e);

    // 2) Register the live push callback for subsequently-emitted events.
    const subscriber: Subscriber = {
      push: (event) => writeFrame(event),
      // deleteSession ends the stream; the socket's close handler then runs the
      // normal teardown (removing this subscriber from the map).
      end: () => {
        try { sock.end(); } catch { /* peer already gone */ }
      },
    };
    let set = this.subscribers.get(req.sessionId);
    if (!set) {
      set = new Set<Subscriber>();
      this.subscribers.set(req.sessionId, set);
    }
    set.add(subscriber);
    this.log(`subscribe: session ${req.sessionId} (sinceSeq=${req.sinceSeq ?? 0}, backlog=${backlog.length})`);

    return () => {
      const s = this.subscribers.get(req.sessionId);
      if (s) {
        s.delete(subscriber);
        if (s.size === 0) this.subscribers.delete(req.sessionId);
      }
    };
  }

  /** Fan a freshly-stored event out to every live subscriber of its session.
   * Best-effort: a throwing subscriber is dropped and logged, never propagated
   * back to the emitter. */
  /**
   * The verdict AUDIT event (policy-surface.md §9.6): every human
   * approve/deny lands one `approval_resolved` event in the reserved
   * `arbiter-admin` session stream — approvals are arbiter-global (they decide
   * every future session), so they get the arbiter's own stream rather than
   * being misfiled under whichever session happened to be on screen. The
   * dashboard renders that stream like any session: the standing law's own
   * timeline. BEST-EFFORT and off the security path (like every emit): a
   * failure logs and is swallowed — an unrecorded audit line must not fail the
   * resolution that already happened. Carries symbol NAMES / key strings only,
   * never a resolved value (the queue holds none).
   *
   * A prompt hold's answer (plan 15 §7, `prompt:` rows) also carries
   * `promptAnswer` and `promptScope`, top-level scalars like `posture` (the
   * SIEM rules key on them, siem-integration.md §6.6): the row's status
   * alone cannot tell "send masked" from "cancel". Never the span.
   */
  private emitApprovalResolved(approval: EgressApproval, prompt?: { answer: "send" | "mask" | "cancel" | "let-through"; scope: "once" | "session" }): void {
    try {
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: ADMIN_SESSION_ID,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "approval_resolved",
        view: "HumanView",
        boundary: "model_context",
        emitter: "arbiter",
        input: {
          symbolized: `${approval.symbol} × ${approval.destination}`,
          original: null, differs: false, symbols: [],
        },
        output: {
          // Scope is spelled out only for "once" so the pre-scope line shape
          // (and anything pinned to it) is unchanged for standing verdicts.
          // "Send without it" says so (confidentiality.md §4): a DENIAL whose
          // one use sends the request with a marker in the secret's place.
          symbolized: `${approval.status.toUpperCase()} by human (${approval.strip === true ? "send without it; " : ""}${approval.scope === "once" ? "once; " : ""}count ${approval.count}, first seen ${new Date(approval.firstSeen).toISOString()})`,
          original: null, differs: false, symbols: [],
        },
        invariant: { violatedInvariant: false },
        policy: {
          usage: approval.status === "approved" ? "allow" : "deny",
          reason: approval.reason,
          ruleRef: verdictRef(approval.id),
        },
        ...(prompt ? { promptAnswer: prompt.answer, promptScope: prompt.scope } : {}),
      });
      this.fanOut(stored);
    } catch (err) {
      this.log(`approval_resolved emit failed (audit only): ${(err as Error).message}`);
    }
  }

  /**
   * The consumption AUDIT event, `approval_consumed`: a once-scoped verdict was
   * spent by its one satisfying decision. The standing-verdict twin of
   * `approval_resolved` — same reserved `arbiter-admin` stream, same best-effort
   * discipline, same names-only payload. It exists because a once-verdict's
   * consumption IS its lifecycle end (siem-integration.md notes that standing-
   * approval reuse emits no event; a single-use grant must not have that gap —
   * its whole point is that each use is individually visible and re-asked).
   */
  /**
   * Raise a session's high-watermark (SessionLabelStore.raise) and, when its
   * level changed, say so in that session's event stream: `session_level`,
   * from → to, the symbol's NAME and the session's bindings, never content
   * (dashboard.md §4.35: a drill's page shows each turn's level). The raise
   * is the security act and happens first; the event is best-effort and off
   * the security path, as every arbiter emit.
   */
  private raiseSessionLevel(sessionKey: string, level: ConfidentialityLevel, bindings: string[], source?: string): SessionLabel {
    const before = this.sessionLabels.get(sessionKey).confidentiality;
    const raised = this.sessionLabels.raise(sessionKey, level, bindings, source);
    if (raised.confidentiality === before) return raised;
    try {
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: sessionKey,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "session_level",
        view: "HumanView",
        boundary: "model_context",
        emitter: "arbiter",
        // The symbol's name stays in `sessionLevel` alone: in the input or
        // output text, the trace would count it as one more masked item.
        input: { symbolized: "", original: null, differs: false, symbols: [] },
        output: { symbolized: `session ${before} → ${raised.confidentiality}`, original: null, differs: false, symbols: [] },
        invariant: { violatedInvariant: false },
        sessionLevel: { from: before, to: raised.confidentiality, symbol: source ?? null, bindings: [...raised.bindings] },
      });
      this.fanOut(stored);
    } catch (err) {
      this.log(`session_level emit failed (observability only): ${(err as Error).message}`);
    }
    return raised;
  }

  private emitApprovalConsumed(approval: EgressApproval): void {
    try {
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: ADMIN_SESSION_ID,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "approval_consumed",
        view: "HumanView",
        boundary: "model_context",
        emitter: "arbiter",
        input: {
          symbolized: `${approval.symbol} × ${approval.destination}`,
          original: null, differs: false, symbols: [],
        },
        output: {
          symbolized: `${approval.status.toUpperCase()} (once) spent by its one use — the next attempt asks again`,
          original: null, differs: false, symbols: [],
        },
        invariant: { violatedInvariant: false },
        policy: {
          usage: approval.status === "approved" ? "allow" : "deny",
          reason: approval.reason,
          ruleRef: verdictRef(approval.id),
        },
      });
      this.fanOut(stored);
    } catch (err) {
      this.log(`approval_consumed emit failed (audit only): ${(err as Error).message}`);
    }
  }

  /**
   * Consult a prior human verdict for a queue pair and enact verdict scope:
   *   - no row / still pending → undefined (no prior — run the pure gate);
   *   - scope "always"         → the verdict, untouched (standing, never expires);
   *   - scope "once", unspent  → the verdict, and this consultation IS its one
   *     use: `consumedAt` is stamped (write-through) + `approval_consumed`
   *     audited before returning;
   *   - scope "once", spent    → undefined (no longer applies; the pure gate
   *     runs and, if it still requires approval, recordPending resets the row
   *     to a fresh pending cycle — the human is asked again).
   * Shared by all three gate wraps (network / fs / exec-escalate) so a "once"
   * verdict means the same thing at every chokepoint.
   */
  /**
   * Plan 10 §11.2: write a reader PIN into the law on disk. A bare name on
   * `paths[].readers` becomes `{app, path, sha256}` the first time it is used;
   * a human's standing allow adds one. The arbiter is the file's single
   * writer; an in-memory law (tests, embedders) has nowhere to write and the
   * verdict simply lives in the approval store for the session.
   *
   * Written like every other write (policy-surface.md §8.4.6): into the
   * person's text, comments kept, and, while a hand edit of policy.yaml
   * waits in Approvals, made to that held edit as well (layered, never
   * written over it; its card is filed again for the new bytes and nothing
   * it relaxes takes effect). The pin is refused, and the verdict holds for
   * the session (an Always pins again at the next open), when the held edit
   * changes this file's own rule, or when the file has no rule of its own
   * yet and the held edit changes any `paths:` rule: the new entry copies
   * the label the law gives the file, which the held edit may have changed.
   * A hand edit that landed inside the poll window is loaded first, and the
   * pin is made once more over the law that edit left.
   */
  private pinReader(path: string, pin: { app: string; path: string; sha256?: string; from?: string; script?: string; scriptSha256?: string; prints?: "nothing" }, level: string, system: boolean): void {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        this.pinReaderOnce(path, pin, level, system);
        return;
      } catch (e) {
        if (e instanceof StalePolicyError && !e.held && attempt === 0) continue;
        this.log(`pinReader: not written (${(e as Error).message}); the verdict holds for this session`);
        return;
      }
    }
  }

  private pinReaderOnce(path: string, pin: { app: string; path: string; sha256?: string; from?: string; script?: string; scriptSha256?: string; prints?: "nothing" }, level: string, system: boolean): void {
    const current = this.policyDocs.document;
    const doc: PolicyFileConfig = current ? structuredClone(current) : { version: 1 };
    const norm = normalizeLabelPath(path) ?? path;
    const paths = (doc.paths ??= []);
    let entry = paths.find((e) => (normalizeLabelPath(e.path) ?? e.path) === norm);
    const ownEntry = entry !== undefined;
    if (!entry) {
      // The file is labelled by a pattern or an ancestor: its own entry,
      // which outranks that label from now on, carries what that label
      // gave it (2026-10-05). A bare `{path, level}` here dropped the
      // pattern's bindings, `others`, `extract` and other readers for this
      // file once its first reader was pinned; since a symbol's bindings
      // follow the law in force (confidentiality.md §2.1), that would stop
      // a bound key reaching its own host.
      const from = this.labelLookup(norm);
      const inherited = from && (from.origin ?? "user") === "user" ? from : null;
      entry = {
        path: norm,
        level: (inherited?.level ?? level) as PathLabelEntry["level"],
        // The label's own declared bindings and `values:` (plan 13 §5.2),
        // not the whole file's intersection `bindings` answers under them.
        ...(() => { const b = inherited ? inherited.fileBindings ?? inherited.bindings : []; return b.length > 0 ? { bindings: [...b] } : {}; })(),
        ...(inherited?.values ? { values: valueRulesToDocument(inherited.values) } : {}),
        ...(inherited?.readers ? { readers: structuredClone(inherited.readers) } : {}),
        ...(inherited?.others ? { others: inherited.others } : {}),
        ...(inherited?.extract ? { extract: inherited.extract } : {}),
      };
      paths.push(entry);
    }
    // The entry that matched (a bare name, or a lineage-conditional
    // { app, from } without a pin yet) becomes the pin, which keeps `from`,
    // so pinning never widens a lineage-conditional reader into an
    // unconditional one; its `output:` follows only to a binary out of the
    // agent's reach (Plan 13 D3, withPinnedReader).
    const readers = withPinnedReader(entry.readers ?? [], pin, { system });
    if (readers === null) return;
    entry.readers = readers;
    const lawPaths = canonicalJson(current?.paths ?? []);
    this.policyDocs.apply(doc, { via: "pin-reader", requestedBy: "arbiter", summary: `reader pinned: ${pin.app} (${pin.path}) on ${norm}` }, {
      mayLayer: (held) => ownEntry || canonicalJson(held?.paths ?? []) === lawPaths,
    });
  }

  /**
   * Is this classify request the `declassify_symbol` tool result carrying
   * exactly what the arbiter released to this session (plan 11 §6)? Rung 3
   * exists to put that value in front of the model; without this, the generic
   * `mcp__*` UNTRUSTED rule masked it again whenever the integrity axis was on,
   * so an allowed read never arrived. The match is narrow on purpose: the
   * Mandu declassify tool by exact name, the whole result, a session with a
   * recorded release of the symbol named in the tool's input, and a result
   * that is that value alone or inspect-mcp's one-line `[DECLASSIFIED …]`
   * notice followed by it. Anything else keeps the policy's verdict. The
   * released datum is trusted-integrity by construction (decideDeclassify
   * refuses untrusted data), so trusting it adds no untrusted byte.
   */
  private declassifyResultTrusted(req: { tool?: unknown; field?: unknown; value?: unknown; sessionKey?: unknown; params?: unknown }): boolean {
    if (typeof req.tool !== "string" || !isManduDeclassifyTool(req.tool)) return false;
    if (req.field !== undefined && req.field !== "") return false;
    if (typeof req.sessionKey !== "string" || typeof req.value !== "string") return false;
    const symbol = (req.params as { symbol?: unknown } | undefined)?.symbol;
    if (typeof symbol !== "string") return false;
    const grant = this.declassifyGrants.get(req.sessionKey)?.get(symbol);
    if (grant === undefined) return false;
    // Claude Code appends its token-budget reminder to every tool_result,
    // and the whole result is classified with it: past exactly that shape
    // (claude-code-inbound.ts withoutHarnessBudgetTail; any other trailing
    // text still fails the match), the grant compared without its own
    // trailing whitespace, which is all the harness's separator can change.
    const { body: value, stripped } = withoutHarnessBudgetTail(req.value);
    const released = stripped ? grant.trimEnd() : grant;
    if (value === released) return true;
    const tail = `\n\n${released}`;
    if (!value.endsWith(tail)) return false;
    return /^\[DECLASSIFIED[^\n\]]*\]$/.test(value.slice(0, value.length - tail.length));
  }

  /** The structured twin (and secret texts) of the registered file at
   *  `path`, for a proxy's row on that path (the value index's twin-line
   *  exclusion, plan 10 §11.8, review of !1604): null for a path no
   *  registration covers. Memoized until the symbol table or the label law
   *  changes. */
  private registeredTwinOfPath(path: string): { text: string; secrets: string[] } | null {
    const c = this.twinPathCache();
    if (!c.paths.has(path)) return null;
    let t = c.twins.get(path);
    if (t === undefined) {
      t = structuredTwinWithSecretsFor(this.symbolMap, path, { resolveLabel: this.labelLookup });
      // Plan 10 §11.13 (2026-10-17): a config whose twin is its own text
      // (no secret value in it): every line of it is shown to the agent, so
      // none of them is a fingerprint of a proxy's row on that path either;
      // the row's whole value and its other lines (a secret the file did
      // not have at registration) still are.
      if (t === null) {
        const own = this.ownTextOf(path);
        if (own !== null) t = { text: own, secrets: [] };
      }
      c.twins.set(path, t);
    }
    return t;
  }

  /** `twinByPath`, valid for the symbol table, the law, the labels and the
   *  named HOMEs as they stand. */
  private twinPathCache(): NonNullable<ArbiterServer["twinByPath"]> {
    const gen = symbolMapGeneration(this.symbolMap);
    const size = this.symbolMap.symbols.size;
    const policy = getCurrentPolicy();
    const labels = this.pathLabels.version;
    const derived = this.derivedLabels.generation();
    const homes = this.namedHomes().join("\u0000");
    let c = this.twinByPath;
    if (!c || c.map !== this.symbolMap || c.gen !== gen || c.size !== size || c.policy !== policy || c.labels !== labels || c.derived !== derived || c.homes !== homes) {
      c = { map: this.symbolMap, gen, size, policy, labels, derived, homes, paths: new Set(registeredFilePaths(this.symbolMap)), twins: new Map(), kinds: new Map() };
      this.twinByPath = c;
    }
    return c;
  }

  /** The twin a read of the registered file at `path` on its own gives
   *  (named-twins.ts): `fields` (structured), `lines` (the document twin),
   *  `whole` (one placeholder), `text` (its own text), or null for a path
   *  no registration covers or with no twin. Memoized with `twinByPath`. */
  private twinKindOfPath(path: string): NamedTwinKind | null {
    const c = this.twinPathCache();
    const known = c.kinds.get(path);
    if (known !== undefined) return known;
    let kind: NamedTwinKind | null = null;
    if (c.paths.has(path)) {
      if (structuredTwinWithSecretsFor(this.symbolMap, path, { resolveLabel: this.labelLookup }) !== null) {
        // the extract the twin was rendered by (renderRegisteredTwin)
        kind = pathConfidentiality(path, undefined, this.labelLookup).extract === DOCUMENT_TWIN_EXTRACT ? "lines" : "fields";
      } else if (wholeFileTwinFor(this.symbolMap, path, { homes: this.namedHomes(), resolveLabel: this.labelLookup }) !== null) {
        kind = "whole";
      } else if (this.ownTextOf(path) !== null) {
        kind = "text";
      }
    }
    if (c.kinds.size >= 4096) c.kinds.clear();
    c.kinds.set(path, kind);
    return kind;
  }

  /** The classify answer's `namedTwins` (named-twins.ts, confidentiality.md
   *  §7.1): for a shell command's secret verdict, the twin kind of each
   *  named token's secret files. Relative tokens are read in the call's
   *  start directory, or its leading `cd`; a command that may change
   *  directory otherwise answers only for its absolute tokens. Utility
   *  only: any failure is no answer. */
  private namedTwinsOf(req: ClassifyRequest, namedPaths: readonly string[] | undefined): NamedTwin[] {
    try {
      if (namedPaths === undefined || namedPaths.length === 0) return [];
      const params = (req.params ?? {}) as Record<string, unknown>;
      const command = typeof params["cmd"] === "string" ? params["cmd"] as string : typeof params["command"] === "string" ? params["command"] as string : null;
      if (command === null) return [];
      const workdir = this.policy.callWorkdirOf?.(req);
      const start = req.callStartDir ?? (workdir !== undefined && workdir.startsWith("/") ? workdir : undefined);
      const base = directoryMayChange(command) ? leadingCdDir(command, start) : start;
      const home = this.sessionHome(req.sessionKey) ?? homedir();
      return namedTwinsFor(namedPaths, {
        base,
        home,
        fs: {
          kind: (p) => {
            try {
              const st = statSync(p);
              return st.isFile() ? "file" : st.isDirectory() ? "dir" : null;
            } catch {
              return null;
            }
          },
          list: (d) => {
            try { return readdirSync(d); } catch { return null; }
          },
        },
        isSecretFile: (p) => this.protectedLevelOf(p) !== null,
        twinKindOf: (p) => this.twinKindOfPath(p),
      });
    } catch (err) {
      this.log(`named twins unavailable (non-fatal, utility only): ${(err as Error).message}`);
      return [];
    }
  }

  /**
   * Plan 10 §11.8, "A twin line is no piece of an output that prints it"
   * (2026-10-19): the twin(s) of the registered files whose FIELD
   * placeholders an output row's value carries, merged (their texts one
   * after the other, their secret texts together), else null. The value
   * index then drops from that row's line pieces each line one of those twins
   * carries verbatim that holds none of their secret texts and none of the
   * row's other pieces (`withoutTwinLines`): the agent is shown such a line
   * in the twin anyway, and the guard serves it to every program.
   *
   * The case (demo-c17, 2026-10-19): `cat bank/statement-2026-09.md; cat
   * contacts.md` printed the statement's document twin beside the contacts;
   * the command names a secret file, so the output was masked whole as a new
   * row, and each twin line (`Account: $MDU:…`, a label beside a token) was
   * a fingerprint of it. The upload of the twin to the accountant, every
   * placeholder answered Allow once, then tripped the egress tripwire.
   *
   * Only placeholders of a registered file (`isRegisteredFileRow`, a field,
   * secret, active) name a twin; the row's value is what names them, so a
   * line of a file the output does not show stays a piece. The row's whole
   * value, its other lines and every credential-shaped span stay pieces.
   */
  private outputRowTwin(name: string, e: SymbolEntry): { text: string; secrets: string[] } | null {
    let m = this.outputTwinPaths.get(name);
    if (m === undefined || m.len !== e.value.length) {
      const paths = new Set<string>();
      if (e.value.includes("$MDU:")) {
        for (const token of e.value.match(new RegExp(getActiveFormat().pattern.source, "g")) ?? []) {
          const row = this.symbolMap.symbols.get(token);
          if (!row || row.field === null || row.obsoleted_at !== null || !isRegisteredFileRow(row) || !isSecret(row.confidentiality)) continue;
          paths.add(row.origin as string);
          if (paths.size >= OUTPUT_TWIN_MAX_FILES) break;
        }
      }
      m = { len: e.value.length, paths: [...paths].sort() };
      if (this.outputTwinPaths.size >= 4096) this.outputTwinPaths.clear();
      this.outputTwinPaths.set(name, m);
    }
    if (m.paths.length === 0) return null;
    const texts: string[] = [];
    const secrets: string[] = [];
    for (const p of m.paths) {
      const t = this.registeredTwinOfPath(p);
      if (t === null) continue;
      texts.push(t.text);
      secrets.push(...t.secrets);
    }
    return texts.length === 0 ? null : { text: texts.join("\n"), secrets };
  }

  /** The HOME the launcher of `session` recorded on an attested
   *  `beginLaunch` (the newest live launch of it), else null. Plan 10
   *  §11.13. */
  private sessionHome(session: unknown): string | null {
    if (typeof session !== "string" || session === "") return null;
    let home: string | null = null;
    for (const l of this.launchHomes.values()) if (l.session === session) home = l.home;
    return home;
  }

  /** The launch whose HOME `whyPath` (`mandu why <path>`) judges a path
   *  under as well as the caller's (plan 10 §11.13, 2026-10-17), on the
   *  human plane only (a data-socket request names no session's HOME):
   *  `session`'s newest live launch when one is named (`home: null` when
   *  that session has no live launch here), else the newest live launch of
   *  any session (`newest: true`), else null. */
  private whyLaunchHome(channel: IpcChannel, session: unknown): NonNullable<WhyPathOpResult["launch"]> | null {
    if (!this.attested(channel)) return null;
    if (typeof session === "string" && session !== "" && session.length <= 256) {
      return { session, home: this.sessionHome(session), newest: false };
    }
    let last: { session: string; home: string } | null = null;
    for (const l of this.launchHomes.values()) last = l;
    return last !== null ? { session: last.session, home: last.home, newest: true } : null;
  }

  /** The match `whyPath`'s `twin` is decided by (registry.ts `twinMatchOf`):
   *  the arbiter's HOME and the named HOMEs (the live launches', the
   *  launcher's registrations'), as `isOwnTextTwin` reads them, and the
   *  caller's `home` (a launch from it would name it: "what a launch would
   *  do"); `m` itself for an agent's login moved out of the catalog's places
   *  (`agent-login:` decides its twin, as `registerSecret` does). */
  private whyTwinMatch(path: string, m: { rule?: string | null; extract?: string }, home: string | undefined, launch: WhyPathOpResult["launch"] | null): { rule: string | null; extract?: string } {
    if (m.rule?.startsWith("agent-login:")) return { rule: m.rule, ...(m.extract ? { extract: m.extract } : {}) };
    const homes = new Set(this.namedHomes());
    if (home !== undefined) homes.add(home);
    if (launch?.home) homes.add(launch.home);
    return twinMatchOf(path, { homes: [...homes], resolveLabel: this.labelLookup });
  }

  /** Every HOME the human plane named (the live launches', the launcher's
   *  registrations'), sorted: the places whose catalog may vouch for a
   *  config's own text besides the arbiter's own (registry.ts
   *  `isOwnTextTwin`). Plan 10 §11.13. */
  private namedHomes(): string[] {
    const homes = new Set(this.registrationHomes);
    for (const l of this.launchHomes.values()) homes.add(l.home);
    return [...homes].sort();
  }

  /** The own-text twin of `path` now (registry.ts `ownTextTwinFor`), its
   *  text, or null. Plan 10 §11.13. */
  private ownTextOf(path: string): string | null {
    return ownTextTwinFor(this.symbolMap, path, { homes: this.namedHomes(), resolveLabel: this.labelLookup })?.text ?? null;
  }

  /** Does row `name` hold only (a piece of) an own-text twin (registry.ts
   *  `isOwnTextRow`), so the value backstop does not count it? Memoized
   *  until the symbol table, the label law or the named HOMEs change. */
  private isOwnTextRow(name: string): boolean {
    const homes = this.namedHomes();
    const key = [symbolMapGeneration(this.symbolMap), this.symbolMap.symbols.size, this.pathLabels.version, this.derivedLabels.generation(), homes.join("\u0000")].join("\u0001");
    // The law in force (`getCurrentPolicy`) can change the catalog too: the
    // memo holds only within one law.
    const policy = getCurrentPolicy();
    let c = this.ownTextRowCache;
    if (c === null || c.key !== key || c.policy !== policy || c.rows.size > 4096) {
      c = { key, policy, rows: new Map() };
      this.ownTextRowCache = c;
    }
    let v = c.rows.get(name);
    if (v === undefined) {
      v = isOwnTextRow(this.symbolMap, name, { homes, resolveLabel: this.labelLookup });
      c.rows.set(name, v);
    }
    return v;
  }

  /** Is field row `name` a person's name in a personal document's twin
   *  (registry.ts `documentNameRows`, secret-discovery.md §2.7, "A person's
   *  name")? Such a row is a placeholder in its file's twin but no
   *  fingerprint: the value index and the residue scan leave it out.
   *  Memoized until the symbol table, the label law or the labels change. */
  private isDocumentNameRow(name: string, e: SymbolEntry): boolean {
    if (e.field === null || e.obsoleted_at !== null || !isRegisteredFileRow(e)) return false;
    const key = [symbolMapGeneration(this.symbolMap), this.symbolMap.symbols.size, this.pathLabels.version, this.derivedLabels.generation()].join("\u0001");
    const policy = getCurrentPolicy();
    let c = this.documentNameRowCache;
    if (c === null || c.key !== key || c.policy !== policy) {
      c = { key, policy, rows: documentNameRows(this.symbolMap, { resolveLabel: this.labelLookup }) };
      this.documentNameRowCache = c;
    }
    return c.rows.has(name);
  }

  /** The registered files' paths for the key listing test (plan 10
   *  §11.8), cached until the symbol table changes (its generation or size).
   *  Only paths: a twin is rendered only for a file the command names. */
  private registeredPathsForKeyListing(): string[] {
    const gen = symbolMapGeneration(this.symbolMap);
    const size = this.symbolMap.symbols.size;
    const c = this.keyListingPaths;
    if (c && c.map === this.symbolMap && c.gen === gen && c.size === size) return c.paths;
    const paths = registeredFilePaths(this.symbolMap);
    this.keyListingPaths = { map: this.symbolMap, gen, size, paths };
    return paths;
  }

  /** Is a symbol row's value one contiguous piece of ONE registered file's
   *  structured twin (claude-code-inbound.ts structuredTwinExecOutputPath)?
   *  Memoized per row: the answer is about the row's own bytes (no secret
   *  byte in them), which never change once a twin vouched for them. */
  private isTwinPieceRow(name: string, value: string): boolean {
    let v = this.twinPieceRowCache.get(name);
    if (v === undefined) {
      const cache = new Map<string, RegisteredTwin | null>();
      // `codexHead`: as before the review of !1604 (a row's value may be a
      // Codex result). This only spares a row whose text is twin content
      // from being a fingerprint; no release reads it, and the release
      // rules strip a head only for a Codex call.
      v = structuredTwinExecOutputPath(value, (token) =>
        structuredTwinOfField(this.symbolMap, token, { resolveLabel: this.labelLookup, cache }), { codexHead: true }) !== null;
      this.twinPieceRowCache.set(name, v);
    }
    return v;
  }

  /** The value backstop (the `scanSecretValues` op, and the classify-time
   *  scan): every active secret row whose value, or (a multi-line secret such
   *  as a labeled document) one of whose long lines, appears in `text`. An
   *  exec-output row counts only when its own call's tree held a secret (see
   *  the op's comment). */
  private secretValueHits(text: string): ScanSecretValuesResultWire["hits"] {
    // The whole value, or any line long enough to stand alone, so a diff or
    // a partial print of a copy the guard never saw opened still counts
    // (egress-fingerprint.ts MIN_LINE_FINGERPRINT_LEN). One pass over the
    // text for every row (plan 15 §4.1); the per-row `secretValueMatch` it
    // replaces is the reference its equivalence test compares against.
    return this.levelledValueHits(this.syncedValueIndex().hits(text));
  }

  /** The value index's hits (over a text, or a streamed file), each row
   *  re-read live: its level, and an exec-output row only with its call's
   *  evidence (`backstopRowLevel`). */
  private levelledValueHits(found: ReadonlyArray<{ symbol: string; how: ValueHow }>): ScanSecretValuesResultWire["hits"] {
    const hits: ScanSecretValuesResultWire["hits"] = [];
    const evidence = new Map<string, boolean>();
    for (const { symbol: name, how } of found) {
      const level = this.backstopRowLevel(name, evidence);
      if (level === null) continue;
      hits.push({ symbol: name, level, how });
    }
    return hits;
  }

  /**
   * The value-only release the classify op offers beside a value-backstop
   * raise (docs/design/confidentiality/backstop-value-only.md §2, A2-A7):
   * each counted whole-value occurrence of a registered single-line value
   * replaced by that row's symbol (`planValueOnly`), then verified twice on
   * what would be released: the backstop's own scan finds nothing in the
   * planned text, and the residue scan (`ResidueScanner`: every secret
   * row's value encoded, spread or in fragments) finds nothing in the text
   * outside the replaced spans. Null (mask whole) on any refusal, and on any
   * error: the offer is never the fail-open path.
   */
  private valueOnlyOffer(text: string): ArbiterServerValueOnly | null {
    try {
      const evidence = new Map<string, boolean>();
      const index = this.syncedValueIndex();
      // A row whose pieces were cut at the bound (plan 10 §11.18): a piece
      // past the bound is matched by nothing, so nothing can be proved.
      if (index.incompleteRows().size > 0) return null;
      const occ = index.occurrences(text).filter((o) => this.backstopRowLevel(o.symbol, evidence) !== null);
      const order = new Map(index.rowNames().map((n, i) => [n, i]));
      const plan = planValueOnly(text, occ, (symbol) => {
        const e = this.symbolMap.symbols.get(symbol);
        return e ? { value: e.value, level: parseConfidentialityLevel(e.confidentiality), order: order.get(symbol) ?? Number.MAX_SAFE_INTEGER } : undefined;
      });
      if (!plan.ok) return null;
      if (this.secretValueHits(plan.text).length > 0) return null;
      const check = residueCheckText(text, plan.spans);
      if (this.residueScanner().find(check) !== null) return null;
      // The values this release replaces are also looked for spread and in
      // fragments, whatever they look like (review round 4).
      const replaced = [...new Set(plan.spans.map((s) => this.symbolMap.symbols.get(s.symbol)?.value ?? ""))];
      if (new ResidueScanner(replaced).find(check) !== null) return null;
      return { text: plan.text, spans: plan.spans };
    } catch (err) {
      this.log(`value-only release refused (error): ${(err as Error).message}`);
      return null;
    }
  }

  /**
   * The clean-tree release (docs/design/confidentiality/clean-tree-release.md
   * §2, rules R1-R8): the offer beside a path-derived verdict of a shell
   * command, or null (the result is masked whole). `req` is the request as
   * the policy classified it (`withCallStartDir` applied), whose verdict is
   * secret by the path rules alone. No offer unless the call's recorded tree
   * read no secret, every secret reading of the command is a reading of a
   * registered credential file (the counterfactual, R4), and the text holds
   * no secret byte of those files in any form looked for; registered values
   * become their symbols as in the value-only release.
   */
  /**
   * The evidence the clean-tree release and the compound listing both need
   * (clean-tree-release.md R1-R3, R5, R6; folder-listing-compound.md L0,
   * L7): a shell command tool, a result of at most `maxChars` holding no
   * `$MDU`, the call named, no placeholder in the call, a tree the recorder
   * bound with a root, no raw read, no refused open or connection, and the
   * command the request carries is one the proxy recorded for the call (its
   * signature among the recorded ones). The call's id, or null.
   */
  private releaseEvidence(req: ClassifyRequest, maxChars: number): string | null {
    // R1, R5, R6
    if (!this.confidentiality || typeof req.tool !== "string" || !PATH_RELEASE_TOOLS.has(req.tool)) return null;
    const value = req.value;
    if (typeof value !== "string" || value === "" || value.length > maxChars || /\$MDU/i.test(value)) return null;
    const callId = typeof req.callId === "string" && req.callId !== "" ? req.callId
      : typeof req.treeCallId === "string" && req.treeCallId !== "" ? req.treeCallId : null;
    if (callId === null) return null;
    // R2
    if (callHoldsPlaceholder([req.origin, req.originHuman, req.params, req.paramsHuman])) return null;
    // R3: a tree the recorder bound, with a root, no raw read, no refused
    // open, no refused connection (one tied to no process included)
    const tree = this.provenance.callTree(callId, { readOnly: true });
    if ((tree.binding !== "exact" && tree.binding !== "shared") || tree.root === null || tree.level !== null || tree.rows.length > 0) return null;
    if (tree.denied.length > 0 || (tree.refusedEgress?.length ?? 0) > 0) return null;
    if (this.provenance.unattributedEgressRefusalsFor(callId, req.sessionKey).length > 0) return null;
    // the command the request carries is the one the call was given
    // (folder-listing-compound.md L7; design review round 3: nothing tied the
    // history's echo of the command to the recorded one on this path)
    // (an argv, Codex's classic `shell` / `local_shell`, by its own
    // elements: implementation review round 2)
    const params = (req.params ?? {}) as Record<string, unknown>;
    const raw = params["cmd"] ?? params["command"];
    const signature = typeof raw === "string" ? execSignature(raw)
      : Array.isArray(raw) && raw.length > 0 && raw.every((w) => typeof w === "string") ? execSignatureForArgv(raw as string[]) : null;
    if (signature === null || signature === "") return null;
    const recorded = this.provenance.callCommandSignatures(callId);
    if (recorded.length === 0 || !recorded.includes(signature)) return null;
    return callId;
  }

  /**
   * A folder's names beside another command
   * (docs/design/confidentiality/folder-listing-compound.md §2, L0-L9): the
   * clean-tree release's offer (`spans` empty) with `listing`, beside a
   * path-derived verdict of a shell command such as `tools/mail list; ls
   * mail/inbox bank`, or null (the result is masked whole). `req` is the
   * request as the policy classified it.
   */
  private compoundListingOffer(req: ClassifyRequest): (ArbiterServerValueOnly & { listing: { operands: string[]; part: "first" | "last" } }) | null {
    try {
      // L0, L7
      const callId = this.releaseEvidence(req, KEY_LISTING_OUTPUT_MAX);
      if (callId === null || this.policy.pathLevelWith === undefined) return null;
      const value = req.value;
      const params = (req.params ?? {}) as Record<string, unknown>;
      // L6: every command source a string, each the same compound
      const agentCommand = typeof params["cmd"] === "string" ? params["cmd"] as string : typeof params["command"] === "string" ? params["command"] as string : null;
      if (agentCommand === null) return null;
      const c = compoundLsCommand(agentCommand);
      if (c === null) return null;
      for (const x of [params, req.paramsHuman ?? {}] as Array<Record<string, unknown>>) {
        for (const k of ["command", "cmd"]) if (x[k] !== undefined && typeof x[k] !== "string") return null;
      }
      if (params["tty"] === true || (params["shell"] !== undefined && !(typeof params["shell"] === "string" && /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh)$/.test(params["shell"])))) return null;
      // L3: a `/` first word that is a directory refuses (interactive bash's autocd)
      const start = req.callStartDir ?? this.provenance.callStartDir(callId);
      if (start === null || start === undefined) return null;
      const workdir = this.policy.callWorkdirOf?.(req);
      if (req.callStartDir === undefined && workdir !== undefined && workdir !== start) return null;
      for (const [i, seg] of c.segments.entries()) {
        if (i === c.lsIndex) continue;
        const first = seg.split(" ")[0]!;
        if (first.includes("/")) {
          try { if (statSync(first.startsWith("/") ? first : join(start, first)).isDirectory()) return null; } catch { /* not there: the shell fails, nothing printed */ }
        }
      }
      // L4: the request with every command source rebuilt without the
      // listing segment, read by the path rules with the engine's own lookup
      const rebuild = (t: unknown): string | null | undefined => typeof t !== "string" ? (t === undefined ? undefined : null) : compoundWithoutLs(t, c.lsIndex, c.segments.length);
      const rebuildParams = (x: Record<string, unknown> | undefined): Record<string, unknown> | null | undefined => {
        if (x === undefined) return undefined;
        const out = { ...x };
        for (const k of ["command", "cmd"]) {
          if (x[k] === undefined) continue;
          const r = rebuild(x[k]);
          if (r === null || r === undefined) return null;
          out[k] = r;
        }
        return out;
      };
      const isCommand = (t: unknown): boolean => typeof t === "string" && (t === params["command"] || t === params["cmd"] || t === (req.paramsHuman as Record<string, unknown> | undefined)?.["command"] || t === (req.paramsHuman as Record<string, unknown> | undefined)?.["cmd"]);
      const origin = isCommand(req.origin) ? rebuild(req.origin) : req.origin;
      const originHuman = isCommand(req.originHuman) ? rebuild(req.originHuman) : req.originHuman;
      const p2 = rebuildParams(req.params as Record<string, unknown> | undefined);
      const ph2 = rebuildParams(req.paramsHuman as Record<string, unknown> | undefined);
      if (origin === null || originHuman === null || p2 === null || ph2 === null) return null;
      const cfReq = { ...req, ...(origin !== undefined ? { origin } : {}), ...(originHuman !== undefined ? { originHuman } : {}), ...(p2 ? { params: p2 } : {}), ...(ph2 ? { paramsHuman: ph2 } : {}) } as ClassifyRequest;
      if (isSecret(this.policy.pathLevelWith(cfReq, this.labelLookup))) return null;
      // L8: exactly one exec of `ls`, with the listing's operands
      const argvs = this.provenance.callTreeExecArgvs(callId);
      if (argvs === null) return null;
      const lsExecs = argvs.filter((a) => isLsArgv(a));
      if (lsExecs.length !== 1 || !lsArgvMatches(lsExecs[0]!, c.ls)) return null;
      // R7: no registered value, nothing the residue scan, the shapes or the
      // bare-token check find
      if (this.syncedValueIndex().incompleteRows().size > 0) return null;
      if (this.secretValueHits(value).length > 0 || this.residueScanner().find(value) !== null) return null;
      if (pathReleaseContentProblem(value, []) !== null) return null;
      // L5 (L9: once offered for this exact result, not compared again)
      const memoKey = `${callId}\u0000${createHash("sha256").update(value, "utf8").digest("hex")}`;
      const part: "first" | "last" = c.lsIndex === 0 ? "first" : "last";
      if (!this.compoundListings.has(memoKey)) {
        const lsSegment = c.segments[c.lsIndex]!;
        const codexHead = typeof req.treeCallId === "string" && req.callId === undefined;
        const paths = compoundListingPaths(value, lsSegment, part === "first", hostListingFs(start, homedir()), { codexHead });
        if (paths === null) return null;
        this.compoundListings.add(memoKey);
        if (this.compoundListings.size > 4096) this.compoundListings.delete(this.compoundListings.values().next().value!);
      }
      return { text: value, spans: [], listing: { operands: [...c.ls.operands], part } };
    } catch (err) {
      this.log(`compound listing refused (error): ${(err as Error).message}`);
      return null;
    }
  }

  private pathReleaseOffer(req: ClassifyRequest): ArbiterServerValueOnly | null {
    try {
      const callId = this.releaseEvidence(req, VALUE_ONLY_MAX_CHARS);
      if (callId === null) return null;
      const value = req.value;
      // R4: the credential files, then the counterfactual reading
      if (this.policy.pathLevelWith === undefined) return null;
      const index = this.syncedValueIndex();
      if (index.incompleteRows().size > 0) return null;
      const registered = new Set(registeredFilePaths(this.symbolMap));
      const credential = new Map<string, readonly string[]>();
      for (const path of registered) {
        if (this.fileUnpieced(path)) continue;
        const level = this.protectedLevelOf(path);
        if (level === null || !isSecret(level)) continue;
        const twin = structuredTwinWithSecretsFor(this.symbolMap, path, { resolveLabel: this.labelLookup });
        if (twin === null || twin.secrets.length === 0) continue;
        const text = this.readPlainFileBounded(path, this.pieceLimits.scanChars);
        if (text === null || !fileRegisteredAsIs(this.symbolMap, path, text, level)) continue;
        // R7d: the file's masked values, and every value an earlier
        // registration of it held (a rotated key an old commit may print;
        // review round 1 of the design, finding 2)
        const own = [...twin.secrets];
        for (const e of this.symbolMap.symbols.values()) {
          if (e.origin === path && e.field !== null && isSecret(e.confidentiality) && !/\$MDU/i.test(e.value)) own.push(e.value);
        }
        credential.set(path, own);
      }
      if (credential.size === 0) return null;
      const exists = (p: string): boolean => {
        try { lstatSync(p); return true; } catch (err) { return (err as NodeJS.ErrnoException).code !== "ENOENT"; }
      };
      // The places a relative token is read in: the call's start directory
      // (the guard's, or a shell's absolute `workdir`) and each plain `cd`
      // of every command text the request carries, each known absolutely.
      // The `workdir` only as the classify reads it: for a tool whose gate
      // surface acts on one (review round 3: Claude Code's Bash ignores a
      // `workdir` the model writes).
      const params = (req.params ?? {}) as Record<string, unknown>;
      const workdir = this.policy.callWorkdirOf?.(req);
      const start = req.callStartDir ?? (workdir !== undefined && workdir.startsWith("/") ? workdir : undefined) ?? null;
      const texts = [req.origin, req.originHuman, ...[params, req.paramsHuman ?? {}].map((x) => {
        const c = (x as Record<string, unknown>)["command"] ?? (x as Record<string, unknown>)["cmd"];
        return Array.isArray(c) && c.every((w) => typeof w === "string") ? c.join(" ") : c;
      })].filter((t): t is string => typeof t === "string" && t !== "");
      let dirs: string[] | null = texts.length === 0 ? null : [];
      for (const t of texts) {
        const d = wordDirectories(t, start, (c, s0) => commandDirsReached(c, s0), { directoryMayChange, unresolvedDirChange });
        if (d === null || dirs === null) { dirs = null; break; }
        dirs.push(...d);
      }
      // Every string the path rules may read as one whole path: each string
      // of the request and, for a tool the spec does not map
      // (`labelForUnmappedInput`), each object key. A `file:` URL, which
      // that scan decodes into another string, refuses the release (review
      // round 2). Deeper than the scan's own bound refuses too.
      const sources = new Set<string>();
      let unread = false;
      const addSources = (x: unknown, depth = 0): void => {
        if (depth > 16) { unread = true; return; }
        if (typeof x === "string") { sources.add(x); if (/file:/i.test(x)) unread = true; }
        else if (Array.isArray(x)) for (const v of x) addSources(v, depth + 1);
        else if (x !== null && typeof x === "object") for (const [k, v] of Object.entries(x as Record<string, unknown>)) { addSources(k, depth + 1); addSources(v, depth + 1); }
      };
      addSources([req.origin, req.originHuman, req.params, req.paramsHuman]);
      if (unread) return null;
      // The request the counterfactual reads: each command text with its
      // message words blanked (`messageSpans`: `printf`/`echo` arguments, a
      // `git commit -m` message), never opened by any program.
      const blank = (t: unknown): unknown => typeof t === "string" ? blankSpans(t, messageSpans(t)) : t;
      const blankParams = (x: Record<string, unknown> | undefined): Record<string, unknown> | undefined => x === undefined ? x
        : { ...x, ...(typeof x["command"] === "string" ? { command: blank(x["command"]) } : {}), ...(typeof x["cmd"] === "string" ? { cmd: blank(x["cmd"]) } : {}) };
      const cfReq: ClassifyRequest = {
        ...req,
        ...(typeof req.origin === "string" ? { origin: blank(req.origin) as string } : {}),
        ...(typeof req.originHuman === "string" ? { originHuman: blank(req.originHuman) as string } : {}),
        ...(req.params ? { params: blankParams(req.params as Record<string, unknown>) } : {}),
        ...(req.paramsHuman ? { paramsHuman: blankParams(req.paramsHuman as Record<string, unknown>) } : {}),
      } as ClassifyRequest;
      addSources([cfReq.origin, cfReq.originHuman, cfReq.params, cfReq.paramsHuman]);
      // and each as the path rules may read it: the shell command with its
      // grep exclusions blanked (exclusion-flags.md; its implementation
      // review found the blanked whole command answered as an empty place)
      for (const x of [...sources]) sources.add(withoutGrepExclusions(x));
      const words = new Set(texts.flatMap((t) => commandWords(t)));
      const lookup = counterfactualLookup(this.labelLookup, {
        credentialFiles: new Set(credential.keys()), registered, exists, sources, dirs: dirs === null ? null : [...new Set(dirs)], words,
      });
      if (isSecret(this.policy.pathLevelWith(cfReq, lookup))) return null;
      // R7: the content, with each registered value its own symbol
      let offer: ArbiterServerValueOnly;
      let check: string;
      if (this.secretValueHits(value).length === 0) {
        if (this.residueScanner().find(value) !== null) return null;
        offer = { text: value, spans: [] };
        check = value;
      } else {
        const vo = this.valueOnlyOffer(value);
        if (vo === null) return null;
        offer = vo;
        check = residueCheckText(value, vo.spans);
      }
      if (pathReleaseContentProblem(check, [...credential.values()].flat()) !== null) return null;
      return offer;
    } catch (err) {
      // R8
      this.log(`clean-tree release refused (error): ${(err as Error).message}`);
      return null;
    }
  }

  /** The residue scan over every active secret row whose value is one line
   *  of RESIDUE_MIN_LEN or more and holds no symbol token (a twin's piece, a
   *  vetted config's own text: no secret byte), rebuilt when that set of
   *  values changes. Every such value is looked for whole in every form; only
   *  those that read as a credential (`looksLikeSecretValue`), and are no
   *  command's whole output, also spread and in fragments (review round 4:
   *  an earlier one-line output `payments: connected to Stripe`, or a field
   *  `noreply@shop.example.com`, refused every log sharing a word with it).
   *  The values a release replaces get the fragment checks in any case
   *  (`valueOnlyOffer`). */
  private residueScanner(): ResidueScanner {
    const values: string[] = [];
    const fragments: string[] = [];
    for (const [name, e] of this.symbolMap.symbols) {
      if (!indexableRow(e)) continue;
      const v = e.value.replace(/\r?\n$/, "");
      if (v.length < RESIDUE_MIN_LEN || /[\r\n]/.test(v) || /\$MDU/i.test(v)) continue;
      if (this.isTwinPieceRow(name, e.value) || this.isOwnTextRow(name) || this.isDocumentNameRow(name, e)) continue;
      values.push(v);
      if (!EXEC_OUTPUT_TOOLS.has(e.tool) && looksLikeSecretValue(v)) fragments.push(v);
    }
    const key = createHash("sha256").update(JSON.stringify([values, fragments])).digest("hex");
    if (this.residue?.key !== key) this.residue = { key, scanner: new ResidueScanner(values, fragments) };
    return this.residue.scanner;
  }

  /** Plan 10 §11.14: remember that `name`'s value is an agent's whole result
   *  led by its runtime's own head, when the request says so AND the value
   *  starts with exactly that grammar (the index re-matches it on the row's
   *  value anyway). Only lowers what the index fingerprints for that row's
   *  head; the whole value and every line after the head stay (a value
   *  that is all head has neither: RegisteredValueIndex.sync). Stored with
   *  the row, bound to its value (`ResultHeadStore`); a failed store keeps
   *  the mark for this process only (fail-closed after a restart). */
  private learnResultHead(name: string, req: { value: string; resultHead?: string }): void {
    const kind = parseResultHead(req.resultHead);
    if (kind === null || this.headedRows.has(name)) return;
    const e = this.symbolMap.symbols.get(name);
    if (e === undefined || e.value !== req.value || resultHeadLength(kind, e.value, e.origin) === 0) return;
    // A write notice leads only a write tool's own whole result (plan 15
    // §13.10): never a field row, never another tool's.
    if (kind === "write-notice" && !writeNoticeRow(e)) return;
    const value = e.value;
    this.headedRows.set(name, kind);
    this.resultHeadsVersion++;
    try {
      this.resultHeadStore.record(name, kind, value);
    } catch (err) {
      this.log(`result head of ${name} not stored (kept in memory): ${(err as Error).message}`);
    }
  }

  /**
   * Plan 10 §11.15, case 2 (the maintainer, 2026-10-03): the guard reported,
   * on the human plane, a raw read of `path`, a labelled secret; register the
   * file as the launcher would (`registerSecret`: the arbiter reads it, the
   * label's level and bindings, a structured twin's fields), so its values
   * are known secrets the value backstop, the tripwire and the prompt filter
   * match even when the launch never registered it. Called ONLY on an
   * attested report: a data-socket claim never makes the arbiter read or
   * register a file. No output is registered. Idempotent: the launch's own
   * reuse key (no session), and a file whose size and mtime have not moved
   * since its last registration here is not read again. Plan 10 §11.18: a
   * file over 1 MiB or binary is registered too (its pieces are computed
   * window by window, a binary file's from its printable strings); a file
   * over the bound (`pieceLimits.scanChars`) is not read: it is recorded as
   * UNPIECED, and the arbiter fails closed on it (`fileUnpieced`). Never
   * throws.
   */
  private registerReadFile(path: string, why = "guard-reported raw read"): void {
    if (!this.confidentiality) return;
    try {
      const st = statSync(path);
      if (!st.isFile() || st.size === 0) return;
      const stamp = `${st.size}:${st.mtimeMs}:${st.ino}`;
      if (st.size > this.pieceLimits.scanChars) {
        if (this.unpiecedFiles.get(path) !== stamp) this.log(`registerSecret (${why}): ${path} is over the piece bound (${st.size} bytes > ${this.pieceLimits.scanChars}): not registered; its readers' output is masked whole (plan 10 §11.18)`);
        this.unpiecedFiles.set(path, stamp);
        this.selfRegistered.delete(path);
        return;
      }
      this.unpiecedFiles.delete(path);
      if (this.selfRegistered.get(path) === stamp) return;
      const bytes = readFileSync(path);
      // The launch registered this very text (at a level at least the
      // label's): it is a known secret already. A second base row under the
      // self-registration's key (no session, no launch HOME, so no wire
      // binding) would be "the newest registration" one second later and
      // take the `.npmrc` wire twin away (`fileRegisteredAsIs`).
      const pm = pathConfidentiality(path, undefined, this.labelLookup);
      const level = pm.level;
      // A PDF or Office document under an `extract:` is registered by its
      // text (registry.ts `registeredDocumentText`, secret-discovery.md §2.8).
      const asText = (pm.extract !== undefined ? registeredDocumentText(path) : null) ?? bytes.toString("utf8");
      if (isSecret(level) && fileRegisteredAsIs(this.symbolMap, path, asText, level)) { this.selfRegistered.set(path, stamp); return; }
      const result = registerSecret(this.symbolMap, { path, resolveLabel: this.labelLookup, fieldGrants: this.fieldGrants }, this.dbPath ?? getSymbolDbPath());
      this.selfRegistered.set(path, stamp);
      if (result.symbol !== null) this.log(`registerSecret (${why}): ${path} → ${result.symbol} (${result.reason})`);
    } catch (err) {
      this.log(`registerSecret (${why}) failed for ${path} (ignored): ${(err as Error).message}`);
    }
  }

  /**
   * Plan 10 §11.18, fail-closed: are the pieces of the labelled file `path`
   * unknown? True for a file a raw read found over the bound (not
   * registered), and for a file whose registered row's pieces the value
   * index cut at the bound. A piece of such a file past the bound would not
   * be matched, so no output rule releases a call that read it raw
   * (`callTaint`), and a holder's copy of it is not read raw
   * (`decideSecretOpen`, plan 13 D4).
   */
  private fileUnpieced(path: string): boolean {
    if (this.unpiecedFiles.has(path)) return true;
    const incomplete = this.syncedValueIndex().incompleteRows();
    if (incomplete.size === 0) return false;
    for (const name of incomplete) {
      const e = this.symbolMap.symbols.get(name);
      if (e && e.origin === path && e.field === null && e.obsoleted_at === null) return true;
    }
    return false;
  }

  /**
   * A kept row's exemption in its own session's tripwire scan
   * (secret-discovery.md §2.10): null when it is exempt everywhere (a
   * login's token, an MCP stdio server's variable), or the one host it is
   * exempt at (an MCP config's HTTP server credential: the host of that
   * entry's own `url`, `ownWireHost`, read from the row's own registration).
   * Memoized by symbol name (a row's value and its base row never change).
   */
  private keptRowWireHost(name: string, entry: SymbolEntry): string | null {
    let host = this.keptWireHostMemo.get(name);
    if (host === undefined) {
      host = !mcpConfigLike(entry.origin ?? "") ? null : ownWireHost(this.symbolMap, name, entry, this.labelLookup);
      if (this.keptWireHostMemo.size >= 1024) this.keptWireHostMemo.clear();
      this.keptWireHostMemo.set(name, host);
    }
    return host;
  }

  /**
   * The values of the kept MCP configs' own field rows (secret-discovery.md
   * §2.10), each with the one host it is exempt at (`keptRowWireHost`) or
   * null (everywhere): what a session's agent and its servers send as their
   * own. Values under the fingerprint floor are left out (they never
   * fingerprint). Memoized by the kept paths and the symbol table's
   * generation.
   */
  private keptMcpValues(kept: readonly string[]): ReadonlyMap<string, string | null> {
    // An MCP config by its name, or a `config.toml` (Codex's where
    // CODEX_HOME moved it: the only `config.toml` sessionMcpConfigPaths
    // names).
    const configs = kept.filter((p) => mcpConfigLike(p));
    if (configs.length === 0) return EMPTY_KEPT_VALUES;
    const key = `${symbolMapGeneration(this.symbolMap)}\u0001${this.symbolMap.symbols.size}\u0001${configs.join("\u0000")}`;
    const memo = this.keptMcpValuesMemo;
    if (memo !== null && memo.key === key) return memo.values;
    const values = new Map<string, string | null>();
    for (const [name, e] of this.symbolMap.symbols) {
      if (e.obsoleted_at !== null || e.field === null || !isRegisteredFileRow(e) || !originUnder(e.origin ?? "", configs)) continue;
      if (!isSecret(parseConfidentialityLevel(e.confidentiality)) || e.value.length < MIN_FINGERPRINT_LEN) continue;
      const host = this.keptRowWireHost(name, e);
      // An Authorization value's credential after its scheme word (`Bearer
      // <token>`) is the same credential: a tool result's row may hold it
      // as a bare token.
      const scheme = /^(?:bearer|basic|token)\s+(\S+)$/i.exec(e.value);
      for (const v of scheme !== null && scheme[1]!.length >= MIN_FINGERPRINT_LEN ? [e.value, scheme[1]!] : [e.value]) {
        // Two rows of one value: exempt only as far as both are.
        const prev = values.get(v);
        values.set(v, prev === undefined ? host : prev === null ? host : host === null ? prev : prev === host ? host : "\u0000none");
      }
    }
    this.keptMcpValuesMemo = { key, values };
    return values;
  }

  /**
   * The login files a session leaves raw (secret-discovery.md §1.10), from
   * its net-proxy's `sessionLogins`: every spelling `sessionLoginPaths`
   * gives, and the real path of each (a row registered from a guard report
   * carries the real path). Empty for a malformed or absent value: nothing
   * is exempt, so the tripwire fires as before (the strict direction).
   * Memoized by the wire value; a real path is read when first asked.
   * Since 2026-10-21 also the kept agents' MCP configs (§2.10).
   */
  private sessionLoginExemptions(raw: unknown): readonly string[] {
    const s = parseSessionLogins(raw);
    if (s === null) return [];
    const key = JSON.stringify(s);
    let paths = this.sessionLoginMemo.get(key);
    if (paths === undefined) {
      const out = new Set<string>();
      for (const p of sessionLoginPaths(s)) {
        out.add(p);
        try { out.add(realpathSync(p)); } catch { /* not there (yet): its own spelling stands */ }
      }
      paths = [...out];
      if (this.sessionLoginMemo.size >= 64) this.sessionLoginMemo.clear();
      this.sessionLoginMemo.set(key, paths);
    }
    return paths;
  }

  /** The value index, brought up to date with the symbol table. */
  private syncedValueIndex(): RegisteredValueIndex {
    this.valueIndex.sync(
      this.symbolMap,
      // Plan 10 §11.14: the head is re-matched on the row's own value, so
      // a row whose value does not start with the exact grammar keeps
      // every line.
      // Plan 15 §13.10: a write tool's row whose WHOLE value is its own
      // success notice is all head, mark or no mark (a row minted before
      // the `write-notice` mark, or the notice body of a result whose
      // reminder tail the proxy split off): it holds no piece at all.
      (name, e) => {
        if (isWholeWriteNotice(e.tool, e.field, e.value, e.origin)) return e.value.length;
        const kind = this.headedRows.get(name);
        if (kind === undefined || (kind === "write-notice" && !writeNoticeRow(e))) return 0;
        return resultHeadLength(kind, e.value, e.origin);
      },
      // Both counters only grow, so their sum moves whenever either does.
      this.resultHeadsVersion + this.raisedRowsVersion,
      // Plan 10 §11.8: a line a registered file's own structured twin carries
      // verbatim (a `.env` comment) is no fingerprint of that file's row: the
      // agent is shown it in the twin, and as one it masked every Read of
      // the twin whole. Base rows of registered files; and (review of !1604,
      // second pass) a proxy's own row on a registered file's path (a Read
      // it masked whole: the file's bytes again), whose twin lines otherwise
      // masked every later Read, `cat` and key listing of the twin whole.
      // Plan 10 §11.8, "A twin line is no piece of an output that prints
      // it" (2026-10-19): any other output row, from the twins of the
      // registered files whose placeholders its value carries
      // (`outputRowTwin`).
      (name, e) => {
        if (e.field !== null) return null;
        if (e.call_id === null) return registeredFileTwin(this.symbolMap, name, { resolveLabel: this.labelLookup });
        return (typeof e.origin === "string" ? this.registeredTwinOfPath(e.origin) : null) ?? this.outputRowTwin(name, e);
      },
      // Plan 15 §4.1: a row the value backstop raised keeps only the lines a
      // registered secret was found in (`learnRaisedRow`).
      (name) => this.raisedRows.get(name) ?? null,
      // Secret-discovery.md §2.7, "A person's name" (2026-10-19): the
      // holder's name in a personal document's twin is no fingerprint, so
      // a mail quoting the user is not masked whole.
      (name, e) => this.isDocumentNameRow(name, e),
    );
    return this.valueIndex;
  }

  /** Plan 15 §4.1: the keys a classify's record is kept under: the call
   *  (when the classify names it), and the value itself (the openai-proxy's
   *  classify names no call; its symbolize of the whole output carries the
   *  same value). */
  private backstopCallKeys(sessionKey: unknown, callId: unknown, value: unknown): string[] {
    if (typeof sessionKey !== "string" || sessionKey === "") return [];
    const keys: string[] = [];
    if (typeof callId === "string" && callId !== "") keys.push(`${sessionKey}\u0000c\u0000${callId}`);
    if (typeof value === "string") keys.push(`${sessionKey}\u0000v\u0000${createHash("sha256").update(value, "utf8").digest("hex")}`);
    return keys;
  }

  /** Plan 15 §4.1: remember what this arbiter's classify said of a call's
   *  result (`backstopCalls`). Bounded: the oldest record is dropped first. */
  private noteBackstopCall(sessionKey: unknown, callId: unknown, value: unknown, patch: { raised?: boolean; policySecret?: boolean; path?: { files: readonly string[] | null; placed: readonly string[]; level: ConfidentialityLevel; ifCdFailed?: { dir: string; namedFiles: readonly string[]; placedFiles: readonly string[] } | null } }): void {
    for (const k of this.backstopCallKeys(sessionKey, callId, value)) {
      const cur = this.backstopCalls.get(k) ?? { raised: false, policySecret: false, pathMixed: false };
      this.backstopCalls.delete(k);
      const next: BackstopCallRecord = { raised: cur.raised || patch.raised === true, policySecret: cur.policySecret || patch.policySecret === true, pathMixed: cur.pathMixed };
      if (patch.policySecret === true) {
        // Plan 15 §13.12: a policy-secret classify that is not the path
        // rule's with every reading placed spoils the call's path record.
        const files = patch.path?.files ?? null;
        if (files === null || files.length === 0 || next.pathMixed) next.pathMixed = true;
        else {
          next.pathFiles = [...new Set([...(cur.pathFiles ?? []), ...files])].sort();
          next.pathPlaced = [...new Set([...(cur.pathPlaced ?? []), ...patch.path!.placed])].sort();
          next.pathLevel = cur.pathLevel === undefined ? patch.path!.level : maxConfidentiality(cur.pathLevel, patch.path!.level);
          // "A cd that fails": kept only while every classify of the call
          // offered one, for the same folder (their union)
          const alt = patch.path!.ifCdFailed ?? null;
          const had = cur.pathFiles === undefined ? undefined : cur.pathIfCdFailed ?? null;
          next.pathIfCdFailed = alt === null || had === null ? null
            : had === undefined ? { dir: alt.dir, files: [...new Set(alt.namedFiles)].sort(), placed: [...new Set(alt.placedFiles)].sort() }
            : had.dir !== alt.dir ? null
            : { dir: alt.dir, files: [...new Set([...had.files, ...alt.namedFiles])].sort(), placed: [...new Set([...had.placed, ...alt.placedFiles])].sort() };
        }
      }
      if (next.pathMixed) { delete next.pathFiles; delete next.pathLevel; delete next.pathPlaced; delete next.pathIfCdFailed; }
      else if (cur.pathFiles !== undefined && next.pathFiles === undefined) { next.pathFiles = cur.pathFiles; next.pathLevel = cur.pathLevel; next.pathPlaced = cur.pathPlaced; next.pathIfCdFailed = cur.pathIfCdFailed; }
      this.backstopCalls.set(k, next);
      if (this.backstopCalls.size > 4096) this.backstopCalls.delete(this.backstopCalls.keys().next().value!);
    }
  }

  /**
   * Plan 15 §4.1, "What a raised row registers": a row the value backstop
   * made secret registers, of its long lines, only those a registered secret
   * was found in. Every line of it was a piece before, so a later unrelated
   * result sharing an ordinary line (a heading, `}`, a log line) was masked
   * whole. The row itself, its level, its whole value and its
   * credential-shaped spans are untouched: the result stays one symbol.
   *
   * Learned only when ALL of these hold (else every line stays a piece,
   * fail-closed): the symbolize says the level is the classify's backstop
   * raise and nothing else (`secretBy`, set by the proxy only when it raised
   * the verdict no further); this arbiter's classify of that call raised a
   * public verdict and never called a result of the call secret by policy;
   * the row's own origin carries no secret label and the call's process tree
   * read no secret (its output could hold a secret in a form no piece
   * matches); and the registered secrets found in the row, counted live as
   * the backstop counts them, reach the row's level. The row itself, a copy
   * of its value, and another raised row's whole value are not counted as
   * what made it secret.
   */
  private learnRaisedRow(name: string, req: { value: string; sessionKey?: string; callId?: string; origin?: string; secretBy?: unknown }, levelOrigin: string | undefined): void {
    if (!this.confidentiality || req.secretBy !== "value-backstop" || this.raisedRows.has(name)) return;
    if (typeof req.sessionKey !== "string" || typeof req.callId !== "string") return;
    // The call's record when its classify named the call, else the record
    // of a classify of exactly this value in the session.
    const note = this.backstopCallKeys(req.sessionKey, req.callId, req.value)
      .map((k) => this.backstopCalls.get(k))
      .find((n) => n !== undefined);
    if (!note || !note.raised || note.policySecret) return;
    const e = this.symbolMap.symbols.get(name);
    if (!e || e.value !== req.value || e.field !== null || e.obsoleted_at !== null || !isSecret(e.confidentiality)) return;
    if (isSecret(confidentialityForOrigin(levelOrigin, undefined, this.labelLookup).level)) return;
    if (isSecret(this.originSymbolLabel(req.origin).level)) return;
    if (this.provenance.callTaint(req.callId).level !== null) return;
    const evidence = new Map<string, boolean>();
    let reach: ConfidentialityLevel | null = null;
    const spans: Array<{ start: number; end: number }> = [];
    for (const o of this.syncedValueIndex().occurrences(e.value)) {
      if (o.symbol === name) continue;
      const src = this.symbolMap.symbols.get(o.symbol);
      if (!src || src.value === e.value) continue;
      if (o.how === "value" && this.raisedRows.has(o.symbol)) continue;
      const level = this.backstopRowLevel(o.symbol, evidence);
      if (level === null) continue;
      reach = reach === null ? level : maxConfidentiality(reach, level);
      spans.push({ start: o.start, end: o.end });
    }
    if (reach === null || maxConfidentiality(reach, e.confidentiality) !== reach) return;
    const keep = raisedRowKeptLines(e.value, spans);
    if (keep.size === 0) return;
    this.raisedRows.set(name, keep);
    this.raisedRowsVersion++;
    try {
      this.raisedRowStore.record(name, e.value, keep);
    } catch (err) {
      this.log(`raised row ${name} not stored (kept in memory): ${(err as Error).message}`);
    }
  }

  /**
   * One bounded read of a file the arbiter vouches for (plan 15 §13.12; the
   * clean-tree release, clean-tree-release.md R4). Second review of §13.12:
   * a size-0 pseudo-file such as `/proc/<pid>/pagemap` reads without end, so
   * the descriptor's own stat decides: a regular non-empty file, at most
   * `cap` bytes, its own real path, never under the kernel's pseudo
   * filesystems or Mandu's own state. `plain`: also one name only (not a
   * hard link to another file) and not changed since the call was relayed.
   * Null on anything else.
   */
  private readPlainFileBounded(f: string, cap: number, plain?: { relay: number }): string | null {
    const dbFile = this.dbPath ?? getSymbolDbPath();
    const ownDirs = [...ownDbDirs(dirname(dbFile)), this.events.directory];
    if (/^\/(?:proc|sys|dev|run)(?:\/|$)/.test(f) || f.startsWith(dbFile) || ownDirs.some((d) => f === d || f.startsWith(`${d}/`))) return null;
    let fd: number | null = null;
    try {
      if (realpathSync(f) !== f) return null;
      fd = openSync(f, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW);
      const st = fstatSync(fd);
      if (!st.isFile() || st.size === 0 || st.size > cap) return null;
      if (plain && (st.nlink !== 1 || st.mtimeMs > plain.relay)) return null;
      const buf = Buffer.alloc(st.size);
      let off = 0;
      while (off < st.size) {
        const n = readSync(fd, buf, off, st.size - off, off);
        if (n <= 0) break;
        off += n;
      }
      return buf.subarray(0, off).toString("utf8");
    } catch {
      return null;
    } finally {
      if (fd !== null) try { closeSync(fd); } catch { /* ignore */ }
    }
  }

  /**
   * Plan 15 §13.12, "What a path row registers": a row masked whole ONLY
   * because its command names a secret path (the path-derived precaution)
   * registers, of its long lines, those a registered secret was found in
   * and those no plain file the command names holds (condition 5), plus
   * (as for a raised row, `raisedRowPieces`) every line with a credential
   * shape, every such span and the whole value. Before, every
   * long line of the output was a piece, so a batched read (`.env`, a
   * script and the meeting notes in one command, the live c6 demo on Codex,
   * 2026-10-17) made the notes' lines a fingerprint of a row bound nowhere,
   * and the egress tripwire blocked the notes' upload to the very host the
   * `.env`'s token is bound to, in that session and every later one. The
   * row itself is untouched: its level, its symbol, the model-side mask.
   *
   * Learned only when ALL of these hold, else every line stays a piece
   * (fail-closed):
   *   1. the symbolize says the level is the path rule's and nothing else
   *      (`secretBy: "path-rule"`), and this arbiter's own classify record
   *      of the call (or of this value in the session) agrees: every
   *      policy-secret classify of it was the path rule's, each secret
   *      reading placed on a file, none raised by the value backstop, and
   *      the row's level is no higher than the path rule's;
   *   2. the row is that symbolize's own row: not a field row, active,
   *      secret, an exec tool's (`EXEC_OUTPUT_TOOLS`), minted for this call,
   *      with no placeholder anywhere in its origin (a command that carries
   *      one may be run with the value it stands for, and print it);
   *   3. the call's process tree was bound by the recorder (`exact` or
   *      `shared`, never a claim or a guess) and no process in it (or in an
   *      orphan root it may have started) opened a secret raw;
   *   4. every file the path rule placed a secret reading on is registered
   *      as it is on disk NOW (`fileRegisteredAsIs`: a registry base row of
   *      that path whose value is the file's current text, at a level at
   *      least the file's label) and its pieces are complete
   *      (`fileUnpieced`). A labelled file nobody registered, one changed
   *      since, one over the piece bound, an unreadable one: no mark. So
   *      whatever of such a file the output holds verbatim is already a
   *      piece of the file's own row, whichever way the guard served it.
   *      (A command that opens with a `cd` whose folder is not a directory
   *      now, `isDirectoryNow`, is placed where it started: the classify's
   *      `ifCdFailed` files, here and in condition 5; "A cd that fails",
   *      2026-10-19.)
   *   5. (what may go) a long line stops being a piece only when a plain
   *      file the command names (a placed token, no label's secret, its own
   *      real path, one link, unchanged since the call was relayed, not a
   *      pseudo file nor Mandu's state) holds it verbatim now: a line of
   *      unknown origin, from a read the path scan cannot place, stays a
   *      piece (review of §13.12).
   */
  private learnPathRow(name: string, req: { value: string; sessionKey?: string; callId?: string; origin?: string; secretBy?: unknown }): void {
    if (!this.confidentiality || req.secretBy !== "path-rule" || this.raisedRows.has(name)) return;
    if (typeof req.sessionKey !== "string" || typeof req.callId !== "string" || req.callId === "") return;
    // 1. the classify record
    const notes = this.backstopCallKeys(req.sessionKey, req.callId, req.value)
      .map((k) => this.backstopCalls.get(k))
      .filter((n): n is BackstopCallRecord => n !== undefined);
    if (notes.length === 0 || notes.some((n) => n.raised || n.pathMixed || n.pathFiles === undefined || n.pathLevel === undefined)) return;
    // "A cd that fails" (2026-10-19): a command that opens with a `cd` whose
    // folder is not a directory now could not have entered it (or removed
    // it): its readings are placed where the command started instead. The
    // one choice, read off the disk here; every condition below still holds.
    const alts = notes.map((n) => n.pathIfCdFailed ?? null);
    const failedCd = alts.every((a) => a !== null) && new Set(alts.map((a) => a!.dir)).size === 1 && !isDirectoryNow(alts[0]!.dir);
    const files = [...new Set(notes.flatMap((n) => (failedCd ? n.pathIfCdFailed!.files : n.pathFiles!)))];
    const placed = [...new Set(notes.flatMap((n) => (failedCd ? n.pathIfCdFailed!.placed : n.pathPlaced ?? [])))];
    const pathLevel = notes.map((n) => n.pathLevel!).reduce((a, b) => maxConfidentiality(a, b));
    // 2. the row
    const e = this.symbolMap.symbols.get(name);
    if (!e || e.value !== req.value || e.field !== null || e.obsoleted_at !== null || !isSecret(e.confidentiality)) return;
    if (!EXEC_OUTPUT_TOOLS.has(e.tool) || e.call_id !== req.callId) return;
    if (maxConfidentiality(e.confidentiality, pathLevel) !== pathLevel) return;
    // A command that carries a placeholder (whole, inside its text, or with
    // its `$` lost to a shell) may be run with the value it stands for, and
    // print it: no mark, whatever the token's row says.
    if (typeof req.origin !== "string" || req.origin.includes("MDU:") || isSecret(this.originSymbolLabel(req.origin).level)) return;
    // 3. the tree
    const tree = this.provenance.callTree(req.callId, { readOnly: true });    if ((tree.binding !== "exact" && tree.binding !== "shared") || tree.level !== null) return;
    // 4. the files (each its own real path: the kernel resolves a symlink,
    // and the registration is keyed by the path as spelled)
    if (files.length === 0) return;
    const readBounded = (f: string, cap: number, plain?: { relay: number }): string | null => this.readPlainFileBounded(f, cap, plain);
    for (const f of files) {
      if (this.fileUnpieced(f)) return;
      const text = readBounded(f, this.pieceLimits.scanChars);
      if (text === null) return;
      const label = pathConfidentiality(f, undefined, this.labelLookup).level;
      if (!isSecret(label) || !fileRegisteredAsIs(this.symbolMap, f, text, label)) return;
    }
    // 5. what may stop being a piece: a long line some OTHER file the
    // command names holds verbatim, a file no label calls secret, read now
    // (review of §13.12: a line of unknown origin, from a read the path scan
    // cannot place, stays a piece). Bounded like one value's scan.
    const secretFiles = new Set(files);
    const plainLines = new Set<string>();
    let budget = this.pieceLimits.scanChars;
    const relay = this.provenance.callRelayTime(req.callId);
    for (const f of relay === null ? [] : placed) {
      if (secretFiles.has(f) || budget <= 0) continue;
      if (isSecret(pathConfidentiality(f, undefined, this.labelLookup).level)) continue;
      const text = readBounded(f, budget, { relay: relay! });
      if (text === null) continue;
      budget -= text.length;
      for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (line.length >= MIN_LINE_FINGERPRINT_LEN) plainLines.add(line);
      }
    }
    // The lines a registered secret was found in, counted as the value
    // backstop counts them (`learnRaisedRow`); none is the usual case.
    const evidence = new Map<string, boolean>();
    const spans: Array<{ start: number; end: number }> = [];
    for (const o of this.syncedValueIndex().occurrences(e.value)) {
      if (o.symbol === name) continue;
      const src = this.symbolMap.symbols.get(o.symbol);
      if (!src || src.value === e.value) continue;
      if (o.how === "value" && this.raisedRows.has(o.symbol)) continue;
      if (this.backstopRowLevel(o.symbol, evidence) === null) continue;
      spans.push({ start: o.start, end: o.end });
    }
    const keep = new Set(raisedRowKeptLines(e.value, spans));
    e.value.split("\n").forEach((raw, i) => {
      const line = raw.trim();
      if (line.length >= MIN_LINE_FINGERPRINT_LEN && !plainLines.has(line)) keep.add(i);
    });
    this.raisedRows.set(name, keep);
    this.raisedRowsVersion++;
    try {
      this.pathRowStore.record(name, e.value, keep);
    } catch (err) {
      this.log(`path row ${name} not stored (kept in memory): ${(err as Error).message}`);
    }
  }

  /** A matched row's level when the value backstop counts it, read live,
   *  else null. `evidence` memoizes the call-taint answers of one scan. */
  private backstopRowLevel(name: string, evidence: Map<string, boolean>): ConfidentialityLevel | null {
    const e = this.symbolMap.symbols.get(name);
    if (!e || e.obsoleted_at !== null || !isSecret(e.confidentiality)) return null;
    if (EXEC_OUTPUT_TOOLS.has(e.tool)) {
      // An exec-output row counts only when its own call's tree held a
      // secret (the `scanSecretValues` op's comment). A background poll's
      // row (`BashOutput`, whose own id binds no tree) counts by the tree of
      // the call the proxy tied the poll to (plan 13 D7, `call_polls`).
      const callId = e.call_id;
      if (callId === null) return null;
      let held = evidence.get(callId);
      if (held === undefined) {
        held = this.provenance.callTaint(callId).level !== null;
        const of = held ? null : this.provenance.pollOf(callId);
        if (of !== null) held = this.provenance.callTaint(of).level !== null;
        evidence.set(callId, held);
      }
      if (!held) return null;
    }
    // A row whose value is (a piece of) a registered file's structured
    // twin holds no secret byte (plan 10 §11.8): an agent's read of the
    // twin masked whole at the path-derived level. Fingerprinting it made
    // every later rendering of the same twin (Claude's Read, a `cat` in
    // Bash or Codex) a "registered value verbatim" and masked it whole
    // (VM run 2026-09-28: one OpenClaw `read` of ~/.aws/credentials, then
    // every agent's view of that file was one handle).
    if (this.isTwinPieceRow(name, e.value)) return null;
    // Plan 10 §11.13, "A config with no secret" (2026-10-17): a config's
    // text Mandu vetted as holding no secret (an exhaustive shape, every
    // secret place read and found public: its own-text twin) is what the
    // model is shown. As a fingerprint (the whole file, and each long line)
    // its base row, and a proxy's Read row of it, masked every Read and
    // `cat` of that config whole. Whole-text rows only: a field row (a
    // secret value, an old registration's included) still counts.
    if (this.isOwnTextRow(name)) return null;
    return e.confidentiality;
  }

  /** The pattern packs, re-read when a pack directory changes (checked at
   *  most once a second, plan 15 §4.2). `force` re-reads now (after an edit). */
  private loadedPromptPacks(force = false): NonNullable<ArbiterServer["promptPacks"]> {
    const now = Date.now();
    const cur = this.promptPacks;
    if (cur && !force && now - cur.checkedAt < 1000) return cur;
    const dirs = this.promptPackDirs;
    const sig = packDirsSignature([dirs.admin, dirs.user], dirs.keys);
    if (cur && !force && sig === cur.sig) {
      cur.checkedAt = now;
      return cur;
    }
    const loaded = loadPromptPacks({ userDir: dirs.user, adminDir: dirs.admin, keysDir: dirs.keys });
    const filters = new Map<string, PromptFilter>();
    for (const p of loaded.packs) {
      try {
        if (p.doc.plugin) {
          // Plan 15 §4.3: an out-of-process plugin, pinned and confined.
          let stats = this.plugins.stats.get(p.doc.pack);
          if (!stats) { stats = { runs: 0, errors: 0 }; this.plugins.stats.set(p.doc.pack, stats); }
          mkdirSync(this.plugins.dir, { recursive: true, mode: 0o700 });
          filters.set(p.doc.pack, new PluginFilter(p, {
            pins: this.plugins.pins, legs: this.plugins.legs, tools: this.plugins.tools,
            models: () => getCurrentPolicy().models, scratchRoot: this.plugins.dir, stats,
            ...(this.plugins.run ? { run: this.plugins.run } : {}),
          }));
          continue;
        }
        filters.set(p.doc.pack, new PackFilter(p));
      } catch (err) {
        loaded.problems.push({ file: p.file, source: p.source, pack: p.doc.pack, problems: [(err as Error).message] });
      }
    }
    for (const p of loaded.packs) this.log(`prompt filter pack: ${p.doc.pack} ${p.doc.version} (${p.source}, ${p.file}${p.signedBy ? `, signed by ${p.signedBy}` : ""})`);
    for (const p of loaded.problems) this.log(`prompt filter pack REFUSED: ${p.file}: ${p.problems.join("; ")}`);
    this.promptPacks = { sig, checkedAt: now, loaded, filters };
    return this.promptPacks;
  }

  /** The panel's filter rows, each plugin's with its pin, model, last run
   *  and confinement (plan 15 §8.1). Starts the confinement probe when a
   *  plugin exists and it has not run (the answer shows on the next read). */
  private promptFilterViewsWithPlugins(loaded: LoadedPacks): PromptFiltersResultWire["filters"] {
    const byId = new Map(loaded.packs.map((p) => [p.doc.pack, p]));
    if (this.plugins.legsKnown === null && loaded.packs.some((p) => p.doc.plugin)) void this.plugins.legs().catch(() => { /* noted in the log */ });
    return this.promptFilter.filterViews().map((v) => {
      const pl = byId.get(v.id)?.doc.plugin;
      if (!pl) return v;
      const st = this.plugins.stats.get(v.id) ?? { runs: 0, errors: 0 };
      const legs = this.plugins.legsKnown;
      return {
        ...v, kind: "plugin" as const,
        plugin: {
          exec: pl.exec, sha256: pl.sha256, ...(pl.script ? { script: pl.script, scriptSha256: pl.scriptSha256 } : {}),
          ...(pl.modules && pl.modules.length > 0 ? { modules: pl.modules.map((m) => ({ path: m.path, sha256: m.sha256 })) } : {}),
          cost: pl.cost, needsEndpoint: pl.endpoint === "required", deadlineMs: pl.deadlineMs,
          ...st,
          ...(legs ? { confinement: { guard: legs.guard, landlock: legs.landlock, seccomp: legs.seccomp, namespaces: legs.namespaces, notes: [...legs.notes] } } : {}),
        },
      };
    });
  }

  /** The prompt filter's policy in force (plan 15 §6): the person's
   *  `prompt_filters:` under the administrator's layer, and the packs that
   *  may run (an unsigned pack of the person's does not under
   *  `signed_only`). Memoized on the document, the layer and the packs. */
  private promptPolicyInput(): PromptPolicyInput {
    const packs = this.loadedPromptPacks();
    const doc = this.policyDocs?.document?.prompt_filters;
    const admin = getAdminLayer().promptFilters ?? [];
    const m = this.promptPolicyMemo;
    if (m && m.doc === doc && m.admin === admin && m.packs === packs.loaded) return m.input;
    const config = effectivePromptConfig(doc, admin);
    const usable = new Map<string, PromptFilter>();
    const unavailable = new Map<string, string>();
    for (const p of packs.loaded.packs) {
      const f = packs.filters.get(p.doc.pack);
      if (!f) continue;
      if (config.signedOnly && p.source === "user" && p.signedBy === null) {
        unavailable.set(p.doc.pack, `unsigned, and signed_only is on (${p.file})`);
        continue;
      }
      usable.set(p.doc.pack, f);
    }
    for (const p of packs.loaded.problems) {
      if (p.pack && !usable.has(p.pack) && !unavailable.has(p.pack)) unavailable.set(p.pack, `refused: ${packProblemOutline(p.problems[0] ?? "invalid")} (${p.file})`);
    }
    const input: PromptPolicyInput = { config, packs: usable, unavailable, packsDigest: packs.loaded.digest };
    this.promptPolicyMemo = { doc, admin, packs: packs.loaded, input };
    return input;
  }

  /**
   * `promptPackEdit` (plan 15 §8.1; admin channel only): apply typed edits
   * to ONE of the person's own packs (a missing one is created as
   * `<pack>.yaml` in the person's pack directory), validated by the loader's
   * own rules (every regex through RE2) before anything is written. An
   * administrator's pack, and a signed pack of the person's (the edit would
   * void its signature), are read-only. The write is atomic (0600, rename),
   * audited as a `config_change` (`via: prompt-pack`), and the packs are
   * re-read at once, so the next request runs the new patterns.
   */
  private promptPackEdit(req: PromptPackEditOpRequest): PromptPackEditResultWire {
    const dryRun = req.dryRun === true;
    const sample = typeof req.sample === "string" ? req.sample.slice(0, 64 * 1024) : "";
    const userDir = this.promptPackDirs.user;
    if (userDir === null) return { ok: false, dryRun, problems: ["this arbiter has no directory for your packs"] };
    const edits = req.edits;
    const packId = Array.isArray(edits) && edits.length > 0 && typeof (edits[0] as { pack?: unknown })?.pack === "string" ? (edits[0] as { pack: string }).pack : null;
    if (packId === null) return { ok: false, dryRun, problems: ["edits: a non-empty list whose edits name a pack"] };
    const packs = this.loadedPromptPacks(true).loaded;
    const existing = packs.packs.find((p) => p.doc.pack === packId);
    if (existing && existing.source === "admin") return { ok: false, dryRun, problems: [`the pack ${packId} is set by your administrator (${existing.file}); it cannot be changed here`] };
    if (existing && existing.signedBy !== null) return { ok: false, dryRun, problems: [`the pack ${packId} is signed (${existing.file}.sig); an edit here would void its signature`] };
    // Plan 15 §12 (2026-10-03): a plugin pack is a file only.
    if (existing && existing.doc.plugin) return { ok: false, dryRun, problems: [`the pack ${packId} is a plugin (${existing.file}); a plugin pack is changed only in its file`] };
    const refused = packs.problems.find((p) => p.pack === packId);
    if (!existing && refused) return { ok: false, dryRun, problems: [`the pack file ${refused.file} is refused (${refused.problems.join("; ")}); fix or remove it first`] };
    const r = applyPackEdits(existing ? existing.doc : null, edits);
    if (!r.ok) return { ok: false, dryRun, problems: r.problems };
    const counts = (Array.isArray(edits) ? edits : [])
      .filter((e): e is { op: "set-prompt-pattern"; pattern: { id: string } } => !!e && (e as { op?: unknown }).op === "set-prompt-pattern")
      .map((e) => {
        const p = r.doc.patterns.find((x) => x.id === e.pattern?.id);
        return p ? { id: p.id, ...patternMatchCounts(p, sample) } : null;
      })
      .filter((c): c is { id: string; corpus: number; sample: number } => c !== null);
    const file = existing ? existing.file : join(userDir, `${packId}.yaml`);
    const base = { ok: true, pack: packId, file, created: r.created, changes: r.changes, counts, dryRun };
    if (dryRun || r.changes.length === 0) return base;
    if (!existing && existsSync(file)) return { ok: false, dryRun, problems: [`${file} exists but holds no pack named ${packId}; choose another id`] };
    try {
      mkdirSync(userDir, { recursive: true, mode: 0o700 });
      const tmp = `${file}.tmp-${process.pid}-${Date.now().toString(36)}`;
      writeFileSync(tmp, packToYaml(r.doc), { mode: 0o600 });
      renameSync(tmp, file);
    } catch (err) {
      return { ok: false, dryRun, problems: [`could not write ${file}: ${(err as Error).message}`] };
    }
    this.loadedPromptPacks(true);
    const by = typeof req.requestedBy === "string" && req.requestedBy ? req.requestedBy.slice(0, 128) : "human";
    const relaxed = r.changes.filter((c) => c.direction === "relax").length;
    const summary = `${by} ${r.created ? "created" : "changed"} the prompt filter pack ${packId} (${file}): ${r.changes.map((c) => c.detail).join("; ")}${relaxed > 0 ? ` (${relaxed} relaxation${relaxed === 1 ? "" : "s"}, the human's channel)` : ""}`;
    this.log(`[prompt-pack] ${summary}`);
    this.emitPolicyChange({ via: "prompt-pack", requestedBy: by, summary });
    return base;
  }

  /** Mint the symbol a prompt-filter span becomes when it is not exactly one
   *  registered value (plan 15 §4: a line of a multi-line secret, merged
   *  overlapping values). Through `symbolize`, so the reuse key keeps it
   *  stable across resends; the human's own text keeps its trusted
   *  integrity (§9), harness and side-call text stays untrusted, as the !292
   *  scan minted it. Throws on failure (the op answers an error and the
   *  proxy refuses the request). */
  /**
   * Plan 13 §4.5.1 (decision 2026-10-02), the side-call leg: a model request
   * the harness makes with no tools (Claude Code's WebFetch summarizer, whose
   * one user message is the page the agent fetched) while the agent itself
   * was connected to a holder in a call still out
   * (`ProvenanceStore.sideCallAgentTaint`) is masked whole at the holders'
   * level, as the call's own result will be. Raise-only over the filter's
   * answer; a dry run is left as it is.
   */
  private maskSideCallsAfterAgentFlow(
    result: FilterPromptResultWire,
    segments: ReadonlyArray<{ id: string; origin: string; text: string }>,
    session: string | undefined,
    dryRun: boolean,
  ): FilterPromptResultWire {
    if (!this.confidentiality || dryRun) return result;
    const side = segments.filter((s) => s.origin === "side-call" && s.text !== "");
    if (side.length === 0) return result;
    const t = this.provenance.sideCallAgentTaint(session);
    if (t.level === null) return result;
    const level = parseConfidentialityLevel(t.level);
    const files = [...new Set(t.rows.map((r) => r.path.split("/").pop()))].join(", ");
    const byId = new Map(side.map((s) => [s.id, s.text]));
    return {
      ...result,
      segments: result.segments.map((seg) => {
        const text = byId.get(seg.id);
        if (text === undefined || seg.action === "block") return seg;
        const symbol = this.mintPromptSymbol(text, level, "side-call", session);
        this.log(`filterPrompt: a side call while the agent was connected to a holder of ${files || "a secret"}: masked whole at ${t.level} (plan 13 §4.5.1)`);
        return {
          ...seg, action: "rewrite" as const,
          text: `${symbol}\n\n[mandu:secret] masked: the agent received this text from a program that holds ${files || "a secret"}; the model sees it as a symbol.`,
          findings: [...seg.findings, { start: 0, end: text.length, category: "agent-flow", filterId: "agent-flow", action: "mask" as const, symbol }],
          cached: false,
        };
      }),
    };
  }

  private mintPromptSymbol(value: string, level: ConfidentialityLevel, origin: "human" | "harness" | "side-call", session: string | undefined): string {
    const r = this.dispatch({
      id: "prompt-filter", op: "symbolize",
      tool: origin === "side-call" ? "side_call" : "prompt_filter",
      value, confidentiality: level,
      ...(session ? { sessionKey: session } : {}),
      ...(origin === "human" ? { integrity: "trusted" } : {}),
    } as ArbiterRequest);
    if (!r.ok) throw new Error(`filterPrompt: could not mint a symbol: ${r.error}`);
    return (r.result as { symbol: string }).symbol;
  }

  /**
   * Plan 15 §13.10 (2026-10-09): the registered rows a HIGH session's OWN
   * writes made, which that session's human text may carry unmasked. A row
   * counts when all of these hold:
   *   - it is a registered file's row (`isRegisteredFileRow`) whose value is,
   *     byte for byte, the `content` of a whole-content write
   *     (`OWN_WRITE_TOOLS`) this session's model made to that path, as the
   *     model proxy recorded it (`recordToolCall`, believed records only;
   *     `ownWriteHashes`): every byte of it is in the session's transcript
   *     already, the model's own tool input, re-sent as written. A file
   *     anyone changed since (another session, the human, a program) has
   *     another value and keeps the mask, as does an `Edit` (bytes the model
   *     may never have read raw);
   *   - the path's composed level and the row's level are at most the
   *     session's watermark: the session already holds data at that level,
   *     and everything it emits is confined there (confidentiality.md §4,
   *     §8 "the watermark subsumes in-session derivation"). A human or
   *     catalog label above the watermark keeps the mask.
   * A prompt-filter mint whose value is text of such a row counts too (the
   * mask another session's prompt made of the same sentence). Every other
   * session keeps the mask, as does harness and side-call text in this one.
   * Null when nothing qualifies (the engine's cache key is then unchanged).
   */
  private promptOwnWrites(session: string): SessionOwnWrites | null {
    if (!this.confidentiality || session === "") return null;
    const written = this.ownWriteHashes.get(session);
    if (written === undefined) return null;
    const watermark = this.sessionLabels.get(session).confidentiality;
    if (!isSecret(watermark)) return null;
    const within = (level: ConfidentialityLevel): boolean => maxConfidentiality(level, watermark) === watermark;
    const paths = new Map<string, ReadonlySet<string>>();
    const sig: Array<[string, ConfidentialityLevel, string[]]> = [];
    for (const [path, hashes] of written) {
      const level = pathConfidentiality(path, undefined, this.labelLookup).level;
      if (!within(level)) continue;
      paths.set(path, hashes);
      sig.push([path, level, [...hashes].sort()]);
    }
    if (paths.size === 0) return null;
    const signature = createHash("sha256")
      .update(JSON.stringify([watermark, sig.sort((a, b) => a[0].localeCompare(b[0]))]))
      .digest("hex").slice(0, 16);
    const ownRow = (e: SymbolEntry): boolean => {
      if (!isRegisteredFileRow(e) || e.origin === null || !within(e.confidentiality)) return false;
      const p = normalizeLabelPath(e.origin);
      const hashes = p === null ? undefined : paths.get(p);
      return hashes !== undefined && hashes.has(sha256Hex(e.value));
    };
    // The values of those files' rows, read once per request and only when
    // a prompt-filter mint asks (below).
    let ownValues: string[] | null = null;
    return {
      signature,
      covers: (symbol) => {
        const e = this.symbolMap.symbols.get(symbol);
        if (!e || e.obsoleted_at !== null) return false;
        if (ownRow(e)) return true;
        if (!this.isPromptFilterMint(symbol) || e.value === "" || !within(e.confidentiality)) return false;
        if (ownValues === null) {
          ownValues = [];
          for (const r of this.symbolMap.symbols.values()) if (r.obsoleted_at === null && ownRow(r)) ownValues.push(r.value);
        }
        return ownValues.some((v) => v.includes(e.value));
      },
    };
  }

  /** Plan 15 §13.10: remember the content of a believed whole-content write
   *  (by its session and path, as a SHA-256), the evidence `promptOwnWrites`
   *  reads. In memory only: a restarted arbiter forgets it, and the mask
   *  comes back (the safe direction). Bounded per session and per path. */
  private noteOwnWrite(record: ToolCallRecord): void {
    if (!record.sessionKey || !OWN_WRITE_TOOLS.has(record.name)) return;
    const input = record.input;
    if (input === null || typeof input !== "object" || Array.isArray(input)) return;
    const o = input as Record<string, unknown>;
    const content = o["content"];
    const raw = [o["file_path"], o["filePath"], o["path"]].find((v): v is string => typeof v === "string" && v !== "");
    if (typeof content !== "string" || raw === undefined) return;
    const path = normalizeLabelPath(raw);
    if (path === null) return;
    let bySession = this.ownWriteHashes.get(record.sessionKey);
    if (bySession === undefined) {
      if (this.ownWriteHashes.size >= OWN_WRITE_SESSIONS_CAP) {
        const oldest = this.ownWriteHashes.keys().next().value;
        if (oldest !== undefined) this.ownWriteHashes.delete(oldest);
      }
      bySession = new Map();
      this.ownWriteHashes.set(record.sessionKey, bySession);
    }
    let hashes = bySession.get(path);
    if (hashes === undefined) {
      if (bySession.size >= OWN_WRITE_PATHS_CAP) {
        const oldest = bySession.keys().next().value;
        if (oldest !== undefined) bySession.delete(oldest);
      }
      hashes = new Set();
      bySession.set(path, hashes);
    }
    hashes.add(sha256Hex(content));
    while (hashes.size > OWN_WRITE_HASHES_CAP) {
      const oldest = hashes.values().next().value;
      if (oldest === undefined) break;
      hashes.delete(oldest);
    }
  }

  /** Plan 15 §13.6: a row the prompt filter minted for a span it masked
   *  (tool `prompt_filter`), not a registered secret. A line of a real
   *  multi-line secret minted the same way still matches its own row. */
  private isPromptFilterMint(symbol: string): boolean {
    return this.symbolMap.symbols.get(symbol)?.tool === "prompt_filter";
  }

  /**
   * A human's standing answer for {subject, target}, consulted by every gate
   * that queues an Inbox row, before the law. A *once* answer is spent by the
   * consultation that uses it, and only an ask that `spends` may use it
   * (arbiter-human-plane.md §10.3, confidentiality plan 13 D9): the gates'
   * own asks on the human socket or the admin channel, and the in-context
   * read whose only caller lives in the agent's tree by design
   * (`declassifySymbol`). Any other ask (the data socket the agent's
   * programs reach, the Test-a-flow probe) reads an unspent *once* without
   * spending it: a denial still answers (fail-closed: reading a denial
   * grants nothing), an approval is no verdict (the law decides, and a gate
   * that still requires approval re-files the row without resetting it:
   * `recordPending` keeps an unspent answer). So the agent can neither spend
   * the human's *Allow once* before the real send nor be granted it. A
   * standing (*always*) answer is the same to every asker. `"preflight"`
   * (an attested pre-check whose release is judged again downstream, the
   * model proxy's network gate) reads an approval unspent and spends a
   * denial (§10.3, "the pre-check reads, the send spends").
   */
  private consultPriorVerdict(subject: string, target: string, spends: VerdictSpend, requestId?: string): EgressApproval | undefined {
    const prior = this.egressApprovals.lookupEntry(subject, target);
    if (!prior || prior.status === "pending") return undefined;
    if (prior.scope === "once") {
      if (prior.consumedAt !== null) {
        // egress-hold.md "One card per file": a once spent by THIS request
        // (the same caller's id, the same spending) still answers its other
        // asks; any other ask finds it spent.
        const by = this.onceSpentBy.get(prior.id);
        const same = spends === true && typeof requestId === "string" && requestId !== "" && by !== undefined &&
          by.requestId === requestId && by.consumedAt === prior.consumedAt && Date.now() - by.at <= ONCE_REQUEST_WINDOW_MS;
        return same ? prior : undefined;
      }
      if (spends === false) return prior.status === "denied" ? prior : undefined;
      // A pre-check reads an approval (the send it allows asks again where
      // the value is put back, and spends it there) and spends a denial (it
      // enacts the refusal; no send follows).
      if (spends === "preflight" && prior.status === "approved") return prior;
      // "Send without it" (confidentiality.md §4) acts where the request is
      // sent, like an approval: a pre-check reads it unspent, and the
      // net-proxy's ask on the wire spends it.
      if (spends === "preflight" && prior.strip === true) return prior;
      const consumed = this.egressApprovals.consumeOnce(prior.id) ?? prior;
      if (spends === true && typeof requestId === "string" && requestId !== "" && consumed.consumedAt !== null) {
        if (this.onceSpentBy.size >= 1024) {
          for (const [id, s] of this.onceSpentBy) if (Date.now() - s.at > ONCE_REQUEST_WINDOW_MS) this.onceSpentBy.delete(id);
          if (this.onceSpentBy.size >= 1024) this.onceSpentBy.clear();
        }
        this.onceSpentBy.set(prior.id, { requestId, consumedAt: consumed.consumedAt, at: Date.now() });
      }
      this.log(`consultPriorVerdict: ${prior.id} (${prior.status}, once) consumed`);
      this.emitApprovalConsumed(consumed);
      return consumed;
    }
    return prior;
  }

  /**
   * The posture AUDIT event (siem-integration.md §4.3, scenario D): every
   * APPLIED posture change — a SIEM-requested tighten OR an `allowRelax` human
   * relax (policy-surface.md §9.8.6), both directions identically — lands one
   * `posture_change` event in the reserved `arbiter-admin` stream — the actuator
   * loop's own record ("the lockdown the SIEM requested is now active"). Refused
   * requests emit nothing. Same shape/discipline as the verdict audit:
   * BEST-EFFORT, off the security path, carries no symbol value (a posture is not
   * data). The SIEM can alert on it (rule 100222) to confirm the loop closed.
   */
  private emitPostureChange(change: PostureChange, requestedBy?: string): void {
    try {
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: ADMIN_SESSION_ID,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "posture_change",
        view: "HumanView",
        boundary: "model_context",
        emitter: "arbiter",
        // Top-level scalars the SIEM rule keys on (survive the exporter's redact).
        posture: change.to,
        requestedBy: requestedBy ?? null,
        input: {
          symbolized: `egress posture ${change.from} → ${change.to}${requestedBy ? ` (requested by ${requestedBy})` : ""}`,
          original: null, differs: false, symbols: [],
        },
        output: {
          symbolized: change.to === "lockdown"
            ? "LOCKDOWN engaged — every network egress now requires human approval"
            : `egress posture → ${change.to}`,
          original: null, differs: false, symbols: [],
        },
        invariant: { violatedInvariant: false },
        policy: {
          usage: change.to === "lockdown" ? "needs_approval" : "allow",
          reason: change.reason,
        },
      } as Parameters<typeof this.events.append>[0]);
      this.fanOut(stored);
    } catch (err) {
      this.log(`posture_change emit failed (audit only): ${(err as Error).message}`);
    }
  }

  private fanOut(event: StoredEvent): void {
    const set = this.subscribers.get(event.sessionId);
    if (!set || set.size === 0) return;
    for (const sub of [...set]) {
      try {
        sub.push(event);
      } catch (err) {
        this.log(`subscriber error, dropping: ${(err as Error).message}`);
        set.delete(sub);
      }
    }
  }

  /** Parse one NDJSON line and dispatch it. Never throws. */
  private handleLine(line: string, ctx: DispatchContext): ArbiterResponse<unknown> | Promise<ArbiterResponse<unknown>> {
    let req: ArbiterRequest;
    try {
      req = JSON.parse(line) as ArbiterRequest;
    } catch (err) {
      return { id: 0, ok: false, error: `malformed JSON: ${(err as Error).message}` };
    }
    if (req == null || typeof req !== "object" || !("op" in req)) {
      return { id: (req as { id?: string | number })?.id ?? 0, ok: false, error: "missing 'op'" };
    }
    this.syncSymbolBindings();
    if (req.op === "discoverSecrets") return this.dispatchDiscoverSecrets(req, ctx);
    if (req.op === "scanSecretHistory") return this.scanSecretHistoryOp(req);
    if (req.op === "scanAgentTranscripts") return this.scanAgentTranscriptsOp(req);
    if (req.op === "suggestPolicy") return this.suggestPolicyOp(req);
    if (req.op === "modelSuggestPreview") return this.modelSuggestPreviewOp(req);
    if (req.op === "modelSuggest") return this.modelSuggestOp(req);
    if (req.op === "registerRepository") return this.registerRepositoryOp(req);
    if (req.op === "filterPrompt") return this.filterPromptOp(req, ctx);
    if (req.op === "fileUploadDecision") return this.fileUploadDecisionOp(req, ctx);
    try {
      return this.dispatch(req, ctx);
    } catch (err) {
      return { id: req.id, ok: false, error: (err as Error).message };
    }
  }

  /**
   * `filterPrompt` (confidentiality plan 15 §3.2): the prompt filter. A proxy
   * op on the data socket; `dryRun` is refused there (channelRefusal, the
   * human plane only). A malformed request, or a mint that fails, is an
   * error: the proxy refuses the model request (fail-closed). Asynchronous
   * since phase 3: a plugin filter (§4.3) answers from a child process.
   * Never rejects.
   */
  async filterPromptOp(
    req: Extract<ArbiterRequest, { op: "filterPrompt" }>,
    ctx: DispatchContext = { channel: "admin" },
  ): Promise<ArbiterResponse<unknown>> {
    const refused = channelRefusal(req, ctx.channel);
    if (refused !== null) {
      this.log(`refused on ${ctx.channel} channel: ${req.op}`);
      return { id: req.id, ok: false, error: refused };
    }
    const segments = parseSegments(req.segments);
    if (typeof segments === "string") return { id: req.id, ok: false, error: `filterPrompt: ${segments}` };
    if (typeof req.agent !== "string" || req.agent === "") return { id: req.id, ok: false, error: "filterPrompt: agent is required" };
    // Plan 15 §13.5 item 11: a plugin may take seconds; a client that asked
    // hears that the arbiter is at work, so it can tell a slow plugin from
    // an arbiter that never answers.
    const notify = ctx.notify;
    const ticker = req.progress === true && notify ? setInterval(() => notify({ id: req.id, progress: true }), FILTER_PROMPT_PROGRESS_MS) : null;
    ticker?.unref?.();
    try {
      const session = typeof req.session === "string" && req.session !== "" ? req.session : undefined;
      const dryRun = req.dryRun === true;
      const outcome = await this.promptFilter.run(segments, {
        ...(session ? { session } : {}),
        dryRun,
      });
      // Plan 15 §7 (phase 3): the human's verdicts and the Inbox hold, per
      // request over the (cached) scan. Only an attested caller files a row,
      // consults a verdict or holds (plan 13 D9).
      const result: FilterPromptResultWire = await this.promptHolds.apply(outcome, segments, {
        ...(session ? { session } : {}),
        live: !dryRun && outcome.enforcing,
        attested: this.attested(ctx.channel),
        holds: req.holds === true,
        ...(typeof req.heldMs === "number" && Number.isFinite(req.heldMs) ? { heldMs: req.heldMs } : {}),
        config: this.promptFilter.config(),
        // The prompt filter's own masks are rows too; they are not the
        // registered secrets that never go as written (holds.ts).
        holdsRegisteredValue: (span) => this.promptFilter.holdsRegisteredValue(span, (s) => this.isPromptFilterMint(s)),
        enforcedRegisteredIn: (text) => this.promptFilter.enforcedRegisteredIn(text, "human", (s) => this.isPromptFilterMint(s)),
      });
      return { id: req.id, ok: true, result: this.maskSideCallsAfterAgentFlow(result, segments, session, dryRun) };
    } catch (err) {
      return { id: req.id, ok: false, error: (err as Error).message };
    } finally {
      if (ticker) clearInterval(ticker);
    }
  }

  /**
   * `discoverSecrets` from a socket: the same answer as `dispatch`, walked on
   * a worker thread (secret-discovery-thread.ts; runtime-instances.md §14.2 item 7) so
   * the ~1-3 s HOME walk no longer holds every other client's call. The job,
   * the label snapshot included, is fixed HERE, at request time. Never rejects.
   */
  /**
   * `fileUploadDecision`: the local-file upload gate (file-upload.ts;
   * supported-agents.md §2, DesignSync write_files and the upload kinds of
   * tool-gate-surface.ts): may this tool send this file's bytes to this
   * destination? The arbiter reads the file only for an attested ask (a
   * data-socket claim never makes it read one), only when the path does not
   * decide, and in chunks (upload-scan.ts); approval-wrapped. A client that
   * asked (`progress: true`) hears (FILE_UPLOAD_PROGRESS_MS) that the
   * scan is at work, so a large file's scan outlives the idle timeout while
   * an arbiter that never answers still fails closed at it. Never rejects.
   */
  async fileUploadDecisionOp(
    req: Extract<ArbiterRequest, { op: "fileUploadDecision" }>,
    ctx: DispatchContext = { channel: "admin" },
  ): Promise<ArbiterResponse<unknown>> {
    const refused = channelRefusal(req, ctx.channel);
    if (refused !== null) {
      this.log(`refused on ${ctx.channel} channel: ${req.op}`);
      return { id: req.id, ok: false, error: refused };
    }
    const notify = req.progress === true ? ctx.notify : undefined;
    const every = this.uploadScanPace.progressMs;
    let lastFrame = -Infinity;
    const ticker: { t: ReturnType<typeof setInterval> | null } = { t: null };
    // A frame when the byte scan starts, then at most every `every` ms: from
    // each chunk (a timer the scan's own work delays still gets one out) and
    // from a timer (a slow read between chunks).
    const frame = (): void => {
      if (!notify) return;
      const now = Date.now();
      if (now - lastFrame < every) return;
      lastFrame = now;
      notify({ id: req.id, progress: true });
    };
    const onScan = notify ? (): void => {
      frame();
      if (ticker.t === null) { ticker.t = setInterval(frame, every); ticker.t.unref?.(); }
    } : undefined;
    try {
      const result = await this.decideFileUploadWithApprovals(req.request, attestedChannel(ctx.channel), onScan);
      return { id: req.id, ok: true, result };
    } catch (err) {
      return { id: req.id, ok: false, error: (err as Error).message };
    } finally {
      if (ticker.t !== null) clearInterval(ticker.t);
    }
  }

  private async dispatchDiscoverSecrets(
    req: Extract<ArbiterRequest, { op: "discoverSecrets" }>,
    ctx: DispatchContext,
  ): Promise<ArbiterResponse<unknown>> {
    try {
      if (channelRefusal(req, ctx.channel) !== null) return this.dispatch(req, ctx);
      const job = this.discoveryJob(req);
      const result = job
        ? this.recordFound(await this.discoveryWorker.run(job))
        : EMPTY_DISCOVERY;
      return { id: req.id, ok: true, result };
    } catch (err) {
      return { id: req.id, ok: false, error: (err as Error).message };
    }
  }

  /**
   * `scanSecretHistory` (secret-discovery.md §3): the reachable git history of
   * each root's work tree, scanned for secret-shaped blobs. The ARBITER reads
   * the blobs (the one component that may hold secret bytes); the answer
   * carries no value. Read-only and data plane: it changes nothing and
   * returns only kinds, lines and fixed masks. One scan at a time, so a
   * caller cannot stack scans on the arbiter; matching yields to the event
   * loop, so a scan does not hold other clients. Never rejects.
   */
  async scanSecretHistoryOp(req: Extract<ArbiterRequest, { op: "scanSecretHistory" }>): Promise<ArbiterResponse<unknown>> {
    const roots = Array.isArray(req.roots) ? req.roots : null;
    if (roots === null || !roots.every((r) => typeof r === "string")) {
      return { id: req.id, ok: false, error: "scanSecretHistory: roots must be a list of absolute paths" };
    }
    if (!this.confidentiality) {
      const limits = this.historyScanOpts.limits ? { ...DEFAULT_HISTORY_LIMITS, ...this.historyScanOpts.limits } : DEFAULT_HISTORY_LIMITS;
      return {
        id: req.id, ok: true,
        result: {
          axis: false, repos: [], counts: { blobs: 0, scanned: 0, classified: 0 },
          capped: { tooBig: 0, overTotal: 0, overTime: 0, readFailed: 0, binary: 0, pathsUnchecked: 0, untraced: 0, unlisted: false, lines: [] },
          findings: [], limits, ms: 0,
        },
      };
    }
    if (this.historyScanRunning) {
      return { id: req.id, ok: false, error: "scanSecretHistory: a history scan is already running; try again when it ends" };
    }
    this.historyScanRunning = true;
    try {
      const home = typeof req.home === "string" && req.home !== "" ? req.home : undefined;
      const scan = await this.runHistoryScan(roots, home, "scanSecretHistory");
      return { id: req.id, ok: true, result: { ...scan, axis: true } };
    } catch (err) {
      return { id: req.id, ok: false, error: `scanSecretHistory: ${(err as Error).message}` };
    } finally {
      this.historyScanRunning = false;
    }
  }

  /**
   * `scanAgentTranscripts` (confidentiality-plan-17-past-sessions-scan.md):
   * the agents' own transcripts under `home`, scanned for secrets that
   * already reached a model. The ARBITER reads the transcripts and the
   * credential files; the answer carries no value, length or hash. The
   * values it looks for by exact match come from this arbiter's own
   * discovery of `home` (the agents' login files too) and its own
   * environment, never from the caller. Read-only: it records no found
   * label and writes nothing. One scan at a time. Never rejects.
   */
  async scanAgentTranscriptsOp(req: Extract<ArbiterRequest, { op: "scanAgentTranscripts" }>): Promise<ArbiterResponse<unknown>> {
    const home = typeof req.home === "string" && req.home.startsWith("/") ? req.home : homedir();
    if (req.eventsDir !== undefined && (typeof req.eventsDir !== "string" || !req.eventsDir.startsWith("/"))) {
      return { id: req.id, ok: false, error: "scanAgentTranscripts: eventsDir must be an absolute path" };
    }
    if (req.since !== undefined && (typeof req.since !== "number" || !Number.isFinite(req.since))) {
      return { id: req.id, ok: false, error: "scanAgentTranscripts: since must be a time in ms" };
    }
    if (!this.confidentiality) {
      return { id: req.id, ok: true, result: { axis: false, ...(await scanAgentTranscripts({ home, sources: [] })) } };
    }
    if (this.transcriptScanRunning) {
      return { id: req.id, ok: false, error: "scanAgentTranscripts: a scan is already running; try again when it ends" };
    }
    this.transcriptScanRunning = true;
    try {
      // The agents' directory variables (CLAUDE_CONFIG_DIR, XDG_DATA_HOME,
      // OPENCLAW_STATE_DIR, …) belong to this process's HOME: for another
      // home (a test's fixture home) the stores are at its defaults.
      const own = home === process.env["HOME"];
      const sources = transcriptSources(home, own ? process.env : {});
      const known = await this.transcriptScanKnown(home, sources);
      const run = await scanAgentTranscripts({
        home,
        sources,
        known,
        ...(req.eventsDir !== undefined ? { manduWindows: manduWindowsFrom(req.eventsDir) } : {}),
        ...(req.since !== undefined ? { since: req.since } : {}),
        limits: transcriptLimitsFromEnv(process.env),
        // Where the agents' requests went, from their own settings
        // (transcript-providers.ts): read-only, kinds only. The managed
        // settings and this process's variables are this HOME's alone.
        providers: providerSettingsOf({ home, env: own ? process.env : {}, system: own }),
        projectProviders: projectProviderReader({ codexDir: codexDirOf(home, own ? process.env : {}) }),
      });
      return { id: req.id, ok: true, result: { ...run, axis: true } };
    } catch (err) {
      return { id: req.id, ok: false, error: `scanAgentTranscripts: ${(err as Error).message}` };
    } finally {
      this.transcriptScanRunning = false;
    }
  }

  /** The values `scanAgentTranscripts` looks for by exact match
   *  (transcript-known.ts): each credential file discovery finds under
   *  `home`, every agent's login files and every catalog credential store
   *  there read by their own places (the walk's caps never drop one), the
   *  person's systemd user units, each split into its values, and the
   *  secret-named variables of this process's environment. A transcript
   *  the scan reads is never one of those files (discovery walks
   *  OpenClaw's store like any other folder): its values are what is
   *  looked at, not where a secret lives. The scanner keeps only the
   *  credential-like ones (`knownIsCredential`). */
  private async transcriptScanKnown(home: string, sources: readonly TranscriptSource[]): Promise<KnownSecret[]> {
    const job = this.discoveryJob({ op: "discoverSecrets", id: 0, roots: [home], home } as Extract<ArbiterRequest, { op: "discoverSecrets" }>);
    // The walk's file cap is a launch's (its argv): the scan binds nothing.
    const report = job ? await this.discoveryWorker.run({ ...job, opts: { ...job.opts, maxFiles: SCAN_MAX_FILES } }) : EMPTY_DISCOVERY;
    const own = home === process.env["HOME"];
    const isTranscript = (p: string): boolean => isTranscriptStorePath(p, sources);
    const xdg = own ? process.env["XDG_CONFIG_HOME"] : undefined;
    const files = transcriptKnownFiles({
      home,
      discovered: [...report.files.map((f) => f.path), ...report.skipped.filter((c) => c.reason === "agent-login").map((c) => c.path)],
      isSecretPath: (p) => isSecret(pathConfidentiality(p, home, this.labelLookup).level),
      isTranscript,
      loginEnv: own ? process.env : {},
      ...(xdg !== undefined && xdg.startsWith("/") ? { configHome: xdg } : {}),
    });
    const known = knownSecretsOf(files, { home, isTranscript });
    for (const [name, value] of Object.entries(process.env)) {
      const sp = value === undefined ? null : envSecretSpan(name, value);
      if (sp !== null) known.push({ value: sp.value, path: "your environment", name });
    }
    return known;
  }

  /**
   * `suggestFromScan` (plan 17 §3 item 13): the files `mandu scan`'s "your
   * secrets" came from, each checked here (transcript-suggestions.ts
   * `verifyScanFile`: a regular file under `home`, not an agent's own, not
   * Mandu's, and a credential under a named key in it by this arbiter's own
   * reading), then the past-sessions generator and the suggestions' filing
   * path. Paths, names and counts in; paths, names and counts out. The log
   * line holds counts only.
   */
  suggestFromScanOp(req: Extract<ArbiterRequest, { op: "suggestFromScan" }>): ArbiterResponse<unknown> {
    const home = typeof req.home === "string" && req.home.startsWith("/") ? req.home.replace(/\/+$/, "") : null;
    if (home === null || home === "") return { id: req.id, ok: false, error: "suggestFromScan: home must be an absolute path" };
    const claims = parseScanFileClaims(req.files);
    if ("error" in claims) return { id: req.id, ok: false, error: `suggestFromScan: ${claims.error}` };
    const empty: SuggestFromScanResultWire = { axis: false, filed: [], covered: 0, alreadyPending: 0, dismissed: 0, overCap: 0, refused: [], suggestions: [] };
    if (!this.confidentiality) return { id: req.id, ok: true, result: empty };
    const manduHomes = [...new Set([manduPath("mandu-home", process.env, home), join(home, ".mandu")])];
    const under = (p: string, dir: string): boolean => p === dir || p.startsWith(`${dir}/`);
    const files: PastSessionsFile[] = [];
    const refused: SuggestFromScanResultWire["refused"] = [];
    for (const c of claims) {
      const v = verifyScanFile(c, {
        home,
        read: (p) => readTranscriptClaimFile(p),
        agentOwn: (p) => agentFileOf(p, home, process.env) !== null || isAgentAuthPath(p, home),
        manduState: (p) => manduHomes.some((d) => under(p, d)),
        isWorkTree: (d) => existsSync(join(d, ".git")),
      });
      if (v.ok) files.push(v.file);
      else refused.push({ path: c.path, why: v.why });
    }
    const r = this.policySuggestions.fileFromPastSessions(files, {
      home,
      isCovered: (p) => {
        const m = pathConfidentiality(p, home, this.labelLookup);
        return m.rule !== null && isSecret(m.level);
      },
    });
    this.log(`suggestFromScan: ${claims.length} file(s) named, ${files.length} verified, ${r.filed.length} filed, ${r.covered} covered, ${refused.length} refused`);
    const result: SuggestFromScanResultWire = {
      axis: true, filed: r.filed, covered: r.covered,
      alreadyPending: r.counts.alreadyPending, dismissed: r.counts.dismissed, overCap: r.counts.overCap,
      refused, suggestions: r.suggestions,
    };
    return { id: req.id, ok: true, result };
  }

  /** One history scan with the arbiter's catalog and labels as the path
   *  classifier. The caller holds `historyScanRunning`. */
  private async runHistoryScan(roots: string[], home: string | undefined, op: string): Promise<SecretHistoryScan> {
    const scan = await scanSecretHistory(roots, {
      ...(this.historyScanCache ? { cache: this.historyScanCache } : {}),
      ...this.historyScanOpts,
      classifyPaths: (paths) => paths.map((p) => {
        const m = confidentialityForOrigin(p, home, this.labelLookup);
        return { level: m.level, rule: m.rule ?? null };
      }),
      // Plan 14 §8.1/§8.2: what the launcher's object twins hide beyond the
      // confined files (gitHistoryLocks), so a finding the law now covers
      // (a human label on its gone path, a blob lock) is reported covered.
      labelledAbovePublic: (paths) => {
        const labels = this.humanLabels();
        return paths.map((p) => {
          const l = resolvePathLabel(p, labels, home);
          return l !== null && l.level !== "public";
        });
      },
      lockedBlobs: new Set([...getCurrentPolicy().blobLocks.values()].filter((b) => b.level !== "public").map((b) => b.id)),
    });
    // Plan 14 §11.1 R1: a scanned repository is a known one (source `scan`).
    this.lockResolver?.note(scan.repos.map((r) => r.repoRoot).filter((r): r is string => r !== null), "scan");
    const cached = scan.repos.filter((r) => r.cache !== undefined).map((r) => `${r.cache!.plan}, ${r.cache!.read} read`);
    this.log(`${op}: ${scan.repos.map((r) => r.repoRoot ?? r.root).join(", ")} → ${scan.findings.length} finding(s), ${scan.counts.scanned} blob(s) scanned in ${scan.ms} ms${cached.length > 0 ? ` (cache: ${cached.join("; ")})` : ""}`);
    return scan;
  }

  /** One workspace scan (plan 14 §13) with the arbiter's catalog and labels
   *  as the coverage check (the call discovery makes: a covered file is
   *  never opened). The caller holds `historyScanRunning`. Logs counts only,
   *  never a path. */
  private async runWorkspaceScan(
    roots: string[],
    home: string | undefined,
    includeHome: boolean,
    what: { text: boolean; labels: { mapping: readonly LabelMappingEntry[]; count: boolean } | null },
  ): Promise<SecretWorkspaceScan> {
    const lab = what.labels;
    const scan = await scanSecretWorkspace(roots, {
      ...this.workspaceScanOpts,
      ...(home ? { home } : {}),
      includeHome,
      cache: this.workspaceScanCache,
      readText: what.text,
      isCovered: (p) => {
        const m = pathConfidentiality(p, home, this.labelLookup);
        return m.rule !== null && isSecret(m.level);
      },
      // Plan 14 §14.1: no Office file is opened while no mapping is in
      // force, unless an explicit scan asked to count the labels.
      ...(lab !== null
        ? {
            sensitivityLabels: {
              ...(this.workspaceScanOpts.labelLimits ? { limits: this.workspaceScanOpts.labelLimits } : {}),
              mode: lab.mapping.length > 0 ? "mapped" as const : lab.count ? "count" as const : "off" as const,
              isMapped: (l: { id: string; site: string | null }) => mapLabel(l, lab.mapping) !== null,
              cache: this.labelScanCache,
            },
          }
        : {}),
    });
    const walked = scan.roots.filter((r) => r.reason === undefined).length;
    const labels = scan.labels && scan.labels.mode !== "off"
      ? `; sensitivity labels (${scan.labels.mode}): ${scan.labels.read} Office file(s) read, ${scan.labels.cached} from the cache, ${scan.labels.files} labelled, ${scan.labels.unmappedFiles} with a label not mapped`
      : "";
    this.log(`suggestPolicy: workspace scan of ${walked} root(s) → ${scan.findings.length} finding(s), ${scan.counts.read} file(s) read, ${scan.counts.cached} from the cache, ${scan.counts.covered} protected and not opened, in ${scan.ms} ms${labels}`);
    return scan;
  }

  /** Plan 14 §14.1: the `sensitivity_labels:` mapping in force (the user's
   *  document and the administrator's layer, the stricter level winning). */
  private labelMapping(): LabelMappingEntry[] {
    return effectiveLabelMapping(this.policyDocs?.document?.sensitivity_labels ?? [], getAdminLayer());
  }

  /**
   * `suggestPolicy` (confidentiality-plan-14 §4, §5.1, §5.5, §13.5): the
   * history scan and the workspace scan (`sources`, both by default), then
   * the generator, then filing. DATA plane: what it files are tightenings a
   * human still has to apply, deduplicated and capped. One job runs both
   * scans in turn under the one-scan-at-a-time rule it shares with
   * `scanSecretHistory`, so the `waitMs` budget (a launch's) and the
   * background filing cover both: when the budget ends first it answers
   * `running: true`, and the scans finish here and file what they find.
   * Never rejects.
   */
  async suggestPolicyOp(req: Extract<ArbiterRequest, { op: "suggestPolicy" }>): Promise<ArbiterResponse<unknown>> {
    const roots = Array.isArray(req.roots) ? req.roots : null;
    if (roots === null || !roots.every((r) => typeof r === "string")) {
      return { id: req.id, ok: false, error: "suggestPolicy: roots must be a list of absolute paths" };
    }
    const sources = parseSuggestSources(req.sources);
    if (sources === null) {
      return { id: req.id, ok: false, error: 'suggestPolicy: sources must list "git-history", "workspace" and/or "sensitivity-label", each once' };
    }
    if (req.includeHome !== undefined && typeof req.includeHome !== "boolean") {
      return { id: req.id, ok: false, error: "suggestPolicy: includeHome must be a boolean" };
    }
    if (req.countLabels !== undefined && typeof req.countLabels !== "boolean") {
      return { id: req.id, ok: false, error: "suggestPolicy: countLabels must be a boolean" };
    }
    if (req.answerFromEarlier !== undefined && typeof req.answerFromEarlier !== "boolean") {
      return { id: req.id, ok: false, error: "suggestPolicy: answerFromEarlier must be a boolean" };
    }
    const home = typeof req.home === "string" && req.home !== "" ? req.home : undefined;
    const includeHome = req.includeHome === true;
    if (includeHome && (home === undefined || !home.startsWith("/"))) {
      return { id: req.id, ok: false, error: "suggestPolicy: includeHome needs home (an absolute path)" };
    }
    if (!this.confidentiality) {
      const result: SuggestPolicyResult = { axis: false, running: false, suggestions: [], filed: [], covered: [], counts: emptyCounts(), scan: null, workspaceScan: null };
      return { id: req.id, ok: true, result };
    }
    // §5.5: a launch that already has a finished scan of this workspace
    // answers at once from what it filed (the pending suggestions, refreshed
    // against the law) and leaves this scan to run in the background.
    // Kept in mandu.db (`suggest_scans`), so an arbiter restart keeps it.
    const earlier = earlierScanAt(this.policyProposals.suggestScansFinished(), roots);
    const fromEarlier = req.answerFromEarlier === true && earlier !== null;
    const asked = typeof req.waitMs === "number" && Number.isFinite(req.waitMs) && req.waitMs >= 0 ? req.waitMs : null;
    const waitMs = fromEarlier ? 0 : asked;
    if (this.historyScanRunning) {
      if (waitMs !== null) return { id: req.id, ok: true, result: this.runningAnswer(earlier, fromEarlier) };
      return { id: req.id, ok: false, error: "suggestPolicy: a history scan is already running; try again when it ends" };
    }
    const everySource = SUGGEST_SOURCES.every((x) => sources.has(x));
    this.historyScanRunning = true;
    const job = (async (): Promise<SuggestPolicyResult> => {
      try {
        const history = sources.has("git-history") ? await this.runHistoryScan(roots, home, "suggestPolicy") : null;
        // The workspace walk reads the text files (S2) and, in the same
        // walk, the Office files' labels (S4, plan 14 §14.1).
        const mapping = this.labelMapping();
        const labels = sources.has("sensitivity-label") ? { mapping, count: req.countLabels === true } : null;
        const workspace = sources.has("workspace") || labels !== null
          ? await this.runWorkspaceScan(roots, home, includeHome, { text: sources.has("workspace"), labels })
          : null;
        const filed = this.policySuggestions.fileFromScans({ history, workspace }, { ...(home ? { home } : {}), labelMapping: mapping });
        const at = Date.now();
        if (everySource) this.policyProposals.recordSuggestScan(roots, at);
        return { ...filed, lastScanAt: everySource ? at : earlierScanAt(this.policyProposals.suggestScansFinished(), roots) };
      } finally {
        this.historyScanRunning = false;
      }
    })();
    try {
      if (waitMs === null) return { id: req.id, ok: true, result: await job };
      let timer: NodeJS.Timeout | undefined;
      const late = new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), waitMs);
        timer.unref?.();
      });
      const first = await Promise.race([job, late]);
      if (timer) clearTimeout(timer);
      if (first !== null) return { id: req.id, ok: true, result: first };
      job.then(
        (r) => this.log(`suggestPolicy (background): ${r.counts.filed} suggestion(s) filed after the caller's budget`),
        (err) => this.log(`suggestPolicy (background) failed: ${(err as Error).message}`),
      );
      return { id: req.id, ok: true, result: this.runningAnswer(earlier, fromEarlier) };
    } catch (err) {
      return { id: req.id, ok: false, error: `suggestPolicy: ${(err as Error).message}` };
    }
  }

  /**
   * `registerRepository` (plan 14 §11.1 R1): add a work tree to the
   * known-repository registry so the background resolution covers it. DATA
   * plane and add-only: it only widens what a lock reaches. Validated (an
   * absolute path in a git work tree the arbiter's hardened git reads, never
   * inside Mandu's own home) and capped (the data-plane sources hold at most
   * 256 roots; a full registry refuses). Never rejects.
   */
  async registerRepositoryOp(req: Extract<ArbiterRequest, { op: "registerRepository" }>): Promise<ArbiterResponse<unknown>> {
    if (!this.confidentiality || this.lockResolver === null) {
      const result: RegisterRepositoryResult = { axis: this.confidentiality, root: null, added: false, known: 0 };
      return { id: req.id, ok: true, result };
    }
    try {
      const got = await this.lockResolver.register(req.root);
      if (!got.ok) return { id: req.id, ok: false, error: `registerRepository: ${got.error}` };
      const result: RegisterRepositoryResult = { axis: true, root: got.root, added: got.added, known: got.known };
      return { id: req.id, ok: true, result };
    } catch (err) {
      return { id: req.id, ok: false, error: `registerRepository: ${(err as Error).message}` };
    }
  }

  /** The names-only model's walk (plan 14 §14.2): the workspace scan with
   *  its listing, under the one-scan-at-a-time flag. */
  private async runModelWalk(roots: string[], home: string | undefined, includeHome: boolean, documents = false): Promise<SecretWorkspaceScan> {
    if (this.historyScanRunning) throw new Error("a scan is already running; try again when it ends");
    this.historyScanRunning = true;
    try {
      return await scanSecretWorkspace(roots, {
        ...this.workspaceScanOpts,
        ...(home ? { home } : {}),
        includeHome,
        list: true,
        // Plan 14 §14.11 (T2): the home tier reads the documents too, so the
        // detectors have run over every candidate before any head is read.
        ...(documents ? { documents: (name: string) => documentExtension(name) !== null } : {}),
        cache: this.workspaceScanCache,
        isCovered: (p) => {
          const m = pathConfidentiality(p, home, this.labelLookup);
          return m.rule !== null && isSecret(m.level);
        },
      });
    } finally {
      this.historyScanRunning = false;
    }
  }

  /** `modelSuggestPreview` (plan 14 §14.2): data plane. Axis OFF: refused
   *  (there is no suggestion store to file into). Never rejects. */
  async modelSuggestPreviewOp(req: Extract<ArbiterRequest, { op: "modelSuggestPreview" }>): Promise<ArbiterResponse<unknown>> {
    if (!this.confidentiality) return { id: req.id, ok: false, error: "modelSuggestPreview: secret protection is off (see `mandu mode`); there is nothing to suggest" };
    try {
      return { id: req.id, ok: true, result: await this.policyModel.preview(req) };
    } catch (err) {
      return { id: req.id, ok: false, error: `modelSuggestPreview: ${(err as Error).message}` };
    }
  }

  /** `modelSuggest` (plan 14 §14.2): data plane. Never rejects. */
  async modelSuggestOp(req: Extract<ArbiterRequest, { op: "modelSuggest" }>): Promise<ArbiterResponse<unknown>> {
    if (!this.confidentiality) return { id: req.id, ok: false, error: "modelSuggest: secret protection is off (see `mandu mode`); there is nothing to suggest" };
    try {
      return { id: req.id, ok: true, result: await this.policyModel.send(req) };
    } catch (err) {
      return { id: req.id, ok: false, error: `modelSuggest: ${(err as Error).message}` };
    }
  }

  /** One `policy_model_call` event per model run (plan 14 §14.5), on the
   *  arbiter-admin stream: counts only, never a name or an answer. */
  private emitPolicyModelCall(e: PolicyModelCallEvent): void {
    try {
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: ADMIN_SESSION_ID,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "policy_model_call",
        view: "HumanView",
        boundary: "model_context",
        emitter: "arbiter",
        input: {
          symbolized: e.tier === "contents"
            ? `contents model run: ${e.items} document(s), ${e.bytes} bytes in ${e.requests} request(s) to ${e.endpoint} (${e.location})`
            : `names-only model run: ${e.items} name(s), ${e.bytes} bytes in ${e.requests} request(s) to ${e.endpoint}`,
          original: null, differs: false, symbols: [],
        },
        output: { symbolized: `${e.kept} ${e.tier === "contents" ? "suggestion" : "rule"}(s) kept, ${e.dropped} dropped, ${e.filed} filed, ${e.failed} request(s) failed, in ${e.ms} ms`, original: null, differs: false, symbols: [] },
        invariant: { violatedInvariant: false },
        policyModelCall: { ...e },
      });
      this.fanOut(stored);
    } catch (err) {
      this.log(`policy model event emit failed (ignored): ${(err as Error).message}`);
    }
  }

  /** The answer while a scan still runs: what is pending now, and when a
   *  finished scan last covered the roots (§5.5). An answer from the earlier
   *  result first closes what the law now covers (as a read does). */
  private runningAnswer(lastScanAt: number | null = null, refresh = false): SuggestPolicyResult {
    const suggestions = refresh ? this.policySuggestions.list("pending").suggestions : this.policySuggestions.pending();
    return { axis: true, running: true, suggestions, filed: [], covered: [], counts: emptyCounts(), scan: null, workspaceScan: null, lastScanAt };
  }

  /** A suggestion was filed / applied / dismissed / superseded (plan 14):
   *  one line on the arbiter-admin stream so the dashboard can react. Ids
   *  and a count only, never a path's content or a value. Best-effort. */
  /** Plan 14 §11.2: an enforcement cache entry was not used (it did not
   *  match a seal of the current epoch) or the epoch rotated. Names kinds
   *  and keys only, never content. Best-effort, into the admin stream. */
  private emitCacheSealEvent(action: "rejected" | "rotated", why: string, entries: readonly CacheSealRejection[]): void {
    try {
      const shown = entries.slice(0, 50).map((r) => ({ kind: r.kind, key: r.key, reason: r.reason }));
      const summary = action === "rotated"
        ? `enforcement caches: a new epoch started, every older seal is void (${why})`
        : `enforcement caches: ${entries.length} entr${entries.length === 1 ? "y" : "ies"} not trusted and rebuilt (${shown.slice(0, 5).map((r) => `${r.kind} ${r.key}: ${r.reason}`).join("; ")}${entries.length > 5 ? "; …" : ""})`;
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: ADMIN_SESSION_ID,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "config_change",
        view: "HumanView",
        boundary: "filesystem",
        emitter: "arbiter",
        input: { symbolized: "enforcement cache seals", original: null, differs: false, symbols: [] },
        output: { symbolized: summary, original: null, differs: false, symbols: [] },
        invariant: { violatedInvariant: false },
        cacheSeal: { action, why, entries: shown, count: entries.length },
      });
      this.fanOut(stored);
    } catch (err) {
      this.log(`cache seal event emit failed (ignored): ${(err as Error).message}`);
    }
  }

  private emitSuggestionEvent(e: SuggestionEvent): void {
    try {
      const words = { filed: "filed", applied: "applied", dismissed: "dismissed (not a secret)", superseded: "closed (the law covers them now)" }[e.action];
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: ADMIN_SESSION_ID,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "config_change",
        view: "HumanView",
        boundary: "model_context",
        emitter: "arbiter",
        input: { symbolized: "policy suggestions", original: null, differs: false, symbols: [] },
        output: { symbolized: `${e.ids.length} policy suggestion(s) ${words}`, original: null, differs: false, symbols: [] },
        invariant: { violatedInvariant: false },
        policySuggestion: { action: e.action, ids: [...e.ids] },
      });
      this.fanOut(stored);
    } catch (err) {
      this.log(`policy suggestion event emit failed (ignored): ${(err as Error).message}`);
    }
  }

  /** The discovery a request asks for, or null when the confidentiality axis
   *  is OFF (nothing to twin). Plan 12 D3: a declared model's client key is a
   *  secret file wherever it lives, so it is walked as a root of its own
   *  (outside HOME too) and the label lookup marks it no-model. */
  /**
   * The content tier's verdicts of one walk, recorded (found-labels.ts,
   * secret-discovery.md §2.6): each config file it read a credential in
   * gets a found label, before the answer reaches the launcher, so its
   * `registerSecret` of the file finds it labelled; each found label's file
   * it read and found no credential in loses its label. Raise-only but for
   * that read: no caller can drop a label without the arbiter reading the
   * file clean. Returns the report.
   */
  private recordFound(report: SecretDiscoveryReport): SecretDiscoveryReport {
    let added = 0;
    let dropped = 0;
    for (const f of report.found ?? []) {
      const before = this.foundLabels.generation();
      // A personal document (§2.7) is recorded with its kind: the label
      // lookup gives it the document twin.
      if (this.foundLabels.add(f.path, f.field, undefined, f.kind === "document" ? "document" : "credential") !== null && this.foundLabels.generation() !== before) added++;
    }
    for (const p of report.cleared ?? []) if (this.foundLabels.drop(p)) dropped++;
    if (added > 0 || dropped > 0) {
      // The bindings sync (`syncSymbolBindings`) sees the new generation
      // on the next request: a found file's rows are bound nowhere.
      this.log(`content tier: ${added} file(s) found (a credential in a config file, or a personal document), ${dropped} found label(s) cleared (secret-discovery.md §2.6, §2.7)`);
    }
    return report;
  }

  private discoveryJob(req: Extract<ArbiterRequest, { op: "discoverSecrets" }>): DiscoveryJob | null {
    if (!this.confidentiality) return null;
    const labels = this.labelSnapshot();
    const keyRoots = labels.clientKeys.filter((k) => !req.roots.includes(k));
    return {
      roots: [...req.roots, ...keyRoots],
      home: req.home,
      // The label paths in force let the macOS HOME prune (secret-discovery.ts
      // darwinPrune) keep visiting a labeled file under a pruned folder such as
      // ~/Library: the prune must never hide a label (confidentiality.md §7.2).
      // Plan 13 D4: the derived labels are candidates of their own, so the
      // next launch registers and twins a copy wherever it was written.
      // The launch's moved package caches (secret-discovery.md §1.9 G): the
      // known variable names only, whatever the wire carried.
      // The launch's agent and its AI helper's CLI (secret-discovery.md
      // §1.10): only their login files stay raw; absent, every agent's does.
      // The login variables: the known names, absolute paths only.
      opts: {
        stateBase: req.stateBase, cacheEnv: pickPackageCacheEnv(req.cacheEnv),
        labelPaths: [...labels.human.keys(), ...labels.derived.keys(), ...labels.clientKeys, ...(labels.found?.keys() ?? [])], derivedPaths: [...labels.derived.keys()],
        // The content tier (secret-discovery.md §2.6): the found labels'
        // files are candidates of their own, as the derived ones are.
        foundPaths: [...(labels.found?.keys() ?? [])],
        // D (2026-10-17): the human labels' places are roots of their own
        // (secret-discovery.ts `labelRoots`): a labelled folder outside HOME
        // and the workspace, too deep for their walks, or past their file
        // cap is registered and twinned by this launch.
        labelRoots: labelWalkRoots(labels.human),
        ...(typeof req.target === "string" && req.target !== "" ? { target: req.target } : {}),
        ...(typeof req.ullmBinary === "string" && req.ullmBinary !== "" ? { ullmBinary: req.ullmBinary } : {}),
        loginEnv: pickLoginEnv(req.loginEnv),
      },
      labels,
    };
  }

  /**
   * Dispatch a parsed request to the matching operation. `ctx` names the
   * channel it arrived on; the default is `admin` because a DIRECT caller
   * (tests, embedders) holds the server object and is trusted by construction
   * — only the socket paths pass `data`, and only they can be reached by the
   * agent.
   */
  /** The unwalled launches live now (`CacheSealStore.humanPlaneExposure`),
   *  memoized for {@link EXPOSURE_MEMO_MS} (a launch's begin and end clear it;
   *  a launcher found gone ends the exposure at most that much later). A
   *  store that cannot answer counts as exposed: fail closed. */
  private humanPlaneExposure(): LiveLaunch[] {
    const now = Date.now();
    if (this.exposureMemo !== null && now - this.exposureMemo.at < EXPOSURE_MEMO_MS) return this.exposureMemo.launches;
    let launches: LiveLaunch[];
    try {
      launches = this.cacheSeals.humanPlaneExposure();
    } catch {
      launches = [{ pid: 0, mode: "unknown", posture: "unknown", walled: false }];
    }
    const before = this.exposureMemo?.launches ?? [];
    this.exposureMemo = { at: now, launches };
    // Told once per change of the set (arbiter-human-plane.md §10.1.1): the
    // log, and one event on the arbiter's audit stream. Display only: the
    // belief rule reads `launches` itself, never this.
    if (exposureKey(before) !== exposureKey(launches)) {
      const desc = launches.map((l) => `pid ${l.pid}${l.session ? ` session ${l.session}` : ""} ${l.mode}/${l.posture}`).join("; ");
      if (launches.length > 0) {
        if (before.length === 0) this.exposedSince = now;
        this.log(`human plane exposed: ${launches.length} launch(es) whose agent can reach the human socket (${desc}); the guard's and the proxies' records there are claims until they end`);
        this.startExposureWatch();
      } else {
        this.exposedSince = null;
        this.log("human plane walled again: the human socket's records are believed");
        this.stopExposureWatch();
      }
      this.emitHumanPlaneEvent(launches, before);
    }
    return launches;
  }

  /** The exposure as `humanPlaneStatus` answers it. */
  private humanPlaneStatus(): HumanPlaneStatusResult {
    const launches = this.humanPlaneExposure();
    return {
      exposed: launches.length > 0,
      since: launches.length > 0 ? this.exposedSince : null,
      launches: launches.map((l) => ({
        pid: l.pid, mode: l.mode, posture: l.posture,
        ...(l.session !== undefined ? { session: l.session } : {}),
        ...(l.begunAt !== undefined ? { begunAt: l.begunAt } : {}),
      })),
    };
  }

  /** A launch began or ended: re-read the exposure now, so a change is told
   *  at once (its event, and the watch below). */
  private refreshExposure(): void {
    if (this.exposureMemo !== null) this.exposureMemo = { ...this.exposureMemo, at: 0 };
    try { this.humanPlaneExposure(); } catch { /* the next ask re-reads */ }
  }

  private startExposureWatch(): void {
    if (this.exposureTimer !== null) return;
    this.exposureTimer = setInterval(() => {
      if (this.exposureMemo !== null) this.exposureMemo = { ...this.exposureMemo, at: 0 };
      try { this.humanPlaneExposure(); } catch { /* the next tick */ }
    }, 1000);
    this.exposureTimer.unref?.();
  }

  private stopExposureWatch(): void {
    if (this.exposureTimer !== null) clearInterval(this.exposureTimer);
    this.exposureTimer = null;
  }

  /** The exposure began, changed or ended (arbiter-human-plane.md §10.1.1):
   *  one `config_change` event on the arbiter's audit stream, carrying
   *  `humanPlane: {state, since, launches, ended?}`. Pids, modes, postures
   *  and sessions only. Best-effort, off the security path. */
  private emitHumanPlaneEvent(launches: readonly LiveLaunch[], before: readonly LiveLaunch[]): void {
    try {
      const exposed = launches.length > 0;
      const name = (l: LiveLaunch): string => `pid ${l.pid}${l.session ? ` (session ${l.session})` : ""}`;
      const summary = exposed
        ? `human plane EXPOSED: ${launches.length} launch(es) with no wall can reach the human socket (${launches.slice(0, 5).map((l) => `${name(l)}, ${l.mode}/${l.posture}`).join("; ")}); ` +
          `every guard and model-proxy report there is a claim until ${launches.length === 1 ? "it ends" : "they end"} (confined launches get placeholders, refused protected writes, masked shell results)`
        : `human plane walled again: the launch(es) with no wall ended (${before.slice(0, 5).map(name).join("; ")}); the guard's and the proxies' reports on the human socket are believed`;
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: ADMIN_SESSION_ID,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "config_change",
        view: "HumanView",
        boundary: "model_context",
        emitter: "arbiter",
        input: { symbolized: "human plane", original: null, differs: false, symbols: [] },
        output: { symbolized: summary, original: null, differs: false, symbols: [] },
        invariant: { violatedInvariant: false },
        humanPlane: {
          state: exposed ? "exposed" : "walled",
          since: this.exposedSince,
          launches: launches.slice(0, 20).map((l) => ({ pid: l.pid, mode: l.mode, posture: l.posture, ...(l.session ? { session: l.session } : {}) })),
          ...(exposed ? {} : { ended: before.slice(0, 20).map((l) => ({ pid: l.pid, ...(l.session ? { session: l.session } : {}) })) }),
        },
      });
      this.fanOut(stored);
    } catch (err) {
      this.log(`human plane event emit failed (ignored): ${(err as Error).message}`);
    }
  }

  /** Plan 13 D9: is a report on `channel` believed? The admin channel
   *  always; the human socket unless an unwalled launch is live (its
   *  agent's programs reach it: the D9 leftovers); the data socket never. */
  /**
   * A classify request as the policy reads it (2026-10-04, confidentiality.md
   * §6): `callStartDir` is the arbiter's own, never a caller's. Any value the
   * caller sent is dropped; with the confidentiality axis on, a call that
   * runs a command (`params.command`) and that the call-root recorder bound
   * to its shell gets the directory the kernel says that shell started in
   * (`ProvenanceStore.callStartDir`: the guard's report on the human plane,
   * read off `/proc/<pid>/cwd` while the exec was suspended). The record is
   * only read here, never written, so the channel the ask came on does not
   * matter: the binding and the directory were both recorded from the human
   * plane, and a caller that names another call's id only gets that call's
   * directory applied to its own command, in its own answer.
   */
  private withCallStartDir(request: ClassifyRequest): ClassifyRequest {
    const { callStartDir: _dropped, agentOpened: _droppedOpens, ...rest } = request as ClassifyRequest & { callStartDir?: unknown; agentOpened?: unknown };
    const params = rest.params as Record<string, unknown> | undefined;
    const command = params?.["command"];
    if (!this.confidentiality || typeof rest.callId !== "string" || rest.callId === "") return rest;
    if (typeof command !== "string") return this.withAgentOpens(rest, params);
    const dir = this.provenance.callStartDir(rest.callId);
    return dir !== null ? { ...rest, callStartDir: dir } : rest;
  }

  /**
   * 2026-10-17 (confidentiality.md §6, "The base follows the shell"): a file
   * tool's RELATIVE path (`file_path`, `notebook_path`, `path`) is resolved
   * by the agent against its own directory, which a `cd` in an earlier
   * `Bash` call or EnterWorktree moved, and which no request names (Claude
   * Code's). The guard saw the file the agent then opened, in the kernel
   * (`labelledLevel` with `agentOpen`, human plane): each such file opened
   * in the call's window whose path ends with the value is read too,
   * raise-only (`ClassifyRequest.agentOpened`, set here alone). No guard, or
   * no such open: nothing added, the value keeps its other readings.
   */
  private withAgentOpens(request: ClassifyRequest, params: Record<string, unknown> | undefined): ClassifyRequest {
    if (params === undefined) return request;
    const values: string[] = [];
    for (const key of ["file_path", "notebook_path", "path"]) {
      const v = params[key];
      if (typeof v === "string" && v !== "" && !v.startsWith("/") && !v.startsWith("~")) values.push(v);
    }
    if (values.length === 0) return request;
    const opened = this.provenance.callAgentOpens(request.callId!, request.sessionKey, values);
    return opened.length > 0 ? { ...request, agentOpened: opened } : request;
  }

  private attested(channel: IpcChannel): boolean {
    if (channel === "admin") return true;
    if (channel !== "human") return false;
    return this.humanPlaneExposure().length === 0;
  }

  /** Why a report on `channel` is a claim. */
  private unattested(op: string, channel: IpcChannel): string {
    return channel === "human" ? exposedHumanPlaneReason(op, this.humanPlaneExposure()) : unattestedReason(op);
  }

  dispatch(req: ArbiterRequest, ctx: DispatchContext = { channel: "admin" }): ArbiterResponse<unknown> {
    this.syncSymbolBindings();
    const refused = channelRefusal(req, ctx.channel);
    if (refused !== null) {
      this.log(`refused on ${ctx.channel} channel: ${req.op}`);
      return { id: req.id, ok: false, error: refused };
    }
    switch (req.op) {
      case "symbolizeDerived":
      case "symbolize": {
        const sources = req.op === "symbolizeDerived"
          ? sourceLabel(this.symbolMap, req.sourceSymbols) : undefined;
        // The origin the LEVEL is derived from: the HumanView spelling when the
        // caller runs a view map (Plan 9 — the label stores and the catalog are
        // keyed in HumanView, while the wire origin is the AgentView twin the
        // agent actually executed). The STORED provenance origin stays `req.origin`
        // — that is what the agent really touched, and the fs-provenance/blame
        // machinery keys on it.
        //
        // A RELATIVE typed path (OpenClaw's `read {path: "memo/brief.md"}`)
        // is stored where the agent read it: `<launch dir>/<path>`, under the
        // same rule the result's classify read it by (`placedTypedOrigin`).
        // Otherwise the row kept the relative text, which no label matches:
        // secret by the classify's level but bound nowhere, at mint and at
        // every bindings sync, so a declassify of it left the session's bound
        // set empty and its own bound host asked (2026-10-10, §6).
        const origin = this.placedTypedOrigin(req) ?? req.origin;
        const levelOrigin = req.originHuman ?? origin;
        const key = {
          tool: req.tool,
          value: req.value,
          field: req.field,
          origin,
          sessionKey: req.sessionKey,
          callId: req.callId,
          // Lineage provenance (symbol-lineage.md G2): stored in derived_from,
          // deliberately NOT part of the reuse key — findReusableSymbol ignores
          // it, so a re-sent identical allocation keeps the first mint's parent.
          derivedFrom: req.derivedFrom,
          lineRange: req.lineRange,
          // Server-side level derivation (confidentiality.md §6): no client
          // can under-label by omission; an explicit request can only RAISE
          // (parseConfidentialityLevel maps absent → public, unknown →
          // no-model). Axis OFF derives public/no bindings for a fresh
          // allocation key and omits the result level; explicit requested
          // levels are ignored (§11 kill switch). Existing rows retain their
          // labels/markers during reuse or canonical-name replacement below,
          // but OFF enforcement does not consult those preserved restrictions.
          confidentiality: this.confidentiality
            ? maxConfidentiality(
                parseConfidentialityLevel(req.confidentiality),
                sources?.level ?? "public",
                // Consults the USER labels first (Plan 6) — so a `model-ok`
                // contract mints a `anymodel_` symbol, and a declassified fixture
                // mints an ordinary one — and the DERIVED labels (Plan 9), so a
                // file a high session wrote mints one too. Keyed on the HumanView
                // spelling when the caller runs a view map (see `originHuman`):
                // the stores are HumanView, the wire origin is the AgentView twin,
                // and without this the label is written and never read.
                confidentialityForOrigin(levelOrigin, undefined, this.labelLookup).level,
                // ...and INHERITS from the origin SYMBOL when there is one (Plan 7).
                this.originSymbolLabel(req.origin).level,
              )
            : ("public" as const),
          bindings: this.confidentiality
            ? (sources?.bindings !== undefined
               ? sources.bindings.filter((b) => req.bindings === undefined || req.bindings.includes(b))
               : req.bindings
               ?? this.originSymbolLabel(req.origin).bindings
               ?? this.bindingsForOrigin(levelOrigin))
            : undefined,
          // Only the exact string "trusted" grants integrity trust; the axis
          // OFF keeps the pre-axis invariant (every row untrusted).
          integrity: this.confidentiality && !sources ? parseIntegrityLabel(req.integrity) : ("untrusted" as const),
        };
        // The stateless Messages API re-sends the whole conversation every
        // turn, so the ingress proxy re-symbolizes the SAME tool_result on
        // every later model call. Reuse the live symbol already minted for the
        // identical allocation key so the name stays STABLE across turns
        // (context coherence for T-LLM; no per-turn symbol-table growth) —
        // see findReusableSymbol for the exact key semantics. The level is NOT
        // part of that key: a higher-level re-send escalates the stored row
        // in place (monotone, fail-closed) and keeps the one stable name.
        // §9 rule 2's other half: the session has now ingested untrusted data.
        // Sticky, and it SUSPENDS the model-ok in-context-read clearance later
        // (declassify.ts). Under the real inbound policy a `Read` result is
        // untrusted, so in practice this goes true almost immediately — which is
        // correct, and is why rung 2 (the quarantine) is the path anyone will
        // actually use. See declassify.ts's header on the cost.
        if (this.confidentiality && req.sessionKey && key.integrity === "untrusted") {
          this.sessionLabels.taint(req.sessionKey);
        }
        const reused = sources ? null : findReusableSymbol(this.symbolMap, key);
        if (reused !== null) {
          if (this.confidentiality) {
            escalateSymbolConfidentiality(
              this.symbolMap, reused, key.confidentiality, this.dbPath ?? getSymbolDbPath());
          }
          this.log(`symbolize: reused ${reused} (same call re-sent)`);
          if (req.op === "symbolize") { this.learnResultHead(reused, req); this.learnRaisedRow(reused, req, levelOrigin); this.learnPathRow(reused, req); }
          const level = this.symbolMap.symbols.get(reused)?.confidentiality ?? "public";
          return {
            id: req.id, ok: true,
            result: this.confidentiality
              ? { symbol: reused, confidentiality: level }
              : { symbol: reused },
          };
        }
        // A malformed legacy name cannot be reused, but its restrictions and
        // first-mint lineage still constrain the canonical replacement. Never
        // turn a presentation repair into a confidentiality/integrity downgrade.
        const legacy = sources ? [] : [...findAllocationMatches(this.symbolMap, key)];
        if (legacy.length > 0) {
          const first = legacy[0]![1];
          let restrictedBindings = key.confidentiality === "public" ? undefined : (key.bindings ?? []);
          for (const [, entry] of legacy) {
            key.confidentiality = maxConfidentiality(key.confidentiality, entry.confidentiality);
            if (entry.confidentiality !== "public") {
              const allowed = entry.bindings ?? [];
              restrictedBindings = restrictedBindings === undefined ? [...allowed] : restrictedBindings.filter(b => allowed.includes(b));
            }
            if (entry.integrity !== "trusted") key.integrity = "untrusted";
          }
          key.bindings = restrictedBindings ?? first.bindings ?? key.bindings;
          key.derivedFrom = first.derived_from ?? undefined;
          key.lineRange = first.line_range ?? undefined;
          if (this.confidentiality && req.sessionKey && key.integrity === "untrusted") {
            this.sessionLabels.taint(req.sessionKey);
          }
        }
        // Resolve the default DB path explicitly: allocateSymbol treats an
        // undefined dbPath as "in-memory only" (the unit-fixture mode), which
        // silently broke daemon persistence — every symbol died with the
        // process while loadSymbolMap dutifully re-read an empty file at each
        // start (found 2026-07-10: an arbiter restart lost every historical
        // session's symbol table, so the dashboard's delivered-reply reveal
        // and the U-LLM resolve had nothing to resolve).
        const symbol = allocateSymbol(this.symbolMap, key, this.dbPath ?? getSymbolDbPath());
        if (req.op === "symbolize") { this.learnResultHead(symbol, req); this.learnRaisedRow(symbol, req, levelOrigin); this.learnPathRow(symbol, req); }
        // A join's sources, whole: the row records one parent, and a binding
        // removed from any source must reach it (current-bindings.ts rule 2).
        if (req.op === "symbolizeDerived" && this.confidentiality && isSecret(key.confidentiality)) {
          this.symbolSources.record(symbol, req.sourceSymbols.map((s) => findSymbolByName(this.symbolMap, s)?.name ?? s));
        }
        return {
          id: req.id, ok: true,
          result: this.confidentiality
            ? { symbol, confidentiality: key.confidentiality }
            : { symbol },
        };
      }
      case "desymbolize": {
        // DEEP (fixpoint): this op serves full-fidelity HumanView surfaces
        // (fs-sync syncToHuman), which must never receive a half-resolved
        // nested chain (the fs-sync-twin-Read double-symbolization). Gated
        // egress paths resolve per approved symbol via `resolve` instead.
        // DELIBERATELY label-unrestricted: HumanView surfaces (fs-sync, the
        // reply-filter) face the human, who owns their secrets at every
        // confidentiality level (confidentiality.md §4/§7 reply-filter row).
        const text = resolveAllSymbolsDeep(req.text, this.symbolMap);
        return { id: req.id, ok: true, result: { text } };
      }
      case "symbolShape": {
        // Reply row reservation (reply-row-reservation.md §3.3): the line count
        // of ONE token's value, so the proxy can reserve rows without ever
        // holding the value. Resolves as `desymbolize` does (deep, candidate
        // walk: `.field` paths, mutated tokens), after the Markdown-escape
        // normalization a model applies to tokens it repeats.
        //
        // EXPOSURE: the same as `desymbolize`: a HUMAN_PLANE_OPS member,
        // refused on the data socket the agent's tools reach (§5.3,
        // arbiter-human-plane.md). The proxy asks over the human socket.
        //
        // Returns ONLY `{ lines }` — never the value, its length, widths or
        // label (§5.2: the count is the one new flow). v2 (§11.5): with a
        // `width` it also returns `rows`, the value's row count under
        // `layoutRows` at that width, and `last`, the display width of the
        // last of those rows (§14: where the text after a mid-line block
        // wraps) — a count and a width only; `rule` (§17) picks the TUI's
        // wrap rule they are counted by, `indent` (§11.2) the content area's
        // column a TAB's stop counts from. `width`/`first`/`rule`/`indent`
        // are validated before the lookup, so a malformed request is refused
        // whether or not the token is known.
        if (typeof req.token !== "string") {
          return { id: req.id, ok: false, error: "symbolShape: token must be a string" };
        }
        const layout = parseShapeLayout(req);
        if (typeof layout === "string") return { id: req.id, ok: false, error: layout };
        const token = unescapeSymbols(req.token);
        // Exactly one token, nothing around it: the op is a count for a token
        // the proxy found, not a resolver for arbitrary text.
        const whole = new RegExp(`^(?:${getActiveFormat().pattern.source})$`);
        const hit = whole.test(token) ? findSymbolByName(this.symbolMap, token) : null;
        if (!hit) return { id: req.id, ok: true, result: null };
        // Deep-resolve the hit's value (what `desymbolize` substitutes for the
        // token). The trailing-dot re-attachment `desymbolize` does for prose
        // punctuation is deliberately not applied: it is not part of the value.
        const value = resolveAllSymbolsDeep(hit.entry.value, this.symbolMap);
        if (value === token) return { id: req.id, ok: true, result: null };
        const result: SymbolShapeResult = { lines: shapeLines(value) };
        if (layout) {
          const shape = shapeRowsLast(value, layout);
          result.rows = shape.rows;
          result.last = shape.last;
        }
        return { id: req.id, ok: true, result };
      }
      case "setSessionRelay": {
        // The reply filter reports its relay mode (reply-row-reservation.md
        // §3.6); the proxy reads it back with `sessionRelay`. NOT bind-once
        // (unlike setSessionSpec): it is re-reported on every resize.
        // HUMAN_PLANE_OPS member since v2 (§11.5): `cols` sets the wrap width
        // the proxy asks `symbolShape` for, so the agent's world must not be
        // able to write it (nor, symmetrically, read it). Validated strictly.
        const parsed = parseSessionRelay(req as unknown as Record<string, unknown>);
        if (typeof parsed === "string") return { id: req.id, ok: false, error: parsed };
        const prior = this.sessionRelays.get(parsed.sessionKey);
        this.sessionRelays.set(parsed);
        if (!prior || prior.mode !== parsed.mode || prior.reserve !== parsed.reserve || prior.wrap !== parsed.wrap || prior.rule !== parsed.rule) {
          this.log(`setSessionRelay: ${parsed.sessionKey} → ${parsed.mode}${parsed.reserve ? " (reserve)" : ""}${parsed.wrap ? " (wrap)" : ""}${parsed.rule ? ` (rule ${parsed.rule})` : ""}`);
        }
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "sessionRelay": {
        const keyProblem = relaySessionKeyProblem("sessionRelay", req.sessionKey);
        if (keyProblem) return { id: req.id, ok: false, error: keyProblem };
        return { id: req.id, ok: true, result: this.sessionRelays.get(req.sessionKey) };
      }
      case "noteReserveBlock": {
        // The proxy records a block it expanded (reply-row-reservation.md
        // §3.8), so the reply filter can lay out a continuation row whose
        // head never reached the screen. `token` must be exactly one symbol
        // token (unescaped here); nothing is resolved and no value is held.
        if (typeof req.token !== "string") {
          return { id: req.id, ok: false, error: "noteReserveBlock: token must be a string" };
        }
        const token = unescapeSymbols(req.token);
        const whole = new RegExp(`^(?:${getActiveFormat().pattern.source})$`);
        if (!whole.test(token)) return { id: req.id, ok: false, error: "noteReserveBlock: token must be exactly one symbol token" };
        const parsed = parseReserveBlock(req as unknown as Record<string, unknown>, token);
        if (typeof parsed === "string") return { id: req.id, ok: false, error: parsed };
        this.reserveBlocks.note(parsed);
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "recordForwardedClear":
      case "forwardedClear": {
        // Confidentiality §7.1, "Masked after the fact", across a resume: a
        // model proxy records the ids whose result body it forwarded in
        // clear, and a later launch's proxy asks which of a resumed
        // history's ids were. Ids only; a malformed one is skipped (it can
        // only lose a note, never a mask).
        if (!Array.isArray(req.ids)) return { id: req.id, ok: false, error: `${req.op}: ids must be an array of strings` };
        if (req.ids.length > FORWARDED_CLEAR_MAX_IDS) {
          return { id: req.id, ok: false, error: `${req.op}: at most ${FORWARDED_CLEAR_MAX_IDS} ids per request` };
        }
        const valid = (req.ids as unknown[]).filter(isCallId);
        const ids = [...new Set(valid)];
        if (req.op === "forwardedClear") {
          // "Two launches at once" (§7.1, 2026-10-17): the generation, and
          // with `since` the ids recorded after it, read with the answer.
          const generation = this.forwardedClear.generation();
          const since = typeof req.since === "number" && Number.isSafeInteger(req.since) && req.since >= 0 && req.since <= generation ? req.since : null;
          const recent = since === null ? null : this.forwardedClear.since(since);
          return {
            id: req.id, ok: true,
            result: { ids: this.forwardedClear.known(ids), generation, ...(recent ? { recent: recent.ids, recentComplete: recent.complete } : {}) },
          };
        }
        const recorded = ids.length > 0 ? this.forwardedClear.record(ids) : 0;
        return { id: req.id, ok: true, result: { recorded, skipped: req.ids.length - valid.length } };
      }
      case "recordForwardedPlaceholders": {
        // Confidentiality §6, *Across a relaunch*: a model proxy records, for
        // an OpenClaw result it forwarded in clear, where Mandu's placeholders
        // sat and the text's digest. Each map is validated whole (every
        // placeholder exactly one symbol token), so nothing but tokens,
        // offsets and a digest is stored; a malformed one is skipped (it can
        // only lose a restore, never a mask).
        if (!Array.isArray(req.maps)) return { id: req.id, ok: false, error: "recordForwardedPlaceholders: maps must be an array" };
        if (req.maps.length > FORWARDED_PLACEHOLDERS_MAX_MAPS) {
          return { id: req.id, ok: false, error: `recordForwardedPlaceholders: at most ${FORWARDED_PLACEHOLDERS_MAX_MAPS} maps per request` };
        }
        const valid: PlaceholderMap[] = [];
        for (const m of req.maps as unknown[]) {
          const parsed = parsePlaceholderMap(m);
          if (typeof parsed !== "string") valid.push(parsed);
        }
        const recorded = valid.length > 0 ? this.forwardedPlaceholders.record(valid) : 0;
        return { id: req.id, ok: true, result: { recorded, skipped: req.maps.length - valid.length } };
      }
      case "forwardedPlaceholders": {
        if (!Array.isArray(req.ids)) return { id: req.id, ok: false, error: "forwardedPlaceholders: ids must be an array of strings" };
        if (req.ids.length > FORWARDED_PLACEHOLDERS_MAX_IDS) {
          return { id: req.id, ok: false, error: `forwardedPlaceholders: at most ${FORWARDED_PLACEHOLDERS_MAX_IDS} ids per request` };
        }
        const ids = [...new Set((req.ids as unknown[]).filter(isCallId))];
        return { id: req.id, ok: true, result: { maps: this.forwardedPlaceholders.known(ids) } };
      }
      case "reserveBlock": {
        const keyProblem = relaySessionKeyProblem("reserveBlock", req.sessionKey);
        if (keyProblem) return { id: req.id, ok: false, error: keyProblem };
        if (typeof req.hash !== "string" || !/^[0-9a-f]{4,8}$/.test(req.hash)) {
          return { id: req.id, ok: false, error: "reserveBlock: hash must be 4 to 8 hex digits" };
        }
        return { id: req.id, ok: true, result: this.reserveBlocks.get(req.sessionKey, req.hash) };
      }
      case "resolve": {
        let value = resolveSymbol(this.symbolMap, req.symbol);
        // Opt-in deep expansion for ungated full-fidelity consumers (the
        // quarantined U-LLM). Unknown symbol stays null (fail-closed refusal).
        if (req.deep === true && value !== null) {
          {
            // The U-LLM quarantine call is ALSO an egress to the model provider,
            // so the exclusion is PER LEVEL (confidentiality.md §3.2/§3.3):
            //
            //   no-model   → REFUSED. The provider is not a cleared reader
            //                     at this level, and the U-LLM is the provider.
            //                     This refusal IS the headline residency claim
            //                     ("your key never reaches any vendor model").
            //                     It never relaxes, and no approval opens it.
            //   any-model → ADMITTED (Plan 7, rung 2). The provider IS a
            //                     cleared reader for this datum; the quarantine
            //                     shares no T-LLM context and its only egress is
            //                     a re-symbolized, SAME-LABEL return value —
            //                     which symbolize now guarantees server-side
            //                     (originSymbolLabel), so the result cannot come
            //                     back public and launder the secret.
            //   local-model → ADMITTED only when the request names an endpoint
            //                     the law declares `local: true` (plan 11 D4);
            //                     an absent, unknown or external endpoint is
            //                     refused exactly as no-model is.
            //
            // One rule decides all of it: `admits(location, level)`. The
            // location comes from the arbiter's OWN registry (policy.yaml
            // `models:`), never from the caller: a caller can only NAME an
            // endpoint, and an unknown name is external.
            //
            // Nesting follows admission, not the top level (plan 11 D3): inside
            // an admitted value, a nested symbol expands only if ITS level is
            // admitted at this endpoint. A no-model token quoted inside an
            // any-model value stays a token everywhere; a local-model one stays
            // a token at an external endpoint and expands at a local one.
            //
            // Shallow resolve is untouched — gated egress paths run
            // desymbolizationDecision first, and it is human-plane only.
            //
            // The gate runs WHATEVER the confidentiality axis says
            // (arbiter-human-plane.md §4): a `no-model` row minted while the
            // axis was on outlives a restart with it off, and this op is on
            // the data socket the agent world can reach. An unlabelled row
            // parses `public` and is admitted, so an axis-off stack with no
            // secret rows answers exactly as before.
            const location = modelLocation(
              getCurrentPolicy().models,
              typeof req.endpoint === "string" ? req.endpoint : undefined,
            );
            // The level is the strictest of every labelled source of the
            // value (value-sources.ts): another file holding the same bytes
            // at no-model keeps them from every model.
            const top = getSymbolEntry(this.symbolMap, req.symbol);
            if (top && !admits(location, valueSourceLevel(this.symbolMap, top))) {
              this.log(`resolve(deep): refused ${top.confidentiality} symbol ${req.symbol} at a${location === "local" ? " local" : "n external"} endpoint`);
              return { id: req.id, ok: true, result: { value: null } };
            }
            value = resolveAllSymbolsDeep(
              value, this.symbolMap, undefined,
              (e) => !admits(location, valueSourceLevel(this.symbolMap, e)));
            // Axis OFF: the wire shape stays the axis-off one ({ value }).
            if (!this.confidentiality) return { id: req.id, ok: true, result: { value } };
            // Hand the caller the level it must inherit. It is BELT to the
            // arbiter's braces: symbolize derives the inheritance server-side
            // regardless, but a caller that can SEE the label can also label its
            // event stream and refuse to do anything careless with the content.
            return {
              id: req.id, ok: true,
              result: {
                value,
                ...(top ? {
                  confidentiality: valueSourceLevel(this.symbolMap, top),
                  bindings: top.bindings ?? [],
                } : {}),
                location,
              },
            };
          }
        }
        return { id: req.id, ok: true, result: { value } };
      }
      case "symbolProvenance": {
        // symbol-quality.md §4.1 v2: the tool call that produced a symbol's
        // value, via the TCB-recorded linkage symbol.call_id → recordToolCall.
        // BEST-EFFORT by contract: every missing link degrades to nulls (the
        // tool-call records are in-memory, so a restart loses them) — the
        // consumer (inspect-mcp triage) falls back to provenance-free v1.
        const entry = getSymbolEntry(this.symbolMap, req.symbol);
        const callId = entry?.call_id ?? null;
        // A claimed record (arbiter-human-plane.md §10.2) is not the model
        // proxy's: answered as no record, so triage takes the provenance-free
        // prompt rather than a request the agent's own program wrote.
        const found = callId ? this.toolCalls.get(callId) : undefined;
        const record = found?.claimed ? undefined : found;
        return {
          id: req.id,
          ok: true,
          result: {
            tool: entry?.tool ?? null,
            ...(entry ? { field: entry.field } : {}),
            callId,
            toolName: record?.name ?? null,
            toolInput: record?.input,
          },
        };
      }
      case "classify": {
        // Bind-once bookkeeping for setSessionSpec: once a session has
        // classified traffic, its spec is frozen (see that handler).
        const sk = (req.request as { sessionKey?: unknown }).sessionKey;
        if (typeof sk === "string" && sk) this.classifiedSessions.add(sk);
        const classifyReq = this.withCallStartDir(req.request);
        const result = this.policy.classify(classifyReq);
        // Rung 3's own result (plan 11 §6): exactly the value decideDeclassify
        // released to this session, its watermark already raised. Neither
        // axis may mask it again: the generic `mcp__*` UNTRUSTED rule (the
        // integrity axis), nor a path-derived level read off the tool's
        // input (the confidentiality axis: the model's free-text `reason`
        // naming the file it is declassifying, which since the label-root
        // text scan of 2026-10-17 raised the result to that file's level,
        // so a granted read reached the model as a fresh token; nightly
        // 11551, conf-derived-label-next-session). The release stands only
        // for the exact grant (declassifyResultTrusted); anything else keeps
        // the policy's verdict, and the value backstop below still never
        // runs on Mandu's own quarantine tools.
        const inputLevel = parseConfidentialityLevel(result.confidentiality);
        const raised = this.confidentiality && isSecret(inputLevel);
        if ((result.trust === "UNTRUSTED" || raised) && this.declassifyResultTrusted(req.request)) {
          const { namedFiles: _kept, placedFiles: _placed, ifCdFailed: _failed, ...declassified } = result;
          let reason = "declassify_symbol result: exactly the value the arbiter released to this session (rung 3)";
          if (raised) {
            delete declassified.bindings;
            delete declassified.namedPaths;
            declassified.confidentiality = "public";
            reason += `; the ${inputLevel} level its input names is the session's watermark, not a mask`;
          }
          return { id: req.id, ok: true, result: { ...declassified, trust: "TRUSTED", reason } };
        }
        // The value backstop at the model door (confidentiality-plan-11 §8 row
        // 1, found by the live drill 2026-09-27): a tool result the path rules
        // call public can still carry a registered secret or a long line of
        // one, by a route no open of the labeled file shows: `git diff` /
        // `git show` of a copy committed to the workspace's own repository, or
        // that copy written to another file and read back. Such a result is
        // raised to the secret's level. Mandu's own quarantine tools are
        // exempt (inspect answers in symbols; declassify returns a released
        // value on purpose), and a result already secret is left as it is.
        const cReq = req.request as { tool?: unknown; value?: unknown; sessionKey?: unknown; callId?: unknown };
        const policySecret = isSecret(parseConfidentialityLevel(result.confidentiality));
        // Plan 15 §13.12: the files the path rule placed its secret readings
        // on stay in this arbiter (HumanView paths), never on the wire.
        const { namedFiles, placedFiles, ifCdFailed, ...wire } = result;
        if (
          this.confidentiality && typeof cReq.value === "string" && cReq.value !== "" &&
          !policySecret &&
          !(typeof cReq.tool === "string" && (isManduQuarantineTool(cReq.tool) || isManduPolicyTool(cReq.tool)))
        ) {
          const hits = this.secretValueHits(cReq.value);
          if (hits.length > 0) {
            const level = hits.map((h) => parseConfidentialityLevel(h.level)).reduce((a, b) => maxConfidentiality(a, b));
            const byLine = hits.some((h) => h.how === "line");
            this.noteBackstopCall(cReq.sessionKey, cReq.callId, cReq.value, { raised: true });
            // backstop-value-only.md: the narrower release, offered beside
            // the raise (the level stays the raise; the proxy decides).
            const valueOnly = typeof cReq.tool === "string" && VALUE_ONLY_TOOLS.has(cReq.tool) ? this.valueOnlyOffer(cReq.value) : null;
            return {
              id: req.id, ok: true,
              result: {
                ...wire,
                confidentiality: level,
                reason: `${result.reason}; a registered secret ${byLine ? "(or a line of one) " : ""}appears verbatim (${hits.map((h) => h.symbol).join(", ")}), so the result is ${level}`,
                // Plan 15 §4.1: the level is the backstop's alone. A proxy
                // that symbolizes the result at this level and raised it no
                // further says so (`secretBy`), and the row then registers
                // only the lines a secret was found in.
                raisedBy: "value-backstop" as const,
                ...(valueOnly !== null ? { valueOnly } : {}),
              },
            };
          }
        }
        if (this.confidentiality && policySecret) {
          this.noteBackstopCall(cReq.sessionKey, cReq.callId, cReq.value, {
            policySecret: true,
            path: { files: namedFiles ?? null, placed: placedFiles ?? [], level: parseConfidentialityLevel(result.confidentiality), ifCdFailed: ifCdFailed ?? null },
          });
          // clean-tree-release.md: the release of a shell command's result
          // masked only because its command names a registered credential
          // file, offered beside the verdict (the level stays; the proxy
          // decides on its own evidence).
          const pathRelease = this.pathReleaseOffer(classifyReq) ?? this.compoundListingOffer(classifyReq);
          // confidentiality.md §7.1: how a read of each named secret file
          // on its own reads (named-twins.ts); explains only.
          const namedTwins = this.namedTwinsOf(classifyReq, wire.namedPaths);
          const answer = namedTwins.length > 0 ? { ...wire, namedTwins } : wire;
          if (pathRelease !== null) return { id: req.id, ok: true, result: { ...answer, pathRelease } };
          return { id: req.id, ok: true, result: answer };
        }
        return { id: req.id, ok: true, result: wire };
      }
      case "desymbolizationDecision": {
        // Data-usage / egress gate: may this symbol be resolved on egress?
        // §10.3: only an ask on an attested channel spends a human's once;
        // an attested pre-check reads an approval and spends a denial.
        const spends: VerdictSpend = !attestedChannel(ctx.channel) ? false : req.request?.preflight === true ? "preflight" : true;
        const result = this.decideDesymWithApprovals(req.request, spends);
        return { id: req.id, ok: true, result };
      }
      case "fsPathDecision": {
        // Sensitive-path gate (fs data-usage policy): may this tool touch this
        // absolute path? Wrapped by the same interactive approval queue.
        const result = this.decideFsPathWithApprovals(req.request, attestedChannel(ctx.channel));
        return { id: req.id, ok: true, result };
      }
      case "fileUploadDecision":
        // Asynchronous since 2026-10-17 (the file is scanned in chunks,
        // upload-scan.ts): the socket path answers it (handleLine →
        // fileUploadDecisionOp); an in-process caller awaits that.
        return { id: req.id, ok: false, error: "fileUploadDecision is asynchronous: call it over the socket, or await fileUploadDecisionOp" };
      case "egressApprovals": {
        // List the interactive egress-approval queue, optionally by status.
        const approvals = this.withProvenance(this.listApprovals(
          req.status ? { status: req.status } : undefined,
        ));
        return { id: req.id, ok: true, result: { approvals } };
      }
      case "policyDocument": {
        const onDisk = this.policyDocs.readRaw();
        const result = {
          status: this.policyDocs.status,
          inForce: this.policyDocs.document,
          // The version of `inForce`: a whole-file apply built from it sends
          // it back (`applyPolicyDocument.lawHash`) and is refused as stale
          // once the law moved. Keyed per arbiter process, so the data
          // socket's copy says nothing about a hidden pattern.
          lawHash: this.policyDocs.lawHash,
          // Each item's version, the same keyed way: a typed edit that
          // carries fields over from this read names the items it read
          // (`policyPropose.basedOn`, §8.4.6 "An item-level version").
          itemVersions: this.policyDocs.itemVersions(),
          // The version of an item the law does not have: a writer that
          // creates one where its read found none names it with this.
          absentVersion: this.policyDocs.absentVersion,
          // `warnings` (Plan 13 D8): advice on a valid document, e.g. a
          // reader that is a shell or an interpreter.
          onDisk: { text: onDisk.text, parsed: onDisk.parsed, problems: onDisk.problems, warnings: policyWarnings(onDisk.parsed) },
          // Plan 12 D5: the administrator's entries as their files spell
          // them (the dashboard's Test connection probes one by name), the
          // user's entries the layer keeps out of force, a refused re-read.
          ...this.adminView(),
        };
        // Plan 15 §13.7 item 4: the DATA socket gets every prompt
        // exception's pattern replaced (prompt-pattern-redact.ts); the human
        // socket and the admin channel get the document as it is.
        return { id: req.id, ok: true, result: ctx.channel === "data" ? redactPolicyDocumentResult(result, this.adminPromptPatterns()) : result };
      }
      case "applyPolicyDocument": {
        // The law the document was built from (policy-surface.md §8.4.6 "A
        // whole-file apply names the law it was built from"): required, so
        // no apply lands on a newer law unchecked and undoes what changed.
        if (typeof req.lawHash !== "string" || req.lawHash === "") {
          return { id: req.id, ok: false, error: "applyPolicyDocument needs lawHash: the lawHash a policyDocument read gave with the law the document was built from; nothing was written" };
        }
        const r = this.policyDocs.applyDocument(req.document, req.lawHash, { via: "apply", requestedBy: req.requestedBy });
        return { id: req.id, ok: true, result: { path: r.path, status: this.policyDocs.status } };
      }
      case "mintUserRule": {
        const { id, result } = this.policyDocs.mintUserRule(req.rule, req.requestedBy);
        return { id: req.id, ok: true, result: { id, path: result.path, status: this.policyDocs.status } };
      }
      case "movePageLabels": {
        const rows = this.pathLabels.list();
        if (rows.length === 0) return { id: req.id, ok: true, result: { moved: 0, changeId: null } };
        const labels = rows.map((l) => ({ path: l.path, level: l.confidentiality, bindings: l.bindings, recursive: l.recursive }));
        // The file first: if it cannot be written, no row is deleted.
        const { moved } = this.policyDocs.moveDbLabels(labels, req.requestedBy);
        for (const l of rows) this.pathLabels.remove(l.path);
        const changeId = this.policyAgent.changesList(1).changes[0]?.id ?? null;
        this.log(`movePageLabels: ${moved} rule(s) moved from mandu.db into policy.yaml`);
        return { id: req.id, ok: true, result: { moved, changeId } };
      }
      case "exportDbLabels": {
        const labels = this.pathLabels.list().map((l) => ({
          path: l.path, level: l.confidentiality, bindings: l.bindings, recursive: l.recursive,
        }));
        const { added, result } = this.policyDocs.exportDbLabels(labels, req.requestedBy);
        return { id: req.id, ok: true, result: { added, path: result.path, status: this.policyDocs.status } };
      }
      // ── policy agent surface (policy-surface.md §8.4.2) ──
      case "policyPropose":
        return { id: req.id, ok: true, result: this.policyAgent.propose(req, ctx.channel === "admin" ? "admin" : "data") };
      case "policyProposals": {
        // The held disk text stays admin-only (proposalWire); an exception's
        // pattern stays off the DATA socket (plan 15 §13.7 item 4).
        const r = this.policyAgent.proposalsList(req.status, ctx.channel === "admin" ? "admin" : "data", req.kind === "suggestion" ? "suggestion" : "proposal");
        return { id: req.id, ok: true, result: ctx.channel === "data" ? { proposals: r.proposals.map(redactProposal) } : r };
      }
      // ── policy suggestions (confidentiality-plan-14 §5.2) ──
      case "suggestPolicy":
        // Asynchronous (the history scan): the socket path answers it
        // (handleLine → suggestPolicyOp).
        return { id: req.id, ok: false, error: "suggestPolicy is asynchronous: call it over the socket, or await suggestPolicyOp" };
      case "modelSuggestPreview":
      case "modelSuggest":
        // Asynchronous, like suggestPolicy (handleLine → modelSuggest*Op).
        return { id: req.id, ok: false, error: `${req.op} is asynchronous: call it over the socket` };
      case "policySuggestions":
        return { id: req.id, ok: true, result: this.policySuggestions.list(req.status) };
      case "suggestFromScan":
        return this.suggestFromScanOp(req);
      case "applySuggestion":
      case "dismissSuggestion": {
        // The data plane applies as itself: it never names a human.
        const by = ctx.channel === "admin"
          ? (typeof req.requestedBy === "string" && req.requestedBy && !req.requestedBy.startsWith("mandu:") ? req.requestedBy.slice(0, 128) : "human")
          : "data-plane";
        try {
          const result = req.op === "applySuggestion"
            // Provenance: the data plane is the agent's channel, so its
            // apply is recorded as the agent's (plan 14 §5.2), never as a
            // person's; it applies only a pure tightening (`apply`).
            ? this.policySuggestions.apply(String(req.suggestionId), { via: ctx.channel === "admin" ? "tighten" : "agent-tighten", by })
            : this.policySuggestions.dismiss(String(req.suggestionId), by);
          return { id: req.id, ok: true, result };
        } catch (err) {
          if (err instanceof OpError) return { id: req.id, ok: false, error: err.message };
          throw err;
        }
      }
      case "policyChanges": {
        const r = this.policyAgent.changesList(req.limit);
        return { id: req.id, ok: true, result: ctx.channel === "data" ? { changes: r.changes.map(redactChange) } : r };
      }
      case "policyPreview":
        return { id: req.id, ok: true, result: this.policyAgent.preview(req.edits) };
      case "policySchema":
        // The AGENT schema: the model-endpoint ops are never offered (§4.3a).
        return { id: req.id, ok: true, result: { edits: policyAgentEditSchema() } };
      case "policyExplain":
        return { id: req.id, ok: true, result: this.policyAgent.explain({ audience: req.audience, sessionKey: req.sessionKey }) };
      case "resolvePolicyProposal":
      case "undoPolicyChange": {
        const by = typeof req.requestedBy === "string" && req.requestedBy ? req.requestedBy.slice(0, 128) : "human";
        try {
          const result = req.op === "resolvePolicyProposal"
            ? this.policyAgent.resolve(req.proposalId, req.verdict === "approved" ? "approved" : "denied", by)
            : this.policyAgent.undo(req.changeId, by);
          return { id: req.id, ok: true, result };
        } catch (err) {
          if (err instanceof OpError) return { id: req.id, ok: false, error: err.message };
          throw err;
        }
      }
      case "resolveEgressApproval": {
        // Apply a human verdict (approve/deny) to a queued entry by id. The entry
        // id is `approvalId` (req.id is the wire correlation id, distinct).
        // Scope: "always" unless the wire explicitly says "once" — an absent or
        // unrecognized value must land on the standing default, never on the
        // narrower single-use verdict (pre-scope callers keep their semantics).
        const asked = req.scope === "once" ? "once" : "always";
        // "Send without it" (confidentiality.md §4): only `strip: true`
        // asks for it (anything else is the old answer), only as a denial,
        // and only on a card about a secret's placeholder in a network
        // request. Refused anywhere else, fail-closed: on a content-agnostic
        // card (a program holding a secret, a session's request) the request
        // may hold the raw value, and there is no placeholder to take out.
        const strip = req.strip === true;
        if (strip && req.approve !== false) {
          return { id: req.id, ok: false, error: `egress-approval ${String(req.approvalId)}: Send without it is not an allow (send approve: false)` };
        }
        // The !437 leftover (4): a question filed before printers (or bare
        // interpreters) stopped being readers is retired (removed, never
        // answered), and an answer to it, which would change nothing, is
        // refused and says why. Retired first, so a question that became moot
        // since the last listing (a printer hashed since) is refused too.
        this.retireMootQuestions();
        const retired = typeof req.approvalId === "string" ? this.retiredQuestions.get(req.approvalId) : undefined;
        if (retired !== undefined) {
          this.log(`resolveEgressApproval: ${req.approvalId} refused (no longer applies)`);
          return { id: req.id, ok: false, error: `egress-approval ${req.approvalId} no longer applies: ${retired}` };
        }
        // Plan 13 §8 decision (c): a row about one run of a program that
        // runs code no script pin names (`…#run:<procKey>`) takes no
        // standing answer: an Always is kept as once.
        const row = this.egressApprovals.list().find((a) => a.id === req.approvalId);
        // A HIGH session's ask (confidentiality.md §4, 2026-10-11) takes no
        // standing answer either: an Always is kept as once, since the card
        // speaks of one request (or one command) of one session.
        // A holder's send question (plan 13 §5.4) keyed to no session takes
        // no standing answer either: its Always is "this session", and there
        // is no session to scope it to.
        const holderRow = row !== undefined ? parseHolderSendSubject(row.symbol) : null;
        const scope = row !== undefined && ((binaryVerdictParts(row.symbol).run !== undefined && /^(open|write):/.test(row.symbol)) || isSessionApprovalSubject(row.symbol) || (holderRow !== null && holderRow.session === null)) ? "once" : asked;
        // Plan 15 §12 (2026-10-04): a prompt hold under a locked
        // administrator's `ask` row takes no session answer; an Always here
        // would be one, so it is refused with the reason (never kept as once:
        // the human chose the session and must see it was not given).
        const onceOnly = this.promptHolds.genericRefusal(row, scope, this.promptFilter.config());
        if (onceOnly !== null) {
          this.log(`resolveEgressApproval: ${req.approvalId} refused (a locked ask row: this message only)`);
          return { id: req.id, ok: false, error: `egress-approval ${req.approvalId}: ${onceOnly}` };
        }
        if (strip) {
          if (row === undefined) return { id: req.id, ok: false, error: `unknown egress-approval id: ${req.approvalId}` };
          const refusal = this.sendWithoutRefusalOf(row);
          if (refusal !== null) {
            this.log(`resolveEgressApproval: ${req.approvalId} refused (send without it: ${refusal})`);
            return { id: req.id, ok: false, error: `egress-approval ${req.approvalId} cannot be answered Send without it: ${refusal}` };
          }
        }
        const approval = this.egressApprovals.resolve(req.approvalId, req.approve, scope, strip ? { strip: true } : {});
        if (!approval) {
          return { id: req.id, ok: false, error: `unknown egress-approval id: ${req.approvalId}` };
        }
        this.log(`resolveEgressApproval: ${req.approvalId} → ${approval.status} (${approval.scope}${approval.strip ? ", send without it" : ""})`);
        // Plan 15 §7: a prompt hold answered here (Allow = send as written,
        // Deny = send with the default); an Always covers the session.
        this.promptHolds.afterResolve(approval, this.promptFilter.config());
        // A prompt hold answered on the generic route: Allow = send, Deny =
        // the default (masked); Always = the session.
        const promptRow = parsePromptRow(approval);
        this.emitApprovalResolved(approval, promptRow?.turn !== undefined
          ? { answer: approval.status === "approved" ? "send" : "mask", scope: approval.scope === "always" ? "session" : "once" }
          : undefined);
        return { id: req.id, ok: true, result: { approval } };
      }
      case "holderSourceBinding": {
        // Plan 13 §5.4, §9 R2: a READ. It names the edit an *Always* on one
        // file of a holder's send question files; the dashboard applies it
        // on the admin channel (policyPropose + resolvePolicyProposal).
        if (typeof req.approvalId !== "string" || typeof req.path !== "string" || req.path === "") {
          return { id: req.id, ok: false, error: "holderSourceBinding: approvalId and path required" };
        }
        try {
          return { id: req.id, ok: true, result: this.holderSourceBinding(req.approvalId, req.path) };
        } catch (err) {
          if (err instanceof OpError) return { id: req.id, ok: false, error: err.message };
          throw err;
        }
      }
      case "forgetEgressApproval": {
        // Forget a human verdict (dashboard.md §4.25): the pair asks again on
        // its next attempt. Admin-only (ADMIN_ONLY_OPS): only a human forgets.
        const approvalId = typeof req.approvalId === "string" ? req.approvalId : "";
        const pending = this.egressApprovals.list({ status: "pending" }).some((a) => a.id === approvalId);
        const approval = this.egressApprovals.forget(approvalId);
        if (!approval) {
          return { id: req.id, ok: false, error: pending ? `egress-approval ${approvalId} is still waiting for an answer` : `unknown egress-approval id: ${approvalId}` };
        }
        this.log(`forgetEgressApproval: ${approvalId} (${approval.status} → asks again)`);
        return { id: req.id, ok: true, result: { approval } };
      }
      case "setSessionPosture": {
        // Two callers, one op: SIEM-triggered lockdown (siem-integration.md §4.3,
        // scenario D — a Wazuh active-response callback TIGHTENS the egress
        // posture) and the dashboard's human-driven route, which alone may RELAX
        // it via the explicit allowRelax flag (policy-surface.md §9.8.6).
        // Enforcement stays in the arbiter — both are REQUESTERS of a posture the
        // hub already knows how to enforce (decideDesymWithApprovals below).
        const posture = parsePosture(req.posture);
        if (!posture) {
          return { id: req.id, ok: false, error: `invalid posture: ${JSON.stringify(req.posture)} (want "normal"|"lockdown")` };
        }
        // GLOBAL scope only today — the network egress gate carries no sessionId, so
        // a per-session posture would be state nothing reads. Refuse it loudly
        // rather than store a lie (confidentiality.md §12 "posture nobody runs").
        if (req.sessionId && req.sessionId !== "*" && req.sessionId !== "global") {
          return { id: req.id, ok: false, error: `per-session posture not yet enforceable at the network egress gate; omit sessionId (or use "*") for a global campaign-wide lockdown` };
        }
        // TIGHTEN-ONLY BY DEFAULT: the store refuses a loosen unless the request
        // carries the explicit `allowRelax` flag (policy-surface.md §9.8.6 — the
        // dashboard's human-driven ▶ Resume). A SIEM rule never sends the flag, so
        // it still can never relax policy; an APPLIED relax audits through the
        // same posture_change event as a tighten (emitPostureChange below).
        const change = this.sessionPosture.requestGlobal(posture, { allowRelax: req.allowRelax === true });
        this.log(
          `setSessionPosture: global ${change.from}→${change.to} ` +
            `[${change.applied ? "APPLIED" : "refused"}: ${change.reason}]` +
            (req.requestedBy ? ` requestedBy=${req.requestedBy}` : ""),
        );
        if (change.applied) this.emitPostureChange(change, req.requestedBy);
        return {
          id: req.id, ok: true,
          result: {
            posture: this.sessionPosture.globalPosture(),
            applied: change.applied, from: change.from, to: change.to, reason: change.reason,
          },
        };
      }
      case "setSessionSpec": {
        // Session-keyed trust specs (agent-e2e-harness.md §7.1): bind a session
        // to an agent's inbound/outbound spec so ONE arbiter can serve mixed
        // agents. Classification falls back to the process-global boot spec for
        // unbound sessions, so this op only ever NARROWS what a foreign
        // session's tool names can classify as.
        if (!req.sessionKey || typeof req.sessionKey !== "string") {
          return { id: req.id, ok: false, error: "setSessionSpec: sessionKey required" };
        }
        if (typeof req.spec !== "string") {
          return { id: req.id, ok: false, error: "setSessionSpec: spec must be a string" };
        }
        // FAIL-CLOSED on an unknown spec id: the caller declared "this session
        // is agent X" and we cannot honor it — binding the empty fail-closed
        // spec (every tool UNTRUSTED) is strictly safer than leaving the
        // session on another agent's TRUSTED grants.
        const known = isInboundSpecId(req.spec);
        const bound = isInboundSpecId(req.spec) ? req.spec : "fail-closed";
        // BIND-ONCE (policy-surface.md §2.6): this op is data-plane —
        // the proxy binds its session at boot, before the agent exists — so the
        // agent's own processes can reach it too. What they must not be able
        // to do is move a LIVE session onto a laxer spec. Two refusals close
        // that: a session that already classified traffic cannot be bound at
        // all, and a bound session cannot be re-bound to a different spec
        // (re-binding to the same spec is an idempotent no-op). The bindings
        // are THIS server's (`this.sessionSpecs`), for its life: another
        // arbiter in the same process neither sees nor blocks them.
        const prior = this.sessionSpecs.specOf(req.sessionKey);
        if (prior !== undefined && prior !== bound) {
          this.log(`setSessionSpec refused: ${req.sessionKey} already bound to '${prior}' (asked '${bound}')`);
          return {
            id: req.id,
            ok: false,
            error: `setSessionSpec: session already bound to '${prior}' — specs are bind-once`,
          };
        }
        if (prior === undefined && this.classifiedSessions.has(req.sessionKey)) {
          this.log(`setSessionSpec refused: ${req.sessionKey} has already classified traffic`);
          return {
            id: req.id,
            ok: false,
            error: "setSessionSpec: session has already classified traffic — a spec binds only before the first classify",
          };
        }
        // The registry enforces bind-once itself too (the check above is what
        // logs and words the refusal); a refusal here is the same answer.
        const bind = this.sessionSpecs.bind(req.sessionKey, bound);
        if (!bind.ok) {
          return { id: req.id, ok: false, error: `setSessionSpec: session already bound to '${bind.prior}' — specs are bind-once` };
        }
        const reason = known
          ? `session bound to spec '${bound}'`
          : `unknown spec '${req.spec}' — bound 'fail-closed' (every tool UNTRUSTED)`;
        this.log(
          `setSessionSpec: ${req.sessionKey} → ${bound}` +
            (known ? "" : ` [requested '${req.spec}' unknown]`) +
            (req.requestedBy ? ` requestedBy=${req.requestedBy}` : ""),
        );
        return { id: req.id, ok: true, result: { bound, applied: known, reason } };
      }
      case "classifyExec": {
        // Select AgentShell vs HumanShell for a command argv.
        const result = classifyExec({
          argv: req.argv,
          cwd: req.cwd,
          needsNetwork: req.needsNetwork,
          needsOriginalFs: req.needsOriginalFs,
          params: req.params,
        });
        return { id: req.id, ok: true, result };
      }
      case "resolveExecArgv": {
        // Desymbolize an argv for the chosen shell AFTER the data-usage check +
        // command rewriting. Reads the live symbol table.
        const result = resolveExecArgv(
          { argv: req.argv, shell: req.shell, params: req.params },
          this.symbolMap,
          { confidentiality: this.confidentiality },
        );
        return { id: req.id, ok: true, result };
      }
      case "execGate": {
        // Model-context-layer exec gate: classify a raw shell command and decide
        // allow/block (blocks only an untrusted symbol in command/exec position).
        // Pure over the command string — reads no state.
        let result = execGate({ command: req.command, cwd: req.cwd });
        // Plan 13 D7: the proxy gates a tool_use before the agent sees it, so
        // no exec older than now is this call's root (callTree's bound).
        // Plan 13 D9: only the proxy's own gate (the human socket) records it.
        // The D9 follow-up: and the command it gated, which callTaint binds
        // the call by (unless the proxy records the delivered form, below).
        if (typeof req.callId === "string" && req.callId !== "" && this.attested(ctx.channel)) {
          this.provenance.recordCallPending(req.callId, req.sessionKey);
          this.provenance.recordCallCommand(req.callId, execSignature(req.command), "gate", req.sessionKey);
        }
        // exec-routing.md §8.7a — the PROVENANCE gate. The token gate above is
        // structurally blind to `curl -o setup.sh` → `bash setup.sh` (no symbol
        // on the wire: the bytes flow curl → disk → bash without re-entering the
        // proxy). This reads the program text's ORIGIN instead — off the taint
        // registry (the declared net writes recorded below + kernel-observed
        // file_taint rows) and off the string itself (`curl … | bash`) — and
        // denies on AFFIRMATIVE taint only, behind the same approval queue as
        // the fs/net gates (unknown / pre-existing scripts are not gated: the
        // world-swap floors that case). Integrity-gated: with the axis off,
        // nothing is untrusted-by-origin.
        if (this.integrity && result.decision !== "block") {
          result = this.gateProgramText(result, req.command, req.sessionKey, attestedChannel(ctx.channel));
        }
        // A HIGH session tightens exec (§4, §7 ③). This is where the watermark
        // earns its keep: the command need contain NO SYMBOL — the model may have
        // PARAPHRASED the secret it read into an argv — and the per-symbol gate
        // above is structurally blind to that. Only the session label can see it.
        //
        // WHY `netEnabled: true` UNCONDITIONALLY, rather than `shell ===
        // "HumanShell"`. `ExecGateResult.shell` is documented as INFORMATIONAL
        // and defaults to AgentShell — it is the world a command WOULD route to,
        // not one anything has established. In Track A the exec-supervisor's
        // world-swap is kernel-tier and OFF, so a Bash command runs with the
        // user's real network. Trusting that label would mean reading "AgentShell"
        // (net off) off a process that in fact holds a socket — a fail-OPEN on a
        // security decision. Unknown world ⇒ assume net ⇒ approval.
        //
        // THE COST IS REAL AND BLUNT: in a high session this gates EVERY Bash
        // command, `ls` included, because Track A cannot prove any of them is
        // net-less. It is defense-in-depth against exactly the documented
        // `exec-curl-run-blindspot` (exec-routing.md §6) that the integrity
        // lattice already carries. The PRECISE gate is the network boundary
        // (sessionEgressDecision), which net-proxy enforces when on; once the
        // world-swap really confines AgentShell, pass its true net capability here
        // and the `netEnabled: false` branch relaxes this automatically — the pure
        // gate already supports it. That is the follow-up. A denylist of
        // "network-looking" commands would be detection, and detection is not what
        // this system does.
        //
        // The HUMAN half (confidentiality.md §4, 2026-10-11): the refusal files
        // an Approvals row keyed on this session × this exact command; an
        // Allow once lets that command run once (spent here, on an attested
        // channel only), a Block refuses it again with no new card.
        if (this.confidentiality && result.decision !== "block") {
          const verdict = this.decideSessionEgressWithApprovals(
            { sessionKey: req.sessionKey, boundary: "shell", netEnabled: true, command: req.command },
            attestedChannel(ctx.channel),
          );
          if (!verdict.allow) {
            result = {
              ...result, decision: "block", reason: verdict.reason,
              ...(verdict.ruleRef ? { ruleRef: verdict.ruleRef } : {}),
              ...(verdict.approvalId ? { approvalId: verdict.approvalId } : {}),
            };
            this.log(`execGate: HIGH SESSION → blocked (net capability unprovable${verdict.approvalId ? `; asked ${verdict.approvalId}` : ""})`);
          } else if (verdict.ruleRef?.source === "verdict") {
            result = { ...result, reason: verdict.reason, ruleRef: verdict.ruleRef };
            this.log(`execGate: HIGH SESSION → allowed by the human (${verdict.ruleRef.id})`);
          }
        }
        // The requoted command (shell-placeholder-quoting.ts) rides an allow
        // only: a blocked command is delivered as the block sentinel.
        if (result.decision !== "allow" && result.requoted !== undefined) {
          result = { ...result };
          delete result.requoted;
        }
        // An ALLOWED fetch-to-disk declares its output net-influenced (§7a):
        // the registry row is what a later `bash <that file>` trips on. The
        // command runs only when allowed, so record on the FINAL verdict.
        if (result.decision === "allow") this.recordDeclaredNetWrites(req.command, req.sessionKey, req.callId);
        // RECORD the verdict by command signature so the exec supervisor can
        // correlate it later (exec-routing.md §4 step 1). Best-effort memory.
        this.execDecisions.record(execSignature(req.command), {
          block: result.decision === "block",
          shell: result.shell,
          evasion: result.evasion,
          reason: result.reason,
          sessionKey: req.sessionKey,
          // The callId leg of the correlation (exec-routing.md §8.5): the
          // supervisor's signature lookup hands back the tool_use id its
          // clean-verdict report must be keyed on.
          ...(req.callId ? { callId: req.callId } : {}),
        });
        return { id: req.id, ok: true, result };
      }
      case "recordCallCommand": {
        // Plan 13 D9 follow-up: the command the model proxy DELIVERED to the
        // agent for a call (after its view map and gates rewrote it), which
        // callTaint binds the call to the agent's shell by. Believed only
        // from the human socket (the proxies' human client); from the data
        // socket nothing is recorded, so a forged command never binds a call.
        if (typeof req.callId !== "string" || req.callId === "" || (req.command !== undefined && typeof req.command !== "string")) {
          return { id: req.id, ok: false, error: "recordCallCommand: callId required, command a string when given" };
        }
        if (!this.attested(ctx.channel)) return { id: req.id, ok: true, result: { recorded: false, reason: this.unattested("recordCallCommand", ctx.channel) } };
        // Plan 13 §4.5.1 (2026-10-02): a call with no command (WebFetch, an
        // MCP tool) records only its relay: the start of the window in which
        // the agent's own connections to a holder mask its result.
        if (req.command === undefined) {
          this.provenance.recordCallPending(req.callId, req.sessionKey);
          return { id: req.id, ok: true, result: { recorded: true } };
        }
        const signature = execSignature(req.command);
        this.provenance.recordCallCommand(req.callId, signature, "delivered", req.sessionKey);
        return { id: req.id, ok: true, result: { recorded: signature !== "" } };
      }
      case "recordEgressRefusal": {
        // Plan 10 §11.8, "Refused connections": the egress proxy refused a
        // connection from these processes. callTaint folds it into the tool
        // call whose tree holds one of them, so the result says so. Believed
        // only from the human socket (the net-proxy's human client); a kind
        // from the fixed set, never a host.
        // "A refusal no process is tied to" (2026-10-17): `unattributed`
        // with no procKeys records the kind for the session alone, folded
        // into the calls that were running (never a guessed process).
        const keys = Array.isArray(req.procKeys) ? req.procKeys.filter((k): k is string => typeof k === "string" && k !== "").slice(0, 16) : [];
        const unattributed = req.unattributed === true && keys.length === 0;
        if ((keys.length === 0 && !unattributed) || !(EGRESS_REFUSAL_KINDS as readonly string[]).includes(req.kind)) {
          return { id: req.id, ok: false, error: `recordEgressRefusal: procKeys required (or unattributed: true), kind one of ${EGRESS_REFUSAL_KINDS.join(", ")}` };
        }
        if (!this.attested(ctx.channel)) return { id: req.id, ok: true, result: { recorded: false, reason: this.unattested("recordEgressRefusal", ctx.channel) } };
        if (unattributed) {
          const recorded = this.provenance.recordUnattributedEgressRefusal({ kind: req.kind, ...(req.sessionKey ? { session: req.sessionKey } : {}) });
          return { id: req.id, ok: true, result: recorded ? { recorded: true } : { recorded: false, reason: "no call of the session is running, or each running call already has this note" } };
        }
        for (const procKey of keys) this.provenance.recordEgressRefusal({ procKey, kind: req.kind, ...(req.sessionKey ? { session: req.sessionKey } : {}) });
        return { id: req.id, ok: true, result: { recorded: true } };
      }
      case "execDecisionFor": {
        // Correlation lookup: the proxy's recorded execGate decision for a
        // command (by signature), or null on a miss.
        const command = req.command ?? (req.argv ? undefined : "");
        const signature =
          command !== undefined
            ? execSignature(command)
            : execSignatureForArgv(req.argv ?? []);
        const decision = this.execDecisions.lookup(signature) ?? null;
        return { id: req.id, ok: true, result: { decision, signature } };
      }
      case "escalateExec": {
        // Exec escalation gate: an AgentShell command that needs a restricted
        // resource may escalate to HumanShell ONLY behind a human approval.
        const result = this.decideExecEscalation(req.argv, req.resource, req.sessionKey, attestedChannel(ctx.channel));
        return { id: req.id, ok: true, result };
      }
      case "reportExecCleanVerdict": {
        // Exec-output rung 2 (exec-routing.md §8.5): resolve the
        // supervisor's claim through the fail-closed gate chain (boxed,
        // AgentShell, arbiter-side taint re-check, output hash) and record it
        // by callId for the classify-time upgrade.
        // The agent tree reaches this socket too, so a report is honored only
        // when it carries the reporter token the session's guard claimed
        // (exec-routing.md §8.5.3); anything else is `data-socket` and
        // resolves UNCLEAN (sandbox-security-review finding 4).
        const reporterSession = this.cleanReporters.sessionFor(req.reporterToken);
        const verdict = this.execCleanVerdicts.report(
          req.report,
          reporterSession === undefined ? "data-socket" : { via: "authenticated-supervisor", sessionKey: reporterSession },
        );
        this.log(
          `reportExecCleanVerdict: ${req.report.callId || "(no callId)"} → ` +
            `${verdict.clean ? "CLEAN" : "unclean"} (${verdict.reason})` +
            (reporterSession === undefined ? (req.reporterToken !== undefined ? " [unknown reporter token]" : "") : ` [guard of ${reporterSession}]`),
        );
        return { id: req.id, ok: true, result: { verdict } };
      }
      case "claimCleanReporter": {
        // The session's guard claims its reporter token before its agent
        // starts (clean-reporters.ts); a second claim revokes the reporter.
        if (typeof req.sessionKey !== "string" || req.sessionKey === "") {
          return { id: req.id, ok: false, error: "claimCleanReporter: sessionKey required" };
        }
        const claimed = this.cleanReporters.claim(req.sessionKey);
        if (!claimed.ok) {
          this.log(`${claimed.error} [${req.sessionKey}]`);
          return { id: req.id, ok: false, error: claimed.error };
        }
        this.log(`claimCleanReporter: ${req.sessionKey} → claimed`);
        return { id: req.id, ok: true, result: { token: claimed.token } };
      }
      case "execCleanVerdictFor": {
        const verdict = this.execCleanVerdicts.lookup(req.callId) ?? null;
        return { id: req.id, ok: true, result: { verdict } };
      }
      case "reportExecTwins": {
        // Symbol-twin hint from the exec box (symbol-twin-shell-blindness.md
        // §4.1 v2): utility-only, off the security path — recorded for the
        // proxy's `execTwinsFor` read; nothing is classified by it.
        const recorded = this.execTwins.record(req.report);
        if (recorded > 0) {
          this.log(`reportExecTwins: ${(req.report?.argv ?? []).slice(0, 3).join(" ")} → ${recorded} twin(s)`);
        }
        return { id: req.id, ok: true, result: { recorded } };
      }
      case "execTwinsFor": {
        return { id: req.id, ok: true, result: this.execTwins.twinsFor(req.command ?? "") };
      }
      case "pathLevel": {
        // The mint-time derivation for a path, read-only (fs-sync's relabel
        // guard, fs-sync.md §3.2). Same inputs as symbolize's own
        // derivation: the user labels and the catalog, on the given spelling.
        if (!this.confidentiality) return { id: req.id, ok: true, result: { level: "public", bindings: [], axis: false, rule: null } };
        const m = confidentialityForOrigin(typeof req.path === "string" ? req.path : "", undefined, this.labelLookup);
        return { id: req.id, ok: true, result: { level: m.level, bindings: m.bindings ?? [], axis: true, rule: m.rule ?? null } };
      }
      case "pathLevels": {
        // The Rules page's file browser (dashboard.md §4.25m): pathLevel's
        // derivation per entry of one listed folder, read-only. Answers with
        // the axis OFF too (axis: false), unlike pathLevel, whose caller mints.
        const paths = Array.isArray(req.paths) ? req.paths : null;
        if (paths === null || paths.length > PATH_LEVELS_MAX || !paths.every((p) => typeof p === "string")) {
          return { id: req.id, ok: false, error: `pathLevels: paths must be a list of at most ${PATH_LEVELS_MAX} strings` };
        }
        const home = typeof req.home === "string" && req.home !== "" ? req.home : undefined;
        const answer = (): PathLevelsOpResult => ({ axis: this.confidentiality, levels: paths.map((p) => this.pathLevelsEntry(p, home)) });
        if (req.withEdits !== undefined) {
          const ev = evaluateEdits({ specId: getCurrentPolicy().specId, document: this.policyDocs.document }, req.withEdits);
          if (!ev.ok) return { id: req.id, ok: false, error: `withEdits: ${ev.problems.join("; ")}` };
          // The memo is keyed on the law object, so the hypothetical law gets
          // its own merge and the real one is untouched afterwards.
          return { id: req.id, ok: true, result: this.withHypotheticalLaw(ev.document, answer) };
        }
        return { id: req.id, ok: true, result: answer() };
      }
      case "whyPath": {
        // `mandu why <path>` (comparisons.md §3.2): the gates' own
        // derivations for one file, read-only (no pin, no queue, no count).
        const path = typeof req.path === "string" ? req.path : "";
        const home = typeof req.home === "string" && req.home !== "" ? req.home : undefined;
        // An agent's own file (secret-discovery.md §1.10): `mandu why` must
        // not promise a placeholder copy where a launch leaves it raw.
        const agentFile = agentFileOf(path, home ?? homedir(), pickLoginEnv(req.loginEnv));
        // Another agent's login is judged as the walk judges it: a login a
        // variable moved out of the catalog's places is `no-model` all the
        // same (`agentLoginConfidentiality`).
        // Plan 10 §11.13 (2026-10-17): judged as the guard judges a
        // session's opens, under a launch's HOME as well (`stricterMatch`):
        // on the human plane, the HOME of the launch of `session`, else of
        // the newest live launch (`whyLaunchHome`); a data-socket request
        // names no session's HOME. The answer says which (`launch`).
        const launch = this.confidentiality ? this.whyLaunchHome(ctx.channel, req.session) : null;
        const atLaunch = (): SecretCatalogMatch | null => launch?.home && launch.home !== (home ?? homedir()) ? pathConfidentiality(path, launch.home, this.labelLookup) : null;
        const catalog = this.confidentiality
          ? stricterMatch(pathConfidentiality(path, home, this.labelLookup), atLaunch())
          : { level: "public" as const, bindings: [], rule: null };
        const m = this.confidentiality && agentFile?.kind === "login" ? agentLoginConfidentiality(catalog, agentFile.agent) : catalog;
        const label = this.confidentiality ? this.labelLookup(path) : null;
        const hint = this.testFlowPathLabel(path);
        const shape = secretFileShape(path);
        const result: WhyPathOpResult = {
          path,
          axis: this.confidentiality,
          level: m.level,
          rule: m.rule ?? null,
          bindings: [...(m.bindings ?? [])],
          // Plan 13 §5.2: per-value bindings, and the file's own.
          ...(m.values && m.fileBindings ? { values: m.values.map((v) => ({ key: v.key, bindings: [...v.bindings] })), fileBindings: [...m.fileBindings] } : {}),
          outranked: (hint?.outranked ?? []).map((o) => ({ path: o.pattern, level: o.level })),
          readers: label?.readers ? [...label.readers] : [],
          readersAdmitNothing: (label?.readers ?? []).map((r) => entryAdmitsNothing(r)),
          readersPrint: (label?.readers ?? []).map((r) => (typeof r === "string" ? readerPrints(r) : binaryPrints(r))),
          readersCopyOf: (label?.readers ?? []).map((r) => (typeof r === "string" ? null : renamedCopyOf(r)?.of ?? null)),
          // Plan 13 D8 (12): the entries whose program reads the twin (neither
          // vetted nor vouched for with `prints: nothing`).
          readersReadTwin: (label?.readers ?? []).map((r) => entryReadsTwin(r)),
          others: label?.others ?? null,
          consumers: [...knownConsumers(path)],
          consumersPrint: knownConsumers(path).map((c) => readerPrints(c)),
          wire: consumerWireRelease(path),
          twinShape: shape,
          // 2026-10-09: the twin a registration makes of the file as it is
          // now (its form, shape and number of masked values), not the
          // shape its path suggests.
          // Plan 10 §11.13.3: and the commands an ssh config's twin
          // withholds, by line and keyword only (never their text). Read
          // from the real file, bounded (why-preview.ts: the agent reaches
          // this op on the data socket).
          // The twin is decided as the guard decides it (registry.ts
          // `twinMatchOf`): the catalog's word under the arbiter's HOME, a
          // HOME the human plane named or the caller's `home`, a label
          // under any of them first (2026-10-17: before, the caller's
          // `home` alone, so a config under a launch HOME the arbiter does
          // not share got no twin answer here, its own text to the AI).
          ...(this.confidentiality && m.level !== "public"
            ? (ctx.channel === "data" ? this.whyPreview : this.whyPreviewHuman).facts(path, this.whyTwinMatch(path, m, home, launch), { withheld: shape === "ssh-config" })
            : {}),
          // Held opens and held changes (write-protection.md §2.1), each by
          // the binary's path; the hash stays in the key, not on the screen.
          verdicts: this.listApprovals()
            .filter((e) => (e.symbol.startsWith("open:") || e.symbol.startsWith("trust:") || e.symbol.startsWith("write:")) && e.destination === path)
            .map((e) => {
              const v = binaryVerdictParts(e.symbol);
              // Plan 13 §8 decision (c): the script (or the one run) an
              // interpreter's answer names; an answer naming the interpreter
              // alone applies to nothing any more.
              return {
                kind: v.kind === "write" ? "write" as const : v.kind === "trust" ? "trust" as const : "open" as const, app: v.app, ...(v.exe ? { exe: v.exe } : {}), status: e.status, scope: e.scope ?? "always",
                ...(v.script !== undefined ? { script: v.script } : {}), ...(v.run !== undefined ? { run: true } : {}),
                ...(staleInterpreterVerdict(e.symbol) ? { stale: true } : {}),
                // Plan 13 D8, printers admit nothing (2026-10-03).
                ...(printerOpenVerdict(e.symbol) ? { printer: true } : {}),
                // Plan 13 D8 (12): an old answer about an unvetted program.
                ...(unvettedOpenVerdict(e.symbol) ? { unvetted: true } : {}),
              };
            }),
          // Tour item 17: a change waiting in Approvals that would change
          // this answer, and what it would make it. The rows above are the
          // law in force until the human answers.
          ...(this.confidentiality ? {
            pending: this.whyPending(() => {
              const now = stricterMatch(pathConfidentiality(path, home, this.labelLookup), atLaunch());
              const l = this.labelLookup(path);
              return { level: now.level, bindings: [...(now.bindings ?? [])].sort(), rule: now.rule ?? null, readers: l?.readers ?? null, others: l?.others ?? null };
            }, (a) => ({ level: a.level, bindings: a.bindings, rule: a.rule })),
          } : {}),
          ...(agentFile !== null ? { agentFile } : {}),
          ...(launch !== null ? { launch } : {}),
        };
        return { id: req.id, ok: true, result };
      }
      case "whyHost": {
        // `mandu why <host>`: who may be sent there, and what the gate says.
        const host = typeof req.host === "string" ? req.host.trim().toLowerCase() : "";
        const bound: WhyHostOpResult["bound"] = [];
        for (const l of this.humanLabels().values()) {
          if (destinationMatchesBindings(host, [...l.bindings])) bound.push({ path: l.path, level: l.confidentiality, binding: [...l.bindings], source: "label" });
          // Plan 13 §5.2: a value bound there on its own (`values:`).
          else if ((l.values ?? []).some((v) => destinationMatchesBindings(host, [...v.bindings]))) {
            const hit = (l.values ?? []).filter((v) => destinationMatchesBindings(host, [...v.bindings]));
            bound.push({ path: l.path, level: l.confidentiality, binding: hit.flatMap((v) => v.bindings.map((b) => `${v.key}: ${b}`)), source: "label" });
          }
        }
        for (const e of listSecretRegistry(this.symbolMap)) {
          if (destinationMatchesBindings(host, e.bindings) && !bound.some((b: WhyHostOpResult["bound"][number]) => b.path === e.path)) {
            bound.push({ path: e.path, level: e.level, binding: [...e.bindings], source: "registry" });
          }
        }
        const probe = (bindings: string[] | null): { decision: DesymbolizationDecision; stage: string } | null => {
          if (!this.policy.desymbolizationDecisionWith || host === "") return null;
          const entry: SymbolEntry = {
            value: "<probe>", tool: "Read", field: null, origin: null, session_key: null, call_id: null,
            created_at: Date.now(), obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
            confidentiality: "no-model", bindings, integrity: "trusted",
          };
          const r = this.decideDesym({ symbol: TEST_FLOW_PROBE_SYMBOL, boundary: "network", destination: host }, { kind: "probe", entry });
          return { decision: r.decision, stage: r.stage };
        };
        const result: WhyHostOpResult = {
          host,
          axis: this.confidentiality,
          bound,
          release: { bound: probe([host]), unbound: probe(null) },
          destinations: getCurrentPolicy().destinations
            .filter((d) => destinationMatchesBindings(host, [d.host]) || d.host === "*")
            .map((d) => ({ host: d.host, port: d.port, proto: d.proto, connect: d.connect, ...(d.reason !== undefined ? { reason: d.reason } : {}) })),
          verdicts: this.egressApprovals.list()
            .filter((e) => !e.symbol.startsWith("open:") && !e.symbol.startsWith("write:") && destinationMatchesBindings(host, [e.destination]))
            .map((e) => ({ symbol: e.symbol, status: e.status, scope: e.scope ?? "always" })),
          // confidentiality.md §2.3: an issuer's API host says which key
          // formats go to it without asking, and whether that is on.
          ...((): { issuer?: WhyHostOpResult["issuer"] } => {
            const iss = issuerOfHost(host);
            if (iss === null) return {};
            const law = getCurrentPolicy().issuerBindings;
            return { issuer: { id: iss.id, name: iss.name, shapes: [...iss.shapes], on: law.enabled && !law.issuersOff.includes(iss.id) } };
          })(),
          // Tour item 17: a change waiting in Approvals that would change
          // which secrets may go here, the gate's answer, or the host's rows.
          ...(host !== "" ? {
            pending: this.whyPending(() => ({
              bound: [...this.humanLabels().values()].filter((l) => destinationMatchesBindings(host, [...l.bindings])).map((l) => `${l.path}\0${l.confidentiality}`).sort(),
              release: [probe([host]), probe(null)].map((r) => (r ? `${r.decision.allow}/${"requiresApproval" in r.decision && r.decision.requiresApproval === true}` : null)),
              destinations: getCurrentPolicy().destinations
                .filter((d) => destinationMatchesBindings(host, [d.host]) || d.host === "*")
                .map((d) => `${d.host}:${d.port}/${d.proto}/${d.connect}`).sort(),
            })),
          } : {}),
        };
        return { id: req.id, ok: true, result };
      }
      case "whySymbol": {
        // `mandu why <symbol>` (plan 15 §13.8; human plane): read-only, and
        // never a value (prompt-filter/why-symbol.ts copies the events'
        // `promptFilter` fields one by one, never their panes).
        const symbol = typeof req.symbol === "string" ? req.symbol.trim() : "";
        if (!WHY_SYMBOL_RE.test(symbol)) return { id: req.id, ok: false, error: "whySymbol: symbol must be a complete $MDU: name ($MDU:<tag>[<hex>])" };
        const entry = getSymbolEntry(this.symbolMap, symbol);
        const hint = typeof req.session === "string" && req.session !== "" && req.session.length <= 256 ? req.session : undefined;
        const sessions = whySymbolSessions(entry, hint, this.events.sessions(), new Set([ADMIN_SESSION_ID]));
        const store = this.events;
        const events = function* (): Generator<StoredEvent> {
          for (const sid of sessions) {
            let rows: StoredEvent[] = [];
            try { rows = store.since(sid, 0); } catch { /* an unsafe or vanished id: skip */ }
            yield* rows;
          }
        };
        const packs = this.loadedPromptPacks();
        const described = new Map(packs.loaded.packs.map((p) => [p.doc.pack, p.doc.description]));
        const result = whySymbol({
          symbol, axis: this.confidentiality, entry, events: events(),
          rows: this.egressApprovals.list(), config: this.promptPolicyInput().config, searched: sessions.length,
          filters: this.promptFilterViewsWithPlugins(packs.loaded).map((f) => {
            const description = described.get(f.id);
            return { id: f.id, kind: f.kind, ...(description !== undefined ? { description } : {}) };
          }),
        });
        return { id: req.id, ok: true, result };
      }
      case "testFlow": {
        // Test a flow (§4 / §5 "Tester ≡ gates"): a READ — nothing symbolized,
        // queued or counted; same composition as the live gate.
        if (req.withEdits !== undefined) {
          const ev = evaluateEdits({ specId: getCurrentPolicy().specId, document: this.policyDocs.document }, req.withEdits);
          if (!ev.ok) return { id: req.id, ok: false, error: `withEdits: ${ev.problems.join("; ")}` };
          return { id: req.id, ok: true, result: this.withHypotheticalLaw(ev.document, () => this.testFlow(req)) };
        }
        return { id: req.id, ok: true, result: this.testFlow(req) };
      }
      case "modelEndpoints": {
        // The declared model endpoints (plan 11 D5), from the law IN FORCE so
        // a hot-reloaded file reaches the next inspect call. Read-only data.
        const law = getCurrentPolicy();
        const endpoints = law.models.map((m) => ({ ...m }));
        // Plan 12 D5: doctor names the administrator's files and the lock.
        const view = this.adminView().admin;
        const admin = law.admin || view
          ? { admin: { files: [...(law.admin?.files ?? [])], locked: law.admin?.locked ?? false, conflicts: view?.conflicts ?? [], refused: view?.refused ?? [] } }
          : {};
        return { id: req.id, ok: true, result: { endpoints, ...admin } };
      }
      case "setSessionUpstream": {
        // Plan 11 phase 3: the launcher records which declared model the
        // session's main conversation goes to (null = the default vendor).
        // Bind-once, refused after traffic, persisted: see
        // policy/session-upstreams.ts for why each rule is needed.
        if (typeof req.sessionKey !== "string" || req.sessionKey === "") {
          return { id: req.id, ok: false, error: "setSessionUpstream: sessionKey required" };
        }
        if (req.endpoint !== null && (typeof req.endpoint !== "string" || req.endpoint === "")) {
          return { id: req.id, ok: false, error: "setSessionUpstream: endpoint must be a models: entry name or null" };
        }
        const hasTraffic =
          this.classifiedSessions.has(req.sessionKey) || this.sessionLabels.get(req.sessionKey).updatedAt > 0;
        const r = this.sessionUpstreams.bind(
          req.sessionKey, req.endpoint, typeof req.requestedBy === "string" ? req.requestedBy : "", hasTraffic,
        );
        if (!r.ok) {
          this.log(`${r.error} [${req.sessionKey}]`);
          return { id: req.id, ok: false, error: r.error };
        }
        // exec-routing.md §8.5.3: only the launcher's FRESH bind can make
        // the session's clean reporter claimable (a re-bind is a no-op here).
        if (r.changed && req.cleanReporter === true) this.cleanReporters.allow(req.sessionKey);
        const result = this.sessionUpstreamOf(req.sessionKey);
        if (r.changed) {
          this.log(
            `setSessionUpstream: ${req.sessionKey} → ${req.endpoint ?? "(default vendor)"} (${result.location})` +
              (req.requestedBy ? ` requestedBy=${req.requestedBy}` : ""),
          );
        }
        return { id: req.id, ok: true, result };
      }
      case "sessionUpstream": {
        if (typeof req.sessionKey !== "string" || req.sessionKey === "") {
          return { id: req.id, ok: false, error: "sessionUpstream: sessionKey required" };
        }
        return { id: req.id, ok: true, result: this.sessionUpstreamOf(req.sessionKey) };
      }
      case "netConnectAllow": {
        // The law's reachability allowances for the launcher's connect-guard
        // (§2.3, 4b) — computed from the law IN FORCE, so a hot-reloaded file
        // reaches the next launch without an arbiter restart.
        return { id: req.id, ok: true, result: { specs: connectAllowSpecs(getCurrentPolicy()) } };
      }
      case "policySnapshot": {
        // Observability: the active trust rules (per-tool-call policy modal)
        // PLUS the server-composed standing state for the Policy panel
        // (policy-surface.md §9.4) — posture, the usage-gate rule catalog,
        // and the approval queue at every status. Decides nothing.
        const result: PolicySnapshotOpResult = {
          ...this.policy.policySnapshot(),
          posture: { integrity: this.integrity, confidentiality: this.confidentiality },
          usage: {
            rules: listUsageRules(),
            sensitivePaths: [...SENSITIVE_PATHS],
            gates: listUsageGates(),
          },
          verdicts: this.withProvenance(this.listApprovals()),
          egressPosture: this.sessionPosture.globalPosture(),
          lawSource: this.lawSource,
          policyFile: this.policyDocs.status,
          // The operator's law (policy-surface.md §2.1, stage 4).
          document: (() => {
            const c = getCurrentPolicy();
            return {
              lists: Object.fromEntries(Object.entries(c.lists).map(([k, v]) => [k, [...v]])),
              // Plan 13 D8 (13), P0 item 14: each path's readers, with this
              // arbiter's judgment of each entry (by name, a pin's hash, a
              // script pin), so the rule list need not judge them by the
              // names it mirrors: `whyPath`'s per-entry fields.
              paths: [...c.pathLabels.values()].map((l) => ({
                path: l.path, level: l.confidentiality, bindings: [...l.bindings], recursive: l.recursive,
                ...(l.glob ? { glob: true } : {}),
                // Plan 13 §5.2: per-value bindings, in document order.
                ...(l.values?.length ? { values: l.values.map((v) => ({ key: v.key, bindings: [...v.bindings] })), wholeBindings: wholeFileBindings(l.bindings, l.values) } : {}),
                ...(l.readers ? {
                  readers: l.readers.map((r) => (typeof r === "string" ? r : { ...r })),
                  readersAdmitNothing: l.readers.map((r) => entryAdmitsNothing(r)),
                  readersReadTwin: l.readers.map((r) => entryReadsTwin(r)),
                  readersCopyOf: l.readers.map((r) => (typeof r === "string" ? null : renamedCopyOf(r)?.of ?? null)),
                  others: l.others ?? "deny",
                } : {}),
              })),
              rules: Object.fromEntries(Object.entries(c.dispositions).map(([k, mode]) => [k, { mode }])),
              userRules: c.userRules.map((r) => ({
                id: r.id, kind: r.kind, from: r.from ? [...r.from] : null, to: [...r.to], mode: r.mode,
                ...(r.reason !== undefined ? { reason: r.reason } : {}),
                ...(r.by !== undefined ? { by: r.by } : {}),
                ...(r.added !== undefined ? { added: r.added } : {}),
                expires: r.expiresAt === null ? null : new Date(r.expiresAt).toISOString(),
              })),
              destinations: c.destinations.map((d) => ({
                host: d.host, port: d.port, proto: d.proto, connect: d.connect,
                ...(d.reason !== undefined ? { reason: d.reason } : {}),
              })),
              // Plan 11 D6: the declared model endpoints, read-only.
              models: c.models.map((m) => ({ ...m })),
              // Each entry's version (policy-surface.md §8.4.6 "An
              // item-level version"): Settings › Models' update names the
              // entry it read, and is refused once it changed.
              modelVersions: Object.fromEntries(c.models.map((m) => [m.name, this.policyDocs.itemVersion("models", m.name)])),
              // The same for each file rule, by its path as listed above:
              // the Rules page's label buttons name the rule they read.
              pathVersions: Object.fromEntries([...c.pathLabels.values()].map((l) => [l.path, this.policyDocs.itemVersion("paths", pathIdentity(l.path))])),
              // Plan 12 D4: the perimeter in force, and who set it.
              ...(c.perimeter ? { perimeter: this.perimeterView(c.perimeter) } : {}),
              // Plan 12 D5: the administrator's layer (Settings shows the lock,
              // the user's entries it keeps out of force, the ones the user
              // removed so they can be brought back, and a refused re-read).
              ...(c.admin || this.adminRefused.length > 0 ? { modelsAdmin: this.modelsAdminView() } : {}),
            };
          })(),
          relaxations: [
            ...relaxationsOf(getCurrentPolicy()),
            ...this.consumerPacks.flatMap((p) => p.consumers.map((c) => ({
              kind: "pack-consumer" as const,
              subject: c.basename ?? c.pathSuffix ?? "",
              detail: `${c.apps.join(", ")} may read ${c.basename ?? c.pathSuffix} raw by default (consumer pack ${p.name} ${p.version}, key ${p.keyId})`,
            }))),
          ],
          hits: this.ruleHits.all(),
        };
        return { id: req.id, ok: true, result };
      }
      case "toolSurface": {
        // Session-health: which advertised tools have no inbound spec (their
        // outputs fail closed). Read-only, utility surface. A name the
        // session's gate surface handles itself is not "unknown": a
        // dispatcher (OpenClaw's tool_call, unmapped on purpose, gated as
        // its inner tool) or a tool refused on every call (tool-gate-surface.ts).
        // Nor is a tool the gate surface reads (Goose's `analyze` and
        // `read_image`: left out of the spec on purpose so their input is
        // scanned, mapped by the surface for the §11.18 rule), nor one masked
        // whole by decision (mapped-tools.ts MASKED_BY_DECISION). What stays
        // is the drift: a tool whose result is masked whole (or UNTRUSTED by
        // omission) because nobody looked at it.
        const names = Array.isArray(req.names) ? req.names.filter((n): n is string => typeof n === "string") : [];
        const gs = gateSurfaceFor(req.sessionKey, this.sessionSpecs);
        const specId = resolveInboundSpecId(req.sessionKey, this.sessionSpecs);
        const handled = (n: string): boolean => surfaceNamesTool(gs, n) || maskedByDecision(n, specId);
        return { id: req.id, ok: true, result: { unknown: unknownToolNames(names, req.sessionKey, this.sessionSpecs).filter((n) => !handled(n)) } };
      }
      case "gateSurface": {
        // The per-agent gate surface (tool-gate-surface.ts): read-only, keyed by
        // the same spec resolution classification uses.
        const sessionKey = typeof req.sessionKey === "string" && req.sessionKey !== "" ? req.sessionKey : undefined;
        return { id: req.id, ok: true, result: gateSurfaceFor(sessionKey, this.sessionSpecs) };
      }
      case "handlingPrompt": {
        // Build the T-LLM symbol system prompt from the active SymbolFormat.
        // The proxy injects this so the privileged model knows the symbol
        // contract. `mode` defaults to "full" inside buildSymbolSystemPrompt;
        // absent `capabilities` (or absent fields) default to present, so an
        // older proxy gets the full prompt.
        const prompt = buildSymbolSystemPrompt(getActiveFormat(), {
          mode: req.mode,
          capabilities: req.capabilities,
          // The secret-symbol section rides the server's own switch — the
          // proxies need no change and OFF keeps the prompt byte-identical.
          confidentiality: this.confidentiality,
          // Integrity OFF drops the trust-machinery sections (Data Trust
          // Policy, exec trust contract) while the symbol contract stays for
          // the confidentiality axis; both OFF ⇒ empty prompt (nothing ever
          // symbolizes).
          integrity: this.integrity,
          // Plan 11 phase 3: whether this session's main model is the user's
          // own, from the launcher's binding and the law in force. Without a
          // session key the text stays the strict one.
          tllmLocation: this.tllmLocationOf(typeof req.sessionKey === "string" ? req.sessionKey : undefined),
        });
        return { id: req.id, ok: true, result: { prompt } };
      }
      case "recordToolCall": {
        // Record the tool_use decision in-memory so later OS interceptors can
        // correlate a syscall to a known tool decision. Non-persistent for now.
        // arbiter-human-plane.md §10.2: believed only from the model proxy on
        // the human socket. A claim never replaces a believed record.
        const claimed = !this.attested(ctx.channel);
        const prior = this.toolCalls.get(req.toolUseId);
        if (claimed && prior !== undefined && !prior.claimed) {
          return { id: req.id, ok: true, result: { ok: true } };
        }
        const record: ToolCallRecord = {
          toolUseId: req.toolUseId,
          name: req.name,
          input: req.input,
          sessionKey: req.sessionKey,
          recordedAt: Date.now(),
          ...(claimed ? { claimed: true as const } : {}),
        };
        this.toolCalls.set(req.toolUseId, record);
        if (!claimed) this.noteOwnWrite(record);
        this.log(
          `recordToolCall: ${req.toolUseId} → ${req.name}` +
          (req.sessionKey ? ` [session ${req.sessionKey}]` : ""),
        );
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "emit": {
        // Observability event stream: persist one opaque event with an assigned
        // per-session monotonic seq, then fan it out to live subscribers.
        // FIRE-AND-FORGET: a failure here is reported as an error response, but
        // emit is never on the security path — callers treat it as best-effort.
        //
        // The coalescer (defense-in-depth) maps one incoming event to the events
        // actually persisted: usually the event itself, but a runaway burst of
        // identical events collapses to 0 (suppressed) or a single `coalesced`
        // summary — so no emitter can balloon the log (the 35,723-event incident).
        // TENANCY (policy-surface.md §2.7): an explicitly tenanted
        // arbiter never persists the other tenant's events — a test harness
        // pointed at the live store is refused here, loudly, once per session —
        // and stamps its own tenant onto unstamped ones so every session it
        // holds is attributable without id-prefix guessing.
        // arbiter-human-plane.md §10.2: an event is believed only from a
        // channel the agent's programs cannot reach (the human socket while
        // no unwalled launch is live, or the admin channel). Anything else is
        // stored as a CLAIM (`claimed: true`, under the hash chain), which
        // the dashboard and the SIEM show as such and no decision reads; a
        // caller's own `claimed` is never taken. The arbiter's audit stream
        // takes no claim at all.
        const believed = this.attested(ctx.channel);
        const evRec = req.event as { claimed?: unknown; sessionId?: unknown };
        if (believed) delete evRec.claimed;
        else {
          if (evRec.sessionId === ADMIN_SESSION_ID) {
            return { id: req.id, ok: false, error: `emit: the '${ADMIN_SESSION_ID}' stream takes events only from the arbiter, the dashboard's admin channel or the human socket` };
          }
          evRec.claimed = true;
        }
        const stamped = (req.event as { tenant?: unknown }).tenant;
        if (this.tenant !== undefined) {
          if (stamped !== undefined && stamped !== this.tenant) {
            const sid = String((req.event as { sessionId?: unknown }).sessionId ?? "?");
            if (!this.tenantRefusalsLogged.has(sid)) {
              this.tenantRefusalsLogged.add(sid);
              this.log(`refused emit for session ${sid}: event tenant '${String(stamped)}' ≠ this arbiter's '${this.tenant}'`);
            }
            return {
              id: req.id,
              ok: false,
              error: tenantMismatchError(this.tenant, stamped),
            };
          }
          if (stamped === undefined) (req.event as { tenant?: Tenant }).tenant = this.tenant;
        }
        const toStore = this.coalescer ? this.coalescer.consider(req.event) : [req.event];
        let lastSeq = -1; // -1 ⇒ this emit was suppressed (caller ignores the seq)
        for (const ev of toStore) {
          const stored = this.events.append(ev);
          this.fanOut(stored);
          lastSeq = stored.seq;
        }
        return { id: req.id, ok: true, result: { seq: lastSeq } };
      }
      case "verifyEvents": {
        // The session log's hash chain (comparisons.md §3.9): intact, or
        // the first seq that does not link. Read-only.
        try {
          return { id: req.id, ok: true, result: this.events.verifyChain(req.sessionId) };
        } catch (err) {
          return { id: req.id, ok: false, error: (err as Error).message };
        }
      }
      case "events": {
        // Persisted events for a session with seq > sinceSeq (default 0), in
        // seq order. Tolerates partial/concurrent writes (torn tail line).
        const events = this.events.since(req.sessionId, req.sinceSeq ?? 0);
        return { id: req.id, ok: true, result: { events } };
      }
      case "sessions": {
        const sessions = this.events.sessions();
        return { id: req.id, ok: true, result: { sessions } };
      }
      case "deleteSession": {
        // OBSERVABILITY-ONLY removal of ONE session (the dashboard's sidebar
        // delete — ANY session, live or test; 2026-07-11: the original
        // test-only rule was dropped at the user's request): the NDJSON event
        // log, the store's in-memory seq state, any live subscriptions, and
        // the coalescer's run state — and NOTHING on the security path
        // (symbol table / policy / approvals). What protects live traces is
        // the dashboard's mutating-route gating (IP allowlist → auth → CSRF)
        // + the client confirm; the store's isSafeSessionId guard still
        // rejects traversal-shaped ids.
        if (typeof req.sessionId !== "string") {
          return { id: req.id, ok: false, error: "deleteSession requires a string sessionId" };
        }
        // removeSession also ends live subscribe streams on the id and drops
        // the coalescer's run state (shared with the retention sweep).
        if (!this.removeSession(req.sessionId)) {
          return { id: req.id, ok: false, error: `unknown session: ${req.sessionId}` };
        }
        this.log(`deleteSession: removed session ${req.sessionId}`);
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "subscribe": {
        // `subscribe` is a STREAMING op handled at the connection layer
        // (onConnection → startSubscription) before reaching dispatch. If it
        // arrives here it was sent over a shared one-req-one-res connection,
        // which is unsupported — it must use a dedicated connection.
        return {
          id: req.id,
          ok: false,
          error: "subscribe must be sent on a dedicated connection (it monopolizes the stream)",
        };
      }
      case "ping": {
        return { id: req.id, ok: true, result: { pong: true, protocolVersion: PROTOCOL_VERSION } };
      }
      case "hello": {
        // Identity handshake (runtime-instances.md): tells clients WHO answers
        // this socket — pid + code rev + start time — so a supervisor can adopt
        // knowingly (and flag staleness) instead of trusting the path.
        return {
          id: req.id, ok: true,
          result: {
            pid: process.pid,
            startedAt: this.startedAt,
            instanceId: this.identity.instanceId,
            gitRev: this.identity.gitRev,
            gitDirty: this.identity.gitDirty,
            // The release (runtime-instances.md §4.1): the launcher refuses or
            // restarts an arbiter of another release before it uses it.
            ...(this.identity.version === null ? {} : { version: this.identity.version ?? releaseVersion() }),
            // Which build of that release (build-identity.ts): two commits of
            // one version differ here, so the launcher can tell them apart.
            ...(this.identity.build === null ? {} : { build: this.identity.build ?? arbiterBuild(this.identity.gitRev) }),
            sockPath: this.socketPath,
            // The human-plane socket (arbiter-human-plane.md), for DISCOVERY by
            // the launcher / supervisor that wire the human-facing consumers.
            // A client must never fall back to the data socket when it is
            // absent or unreachable. null = no human channel on this instance.
            humanSock: this.humanServer ? (this.humanSocketPath ?? null) : null,
            // The channel this answer came on (plan 13 D9): the guard checks
            // it dialled a socket whose reports are believed (`human`).
            channel: ctx.channel,
            eventDir: this.events.directory,
            symbolDb: this.dbPath ?? getSymbolDbPath(),
            protocolVersion: PROTOCOL_VERSION,
            // The axis POSTURE this instance runs (the e2e posture guard's
            // probe): which folds of the int×conf matrix are live here.
            integrity: this.integrity,
            confidentiality: this.confidentiality,
            // Tenant identity (§2.7): a launcher/harness compares this with its
            // own before sending a single event. null = untenanted (legacy).
            tenant: this.tenant ?? null,
          },
        };
      }
      case "taintProcess": {
        this.provenance.taintProcess(req.procKey, req.originHost, req.session);
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "processLineage": {
        // Plan 13 D9: from the data socket an edge is a claim (it widens a
        // walk, never takes the guard's first-edge slot).
        this.provenance.recordLineage(req.childKey, req.parentKey, req.session, { claimed: !this.attested(ctx.channel) });
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "recordProcessFlow": {
        // Plan 13 §9 R1: a process that received a holder's bytes through a
        // descriptor holds what it holds (every taint walk follows the flow,
        // the model exit's fold included). Only adds taint, so the data
        // socket may report one too, kept as a claim (D9).
        if (typeof req.procKey !== "string" || req.procKey === "" || !Array.isArray(req.flowsFrom)) {
          return { id: req.id, ok: false, error: "recordProcessFlow: procKey and flowsFrom are required" };
        }
        const flows = req.flowsFrom.filter((f): f is string => typeof f === "string" && f !== "").slice(0, 256);
        this.provenance.recordProcessFlow(req.procKey, flows, req.session, { claimed: !this.attested(ctx.channel) });
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "recordAgentFlow": {
        // Plan 13 §4.5.1 (decision 2026-10-02: mask, do not refuse): the
        // agent process itself holds a channel a holder writes into. An open
        // only adds masking, so the data socket's is kept as a claim (D9); a
        // close narrows later windows, so it is believed on the human socket
        // only.
        if (typeof req.channel !== "string" || req.channel === "") {
          return { id: req.id, ok: false, error: "recordAgentFlow: channel is required" };
        }
        if (req.closed === true) {
          if (!this.attested(ctx.channel)) return { id: req.id, ok: true, result: { recorded: false, reason: this.unattested("recordAgentFlow", ctx.channel) } };
          return { id: req.id, ok: true, result: { recorded: this.provenance.closeAgentFlow(req.channel) > 0 } };
        }
        if (!Array.isArray(req.flowsFrom) || req.flowsFrom.length === 0) {
          return { id: req.id, ok: false, error: "recordAgentFlow: flowsFrom is required for an open" };
        }
        const from = req.flowsFrom.filter((f): f is string => typeof f === "string" && f !== "").slice(0, 256);
        this.provenance.recordAgentFlow(req.channel, from, req.session, { claimed: !this.attested(ctx.channel) });
        return { id: req.id, ok: true, result: { recorded: true } };
      }
      case "agentReceiptTaint": {
        // Plan 13 §4.5.1: per tool result, the level the agent's own
        // connections to a holder mask it at. Only a tool whose result the
        // agent itself produces is answered (agent-receipt.ts); the human
        // socket's first ask ends each call's window, the data socket reads.
        if (!Array.isArray(req.calls)) return { id: req.id, ok: false, error: "agentReceiptTaint: calls is required" };
        const session = typeof req.session === "string" && req.session !== "" ? req.session : undefined;
        const surface = gateSurfaceFor(session, this.sessionSpecs);
        const readOnly = !this.attested(ctx.channel);
        const asks: Array<{ callId: string; covered: boolean; opts: AgentReceiptOpts }> = [];
        for (const c of req.calls.slice(0, 1024)) {
          if (!c || typeof c.callId !== "string" || c.callId === "" || typeof c.tool !== "string") continue;
          // Every call's first ask is recorded (a side call's window reads
          // which calls are still out), whatever its tool. A file tool
          // (2026-10-02) counts only a flow on a file-like channel: a named
          // pipe a holder writes that the agent read itself.
          const receipt = this.confidentiality && isAgentReceiptTool(c.tool, surface);
          const fileTool = this.confidentiality && !receipt && isAgentFileTool(c.tool, surface);
          const covered = receipt || fileTool;
          asks.push({ callId: c.callId, covered, opts: { ...(session ? { session } : {}), readOnly, recordOnly: !covered, ...(fileTool ? { channels: "file" as const } : {}) } });
        }
        // Every call of the request in ONE commit (agentReceiptTaints): a
        // commit per call was a WAL sync per call, and on a slow disk a
        // request carrying 82 results outran the proxy's 5 s deadline (its
        // fail-closed 502; CI pipelines 10995, 11016).
        const answers = this.provenance.agentReceiptTaints(asks);
        const out: AgentReceiptTaintResultWire["calls"] = [];
        for (const [i, { callId, covered }] of asks.entries()) {
          const t = answers[i]!;
          if (!covered || t.level === null) {
            out.push({ callId, level: null, files: [], apps: [] });
            continue;
          }
          out.push({
            callId, level: t.level,
            files: [...new Set(t.rows.map((r) => r.path))], apps: [...new Set(t.rows.map((r) => r.app))],
            ...(t.relayKnown ? {} : { unattributed: true }),
          });
        }
        return { id: req.id, ok: true, result: { calls: out } satisfies AgentReceiptTaintResultWire };
      }
      case "isProcessTainted": {
        const result = this.provenance.isProcessTainted(req.procKey);
        return { id: req.id, ok: true, result };
      }
      case "taintProcessSecret": {
        // Plan 10 §3.1: recorded BEFORE the interposer injects the descriptor,
        // so a process is never raw-reading while unrecorded.
        // Plan 13 D9: from the data socket a claimed row (it taints, folds as
        // `secret`, and is never a secret the process holds raw).
        this.provenance.taintProcessSecret({ procKey: req.procKey, path: req.path, level: req.level, app: req.app, session: req.session, ...(this.attested(ctx.channel) ? {} : { claimed: true }) });
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "processSecretTaint": {
        return { id: req.id, ok: true, result: this.provenance.processSecretTaint(req.procKey) };
      }
      case "recordCallRoot": {
        this.provenance.recordCallRoot(req.callId, req.procKey, req.session);
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "decideSecretOpen": {
        // Plan 10 §4.1. The file's reader list comes from the HUMAN label
        // (policy.yaml `paths[].readers`, or an Inbox verdict, §11.1); absent
        // ⇒ the structured twin for everyone (a known consumer excepted,
        // §11.3). Axis OFF ⇒ twin too: no raw byte is handed out on a wire
        // that carries no confidentiality.
        // Plan 10 §11.13 (2026-10-17): the catalog's `~` places are the
        // LAUNCH's HOME as its launcher recorded it on an attested
        // `beginLaunch` (`sessionHome`), as well as this arbiter's own; the
        // stricter match decides, so a launch HOME adds places and never
        // takes one away. Before, only the arbiter's HOME counted: under
        // `HOME=/tmp/x mandu …` a key in /tmp/x/.ssh was "not a secret" here
        // and every program, ssh included, got its twin (fail-safe, but ssh
        // could not log in). A data-socket request names no HOME: the
        // session's is the human plane's word.
        const launchHome = this.confidentiality ? this.sessionHome(req.session) : null;
        const level = this.confidentiality ? stricterMatch(
          pathConfidentiality(req.path, undefined, this.labelLookup),
          launchHome !== null ? pathConfidentiality(req.path, launchHome, this.labelLookup) : null,
        ) : null;
        if (!level || !isSecret(level.level)) {
          return { id: req.id, ok: true, result: { verdict: "twin", app: "", level: level?.level ?? "public", reason: "not a registered secret on this arbiter, or the axis is off", pinNeeded: false } };
        }
        const app = basenameOf(req.exe);
        // Plan 13 D9: only the guard, on the human socket, reports an open.
        // From the data socket the chain is a claim and the answer the twin:
        // no identity fact is read, no verdict consulted or spent, no reader
        // pinned, no row written. (An older guard that still reports here
        // serves every open its twin: fail-closed.)
        if (typeof req.orphanRoot === "string" && req.orphanRoot !== "") this.provenance.recordOrphanRoot(req.orphanRoot, req.session, { claimed: !this.attested(ctx.channel) });
        if (!this.attested(ctx.channel)) {
          this.provenance.recordLineageChain(req.procKey, lineageChain(req.parentKey, req.ancestorKeys), req.session, { claimed: true });
          this.log(`decideSecretOpen: ${req.path} by ${req.exe} (${req.procKey}) → twin (unauthenticated: data socket)`);
          return { id: req.id, ok: true, result: { verdict: "twin", app, level: level.level, reason: this.unattested("decideSecretOpen", ctx.channel), pinNeeded: false } };
        }
        // Plan 13 D7: the opener's whole live chain (`ancestorKeys`), so a
        // reader under a subshell that never exec'd is in its call's tree;
        // an older guard's single `parentKey` edge otherwise.
        this.provenance.recordLineageChain(req.procKey, lineageChain(req.parentKey, req.ancestorKeys), req.session);
        // Plan 13 D3: the row names the binary and how it was let in, so the
        // fold finds the output rule of this (file, binary) pair.
        // Plan 13 R5: the script an interpreter runs, as the guard read it.
        // The row records it only when a `script:` entry could match on it,
        // so the fold's script entries speak only for such a row.
        const script = parseScriptFacts(req.script);
        const scriptRow = script && scriptFactsProblem({ app, script: script.path }, { exe: req.exe, script }) === null
          ? { script: script.path, scriptSha256: script.sha256! } : null;
        const grantRaw = (why: string, pinNeeded: boolean, via: "reader" | "verdict", from?: string, scriptPin?: { app: string; script: string }, vouched = false): DecideSecretOpenResultWire => {
          this.provenance.taintProcessSecret({ procKey: req.procKey, path: req.path, level: level.level, app, session: req.session, exe: req.exe, ...(req.sha256 ? { sha256: req.sha256 } : {}), via, ...(scriptRow ?? {}) });
          // Plan 10 §11.15, case 2: a labelled file read raw is a known
          // secret from now on, registered if the launch did not (labelled
          // later, outside the roots). Attested reports only: this branch
          // is past the data-socket refusal above.
          this.registerReadFile(req.path);
          if (pinNeeded) {
            // An (interpreter, script) pin keeps the entry's own app name, so
            // it replaces that entry (python3, not python3.12).
            const vouch = vouched ? { prints: "nothing" as const } : {};
            const pin = scriptPin && scriptRow
              ? { app: scriptPin.app, path: req.exe, ...(req.sha256 ? { sha256: req.sha256 } : {}), ...(from ? { from } : {}), script: scriptPin.script, scriptSha256: scriptRow.scriptSha256, ...vouch }
              : { app, path: req.exe, ...(req.sha256 ? { sha256: req.sha256 } : {}), ...(from ? { from } : {}), ...vouch };
            this.pinReader(req.path, pin, level.level, req.exeSystem === true);
          }
          this.log(`decideSecretOpen: ${req.path} by ${req.exe} (${req.procKey}) → raw (${why})${pinNeeded ? " [pinned]" : ""}`);
          return { verdict: "raw", app, level: level.level, reason: why, pinNeeded };
        };
        // 1. A prior human verdict for (this executable, this file) short-
        //    circuits (the fs-gate's precedent): approved ⇒ raw and pinned;
        //    denied ⇒ deny. Keyed by the resolved path and hash, never the
        //    basename (Plan 13 D8): approving /usr/bin/psql admits no other
        //    binary named psql, nor a rebuilt one.
        // Plan 13 D8: the guard's facts about who the opener is. Each one
        // absent (an older guard, a test) counts against the opener.
        const trusted = Array.isArray(req.ancestorTrusted) ? req.ancestorTrusted : [];
        const opener = {
          exe: req.exe,
          ...(req.sha256 ? { sha256: req.sha256 } : {}),
          isAgent: req.isAgent,
          integrityTainted: this.integrity ? this.provenance.isProcessTainted(req.procKey).tainted : false,
          ...(Array.isArray(req.ancestorExes) ? { ancestors: req.ancestorExes.filter((e): e is string => typeof e === "string").map((exe, i) => ({ exe, trusted: trusted[i] === true })) } : {}),
          exeSystem: req.exeSystem === true,
          ...(Array.isArray(req.openerEnv) ? { loaderEnv: req.openerEnv.filter((n): n is string => typeof n === "string") } : {}),
          ...(script ? { script } : {}),
          ...(typeof req.scriptProblem === "string" ? { scriptProblem: req.scriptProblem } : {}),
        };
        // Plan 13 §8 decision (c): an interpreter's verdict names the script
        // it runs too (`open:<exe>#<sha256>#script:<path>#<sha256>`), so
        // allowing python3 running a.py allows neither b.py nor `python3 -c`;
        // a verdict naming the interpreter alone (before the decision)
        // matches nothing. An interpreter running no pinnable script has no
        // key: it is never asked about (decision (b), `decideOpen`).
        // A renamed copy of a printer or of a program that runs code is that
        // program (its hash: the !437 leftover (2), and decision (b) by
        // content); the host's are re-hashed now and then, before the key.
        refreshProgramHashes({ minIntervalMs: 600_000 });
        const program = verdictProgramOf(opener);
        // Plan 13 D8 (12), the allow-list (2026-10-04): a program that is not
        // vetted is asked the warning question, under its own kind
        // (`trust:`), so an answer given to the old question (`open:`),
        // which never said the program may print the file, does not count.
        const unvettedOpener = !binaryVetted(opener);
        // A question names the program's FILE (2026-10-02): an opener whose
        // path could not be read (no absolute path) is named by no answer, as
        // `decideProtectedWrite` refuses such a writer; its key would be the
        // name-only form `nameOnlyVerdict` retires (dashboard.md §4.34
        // "Answers that no longer apply").
        const key = program === null || !String(req.exe ?? "").startsWith("/") ? null : unvettedOpener ? trustVerdictSubject(req.exe, req.sha256, program) : openVerdictSubject(req.exe, req.sha256, program);
        // A prior answer is about the program the human saw; an opener run
        // with a loader or interpreter variable the launch did not give is
        // not that program, and must not spend a `once` (the law below
        // answers it: the twin or a denial, never raw).
        // Plan 13 §8 decision (b): nor is a program running code it is
        // given with no script R5 pins (inline code, stdin, an agent-writable
        // script): no answer, old or new, makes it a reader (`decideOpen`
        // refuses it below, unprompted).
        // Plan 13 D8, printers admit nothing (2026-10-03): nor is a program
        // that prints or copies the file. An *Always* (or a *once*) given
        // for it before the decision admits nothing and is not spent; a
        // denial is moot (`decideOpen` gives it what a non-reader gets).
        // A copy of a printer under another name is one (its hash, the !437
        // leftover (2)), as a copy of an interpreter is one
        // (`inlineCodeProblem`).
        const printer = openerPrints(opener);
        const prior = key !== null && !printer && loaderEnvProblem(opener) === null && inlineCodeProblem(opener) === null ? this.consultPriorVerdict(key, req.path, true) : undefined;
        if (prior?.status === "approved") {
          // Plan 13 D3: a verdict's open is a reader's (its entry's output
          // rule applies) only once the law names this exact binary by a pin
          // (path and hash); until then the Inbox's promise holds: masked.
          const listed = this.labelLookup(req.path)?.readers;
          const pinMatch = listed ? matchReader(listed, opener) : null;
          // An interpreter is pinned with the script it runs (decision b): a
          // pin of the interpreter alone would admit nothing.
          const scriptPin = script && readerRunsCode(app) ? { app, script: script.path } : undefined;
          // D8 (12): an *Always allow* on the warning question is the human's
          // word, written into the law as `prints: nothing`.
          return { id: req.id, ok: true, result: grantRaw(`human-approved (${prior.scope})`, prior.scope === "always", pinMatch !== null && !pinMatch.pinNeeded ? "reader" : "verdict", undefined, scriptPin, unvettedOpener && prior.scope === "always") };
        }
        if (prior?.status === "denied") {
          this.provenance.recordSecretOpenDenial({ procKey: req.procKey, path: req.path, app, reason: "human-denied", session: req.session });
          return { id: req.id, ok: true, result: { verdict: "deny", app, level: level.level, reason: "human-denied", pinNeeded: false } };
        }
        // 2. The law.
        const label = this.labelLookup(req.path);
        // Plan 13 D4: a derived file (a copy a process holding a secret
        // wrote) has no reader list, so every program gets its twin, except
        // a process that already holds raw every source the copy was written
        // from (its taint, its ancestors' included): the copy carries nothing
        // new to it, so it gets the file with no new taint row (its exits are
        // already held to those sources; a copy's own row would carry no
        // bindings and cut it off from its sources' hosts). npm's own child
        // reading the package npm wrote while holding `~/.npmrc` is the case.
        // Never the agent's process; never a copy whose sources are unknown.
        // Plan 13 D8, printers admit nothing: not even a copy of what the
        // printer's tree already holds (its output would hand the bytes on).
        if (label?.origin === "derived" && !req.isAgent && !printer) {
          const row = resolveDerivedLabel(req.path, this.derivedLabels.map());
          // Plan 13 D9: what the process holds by the guard's records alone; a
          // claimed edge or row (more taint) must not buy a raw read.
          const held = new Set(this.provenance.processSecretTaint(req.procKey, { attestedOnly: true }).rows.map((r) => r.path));
          if (row && holderMayReadDerived(row, held)) {
            // Plan 10 §11.18: the copy is a known secret from now on, as its
            // sources are (its own values: a holder may write what its
            // sources never held, a session token derived from a key), at
            // its sources' bindings (by reference, plan 13 §4.6). A copy
            // whose pieces are unknown (over the bound) is not read raw:
            // what the holder could print from it would not be matched.
            this.registerReadFile(req.path);
            if (this.fileUnpieced(req.path)) {
              this.log(`decideSecretOpen: ${req.path} by ${req.exe} (${req.procKey}): a copy over the piece bound is not read raw (plan 10 §11.18); the law decides`);
            } else {
              this.log(`decideSecretOpen: ${req.path} by ${req.exe} (${req.procKey}) → raw (holds every source: ${(row.sources ?? []).join(", ")})`);
              return { id: req.id, ok: true, result: { verdict: "raw", app, level: level.level, reason: "a copy of secrets this process already holds", pinNeeded: false } };
            }
          }
        }
        const file = { ...(label?.readers ? { readers: label.readers } : {}), ...(label?.others ? { others: label.others } : {}) };
        const ask = req.ask === "always" || req.ask === "never" || req.ask === "known" ? req.ask : "never";
        // §11.13.1: npm needs no raw `.npmrc` when this session's proxy puts
        // each token back at its registry. Unknown session ⇒ today's default.
        const wireSession = typeof req.session === "string" ? this.wireReleaseSessions.get(req.session) : undefined;
        const wire = wireSession ? wireServableTwin(this.symbolMap, req.path, { direct: wireSession.direct }) : null;
        const d = decideOpen(req.path, file, opener, { ask, ...(wire?.servable ? { wireTwin: { why: wire.why } } : {}) });
        if (d.verdict === "raw") {
          // Plan 13 D8 (12): the pin carries the word of the entry it came
          // from (a glob label's entry too, whose pin lands in an entry of
          // its own for the file: without the word it would read the twin).
          return { id: req.id, ok: true, result: grantRaw(d.why, d.pinNeeded === true, "reader", d.reader?.from, d.reader?.script !== undefined ? { app: d.reader.app, script: d.reader.script } : undefined, d.reader?.prints === "nothing") };
        }
        if (d.verdict === "ask" && key === null) {
          // No verdict can name this program (decision (c)): refused, no row.
          const why = `no answer can name ${req.exe} (${d.why})`;
          this.provenance.recordSecretOpenDenial({ procKey: req.procKey, path: req.path, app, reason: why, session: req.session });
          this.log(`decideSecretOpen: ${req.path} by ${req.exe} (${req.procKey}) → deny (${why})`);
          return { id: req.id, ok: true, result: { verdict: "deny", app, level: level.level, reason: why, pinNeeded: false } };
        }
        if (d.verdict === "ask" && key !== null) {
          if (typeof req.heldMs === "number" && Number.isFinite(req.heldMs)) {
            // 3a. The ceiling (§12.2): the guard held this open for `heldMs`
            //     and nobody answered. Recorded as a denial so the tool
            //     result can say "held: …" (§11.8; before 2026-09-24 the
            //     guard denied on its own and the note had nothing to cite).
            //     The row is NOT touched: it stays pending, and the answer
            //     given later decides the next attempt with no new prompt.
            const reason = heldTimeoutReason(req.heldMs);
            this.provenance.recordSecretOpenDenial({ procKey: req.procKey, path: req.path, app, reason, session: req.session });
            this.log(`decideSecretOpen: ${req.path} by ${req.exe} (${req.procKey}) → deny (${reason})`);
            return { id: req.id, ok: true, result: { verdict: "deny", app, level: level.level, reason, pinNeeded: false } };
          }
          // 3. The hold (§11.1): a pending Inbox row the human resolves with the
          //    same allow / once / deny as any withheld symbol. The guard keeps
          //    the open suspended and re-asks; the row outlives the hold.
          const runs = program ? ` running ${program.script}` : "";
          // D8 (12): the warning question says plainly what an unvetted
          // program may do with what it reads.
          const warning = unvettedOpener
            ? ` Mandu does not know whether ${app} keeps what it reads out of what it prints: if you allow it, the AI's other programs may be able to read the file through it.`
            : "";
          const entry = this.egressApprovals.recordPending(
            key, req.path,
            `${app} (${req.exe})${runs} wants to read ${req.path} as a program (raw bytes; its output to the AI will be masked).${warning} ${d.why}`,
            req.session,
          );
          this.log(`decideSecretOpen: ${req.path} by ${req.exe} (${req.procKey}) → held (${entry.id})`);
          return { id: req.id, ok: true, result: { verdict: "ask", app, level: level.level, reason: `held for the human: ${d.why}`, pinNeeded: false, approvalId: entry.id } };
        }
        if (d.verdict === "deny") {
          this.provenance.recordSecretOpenDenial({ procKey: req.procKey, path: req.path, app, reason: d.why, session: req.session });
        }
        this.log(`decideSecretOpen: ${req.path} by ${req.exe} (${req.procKey}) → ${d.verdict} (${d.why})`);
        return { id: req.id, ok: true, result: { verdict: d.verdict, app, level: level.level, reason: d.why, pinNeeded: false } };
      }
      case "decideProtectedWrite": {
        // sandbox-security-review-2026-09-28 finding 6: a file that runs later
        // outside Mandu (a shell startup file, a systemd user unit, a git
        // hook). Same hold as a secret read: a prior human verdict for
        // (program, file) decides; else a pending Inbox row and `ask`.
        //
        // The program is its BINARY (write-protection.md §2.1, the Plan 13
        // D8 follow-up): the verdict is keyed `write:<exe>#<sha256>`, so
        // approving /usr/bin/vim admits no other binary named vim (an
        // agent-written /tmp/x/vim) nor a rebuilt one, and a row keyed by the
        // name alone (before 2026-10-02) no longer matches. A writer run with
        // a loader or interpreter variable the launch did not give, or with
        // agent-writable code mapped in, or whose environment the guard did
        // not report, is not the program the human would be asked about: it
        // is refused outright, as D8 refuses such an opener, and neither
        // matches nor spends a prior answer nor files a row (a prompt naming
        // /usr/bin/vim would put the agent's code behind the human's Allow).
        const path = typeof req.path === "string" ? req.path : "";
        const exe = typeof req.exe === "string" ? req.exe : "";
        const app = basenameOf(exe) || "a program";
        const answer = (verdict: DecideProtectedWriteResultWire["verdict"], reason: string, approvalId?: string) => {
          this.log(`decideProtectedWrite: ${path} by ${exe || app} → ${verdict} (${reason})`);
          return { id: req.id, ok: true as const, result: { verdict, reason, ...(approvalId ? { approvalId } : {}) } };
        };
        // Plan 13 D9: only the guard, on the human socket, reports a write.
        // From the data socket: refused, with no row in front of the human
        // and no verdict consulted (a forged report could word the row as
        // the guard does, with `exeSystem` claimed).
        if (!this.attested(ctx.channel)) return answer("deny", this.unattested("decideProtectedWrite", ctx.channel));
        if (!path.startsWith("/")) return answer("deny", "no absolute path to judge");
        if (!exe.startsWith("/")) return answer("deny", "the writer's program could not be read");
        const sha = typeof req.sha256 === "string" ? req.sha256 : undefined;
        const script = parseScriptFacts(req.script);
        const writer = {
          exe,
          ...(sha ? { sha256: sha } : {}),
          exeSystem: req.exeSystem === true,
          ...(Array.isArray(req.openerEnv) ? { loaderEnv: req.openerEnv.filter((n): n is string => typeof n === "string") } : {}),
          ...(script ? { script } : {}),
          ...(typeof req.scriptProblem === "string" ? { scriptProblem: req.scriptProblem } : {}),
        };
        // Plan 13 §8 decision (c): a writer that runs code (a shell, an
        // interpreter) is named with the script it runs, under R5's checks
        // (`write:<exe>#<sha256>#script:<path>#<sha256>`): allowing python3
        // running a.py to change ~/.bashrc allows no other script and no
        // inline code. One running no pinnable script (`bash -c 'echo … >>
        // ~/.bashrc'`, the agent's own shell) gets no reusable verdict: the
        // row names its process (`…#run:<procKey>`), so an answer covers that
        // run's changes only (an Always is kept as once, at resolve), and the
        // next run asks again. A row naming the interpreter alone (before the
        // decision) matches nothing.
        const program = verdictProgramOf(writer);
        const procKey = typeof req.procKey === "string" ? req.procKey : "";
        if (program === null && procKey === "") return answer("deny", `${app} runs code no script pin names, and its run could not be named`);
        const key = writeVerdictSubject(exe, sha, program === null ? { run: procKey } : program);
        if (key === null) return answer("deny", "the writer's program hash is malformed, or its path cannot be named");
        const envProblem = loaderEnvProblem(writer);
        if (envProblem !== null) return answer("deny", `${app} is not the program a human could approve: ${envProblem}`);
        // Only an attested report reaches here (the D9 check above).
        const prior = this.consultPriorVerdict(key, path, true);
        if (prior?.status === "approved") return answer("allow", `human-approved (${prior.scope})`);
        if (prior?.status === "denied") return answer("deny", "human-denied");
        if (typeof req.heldMs === "number" && Number.isFinite(req.heldMs)) return answer("deny", heldTimeoutReason(req.heldMs));
        // The label rides from the guard, which reads it from the launcher's
        // list; the Inbox shows only labels the launcher writes, so a caller
        // on the data socket cannot put its own words in front of the human.
        const label = PROTECTED_WRITE_LABELS.has(String(req.label ?? "")) ? String(req.label) : "a protected file";
        const runtime = runtimeOf(writer);
        const who = program === null
          ? runtime !== null
            ? `${app} (${exe}), by its content a ${runtime} interpreter, running code that is not a pinned script`
          : argsCodeProblem(writer) !== null
            ? `${app} (${exe}) running code its command line or environment hands it`
            : `${app} (${exe}) running code that is not a pinned script`
          : program !== undefined ? `${app} (${exe}) running ${program.script}` : `${app} (${exe})`;
        const entry = this.egressApprovals.recordPending(
          key, path,
          (label === "a file you protected in policy.yaml"
            ? `${who} wants to change ${path} (${label}). You asked to decide each change to it.`
            : `${who} wants to change ${path} (${label}). A file like this runs later, outside Mandu's protection.`)
            // Said, not decided on: the human judges where the program lives.
            + (req.exeSystem === true ? "" : " The agent could have written this program.")
            + (program === null ? " Your answer covers this change only; the next one asks again." : ""),
          req.session,
        );
        return answer("ask", "held for the human", entry.id);
      }
      case "recordExecRoot": {
        // Plan 13 D7: the guard's `ancestors` (the live chain at the exec)
        // become edges, so a subshell that never execs is still in the tree.
        // `callRoot` (the exec'ing process is the agent's own child) makes it
        // a candidate root of a tool call under every command signature it can
        // be the root of: the call-root recorder of callTree.
        // Plan 13 D9: from the data socket only the chain is kept, as claimed
        // edges; no signature (the `guess`), no argv (an MCP server's process)
        // and no call-root candidate.
        // Plan 13 D7, the orphan subshell: an orphan root only widens the
        // fold of the calls relayed before it was first seen, so it is kept
        // from either socket (claimed from the data socket).
        if (typeof req.orphanRoot === "string" && req.orphanRoot !== "") this.provenance.recordOrphanRoot(req.orphanRoot, req.session, { claimed: !this.attested(ctx.channel) });
        if (!this.attested(ctx.channel)) {
          this.provenance.recordLineageChain(req.procKey, lineageChain(req.parentKey, Array.isArray(req.ancestors) ? req.ancestors : undefined), req.session, { claimed: true });
          return { id: req.id, ok: true, result: { ok: true } };
        }
        this.provenance.recordExecRoot({
          procKey: req.procKey, parentKey: req.parentKey, session: req.session,
          ...(Array.isArray(req.ancestors) ? { ancestors: req.ancestors } : {}),
          signature: execSignatureForArgv(req.argv), argv: req.argv,
          ...(req.callRoot === true ? { callRoot: true, rootSignatures: rootSignaturesOfArgv(req.argv) } : {}),
          // 2026-10-04: the directory the kernel says the call's shell
          // started in (confidentiality.md §6), from the human plane only.
          ...(req.callRoot === true && typeof req.cwd === "string" ? { cwd: req.cwd } : {}),
        });
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "taintedProcessBindings": {
        // Plan 10 §4.3. Ancestor edges first (a fork-only child has none until
        // a moment like this), then the taint over the chain, then the
        // INTERSECTION over the files in it (confidentiality plan 13 D1: a
        // holder of two secrets may send only where both may go; the union
        // this answered before let a process holding `.env` and
        // `~/.aws/credentials` send the AWS key to Stripe). One file's
        // bindings are its human label's plus its registry rows' (a symbol
        // row's `bindings`): per file, until §5.2's `values:` keys them per
        // value.
        // Plan 13 D9: from the data socket (net-proxy, or a forger) the chain
        // is claimed edges: they widen the walk below, never cut the guard's.
        if (req.ancestors) this.provenance.recordLineageChain(req.procKey, req.ancestors, req.session, { claimed: !this.attested(ctx.channel) });
        // Plan 13 D2: the processes whose taint reached this one through a
        // descriptor (a pipe, a FIFO, a socket pair) or as an orphan's lost
        // holders, unioned in without recording them as parents.
        const t = this.provenance.processSecretTaintWithFlows(req.procKey, flowsFromOf(req.flowsFrom));
        if (t.level === null) {
          return { id: req.id, ok: true, result: { tainted: false, level: null, files: [], bindings: [] } satisfies TaintedProcessBindingsResultWire };
        }
        const files = [...new Set(t.rows.map((r) => r.path))];
        const registry = listSecretRegistry(this.symbolMap);
        // A HIGH session's row for a value with no file (`symbol:<name>`,
        // taintProcessSession) binds where its symbol does, as the law
        // stands now (confidentiality.md §4).
        // Plan 13 §5.2: a file with `values:` is held WHOLE, so its label
        // bindings are the intersection over its values, and its field rows'
        // per-value hosts are not counted (`holderFileBindings`).
        const perFile = files.map((f) => f.startsWith(SESSION_SYMBOL_ROW_PREFIX)
          ? [...(this.symbolMap.symbols.get(f.slice(SESSION_SYMBOL_ROW_PREFIX.length))?.bindings ?? [])]
          : holderFileBindings(
            pathConfidentiality(f, undefined, this.labelLookup),
            registry.filter((e) => e.path === f).flatMap((e) => e.bindings),
          ));
        const result: TaintedProcessBindingsResultWire = { tainted: true, level: t.level, files, bindings: intersectBindings(perFile) };
        // Plan 13 §5.4 (2026-10-11): the proxy that refuses this holder's
        // send names the destination, and the human's answer for {session,
        // these files} × destination is consulted (and spent) here, or a
        // question filed that names every file (holder-send-ask.ts). An
        // attested report only: from the data socket the destination is
        // ignored (no verdict consulted, no row filed: ATTESTED_REPORT_OPS).
        const dest = typeof req.destination === "string" ? req.destination.trim().toLowerCase() : "";
        // confidentiality.md §4, "A held command's refused connection"
        // (2026-10-12): a process that holds only what ONE HIGH session read
        // (its `session` rows, `sessionExecRoot`) asks that session's own
        // network question, `session-net:<session>` × host: an Allow once
        // there is spent here by the next such connection (the retry, a new
        // command), a Block refuses with no new card. The asking process's
        // call is told it was asked (or blocked) through its refusal record.
        const heldSession = dest !== "" && this.attested(ctx.channel) && !holderHostIsBound(dest, result.bindings)
          ? heldSessionOf(t.rows, req.session)
          : null;
        if (heldSession !== null) {
          const subject = sessionApprovalSubject("network", heldSession);
          const target = sessionNetTarget(dest);
          const prior = this.consultPriorVerdict(subject, target, true);
          if (prior && prior.status !== "pending") {
            result.ask = { approvalId: prior.id, status: prior.status, scope: prior.scope, question: "session" };
          } else {
            const entry = this.egressApprovals.recordPending(subject, target, sessionHeldNetReason(target, files), heldSession);
            this.log(`taintedProcessBindings: held ${req.procKey} → ${target} asked as session ${heldSession} (${entry.id})`);
            result.ask = { approvalId: entry.id, status: "pending", question: "session" };
          }
          const kind = heldRefusalKind(result.ask.status);
          if (kind !== null) this.provenance.recordEgressRefusal({ procKey: req.procKey, kind, session: heldSession });
        } else if (dest !== "" && req.sessionAskOnly !== true && this.attested(ctx.channel) && !holderHostIsBound(dest, result.bindings)) {
          const subject = holderSendSubject(req.session, files);
          const prior = this.consultPriorVerdict(subject, dest, true);
          if (prior) {
            result.ask = { approvalId: prior.id, status: prior.status, scope: prior.scope, question: "holder" };
          } else {
            const apps = [...new Set(t.rows.map((r) => r.app).filter((a) => typeof a === "string" && a !== ""))];
            const entry = this.egressApprovals.recordPending(
              subject, dest,
              `${apps.join(", ") || "a program"} holds ${files.join(", ")}; ${dest} is not a place all of it may go (plan 13 §5.4)`,
              req.session,
            );
            this.log(`taintedProcessBindings: ${req.procKey} → ${dest} asked (${entry.id}, ${files.length} file(s))`);
            result.ask = { approvalId: entry.id, status: "pending", question: "holder" };
          }
        }
        return { id: req.id, ok: true, result };
      }
      case "guardAttach": {
        // confidentiality.md §4, "Without the guard": the session's kernel
        // guard announces that it holds the session's processes, so a HIGH
        // session's command card can say an allowed command runs confined.
        // Believed from the human plane only (a data-socket claim would let
        // a card overstate the confinement).
        if (typeof req.sessionKey !== "string" || req.sessionKey === "") {
          return { id: req.id, ok: false, error: "guardAttach: sessionKey required" };
        }
        if (!this.attested(ctx.channel)) {
          return { id: req.id, ok: true, result: { attached: false, reason: this.unattested("guardAttach", ctx.channel) } satisfies GuardAttachResultWire };
        }
        this.guardedSessions.add(req.sessionKey);
        while (this.guardedSessions.size > GUARDED_SESSIONS_MAX) {
          const oldest = this.guardedSessions.values().next().value;
          if (oldest === undefined) break;
          this.guardedSessions.delete(oldest);
        }
        this.log(`guardAttach: ${req.sessionKey} → its commands are held by the guard`);
        return { id: req.id, ok: true, result: { attached: true } satisfies GuardAttachResultWire };
      }
      case "sessionExecRoot": {
        // confidentiality.md §4, "What Allow once means for a command": the
        // guard's question at a tool call's shell exec, before it lets the
        // exec go. In a HIGH session the process holds what the session read
        // (one `session` row per datum) and the guard makes it a holder, so
        // its connections go only where every datum may go and its writes
        // are labeled. Human plane only, like the exec roots it records.
        const no = (reason: string) => ({ id: req.id, ok: true as const, result: { holder: false, reason } satisfies SessionExecRootResultWire });
        if (typeof req.procKey !== "string" || req.procKey === "") return { id: req.id, ok: false, error: "sessionExecRoot: procKey required" };
        if (!this.confidentiality) return no("confidentiality axis is OFF");
        // arbiter-human-plane.md §5.2 (2026-10-17): from a channel whose
        // reports are claims (the data socket, or the human socket while an
        // unwalled launch is live) the process is STILL a holder, its rows
        // kept as claims. A session row only confines (its exits go where the
        // session's data may, its writes are labeled; it never masks a result
        // and never buys a raw read), so a forged one takes nothing away;
        // answering `holder: false` there let a HIGH session's command run
        // unconfined under a guard that had no human plane.
        const claimed = !this.attested(ctx.channel);
        const sess = this.sessionLabels.get(req.session);
        if (sess.confidentiality === "public") return no("the session has read no secret into context");
        const rows = this.sessionSourceRows(req.session!, sess.confidentiality);
        this.provenance.taintProcessSession(req.procKey, rows, req.session, { claimed });
        this.log(`sessionExecRoot: ${req.procKey} holds what session ${req.session} read (${rows.map((r) => r.path).join(", ")})${claimed ? ` [claimed: ${this.unattested("sessionExecRoot", ctx.channel)}]` : ""}`);
        return {
          id: req.id, ok: true,
          result: {
            holder: true, level: sess.confidentiality,
            reason: claimed ? `a HIGH session's command holds what the session read (kept as a claim: ${this.unattested("sessionExecRoot", ctx.channel)})` : "a HIGH session's command holds what the session read",
          } satisfies SessionExecRootResultWire,
        };
      }
      case "sessionSecretTaint": {
        // Plan 13 D6: the net-proxy's question for a connection it cannot
        // attribute to a process. Raw reads are recorded only while the
        // confidentiality axis is on, so off ⇒ nothing is held.
        const s = this.confidentiality ? this.provenance.sessionSecretTaint(req.session) : { level: null, rows: [] };
        const result: SessionSecretTaintResultWire = {
          tainted: s.level !== null,
          level: s.level,
          files: [...new Set(s.rows.map((r) => r.path))],
        };
        return { id: req.id, ok: true, result };
      }
      case "secretTaintedProcesses": {
        // Plan 13 D6, a blind tunnel's chunks: the processes the net-proxy
        // looks for among a tunnel's holders before each chunk. Not gated on
        // the axis: it is the forward image of the walk
        // `taintedProcessBindings` answers by (also ungated), so no holder
        // that question would call tainted is left out.
        const result: SecretTaintedProcessesResultWire = { procKeys: this.provenance.secretTaintedProcesses() };
        return { id: req.id, ok: true, result };
      }
      case "labelWrittenPathTainted": {
        // Plan 10 §4, the filesystem exit: the file a tainted process writes
        // inherits the taint's LEVEL (never its bindings: §8) as a derived
        // label, so the next reader of that path is judged at that level.
        if (!this.confidentiality) {
          return { id: req.id, ok: true, result: { labeled: false, level: "public", reason: "confidentiality axis is OFF" } satisfies LabelWrittenPathTaintedResultWire };
        }
        // Plan 13 D9: a data-socket chain is claimed edges (more labels, never fewer).
        if (req.ancestors) this.provenance.recordLineageChain(req.procKey, req.ancestors, req.session, { claimed: !this.attested(ctx.channel) });
        const t = this.provenance.processSecretTaintWithFlows(req.procKey, flowsFromOf(req.flowsFrom));
        const norm = normalizeLabelPath(req.path);
        if (t.level === null || norm === null || !isSecret(t.level as ConfidentialityLevel)) {
          return { id: req.id, ok: true, result: { labeled: false, level: "public", reason: t.level === null ? "the writing process holds no secret" : "path not labelable" } satisfies LabelWrittenPathTaintedResultWire };
        }
        // The secret files themselves are not re-labeled by their own readers.
        if (t.rows.some((r) => r.path === norm)) {
          return { id: req.id, ok: true, result: { labeled: false, level: t.level, reason: "the secret file itself" } satisfies LabelWrittenPathTaintedResultWire };
        }
        const row = this.derivedLabels.raise(norm, t.level as ConfidentialityLevel, { sessionKey: req.session ?? `proc:${req.procKey}`, tool: "process", sources: [...new Set(t.rows.map((r) => r.path))] });
        this.log(`labelWrittenPathTainted: ${norm} ← ${req.procKey} (${t.rows.map((r) => r.app).join(",")} read ${t.rows.map((r) => r.path).join(",")}) → ${row?.confidentiality ?? "none"}`);
        return { id: req.id, ok: true, result: { labeled: row !== null, level: row?.confidentiality ?? t.level, reason: `written by a process that read ${t.rows.map((r) => r.path).join(", ")}` } satisfies LabelWrittenPathTaintedResultWire };
      }
      case "derivedLabelsSince": {
        // Confidentiality plan 13 D4: the guard's live index of derived
        // paths. Another epoch (this arbiter restarted since the guard last
        // asked) answers every row; within one, the rows changed after
        // `since`. Listed only while the path still classifies secret (an
        // exact human `public` label releases the copy).
        const store = this.derivedLabels;
        const epoch = store.epoch;
        const gen = store.generation();
        if (!this.confidentiality) {
          return { id: req.id, ok: true, result: { epoch, gen, labels: [] } satisfies DerivedLabelsSinceResultWire };
        }
        const since = req.epoch === epoch && typeof req.since === "number" && Number.isFinite(req.since) ? req.since : 0;
        const labels: DerivedLabelsSinceResultWire["labels"] = [];
        for (const row of store.since(since)) {
          const level = pathConfidentiality(row.path, undefined, this.labelLookup).level;
          if (isSecret(level)) labels.push({ path: row.path, level });
        }
        // A live session's labels (session-path-labels.ts) are NOT listed
        // (2026-10-05): the guard would gate the agent's own reads of its
        // background output file and hand OpenCode a twin of it. Those files
        // are classified by the catalog now (secret-catalog.ts, OpenCode's
        // data directory), which no open-gating reads either.
        return { id: req.id, ok: true, result: { epoch, gen, labels } satisfies DerivedLabelsSinceResultWire };
      }
      case "labelRootsSince": {
        // 2026-10-17 (confidentiality.md §6, "Read by a program the launch
        // did not see"): the guard's list of where the human labels lie, so
        // it gates a labelled file the launch did not register. Read-only,
        // no value: the paths and shapes of the labels in force, which the
        // label surface lists anyway. An unchanged list answers no rows.
        // Axis OFF ⇒ no roots: nothing is gated.
        // Since the same day, the CATALOG too: its prefixes as roots (for
        // the arbiter's HOME and the session's launch HOME) and its name
        // shapes as a prefilter (`catalog`), so a `.env` or a key the launch
        // did not register (created mid-session, deeper than the walk, past
        // its cap, outside HOME) is gated as the walk would have twinned it.
        const g = this.guardRoots(req.session);
        if (typeof req.key === "string" && req.key === g.key) {
          return { id: req.id, ok: true, result: { key: g.key, unchanged: true, roots: [], skipDirs: [...SKIP_DIRS] } satisfies LabelRootsSinceResultWire };
        }
        return { id: req.id, ok: true, result: { key: g.key, unchanged: false, roots: g.roots, skipDirs: [...SKIP_DIRS], ...(g.catalog ? { catalog: g.catalog } : {}) } satisfies LabelRootsSinceResultWire };
      }
      case "labelledLevel": {
        // The level a file the guard gates (under a label root, or one the
        // catalog's prefixes or names may cover) classifies at now: labels,
        // then the catalog, as `decideSecretOpen` reads them (the session's
        // launch HOME too), and for a catalog verdict the walk's own prunes
        // (`gateVerdict`: an agent's files, Mandu's state, the skipped
        // directories, package caches, another account's file outside every
        // home), so the gate twins what a launch would have. Read-only.
        const g = this.guardRoots(req.session);
        if (!this.confidentiality || typeof req.path !== "string" || !req.path.startsWith("/")) {
          return { id: req.id, ok: true, result: { level: "public", key: g.key } satisfies LabelledLevelResultWire };
        }
        const m = gateVerdict(req.path, this.gateHomes(req.session), this.labelLookup);
        // 2026-10-17 (confidentiality.md §6, "The base follows the shell"):
        // the AGENT's own open of the file, which the guard lets run raw (its
        // tool's result is classified at the model door): recorded, from the
        // human plane only, for the classify of the file tool that named it
        // by a relative path (`withAgentOpens`). Raise-only.
        if (req.agentOpen === true && this.attested(ctx.channel) && isSecret(m.level)) {
          this.provenance.recordAgentOpen(req.path, typeof req.session === "string" && req.session !== "" ? req.session : undefined);
          return { id: req.id, ok: true, result: { level: m.level, key: g.key, recorded: true } satisfies LabelledLevelResultWire };
        }
        return { id: req.id, ok: true, result: { level: m.level, key: g.key } satisfies LabelledLevelResultWire };
      }
      case "sessionPathLabel": {
        // supported-agents.md §2.3 item 7: a session's machine label on one
        // exact path, `no-model`, in memory. Raise-only, so the data plane
        // (the proxy) may ask: the worst a caller does is mask a path.
        const answer = (labeled: boolean, path: string | null, reason: string) =>
          ({ id: req.id, ok: true as const, result: { labeled, path, level: labeled ? "no-model" as const : null, reason } satisfies SessionPathLabelResultWire });
        if (!this.confidentiality) return answer(false, null, "confidentiality axis is OFF");
        if (typeof req.sessionKey !== "string" || req.sessionKey === "") return { id: req.id, ok: false, error: "sessionPathLabel: sessionKey must be a non-empty string" };
        const row = this.sessionPathLabels.set(String(req.path ?? ""), req.sessionKey, String(req.reason ?? ""), () => this.derivedLabels.nextGen());
        if (row === null) return { id: req.id, ok: false, error: "sessionPathLabel: not an absolute path, or the session label store is full" };
        this.log(`sessionPathLabel: ${row.path} → no-model for session ${row.sessionKey}${row.reason ? ` (${row.reason})` : ""}`);
        return answer(true, row.path, row.reason);
      }
      case "clearSessionPathLabels": {
        // The session ended (the launcher): its labels go. Human plane only
        // (HUMAN_PLANE_OPS): dropping a label lowers protection.
        if (typeof req.sessionKey !== "string" || req.sessionKey === "") return { id: req.id, ok: false, error: "clearSessionPathLabels: sessionKey must be a non-empty string" };
        const cleared = this.sessionPathLabels.clearSession(req.sessionKey);
        if (cleared > 0) this.derivedLabels.nextGen(); // the bindings sync re-reads the law
        return { id: req.id, ok: true, result: { cleared } satisfies ClearSessionPathLabelsResultWire };
      }
      case "followDerivedLabel": {
        // Confidentiality plan 13 D4: the label follows the file. Raise-only
        // (a machine may taint, never declassify, derived-labels.ts), so the
        // data socket may ask it: the worst a caller does is label a path.
        const answer = (labeled: boolean, level: string | null, reason: string) =>
          ({ id: req.id, ok: true as const, result: { labeled, level, reason } satisfies FollowDerivedLabelResultWire });
        if (!this.confidentiality) return answer(false, null, "confidentiality axis is OFF");
        const from = normalizeLabelPath(String(req.from ?? ""));
        const to = normalizeLabelPath(String(req.to ?? ""));
        if (from === null || to === null) return answer(false, null, "not an absolute path");
        const how = req.how === "rename" || req.how === "link" ? req.how : "identity";
        // 2026-10-16: never onto a REGISTERED file. A holder of a file may send
        // where its label goes AND where its registry rows go
        // (`taintedProcessBindings`); a derived row by reference to a source
        // would give a registered file with no label of its own its source's
        // destinations on the label side: a widening. (The caller names the
        // target, so an agent could aim a follow at another registered
        // file's path.) A file that is merely labelled keeps its own label in
        // the intersection, so a follow onto it only narrows.
        if (listSecretRegistry(this.symbolMap).some((e) => e.path === to)) {
          return answer(false, null, `${to} is a registered file: a label never follows onto one`);
        }
        const src = this.derivedLabels.map().get(from);
        if (!src) {
          // 2026-10-16 (guard-file-identity: a folder moved above a protected
          // file): the guard asks the same for a PROTECTED file it moved with
          // its folder, so the next session gates it under its new path. Its
          // level is the file's own (a human label, the catalog, or the secret
          // registry), carried as a derived label whose source is the file.
          // It never adds a destination: a new row's are the moved file's own
          // (its label and registry rows, by reference), and an existing
          // row's sources only grow (an intersection: narrower) unless the row
          // was bound nowhere, which it stays (DerivedLabelStore.raise).
          const protectedLevel = this.protectedLevelOf(from);
          if (protectedLevel === null) return answer(false, null, `${from} carries no derived label and is no protected file`);
          const row = this.derivedLabels.raise(to, protectedLevel, { sessionKey: req.session ?? "guard", tool: how, sources: [from] });
          this.log(`followDerivedLabel: ${from} → ${to} (${how}, protected file) → ${row?.confidentiality ?? "none"}`);
          return answer(row !== null, row?.confidentiality ?? null, `the label of ${from} follows its file (${how})`);
        }
        const row = this.derivedLabels.raise(to, src.confidentiality, { sessionKey: req.session ?? src.sessionKey, tool: how, sources: src.sources });
        this.log(`followDerivedLabel: ${from} → ${to} (${how}) → ${row?.confidentiality ?? "none"}`);
        return answer(row !== null, row?.confidentiality ?? null, `the label of ${from} follows its file (${how})`);
      }
      case "scanSecretValues": {
        // The verbatim-value backstop of §2.2: every active secret row whose
        // value (at or above the fingerprint floor) appears in the text. The
        // rows are the secrets themselves (registry values and their fields,
        // a labeled file's content the model tried to read) and the exec
        // outputs masked on EVIDENCE: a `nomodel_Bash` row whose call's tree held
        // a secret (rule (i): a reader printed it) fingerprints, so a later
        // (ii)/(iii) release or denied-only release of the same bytes stays
        // masked even when the file is not in the registry. A `nomodel_Bash` row
        // masked as a PRECAUTION (no taint on record: the path-derived level,
        // a fail-closed unknown) holds whatever the command printed, and the
        // harmless "cat: .env: Permission denied" of one refused run would
        // otherwise match every later one (drill S7 rerun, 2026-09-24: the
        // §11.8 denied-only release never fired on a database that had seen
        // the text masked once). Evidence is the provenance store's answer
        // for the row's own call, memoized per scan.
        const hits = this.confidentiality && typeof req.text === "string" && req.text !== ""
          ? this.secretValueHits(req.text)
          : [];
        const result: ScanSecretValuesResultWire = { hits };
        return { id: req.id, ok: true, result };
      }
      case "documentText": {
        // Secret-discovery.md §2.8, "A document block": the text the model
        // proxy forwards in place of a PDF block (document-blocks.ts). The
        // twin is looked up only at an absolute `origin`; any answer is
        // then judged by the proxy's classify as any text is.
        const origin = typeof req.origin === "string" && req.origin.startsWith("/") ? req.origin : null;
        const twin = origin !== null ? registeredDocumentTwin(this.symbolMap, origin, { resolveLabel: this.labelLookup }) : null;
        const a = documentBlockText(req.data, req.mediaType, twin);
        const result: DocumentTextResultWire = { text: a.text, reason: a.reason, ...(a.twinOf ? { twinOf: a.twinOf } : {}) };
        return { id: req.id, ok: true, result };
      }
      case "filterPrompt":
        // Asynchronous since plan 15 phase 3 (a plugin filter answers from a
        // child process): the socket path answers it (handleLine →
        // filterPromptOp); an in-process caller awaits `filterPromptOp`.
        return { id: req.id, ok: false, error: "filterPrompt is asynchronous: call it over the socket, or await filterPromptOp" };
      case "promptFilters": {
        // Plan 15 §8.1: the panel's Filters, Actions, Exceptions and Packs
        // (counts only: a pack's regexes and keywords are promptFilterPacks,
        // human plane).
        const packs = this.loadedPromptPacks();
        const input = this.promptPolicyInput();
        const av = this.promptFilter.actionViews();
        const result: PromptFiltersResultWire = {
          filters: this.promptFilterViewsWithPlugins(packs.loaded),
          actions: av.rows.map((r) => ({ category: r.category, action: r.action, setBy: r.setBy, locked: r.locked, ...(r.file ? { file: r.file } : {}) })),
          fallback: av.fallback,
          // Without the pattern: that is `promptExceptions`, human plane.
          exceptions: av.exceptions.map((e) => ({ category: e.category, setBy: e.setBy, ...(e.file ? { file: e.file } : {}), inForce: e.inForce })),
          signedOnly: av.signedOnly,
          packs: packs.loaded.packs.map((p) => ({
            id: p.doc.pack, source: p.source, file: p.file, version: String(p.doc.version),
            ...(p.doc.description !== undefined ? { description: p.doc.description } : {}),
            signedBy: p.signedBy,
            ...(input.unavailable?.has(p.doc.pack) ? { ignored: input.unavailable.get(p.doc.pack)! } : {}),
            patterns: p.doc.patterns.length,
            keywordGroups: p.doc.keywords.length,
            keywords: p.doc.keywords.reduce((n, k) => n + (k.words?.length ?? 0), 0),
            hashedKeywords: p.doc.keywords.reduce((n, k) => n + (k.hashes?.length ?? 0), 0),
            categories: [...new Set([...p.doc.patterns.map((x) => x.category), ...p.doc.keywords.map((x) => x.category), ...(p.doc.categories ?? []).map((x) => x.category)])].sort(),
            ...(p.doc.plugin ? { plugin: true } : {}),
          })),
          // Outlined: the engine's message quotes a fragment of the regex,
          // which stays on the human plane (promptFilterPacks).
          packProblems: packs.loaded.problems.map((p) => ({ file: p.file, source: p.source, ...(p.pack ? { pack: p.pack } : {}), problems: p.problems.map(packProblemOutline) })),
          conflicts: promptLockProblems(this.policyDocs?.document?.prompt_filters, getAdminLayer().promptFilters ?? []),
          userPackDir: this.promptPackDirs.user,
          enforcing: this.confidentiality,
          digest: this.promptFilter.digest(),
          registeredValues: this.syncedValueIndex().rowCount,
        };
        return { id: req.id, ok: true, result };
      }
      case "promptExceptions": {
        // Plan 15 §13.7 item 4 (human plane): the exceptions with their
        // patterns, in promptFilters' order.
        const result: PromptExceptionsResultWire = {
          exceptions: this.promptFilter.actionViews().exceptions.map((e) => ({ category: e.category, match: e.match, setBy: e.setBy, ...(e.file ? { file: e.file } : {}), inForce: e.inForce })),
        };
        return { id: req.id, ok: true, result };
      }
      case "promptFilterPacks": {
        // Plan 15 §8.1 (human plane): every pack in full; hashed keywords as
        // a count only.
        const packs = this.loadedPromptPacks();
        const result: PromptFilterPacksResultWire = {
          packs: packs.loaded.packs.map((p) => ({
            id: p.doc.pack, source: p.source, file: p.file, version: String(p.doc.version),
            ...(p.doc.description !== undefined ? { description: p.doc.description } : {}),
            signedBy: p.signedBy,
            // A plugin pack is a file only (plan 15 §12, 2026-10-03).
            editable: p.source === "user" && p.signedBy === null && !p.doc.plugin,
            ...(p.doc.plugin ? { plugin: { exec: p.doc.plugin.exec, sha256: p.doc.plugin.sha256, ...(p.doc.plugin.script ? { script: p.doc.plugin.script, scriptSha256: p.doc.plugin.scriptSha256 } : {}), ...(p.doc.plugin.modules && p.doc.plugin.modules.length > 0 ? { modules: p.doc.plugin.modules.map((m) => ({ path: m.path, sha256: m.sha256 })) } : {}), args: [...p.doc.plugin.args], cost: p.doc.plugin.cost, endpoint: p.doc.plugin.endpoint, deadlineMs: p.doc.plugin.deadlineMs }, categories: (p.doc.categories ?? []).map((c) => ({ ...c })) } : {}),
            patterns: p.doc.patterns.map((x) => ({ id: x.id, category: x.category, regex: x.regex, ...(x.check ? { check: x.check } : {}), ...(x.level ? { level: x.level } : {}) })),
            keywords: p.doc.keywords.map((k) => ({
              category: k.category, match: k.match, hashed: k.hashes !== undefined,
              count: k.hashes?.length ?? k.words?.length ?? 0,
              ...(k.words ? { words: [...k.words] } : {}),
              ...(k.level ? { level: k.level } : {}),
            })),
          })),
          packProblems: packs.loaded.problems.map((p) => ({ file: p.file, source: p.source, ...(p.pack ? { pack: p.pack } : {}), problems: [...p.problems] })),
        };
        return { id: req.id, ok: true, result };
      }
      case "resolvePromptHold": {
        // Plan 15 §7 (admin channel only): the human's answer to a held
        // prompt: send as written, send masked (the default), or cancel; for
        // this message or the session. Under a locked administrator's `ask`
        // row a session answer is refused (§12, 2026-10-04; holds.ts).
        const answer = req.answer;
        if (answer !== "send" && answer !== "mask" && answer !== "cancel") return { id: req.id, ok: false, error: "resolvePromptHold: answer must be send, mask or cancel" };
        const scope = req.scope === "session" ? "session" : "once";
        try {
          const approval = this.promptHolds.answer(String(req.approvalId ?? ""), answer, scope, this.promptFilter.config());
          this.log(`resolvePromptHold: ${approval.id} → ${answer} (${scope})`);
          this.emitApprovalResolved(approval, { answer, scope });
          return { id: req.id, ok: true, result: { approval, answer, scope } };
        } catch (err) {
          return { id: req.id, ok: false, error: (err as Error).message };
        }
      }
      case "letPromptFindingThrough": {
        // Plan 15 §7 "Overriding a finding" (admin channel only): a past
        // finding goes as written in this message or for the session.
        try {
          const approval = this.promptHolds.letThrough(req, this.promptFilter.config());
          this.log(`letPromptFindingThrough: ${approval.id} (${String(req.scope)})`);
          this.emitApprovalResolved(approval, { answer: "let-through", scope: req.scope === "session" ? "session" : "once" });
          return { id: req.id, ok: true, result: { approval } };
        } catch (err) {
          return { id: req.id, ok: false, error: (err as Error).message };
        }
      }
      case "promptHolds": {
        // Plan 15 §7 (human plane): the pending holds with the human's own
        // found text, for the Inbox card.
        const result: PromptHoldsResultWire = { holds: this.promptHolds.pending(this.promptFilter.config()), timeoutMs: this.promptHolds.timeoutMs };
        return { id: req.id, ok: true, result };
      }
      case "promptPackEdit": {
        // Plan 15 §8.1 (admin channel only): typed edits to one of the
        // person's own packs, validated (RE2) before anything is written.
        const result = this.promptPackEdit(req);
        return { id: req.id, ok: true, result };
      }
      case "registerMcpServers": {
        // Plan 10 §11.13 (human plane): the launcher's read of the agent's
        // stdio MCP config, before the agent started. Malformed entries are
        // dropped (they stay unmapped). A later registration of the same
        // session (a re-read of a changed config) only ADDS: a server keeps
        // every command line it was registered with. Replacing let a config
        // the agent edited point a tainted server at a clean look-alike (one
        // clean process: `clean`, which skips the session ask on Codex).
        if (typeof req.sessionKey !== "string" || req.sessionKey === "" || !Array.isArray(req.servers)) {
          return { id: req.id, ok: false, error: "registerMcpServers: sessionKey and servers[] are required" };
        }
        // A malformed `sources` list is refused whole, before anything is
        // kept, so a half-read one never drops a file from the check.
        if (req.sources !== undefined && !(Array.isArray(req.sources) && req.sources.length <= 256 && req.sources.every((x) =>
          !!x && typeof x.path === "string" && x.path.startsWith("/") && typeof x.stamp === "string" && x.stamp !== ""))) {
          return { id: req.id, ok: false, error: "registerMcpServers: sources must be [{path (absolute), stamp}] (at most 256)" };
        }
        const servers = req.servers
          .filter((s): s is { name: string; command: string; args: string[] } =>
            !!s && typeof s.name === "string" && s.name !== "" && typeof s.command === "string" && s.command !== ""
            && Array.isArray(s.args) && s.args.every((a) => typeof a === "string"))
          .slice(0, 256)
          .map((s) => ({ name: s.name, command: s.command, args: [...s.args] }));
        const merged = [...(this.mcpServersBySession.get(req.sessionKey) ?? [])];
        const same = (a: { name: string; command: string; args: string[] }, b: typeof a): boolean =>
          a.name === b.name && a.command === b.command && a.args.length === b.args.length && a.args.every((x, i) => x === b.args[i]);
        for (const s of servers) if (!merged.some((m) => same(m, s)) && merged.length < 1024) merged.push(s);
        this.mcpServersBySession.set(req.sessionKey, merged);
        // §11.17: the files this read consulted, with their stamps then.
        // The latest list replaces the last (it is the newer read).
        if (req.sources !== undefined) this.mcpSourcesBySession.set(req.sessionKey, req.sources.map((x) => ({ path: x.path, stamp: x.stamp })));
        return { id: req.id, ok: true, result: { registered: servers.length } };
      }
      case "registerWireRelease": {
        // Plan 10 §11.13.1 (human plane): the launcher's word that this
        // session's egress proxy terminates TLS, so npm may be served the
        // `.npmrc` twin (decideSecretOpen, wireServableTwin).
        if (typeof req.sessionKey !== "string" || req.sessionKey === "" || typeof req.inspecting !== "boolean") {
          return { id: req.id, ok: false, error: "registerWireRelease: sessionKey and inspecting (boolean) are required" };
        }
        // `direct`: the session's NO_PROXY hosts (npm reaches them around the
        // proxy, so a token bound there is not servable). Malformed ⇒ none.
        const direct = parseDirectHosts(req.direct);
        // The launcher's pid (optional): with it the word is also kept in
        // mandu.db while that launcher runs, so a restart under the live
        // session keeps npm on the twin; `inspecting: false` with it drops
        // only that launcher's word (the session's end).
        const pid = typeof req.pid === "number" && Number.isSafeInteger(req.pid) && req.pid > 0 ? req.pid : undefined;
        if (req.inspecting) this.wireReleaseSessions.set(req.sessionKey, direct, pid);
        else this.wireReleaseSessions.clear(req.sessionKey, pid);
        return { id: req.id, ok: true, result: { inspecting: req.inspecting } };
      }
      case "registerAuthGrant": {
        // Agent-sign-in.md §3 (human plane): the launcher's word that a field
        // of the agent's own key file authenticates to a host (the provider
        // it routes), so the model proxy may put the key back in the auth
        // header of a request to that host. Recorded in memory, then the
        // file's rows are brought to the law at once (rows registered by an
        // earlier launch included). The environment form (`env`, 2026-10-11,
        // §3.8): the agent's key in a variable of the launcher's environment
        // (Claude Code's ANTHROPIC_API_KEY), its row `env:NAME`, each
        // grant's field the variable's own name.
        const envName = typeof req.env === "string" ? req.env : undefined;
        if (envName !== undefined) {
          if (req.path !== undefined) return { id: req.id, ok: false, error: "registerAuthGrant: path and env are exclusive" };
          if (!isGrantOrigin(`env:${envName}`)) return { id: req.id, ok: false, error: "registerAuthGrant: env must be a variable name" };
        } else if (typeof req.path !== "string" || !req.path.startsWith("/")) {
          return { id: req.id, ok: false, error: "registerAuthGrant: path must be absolute" };
        }
        let grants;
        try {
          grants = parseAuthGrants(req.grants);
          if (envName !== undefined && grants.some((g) => g.field !== envName)) throw new Error("an env grant's field is the variable's own name");
        } catch (err) {
          return { id: req.id, ok: false, error: `registerAuthGrant: ${(err as Error).message}` };
        }
        const origin = envName !== undefined ? `env:${envName}` : (req.path as string);
        // The launcher's pid (optional): with it the grant is also kept in
        // mandu.db and taken back by a restarted arbiter while that
        // launcher lives (auth-grants.ts); without it, memory only.
        const pid = typeof req.pid === "number" && Number.isSafeInteger(req.pid) && req.pid > 0 ? req.pid : undefined;
        const paths = this.authGrants.grant(origin, grants, pid !== undefined ? { pid } : undefined);
        if (this.confidentiality) {
          if (envName !== undefined) {
            // Rule 3: the variable's rows (one an earlier launch minted
            // included) take the granted host now.
            syncEnvBindings(this.symbolMap, {
              envBindings: (name) => this.envLawBindings(name),
              envWire: (symbol) => this.envWireHosts.get(symbol),
              fieldGrants: this.fieldGrants,
            }, this.dbPath ?? getSymbolDbPath());
          } else {
            syncRegisteredBindings(this.symbolMap, { resolveLabel: this.labelLookup, paths, fieldGrants: this.fieldGrants }, this.dbPath ?? getSymbolDbPath());
          }
        }
        this.log(`registerAuthGrant: ${origin}: ${grants.map((g) => `${g.field} -> ${g.host}${g.https ? "" : " (http, loopback)"}`).join(", ")}`);
        return { id: req.id, ok: true, result: { granted: grants.length } };
      }
      case "mcpServerTaint": {
        const answer = (verdict: McpServerTaintResultWire["verdict"], extra: Partial<McpServerTaintResultWire> = {}): McpServerTaintResultWire =>
          ({ verdict, candidates: 0, level: null, files: [], apps: [], ...extra });
        const tool = typeof req.tool === "string" ? req.tool : "";
        if (isManduInspectTool(tool) || isManduDeclassifyTool(tool) || isManduPolicyTool(tool)) {
          return { id: req.id, ok: true, result: answer("own") };
        }
        if (!this.confidentiality || typeof req.sessionKey !== "string" || !tool.startsWith("mcp__")) {
          return { id: req.id, ok: true, result: answer("unmapped") };
        }
        // The tool's server: the registered names whose tool prefix it
        // carries, in each agent's spelling (Claude Code keeps `-`, Codex
        // turns it into `_`). More than one name ⇒ ambiguous ⇒ unmapped.
        const matches = (this.mcpServersBySession.get(req.sessionKey) ?? []).filter((s) => mcpToolPrefixes(s.name).some((p) => tool.startsWith(p)));
        const names = [...new Set(matches.map((s) => s.name))];
        if (names.length !== 1) return { id: req.id, ok: true, result: answer("unmapped") };
        const server = names[0]!;
        const argvs = matches.flatMap((s) => mcpArgvSpellings(s.command, s.args));
        const procs = this.provenance.procsWithArgv(req.sessionKey, argvs);
        if (procs.length === 0) return { id: req.id, ok: true, result: answer("unmapped", { server }) };
        const rows: SecretTaintRow[] = [];
        for (const p of procs) rows.push(...this.provenance.treeTaint(p).rows);
        const level = strictestLevel(rows);
        const tally = { server, candidates: procs.length, files: [...new Set(rows.map((r) => r.path))], apps: [...new Set(rows.map((r) => r.app))] };
        if (level !== null) return { id: req.id, ok: true, result: answer("tainted", { ...tally, level }) };
        // Clean only when exactly one process carries the server's argv: a
        // second one (a restart, a subagent, a look-alike a tool call
        // spawned) leaves which one answered unknown.
        if (procs.length !== 1) return { id: req.id, ok: true, result: answer("unmapped", tally) };
        // §11.17, fail-closed: a config file the launcher read has changed
        // since (its re-read has not landed). The server may now run another
        // command line, whose process this registration does not name, and
        // the one process it does name would vouch for it. Unmapped (the
        // session rule) until the re-read registers the new command line.
        const sources = this.mcpSourcesBySession.get(req.sessionKey) ?? [];
        const moved = sources.find((x) => mcpSourceStamp(x.path) !== x.stamp);
        if (moved !== undefined) {
          this.log(`mcpServerTaint: ${tool}: ${moved.path} changed since the launcher read it; the server is unmapped until the re-read`);
          return { id: req.id, ok: true, result: answer("unmapped", { ...tally, configChanged: true }) };
        }
        return { id: req.id, ok: true, result: answer("clean", tally) };
      }
      case "callTaint": {
        // Plan 10 §11.12, the unmapped-command backstop: answered only for a
        // tool the session's spec does not know, with the axis on. A mapped
        // tool keeps its own legs (and its path-derived releases); the proxy
        // asks for any tool whose input merely looks like a command, and (the
        // openai-proxy, §11.13) for every MCP tool. Mandu's own declassify
        // tool answers only the value the human released for the session (its
        // result is checked by declassifyResultTrusted), never a store a cell
        // could have written to: it is answered empty like the mapped tools.
        const unmapped = typeof req.unmappedTool === "string" ? req.unmappedTool : undefined;
        // Plan 10 §11.18 (P0 item 4b, the maintainer's decision 2026-10-07):
        // a tool Mandu has NO mapping for is masked whole, whatever the
        // session read (mapped-tools.ts). One with a mapping the spec does not
        // carry (the gate surface's, policy.yaml `mapped_tools:`) is answered
        // as a tool the spec knows; a registered MCP server's keeps the rules
        // below (§11.13).
        const mapping: ToolMapping | null | undefined = unmapped !== undefined && this.confidentiality ? (req.builtin === true ? "builtin" : this.toolMappingFor(unmapped, req.session)) : undefined;
        if (unmapped !== undefined && mapping === null) {
          const why = requiresGuard(unmapped, resolveInboundSpecId(req.session, this.sessionSpecs)) ? unguardedToolWhy(unmapped) : unmappedToolWhy(unmapped);
          const masked: CallTaintResultWire = { level: "no-model", files: [], apps: [], rule: "secret", mask: [], root: null, denied: [], evidence: "unmapped", why };
          return { id: req.id, ok: true, result: masked };
        }
        if (unmapped !== undefined && (!this.confidentiality || mapping === "surface" || mapping === "policy" || mapping === "harness" || inboundSpecNamesInput(unmapped, req.session, this.sessionSpecs) || isManduDeclassifyTool(unmapped))) {
          const empty: CallTaintResultWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
          return { id: req.id, ok: true, result: empty };
        }
        // The fold of §3.2: the strictest output rule of any taint row in
        // the call's tree, each from its file's reader entry (Plan 13 D3;
        // default `secret`; a program that runs code is always `secret`).
        // Plan 13 D9: only the proxy's ask (the human socket) binds a call;
        // from the data socket the bindings are read as they are.
        // The D9 follow-up: the call binds by the command the proxy recorded
        // for it (execGate, recordCallCommand); the text the agent echoes back
        // (`command`) only names the most-recent-exec guess, which is folded
        // and never lowers a mask. A mismatch is logged: the agent showed the
        // model a different command than the one it was given.
        const echoed = req.command ? execSignature(req.command) : "";
        const tree = this.provenance.callTree(req.callId, {
          ...(echoed !== "" ? { signature: echoed } : {}),
          ...(req.session ? { session: req.session } : {}),
          ...(this.attested(ctx.channel) ? {} : { readOnly: true }),
        });
        // Plan 10 §11.8, "A refusal no process is tied to": the refusals the
        // egress proxy tied to no process, made while this call ran (after
        // callTree, which fixes the call's first ask, the window's end). The
        // kind only; explains, never lowers or raises a mask.
        const unattributedRefusals = this.provenance.unattributedEgressRefusalsFor(req.callId, req.session);
        const t = unattributedRefusals.length === 0 ? tree : {
          ...tree,
          refusedEgress: [...(tree.refusedEgress ?? []), ...unattributedRefusals.map((kind) => ({ app: "", kind, unattributed: true as const }))],
        };
        // Plan 13 D7, a poll tied to this call (`forPoll`, human plane only):
        // its output's symbol is evidence when this call's tree is.
        if (typeof req.forPoll === "string" && req.forPoll !== "" && req.forPoll !== req.callId && this.attested(ctx.channel)) {
          this.provenance.recordPollOf(req.forPoll, req.callId, req.session);
        }
        if (echoed !== "" && this.attested(ctx.channel)) {
          const recorded = this.provenance.callCommandSignatures(req.callId);
          if (recorded.length > 0 && !recorded.includes(echoed)) {
            this.log(`callTaint: ${req.callId}: the echoed command differs from the one the proxy recorded; bound by the recorded one (${t.binding})`);
          }
        }
        // Plan 13 D7, fail-closed: the tree is evidence only when the
        // call-root recorder bound the call (the agent's own exec of the
        // call's shell, matched by the command text the proxy recorded for
        // the call on the human plane). A call it could not bind (no shell
        // exec of the agent matched: a tool with no command such as
        // BashOutput, an agent that runs commands another way, a lost record,
        // a call the proxy recorded no command for)
        // is masked at the level of every raw read of the session while the
        // session holds any; with none there is nothing to mask. A guessed
        // or claimed tree is folded in, never trusted to lower that.
        // Plan 10 §11.8, "Blocked commands": the shim's verdict over each of
        // its runs in the tree, recomputed here from the guard's argv record
        // (the program's name and a kind; explains only, never lowers a mask).
        // A call the recorder did not bind (Codex under its own sandbox:
        // the agent's child is the sandbox helper, never the command's
        // shell) takes the shim runs under the processes that exec'd its
        // recorded command too (`commandShimExecs`; for this line only).
        // A shim run under Codex's network-off sandbox is `codex_sandbox`:
        // that sandbox refused its connection, so it never asked.
        const determined = bindingDetermined(t.binding);
        const byCommand = determined
          ? { shimExecs: [], codexSandboxShims: [] }
          : this.provenance.commandShimExecs(req.callId, { ...(req.session ? { session: req.session } : {}), signatureOf: execSignatureForArgv });
        const shims = [...(t.shimExecs ?? []), ...byCommand.shimExecs];
        const blocked = shims.length > 0
          ? blockedExecFold(shims, this.symbolMap, {
            holdsSecret: (x) => this.secretValueHits(x).length > 0,
            codexSandbox: [...(t.codexSandboxShims ?? []), ...byCommand.codexSandboxShims],
          })
          : [];
        const blockedExec = blocked.length > 0 ? { blockedExec: blocked } : {};
        const held = this.confidentiality && !determined ? this.provenance.heldSessionTaint(req.session) : null;
        if (held !== null && held.level !== null) {
          const rows = [...held.rows, ...t.rows];
          return {
            id: req.id, ok: true,
            result: {
              level: strictestLevel(rows), files: [...new Set(rows.map((r) => r.path))], apps: [...new Set(rows.map((r) => r.app))],
              rule: "secret", mask: [], root: t.root, denied: t.denied, evidence: "session",
              ...(t.refusedEgress ? { refusedEgress: t.refusedEgress as CallTaintResultWire["refusedEgress"] } : {}),
              ...blockedExec,
            } satisfies CallTaintResultWire,
          };
        }
        const apps = [...new Set(t.rows.map((r) => r.app))];
        // Plan 13 D3: per ROW, the rule the reader entry of that row's file
        // gives that row's binary; the fold is the strictest, so the output
        // is released only when every file the tree holds clears its reader.
        // Plan 13 R5: a script row's process that started another program
        // in the tree (a lineage child) is `spawned`: its clear is not taken.
        const rule = t.rows.length === 0 ? { app: "", output: "secret" as const, mask: [] as string[] } : foldRules(t.rows.map((r) => readerOutputRule(r.script !== undefined ? { ...r, spawned: this.provenance.hasChildren(r.procKey) } : r, this.labelLookup(r.path)?.readers)));
        // Plan 10 §11.18, fail-closed: a file whose pieces are unknown (over
        // the bound) is matched by the value backstop only in part, so no
        // output rule releases a call that read it raw.
        const unpieced = rule.output !== "secret" ? [...new Set(t.rows.map((r) => r.path))].filter((p) => this.fileUnpieced(p)) : [];
        if (unpieced.length > 0) this.log(`callTaint: ${req.callId}: ${unpieced.join(", ")} over the piece bound: output masked whole, not ${rule.output} (plan 10 §11.18)`);
        const result: CallTaintResultWire = {
          level: t.level,
          files: [...new Set(t.rows.map((r) => r.path))],
          apps,
          rule: unpieced.length > 0 ? "secret" : rule.output,
          mask: unpieced.length > 0 ? [] : rule.mask ?? [],
          root: t.root,
          denied: t.denied,
          ...(t.refusedEgress ? { refusedEgress: t.refusedEgress as CallTaintResultWire["refusedEgress"] } : {}),
          ...blockedExec,
          // `tree` only for a tree the recorder bound (plan 13 D7)
          ...(this.confidentiality && determined ? { evidence: "tree" as const } : {}),
        };
        // Plan 10 §11.8: the output is (part of) ONE registered file's
        // structured twin. Answered only on evidence: the guard recorded the
        // call's tree (a root) and no process in it opened a secret raw, so
        // nothing in the tree held the bytes the text could have been chosen
        // from. The proxy then lowers the path-derived precaution. (A tree
        // the recorder did not bind reaches here only when the session holds
        // no raw read at all, plan 13 D7.)
        if (unmapped === undefined && this.confidentiality && t.root !== null && t.level === null && typeof req.output === "string" && req.output !== "") {
          const cache = new Map<string, RegisteredTwin | null>();
          // Codex's own head is looked through only when the openai-proxy
          // says the output is a Codex exec result (review of !1604).
          const head = { codexHead: req.codexHead === true };
          const path = structuredTwinExecOutputPath(req.output, (token) =>
            structuredTwinOfField(this.symbolMap, token, { resolveLabel: this.labelLookup, cache }), head);
          if (path !== null) result.twinOf = [path];
          else {
            // "A document's own twin": the output is exactly one labelled
            // document's whole-file twin (its base symbol and the file's
            // own terminator), on the same evidence.
            const whole = wholeFileTwinExecOutputPath(req.output, (token) =>
              wholeFileTwinOfBase(this.symbolMap, token, { homes: this.namedHomes(), resolveLabel: this.labelLookup }), head);
            if (whole !== null) { result.twinOf = [whole]; result.twinWhole = true; }
            else {
              // "A key listing" (2026-10-16): the output holds no
              // token and is the keys of ONE registered file's structured
              // twin, in order (`sed 's/=.*//' .env`), on the same evidence.
              // Only a file the call's command names is a candidate (review
              // of !1604), read where the call started (the guard's record).
              const command = typeof req.command === "string" ? req.command : "";
              const output = req.output;
              const twins = new Map<string, KeyListingTwin | null>();
              // `~` in the command is the launch's HOME when its launcher
              // recorded one (plan 10 §11.13), else this arbiter's.
              let named: string[][] | null = null;
              const candidates = (): string[][] => (named ??= keyListingCandidates(command, this.registeredPathsForKeyListing(), { startDir: this.provenance.callStartDir(req.callId), home: this.sessionHome(req.session) ?? homedir() }));
              const keys = command === "" ? null : structuredTwinKeyListingPath(
                output,
                candidates,
                (path) => {
                  if (!twins.has(path)) {
                    const t = structuredTwinWithSecretsFor(this.symbolMap, path, { resolveLabel: this.labelLookup, pieces: true });
                    twins.set(path, t === null ? null : { path, text: t.text, secrets: t.secrets, pieces: t.pieces ?? [] });
                  }
                  return twins.get(path)!;
                },
                head);
              // "A config with no secret" (plan 10 §11.13, 2026-10-17): the
              // output holds no token and is a piece of the OWN-TEXT twin of
              // ONE registered config the command names (`cat
              // ~/.ssh/config`), on the same evidence.
              const own = keys !== null || command === "" ? null : ownTextTwinExecOutputPath(output, candidates, (path) => this.ownTextOf(path), head);
              if (keys !== null) { result.twinOf = [keys]; result.twinKeys = true; }
              else if (own !== null) { result.twinOf = [own]; result.twinOwn = true; }
              else if (command !== "") {
                // "A folder's names" (2026-10-17): the output is exactly what
                // ONE plain `ls` (no `-l`, no chain or pipe) prints for the
                // folders it names, as they are now (`ls mail/inbox bank/`).
                // A name is not a file's content (plan 13 §4.9); same
                // evidence. The operands are read where the call started, off
                // the echoed command, so it must be the one the proxy
                // recorded for the call when it recorded one.
                const recorded = this.provenance.callCommandSignatures(req.callId);
                const listed = recorded.length > 0 && !recorded.includes(echoed) ? null
                  : plainLsListingPaths(output, command, hostListingFs(this.provenance.callStartDir(req.callId), homedir()), head);
                if (listed !== null) { result.twinOf = listed; result.dirListing = true; }
              }
            }
          }
        }
        if (unmapped !== undefined) {
          if (t.root !== null) return { id: req.id, ok: true, result: { ...result, evidence: "tree" } };
          // No tree: the tool may run its command in-process (an eval tool),
          // through a program the guard never saw, or not on this host. The
          // most its output can carry is what any process of the session read
          // raw, so that is the level, under rule `secret` (no app rule speaks
          // for output the tree cannot attribute). No raw read in the session
          // ⇒ nothing to mask: every other process got the twin. (Plan 13 D7:
          // a session holding a raw read already answered above, unless the
          // recorder bound the call.)
          const s = this.provenance.heldSessionTaint(req.session);
          return {
            id: req.id, ok: true,
            result: {
              level: s.level, files: [...new Set(s.rows.map((r) => r.path))], apps: [...new Set(s.rows.map((r) => r.app))],
              rule: "secret", mask: [], root: null, denied: [], evidence: "session",
            },
          };
        }
        return { id: req.id, ok: true, result };
      }
      case "taintFile": {
        this.provenance.taintFile({
          contentHash: req.contentHash,
          path: req.path,
          originHost: req.originHost,
          writerProc: req.writerProc,
          session: req.session,
        });
        return { id: req.id, ok: true, result: { ok: true } };
      }
      case "registerSecret": {
        // Pre-symbolize a secret so the agent learns its NAME, never its bytes
        // (confidentiality.md §7.2). THE ARBITER READS THE FILE — it runs
        // outside the agent's sandbox, so the bytes never enter the launcher
        // process or this request. Refused while the axis is OFF: minting
        // secret symbols is a confidentiality act, and the OFF wire carries no
        // confidentiality at all (§11).
        if (!this.confidentiality) {
          return {
            id: req.id, ok: true,
            result: { symbol: null, reason: "confidentiality axis is OFF — registration refused" },
          };
        }
        // The launch's login variables (secret-discovery.md §1.10): another
        // agent's login a variable moved out of the catalog's places is
        // registered as the walk found it. Known names, absolute paths only.
        const loginEnv = pickLoginEnv(req.loginEnv);
        // 2026-10-17 (confidentiality.md §6, "A catalog file the launch did
        // not register"): the guard registers a file it gated naming no
        // HOME; one that only a live launch's HOME's catalog calls secret
        // (a new key in a launch's `~/.ssh` under `HOME=/tmp/x mandu`) is
        // registered under that HOME, as `labelledLevel` judged it. Human
        // plane only, and with no wire grant (the launcher's own
        // registration names its HOME and keeps that).
        const inferredHome = req.home === undefined && this.attested(ctx.channel) ? this.launchHomeJudging(req.path) : null;
        const result = registerSecret(
          this.symbolMap,
          {
            path: req.path, sessionKey: req.sessionKey, resolveLabel: this.labelLookup, home: req.home ?? inferredHome ?? undefined, fieldGrants: this.fieldGrants,
            ...(Object.keys(loginEnv).length > 0 ? { loginEnv } : {}),
            // The launch HOME's wire grant only on the human plane (the
            // launcher's own registration): on the data socket the agent's
            // world could name a `home` of its choosing and plant a
            // `.npmrc` there. Accepted with no grant, never refused: the
            // `home` still decides the catalog's `~` places
            // (confidentiality.md §2.1, 2026-10-17).
            wireGrant: attestedChannel(ctx.channel) && inferredHome === null,
          },
          this.dbPath ?? getSymbolDbPath(),
        );
        // Plan 10 §11.13 (2026-10-17): a HOME the launcher named on the
        // human plane is one whose catalog may vouch for a config's own text
        // (`isOwnTextTwin`); a data-socket `home` names nothing.
        const regHome = this.attested(ctx.channel) && result.symbol !== null ? attestedHomeOf(req.home) : null;
        if (regHome !== null && !this.registrationHomes.has(regHome) && this.registrationHomes.size < 64) this.registrationHomes.add(regHome);
        this.log(`registerSecret: ${req.path} → ${result.symbol ?? "none"} (${result.reason})`);
        return { id: req.id, ok: true, result };
      }
      case "registerEnvSecrets": {
        // The environment half of the secret registry (plan 10 §11.4): the
        // launcher's own environment, masked before the agent inherits it.
        // Same axis rule as registerSecret: OFF ⇒ nothing is minted.
        if (!this.confidentiality) {
          return {
            id: req.id, ok: true,
            result: { vars: req.vars.map((v) => ({ name: v.name, symbol: null, reason: "confidentiality axis is OFF — registration refused" })) },
          };
        }
        const dbPath = this.dbPath ?? getSymbolDbPath();
        // The law's `env:` section (plan 10 §11.4): names it adds or exempts,
        // read from the law in force so a policy.yaml edit applies at the
        // next launch with no restart.
        const law = getCurrentPolicy();
        // A sourced variable (env.sources) is a secret whatever its name says,
        // and carries its sources entry's bindings.
        const sources = new Map(law.envSources.map((e) => [e.name, e]));
        // So is a declared model's token (policy.yaml models[].token_env,
        // plan 11 D2), bound to that model's host: the helper sends it there,
        // and the agent's environment carries it masked.
        const modelTokens = modelTokenBindings(law.models);
        const rules = { ...law.envSecrets, secrets: [...(law.envSecrets.secrets ?? []), ...sources.keys(), ...modelTokens.keys()] };
        const vars = req.vars.map((v) => {
          // An auth grant's hosts (agent-sign-in.md §3.8): the variable's
          // row is bound there from its first registration, as rule 3 keeps.
          const granted = this.authGrants.hosts(`env:${v.name}`, v.name);
          const bound = [...new Set([...this.envLawBindings(v.name), ...granted])];
          const bindings = bound.length ? bound : undefined;
          // The agent's own key variable is masked only when the launch
          // asked (`agentKey`) AND holds an auth grant for it, so the model
          // proxy can put the key back; else it stays exempt (raw), as
          // before, and the agent keeps a key it can use.
          const varRules = v.agentKey === true && granted.length > 0 ? { ...rules, agentKeys: [v.name] } : rules;
          const r = registerEnvSecret(this.symbolMap, { name: v.name, value: v.value, sessionKey: req.sessionKey, rules: varRules, ...(bindings ? { bindings } : {}) }, dbPath);
          // The value's own wire host, kept for the bindings sync (rule 3).
          // A registration on the human plane (the launcher's, of its own
          // environment) is RECORDED, so a restarted arbiter keeps it
          // (confidentiality.md §2.1, 2026-10-17); one on the data plane,
          // which the agent's world can reach, stays in this process's
          // memory, as every one did before: the agent never earns a grant
          // that outlives the arbiter.
          if (r.symbol !== null && r.wireHost !== undefined) {
            if (attestedChannel(ctx.channel)) {
              this.envWireHosts.delete(r.symbol);
              recordWireGrant(this.symbolMap, r.symbol, r.wireHost, dbPath);
            } else {
              this.envWireHosts.set(r.symbol, r.wireHost);
            }
          }
          return { name: v.name, symbol: r.symbol, ...(r.twin !== undefined ? { twin: r.twin } : {}), reason: r.reason };
        });
        const masked = vars.filter((v) => v.symbol !== null).map((v) => v.name);
        if (masked.length > 0) this.log(`registerEnvSecrets: masked ${masked.join(", ")}`);
        return { id: req.id, ok: true, result: { vars } };
      }
      case "envSources": {
        // policy.yaml env.sources (comparisons.md §3.4): WHAT the launch
        // should fetch and from where. Never a value: the launcher resolves
        // each source itself and hands the value back to registerEnvSecrets.
        return { id: req.id, ok: true, result: { sources: getCurrentPolicy().envSources.map((e) => ({ name: e.name, source: e.source, bindings: [...e.bindings] })) } };
      }
      case "consumerPacks": {
        // The signed consumer packs in force, and the ones refused (why).
        return { id: req.id, ok: true, result: {
          packs: this.consumerPacks.map((p) => ({ name: p.name, version: p.version, keyId: p.keyId, consumers: p.consumers.length })),
          refused: [...this.consumerPackErrors],
        } };
      }
      case "protectPaths": {
        // policy.yaml protect: (learn-from-nono §4 item 8), as written.
        return { id: req.id, ok: true, result: { paths: [...getCurrentPolicy().protect] } };
      }
      case "guardSettings": {
        // policy.yaml unix_sockets: / write_protect: / remote_mounts:
        // (guard-settings.ts), as written; the launcher expands `~` and
        // hands them to the guard.
        const g = guardSettingsOf(getCurrentPolicy().document);
        return {
          id: req.id, ok: true,
          result: { unixAllow: g.unixAllow, writeProtect: { deny: g.writeDeny, ask: g.writeAsk, unprotect: g.writeUnprotect }, trustLookups: g.trustLookups } satisfies GuardSettingsResult,
        };
      }
      case "gitHistoryLocks": {
        // Plan 14 §8.1/§8.2: what the launcher's object twins hide beyond
        // the confined files. Blob locks above `public`; the human labels
        // whole (policy.yaml + the dashboard's, the map every derivation
        // reads), public ones included: the launcher decides a history path
        // by the same most-specific rule, and a public carve-out is part of
        // it. Axis OFF: nothing is hidden, so nothing is answered.
        //
        // Plan 14 §11.1 R1/R2: the caller's `roots` join the registry
        // (source `launch`), and the answer carries the background
        // resolution: the global locked set, the resolved repositories with
        // their keys, and what is pending.
        if (!this.confidentiality) {
          return {
            id: req.id, ok: true,
            result: { axis: false, blobs: [], labels: [], lockedSet: { sha1: [], sha256: [] }, repos: [], complete: true, pending: [] } satisfies GitHistoryLocksResult,
          };
        }
        const law = getCurrentPolicy();
        const blobs = [...law.blobLocks.values()].filter((b) => b.level !== "public").map((b) => ({ id: b.id, level: b.level }));
        const labels = this.historyLabelsWire();
        const roots = Array.isArray(req.roots) ? req.roots : [];
        const named = this.lockResolver !== null && roots.length > 0 ? this.lockResolver.note(roots, "launch") : [];
        const res = this.lockResolver !== null
          ? this.lockResolver.snapshot(named)
          : { lockedSet: { sha1: [], sha256: [] }, repos: [], complete: false, pending: [] };
        // Plan 14 §11.1 R3: the repositories whose sanitized copies are
        // prepared (present and sealed at the last cycle; the launcher
        // checks each against its own exclusion and the seals), and a
        // summary for the doctor. Absent when preparation is off.
        const prep = this.preparedCopies?.summary();
        const prepared = prep === undefined ? {} : {
          prepared: prep.ready,
          preparation: {
            ready: prep.ready.length, pending: prep.pending, capped: prep.capped, failed: prep.failed,
            ...(prep.paused !== undefined ? { paused: prep.paused } : {}), bytes: prep.bytes, caps: prep.caps, at: prep.at,
          },
        };
        return { id: req.id, ok: true, result: { axis: true, blobs, labels, ...res, ...prepared } satisfies GitHistoryLocksResult };
      }
      // Plan 14 §11.2: the enforcement caches' seals and epochs. Human plane
      // (channelRefusal refused them on the data socket before this point).
      case "cacheSeals": {
        const r = this.cacheSeals.seals(req.kind, req.keys);
        return { id: req.id, ok: true, result: r satisfies CacheSealsResult };
      }
      case "sealCacheEntries": {
        const rejected = Array.isArray(req.rejected) ? req.rejected : [];
        const kinds = /^[a-z][a-z0-9-]{0,40}$/;
        if (rejected.length > 10_000 || !rejected.every((x) => x !== null && typeof x === "object" && typeof x.kind === "string" && kinds.test(x.kind)
          && typeof x.key === "string" && x.key.length > 0 && x.key.length <= 256 && (x.reason === "unsealed" || x.reason === "mismatch"))) {
          throw new Error("sealCacheEntries: rejected is [{kind, key, reason: unsealed | mismatch}]");
        }
        const r = this.cacheSeals.record(req.entries);
        if (rejected.length > 0) this.emitCacheSealEvent("rejected", "cache entries did not match a seal of the current epoch and were rebuilt", rejected);
        // Plan 14 §11.1 R3: a prepared copy a launcher found changed under its
        // seal is rebuilt (an unsealed one is sealed again or rebuilt anyway).
        const mismatched = rejected.filter((x) => x.kind === "object-twin" && x.reason === "mismatch").map((x) => x.key);
        if (mismatched.length > 0) this.preparedCopies?.distrust(mismatched);
        return { id: req.id, ok: true, result: r satisfies SealCacheEntriesResult };
      }
      case "beginLaunch": {
        // GUARD_MAPPED_TOOLS: read BEFORE this launch is on the record (an
        // unwalled one would make its own claim unattested).
        const attestedClaim = this.attested(ctx.channel);
        const r = this.cacheSeals.beginLaunch({
          pid: req.pid, mode: req.mode, posture: req.posture, writeProtect: req.writeProtect === true, homeSealed: req.homeSealed === true,
          ...(typeof req.humanPlaneWalled === "boolean" ? { humanPlaneWalled: req.humanPlaneWalled } : {}),
          ...(typeof req.sessionId === "string" ? { sessionId: req.sessionId } : {}),
          ...(typeof req.workspace === "string" ? { workspace: req.workspace } : {}),
        });
        // The session's guard (mapped-tools.ts GUARD_MAPPED_TOOLS): a launch
        // the cache rules call confined whose posture is `confined` (the file
        // guard serves the agent's own opens the twin), claimed on an attested
        // channel. Any other launch of the session marks it unguarded for good.
        const sid = typeof req.sessionId === "string" ? req.sessionId : "";
        if (sid !== "") {
          if (attestedClaim && r.confined && req.posture === "confined") this.guardedLaunches.set(r.token, sid);
          else this.unguardedSessions.add(sid);
          // Plan 10 §11.13 (2026-10-17): the launch's HOME, the catalog's `~`
          // for this session's opens (`decideSecretOpen`). Attested only:
          // nothing on the data socket names a session's HOME.
          const home = attestedHomeOf(req.home);
          if (attestedClaim && home !== null && this.launchHomes.size < 1024) this.launchHomes.set(r.token, { session: sid, home });
        }
        this.refreshExposure();
        return { id: req.id, ok: true, result: r satisfies BeginLaunchResult };
      }
      case "endLaunch": {
        if (typeof req.token === "string") { this.guardedLaunches.delete(req.token); this.launchHomes.delete(req.token); }
        const r = this.cacheSeals.endLaunch(req.token);
        this.refreshExposure();
        return { id: req.id, ok: true, result: r satisfies EndLaunchResult };
      }
      case "humanPlaneStatus": {
        // arbiter-human-plane.md §10.1.1: display only; the belief rule
        // (`attested`) reads the same exposure and is not changed by it.
        return { id: req.id, ok: true, result: this.humanPlaneStatus() satisfies HumanPlaneStatusResult };
      }
      case "readerProgram": {
        // Plan 13 D8 (2026-10-03): what this arbiter knows a binary to be,
        // judged as every reader list judges it: by its name and path, and
        // by the hashes of the host's installed printers and code-running
        // programs (`binaryPrints`, `binaryRunsCode`, `renamedCopyOf`). The
        // guard asks it for a secret socket's reader (the ssh-agent), whose
        // list it otherwise judged by name only. Decides nothing; read-only.
        if (typeof req.exe !== "string" || req.exe === "") return { id: req.id, ok: false, error: "readerProgram: exe must be a non-empty string" };
        if (req.sha256 !== undefined && (typeof req.sha256 !== "string" || !/^[0-9a-fA-F]{64}$/.test(req.sha256))) {
          return { id: req.id, ok: false, error: "readerProgram: sha256 must be 64 hex digits" };
        }
        refreshProgramHashes({ minIntervalMs: 600_000 });
        const b = { exe: req.exe, ...(req.sha256 !== undefined ? { sha256: req.sha256.toLowerCase() } : {}) };
        return { id: req.id, ok: true, result: { prints: binaryPrints(b), runsCode: binaryRunsCode(b), copyOf: renamedCopyOf(b)?.of ?? null } satisfies ReaderProgramOpResult };
      }
      case "sshAgentPolicy": {
        // policy.yaml ssh_agent (comparisons.md §3.5): the readers the
        // launcher hands the guard for $SSH_AUTH_SOCK; null = ungated.
        return { id: req.id, ok: true, result: { readers: getCurrentPolicy().sshAgentReaders } };
      }
      case "envSecretNames": {
        // The names-only dry run (secret-discovery.md §1.3): no
        // values cross the socket, nothing is minted, the law in force decides.
        const rules = getCurrentPolicy().envSecrets;
        const matched = req.names.filter((n) => envSecretNameMatches(n, rules));
        return { id: req.id, ok: true, result: { matched } };
      }
      case "confidentialityState": {
        // The dashboard's one call: the switch + the standing release surface
        // (§6). Deliberately carries NO secret values — this panel shows what
        // is confined and where it may go, not what is inside.
        //
        // The LABELS are part of that surface, not a separate concern: every
        // `model-ok` label is a standing grant of model readability, and every
        // `public` label on a catalog-matching path is a standing
        // declassification. §6 requires both be visible.
        return {
          id: req.id, ok: true,
          result: {
            enabled: this.confidentiality,
            secrets: this.confidentiality
              ? listSecretRegistry(this.symbolMap).map((e) => {
                  // A reader list, when one exists (an EMPTY list is a list:
                  // every program is then `others`, deny unless the label says
                  // twin, §3.3), so the panel can tell "no list" from "none".
                  const label = this.labelLookup(e.path);
                  const readers = label?.readers;
                  return {
                    ...e,
                    // Plan 13 D8 (2026-10-03): per entry, whether it admits
                    // nothing as this arbiter judges it (a pin's hash
                    // included), so the panel need not judge by name.
                    ...(readers ? { readers: readers.map((r) => (typeof r === "string" ? r : r.app)), readersAdmitNothing: readers.map((r) => entryAdmitsNothing(r)), readersReadTwin: readers.map((r) => entryReadsTwin(r)), others: label?.others ?? "deny" } : {}),
                  };
                })
              : [],
            taintedProcesses: this.confidentiality ? this.provenance.listSecretTaint(100) : [],
            labels: [...this.humanLabels().values()].map((l) => ({
              path: l.path,
              level: l.confidentiality,
              bindings: l.bindings,
              recursive: l.recursive,
              source: l.source,
              ...(l.glob ? { glob: true } : {}),
              updatedAt: l.updatedAt,
              // Is this label WEAKER than what the catalog would have said? That
              // is a declassification, and the surface must say so.
              declassifies: this.declassifies(l.path, l.confidentiality, l.glob),
            })),
            // The DERIVED surface (Plan 9): files a HIGH session wrote, labeled on
            // disk at its watermark. Kept apart from `labels` because those are
            // human decisions and these are machine taint records — and because
            // §8's release UI acts on THESE, with the provenance (which session,
            // which tool) that tells a human what fed the artifact.
            derived: this.confidentiality ? this.derivedLabels.list().map((d) => {
              const effective = pathConfidentiality(d.path, undefined, this.labelLookup);
              return {
                path: d.path,
                level: d.confidentiality,
                bindings: d.bindings,
                sessionKey: d.sessionKey,
                tool: d.tool,
                updatedAt: d.updatedAt,
                effective: effective.level,
                overridden: effective.level !== d.confidentiality,
              };
            }) : [],
          },
        };
      }
      case "setPathLabel": {
        // The labeling act (§6 item 2) — and the ONLY producer of
        // `any-model` in the system.
        const row = this.pathLabels.set({
          path: req.path,
          confidentiality: req.confidentiality,
          bindings: req.bindings,
          recursive: req.recursive,
        });
        if (row === null) {
          return {
            id: req.id, ok: false,
            error: `invalid label: path must be absolute and level one of public|any-model|local-model|no-model`,
          };
        }
        const declassifies = this.declassifies(row.path, row.confidentiality);
        this.log(
          `setPathLabel: ${row.path} → ${row.confidentiality}` +
          `${declassifies ? " (DECLASSIFICATION — weaker than the catalog)" : ""}`,
        );
        return {
          id: req.id, ok: true,
          result: {
            path: row.path,
            level: row.confidentiality,
            bindings: row.bindings,
            recursive: row.recursive,
            declassifies,
          },
        };
      }
      case "declassifySymbol": {
        // §3.3 RUNG 3 — the IN-CONTEXT READ. An EXPLICIT, named, logged act:
        // nothing auto-desymbolizes into T-LLM's context (that would delete
        // symbol opacity, the one invariant). The model must ask, by name, and
        // this is where the asking is answered.
        //
        // Split from `inspect_symbol` deliberately (Plan 8 decision 1): two
        // tools, so the escalation from "process it in the quarantine" (rung 2,
        // no watermark, preferred) to "put it in my context" (rung 3, watermark)
        // is a decision the model makes on purpose and the human can see.
        if (!this.confidentiality) {
          return {
            id: req.id, ok: false,
            error: "confidentiality axis is OFF — there are no secret symbols to declassify",
          };
        }
        const entry = getSymbolEntry(this.symbolMap, req.symbol);
        if (!entry) {
          return { id: req.id, ok: false, error: `unknown symbol: ${req.symbol}` };
        }
        const sess = this.sessionLabels.get(req.sessionKey);
        // The strictest level of every labelled source of the value
        // (value-sources.ts).
        const entryLevel = valueSourceLevel(this.symbolMap, entry);
        let decision = decideDeclassify({
          level: entryLevel,
          integrity: parseIntegrityLabel(entry.integrity),
          sessionUntrustedTainted: sess.untrustedTainted,
          // Plan 11 phase 3: local only when the launcher bound this session
          // to a `models:` entry that the law in force declares `local: true`.
          tllmLocation: this.tllmLocationOf(req.sessionKey),
        });

        // A HUMAN VERDICT on an approval-gated read (plan 11 §6): the queued
        // question is answered on the dashboard and the model retries. Without
        // this consultation the retry only queued the question again, so an
        // approved read could never complete. Consulted ONLY when approval is
        // what stands in the way: no verdict opens a hard refusal (untrusted
        // data, no-model, local-model under an outside model).
        if (!decision.allow && decision.requiresApproval) {
          // Spent from any channel: its one caller, the quarantined inspect
          // child, runs in the agent's tree by design (arbiter-human-plane.md
          // §10.3), and the read it completes is itself the human's answer.
          const prior = this.consultPriorVerdict(req.symbol, IN_CONTEXT_READ, true);
          if (prior?.status === "approved") {
            decision = { ...decision, allow: true, requiresApproval: false, reason: `approved by the user (${prior.scope}): ${decision.reason}` };
          } else if (prior?.status === "denied") {
            this.log(`declassifySymbol: REFUSED ${req.symbol} — the user declined (${prior.id})`);
            return {
              id: req.id, ok: true,
              result: { value: null, allowed: false, requiresApproval: false, reason: "the user declined to show this to the model" },
            };
          }
        }

        if (!decision.allow) {
          // Approval-gated (§9 rule 2's session half) → queue it, exactly like a
          // network egress. The synthetic destination keys the approval to the
          // ACT rather than to a host — the fs-gate's precedent (`fs:<tool>:<mode>`).
          if (decision.requiresApproval) {
            this.egressApprovals.recordPending(
              req.symbol, IN_CONTEXT_READ, decision.reason,
              req.sessionKey,
            );
          }
          this.log(`declassifySymbol: REFUSED ${req.symbol} — ${decision.reason}`);
          return {
            id: req.id, ok: true,
            result: {
              value: null,
              allowed: false,
              requiresApproval: decision.requiresApproval,
              reason: decision.reason,
            },
          };
        }

        // ALLOWED. Raise the watermark BEFORE handing over the content: §4 is
        // explicit that granting the read and skipping the watermark "is
        // theater", and an exception between the two would be exactly that.
        const level = entryLevel;
        if (req.sessionKey) {
          // The symbol is recorded as the session's source, so the session's
          // bindings follow its row under a changed law (§2.1, §4).
          const raised = this.raiseSessionLevel(req.sessionKey, level, entry.bindings ?? [], findSymbolByName(this.symbolMap, req.symbol)?.name);
          this.log(`declassifySymbol: ALLOWED ${req.symbol} → session ${req.sessionKey} is now HIGH (${raised.confidentiality})`);
        } else {
          // No session key ⇒ no watermark can be attributed ⇒ we cannot confine
          // what follows. Refuse rather than hand over content we could not then
          // contain.
          return {
            id: req.id, ok: true,
            result: {
              value: null, allowed: false, requiresApproval: false,
              reason: "fail-closed: no sessionKey — an in-context read that cannot be watermarked cannot be confined",
            },
          };
        }
        // The CONTENT, not the next wrapper (model-endpoints.md §1.6, the
        // confidentiality-axis twin): a symbol's value can itself be a symbol
        // (the agent Reads a labeled file through its AgentView twin, whose
        // bytes are the registered row's token, and the proxy symbolizes that
        // result again), and a one-level resolve handed the model a fresh
        // token instead of the file. Nesting follows admission, as for rung 2
        // (plan 11 D3): a nested symbol opens only when ITS OWN rung-3
        // decision, in this session, allows it (its level admits this T-LLM,
        // its integrity is trusted, no approval is pending on it); any other
        // stays an opaque token. Each one opened raises the watermark with its
        // level and bindings, before the value is handed over.
        const shallow = resolveSymbol(this.symbolMap, req.symbol);
        const tllmLocation = this.tllmLocationOf(req.sessionKey);
        const opened = new Set<SymbolEntry>();
        const released = typeof shallow === "string"
          ? resolveAllSymbolsDeep(shallow, this.symbolMap, undefined, (e) => {
            const nested = decideDeclassify({
              level: valueSourceLevel(this.symbolMap, e),
              integrity: parseIntegrityLabel(e.integrity),
              sessionUntrustedTainted: sess.untrustedTainted,
              tllmLocation,
            });
            if (!nested.allow) return true;
            opened.add(e);
            return false;
          })
          : shallow;
        let watermark = decision.watermark;
        // Each opened row's name, so the session records it as a source.
        const openedNames = new Map<SymbolEntry, string>();
        if (opened.size > 0) {
          for (const [n, e] of this.symbolMap.symbols) if (opened.has(e)) openedNames.set(e, n);
        }
        for (const e of opened) {
          const nestedLevel = valueSourceLevel(this.symbolMap, e);
          const raised = this.raiseSessionLevel(req.sessionKey, nestedLevel, e.bindings ?? [], openedNames.get(e));
          watermark = watermark === null ? nestedLevel : maxConfidentiality(watermark, nestedLevel);
          this.log(`declassifySymbol: a nested ${nestedLevel} symbol (${e.origin ?? e.tool}) opened with ${req.symbol}; session ${req.sessionKey} is ${raised.confidentiality}`);
        }
        if (typeof released === "string") {
          // Remember exactly what was released to whom: the tool result that
          // carries it back through the model proxy is trusted only when it is
          // this value, for this session (declassifyResultTrusted).
          let grants = this.declassifyGrants.get(req.sessionKey);
          if (!grants) this.declassifyGrants.set(req.sessionKey, (grants = new Map()));
          grants.set(req.symbol, released);
        }
        return {
          id: req.id, ok: true,
          result: {
            value: released,
            allowed: true,
            requiresApproval: false,
            reason: decision.reason,
            watermark,
          },
        };
      }
      case "sessionEgressDecision": {
        // What a HIGH session may still do (§4). Consulted IN ADDITION to the
        // per-symbol egress gate, because a PARAPHRASE carries no symbol and the
        // per-symbol gate cannot see it.
        if (!this.confidentiality) {
          return {
            id: req.id, ok: true,
            result: { allow: true, requiresApproval: false, reason: "confidentiality axis is OFF" },
          };
        }
        // The human half (confidentiality.md §4, 2026-10-11): a refusal that
        // needs a human files an Approvals row (session × host); a prior
        // answer decides the retry. Only an attested ask (the proxy's human
        // client) spends an Allow once.
        const verdict = this.decideSessionEgressWithApprovals(
          { sessionKey: req.sessionKey, boundary: req.boundary, destination: req.destination, netEnabled: req.netEnabled },
          attestedChannel(ctx.channel),
        );
        return { id: req.id, ok: true, result: verdict };
      }
      case "strippedPlaceholders": {
        // confidentiality.md §7, "A placeholder the agent's shell would
        // expand": which of these names (the net-proxy rebuilt them from text
        // that lost its `$MDU` to a shell) are secret-labelled rows. Names
        // only, never a value, label or binding: the same existence answer
        // `desymbolizationDecision` gives on this socket. The level is the
        // ROW's, never the name's marker. Axis OFF: no secret rows, none found.
        const cands = req.candidates;
        if (!Array.isArray(cands) || cands.length > STRIPPED_PLACEHOLDERS_MAX || cands.some((c) => typeof c !== "string" || c.length > 512)) {
          return { id: req.id, ok: false, error: `strippedPlaceholders: candidates must be at most ${STRIPPED_PLACEHOLDERS_MAX} strings` };
        }
        const found: string[] = [];
        if (this.confidentiality) {
          for (const c of cands as string[]) {
            if (found.includes(c) || !WHY_SYMBOL_RE.test(c)) continue;
            // The lookup the egress gate and `resolve` use (a glued trailing
            // dot-run trims; an invented field never falls back to a file's
            // whole-value row).
            const hit = findSymbolByName(this.symbolMap, c);
            if (hit && isSecret(parseConfidentialityLevel(hit.entry.confidentiality))) found.push(c);
          }
        }
        return {
          id: req.id, ok: true,
          result: { found, ...(found.length > 0 ? { ruleRef: ruleRef("egress:shell-expanded-placeholder") } : {}) },
        };
      }
      case "relayNotice": {
        // devtools-relay.md §3.4: a refusal the relay reports, kept for the
        // browser agent's next model call. Checked field by field (kinds,
        // a host, placeholder names): never free text, never a value. Not an
        // axis matter: a hint for the model, no secret in it.
        const notice = parseRelayNotice((req as { notice?: unknown }).notice);
        if (typeof notice === "string") return { id: req.id, ok: false, error: `relayNotice: ${notice}` };
        const key = typeof req.sessionKey === "string" ? req.sessionKey : "";
        this.relayNotices.add(key, notice);
        return { id: req.id, ok: true, result: { queued: true } };
      }
      case "placeholderKnown": {
        // devtools-relay.md §3.3: the relay asks on the key that closes a
        // typed placeholder's code, and refuses that key when no row has the
        // base (no name the agent could go on to type resolves). A base only,
        // names only. Not an axis matter: it reads the table, as `resolve`.
        const base = (req as { base?: unknown }).base;
        if (typeof base !== "string" || !PLACEHOLDER_BASE_RE.test(base)) {
          return { id: req.id, ok: false, error: "placeholderKnown: base must be one placeholder's base ($MDU:kind[code], no field path)" };
        }
        return { id: req.id, ok: true, result: { known: placeholderBaseKnown(this.symbolMap, base) } };
      }
      case "takeRelayNotices": {
        // The egress proxy's take on a model-service call: the session's
        // pending notices, cleared (each told once).
        const key = typeof req.sessionKey === "string" ? req.sessionKey : "";
        return { id: req.id, ok: true, result: { notices: this.relayNotices.take(key) } };
      }
      case "egressFingerprintScan": {
        // The §4 verbatim-leak TRIPWIRE. Scans the outbound surfaces against
        // the arbiter's known SECRET values (never public — a public value on
        // the wire is not a leak). Axis OFF ⇒ inert (no secrets exist). This
        // BACKS the symbol gates; it is not the guarantee, so it only ever adds
        // a block on a positive hit and never fails a benign request.
        if (!this.confidentiality) {
          return { id: req.id, ok: true, result: { tripped: false, hits: [] } };
        }
        // One pass per surface over the value index (plan 15 §4.1); the same
        // answer as scanEgressFingerprint over the active secret rows, which
        // its equivalence test pins.
        // The logins the asking SESSION leaves raw (secret-discovery.md
        // §1.10, the net-proxy's `sessionLogins`): registration is global and
        // durable, so another session's launch may have registered them; in
        // this session their registered rows are inert here, as they were
        // before any launch registered them. Login files only
        // (`sessionLoginPaths`), registered-file rows only.
        const kept = this.sessionLoginExemptions(req.sessionLogins);
        const fingerprintOf = (name: string): SecretFingerprint | null => {
          const entry = this.symbolMap.symbols.get(name);
          if (!entry || entry.obsoleted_at != null) return null;
          const level = parseConfidentialityLevel(entry.confidentiality);
          if (!isSecret(level)) return null;
          // An MCP config's HTTP server credential (secret-discovery.md
          // §2.10): the session's agent sends it raw, to the host of the
          // entry's own URL only, so in that session it is exempt there and
          // nowhere else (the narrower exemption; any other kept row, as
          // before, everywhere).
          const keptHost = kept.length > 0 && isRegisteredFileRow(entry) && originUnder(entry.origin ?? "", kept) ? this.keptRowWireHost(name, entry) : undefined;
          if (keptHost === null) return null;
          // Bound where any labelled source of the value binds it, as the
          // egress gate releases it (value-sources.ts).
          const view = this.releaseView(entry);
          const bindings = view.bindings ?? [];
          return { symbol: name, value: entry.value, level: parseConfidentialityLevel(view.confidentiality), bindings: keptHost === undefined ? bindings : [...bindings, keptHost] };
        };
        // §2.10: a value of the session's agent's own MCP config is that
        // agent's (or its server's) own traffic wherever it shows up in the
        // index, also as a piece of a tool result's row (a masked Read of
        // the config the model made, which outlives the session): exempt
        // where its row is, never a longer text around it.
        const ownMcp = this.keptMcpValues(kept);
        const dest = req.destination ?? "";
        const exemptText = ownMcp.size === 0 ? undefined : (text: string, symbol: string): boolean => {
          if (!ownMcp.has(text)) return false;
          const host = ownMcp.get(text)!;
          if (host !== null && (dest === "" || !destinationMatchesBindings(dest, [host]))) return false;
          // Never for another source the user's setup registered with the
          // same value (another file's row, a masked variable): that row
          // keeps its own rule. A kept row's own answer is fingerprintOf's.
          const e = this.symbolMap.symbols.get(symbol);
          if (e === undefined) return false;
          if (envRowVariable(e) !== null) return false;
          return !isRegisteredFileRow(e) || originUnder(e.origin ?? "", kept);
        };
        const hits = scanEgressFingerprintIndexed(req.surfaces ?? [], this.syncedValueIndex(), fingerprintOf, dest, exemptText);
        return {
          id: req.id, ok: true,
          result: { tripped: hits.length > 0, hits },
        };
      }
      case "sessionState": {
        const st = this.sessionLabels.get(req.sessionKey);
        return {
          id: req.id, ok: true,
          result: {
            sessionKey: st.sessionKey,
            confidentiality: this.confidentiality ? st.confidentiality : "public",
            untrustedTainted: this.confidentiality ? st.untrustedTainted : false,
            bindings: this.confidentiality ? st.bindings : [],
            high: this.confidentiality && st.confidentiality !== "public",
          },
        };
      }
      case "labelWrittenPath": {
        // §4 bullet 2 / §8 (Plan 9) — THE CROSS-SESSION HALF OF THE WATERMARK.
        // A high session is about to write a file. Its bytes may be derived from
        // the secret content the model read into context, and the watermark that
        // confines them is SESSION state: it dies with the process. So we persist
        // it as an on-disk label BEFORE the bytes land, and every future classify
        // of that path (which funnels through `labelLookup`) sees it.
        //
        // Inert while the axis is OFF and for a session that is not high — the
        // no-regression fold: nothing changes for anyone who is not doing the one
        // thing this exists to confine.
        if (!this.confidentiality) {
          return {
            id: req.id, ok: true,
            result: {
              labeled: false, refused: false, level: "public", bindings: [],
              reason: "confidentiality axis is OFF",
            },
          };
        }
        // The SESSION first: whether we can label the path only MATTERS when the
        // session is high, and the answer decides whether the caller may proceed.
        const sess = this.sessionLabels.get(req.sessionKey);
        const norm = normalizeLabelPath(req.path);
        if (sess.confidentiality === "public") {
          // Not high ⇒ nothing to persist, whatever the path looks like. Inert,
          // byte-identical to the pre-Plan-9 system.
          const base = norm === null
            ? { level: "public" as const, bindings: [] as string[] }
            : pathConfidentiality(norm, undefined, this.labelLookup);
          return {
            id: req.id, ok: true,
            result: {
              labeled: false, refused: false, level: base.level, bindings: base.bindings,
              reason: "session is not high (no in-context secret read) — nothing to persist",
            },
          };
        }
        if (norm === null) {
          // A HIGH session writing a path we cannot key (a relative path has no
          // stable identity, and we do not GUESS one). We cannot record the label,
          // so the write must not happen: `refused` tells the caller to fail
          // closed. Silently skipping here would be the laundering hole with a
          // different spelling.
          return {
            id: req.id, ok: true,
            result: {
              labeled: false, refused: true, level: "public", bindings: [],
              reason:
                "REFUSED: the session is HIGH and this path has no stable identity " +
                "(not absolute) — it cannot be labeled, so it must not be written",
            },
          };
        }
        const base = pathConfidentiality(norm, undefined, this.labelLookup);
        if (maxConfidentiality(base.level, sess.confidentiality) === base.level) {
          // Already classified at or above the watermark (a `.env` the catalog
          // calls strict, a path the human labeled). Recording a LOWER derived row
          // would be a machine-authored declassification; recording an equal one
          // would be noise.
          return {
            id: req.id, ok: true,
            result: {
              labeled: false, refused: false, level: base.level, bindings: base.bindings,
              reason: `path already classifies at or above the watermark (${base.rule ?? "no rule"})`,
            },
          };
        }
        // NO BINDINGS: the taint carries the LEVEL and nothing else. Inheriting the
        // session's bound sinks would let a machine mint a STANDING RELEASE — a
        // future session could then egress the derived file to those sinks with no
        // human in the loop, where before the write it needed approval. §8 says
        // derived data inherits the source's LEVEL; §6 says every release is a
        // human act. See derived-labels.ts.
        const row = this.derivedLabels.raise(norm, sess.confidentiality, {
          sessionKey: sess.sessionKey,
          tool: req.tool ?? null,
        });
        // Re-resolve: an EXACT human label on this path overrides the taint (§8's
        // first-class declassification — the release is the human's to make). The
        // record still stands; the UI shows it as overridden. `level` is the truth
        // a future session will see, which is the only number worth reporting.
        const after = pathConfidentiality(norm, undefined, this.labelLookup);
        const suppressed = row !== null && after.level !== row.confidentiality;
        this.log(
          `labelWrittenPath: ${norm} ← ${req.tool ?? "?"} in HIGH session ${sess.sessionKey} ` +
          `(${sess.confidentiality}) → derived ${row?.confidentiality ?? "none"}, effective ${after.level}` +
          `${suppressed ? " (SUPPRESSED by an exact user label)" : ""}`,
        );
        return {
          id: req.id, ok: true,
          result: {
            labeled: row !== null,
            refused: false,
            level: after.level,
            bindings: after.bindings,
            reason: suppressed
              ? `derived label recorded at the watermark (${row?.confidentiality}) but SUPPRESSED by your explicit label on this path (${after.rule}) — the release is yours`
              : `on-disk label recorded at the session watermark (${after.level}) — future sessions classify it there (§4/§8)`,
          },
        };
      }
      case "removeDerivedLabel": {
        // §8's declassification, the blunt form: forget that a high session wrote
        // this file. (The other form is an exact-path user label, which overrides
        // the record without destroying it.)
        const removed = this.derivedLabels.remove(req.path);
        this.log(`removeDerivedLabel: ${req.path} → ${removed ? "cleared" : "no such record"}`);
        return { id: req.id, ok: true, result: { removed } };
      }
      case "removePathLabel": {
        const removed = this.pathLabels.remove(req.path);
        this.log(`removePathLabel: ${req.path} → ${removed ? "removed" : "no such label"}`);
        return { id: req.id, ok: true, result: { removed } };
      }
      case "pathLabels": {
        return {
          id: req.id, ok: true,
          result: {
            labels: [...this.humanLabels().values()].map((l) => ({
              path: l.path,
              level: l.confidentiality,
              bindings: l.bindings,
              recursive: l.recursive,
              source: l.source,
              ...(l.glob ? { glob: true } : {}),
              updatedAt: l.updatedAt,
              declassifies: this.declassifies(l.path, l.confidentiality, l.glob),
            })),
          },
        };
      }
      case "secretRegistry": {
        const entries = this.confidentiality ? listSecretRegistry(this.symbolMap) : [];
        return { id: req.id, ok: true, result: { entries } };
      }
      case "discoverSecrets": {
        // Filesystem discovery — never answers a secret. Since 2026-10-19 it
        // reads small config files for the catalog's content tier
        // (found-labels.ts, secret-discovery.md §2.6) and records their
        // found labels (`recordFound`); the answer holds paths and fields.
        // Consults the USER labels too (Plan 6): a file under a labeled
        // directory is discovered and twinned by this same walk, and one the
        // human labeled `public` is excluded from it.
        // The full report (secret-discovery.md §1.3): `files` as
        // before, plus the "not covered" ledger — skipped candidates with a
        // reason, per-reason counts, the caps, and whether a cap truncated the
        // walk. Old clients read `files` and ignore the rest.
        // The declared model client keys are roots of their own (plan 12 D3,
        // `discoveryJob`). Over the socket this op runs on a worker thread instead
        // (`dispatchDiscoverSecrets`); a direct `dispatch` walks in-process.
        const job = this.discoveryJob(req);
        return { id: req.id, ok: true, result: job ? this.recordFound(runDiscoveryJob(job)) : EMPTY_DISCOVERY };
      }
      case "scanAgentTranscripts":
        // Asynchronous (it reads files): the socket path answers it
        // (handleLine → scanAgentTranscriptsOp).
        return { id: req.id, ok: false, error: "scanAgentTranscripts is asynchronous: call it over the socket, or await scanAgentTranscriptsOp" };
      case "scanSecretHistory":
        // Asynchronous (git child processes): the socket path answers it
        // (handleLine → scanSecretHistoryOp); an in-process caller awaits
        // `scanSecretHistoryOp` itself.
        return { id: req.id, ok: false, error: "scanSecretHistory is asynchronous: call it over the socket, or await scanSecretHistoryOp" };
      case "registerRepository":
        // Asynchronous (the root is validated by git): the socket path
        // answers it (handleLine → registerRepositoryOp).
        return { id: req.id, ok: false, error: "registerRepository is asynchronous: call it over the socket, or await registerRepositoryOp" };
      case "fileTrust": {
        const result = this.provenance.fileTrust({
          contentHash: req.contentHash,
          path: req.path,
        });
        return { id: req.id, ok: true, result };
      }
      default: {
        const op = (req as { op?: string }).op;
        return { id: (req as ArbiterRequest).id, ok: false, error: `unknown op: ${op}` };
      }
    }
  }

  /**
   * The egress gate wrapped by the interactive approval queue.
   *
   * The pure decision (`policy.desymbolizationDecision` → `decideDesymbolization`)
   * stays a stateless oracle; the queue mutation lives HERE, in the stateful
   * arbiter hub. Only NETWORK egress is queued (other boundaries pass through
   * unchanged, preserving the existing allow/deny behavior).
   *
   * For a NETWORK egress with a concrete destination:
   *   1. consult a prior human verdict for {symbol, destination} (via
   *      consultPriorVerdict, which also enacts verdict SCOPE — a "once"
   *      verdict is spent by this consultation when it comes from an
   *      attested channel, and only read otherwise (arbiter-human-plane.md
   *      §10.3); a spent one reads as no prior):
   *        approved → allow (reason "human-approved");
   *        denied   → deny WITHOUT approval (reason "human-denied");
   *   2. otherwise run the pure gate. If it requires approval, UPSERT a pending
   *      entry (idempotent by key) and return the original deny verdict.
   *
   * The request's `sessionKey` (attribution only — the pure gate ignores it) is
   * stamped onto any queued row (EgressApproval.sessions).
   */
  /**
   * Build the engine-backed policy for a document (undefined = load
   * `policyPath` from disk; null = built-ins). Every closure below is LIVE over
   * this server's stores, so a rebuilt policy sees the same symbol table,
   * labels and exec verdicts — only the law changes.
   */
  private buildPolicy(document: PolicyFileConfig | null | undefined, quiet = false): PolicyEngine {
    return createEngineBackedPolicy({
      policyPath: this.policyPathOpt,
      ...(document !== undefined ? { policyFileOverride: document } : {}),
      log: quiet ? { info: () => {}, warn: () => {} } : { info: (m) => this.log(m), warn: (m) => this.log(m) },
      // The egress gate resolves a symbol name → its provenance so it can tell
      // an active (untrusted) symbol from an unknown/obsolete one.
      // The candidate walk, NOT a raw map.get: the gate's notion of "known"
      // must match resolution's (findSymbolByName), or a model-mutated token
      // could be unknown to the decision yet resolvable on a gated surface.
      // A value several labelled sources hold is judged by all of them
      // (value-sources.ts): the strictest level, the union of the bindings.
      symbolLookup: (sym) => {
        const e = findSymbolByName(this.symbolMap, sym)?.entry;
        return e ? this.releaseView(e) : undefined;
      },
      // The read-twin rule's EXACT allocation test — deliberately NOT the
      // candidate walk above: a token with an invented field tail resolves
      // under the walk, and forwarding it raw would let a forged file pass
      // identifier-shaped text to the model as "a symbol".
      symbolAllocated: (sym) => this.symbolMap.symbols.has(sym),
      // The structured read-twin rule (plan 10 §2.4): the twin text the
      // registry minted for a path, re-rendered from the live symbol table.
      twinRendering: (path) => structuredTwinWithSecretsFor(this.symbolMap, path, { resolveLabel: this.labelLookup }),
      // The read leg of "A document's own twin" (plan 10 §11.8): the
      // whole-file twin the guard serves for a labelled document now.
      // Under the HOMEs the human plane named too, as the own-text leg below.
      wholeFileTwin: (path) => wholeFileTwinFor(this.symbolMap, path, { homes: this.namedHomes(), resolveLabel: this.labelLookup }),
      // The read leg of "A config with no secret" (plan 10 §11.13): the
      // own-text twin the guard serves for a registered config now.
      ownTextTwin: (path) => this.ownTextOf(path),
      // Plan 10 §11.13: a session's launch HOME, as its launcher recorded it.
      sessionHome: (sessionKey) => this.sessionHome(sessionKey),
      // The confidentiality derivation consults the USER labels first (§6: the
      // catalog is a DEFAULT; an explicit human label is authoritative for its
      // path), RAISED by any derived taint (§8). Closes over the live stores, so
      // a label set mid-session takes effect on the next classify with no restart.
      labelLookup: this.labelLookup,
      // Exec-output rung 2 (exec-routing.md §8.5): classify consults the
      // per-invocation CLEAN verdicts this server records from the exec
      // supervisor. Live closure — a verdict reported between two classifies
      // is visible to the second with no restart.
      execCleanLookup: (callId) => this.execCleanVerdicts.lookup(callId),
      // This server's session→spec bindings, the SAME object across rebuilds:
      // a policy reload must not forget (and so re-open) a bind-once binding.
      sessionSpecs: this.sessionSpecs,
      // Server and engine must never disagree on the axis switches.
      confidentiality: this.confidentiality,
      integrity: this.integrity,
    });
  }

  /** Swap the law in force for a validated document (policy-document-store.ts
   *  calls this after an apply or a disk reload). The compiled policy is swapped
   *  inside createEngineBackedPolicy; the origin classifiers are rebuilt with it. */
  /**
   * Run `fn` against a HYPOTHETICAL law (the Describe box's "Try it"): build
   * an engine for `document`, which swaps the process-wide compiled law,
   * run `fn`, and restore both the engine and the law in `finally`. Safe
   * only because it is SYNCHRONOUS: dispatch is sync and `fn` must be too, so
   * no other request can observe the hypothetical law.
   */
  /**
   * `mandu why` (tour item 17): the pending changes in Approvals (a held
   * policy.yaml edit, a proposal, a suggestion) under whose law `answer`
   * would come out differently, each with `describe` of that answer. Read
   * only: each law is built aside (`withHypotheticalLaw`) and the law in
   * force restored. A change whose law cannot be built is left out.
   */
  private whyPending<T>(answer: () => T, describe?: (a: T) => Partial<WhyPendingChange>): WhyPendingChange[] {
    const agent = this.policyAgent as PolicyAgentOps | undefined; // undefined only while the constructor runs
    if (!agent) return [];
    const now = JSON.stringify(answer());
    const out: WhyPendingChange[] = [];
    for (const pl of agent.pendingLaws()) {
      let next: T;
      try {
        next = this.withHypotheticalLaw(pl.document, answer);
      } catch {
        continue;
      }
      if (JSON.stringify(next) === now) continue;
      out.push({ id: pl.id, from: pl.from, ...(describe ? describe(next) : {}) });
    }
    return out;
  }

  private withHypotheticalLaw<T>(document: PolicyFileConfig | null, fn: () => T): T {
    const savedPolicy = this.policy;
    const savedLaw = getCurrentPolicy();
    try {
      this.policy = this.buildPolicy(document, true);
      return fn();
    } finally {
      this.policy = savedPolicy;
      swapCurrentPolicy(savedLaw);
    }
  }

  /** The perimeter in force for the snapshot (plan 12 D4): its networks
   *  and domains, and whether the administrator set the networks, the user
   *  did, or the user narrowed the administrator's. */
  private perimeterView(p: { networks: readonly string[] | null; domains: readonly string[] }): { networks: string[] | null; domains: string[]; by: "administrator" | "you" | "narrowed" } {
    const adminNets = getAdminLayer().perimeter?.networks;
    const nets = p.networks ? [...p.networks] : null;
    const by = !adminNets ? "you" : JSON.stringify(nets) === JSON.stringify(adminNets) ? "administrator" : "narrowed";
    return { networks: nets, domains: [...p.domains], by };
  }

  /** Settings' view of the administrator's layer (plan 12 D5). */
  private modelsAdminView(): { files: string[]; locked: boolean; conflicts: string[]; refused: string[]; removed: Array<{ name: string; file: string }> } {
    const layer = getAdminLayer();
    const doc = this.policyDocs?.document ?? null;
    const markers = new Set((Array.isArray(doc?.models) ? doc!.models : []).filter((m) => m && (m as { disabled?: unknown }).disabled === true).map((m) => m.name));
    return {
      files: [...layer.files],
      locked: layer.locked,
      conflicts: layerProblems(doc),
      refused: [...this.adminRefused],
      removed: layer.models.filter((m) => markers.has(m.entry.name)).map((m) => ({ name: m.entry.name, file: m.file })),
    };
  }

  /** The administrator's layer as the ops answer it (plan 12 D5). */
  /** The administrator's layer's exception patterns (they may appear in
   *  its messages; prompt-pattern-redact.ts). */
  private adminPromptPatterns(): string[] {
    return (getAdminLayer().promptFilters ?? []).flatMap((p) => documentPatterns({ prompt_filters: p.config }));
  }

  private adminView(): ReturnType<typeof adminLayerView> {
    return adminLayerView(getAdminLayer(), { conflicts: layerProblems(this.policyDocs?.document ?? null), refused: this.adminRefused });
  }

  private logAdminConflicts(): void {
    for (const p of layerProblems(this.policyDocs?.document ?? null)) {
      this.log(`[admin] not in force, your administrator's policy wins: ${p}`);
    }
  }

  /** Re-read the administrator's layer when its files changed (the poll). */
  private pollAdminLayer(): void {
    const sig = adminLayerSignature(this.adminDir);
    if (sig === this.adminSig) return;
    this.adminSig = sig;
    this.reloadAdminLayer();
  }

  /**
   * Read the administrator's layer again and put it in force (plan 12 D5).
   * A layer that cannot be used keeps the one in force (as a hand edit that
   * does not validate keeps the law), and the problems are answered by the
   * policyDocument and modelEndpoints ops. The administrator wins a
   * conflict with the user's file: the law is rebuilt from the same user
   * document under the new layer. Public for tests.
   */
  reloadAdminLayer(): { ok: true } | { ok: false; problems: string[] } {
    let next;
    try {
      next = readAdminLayer(this.adminDir);
    } catch (err) {
      const problems = err instanceof AdminLayerError ? [...err.problems] : [String((err as Error).message ?? err)];
      this.adminRefused = problems;
      this.log(`WARNING: your administrator's policy changed and cannot be used; the one read before stays in force:\n${problems.map((p) => `  - ${p}`).join("\n")}`);
      return { ok: false, problems };
    }
    this.adminRefused = [];
    setAdminLayer(next);
    if (!this.injectedPolicy) this.rebuildPolicy(this.policyDocs.document);
    const summary = next.files.length > 0
      ? `your administrator's policy was read again: ${next.files.join(", ")}${next.locked ? " (models locked)" : ""}`
      : `your administrator's policy is gone (${this.adminDir}); your own models are the whole list`;
    this.log(`[admin] ${summary}`);
    this.emitPolicyChange({ via: "admin", requestedBy: "administrator", summary });
    this.logAdminConflicts();
    return { ok: true };
  }

  private rebuildPolicy(document: PolicyFileConfig | null): void {
    this.policy = this.buildPolicy(document);
    this.humanLabelsMemo = null;
    // The law source stays "file" (same path) — only its sections changed.
    if (this.lawSource.kind !== "custom" && this.policyPathOpt) {
      this.lawSource = describeLawSource(this.policyPathOpt, process.cwd());
    }
  }

  /** The policy_change audit line (reuses the §4.19 `config_change` kind on the
   *  reserved arbiter-admin stream; best-effort like every emit). */
  /**
   * Record a write that did not pass through the policy surface (a hand
   * edit, the developer view, a pinned reader) in the same change log, with
   * the items it touched, so every rule has a known origin (dashboard.md
   * §4.25j). The surface's own writes are recorded by PolicyAgentOps and are
   * skipped here. A write that changed no item (a touch, a comment) records
   * nothing. Best-effort: attribution, never on the decision path.
   */
  private recordOutsideChange(change: PolicyChange, docs: { before: PolicyFileConfig | null; after: PolicyFileConfig | null }): void {
    if (!OUTSIDE_VIAS.has(change.via as never)) return;
    try {
      const revert = diffItems(docs.before, docs.after);
      if (revert.length === 0) return;
      const specId = getCurrentPolicy().specId;
      const d = policyDelta(compilePolicy({ specId, document: docs.before }), compilePolicy({ specId, document: docs.after }));
      this.policyProposals.recordChange({
        via: change.via as "disk",
        requestedBy: change.requestedBy ?? (change.via === "disk" ? "file" : "dashboard"),
        sessionKey: null,
        edits: [],
        delta: [...d.relaxations, ...d.tightenings],
        revert,
        proposalId: null,
      });
    } catch (err) {
      this.log(`policy change record failed (ignored): ${(err as Error).message}`);
    }
  }

  private emitPolicyChange(change: PolicyChange): void {
    try {
      const stored = this.events.append({
        id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
        sessionId: ADMIN_SESSION_ID,
        turn: 0,
        ts: new Date().toISOString(),
        callId: null,
        kind: "config_change",
        view: "HumanView",
        boundary: "model_context",
        emitter: "arbiter",
        input: { symbolized: `policy.yaml (${change.via})`, original: null, differs: false, symbols: [] },
        output: { symbolized: change.summary, original: null, differs: false, symbols: [] },
        invariant: { violatedInvariant: false },
        // `?.`: a start-time restore is audited while the store is being built.
        policyChange: { via: change.via, requestedBy: change.requestedBy ?? null, path: this.policyDocs?.path ?? this.policyPathOpt ?? null },
      });
      this.fanOut(stored);
    } catch (err) {
      this.log(`policy_change audit emit failed (ignored): ${(err as Error).message}`);
    }
  }

  /** Attach each approval's provenance from the symbol table at read time:
   *  its origin host (the Inbox's mintable rule) and its source (the Rules
   *  page's "which data", dashboard.md §4.25e). Never the value. */
  /** The approval queue as every listing shows it: a PENDING question that no
   *  answer can make take effect (`mootQuestionReason`: about a printer, or
   *  naming an interpreter alone, filed before the decisions that made it
   *  apply to nothing) is retired first, so it is in no listing (the !437
   *  leftover (4)). */
  private listApprovals(filter?: { status?: EgressApproval["status"] }): EgressApproval[] {
    this.retireMootQuestions();
    return this.egressApprovals.list(filter);
  }

  /** The !437 leftover (4), durable (confidentiality plan 13 §3 D8): remove
   *  every PENDING question no answer can make take effect
   *  (`mootQuestionReason`) from the store, the DB row included, and keep
   *  its reason for a stale answer (`retiredQuestions`). Run at start and
   *  before every listing and answer. Fail-closed by construction: it only
   *  ever removes a pending row (`EgressApprovalStore.withdraw`), never an
   *  answer, and a removed question grants nothing: no prior answer is found
   *  for it, so the gate decides by the law (a printer gets what a
   *  non-reader gets; an interpreter alone is refused), and a guard still
   *  holding the open re-asks and gets that answer, not a hang. An ANSWERED
   *  moot row is kept, marked (`whyPath`), as the human's record. */
  private retireMootQuestions(): void {
    for (const a of this.egressApprovals.list({ status: "pending" })) {
      // Plan 13 §5.4: a holder's send question whose files may all go to
      // the destination now (an *Always* on each that blocked, or a rule
      // changed under Rules) is answered by the law: its next send goes.
      const holder = parseHolderSendSubject(a.symbol);
      const reason = holder !== null
        ? (holderSendReleased(this.holderSourcesOf(holder.files, a.destination), a.destination) ? `every file it holds may now go to ${a.destination}, so the send goes without asking` : null)
        : mootQuestionReason(a.symbol);
      if (reason === null) continue;
      if (this.egressApprovals.withdraw(a.id) === undefined) continue;
      this.retiredQuestions.set(a.id, reason);
      this.log(`retired ${a.id} (${a.symbol.split("#")[0]} for ${a.destination}, pending since ${new Date(a.firstSeen).toISOString()}): no answer can take effect`);
    }
  }

  /** Plan 13 §5.4: the files a holder of `files` holds, as a send question
   *  to `host` names them now (holder-send-ask.ts `holderSources`), over
   *  the same label composition `taintedProcessBindings` counts by. */
  private holderSourcesOf(files: readonly string[], host: string): HolderSource[] {
    let registry: ReturnType<typeof listSecretRegistry> | null = null;
    return holderSources(files, host, {
      snapshot: this.labelSnapshot(),
      registryBindings: (p) => {
        registry ??= listSecretRegistry(this.symbolMap);
        return registry.filter((e) => e.path === p).flatMap((e) => e.bindings);
      },
      sessionValueBindings: (row) => this.symbolMap.symbols.get(row.slice(SESSION_SYMBOL_ROW_PREFIX.length))?.bindings ?? null,
    });
  }

  /** Plan 13 §5.4, §9 R2: the edit an *Always* on `path` of the waiting
   *  holder's send question `approvalId` files, previewed: refused unless
   *  the file blocks, its rule can take the host, and the preview loosens
   *  that rule and nothing else. */
  private holderSourceBinding(approvalId: string, path: string): HolderSourceBindingResultWire {
    this.retireMootQuestions();
    const retired = this.retiredQuestions.get(approvalId);
    if (retired !== undefined) throw new OpError(`egress-approval ${approvalId} no longer applies: ${retired}`);
    const row = this.egressApprovals.list({ status: "pending" }).find((a) => a.id === approvalId);
    const holder = row ? parseHolderSendSubject(row.symbol) : null;
    if (!row || !holder) throw new OpError(`no waiting send question ${approvalId} names the files a program holds`);
    const sources = this.holderSourcesOf(holder.files, row.destination);
    const unit = sources.find((s) => s.path === path && !s.rule);
    if (!unit) throw new OpError(`${path} is not one of the files of ${approvalId}`);
    if (!unit.blocks) throw new OpError(`${path} may already go to ${row.destination}`);
    if (!unit.always) throw new OpError(`${path} takes no Always from here (${unit.noAlways ?? "no rule"}): change it under Rules`);
    const planned = holderBindEdit(path, row.destination, {
      snapshot: this.labelSnapshot(),
      document: this.policyDocs.document,
      registryBindings: (p) => listSecretRegistry(this.symbolMap).filter((e) => e.path === p).flatMap((e) => e.bindings),
    });
    if ("refused" in planned) throw new OpError(`${path} takes no Always from here (${planned.refused}): change it under Rules`);
    // The items the edit was planned from, with their versions in THIS read
    // (policy-surface.md §8.4.6 "An item-level version"): the file's own
    // rule, which the edit rewrites with its level and hosts carried over,
    // and the rule that decided its label now when that is another (a
    // folder rule or a pattern the new rule copies its level from). The
    // dashboard proposes the edit with them, so a change to either landing
    // in between refuses it instead of being overwritten.
    const decided = resolvePathLabel(normalizeLabelPath(path) ?? path, this.labelSnapshot().human);
    const keys = new Set(planned.edits.map((e) => pathIdentity((e as { path: string }).path)));
    if (decided !== null) keys.add(pathIdentity(decided.via));
    const basedOn = [...keys].map((key) => ({ section: "paths", key, version: this.policyDocs.itemVersion("paths", key) }));
    const preview = this.policyAgent.preview(planned.edits);
    if (!preview.ok) throw new OpError(`the change is not valid: ${preview.problems.join("; ")}`);
    // Fail-closed: the edit may loosen this file's rule and nothing else.
    const relaxes = preview.relaxations.map((r) => ({ facet: r.facet, subject: r.subject }));
    const other = relaxes.find((r) => r.facet !== "paths" || (normalizeLabelPath(r.subject) ?? r.subject) !== planned.rule);
    if (other !== undefined) throw new OpError(`adding ${row.destination} to ${path} would also loosen ${other.facet} ${other.subject}; change it under Rules`);
    return { edits: planned.edits, rule: planned.rule, relaxes, basedOn };
  }

  /** Why `row` takes no "Send without it" (send-without.ts), or null when
   *  it does: a card about a SECRET symbol the table holds (the candidate
   *  walk, as the gate resolves it) in a request to a network host, with
   *  the confidentiality axis on. */
  private sendWithoutRefusalOf(row: Pick<EgressApproval, "symbol" | "destination">): string | null {
    const found = row.symbol.startsWith("$MDU:") ? findSymbolByName(this.symbolMap, row.symbol) : null;
    const secretSymbol = found !== null && found.entry.obsoleted_at == null && isSecret(parseConfidentialityLevel(found.entry.confidentiality));
    return sendWithoutRefusal(row, { confidentiality: this.confidentiality, secretSymbol });
  }

  private withProvenance(list: EgressApproval[]): EgressApproval[] {
    let promptConfig: ReturnType<PromptFilterEngine["config"]> | null = null;
    return list.map((a) => {
      const entry = this.symbolMap.symbols.get(a.symbol);
      // Plan 15 §12 (2026-10-04): a waiting prompt hold under a locked
      // administrator's `ask` row takes an answer for this message only.
      let onceOnly = false;
      if (a.status === "pending" && a.symbol.startsWith(PROMPT_SUBJECT_PREFIX)) {
        promptConfig ??= this.promptFilter.config();
        onceOnly = this.promptHolds.genericRefusal(a, "always", promptConfig) !== null;
      }
      // An answered verdict about a program that applies to nothing any
      // more (a pending one is retired, `retireMootQuestions`): marked, so
      // the dashboard says so instead of offering to change it
      // (dashboard.md §4.34 "Answers that no longer apply").
      const stale = a.status !== "pending" ? verdictNoLongerApplies(a.symbol) : null;
      // A HIGH session's ask names what that session read (confidentiality.md
      // §4, "What the card says"): the symbols in session_label_sources with
      // their origins. Provenance, never a value.
      const session = parseSessionApprovalSubject(a.symbol);
      const reads = session ? this.sessionReadsOf(session.sessionKey) : null;
      // A holder's send question names every file the holder holds, as it
      // stands now (plan 13 §5.4): after an *Always* on one, the card says
      // which are left.
      const holder = a.status === "pending" ? parseHolderSendSubject(a.symbol) : null;
      // "Send without it" (confidentiality.md §4): offered on a waiting card
      // the arbiter would take it on, and only there.
      const stripOffered = a.status === "pending" && this.sendWithoutRefusalOf(a) === null;
      // A file's card (egress-hold.md "One card per file"): how many of the
      // file's values its answer covers.
      const fileValues = this.fileCardValues(a.symbol);
      return {
        ...a,
        ...(stripOffered ? { stripOffered: true as const } : {}),
        ...(fileValues > 1 ? { fileValues } : {}),
        ...(holder ? { holderSources: this.holderSourcesOf(holder.files, a.destination) } : {}),
        originHost: originHostOf(entry?.origin),
        source: entry ? { tool: entry.tool, origin: entry.origin ?? null } : null,
        ...(onceOnly ? { onceOnly: true as const } : {}),
        ...(stale !== null ? { noLongerApplies: stale } : {}),
        ...(reads ? { sessionReads: reads.reads, ...(reads.more > 0 ? { sessionReadsMore: reads.more } : {}) } : {}),
        // A command's card says what an allowed run may do: held by the
        // guard (only the session's bound hosts, its files labeled) or not
        // (confidentiality.md §4, "Without the guard").
        ...(session?.boundary === "shell"
          ? { sessionConfined: this.confidentiality && this.guardedSessions.has(session.sessionKey), sessionBindings: [...this.sessionLabels.get(session.sessionKey).bindings] }
          : {}),
        // A held command's refused connection (confidentiality.md §4): the
        // card says the command's request was stopped and what it holds.
        ...(session?.boundary === "network" && isSessionHeldReason(a.reason)
          ? { sessionHeld: true as const, sessionBindings: [...this.sessionLabels.get(session.sessionKey).bindings] }
          : {}),
      };
    });
  }

  /** The taint rows a HIGH session's command holds (`sessionExecRoot`): one
   *  per datum the session read into context, its file when its origin is
   *  an absolute path, else `symbol:<name>` (bound where the symbol is;
   *  a datum of unknown origin binds nowhere), at that datum's level (the
   *  session's when the symbol is gone). */
  private sessionSourceRows(sessionKey: string, sessionLevel: string): Array<{ path: string; level: string }> {
    const out: Array<{ path: string; level: string }> = [];
    const sources = this.sessionLabels.sourcesOf(sessionKey);
    for (const symbol of sources.length > 0 ? sources : ["(unknown)"]) {
      const entry = this.symbolMap.symbols.get(symbol);
      const origin = typeof entry?.origin === "string" ? entry.origin : "";
      const path = origin.startsWith("/") ? origin : `${SESSION_SYMBOL_ROW_PREFIX}${symbol}`;
      const level = entry ? parseConfidentialityLevel(entry.confidentiality) : sessionLevel;
      if (!out.some((r) => r.path === path)) out.push({ path, level: isSecret(level as ConfidentialityLevel) ? level : sessionLevel });
    }
    return out;
  }

  /** What a session read into context above `public`, for its Approvals
   *  card: up to {@link SESSION_READS_SHOWN} symbols with their origins (a
   *  file path, `env:NAME`, a URL, or null), and how many more. */
  private sessionReadsOf(sessionKey: string): { reads: Array<{ symbol: string; origin: string | null }>; more: number } {
    const all = this.sessionLabels.sourcesOf(sessionKey);
    const reads = all.slice(0, SESSION_READS_SHOWN).map((symbol) => ({ symbol, origin: this.symbolMap.symbols.get(symbol)?.origin ?? null }));
    return { reads, more: Math.max(0, all.length - reads.length) };
  }

  /**
   * The session gate with its human half (confidentiality.md §4, "The human
   * half", 2026-10-11): the pure `decideSessionEgress`, then — only when it
   * says a human must decide — the prior answer for this session × host (or
   * × exact command), consulted and (an attested ask) spent like every other
   * verdict, and otherwise a PENDING row filed. Fail-closed throughout: no
   * answer refuses; a data-socket ask reads an approval as no verdict; a
   * request with no session key is not high (`sessionLabels.get`), so it
   * never reaches the queue.
   */
  private decideSessionEgressWithApprovals(
    req: { sessionKey?: string; boundary: SessionEgressBoundary; destination?: string; netEnabled?: boolean; command?: string },
    spends: boolean,
  ): SessionEgressDecision & { approvalId?: string } {
    const sess = this.sessionLabels.get(req.sessionKey);
    const verdict = decideSessionEgress({
      sessionLevel: sess.confidentiality,
      sessionBindings: sess.bindings,
      boundary: req.boundary,
      destination: req.destination,
      netEnabled: req.netEnabled,
      // §9 rule 1(b): an untrusted-tainted high session loses the standing
      // bound-destination release — even a bound sink takes one approval.
      untrustedTainted: sess.untrustedTainted,
    });
    if (verdict.allow || !verdict.requiresApproval || !req.sessionKey || req.boundary === "filesystem") return verdict;
    // A shell ask names its command; one without it cannot be keyed (it
    // could never be told apart from another), so it is refused unfiled.
    if (req.boundary === "shell" && (typeof req.command !== "string" || req.command === "")) return verdict;
    const subject = sessionApprovalSubject(req.boundary, req.sessionKey);
    const target = req.boundary === "shell" ? sessionExecTarget(req.command!) : sessionNetTarget(req.destination);
    const prior = this.consultPriorVerdict(subject, target, spends);
    const step = composeSessionApproval(
      verdict,
      prior && prior.status !== "pending" ? { id: prior.id, status: prior.status, scope: prior.scope } : undefined,
    );
    if (step.kind === "decided") return step.decision;
    const entry = this.egressApprovals.recordPending(subject, target, verdict.reason, req.sessionKey);
    this.log(`session gate: ${req.boundary} ${req.boundary === "shell" ? "command" : target} → asked (${entry.id})`);
    return { ...step.decision, approvalId: entry.id };
  }

  /** Best-effort hit accounting — never on a decision's path. */
  private recordHit(ruleId: string, kind: "hit" | "audit" = "hit"): void {
    try {
      if (kind === "audit") this.ruleHits.auditHit(ruleId);
      else this.ruleHits.hit(ruleId);
    } catch (err) {
      this.log(`rule-hits: ${(err as Error).message}`);
    }
  }

  private decideDesymWithApprovals(req: DesymbolizationRequest, spends: VerdictSpend): DesymbolizationDecision {
    return this.decideDesym(req, { kind: "live", spends }).decision;
  }

  /**
   * The egress gate's ONE composition, in two modes (policy-surface.md
   * §5 "Tester ≡ gates"): `live` decides for a real symbol and carries every
   * side effect (queue a pending ask, count a rule hit); `probe` decides for a
   * SYNTHETIC entry (the Test-a-flow tester) and records nothing — same
   * branches, same order, so the tester's answer IS the gate's. `stage` names
   * the layer that decided: standing verdict → lockdown → user rule →
   * disposition → built-in.
   */
  private decideDesym(
    req: DesymbolizationRequest,
    mode: { kind: "live"; spends: VerdictSpend } | { kind: "probe"; entry: SymbolEntry },
  ): { decision: DesymbolizationDecision; stage: DesymStage } {
    const live = mode.kind === "live";
    const hit = (id: string, audit = false): void => {
      if (!live) return;
      if (audit) this.recordHit(id, "audit");
      else this.recordHit(id);
    };
    const queueable =
      req.boundary === "network" &&
      typeof req.symbol === "string" && req.symbol !== "" &&
      typeof req.destination === "string" && req.destination !== "";

    // Plan 10 §11.13.1 (2026-10-03): a wire-twin credential declared for
    // https never travels over plain HTTP. First, so no standing verdict can
    // release it there; a hard refusal, nothing queued.
    if (live && this.confidentiality && req.boundary === "network" && typeof req.symbol === "string") {
      const dest = typeof req.destination === "string" ? req.destination : undefined;
      // The row the gate decides and `resolve` returns: the candidate walk,
      // so a mutated token (`<field>.x`) is judged as the field it resolves
      // to, not as an unknown name the rule skips (2026-10-09).
      const row = findSymbolByName(this.symbolMap, req.symbol)?.name ?? req.symbol;
      const refused = wireSchemeRefusal(req, wireReleaseScheme(this.symbolMap, row, {
        resolveLabel: this.labelLookup,
        grantScheme: (origin, field) => this.authGrants.scheme(origin, field, dest),
      }));
      if (refused) {
        hit(refused.ruleRef!.id);
        return { decision: refused, stage: "built-in" };
      }
      // Plan 10 §11.13.1 (2026-10-09): a credential bound to this host only
      // by its own config file or an auth grant (never a binding of the
      // user's) is put back only in the request's Authorization header.
      // Here too, before any standing verdict; a hard refusal.
      // Another labelled source of the same value that the user bound to
      // this host makes it a binding of theirs (value-sources.ts).
      const misplaced = wirePositionRefusal(req, dest !== undefined && releaseRestsOnWireGrant(this.symbolMap, req.symbol, dest, {
        resolveLabel: this.labelLookup,
        envBindings: (name) => this.envLawBindings(name),
        sourcesOf: (symbol) => this.symbolSources.get(symbol),
      }) && !this.siblingDeclares(req.symbol, dest));
      if (misplaced) {
        hit(misplaced.ruleRef!.id);
        return { decision: misplaced, stage: "built-in" };
      }
    }

    if (queueable) {
      // The human's answers are keyed by host less a default port
      // (session-approvals.ts `approvalDestination`, 2026-10-17).
      const dest = approvalDestination(req.destination as string);
      // A probe reads, never spends (§10.3); a live ask spends only from an
      // attested channel.
      // Keyed by the ROW the token resolves to (`cardKeyOf`), so `X.` at a
      // sentence's end and `X` are one card; an answer filed under a raw
      // spelling before (2026-10-19) is still read.
      const key = this.cardKeyOf(req.symbol);
      const spends = mode.kind === "live" ? mode.spends : false;
      const prior = this.consultPriorVerdict(key, dest, spends, req.requestId) ??
        (key !== req.symbol ? this.consultPriorVerdict(req.symbol, dest, spends, req.requestId) : undefined);
      const answered = verdictDecisionOf(prior, mode);
      if (answered) return { decision: answered, stage: "verdict" };
      // SIEM-triggered lockdown (siem-integration.md §4.3, scenario D): a global
      // lockdown forces EVERY network egress to human approval, overriding the
      // pure gate's allow. Placed AFTER the prior-verdict short-circuit above, so
      // a human can still relax a specific egress per-approval even under lockdown
      // (the one sanctioned relaxation) — but a fresh egress the pure gate would
      // have allowed is now queued. This is the actuator half of scenario D.
      if (this.sessionPosture.isLockedDown()) {
        const entry = live
          ? this.egressApprovals.recordPending(
              key, dest, "SIEM lockdown: network egress requires approval (posture=lockdown)",
              req.sessionKey,
            )
          : null;
        return {
          decision: {
            allow: false, requiresApproval: true,
            reason: "SIEM lockdown: network egress requires human approval",
            ruleRef: ruleRef("egress:siem-lockdown"), ...(entry ? { approvalId: entry.id } : {}),
          },
          stage: "lockdown",
        };
      }
    }

    // ── The operator's law (policy-surface.md §2.4, §2.5) ──────────
    // After a standing verdict and the lockdown posture, before the built-in
    // branches: user release rules decide for NON-secret symbols at a known
    // destination (a secret keeps the bound-destination path — a user rule
    // never declassifies). Block beats Allow; audit rules only count. The
    // origin is the symbol's URL host; a non-URL origin matches only rules
    // with no `from` (fail-closed toward asking).
    const compiled = getCurrentPolicy();
    if (queueable && compiled.userRules.length > 0) {
      const symEntry = mode.kind === "probe" ? mode.entry : this.symbolMap.symbols.get(req.symbol);
      const secret = symEntry ? isSecret(parseConfidentialityLevel(symEntry.confidentiality)) : false;
      if (symEntry && !(this.confidentiality && secret)) {
        const verdict = matchUserRules(compiled, {
          originHost: originHostOf(symEntry.origin),
          destinationHost: hostOfDestination(req.destination as string),
        });
        for (const r of verdict.audited) hit(`user:${r.id}`, true);
        if (verdict.decision?.mode === "block") {
          hit(`user:${verdict.decision.rule.id}`);
          hit("egress:user-rule-block");
          return {
            decision: {
              allow: false, requiresApproval: false,
              reason: `user rule ${verdict.decision.rule.id} blocks releasing data to '${req.destination}'` +
                (verdict.decision.rule.reason ? ` (${verdict.decision.rule.reason})` : ""),
              ruleRef: ruleRef("egress:user-rule-block"),
            },
            stage: "user-rule",
          };
        }
        if (verdict.decision?.mode === "allow") {
          hit(`user:${verdict.decision.rule.id}`);
          hit("egress:user-rule-allow");
          return {
            decision: {
              allow: true,
              reason: `user rule ${verdict.decision.rule.id} allows releasing data to '${req.destination}'` +
                (verdict.decision.rule.reason ? ` (${verdict.decision.rule.reason})` : ""),
              ruleRef: ruleRef("egress:user-rule-allow"),
            },
            stage: "user-rule",
          };
        }
      }
    }

    const result = mode.kind === "probe"
      ? (this.policy.desymbolizationDecisionWith
          ? this.policy.desymbolizationDecisionWith(req, () => mode.entry)
          : this.policy.desymbolizationDecision(req))
      : this.policy.desymbolizationDecision(req);

    // The default catalog's ISSUER BINDINGS (confidentiality.md §2.3,
    // 2026-10-19): a secret the gate would ask about only because nothing
    // binds it (`egress:secret-unbound`) is released when its value's own
    // format names the destination's issuer, exactly that host, HTTPS, in
    // the Authorization header only, and the switch is on. After every
    // standing answer about the placeholder and the lockdown (above), and
    // after the human's answer about its FILE at this host (here): an answer
    // of the human's always wins over the default.
    if (this.confidentiality && result.allow === false && result.requiresApproval && result.ruleRef?.id === "egress:secret-unbound") {
      const issuer = this.issuerReleaseOf(req, mode.kind === "probe");
      if (issuer !== null) {
        const fileGroup = queueable ? this.approvalGroupOf(req.symbol) : null;
        if (fileGroup !== null) {
          const prior = this.consultPriorVerdict(fileGroup, approvalDestination(req.destination as string), mode.kind === "live" ? mode.spends : false, req.requestId);
          const answered = verdictDecisionOf(prior, mode);
          if (answered) return { decision: answered, stage: "verdict" };
        }
        hit("egress:secret-issuer");
        return {
          decision: {
            allow: true,
            reason: `secret at '${req.destination}', the API host of ${issuer.name}, the issuer its format names → allow in the Authorization header over HTTPS (built-in issuer binding, confidentiality §2.3; policy.yaml issuer_bindings turns it off)`,
            ruleRef: ruleRef("egress:secret-issuer"),
          },
          stage: "built-in",
        };
      }
    }

    // Dispositions (§2.4): a built-in ask the operator set to Block denies
    // outright — nothing is queued; the row would only be noise.
    if (result.allow === false && result.requiresApproval && result.ruleRef?.source === "rule") {
      if (compiled.dispositions[result.ruleRef.id] === "block") {
        hit(result.ruleRef.id);
        hit("egress:disposition-block");
        return {
          decision: {
            allow: false, requiresApproval: false,
            reason: `${result.reason} — set to Block by the operator (policy.yaml rules: ${result.ruleRef.id})`,
            ruleRef: ruleRef("egress:disposition-block"),
          },
          stage: "disposition",
        };
      }
    }
    if (result.ruleRef && result.ruleRef.source !== "verdict") hit(result.ruleRef.id);

    // One card per FILE (egress-hold.md "One card per file", 2026-10-19): the
    // human's answer about a registered file at a host decides each of its
    // placeholders there. Read only where the per-placeholder answer above
    // found nothing and the gate itself asks: it never releases what the
    // gate refuses outright, and an answer about the placeholder itself
    // still wins.
    const group = queueable && result.allow === false && result.requiresApproval ? this.approvalGroupOf(req.symbol) : null;
    if (group !== null) {
      const prior = this.consultPriorVerdict(group, approvalDestination(req.destination as string), mode.kind === "live" ? mode.spends : false, req.requestId);
      const answered = verdictDecisionOf(prior, mode);
      if (answered) return { decision: answered, stage: "verdict" };
    }

    // Only queue a fresh NETWORK egress that the pure gate says needs approval.
    // The deny then carries the queue entry's id so a session's gate events can
    // be joined back to the Pending row (policy-surface.md §9.5). A request
    // carrying two or more of one file's placeholders asks on the FILE's card,
    // one card for all of them; a lone placeholder keeps its own (it names
    // its key).
    if (live && queueable && result.allow === false && result.requiresApproval) {
      const subject = group !== null && this.fileSharesRequest(req.symbol, group, req.requestSymbols) ? group : this.cardKeyOf(req.symbol);
      const entry = this.egressApprovals.recordPending(
        subject, approvalDestination(req.destination as string), result.reason, req.sessionKey,
      );
      return { decision: { ...result, approvalId: entry.id }, stage: "built-in" };
    }
    return { decision: result, stage: "built-in" };
  }

  /**
   * The issuer that releases this send (confidentiality.md §2.3), or null.
   * The row must be one the release may read (current-bindings.ts
   * `issuerSourceOf`: a registered file's field or a masked variable, the
   * user's own), and the send must pass `issuerRelease` under the law in
   * force. A probe reads the real row its placeholder names (a synthetic
   * probe symbol names none, so it never releases) and answers for a send
   * in the Authorization header over HTTPS.
   */
  private issuerReleaseOf(req: DesymbolizationRequest, probe: boolean): Issuer | null {
    if (req.boundary !== "network" || typeof req.symbol !== "string" || typeof req.destination !== "string") return null;
    if (issuerOfHost(req.destination) === null) return null;
    const source = issuerSourceOf(this.symbolMap, req.symbol, this.labelLookup);
    if (source === null) return null;
    const r = issuerRelease({
      value: source.value, names: source.names, destination: req.destination,
      scheme: req.scheme, positions: req.positions, probe,
    }, getCurrentPolicy().issuerBindings);
    return "issuer" in r ? r.issuer : null;
  }

  /**
   * The card a placeholder's ask is filed under when it is one of a
   * registered FILE's field placeholders (egress-hold.md "One card per
   * file", 2026-10-19): that file's base symbol (`$MDU:…[h]` of
   * `$MDU:…[h].KEY`), the registry row the file itself was registered as.
   * Null for anything else (a masked output, a page, an environment
   * variable, a base symbol itself): its own card, as before.
   *
   * Before, a document twin's placeholders (a bank statement: one per line)
   * each filed a card, so one upload of the statement raised seven cards at
   * once (demo-c17, 2026-10-19). Now the human answers the FILE to the host
   * once; a different file is a different card. The base row must be the
   * same registration (same hash, same file, active): anything else keeps
   * the placeholder's own card.
   */
  private approvalGroupOf(symbol: string): string | null {
    if (typeof symbol !== "string" || !symbol.startsWith("$MDU:")) return null;
    const found = findSymbolByName(this.symbolMap, symbol);
    if (!found) return null;
    const e = found.entry;
    if (e.field === null || e.obsoleted_at !== null || !isRegisteredFileRow(e) || !isSecret(parseConfidentialityLevel(e.confidentiality))) return null;
    const cut = found.name.indexOf("].");
    if (cut < 0) return null;
    const base = found.name.slice(0, cut + 1);
    const b = this.symbolMap.symbols.get(base);
    if (!b || b.field !== null || b.obsoleted_at !== null || !isRegisteredFileRow(b) || b.origin !== e.origin) return null;
    return base;
  }

  /** The key a placeholder's card and answers are filed under: the token
   *  without a sentence's trailing period when that names a row
   *  (`$MDU:…[h].KEY.` is the row `$MDU:…[h].KEY`), else the token as
   *  written. The net-proxy's scanner keeps such a period in the token (MR
   *  !2136) and the gate's lookup trims it, so `X.` and `X` filed two cards.
   *  Only the period: a field path the table holds no row for keeps its
   *  spelling (the card names that key). */
  private cardKeyOf(symbol: string): string {
    if (typeof symbol !== "string" || !symbol.startsWith("$MDU:") || this.symbolMap.symbols.has(symbol)) return symbol;
    const trimmed = symbol.replace(/\.+$/, "");
    if (trimmed === symbol) return symbol;
    return this.symbolMap.symbols.has(trimmed) || findSymbolByName(this.symbolMap, symbol)?.name === trimmed ? trimmed : symbol;
  }

  /** How many protected values a card about `subject` covers when it is a
   *  registered file's base symbol (its registration's active field rows),
   *  else 0. Provenance for the card's words only. */
  private fileCardValues(subject: string): number {
    const e = typeof subject === "string" && subject.startsWith("$MDU:") ? this.symbolMap.symbols.get(subject) : undefined;
    if (!e || e.field !== null || e.obsoleted_at !== null || !isRegisteredFileRow(e)) return 0;
    let n = 0;
    const prefix = `${subject}.`;
    for (const [name, r] of this.symbolMap.symbols) {
      if (name.startsWith(prefix) && r.field !== null && r.obsoleted_at === null && r.origin === e.origin && isRegisteredFileRow(r)) n++;
    }
    return n;
  }

  /** Does the request (`requestSymbols`, the caller's list of every
   *  placeholder it carries) hold another placeholder of the file `group`
   *  besides `symbol`? Then the ask files the file's one card. At most
   *  REQUEST_SYMBOLS_MAX entries are read; anything not a list of strings
   *  is no list (each placeholder keeps its own card). */
  private fileSharesRequest(symbol: string, group: string, requestSymbols: unknown): boolean {
    if (!Array.isArray(requestSymbols)) return false;
    const self = this.cardKeyOf(symbol);
    for (const s of requestSymbols.slice(0, REQUEST_SYMBOLS_MAX)) {
      if (typeof s !== "string" || s === symbol || !s.startsWith(`${group}.`)) continue;
      // another spelling of the same placeholder (`X.` beside `X`) is not another
      if (this.cardKeyOf(s) !== self && this.approvalGroupOf(s) === group) return true;
    }
    return false;
  }

  /**
   * Test a flow (policy-surface.md §4 "Test a flow"): classify the
   * source as the inbound gate would, build a SYNTHETIC symbol entry from that
   * classification (or the forced level), and run the egress composition in
   * probe mode. Nothing is symbolized, queued or counted — the answer is what
   * WOULD happen, from the same code that decides when it does. For a
   * registered file the probe is keyed on each placeholder a real send of
   * it carries, so a standing human answer counts (`testFlowSubjects`).
   */
  private testFlow(req: TestFlowOpRequest): TestFlowResult {
    const src = req.source ?? {};
    const tool = typeof src.tool === "string" && src.tool.trim() !== "" ? src.tool.trim() : "WebFetch";
    const field = typeof src.field === "string" && src.field.trim() !== "" ? src.field.trim() : undefined;
    const origin = typeof src.origin === "string" && src.origin.trim() !== "" ? src.origin.trim() : undefined;
    // The params the proxy would have passed: a schema keys a field's category
    // off `params.<x>` (WebFetch.content ← params.url; Read ← file_path).
    const params: Record<string, string> = src.params && typeof src.params === "object"
      ? Object.fromEntries(Object.entries(src.params).filter(([, v]) => typeof v === "string") as [string, string][])
      : origin === undefined ? {}
        : /^[a-z][a-z0-9+.-]*:\/\//i.test(origin) ? { url: origin } : { file_path: origin, path: origin };
    const inbound = this.policy.classify({
      tool, value: "<probe>", boundary: "model_context",
      ...(field !== undefined ? { field } : {}),
      ...(origin !== undefined ? { origin } : {}),
      ...(Object.keys(params).length ? { params } : {}),
    });
    const level = parseConfidentialityLevel(req.level ?? inbound.confidentiality ?? "public");
    const integrity = inbound.trust === "TRUSTED" ? "trusted" : "untrusted";
    const probe: SymbolEntry = {
      value: "<probe>", tool, field: field ?? null, origin: origin ?? null,
      session_key: null, call_id: null, created_at: Date.now(),
      obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
      confidentiality: level, bindings: inbound.bindings ?? null, integrity,
    };
    const wantsEgress = (typeof req.destination === "string" && req.destination !== "") || req.boundary !== undefined;
    let egress: TestFlowResult["egress"] = null;
    let note: string | undefined;
    let placeholders: number | undefined;
    if (wantsEgress) {
      if (!this.policy.desymbolizationDecisionWith) {
        note = "this arbiter runs an injected policy engine without a probe hook — the egress half of the tester is unavailable";
      } else {
        // The standing-answer layer is keyed on the symbol a real send
        // carries. A registered file's placeholders are known, so the
        // tester asks with each of them (tour 1: asking with the probe name
        // alone never found the human's Always allow, and `mandu why` said
        // "held" while every real send went out). The law still sees the
        // synthetic entry; only the key changes. Most restrictive wins.
        const subjects = this.testFlowSubjects(tool, origin, req.level);
        if (subjects !== null) placeholders = subjects.length;
        const rank = (d: DesymbolizationDecision): number => (d.allow ? 0 : d.requiresApproval ? 1 : 2);
        for (const symbol of subjects ?? [TEST_FLOW_PROBE_SYMBOL]) {
          const r = this.decideDesym({
            symbol,
            boundary: req.boundary ?? "network",
            ...(typeof req.destination === "string" && req.destination !== "" ? { destination: req.destination } : {}),
            ...(req.asCommand ? { asCommand: true } : {}),
          }, { kind: "probe", entry: probe });
          if (egress === null || rank(r.decision) > rank(egress.decision)) egress = { decision: r.decision, stage: r.stage };
        }
      }
    }
    const pathLabel = this.testFlowPathLabel(origin);
    return {
      inbound,
      probe: { tool, field: field ?? null, origin: origin ?? null, level, integrity },
      egress,
      ...(placeholders !== undefined ? { placeholders } : {}),
      ...(note ? { note } : {}),
      ...(pathLabel ? { pathLabel } : {}),
    };
  }

  /**
   * The symbols a real send of the tested datum carries, when they are
   * known: a registered FILE read (`tool: Read`, an absolute path origin)
   * whose registrations the symbol table holds (`registeredFileSymbols`:
   * every active registration's twin placeholders). Null (the synthetic
   * probe symbol, which no human answer is keyed on) for anything else: a
   * URL or channel origin, another tool, a file never registered, the axis
   * off, or a FORCED level other than the file's own (a hypothetical datum,
   * not this file). Read-only: the probe consults answers without spending
   * an Allow once (`consultPriorVerdict`, spends false) and queues nothing.
   */
  private testFlowSubjects(tool: string, origin: string | undefined, forcedLevel: string | undefined): string[] | null {
    if (!this.confidentiality || tool !== "Read" || origin === undefined || !origin.startsWith("/")) return null;
    const rows = registeredFileSymbols(this.symbolMap, origin);
    if (rows.length === 0) return null;
    if (forcedLevel !== undefined && rows.some((r) => r.level !== parseConfidentialityLevel(forcedLevel))) return null;
    return rows.map((r) => r.symbol);
  }

  /**
   * The tester's "which rule decided, and why" for a filesystem-path source
   * (policy-surface.md §4, confidentiality.md §6.1): `pathLevel`'s
   * derivation plus the outranked-pattern hint. Observability only; the probe
   * above never reads it. Null for a URL / channel / absent origin.
   */
  private testFlowPathLabel(origin: string | undefined): TestFlowPathLabel | null {
    if (origin === undefined || /^[a-z][a-z0-9+.-]*:\/\//i.test(origin)) return null;
    if (normalizeLabelPath(origin) === null) return null;
    if (!this.confidentiality) return { path: origin, level: "public", bindings: [], axis: false, rule: null, outranked: [] };
    const m = confidentialityForOrigin(origin, undefined, this.labelLookup);
    const rule = m.rule ?? null;
    // Only when a HUMAN label decided, and only when the pure resolver names
    // the same row (a derived label or the catalog deciding ⇒ no hint).
    let outranked: TestFlowPathLabel["outranked"] = [];
    if (rule !== null && rule.startsWith("label:")) {
      const labels = this.humanLabels();
      if (resolvePathLabel(origin, labels)?.via === rule.slice("label:".length)) {
        outranked = outrankedStricterPatterns(origin, labels);
      }
    }
    return { path: origin, level: m.level, bindings: m.bindings ?? [], axis: true, rule, outranked };
  }

  /** One `pathLevels` entry: the mint-time derivation (user labels, then the
   *  catalog) and, when a human label decided, which store holds it. The page
   *  store wins over policy.yaml on the same path (humanLabels), so it is
   *  asked first. */
  private pathLevelsEntry(path: string, home: string | undefined): PathLevelsEntry {
    const m = confidentialityForOrigin(path, home, this.labelLookup);
    const rule = m.rule ?? null;
    let store: PathLevelsEntry["store"] = null;
    if (rule !== null && rule.startsWith("label:")) {
      const via = rule.slice("label:".length);
      const law = getCurrentPolicy().pathLabels;
      store = this.pathLabels.map().has(via) ? "page"
        : law.has(via) || law.has(GLOB_KEY_PREFIX + via) ? "policy"
        : "models";
    }
    // Plan 13 §5.2: a human label's per-value bindings, and the file's own
    // (`bindings` above is the whole file's, the intersection over them).
    const d = store !== null ? this.labelLookup(normalizeLabelPath(path, home) ?? path) : null;
    const values = d && d.origin !== "derived" && d.values && d.fileBindings
      ? { values: d.values.map((v) => ({ key: v.key, bindings: [...v.bindings] })), fileBindings: [...d.fileBindings] }
      : {};
    return { path, level: m.level, bindings: [...(m.bindings ?? [])], rule, store, ...values };
  }

  /**
   * The sensitive-path gate wrapped by the SAME interactive approval queue as
   * the network egress gate (fs-sync.md §1.4.1). Entries are keyed
   * `fs:<tool>:<mode>` × path, so the existing queue store, dashboard list and
   * `resolveEgressApproval` op work unchanged:
   *   1. a prior human verdict for the pair short-circuits the gate
   *      (approved → allow; denied → deny WITHOUT re-queueing);
   *   2. otherwise the pure gate (`policy.fsPathDecision` → `decideFsPath`)
   *      decides; requiresApproval UPSERTs a pending entry (idempotent).
   * The request's `sessionKey` (attribution only) is stamped onto queued rows.
   */
  private decideFsPathWithApprovals(req: FsPathDecisionRequest, spends: boolean): FsPathDecision {
    const queueable =
      req != null &&
      typeof req.tool === "string" && req.tool !== "" &&
      typeof req.path === "string" && req.path !== "";
    const key = queueable ? `fs:${req.tool}:${req.mode}` : "";
    // Key the queue on the CANONICAL path — the same normalization the pure gate
    // decides on (`normalizeFsPath` mirrors decideFsPath's internal normalize).
    // Keying on the raw req.path let a human "deny" pin only the exact spelling
    // while `/x//y`, `/x/./y`, `~/y` each missed the verdict and re-queued a
    // fresh entry for one target. decideFsPath normalizes internally, so the
    // verdict is identical whichever spelling reaches it.
    const canonicalPath = queueable ? normalizeFsPath(req.path) : req.path;

    if (queueable) {
      const prior = this.consultPriorVerdict(key, canonicalPath, spends);
      if (prior?.status === "approved") {
        return { allow: true, reason: "human-approved", ruleRef: verdictRef(prior.id) };
      }
      if (prior?.status === "denied") {
        return { allow: false, requiresApproval: false, reason: "human-denied", ruleRef: verdictRef(prior.id) };
      }
    }

    const result = this.policy.fsPathDecision(req);

    if (queueable && result.allow === false && result.requiresApproval) {
      const entry = this.egressApprovals.recordPending(key, canonicalPath, result.reason, req.sessionKey);
      return { ...result, approvalId: entry.id };
    }
    return result;
  }

  /**
   * The local-file UPLOAD gate (file-upload.ts) wrapped by the same approval
   * queue as the sensitive-path gate, keyed `fs:<tool>:upload` × the
   * canonical path, so the Approvals page, `resolveEgressApproval` and *Allow
   * once* work unchanged (a prior verdict short-circuits; a fresh ask queues
   * one pending row). From the data socket nothing is consulted, read or
   * queued: the pure gate's rule 2 answers.
   *
   * PATH FIRST (2026-10-17): the path phase (`decideFileUploadByPath`: the
   * path's labels, the catalog, the sensitive and process paths, what is
   * there) answers before a byte is read; only when it does not are the
   * bytes scanned, in chunks (`fileUploadContent`).
   */
  private async decideFileUploadWithApprovals(req: FileUploadDecisionRequest, attested: boolean, onScan?: () => void): Promise<FileUploadDecision> {
    const queueable =
      req != null &&
      typeof req.tool === "string" && req.tool !== "" &&
      typeof req.path === "string" && req.path !== "";
    const key = queueable ? `fs:${req.tool}:upload` : "";
    const canonicalPath = queueable ? normalizeFsPath(req.path) : "";
    if (queueable && attested) {
      const prior = this.consultPriorVerdict(key, canonicalPath, true);
      if (prior?.status === "approved") return { allow: true, reason: "human-approved", ruleRef: verdictRef(prior.id) };
      if (prior?.status === "denied") return { allow: false, requiresApproval: false, reason: "human-denied", ruleRef: verdictRef(prior.id) };
    }
    // The unmapped form (file-upload.ts rule 0): the session's mapping of the
    // tool and, for a registered local MCP server's tool, the guard, asked
    // BEFORE any file is read (an exempt tool's path is never opened). Only
    // for an attested ask (the data socket gets rule 2).
    let exempt: Pick<FileUploadFacts, "mapping" | "confinedServer"> = {};
    if (queueable && attested && req.unmapped === true) {
      const mapping = this.toolMappingFor(req.tool, req.sessionKey);
      exempt = { mapping, confinedServer: mapping === "mcp-config" && this.sessionGuarded(req.sessionKey) };
    }
    const asked = req ?? { tool: "", path: "", destination: "" };
    let facts: FileUploadFacts = isUploadExempt(exempt)
      ? { attested, axis: this.confidentiality, paths: [canonicalPath], labels: [], content: null, ...exempt }
      : { ...this.fileUploadPathFacts(canonicalPath, attested), ...exempt };
    let result = decideFileUploadByPath(asked, facts);
    if (result === null) {
      // Only the bytes can decide (rules 6–8): an attested ask, the axis on,
      // a path no label holds. `presence` was stat'ed in the path phase.
      facts = { ...facts, content: await this.fileUploadContent(canonicalPath, onScan) };
      result = decideFileUpload(asked, facts);
    }
    if (queueable && attested && result.allow === false && result.requiresApproval) {
      const entry = this.egressApprovals.recordPending(key, canonicalPath, result.reason, req.sessionKey);
      return { ...result, approvalId: entry.id };
    }
    return result;
  }

  /**
   * decideFileUpload's PATH facts for one canonical path (no byte read):
   * the path and its real path (through a symlink), each one's label
   * (`labelLookup`: human, catalog, derived and session labels) and
   * registration, each with its bindings, and what the path names (stat).
   * Gathered only for an attested ask; `content` is left null for
   * `fileUploadContent`, which the server calls only when the path phase
   * does not decide.
   */
  private fileUploadPathFacts(canonicalPath: string, attested: boolean): FileUploadFacts {
    const axis = this.confidentiality;
    if (canonicalPath === "" || !canonicalPath.startsWith("/") || !attested) {
      return { attested, axis, paths: canonicalPath ? [canonicalPath] : [], labels: [], content: null };
    }
    const paths = [canonicalPath];
    try {
      const real = realpathSync(canonicalPath);
      if (real !== canonicalPath) paths.push(real);
    } catch { /* a missing file: the stat below says so */ }
    if (!axis) return { attested, axis, paths, labels: [], content: null };
    const labels: UploadLabelFact[] = [];
    const registry = listSecretRegistry(this.symbolMap);
    for (const p of paths) {
      const m = pathConfidentiality(p, undefined, this.labelLookup);
      labels.push({ path: p, level: m.level, bindings: [...(m.bindings ?? [])], rule: m.rule ?? null });
      for (const e of registry) {
        if (e.path === p) labels.push({ path: p, level: parseConfidentialityLevel(e.level), bindings: [...e.bindings], rule: "registry" });
      }
    }
    // What the path names (the unmapped form's rules 4a and 5a; the mapped
    // form decides on `content` alone). Absent on an error other than
    // nothing-there: read as a file whose bytes could not be checked.
    let presence: UploadPresence | undefined;
    try {
      const st = statSync(canonicalPath);
      presence = st.isFile() ? "file" : st.isDirectory() ? "directory" : "special";
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") presence = "missing";
    }
    return { attested, axis, paths, labels, content: null, ...(presence !== undefined ? { presence } : {}) };
  }

  /**
   * The registered secret values in the bytes at `canonicalPath`, each with
   * its row's live level and bindings: the value backstop's matcher
   * (`secretValueHits`) over the file, STREAMED (upload-scan.ts): read in
   * FILE_UPLOAD_SCAN_CHUNK_BYTES chunks, never whole, the event loop free
   * between them. Unreadable (the gate holds) past FILE_UPLOAD_MAX_BYTES,
   * past FILE_UPLOAD_SCAN_DEADLINE_MS, for anything but a regular file, and
   * on any read error.
   */
  private async fileUploadContent(canonicalPath: string, onScan?: () => void): Promise<UploadContentFact> {
    onScan?.(); // the first progress frame: the scan starts
    const scan = await scanFileForValues(canonicalPath, this.syncedValueIndex().stream(), {
      maxBytes: FILE_UPLOAD_MAX_BYTES,
      chunkBytes: FILE_UPLOAD_SCAN_CHUNK_BYTES,
      deadline: Date.now() + this.uploadScanPace.deadlineMs,
      ...(onScan ? { onChunk: () => onScan() } : {}),
    });
    if (scan.kind === "unreadable") return scan;
    // Each value as the egress gate judges it: with every labelled source
    // that holds it (value-sources.ts), the strictest level, the union of
    // the bindings.
    const hits = this.levelledValueHits(scan.hits).map((h) => {
      const row = this.symbolMap.symbols.get(h.symbol);
      const view = row ? this.releaseView(row) : undefined;
      return {
        level: maxConfidentiality(parseConfidentialityLevel(h.level), parseConfidentialityLevel(view?.confidentiality)),
        bindings: [...(view?.bindings ?? [])],
      };
    });
    return { kind: "read", hits };
  }

  /**
   * The provenance half of the exec gate (exec-routing.md §8.7a), wrapped by
   * the SAME approval queue as the network/fs/escalation gates. Candidates:
   *   - each file the command reads as its PROGRAM (programTextPaths) whose
   *     registry row says untrusted-by-origin (a declared net write of this
   *     session, or a kernel-observed file_taint row);
   *   - each program that is not a file argument (stdinPrograms): a `curl … | bash`
   *     pipe or a `$(curl …)`/`<(curl …)` substitution — provenance in the
   *     string, keyed `(stdin)`; and a `cat x | bash` / `bash -c "$(cat x)"` /
   *     `eval "$(<x)"` — the fed file looked up in the registry like a script arg.
   * Entries are keyed `exec-program:<originHost>` × path (`(stdin)` for a pipe)
   * so the queue store, dashboard inbox and `resolveEgressApproval` work
   * unchanged: a prior "approved" lets that candidate through (verdict
   * provenance stamped); a prior "denied" blocks without re-queueing; otherwise
   * a PENDING entry is queued and the command is blocked (fail-closed: the
   * proxy rewrites it to the exit-77 sentinel). Nothing tainted ⇒ the token
   * gate's result passes through untouched.
   */
  private gateProgramText(result: ExecGateResult, command: string, sessionKey: string | undefined, spends: boolean): ExecGateResult {
    const candidates: { path: string; originHost: string }[] = [];
    const seen = new Set<string>();
    const add = (path: string, originHost: string): void => {
      const key = `${originHost}\u0000${path}`;
      if (seen.has(key)) return;
      seen.add(key);
      candidates.push({ path, originHost });
    };
    const lookup = (path: string): void => {
      const trust = this.provenance.programTextTrust({ path, session: sessionKey });
      if (trust.untrusted) add(path, trust.origin ?? "unknown");
    };
    for (const path of programTextPaths(command)) lookup(path);
    for (const sp of stdinPrograms(command)) {
      for (const host of sp.originHosts) add("(stdin)", host);
      for (const file of sp.sourceFiles) lookup(file);
    }
    if (candidates.length === 0) return result;
    let approvedBy: string | undefined;
    for (const c of candidates) {
      const key = `exec-program:${c.originHost}`;
      const what = c.path === "(stdin)"
        ? `code piped from ${c.originHost}`
        : `program text "${c.path}" fetched from ${c.originHost}`;
      const prior = this.consultPriorVerdict(key, c.path, spends);
      if (prior?.status === "approved") { approvedBy = prior.id; continue; }
      if (prior?.status === "denied") {
        this.log(`execGate: PROVENANCE block — ${what} (human-denied ${prior.id})`);
        return {
          ...result, decision: "block",
          reason: `${what} — executing net-fetched code was human-denied`,
          ruleRef: verdictRef(prior.id), programText: c,
        };
      }
      const reason = `${what} — executing net-fetched code requires approval`;
      const entry = this.egressApprovals.recordPending(key, c.path, reason, sessionKey);
      this.log(`execGate: PROVENANCE block — ${what} (pending ${entry.id})`);
      return {
        ...result, decision: "block",
        reason: `${reason} → pending`,
        ruleRef: ruleRef("exec:tainted-program-text"), programText: c, approvalId: entry.id,
      };
    }
    // Every tainted program text carries a standing/once human approval.
    const last = candidates[candidates.length - 1]!;
    return {
      ...result,
      reason: `human-approved execution of net-fetched code (${last.originHost})`,
      ruleRef: verdictRef(approvedBy!), programText: last,
    };
  }

  /** Record the files an ALLOWED command declares it fills with network bytes
   * (`curl -o`, `wget -O`, a redirect/`tee` downstream of a fetcher) as
   * untrusted-by-origin in the taint registry — Track A's declared-write
   * substitute for the kernel fs-supervisor's observed writes (§7a). */
  private recordDeclaredNetWrites(command: string, sessionKey?: string, callId?: string): void {
    for (const w of declaredNetWrites(command)) {
      this.provenance.declareNetWrite({ path: w.path, originHost: w.originHost, session: sessionKey, callId });
      this.log(`execGate: declared net write ${JSON.stringify(w.path)} ← ${w.originHost}`);
    }
  }

  /**
   * The exec escalation gate (exec-routing.md §5), wrapped by the SAME
   * interactive approval queue as the network/fs gates. An AgentShell command
   * that needs a restricted resource (real network / the HumanView filesystem)
   * may escalate to HumanShell ONLY behind a human approval. Entries are keyed
   * `exec-escalate:<resource>` × command-signature, so the queue store, dashboard
   * list and `resolveEgressApproval` op all work unchanged:
   *   - a prior "approved" → HumanShell;
   *   - a prior "denied"   → stay AgentShell (no re-queue);
   *   - otherwise          → queue a PENDING entry and stay AgentShell (fail-safe:
   *                          never escalate protection away without a human OK).
   * `sessionKey` (attribution only) is stamped onto queued rows.
   */
  private decideExecEscalation(
    argv: string[],
    resource: "network" | "original-fs",
    sessionKey: string | undefined,
    spends: boolean,
  ): { shell: "AgentShell" | "HumanShell"; approved: boolean; requiresApproval: boolean; reason: string; ruleRef?: RuleRef; approvalId?: string } {
    const signature = execSignatureForArgv(argv);
    const key = `exec-escalate:${resource}`;
    const prior = signature ? this.consultPriorVerdict(key, signature, spends) : undefined;
    if (prior?.status === "approved") {
      return {
        shell: "HumanShell",
        approved: true,
        requiresApproval: false,
        reason: `human-approved escalation to HumanShell (${resource})`,
        ruleRef: verdictRef(prior.id),
      };
    }
    if (prior?.status === "denied") {
      return {
        shell: "AgentShell",
        approved: false,
        requiresApproval: false,
        reason: `human-denied escalation (${resource}) → stay AgentShell`,
        ruleRef: verdictRef(prior.id),
      };
    }
    // Absent/pending: queue and stay AgentShell (fail-safe — never auto-escalate).
    const reason = `command needs ${resource}; escalation to HumanShell requires approval`;
    const entry = signature
      ? this.egressApprovals.recordPending(key, signature, reason, sessionKey)
      : undefined;
    return {
      shell: "AgentShell",
      approved: false,
      requiresApproval: true,
      reason: `${reason} → pending (stay AgentShell)`,
      ruleRef: ruleRef("exec:escalation-approval"),
      ...(entry ? { approvalId: entry.id } : {}),
    };
  }

  /** Retrieve a recorded tool_use decision by its toolUseId, or undefined if
   * none was recorded. Exposed for OS interceptors embedding the arbiter
   * in-process and for tests; the record is in-memory only. */
  getToolCall(toolUseId: string): ToolCallRecord | undefined {
    return this.toolCalls.get(toolUseId);
  }

  /** The resolved observability event directory (one NDJSON file per session).
   * Exposed for the launcher/tests. */
  get eventDirectory(): string {
    return this.events.directory;
  }
}

/**
 * Resolve true iff a server is ACTIVELY accepting connections on `path` (a live
 * arbiter). A stale socket file from a crashed run fast-rejects with ECONNREFUSED
 * (→ false). Any other error, or a connect that hangs past the short timeout,
 * also returns false (fail toward "not live" so a single bad probe can't wedge
 * startup) — listen() then reclaims the path.
 */
function socketIsLive(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (live: boolean): void => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(live);
    };
    const sock = connect({ path });
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
    sock.setTimeout(1000, () => done(false));
  });
}
