/**
 * server/home-routes — GET /api/home, the PRODUCT home projection
 * (dashboard.md §4.25). One request answers the end-user page's two
 * questions from the same sources the inspector uses:
 *
 *   - the session list, split by session-batches into live / drills / testing
 *     — the product shows LIVE only (a drill or e2e session is never someone's
 *     work);
 *   - each live session in the window (the newest HOME_SESSION_CAP, and every
 *     other one where protection failed), modeled with toSessionViewModel for its
 *     lineage stats + invariant verdict, the blocked steps and sends its
 *     page's story counts, and its secrets as its page's tiles count them
 *     (cached per (id, eventCount, lastTs) and the label times on the files
 *     it read as they were, server/label-times.ts: a session that has not
 *     moved is not re-read unless a file it read was labelled since);
 *   - the policy-panel VM (posture + the approval queue), via the SAME loader
 *     the Policy panel uses;
 *   - the configured protection mode (config-axes);
 *   - how many rule changes wait (the pending policy proposals, the read
 *     GET /api/policy/proposals serves): their number only, for the hero.
 *
 * Read-only, GET, no CSRF: everything it returns is already served by other
 * GET routes; this one composes them so the page needs one fetch.
 */

import { type ServerResponse } from "node:http";
import { homedir } from "node:os";
import { json } from "./http-util.js";
import { type ManduNotRunning } from "../mandu-running.js";
import { type EventSource } from "../event-source.js";
import { type SessionRef } from "../event-source/contract.js";
import { type VerdictEntry } from "../policy-model.js";
import { toSessionViewModel } from "../view-model.js";
import { builtinFiles } from "../view-model/builtin-files.js";
import { discardedWritesOf } from "../view-model/discarded-writes.js";
import { buildAgentPage, buildStory, locateAsk, pageLaterLabels, pageSecrets, revealValues, sessionExited, storyCounts, untrustedMasked, type AgentPageShow, type AgentPageVM } from "../view-model/agent-page.js";
import { baseSymbol } from "../view-model/secret-path.js";
import { buildSidebarSections, type SidebarTestRun, type SidebarWatchRun } from "../session-batches.js";
import { sessionCwd } from "../session-paths.js";
import { believedEvents, recordUnchecked, type ManduEvent } from "../event-model.js";
import { type SessionViewModel } from "../view-model.js";
import { readAxesState, readConfigText } from "../config-axes.js";
import { loadPolicyPanel, loadPolicySnapshot, type ReadFirstLookup } from "./api-routes.js";
import { type ApprovalsArbiter } from "./approval-routes.js";
import { promptLocks, type PromptFiltersArbiter } from "./prompt-filter-routes.js";
import { type PolicyProposalArbiter } from "./policy-proposal-routes.js";
import { type PolicyDocArbiter } from "./policy-doc-routes.js";
import { type IssuerReading } from "../view-model/issuer-words.js";
import { ANSWERED_PAGE, answeredOutcome, answeredPage, buildHistoryViewModel, buildHomeViewModel, historyBefore, historyFactsMatch, historyFlagged, historyListing, historyMatches, historyPage, historyPageWhere, historyWords, homeAgentRow, HISTORY_ONLY_STEPPED_IN, HISTORY_PAGE, HISTORY_PAGE_MAX, HISTORY_QUERY_MAX, HISTORY_SCAN_BUDGET, isAgentSession, rowContext, sessionNeighbours, steppedIn, windowCountedNothing, type FoundName, type HistoryVM, type HomeLastSteppedIn, type HomeSessionFacts, type HomeVM } from "../view-model/home.js";
import { toPolicyPanelViewModel } from "../view-model/policy-panel.js";
import { redactEvents } from "../view-model/redact.js";
import { readFirstByBase, readFirstByFile, symbolBase } from "../view-model/lineage.js";
import { plainReads, type LabelTime } from "../view-model/later-labels.js";
import { LabelTimes, type LabelTimesArbiter } from "./label-times.js";
import { sendHosts, sessionKept } from "../view-model/session-kept.js";
import { releaseVersion } from "../release-version.js";
import { configuredUpdateCheck, updateCheckSetting, type LayoutMode, type UpdateCache, type UpdateChannel } from "../update-notice.js";
import { homeScanCard, type LastScanWire } from "../view-model/last-scan.js";
import { type OpenPlace } from "../data-locations.js";

/** The window the home counts cover. A day is what "today" means to a person
 *  glancing at the page; the copy names the hours so it is never a guess. */
export const HOME_WINDOW_HOURS = 24;
/** Sessions modeled per request, newest first, plus every other one in the
 *  window where protection failed (`buildHome`). Beyond it the window's counts
 *  are a floor, which the page says (`window.counted`, dashboard.md §4.25). */
export const HOME_SESSION_CAP = 25;

/** The session's BELIEVED events (a claimed one, arbiter-human-plane.md
 *  §10.2, may not make a safety claim) and their view-model: `vm` itself
 *  when every event is believed, null when none is. The session's page and
 *  its Home row read the same. */
function believedView(sessionId: string, events: readonly ManduEvent[], vm: SessionViewModel | null): { believed: ManduEvent[]; believedVm: SessionViewModel | null } {
  const believed = believedEvents(events);
  const believedVm = believed.length === events.length ? vm : believed.length ? toSessionViewModel(sessionId, believed) : null;
  return { believed, believedVm };
}

interface FactsCacheEntry {
  key: string;
  facts: HomeSessionFacts;
  /** The files the session read as they were (later-labels.ts
   *  `plainReads`), and the label times on them the facts were counted
   *  with (`labelSig`): a label made after the session ended changes its
   *  counts, though its listing does not move. */
  paths: string[];
  sig: string;
  /** The base symbols of the session's masked items, and the registered
   *  files they stand for that the facts were named with (`filesSig`): a
   *  secret registered after the session renames its card, so its count's
   *  grouping, though its listing does not move. */
  bases: string[];
  filesSig: string;
}

/** The registry's files of `bases`, as one string to compare. */
function filesSig(files: ReadonlyMap<string, string>, bases: readonly string[]): string {
  return bases.map((b) => `${b}\u0000${files.get(b) ?? ""}`).join("\n");
}

/** The label times as one comparable string (order-free). */
function labelSig(labels: readonly LabelTime[]): string {
  return labels.map((l) => `${l.path}\u0000${l.level}\u0000${l.at}`).sort().join("\n");
}

/** How many files the session's last believed exit names as changed in
 *  their masked copy (`discardedWritesOf`, the page's block), as a fact
 *  only when there is one: a count, never a path (dashboard.md §4.25b). */
function notAppliedOf(events: readonly ManduEvent[], home: string): { notApplied?: number } {
  const d = discardedWritesOf(events, home);
  return d ? { notApplied: d.files.length + d.more } : {};
}

export class HomeFacts {
  private readonly cache = new Map<string, FactsCacheEntry>();

  /** `home`: the folder the page's `~` stands for (HomeDeps `home`), so a
   *  row counts the secrets its page groups under the same names.
   *  `labels`: where the label times on the files a session read are read
   *  (server/label-times.ts), late-bound with the arbiter; absent or
   *  undefined: none, so no row counts a file labelled after its session. */
  constructor(private readonly source: EventSource, private readonly home: string = homedir(), private readonly labels?: () => LabelTimesArbiter | undefined) {}

  /** One request's label reads: pass it to each `of` of that request, so a
   *  read is made once. */
  labelTimes(): LabelTimes {
    return new LabelTimes(this.labels?.(), this.home);
  }

  /** The files the cached sessions `ids` read as they were (none for one
   *  not cached yet): what a request asks the label times of at once. */
  pathsOf(ids: Iterable<string>): string[] {
    const out = new Set<string>();
    for (const id of ids) for (const p of this.cache.get(id)?.paths ?? []) out.add(p);
    return [...out];
  }

  /** Facts for one session, re-derived only when its listing moved or the
   *  label times on the files it read changed. `times`: the request's label
   *  reads (`labelTimes`); absent: a cached entry is taken as it is. */
  async of(s: SessionRef, times?: LabelTimes): Promise<HomeSessionFacts> {
    const key = `${s.eventCount}|${s.lastTs ?? ""}`;
    const hit = this.cache.get(s.id);
    if (hit && hit.key === key) {
      if (!times) return hit.facts;
      if (await this.fresh(hit, times)) return hit.facts;
    }
    const events = await this.source.readEvents(s.id);
    return this.derive(s.id, key, events, times);
  }

  /** Facts for the session `id`, read now and cached as `of` caches them
   *  (the launcher's end-of-session line, dashboard.md §4.25ah, asks for a
   *  session that just ended, before any listing has moved): null when the
   *  record holds no event of it. */
  async ofId(id: string, times?: LabelTimes): Promise<HomeSessionFacts | null> {
    const events = await this.source.readEvents(id);
    if (!events.length) return null;
    const key = `${events.length}|${events[events.length - 1]!.ts ?? ""}`;
    const hit = this.cache.get(id);
    if (hit && hit.key === key && (!times || await this.fresh(hit, times))) return hit.facts;
    return this.derive(id, key, events, times);
  }

  /** A cached entry still holds: the label times on its files and the
   *  registered files of its items are the ones it was counted with. */
  private async fresh(hit: FactsCacheEntry, times: LabelTimes): Promise<boolean> {
    if (labelSig(await times.of(hit.paths)) !== hit.sig) return false;
    return !hit.bases.length || filesSig(await times.registeredFiles(), hit.bases) === hit.filesSig;
  }

  private async derive(id: string, key: string, events: ManduEvent[], times?: LabelTimes): Promise<HomeSessionFacts> {
    const vm = toSessionViewModel(id, events);
    // Counted over the story the session's page tells, so its row and its
    // page agree (no values: an outcome never depends on one).
    const turns = buildStory(vm);
    const { blocked, sent } = storyCounts(turns);
    // Its secrets as its page's tiles count them, by each Your secrets
    // card's first line, from the same believed events, with the labels
    // made after it read their files (dashboard.md §4.25b).
    const { believed, believedVm } = believedView(id, events, vm);
    const cwd = sessionCwd(events);
    const paths = [...new Set(plainReads(vm, cwd, this.home).map((r) => r.path))];
    const reads = times ?? this.labelTimes();
    const labels = await reads.of(paths);
    const laterInput = { labels, cwd };
    // The file each placeholder stands for (the registry's), so a row
    // groups its secrets under the names its page does (§4.25b).
    const bases = [...new Set(vm.lineage.flows.map((f) => baseSymbol(f.root)).filter((b): b is string => b !== null))].sort();
    const files = bases.length ? await reads.registeredFiles() : new Map<string, string>();
    const later = vm.dualLanes.steps.flatMap((st) => (st.step === "tool" && st.maskedLater ? [st.maskedLater] : []));
    const origins = new Map(vm.symbols.map((r) => [r.name, r.origin]));
    // A file read as it was before its label is a file the AI has seen,
    // as the trace's `maskedLater` reads are (§4.34).
    const readFirstFiles = readFirstByFile(later, (name) => origins.get(name));
    for (const l of pageLaterLabels(vm, believedVm, this.home, laterInput)) {
      const ts = l.reads[0]!.ts;
      const had = readFirstFiles.get(l.path);
      if (had === undefined || ts < had) readFirstFiles.set(l.path, ts);
    }
    // A record Mandu could not check (every event a claim, or a launch with
    // no wall) says so; it never raises a count (dashboard.md §4.25ah).
    const story = pageSecrets(vm, believed, believedVm, this.home, undefined, laterInput, { unchecked: recordUnchecked(events), ...(files.size ? { files } : {}) });
    // The line's blocks and sends: the believed story's (a claim never
    // raises the line's count); the same as the row's when nothing is a claim.
    const believedTurns = believedVm === vm ? turns : believedVm ? buildStory(believedVm) : [];
    const keptCounts = believedVm === vm ? { blocked, sent } : storyCounts(believedTurns);
    const facts: HomeSessionFacts = {
      stats: vm.lineage.stats,
      secrets: story.counts,
      untrusted: untrustedMasked(vm.lineage.stats, vm.paired.mode),
      blocked,
      sent,
      holds: vm.invariant.holds,
      violations: vm.invariant.violationCount,
      // The mode the session recorded, never today's (dashboard.md §4.25).
      off: vm.paired.mode === "off",
      cwd,
      // The session page's rule, so Home's "Running now" and the page agree.
      exited: sessionExited(events),
      // The changes its page lists as not applied, counted from a believed
      // exit only (dashboard.md §4.25b *Home and History say so*); the row
      // shows them once it ended.
      ...notAppliedOf(events, this.home),
      // What the AI read as it was before it was masked, so a waiting card
      // about it never says the AI never read it (dashboard.md §4.34).
      readFirst: readFirstByBase(later),
      // The same by the file each came from, so a waiting card about a
      // program reading that file never says the AI has not seen it.
      readFirstFiles,
      // The same counts with the names behind them, for the line the
      // launcher prints when the session ends (dashboard.md §4.25ah), over
      // the believed events only.
      kept: sessionKept(story, believedTurns, keptCounts),
      // The hosts its sends went to or were stopped on their way to, over
      // the same believed story: what History's search finds it by beside
      // the names above (§4.25ae *By a secret or a host*). Hosts only.
      hosts: sendHosts(believedTurns),
    };
    this.cache.set(id, { key, facts, paths, sig: labelSig(labels), bases, filesSig: filesSig(files, bases) });
    return facts;
  }

  /** Drop entries for sessions no longer listed (a deleted session). */
  prune(live: Iterable<string>): void {
    const keep = new Set(live);
    for (const id of [...this.cache.keys()]) if (!keep.has(id)) this.cache.delete(id);
  }
}

/** A waiting row about a program reading a secret file (`open:`, or the
 *  warning question `trust:`), whose destination is that file. */
function programReadsFile(v: VerdictEntry): boolean {
  return (v.symbol.startsWith("open:") || v.symbol.startsWith("trust:")) && typeof v.destination === "string" && v.destination.startsWith("/");
}

/** When the AI first read each waiting row's item as it was, before it was
 *  masked, in any session on the row (by verdict id; dashboard.md §4.34
 *  "Read before it was marked"): the earliest such time over those
 *  sessions' facts, cached as Home keeps them, so a session that has not
 *  moved is not re-read. A `$MDU:` row is looked up by its token's base; a
 *  program's request to read a secret file (`open:`, `trust:`) by that file.
 *  A session not listed, or unreadable, adds nothing. `list`: the sessions
 *  on record (a caller that has listed them passes its own). */
export function readFirstLookup(facts: HomeFacts, list: () => Promise<SessionRef[]>): ReadFirstLookup {
  return async (verdicts) => {
    const out = new Map<string, string>();
    const asks = verdicts.filter((v) => v.status === "pending" && typeof v.symbol === "string" && (v.symbol.startsWith("$MDU:") || programReadsFile(v)) && (v.sessions?.length ?? 0) > 0);
    if (!asks.length) return out;
    const refs = new Map((await list()).map((s) => [s.id, s]));
    for (const v of asks) {
      const file = v.symbol.startsWith("$MDU:") ? null : v.destination;
      const base = symbolBase(v.symbol);
      for (const id of v.sessions ?? []) {
        const s = refs.get(id);
        if (!s) continue;
        let ts: string | undefined;
        try {
          const f = await facts.of(s);
          ts = file === null ? f.readFirst?.get(base) : f.readFirstFiles?.get(file);
        } catch {
          ts = undefined;
        }
        const had = out.get(v.id);
        if (ts !== undefined && (had === undefined || ts < had)) out.set(v.id, ts);
      }
    }
    return out;
  };
}

export interface HomeDeps {
  source: EventSource;
  facts: HomeFacts;
  approvals: ApprovalsArbiter | undefined;
  /** Where the agent page reads the prompt filter's locks in force (the
   *  arbiter's `promptFilters`), so a note offers no let-through the arbiter
   *  refuses. Absent: the events alone decide. */
  prompt?: Pick<PromptFiltersArbiter, "promptFilters">;
  /** Where Home reads how many rule changes wait (the arbiter's pending
   *  `policyProposals`, as Approvals lists them), so the hero counts what
   *  the Approvals badge counts. Absent, or a read that fails: none. */
  proposals?: Pick<PolicyProposalArbiter, "policyProposals">;
  /** Where Home reads policy.yaml's `issuer_bindings` as in force (the
   *  arbiter's `policyDocument`), for Rules › Built-in protections, and in
   *  the same read the file's status, for Home's card on an edit Mandu
   *  refused. Display only. Absent, or a read that fails: the item says it
   *  does not know, and no card shows. */
  policy?: Pick<PolicyDocArbiter, "policyDocument">;
  /** The test runs whose sessions are not the person's own (the
   *  developer view's; none in a product-only build). */
  testRuns: SidebarTestRun[];
  watchRuns: SidebarWatchRun[];
  env: Record<string, string | undefined>;
  now?: () => number;
  /** The folder `~` stands for on the product pages (the Rules page's file
   *  browser's; the server's test seam). Absent: `os.homedir()`, the
   *  person's own, since the dashboard runs as them. */
  home?: string;
  /** The build serves the developer view (the inspector extension,
   *  dashboard.md §4.25ac): the product's words may point to the detailed
   *  trace. False: none does (§4.25ad). Absent = true. */
  dev?: boolean;
  /** The last `mandu scan` the launcher kept (last-scan.ts
   *  through scan-routes.ts `LastScanCache`; dashboard.md §4.25ai): null,
   *  none was kept. Absent:
   *  Home has no scan card (a test seam). */
  lastScan?: () => LastScanWire | null;
  /** That scan's `rev`, the one `/api/scan` sends (null: none kept), for
   *  the card (`HomeScanCard.rev`): the Scan page reads again when it
   *  changed (§4.25ai *The Scan page follows a new scan*). Absent: the
   *  card carries none. */
  lastScanRev?: () => string | null;
  /** The launcher's update-check cache (update-notice.ts
   *  UpdateCacheReader: null, absent or refused), the channel this
   *  package updates through and its layout (installed or a source
   *  checkout: whether the launcher checks), for About Mandu's *A newer release*
   *  (dashboard.md §4.25). A file read, never a network request. Absent:
   *  not read (a test seam), and the row says nothing of updates. */
  updateCheck?: { cache: () => UpdateCache | null; channel: () => UpdateChannel; layout: () => LayoutMode };
  /** Is Mandu running at all (mandu-running.ts `manduNotRunning`)? Asked
   *  only when the session list could not be read: not running, Home says
   *  protection is off (§4.25, *Protection is off when nothing runs*);
   *  null, or absent (the test tenant, a test seam), the read's failure
   *  stands and the page says "Not connected.". */
  notRunning?: () => ManduNotRunning | null;
  /** The scope ids of the `mandu` launches alive now (mandu-running.ts
   *  `liveLaunches`: a `readdir` of the runtime base and a `kill(0)` per
   *  launch), read once per build: a session among them with no recorded
   *  exit stays running however long it has been quiet (`withLive`,
   *  dashboard.md §4.10.4 *A live launch keeps R*). Absent (the test tenant,
   *  a test seam): the recency rule alone, as before. */
  live?: () => ReadonlySet<string>;
  /** The viewer's sign-in to the dashboard account (server.ts, dashboard.md
   *  §6.z), copied to the page as `signIn`. Absent: none (a test seam). */
  signIn?: HomeVM["signIn"];
  /** The places in Mandu's folder other people on this computer can open
   *  (data-locations.ts `openPlacesOf` over `buildDataLocations`: a `stat`
   *  per place, metadata only), for Home's warning card (dashboard.md
   *  §4.25q *Home warns about open places*). Asked on every Home read, no
   *  cache, so the card goes on the next poll once the modes are fixed.
   *  Absent: not read (a test seam), no card. */
  openPlaces?: () => OpenPlace[];
}

/** The live launches `deps.live` reads now (none without the dep, or when
 *  the read throws: display only, the recency rule then decides). */
function liveRead(deps: Pick<HomeDeps, "live">): ReadonlySet<string> {
  try {
    return deps.live?.() ?? new Set();
  } catch {
    return new Set();
  }
}

/**
 * The listed sessions, those whose `mandu` launch is alive (`live`, from
 * `liveLaunches`) marked `live` (SessionRef.live), so `sessionStatus` keeps
 * them running past the recency window. COPIES: a source caches its
 * SessionRefs (arbiter-source.ts), and a mark left on one would keep a dead
 * launch's session running until its next event.
 */
export function withLive(all: SessionRef[], live: ReadonlySet<string>): SessionRef[] {
  if (live.size === 0) return all;
  return all.map((s) => (live.has(s.id) ? { ...s, live: true as const } : s));
}

export async function buildHome(deps: HomeDeps): Promise<HomeVM> {
  const nowMs = (deps.now ?? Date.now)();
  let all: SessionRef[];
  let notRunning: ManduNotRunning | null = null;
  try {
    all = withLive(await deps.source.listSessions(), liveRead(deps));
  } catch (err) {
    // No arbiter answered. Nothing of Mandu's running is not a fault: the
    // page says protection is off, with no session (none can be read, and
    // no agent runs under Mandu). Anything else is the fault it was.
    notRunning = deps.notRunning?.() ?? null;
    if (notRunning === null) throw err;
    all = [];
  }
  const sections = buildSidebarSections(all, deps.testRuns, nowMs, undefined, deps.watchRuns);
  // Newest first, as the sidebar lists them; status is stamped by the section
  // builder. The System logs group (the admin log, the net-guard fallback) is
  // in Live for the inspector's sidebar, but holds no agent: never a row, a
  // count or the history's number here (`isAgentSession`).
  const live = sections.live.flatMap((b) => b.sessions).filter(isAgentSession);
  deps.facts.prune(live.map((s) => s.id));
  const since = nowMs - HOME_WINDOW_HOURS * 3_600_000;
  // The newest HOME_SESSION_CAP, and every other session in the window the
  // listing flags violated (the oracle's per-event flag, read from every
  // session's events): the cap never hides a failure behind a green hero
  // (the verdict ladder, dashboard.md §4.25).
  const modeled = live
    .filter((s) => s.lastTs && Date.parse(s.lastTs) >= since)
    .filter((s, i) => i < HOME_SESSION_CAP || s.violated);
  const facts = new Map<string, HomeSessionFacts>();
  // The label times on the files these sessions read, asked at once for the
  // cached ones (a label made after a session ended changes its counts).
  const times = deps.facts.labelTimes();
  await times.of(deps.facts.pathsOf(modeled.map((s) => s.id)));
  for (const s of modeled) {
    try {
      facts.set(s.id, await deps.facts.of(s, times));
    } catch {
      // An unreadable session contributes nothing; the page shows what it has.
    }
  }
  // Asked beside the panel; it never rejects (pendingProposals).
  const proposalsRead = pendingProposals(deps.proposals);
  // One read of the policy document: its `issuer_bindings` for Rules ›
  // Built-in protections, its file status for the refused-edit card.
  const policyRead = policyDocumentRead(deps.policy);
  // The waiting cards' words read the asking sessions' records too, so one
  // about an item the AI read before it was masked says so (§4.34).
  const panel = await loadPolicyPanel(deps.source, deps.approvals, readFirstLookup(deps.facts, async () => all), deps.home ?? homedir());
  // config.toml, read once for the mode and About Mandu's `update-check`
  // key. Neither read throws: an absent or unreadable file configures
  // nothing (the defaults; the key unset).
  const configText = readConfigText(deps.env);
  const configuredMode = readAxesState(deps.env, () => configText).effectiveMode;
  const proposalsWaiting = await proposalsRead;
  const { issuerBindings, policyFile: policyFileStatus, lawHash } = await policyRead;
  // The last `mandu scan` (§4.25ai): a stat per request, read again only
  // when the file changed (scan-routes.ts LastScanCache; never a value), so
  // a scan run meanwhile shows on the poll. Its sessions per agent pick the
  // commands Home names (`start`).
  const scan = deps.lastScan ? deps.lastScan() : undefined;
  const vm = buildHomeViewModel({
    sessions: live,
    agentOf: new Map(all.map((s) => [s.id, s])),
    facts,
    panel,
    configuredMode,
    nowMs,
    windowHours: HOME_WINDOW_HOURS,
    historyTotal: live.length,
    home: deps.home ?? homedir(),
    dev: deps.dev !== false,
    proposalsWaiting,
    version: releaseVersion(),
    // The launcher's last update check (a stat per poll, a read only when
    // the file changed): read, never asked of the network. With no answer,
    // whether the launcher checks at all: the config key, else the layout.
    update: deps.updateCheck ? {
      cache: deps.updateCheck.cache(),
      channel: deps.updateCheck.channel(),
      check: updateCheckSetting(configuredUpdateCheck(configText), deps.updateCheck.layout()),
    } : undefined,
    issuerBindings,
    ...(policyFileStatus !== undefined ? { policyFileStatus } : {}),
    ...(lawHash !== undefined ? { lawHash } : {}),
    notRunning,
    scanSessions: scan?.sessions ?? null,
  });
  if (scan !== undefined) {
    vm.scan = homeScanCard(scan, vm.start);
    if (deps.lastScanRev) vm.scan.rev = deps.lastScanRev();
  }
  if (deps.signIn) vm.signIn = deps.signIn;
  // Places in Mandu's folder open to others (§4.25q): only when there are
  // any. A read that throws says nothing, as a missing reader does.
  const open = openPlacesRead(deps.openPlaces);
  if (open.length) vm.openPlaces = open;
  // The window counts nothing: when Mandu last stepped in before it (§4.25
  // *An empty window says when Mandu last stepped in*).
  if (windowCountedNothing(vm)) {
    const last = await lastSteppedIn(deps, live, since, rowContext(panel), nowMs);
    if (last) vm.lastSteppedIn = last;
  }
  return vm;
}

/** The open places `read` finds; none when there is no reader or it throws. */
function openPlacesRead(read: HomeDeps["openPlaces"]): OpenPlace[] {
  if (!read) return [];
  try {
    return read();
  } catch {
    return [];
  }
}

/** The answer of the last look-through per `HomeFacts` (one per server),
 *  with what it was looked up over. */
const lastSteppedInMemo = new WeakMap<HomeFacts, { key: string; value: HomeLastSteppedIn | null }>();

/**
 * The newest session that ended before the window (its last event before
 * `since`) where Mandu stepped in, as History's switch keeps it (`steppedIn`
 * over its row, counted as its row is, with the questions it raised that
 * still wait), looked through newest first, at most HISTORY_SCAN_BUDGET
 * (dashboard.md §4.25 *An empty window says when Mandu last stepped in*).
 * A session in the window is never named: its counts are the window's.
 * Metadata only (id, agent, folder, time, and its row's numbers as
 * `counts`, from the row already built). The answer is kept while the
 * sessions looked through, their waiting questions and the minute are the
 * same, so a 10-second poll looks through again at most once a minute (a
 * label made later can change a row's counts). null: none, or the
 * look-through failed.
 */
async function lastSteppedIn(deps: HomeDeps, live: readonly SessionRef[], since: number, context: { waiting: Map<string, number>; masking: boolean }, nowMs: number): Promise<HomeLastSteppedIn | null> {
  const before = live.filter((s) => {
    const last = s.lastTs ? Date.parse(s.lastTs) : NaN;
    return Number.isFinite(last) && last < since;
  });
  const looked = before.slice(0, HISTORY_SCAN_BUDGET);
  const key = [
    Math.floor(nowMs / 60_000),
    context.masking,
    ...looked.map((s) => `${s.id}|${s.eventCount}|${s.lastTs}|${context.waiting.get(s.id) ?? 0}`),
  ].join("\n");
  const kept = lastSteppedInMemo.get(deps.facts);
  if (kept && kept.key === key) return kept.value;
  let value: HomeLastSteppedIn | null = null;
  try {
    const times = deps.facts.labelTimes();
    await times.of(deps.facts.pathsOf(looked.map((s) => s.id)));
    const rowOf = async (s: SessionRef) => {
      let f: HomeSessionFacts | undefined;
      try {
        f = await deps.facts.of(s, times);
      } catch {
        // An unreadable session keeps its listing's verdict, as on History.
        f = undefined;
      }
      return homeAgentRow(s, f, context.waiting.get(s.id) ?? 0, context.masking);
    };
    const { page } = await historyPageWhere(looked, null, 1, HISTORY_SCAN_BUDGET, async (s) => steppedIn(await rowOf(s)));
    const s = page[0];
    if (s?.lastTs) {
      const row = await rowOf(s);
      const counts = {
        secrets: { masked: row.secrets.masked, early: row.secrets.early },
        untrusted: row.untrusted, blocked: row.blocked, sent: row.sent, waiting: row.waiting,
        holds: row.holds, protectionOff: row.protectionOff,
        ...(row.lessProtection ? { lessProtection: true as const } : {}),
      };
      value = { id: s.id, agent: row.agent, cwd: row.cwd, at: s.lastTs, counts };
    }
  } catch {
    // Nothing found, nothing said: the line stays as it was.
    return null;
  }
  lastSteppedInMemo.set(deps.facts, { key, value });
  return value;
}

/** policy.yaml's `issuer_bindings` as in force (dashboard.md §4.25z): the
 *  raw value, which the view model reads as the arbiter compiles it. No
 *  reader, or a read that fails: not read, never a guess. It never rejects. */
async function issuerBindingsRead(arbiter: HomeDeps["policy"]): Promise<IssuerReading> {
  return (await policyDocumentRead(arbiter)).issuerBindings;
}

/** One read of the policy document for Home: `issuer_bindings` as in force
 *  (issuerBindingsRead), and the file's `status` as the arbiter reports it,
 *  for the card on an edit it refused (dashboard.md §4.25 *An edit to
 *  policy.yaml Mandu refused*; the view model keeps its count, never its
 *  problems), and the version of the law in force (`lawHash`, for Rules'
 *  `rulesVersion`, §4.25 *Rules follows a change made elsewhere*). No
 *  reader, or a read that fails: none is read, and `policyFile` and
 *  `lawHash` are absent. It never rejects. */
async function policyDocumentRead(arbiter: HomeDeps["policy"]): Promise<{ issuerBindings: IssuerReading; policyFile?: unknown; lawHash?: string }> {
  if (!arbiter) return { issuerBindings: { read: false } };
  try {
    const view = await arbiter.policyDocument();
    const status = view?.status;
    const policyFile = {
      ...(status !== undefined && status !== null ? { policyFile: status } : {}),
      ...(typeof view?.lawHash === "string" && view.lawHash !== "" ? { lawHash: view.lawHash } : {}),
    };
    const doc = view?.inForce;
    if (doc !== undefined && doc !== null && (typeof doc !== "object" || Array.isArray(doc))) return { issuerBindings: { read: false }, ...policyFile };
    return { issuerBindings: { read: true, raw: (doc as Record<string, unknown> | null | undefined)?.["issuer_bindings"] }, ...policyFile };
  } catch {
    return { issuerBindings: { read: false } };
  }
}

/** How many rule changes wait for the person (dashboard.md §4.25, the
 *  verdict ladder): the count only, never a proposal's words. No read, or
 *  one that fails: 0, and the hero counts the questions alone. */
async function pendingProposals(arbiter: HomeDeps["proposals"]): Promise<number> {
  if (!arbiter?.policyProposals) return 0;
  try {
    const r = await arbiter.policyProposals("pending");
    return Array.isArray(r?.proposals) ? r.proposals.filter((p) => p?.status === "pending").length : 0;
  } catch {
    return 0;
  }
}

/** Folders the Suggested view's Scan reads (dashboard.md §4.25r): where the
 *  recorded LIVE sessions worked (each session's cwd, the same fact the home
 *  shows per agent), newest first, deduplicated, at most `max`. No time
 *  window: a project worked in last month still holds its history. */
export async function recentWorkspaces(deps: Pick<HomeDeps, "source" | "facts" | "testRuns" | "watchRuns" | "now" | "live">, max = 10): Promise<string[]> {
  const nowMs = (deps.now ?? Date.now)();
  const all = withLive(await deps.source.listSessions(), liveRead(deps));
  const sections = buildSidebarSections(all, deps.testRuns, nowMs, undefined, deps.watchRuns);
  const live = sections.live.flatMap((b) => b.sessions).filter(isAgentSession).slice(0, HOME_SESSION_CAP);
  const out: string[] = [];
  for (const s of live) {
    let cwd: string | null = null;
    try {
      cwd = (await deps.facts.of(s)).cwd;
    } catch {
      cwd = null;
    }
    if (cwd && cwd.startsWith("/") && !out.includes(cwd)) out.push(cwd);
    if (out.length >= max) break;
  }
  return out;
}

/** GET /api/home. `?files=1` (the Rules page, once) adds the Which files
 *  fold's lists where the mode has the fold (`builtIn.filesAt`, dashboard.md
 *  §4.25z): fixed copy, kept out of the polled home. */
export async function apiHome(deps: HomeDeps, res: ServerResponse, url = ""): Promise<void> {
  const vm = await buildHome(deps);
  const q = new URLSearchParams(url.includes("?") ? url.slice(url.indexOf("?") + 1) : "");
  if (q.get("files") === "1" && vm.builtIn.filesAt !== null) vm.builtIn.files = builtinFiles();
  json(res, 200, vm);
}

// ── GET /api/home/history?after=<id>&limit=<n>&q=<words>&only=stepped-in&before=<ms> ─

/** Every agent session on record, newest first, as the History page lists
 *  them (dashboard.md §4.25ae): the live sessions Home reads (no test or
 *  drill run, no system log), with no time window, one page past `after`.
 *  Each row is counted as its Home row is (`HomeFacts`, cached per session),
 *  so a row, Home's and the page it opens agree, and with the questions it
 *  raised that still wait (the queue `/api/home` reads). Metadata only:
 *  names, times, counts, the session's prompt label (as `/api/sessions`
 *  serves). `q`: a search (§4.25ae *Finding a session*), matched on each
 *  row's agent, served label and folder (`historyMatches`) and, for a
 *  session those do not find, on its secrets' and hosts' names from its
 *  cached facts (`historyFactsMatch`, §4.25ae *By a secret or a host*;
 *  such a row carries `found`). The search looks through the sessions from
 *  the newest to HISTORY_SCAN_BUDGET past `after`, so `total` counts the
 *  matches among them and `next` and Show more page through them; when it
 *  stopped short of the oldest, `query.through` says how far it looked.
 *  `only`: the switch (§4.25ae *Only the sessions where Mandu stepped
 *  in*), the rows `historyFlagged` keeps, looked through as they are
 *  counted, at most HISTORY_SCAN_BUDGET a read; with `q`, both hold, and
 *  `total` is every session it may look through. `before`: a day (§4.25ae
 *  *Go to a day*), the sessions whose last moment is before it
 *  (`historyBefore`; the browser sends the start of the day after the one
 *  chosen, so the server needs no time zone), cut first; every filter
 *  holds together. */
export async function buildHistoryFor(deps: HomeDeps, after: string | null, limit: number, q = "", only = false, before: number | null = null): Promise<HistoryVM> {
  const nowMs = (deps.now ?? Date.now)();
  const all = withLive(await deps.source.listSessions(), liveRead(deps));
  const sections = buildSidebarSections(all, deps.testRuns, nowMs, undefined, deps.watchRuns);
  const live = sections.live.flatMap((b) => b.sessions).filter(isAgentSession);
  const bounded = before !== null && Number.isFinite(before);
  const dated = bounded ? historyBefore(live, before) : live;
  const words = historyWords(q);
  // Matched as the rows draw it: the folder `~`-shortened with this home.
  const home = deps.home ?? homedir();
  const listed = new Set(words.length ? historyMatches(dated, q, home).map((s) => s.id) : []);
  // The asks still waiting, by the session that raised each, as Home's rows
  // count them (§4.25ae *History says what waits for you*): the queue Home
  // reads, without the words its cards need. No snapshot: none waits.
  const panel = toPolicyPanelViewModel(await loadPolicySnapshot(deps.source, deps.approvals));
  const context = rowContext(panel);
  const facts = new Map<string, HomeSessionFacts>();
  const times = deps.facts.labelTimes();
  const count = async (s: SessionRef): Promise<HomeSessionFacts | undefined> => {
    try {
      const f = await deps.facts.of(s, times);
      facts.set(s.id, f);
      return f;
    } catch {
      // An unreadable session keeps its listing's verdict and no counts.
      return undefined;
    }
  };
  // With a search: a session its listing finds is found (§4.25ae *Finding
  // a session*); any other, by its secrets and hosts (*By a secret or a
  // host*), the names it was found by kept for its row.
  const found = new Map<string, FoundName[]>();
  const matches = async (s: SessionRef): Promise<boolean> => {
    if (!words.length || listed.has(s.id)) return true;
    const names = historyFactsMatch(words, historyListing(s, home), await count(s), home);
    if (names) found.set(s.id, names);
    return names !== null;
  };
  const at = after === null ? -1 : dated.findIndex((s) => s.id === after);
  let cut: { page: SessionRef[]; next: string | null; through?: number };
  let total = dated.length;
  let looked: number | null = null;
  if (only) {
    // The label times of the cached sessions it may look through, asked at once.
    await times.of(deps.facts.pathsOf(dated.slice(at + 1, at + 1 + HISTORY_SCAN_BUDGET).map((s) => s.id)));
    cut = await historyPageWhere(dated, after, limit, HISTORY_SCAN_BUDGET, async (s) =>
      await matches(s) && historyFlagged(homeAgentRow(s, await count(s), context.waiting.get(s.id) ?? 0, context.masking)));
  } else if (words.length) {
    // Looked through from the newest, so `total` counts every match before
    // where it stops; a session looked through on an earlier read is cached.
    const end = Math.min(dated.length, at + 1 + HISTORY_SCAN_BUDGET);
    await times.of(deps.facts.pathsOf(dated.slice(0, end).filter((s) => !listed.has(s.id)).map((s) => s.id)));
    const hits: number[] = [];
    for (let i = 0; i < end; i++) if (await matches(dated[i]!)) hits.push(i);
    const n = Math.max(1, Math.min(HISTORY_PAGE_MAX, Math.floor(Number.isFinite(limit) ? limit : HISTORY_PAGE)));
    const past = hits.filter((i) => i > at);
    const page = past.slice(0, n).map((i) => dated[i]!);
    const next = past.length > n ? page[page.length - 1]!.id : end < dated.length ? dated[end - 1]!.id : null;
    cut = { page, next };
    total = hits.length;
    if (end < dated.length) looked = end;
    await times.of(deps.facts.pathsOf(page.map((s) => s.id)));
    for (const s of page) if (!facts.has(s.id)) await count(s);
  } else {
    cut = historyPage(dated, after, limit);
    await times.of(deps.facts.pathsOf(cut.page.map((s) => s.id)));
    for (const s of cut.page) await count(s);
  }
  const query = words.length ? { query: { text: words.join(" "), all: live.length, ...(looked !== null ? { through: looked, of: dated.length } : {}) } } : {};
  const filtered = only ? { only: { through: cut.through ?? 0 } } : {};
  const day = bounded ? { before: { at: before, all: live.length } } : {};
  return buildHistoryViewModel({ total, page: cut.page, next: cut.next, facts, found, ...context, ...query, ...filtered, ...day });
}

/** A History read's `before` (§4.25ae *Go to a day*): epoch milliseconds;
 *  absent, empty or not a finite number reads as no day. Pure. */
export function historyBeforeParam(raw: string | null): number | null {
  if (raw === null || raw.trim() === "") return null;
  const ms = Number(raw);
  return Number.isFinite(ms) ? ms : null;
}

export async function apiHomeHistory(deps: HomeDeps, url: string, res: ServerResponse): Promise<void> {
  const q = new URLSearchParams(url.split("?")[1] ?? "");
  const after = q.get("after") || null;
  const raw = q.get("limit");
  const limit = raw === null || raw === "" ? HISTORY_PAGE : Number(raw);
  const words = (q.get("q") ?? "").slice(0, HISTORY_QUERY_MAX);
  const only = q.get("only") === HISTORY_ONLY_STEPPED_IN;
  const before = historyBeforeParam(q.get("before"));
  json(res, 200, await buildHistoryFor(deps, after, Number.isFinite(limit) ? limit : HISTORY_PAGE, words, only, before));
}

// ── GET /api/home/answered?after=<id>&limit=<n>&q=<words>&before=<ms> — Answered earlier ──

/** Approvals › Answered earlier past its first page (dashboard.md §4.25
 *  *Past the newest 20*): `limit` answers after the one `after`, built as
 *  `/api/home` builds its `answered` (the same panel read, the same asking
 *  sessions and `~`, answeredPage), so a row carries nothing `/api/home`
 *  does not carry for the newest 20. `q`: a search (§4.25 *Finding an
 *  answer*), matched on each row's words before the page is cut. `before`:
 *  a day (§4.25 *Go to a day on Answered earlier*), the answers decided
 *  before it (answeredBefore), cut first. null: the queue is not known
 *  (the service unreachable, or its verdicts unread). */
export async function buildAnsweredFor(deps: HomeDeps, after: string | null, limit: number, q = "", before: number | null = null): Promise<{ page: ReturnType<typeof answeredPage> | null; unreachable: boolean }> {
  const all = withLive(await deps.source.listSessions(), liveRead(deps));
  const panel = await loadPolicyPanel(deps.source, deps.approvals, readFirstLookup(deps.facts, async () => all), deps.home ?? homedir());
  if (!panel.available || !panel.verdictsKnown) return { page: null, unreachable: !panel.available };
  return { page: answeredPage(panel.queue, new Map(all.map((s) => [s.id, s])), deps.home ?? homedir(), after, limit, q, before), unreachable: false };
}

export async function apiHomeAnswered(deps: HomeDeps, url: string, res: ServerResponse): Promise<void> {
  const q = new URLSearchParams(url.split("?")[1] ?? "");
  const after = q.get("after") || null;
  const raw = q.get("limit");
  const limit = raw === null || raw === "" ? ANSWERED_PAGE : Number(raw);
  // `q`: a search (§4.25 *Finding an answer*), cut as History's is.
  const words = (q.get("q") ?? "").slice(0, HISTORY_QUERY_MAX);
  // `before`: a day (§4.25 *Go to a day on Answered earlier*), read as
  // History reads its own.
  const before = historyBeforeParam(q.get("before"));
  const { page, unreachable } = await buildAnsweredFor(deps, after, Number.isFinite(limit) ? limit : ANSWERED_PAGE, words, before);
  // Unknown: the page says why beside Show more, never "no more answers".
  if (!page) return json(res, 503, { error: "the approval queue could not be read", unreachable });
  json(res, 200, page);
}

// ── GET /api/home/agent?session=<id> — the product's per-agent page ──────────

/** The most `?steps=` turn ids one request honours: each is one *Show them*
 *  pressed in this visit. */
export const SHOW_STEPS_MAX = 50;

/** What the page asked to see past its caps (dashboard.md §4.25ad):
 *  `turns=all`, `secrets=all`, and one `steps=<turn id>` per turn whose every
 *  step it shows. Anything else is the caps. */
export function agentShowOf(q: URLSearchParams): AgentPageShow {
  const steps = q.getAll("steps").filter((x) => x !== "").slice(0, SHOW_STEPS_MAX);
  // `background=<turn id>`: that turn's background steps, one by one
  // (§4.25ae), as many turns as `steps`.
  const background = q.getAll("background").filter((x) => x !== "").slice(0, SHOW_STEPS_MAX);
  return {
    ...(q.get("turns") === "all" ? { turns: true } : {}),
    ...(q.get("secrets") === "all" ? { secrets: true } : {}),
    ...(steps.length ? { steps: new Set(steps) } : {}),
    ...(background.length ? { background: new Set(background) } : {}),
  };
}

/** `ask`: an approval-queue id (`egr-<n>`) whose moment the page marks (§4.25h).
 *  `values`: the viewer holds the admin session (dashboard.md §6,
 *  read-gate.ts). Without it the page is built from the signed-out
 *  projection of the events (view-model/redact.ts) and nothing is resolved,
 *  so it carries what the AI saw and no original; `valuesShown` says so.
 *  `show`: what the page asked to see past its caps (§4.25ad), under the
 *  same projection. */
export async function buildAgentPageFor(deps: HomeDeps, sessionId: string, ask?: string | null, values = true, show?: AgentPageShow): Promise<AgentPageVM> {
  const nowMs = (deps.now ?? Date.now)();
  // The live launches read once, for this list and the Home built below.
  const live = liveRead(deps);
  deps = { ...deps, live: () => live };
  const all = withLive(await deps.source.listSessions(), live);
  const sections = buildSidebarSections(all, deps.testRuns, nowMs, undefined, deps.watchRuns);
  // Any section: the page is reachable from an ask a drill raised, too.
  const stamped = [...sections.live, ...sections.drills, ...sections.testing].flatMap((b) => b.sessions);
  const session = stamped.find((s) => s.id === sessionId) ?? all.find((s) => s.id === sessionId) ?? null;
  let events: Awaited<ReturnType<EventSource["readEvents"]>> = [];
  try {
    events = session ? await deps.source.readEvents(sessionId) : [];
    if (!values) events = redactEvents(events);
  } catch {
    events = [];
  }
  const vm = events.length ? toSessionViewModel(sessionId, events) : null;
  // Originals ONE level at a time (never the deep `desymbolize`, which would
  // expand a secret nested inside an ordinary item): agent-page checks every
  // token against the session's secrets before it asks. Display only: an
  // unreachable arbiter leaves the items masked.
  // What may be revealed is decided over the BELIEVED events only: a claimed
  // one (arbiter-human-plane.md §10.2) could mark a token known and public.
  const { believed, believedVm: scopeVm } = believedView(sessionId, events, vm);
  const revealed = values && vm && scopeVm
    ? await revealValues(scopeVm, deps.source.resolveSymbol ? (name) => deps.source.resolveSymbol!(name) : undefined).catch(() => undefined)
    : undefined;
  const home = await buildHome(deps);
  // The approval queue, read when the page needs it: for `?ask=`, and for
  // the answer to each question this session filed (§4.25b).
  const filed = events.some((e) => typeof e.policy?.approvalId === "string");
  const panel = vm && (ask || filed) ? await loadPolicyPanel(deps.source, deps.approvals) : null;
  // The queue row the ask came from (any status: an answered ask is the Rules
  // page's case). An unknown id, or no arbiter, locates nothing: the page
  // says it could not find the moment rather than guess.
  let focus: { ask: string; stepId: string | null; match: "exact" | "destination" | null } | undefined;
  if (ask) {
    const row = panel?.queue.find((q) => q.id === ask);
    const hit = row && vm ? locateAsk(events, vm.dualLanes.steps, { id: row.id, subject: row.subject, target: row.target, family: row.family }) : null;
    focus = { ask, stepId: hit?.stepId ?? null, match: hit?.match ?? null };
  }
  // Each answered row's outcome, as Answered earlier states it. Statuses are
  // open data (/api/egress/approvals); no queue, no answers: a step then
  // says only that Mandu asked.
  const answers = panel?.available && panel.verdictsKnown
    ? new Map(panel.queue.filter((r) => r.status !== "pending").map((r) => [r.id, answeredOutcome(r)]))
    : undefined;
  // Which declared model the main conversation goes to (§4.25l). Display
  // only: an arbiter without the op, or no answer, leaves the line out.
  const upstream = session && deps.source.sessionUpstream
    ? await deps.source.sessionUpstream(sessionId).catch(() => null)
    : null;
  // The administrator's prompt filter locks in force, read only for a
  // session the filter recorded something in (§4.25y).
  const locks = believed.some((e) => e.kind === "prompt_filter") ? await promptLocks(deps.prompt) : null;
  // The labels on the files the session read as they were, and when each
  // was made (the rule-change log): a Read before its file's label says so
  // (dashboard.md §4.25b, *Labelled after the session*). Display only: no
  // arbiter, or no record, leaves the page as the session's own record.
  const cwd = events.length ? sessionCwd(events) : null;
  const pageHome = deps.home ?? homedir();
  const times = deps.facts.labelTimes();
  const labels = vm ? await times.of(plainReads(vm, cwd, pageHome).map((r) => r.path)) : [];
  // Where each secret went (§4.25b *Where it went*): the file each
  // placeholder stands for, from the arbiter's registry, and the kept scan,
  // for a secret that reached an AI without Mandu. Display only: no
  // arbiter, or no scan, leaves the cards as the record alone tells them.
  const secretFiles = vm && vm.lineage.flows.length ? await times.registeredFiles() : undefined;
  const scan = deps.lastScan ? deps.lastScan() : undefined;
  // The sessions above and below this one in History's full list (§4.25b
  // *Newer and older sessions*): the list buildHistoryFor reads, none of its
  // filters applied; no extra read, no facts counted.
  const neighbours = sessionNeighbours(sections.live.flatMap((b) => b.sessions).filter(isAgentSession), sessionId);
  const page = buildAgentPage({
    session,
    id: sessionId,
    upstream,
    vm,
    cwd,
    // The asks this session raised last (home.ts `askedBy`): a row an
    // earlier session shares is the later one's question.
    waiting: home.waiting.filter((a) => a.sessions[a.sessions.length - 1] === sessionId),
    values: revealed,
    valuesShown: values,
    // Plan 15 §13.7: the prompt filter's notes, from the believed events only.
    events: believed,
    promptLocks: locks,
    believedVm: scopeVm,
    // Your secrets says when Mandu could not check the record (§4.25ah).
    unchecked: recordUnchecked(events),
    // Your secrets names a file under the home folder `~/…`.
    home: pageHome,
    ...(labels.length ? { labels } : {}),
    ...(focus ? { focus } : {}),
    ...(answers ? { answers } : {}),
    // The agent's warning is worded for the level running now, as its Home
    // row's: untrusted content is masked only at `injection` and `full`.
    masking: home.protection.level === "injection" || home.protection.level === "full",
    // A send to a company's own API says why it did not ask (§4.25b), while
    // the level running now lists the companies under Rules › Built-in
    // protections (builtInProtections: `secrets`, `full`). Display only.
    ...(home.protection.level === "secrets" || home.protection.level === "full" ? { issuerBindings: await issuerBindingsRead(deps.policy) } : {}),
    ...(show ? { show } : {}),
    ...(secretFiles?.size ? { secretFiles } : {}),
    ...(scan !== undefined ? { scan } : {}),
    dev: deps.dev !== false,
  });
  return page.found && neighbours ? { ...page, neighbours } : page;
}

export async function apiHomeAgent(deps: HomeDeps, url: string, res: ServerResponse, values = false): Promise<void> {
  const q = new URLSearchParams(url.split("?")[1] ?? "");
  const id = q.get("session");
  if (!id) {
    json(res, 400, { error: "missing ?session=" });
    return;
  }
  json(res, 200, await buildAgentPageFor(deps, id, q.get("ask"), values, agentShowOf(q)));
}

// ── GET /api/home/original?session=<id>&step=<step id> — a whole original ───

/** The whole original behind one step's mask (dashboard.md §4.25ae), up to
 *  ORIGINAL_ALL_CAP: what *Show what was hidden* shows past HIDDEN_CAP. The
 *  read gate makes it `admin` (403 signed out, before this runs), and it is
 *  built as the signed-in agent page is (`values`), so a secret stays
 *  withheld: a step whose original holds one has none here (404). */
export async function apiHomeOriginal(deps: HomeDeps, url: string, res: ServerResponse): Promise<void> {
  const q = new URLSearchParams(url.split("?")[1] ?? "");
  const id = q.get("session");
  const step = q.get("step");
  if (!id || !step) {
    json(res, 400, { error: "missing ?session= or ?step=" });
    return;
  }
  const page = await buildAgentPageFor(deps, id, null, true, { original: step });
  const original = page.original ?? null;
  if (!original || original.text === null) {
    json(res, 404, { error: "no original for that step" });
    return;
  }
  json(res, 200, { text: original.text, truncated: original.truncated });
}
