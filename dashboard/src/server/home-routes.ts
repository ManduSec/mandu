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
import { type EventSource } from "../event-source.js";
import { type SessionRef } from "../event-source/contract.js";
import { type VerdictEntry } from "../policy-model.js";
import { toSessionViewModel } from "../view-model.js";
import { buildAgentPage, buildStory, locateAsk, pageLaterLabels, pageSecrets, revealValues, sessionExited, storyCounts, untrustedMasked, type AgentPageShow, type AgentPageVM } from "../view-model/agent-page.js";
import { buildSidebarSections, type SidebarTestRun, type SidebarWatchRun } from "../session-batches.js";
import { sessionCwd } from "../session-paths.js";
import { believedEvents, type ManduEvent } from "../event-model.js";
import { type SessionViewModel } from "../view-model.js";
import { readAxesState } from "../config-axes.js";
import { loadPolicyPanel, loadPolicySnapshot, type ReadFirstLookup } from "./api-routes.js";
import { type ApprovalsArbiter } from "./approval-routes.js";
import { promptLocks, type PromptFiltersArbiter } from "./prompt-filter-routes.js";
import { type PolicyProposalArbiter } from "./policy-proposal-routes.js";
import { ANSWERED_PAGE, answeredOutcome, answeredPage, buildHistoryViewModel, buildHomeViewModel, historyMatches, historyPage, historyPageWhere, historyWords, homeAgentRow, HISTORY_ONLY_STEPPED_IN, HISTORY_PAGE, HISTORY_QUERY_MAX, HISTORY_SCAN_BUDGET, isAgentSession, rowContext, steppedIn, type HistoryVM, type HomeSessionFacts, type HomeVM } from "../view-model/home.js";
import { toPolicyPanelViewModel } from "../view-model/policy-panel.js";
import { redactEvents } from "../view-model/redact.js";
import { readFirstByBase, readFirstByFile, symbolBase } from "../view-model/lineage.js";
import { plainReads, type LabelTime } from "../view-model/later-labels.js";
import { LabelTimes, type LabelTimesArbiter } from "./label-times.js";

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
}

/** The label times as one comparable string (order-free). */
function labelSig(labels: readonly LabelTime[]): string {
  return labels.map((l) => `${l.path}\u0000${l.level}\u0000${l.at}`).sort().join("\n");
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
      if (labelSig(await times.of(hit.paths)) === hit.sig) return hit.facts;
    }
    const events = await this.source.readEvents(s.id);
    const vm = toSessionViewModel(s.id, events);
    // Counted over the story the session's page tells, so its row and its
    // page agree (no values: an outcome never depends on one).
    const { blocked, sent } = storyCounts(buildStory(vm));
    // Its secrets as its page's tiles count them, by each Your secrets
    // card's first line, from the same believed events, with the labels
    // made after it read their files (dashboard.md §4.25b).
    const { believed, believedVm } = believedView(s.id, events, vm);
    const cwd = sessionCwd(events);
    const paths = [...new Set(plainReads(vm, cwd, this.home).map((r) => r.path))];
    const labels = await (times ?? this.labelTimes()).of(paths);
    const laterInput = { labels, cwd };
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
    const facts: HomeSessionFacts = {
      stats: vm.lineage.stats,
      secrets: pageSecrets(vm, believed, believedVm, this.home, undefined, laterInput).counts,
      untrusted: untrustedMasked(vm.lineage.stats, vm.paired.mode),
      blocked,
      sent,
      holds: vm.invariant.holds,
      violations: vm.invariant.violationCount,
      cwd,
      // The session page's rule, so Home's "Running now" and the page agree.
      exited: sessionExited(events),
      // What the AI read as it was before it was masked, so a waiting card
      // about it never says the AI never read it (dashboard.md §4.34).
      readFirst: readFirstByBase(later),
      // The same by the file each came from, so a waiting card about a
      // program reading that file never says the AI has not seen it.
      readFirstFiles,
    };
    this.cache.set(s.id, { key, facts, paths, sig: labelSig(labels) });
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
}

export async function buildHome(deps: HomeDeps): Promise<HomeVM> {
  const nowMs = (deps.now ?? Date.now)();
  const all = await deps.source.listSessions();
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
  // The waiting cards' words read the asking sessions' records too, so one
  // about an item the AI read before it was masked says so (§4.34).
  const panel = await loadPolicyPanel(deps.source, deps.approvals, readFirstLookup(deps.facts, async () => all), deps.home ?? homedir());
  // readAxesState never throws: an unreadable config reads as the defaults.
  const configuredMode = readAxesState(deps.env).effectiveMode;
  const proposalsWaiting = await proposalsRead;
  return buildHomeViewModel({
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
  });
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
export async function recentWorkspaces(deps: Pick<HomeDeps, "source" | "facts" | "testRuns" | "watchRuns" | "now">, max = 10): Promise<string[]> {
  const nowMs = (deps.now ?? Date.now)();
  const all = await deps.source.listSessions();
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

export async function apiHome(deps: HomeDeps, res: ServerResponse): Promise<void> {
  json(res, 200, await buildHome(deps));
}

// ── GET /api/home/history?after=<id>&limit=<n>&q=<words>&only=stepped-in ─────

/** Every agent session on record, newest first, as the History page lists
 *  them (dashboard.md §4.25ae): the live sessions Home reads (no test or
 *  drill run, no system log), with no time window, one page past `after`.
 *  Each row is counted as its Home row is (`HomeFacts`, cached per session),
 *  so a row, Home's and the page it opens agree, and with the questions it
 *  raised that still wait (the queue `/api/home` reads). Metadata only:
 *  names, times, counts, the session's prompt label (as `/api/sessions`
 *  serves). `q`: a search (§4.25ae *Finding a session*), matched on each
 *  row's agent and served label before the page is cut, so `total`, `next`
 *  and Show more count the matches. `only`: the switch (§4.25ae *Only the
 *  sessions where Mandu stepped in*), the rows `steppedIn` keeps, looked
 *  through as they are counted, at most HISTORY_SCAN_BUDGET a read; with
 *  `q`, both hold. */
export async function buildHistoryFor(deps: HomeDeps, after: string | null, limit: number, q = "", only = false): Promise<HistoryVM> {
  const nowMs = (deps.now ?? Date.now)();
  const all = await deps.source.listSessions();
  const sections = buildSidebarSections(all, deps.testRuns, nowMs, undefined, deps.watchRuns);
  const live = sections.live.flatMap((b) => b.sessions).filter(isAgentSession);
  const words = historyWords(q);
  const found = words.length ? historyMatches(live, q) : live;
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
  let cut: { page: SessionRef[]; next: string | null; through?: number };
  if (only) {
    // The label times of the cached sessions it may look through, asked at once.
    const at = after === null ? -1 : found.findIndex((s) => s.id === after);
    await times.of(deps.facts.pathsOf(found.slice(at + 1, at + 1 + HISTORY_SCAN_BUDGET).map((s) => s.id)));
    cut = await historyPageWhere(found, after, limit, HISTORY_SCAN_BUDGET, async (s) =>
      steppedIn(homeAgentRow(s, await count(s), context.waiting.get(s.id) ?? 0, context.masking)));
  } else {
    cut = historyPage(found, after, limit);
    await times.of(deps.facts.pathsOf(cut.page.map((s) => s.id)));
    for (const s of cut.page) await count(s);
  }
  const query = words.length ? { query: { text: words.join(" "), all: live.length } } : {};
  const filtered = only ? { only: { through: cut.through ?? 0 } } : {};
  return buildHistoryViewModel({ total: found.length, page: cut.page, next: cut.next, facts, ...context, ...query, ...filtered });
}

export async function apiHomeHistory(deps: HomeDeps, url: string, res: ServerResponse): Promise<void> {
  const q = new URLSearchParams(url.split("?")[1] ?? "");
  const after = q.get("after") || null;
  const raw = q.get("limit");
  const limit = raw === null || raw === "" ? HISTORY_PAGE : Number(raw);
  const words = (q.get("q") ?? "").slice(0, HISTORY_QUERY_MAX);
  const only = q.get("only") === HISTORY_ONLY_STEPPED_IN;
  json(res, 200, await buildHistoryFor(deps, after, Number.isFinite(limit) ? limit : HISTORY_PAGE, words, only));
}

// ── GET /api/home/answered?after=<id>&limit=<n> — Answered earlier, on ────────

/** Approvals › Answered earlier past its first page (dashboard.md §4.25
 *  *Past the newest 20*): `limit` answers after the one `after`, built as
 *  `/api/home` builds its `answered` (the same panel read, the same asking
 *  sessions and `~`, answeredPage), so a row carries nothing `/api/home`
 *  does not carry for the newest 20. null: the queue is not known (the
 *  service unreachable, or its verdicts unread). */
export async function buildAnsweredFor(deps: HomeDeps, after: string | null, limit: number): Promise<{ page: ReturnType<typeof answeredPage> | null; unreachable: boolean }> {
  const all = await deps.source.listSessions();
  const panel = await loadPolicyPanel(deps.source, deps.approvals, readFirstLookup(deps.facts, async () => all), deps.home ?? homedir());
  if (!panel.available || !panel.verdictsKnown) return { page: null, unreachable: !panel.available };
  return { page: answeredPage(panel.queue, new Map(all.map((s) => [s.id, s])), deps.home ?? homedir(), after, limit), unreachable: false };
}

export async function apiHomeAnswered(deps: HomeDeps, url: string, res: ServerResponse): Promise<void> {
  const q = new URLSearchParams(url.split("?")[1] ?? "");
  const after = q.get("after") || null;
  const raw = q.get("limit");
  const limit = raw === null || raw === "" ? ANSWERED_PAGE : Number(raw);
  const { page, unreachable } = await buildAnsweredFor(deps, after, Number.isFinite(limit) ? limit : ANSWERED_PAGE);
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
  const all = await deps.source.listSessions();
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
  const labels = vm ? await deps.facts.labelTimes().of(plainReads(vm, cwd, pageHome).map((r) => r.path)) : [];
  return buildAgentPage({
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
    // Your secrets names a file under the home folder `~/…`.
    home: pageHome,
    ...(labels.length ? { labels } : {}),
    ...(focus ? { focus } : {}),
    ...(answers ? { answers } : {}),
    // The agent's warning is worded for the level running now, as its Home
    // row's: untrusted content is masked only at `injection` and `full`.
    masking: home.protection.level === "injection" || home.protection.level === "full",
    ...(show ? { show } : {}),
    dev: deps.dev !== false,
  });
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
