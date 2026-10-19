/**
 * drill-shorts — the drill rows' short-index badge (dashboard.md §4.35,
 * test-reorganization.md §6.1.1): every catalog drill carries a short, stable
 * index (`util-c5`, `con-i2`, `int-i11w`: its area, its axis, a number;
 * since 2026-10-16, which spelled it `UCon-5` for a few hours first), and
 * the Drills page badges the REPLAY and the LIVE rows with it, so the two
 * lists can be compared row by row.
 *
 * The join is server-side, from the catalog index the drill matrix already
 * reads (drill-matrix.ts readCatalog, `drills.json`), so
 * a record written before the index existed is badged too:
 *   - a replay row by its record's drill id (`SessionRef.replay.short`);
 *   - a live row by the scenario key it ran (`SessionRef.drillShort`), from
 *     the run's record, the launch's word or, for a session whose record is
 *     gone, its own id (the runner names every session
 *     `<runId>-<key slug>`, drill-launch.ts scenarioScopeId). A key is a
 *     drill id (`util-reasoning@sonnet#2`) or, in runs before 2026-10-01, an
 *     old watch id (`U7`, `S6`), which maps through the drill's `was` (every
 *     older index it had: `S6` and `U30` → util-npm-pack-dry-run, util-c17).
 *     A retired old id (`U11`) maps to nothing.
 *
 * The key rule is index.ts `drillByKey`'s; a parity test
 * (dashboard-drill-catalog.test.ts) holds the two equal over
 * every drill and old id. Pure: no I/O. Mandu-new (NO reference origin).
 * OBSERVABILITY / DEV TOOLING ONLY — nothing here is on the security path.
 */
import type { SessionRef } from "./event-source.js";

/** One catalog drill as the badge needs it. */
export interface DrillShortEntry {
  id: string;
  short: string;
  title: string;
}

/** The catalog drills by id and by key (a short index, an older index
 *  through `was`). */
export interface DrillShortIndex {
  byId: ReadonlyMap<string, DrillShortEntry>;
  byKey: ReadonlyMap<string, DrillShortEntry>;
}

/** Build the index from the validated catalog (drill-matrix.ts CatalogDrill:
 *  every field already checked). A drill with no short index is left out. */
export function drillShortIndex(drills: ReadonlyArray<{ id: string; short?: string; was?: readonly string[]; title: string }>): DrillShortIndex {
  const byId = new Map<string, DrillShortEntry>();
  const byKey = new Map<string, DrillShortEntry>();
  for (const d of drills) {
    if (d.short === undefined) continue;
    const e = { id: d.id, short: d.short, title: d.title };
    byId.set(d.id, e);
  }
  // `was` first: an older index wins over a short of the same spelling
  // (validateCatalog refuses that pair anyway). A short is keyed by its
  // current spelling, so a catalog written before 2026-10-16's second
  // spelling (`UCon-5`) answers a `util-c5` key, and the other way round.
  for (const d of drills) if (byId.has(d.id)) for (const w of d.was ?? []) byKey.set(w, byId.get(d.id)!);
  for (const e of byId.values()) {
    const k = normalShortKey(e.short) ?? e.short;
    if (!byKey.has(k)) byKey.set(k, e);
  }
  return { byId, byKey };
}

/** A short index, any case: `<area word>-<axis letter><number><suffix>`
 *  (`util-c5`, `int-i11w`). No drill id has this shape (the catalog's
 *  check), so it never shadows an id. */
const SHORT_KEY_RE = /^(util|fid|con|int|pol|demo)-([ci])([1-9]\d*)([a-z]*)$/i;
/** The same day's first spelling, any case (`UCon-5`, `IInt-11w`; 2026-10-16). */
const SHORT_2026_10_16_KEY_RE = /^([ufcipd])(con|int)-([1-9]\d*)([a-z]*)$/i;
const AREA_OF_LETTER: Readonly<Record<string, string>> = { u: "util", f: "fid", c: "con", i: "int", p: "pol", d: "demo" };
/** An older index or an old watch id, any case: `<letter><number><suffix>`. */
const OLD_KEY_RE = /^([a-zA-Z])([1-9]\d*)([a-zA-Z]*)$/;

/** A key in a short index's form as the current spelling: `UTIL-C5` →
 *  `util-c5`, `UCon-5` → `util-c5` (number for number, index.ts
 *  normalShort); undefined when it is not one. */
export function normalShortKey(key: string): string | undefined {
  const s = SHORT_KEY_RE.exec(key);
  if (s) return key.toLowerCase();
  const o = SHORT_2026_10_16_KEY_RE.exec(key);
  if (!o) return undefined;
  return `${AREA_OF_LETTER[o[1]!.toLowerCase()]}-${o[2]!.toLowerCase() === "con" ? "c" : "i"}${o[3]}${o[4]!.toLowerCase()}`;
}

/** The drill a recorded key names: a drill id, a short index (either
 *  spelling) or an older index, with a variant tail (`@sonnet#2`) ignored
 *  (index.ts drillByKey). */
export function resolveDrillKey(ix: DrillShortIndex, key: string): DrillShortEntry | undefined {
  const base = key.split("@")[0]!;
  const byId = ix.byId.get(base);
  if (byId) return byId;
  const s = normalShortKey(base);
  if (s !== undefined) return ix.byKey.get(s);
  const m = OLD_KEY_RE.exec(base);
  if (!m) return undefined;
  return ix.byKey.get(`${m[1]!.toUpperCase()}${m[2]}${m[3]!.toLowerCase()}`);
}

/** A session-id key slug (drill-launch.ts keySlug: lower case, `-` joined):
 *  the longest drill id it starts with, else an old id's slug (`u7`,
 *  `s3-haiku-2`), each with the rest as the variant. */
function resolveSlug(ix: DrillShortIndex, slug: string): { entry: DrillShortEntry; variant: string; key: string } | undefined {
  let best: DrillShortEntry | undefined;
  for (const e of ix.byId.values()) {
    if ((slug === e.id || slug.startsWith(e.id + "-")) && (!best || e.id.length > best.id.length)) best = e;
  }
  if (best) return { entry: best, variant: slug.slice(best.id.length), key: best.id };
  const m = /^([a-z][1-9]\d*[a-z]*)((?:-[a-z0-9]+)*)$/.exec(slug);
  const entry = m ? resolveDrillKey(ix, m[1]!) : undefined;
  return entry ? { entry, variant: m![2]!, key: m![1]!.toUpperCase() } : undefined;
}

/** The runner's default run id on a session id (`watch-<stamp>-<key>`). */
const DEFAULT_RUN_ID_RE = /^watch-\d{8}T\d{6}-(.+)$/;
/** A demo side's run id (the demo runner's planDemo: `demo-<stamp>-<the
 *  drill's short index, or its id>-<side>`; a battery of several models or
 *  takes adds `m<i>r<j>` to the stamp), and its session `<runId>-<drill
 *  id>`. */
const DEMO_RUN_ID_RE = /^demo-\d{8}T\d{6}(?:m\d+r\d+)?-(.+)$/;
/** A short index leading a demo run id's rest, in either spelling. */
const DEMO_LEAD_RE = /^((?:util|fid|con|int|pol|demo)-[ci][1-9]\d*[a-z]*|[ufcipd](?:con|int)-[1-9]\d*[a-z]*)-(.+)$/;

/** A demo run id's rest (`demo-c1-mandu-demo-poisoned-readme`): the drill
 *  its short index (or id) leads with, the side (`mandu`, `baseline-none`)
 *  as the variant, the session's own drill-id tail dropped. */
function resolveDemoSlug(ix: DrillShortIndex, rest: string): { entry: DrillShortEntry; variant: string; key: string } | undefined {
  const lead = DEMO_LEAD_RE.exec(rest);
  const byShort = lead ? resolveDrillKey(ix, lead[1]!) : undefined;
  const r = byShort ? { entry: byShort, variant: "-" + lead![2]!, key: lead![1]! } : resolveSlug(ix, rest);
  if (!r) return undefined;
  const tail = "-" + r.entry.id;
  const variant = r.variant.endsWith(tail) ? r.variant.slice(0, -tail.length) : r.variant;
  return { ...r, variant };
}

/**
 * The catalog drill a LIVE drill session ran, best source first (the order
 * the row's badge has always used, dashboard.md §4.22):
 *   1. the run-joined `watch.scenario.id`;
 *   2. the launch's own word (`batchMember`, kind `scenario`; a `posture`
 *      member is a --shared-session GROUP, which ran several drills: none);
 *   3. the session id's key slug, after its batch stamp or the runner's
 *      default run id (only drill rows are asked, so any stamp is a run's),
 *      or a demo side's run id (`demo-<stamp>-demo-c1-mandu-<drill id>`:
 *      the drill its short index names, the side as the variant).
 * Undefined when no source names a catalog drill.
 */
export function liveDrillShort(ix: DrillShortIndex, s: SessionRef): SessionRef["drillShort"] {
  const fromKey = (key: string, via: "run" | "launch"): SessionRef["drillShort"] => {
    const e = resolveDrillKey(ix, key);
    if (!e) return undefined;
    const base = key.split("@")[0]!;
    const variant = key.slice(base.length);
    return { short: e.short, drill: e.id, title: e.title, via, ...(base !== e.id && base !== e.short ? { key: base } : {}), ...(variant ? { variant } : {}) };
  };
  const joined = s.watch?.scenario?.id;
  if (joined) return fromKey(joined, "run");
  const m = s.batchMember;
  if (m && m.key) return m.kind === "scenario" ? fromKey(m.key, "launch") : undefined;
  const id = s.id;
  let slug: string | null = null;
  const demo = DEMO_RUN_ID_RE.exec(id)?.[1];
  if (s.batchId && id.startsWith(s.batchId + "-")) slug = id.slice(s.batchId.length + 1);
  else slug = DEFAULT_RUN_ID_RE.exec(id)?.[1] ?? demo ?? null;
  if (!slug) return undefined;
  const r = slug === demo ? resolveDemoSlug(ix, slug) : resolveSlug(ix, slug);
  if (!r) return undefined;
  return {
    short: r.entry.short, drill: r.entry.id, title: r.entry.title, via: "id",
    ...(r.key !== r.entry.id && r.key !== r.entry.short ? { key: r.key } : {}), ...(r.variant ? { variant: r.variant } : {}),
  };
}
