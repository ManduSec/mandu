/**
 * server/label-times — when each file a session read was labelled a secret,
 * for the product's session page and Home (dashboard.md §4.25b, *Labelled
 * after the session*). Mandu-new (no reference origin).
 *
 * Three READS, each optional (an arbiter without one, or one that fails,
 * gives no time, so the page makes no claim and reads as before):
 *   - `pathLevels`: which rule decides each file now and at what level (the
 *     arbiter's own answer; the file browser's op, data socket);
 *   - `policyChanges`: the rule-change log, for a policy.yaml rule's time
 *     (human plane, as Approvals' *Rule changes* reads it);
 *   - `confidentialityState`: a Rules page label's own time, read only when
 *     a page label decides one of the files.
 * The arbiter-client pattern: a narrow interface over surfaces the
 * production wiring already builds (arbiter-adapter.ts `secrets` and
 * `policyDoc`); the stack test reads through that wiring.
 *
 * One `LabelTimes` serves one request: each read is made once, and a path
 * is asked once, however many sessions name it.
 */

import type { PathLevelsEntryWire } from "../view-model/file-browser.js";
import type { PolicyChangeRow } from "../view-model/policy-proposals.js";
import { labelTimes, type LabelTime, type PageLabelTime } from "../view-model/later-labels.js";

/** The arbiter's `pathLevels` bound (protocol.ts PATH_LEVELS_MAX). */
export const PATH_LEVELS_CHUNK = 1000;
/** The change-log rows read (the arbiter's own cap). */
export const CHANGES_READ = 500;

export interface LabelTimesArbiter {
  pathLevels?(paths: string[], home?: string): Promise<{ axis: boolean; levels: PathLevelsEntryWire[] }>;
  policyChanges?(limit?: number): Promise<{ changes: PolicyChangeRow[] }>;
  confidentialityState?(): Promise<{ labels?: PageLabelTime[] }>;
}

/** The three reads over a tenant's surfaces (the production wiring's
 *  `secrets` and `policyDoc`, arbiter-adapter.ts), each forwarded as the
 *  surface takes it. Undefined when neither surface is there. */
export function labelTimesArbiter(
  secrets: Pick<LabelTimesArbiter, "pathLevels"> & { confidentialityState(): Promise<{ labels?: PageLabelTime[] }> } | undefined,
  policyDoc: Pick<LabelTimesArbiter, "policyChanges"> | undefined,
): LabelTimesArbiter | undefined {
  if (!secrets && !policyDoc) return undefined;
  return {
    ...(secrets?.pathLevels ? { pathLevels: (paths: string[], home?: string) => secrets.pathLevels!(paths, home) } : {}),
    ...(secrets ? { confidentialityState: () => secrets.confidentialityState() } : {}),
    ...(policyDoc?.policyChanges ? { policyChanges: (limit?: number) => policyDoc.policyChanges!(limit) } : {}),
  };
}

export class LabelTimes {
  private readonly levels = new Map<string, PathLevelsEntryWire | null>();
  private changes: Promise<PolicyChangeRow[] | null> | undefined;
  private pageLabels: Promise<PageLabelTime[] | null> | undefined;

  constructor(private readonly arbiter: LabelTimesArbiter | undefined, private readonly home: string) {}

  /** The label times of `paths` (absolute), for the files a label decides
   *  now and whose time is recorded. Never throws. */
  async of(paths: readonly string[]): Promise<LabelTime[]> {
    const arb = this.arbiter;
    if (!arb?.pathLevels || !paths.length) return [];
    const missing = [...new Set(paths)].filter((p) => !this.levels.has(p));
    for (let i = 0; i < missing.length; i += PATH_LEVELS_CHUNK) {
      const chunk = missing.slice(i, i + PATH_LEVELS_CHUNK);
      for (const p of chunk) this.levels.set(p, null);
      try {
        const r = await arb.pathLevels(chunk, this.home);
        // Protection off on the arbiter: no label decides anything now.
        if (r.axis) for (const e of r.levels) if (chunk.includes(e.path)) this.levels.set(e.path, e);
      } catch {
        // No answer: no time, no claim.
      }
    }
    const entries = [...new Set(paths)].map((p) => this.levels.get(p)).filter((e): e is PathLevelsEntryWire => !!e && !!e.rule?.startsWith("label:"));
    if (!entries.length) return [];
    const changes = entries.some((e) => e.store === "policy") ? await this.changeLog() : null;
    const page = entries.some((e) => e.store === "page") ? await this.pageLabelTimes() : null;
    return labelTimes(entries, changes, page);
  }

  private changeLog(): Promise<PolicyChangeRow[] | null> {
    const arb = this.arbiter;
    this.changes ??= arb?.policyChanges ? arb.policyChanges(CHANGES_READ).then((r) => r.changes, () => null) : Promise.resolve(null);
    return this.changes;
  }

  private pageLabelTimes(): Promise<PageLabelTime[] | null> {
    const arb = this.arbiter;
    this.pageLabels ??= arb?.confidentialityState ? arb.confidentialityState().then((s) => s.labels ?? [], () => null) : Promise.resolve(null);
    return this.pageLabels;
  }
}
