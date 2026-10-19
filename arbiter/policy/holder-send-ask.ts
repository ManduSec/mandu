/**
 * holder-send-ask — the question a holder's send asks, and its one *Always*
 * per source (confidentiality plan 13 §5.4, §9 R2). Mandu-new (no reference
 * origin).
 *
 * A process that read several secret files (a holder, plan 10 §4.3) may send
 * only where EVERY one of them may go (plan 13 D1: the intersection of their
 * bindings). When the net-proxy refuses such a send it asks the arbiter, which
 * files ONE Inbox row per {session, the set of files held} × destination:
 *
 *     holder-send:{"session":"<key>","files":["/home/u/ws/app/.env", …]}  ×  hooks.slack.com
 *
 * The row is self-describing (the files ride in its key, so it survives a
 * restart) and is answered three ways:
 *
 *   - *Allow once* / *Block*: the ordinary verdicts on the row;
 *   - *Allow this session*: a standing verdict on the row, whose key names the
 *     session, so it covers that session's holders of exactly these files and
 *     nothing else (a row with no session takes an Always as once);
 *   - *Always: add <host> to <file>*: one per file that blocks, each its own
 *     human-plane policy edit (a `lock-path` that adds the host to THAT file's
 *     rule, applied through `policyPropose` + `resolvePolicyProposal` on the
 *     admin channel, exactly as the Rules page applies a loosening). The send
 *     goes when no file blocks; until then the row stays pending and names the
 *     files left. Never a verdict on the row: a binding the human removes later
 *     takes the release away again, which a standing verdict would not.
 *
 * What a file is, for the row (`holderSources`): the composed label decides
 * exactly as `taintedProcessBindings` counts it, so the row and the gate never
 * disagree.
 *
 *   - An ordinary secret file: its label's bindings plus its registry rows'.
 *   - A COPY whose sources are known (plan 13 §4.6, label by reference) and on
 *     which no exact human label speaks: its release IS the intersection of its
 *     sources', so the row names the SOURCES (each with `via: <copy>`), and an
 *     *Always* binds at the source, never at the copy. A folder rule over the
 *     copy counts too (its bindings are intersected in), but takes no *Always*
 *     (it covers other files). A source that no longer classifies secret, a
 *     cycle or a chain deeper than `MAX_REFERENCE_DEPTH` counts as bound
 *     nowhere and takes no *Always* (no rule could release it).
 *   - A copy with UNKNOWN sources (a high session's write, an older row) is an
 *     ordinary file bound nowhere: its *Always* writes an exact `paths:` rule
 *     on the copy at its level with this host, the human's own act on that copy
 *     (the ledger's "an *Always* on a held open of a copy writes an exact
 *     `paths:` label that binds nowhere until a binding is added" is this edit
 *     with the binding in it).
 *
 * Where the *Always* writes (`holderBindEdit`):
 *
 *   - the file's EXACT rule in policy.yaml: that rule, its level, readers,
 *     `others` and `extract` kept, the host added to its bindings;
 *   - a FOLDER rule (an ancestor or a pattern) with no readers, `others` or
 *     `extract`, or no human rule at all (the catalog, a declared model key, a
 *     copy of unknown origin): a new exact rule for the file alone, at the
 *     level and with the destinations that apply to it now, plus the host, so
 *     nothing else under the folder changes and the file is never lowered;
 *   - refused (no button, the card says why): a folder rule WITH readers,
 *     `others` or `extract` (an exact rule would drop them for this file); a
 *     rule made on the Rules page before rules lived in policy.yaml (a
 *     `mandu.db` row outranks the file, so the edit would change nothing); a
 *     file name that reads as a pattern.
 *
 * The arbiter previews every planned edit and refuses one whose relaxations
 * name anything but that file's rule (server.ts `holderSourceBinding`), and
 * the dashboard previews again before it applies (`applyAsHuman`'s
 * `expected`): an *Always* widens exactly the source it names.
 *
 * Pure: every store is passed in.
 */
import { holderFileBindings } from "./value-bindings.js";
import { isSecret, type ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { resolveDerivedLabel, resolveWithDerived } from "./derived-labels.js";
import { bindingCovers, intersectBindings } from "./flow-taint.js";
import { destinationMatchesBindings } from "./host-bindings.js";
import { composedLabel, MAX_REFERENCE_DEPTH, type LabelSnapshot } from "./label-lookup.js";
import type { PolicyFileConfig } from "./load-policy.js";
import { hasGlobMeta } from "./path-glob.js";
import { normalizeLabelPath, resolvePathLabel } from "./path-labels.js";
import type { PolicyEdit } from "./policy-edit.js";
import { pathConfidentiality } from "./secret-catalog.js";

/** The subject prefix of a holder's send question. */
export const HOLDER_SEND_PREFIX = "holder-send:";

/** A taint row that is a value a HIGH session read, not a file
 *  (server.ts `SESSION_SYMBOL_ROW_PREFIX`). */
export const SESSION_VALUE_ROW_PREFIX = "symbol:";

/** The row key for a holder of `files` in `session`: the files sorted and
 *  deduplicated, so one set is one question whatever order it was read in. */
export function holderSendSubject(session: string | undefined | null, files: readonly string[]): string {
  const sorted = [...new Set(files)].sort();
  return HOLDER_SEND_PREFIX + JSON.stringify({ session: typeof session === "string" && session !== "" ? session : null, files: sorted });
}

/** The session and files a holder-send key names; null for any other key
 *  (or a malformed one, which then matches no question). */
export function parseHolderSendSubject(subject: string): { session: string | null; files: string[] } | null {
  if (typeof subject !== "string" || !subject.startsWith(HOLDER_SEND_PREFIX)) return null;
  try {
    const v = JSON.parse(subject.slice(HOLDER_SEND_PREFIX.length)) as { session?: unknown; files?: unknown };
    if (!v || typeof v !== "object" || !Array.isArray(v.files) || !v.files.every((f) => typeof f === "string" && f !== "")) return null;
    if (v.files.length === 0) return null;
    return { session: typeof v.session === "string" && v.session !== "" ? v.session : null, files: v.files as string[] };
  } catch {
    return null;
  }
}

/** Is `subject` a holder's send question? */
export function isHolderSendSubject(subject: string): boolean {
  return parseHolderSendSubject(subject) !== null;
}

/** Does `destination` (`host` or `host:port`) fall under one of `bindings`?
 *  The one binding rule (host-bindings.ts), which the net-proxy's copy
 *  (`hostIsBound`) is held to, so the arbiter asks exactly when the proxy
 *  refuses. */
export function hostIsBound(destination: string, bindings: readonly string[]): boolean {
  return destinationMatchesBindings(destination, bindings);
}

/** Does one file's binding list let `host` through, in the join's sense
 *  (`bindingCovers`, conservative)? A file that does not is one that blocks:
 *  adding `host` itself to it is what makes the intersection keep `host`. */
export function bindingsAdmit(bindings: readonly string[], host: string): boolean {
  return bindings.some((b) => bindingCovers(b, host));
}

/** Why a file that blocks takes no *Always* (the card says it in words). */
export type NoAlwaysReason = "folder-rule" | "page-rule" | "not-secret" | "unknown-origin" | "session-value" | "pattern-name" | "per-value";

/** One file the holder holds, as the row shows it. */
export interface HolderSource {
  /** The file (or, with `rule`, the folder rule's path or pattern). */
  path: string;
  /** The copy the holder read, when this file is one of its sources. */
  via?: string;
  /** This entry is a folder rule over a copy, not a file. */
  rule?: true;
  level: string;
  /** Where it may go now: its label's bindings and its registry rows'. */
  bindings: string[];
  /** It does not let the destination through. */
  blocks: boolean;
  /** An *Always* is offered: it blocks, and its rule can take the host. */
  always: boolean;
  noAlways?: NoAlwaysReason;
}

export interface HolderSourceDeps {
  snapshot: LabelSnapshot;
  /** A file's registry rows' bindings (as `taintedProcessBindings` counts). */
  registryBindings: (path: string) => readonly string[];
  /** A HIGH session's value row (`symbol:<name>`): where its symbol may go,
   *  or null when the symbol is gone (bound nowhere). */
  sessionValueBindings: (row: string) => readonly string[] | null;
  home?: string;
}

/** Every file a holder of `files` holds, for a send to `host`: a copy whose
 *  sources are known is replaced by its sources (module header). Ordered as
 *  the files, deduplicated by (path, via). */
export function holderSources(files: readonly string[], host: string, deps: HolderSourceDeps): HolderSource[] {
  const out: HolderSource[] = [];
  const seen = new Set<string>();
  const { snapshot } = deps;
  const lookup = (p: string) => composedLabel(p, snapshot, { sourceBindings: deps.registryBindings });
  const push = (s: HolderSource): void => {
    const k = `${s.path}\u0000${s.via ?? ""}\u0000${s.rule ? "r" : ""}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(s);
  };
  const visit = (f: string, via: string | undefined, visiting: readonly string[]): void => {
    if (f.startsWith(SESSION_VALUE_ROW_PREFIX)) {
      const b = [...(deps.sessionValueBindings(f) ?? [])];
      const blocks = !bindingsAdmit(b, host);
      push({ path: f, ...(via ? { via } : {}), level: "no-model", bindings: b, blocks, always: false, ...(blocks ? { noAlways: "session-value" as const } : {}) });
      return;
    }
    const row = resolveDerivedLabel(f, snapshot.derived, deps.home);
    const human = resolvePathLabel(f, snapshot.human, deps.home);
    const exactHuman = human !== null && row !== null && human.via === row.path && !human.glob;
    if (row !== null && row.sources !== null && row.sources.length > 0 && !exactHuman) {
      // The copy refers to its sources (label-lookup.ts `byReference`).
      if (visiting.includes(row.path) || visiting.length >= MAX_REFERENCE_DEPTH) {
        push({ path: f, ...(via ? { via } : {}), level: "no-model", bindings: [], blocks: true, always: false, noAlways: "unknown-origin" });
        return;
      }
      const here = [...visiting, row.path];
      const r = resolveWithDerived(f, snapshot.human, snapshot.derived, deps.home);
      if (r !== null && r.origin !== "derived") {
        const blocks = !bindingsAdmit(r.bindings, host);
        if (blocks) push({ path: r.via, via: via ?? f, rule: true, level: r.level, bindings: [...r.bindings], blocks, always: false, noAlways: "folder-rule" });
      }
      for (const src of row.sources) {
        const m = pathConfidentiality(src, deps.home, lookup);
        if (!isSecret(m.level)) {
          push({ path: src, via: via ?? f, level: m.level, bindings: [], blocks: true, always: false, noAlways: "not-secret" });
          continue;
        }
        visit(src, via ?? f, here);
      }
      return;
    }
    const m = pathConfidentiality(f, deps.home, lookup);
    // Plan 13 §5.2: a file with `values:` is held whole, the intersection
    // over its values; its field rows' per-value hosts are not the file's
    // (`holderFileBindings`, as `taintedProcessBindings` counts it).
    const bindings = [...new Set(holderFileBindings(m, deps.registryBindings(f)))];
    const blocks = !bindingsAdmit(bindings, host);
    const why = blocks ? noAlwaysFor(f, snapshot, deps.home) : null;
    push({
      path: f, ...(via ? { via } : {}), level: m.level, bindings, blocks,
      always: blocks && why === null,
      ...(blocks && why !== null ? { noAlways: why } : {}),
    });
  };
  for (const f of files) visit(f, undefined, []);
  return out;
}

/** May an *Always* write this file's rule (module header)? null = yes. */
function noAlwaysFor(f: string, snapshot: LabelSnapshot, home?: string): NoAlwaysReason | null {
  if (hasGlobMeta(f)) return "pattern-name";
  const human = resolvePathLabel(f, snapshot.human, home);
  if (human === null) return null;
  const n = normalizeLabelPath(f, home) ?? f;
  if (human.via === n && !human.glob) {
    // A mandu.db row on the same path outranks policy.yaml (server.ts
    // `humanLabels`): an edit of the file would change nothing.
    if (snapshot.human.get(n)?.source !== "policy-file") return "page-rule";
    return human.values !== undefined ? "per-value" : null;
  }
  if (human.readers !== undefined || human.others !== undefined || human.extract !== undefined) return "folder-rule";
  // Plan 13 §5.2: a rule with `values:` lets the whole file go only where
  // every value may; a host added to the file's own bindings would reach
  // only the values with no entry, so the send would stay refused. The
  // per-value Always is a follow-up; until then the card says where to add it.
  return human.values !== undefined ? "per-value" : null;
}

/** Does every file let `host` through, and does the gate's own check (the
 *  proxy's matcher over the intersection) agree? Then the send goes by the
 *  law and the question is moot. */
export function holderSendReleased(sources: readonly HolderSource[], host: string): boolean {
  if (sources.length === 0 || sources.some((s) => s.blocks)) return false;
  return hostIsBound(host, intersectBindings(sources.map((s) => s.bindings)));
}

/** The policy edit an *Always* on `path` files (module header), or why none. */
export function holderBindEdit(
  path: string,
  host: string,
  deps: { snapshot: LabelSnapshot; document: PolicyFileConfig | null; registryBindings?: (path: string) => readonly string[]; home?: string },
): { edits: PolicyEdit[]; rule: string } | { refused: NoAlwaysReason | "invalid" } {
  const f = normalizeLabelPath(path, deps.home);
  const h = host.trim();
  if (f === null || h === "" || /\s/.test(h)) return { refused: "invalid" };
  const why = noAlwaysFor(f, deps.snapshot, deps.home);
  if (why !== null) return { refused: why };
  const human = resolvePathLabel(f, deps.snapshot.human, deps.home);
  const add = (bindings: readonly string[]): string[] => (bindingsAdmit(bindings, h) ? [...bindings] : [...bindings, h]);
  if (human !== null && human.via === f && !human.glob) {
    // The exact rule in policy.yaml, as written there (`~` kept).
    const entry = (deps.document?.paths ?? []).find((e) => !hasGlobMeta(e.path) && normalizeLabelPath(e.path, deps.home) === f);
    if (!entry) return { refused: "page-rule" };
    return {
      rule: f,
      edits: [{ op: "lock-path", path: entry.path, level: entry.level as "public" | "any-model" | "local-model" | "no-model", bindings: add(entry.bindings ?? []), ...(entry.recursive === false ? { recursive: false } : {}) }],
    };
  }
  // A folder rule with nothing but a level and bindings, or no rule at all:
  // a new exact rule for the file alone, at the level and with the
  // destinations that apply to it now (the composed label: a machine record
  // that raised a copy's level, or bound it nowhere, is kept as it is), plus
  // the host. Never lower, never another destination.
  const lookup = (p: string) => composedLabel(p, deps.snapshot, deps.registryBindings ? { sourceBindings: deps.registryBindings } : {});
  const now = pathConfidentiality(f, deps.home, lookup);
  return { rule: f, edits: [{ op: "lock-path", path: f, level: now.level as ConfidentialityLevel, bindings: add(now.bindings) }] };
}
