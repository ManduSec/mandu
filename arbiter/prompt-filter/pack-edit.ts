/**
 * pack-edit — typed edits to a person's own pattern pack
 * (confidentiality-plan-15-prompt-filter.md §8.1, phase 2). Mandu-new (no
 * reference origin).
 *
 * The developer dashboard's Prompt filters panel edits the person's packs in
 * `~/.mandu/prompt-filters/` with these, never with YAML:
 *
 *   { op: "set-prompt-pattern",    pack, pattern: { id, category, regex, check?, level? } }
 *   { op: "remove-prompt-pattern", pack, id }
 *   { op: "add-prompt-keyword",    pack, category, word, match? }
 *   { op: "remove-prompt-keyword", pack, category, word, match? }
 *
 * `applyPackEdits` is pure: it applies one list to a copy of the pack (a
 * missing pack is created), validates the result with the loader's own
 * validator (the RE2 engine must accept every regex) and classifies the
 * change by the §6 rule, compared by pattern id and content: a new pattern or
 * keyword is a tightening; a removed one, and an edited one (remove, then
 * add), are relaxations. The arbiter applies a list only on the admin channel
 * (`promptPackEdit` is an ADMIN_ONLY op: the person's own decision, audited),
 * so a relaxation made there applies; the agent cannot reach it. An
 * administrator's pack is read-only; a signed pack of the person's is too
 * (an edit would void its signature).
 */
import type { PromptDeltaChange } from "./policy.js";
import { normalizeKeyword, validatePack, validatePattern, type PackDocument, type PackPattern } from "./packs.js";

export type PromptPackEdit =
  | { op: "set-prompt-pattern"; pack: string; pattern: PackPattern }
  | { op: "remove-prompt-pattern"; pack: string; id: string }
  | { op: "add-prompt-keyword"; pack: string; category: string; word: string; match?: "word" | "substring" }
  | { op: "remove-prompt-keyword"; pack: string; category: string; word: string; match?: "word" | "substring" };

export const PACK_EDIT_OPS = ["set-prompt-pattern", "remove-prompt-pattern", "add-prompt-keyword", "remove-prompt-keyword"] as const;

const KEYS: Record<(typeof PACK_EDIT_OPS)[number], readonly string[]> = {
  "set-prompt-pattern": ["op", "pack", "pattern"],
  "remove-prompt-pattern": ["op", "pack", "id"],
  "add-prompt-keyword": ["op", "pack", "category", "word", "match"],
  "remove-prompt-keyword": ["op", "pack", "category", "word", "match"],
};

export type PackEditResult =
  | { ok: true; pack: string; doc: PackDocument; created: boolean; changes: PromptDeltaChange[] }
  | { ok: false; problems: string[] };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const samePattern = (a: PackPattern, b: PackPattern): boolean =>
  a.category === b.category && a.regex === b.regex && (a.check ?? null) === (b.check ?? null) && (a.level ?? null) === (b.level ?? null);

/**
 * Apply `edits` (all for one pack) to `current` (null: the pack does not
 * exist yet and is created at version 1). Pure.
 */
export function applyPackEdits(current: PackDocument | null, edits: unknown): PackEditResult {
  if (!Array.isArray(edits) || edits.length === 0) return { ok: false, problems: ["edits: must be a non-empty list"] };
  const problems: string[] = [];
  const packIds = new Set<string>();
  for (const e of edits) if (isPlainObject(e) && typeof e.pack === "string") packIds.add(e.pack);
  if (packIds.size !== 1) return { ok: false, problems: ["edits: every edit names the same pack"] };
  const pack = [...packIds][0]!;
  if (current !== null && current.pack !== pack) return { ok: false, problems: [`edits: the pack is ${current.pack}, not ${pack}`] };
  const doc: PackDocument = current
    ? structuredClone(current)
    : { pack, version: 0, patterns: [], keywords: [] };
  const changes: PromptDeltaChange[] = [];
  edits.forEach((raw, i) => {
    const at = `edits[${i}]`;
    if (!isPlainObject(raw) || typeof raw.op !== "string") { problems.push(`${at}: must be a mapping with an 'op'`); return; }
    const allowed = (KEYS as Record<string, readonly string[] | undefined>)[raw.op];
    if (!allowed) { problems.push(`${at}: unknown op (known: ${PACK_EDIT_OPS.join(", ")})`); return; }
    const extra = Object.keys(raw).filter((k) => !allowed.includes(k));
    if (extra.length > 0) { problems.push(`${at} (${raw.op}): unknown key${extra.length > 1 ? "s" : ""} ${extra.map((k) => `'${k}'`).join(", ")}`); return; }
    const e = raw as PromptPackEdit;
    switch (e.op) {
      case "set-prompt-pattern": {
        const v = validatePattern(e.pattern);
        if ("problems" in v) { for (const p of v.problems) problems.push(`${at} (set-prompt-pattern): pattern.${p}`); return; }
        const idx = doc.patterns.findIndex((p) => p.id === v.pattern.id);
        if (idx >= 0) {
          if (samePattern(doc.patterns[idx]!, v.pattern)) return;
          doc.patterns[idx] = v.pattern;
          // An edited pattern is remove-then-add (§6): it can match less.
          changes.push({ direction: "relax", subject: `pattern ${pack}/${v.pattern.id}`, detail: `the pattern ${v.pattern.id} of ${pack} is changed (the old one no longer runs)` });
        } else {
          doc.patterns.push(v.pattern);
          changes.push({ direction: "tighten", subject: `pattern ${pack}/${v.pattern.id}`, detail: `the pattern ${v.pattern.id} (${v.pattern.category}) is added to ${pack}` });
        }
        return;
      }
      case "remove-prompt-pattern": {
        const idx = doc.patterns.findIndex((p) => p.id === e.id);
        if (idx < 0) { problems.push(`${at} (remove-prompt-pattern): no pattern ${String(e.id)} in ${pack}`); return; }
        doc.patterns.splice(idx, 1);
        changes.push({ direction: "relax", subject: `pattern ${pack}/${e.id}`, detail: `the pattern ${e.id} is removed from ${pack}` });
        return;
      }
      case "add-prompt-keyword":
      case "remove-prompt-keyword": {
        const match = e.match ?? "word";
        if (match !== "word" && match !== "substring") { problems.push(`${at} (${e.op}): match must be word or substring`); return; }
        if (typeof e.category !== "string" || typeof e.word !== "string" || e.word.trim() === "") { problems.push(`${at} (${e.op}): category and word are required`); return; }
        const same = (w: string): boolean => (match === "word" ? normalizeKeyword(w) === normalizeKeyword(e.word) : w.toLowerCase() === e.word.toLowerCase());
        let group = doc.keywords.find((k) => k.words !== undefined && k.category === e.category && k.match === match);
        if (e.op === "add-prompt-keyword") {
          if (group?.words?.some(same)) return;
          if (!group) { group = { category: e.category, match, words: [] }; doc.keywords.push(group); }
          group.words!.push(e.word);
          changes.push({ direction: "tighten", subject: `keyword ${pack}/${e.category}`, detail: `a keyword of ${e.category} is added to ${pack}` });
          return;
        }
        const idx = group?.words?.findIndex(same) ?? -1;
        if (!group || idx < 0) { problems.push(`${at} (remove-prompt-keyword): no such keyword of ${String(e.category)} in ${pack}`); return; }
        group.words!.splice(idx, 1);
        if (group.words!.length === 0) doc.keywords.splice(doc.keywords.indexOf(group), 1);
        changes.push({ direction: "relax", subject: `keyword ${pack}/${e.category}`, detail: `a keyword of ${e.category} is removed from ${pack}` });
        return;
      }
    }
  });
  if (problems.length > 0) return { ok: false, problems };
  if (changes.length === 0) return { ok: true, pack, doc: current ?? doc, created: false, changes };
  doc.version = typeof doc.version === "number" ? doc.version + 1 : doc.version;
  // The loader's own validator, on the whole result (a pack emptied by a
  // removal is refused: remove the file instead).
  const v = validatePack({
    pack: doc.pack, version: doc.version, ...(doc.description !== undefined ? { description: doc.description } : {}),
    ...(doc.patterns.length > 0 ? { patterns: doc.patterns } : {}),
    ...(doc.keywords.length > 0 ? {
      keywords: doc.keywords.map((k) => ({
        category: k.category, ...(k.match !== "word" ? { match: k.match } : {}),
        ...(k.salt !== undefined ? { salt: k.salt, hashes: k.hashes, max_words: k.maxWords } : { words: k.words }),
        ...(k.level ? { level: k.level } : {}),
      })),
    } : {}),
  });
  if ("problems" in v) return { ok: false, problems: v.problems };
  return { ok: true, pack, doc: v.doc, created: current === null, changes };
}
