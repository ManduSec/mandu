/**
 * sensitivity-labels — Settings › Sensitivity labels
 * (confidentiality-plan-14-policy-suggestions.md §14.1; dashboard.md
 * §4.25s): the Purview / MIP sensitivity labels mapped to levels in
 * policy.yaml `sensitivity_labels:`, and the labels Mandu's last scan found
 * on documents that no mapping names yet, with how many files carry each.
 * Pure; the routes (server/sensitivity-label-routes.ts) do the arbiter.
 * Mandu-new (no reference origin).
 *
 * What is shown: label GUIDs (and their tenants'), the names the PERSON or
 * the administrator gave them, levels, and file counts. Never a path and
 * never a word from inside a document: the arbiter's scan keeps no label
 * name as a file spells it.
 *
 * The mapping changes what Mandu's scan suggests (a document with a mapped
 * label becomes a suggestion in the Suggested view), never what is
 * protected now. Each row carries the version of its mapping as read
 * (policy-surface.md §8.4.6 "An item-level version"), and a change sends
 * it back: a mapping changed somewhere else since is refused, nothing
 * saved, instead of being overwritten with what the row was filled from.
 * Mandu reads no tenant policy, so the level is the person's
 * pick; the form's default is "No AI" (confidentiality.md
 * §3's reading: a label whose policy allows cloud AI maps to "the AI may read
 * it", any other to hidden).
 */
import type { HomeTextPart } from "./ask-words.js";
import { labelLevelWords } from "./policy-proposals.js";
import { labelUncheckedSentences, type LabelScanWire, type LabelUncheckedWire } from "./suggestions.js";

export const LEVELS = ["public", "any-model", "local-model", "no-model"] as const;
export type LabelLevel = (typeof LEVELS)[number];

/** The form's default level (§14.1: any label not known to allow cloud AI). */
export const DEFAULT_LABEL_LEVEL: LabelLevel = "no-model";
/** A name, in the person's words: at most this many characters, one line. */
export const LABEL_NAME_MAX = 64;

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A GUID as written (braces and case optional) → lowercase without braces,
 *  or null (the arbiter's sensitivity-labels.ts `normalizeGuid`). Pure. */
export function normalizeGuid(v: unknown): string | null {
  if (typeof v !== "string") return null;
  let s = v.trim().toLowerCase();
  if (s.startsWith("{") && s.endsWith("}")) s = s.slice(1, -1);
  return GUID_RE.test(s) ? s : null;
}

/** One mapping as the section lists it. */
export interface LabelMappingVM {
  id: string;
  site: string | null;
  name: string;
  level: string;
  levelWords: string;
  /** The administrator's file that sets it (read-only here), or null for the
   *  person's own entry in policy.yaml. */
  admin: string | null;
  /** The person's entry's version as read (an opaque keyed hash): Save and
   *  Remove send it back. null for an administrator's row, or when the
   *  service sends no versions (an older one). */
  version: string | null;
}

/** A label the last scan found that no mapping names. */
export interface UnmappedLabelVM {
  id: string;
  site: string | null;
  /** Files that carry it. */
  files: number;
  filesWords: string;
  /** The version of a mapping that does not exist yet (the service's
   *  `absentVersion`): Save sends it, refused once someone else gave the
   *  label a level meanwhile. null when the service sends none. */
  version: string | null;
}

export interface LabelSettingsVM {
  mappings: LabelMappingVM[];
  unmapped: UnmappedLabelVM[];
  /** More unmapped labels than the scan listed. */
  unmappedMore: number;
  /** When the scan that found them ended (ms), or null before any. */
  scannedAt: number | null;
  /** One line under the list, or null: `noteParts` joined. */
  note: string | null;
  /** The same line as parts, the place it names a link part; null with no note. */
  noteParts: LabelNotePart[] | null;
  levels: Array<{ level: LabelLevel; words: string }>;
  defaultLevel: LabelLevel;
}

/** A place the note sends the person (dashboard.md §4.25s, *The note links
 *  where Scan for keys is*): Keys Mandu found on Rules, opened, where the
 *  Scan for keys button is. It names the place, never an address: the page
 *  builds the link (home.js `placeLink`), as for the Home hero's. */
export type LabelNotePart = HomeTextPart | { kind: "link"; text: string; to: "suggested" };

/** The last scan's label counts (suggestion-routes.ts `lastLabelScan`).
 *  `files`: the files carrying a label (absent from an older scan's answer).
 *  `encrypted`, `unreadable`, `capped`, `limits`: what the label read could
 *  not tell (`LabelUncheckedWire`), absent from an older answer too. */
export interface LastLabelScan {
  labels: { unmapped: Array<{ id: string; site: string | null; files: number }>; unmappedMore: number; files?: number; mode?: LabelScanWire["mode"] } & LabelUncheckedWire;
  at: number;
}

const SCAN_LINK: LabelNotePart = { kind: "link", text: "Keys Mandu found", to: "suggested" };
/** Before any scan. Until 2026-10-08 it said "Press Scan for keys in Rules,
 *  Keys Mandu found," with no link, and Rules shows that button only once
 *  Keys Mandu found is opened. */
export const NO_SCAN_NOTE_PARTS: readonly LabelNotePart[] = [
  { kind: "text", text: "Mandu lists here the sensitivity labels it finds on your documents. To look for them, open " },
  SCAN_LINK,
  { kind: "text", text: " in Rules and press Scan for keys." },
];
/** After a scan that found no document with a label. Until 2026-10-08 this
 *  case said ALL_MAPPED_NOTE, a claim about labels the scan never found. */
export const NO_LABELS_NOTE_PARTS: readonly LabelNotePart[] = [
  { kind: "text", text: "The last scan found no sensitivity label on your documents. To look in another folder, open " },
  SCAN_LINK,
  { kind: "text", text: " in Rules." },
];
const joined = (parts: readonly LabelNotePart[]): string => parts.map((p) => p.text).join("");
export const NO_SCAN_NOTE = joined(NO_SCAN_NOTE_PARTS);
export const NO_LABELS_NOTE = joined(NO_LABELS_NOTE_PARTS);
export const ALL_MAPPED_NOTE = "Every sensitivity label the last scan found has a level.";

/** What the last scan's label read could not tell, in the words Rules' scan
 *  line ends with (suggestions.ts `labelUncheckedSentences`): the encrypted
 *  documents, and the documents past its caps or that it could not read.
 *  None before a scan, or for a label read that opened nothing. Until
 *  2026-10-08 the note never said these, so after a scan that left
 *  documents unchecked it still read "found no sensitivity label on your
 *  documents" (dashboard.md §4.25s *The note says what the scan left
 *  unchecked*). */
function uncheckedSentences(last: LastLabelScan | null): string[] {
  return last === null || last.labels.mode === "off" ? [] : labelUncheckedSentences(last.labels);
}

/** After a scan that found no labelled document: NO_LABELS_NOTE_PARTS, or,
 *  when it left documents unchecked, "on the documents it checked" and the
 *  sentences saying which, before the link. */
function noLabelsParts(unchecked: readonly string[]): readonly LabelNotePart[] {
  if (unchecked.length === 0) return NO_LABELS_NOTE_PARTS;
  return [
    { kind: "text", text: `The last scan found no sensitivity label on the documents it checked. ${unchecked.join(" ")} To look in another folder, open ` },
    SCAN_LINK,
    { kind: "text", text: " in Rules." },
  ];
}

const VERSION_RE = /^[0-9a-f]{32}$/;

/** A mapping's item key, as the service names its version: `id|site`
 *  (each a normalized GUID, site empty when there is none), the arbiter's
 *  policy-edit.ts `labelKey`. */
export function labelItemKey(id: string, site: string | null | undefined): string {
  return `${id}|${site ?? ""}`;
}

/** The versions a read of the law gave (`policyDocument`'s `itemVersions`
 *  and `absentVersion`). */
export interface LabelVersions {
  itemVersions?: Record<string, Record<string, string>>;
  absentVersion?: string;
}

/** The version a read gives one mapping, or null when it gave none (an
 *  older service). An item it does not name has the absent version. */
export function labelVersionOf(versions: LabelVersions | null | undefined, key: string): string | null {
  if (!versions?.itemVersions || typeof versions.absentVersion !== "string") return null;
  const v = versions.itemVersions["sensitivity-labels"]?.[key] ?? versions.absentVersion;
  return VERSION_RE.test(v) ? v : null;
}

function entryOf(raw: unknown, admin: string | null): Omit<LabelMappingVM, "version"> | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const id = normalizeGuid(r["id"]);
  if (id === null) return null;
  const site = r["site"] === undefined || r["site"] === null ? null : normalizeGuid(r["site"]);
  const level = typeof r["level"] === "string" ? r["level"] : "";
  const name = typeof r["name"] === "string" ? r["name"] : "";
  return { id, site, name, level, levelWords: labelLevelWords(level), admin };
}

function plural(k: number, one: string, many: string): string {
  return `${k.toLocaleString("en-US")} ${k === 1 ? one : many}`;
}

/**
 * The section: the person's mappings (policy.yaml, in force), then the
 * administrator's (read-only, with their file), then the labels the last
 * scan found that no mapping names now (a label mapped since the scan drops
 * out). The note under them: before any scan, where to scan; after one that
 * found no labelled document, that it found none; once every label it found
 * has a level, that. After a scan, it ends with what the label read could
 * not tell (`uncheckedSentences`), and says only that while a label waits
 * for a level. Pure.
 */
export function labelSettingsVM(inForce: unknown, admin: unknown, last: LastLabelScan | null, versions?: LabelVersions | null): LabelSettingsVM {
  const own = inForce && typeof inForce === "object" ? (inForce as { sensitivity_labels?: unknown }).sensitivity_labels : undefined;
  const adminList = admin && typeof admin === "object" ? (admin as { sensitivityLabels?: unknown }).sensitivityLabels : undefined;
  const mappings: LabelMappingVM[] = [];
  for (const raw of Array.isArray(own) ? own : []) {
    const m = entryOf(raw, null);
    if (m) mappings.push({ ...m, version: labelVersionOf(versions, labelItemKey(m.id, m.site)) });
  }
  for (const raw of Array.isArray(adminList) ? adminList : []) {
    const file = raw && typeof raw === "object" && typeof (raw as Record<string, unknown>)["file"] === "string" ? (raw as Record<string, string>)["file"]! : "";
    const m = entryOf(raw, file);
    if (m) mappings.push({ ...m, version: null });
  }
  const mapped = (l: { id: string; site: string | null }): boolean =>
    mappings.some((m) => m.id === l.id && (m.site === null || m.site === l.site));
  const unmapped: UnmappedLabelVM[] = [];
  for (const u of last?.labels.unmapped ?? []) {
    const id = normalizeGuid(u.id);
    if (id === null) continue;
    const site = u.site === null ? null : normalizeGuid(u.site);
    if (mapped({ id, site })) continue;
    const files = Number.isFinite(u.files) && u.files > 0 ? Math.floor(u.files) : 0;
    unmapped.push({ id, site, files, filesWords: plural(files, "file carries it", "files carry it"), version: labelVersionOf(versions, labelItemKey(id, site)) });
  }
  const unchecked = uncheckedSentences(last);
  const noteParts: readonly LabelNotePart[] | null =
    last === null
      ? NO_SCAN_NOTE_PARTS
      : unmapped.length > 0 || (last.labels.unmappedMore ?? 0) > 0
        ? unchecked.length ? [{ kind: "text", text: unchecked.join(" ") }] : null
        : last.labels.files === 0
          ? noLabelsParts(unchecked)
          : [{ kind: "text", text: [ALL_MAPPED_NOTE, ...unchecked].join(" ") }];
  return {
    mappings,
    unmapped,
    unmappedMore: last?.labels.unmappedMore ?? 0,
    scannedAt: last?.at ?? null,
    note: noteParts === null ? null : joined(noteParts),
    noteParts: noteParts === null ? null : noteParts.map((p) => ({ ...p })),
    levels: LEVELS.map((level) => ({ level, words: labelLevelWords(level) })),
    defaultLevel: DEFAULT_LABEL_LEVEL,
  };
}

export type LabelChangePlan =
  /** `key`: the mapping's item key (`labelItemKey`), the item the edit
   *  writes; `name`: what to call it in a sentence. */
  | { ok: true; edits: Array<Record<string, unknown>>; key: string; name: string | null }
  | { ok: false; status: number; error: string };

/**
 * One Settings action → the edit (arbiter policy-edit.ts
 * `map-sensitivity-label` / `unmap-sensitivity-label`). Pure. The arbiter's
 * validator judges the result again; this refuses early what the form can
 * get wrong, in the page's words.
 *   { action: "map", id, site?, name, level }
 *   { action: "unmap", id, site? }
 */
export function planLabelChange(body: unknown): LabelChangePlan {
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const action = b["action"];
  if (action !== "map" && action !== "unmap") return { ok: false, status: 400, error: "action must be map or unmap" };
  const id = normalizeGuid(b["id"]);
  if (id === null) return { ok: false, status: 400, error: "Which label? Its id is a GUID like 9fbde396-1a24-4c79-8edf-9254a0f35055." };
  let site: string | undefined;
  if (b["site"] !== undefined && b["site"] !== null && b["site"] !== "") {
    const s = normalizeGuid(b["site"]);
    if (s === null) return { ok: false, status: 400, error: "The organization id must be a GUID too." };
    site = s;
  }
  const key = labelItemKey(id, site);
  if (action === "unmap") return { ok: true, edits: [{ op: "unmap-sensitivity-label", id, ...(site ? { site } : {}) }], key, name: null };
  const name = typeof b["name"] === "string" ? b["name"].trim() : "";
  if (name === "") return { ok: false, status: 400, error: "Give the label a name, as your organization calls it." };
  if (name.length > LABEL_NAME_MAX || /[\u0000-\u001f\u007f-\u009f]/.test(name)) {
    return { ok: false, status: 400, error: `The name must be one line of at most ${LABEL_NAME_MAX} characters.` };
  }
  const level = b["level"];
  if (typeof level !== "string" || !(LEVELS as readonly string[]).includes(level)) return { ok: false, status: 400, error: "Pick a level." };
  return { ok: true, edits: [{ op: "map-sensitivity-label", id, ...(site ? { site } : {}), name, level }], key, name };
}

/** Said when the mapping a change was made from changed somewhere else
 *  meanwhile (policy-surface.md §8.4.6): nothing was saved. */
export function labelStaleWords(name: string, action: "map" | "unmap"): string {
  return action === "unmap"
    ? `${name} was changed somewhere else just now, so nothing was removed. It is shown as it is now: look at it, then remove it again if you still want to.`
    : `${name} was changed somewhere else just now, so nothing was saved. The level you picked is still on the row: compare it with ${name} as it is now, then save again.`;
}
