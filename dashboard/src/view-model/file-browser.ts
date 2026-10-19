/**
 * file-browser — the Rules page's file browser (dashboard.md §4.25m): the
 * words for each listed file's label and the plan that turns the person's
 * pending changes into rule edits. Pure; the routes (server/file-browser-routes.ts)
 * do the disk and the arbiter. Mandu-new (no reference origin).
 *
 * The label shown is the one a read would get today (`pathLevels`, the same
 * derivation `pathLevel` answers for the mint), never a guess made here, and
 * each says where it came from (your rule, a folder rule above, a pattern, a
 * built-in secret, a file the AI wrote after reading a secret), in the page's
 * own terms (rule-words.ts).
 */
import type { HomeTextPart } from "./ask-words.js";
import { hostParts, levelParts, levelWords, perValueParts, perValueWords, sentenceParts, TERMS, tildePath } from "./rule-words.js";
import { levelClassOf, type LevelClass } from "./secrets.js";
import { ADMITS_NOTHING, READS_PLACEHOLDER, codeRunningReadersWarning, judgedAdmitsNothing, judgedCopyOf, judgedReadsTwin, readerPrints, type ArbiterReaderJudgment } from "./reader-runs-code.js";

// `tildePath` lives with the words that use it (rule-words.ts); kept importable here.
export { tildePath };

/** One `pathLevels` entry as the arbiter answers it. */
export interface PathLevelsEntryWire {
  path: string;
  level: string;
  bindings: string[];
  rule: string | null;
  store: "policy" | "page" | "models" | null;
  /** Plan 13 §5.2: the deciding label's per-value hosts and its own (then
   *  `bindings` is the whole file's). Absent on an older arbiter. */
  values?: Array<{ key: string; bindings: string[] }>;
  fileBindings?: string[];
}

export type LabelSource = "yours" | "inherited" | "pattern" | "builtin" | "written" | "model-key" | "none";

/** One entry's label as the page paints it. */
export interface FileLabelVM {
  level: string;
  levelClass: LevelClass;
  /** The level in the glossary's words ("No AI"). */
  words: string;
  source: LabelSource;
  /** Where it came from, in words ("From your rule on ~/proj"). Empty for none. */
  from: string;
  /** The deciding rule's path or pattern (the tooltip), or null. */
  via: string | null;
  /** This path carries a rule of its own that the person can remove here. */
  removable: boolean;
  /** Where that rule is kept, when a rule of the person's decided. */
  store: "policy" | "page" | "models" | null;
  bindings: string[];
  /** Plan 13 §5.2: per-value hosts (`values:`) and the sentence that says
   *  where each value may go (`perValueWords`), also as parts, each key and
   *  host a code (`perValueParts`). Absent when none. */
  values?: Array<{ key: string; bindings: string[] }>;
  send?: string;
  sendParts?: HomeTextPart[];
}

const GLOB_META = /[*?[]/;


/** The built-in rule as words (secret-catalog.ts's `shape:` / `prefix:` ids). */
const SHAPE_WORDS: Readonly<Record<string, string>> = {
  "shape:.env*": "environment files",
  "shape:*.env": "environment files",
  "shape:*credentials*": "credential files",
  "shape:secrets*.json": "secrets files",
  "shape:ssh-private-key": "SSH keys",
  "shape:*.keytab": "keytab files",
  "shape:*secret*": "files named secret",
  "shape:private-key-file": "private keys",
  "shape:service-account-key": "service account keys",
  "shape:*.tfstate": "Terraform state",
  "shape:tool-login-file": "a tool's saved sign-in",
  "shape:*.private.env.json": "HTTP client private settings",
  // The catalog's content tier (secret-discovery.md §2.6): no name, a
  // credential Mandu read in the file.
  "content:secret-key": "a saved password or key Mandu found in it",
  // §2.7: a statement, a tax return, a lab report, household codes.
  "content:personal-document": "a personal document Mandu recognised",
};

export function builtinWords(rule: string, home: string): string {
  if (rule.startsWith("prefix:")) return `Built in: ${tildePath(rule.slice("prefix:".length), home)}`;
  return `Built in: ${SHAPE_WORDS[rule] ?? rule.replace(/^[a-z]+:/, "")}`;
}

/** Strip a trailing slash so `/a/b/` and `/a/b` compare equal. */
function norm(p: string): string {
  return p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p;
}

/** The label of one listed path, in the page's words. `path` is absolute. */
export function fileLabel(entry: PathLevelsEntryWire, home: string): FileLabelVM {
  const rule = entry.rule;
  const perValue = entry.values?.length && entry.level !== "public" ? entry.values : null;
  const base = {
    level: entry.level,
    levelClass: levelClassOf(entry.level),
    words: perValue ? levelWords(entry.level) : levelWords(entry.level, entry.bindings),
    bindings: [...entry.bindings],
    store: entry.store,
    ...(perValue ? {
      values: perValue.map((v) => ({ key: v.key, bindings: [...v.bindings] })),
      send: perValueWords(perValue, entry.fileBindings ?? [], entry.bindings),
      sendParts: perValueParts(perValue, entry.fileBindings ?? [], entry.bindings),
    } : {}),
  };
  if (rule === null) {
    return { ...base, words: "Like any other file", source: "none", from: "", via: null, removable: false };
  }
  if (rule.startsWith("label:")) {
    const via = rule.slice("label:".length);
    if (entry.store === "models") {
      return { ...base, source: "model-key", from: "The key for a model in Settings › Models", via, removable: false };
    }
    if (GLOB_META.test(via)) {
      return { ...base, source: "pattern", from: `Matches your rule ${tildePath(via, home)}`, via, removable: false };
    }
    if (norm(via) === norm(entry.path)) {
      return { ...base, source: "yours", from: "Your rule", via, removable: true };
    }
    return { ...base, source: "inherited", from: `From your rule on ${tildePath(via, home)}`, via, removable: false };
  }
  if (rule.startsWith("derived:")) {
    return { ...base, source: "written", from: "Written by the AI after it read a secret", via: null, removable: false };
  }
  return { ...base, source: "builtin", from: builtinWords(rule, home), via: rule, removable: false };
}

// ── the plan for Save ─────────────────────────────────────────────────────────

export const LEVELS = ["no-model", "local-model", "any-model", "public"] as const;
export type Level = (typeof LEVELS)[number];

/** How strict a level is: a lower rank is weaker. An unknown level ranks as
 *  the strictest (fail closed: moving off it is a loosening). */
export function levelRank(level: string): number {
  return level === "public" ? 0 : level === "any-model" ? 1 : level === "local-model" ? 2 : 3;
}

/** One pending change as the page sends it. `level: null` removes the
 *  person's own rule on the path. `version`: the version of the path's own
 *  rule in policy.yaml as the page read it (the listing's or the rule
 *  list's `version`; the absent version when it had none), so a rule
 *  changed somewhere else since refuses the save (policy-surface.md §8.4.6
 *  "An item-level version"). */
export interface FileChange {
  path: string;
  level: Level | null;
  bindings?: string[];
  recursive?: boolean;
  version?: string | null;
}

/** An item version as the service writes one (32 hex). */
export const VERSION_RE = /^[0-9a-f]{32}$/;

/** The key the service names a path's own rule by in `itemVersions.paths`
 *  (the arbiter's policy-edit.ts `pathIdentity`): a pattern as `glob:` and
 *  the pattern, a path as its absolute spelling (`abs` is already that,
 *  resolveWrittenPath / normalizeLabelPath). */
export function pathItemKey(abs: string): string {
  return GLOB_META.test(abs) ? `glob:${abs.trim()}` : abs;
}

/** The version a read gives one path's own rule, or null when the read
 *  gave none (an older service). A path with no rule of its own has the
 *  absent version. */
export function pathVersionOf(read: { itemVersions?: Record<string, Record<string, string>>; absentVersion?: string } | null | undefined, abs: string): string | null {
  if (!read?.itemVersions || typeof read.absentVersion !== "string") return null;
  const v = read.itemVersions["paths"]?.[pathItemKey(abs)] ?? read.absentVersion;
  return VERSION_RE.test(v) ? v : null;
}

/** Said when a rule a save was made from changed somewhere else meanwhile:
 *  nothing was saved, and the choice still waits. `displays`: the paths as
 *  the page shows them (`~/…`). */
export function fileStaleWords(displays: readonly string[]): string {
  const names = displays.length <= 1 ? (displays[0] ?? "A rule") : `${displays.slice(0, -1).join(", ")} and ${displays[displays.length - 1]}`;
  const verb = displays.length > 1 ? "were" : "was";
  return `${names} ${verb} changed somewhere else while you were choosing, so nothing was saved. Your choice still waits in Changes to save: look at the label as it is now, then save again.`;
}

/** A label made on the page before labels moved to policy.yaml (the mandu.db
 *  store), as `confidentialityState` lists it. */
export interface PageLabel {
  path: string;
  level: string;
  bindings: string[];
  recursive: boolean;
}

/** A rule edit for policy.yaml (the arbiter's policy-edit grammar). */
export type LockEdit =
  | { op: "lock-path"; path: string; level: Level; bindings?: string[]; recursive?: boolean }
  | { op: "unlock-path"; path: string };

/** A change to a rule kept in the page's own store, made in place there. */
export type PageAct =
  | { act: "set"; path: string; level: Level; bindings: string[]; recursive: boolean }
  | { act: "remove"; path: string };

export interface ChangePlan {
  edits: LockEdit[];
  /** Per edit (same order): the version of its path's own rule the page
   *  read, or null when the change named none. */
  versions: Array<string | null>;
  page: PageAct[];
  /** The page acts that loosen protection: `page\0<path>` keys (the policy
   *  edits' loosenings come from the arbiter's own preview). */
  pageLoosens: PageLoosen[];
}

/** One page-store loosening. `fileDetail`, on a rule that reaches everything
 *  inside its path, is the same words for a path that is a file, with
 *  nothing said of its inside (pageLooseningWords). The `…Parts` are the
 *  same words with each host a code, on a line that names hosts. */
export interface PageLoosen {
  key: string;
  subject: string;
  detail: string;
  detailParts?: HomeTextPart[];
  fileDetail?: string;
  fileDetailParts?: HomeTextPart[];
}

export const MAX_CHANGES = 200;
const HOST = /^[A-Za-z0-9*][A-Za-z0-9.*:-]*$/;

/** The key a page-store loosening is confirmed by (the policy ones use
 *  policy-assistant.ts relaxKey). */
export function pageKey(path: string): string {
  return `page\u0000${path}`;
}

/** Validate the body and plan it. `resolve` turns a written path into its
 *  absolute spelling (`~` expanded; a pattern kept as written) or null;
 *  `pageLabels` are the page store's rows. A path with a rule of its own in
 *  the page's store is changed there, in place (that rule wins over
 *  policy.yaml on the same path); every other change is a policy.yaml edit.
 *  Returns an error string for a body that is not a valid list of changes. */
export function planFileChanges(
  raw: unknown,
  resolve: (p: string) => string | null,
  pageLabels: readonly PageLabel[],
): ChangePlan | string {
  if (!Array.isArray(raw) || raw.length === 0) return "changes must be a non-empty list";
  if (raw.length > MAX_CHANGES) return `at most ${MAX_CHANGES} changes at once`;
  const seen = new Set<string>();
  const plan: ChangePlan = { edits: [], versions: [], page: [], pageLoosens: [] };
  const pageByPath = new Map(pageLabels.map((l) => [norm(l.path), l]));
  for (const [i, c] of raw.entries()) {
    if (!c || typeof c !== "object") return `changes[${i}] must be an object`;
    const { path, level: rawLevel, bindings, recursive, version: rawVersion } = c as Record<string, unknown>;
    if (typeof path !== "string" || path.trim() === "") return `changes[${i}].path is required`;
    const written = resolve(path.trim());
    if (written === null) return `changes[${i}].path must start with /, ~ or **/ (got ${JSON.stringify(path)})`;
    const abs = norm(written);
    if (seen.has(abs)) return `changes[${i}]: ${path} is listed twice`;
    seen.add(abs);
    if (rawLevel !== null && !(typeof rawLevel === "string" && (LEVELS as readonly string[]).includes(rawLevel))) {
      return `changes[${i}].level must be one of ${LEVELS.join(", ")} or null`;
    }
    const level = rawLevel as Level | null;
    if (bindings !== undefined && (!Array.isArray(bindings) || !bindings.every((b) => typeof b === "string" && HOST.test(b)))) {
      return `changes[${i}].bindings must be a list of host names`;
    }
    if (recursive !== undefined && typeof recursive !== "boolean") return `changes[${i}].recursive must be true or false`;
    if (rawVersion !== undefined && rawVersion !== null && !(typeof rawVersion === "string" && VERSION_RE.test(rawVersion))) {
      return `changes[${i}].version must be the version the page read`;
    }
    const version = typeof rawVersion === "string" ? rawVersion : null;
    const hosts = (bindings as string[] | undefined) ?? [];
    const glob = GLOB_META.test(abs);
    // The rule in the page's store on this very path, if any: it wins over
    // policy.yaml on the same path, so a change there is made in place.
    const page = glob ? undefined : pageByPath.get(norm(abs));
    if (level === null) {
      if (page) {
        plan.page.push({ act: "remove", path: page.path });
        if (levelRank(page.level) > 0) {
          plan.pageLoosens.push({ key: pageKey(page.path), subject: page.path, detail: "Loses its own rule. A folder rule above it, or the built-in secrets, decide there again." });
        }
      } else {
        plan.edits.push({ op: "unlock-path", path: abs });
        plan.versions.push(version);
      }
      continue;
    }
    const rec = glob ? undefined : (recursive as boolean | undefined) ?? true;
    if (page) {
      plan.page.push({ act: "set", path: page.path, level, bindings: hosts, recursive: rec ?? true });
      const wider = hosts.some((h) => !page.bindings.includes(h)) && level !== "public";
      const reach = rec === true && !page.recursive && level !== "no-model";
      if (levelRank(level) < levelRank(page.level) || wider || reach) {
        const becomes = sentenceParts("Becomes ", levelParts(level, hosts));
        const detailParts = sentenceParts(becomes, `${rec ? ", and so does everything inside it that has no rule of its own" : ""}.`);
        const fileDetailParts = sentenceParts(becomes, ".");
        plan.pageLoosens.push({ key: pageKey(page.path), subject: page.path, detail: partsText(detailParts), detailParts, ...(rec ? { fileDetail: partsText(fileDetailParts), fileDetailParts } : {}) });
      }
      continue;
    }
    plan.edits.push({ op: "lock-path", path: abs, level, ...(hosts.length ? { bindings: hosts } : {}), ...(rec === false ? { recursive: false } : {}) });
    plan.versions.push(version);
  }
  return plan;
}

/** The words for a level choice, for the confirmation (re-exported so the
 *  routes need one import), and the same words as parts. */
export { levelParts, levelWords, TERMS };

// ── Why this label ────────────────────────────────────────────────────────────

/** The arbiter's `whyPath` answer (the fields this page reads). */
export interface WhyPathWire {
  path: string;
  axis: boolean;
  level: string;
  rule: string | null;
  bindings: string[];
  outranked: Array<{ path: string; level: string }>;
  readers: unknown[];
  /** Plan 13 D8 (2026-10-03): the arbiter's own judgment of `readers`, per
   *  entry and in its order (by name, path and a pin's hash: a renamed copy
   *  of an installed printer or interpreter is that program). The page says
   *  what the arbiter decides; its name-only mirror is the fallback when
   *  these are absent (an older arbiter). */
  readersAdmitNothing?: boolean[];
  /** Plan 13 D8 (12): per entry, its program reads the placeholder copy. */
  readersReadTwin?: boolean[];
  readersPrint?: boolean[];
  readersCopyOf?: Array<string | null>;
  others: string | null;
  consumers: string[];
  /** Per `consumers` entry, the arbiter's word that it prints (plan 13 D8,
   *  §4.9): such a program gets the masked copy. Absent from an older
   *  arbiter (the name rule is the fallback). */
  consumersPrint?: boolean[];
  twinShape: string | null;
  /** 2026-10-09: the masked copy the arbiter makes of the file as it is
   *  now: `structured` (each of `fields` values hidden), `own-text`, or
   *  `whole-file`. Absent from an older arbiter or for an unreadable file
   *  (`twinShape`, by the path alone, is the fallback). */
  twin?: { form: "structured" | "own-text" | "whole-file"; shape: string | null; fields: number };
  /** Plan 10 §11.13.3: the commands an ssh config's masked copy leaves
   *  out, by line and keyword (never their text). Absent from an older
   *  arbiter. */
  withheld?: Array<{ line: number; keyword: string }>;
  /** `exe`: the binary the verdict is for (Plan 13 D8), when the row names
   *  one; `script`, `run`, `stale`: plan 13 §8 decision (c) (the script an
   *  interpreter's answer names; an answer about one run; an answer naming
   *  an interpreter alone, which applies to nothing); `printer`: plan 13
   *  D8, an answer about a program that prints the file, which applies to
   *  nothing and is never asked again (2026-10-03). */
  verdicts: Array<{ kind?: string; app: string; exe?: string; status: string; scope: string; script?: string; run?: boolean; stale?: boolean; printer?: boolean; unvetted?: boolean }>;
}

export interface WhyVM {
  path: string;
  display: string;
  label: FileLabelVM;
  /** Protection is off: nothing below is enforced now. */
  off: boolean;
  /** Plain lines, each a heading and what it says; a line that names hosts
   *  also as parts, each host a code (the text exactly `text`). */
  lines: Array<{ term: string; text: string; parts?: HomeTextPart[] }>;
}

/** *May be sent to*: the hosts where the file may go, each a code. A file
 *  whose values are bound one by one (plan 13 §5.2) says where each value
 *  may go, the sentence its row's *Per value* shows: its `bindings` are only
 *  the whole file's, and "Nowhere without your OK." said less than the
 *  rules let leave (dashboard.md §4.25u, *Rules names each host*). */
export function sendLine(entry: PathLevelsEntryWire): { term: string; text: string; parts: HomeTextPart[] } {
  const term = "May be sent to";
  if (entry.values?.length && entry.level !== "public") {
    return { term, text: perValueWords(entry.values, entry.fileBindings ?? [], entry.bindings), parts: perValueParts(entry.values, entry.fileBindings ?? [], entry.bindings) };
  }
  if (!entry.bindings.length) return { term, text: "Nowhere without your OK.", parts: [{ kind: "text", text: "Nowhere without your OK." }] };
  return { term, text: entry.bindings.join(", "), parts: hostParts(entry.bindings) };
}

/** One reader as written in policy.yaml: `psql`, or `{ app: ssh, from: git }`.
 *  A shell or an interpreter with no script pin admits nothing (plan 13 §8
 *  decision (b)), and says so. */
function readerWords(r: unknown, i: number, judged?: ArbiterReaderJudgment): string {
  if (judgedAdmitsNothing(r, i, judged)) {
    const of = judgedCopyOf(i, judged);
    return `${typeof r === "string" ? r : (r as { app?: unknown }).app}${of !== null ? ` (a copy of ${of})` : ""}${ADMITS_NOTHING}`;
  }
  // Plan 13 D8 (12): a program neither vetted nor vouched for reads the
  // placeholder copy, and the entry says so.
  const twin = judgedReadsTwin(r, i, judged) ? READS_PLACEHOLDER : "";
  if (typeof r === "string") return `${r}${twin}`;
  if (r && typeof r === "object") {
    const o = r as { app?: unknown; from?: unknown; script?: unknown };
    // Plan 13 R5: an interpreter pinned with the script it runs.
    const app = typeof o.app === "string" && typeof o.script === "string" ? `${o.app} running ${o.script}` : o.app;
    if (typeof app === "string") return `${typeof o.from === "string" ? `${app} (only when ${o.from} starts it)` : app}${twin}`;
  }
  return "a program";
}

/** Plan 13 D3: what the AI sees of the readers' output once they hold THIS
 *  file. A reader entry may carry `output: clear | mask` (this file only);
 *  everything else is one placeholder. A program that runs code is never
 *  shown (the arbiter refuses the rule), so the page does not say it is. */
function readerOutputWords(readers: readonly unknown[], judged?: ArbiterReaderJudgment): string {
  const shown: string[] = [];
  for (const [i, r] of readers.entries()) {
    if (!r || typeof r !== "object") continue;
    const o = r as { app?: unknown; output?: unknown; script?: unknown };
    // Plan 13 R5: an interpreter pinned with its script is that program.
    const script = typeof o.script === "string" ? o.script : null;
    // Plan 13 D8: an entry that admits nothing (a printer, a program that
    // runs code with no script pin, a renamed copy of either) shows nothing.
    if (typeof o.app !== "string" || judgedAdmitsNothing(r, i, judged) || judgedReadsTwin(r, i, judged)) continue;
    const who = script !== null ? `${o.app} running ${script}` : o.app;
    if (o.output === "clear") shown.push(`${who}: shown as printed`);
    else if (o.output === "mask") shown.push(`${who}: shown, with the parts your patterns name hidden`);
  }
  if (shown.length === 0) return "Masked as a whole, for every program above.";
  return `${shown.join("; ")} (a value from this file is still hidden). Any other program above: masked as a whole. This is about this file only.`;
}

function clock(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 16).replace("T", " ");
}

/** Plan 10 §11.13.3: the ssh commands the masked copy leaves out, where,
 *  why and the way out, in the page's words. */
export function withheldWords(held: ReadonlyArray<{ line: number; keyword: string }>): string {
  const where = held.map((w) => `line ${w.line} (${w.keyword})`).join(", ");
  return `${where}. Programs the AI runs get this file without ${held.length === 1 ? "that command" : "those commands"}, `
    + "because Mandu cannot tell whether a command holds a secret, and running it would run code holding one; ssh prints a notice there instead. "
    + "Use ProxyJump (or plain ssh -W) instead, or move the command into a script the AI cannot change and let ssh read the real file "
    + "(name ssh in readers: in policy.yaml), or run that ssh outside the AI.";
}

/** What the masked copy of a file is, in the page's words (2026-10-09):
 *  the copy the arbiter makes of the file as it is now. The line used to
 *  say "only the values are hidden" of every file whose path has a
 *  structured shape, whatever the file held. An older arbiter sends no
 *  `twin`: the path's shape is all there is, and the words say what it
 *  depends on. Null: nothing to add (a file hidden whole, by an older
 *  arbiter's word). */
export function maskedCopyWords(why: Pick<WhyPathWire, "twin" | "twinShape">): string | null {
  const t = why.twin;
  if (t === undefined) {
    return why.twinShape ? "Keeps the file's shape and names when Mandu recognizes a secret value in it, and hides each value it recognizes; otherwise the whole file is hidden." : null;
  }
  if (t.form === "structured") return `Keeps the file's shape and names; each secret value Mandu recognizes is hidden (${t.fields} now).`;
  if (t.form === "own-text") return "Is the file as it is: Mandu recognizes no secret value in it.";
  // 2026-10-10: also a file whose only recognized secret is a list item.
  return "Hides the whole file: Mandu finds no secret value in it that it can hide in place.";
}

/** Everything the rules say about one file, in the page's words. */
export function whyWords(
  why: WhyPathWire,
  entry: PathLevelsEntryWire,
  held: ReadonlyArray<{ app: string; since: number }>,
  home: string,
  folder = false,
): WhyVM {
  const label = fileLabel(entry, home);
  const lines: WhyVM["lines"] = [];
  const secret = entry.level !== "public";
  if (label.from) lines.push({ term: "Where the label comes from", text: label.via && label.source !== "builtin" ? `${label.from} (${tildePath(label.via, home)})` : label.from });
  if (secret && folder) {
    // Which programs may read is decided file by file (the consumer table
    // names ssh for a key, not for its folder).
    lines.push({ term: "Programs that get the real files", text: "Decided for each file inside. Open the folder and use Why? on a file." });
    lines.push(sendLine(entry));
  } else if (secret) {
    // Plan 13 D8 (2026-10-03): the arbiter's judgment of each entry, so the
    // page says what it decides (a pinned renamed copy included).
    const judged: ArbiterReaderJudgment = { ...(why.readersAdmitNothing ? { admitNothing: why.readersAdmitNothing } : {}), ...(why.readersPrint ? { print: why.readersPrint } : {}), ...(why.readersCopyOf ? { copyOf: why.readersCopyOf } : {}), ...(why.readersReadTwin ? { readTwin: why.readersReadTwin } : {}) };
    const readers = (why.readers ?? []).map((r, i) => readerWords(r, i, judged));
    if (readers.length) {
      lines.push({ term: "Programs that get the real file", text: readers.join(", ") });
      // Plan 13 §8 decision (b): a shell or an interpreter here admits
      // nothing; nor, since 2026-10-03, does a printer (cat, head, cp, …).
      const warn = codeRunningReadersWarning(why.readers, judged);
      if (warn) lines.push({ term: "Warning", text: warn });
      lines.push({ term: "What the AI sees of their output", text: readerOutputWords(why.readers ?? [], judged) });
      lines.push({ term: "Any other program", text: why.others === "twin" ? "Gets a masked copy." : "Is refused." });
    } else if (why.consumers?.length) {
      // Plan 13 D8 and §4.9 (2026-10-04): a known program that prints (curl
      // for .netrc, git for .git-credentials) is no default reader; it gets
      // the masked copy. The arbiter's word, else the name rule.
      const prints = why.consumers.map((c, i) => why.consumersPrint?.[i] ?? readerPrints(c));
      const raw = why.consumers.filter((_, i) => !prints[i]);
      const printing = why.consumers.filter((_, i) => prints[i]);
      const printWords = printing.length === 0 ? ""
        : `${printing.join(", ")} ${printing.length === 1 ? "prints what it reads, so it gets" : "print what they read, so they get"} a masked copy too. `;
      lines.push({ term: "Programs that get the real file", text: raw.length
        ? `${raw.join(", ")} (known to need it). ${printWords}Any other program gets a masked copy.`
        : `None. ${printWords}Any other program gets a masked copy.` });
    } else {
      lines.push({ term: "Programs that get the real file", text: "None listed. Programs get a masked copy; name the ones that need it with readers: in policy.yaml." });
    }
    const copy = maskedCopyWords(why);
    if (copy !== null) lines.push({ term: "The masked copy", text: copy });
    const withheld = why.withheld ?? [];
    if (withheld.length) lines.push({ term: "Commands left out", text: withheldWords(withheld) });
    lines.push(sendLine(entry));
    for (const v of why.verdicts ?? []) {
      const who = `${v.exe ?? v.app}${v.script !== undefined ? ` running ${v.script}` : v.run ? " running its own code (that change only)" : ""}`;
      const stale = v.printer ? ` (no longer applies: ${v.app} prints the file to whatever reads its output, so it never gets the real file and you will not be asked again)`
        : v.stale ? " (no longer applies: it names the interpreter, not the script it runs; you will be asked again)"
        : v.unvetted ? ` (no longer applies: the question did not say ${v.app} may print what it reads; you will be asked again)` : "";
      lines.push({ term: "Your answer", text: `${who}: ${v.status === "approved" ? "allowed" : v.status === "denied" ? "blocked" : v.status}${v.scope === "once" ? " once" : ""}${stale}` });
    }
    if (held.length) {
      lines.push({ term: "Programs that read the real file", text: held.map((h) => (clock(h.since) ? `${h.app} (${clock(h.since)} UTC)` : h.app)).join(", ") });
    }
  }
  for (const o of why.outranked ?? []) {
    lines.push({ term: "Also matches", text: `${tildePath(o.path, home)} (${levelWords(o.level)}), but a closer rule decides here.` });
  }
  return { path: entry.path, display: tildePath(entry.path, home), label, off: !why.axis, lines };
}

/** A loosening as Save's confirmation names it. */
export interface LooseningWords {
  subject: string;
  detail: string;
  /** `detail` with each host a code, on a line that names hosts (§4.25u). */
  detailParts?: HomeTextPart[];
}

/** One loosening the person confirms, in the page's words. `r` is one of the
 *  arbiter's preview relaxations for `edits`; its own detail is written for
 *  the inspector, so the words here are rebuilt from the edit it is about.
 *  `files` are the edits' paths that are files on this computer
 *  (server/path-kinds.ts): a rule reaching everything inside one of them
 *  reads as that file, with nothing said of its inside (dashboard.md
 *  §4.25f). A path not in it keeps the words the rule says. */
export function looseningWords(
  r: { facet: string; subject: string },
  edits: readonly LockEdit[],
  home: string,
  files: ReadonlySet<string> = new Set(),
): LooseningWords {
  const subject = tildePath(r.subject, home);
  const e = edits.find((x) => norm(x.path) === norm(r.subject));
  if (r.facet !== "paths" || !e) {
    return { subject, detail: "A rule you are adding takes over from your rule here, so it may be less protected." };
  }
  if (e.op === "unlock-path") {
    return { subject, detail: "Loses its own rule. A folder rule above it, or the built-in secrets, decide there again." };
  }
  const inside = e.recursive !== false && !GLOB_META.test(e.path) && !files.has(e.path) ? " This covers everything inside it that has no rule of its own." : "";
  if (e.level === "public") {
    return { subject, detail: `Becomes ${TERMS.notSecret}, even where Mandu treats a file as secret by default (a .env file or a key, for example).${inside}` };
  }
  const detailParts = sentenceParts("Becomes ", levelParts(e.level, e.bindings ?? []), `, which lets more reach an AI or leave this computer than now.${inside}`);
  return { subject, detail: partsText(detailParts), detailParts };
}

/** A page-store loosening the person confirms, in the page's words: its
 *  file words when its path is one of `files`, as looseningWords. */
export function pageLooseningWords(
  l: PageLoosen,
  home: string,
  files: ReadonlySet<string> = new Set(),
): LooseningWords {
  const file = l.fileDetail !== undefined && files.has(l.subject);
  const parts = file ? l.fileDetailParts : l.detailParts;
  return { subject: tildePath(l.subject, home), detail: file ? l.fileDetail! : l.detail, ...(parts ? { detailParts: sentenceParts(parts) } : {}) };
}

function partsText(parts: readonly HomeTextPart[]): string {
  return parts.map((p) => p.text).join("");
}
