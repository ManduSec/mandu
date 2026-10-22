/**
 * rules-by-who — the Rules page's per-principal view (confidentiality plan 13
 * §5.3, dashboard.md §4.25aa). Mandu-new (no reference origin).
 *
 * A label is three relations per file (plan 13 §4.2): which AI may read it
 * (the level), where its value may be sent (`bindings`) and which programs
 * may open the real file (`readers:`). The Rules rows read them per file
 * (§4.25p). This module reads the same rules the other way round, per
 * program, per host and per AI, as plan 13 Figure 7 does for its example:
 *
 *   - a program row: only where it differs from any other program (queue
 *     item #52): the files it opens raw (and how each admits it: checked by
 *     Mandu, or the human's word, `prints: nothing`), the ones it never gets
 *     because it prints or runs what it reads, and a masked copy where any
 *     other program is refused; a line counts the rest, which it gets as
 *     "Any other program", the closing row, does;
 *   - a host row: the files whose real value goes there without asking (the
 *     rule's hosts); then "Any other host", which gets no secret;
 *   - an AI row: what any AI reads as written (Not secret), what it may read
 *     when it asks (`any-model`), and what it always sees masked; each AI of
 *     your own (a declared `local: true` model) also reads `local-model`
 *     files when it asks.
 *
 * READ ONLY. It changes nothing: every change stays in the per-file menus.
 * Every string is the product's closed vocabulary (rule-words.ts, §4.25d).
 * It carries paths, program names, hosts and model names, never a value
 * (the fields are copied by name).
 */

import type { PolicyDocumentRow } from "../policy-model.js";
import { MODELS_LINK, toModelEndpointRows, type ModelsPlacePart } from "./model-endpoints.js";
import { judgedAdmitsNothing, judgedReadsTwin, type ArbiterReaderJudgment } from "./reader-runs-code.js";
import { pathReach, tildePath, type OpenerHow } from "./rule-words.js";

type PathRow = PolicyDocumentRow["paths"][number];

/** One opener of a `paths:` row, as the arbiter judges it (plan 13 D8). */
export interface PathOpener {
  /** The program's name as written (`app`). */
  name: string;
  /** An interpreter's pinned script (plan 13 R5): that program is the pair. */
  script: string | null;
  how: OpenerHow;
}

/** Plan 13 §4.2, Openers: a `paths:` row's `readers:` as the arbiter judges
 *  each entry (its per-entry judgment when the snapshot carries one, else
 *  the name rule), or null when the row has no `readers:` list (every
 *  program then gets the masked copy). Shared by the Rules row's "Opens it"
 *  line (policy-panel.ts) and the per-program view below. */
export function pathOpeners(p: PathRow): PathOpener[] | null {
  if (!p.readers) return null;
  const judged: ArbiterReaderJudgment = {
    ...(p.readersAdmitNothing ? { admitNothing: p.readersAdmitNothing } : {}),
    ...(p.readersReadTwin ? { readTwin: p.readersReadTwin } : {}),
    ...(p.readersCopyOf ? { copyOf: p.readersCopyOf } : {}),
  };
  return p.readers.map((r, i) => ({
    name: typeof r === "string" ? r : r.app,
    script: typeof r !== "string" && typeof r.script === "string" && r.script !== "" ? r.script : null,
    how: judgedAdmitsNothing(r, i, judged) ? "never"
      : judgedReadsTwin(r, i, judged) ? "masked"
      : typeof r !== "string" && r.prints === "nothing" ? "word"
      : "checked",
  }));
}

// ── the view-model ────────────────────────────────────────────────────────────

/** One file in a list: its path (`~` for the dashboard's home), how far the
 *  rule reaches when it is more than one file, and a short note. */
export interface ByWhoItem {
  path: string;
  /** The rule's own path as policy.yaml or the page label gives it (no `~`,
   *  no ": KEY"): the page opens that rule's row under Your rules with it
   *  (dashboard.md §4.25aa). */
  rule: string;
  /** "and everything inside" | "every matching file"; null for one file. */
  reach: string | null;
  /** "checked by Mandu" | "your word"; null when there is nothing to add. */
  how: string | null;
}

export interface ByWhoGroup {
  /** What the row's program, host or AI may do with these files. */
  label: string;
  /** "ok" (gets the real file or value), "warn" (when it asks), "bad"
   *  (masked, refused): the colour of the group's mark. */
  tone: "ok" | "warn" | "bad";
  items: ByWhoItem[];
}

export interface ByWhoRow {
  /** The program, host or AI. */
  name: string;
  /** A line under the name, or null. */
  about: string | null;
  /** `about` as parts where it names a place the page links (Settings ›
   *  Models, dashboard.md §4.25aa); absent otherwise. */
  aboutParts?: ModelsPlacePart[];
  /** "any": the closing row of a tab, everything not named above. */
  kind: "named" | "any";
  groups: ByWhoGroup[];
  /** A named program: the line under its lists for the files it gets as
   *  any other program does (`sameAsAny`, or `allAsAny` when that is every
   *  file); null or absent otherwise. */
  rest?: string | null;
}

export interface ByWhoTab {
  rows: ByWhoRow[];
  /** The closing line under the tab's list. */
  note: string;
}

export interface ByWhoVM {
  /** False: the rules could not be read (no protection service, an older
   *  one): the page says so, never "nothing". */
  available: boolean;
  /** True when some rules could not be read (the labels made on the page),
   *  so the lists may miss files. */
  partial: boolean;
  /** How many files and folders the rules make secret (not `public`). */
  secretCount: number;
  programs: ByWhoTab;
  hosts: ByWhoTab;
  models: ByWhoTab;
}

/** One file rule, from policy.yaml or made on the page. */
export interface ByWhoRule {
  path: string;
  level: string;
  bindings: readonly string[];
  recursive: boolean;
  glob: boolean;
  /** A recursive rule whose path is a file on disk (server/path-kinds.ts):
   *  listed as that one file, with no reach (dashboard.md §4.25f *A rule on a
   *  file reads as a file*). */
  isFile?: boolean;
  /** null: no `readers:` list (programs get the masked copy). */
  openers: PathOpener[] | null;
  /** `others:` — "twin" gives a non-opener the masked copy, else refused. */
  others: string | undefined;
  /** Plan 13 §5.2: per-value hosts (`values:`), and where the whole file
   *  may go (the arbiter's intersection; absent ⇒ nowhere). Absent when the
   *  rule has none. */
  values?: ReadonlyArray<{ key: string; bindings: readonly string[] }>;
  wholeBindings?: readonly string[];
}

export const BY_WHO_WORDS = {
  opens: "Opens the real file",
  masked: "Gets a masked copy",
  never: "Never gets the real file: it prints or runs what it reads",
  refused: "Refused",
  sameAsAny: (n: number) => "The rest (" + n + "): as any other program, below.",
  allAsAny: "Everything: as any other program, below.",
  anyProgram: "Any other program",
  anyProgramAbout: "A program no rule names.",
  noProgram: "No rule of yours names a program.",
  programsNote: "Opening a file does not let a program send it: the Hosts list says where it may go.",
  sends: "Gets the real value without asking",
  anyHost: "Any other host",
  otherValue: "any other value",
  anyHostAbout: "No secret goes there without a rule or your OK.",
  notSecretAnywhere: "Not secret, so it may go anywhere",
  hostsNote: "A program that read two secrets may send only where both may go. An answer you gave may let one piece of data go to one more place; your answers are listed under Your rules.",
  asWritten: "Reads it as written",
  whenAsks: "May read it when it asks",
  alwaysMasked: "Always sees it masked",
  anyAI: "Any AI",
  anyAIAbout: "Your agent's AI and Mandu's helper. Your AI provider gets what they read.",
  ownAI: "Your own AI",
  noOwnAIAbout: "None is listed in Settings › Models, so no AI reads these files.",
  modelsNote: "Your OK never lets an AI read a file its rule keeps from it. Each read when it asks is logged.",
} as const;

/** `BY_WHO_WORDS.noOwnAIAbout` as parts, "Settings › Models" the link:
 *  joined, the same words. */
const NO_OWN_AI_ABOUT_PARTS: ModelsPlacePart[] = [
  { kind: "text", text: "None is listed in " },
  MODELS_LINK,
  { kind: "text", text: ", so no AI reads these files." },
];

const SECRET_LEVELS = new Set(["no-model", "local-model", "any-model"]);

/** The rule's level as one of the four; an unknown level reads as
 *  `no-model` (the fail-closed direction, as `levelWords` does). */
function levelOf(level: string): "public" | "any-model" | "local-model" | "no-model" {
  return level === "public" ? "public" : SECRET_LEVELS.has(level) ? (level as "any-model" | "local-model" | "no-model") : "no-model";
}

const byPath = (a: ByWhoItem, b: ByWhoItem) => a.path.localeCompare(b.path);

function group(label: string, tone: ByWhoGroup["tone"], items: ByWhoItem[]): ByWhoGroup[] {
  return items.length ? [{ label, tone, items: [...items].sort(byPath) }] : [];
}

/** The rules of `document.paths` and the labels made on the page (the
 *  confidentiality state's labels whose source is not the policy file), one
 *  per path, policy.yaml first. Copied field by field. `files`: the paths
 *  that are files on disk (server/path-kinds.ts). */
export function byWhoRules(
  paths: ReadonlyArray<PathRow> | null | undefined,
  pageLabels: ReadonlyArray<{ path?: unknown; level?: unknown; bindings?: unknown; recursive?: unknown; glob?: unknown; source?: unknown }> | null | undefined,
  files: ReadonlySet<string> = new Set(),
): ByWhoRule[] {
  const out: ByWhoRule[] = [];
  const seen = new Set<string>();
  for (const p of paths ?? []) {
    if (typeof p?.path !== "string" || seen.has(p.path)) continue;
    seen.add(p.path);
    out.push({
      path: p.path,
      level: String(p.level ?? ""),
      bindings: Array.isArray(p.bindings) ? p.bindings.filter((b): b is string => typeof b === "string" && b !== "") : [],
      recursive: p.recursive === true,
      glob: (p as { glob?: boolean }).glob === true || /[*?[]/.test(p.path),
      ...(files.has(p.path) ? { isFile: true } : {}),
      openers: pathOpeners(p),
      others: p.others,
      ...(Array.isArray(p.values) && p.values.length ? {
        values: p.values.map((v) => ({ key: v.key, bindings: v.bindings.filter((b): b is string => typeof b === "string" && b !== "") })),
        wholeBindings: Array.isArray(p.wholeBindings) ? p.wholeBindings.filter((b): b is string => typeof b === "string" && b !== "") : [],
      } : {}),
    });
  }
  for (const l of pageLabels ?? []) {
    if (!l || typeof l.path !== "string" || l.path === "" || l.source === "policy-file" || seen.has(l.path)) continue;
    seen.add(l.path);
    out.push({
      path: l.path,
      level: typeof l.level === "string" ? l.level : "",
      bindings: Array.isArray(l.bindings) ? l.bindings.filter((b): b is string => typeof b === "string" && b !== "") : [],
      recursive: l.recursive !== false,
      glob: l.glob === true,
      ...(files.has(l.path) ? { isFile: true } : {}),
      openers: null,
      others: undefined,
    });
  }
  return out;
}

/** The per-principal view of `rules`. `models`: policy.yaml `models:` as the
 *  snapshot carries them; `home`: the folder the paths call `~`. */
export function toByWhoVM(
  rules: readonly ByWhoRule[] | null,
  models: unknown,
  opts: { home?: string; partial?: boolean } = {},
): ByWhoVM {
  const home = opts.home ?? "";
  const empty = (note: string): ByWhoTab => ({ rows: [], note });
  if (rules === null) {
    return {
      available: false, partial: false, secretCount: 0,
      programs: empty(BY_WHO_WORDS.programsNote), hosts: empty(BY_WHO_WORDS.hostsNote), models: empty(BY_WHO_WORDS.modelsNote),
    };
  }
  const item = (r: ByWhoRule, how: string | null = null): ByWhoItem => ({
    path: tildePath(r.path, home),
    rule: r.path,
    reach: r.glob || (r.recursive && !r.isFile) ? pathReach({ recursive: r.recursive, glob: r.glob }) : null,
    how,
  });
  const secret = rules.filter((r) => levelOf(r.level) !== "public");
  const open = rules.filter((r) => levelOf(r.level) === "public");

  // ── per program: the readers lists, read by program ──
  // A rule that does not name a program: a masked copy (no list, or
  // `others: twin`), else refused. "Any other program" is named by none.
  const notNamed = (r: ByWhoRule): "masked" | "refused" => (r.openers === null || r.others === "twin" ? "masked" : "refused");
  // A named program lists only what differs from "Any other program", and
  // counts the rest (`rest`): what every row repeats hid what sets it apart.
  const programs = new Map<string, { name: string; about: string | null; opens: ByWhoItem[]; masked: ByWhoItem[]; never: ByWhoItem[]; rest: number }>();
  const rank: Record<OpenerHow, number> = { checked: 0, word: 0, masked: 1, never: 2 };
  for (const r of secret) {
    // One entry per program in a rule: the best of its entries decides.
    const mine = new Map<string, PathOpener>();
    for (const o of r.openers ?? []) {
      const key = o.script ? `${o.name}\0${o.script}` : o.name;
      const had = mine.get(key);
      if (!had || rank[o.how] < rank[had.how]) mine.set(key, o);
      if (!programs.has(key)) {
        programs.set(key, {
          name: o.script ? `${o.name} running ${tildePath(o.script, home)}` : o.name,
          about: null, opens: [], masked: [], never: [], rest: 0,
        });
      }
    }
    for (const [key, o] of mine) {
      const p = programs.get(key)!;
      if (o.how === "checked" || o.how === "word") p.opens.push(item(r, o.how === "checked" ? "checked by Mandu" : "your word"));
      else if (o.how === "masked") {
        if (notNamed(r) === "masked") p.rest++;
        else p.masked.push(item(r));
      } else p.never.push(item(r));
    }
  }
  for (const [key, p] of programs) {
    for (const r of secret) {
      const named = (r.openers ?? []).some((o) => (o.script ? `${o.name}\0${o.script}` : o.name) === key);
      if (!named) p.rest++;
    }
  }
  const programRows: ByWhoRow[] = [...programs.values()]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((p) => {
      const groups = [
        ...group(BY_WHO_WORDS.opens, "ok", p.opens),
        ...group(BY_WHO_WORDS.masked, "bad", p.masked),
        ...group(BY_WHO_WORDS.never, "bad", p.never),
      ];
      return {
        name: p.name, about: p.about, kind: "named" as const, groups,
        rest: !groups.length ? BY_WHO_WORDS.allAsAny : p.rest ? BY_WHO_WORDS.sameAsAny(p.rest) : null,
      };
    });
  if (secret.length) {
    programRows.push({
      name: BY_WHO_WORDS.anyProgram,
      about: programs.size ? BY_WHO_WORDS.anyProgramAbout : BY_WHO_WORDS.noProgram,
      kind: "any",
      groups: [
        ...group(BY_WHO_WORDS.masked, "bad", secret.filter((r) => notNamed(r) === "masked").map((r) => item(r))),
        ...group(BY_WHO_WORDS.refused, "bad", secret.filter((r) => notNamed(r) === "refused").map((r) => item(r))),
      ],
    });
  }

  // ── per host: the rules' hosts, read by host ──
  // Plan 13 §5.2: a rule with `values:` sends each value to its own hosts.
  // A host the whole file may go to (every value and the file allow it)
  // names the file; any other host names the values that go there ("~/.env:
  // STRIPE_KEY"), and a host of the file's own only "any other value", the
  // values with no entry.
  const hosts = new Map<string, ByWhoItem[]>();
  const add = (h: string, it: ByWhoItem): void => {
    if (!hosts.has(h)) hosts.set(h, []);
    hosts.get(h)!.push(it);
  };
  for (const r of secret) {
    if (!r.values || r.values.length === 0) {
      for (const h of new Set(r.bindings)) add(h, item(r));
      continue;
    }
    const whole = new Set(r.wholeBindings ?? []);
    for (const h of whole) add(h, item(r));
    const part = (label: string): ByWhoItem => ({ ...item(r), path: `${tildePath(r.path, home)}: ${label}` });
    for (const v of r.values) for (const h of new Set(v.bindings)) if (!whole.has(h)) add(h, part(v.key));
    for (const h of new Set(r.bindings)) if (!whole.has(h)) add(h, part(BY_WHO_WORDS.otherValue));
  }
  const hostRows: ByWhoRow[] = [...hosts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([h, items]) => ({ name: h, about: null, kind: "named" as const, groups: group(BY_WHO_WORDS.sends, "ok", items) }));
  if (rules.length) {
    hostRows.push({
      name: BY_WHO_WORDS.anyHost,
      about: secret.length ? BY_WHO_WORDS.anyHostAbout : null,
      kind: "any",
      groups: group(BY_WHO_WORDS.notSecretAnywhere, "ok", open.map((r) => item(r))),
    });
  }

  // ── per AI: the levels, read by AI ──
  const asWritten = open.map((r) => item(r));
  const whenAsks = secret.filter((r) => levelOf(r.level) === "any-model").map((r) => item(r));
  const ownOnly = secret.filter((r) => levelOf(r.level) === "local-model").map((r) => item(r));
  const noAI = secret.filter((r) => levelOf(r.level) === "no-model").map((r) => item(r));
  const modelRows: ByWhoRow[] = [];
  if (rules.length) {
    modelRows.push({
      name: BY_WHO_WORDS.anyAI, about: BY_WHO_WORDS.anyAIAbout, kind: "named",
      groups: [
        ...group(BY_WHO_WORDS.asWritten, "ok", asWritten),
        ...group(BY_WHO_WORDS.whenAsks, "warn", whenAsks),
        ...group(BY_WHO_WORDS.alwaysMasked, "bad", [...ownOnly, ...noAI]),
      ],
    });
    const own = toModelEndpointRows(models).filter((m) => m.local);
    for (const m of own) {
      modelRows.push({
        name: m.name,
        about: [BY_WHO_WORDS.ownAI, m.placementWords ? m.placementWords.toLowerCase() : null].filter(Boolean).join(", ") + ".",
        kind: "named",
        groups: [
          ...group(BY_WHO_WORDS.asWritten, "ok", asWritten),
          ...group(BY_WHO_WORDS.whenAsks, "warn", [...whenAsks, ...ownOnly]),
          ...group(BY_WHO_WORDS.alwaysMasked, "bad", noAI),
        ],
      });
    }
    if (!own.length && ownOnly.length) {
      modelRows.push({
        name: BY_WHO_WORDS.ownAI, about: BY_WHO_WORDS.noOwnAIAbout, aboutParts: NO_OWN_AI_ABOUT_PARTS, kind: "named",
        groups: group(BY_WHO_WORDS.alwaysMasked, "bad", ownOnly),
      });
    }
  }

  return {
    available: true,
    partial: opts.partial === true,
    secretCount: secret.length,
    programs: { rows: programRows, note: BY_WHO_WORDS.programsNote },
    hosts: { rows: hostRows, note: BY_WHO_WORDS.hostsNote },
    models: { rows: modelRows, note: BY_WHO_WORDS.modelsNote },
  };
}
