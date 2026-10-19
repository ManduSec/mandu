/**
 * policy-level-spelling — line scans over policy.yaml for `mandu doctor`.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 *
 * The launcher never parses YAML, so these are line scans: they find `level:`
 * keys in both block and flow style (every shape the validator accepts) and a
 * top-level `models:` key. Used for the confidentiality-plan-11 D6 doctor row
 * (a `local-model` label with no local model declared is read by no model),
 * and for the §8 item 3 row (a `local: true` entry naming a cloud-backed
 * model, which the arbiter refuses to load; doctor may be reading a file the
 * arbiter has not loaded, or one it refused and kept the old law over).
 * The level names retired on 2026-09-27 are not scanned for: the arbiter
 * refuses to start on one and its error names the entry
 * (confidentiality.md).
 *
 * Pure: no filesystem access; the caller passes the file text.
 */
import { manduPath } from "./generated/mandu-paths.js";
import { isCloudBackedModel } from "./model-endpoints.js";

/** The policy file the arbiter reads: MANDU_POLICY_FILE, else the path
 *  table's `policy` ($MANDU_HOME/policy.yaml, else ~/.mandu/policy.yaml;
 *  on-disk-layout.md §5). null when neither MANDU_HOME nor HOME is set. */
export function policyFilePath(env: Record<string, string | undefined>): string | null {
  if (env["MANDU_POLICY_FILE"]) return env["MANDU_POLICY_FILE"]!;
  if (!env["MANDU_HOME"] && !env["HOME"]) return null;
  return manduPath("policy", env, env["HOME"] ?? "");
}

const LOCAL_MODEL_RE = /\blevel\s*:\s*["']?local-model["']?(?=[\s,}#]|$)/;

/** The 1-based lines whose `level:` is `local-model` (confidentiality-plan-11
 *  D6: with no `models:` section, such files are read by no model, and
 *  `mandu doctor` says so). A line scan (comments are skipped). */
export function localModelLevelLines(text: string): number[] {
  const out: number[] = [];
  text.split("\n").forEach((raw, i) => {
    const code = raw.replace(/(^|\s)#.*$/, "$1");
    if (LOCAL_MODEL_RE.test(code)) out.push(i + 1);
  });
  return out;
}

/** Does the file have a top-level `models:` key? A line scan (a top-level key
 *  starts in column 0), used only when the arbiter cannot answer the
 *  `modelEndpoints` op itself. */
export function hasModelsSection(text: string): boolean {
  // `models:` with a block below, or an inline non-empty flow list, counts;
  // an inline empty value (`[]`, `null`, `~`) declares nothing.
  return text.split("\n").some((l) => {
    const m = /^models\s*:(.*)$/.exec(l.replace(/(^|\s)#.*$/, "$1"));
    if (!m) return false;
    const v = m[1]!.trim();
    return v === "" || !/^(\[\s*\]|null|~)$/.test(v);
  });
}

/** One `models:` entry the line scan found declaring a cloud-backed model
 *  `local: true` (plan 11 §8 item 3). */
export interface CloudLocalEntry {
  /** 1-based line of the entry's `model:` key. */
  line: number;
  name: string | null;
  model: string;
}

const SCALAR = (key: string): RegExp => new RegExp(`(?:^|[\\s{,])${key}\\s*:\\s*(?:"([^"]*)"|'([^']*)'|([^\\s,}#]+))`);
const MODEL_KEY_RE = SCALAR("model");
const NAME_KEY_RE = SCALAR("name");
const LOCAL_TRUE_RE = /(?:^|[\s{,])local\s*:\s*(?:true|True|TRUE)(?=[\s,}]|$)/;

function scalar(re: RegExp, text: string): string | null {
  const m = re.exec(text);
  return m ? (m[1] ?? m[2] ?? m[3] ?? null) : null;
}

/**
 * The `models:` entries that say `local: true` and name a cloud-backed model
 * ({@link isCloudBackedModel}). A line scan over the top-level `models:`
 * section in block style (`- name: …` items, one key per line, the list at
 * the key's column or indented) or flow style on the key's line
 * (`models: [{ name: a, model: b, local: true }]`). Comments are skipped. It
 * reports only what it can see; the arbiter's validator is the authority.
 */
export function cloudLocalModelEntries(text: string): CloudLocalEntry[] {
  const lines = text.split("\n").map((raw) => raw.replace(/(^|\s)#.*$/, "$1"));
  const out: CloudLocalEntry[] = [];
  const consider = (entryText: string, line: number): void => {
    const model = scalar(MODEL_KEY_RE, entryText);
    if (model === null || !LOCAL_TRUE_RE.test(entryText) || !isCloudBackedModel(model)) return;
    out.push({ line, name: scalar(NAME_KEY_RE, entryText), model });
  };
  const start = lines.findIndex((l) => /^models\s*:/.test(l));
  if (start < 0) return out;
  const inline = lines[start]!.replace(/^models\s*:/, "").trim();
  if (inline !== "") {
    for (const m of inline.matchAll(/\{[^}]*\}/g)) consider(m[0], start + 1);
    return out;
  }
  let entry: { text: string; modelLine: number } | null = null;
  const flush = (): void => { if (entry) consider(entry.text, entry.modelLine); entry = null; };
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.trim() === "") continue;
    if (/^\S/.test(l) && !/^-(\s|$)/.test(l)) break; // the next top-level key
    if (/^\s*-(\s|$)/.test(l)) { flush(); entry = { text: "", modelLine: i + 1 }; }
    if (entry === null) continue;
    entry.text += `${l}\n`;
    if (MODEL_KEY_RE.test(l)) entry.modelLine = i + 1;
  }
  flush();
  return out;
}
