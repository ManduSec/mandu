/**
 * prompt-pattern-redact — the policy reads the DATA socket answers, with every
 * prompt exception's pattern taken out (confidentiality-plan-15-prompt-filter.md
 * §13.7 item 4; arbiter-human-plane.md §3). Mandu-new (no reference origin).
 *
 * An exception's `match` (`*@example.com`, or the person's own words) names
 * what the prompt filter lets through as written. Enforcement needs none of
 * it outside the arbiter (the engine matches the exceptions itself), so the
 * data socket's `policyDocument`, `policyProposals` and `policyChanges` answer
 * with each pattern replaced by {@link PROMPT_PATTERN_PLACEHOLDER} and a flag
 * (`patternHidden: true`) beside it; the human socket and the admin channel
 * answer in full. Everything else in the answer is kept as it was: the
 * policy file's text is changed only inside the `match:` values of its
 * `prompt_filters:` block, and the change is proven by parsing the result
 * back (the parse must equal the redacted parse of the original), else the
 * text is rebuilt from that redacted parse.
 *
 * WRITES. The placeholder is refused as a pattern by the policy validator
 * (prompt-filter/policy.ts), and `patternHidden` is not a key an exception
 * may carry, so a document or an edit built from a data-socket read can never
 * overwrite a stored pattern with the placeholder: it is refused whole.
 *
 * Pure: inputs are not changed.
 */
import yaml from "js-yaml";

import { PROMPT_PATTERN_PLACEHOLDER } from "../prompt-filter/policy.js";

export { PROMPT_PATTERN_PLACEHOLDER };

const EXCEPTION_OPS = new Set(["add-prompt-exception", "remove-prompt-exception"]);

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** The patterns a `prompt_filters:` mapping holds (its `exceptions[].match`). */
function patternsOf(pf: unknown): string[] {
  if (!isObj(pf) || !Array.isArray(pf.exceptions)) return [];
  return pf.exceptions.filter(isObj).map((e) => e.match).filter((m): m is string => typeof m === "string" && m !== "");
}

/** Every pattern a policy document holds. */
export function documentPatterns(doc: unknown): string[] {
  return isObj(doc) ? patternsOf(doc.prompt_filters) : [];
}

/** A `prompt_filters:` mapping with each exception's pattern hidden. */
function redactPromptFilters(pf: unknown): unknown {
  if (!isObj(pf) || !Array.isArray(pf.exceptions)) return pf;
  return {
    ...pf,
    exceptions: pf.exceptions.map((e) => (isObj(e) && "match" in e ? { ...e, match: PROMPT_PATTERN_PLACEHOLDER, patternHidden: true } : e)),
  };
}

/** A policy document with each exception's pattern hidden (other keys, and
 *  their order, as they were). */
export function redactPolicyDocument(doc: unknown): unknown {
  if (!isObj(doc) || !("prompt_filters" in doc)) return doc;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(doc)) out[k] = k === "prompt_filters" ? redactPromptFilters(v) : v;
  return out;
}

/** A typed edit with its pattern hidden (only the exception edits carry one). */
export function redactEdit(edit: unknown): unknown {
  if (!isObj(edit) || !EXCEPTION_OPS.has(String(edit.op)) || !("match" in edit)) return edit;
  return { ...edit, match: PROMPT_PATTERN_PLACEHOLDER, patternHidden: true };
}

const EXCEPTION_DETAIL = /^findings of (\S+) matching .* are (no longer )?let through$/s;

/** A delta line (policy-delta.ts, prompt-filter/policy.ts comparePromptFilters):
 *  an exception's line names its pattern in `detail`. */
export function redactDelta<T extends { subject: string; detail: string }>(d: T): T & { patternHidden?: true } {
  if (typeof d?.subject !== "string" || !d.subject.startsWith("prompt exception ")) return d;
  const m = EXCEPTION_DETAIL.exec(String(d.detail));
  const detail = m ? `findings of ${m[1]} matching ${PROMPT_PATTERN_PLACEHOLDER} are ${m[2] ?? ""}let through` : PROMPT_PATTERN_PLACEHOLDER;
  return { ...d, detail, patternHidden: true };
}

/** Every occurrence of a known pattern in a message (a problem, a warning, a
 *  conflict) replaced. Longest first, so a pattern inside another goes too. */
export function redactMessage(s: string, patterns: readonly string[]): string {
  let out = s;
  for (const p of [...new Set(patterns)].sort((a, b) => b.length - a.length)) out = out.split(p).join(PROMPT_PATTERN_PLACEHOLDER);
  return out;
}

// ── the policy file's text ──────────────────────────────────────────────────

/** A YAML scalar at the start of `s`: '…' ('' escapes), "…" (\ escapes), or
 *  plain (up to a flow indicator, a comment or the line's end). Its length. */
function scalarLength(s: string, flow: boolean): number {
  if (s.startsWith("'")) {
    for (let i = 1; i < s.length; i++) {
      if (s[i] === "'") { if (s[i + 1] === "'") { i++; continue; } return i + 1; }
      if (s[i] === "\n") return -1;
    }
    return -1;
  }
  if (s.startsWith('"')) {
    for (let i = 1; i < s.length; i++) {
      if (s[i] === "\\") { i++; continue; }
      if (s[i] === '"') return i + 1;
      if (s[i] === "\n") return -1;
    }
    return -1;
  }
  const stop = flow ? /[,}\]\n]|\s#/ : /\n|\s#/;
  const m = stop.exec(s);
  const end = m ? m.index : s.length;
  return end - trailingSpace(s.slice(0, end));
}

/** Where a line's comment starts (a `#` at the start or after a space,
 *  outside quotes), or -1. */
function commentStart(line: string): number {
  let q: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (q) {
      if (q === '"' && ch === "\\") { i++; continue; }
      if (ch === q) q = null;
      continue;
    }
    if (ch === "'" || ch === '"') { q = ch; continue; }
    if (ch === "#" && (i === 0 || /\s/.test(line[i - 1]!))) return i;
  }
  return -1;
}

/** Each comment with every known pattern replaced (a note beside an
 *  exception may repeat it). */
function redactComments(text: string, known: readonly string[]): string {
  if (known.length === 0) return text;
  return text.split("\n").map((line) => {
    const at = commentStart(line);
    return at < 0 ? line : line.slice(0, at) + redactMessage(line.slice(at), known);
  }).join("\n");
}

function trailingSpace(s: string): number {
  return s.length - s.trimEnd().length;
}

/** The `match:` values of the `prompt_filters:` block replaced in place. */
function replaceMatchValues(text: string): string {
  const lines = text.split("\n");
  let inBlock = false;
  const out: string[] = [];
  for (const line of lines) {
    if (/^\S/.test(line) && !line.startsWith("#")) inBlock = /^prompt_filters\s*:/.test(line);
    if (!inBlock) { out.push(line); continue; }
    let rewritten = "";
    let rest = line;
    for (;;) {
      const m = /(^|[\s{,-])match\s*:\s+/.exec(rest);
      if (!m) { rewritten += rest; break; }
      const valueAt = m.index + m[0].length;
      // In flow context when an unclosed `{` precedes the key on this line.
      const before = rest.slice(0, valueAt);
      const depth = (before.match(/{/g) ?? []).length - (before.match(/}/g) ?? []).length;
      const len = scalarLength(rest.slice(valueAt), depth > 0);
      if (len <= 0) { rewritten += rest; break; }
      rewritten += rest.slice(0, valueAt) + `'${PROMPT_PATTERN_PLACEHOLDER}'`;
      rest = rest.slice(valueAt + len);
    }
    out.push(rewritten);
  }
  return out.join("\n");
}

const canonical = (v: unknown): string => JSON.stringify(v, (_k, x) => (isObj(x) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => a.localeCompare(b))) : x));

/** The parse a redacted text must give: the original's, with each pattern the
 *  placeholder (no flag: the text carries none). */
function expectedParse(parsed: unknown): unknown {
  if (!isObj(parsed) || !isObj(parsed.prompt_filters) || !Array.isArray(parsed.prompt_filters.exceptions)) return parsed;
  return {
    ...parsed,
    prompt_filters: {
      ...parsed.prompt_filters,
      exceptions: parsed.prompt_filters.exceptions.map((e) => (isObj(e) && "match" in e ? { ...e, match: PROMPT_PATTERN_PLACEHOLDER } : e)),
    },
  };
}

/**
 * The policy file's text with each exception's pattern replaced, byte for
 * byte elsewhere. Proven: the redacted text must parse to the original's
 * parse with the placeholder in each `match`; a text that does not (an
 * alias, a multi-line scalar, a layout this scan does not follow) is
 * rebuilt from that parse instead (`rebuilt: true`: comments and layout
 * lost, no pattern kept). A text that does not parse at all is answered with
 * the scan alone and every known pattern replaced.
 */
export function redactPolicyText(text: string, parsed: unknown, known: readonly string[]): { text: string; rebuilt: boolean } {
  if (documentPatterns(parsed).length === 0 && !/^prompt_filters\s*:/m.test(text)) return { text, rebuilt: false };
  const scanned = redactComments(replaceMatchValues(text), known);
  if (parsed === null || parsed === undefined || !isObj(parsed)) {
    return { text: redactMessage(scanned, known), rebuilt: false };
  }
  const want = expectedParse(parsed);
  let got: unknown;
  try { got = yaml.load(scanned); } catch { got = Symbol("unparseable"); }
  if (typeof got !== "symbol" && canonical(got) === canonical(want)) return { text: scanned, rebuilt: false };
  return { text: yaml.dump(want, { lineWidth: -1, noRefs: true }), rebuilt: true };
}

// ── the three reads ─────────────────────────────────────────────────────────

/** The admin layer's view (admin-layer.ts adminLayerView) with its prompt
 *  filters' patterns hidden. */
function redactAdminView(admin: unknown, known: readonly string[]): unknown {
  if (!isObj(admin)) return admin;
  return {
    ...admin,
    ...(Array.isArray(admin.promptFilters)
      ? { promptFilters: admin.promptFilters.map((p) => (isObj(p) ? { ...p, config: redactPromptFilters(p.config) } : p)) }
      : {}),
    ...(Array.isArray(admin.conflicts) ? { conflicts: admin.conflicts.map((s) => (typeof s === "string" ? redactMessage(s, known) : s)) } : {}),
    ...(Array.isArray(admin.refused) ? { refused: admin.refused.map((s) => (typeof s === "string" ? redactMessage(s, known) : s)) } : {}),
  };
}

/** `policyDocument` as the data socket answers it. `adminPatterns`: the
 *  administrator's layer's patterns (they may appear in its messages). */
export function redactPolicyDocumentResult<T extends Record<string, unknown>>(r: T, adminPatterns: readonly string[] = []): T & { patternsHidden?: true } {
  const onDisk = isObj(r.onDisk) ? r.onDisk : null;
  const known = [...documentPatterns(r.inForce), ...documentPatterns(onDisk?.parsed), ...adminPatterns];
  const msgs = (v: unknown): unknown => (Array.isArray(v) ? v.map((s) => (typeof s === "string" ? redactMessage(s, known) : s)) : v);
  const out: Record<string, unknown> = { ...r };
  if (isObj(r.status)) out.status = { ...r.status, problems: msgs(r.status.problems) };
  out.inForce = redactPolicyDocument(r.inForce);
  if (onDisk) {
    const text = typeof onDisk.text === "string" ? redactPolicyText(onDisk.text, onDisk.parsed, known) : null;
    out.onDisk = {
      ...onDisk,
      text: text ? text.text : onDisk.text,
      parsed: redactPolicyDocument(onDisk.parsed),
      problems: msgs(onDisk.problems),
      warnings: msgs(onDisk.warnings),
      ...(text?.rebuilt ? { textRebuilt: true } : {}),
    };
  }
  if ("admin" in r) out.admin = redactAdminView(r.admin, known);
  if (known.length > 0) out.patternsHidden = true;
  return out as T;
}

/** A proposal row (PolicyProposalWire) as the data socket answers it. */
export function redactProposal<T extends { edits: unknown[]; relaxes: Array<{ subject: string; detail: string }>; tightens: Array<{ subject: string; detail: string }> }>(p: T): T {
  return { ...p, edits: p.edits.map(redactEdit), relaxes: p.relaxes.map(redactDelta), tightens: p.tightens.map(redactDelta) };
}

/** A change row (PolicyChangeWire) as the data socket answers it. */
export function redactChange<T extends { edits: unknown[]; delta: Array<{ subject: string; detail: string }> }>(c: T): T {
  return { ...c, edits: c.edits.map(redactEdit), delta: c.delta.map(redactDelta) };
}
