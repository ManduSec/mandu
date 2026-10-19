/**
 * confidentiality — the second label axis (docs/design/confidentiality/confidentiality.md §2).
 *
 * Total order: public ⊑ any-model ⊑ no-model — each level's
 * restriction set strictly contains the previous one's (strict restricts
 * {model, outside}; model-ok restricts {outside}; public restricts nothing).
 * Values are strings in the DB so later levels/compartments extend without
 * another schema change (§13.5). The symbol-table row is authoritative; the
 * wire-name marker (symbol-format.ts) is presentation only.
 *
 * Mandu-new (no reference origin): the ADFI reference implementation is
 * integrity-only; this module is the confidentiality dual designed in
 * docs/design/confidentiality/confidentiality.md.
 */

/**
 * The confidentiality levels, named by which models may read the content
 * (confidentiality.md). A total order; each level's
 * restriction set strictly contains the previous one's:
 *
 *   public ⊑ any-model ⊑ local-model ⊑ no-model
 *
 * `local-model` (plan 11 D1) may be read only by a model the operator
 * declared `local: true` in policy.yaml `models:`; with none declared it
 * behaves exactly as `no-model` at every model.
 */
export type ConfidentialityLevel = "public" | "any-model" | "local-model" | "no-model";

export const CONFIDENTIALITY_LEVELS: readonly ConfidentialityLevel[] = [
  "public",
  "any-model",
  "local-model",
  "no-model",
];

const RANK: Record<ConfidentialityLevel, number> = {
  "public": 0,
  "any-model": 1,
  "local-model": 2,
  "no-model": 3,
};

/** Where a model endpoint runs (plan 11 D2): `local` only when the operator
 *  declared it `local: true`; everything else, including every undeclared
 *  endpoint, is `external`. Never inferred from an address. */
export type ModelLocation = "local" | "external";

/**
 * May a model at `location` read a datum at `level`? (plan 11 D4). The one
 * admission rule for every model-bound read: the quarantined helper's deep
 * resolve, the nested expansion inside it, and (from phase 3) rung 3.
 *
 *   public, any-model → any model
 *   local-model       → only a declared local model
 *   no-model          → no model, ever
 */
export function admits(location: ModelLocation, level: ConfidentialityLevel): boolean {
  switch (level) {
    case "public":
    case "any-model":
      return true;
    case "local-model":
      return location === "local";
    case "no-model":
      return false;
  }
}

/** The numeric rank of a level (public 0 … no-model 3), for the few callers
 *  that order levels outside {@link maxConfidentiality}. */
export function confidentialityRank(level: ConfidentialityLevel): number {
  return RANK[level];
}

export function isConfidentialityLevel(v: unknown): v is ConfidentialityLevel {
  return typeof v === "string" &&
    (CONFIDENTIALITY_LEVELS as readonly string[]).includes(v);
}

/**
 * Parse a stored or wire value. null/undefined/"" → "public": a row minted
 * before the axis existed carries no confidentiality claim (the DB column
 * default). Any UNRECOGNIZED value → "no-model": fail-closed (§2 —
 * nothing ever defaults to any-model or local-model) and forward-compatible —
 * a level minted by a newer build must never degrade to public in an older one.
 */
export function parseConfidentialityLevel(v: unknown): ConfidentialityLevel {
  if (v === null || v === undefined || v === "") return "public";
  if (isConfidentialityLevel(v)) return v;
  return "no-model";
}

export function maxConfidentiality(
  ...levels: ConfidentialityLevel[]
): ConfidentialityLevel {
  let out: ConfidentialityLevel = "public";
  for (const l of levels) if (RANK[l] > RANK[out]) out = l;
  return out;
}

export function isSecret(level: ConfidentialityLevel): boolean {
  return RANK[level] > 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// The integrity half of the 2×3 label (§2). Stored per symbol from Plan 3 on:
// once the proxies symbolize TRUSTED×secret data, row-presence no longer
// implies untrusted-integrity, so the axis must be explicit.
// ─────────────────────────────────────────────────────────────────────────────

export type IntegrityLabel = "trusted" | "untrusted";

/**
 * Parse a stored or wire integrity value. ONLY the exact string "trusted"
 * counts — absent (legacy rows, whose column default is 'untrusted'),
 * unknown, or junk all parse to "untrusted" (fail-closed: integrity trust is
 * never granted by accident).
 */
export function parseIntegrityLabel(v: unknown): IntegrityLabel {
  return v === "trusted" ? "trusted" : "untrusted";
}
