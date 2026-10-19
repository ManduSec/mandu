/**
 * symbol-formats — Composable symbol format factory for Mandu eval.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted verbatim from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/symbol-formats.ts
 *   Purpose: decomposes the symbol format into Content/Separator/Wrapper
 *   dimensions and composes them into a SymbolFormat (used by the format-
 *   robustness evaluation). No OpenClaw coupling.
 *   Adaptation for Mandu M0: only the local import path changed
 *   (./adfi-symbol-format.js → ./symbol-format.js). Logic is unchanged.
 *
 * Decomposes symbol format into three orthogonal dimensions:
 *   Content  — what information is encoded (prefix, tool, hash, field)
 *   Separator — how parts connect (underscore, dot, colon, dash, camelCase)
 *   Wrapper  — delimiter around the token (double-brace, angle-tag, etc.)
 *
 * composeFormat(content, separator, wrapper) → SymbolFormat
 */

import type { SymbolFormat } from "./symbol-format.js";

// ─────────────────────────────────────────────────────────────────────────────
// Dimension types
// ─────────────────────────────────────────────────────────────────────────────

export interface ContentScheme {
  id: string;   // C1–C4
  name: string;
  /** Return raw parts array (before joining). */
  parts(opts: { prefix: string; tool: string; hash: string; field?: string }): string[];
  /** Does this scheme include a field component? */
  hasField: boolean;
  /** Does this scheme include a tool component? */
  hasTool: boolean;
}

export interface SeparatorScheme {
  id: string;   // S1–S5
  name: string;
  /** Join an array of raw parts into a single token body. */
  join(parts: string[]): string;
  /** Regex character class or pattern fragment matching the separator between parts. */
  separatorPattern: string;
  /**
   * For camelCase: transform a part to its joined form.
   * For others this is identity.
   */
  transformPart?(part: string): string;
}

export interface WrapperScheme {
  id: string;   // W1–W6
  name: string;
  /** Wrap a joined token body. Field is passed separately for W1 (dollar_bracket). */
  wrap(body: string, field?: string): string;
  /** Build a regex pattern string that matches a wrapped token. `bodyPattern` matches the inner body. */
  wrapPattern(bodyPattern: string, fieldPattern?: string): string;
  /** Extract the body (and optionally field) from a full symbol string. */
  unwrap(symbol: string): { body: string; field: string };
}

// ─────────────────────────────────────────────────────────────────────────────
// Content schemes
// ─────────────────────────────────────────────────────────────────────────────

const PREFIX = "SYM";

export const C1_FULL: ContentScheme = {
  id: "C1", name: "full", hasField: true, hasTool: true,
  parts({ tool, hash, field }) {
    const p = [PREFIX, tool, hash];
    if (field) p.push(field);
    return p;
  },
};

export const C2_NO_TOOL: ContentScheme = {
  id: "C2", name: "no_tool", hasField: true, hasTool: false,
  parts({ hash, field }) {
    const p = [PREFIX, hash];
    if (field) p.push(field);
    return p;
  },
};

export const C3_MINIMAL: ContentScheme = {
  id: "C3", name: "minimal", hasField: false, hasTool: false,
  parts({ hash }) {
    return [PREFIX, hash];
  },
};

export const C4_HASH_ONLY: ContentScheme = {
  id: "C4", name: "hash_only", hasField: false, hasTool: false,
  parts({ hash }) {
    return [hash];
  },
};

export const CONTENT_SCHEMES = [C1_FULL, C2_NO_TOOL, C3_MINIMAL, C4_HASH_ONLY];

// ─────────────────────────────────────────────────────────────────────────────
// Separator schemes
// ─────────────────────────────────────────────────────────────────────────────

export const S1_UNDERSCORE: SeparatorScheme = {
  id: "S1", name: "underscore",
  join(parts) { return parts.join("_"); },
  separatorPattern: "_",
};

export const S2_DOT: SeparatorScheme = {
  id: "S2", name: "dot",
  join(parts) { return parts.join("."); },
  separatorPattern: "\\.",
};

export const S3_COLON: SeparatorScheme = {
  id: "S3", name: "colon",
  join(parts) { return parts.join(":"); },
  separatorPattern: ":",
};

export const S4_DASH: SeparatorScheme = {
  id: "S4", name: "dash",
  join(parts) { return parts.join("-"); },
  separatorPattern: "-",
};

function toCamelPart(s: string): string {
  // "web_fetch" → "WebFetch", "a1b2" → "A1b2"
  return s.replace(/(^|_)([a-zA-Z0-9])/g, (_m, _sep, ch) => ch.toUpperCase());
}

export const S5_CAMEL: SeparatorScheme = {
  id: "S5", name: "camel",
  join(parts) { return parts.map(toCamelPart).join(""); },
  separatorPattern: "", // no explicit separator — boundary is case transition
  transformPart: toCamelPart,
};

export const SEPARATOR_SCHEMES = [S1_UNDERSCORE, S2_DOT, S3_COLON, S4_DASH, S5_CAMEL];

// ─────────────────────────────────────────────────────────────────────────────
// Wrapper schemes
// ─────────────────────────────────────────────────────────────────────────────

export const W1_DOLLAR_BRACKET: WrapperScheme = {
  id: "W1", name: "dollar_bracket",
  wrap(body, field) { return field ? `$${body}[${field}]` : `$${body}`; },
  // Intentionally does not include field; field pattern is separate via extractFieldPath
  wrapPattern(bp, fp) { return `\\$${bp}(?:\\[${fp ?? "[a-zA-Z_][a-zA-Z0-9_.]*"}\\])?`; },
  unwrap(sym) {
    const m = sym.match(/^\$(.+?)(?:\[(.+)\])?$/);
    return { body: m?.[1] ?? sym, field: m?.[2] ?? "" };
  },
};

export const W2_DBLBRACE: WrapperScheme = {
  id: "W2", name: "dblbrace",
  wrap(body, field) { return field ? `{{${body}_${field}}}` : `{{${body}}}`; },
  wrapPattern(bp) { return `\\{\\{${bp}\\}\\}`; },
  unwrap(sym) {
    const m = sym.match(/^\{\{(.+)\}\}$/);
    return { body: m?.[1] ?? sym, field: "" };
  },
};

export const W3_ANGLE_TAG: WrapperScheme = {
  id: "W3", name: "angle_tag",
  wrap(body, field) { return field ? `<${body}_${field}/>` : `<${body}/>`; },
  wrapPattern(bp) { return `<${bp}/>`; },
  unwrap(sym) {
    const m = sym.match(/^<(.+)\/>$/);
    return { body: m?.[1] ?? sym, field: "" };
  },
};

export const W4_BRACKET: WrapperScheme = {
  id: "W4", name: "bracket",
  wrap(body, field) { return field ? `[${body}_${field}]` : `[${body}]`; },
  wrapPattern(bp) { return `\\[${bp}\\]`; },
  unwrap(sym) {
    const m = sym.match(/^\[(.+)\]$/);
    return { body: m?.[1] ?? sym, field: "" };
  },
};

export const W5_BARE: WrapperScheme = {
  id: "W5", name: "bare",
  wrap(body, field) { return field ? `${body}_${field}` : body; },
  wrapPattern(bp) { return bp; },
  unwrap(sym) { return { body: sym, field: "" }; },
};

export const W6_BACKTICK: WrapperScheme = {
  id: "W6", name: "backtick",
  wrap(body, field) { return field ? `\`${body}_${field}\`` : `\`${body}\``; },
  wrapPattern(bp) { return `\`${bp}\``; },
  unwrap(sym) {
    const m = sym.match(/^`(.+)`$/);
    return { body: m?.[1] ?? sym, field: "" };
  },
};

export const WRAPPER_SCHEMES = [W1_DOLLAR_BRACKET, W2_DBLBRACE, W3_ANGLE_TAG, W4_BRACKET, W5_BARE, W6_BACKTICK];

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

/** Escape a string for use inside a regex. */
function escRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Build a body regex pattern for the given content + separator combination.
 * This matches the inner token (before wrapping).
 */
function buildBodyPattern(content: ContentScheme, sep: SeparatorScheme): string {
  const hashPat = "[0-9a-f]{4,8}";
  const toolPat = "[a-zA-Z_][a-zA-Z0-9_]*";
  const fieldPat = "[a-zA-Z_][a-zA-Z0-9_.]*";

  if (sep.id === "S5") {
    // camelCase: no separator chars, parts run together with case boundaries
    // We match the known prefix + variable-length identifier chars
    switch (content.id) {
      case "C1": return `${escRe(toCamelPart(PREFIX))}${toolPat}${hashPat}(?:${fieldPat})?`;
      case "C2": return `${escRe(toCamelPart(PREFIX))}${hashPat}(?:${fieldPat})?`;
      case "C3": return `${escRe(toCamelPart(PREFIX))}${hashPat}`;
      case "C4": return hashPat;
    }
  }

  const s = sep.separatorPattern;
  switch (content.id) {
    case "C1": return `${escRe(PREFIX)}${s}${toolPat}${s}${hashPat}(?:${s}${fieldPat})?`;
    case "C2": return `${escRe(PREFIX)}${s}${hashPat}(?:${s}${fieldPat})?`;
    case "C3": return `${escRe(PREFIX)}${s}${hashPat}`;
    case "C4": return hashPat;
    default:   return `${escRe(PREFIX)}${s}${hashPat}`;
  }
}

/**
 * Compose a SymbolFormat from content, separator, and wrapper schemes.
 */
export function composeFormat(
  content: ContentScheme,
  separator: SeparatorScheme,
  wrapper: WrapperScheme,
): SymbolFormat {
  const formatName = `${content.id}_${separator.id}_${wrapper.id}`;

  // Build the full-symbol regex
  const bodyPat = buildBodyPattern(content, separator);
  const fullPattern = wrapper.wrapPattern(bodyPat);
  const pattern = new RegExp(fullPattern, "g");

  // For W1 (dollar_bracket), field is handled via bracket suffix.
  // For all others, field is folded into the body with the separator.
  const fieldInBody = wrapper.id !== "W1";

  // Determine prefix substring for fast pre-check.
  // Must be an invariant substring present in ALL symbols of this format
  // (no tool name or hash — those vary per symbol).
  const computePrefix = (): string => {
    const sepChar = separator.id === "S5" ? "" : separator.separatorPattern.replace(/\\/g, "");
    if (content.id === "C4") {
      // hash-only: invariant is just the wrapper opening
      const sample = wrapper.wrap("0000");
      const idx = sample.indexOf("0000");
      return idx > 0 ? sample.slice(0, idx) : sample.slice(0, 2);
    }
    // C1-C3: invariant is wrapper_open + "SYM" + separator
    // Generate with "SYM" only (no tool/hash) and find it in wrapped form
    const marker = `${PREFIX}${sepChar}`;
    const sample = wrapper.wrap(marker + "0000");
    const mIdx = sample.indexOf(marker);
    return sample.slice(0, mIdx + marker.length);
  };
  const prefix = computePrefix();

  const hashRe = /[0-9a-f]{4,8}/;

  return {
    name: formatName,
    prefix,

    generate({ tool, hash, field }) {
      if (fieldInBody) {
        const parts = content.parts({ prefix: PREFIX, tool, hash, field });
        return wrapper.wrap(separator.join(parts));
      } else {
        // W1: field goes in bracket notation
        const parts = content.parts({ prefix: PREFIX, tool, hash });
        return wrapper.wrap(separator.join(parts), field);
      }
    },

    pattern,

    extractHash(symbol: string): string | null {
      const m = symbol.match(hashRe);
      return m ? m[0] : null;
    },

    extractFieldPath(symbol: string): string {
      if (!fieldInBody) {
        // W1: field is in brackets
        const m = symbol.match(/\[([^\]]+)\]$/);
        return m ? m[1] : "";
      }
      // Field is the last part after the hash in the body
      const { body } = wrapper.unwrap(symbol);
      const parts = content.parts({ prefix: PREFIX, tool: "PLACEHOLDER", hash: "0000", field: "FIELD" });
      if (parts.length <= 1 || !content.hasField) return "";
      // Find the hash in the body and take everything after it
      const hm = body.match(/[0-9a-f]{4,8}/);
      if (!hm) return "";
      const afterHash = body.slice(hm.index! + hm[0].length);
      if (!afterHash) return "";
      // Strip leading separator
      const sepChar = separator.separatorPattern.replace(/\\/g, "");
      return afterHash.startsWith(sepChar) ? afterHash.slice(sepChar.length) : afterHash;
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Representative presets (~18 covering all dimensions)
// ─────────────────────────────────────────────────────────────────────────────

export interface FormatPreset {
  id: string;
  content: ContentScheme;
  separator: SeparatorScheme;
  wrapper: WrapperScheme;
  format: SymbolFormat;
  /** Subjective readability score 1–5 (higher = more readable). */
  readability: number;
}

function preset(
  content: ContentScheme,
  separator: SeparatorScheme,
  wrapper: WrapperScheme,
  readability: number,
): FormatPreset {
  const format = composeFormat(content, separator, wrapper);
  return {
    id: format.name,
    content, separator, wrapper, format, readability,
  };
}

/**
 * Representative subset of ~18 presets spanning all content, separator, and
 * wrapper dimensions. Each dimension value appears at least twice.
 *
 * Naming: C{1-4}_S{1-5}_W{1-6}
 */
export const FORMAT_PRESETS: FormatPreset[] = [
  // ── Full content (C1) across wrappers ──
  preset(C1_FULL, S1_UNDERSCORE, W2_DBLBRACE,    4),  // {{SYM_web_fetch_a1b2_title}}
  preset(C1_FULL, S2_DOT,        W1_DOLLAR_BRACKET, 5), // $SYM.web_fetch.a1b2[title]
  preset(C1_FULL, S3_COLON,      W3_ANGLE_TAG,   3),  // <SYM:web_fetch:a1b2:title/>
  preset(C1_FULL, S4_DASH,       W4_BRACKET,     3),  // [SYM-web_fetch-a1b2-title]
  preset(C1_FULL, S1_UNDERSCORE, W5_BARE,        3),  // SYM_web_fetch_a1b2_title
  preset(C1_FULL, S1_UNDERSCORE, W6_BACKTICK,    4),  // `SYM_web_fetch_a1b2_title`

  // ── No-tool content (C2) ──
  preset(C2_NO_TOOL, S1_UNDERSCORE, W2_DBLBRACE, 4),  // {{SYM_a1b2_title}}
  preset(C2_NO_TOOL, S2_DOT,       W1_DOLLAR_BRACKET, 4), // $SYM.a1b2[title]
  preset(C2_NO_TOOL, S3_COLON,     W5_BARE,      2),  // SYM:a1b2:title
  preset(C2_NO_TOOL, S4_DASH,      W3_ANGLE_TAG, 3),  // <SYM-a1b2-title/>

  // ── Minimal content (C3) ──
  preset(C3_MINIMAL, S1_UNDERSCORE, W2_DBLBRACE,  4),  // {{SYM_a1b2}}
  preset(C3_MINIMAL, S2_DOT,       W4_BRACKET,    3),  // [SYM.a1b2]
  preset(C3_MINIMAL, S3_COLON,     W6_BACKTICK,   3),  // `SYM:a1b2`

  // ── Hash-only content (C4) ──
  preset(C4_HASH_ONLY, S1_UNDERSCORE, W2_DBLBRACE, 3), // {{a1b2}}
  preset(C4_HASH_ONLY, S1_UNDERSCORE, W3_ANGLE_TAG, 2), // <a1b2/>
  preset(C4_HASH_ONLY, S1_UNDERSCORE, W4_BRACKET,  2), // [a1b2]

  // ── CamelCase separator (S5) ──
  preset(C1_FULL, S5_CAMEL,       W2_DBLBRACE,    3),  // {{SymWebFetchA1b2Title}}
  preset(C2_NO_TOOL, S5_CAMEL,    W5_BARE,        2),  // SymA1b2Title
];

/** Look up a preset by its ID string (e.g. "C1_S1_W2"). */
export function getPreset(id: string): FormatPreset | undefined {
  return FORMAT_PRESETS.find((p) => p.id === id);
}

/** Get all preset IDs. */
export function listPresetIds(): string[] {
  return FORMAT_PRESETS.map((p) => p.id);
}
