/**
 * symbol-table — barrel re-export for the lifted Mandu symbol table.
 *
 * Mandu-new (no reference origin): convenience barrel so the arbiter IPC layer
 * and tests can `import { ... } from "../symbol-table/index.js"` without reaching
 * into individual lifted modules. The implementation lives in:
 *   - symbol-format.ts   (lifted from adfi-openclaw/.../adfi-symbol-format.ts)
 *   - handling-prompt.ts (T-LLM prompt builder, extracted from symbol-format.ts)
 *   - symbol-formats.ts  (lifted from adfi-openclaw/.../symbol-formats.ts)
 *   - symbol-table.ts    (lifted from adfi-openclaw/.../adfi-symbol-table.ts)
 *   - confidentiality.ts (Mandu-new: the second label axis, confidentiality.md §2)
 */

export * from "./confidentiality.js";
export * from "./symbol-format.js";
export * from "./handling-prompt.js";
export * from "./symbol-formats.js";
export * from "./symbol-table.js";
