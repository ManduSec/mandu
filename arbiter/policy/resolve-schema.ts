/**
 * resolve-schema — the schema-rule engine of the data-trust policy.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/resolve-schema.ts
 *   Purpose: given a tool's SchemaNode + the tool's params/result, walk the tree
 *   and emit a per-leaf trust decision. This is the *schema rules* half of the
 *   data-trust policy (origin rules live in trust-category.ts). The walker is
 *   what lets the proxy classify individual result fields TRUSTED/UNTRUSTED so
 *   only the untrusted spans get symbolized.
 *
 *   Adaptation for Mandu: NONE of substance. The resolver is pure (no
 *   symbolization, no side effects, no OpenClaw runtime coupling) — lifted
 *   byte-for-byte aside from this header and a comment refresh on PARAM_ALIASES.
 *   This is evaluated security code; the walk/lookup/fail-closed semantics are
 *   preserved exactly.
 *
 * Resolution rules:
 *   - Literal "TRUSTED" / "UNTRUSTED" → direct.
 *   - KeySpec (role: "key")          → TRUSTED (keys are always raw).
 *   - DataSpec (role: "data")        → classify(keyField value, category).
 *   - Fields present in the value but absent from the schema → UNTRUSTED
 *     (deny-by-default) for strings; passthrough TRUSTED for non-strings.
 *   - Unknown/mismatched schema nodes → UNTRUSTED (defensive fallback).
 */

import type {
  SchemaNode,
  ToolSpec,
  FieldMarker,
} from "./schema-types.js";
import {
  isLiteralTrust,
  isKeySpec,
  isDataSpec,
  isItemsSchema,
  isObjectSchema,
  isFieldMarker,
  isActionSpec,
} from "./schema-types.js";
import type { TrustCategory, Trust } from "./trust-category.js";

/** Trust decision for a single field. */
export interface LeafDecision {
  trust: Trust;
  /** Category id if the decision came from a lookup; null for literals / keys. */
  category: string | null;
  /** Role: "literal" for literal leaves, "key" for key fields, "data" for data fields. */
  role: "literal" | "key" | "data";
  /** The raw key value looked up (data fields only). */
  keyValue?: string | null;
}

/** Category registry abstraction — any Map-like the resolver can read. */
export interface CategoryLookup {
  get(id: string): TrustCategory | undefined;
}

/**
 * Pick the schema branch for an action-dispatched tool.
 * Returns null if neither the action nor a default is available.
 */
export function selectSchemaBranch(
  spec: ToolSpec,
  params: Record<string, unknown>,
): SchemaNode | null {
  if (!isActionSpec(spec)) return spec.schema;
  const actionValue = params[spec.actionField];
  if (typeof actionValue === "string" && spec.schemas[actionValue] !== undefined) {
    return spec.schemas[actionValue]!;
  }
  return spec.defaultSchema ?? null;
}

/**
 * Resolve a single FieldMarker to a LeafDecision.
 * `scope` is the immediate enclosing object whose fields siblingKeys can reference.
 */
function resolveMarker(
  marker: FieldMarker,
  scope: Record<string, unknown> | null,
  params: Record<string, unknown>,
  categories: CategoryLookup,
): LeafDecision {
  if (isLiteralTrust(marker)) {
    return { trust: marker, category: null, role: "literal" };
  }
  if (isKeySpec(marker)) {
    return { trust: "TRUSTED", category: marker.category, role: "key" };
  }
  // DataSpec
  const keyValue = lookupKey(marker.keyField, scope, params);
  const category = categories.get(marker.category);
  if (!category) {
    // No registered category → fall back to UNTRUSTED (conservative) and
    // surface the miss via keyValue=null. Engine construction warns about
    // this so it surfaces early in tests.
    return {
      trust: "UNTRUSTED",
      category: marker.category,
      role: "data",
      keyValue,
    };
  }
  return {
    trust: category.classify(keyValue),
    category: marker.category,
    role: "data",
    keyValue,
  };
}

/** Param-name aliases for tools that accept multiple names for the same
 * argument. Carried over from the reference (OpenClaw's read/write/edit
 * accept both `path` and `file_path` for Claude Code compatibility). When a
 * schema references one spelling via `params.<name>`, the other spelling is a
 * valid fallback. Keep this list small and only add pairs where both names
 * mean the same thing. */
const PARAM_ALIASES: Record<string, readonly string[]> = {
  file_path: ["path"],
  path: ["file_path"],
  old_string: ["oldText"],
  oldText: ["old_string"],
  new_string: ["newText"],
  newText: ["new_string"],
};

function readParamValue(
  params: Record<string, unknown>,
  name: string,
): string | null {
  const direct = params[name];
  if (direct != null) return typeof direct === "string" ? direct : String(direct);
  for (const alias of PARAM_ALIASES[name] ?? []) {
    const v = params[alias];
    if (v != null) return typeof v === "string" ? v : String(v);
  }
  return null;
}

/** Resolve a keyField reference. Returns null if missing. */
export function lookupKey(
  keyField: string,
  scope: Record<string, unknown> | null,
  params: Record<string, unknown>,
): string | null {
  if (keyField.startsWith("params.")) {
    return readParamValue(params, keyField.slice("params.".length));
  }
  if (!scope) return null;
  const v = scope[keyField];
  return typeof v === "string" ? v : v == null ? null : String(v);
}

/** Options for a full schema walk. */
export interface WalkOptions {
  /** Called for every field that receives a trust decision. `path` is a
   * dotted path from the result root; array items use `[i]`. `value` is
   * the raw value at that leaf. */
  onLeaf: (args: {
    path: string;
    value: unknown;
    decision: LeafDecision;
  }) => void;
  /** If set, also fires onObject for every interior object before
   * descending. Useful for tests / debugging. */
  onObject?: (args: {
    path: string;
    value: Record<string, unknown>;
    schema: SchemaNode;
  }) => void;
}

/**
 * Walk a schema against a parsed result object, invoking `onLeaf` for
 * every leaf decision. The walker handles:
 *   - top-level `FieldMarker` (the entire result is one leaf)
 *   - object schemas (descend by key; unknown keys default to UNTRUSTED
 *     literal semantics for string values — matches pre-refactor behavior)
 *   - `{ __items }` array schemas (each item resolved independently with
 *     the item object as its scope)
 */
export function walkSchema(
  schema: SchemaNode,
  value: unknown,
  params: Record<string, unknown>,
  categories: CategoryLookup,
  opts: WalkOptions,
  path: string = "",
  scope: Record<string, unknown> | null = null,
): void {
  // Leaf: literal, key, or data marker applies to the *entire value at path*.
  if (isFieldMarker(schema)) {
    const decision = resolveMarker(schema, scope, params, categories);
    opts.onLeaf({ path, value, decision });
    return;
  }

  // Array: each item walked against __items schema.
  if (isItemsSchema(schema)) {
    if (!Array.isArray(value)) {
      // Array expected but value isn't one — treat as single-leaf UNTRUSTED
      // fallback so we don't silently lose taint on malformed results.
      opts.onLeaf({
        path,
        value,
        decision: { trust: "UNTRUSTED", category: null, role: "literal" },
      });
      return;
    }
    const itemSchema = schema.__items;
    value.forEach((item, i) => {
      const itemPath = `${path}[${i}]`;
      const itemScope = (typeof item === "object" && item !== null && !Array.isArray(item))
        ? item as Record<string, unknown>
        : null;
      walkSchema(itemSchema, item, params, categories, opts, itemPath, itemScope);
    });
    return;
  }

  // Object: descend by key.
  if (isObjectSchema(schema)) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      // Object expected but value isn't one — fall through with an
      // UNTRUSTED leaf for the whole thing.
      opts.onLeaf({
        path,
        value,
        decision: { trust: "UNTRUSTED", category: null, role: "literal" },
      });
      return;
    }
    const obj = value as Record<string, unknown>;
    if (opts.onObject) opts.onObject({ path, value: obj, schema });

    // Descend into each field present in the schema. Fields in the
    // value but not in the schema default to UNTRUSTED (deny-by-default),
    // matching pre-refactor semantics.
    const nextScope: Record<string, unknown> = obj; // siblings resolved against this object
    for (const [key, val] of Object.entries(obj)) {
      const childSchema = (schema as Record<string, SchemaNode>)[key];
      const childPath = path ? `${path}.${key}` : key;
      if (childSchema !== undefined) {
        walkSchema(childSchema, val, params, categories, opts, childPath, nextScope);
      } else {
        // Not in schema → deny-by-default for string values, passthrough otherwise.
        if (typeof val === "string") {
          opts.onLeaf({
            path: childPath,
            value: val,
            decision: { trust: "UNTRUSTED", category: null, role: "literal" },
          });
        } else {
          opts.onLeaf({
            path: childPath,
            value: val,
            decision: { trust: "TRUSTED", category: null, role: "literal" },
          });
        }
      }
    }
    return;
  }

  // Unknown schema node — defensive fallback.
  opts.onLeaf({
    path,
    value,
    decision: { trust: "UNTRUSTED", category: null, role: "literal" },
  });
}

/**
 * Summarize a tool's overall trust given its spec + params + category
 * registry, without examining the result body. Used at the pre-result gate
 * and in the correctness runner's skip gate.
 *
 * Rules:
 *   - Literal "TRUSTED" / "UNTRUSTED" → direct.
 *   - Top-level KeySpec → "TRUSTED" (keys are raw).
 *   - Top-level DataSpec → classify keyValue (params-sourced keys are
 *     available; body-sourced keys are not — returns "UNTRUSTED"
 *     conservatively if keyField is a body reference).
 *   - Object/array schema → "UNTRUSTED" if *any* data leaf *could*
 *     become UNTRUSTED given current params, otherwise "TRUSTED".
 */
export function summarizeToolTrust(
  spec: ToolSpec,
  params: Record<string, unknown>,
  categories: CategoryLookup,
): Trust {
  const schema = selectSchemaBranch(spec, params);
  if (schema === null) return "UNTRUSTED"; // no matching action and no default
  return summarizeNode(schema, params, categories);
}

function summarizeNode(
  node: SchemaNode,
  params: Record<string, unknown>,
  categories: CategoryLookup,
): Trust {
  if (isLiteralTrust(node)) return node;
  if (isKeySpec(node)) return "TRUSTED";
  if (isDataSpec(node)) {
    if (node.keyField.startsWith("params.")) {
      const keyValue = lookupKey(node.keyField, null, params);
      const cat = categories.get(node.category);
      if (!cat) return "UNTRUSTED";
      return cat.classify(keyValue);
    }
    // Body-sourced key — unknown until result time. Assume possibly UNTRUSTED.
    return "UNTRUSTED";
  }
  if (isItemsSchema(node)) {
    return summarizeNode(node.__items, params, categories);
  }
  if (isObjectSchema(node)) {
    let any = false;
    for (const child of Object.values(node as Record<string, SchemaNode>)) {
      const t = summarizeNode(child, params, categories);
      if (t === "UNTRUSTED") return "UNTRUSTED";
      if (t === "TRUSTED") any = true;
    }
    return any ? "TRUSTED" : "TRUSTED";
  }
  return "UNTRUSTED";
}
