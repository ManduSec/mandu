/**
 * schema-types — inbound schema marker types for per-field trust classification.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Lifted from
 *     https://github.com/compsec-snu/dualview/blob/main/plugin/dualview/policy/schema-types.ts
 *   Purpose: the type vocabulary the data-trust policy uses to describe how a
 *   tool result's fields map to trust decisions — literal TRUSTED/UNTRUSTED
 *   leaves, KeySpec (the raw key consulted by origin rules), and DataSpec (a
 *   field whose trust is looked up against a named category for a sibling/param
 *   key). Consumed by resolve-schema.ts.
 *
 *   Adaptation for Mandu: NONE. Pure types + type guards, no runtime coupling.
 *   Lifted byte-for-byte aside from this header.
 *
 * See docs/adfi-reference/design/inbound-outbound-spec.md and mandu.md §1 for
 * how markers interact with the resolver.
 */

/** A registered trust category. Built-ins are URL / CHANNEL / DIR but
 * the resolver is category-agnostic — any string id registered on the
 * PolicyEngine is valid. */
export type CategoryId = "URL" | "CHANNEL" | "DIR" | string;

/** A field whose raw value is the lookup key for its category. Always
 * raw (TRUSTED) at the output. Data fields reference it by name via
 * `keyField`. */
export interface KeySpec {
  category: CategoryId;
  role: "key";
}

/** A field whose trust is determined by looking up `keyField` against
 * its category's trust list.
 *
 * keyField has exactly two forms (no parent walk, no wildcards):
 *
 *   "name"         → field named `name` in the *immediate enclosing
 *                    object*. Inside an `__items` array, the immediate
 *                    enclosing object is the current item, so sibling
 *                    references per-item work automatically.
 *
 *   "params.name"  → tool param named `name`. Must be declared in the
 *                    enclosing ToolInboundSpec.paramsKeys — validated
 *                    at engine construction time.
 *
 * If a data field can't reach its key under these rules, restructure
 * the schema or surface the key via paramsKeys. */
export interface DataSpec {
  category: CategoryId;
  role: "data";
  keyField: string;
}

/** Any leaf value in a schema tree. */
export type FieldMarker = "TRUSTED" | "UNTRUSTED" | KeySpec | DataSpec;

/** A schema tree node. Leaves are FieldMarker; interior nodes are
 * either a plain object (keyed by field name) or a homogeneous array
 * (via the `__items` sentinel). */
export type SchemaNode =
  | FieldMarker
  | { [fieldName: string]: SchemaNode }
  | { __items: SchemaNode };

/** Declaration for a params-sourced key. Always role: "key" — the
 * presence in paramsKeys implies the role, but we spell it out so the
 * structure matches in-schema KeySpec exactly. */
export type ParamKeySpec = KeySpec;

/** Single-shape tool spec (the vast majority). */
export interface ToolInboundSpec {
  paramsKeys?: Record<string, ParamKeySpec>;
  schema: SchemaNode;
  /**
   * WHOLE-RESULT rule (Mandu addition, 2026-07-16): the marker applied when a
   * caller classifies the ENTIRE flattened result with no field path — which is
   * how the live model-API proxies call `classify()` (rewrite-request.ts flattens
   * every tool_result to one string). A structured `schema` alone can never
   * match that call shape, so without this field a structured tool's
   * whole-result classification is fail-closed UNTRUSTED (policy-interface.ts).
   *
   * SECURITY: absent ⇒ the fail-closed default stands, unchanged. Present ⇒ the
   * marker is resolved exactly like any schema leaf (literal / KeySpec /
   * DataSpec against a registered category). Only add one when the whole
   * flattened result is honestly described by a single origin key (e.g.
   * WebFetch's body keyed off params.url). Note: a YAML `tools:` override
   * REPLACES the spec's schema and deliberately DROPS this field
   * (tool-overrides.ts) — an operator override must not silently inherit a
   * built-in trust grant.
   */
  wholeResult?: FieldMarker;
}

/** Tool spec whose result shape depends on a params field (e.g.
 * `message` dispatching on params.action). The chosen schema branch
 * is resolved before the schema walker runs. */
export interface ActionToolInboundSpec {
  paramsKeys?: Record<string, ParamKeySpec>;
  actionField: string;
  schemas: Record<string, SchemaNode>;
  defaultSchema?: SchemaNode;
}

export type ToolSpec = ToolInboundSpec | ActionToolInboundSpec;

// ─── Type guards ─────────────────────────────────────────────────────────

export function isLiteralTrust(m: unknown): m is "TRUSTED" | "UNTRUSTED" {
  return m === "TRUSTED" || m === "UNTRUSTED";
}

export function isKeySpec(m: unknown): m is KeySpec {
  if (typeof m !== "object" || m === null) return false;
  const o = m as Record<string, unknown>;
  return o.role === "key" && typeof o.category === "string";
}

export function isDataSpec(m: unknown): m is DataSpec {
  if (typeof m !== "object" || m === null) return false;
  const o = m as Record<string, unknown>;
  return o.role === "data"
    && typeof o.category === "string"
    && typeof o.keyField === "string";
}

export function isFieldMarker(m: unknown): m is FieldMarker {
  return isLiteralTrust(m) || isKeySpec(m) || isDataSpec(m);
}

export function isItemsSchema(m: unknown): m is { __items: SchemaNode } {
  if (typeof m !== "object" || m === null) return false;
  if (isFieldMarker(m)) return false;
  return "__items" in (m as Record<string, unknown>);
}

export function isObjectSchema(m: unknown): m is { [k: string]: SchemaNode } {
  if (typeof m !== "object" || m === null) return false;
  return !isFieldMarker(m) && !isItemsSchema(m);
}

export function isActionSpec(spec: ToolSpec): spec is ActionToolInboundSpec {
  return "actionField" in spec
    && typeof (spec as ActionToolInboundSpec).actionField === "string";
}
