/**
 * policy-edit-schema — the JSON Schema of a `PolicyEdit` list
 * (docs/design/ui/policy-surface.md §8.4.3). Mandu-new.
 *
 * DERIVED, not hand-written: every enum comes from the tables the arbiter
 * itself validates with (`LEVELS`, `DISPOSITION_MODES`, `dispositionableRuleIds()`,
 * `LIST_NAME_RE`, `POLICY_EDIT_OPS`, the per-op key sets `applyEdits`
 * enforces). The confined agent's `mandu_policy_propose` tool description
 * and the dashboard's Describe box embed the AGENT schema verbatim
 * (`policyAgentEditSchema`: every op but the model-endpoint ops, which only
 * Settings › Models and hand edits make; §4.3a), so drift between what the
 * model is told and what the arbiter accepts is the failure the pins prevent:
 *   - `policy-edit.schema.json` is the checked-in copy of the agent schema; a
 *     unit test fails when it differs from `policyAgentEditSchema()`
 *     (regenerate with `npx tsx scripts/gen-policy-schema.ts`);
 *   - a corpus test asserts the schema and `applyEdits` accept and refuse the
 *     same edit shapes.
 */
import { AGENT_EDIT_OPS, EDIT_KEYS, POLICY_EDIT_OPS, type PolicyEditOp } from "./policy-edit.js";
import { CATEGORY_RE, FILTER_ID_RE } from "../prompt-filter/policy.js";
import { BLOB_ID_RE, BLOB_NOTE_MAX, DISPOSITION_MODES, LEVELS, LIST_NAME_RE, MODEL_NAME_RE, SENSITIVITY_LABEL_NAME_MAX, dispositionableRuleIds } from "./policy-file-validate.js";

type Json = Record<string, unknown>;

const str: Json = { type: "string", minLength: 1 };
const strList: Json = { type: "array", items: str };
const host: Json = { type: "object", properties: { host: str }, required: ["host"], additionalProperties: false };
const port: Json = { anyOf: [{ type: "integer", minimum: 1, maximum: 65535 }, { const: "*" }] };
const originKind: Json = { enum: ["url", "dir", "channel"] };
const URL_PATTERN =
  "url: a hostname (pypi.org), a wildcard subdomain (*.python.org) or a hostname/path prefix (github.com/myorg), with no scheme; dir: an absolute or ~/ path; channel: a channel id";

/** `token_env`: an environment variable NAME. The validator's own pattern
 *  (policy-file-validate.ts `checkModels`); the corpus test pins that both
 *  refuse a value that is not a name. */
const ENV_NAME_PATTERN = "^[A-Za-z_][A-Za-z0-9_]*$";

/** A `models:` entry (plan 11 D2). The URL's content rules (http(s), no
 *  credentials) and the cloud-model rule are the validator's; the schema
 *  carries the shape. */
const MODEL: Json = {
  name: { type: "string", pattern: MODEL_NAME_RE.source, description: "the entry's unique name (1-64 letters, digits, _ . -)" },
  url: { ...str, description: "the server's http(s) address, e.g. http://127.0.0.1:11434; no user name or password in it" },
  wire: { enum: ["anthropic", "openai-chat"], description: "the API it speaks (default anthropic)" },
  model: { ...str, description: "the model name to request" },
  local: { type: "boolean", description: "true only for a model the user or their organization runs, on this computer or on the organization's network; files labeled local-model may then be sent to it" },
  token_env: { type: "string", pattern: ENV_NAME_PATTERN, description: "the NAME of an environment variable holding a bearer token; never the token itself" },
  helper: { type: "boolean", description: "true on at most one local: true entry: the quarantined helper uses this model (default: the first local: true entry)" },
  allow_plain_http: { type: "boolean", description: "true only on a local: true entry at an http:// address on another machine: the helper may send local-model files there unencrypted (not allowed on https)" },
  tls: {
    type: "object",
    additionalProperties: false,
    description: "https only: how Mandu checks this server's identity. Paths are absolute or start with ~/; the key never goes in policy.yaml",
    properties: {
      ca_file: { type: "string", description: "a PEM bundle trusted for this server only (your organization's CA)" },
      pin_sha256: { type: "array", minItems: 1, items: { type: "string", pattern: "^[A-Za-z0-9+/]{43}=$" }, description: "base64 SHA-256 of a public key (SPKI) in the server's chain; any one matches" },
      client_cert: { type: "string", description: "a client certificate (PEM) for a server that requires mutual TLS; needs client_key" },
      client_key: { type: "string", description: "the client certificate's private key file (PEM, no passphrase); needs client_cert" },
    },
  },
};

/** A label or tenant GUID as `checkSensitivityLabels` accepts it (braces and
 *  case optional; plan 14 §14.1). */
/** Plan 15 §6: a prompt filter id and a category (prompt-filter/policy.ts). */
const PROMPT_FILTER_ID = FILTER_ID_RE.source;
const PROMPT_CATEGORY = CATEGORY_RE.source;

const GUID_PATTERN = "^\\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}?$";

const PROPS: Record<(typeof POLICY_EDIT_OPS)[number], Json> = {
  "lock-path": {
    path: { ...str, description: "absolute path, ~/path, or a gitignore-style pattern anchored at /, ~/ or **/" },
    level: { enum: [...LEVELS], description: "no-model applies at once; any-model and public lower protection and wait for the user" },
    bindings: { ...strList, description: "hosts this file may be sent to without an ask (loosens protection)" },
    recursive: { type: "boolean" },
  },
  "unlock-path": { path: str },
  "lock-blob": {
    blob: { type: "string", pattern: BLOB_ID_RE.source, description: "a repository object's id: sha1:<40 hex> or sha256:<64 hex>, lowercase; that exact content is hidden from the agent in every repository" },
    level: { enum: [...LEVELS], description: "any level but public hides the object and applies at once; public hides nothing and waits for the user" },
    note: { type: "string", maxLength: BLOB_NOTE_MAX, pattern: "^[^\\u0000-\\u001f\\u007f]*$", description: "one line saying where it was found (never the value)" },
  },
  "unlock-blob": { blob: { type: "string", pattern: BLOB_ID_RE.source } },
  "trust-origin": { kind: originKind, pattern: { ...str, description: URL_PATTERN } },
  "distrust-origin": { kind: originKind, pattern: { ...str, description: URL_PATTERN } },
  release: {
    id: str,
    from: host,
    to: { ...host, description: "destination host, \"*\" for any, or @list" },
    mode: { enum: ["allow", "block", "audit"] },
    expires: { anyOf: [{ type: "string", format: "date-time" }, { type: "null" }] },
    reason: str,
  },
  "retire-rule": { id: str },
  "set-disposition": { rule: { enum: dispositionableRuleIds() }, mode: { enum: [...DISPOSITION_MODES] } },
  "allow-connect": { host: str, port },
  "remove-connect": { host: str, port },
  "trust-command": { id: str, trustHelp: { type: "boolean" } },
  "tool-inbound": { tool: str, trust: { enum: ["TRUSTED", "UNTRUSTED"] } },
  list: { name: { type: "string", pattern: LIST_NAME_RE.source }, add: strList, remove: strList },
  "add-model": MODEL,
  "update-model": { ...MODEL, name: { ...(MODEL.name as Json), description: "the name of the declared entry to replace (every field is replaced; one left out is removed)" } },
  "remove-model": { name: MODEL.name as Json },
  "restore-model": { name: { ...(MODEL.name as Json), description: "an administrator's model the user removed" } },
  "map-sensitivity-label": {
    id: { type: "string", pattern: GUID_PATTERN, description: "the sensitivity label's GUID (Purview / MIP)" },
    site: { type: "string", pattern: GUID_PATTERN, description: "the tenant's GUID; left out, the mapping holds for the label in every tenant" },
    name: { type: "string", minLength: 1, maxLength: SENSITIVITY_LABEL_NAME_MAX, pattern: "^[^\\u0000-\\u001f\\u007f-\\u009f]*$", description: "the label's name in the user's words, shown in the review" },
    level: { enum: [...LEVELS], description: "the level a file carrying this label is suggested at; public suggests nothing" },
  },
  "unmap-sensitivity-label": {
    id: { type: "string", pattern: GUID_PATTERN },
    site: { type: "string", pattern: GUID_PATTERN },
  },
  "set-prompt-filter": {
    filter: { type: "string", pattern: PROMPT_FILTER_ID, description: "a built-in filter (registered-value, key-shapes) or a pack's id" },
    on: { type: "boolean" },
    on_error: { anyOf: [{ enum: ["block", "pass"] }, { type: "null" }], description: "what a failure of this filter does to the prompt; null returns to the default" },
    endpoint: { anyOf: [{ type: "string", minLength: 1 }, { type: "null" }], description: "a classifier plugin's model: a models: entry declared local: true; null removes it (any change is a relaxation)" },
  },
  "set-prompt-action": {
    category: { type: "string", pattern: PROMPT_CATEGORY, description: "a dotted category; the longest prefix row wins" },
    action: { enum: ["pass", "log", "redact", "mask", "ask", "block"] },
  },
  "remove-prompt-action": { category: { type: "string", pattern: PROMPT_CATEGORY } },
  "add-prompt-exception": {
    category: { type: "string", pattern: PROMPT_CATEGORY },
    match: { type: "string", minLength: 1, maxLength: 256, description: "a pattern over the found text (* and ? are wildcards)" },
  },
  "remove-prompt-exception": {
    category: { type: "string", pattern: PROMPT_CATEGORY },
    match: { type: "string", minLength: 1, maxLength: 256 },
  },
};

const REQUIRED: Record<(typeof POLICY_EDIT_OPS)[number], string[]> = {
  "lock-path": ["path", "level"],
  "unlock-path": ["path"],
  "lock-blob": ["blob", "level"],
  "unlock-blob": ["blob"],
  "trust-origin": ["kind", "pattern"],
  "distrust-origin": ["kind", "pattern"],
  release: ["to", "mode"],
  "retire-rule": ["id"],
  "set-disposition": ["rule", "mode"],
  "allow-connect": ["host"],
  "remove-connect": ["host"],
  "trust-command": ["id", "trustHelp"],
  "tool-inbound": ["tool", "trust"],
  list: ["name"],
  "add-model": ["name", "url"],
  "update-model": ["name", "url"],
  "remove-model": ["name"],
  "restore-model": ["name"],
  "map-sensitivity-label": ["id", "name", "level"],
  "unmap-sensitivity-label": ["id"],
  "set-prompt-filter": ["filter", "on"],
  "set-prompt-action": ["category", "action"],
  "remove-prompt-action": ["category"],
  "add-prompt-exception": ["category", "match"],
  "remove-prompt-exception": ["category", "match"],
};

/** The schema over `ops` (default: the whole grammar, as `applyEdits` accepts it). */
export function policyEditSchema(ops: readonly PolicyEditOp[] = POLICY_EDIT_OPS): Json {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://mandu.local/schema/policy-edit.json",
    title: "Mandu policy edits",
    description:
      "A list of typed edits to the Mandu policy. The whole list applies at once only when it tightens protection; " +
      "if any edit loosens it, nothing applies and the list waits for the user's approval.",
    type: "array",
    minItems: 1,
    items: {
      oneOf: ops.map((op) => {
        if (EDIT_KEYS[op].join() !== ["op", ...Object.keys(PROPS[op])].join()) {
          throw new Error(`policy-edit-schema: ${op} properties drifted from applyEdits' key set`);
        }
        return {
          type: "object",
          properties: { op: { const: op }, ...PROPS[op] },
          required: ["op", ...REQUIRED[op]],
          additionalProperties: false,
        };
      }),
    },
  };
}

/** What a model is offered (`policySchema`): the grammar without the
 *  model-endpoint ops (policy-surface.md §8.4.3a). */
export function policyAgentEditSchema(): Json {
  return policyEditSchema(AGENT_EDIT_OPS);
}
