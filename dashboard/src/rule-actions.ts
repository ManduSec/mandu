/**
 * rule-actions — what a button on a "Your rules" row does to the law
 * (dashboard.md §4.25c). Mandu-new (no reference origin).
 *
 * The Rules page shows rows projected from the COMPILED law (policy-panel.ts
 * `yourRulesVM`); a change is an edit to the RAW document in force
 * (arbiter/policy/policy-edit.ts). This module is the one place that turns a
 * row id plus an action into that edit, read against the raw document at the
 * moment of the click. The browser only ever names a row and an action; it
 * never sends an edit, so the page cannot be made to write anything the row
 * does not stand for.
 *
 * Every row kind has a Remove. Two have a flip:
 *   lock:<path>                   remove → unlock-path
 *   trusted-origin:<kind>:<value> remove → distrust-origin (only a value listed
 *                                 literally; one reached through a named list
 *                                 or a category default is refused, so Remove
 *                                 never answers "done" for a no-op)
 *   <user rule id>                remove → retire-rule; allow|block → release
 *                                 with the same id, from, to and expiry
 *   connect:<proto>:<host>:<port> remove → remove-connect
 *   disposition:<rule>            remove → set-disposition ask (the default)
 *   app:<name>                    none: per-program output rules have no edit
 *                                 op; the row says where they are set
 */

export type RuleAction = "remove" | "allow" | "block";

export type RuleActionPlan =
  | { ok: true; edits: Array<Record<string, unknown>> }
  | { ok: false; status: number; error: string };

/** The raw document keys this module reads (policy.yaml as the arbiter holds it). */
interface RawDoc {
  inbound?: Record<string, { default?: unknown; trustedList?: unknown } | unknown>;
  user_rules?: Array<{ id?: unknown; from?: { host?: unknown }; to?: { host?: unknown }; mode?: unknown; expires?: unknown }>;
  destinations?: Array<{ host?: unknown; port?: unknown; proto?: unknown; connect?: unknown }>;
  rules?: Record<string, { mode?: unknown }>;
}

const ORIGIN_KINDS = new Set(["url", "dir", "channel"]);
const NOT_HERE = "This rule can only be changed in the rules file.";

function fail(status: number, error: string): RuleActionPlan {
  return { ok: false, status, error };
}

function asDoc(v: unknown): RawDoc {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as RawDoc) : {};
}

/** The edits that carry out `action` on the row `id`, against the raw document in force. */
export function planRuleAction(document: unknown, id: string, action: RuleAction): RuleActionPlan {
  const doc = asDoc(document);
  if (typeof id !== "string" || id === "") return fail(400, "which rule?");
  if (action !== "remove" && action !== "allow" && action !== "block") return fail(400, "action must be remove, allow or block");
  const onlyRemove = (): RuleActionPlan | null => (action === "remove" ? null : fail(400, "this rule can only be removed"));

  if (id.startsWith("app:")) return fail(409, NOT_HERE);

  if (id.startsWith("lock:")) {
    const bad = onlyRemove();
    if (bad) return bad;
    // The row carries the COMPILED path (a literal is normalized, `~` expanded);
    // unlock-path matches it by the same normalization, and a lock that is gone
    // comes back from the arbiter as a refusal, never as a silent success.
    const path = id.slice("lock:".length);
    if (path === "") return fail(400, "not a rule id");
    return { ok: true, edits: [{ op: "unlock-path", path }] };
  }

  if (id.startsWith("trusted-origin:")) {
    const bad = onlyRemove();
    if (bad) return bad;
    const rest = id.slice("trusted-origin:".length);
    const colon = rest.indexOf(":");
    const kind = colon > 0 ? rest.slice(0, colon) : "";
    const pattern = colon > 0 ? rest.slice(colon + 1) : "";
    if (!ORIGIN_KINDS.has(kind) || pattern === "") return fail(400, "not a rule id");
    const cat = (doc.inbound ?? {})[kind] as { trustedList?: unknown } | undefined;
    const listed = Array.isArray(cat?.trustedList) && cat!.trustedList.includes(pattern);
    if (!listed) return fail(409, "This source is trusted through a named list or a default in the rules file, so it can only be changed there.");
    return { ok: true, edits: [{ op: "distrust-origin", kind, pattern }] };
  }

  if (id.startsWith("connect:")) {
    const bad = onlyRemove();
    if (bad) return bad;
    const d = (doc.destinations ?? []).find((x) => x && x.connect === "allow" && connectId(x) === id);
    if (!d) {
      const viaList = (doc.destinations ?? []).some((x) => x && typeof x.host === "string" && x.host.startsWith("@"));
      return fail(409, viaList ? "This place is allowed through a named list in the rules file, so it can only be changed there." : "This rule is no longer in your rules. Reload the page.");
    }
    return { ok: true, edits: [{ op: "remove-connect", host: d.host, ...(d.port !== undefined ? { port: d.port } : {}) }] };
  }

  if (id.startsWith("disposition:")) {
    const bad = onlyRemove();
    if (bad) return bad;
    const rule = id.slice("disposition:".length);
    if ((doc.rules ?? {})[rule]?.mode !== "block") return fail(409, "This rule is no longer in your rules. Reload the page.");
    return { ok: true, edits: [{ op: "set-disposition", rule, mode: "ask" }] };
  }

  const r = (doc.user_rules ?? []).find((x) => x && x.id === id);
  if (!r) return fail(409, "This rule is no longer in your rules. Reload the page.");
  if (action === "remove") return { ok: true, edits: [{ op: "retire-rule", id }] };
  if (r.mode === action) return fail(409, `This rule already says ${action === "allow" ? "allow" : "block"}.`);
  if (typeof r.to?.host !== "string") return fail(409, NOT_HERE);
  return {
    ok: true,
    edits: [{
      op: "release", id, to: { host: r.to.host }, mode: action,
      ...(typeof r.from?.host === "string" ? { from: { host: r.from.host } } : {}),
      ...(typeof r.expires === "string" ? { expires: r.expires } : {}),
    }],
  };
}

/** The same id `yourRulesVM` gives a destinations row: the compiled port and
 *  proto (443 / tcp when the file leaves them out). */
function connectId(d: { host?: unknown; port?: unknown; proto?: unknown }): string {
  const proto = d.proto === "udp" ? "udp" : "tcp";
  const port = d.port === undefined ? 443 : d.port;
  return `connect:${proto}:${String(d.host).trim().toLowerCase()}:${String(port)}`;
}
