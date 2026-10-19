/**
 * server/model-routes — Settings › Models (dashboard.md §4.25l; confidentiality
 * plan 11 §7.3): add, edit, remove and test the declared models (policy.yaml
 * `models:`).
 *
 *   POST /api/policy/models/change { action, name?, model?, version?, expected? }
 *        action "add"    model = { name, url, wire?, model?, local?, tokenEnv?, helper? }
 *        action "update" name = the entry's current name, model = its new form,
 *                        version = the entry's version as the page read it
 *                        (the panel's `models[].version`; required)
 *        action "remove" name
 *        action "restore" name (an administrator's model the person removed,
 *                         plan 12 D5: the marker in policy.yaml is dropped)
 *        → { applied: false, confirm: true, expected, rows, wouldLet, warnings }
 *          (every models change loosens protection: ask the person, then send
 *          the same body with `expected`)
 *        → { applied: true, changeId, note }
 *        → 409 { stale: true, changed, error } the entry (or one whose helper
 *          mark the change moves) changed since it was read: nothing saved
 *   POST /api/policy/models/test   { name } → { result: ProbeResult }
 *
 * The edit is planned HERE into the one edit grammar (add-model /
 * update-model / remove-model, arbiter/policy/policy-edit.ts); the arbiter's
 * own validator (`checkModels`) judges the entry, so nothing about a model's
 * content is re-checked in this file. Apply is the human-apply sequence the
 * Rules page and the Describe box share (`applyAsHuman`): preview, refuse a
 * loosening that was not shown, propose on the ADMIN channel, approve at once.
 * Every change is recorded and can be undone from History.
 *
 * An update replaces the entry whole, from a form filled from the list the
 * page read, and carries over what the form does not edit (`tls`, and the
 * fields of an entry whose helper mark moves). So it names the entries it
 * was built from with their versions (`basedOn`, policy-surface.md §8.4.6
 * "An item-level version"), and the arbiter refuses it, nothing written,
 * once one of them changed: a change to that entry made meanwhile (a hand
 * edit, another tab) is never overwritten with what was read before it.
 * The preview gate (`expected`) still judges every loosening at apply.
 *
 * The probe reads the entry from the law IN FORCE by name (never an address
 * from the request, so this route cannot be pointed at an arbitrary host) and
 * runs doctor's checks (model-probe.ts). A token named by `token_env` is read
 * from this process's environment for the listing only and never answered.
 *
 * Both are POSTs behind the server's global mutating gate (CSRF + admin
 * session), like every other policy write.
 */
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { asTlsConfig, type EndpointTlsConfig } from "../endpoint-tls.js";
import { endpointPlacement } from "../view-model/model-endpoints.js";
import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import { applyAsHuman } from "./policy-assistant-routes.js";
import type { PolicyDocArbiter, PolicyDocumentView } from "./policy-doc-routes.js";
import { relaxKey } from "../policy-assistant.js";
import { changeWarnings, editRow, relaxLine } from "../view-model/policy-proposals.js";
import { probeModelEndpoint, realProbeDeps, type ProbeDeps, type ProbeEntry } from "../model-probe.js";

/** The approver the arbiter records; History reads it back (policy-proposals.ts). */
export const SETTINGS_APPROVER = "human:settings";
/** Said after every applied change: the confine ports and the main-model
 *  binding are fixed when a session starts (plan 11 §7.1, D5). */
export const RESTART_NOTE = "New sessions use this. Restart a running agent to use it there.";

const UNSUPPORTED = "this Mandu service cannot change models from this page; restart the Mandu stack on the current build";
const MOVED = "Your models changed while you were deciding. Nothing was changed. Try again.";
const GONE = "This model is no longer in your list. Reload the page.";
const UNREAD = "This page did not say which version of the model it showed you. Reload the page and edit it again.";
/** The entry the form was filled from changed (policy-surface.md §8.4.6). */
export function staleWords(name: string): string {
  return `${name} was changed somewhere else while you were editing it, so nothing was saved. What you typed is still in the form: compare it with ${name} as it is now, then save again.`;
}

export type ModelChangePlan =
  /** `reads`: the entries the edits carry fields over from, by name (the
   *  entry an update replaces, any whose helper mark moves). */
  | { ok: true; edits: Array<Record<string, unknown>>; reads: string[] }
  | { ok: false; status: number; error: string };

function text(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

/** The form's fields as a `models:` entry in the file's spelling. Empty
 *  optional fields are left out; `local` is written only as a literal true.
 *  Everything else is the validator's to judge. */
export function entryFromForm(form: unknown): Record<string, unknown> {
  const f = (form && typeof form === "object" ? form : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = { name: text(f["name"]), url: text(f["url"]) };
  const wire = text(f["wire"]);
  if (wire !== "") out["wire"] = wire;
  const model = text(f["model"]);
  if (model !== "") out["model"] = model;
  if (f["local"] === true) out["local"] = true;
  const tokenEnv = text(f["tokenEnv"]);
  if (tokenEnv !== "") out["token_env"] = tokenEnv;
  if (f["helper"] === true) out["helper"] = true;
  // Plan 12 D2: the opt-out, written only as a literal true (the validator
  // refuses it on an https url and judges the rest).
  if (f["allowPlainHttp"] === true) out["allow_plain_http"] = true;
  return out;
}

/** The fields of an update-model edit, in the file's spelling (arbiter
 *  policy-edit.ts MODEL_FIELDS). */
const FILE_FIELDS = ["name", "url", "wire", "model", "local", "token_env", "helper", "allow_plain_http", "tls"] as const;

/**
 * Only one entry can carry `helper: true` (the validator's rule). Choosing a
 * new one in the form MOVES it: every OTHER entry in force that carries it is
 * rewritten without it, in the same edit list, so the file never holds two.
 * `inForce` is the law's `models:` as written (policy.yaml spelling). Pure.
 */
export function helperMoveEdits(entry: Record<string, unknown>, inForce: unknown, replacing: string | null): Array<Record<string, unknown>> {
  if (entry["helper"] !== true || !Array.isArray(inForce)) return [];
  const out: Array<Record<string, unknown>> = [];
  for (const raw of inForce as unknown[]) {
    if (!raw || typeof raw !== "object") continue;
    const m = raw as Record<string, unknown>;
    if (m["helper"] !== true || m["name"] === entry["name"] || m["name"] === replacing) continue;
    const kept: Record<string, unknown> = { op: "update-model" };
    for (const k of FILE_FIELDS) if (k !== "helper" && m[k] !== undefined) kept[k] = m[k];
    out.push(kept);
  }
  return out;
}

/** The edits for one Settings action. Pure. A rename is remove + add.
 *  `inForce` (the law's `models:` as written) lets a new helper choice move
 *  the mark off the entry that had it (helperMoveEdits). */
export function planModelChange(body: unknown, inForce?: unknown): ModelChangePlan {
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const action = b["action"];
  const name = text(b["name"]);
  if (action === "remove") {
    if (name === "") return { ok: false, status: 400, error: "which model?" };
    return { ok: true, edits: [{ op: "remove-model", name }], reads: [] };
  }
  if (action === "restore") {
    if (name === "") return { ok: false, status: 400, error: "which model?" };
    return { ok: true, edits: [{ op: "restore-model", name }], reads: [] };
  }
  if (action !== "add" && action !== "update") return { ok: false, status: 400, error: "action must be add, update, remove or restore" };
  if (!b["model"] || typeof b["model"] !== "object") return { ok: false, status: 400, error: "the model's fields are missing" };
  const entry = entryFromForm(b["model"]);
  if (entry["name"] === "") return { ok: false, status: 400, error: "Give the model a name." };
  if (entry["url"] === "") return { ok: false, status: 400, error: "Give the model's address." };
  if (action === "add") {
    const moves = helperMoveEdits(entry, inForce, null);
    return { ok: true, edits: [...moves, { op: "add-model", ...entry }], reads: moves.map((m) => String(m["name"])) };
  }
  if (name === "") return { ok: false, status: 400, error: "which model?" };
  // Plan 12 D3: the form does not edit `tls:` (its paths and pins live in
  // policy.yaml), and update-model replaces the entry whole, so the entry's
  // tls in force is carried over rather than silently dropped.
  const was = Array.isArray(inForce) ? (inForce as unknown[]).find((m) => !!m && typeof m === "object" && (m as Record<string, unknown>)["name"] === name) as Record<string, unknown> | undefined : undefined;
  if (was?.["tls"] !== undefined && entry["tls"] === undefined) entry["tls"] = was["tls"];
  const moves = helperMoveEdits(entry, inForce, name);
  const reads = [name, ...moves.map((m) => String(m["name"]))];
  if (name === entry["name"]) return { ok: true, edits: [...moves, { op: "update-model", ...entry }], reads };
  return { ok: true, edits: [...moves, { op: "remove-model", name }, { op: "add-model", ...entry }], reads };
}

/** The validator's lines without the file position (`models[2].url: …` → `url: …`). */
export function formProblems(problems: readonly string[]): string[] {
  return problems.map((p) => p.replace(/^models\[\d+\]\./, "").replace(/^edits\[\d+\] \([a-z-]+\): /, ""));
}

export async function postModelChange(arbiter: PolicyDocArbiter, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter.policyPreview || !arbiter.policyPropose || !arbiter.resolvePolicyProposal) return json(res, 501, { error: UNSUPPORTED });
  const body = (await readJson(req)) as Record<string, unknown> | undefined;
  const expected = body?.["expected"];
  if (expected !== undefined && (!Array.isArray(expected) || !expected.every((k) => typeof k === "string"))) {
    return json(res, 400, { error: "expected must be the list this route answered with" });
  }
  // The version of the entry the form was filled from (§8.4.6 "An
  // item-level version"): an update is refused without it.
  const isUpdate = body?.["action"] === "update";
  const version = body?.["version"];
  if (isUpdate && (typeof version !== "string" || !/^[0-9a-f]{32}$/.test(version))) return json(res, 400, { error: UNREAD });
  // A helper choice moves the mark, so the plan needs the list in force.
  let inForce: unknown;
  let versions: Record<string, string> | undefined;
  const wantsHelper = (body?.["model"] as Record<string, unknown> | undefined)?.["helper"] === true;
  // An update carries fields the form does not edit (tls) from the list in force.
  if (wantsHelper || isUpdate) {
    try {
      const pd = await arbiter.policyDocument();
      const doc = pd.inForce;
      inForce = doc && typeof doc === "object" ? (doc as { models?: unknown }).models : undefined;
      // No `models` section: the file names no model (an administrator's only).
      versions = pd.itemVersions ? pd.itemVersions["models"] ?? {} : undefined;
    } catch (err) {
      return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
    }
  }
  const plan = planModelChange(body, inForce);
  if (!plan.ok) return json(res, plan.status, { error: plan.error });
  // What the edits carry over is named with its version: the form's entry
  // as the PAGE read it, a moved helper mark's entry as THIS read found it.
  // An arbiter that answers no versions could not refuse a stale one: no
  // carried-over write is sent to it.
  const name = text(body?.["name"]);
  if (plan.reads.length > 0 && !versions) return json(res, 501, { error: UNSUPPORTED });
  const basedOn = plan.reads.map((n) => ({ section: "models", key: n, version: isUpdate && n === name ? (version as string) : versions?.[n] ?? "" }));
  if (basedOn.some((b) => !/^[0-9a-f]{32}$/.test(b.version))) return json(res, 501, { error: UNSUPPORTED });
  const stale = (changed: unknown): string => (Array.isArray(changed) && isUpdate && changed.includes(`models ${name}`) ? staleWords(name) : MOVED);
  // Changed before the preview: said now, not after the person confirms.
  if (isUpdate && versions && versions[name] !== undefined && versions[name] !== version) {
    return json(res, 409, { error: staleWords(name), stale: true, changed: [`models ${name}`] });
  }

  if (expected === undefined) {
    let preview;
    try {
      preview = await arbiter.policyPreview(plan.edits);
    } catch (err) {
      return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
    }
    if (!preview.ok) {
      const gone = preview.problems.some((p) => /\bno model named\b|\bis not removed\b/.test(p));
      if (gone) return json(res, 409, { error: GONE });
      return json(res, 422, { error: "This model entry is not valid.", problems: formProblems(preview.problems) });
    }
    if (preview.relaxations.length > 0) {
      return json(res, 200, {
        applied: false,
        confirm: true,
        expected: preview.relaxations.map(relaxKey),
        rows: plan.edits.map(editRow),
        wouldLet: preview.relaxations.map(relaxLine),
        warnings: changeWarnings(plan.edits),
      });
    }
  }
  const r = await applyAsHuman(arbiter, plan.edits, (expected as string[] | undefined) ?? [], {
    reason: `Changed in Settings › Models (${String(body?.["action"])})`,
    requestedBy: "settings",
    approver: SETTINGS_APPROVER,
    moved: MOVED,
    basedOn,
  });
  if (r.body["stale"] === true) r.body["error"] = stale(r.body["changed"]);
  if (r.status === 422 && Array.isArray(r.body["problems"])) r.body["problems"] = formProblems(r.body["problems"] as string[]);
  json(res, r.status, r.status === 200 ? { ...r.body, note: RESTART_NOTE } : r.body);
}

/** policy.yaml `perimeter:` (plan 12 D4) as the probe reads it: the
 *  networks (null when absent or unusable) and the domains, lowercased. */
export function perimeterOfFile(raw: unknown): { networks: string[] | null; domains: string[] } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { networks: null, domains: [] };
  const p = raw as Record<string, unknown>;
  const networks = asTlsConfig({ perimeter: p["networks"] })?.perimeter;
  const domains = Array.isArray(p["domains"])
    ? p["domains"].filter((d): d is string => typeof d === "string").map((d) => d.trim().toLowerCase().replace(/^\*?\./, "").replace(/\.$/, ""))
    : [];
  return { networks: networks ? [...networks] : null, domains };
}

/** A raw `models:` entry from the law in force, defaults applied as the
 *  arbiter compiles it (wire anthropic, local only for a literal true), with
 *  the document's `perimeter` where it applies (plan 12 D4). */
export function probeEntryOf(raw: unknown, perimeterRaw?: unknown): ProbeEntry | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (typeof r["name"] !== "string" || typeof r["url"] !== "string") return null;
  const perimeter = perimeterOfFile(perimeterRaw);
  const network = endpointPlacement(r["url"]) === "network";
  let host = "";
  try { host = new URL(r["url"]).hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, ""); } catch { host = ""; }
  return {
    name: r["name"],
    url: r["url"],
    wire: r["wire"] === "openai-chat" ? "openai-chat" : "anthropic",
    ...(typeof r["model"] === "string" && r["model"] !== "" ? { model: r["model"] } : {}),
    local: r["local"] === true,
    ...(typeof r["token_env"] === "string" && r["token_env"] !== "" ? { tokenEnv: r["token_env"] } : {}),
    ...(r["allow_plain_http"] === true ? { allowPlainHttp: true } : {}),
    ...((): { tls?: EndpointTlsConfig } => { const t = tlsOfFileEntry(r["tls"]); return t ? { tls: t } : {}; })(),
    ...(r["local"] === true && network && perimeter.networks ? { perimeter: perimeter.networks } : {}),
    ...(network && host !== "" && perimeter.domains.some((d) => host === d || host.endsWith(`.${d}`)) ? { orgDomain: true } : {}),
  };
}

/** policy.yaml `tls:` (the file's spelling, `~/` paths) as the probe's
 *  config: absolute paths, the pins as written. undefined when absent or
 *  unusable (the arbiter refused such a file already). Plan 12 D3. */
export function tlsOfFileEntry(raw: unknown, home: string = process.env["HOME"] || homedir()): EndpointTlsConfig | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const t = raw as Record<string, unknown>;
  const path = (v: unknown): string | undefined => {
    if (typeof v !== "string" || v === "") return undefined;
    if (v === "~" || v.startsWith("~/")) return join(home, v.slice(1));
    return isAbsolute(v) ? v : undefined;
  };
  const out: EndpointTlsConfig = {};
  const ca = path(t["ca_file"]);
  if (ca) out.caFile = ca;
  if (Array.isArray(t["pin_sha256"])) {
    const pins = t["pin_sha256"].filter((p): p is string => typeof p === "string" && /^[A-Za-z0-9+/]{43}=$/.test(p));
    if (pins.length > 0) out.pinSha256 = pins;
  }
  const cert = path(t["client_cert"]);
  const key = path(t["client_key"]);
  if (cert && key) { out.clientCert = cert; out.clientKey = key; }
  return Object.keys(out).length > 0 ? out : undefined;
}

export async function postModelTest(
  arbiter: PolicyDocArbiter,
  req: IncomingMessage,
  res: ServerResponse,
  deps: ProbeDeps = realProbeDeps(),
): Promise<void> {
  const body = (await readJson(req)) as Record<string, unknown> | undefined;
  const name = text(body?.["name"]);
  if (name === "") return json(res, 400, { error: "which model?" });
  let inForce: unknown;
  let admin: PolicyDocumentView["admin"];
  try {
    const pd = await arbiter.policyDocument();
    inForce = pd.inForce;
    admin = pd.admin;
  } catch (err) {
    return json(res, isAdminBoundaryError(err) ? 503 : 502, { error: String((err as Error)?.message ?? err) });
  }
  const doc = inForce && typeof inForce === "object" ? (inForce as { models?: unknown; perimeter?: unknown }) : undefined;
  // Plan 12 D5: the administrator's entries are probed too (the user's entry
  // of the same name wins, as the arbiter merges them).
  const perimeter = doc?.perimeter ?? admin?.perimeter;
  const own = Array.isArray(doc?.models) ? (doc!.models as unknown[]) : [];
  const disabled = (m: unknown): boolean => !!m && typeof m === "object" && (m as Record<string, unknown>)["disabled"] === true;
  const raw = own.find((m) => !disabled(m) && (m as Record<string, unknown> | null)?.["name"] === name)
    ?? (own.some((m) => disabled(m) && (m as Record<string, unknown>)["name"] === name) ? undefined : admin?.models.find((m) => m["name"] === name));
  const entry = raw === undefined ? null : probeEntryOf(raw, perimeter);
  if (!entry) return json(res, 404, { error: GONE });
  json(res, 200, { result: await probeModelEndpoint(entry, deps) });
}
