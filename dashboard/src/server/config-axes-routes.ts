/**
 * server/config-axes-routes — the Protection drawer's durable axis
 * configuration (`GET|POST /api/config/axes`, dashboard.md §4.19 section ②):
 * the protection MODE (one of four names over the two axes,
 * docs/design/architecture/protection-modes.md) and the two boot-time capability switches
 * (`integrity`, `confidentiality`) in the launcher's unified config file. These are BOOT-TIME flags — a POST here
 * changes what the next arbiter (re)start runs, never the live process; the
 * drawer's pending bar owns saying so.
 *
 * Thin over src/config-axes.ts (the pure read/parse/surgical-write module —
 * see its provenance header: launcher/src/config.ts is the precedence source
 * of truth). Route-layer rules mirror secrets-routes.ts: a non-boolean value
 * is REJECTED with 400, never coerced (a config act is explicit or it is not
 * an act); a write that failed answers 500, never a 200 that lets the human
 * believe a standing config now exists when it does not.
 *
 * THE AUDIT TRAIL (§4.19, the deferred item closed): every APPLIED axis change
 * — one whose next-boot `effective` value actually flipped — lands one
 * `config_change` event in the reserved `arbiter-admin` stream via the
 * arbiter's opaque `emit` op, mirroring the arbiter's own posture_change
 * discipline (a no-op write emits nothing; refused acts emit nothing). It
 * carries the TOP-LEVEL SCALARS `axis`/`from`/`to`/`requestedBy` the SIEM
 * rules key on (100224/100225 — the exporter's redactor passes scalars
 * through) and no symbol value (a config act is not data). BEST-EFFORT: an
 * emit failure (or no connected arbiter) never fails the POST — the config
 * write is the act, the event is its record. Turning protection OFF is the
 * more consequential act than pausing egress, so it gets the same who/when
 * trail; the GET shape's `audit` block feeds that attribution back to the
 * "⚠ Not protected" off-state banner.
 *
 * THE INTEGRITY FREEZE (docs/design/architecture/protection-modes.md §10): a POST whose
 * resulting pair leaves the integrity axis ON is refused with 403
 * `{error, frozen: true}` unless the dashboard's own env carries
 * MANDU_EXPERIMENTAL_INTEGRITY=1 (the GET says which via `integrityAllowed`).
 * Refused before anything is written or emitted. Turning it off is never
 * refused.
 */

import { randomBytes } from "node:crypto";
import { type IncomingMessage, type ServerResponse } from "node:http";

import { json, readJson } from "./http-util.js";
import {
  AXIS_KEYS,
  INTEGRITY_OPT_IN_ENV,
  MODE_AXES,
  MODES,
  integrityOptedIn,
  isMode,
  readAxesState,
  writeAxes,
  writeMode,
  type AxesState,
  type AxesUpdate,
  type AxisKey,
  type Mode,
} from "../config-axes.js";

type Env = Record<string, string | undefined>;

/**
 * The NARROW arbiter surface the audit trail rides (the arbiter-client
 * pattern, beside ApprovalsArbiter/SecretsArbiter/PostureArbiter in
 * attachArbiterSurfaces): the arbiter's opaque observability `emit` op plus
 * the `events` read-back the GET-side attribution uses. server-main wires the
 * real IPC client behind this; the tests inject an in-memory fake. Absent ⇒
 * the routes still work in full (the config edit must work exactly when the
 * arbiter is down for the restart the edit is about) — only the audit
 * event/attribution is skipped.
 */
export interface ConfigAuditArbiter {
  /** Append one opaque event (arbiter assigns seq). Fire-and-forget contract:
   *  a rejection means "not persisted", nothing more. */
  emit(event: Record<string, unknown>): Promise<number>;
  /** Persisted events for a session in seq order. */
  events(sessionId: string, sinceSeq?: number): Promise<Record<string, unknown>[]>;
}

/** Who a dashboard-routed config act is attributed to — same constant the
 *  posture route sends (`requestedBy: "dashboard"`). */
export const CONFIG_REQUESTED_BY = "dashboard";

/** The reserved arbiter-global audit stream (policy-surface.md §9.6). */
const AUDIT_SESSION = "arbiter-admin";

/** The GET/POST answer's per-axis attribution: the LATEST config_change the
 *  audit stream holds for that axis. `from`/`to` are the effective next-boot
 *  values the act moved between. */
export interface AxisChangeAudit {
  ts: string;
  from: boolean;
  to: boolean;
  requestedBy: string | null;
}

/** The §4.19 answer shape: the frozen AxesState, plus `audit` when a
 *  connected arbiter's stream had config_change events to attribute. */
export type AxesStateWithAudit = AxesState & {
  audit?: Partial<Record<AxisKey, AxisChangeAudit>>;
};

/**
 * Build one `config_change` audit event (exported for the tests — the shape
 * mirrors the arbiter's emitPostureChange: id spelling, arbiter-admin stream,
 * top-level SIEM scalars, DualReprs carrying prose only, never a symbol
 * value).
 */
export function buildConfigChangeEvent(
  axis: AxisKey,
  from: boolean,
  to: boolean,
): Record<string, unknown> {
  const word = (v: boolean): string => (v ? "on" : "off");
  return {
    id: `ev_${Date.now().toString(36)}${randomBytes(5).toString("hex")}`,
    sessionId: AUDIT_SESSION,
    turn: 0,
    ts: new Date().toISOString(),
    callId: null,
    kind: "config_change",
    view: "HumanView",
    boundary: "model_context",
    emitter: "dashboard",
    // Top-level scalars the SIEM rules key on (survive the exporter's redact).
    axis,
    from,
    to,
    requestedBy: CONFIG_REQUESTED_BY,
    input: {
      symbolized: `protection axis ${axis}: ${word(from)} → ${word(to)} (requested by ${CONFIG_REQUESTED_BY})`,
      original: null, differs: false, symbols: [],
    },
    output: {
      symbolized: to
        ? `${axis} protection ON at the next service start`
        : `${axis} protection turned OFF — applies at the next service start`,
      original: null, differs: false, symbols: [],
    },
    invariant: { violatedInvariant: false },
    policy: {
      reason: `config.toml ${axis} set to ${to} via the Protection drawer (boot-time; applies on restart)`,
    },
  };
}

/** Reduce the audit stream to the LATEST config_change per axis. Events
 *  arrive in seq order, so last-write-wins is the reduction. */
export function latestAxisAudit(
  events: Record<string, unknown>[],
): Partial<Record<AxisKey, AxisChangeAudit>> {
  const out: Partial<Record<AxisKey, AxisChangeAudit>> = {};
  for (const ev of events) {
    if (ev["kind"] !== "config_change") continue;
    const axis = ev["axis"];
    if (axis !== "integrity" && axis !== "confidentiality") continue;
    if (typeof ev["ts"] !== "string" || typeof ev["from"] !== "boolean" || typeof ev["to"] !== "boolean") {
      continue;
    }
    out[axis] = {
      ts: ev["ts"],
      from: ev["from"],
      to: ev["to"],
      requestedBy: typeof ev["requestedBy"] === "string" ? ev["requestedBy"] : null,
    };
  }
  return out;
}

/** Attach the audit attribution to an AxesState — BEST-EFFORT: no arbiter, an
 *  events failure, or an empty stream all yield the state unchanged (the axes
 *  facts are the point; the attribution is their garnish). */
async function withAudit(
  state: AxesState,
  audit: ConfigAuditArbiter | undefined,
): Promise<AxesStateWithAudit> {
  if (!audit) return state;
  try {
    const latest = latestAxisAudit(await audit.events(AUDIT_SESSION));
    return Object.keys(latest).length > 0 ? { ...state, audit: latest } : state;
  } catch {
    return state;
  }
}

/** GET /api/config/axes → the §4.19 frozen shape ({ok, path, exists,
 *  configured, defaults, effective}, additively {mode, badMode?,
 *  effectiveMode, defaultMode}, plus `audit` when the arbiter-admin
 *  stream attributes a past change). A read — no CSRF (server.ts). */
export async function getConfigAxes(
  env: Env,
  audit: ConfigAuditArbiter | undefined,
  res: ServerResponse,
): Promise<void> {
  json(res, 200, await withAudit(readAxesState(env), audit));
}

/** A validated POST act: a whole MODE (the level picker), or single AXIS keys
 *  (the expert Machinery panel). Never both. */
type AxesAct = { kind: "mode"; mode: Mode } | { kind: "axes"; updates: AxesUpdate };

/** Parse + VALIDATE a POST body. Returns an error string (→ 400) rather than
 *  throwing, and never coerces. The body is EITHER `{mode}` (one of the four
 *  names, exact spelling) OR at least one axis key; a body mixing the two is
 *  refused (which of them wins would be a guess), and an empty POST is not a
 *  configuration act. */
function parseAxesBody(raw: unknown): AxesAct | string {
  if (raw === undefined || raw === null || typeof raw !== "object") {
    return "invalid JSON body";
  }
  const b = raw as Record<string, unknown>;
  if (b["mode"] !== undefined) {
    if (AXIS_KEYS.some((k) => b[k] !== undefined)) {
      return `body sets either mode or the axis keys (${AXIS_KEYS.join(", ")}), never both`;
    }
    if (!isMode(b["mode"])) {
      return `mode must be one of: ${MODES.join(", ")} (got ${JSON.stringify(b["mode"])})`;
    }
    return { kind: "mode", mode: b["mode"] };
  }
  const updates: AxesUpdate = {};
  for (const key of AXIS_KEYS) {
    const v = b[key];
    if (v === undefined) continue;
    if (typeof v !== "boolean") {
      return `${key} must be a boolean (got ${JSON.stringify(v)} — a value is never coerced)`;
    }
    updates[key] = v;
  }
  if (Object.keys(updates).length === 0) {
    return `body must set mode, or at least one of: ${AXIS_KEYS.join(", ")}`;
  }
  return { kind: "axes", updates };
}

/** POST /api/config/axes {mode} | {integrity?, confidentiality?} → surgical
 *  config edit (applyModeEdit / applyAxesEdit: both keep the file
 *  self-consistent), then the GET shape. CSRF-gated by server.ts. Every axis whose
 *  effective next-boot value FLIPPED emits one best-effort `config_change`
 *  audit event (awaited so the answer's `audit` block already reflects the
 *  act; a failure is logged by the caller's contract — never a failed POST). */
export async function postConfigAxes(
  env: Env,
  audit: ConfigAuditArbiter | undefined,
  req: IncomingMessage,
  res: ServerResponse,
  log: (msg: string) => void = () => {},
): Promise<void> {
  const parsed = parseAxesBody(await readJson(req));
  if (typeof parsed === "string") {
    json(res, 400, { error: parsed });
    return;
  }
  // The integrity axis is frozen (docs/design/architecture/protection-modes.md §10): a saved
  // pair with it ON makes the next arbiter start refuse without the opt-in, so
  // no write may leave it on here without that opt-in. The test is the pair
  // the write RESULTS in (a {mode}, or the named key, else the axis's current
  // effective value): `mode: "injection"`, `integrity: true`, and also a
  // `confidentiality` flip while integrity is still on. Turning it OFF (mode
  // secrets / off, integrity false) always stays open.
  const prior = readAxesState(env);
  const integrityAfter =
    parsed.kind === "mode"
      ? MODE_AXES[parsed.mode].integrity
      : (parsed.updates.integrity ?? prior.effective.integrity);
  if (integrityAfter && !integrityOptedIn(env)) {
    json(res, 403, {
      error:
        `the integrity axis (modes injection and full) is frozen: a write that leaves it on is refused ` +
        `unless the dashboard runs with ${INTEGRITY_OPT_IN_ENV}=1; turn it off first (mode secrets or off)`,
      frozen: true,
    });
    return;
  }
  let next: AxesState;
  try {
    next = parsed.kind === "mode" ? writeMode(env, parsed.mode) : writeAxes(env, parsed.updates);
  } catch (err) {
    // The config was NOT written (unresolvable path / FS failure). Say so.
    json(res, 500, { error: (err as Error).message });
    return;
  }
  if (audit) {
    // One event per axis whose EFFECTIVE value flipped — a write that changed
    // only the file spelling (e.g. making a default explicit) is a no-op in
    // effect and emits nothing, the posture_change applied-only discipline.
    // A MODE write speaks for both axes, so both are compared; a single-axis
    // write can only flip the axes it named (its mode-line re-align restates
    // the resulting pair, it never moves the other axis).
    for (const axis of AXIS_KEYS) {
      const from = prior.effective[axis];
      const to = next.effective[axis];
      if (parsed.kind === "axes" && parsed.updates[axis] === undefined) continue;
      if (from === to) continue;
      try {
        await audit.emit(buildConfigChangeEvent(axis, from, to));
      } catch (err) {
        log(`config_change emit failed (audit only): ${(err as Error).message}`);
      }
    }
  }
  json(res, 200, await withAudit(next, audit));
}
