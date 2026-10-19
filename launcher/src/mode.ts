/**
 * mode — the four named protection modes over the two arbiter axes
 * (docs/design/architecture/protection-modes.md). THE source of truth for the mode table
 * and the launcher-side default; the dashboard (dashboard/src/config-axes.ts)
 * and the per-package test helpers (test/axes.ts) mirror the table, and
 * tests/stack/axis-defaults-parity.test.ts fails when they drift.
 *
 *   mode        confidentiality  integrity
 *   secrets     ON               OFF        keys and credentials cannot leave
 *   injection   OFF              ON         untrusted text cannot steer the agent
 *   full        ON               ON         both
 *   off         OFF              OFF        Mandu observes, enforces nothing
 *
 * Resolution (§3.2). Three LEVELS can speak: flags, env, config file, in that
 * precedence. Inside one level an explicit axis (`--no-integrity`,
 * MANDU_INTEGRITY, `integrity = …`) beats that level's mode FOR THAT AXIS
 * ONLY; across levels the first level that says anything about an axis wins
 * it. Nothing said anywhere ⇒ the axis is left to the arbiter (a running
 * arbiter's posture stands; a cold start runs DEFAULT_MODE).
 *
 * FROZEN INTEGRITY (2026-09-28, docs/design/architecture/protection-modes.md §10): the two
 * modes that turn the integrity axis ON (`injection`, `full`) are frozen. They
 * stay in the table (a running arbiter may report them, and the frozen lane
 * still runs them) but a launch or `mandu mode` refuses them unless
 * MANDU_EXPERIMENTAL_INTEGRITY=1, and the help lists only PRODUCT_MODES.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
export const MODES = ["secrets", "injection", "full", "off"] as const;
export type Mode = (typeof MODES)[number];

export interface Axes {
  integrity: boolean;
  confidentiality: boolean;
}

export const MODE_AXES: Record<Mode, Axes> = {
  secrets: { integrity: false, confidentiality: true },
  injection: { integrity: true, confidentiality: false },
  full: { integrity: true, confidentiality: true },
  off: { integrity: false, confidentiality: false },
};

/** The mode a COLD arbiter start runs when nothing states the axes. Must equal
 *  the arbiter flag modules' built-in defaults (the parity test checks). */
export const DEFAULT_MODE: Mode = "secrets";

/** The modes the product offers. The rest are frozen (integrity ON). */
export const PRODUCT_MODES: readonly Mode[] = ["secrets", "off"];

/** The opt-in that unlocks the frozen integrity modes. Mirrors
 *  arbiter/policy/integrity-flag.ts INTEGRITY_OPT_IN_ENV (the parity test). */
export const INTEGRITY_OPT_IN_ENV = "MANDU_EXPERIMENTAL_INTEGRITY";

/** Only an explicit "1"/"true"/"on"/"yes" opts in (the arbiter's rule). */
export function integrityOptedIn(env: Record<string, string | undefined>): boolean {
  const v = (env[INTEGRITY_OPT_IN_ENV] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "on" || v === "yes";
}

/** The refusal for a request that turns integrity ON without the opt-in. */
export function integrityFrozenMessage(source: string): string {
  return (
    `mandu: the integrity axis (modes injection and full; here asked for by ${source}) is frozen ` +
    `(docs/design/architecture/protection-modes.md). Use mode secrets (the default) or off, or set ` +
    `${INTEGRITY_OPT_IN_ENV}=1 to run the frozen axis as is.`
  );
}

/** The axis env a launch hands the arbiter daemon it starts (the axes are
 *  arbiter-owned, confidentiality.md §11). An axis not requested passes
 *  nothing, so a variable the user exported still wins. A request that turns
 *  integrity ON also forwards the opt-in: parse() admitted it only because the
 *  launch's env opted in, and the daemon checks the opt-in again in its OWN
 *  env (arbiter/policy/integrity-flag.ts assertIntegrityAllowed), which is
 *  inherited from process.env and need not carry what main()'s env did. */
export function arbiterAxisEnv(requested: RequestedAxes): Record<string, string> {
  return {
    ...(requested.confidentiality === undefined ? {} : { MANDU_CONFIDENTIALITY: requested.confidentiality ? "1" : "0" }),
    ...(requested.integrity === undefined ? {} : { MANDU_INTEGRITY: requested.integrity ? "1" : "0" }),
    ...(requested.integrity === true ? { [INTEGRITY_OPT_IN_ENV]: "1" } : {}),
  };
}

/** One plain sentence per mode, for `--help`, `mandu mode` and the banner. */
export const MODE_SUMMARY: Record<Mode, string> = {
  secrets: "your keys and credentials cannot leave; untrusted text is not masked",
  injection: "untrusted text cannot steer the agent; secret files behave like ordinary files",
  full: "both: credentials cannot leave, and untrusted text cannot steer the agent",
  off: "Mandu observes and records, and enforces nothing",
};

/** Every axis pair has exactly one name. */
export function modeOf(axes: Axes): Mode {
  if (axes.confidentiality) return axes.integrity ? "full" : "secrets";
  return axes.integrity ? "injection" : "off";
}

export function isMode(v: string): v is Mode {
  return (MODES as readonly string[]).includes(v);
}

/** Parse a user-supplied mode name; an unknown name is a usage error that
 *  lists the four, never a silent default. Empty/undefined ⇒ undefined. */
export function parseMode(v: string | undefined, source: string): Mode | undefined {
  if (v === undefined) return undefined;
  const s = v.trim().toLowerCase();
  if (s === "") return undefined;
  if (isMode(s)) return s;
  throw new Error(`mandu: ${source}: unknown mode '${v}' (want ${MODES.join("|")})`);
}

/** What one precedence level says: a mode, and/or explicit axes. */
export interface AxisLevel {
  mode?: Mode | undefined;
  integrity?: boolean | undefined;
  confidentiality?: boolean | undefined;
}

/** What the launch REQUESTS per axis (undefined = leave it to the arbiter). */
export interface RequestedAxes {
  integrity?: boolean;
  confidentiality?: boolean;
}

/** Resolve the precedence levels (highest first) into the requested axes. */
export function resolveRequestedAxes(levels: readonly AxisLevel[]): RequestedAxes {
  const out: RequestedAxes = {};
  for (const axis of ["integrity", "confidentiality"] as const) {
    for (const level of levels) {
      const v = level[axis] ?? (level.mode !== undefined ? MODE_AXES[level.mode][axis] : undefined);
      if (v !== undefined) { out[axis] = v; break; }
    }
  }
  return out;
}

/** The pair a launch actually runs under: what the attached arbiter reports
 *  wins (the axes are arbiter-owned, read once at its start); an axis it does
 *  not report falls back to the request, then to DEFAULT_MODE. */
export function effectiveAxes(requested: RequestedAxes, reported: RequestedAxes): Axes {
  const d = MODE_AXES[DEFAULT_MODE];
  return {
    integrity: reported.integrity ?? requested.integrity ?? d.integrity,
    confidentiality: reported.confidentiality ?? requested.confidentiality ?? d.confidentiality,
  };
}

/** The `--help` block that lists the product modes (default marked), then
 *  one line naming the frozen ones and their opt-in. */
export function modeHelpLines(): string[] {
  return [
    ...PRODUCT_MODES.map((m) => `  ${m.padEnd(10)} ${MODE_SUMMARY[m]}${m === DEFAULT_MODE ? "  (default)" : ""}`),
    `  (frozen: ${MODES.filter((m) => !PRODUCT_MODES.includes(m)).join(", ")}; need ${INTEGRITY_OPT_IN_ENV}=1)`,
  ];
}
