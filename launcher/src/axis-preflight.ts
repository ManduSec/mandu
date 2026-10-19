/**
 * axis-preflight — refuse a launch whose explicit axis flag cannot take effect.
 *
 * The integrity / confidentiality axes are ARBITER-owned and read ONCE at
 * arbiter start (confidentiality.md §11). run.ts hands `--no-integrity` /
 * `--confidentiality` … to the daemon THIS launch starts — but when a resident
 * arbiter already owns the socket (the shared stack, a dev arbiter), nothing
 * is started and the flag silently changes nothing in the arbiter, while the
 * launcher-side implications still apply (`--no-integrity` forces fs-sync
 * OFF). The result is a half-posture nobody asked for: found 2026-09-19 when
 * the watch catalog's integrity-OFF control (C7) ran `mandu --no-integrity
 * claude` against the resident int-ON arbiter — raw CWD, no sensitive-path
 * gate, and `declassify_symbol` REFUSED the datum as untrusted-integrity,
 * because the axis the flag named was never off.
 *
 * Rule: an axis the launch set EXPLICITLY must equal what the attached arbiter
 * reports; a mismatch refuses before any service starts. An axis left unset
 * is never checked (the arbiter's own posture stands). An arbiter that cannot
 * report its axes (older build, hello unanswered) passes with a warning —
 * the same fail-soft as the tenant preflight: this guards honesty of the
 * posture, not the security invariant (which the arbiter enforces either way).
 *
 * PROVENANCE: NEW Mandu code; mirrors tenant-preflight.ts.
 */
import { connect } from "node:net";
import { modeOf } from "./mode.js";

export interface ArbiterAxes {
  integrity?: boolean;
  confidentiality?: boolean;
}

const pairName = (a: ArbiterAxes): string | undefined =>
  a.integrity === undefined || a.confidentiality === undefined
    ? undefined
    : modeOf({ integrity: a.integrity, confidentiality: a.confidentiality });

/**
 * The refusal (protection-modes.md §3.4, decided 2026-09-21: refuse, do not
 * start a second arbiter). It names the running mode and the two ways out.
 * A per-launch second arbiter was weighed and rejected for v1: the dashboard
 * and its approval inbox attach to ONE arbiter, so a `full` session on a
 * private arbiter would raise egress approvals nobody can answer, and two
 * symbol DBs alternating over one workspace re-seed each other's AgentView
 * twins (the dangling-twin guard in fs-sync).
 */
export class AxisMismatchError extends Error {
  constructor(
    readonly axis: "integrity" | "confidentiality",
    readonly wanted: boolean,
    sock: string,
    actual: ArbiterAxes = {},
    wantedAxes: ArbiterAxes = {},
  ) {
    const running = pairName(actual);
    const asked = pairName({ ...actual, ...wantedAxes });
    const flag = `--${wanted ? "" : "no-"}${axis}`;
    super(
      `mandu: ${asked ? `mode ${asked}` : flag} cannot take effect: the protection service at ${sock} is already running ` +
        `${running ? `in mode ${running}` : `with ${axis}=${wanted ? "OFF" : "ON"}`}, and the mode is read once when it starts ` +
        `(${axis} would have to be ${wanted ? "ON" : "OFF"}). Either launch without the mode flag to join it as it is, ` +
        `or change it for every session: \`mandu mode ${asked ?? "<name>"}\`, then \`mandu stop\`, then launch again ` +
        `(other running sessions end with it). For a side-by-side test arbiter: ` +
        `MANDU_${axis.toUpperCase()}=${wanted ? "1" : "0"} scripts/dev-arbiter.sh, then MANDU_ARBITER_SOCK=<its sock>.`,
    );
    this.name = "AxisMismatchError";
  }
}

function ask(sock: string, op: string, timeoutMs: number): Promise<Record<string, unknown> | undefined> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: Record<string, unknown> | undefined): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { s.destroy(); } catch { /* already gone */ }
      resolve(v);
    };
    const timer = setTimeout(() => finish(undefined), timeoutMs);
    const s = connect(sock);
    let buf = "";
    s.setEncoding("utf8");
    s.once("connect", () => s.write(JSON.stringify({ id: "axis-preflight", op }) + "\n"));
    s.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl)) as { ok?: boolean; result?: Record<string, unknown> };
        finish(resp.ok && resp.result && typeof resp.result === "object" ? resp.result : undefined);
      } catch {
        finish(undefined);
      }
    });
    s.once("error", () => finish(undefined));
  });
}

/** The axes the arbiter reports: `hello` first (top-level fields), then
 *  `policySnapshot.posture` as the fallback. A field is undefined when the arbiter does not report it. */
export async function readArbiterAxes(
  sock: string, timeoutMs = 3000, opts: { helloOnly?: boolean } = {},
): Promise<ArbiterAxes> {
  const pick = (o: unknown): ArbiterAxes => {
    const r = (o ?? {}) as Record<string, unknown>;
    return {
      ...(typeof r["integrity"] === "boolean" ? { integrity: r["integrity"] as boolean } : {}),
      ...(typeof r["confidentiality"] === "boolean" ? { confidentiality: r["confidentiality"] as boolean } : {}),
    };
  };
  // The live `hello` reply carries the axes at its TOP level (beside pid /
  // gitRev / tenant); a nested `identity` object is accepted too.
  const hello = await ask(sock, "hello", timeoutMs);
  const fromHello = { ...pick(hello?.["identity"]), ...pick(hello) };
  if (fromHello.integrity !== undefined && fromHello.confidentiality !== undefined) return fromHello;
  if (opts.helloOnly) return fromHello;
  const snap = await ask(sock, "policySnapshot", timeoutMs);
  return { ...pick(snap?.["posture"]), ...fromHello };
}

/** Throw {@link AxisMismatchError} when an EXPLICITLY requested axis differs
 *  from what the attached arbiter runs. Returns what it learned. */
export async function assertArbiterAxes(
  sock: string,
  wanted: ArbiterAxes,
  opts: { timeoutMs?: number; warn?: (msg: string) => void; readAlways?: boolean } = {},
): Promise<ArbiterAxes> {
  // readAlways (run.ts): the launcher needs the arbiter's REAL pair even when
  // it requested nothing, to derive the effective mode (mode.ts effectiveAxes).
  const nothingWanted = wanted.integrity === undefined && wanted.confidentiality === undefined;
  if (nothingWanted && !opts.readAlways) return {};
  // Nothing to refuse ⇒ this read is informational: one short `hello`, no
  // fallback op, so a mute arbiter costs the launch one second, not six.
  const actual = nothingWanted
    ? await readArbiterAxes(sock, opts.timeoutMs ?? 1000, { helloOnly: true })
    : await readArbiterAxes(sock, opts.timeoutMs);
  for (const axis of ["integrity", "confidentiality"] as const) {
    const want = wanted[axis];
    if (want === undefined) continue;
    const have = actual[axis];
    if (have === undefined) {
      opts.warn?.(`mandu: could not read the arbiter's ${axis} axis from ${sock} — --${want ? "" : "no-"}${axis} may not be in effect`);
      continue;
    }
    if (have !== want) throw new AxisMismatchError(axis, want, sock, actual, wanted);
  }
  return actual;
}
