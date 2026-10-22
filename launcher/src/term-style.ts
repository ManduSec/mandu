/**
 * term-style — the launcher's terminal colours: ANSI SGR wrappers, and the
 * one rule for when to use them. `mandu demo` (demo/render.ts) and `mandu
 * scan` (scan-command.ts) word their output through a `Style`, so the same
 * text renders plain or coloured. Pure.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin); lifted out of demo/render.ts, which defined it first.
 */

export interface Style {
  bold: (s: string) => string;
  dim: (s: string) => string;
  green: (s: string) => string;
  red: (s: string) => string;
  yellow: (s: string) => string;
  cyan: (s: string) => string;
}

const id = (s: string): string => s;
export const PLAIN: Style = { bold: id, dim: id, green: id, red: id, yellow: id, cyan: id };
export const ANSI: Style = {
  bold: (s) => `\x1b[1m${s}\x1b[22m`,
  dim: (s) => `\x1b[2m${s}\x1b[22m`,
  green: (s) => `\x1b[32m${s}\x1b[39m`,
  red: (s) => `\x1b[31m${s}\x1b[39m`,
  yellow: (s) => `\x1b[33m${s}\x1b[39m`,
  cyan: (s) => `\x1b[36m${s}\x1b[39m`,
};

/** The colours, or none. */
export function colors(enabled: boolean): Style {
  return enabled ? ANSI : PLAIN;
}

/**
 * Colour on? A non-empty FORCE_COLOR forces it (any value but `0` or `false`, as
 * Node reads it, ahead of NO_COLOR); else only on a terminal, with NO_COLOR
 * unset or empty (https://no-color.org) and a TERM that is not `dumb`. A
 * pipe, a file and a test's captured output get none.
 */
export function colorOn(isTTY: boolean, env: Record<string, string | undefined>): boolean {
  const force = env["FORCE_COLOR"];
  if (force !== undefined && force !== "") return force !== "0" && force.toLowerCase() !== "false";
  return isTTY && !env["NO_COLOR"] && env["TERM"] !== "dumb";
}

/** Text with its SGR codes taken out (what a pipe would have read). */
export function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}
