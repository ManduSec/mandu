/**
 * demo/render — what `mandu demo` prints (mandu-demo.md §2). Pure: every
 * function returns text; the orchestrator (demo.ts) writes it as the run
 * progresses, so a recording carries the real timings.
 *
 * The default output speaks plain words: no component names, no raw
 * placeholders, no byte counts. A placeholder the AI got shows as
 * `‹hidden›`. `--verbose` adds the internals as dimmed `·` lines.
 *
 * Mandu-new (no reference origin).
 */
import { docsUrl } from "../docs-url.js";
import { BOUND_HOST, UNBOUND_HOST, type SceneId } from "./fixture.js";

export interface Style {
  bold: (s: string) => string;
  dim: (s: string) => string;
  green: (s: string) => string;
  red: (s: string) => string;
  cyan: (s: string) => string;
}

const id = (s: string): string => s;
export const PLAIN: Style = { bold: id, dim: id, green: id, red: id, cyan: id };
export const ANSI: Style = {
  bold: (s) => `\x1b[1m${s}\x1b[22m`,
  dim: (s) => `\x1b[2m${s}\x1b[22m`,
  green: (s) => `\x1b[32m${s}\x1b[39m`,
  red: (s) => `\x1b[31m${s}\x1b[39m`,
  cyan: (s) => `\x1b[36m${s}\x1b[39m`,
};

/** Color only on a terminal that has not opted out (no-color.org). */
export function pickStyle(isTTY: boolean, env: Record<string, string | undefined>): Style {
  return isTTY && !env["NO_COLOR"] && env["TERM"] !== "dumb" ? ANSI : PLAIN;
}

export type AgentId = "claude" | "codex";
export const AGENT_LABEL: Record<AgentId, string> = { claude: "Claude Code", codex: "Codex" };

export function headerLines(st: Style): string[] {
  return [
    st.bold("Mandu demo: your agent works with your secrets without ever seeing them"),
    st.dim("  A throwaway project with a fake Stripe key. The AI is a local stand-in:"),
    st.dim("  no API key, no login, and nothing leaves this machine."),
    "",
  ];
}

const RULE_WIDTH = 60;

/** `Claude Code ─────────…` */
export function agentHeading(agent: AgentId, st: Style): string {
  const label = AGENT_LABEL[agent];
  return `${st.bold(label)} ${st.dim("─".repeat(Math.max(3, RULE_WIDTH - label.length - 1)))}`;
}

export const SCENE_TITLE: Record<SceneId, string> = {
  1: "The agent reads .env",
  2: `The agent uses the key (curl to ${BOUND_HOST}, where it may go)`,
  3: `…and tries to send it somewhere else (${UNBOUND_HOST})`,
};

const LABEL_COL = 16;

/** `      label           first` + aligned continuation rows. */
export function detailLines(label: string, rows: string[], st: Style, mark?: string): string[] {
  const pad = " ".repeat(6);
  const cont = " ".repeat(6 + LABEL_COL);
  const body = rows.length > 0 ? rows : [""];
  return body.map((r, i) => {
    const text = i === body.length - 1 && mark ? `${r} ${mark}` : r;
    return i === 0 ? `${pad}${st.cyan(label.padEnd(LABEL_COL))}${text}`.trimEnd() : `${cont}${text}`.trimEnd();
  });
}

/** A dimmed internal line (`--verbose` only). */
export function verboseLine(text: string, st: Style): string {
  return st.dim(`      · ${text}`);
}

/** `  · started the model-API proxy (anthropic-proxy) ..... 0.3s` (`--verbose`). */
export function serviceLine(label: string, ms: number, st: Style): string {
  return st.dim(`  · started ${label} (${(ms / 1000).toFixed(1)}s)`);
}

/** What one scene showed and whether its checks held. */
export interface SceneView {
  scene: SceneId;
  ok: boolean;
  /** Plain-words reason when a check failed. */
  why?: string;
  /** Scene 1: the AI's view of `.env` (placeholders as ‹hidden›) and yours. */
  aiGot?: string[];
  /** Scene 1: the AI got the file as one placeholder, not per key (a shell
   *  read with no guard on this machine, guard.ts). */
  wholeFile?: boolean;
  youSee?: string[];
  /** Skipped (curl or openssl missing): the reason. */
  skipped?: string;
  /** Internals for `--verbose`. */
  verbose: string[];
}

/** The lines of one scene, in the approved layout. */
export function sceneLines(v: SceneView, st: Style, verbose: boolean): string[] {
  const out = [` ${st.bold(String(v.scene))}  ${SCENE_TITLE[v.scene]}`];
  const okMark = st.green("✓");
  if (v.skipped !== undefined) {
    out.push(...detailLines("skipped", [v.skipped], st));
  } else if (v.scene === 1) {
    out.push(...detailLines("the AI got", v.aiGot ?? [], st));
    out.push(...detailLines("you see", v.youSee ?? [], st));
  } else if (v.scene === 2 && v.ok) {
    out.push(...detailLines("sent", [`${BOUND_HOST} got the real key, filled in on the way out`], st, okMark));
  } else if (v.scene === 3 && v.ok) {
    out.push(...detailLines("stopped", [`nothing was sent to ${UNBOUND_HOST};`, "in a real session the dashboard asks you"], st, okMark));
  }
  if (!v.ok && v.skipped === undefined) out.push(...detailLines("✗ failed", [v.why ?? "a check did not hold"], st).map((l) => st.red(l)));
  if (verbose) out.push(...v.verbose.map((l) => verboseLine(l, st)));
  return out;
}

/** The compact form of a second agent whose scenes all passed:
 *  ` 1 · 2 · 3       the same three steps, through Codex  ✓ ✓ ✓`. */
export function compactLine(agent: AgentId, scenes: SceneView[], st: Style): string {
  const marks = scenes.map((s) => (s.skipped !== undefined ? st.dim("–") : s.ok ? st.green("✓") : st.red("✗"))).join(" ");
  return ` ${st.bold("1 · 2 · 3")}${" ".repeat(LABEL_COL - 4)}the same three steps, through ${AGENT_LABEL[agent]}  ${marks}`;
}

export interface Summary {
  ok: boolean;
  /** Set when the demo could not run at all. */
  error?: string;
  /** Plain-words failures (one per failed check). */
  failures: string[];
  /** True when scenes 2 and 3 were skipped (no curl / openssl). */
  skippedNetwork: boolean;
}

/** The closing lines: the one-line result, then where to go next. */
export function summaryLines(s: Summary, st: Style): string[] {
  const next = ["", `Next: try it with your own agent → ${docsUrl("docs/first-session.md")}`];
  if (s.error !== undefined) return [st.red(`✗ the demo could not run: ${s.error}`), ...next];
  if (!s.ok) return [st.red(`✗ FAILED: ${s.failures.join("; ")}`), ...next];
  const line = s.skippedNetwork
    ? `${st.green("✓")} The AI never got the key, and you saw it. (Steps 2 and 3 need curl and openssl.)`
    : `${st.green("✓")} The AI never got the key. It went only to ${BOUND_HOST}, and you saw it.`;
  return [line, ...next];
}
