/**
 * revert-command — `mandu revert` (comparisons.md §3.8): undo what the
 * agent wrote in this workspace, back to an earlier write, over fs-sync's
 * shadow repository (fs-sync.md §3; fs-sync/src/revert.ts, lifted
 * from adfi's revert design). The machinery existed; this is the verb.
 *
 *   mandu revert                 list the agent's writes (numbered)
 *   mandu revert --to N          show what returning to write N changes, ask, then do it
 *   mandu revert --to N --yes    ... without asking (a script, CI)
 *   --json                         the raw answer
 *
 * History exists only where fs-sync tracked the workspace: the `injection`
 * and `full` modes. The shadow repo keeps the abandoned writes, and the
 * user's own git history is never touched (a revert is working-tree change).
 * Files you changed after the chosen write are overwritten; the plan says
 * which before anything happens.
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import type { Layout } from "./services/layout.js";
import { hardenedGitArgs, hardenedGitEnv } from "./hardened-git.js";
import type { Env } from "./doctor-live.js";

export interface HistoryCycle { number: number; timestamp: string; files: string[]; tool: string; human?: boolean }
export interface RevertPlanOut { ok: true; reverted: boolean; to: number; timestamp: string; abandoned: number; kept: number; removed: string[] }

export interface RevertDeps {
  /** Run the fs-sync CLI (`history` / `revert`) and return its one JSON line. */
  fsCli: (args: string[]) => { code: number; stdout: string; stderr: string };
  gitRoot: (cwd: string) => string | null;
  cwd: () => string;
  isTTY: () => boolean;
  confirm: (question: string) => Promise<boolean>;
  /** Where the command's report goes (default: process.stdout). Tests pass a
   *  collector: patching process.stdout.write swallows the test runner's own
   *  report, which shares the stream. */
  out?: (s: string) => void;
}

export function realRevertDeps(layout: Layout, env: Env): RevertDeps {
  return {
    fsCli: (args) => {
      const cli = layout.fsSyncCli();
      const r = spawnSync(cli.cmd, [...cli.baseArgs, ...args], {
        cwd: cli.cwd, encoding: "utf8", timeout: 120_000,
        env: { ...(env as NodeJS.ProcessEnv), ...cli.env },
      });
      return { code: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? (r.error?.message ?? "") };
    },
    gitRoot: (cwd) => {
      // Hardened (hardened-git.ts): the workspace is the agent's to configure.
      const r = spawnSync("git", hardenedGitArgs(["-C", cwd, "rev-parse", "--show-toplevel"]), { encoding: "utf8", env: hardenedGitEnv() });
      return r.status === 0 ? r.stdout.trim() : null;
    },
    cwd: () => process.cwd(),
    isTTY: () => process.stdin.isTTY === true && process.stdout.isTTY === true,
    confirm: async (q) => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try { return /^y(es)?$/i.test((await rl.question(q)).trim()); } finally { rl.close(); }
    },
  };
}

export function renderHistory(ws: string, cycles: HistoryCycle[]): string {
  if (cycles.length === 0) return `${ws}: no writes recorded yet\n`;
  const L = [`${ws}: ${cycles.length} write${cycles.length === 1 ? "" : "s"} recorded (mandu revert --to <N> returns to one)`];
  for (const c of cycles) {
    const who = c.human ? "you" : c.tool || "agent";
    const files = c.files.length ? `${c.files.slice(0, 4).join(", ")}${c.files.length > 4 ? `, +${c.files.length - 4} more` : ""}` : "(files not recorded)";
    L.push(`  #${String(c.number).padEnd(4)} ${c.timestamp.replace("T", " ").slice(0, 19)}  ${who.padEnd(10)} ${files}`);
  }
  return L.join("\n") + "\n";
}

export function renderPlan(p: RevertPlanOut): string {
  const L = [`Returning to write #${p.to} (${p.timestamp.replace("T", " ").slice(0, 19)}):`];
  L.push(`  ${p.abandoned} later write${p.abandoned === 1 ? "" : "s"} undone (kept in Mandu's history, not in your git history)`);
  L.push(p.removed.length ? `  removed: ${p.removed.join(", ")}` : "  no file is removed");
  L.push(`  ${p.kept} file${p.kept === 1 ? "" : "s"} restored to their state at write #${p.to}; changes you made after it are overwritten`);
  return L.join("\n") + "\n";
}

/** The fs-sync CLI's failure, in the words `mandu revert` uses: its
 *  internal `[fs-sync-cli]` prefix dropped, the common cases explained. */
export function plainRevertError(stderr: string, code: number, ws: string): string {
  const msg = stderr.trim().split("\n").map((l) => l.replace(/^\[fs-sync-cli\]\s*/, "")).join("\n").trim();
  if (/no Mandu history/.test(msg)) {
    return `no Mandu history for ${ws}: Mandu records the agent's writes only in the injection and full modes, which are frozen (docs/design/architecture/protection-modes.md), so there is nothing to undo here`;
  }
  const missing = /Write #(\d+) not found \((\d+) write cycles? exists?\)/.exec(msg);
  if (missing) return `there is no write #${missing[1]}: ${missing[2]} write${missing[2] === "1" ? " is" : "s are"} recorded (\`mandu revert\` lists them)`;
  return msg || `the history tool stopped with code ${code}`;
}

/** `mandu revert [--to N] [--yes] [--json]`. 0 done/listed, 1 failed or declined, 2 usage. */
export async function runRevert(rest: string[], env: Env, layout: Layout, deps: RevertDeps = realRevertDeps(layout, env)): Promise<number> {
  const out = deps.out ?? ((s: string) => { process.stdout.write(s); });
  const json = rest.includes("--json");
  const yes = rest.includes("--yes");
  const toAt = rest.indexOf("--to");
  const to = toAt >= 0 ? Number(rest[toAt + 1]) : undefined;
  if (toAt >= 0 && (!Number.isInteger(to) || to! < 1)) {
    process.stderr.write("usage: mandu revert [--to <write number>] [--yes] [--json]\n");
    return 2;
  }
  const ws = deps.gitRoot(deps.cwd()) ?? deps.cwd();
  const call = <T>(args: string[]): T | null => {
    const r = deps.fsCli([...args, ws]);
    if (r.code !== 0) {
      process.stderr.write(`mandu revert: ${plainRevertError(r.stderr, r.code, ws)}\n`);
      return null;
    }
    return JSON.parse(r.stdout.trim().split("\n").pop()!) as T;
  };

  if (to === undefined) {
    const h = call<{ cycles: HistoryCycle[] }>(["history"]);
    if (!h) return 1;
    out(json ? JSON.stringify(h, null, 2) + "\n" : renderHistory(ws, h.cycles));
    return 0;
  }

  const plan = call<RevertPlanOut>(["revert", "--to", String(to), "--dry-run"]);
  if (!plan) return 1;
  if (!json) out(renderPlan(plan));
  if (!yes) {
    if (!deps.isTTY()) {
      process.stderr.write("mandu revert: not reverting without --yes (no terminal to ask on)\n");
      return 1;
    }
    if (!(await deps.confirm("Revert? [y/N] "))) {
      out("Nothing changed.\n");
      return 1;
    }
  }
  const done = call<RevertPlanOut>(["revert", "--to", String(to)]);
  if (!done) return 1;
  out(json ? JSON.stringify(done, null, 2) + "\n" : `Reverted to write #${done.to}.\n`);
  return 0;
}
