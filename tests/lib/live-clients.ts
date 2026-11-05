/**
 * live-clients — the launch half of the live client suites
 * (docs/design/testing/live-clients.md): one launch of the REAL launcher in
 * `secrets` around the stand-in `claude` (tests/lib/fake-claude-cli.mjs),
 * driven by a scripted model (fake-anthropic.ts) behind the HTTPS shim, whose
 * Bash tool runs each case's command in the agent's world.
 *
 * For a launch: a private stack (launcher-live.ts withStack, `secrets`), the
 * launch HOME's files as a user keeps them (the real credentials: discovery
 * finds them, nothing is labelled by hand), then `mandu --require-confinement
 * claude -p …`. Each case's output stays in the workspace
 * (`.mdu-cases/<name>.out`: what the agent's world saw) and goes back to the
 * model as the tool result through the real model proxy. The result holds the
 * launch's exit code and output tail, each case's output, every request the
 * model received and the session's event log: the suites' oracles.
 *
 * PROVENANCE: NEW Mandu test code.
 */
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { runLauncher, startHttpsShim, withStack } from "./launcher-live.js";
import { startScriptedAnthropic, textTurn, toolUseTurn } from "./fake-anthropic.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE_CLAUDE = join(HERE, "fake-claude-cli.mjs");
const PROMPT_MARKER = "MDU_LIVE_CLIENTS_PROMPT";

/**
 * One case the scripted model has the agent run: a shell command, its
 * output written to `.mdu-cases/<name>.out` in the workspace (what the
 * agent's world saw) and returned to the model as the tool result.
 */
export interface LiveCase {
  name: string;
  cmd: string;
  /** Not run, and why (a case waiting on a feature). */
  skip?: string;
}

/** The tool command for one case: its output (and exit status) into the
 *  workspace, then printed for the model. */
export function caseCommand(c: LiveCase): string {
  return `mkdir -p .mdu-cases; { ${c.cmd} ; } > .mdu-cases/${c.name}.out 2>&1; echo "exit=$?" >> .mdu-cases/${c.name}.out; cat .mdu-cases/${c.name}.out`;
}

/** The exit status a case's output ends with (`exit=N`), or null. */
export function caseExit(out: string): number | null {
  const m = /exit=(\d+)\s*$/.exec(out);
  return m ? Number(m[1]) : null;
}

/** Every form of a secret a check looks for: as written, base64 and
 *  base64url, hex. */
export function secretForms(secret: string): string[] {
  const b = Buffer.from(secret, "utf8");
  return [secret, b.toString("base64").replace(/=+$/, ""), b.toString("base64url"), b.toString("hex")];
}

export interface LiveLaunch {
  name: string;
  /** HOME-relative path → content (mode 0600). */
  files: Record<string, string>;
  cases: LiveCase[];
  /** Extra variables in the launch's environment. */
  env?: Record<string, string>;
}

export interface LiveLaunchResult {
  name: string;
  code: number;
  outTail: string;
  guardLive: boolean;
  cases: Record<string, string>;
  /** The bodies of every request the model received. */
  model: string[];
  /** The session's event log (every file of the private arbiter's events dir). */
  events: string;
  /** The launch HOME's files as they are after the run (the user's own). */
  homeAfter: Record<string, string>;
}

/** Every regular file under `dir`, concatenated. */
function readTree(dir: string): string {
  if (!existsSync(dir)) return "";
  let out = "";
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    const st = statSync(p);
    if (st.isDirectory()) out += readTree(p);
    else if (st.isFile()) out += readFileSync(p, "utf8") + "\n";
  }
  return out;
}

/** Run one launch; its whole output is also kept in `scratch/<name>.launch.out`. */
export async function runLaunch(l: LiveLaunch, scratch: string): Promise<LiveLaunchResult> {
  let result: LiveLaunchResult | null = null;
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    for (const [rel, text] of Object.entries(l.files)) {
      const p = join(home, rel);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, text, { mode: 0o600 });
    }
    const bin = join(tmp, "bin");
    mkdirSync(bin, { recursive: true });
    copyFileSync(FAKE_CLAUDE, join(bin, "claude"));
    chmodSync(join(bin, "claude"), 0o755);
    const runnable = l.cases.filter((c) => !c.skip);
    let step = 0;
    const model = await startScriptedAnthropic({
      script: [{
        match: (r) => r.body.includes(PROMPT_MARKER),
        respond: () => (step < runnable.length
          ? toolUseTurn(`toolu_live_${step}`, "Bash", { command: caseCommand(runnable[step++]!) })
          : textTurn("Done: every client ran.")),
      }],
    });
    const shim = await startHttpsShim(model.origin, tmp);
    try {
      const env = {
        ...launcherEnv(shim.origin, 0),
        HOME: home,
        PATH: `${bin}:${process.env["PATH"] ?? ""}`,
        MDU_FAKE_CLAUDE_LOG: join(tmp, "fake-claude.log"),
        MDU_FAKE_CLAUDE_MAX_TURNS: String(runnable.length + 4),
        // Nobody answers an Approvals card here (as in CI, github-action.md
        // §4.2): an open that would wait for one is refused after 2 s, not 60.
        MANDU_SECRETS_ASK_TIMEOUT: "2000",
        ...(l.env ?? {}),
      };
      const r = await runLauncher(
        ["--no-scope", "--no-mcp", "--no-reply-filter", "--require-confinement", "claude", "-p", `${PROMPT_MARKER} run the clients`],
        env, workspace, 600_000,
      );
      const cases: Record<string, string> = {};
      const dir = join(workspace, ".mdu-cases");
      for (const c of runnable) {
        const f = join(dir, `${c.name}.out`);
        cases[c.name] = existsSync(f) ? readFileSync(f, "utf8") : "(no output: the case never ran)";
      }
      const homeAfter: Record<string, string> = {};
      for (const rel of Object.keys(l.files)) homeAfter[rel] = existsSync(join(home, rel)) ? readFileSync(join(home, rel), "utf8") : "";
      const fakeLog = join(tmp, "fake-claude.log");
      result = {
        name: l.name,
        code: r.code,
        // The banner (the start) and the end.
        outTail: (r.out.length > 14_000 ? `${r.out.slice(0, 6000)}\n[…]\n${r.out.slice(-8000)}` : r.out) +(existsSync(fakeLog) ? `\n--- fake claude ---\n${readFileSync(fakeLog, "utf8").slice(-4000)}` : ""),
        guardLive: /net-guard LIVE/.test(r.out),
        cases,
        model: model.requests.map((q) => q.body),
        events: readTree(join(tmp, "events")),
        homeAfter,
      };
      mkdirSync(scratch, { recursive: true });
      writeFileSync(join(scratch, `${l.name}.launch.out`), r.out);
    } finally {
      await shim.close();
      await model.close();
    }
  }, { mode: "secrets" });
  return result!;
}
