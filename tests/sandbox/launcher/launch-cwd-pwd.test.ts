/**
 * launch-cwd-pwd.test.ts — a confined launch is for the folder it is started
 * IN, not for a `$PWD` naming another one (packaging.md §1, "The launch
 * directory"; launcher/src/launch-cwd.ts).
 *
 * A script that `chdir`s without exporting PWD (Python's
 * `subprocess.run(cwd=…)`, a non-shell parent) starts `mandu` with its cwd in
 * the project and its PWD in another folder. Before the fix the launcher took
 * the PWD as the project: the agent ran in the other folder, beside a
 * confinement, twins and a secret scan meant for it.
 *
 * withStack's workspace holds a `.env` with a canary; a decoy folder beside
 * it holds nothing. The private arbiter runs `secrets`; the real launcher is
 * started with cwd = the workspace, PWD = the decoy, around a shell agent
 * that prints its cwd, its PWD and the `.env` it finds there. Asserted:
 *   - THE LEAK ORACLE: the canary never reaches the agent's output;
 *   - the agent runs in the workspace (the real cwd) and its PWD names it;
 *   - the `.env` it reads there is the twin (confined, read without error).
 *
 * `--no-reply-filter` keeps stdout as the AGENT sees it. GATED on Linux +
 * bwrap + an unprivileged userns + the built guard; zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withStack, runLauncher, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

installExitGuard("launch-cwd-pwd");

// This suite STATES its axes (protection-modes.md §4): `secrets`. withStack
// brings its private arbiter up in the same mode.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : !GUARD.path
        ? "mandu-net-guard is not built (scripts/build-native.sh)"
        : false;

const ENV_KEY = "sk_live_CANARYcwdpwd5e1f2a3b4c6d";

/** The agent's work: where it runs, the PWD it was handed, and the .env it
 *  finds there (by absolute tool paths: the exec-box shims the plain ones). */
const AGENT_SCRIPT = String.raw`
echo "CWD $(/bin/pwd -P)"
echo "PWDENV $PWD"
if [ -e .env ]; then echo "ENV_PRESENT"; /bin/cat .env | /usr/bin/sed 's/^/ENVLINE /'; /bin/cat .env >/dev/null; echo "CAT_EXIT $?"; else echo "ENV_ABSENT"; fi
echo "AGENT_DONE"
`;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("LIVE: started in the workspace with PWD naming a decoy folder, the launch is for the workspace and its secret stays a twin", { skip: GATE, timeout: 300_000 }, async () => {
  await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
    writeFileSync(join(workspace, ".env"), `API_KEY=${ENV_KEY}\nDEBUG=1\n`, { mode: 0o600 });
    const decoy = join(tmp, "decoy");
    mkdirSync(decoy);
    const script = join(tmp, "agent.sh");
    writeFileSync(script, AGENT_SCRIPT);
    // cwd = the workspace (runLauncher's spawn), PWD = the decoy: what a
    // parent that chdir'd without exporting PWD hands the launcher.
    const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home, PWD: decoy };
    const args = ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude"];
    const r = await runLauncher([...args, "--", "/bin/sh", script], env, workspace, 240_000);
    const out = r.out;
    const diag = `\n--- launch output (tail) ---\n${out.slice(-6000)}`;
    const tagged = (t: string): string[] => out.split("\n").filter((l) => l.startsWith(`${t} `)).map((l) => l.slice(t.length + 1));

    // THE LEAK ORACLE first.
    assert.ok(!out.includes(ENV_KEY), `CONFIDENTIALITY VIOLATION: the workspace's secret reached the agent's world${diag}`);

    assert.equal(r.code, 0, `the launch failed${diag}`);
    assert.ok(out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
    assert.ok(/confidentiality — \d+ secret\(s\) confined/.test(out), `the twins engaged${diag}`);
    assert.deepEqual(tagged("CWD"), [workspace], `the agent runs in the real cwd, never the PWD's decoy${diag}`);
    assert.deepEqual(tagged("PWDENV"), [workspace], `the agent's PWD names the folder it runs in${diag}`);
    assert.ok(out.includes("ENV_PRESENT"), `the agent sees the workspace's .env where it runs${diag}`);
    assert.deepEqual(tagged("CAT_EXIT"), ["0"], `the twin reads without error${diag}`);
    assert.ok(tagged("ENVLINE").some((l) => l.startsWith("API_KEY=")), `the twin keeps the file's shape${diag}`);
  }, { mode: "secrets" });
});
