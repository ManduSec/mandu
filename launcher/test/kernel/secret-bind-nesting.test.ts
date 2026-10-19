/**
 * secret-bind-nesting.test — E2E: the secret bind never stops the sandboxes
 * the agent's own tools start (os-test-matrix.md §10.14.1 item 6;
 * confidentiality-plan-10-flow-taint.md §8 phase 6).
 *
 * WHY: on Ubuntu 26.04 the distro `bwrap-userns-restrict` AppArmor profile
 * stacks `unpriv_bwrap` on everything a /usr/bin/bwrap sandbox runs, and that
 * profile denies every capability, CAP_SYS_ADMIN in a child's own user
 * namespace included. Inside the twin bind, Codex's shell sandbox and Mandu's
 * exec box died "bwrap: No permissions to create a new namespace" on every
 * command (VM-verified 2026-09-27; audit: `apparmor="DENIED"
 * operation="capable" profile="unpriv_bwrap" comm="bwrap" capname="sys_admin"`).
 *
 * Real components: the arbiter daemon (subprocess, confidentiality axis ON)
 * through the production socket adapter, its discovery + registry,
 * `applySecretTwins` with its DEFAULT nesting probe (a real spawn of
 * `nestedSandboxProbeArgv`), and the resulting launch prefix run for real.
 * The one stand-in: a `bwrap` on PATH that behaves like 26.04's (a bwrap
 * started inside a bwrap cannot set up its namespace) or like 24.04 under
 * Mandu's grant (nesting works), since this host's AppArmor is not 26.04's.
 * A last leg runs the REAL bwrap where this host can nest.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applySecretTwins, socketSecretArbiter } from "../../src/secret-setup.js";
import { NESTED_SANDBOX_PROBE, nestedSandboxProbeArgv } from "../../src/secret-twins.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";
import { probeUserns } from "../../src/userns.js";
import { stateAxes } from "../axes.js";
import { removeDir, stopGroup, tmpDir } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("secrets"); // this suite states its axes: confidentiality ON (protection-modes.md §4)

const HERE = dirname(fileURLToPath(import.meta.url));
const ARBITER_DIR = join(resolve(HERE, "..", "..", ".."), "arbiter");
const ARBITER_TSX = join(ARBITER_DIR, "node_modules", ".bin", "tsx");

/** A bwrap stand-in: runs whatever follows the first `--`. In `restrict`
 *  mode it marks its children, and a marked bwrap fails the way 26.04's
 *  does; in `nest` mode nesting works. */
const FAKE_BWRAP = `#!/bin/sh
if [ "$FAKE_BWRAP_MODE" = restrict ] && [ -n "$FAKE_BWRAP_INSIDE" ]; then
  echo "bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces." >&2
  exit 1
fi
while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done
[ $# -gt 0 ] && shift
FAKE_BWRAP_INSIDE=1 exec "$@"
`;

/** Mandu's own bubblewrap stand-in (bwrap-grant.ts): its profile lets the
 *  system bwrap run as `mandu_bwrap` inside it, so a bwrap started in its
 *  sandbox CAN set up (the restrict mark is not passed on). */
const FAKE_MANDU_BWRAP = `#!/bin/sh
while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done
[ $# -gt 0 ] && shift
unset FAKE_BWRAP_INSIDE
exec "$@"
`;

test("the secret bind never stops the agent's own sandboxes: guard-only where nesting is barred, the bind where it is not (real arbiter, real probe)", async (t) => {
  if (process.platform !== "linux") { t.skip("Linux only"); return; }
  if (!existsSync(ARBITER_TSX)) { t.skip("arbiter dependencies not installed (cd arbiter && npm install)"); return; }

  const tmp = realpathSync(tmpDir("mandu-nest-"));
  const origPath = process.env["PATH"] ?? "";
  // One temp Mandu home for the arbiter and the code under test (its view
  // state base is the home's state/), restored below.
  const origManduHome = process.env["MANDU_HOME"];
  const manduHome = join(tmp, "mandu-home");
  process.env["MANDU_HOME"] = manduHome;
  let arbiter: ChildProcess | undefined;
  let passed = false;
  try {
    const home = join(tmp, "home", "u");
    mkdirSync(join(home, ".aws"), { recursive: true });
    const cred = join(home, ".aws", "credentials");
    writeFileSync(cred, "[default]\naws_secret_access_key=NEST-RAW-5e1a\n", { mode: 0o600 });
    const fakeDir = join(tmp, "fakebin");
    mkdirSync(fakeDir);
    writeFileSync(join(fakeDir, "bwrap"), FAKE_BWRAP);
    chmodSync(join(fakeDir, "bwrap"), 0o755);

    const sock = join(tmp, "arbiter.sock");
    const logFd = openSync(join(tmp, "arbiter.log"), "a");
    arbiter = spawn(process.execPath, sourceArbiterArgs(sock), {
      cwd: ARBITER_DIR,
      env: {
        ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"),
        MANDU_ARBITER_SOCK: sock, MANDU_HOME: manduHome, MANDU_RUNTIME_DIR: join(tmp, "mandu"),
      },
      stdio: ["ignore", logFd, logFd], detached: true,
    });
    closeSync(logFd);
    // The shared readiness budget (launcher/test/lib/arbiter-ready.ts): load- and
    // CI-aware, ended at once by an exit; a start that does not come up FAILS
    // with the log's last lines.
    await waitForPaths(sock, { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });

    const plan = { confidentiality: true, bestEffort: false } as LaunchPlan;
    // One launch with the DEFAULT probe (nestingOk unset): the fake bwrap is
    // what `bwrap` resolves to, for the probe and for the prefix run below.
    const launch = async (mode: "restrict" | "nest", guard: boolean, name: string, wrapBwrap?: string) => {
      process.env["PATH"] = `${fakeDir}:${origPath}`;
      process.env["FAKE_BWRAP_MODE"] = mode;
      const runDir = join(tmp, name);
      mkdirSync(runDir);
      const mut = emptyMutation();
      const logs: string[] = [];
      const r = await applySecretTwins(plan, runDir, mut, {
        arbiter: socketSecretArbiter(sock), commandExists: () => true, usernsOk: () => true, platform: "linux",
        log: (m) => logs.push(m), home, workspaceRoots: [], onWsl: false, guardServesTwins: guard,
        wrapBwrap: wrapBwrap ?? "bwrap",
        // The CVE-2026-87766 probe has its own suite (bind-only-posture e2e);
        // pinned so the fake bwrap's answer cannot add a WARNING here.
        symlinkProbe: (bwrap) => ({ bwrap, verdict: "unknown" }),
      });
      // What the agent's tool does inside the launch: start its own sandbox.
      const nested = spawnSync("sh", ["-c", '"$@"', "sh", ...mut.launchPrefix, "bwrap", ...NESTED_SANDBOX_PROBE], {
        env: { ...process.env }, encoding: "utf8",
      });
      return { r, mut, logs, runDir, nestedStatus: nested.status, nestedErr: nested.stderr };
    };

    // 26.04 + the guard: no bind, twins served by descriptor, nesting works.
    const a = await launch("restrict", true, "run-2604-guard");
    assert.equal(a.r.posture, "confined");
    assert.equal(a.r.bindGap, "bwrap-nesting");
    assert.equal(a.r.confined.length, 1, `the credential file is registered (${a.logs.join(" | ")})`);
    assert.ok(!a.mut.launchPrefix.includes("bwrap"), "no bind mount");
    assert.equal(a.nestedStatus, 0, `the agent's own sandbox starts: ${a.nestedErr}`);
    const policy = JSON.parse(readFileSync(a.mut.env["MANDU_NET_GUARD_SECRETS"]!, "utf8")) as { secrets: Array<{ path: string; twin: string }> };
    assert.deepEqual(policy.secrets.map((s) => s.path), [cred], "the guard serves the twin for the real path");
    const twin = readFileSync(policy.secrets[0]!.twin, "utf8");
    assert.match(twin, /\$MDU:/);
    assert.doesNotMatch(twin, /NEST-RAW-5e1a/, "the twin never holds the raw value");
    assert.equal(a.logs.filter((l) => /mount layer is off/.test(l)).length, 1);

    // 26.04 without the guard: the bind stays (raw bytes out first), nesting
    // breaks, and a WARNING says so. Bind-only is `gated` (finding 7).
    const b = await launch("restrict", false, "run-2604-noguard");
    assert.deepEqual({ posture: b.r.posture, gap: b.r.gap }, { posture: "gated", gap: "no-guard" });
    assert.ok(b.mut.launchPrefix.includes("bwrap"), "the bind stays");
    assert.notEqual(b.nestedStatus, 0, "nesting is barred under the bind");
    assert.match(b.nestedErr, /No permissions to create a new namespace/);
    assert.ok(b.logs.some((l) => /^WARNING: mandu: .*will fail/.test(l)));

    // 24.04 (nesting works): the bind is used, as before.
    const c = await launch("nest", true, "run-2404");
    assert.equal(c.r.bindGap, undefined);
    assert.ok(c.mut.launchPrefix.includes("bwrap"), "the bind is used");
    assert.equal(c.nestedStatus, 0);
    assert.ok(!c.logs.some((l) => /mount layer/.test(l)));

    // 26.04 after `mandu setup` (rootless-confinement-ubuntu-2404.md §12.3):
    // the wrap runs Mandu's own bubblewrap, whose profile lets the system
    // bwrap nest, so the probe passes and the bind STAYS ON with the guard.
    const manduBwrap = join(tmp, "mandu-bin", "bwrap");
    mkdirSync(dirname(manduBwrap));
    writeFileSync(manduBwrap, FAKE_MANDU_BWRAP);
    chmodSync(manduBwrap, 0o755);
    const d = await launch("restrict", true, "run-2604-mandu-bwrap", manduBwrap);
    assert.equal(d.r.posture, "confined");
    assert.equal(d.r.bindGap, undefined, "both layers: the mount layer is on");
    assert.equal(d.mut.launchPrefix[0], manduBwrap, "the wrap runs Mandu's own bubblewrap");
    assert.equal(d.nestedStatus, 0, `the agent's own sandbox (the system bwrap) starts inside it: ${d.nestedErr}`);
    assert.ok(!d.logs.some((l) => /mount layer is off|WARNING/.test(l)));
    passed = true;
  } finally {
    process.env["PATH"] = origPath;
    delete process.env["FAKE_BWRAP_MODE"];
    if (origManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = origManduHome;
    await stopGroup(arbiter);
    if (!passed) {
      try { process.stderr.write(`arbiter.log:\n${readFileSync(join(tmp, "arbiter.log"), "utf8").slice(-4000)}\n`); } catch { /* none */ }
    }
    removeDir(tmp);
  }
});

test("the probe on this host's REAL bwrap agrees with a nested bwrap run by hand", (t) => {
  if (process.platform !== "linux" || spawnSync("sh", ["-c", "command -v bwrap"]).status !== 0 || !probeUserns()) {
    t.skip("bwrap with user namespaces unavailable");
    return;
  }
  const [cmd, ...args] = nestedSandboxProbeArgv();
  const probe = spawnSync(cmd!, args, { encoding: "utf8" }).status;
  const byHand = spawnSync("bwrap", ["--dev-bind", "/", "/", "--", "bwrap", "--unshare-user", "--unshare-net", "--ro-bind", "/", "/", "--", "true"], { encoding: "utf8" }).status;
  assert.equal(probe === 0, byHand === 0, "the probe answers what a nested sandbox meets on this host");
});
