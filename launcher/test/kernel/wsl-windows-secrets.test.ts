/**
 * wsl-windows-secrets.test — E2E: on WSL the `secrets` mode twins the
 * credential stores of every Windows user profile, not only the Linux HOME's
 * (launcher/src/wsl.ts `windowsProfiles`, confidentiality.md §7.2 "WSL2").
 *
 * Real components: the arbiter daemon (subprocess, confidentiality axis ON)
 * reached through the production socket adapter (`socketSecretArbiter`),
 * its discovery walk + catalog + registry, `applySecretTwins`, and the
 * resulting bwrap wrap run for real. The one stand-in: this host is not WSL,
 * so the WSL signal is pinned and the profile is a directory shaped like
 * `/mnt/c/Users/alice` under a temp root (handed in as `windowsProfiles`,
 * which is what the drvfs mount-table probe yields on a real WSL host).
 *
 * Asserted inside the wrap: the Windows-profile credentials (`.aws/credentials`,
 * the Windows-only spellings `_netrc` and `AppData/Roaming/gcloud/…`) read as
 * their twins (a `$MDU:` symbol, never the raw value), and a profile file the
 * catalog does not name reads through unchanged. Self-SKIPs without bwrap +
 * user namespaces. The same arbiter then answers `mandu doctor --secrets`'s
 * dry run (`gatherSecrets` over the production seams, the profile handed in
 * the same way): it lists exactly the files the launch confined.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applySecretTwins, socketSecretArbiter } from "../../src/secret-setup.js";
import { gatherSecrets, realDoctorSecretsDeps, renderSecrets } from "../../src/doctor-secrets.js";
import { Layout } from "../../src/services/layout.js";
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

const commandExists = (cmd: string): boolean => spawnSync("sh", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0;

test("WSL: a Windows profile's credential files are twinned by the secrets wrap (real arbiter, real bwrap)", async (t) => {
  if (process.platform !== "linux" || !commandExists("bwrap") || !probeUserns()) { t.skip("bwrap with user namespaces unavailable"); return; }
  if (!existsSync(ARBITER_TSX)) { t.skip("arbiter dependencies not installed (cd arbiter && npm install)"); return; }

  const tmp = realpathSync(tmpDir("mandu-winsec-"));
  let arbiter: ChildProcess | undefined;
  // One temp Mandu home for the arbiter and the code under test (its view
  // state base is the home's state/), restored below.
  const origManduHome = process.env["MANDU_HOME"];
  const manduHome = join(tmp, "mandu-home");
  process.env["MANDU_HOME"] = manduHome;
  let passed = false;
  try {
    const home = join(tmp, "home", "u");
    mkdirSync(home, { recursive: true });
    const profile = join(tmp, "mnt", "c", "Users", "alice");
    const put = (rel: string, body: string): string => {
      const p = join(profile, rel);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, body);
      return p;
    };
    const aws = put(".aws/credentials", "[default]\naws_secret_access_key=WIN-AWS-RAW-7d1f\n");
    const netrc = put("_netrc", "machine example.com login a password WIN-NETRC-RAW-51c0\n");
    const gcloud = put("AppData/Roaming/gcloud/application_default_credentials.json", '{"refresh_token":"WIN-GCLOUD-RAW-a9e2"}\n');
    const plain = put("Documents/notes.txt", "PLAIN-NOTES\n");

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

    const runDir = join(tmp, "run");
    mkdirSync(runDir);
    const mut = emptyMutation();
    const logs: string[] = [];
    const plan = { confidentiality: true, bestEffort: false } as LaunchPlan;
    const r = await applySecretTwins(plan, runDir, mut, {
      arbiter: socketSecretArbiter(sock),
      commandExists,
      usernsOk: () => true,
      platform: "linux",
      log: (m) => logs.push(m),
      home,
      workspaceRoots: [],
      onWsl: true,
      // The /run/WSL and /init hiding is wsl-interop.test.ts's; none here.
      pathExists: () => false,
      windowsProfiles: [profile],
      // A guard is around the launch (it recognizes a different-case
      // spelling of a twinned file); without one the launch refuses, below.
      guardServesTwins: true,
      // The bind wrap is what this test reads through. Where the host's
      // bwrap AppArmor profile forbids a sandbox inside it (Ubuntu 26.04's
      // bwrap-userns-restrict), a guarded launch drops the bind and the guard
      // alone serves the twins (secret-setup.ts, the nesting probe): no wrap,
      // an empty launchPrefix, and `cat` below would have nothing to run in.
      // Only the agent's OWN sandboxes need nesting, and `cat` starts none,
      // so the probe is answered yes and the bind runs on every host.
      nestingOk: () => true,
    });
    assert.ok(mut.launchPrefix.length > 0, `the bind wrap is on: ${logs.join("\n")}`);
    assert.equal(r.posture, "confined", `status: ${r.status}\n${logs.join("\n")}`);
    const confined = r.confined.map((c) => c.path).sort();
    assert.deepEqual(confined, [aws, netrc, gcloud].sort(), `the Windows-profile stores are discovered: ${logs.join("\n")}`);

    const read = spawnSync(mut.launchPrefix[0]!, [...mut.launchPrefix.slice(1), "cat", aws, netrc, gcloud, plain], {
      encoding: "utf8", timeout: 30_000,
    });
    assert.equal(read.status, 0, `the wrapped read must run: ${read.stderr}`);
    for (const raw of ["WIN-AWS-RAW-7d1f", "WIN-NETRC-RAW-51c0", "WIN-GCLOUD-RAW-a9e2"]) {
      assert.ok(!read.stdout.includes(raw), `${raw} must not be readable inside the wrap:\n${read.stdout}`);
    }
    assert.match(read.stdout, /\$MDU:/, "the twins carry symbols");
    assert.match(read.stdout, /PLAIN-NOTES/, "a profile file the catalog does not name reads through");
    // Outside the wrap the originals are untouched (the twin is a bind, not an edit).
    assert.match(readFileSync(aws, "utf8"), /WIN-AWS-RAW-7d1f/);

    // `mandu doctor --secrets` answers from the same walk: the dry run over
    // the same arbiter lists exactly the files the launch confined, and says
    // which profile it probed.
    const dry = await gatherSecrets({ HOME: home }, Layout.dev(resolve(HERE, "..", "..", "..")), {
      ...realDoctorSecretsDeps(),
      arbiter: async () => ({ sock, kind: "resident", axisOn: true, stop: async () => {} }),
      confinement: () => ({ posture: "confined" }),
      windowsProfiles: () => [profile],
      guardAvailable: () => true, // as the launch above (guardServesTwins)
    }, { cwd: home });
    assert.equal(dry.launch.ok, true, dry.launch.reason ?? "");
    assert.deepEqual(dry.windowsProfiles, [profile]);
    assert.deepEqual(dry.files.map((f) => f.path).sort(), confined, "the dry run and the launch agree");
    assert.ok(dry.files.every((f) => f.profile === profile && f.bind === "bind"));
    assert.match(renderSecrets(dry, home), new RegExp(`Windows profiles \\(WSL, their credential stores only\\): ${profile}`));

    // Without the guard the bind alone would leave `.AWS/CREDENTIALS` raw on
    // a drive that ignores case: the launch refuses (fail-closed).
    await assert.rejects(
      applySecretTwins(plan, join(tmp, "run-noguard"), emptyMutation(), {
        arbiter: socketSecretArbiter(sock), commandExists, usernsOk: () => true, platform: "linux",
        log: () => {}, home, workspaceRoots: [], onWsl: true, pathExists: () => false, windowsProfiles: [profile],
      }),
      /Windows credential file\(s\).*only the whole-agent guard recognizes another spelling/,
    );

    // Control: the same host read as NOT WSL never looks at the profile, so
    // none of it is confined (the gap this closes).
    const off = await applySecretTwins(plan, join(tmp, "run-off"), emptyMutation(), {
      arbiter: socketSecretArbiter(sock), commandExists, usernsOk: () => true, platform: "linux",
      log: () => {}, home, workspaceRoots: [], onWsl: false, pathExists: () => false, windowsProfiles: [profile],
    });
    assert.deepEqual(off.confined, [], "off WSL the Windows profile is not consulted");
    passed = true;
  } finally {
    if (origManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = origManduHome;
    await stopGroup(arbiter);
    if (!passed) {
      try { process.stderr.write(`arbiter.log:\n${readFileSync(join(tmp, "arbiter.log"), "utf8").slice(-4000)}\n`); } catch { /* none */ }
    }
    removeDir(tmp);
  }
});
