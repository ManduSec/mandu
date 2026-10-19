/**
 * bwrap-path-launch e2e: which bubblewrap the real CLI runs
 * (src/bwrap-path.ts; rootless-confinement-ubuntu-2404.md §0.7, decision A:
 * the distribution's, never one in the workspace).
 *
 * The CLI runs as a child in a workspace that plants a WORKING-looking
 * `bwrap` (exit 0, so a probe that ran it would pass) at `./bwrap`,
 * `bin/bwrap` and `node_modules/.bin/bwrap`, each reached through PATH
 * (`.`, relative entries, and an absolute entry inside the workspace). The
 * only bubblewrap outside the workspace that comes first on PATH is a fake
 * that cannot create a user namespace (it fails like Ubuntu's AppArmor
 * restriction). So:
 *
 *   P1 `mandu doctor`: the functional probe runs the fake outside, never a
 *      planted one, and the secrets section says the mount layer is not
 *      available (it does not claim a bind the host cannot make);
 *   P2 a launch with `--require-confinement` (the guard off, so only the
 *      mount layer could confine) refuses, naming the namespace cause; no
 *      planted bwrap and no agent command ever ran.
 *
 * No real bubblewrap is run, no privilege, no network. Skipped where Mandu's
 * own bubblewrap is in force (the launch then runs that copy, not PATH).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { once } from "node:events";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { manduBwrapInForceHere } from "../../src/bwrap-grant.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis's mount layer is what these bwraps would build

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = process.platform !== "linux" ? "bubblewrap is Linux-only"
  : manduBwrapInForceHere() ? "Mandu's own bubblewrap is in force here, so the launch runs it, not PATH" : false;

interface Rig { root: string; ws: string; planted: string; fakeLog: string; path: string; cleanup: () => void }

function rig(): Rig {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mdu-bwrap-path-e2e-")));
  const ws = join(root, "ws");
  const planted = join(root, "planted-ran");
  const fakeLog = join(root, "fake-ran");
  for (const d of [join(ws, "bin"), join(ws, "node_modules", ".bin"), join(root, "fakebin"), join(root, "home")]) mkdirSync(d, { recursive: true });
  for (const p of [join(ws, "bwrap"), join(ws, "bin", "bwrap"), join(ws, "node_modules", ".bin", "bwrap")]) {
    writeFileSync(p, `#!/bin/sh\necho "$0 $*" >> '${planted}'\nexit 0\n`);
    chmodSync(p, 0o755);
  }
  const fake = join(root, "fakebin", "bwrap");
  writeFileSync(fake, `#!/bin/sh\necho "$*" >> '${fakeLog}'\necho 'bwrap: setting up uid map: Permission denied' >&2\nexit 1\n`);
  chmodSync(fake, 0o755);
  const path = [".", "bin", "node_modules/.bin", join(ws, "bin"), join(root, "fakebin"), process.env["PATH"] ?? ""].join(":");
  return { root, ws, planted, fakeLog, path, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** The real CLI (src/run.ts through tsx) as a child whose cwd is the workspace. */
function cli(argv: string[], cwd: string, env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(join(PKG, "node_modules", ".bin", "tsx"), [join(PKG, "src", "run.ts"), ...argv], { cwd, env: { ...env, PWD: cwd }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8").on("data", (c: string) => { stdout += c; });
    child.stderr.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code: code ?? (signal ? 128 : 127), stdout, stderr }));
  });
}

test("P1 mandu doctor: the probe runs the bubblewrap outside the workspace, never a planted one, and claims no mount layer it cannot make", { skip, timeout: 120_000 }, async () => {
  const r = rig();
  try {
    const out = await cli(["doctor"], r.ws, {
      PATH: r.path, HOME: join(r.root, "home"), MANDU_HOME: join(r.root, "mandu-home"),
      XDG_RUNTIME_DIR: r.root, MANDU_ARBITER_SOCK: join(r.root, "absent.sock"),
    });
    assert.equal(out.code, 0, `the doctor always exits 0: ${out.stderr}`);
    assert.ok(!existsSync(r.planted), `a planted bwrap ran:\n${existsSync(r.planted) ? readFileSync(r.planted, "utf8") : ""}`);
    assert.ok(existsSync(r.fakeLog), "the functional probe ran the bubblewrap outside the workspace");
    assert.match(readFileSync(r.fakeLog, "utf8"), /--unshare-user/, "a namespace probe, not a presence check");
    const secrets = out.stdout.slice(out.stdout.indexOf("Your secrets"));
    assert.match(secrets, /mount layer unavailable|posture: gated/, secrets);
  } finally {
    r.cleanup();
  }
});

test("P2 a strict launch whose only bubblewrap outside the workspace cannot make a namespace refuses; no planted bwrap and no agent command ran", { skip, timeout: 120_000 }, async () => {
  const r = rig();
  const sock = join(r.root, "arbiter.sock");
  const srv = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  try {
    const agentRan = join(r.root, "agent-ran");
    const out = await cli(
      ["--target", "shell", "--confidentiality", "--require-confinement", "--no-kernel", "--no-scope", "--", "bash", "-c", `touch '${agentRan}'`],
      r.ws,
      {
        PATH: r.path, HOME: join(r.root, "home"), MANDU_HOME: join(r.root, "mandu-home"), XDG_RUNTIME_DIR: r.root,
        MANDU_ARBITER_SOCK: sock, MANDU_NO_CONTEXT_PROXY: "1", MANDU_MODE: "off",
      },
    );
    assert.notEqual(out.code, 0, `the launch must refuse:\n${out.stderr}`);
    assert.match(out.stderr, /--require-confinement is set, but unprivileged user namespaces are unavailable/, out.stderr);
    assert.ok(!existsSync(agentRan), "the agent command never ran");
    assert.ok(!existsSync(r.planted), `a planted bwrap ran:\n${existsSync(r.planted) ? readFileSync(r.planted, "utf8") : ""}`);
    assert.ok(existsSync(r.fakeLog), "the launch probed the bubblewrap outside the workspace");
  } finally {
    srv.close();
    r.cleanup();
  }
});
