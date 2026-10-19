/**
 * Bind-only posture + the bwrap symlink probe, across the REAL components
 * (sandbox-security-review-2026-09-28 findings 7 and 14): the launcher's
 * main() in `secrets` mode, a REAL ArbiterServer, the host's REAL bwrap. The
 * "agent" is /bin/sh reading a catalog credential file.
 *
 *   B1 the guard turned off (--no-net-guard) on a host whose bwrap can mount:
 *      the launch PROCEEDS `gated` with gap `guard-off` (notice + the
 *      `launch_posture` event), and the bind STILL goes up: the agent reads
 *      the placeholder, not the raw bytes (the partial layer is real).
 *   B2 `--require-confinement` REFUSES that launch; the child never runs.
 *   B3 the default launch: with the guard binary built it is `confined`
 *      (both layers); without it, `gated` with gap `no-guard`.
 *   P1 the CVE-2026-87766 probe on this host answers `vulnerable` or `fixed`
 *      (never `unknown` where bwrap runs), agrees with an independent look
 *      through the link, and a launch with the bind in use prints the one
 *      WARNING line exactly when the probe says `vulnerable`.
 *
 * Self-SKIPs where bwrap cannot create a user namespace (no bwrap, Ubuntu's
 * AppArmor restriction without a grant, a container).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { resolveWrapBwrap } from "../../launcher/src/bwrap-grant.js";
import { probeBwrapSymlink } from "../../launcher/src/bwrap-symlink-probe.js";
import { resolveNativeBin } from "../../launcher/src/services/native-bins.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the posture is the confidentiality axis's

const BWRAP = (process.platform === "linux" ? resolveWrapBwrap() : null) ?? "bwrap";
const BWRAP_RUNS = process.platform === "linux" && spawnSync(BWRAP, ["--ro-bind", "/", "/", "--", "true"], { stdio: "ignore", timeout: 10_000 }).status === 0;
const skip = BWRAP_RUNS ? false : "bwrap cannot create a user namespace on this host (the bind layer cannot mount)";
const RAW = "AKIA_BIND_ONLY_7731_RAW_MUST_NOT_BE_READ";

interface Launch { code: number | null; err: Error | null; lines: string[]; out: string; events: Array<Record<string, unknown>> }

async function launch(extra: string[], envExtra: Record<string, string> = {}): Promise<Launch> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-bind-only-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".aws"), { recursive: true });
  const secret = join(home, ".aws", "credentials");
  writeFileSync(secret, `[default]\naws_secret_access_key=${RAW}\n`);
  const out = join(dir, "out");
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  let code: number | null = null;
  let err: Error | null = null;
  try {
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    // The launcher's secret discovery walks os.homedir(): the throwaway HOME.
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    try {
      code = await main(
        ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", ...extra,
          "--", "/bin/sh", "-c", `echo CHILD_RAN > ${out}; cat ${secret} >> ${out}`],
        {
          HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
          MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
          MANDU_VERBOSE: "1", ...envExtra,
        },
      );
    } catch (e) {
      err = e as Error;
    }
  } finally {
    console.error = orig;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
  }
  const events: Array<Record<string, unknown>> = [];
  const evDir = join(dir, "events");
  if (existsSync(evDir)) {
    for (const f of readdirSync(evDir, { recursive: true }) as string[]) {
      if (!f.endsWith(".ndjson")) continue;
      for (const l of readFileSync(join(evDir, f), "utf8").split("\n")) if (l.includes('"launch_posture"')) events.push(JSON.parse(l) as Record<string, unknown>);
    }
  }
  const got = existsSync(out) ? readFileSync(out, "utf8") : "";
  await server.close();
  rmSync(dir, { recursive: true, force: true });
  return { code, err, lines, out: got, events };
}

test("B1+B2: the guard turned off ⇒ GATED (guard-off) with the bind still up; --require-confinement refuses", { skip, timeout: 120_000 }, async () => {
  const r = await launch(["--no-net-guard"]);
  const log = r.lines.join("\n");
  assert.equal(r.err, null, `${r.err?.message}\n${log}`);
  assert.equal(r.code, 0, log);
  assert.match(log, /mandu: secrets are GATED, not confined, on this host\./);
  assert.match(log, /Mandu's file guard is turned off/);
  assert.match(log, /mount layer still puts a placeholder/);
  assert.doesNotMatch(log, /absent from the agent's world/, "gated never borrows the confined claim");
  assert.match(log, /mode secrets \(credential files GATED \(1 behind a placeholder, no file guard\)\)/);
  // the partial layer is real: the agent read the placeholder, never the raw bytes
  assert.match(r.out, /CHILD_RAN/);
  assert.ok(!r.out.includes(RAW), `the bind must still cover the file found at launch:\n${r.out}`);
  assert.match(r.out, /\$MDU:/);
  assert.equal(r.events.length, 1, log);
  assert.deepEqual(r.events[0]!["secrets"], { posture: "gated", gap: "guard-off" });

  const s = await launch(["--no-net-guard", "--require-confinement"]);
  assert.ok(s.err !== null || (s.code ?? 0) !== 0, "--require-confinement must refuse a bind-only launch");
  assert.match(s.err?.message ?? s.lines.join("\n"), /--require-confinement is set, but the whole-agent guard is turned off/);
  assert.doesNotMatch(s.out, /CHILD_RAN/, "a refused launch never runs the agent");
});

test("B3: the default launch is confined with the guard built, gated (no-guard) without it", { skip, timeout: 120_000 }, async () => {
  const guard = resolveNativeBin("mandu-net-guard");
  const r = await launch([]);
  const log = r.lines.join("\n");
  assert.equal(r.err, null, `${r.err?.message}\n${log}`);
  assert.equal(r.code, 0, log);
  assert.ok(!r.out.includes(RAW), r.out);
  assert.equal(r.events.length, 1, log);
  if (guard !== null) {
    assert.deepEqual(r.events[0]!["secrets"], { posture: "confined" }, log);
    assert.doesNotMatch(log, /secrets are GATED/);
  } else {
    assert.deepEqual(r.events[0]!["secrets"], { posture: "gated", gap: "no-guard" }, log);
    assert.match(log, /file guard \(mandu-net-guard\) is not available/);
  }
});

test("P1: the CVE-2026-87766 probe answers on this host, agrees with an independent look, and a launch warns exactly when it says vulnerable", { skip, timeout: 120_000 }, async () => {
  const p = probeBwrapSymlink(BWRAP);
  assert.ok(p.verdict === "vulnerable" || p.verdict === "fixed", `bwrap runs here, so the behavior must answer (not ${p.verdict}): ${p.detail}`);
  // The version rides a vulnerable answer (2026-10-07): the row and the line name it.
  if (p.verdict === "vulnerable") assert.match(p.version ?? "", /^\d+\.\d+\.\d+$/, "the installed version is read");
  // Independent look: bind onto a symlink and list the link's target from inside.
  const dir = mkdtempSync(join(tmpdir(), "mandu-bwrap-look-"));
  try {
    mkdirSync(join(dir, "real"));
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", "seen"), "");
    symlinkSync("real", join(dir, "link"));
    const look = spawnSync(BWRAP, ["--dev-bind", "/", "/", "--bind", join(dir, "src"), join(dir, "link"), "--", "ls", join(dir, "real")], { encoding: "utf8", timeout: 10_000 });
    const followed = look.status === 0 && look.stdout.includes("seen");
    assert.equal(p.verdict === "vulnerable", followed, `probe=${p.verdict} look=${JSON.stringify({ status: look.status, stdout: look.stdout, stderr: look.stderr })}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  // A package this host is known to ship unpatched (Ubuntu dropped the fix in 0.9.0-1ubuntu0.3).
  const pkg = spawnSync("dpkg-query", ["-W", "-f", "${Version}", "bubblewrap"], { encoding: "utf8" });
  if (BWRAP === "bwrap" && pkg.status === 0 && pkg.stdout.trim() === "0.9.0-1ubuntu0.3") assert.equal(p.verdict, "vulnerable");

  // The launch: the bind is in use (guard off), so the WARNING line follows the probe.
  const r = await launch(["--no-net-guard"]);
  assert.equal(r.err, null, r.err?.message);
  const warns = r.lines.filter((l) => /CVE-2026-87766/.test(l));
  assert.equal(warns.length, p.verdict === "vulnerable" ? 1 : 0, r.lines.join("\n"));
  if (warns.length === 1) assert.match(warns[0]!, /^WARNING: mandu: bubblewrap on this host follows symlinks/);
  assert.equal(r.code, 0, "warn only: never a refusal");
});
