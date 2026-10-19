/**
 * doctor-live-pty e2e — `mandu doctor --live`'s PTY relay argv (L3) through
 * the HOST's own script(1): util-linux on Linux, BSD on macOS (packaging.md
 * §7b). The unit tests pin the argv shape and its parity with reply-filter's
 * pty-relay.ts; this runs it the way realDoctorLiveDeps does (spawnSync,
 * piped stdio) and asserts what L3 relies on: the child gets a real
 * terminal, its argv arrives verbatim (quotes, spaces and a `$MDU:` token
 * survive util-linux's `sh -c` string and BSD's direct exec alike), its
 * output reaches script's stdout, and its exit status comes back.
 * Before 2026-09-29 the argv was util-linux only, and BSD script refused it
 * ("illegal option -- f"): L3 failed on every Mac. Self-SKIPs where the
 * platform has no relay or no script(1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { livePtyArgv, livePtyFlavor, livePtyScript, livePtyStdin } from "../../src/doctor-live.js";

const flavor = livePtyFlavor(process.platform);

/** The same probe reply-filter's ptyRelayAvailable runs, per flavor. */
const scriptWorks = ((): boolean => {
  if (flavor === null) return false;
  const r = spawnSync(livePtyScript(flavor), flavor === "util-linux" ? ["--version"] : ["-q", "/dev/null", "/usr/bin/true"], { stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
  if (r.error) return false;
  return flavor === "bsd" || (r.status === 0 && String(r.stdout).includes("util-linux"));
})();

test(
  "the doctor's PTY argv runs under this host's script(1): a real TTY, the argv verbatim, the output relayed, the exit status back",
  { skip: !scriptWorks && `no ${flavor ?? "supported"} script(1) relay on ${process.platform}` },
  () => {
    const word = "it's a $MDU:doctor[1a2b] token";
    const argv = livePtyArgv(["/bin/sh", "-c", 'if [ -t 1 ]; then echo TTY-YES; fi; printf "<%s>\\n" "$0"; exit 3', word], flavor!);
    // BSD script by absolute path (macOS); util-linux found on PATH (Linux)
    assert.equal(argv[0], flavor === "bsd" ? "/usr/bin/script" : "script");
    if (flavor === "bsd") assert.deepEqual(argv.slice(1, 3), ["-q", "/dev/null"]);
    // exactly as realDoctorLiveDeps spawns it (stdin per flavor)
    const r = spawnSync(argv[0]!, argv.slice(1), { encoding: "utf8", timeout: 30_000, stdio: [livePtyStdin(flavor!), "pipe", "pipe"] });
    assert.equal(r.error, undefined, String(r.error));
    assert.equal(r.status, 3, `exit status propagates (stderr: ${r.stderr})`);
    assert.match(r.stdout, /TTY-YES/, "the child sees a terminal");
    assert.ok(r.stdout.includes(`<${word}>`), `the argv arrives verbatim: ${JSON.stringify(r.stdout)}`);
    assert.doesNotMatch(r.stderr ?? "", /illegal option/);
  },
);
