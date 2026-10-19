/**
 * write-protect-registry e2e (runtime-instances.md §2, "planted paths"), across
 * the REAL components: the launcher's main() in `secrets` mode puts Mandu's
 * runtime registries on the Linux write-protect list, and the REAL
 * mandu-net-guard refuses the agent tree's changes there, as the macOS
 * profile does. The "agent" is a bash script; the runtime base is
 * `${XDG_RUNTIME_DIR}/mandu` in a throwaway dir, seeded with what a running
 * stack leaves there (an instance with its manifest, `current` linked to it,
 * a dashboard entry, `dashboard.log`, `logs/`, `vm-guests/`).
 *
 *   - refused: a write to an instance's manifest, a manifest in a new
 *     instance dir (the directory itself is not judged: mkdir never was), a
 *     rename over `current` and its removal, the promotion's temp link
 *     `.current.tmp-<pid>`, a `dashboard-<pid>.port`, an append to
 *     `dashboard.log`, a forged `vm-guests/` entry, a log in `logs/`, a
 *     forged release-check marker (`pending-<pid>`, which would take a live
 *     session out of a launch's session scan; runtime-instances.md §4.1), an
 *     owner file in a lock dir the agent made, the gate swapped for a link,
 *     and a rename of the base itself;
 *   - performed (the controls): a new file in the base (where the session's
 *     own folder lives), a file whose name only looks like a registry entry
 *     (`current2`).
 *
 * Self-SKIPs where the guard is not built (scripts/build-native.sh) or the
 * kernel has no seccomp user notification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { main } from "../../launcher/test/lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../lib/axes.js";
import { pickGuard } from "../lib/native-guard.js";

stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, "..", "..", "interceptors", "target");
const PICK = pickGuard(TARGET);
const GUARD = PICK.path;
const skip = process.platform !== "linux" || !GUARD ? "mandu-net-guard is not built (scripts/build-native.sh)" : false;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD }, () => {
  assert.equal(PICK.stale, null, PICK.stale ?? "");
});

test("the agent tree cannot change Mandu's runtime registries; the rest of the runtime folder stays writable", { skip, timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-wp-reg-e2e-"));
  const home = join(dir, "home");
  mkdirSync(home, { recursive: true });
  const base = join(dir, "mandu");
  const inst = join(base, "instances", "20261007-0000-abc-p1");
  mkdirSync(inst, { recursive: true, mode: 0o700 });
  const manifest = join(inst, "manifest.json");
  writeFileSync(manifest, `{"pid":1}`);
  symlinkSync(join("instances", "20261007-0000-abc-p1"), join(base, "current"));
  mkdirSync(join(base, "dashboards"));
  writeFileSync(join(base, "dashboards", "d1.json"), `{"pid":1}`);
  mkdirSync(join(base, "vm-guests"));
  mkdirSync(join(base, "logs"));
  mkdirSync(join(base, "release-check"));
  writeFileSync(join(base, "dashboard.log"), "log\n");
  const out = join(dir, "out");
  const sock = join(dir, "arbiter.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "sym.db"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const lines: string[] = [];
  const orig = console.error;
  const savedBin = process.env["MANDU_NET_GUARD_BIN"];
  const savedHome = process.env["HOME"];
  const savedManduHome = process.env["MANDU_HOME"];
  try {
    const B = base;
    const step = (name: string, cmd: string): string => `${cmd} 2>/dev/null; echo "${name}=$?" >> ${out}; `;
    const script =
      `: > ${out}; ` +
      step("manifest", `echo '{"pid":2}' > ${manifest}`) +
      // A new directory is not judged by the list (write-protection.md §2:
      // it never was); what would make it a forged record is refused.
      `mkdir ${B}/instances/forged 2>/dev/null; ` +
      step("newinst", `echo '{"pid":2}' > ${B}/instances/forged/manifest.json`) +
      step("link", `ln -s /tmp ${B}/cur2`) +
      step("current", `mv -T ${B}/cur2 ${B}/current`) +
      step("rmcurrent", `rm ${B}/current`) +
      step("tmplink", `ln -s ${B}/instances/x ${B}/.current.tmp-99`) +
      step("port", `echo 4444 > ${B}/dashboard-99.port`) +
      step("dlog", `echo x >> ${B}/dashboard.log`) +
      step("dash", `echo '{"pid":3}' > ${B}/dashboards/d1.json`) +
      step("guest", `echo '{"pid":3}' > ${B}/vm-guests/g.json`) +
      step("log", `echo x > ${B}/logs/arbiter-autostart.log`) +
      step("marker", `echo 4242 > ${B}/release-check/pending-4242`) +
      `mkdir ${B}/release-check/lock 2>/dev/null; ` +
      step("lockowner", `echo 4242 > ${B}/release-check/lock/owner`) +
      step("gatelink", `rm -rf ${B}/release-check && ln -s /tmp ${B}/release-check`) +
      step("base", `mv ${B} ${B}.away`) +
      step("free", `echo ok > ${B}/free.txt`) +
      step("lookalike", `echo ok > ${B}/current2`) +
      "true";
    console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
    process.env["MANDU_NET_GUARD_BIN"] = GUARD!;
    process.env["HOME"] = home;
    process.env["MANDU_HOME"] = join(home, ".mandu");
    const code = await main(
      ["--target", "claude", "--no-scope", "--no-landlock-net", "--no-reply-filter", "--no-net-proxy", "--no-exec-box", "--", "bash", "-c", script],
      {
        HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: join(home, ".mandu"), MANDU_MODE: "secrets", XDG_RUNTIME_DIR: dir,
      },
    );
    console.error = orig;
    const got = Object.fromEntries(readFileSync(out, "utf8").trim().split("\n").map((l) => l.split("=") as [string, string]));
    const said = `\nlauncher said:\n${lines.join("\n")}\nagent got: ${JSON.stringify(got)}`;
    assert.equal(code, 0, said);
    for (const k of ["manifest", "newinst", "current", "rmcurrent", "tmplink", "port", "dlog", "dash", "guest", "log", "marker", "lockowner", "gatelink", "base"]) {
      assert.notEqual(got[k], "0", `${k}: the agent changed a runtime registry entry${said}`);
    }
    assert.equal(readFileSync(manifest, "utf8"), `{"pid":1}`, "the manifest is unchanged");
    assert.ok(!existsSync(join(base, "instances", "forged", "manifest.json")), "no forged instance record");
    assert.ok(lstatSync(join(base, "current")).isSymbolicLink());
    assert.equal(readlinkSync(join(base, "current")), join("instances", "20261007-0000-abc-p1"), "`current` still names the instance");
    assert.ok(!existsSync(join(base, ".current.tmp-99")), "no temp promotion link");
    assert.ok(!existsSync(join(base, "dashboard-99.port")), "no forged port file");
    assert.equal(readFileSync(join(base, "dashboard.log"), "utf8"), "log\n");
    assert.equal(readFileSync(join(base, "dashboards", "d1.json"), "utf8"), `{"pid":1}`);
    assert.ok(!existsSync(join(base, "vm-guests", "g.json")), "no forged guest entry");
    assert.ok(!existsSync(join(base, "release-check", "pending-4242")), "no forged release-check marker");
    assert.ok(!existsSync(join(base, "release-check", "lock", "owner")), "no owner in the agent's lock dir");
    assert.ok(lstatSync(join(base, "release-check")).isDirectory(), "the gate is still a real directory");
    assert.ok(!existsSync(`${base}.away`) && existsSync(base), "the base was not renamed");
    // The controls: the rest of the runtime folder stays writable.
    assert.equal(got["link"], "0", `a new link in the base${said}`);
    assert.equal(got["free"], "0", `a new file in the base${said}`);
    assert.equal(got["lookalike"], "0", `current2 is not current${said}`);
  } finally {
    console.error = orig;
    if (savedBin === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = savedBin;
    if (savedHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = savedHome;
    if (savedManduHome === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = savedManduHome;
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
