/**
 * clean-host.test — when the launcher asks for the guard-hosted clean box's
 * reporter, and what it hands the guard (exec-routing.md §8.5.3).
 *
 * Axes: stated per case. The reporter is wanted only with the integrity axis
 * ON (a clean verdict un-masks a Bash result; with integrity OFF nothing is
 * masked), so each case names the pair it runs under.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanHostEnv, cleanHostGuardArgs, cleanHostSocket, cleanReporterWanted } from "../../src/clean-host.js";
import type { LaunchPlan } from "../../src/types.js";

const INJECTION = { integrity: true, confidentiality: false };
const SECRETS = { integrity: false, confidentiality: true };

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return { target: "claude", effectiveAxes: INJECTION, ...over } as LaunchPlan;
}
const built = () => true;

test("wanted: integrity ON on Linux with the box and the guard available", () => {
  assert.equal(cleanReporterWanted(plan(), "linux", built), true);
  assert.equal(cleanReporterWanted(plan({ effectiveAxes: { integrity: true, confidentiality: true } }), "linux", built), true);
});

test("not wanted: integrity OFF (the `secrets` default masks no Bash result)", () => {
  assert.equal(cleanReporterWanted(plan({ effectiveAxes: SECRETS }), "linux", built), false);
  assert.equal(cleanReporterWanted(plan({ effectiveAxes: undefined }), "linux", built), false);
});

test("not wanted: a missing piece (platform, box, clean box refused, guard off or not built, codex's own sandbox)", () => {
  // Axes: injection throughout.
  assert.equal(cleanReporterWanted(plan(), "darwin", built), false);
  assert.equal(cleanReporterWanted(plan({ execBox: false }), "linux", built), false);
  assert.equal(cleanReporterWanted(plan({ execCleanBox: false }), "linux", built), false);
  assert.equal(cleanReporterWanted(plan({ netGuard: false }), "linux", built), false);
  assert.equal(cleanReporterWanted(plan(), "linux", () => false), false);
  assert.equal(cleanReporterWanted(plan({ target: "codex" }), "linux", built), false);
  assert.equal(cleanReporterWanted(plan({ target: "codex", execBox: true }), "linux", built), true);
});

test("the hosted box's environment: the named launch variables, then the box's own configuration", () => {
  const env = cleanHostEnv({
    arbiterSock: "/run/a.sock",
    hostEnv: { PATH: "/usr/bin", HOME: "/h", XDG_RUNTIME_DIR: "/run/user/1", OPENAI_API_KEY: "sk-x", LD_PRELOAD: "/evil.so", TZ: "" },
    projectRoot: "/tmp/proj",
  });
  assert.deepEqual(env, [
    ["PATH", "/usr/bin"], ["HOME", "/h"], ["XDG_RUNTIME_DIR", "/run/user/1"],
    ["MANDU_ARBITER_SOCK", "/run/a.sock"], ["MANDU_WORKSPACE", "/tmp/proj"],
  ]);
});

test("the guard's arguments", () => {
  assert.equal(cleanHostSocket("/run/sid"), "/run/sid/clean.sock");
  assert.deepEqual(
    cleanHostGuardArgs({ socket: "/run/sid/clean.sock", boxBin: "/b", env: [["A", "1=2"]] }, "sid"),
    ["--clean-socket", "/run/sid/clean.sock", "--clean-session", "sid", "--clean-box", "/b", "--clean-env", "A=1=2"],
  );
});

test("the hosted box finds Mandu's own bubblewrap first, as the agent does", () => {
  const env = Object.fromEntries(cleanHostEnv({ arbiterSock: "/a", hostEnv: { PATH: "/usr/bin" }, bwrapDir: "/usr/lib/mandu/bin" }));
  assert.equal(env["PATH"], "/usr/lib/mandu/bin:/usr/bin");
  const bare = Object.fromEntries(cleanHostEnv({ arbiterSock: "/a", hostEnv: {}, bwrapDir: "/usr/lib/mandu/bin" }));
  assert.equal(bare["PATH"], "/usr/lib/mandu/bin");
});
