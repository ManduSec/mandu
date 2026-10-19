/**
 * opencode2-confidentiality — when OpenCode 2 may run with the
 * confidentiality axis on (src/opencode2-confidentiality.ts;
 * supported-agents.md §2.3.1): the early check from the launch's facts, the
 * check of the composed launch, the refusal's words, and the seccomp probe.
 * Pure: no binary runs here (through main(): test/component/opencode-v2-standalone.test.ts;
 * the real binary under the real guard: drill-replay.test.ts
 * with MANDU_REPLAY_OPENCODE=2).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { spawnSync } from "node:child_process";
import {
  opencode2ConfidentialityMissing, opencode2ConfidentialityRefusal, opencode2ConfidentialityUnenforced, probeGuardNotify,
  type Opencode2ConfidentialityFacts, type Opencode2Enactment,
} from "../../src/opencode2-confidentiality.js";

const ALL_ON: Opencode2ConfidentialityFacts = {
  platform: "linux", netGuardOff: false, guardBin: true, seccompNotify: true, ownServerExe: true, writeProtectOff: false,
};
const whats = (f: Partial<Opencode2ConfidentialityFacts>): string[] =>
  opencode2ConfidentialityMissing({ ...ALL_ON, ...f }).map((m) => m.what);

test("every guard in force: nothing missing, the launch is allowed", () => {
  assert.deepEqual(opencode2ConfidentialityMissing(ALL_ON), []);
});

test("each missing protection is named, with its fix", () => {
  assert.match(whats({ netGuardOff: true })[0]!, /connect guard is turned off .*MANDU_NO_KERNEL/);
  assert.match(whats({ guardBin: false, guardBuildHint: "build with: X" })[0]!, /mandu-net-guard\) is not built/);
  assert.equal(opencode2ConfidentialityMissing({ ...ALL_ON, guardBin: false, guardBuildHint: "build with: X" })[0]!.fix, "build with: X");
  assert.match(whats({ seccompNotify: false })[0]!, /no seccomp user notification/);
  assert.match(whats({ ownServerExe: false })[0]!, /could not find the OpenCode 2 executable/);
  assert.match(whats({ writeProtectOff: true })[0]!, /MANDU_WRITE_PROTECT=0 turns off the write-protect guard/);
  // several at once: all listed
  assert.equal(whats({ netGuardOff: true, writeProtectOff: true, ownServerExe: false }).length, 3);
  // the guard's own lines are one chain: an opted-out guard is not also "not built"
  assert.equal(whats({ netGuardOff: true, guardBin: false, seccompNotify: null }).length, 1);
});

test("off Linux: one line (the guard is Linux only), not a list of everything that follows from it", () => {
  const m = opencode2ConfidentialityMissing({ ...ALL_ON, platform: "darwin", guardBin: false, seccompNotify: null });
  assert.equal(m.length, 1);
  assert.match(m[0]!.what, /Linux only/);
});

test("the refusal: one plain line, the mode, what is missing with the fix, the ways out", () => {
  const r = opencode2ConfidentialityRefusal("secrets", opencode2ConfidentialityMissing({ ...ALL_ON, writeProtectOff: true }));
  assert.ok(!r.includes("\n"));
  assert.match(r, /^mandu: refusing OpenCode 2 in mode secrets: Mandu keeps secrets from the model under OpenCode 2 only with its guards in force, and this launch lacks one: /);
  assert.match(r, /MANDU_WRITE_PROTECT=0 .*\(fix: unset MANDU_WRITE_PROTECT\)/);
  assert.match(r, /put a file's text into the conversation as if you had typed it/);
  assert.match(r, /`--mode off`/);
  assert.match(r, /npm i -g opencode-ai@1\.18\.35/);
  assert.match(opencode2ConfidentialityRefusal("full", [{ what: "a", fix: "b" }, { what: "c", fix: "d" }]), /in mode full: .*lacks some: a \(fix: b\); c \(fix: d\)\./);
});

const DIR = "/run/user/1000/mandu/scope-x/opencode-config";
const EXE = "/opt/opencode2/bin/opencode";
const ENACTED: Opencode2Enactment = {
  guardWrap: ["/x/mandu-net-guard", "--allow", "tcp:127.0.0.1:1", "--"],
  env: {
    MANDU_NET_GUARD_OWN_SERVER: EXE, MANDU_NET_GUARD_PROTECT: "1",
    OPENCODE_CONFIG_DIR: DIR, OPENCODE_CONFIG: `${DIR}/mandu-run.json`,
    OPENCODE_DISABLE_PROJECT_CONFIG: "1", OPENCODE_DISABLE_FILEWATCHER: "1",
  },
  ownServerExe: EXE,
  guardPolicy: { writeProtect: [{ path: "/home/u/.mandu", answer: "deny" }, { path: DIR, answer: "deny" }] },
  configDir: DIR,
};
const unenforced = (e: Partial<Opencode2Enactment>, env: Record<string, string | undefined> = {}): string[] =>
  opencode2ConfidentialityUnenforced({ ...ENACTED, ...e, env: { ...ENACTED.env, ...env } }).map((m) => m.what);

test("the composed launch: everything in force passes", () => {
  assert.deepEqual(unenforced({}), []);
});

test("the composed launch: a step that degraded on the way is caught", () => {
  assert.match(unenforced({ guardWrap: null })[0]!, /did not wrap the launch/);
  assert.match(unenforced({ guardWrap: ["/g", "--skip-unsupported", "--"] })[0]!, /unguarded .*--skip-unsupported/);
  assert.match(unenforced({}, { MANDU_NET_GUARD_OWN_SERVER: undefined })[0]!, /allowance does not name/);
  assert.match(unenforced({}, { MANDU_NET_GUARD_OWN_SERVER: "/usr/bin/other" })[0]!, /allowance does not name/);
  assert.match(unenforced({ ownServerExe: undefined })[0]!, /allowance does not name/);
  assert.match(unenforced({}, { MANDU_NET_GUARD_PROTECT: undefined })[0]!, /write-protect guard does not cover/);
  assert.match(unenforced({ guardPolicy: null })[0]!, /write-protect guard does not cover/);
  assert.match(unenforced({ guardPolicy: { writeProtect: [{ path: DIR, answer: "ask" }] } })[0]!, /write-protect guard does not cover/);
  assert.match(unenforced({}, { OPENCODE_CONFIG_DIR: "/home/u/.config/opencode" })[0]!, /config lockdown/);
  assert.match(unenforced({}, { OPENCODE_DISABLE_FILEWATCHER: undefined })[0]!, /config lockdown/);
  assert.match(unenforced({}, { OPENCODE_DISABLE_PROJECT_CONFIG: "0" })[0]!, /config lockdown/);
  assert.match(unenforced({}, { OPENCODE_CONFIG: "/tmp/elsewhere.json" })[0]!, /config lockdown/);
});

test("probeGuardNotify: the guard bin around `true`, without --skip-unsupported; only exit 0 is a yes", () => {
  const calls: Array<{ bin: string; args: readonly string[] }> = [];
  const fake = (status: number | null) => ((bin: string, args: readonly string[]) => {
    calls.push({ bin, args });
    return { status } as ReturnType<typeof spawnSync>;
  }) as unknown as typeof spawnSync;
  assert.equal(probeGuardNotify("/g", fake(0)), true);
  assert.deepEqual(calls[0], { bin: "/g", args: ["--", "true"] });
  assert.equal(probeGuardNotify("/g", fake(71)), false);
  assert.equal(probeGuardNotify("/g", fake(null)), false);
});
