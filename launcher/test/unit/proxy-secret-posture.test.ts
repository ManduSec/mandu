/**
 * proxy-secret-posture.test — the MANDU_SECRET_POSTURE a launch hands its
 * model proxy (src/proxy-secret-posture.ts; handling-prompt.md §2): the
 * `read-blocked` prediction matches what the secret setup does on macOS, and
 * every other host reports nothing (the prompt stays byte-identical).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { proxySecretPosture } from "../../src/proxy-secret-posture.js";
import { resolveHostPosture } from "../../src/confinement-posture.js";
import { SANDBOX_EXEC } from "../../src/seatbelt-profile.js";

const has = (...cmds: string[]) => (c: string): boolean => cmds.includes(c);

test("macOS with the confidentiality axis ON and /usr/bin/sandbox-exec: read-blocked", () => {
  assert.equal(proxySecretPosture({ platform: "darwin", confidentiality: true, commandExists: has(SANDBOX_EXEC) }), "read-blocked");
});

test("macOS: only /usr/bin/sandbox-exec counts; a bare `sandbox-exec` a PATH entry answers for is never asked about", () => {
  const asked: string[] = [];
  const onPathOnly = (c: string): boolean => { asked.push(c); return c === "sandbox-exec"; };
  assert.equal(proxySecretPosture({ platform: "darwin", confidentiality: true, commandExists: onPathOnly }), undefined);
  assert.deepEqual(asked, [SANDBOX_EXEC]);
});

test("nothing to report: axis OFF, no sandbox-exec (gated), Linux, Windows", () => {
  assert.equal(proxySecretPosture({ platform: "darwin", confidentiality: false, commandExists: has(SANDBOX_EXEC) }), undefined);
  assert.equal(proxySecretPosture({ platform: "darwin", confidentiality: true, commandExists: has() }), undefined);
  assert.equal(proxySecretPosture({ platform: "linux", confidentiality: true, commandExists: has(SANDBOX_EXEC, "bwrap") }), undefined);
  assert.equal(proxySecretPosture({ platform: "win32", confidentiality: true, commandExists: has(SANDBOX_EXEC) }), undefined);
});

test("the prediction agrees with the host posture the launch and doctor resolve on macOS", () => {
  for (const sandboxExec of [true, false]) {
    const host = resolveHostPosture({
      platform: "darwin", bwrap: false, userns: false, apparmorRestricted: false,
      sandboxExec, landlockReadBlock: false, guard: false, guardOff: false,
    });
    const predicted = proxySecretPosture({ platform: "darwin", confidentiality: true, commandExists: () => sandboxExec });
    assert.equal(predicted === "read-blocked", host.posture === "read-blocked", `sandbox-exec ${sandboxExec}: host says ${host.posture}`);
  }
});

test("the real check on this host: /usr/bin/sandbox-exec by path (macOS ships it)", () => {
  const got = proxySecretPosture({ platform: process.platform, confidentiality: true });
  if (process.platform === "darwin") assert.equal(got, "read-blocked");
  else assert.equal(got, undefined);
});
