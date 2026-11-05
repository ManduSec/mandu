/**
 * linux-only-rung-parity — ONE answer to "is this launch line about a
 * Linux-only layer's absence?" (dashboard.md §4.21 *On the product page*).
 * The launcher asks it for `mandu doctor` (doctor-live.ts
 * `isLinuxOnlyRungLine`); the dashboard asks it to leave such a line out of
 * a macOS session's count of protections that did not start. The two ship
 * standalone, so the dashboard keeps a display copy (linux-only-rung.ts);
 * this test keeps the copy answering as the launcher does over real launch
 * lines, in the older wording and the newer, and checks that the launcher's
 * own grading off Linux and the dashboard's count agree.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import * as launcher from "../../launcher/src/doctor-live.js";
import * as dash from "../../dashboard/src/linux-only-rung.js";
import { postureFindings } from "../../launcher/src/services/observe.js";
import { deriveHealth } from "../../dashboard/src/session-health.js";
import type { ManduEvent } from "../../dashboard/src/event-model.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("off"); // pure line classification: no axis is exercised

/** Launch lines as the launcher prints them (exec-box-setup.ts,
 *  landlock-net-setup.ts, net-guard-setup.ts, services/manager.ts), plus
 *  the newer macOS wording and lines that must NOT read as Linux-only. */
const LINES = [
  // the older wording: a Linux native bin not built
  "mandu: exec-box is on by default, but the mandu-exec-box bin is not built. build with: cd interceptors && cargo build — proceeding WITHOUT it (the listed commands run normally; --no-exec-box silences this).",
  "mandu: the default-on whole-agent TCP confine is unavailable — the mandu-landlock-apply bin is not built; proceeding WITHOUT it (all TCP stays reachable). build with: …",
  "mandu: the default-on whole-agent connect-guard is unavailable — the mandu-net-guard bin is not built; proceeding WITHOUT it (the landlock-net port wrap / netns stay the boundary). build with: …",
  "mandu: the inspect_symbol network confine is unavailable: the mandu-landlock-apply bin is not built; inspect-mcp keeps the agent's TCP allow set",
  "mandu: exec-box is on by default, but `bwrap` (bubblewrap) is not installed, so the box cannot run — proceeding WITHOUT it",
  "mandu: the default-on whole-agent TCP confine is unavailable — this kernel has no Landlock TCP support; proceeding WITHOUT it (all TCP stays reachable).",
  "mandu: default whole-agent connect-guard cannot start on this machine: user namespaces are restricted; proceeding WITHOUT it.",
  // the newer wording
  "mandu: exec-box: Linux only (not part of the macOS posture)",
  "mandu: landlock-net: Linux only (not part of the macOS posture)",
  "mandu: net-guard: Linux only (not part of the macOS posture)",
  // not Linux-only: the macOS mechanism's own failure, a rung name with no Linux cause, other drops
  "mandu: the default-on whole-agent TCP confine (Seatbelt network rules) could not write its profile — proceeding WITHOUT it",
  "mandu: exec-box (sandbox-exec) could not start — proceeding WITHOUT it",
  "mandu: exec-box is on by default, but the arbiter socket /x is absent — proceeding WITHOUT it",
  "mandu: service 'net-proxy' is on by default but failed to start: 127.0.0.1:8790 is occupied — proceeding WITHOUT it (opt out explicitly with --no-net-proxy to silence this)",
  "mandu: fs rung DEGRADED: fs-sync opted out (--no-fs-sync) — raw CWD, no prefix map",
  "mandu: confidentiality — secrets are GATED (no-sandbox-exec)",
  "mandu: net-proxy LIVE — cooperative egress gate",
];

test("the dashboard's copy answers as the launcher's isLinuxOnlyRungLine, line by line, both wordings", () => {
  for (const line of LINES) assert.equal(dash.isLinuxOnlyRungLine(line), launcher.isLinuxOnlyRungLine(line), line);
  // Both sides of the question are exercised.
  assert.ok(LINES.filter((l) => launcher.isLinuxOnlyRungLine(l)).length >= 8);
  assert.ok(LINES.filter((l) => !launcher.isLinuxOnlyRungLine(l)).length >= 5);
  assert.deepEqual(dash.LINUX_ONLY_RUNG_RES.map(String), launcher.LINUX_ONLY_RUNG_RES.map(String));
});

test("a macOS session's count leaves out exactly the dropped lines the launcher's own grading moves to Linux only", () => {
  const { dropped } = postureFindings(LINES);
  const posture = {
    id: "p", sessionId: "s", turn: 0, ts: new Date().toISOString(), seq: 0, callId: null, parentId: null,
    kind: "launch_posture", view: "HumanView", boundary: "shell", emitter: "launcher", input: null, output: null,
    invariant: { violatedInvariant: false }, live: ["net-proxy"], dropped,
  } as unknown as ManduEvent;
  for (const platform of ["linux", "darwin"] as const) {
    const graded = launcher.gradeLaunch(LINES, platform);
    // The gated line has no gated posture here, so it counts on both sides.
    assert.equal(deriveHealth([posture], platform)!.droppedProtections, graded.dropped.length, platform);
  }
});
