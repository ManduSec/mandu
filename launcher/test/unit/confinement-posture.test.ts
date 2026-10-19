/**
 * confinement-posture.test — the posture vocabulary + the refuse/degrade
 * decision table (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md §2, §3.1, §4).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  bindOnlyLines,
  gapExplanation,
  gatedNotice,
  guardOnlyLines,
  HOST_GAPS,
  isBindOnlyGap,
  onConfinementFailure,
  POSTURE_SENTENCE,
  POSTURES,
  resolveHostPosture,
  SETUP_COMMAND,
  type HostFacts,
} from "../../src/confinement-posture.js";

const linux = (o: Partial<HostFacts>): HostFacts => ({
  platform: "linux", bwrap: true, userns: true, apparmorRestricted: false,
  sandboxExec: false, landlockReadBlock: false, ...o,
});

test("resolveHostPosture: the Linux table (userns × Landlock backend × guard)", () => {
  const rows: Array<[Partial<HostFacts>, string, string | undefined]> = [
    // both layers
    [{ userns: true, landlockReadBlock: false, guard: true }, "confined", undefined],
    [{ userns: true, landlockReadBlock: true, guard: true }, "confined", undefined], // confined always wins
    // bind-only (finding 7, 2026-09-28): the mount layer without the guard is GATED
    [{ userns: true }, "gated", "no-guard"],
    [{ userns: true, guard: false }, "gated", "no-guard"],
    [{ userns: true, landlockReadBlock: true }, "gated", "no-guard"],
    [{ userns: true, guard: false, guardOff: true }, "gated", "guard-off"],
    [{ userns: true, apparmorRestricted: true, nesting: false }, "gated", "no-guard"],
    // no bind, no guard
    [{ userns: false, landlockReadBlock: false }, "gated", "userns-off"],
    [{ userns: false, landlockReadBlock: true }, "read-blocked", "userns-off"],
    [{ userns: false, apparmorRestricted: true }, "gated", "apparmor-userns"],
    [{ bwrap: false, userns: false, apparmorRestricted: true }, "gated", "no-bwrap"], // bwrap first: setup can't fix it
  ];
  for (const [facts, posture, gap] of rows) {
    const r = resolveHostPosture(linux(facts));
    assert.equal(r.posture, posture, JSON.stringify(facts));
    assert.equal(r.gap, gap, JSON.stringify(facts));
    assert.equal(r.bindGap, undefined, "no guard-only row here");
  }
});

test("bind-only (sandbox-security-review finding 7): gated with its own gap; the notice and doctor lines say what the mount layer covers and what it misses", () => {
  assert.ok(isBindOnlyGap("no-guard") && isBindOnlyGap("guard-off"));
  for (const g of HOST_GAPS.filter((x) => x !== "no-guard" && x !== "guard-off")) assert.ok(!isBindOnlyGap(g), g);
  // guardOff never lowers a present guard's posture (the caller clears `guard` for an opt-out)
  assert.deepEqual(resolveHostPosture(linux({ guard: true, guardOff: true })), { posture: "confined" });
  // guard-only is still confined (unchanged)
  assert.deepEqual(resolveHostPosture(linux({ userns: false, guard: true })), { posture: "confined", bindGap: "userns-off" });
  for (const gap of ["no-guard", "guard-off"] as const) {
    const { cause, fix } = gapExplanation(gap);
    assert.match(cause, /replaced while the AI runs/);
    assert.match(cause, gap === "guard-off" ? /turned off .*--no-net-guard/ : /not available/);
    assert.equal(fix, null, "no one-command fix");
    const n = gatedNotice(gap);
    assert.equal(n[0], "mandu: secrets are GATED, not confined, on this host.");
    assert.ok(n.some((l) => /mount layer still puts a placeholder/.test(l)));
    assert.ok(n.some((l) => /replaced while the agent runs is not covered/.test(l)));
    assert.ok(!n.some((l) => /One-time upgrade/.test(l)));
    const lines = bindOnlyLines({ posture: "gated", gap });
    assert.equal(lines.length, 2);
    assert.match(lines[0]!, /^partial layer in use: the mount layer puts a placeholder/);
    assert.match(lines[1]!, /^not covered without the file guard: a credential file replaced while the AI runs/);
  }
  assert.deepEqual(bindOnlyLines({ posture: "gated", gap: "userns-off" }), []);
  assert.deepEqual(bindOnlyLines({ posture: "confined" }), []);
  assert.deepEqual(guardOnlyLines({ posture: "gated", gap: "no-guard" }), []);
});

test("HOST_GAPS: every gap once, each with an explanation", () => {
  assert.equal(new Set(HOST_GAPS).size, HOST_GAPS.length);
  assert.equal(HOST_GAPS.length, 8);
  for (const g of HOST_GAPS) assert.ok(gapExplanation(g).cause.length > 10, g);
});

test("resolveHostPosture: the guard alone confines a host that cannot bind (plan 10 §11.7); the bind gap is named, never as a gap", () => {
  // no userns (Ubuntu 24.04 before `mandu setup`) + the guard → confined, bindGap
  assert.deepEqual(resolveHostPosture(linux({ userns: false, apparmorRestricted: true, guard: true })), { posture: "confined", bindGap: "apparmor-userns" });
  assert.deepEqual(resolveHostPosture(linux({ userns: false, guard: true })), { posture: "confined", bindGap: "userns-off" });
  assert.deepEqual(resolveHostPosture(linux({ bwrap: false, userns: false, guard: true })), { posture: "confined", bindGap: "no-bwrap" });
  // the guard beats the Landlock read-blocked spike too (confined > read-blocked)
  assert.deepEqual(resolveHostPosture(linux({ userns: false, landlockReadBlock: true, guard: true })), { posture: "confined", bindGap: "userns-off" });
  // with a bind the guard changes nothing about the name
  assert.deepEqual(resolveHostPosture(linux({ guard: true })), { posture: "confined" });
  // the guard is a Linux fact: it never lifts macOS or Windows
  assert.deepEqual(resolveHostPosture(linux({ platform: "darwin", sandboxExec: false, guard: true })), { posture: "gated", gap: "no-sandbox-exec" });
  assert.deepEqual(resolveHostPosture(linux({ platform: "win32", guard: true })), { posture: "gated", gap: "unsupported-os" });
  // the doctor lines for the guard-only posture name the second layer
  const lines = guardOnlyLines({ posture: "confined", bindGap: "apparmor-userns" });
  assert.match(lines[0]!, /file guard alone/);
  assert.match(lines[1]!, /mount layer unavailable: Ubuntu restricts/);
  assert.match(lines[2]!, /optional second layer: mandu setup/);
  assert.deepEqual(guardOnlyLines({ posture: "confined" }), []);
  assert.deepEqual(guardOnlyLines({ posture: "gated", gap: "userns-off" }), []);
  assert.equal(guardOnlyLines({ posture: "confined", bindGap: "userns-off" }).length, 2, "no fix for a kernel knob: no second-layer line");
});

test("resolveHostPosture: a bind that would stop nested sandboxes (Ubuntu 26.04) is left off where the guard can serve the twins", () => {
  // os-test-matrix.md §10.14.1 item 6: bwrap + userns work, nesting under the bind does not
  assert.deepEqual(resolveHostPosture(linux({ apparmorRestricted: true, nesting: false, guard: true })), { posture: "confined", bindGap: "bwrap-nesting" });
  // without the guard the bind stays (confinement wins over the agent's
  // shell), but bind-only is gated since finding 7
  assert.deepEqual(resolveHostPosture(linux({ apparmorRestricted: true, nesting: false })), { posture: "gated", gap: "no-guard" });
  // nesting works, or was not probed: the bind is used as before
  assert.deepEqual(resolveHostPosture(linux({ nesting: true, guard: true })), { posture: "confined" });
  assert.deepEqual(resolveHostPosture(linux({ guard: true })), { posture: "confined" });
  // a host that cannot bind at all keeps its own reason
  assert.deepEqual(resolveHostPosture(linux({ userns: false, nesting: false, guard: true })), { posture: "confined", bindGap: "userns-off" });
  // doctor: the mount layer is OFF (by choice), not unavailable; `mandu setup`
  // installs Mandu's own bubblewrap, whose profile lets a sandbox nest
  // (bwrap-grant.ts), so it is offered as the optional second layer
  const lines = guardOnlyLines({ posture: "confined", bindGap: "bwrap-nesting" });
  assert.equal(lines.length, 3);
  assert.match(lines[1]!, /^mount layer off: .*lets no sandbox start inside another.*Codex's shell/);
  assert.match(lines[2]!, /^optional second layer: mandu setup/);
  assert.equal(gapExplanation("bwrap-nesting").fix, "mandu setup");
});

test("resolveHostPosture: macOS is read-blocked (Seatbelt), Windows is gated", () => {
  assert.deepEqual(resolveHostPosture(linux({ platform: "darwin", sandboxExec: true })), { posture: "read-blocked" });
  assert.deepEqual(resolveHostPosture(linux({ platform: "darwin", sandboxExec: false })), { posture: "gated", gap: "no-sandbox-exec" });
  assert.deepEqual(resolveHostPosture(linux({ platform: "win32" })), { posture: "gated", gap: "unsupported-os" });
});

test("onConfinementFailure: host gaps degrade by default; arbiter failures refuse; require-confinement always refuses", () => {
  const t = (kind: "host" | "arbiter", requireConfinement: boolean, bestEffort: boolean) =>
    onConfinementFailure(kind, { requireConfinement, bestEffort });
  assert.equal(t("host", false, false), "degrade");   // the new default: root stays optional
  assert.equal(t("host", false, true), "degrade");    // --best-effort = a synonym for the default
  assert.equal(t("host", true, false), "refuse");
  assert.equal(t("host", true, true), "refuse");      // require wins over --best-effort
  assert.equal(t("arbiter", false, false), "refuse"); // an incident, not a host condition
  assert.equal(t("arbiter", false, true), "degrade");
  assert.equal(t("arbiter", true, false), "refuse");
  assert.equal(t("arbiter", true, true), "refuse");
});

test("gatedNotice: names the posture, the honest consequence, the fix, and doctor", () => {
  const n = gatedNotice("apparmor-userns");
  assert.equal(n[0], "mandu: secrets are GATED, not confined, on this host.");
  assert.ok(n.some((l) => /Ubuntu restricts unprivileged user namespaces \(AppArmor\)/.test(l)));
  assert.ok(n.some((l) => /can still read your credential files/.test(l)));
  assert.ok(n.some((l) => l.includes(`One-time upgrade:  ${SETUP_COMMAND}`)));
  assert.ok(n.at(-1)!.includes("mandu doctor"));
  // never the host-global sysctl
  assert.ok(!n.join("\n").includes("sysctl"));
});

test("gatedNotice: a gap `mandu setup` cannot fix never offers it", () => {
  assert.ok(gatedNotice("no-bwrap").some((l) => l.includes("sudo apt install bubblewrap")));
  for (const gap of ["userns-off", "unsupported-os", "no-sandbox-exec"] as const) {
    assert.equal(gapExplanation(gap).fix, null);
    assert.ok(!gatedNotice(gap).some((l) => /One-time upgrade/.test(l)), gap);
  }
});

test("sentences: every posture has one; only `confined` makes the absent-bytes claim", () => {
  for (const p of POSTURES) assert.ok(POSTURE_SENTENCE[p].length > 20);
  assert.match(POSTURE_SENTENCE.confined, /placeholder copy of each credential file, never the real one/);
  for (const p of POSTURES) assert.doesNotMatch(POSTURE_SENTENCE[p], /symbol|twin|the model\b/, `${p}: plain words (release checklist d5)`);
  assert.doesNotMatch(POSTURE_SENTENCE.gated, /absent/);
  assert.match(POSTURE_SENTENCE.gated, /can still read/);
  // A rule (a file's "may be sent to" host, an Always-allow) sends a secret
  // with no question asked: never "nothing is sent out without your OK"
  // (docs/design/ui/dashboard.md §4.25d).
  assert.match(POSTURE_SENTENCE.gated, /a secret is sent out only where a rule or your OK allows/);
  for (const p of POSTURES) assert.doesNotMatch(POSTURE_SENTENCE[p], /without your OK|cannot leave|can't leave/, p);
});
