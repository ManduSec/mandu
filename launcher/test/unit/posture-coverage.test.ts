/**
 * posture-coverage.test — the posture decided over a COVERAGE, one row per
 * chokepoint (confinement-posture.ts `resolvePosture`; docs/design/agents/
 * openclaw-plugin.md §3.4):
 *
 *   - every files row gives its posture, the other rows never lift it;
 *   - a wrapped launch's host facts derive into a coverage whose posture is
 *     exactly `resolveHostPosture`'s, over the whole host grid;
 *   - the OpenClaw plugin's row (the note's §3.4 table) is `gated` with the
 *     gap `openclaw-plugin`, its own sentence (no egress promise) and notice;
 *   - the wire parser the arbiter decides an attachment by takes a coverage
 *     exactly or nothing;
 *   - a route the service found lost (openclaw-plugin.md §3.6): model calls
 *     around the proxy decide first (`gated` / `model-route-lost`), and an
 *     attachment may claim its kind's coverage or less, never more.
 *
 * Pure; no privilege. Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ATTACHMENT_COVERAGE,
  ATTACHMENT_GAPS,
  attachmentCoverage,
  attachmentCoverageProblem,
  attachmentSessionId,
  gapExplanation,
  gatedNotice,
  GAP_SENTENCE,
  hostCoverage,
  HOST_GAPS,
  isAttachmentKind,
  isRouteGap,
  parseCoverage,
  POSTURE_GAPS,
  POSTURE_SENTENCE,
  postureSentence,
  resolveHostPosture,
  resolvePosture,
  type Coverage,
  type HostFacts,
} from "../../src/confinement-posture.js";

const REST = { modelContext: "proxy", exec: "sandbox", egress: "gate", replies: "terminal" } as const;

test("resolvePosture: the files row names the posture; the other rows never lift it", () => {
  const rows: Array<[Coverage, ReturnType<typeof resolvePosture>]> = [
    [{ ...REST, files: { by: "guard" }, ownState: "walled" }, { posture: "confined" }],
    [{ ...REST, files: { by: "guard", mountGap: "apparmor-userns" }, ownState: "walled" }, { posture: "confined", bindGap: "apparmor-userns" }],
    [{ ...REST, files: { by: "read-deny" }, ownState: "walled" }, { posture: "read-blocked" }],
    [{ ...REST, files: { by: "read-deny", why: "userns-off" }, ownState: "walled" }, { posture: "read-blocked", gap: "userns-off" }],
    [{ ...REST, files: { by: "mount", why: "no-guard" }, ownState: "readable" }, { posture: "gated", gap: "no-guard" }],
    [{ ...REST, files: { by: "mount", why: "guard-off" }, ownState: "walled" }, { posture: "gated", gap: "guard-off" }],
    [{ ...REST, files: { by: "none", why: "no-bwrap" }, ownState: "readable" }, { posture: "gated", gap: "no-bwrap" }],
    [ATTACHMENT_COVERAGE["openclaw-plugin"], { posture: "gated", gap: "openclaw-plugin" }],
  ];
  for (const [c, want] of rows) assert.deepEqual(resolvePosture(c), want, JSON.stringify(c.files));
  // a walled own state, a sandbox and a gate do not lift uncovered files
  assert.deepEqual(resolvePosture({ ...REST, files: { by: "none", why: "openclaw-plugin" }, ownState: "walled" }), { posture: "gated", gap: "openclaw-plugin" });
});

test("hostCoverage: the host facts derive into a coverage whose posture is resolveHostPosture's, over the whole grid", () => {
  let shapes = 0;
  for (const platform of ["linux", "darwin", "win32"] as const) {
    for (const bwrap of [true, false]) for (const userns of [true, false]) for (const apparmorRestricted of [true, false])
      for (const sandboxExec of [true, false]) for (const landlockReadBlock of [true, false])
        for (const guard of [true, false, undefined]) for (const guardOff of [true, false]) for (const nesting of [true, false, undefined]) {
          const f: HostFacts = {
            platform, bwrap, userns, apparmorRestricted, sandboxExec, landlockReadBlock,
            ...(guard !== undefined ? { guard } : {}), guardOff, ...(nesting !== undefined ? { nesting } : {}),
          };
          const c = hostCoverage(f);
          assert.deepEqual(resolvePosture(c), resolveHostPosture(f), JSON.stringify(f));
          // the wrapper's rows; Mandu's own state walled exactly where the files are covered
          assert.equal(c.modelContext, "proxy");
          assert.equal(c.exec, "sandbox");
          assert.equal(c.egress, "gate");
          assert.equal(c.replies, "terminal");
          assert.equal(c.ownState, c.files.by === "guard" || c.files.by === "read-deny" ? "walled" : "readable");
          // what the host says, parsed back from the wire, is the same coverage
          assert.deepEqual(parseCoverage(JSON.parse(JSON.stringify(c))), c);
          shapes++;
        }
  }
  assert.ok(shapes > 1000);
  assert.equal(hostCoverage({ platform: "linux", bwrap: true, userns: true, apparmorRestricted: false, sandboxExec: false, landlockReadBlock: false, guard: true }, { egressGateOff: true }).egress, "none");
});

test("the OpenClaw plugin's coverage (openclaw-plugin.md §3.4): gated with its own gap, sentence and notice", () => {
  const c = ATTACHMENT_COVERAGE["openclaw-plugin"];
  assert.deepEqual(c, {
    modelContext: "proxy",
    files: { by: "none", why: "openclaw-plugin" },
    exec: "policy",
    egress: "none",
    replies: "chat",
    ownState: "readable",
  });
  assert.deepEqual(ATTACHMENT_GAPS, ["openclaw-plugin"]);
  assert.ok(isAttachmentKind("openclaw-plugin") && !isAttachmentKind("apparmor-userns") && !isAttachmentKind("toString"));
  assert.equal(HOST_GAPS.length, 8, "an attachment's gap is not a host gap");
  assert.deepEqual(POSTURE_GAPS, [...HOST_GAPS, "openclaw-plugin", "model-route-lost"]);

  // the gated sentence promises an egress check the attachment does not make
  assert.match(POSTURE_SENTENCE.gated, /sent out only where a rule or your OK allows/);
  const s = postureSentence({ posture: "gated", gap: "openclaw-plugin" });
  assert.equal(s, GAP_SENTENCE["openclaw-plugin"]);
  assert.doesNotMatch(s, /sent out only where/);
  assert.match(s, /every model call goes through Mandu/);
  assert.match(s, /read your real files/);
  assert.match(s, /connect anywhere unchecked/);
  assert.match(s, /Mandu's own records/);
  assert.match(s, /a rule, not a wall/);
  // every other gap keeps the posture's own sentence
  for (const gap of HOST_GAPS) assert.equal(postureSentence({ posture: "gated", gap }), POSTURE_SENTENCE.gated, gap);
  assert.equal(postureSentence({ posture: "confined" }), POSTURE_SENTENCE.confined);

  const { cause, fix } = gapExplanation("openclaw-plugin");
  assert.equal(fix, null, "no one-command fix: the confined form is another way to run the Gateway");
  assert.match(cause, /attached to your OpenClaw Gateway as a plugin/);
  assert.match(cause, /mandu openclaw gateway/);
  const n = gatedNotice("openclaw-plugin");
  assert.ok(!isRouteGap("openclaw-plugin"));
  assert.equal(n[0], "mandu: secrets are GATED, not confined, in this OpenClaw Gateway.");
  assert.ok(n.some((l) => /nothing checks where they send them/.test(l)));
  assert.ok(!n.some((l) => /One-time upgrade/.test(l)));
  assert.equal(gatedNotice("apparmor-userns")[0], "mandu: secrets are GATED, not confined, on this host.", "a host gap's notice is unchanged");
});

test("parseCoverage: a coverage exactly, or nothing", () => {
  const c = ATTACHMENT_COVERAGE["openclaw-plugin"];
  assert.deepEqual(parseCoverage(c), c);
  const bad: unknown[] = [
    null, [], "proxy", {},
    { ...c, extra: true },
    (({ replies: _r, ...rest }) => rest)(c),
    { ...c, modelContext: "elsewhere" },
    { ...c, exec: "box" },
    { ...c, egress: "maybe" },
    { ...c, replies: "email" },
    { ...c, ownState: "hidden" },
    { ...c, files: { by: "none" } },
    { ...c, files: { by: "none", why: "made-up" } },
    { ...c, files: { by: "none", why: "openclaw-plugin", note: 1 } },
    { ...c, files: { by: "mount", why: "apparmor-userns" } },
    { ...c, files: { by: "guard", mountGap: "openclaw-plugin" } },
    { ...c, files: { by: "teleport" } },
    // a covered files row beside a readable own state: not a coverage
    { ...c, files: { by: "guard" } },
    { ...c, files: { by: "read-deny" } },
  ];
  for (const v of bad) assert.equal(parseCoverage(v), null, JSON.stringify(v));
  assert.deepEqual(parseCoverage({ ...c, files: { by: "guard" }, ownState: "walled" }), { ...c, files: { by: "guard" }, ownState: "walled" });
});

test("a route found lost (§3.6): model calls around the proxy decide first; an attachment claims its kind's coverage or less", () => {
  const kind = "openclaw-plugin" as const;
  // The full coverage, and each loss.
  assert.deepEqual(attachmentCoverage(kind), ATTACHMENT_COVERAGE[kind]);
  const noModel = attachmentCoverage(kind, { modelContext: true });
  assert.equal(noModel.modelContext, "none");
  assert.deepEqual(resolvePosture(noModel), { posture: "gated", gap: "model-route-lost" });
  const noPolicy = attachmentCoverage(kind, { policy: true });
  assert.deepEqual([noPolicy.exec, noPolicy.replies, noPolicy.modelContext], ["none", "none", "proxy"]);
  assert.deepEqual(resolvePosture(noPolicy), { posture: "gated", gap: kind }, "the plugin gone alone keeps the model context: the gap stays the kind's");
  const all = attachmentCoverage(kind, { modelContext: true, policy: true });
  assert.deepEqual(resolvePosture(all), { posture: "gated", gap: "model-route-lost" });
  // Model calls around the proxy decide first, whatever the files row covers.
  assert.deepEqual(resolvePosture({ ...REST, modelContext: "none", files: { by: "guard" }, ownState: "walled" }), { posture: "gated", gap: "model-route-lost" });
  // Each one parses back exactly (the arbiter takes it off the wire).
  for (const x of [noModel, noPolicy, all]) assert.deepEqual(parseCoverage(JSON.parse(JSON.stringify(x))), x);
  // The arbiter's rule: the kind's coverage or less.
  for (const x of [ATTACHMENT_COVERAGE[kind], noModel, noPolicy, all]) assert.equal(attachmentCoverageProblem(kind, x), null);
  assert.match(attachmentCoverageProblem(kind, { ...ATTACHMENT_COVERAGE[kind], exec: "sandbox" })!, /exec row/);
  assert.match(attachmentCoverageProblem(kind, { ...ATTACHMENT_COVERAGE[kind], egress: "gate" })!, /egress row/);
  assert.match(attachmentCoverageProblem(kind, { ...ATTACHMENT_COVERAGE[kind], replies: "terminal" })!, /replies row/);
  assert.match(attachmentCoverageProblem(kind, { ...REST, files: { by: "guard" }, ownState: "walled" })!, /files row/);
  // Its words: the gap's own sentence and cause; the notice says where.
  assert.ok(isRouteGap("model-route-lost") && !isRouteGap("openclaw-plugin") && !isAttachmentKind("model-route-lost"));
  const s = postureSentence({ posture: "gated", gap: "model-route-lost" });
  assert.equal(s, GAP_SENTENCE["model-route-lost"]);
  assert.match(s, /no longer sends every model call through Mandu/);
  assert.doesNotMatch(s, /The AI sees your secrets masked/, "never the covered claim");
  assert.match(GAP_SENTENCE["openclaw-plugin"]!, /The AI sees your secrets masked/, "the covered claim, as the plugin gap words it");
  assert.match(s, /as they are, not masked/);
  const { cause, fix } = gapExplanation("model-route-lost");
  assert.equal(fix, null);
  assert.match(cause, /mandu openclaw install`? again, then `?openclaw gateway restart/);
  assert.match(cause, /keeps the config it loaded until it restarts/);
  const n = gatedNotice("model-route-lost");
  assert.equal(n[0], "mandu: secrets are GATED, not confined, in this OpenClaw Gateway.");
  assert.ok(n.some((l) => /go around Mandu carry your secrets as they are/.test(l)));
});

test("attachmentSessionId: `openclaw:<agent id>`, shaped like a session id", () => {
  assert.equal(attachmentSessionId("openclaw-plugin", "main"), "openclaw:main");
  assert.equal(attachmentSessionId("openclaw-plugin", "ops team/1"), "openclaw:ops-team-1");
  assert.equal(attachmentSessionId("openclaw-plugin", ""), "openclaw:default");
  const long = attachmentSessionId("openclaw-plugin", "x".repeat(500));
  assert.equal(long.length, 128);
  assert.match(long, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
});
