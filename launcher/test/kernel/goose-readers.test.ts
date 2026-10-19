/**
 * goose-readers.test — Goose's NAME-ADDRESSED readers under a GUARDED
 * `mandu goose` (supported-agents.md §5.6, "The 1.53.0 tool_surface
 * discrepancy"; arbiter/policy/goose-inbound.ts NAME-ADDRESSED READERS): the
 * REAL goose, the REAL launcher (`main()`), the REAL mandu-net-guard, the
 * real arbiter and proxy, a scripted upstream.
 *
 * `load_skill{name: "<skill>/<file>"}` reads a skill's supporting file in
 * Goose's own process, named by no path field, so the model-context gates
 * cannot see which file it is. The guard is what holds the invariant:
 * Goose's open of a labelled file gets the twin, so the arbiter maps
 * load_skill only in a session whose launch claimed posture `confined`
 * (mapped-tools.ts GUARD_MAPPED_TOOLS) and masks its result whole anywhere
 * else. Here the supporting file is `creds.env` (a catalog shape, labelled
 * at launch) holding a canary value:
 *
 *   control  the same goose WITHOUT Mandu sends the canary to the model in
 *            the tool result (the call really reads the file);
 *   guarded  under the guard the result rides, and it is the twin: no model
 *            request carries the canary;
 *   gated    without the guard (MANDU_NO_KERNEL=1) Goose reads the raw file,
 *            and the result reaches the model masked whole.
 *
 * Self-SKIPs without goose; the guarded case also where the guard is not built or does not come
 * up live (the reason is printed).
 */
import { test, before, after, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { stateAxes } from "../axes.js";
import { FAKE_KEY, findGoose, gooseHome, gooseSkip, launchGoose, runGooseBare, startStand, type Stand } from "../lib/goose-login-stand.js";
import { resolveNativeBin } from "../../src/services/native-bins.js";

stateAxes("secrets"); // the shipped default: the guard serves twins on the confidentiality axis

const GOOSE = findGoose();
const GUARD = process.platform === "linux" ? resolveNativeBin("mandu-net-guard") : null;
const SKIP = gooseSkip(GOOSE) || (GUARD === null ? "mandu-net-guard is not built (scripts/build-native.sh)" : false);

const CANARY = "sk-live-GOOSE-SKILL-CANARY-4410";

let stand: Stand;
before(async () => { if (!gooseSkip(GOOSE)) stand = await startStand("mdu-goose-rd-"); });
after(async () => { await stand?.close(); });

/** A goose home whose launch directory carries the skill `deploy` with a
 *  labelled supporting file. */
function skillHome(name: string): string {
  const { home } = gooseHome(stand, name, `ANTHROPIC_API_KEY: ${FAKE_KEY}\n`);
  const skill = join(home, "work", ".agents", "skills", "deploy");
  mkdirSync(skill, { recursive: true });
  writeFileSync(join(skill, "SKILL.md"), "---\nname: deploy\ndescription: deploy the app\n---\nRun the deploy with the key in creds.env.\n");
  writeFileSync(join(skill, "creds.env"), `DEPLOY_KEY=${CANARY}\n`);
  return home;
}

function guardLive(t: TestContext, lines: string[]): boolean {
  if (lines.some((l) => /net-guard LIVE/.test(l))) return true;
  t.skip(`the guard did not come up live on this host:\n${lines.filter((l) => /guard|WARNING/.test(l)).join("\n")}`);
  return false;
}

test("control: goose without Mandu hands the model a skill's supporting file raw through load_skill", { skip: SKIP, timeout: 300_000 }, async () => {
  const home = skillHome("h-control");
  stand.seen.length = 0;
  stand.call = { name: "load_skill", input: { name: "deploy/creds.env" } };
  const { code, stderr } = await runGooseBare(GOOSE!, stand, home, { GOOSE_DISABLE_KEYRING: "1", ANTHROPIC_API_KEY: FAKE_KEY });
  assert.equal(code, 0, stderr);
  assert.ok(stand.seen.some((q) => q.body.includes(CANARY)), "the tool result carried the file's value: the call reads the file");
});

test("guarded: load_skill of a labelled supporting file never reaches the model raw", { skip: SKIP, timeout: 300_000 }, async (t) => {
  const home = skillHome("h-guarded");
  stand.seen.length = 0;
  stand.call = { name: "load_skill", input: { name: "deploy/creds.env" } };
  const { code, lines } = await launchGoose(GOOSE!, stand, home, { GOOSE_DISABLE_KEYRING: "1" }, { kernel: true, netGuardBin: GUARD! });
  if (!guardLive(t, lines)) return;
  assert.equal(code, 0, lines.join("\n"));
  assert.ok(stand.seen.length >= 2, `the turns reached the upstream (${stand.seen.length})`);
  const result = stand.seen.at(-1)!.body;
  assert.match(result, /tool_result/, "the last request carries the load_skill result");
  assert.match(result, /Loaded: deploy\/creds\.env/, "load_skill ran and read the file");
  assert.match(result, /DEPLOY_KEY=.?\$MDU:/, "what it read is the file's twin: the key kept, the value a placeholder");
  assert.ok(!/without Mandu's file guard/.test(result), "the guarded session's result is forwarded, not masked whole");
  for (const q of stand.seen) assert.ok(!q.body.includes(CANARY), "INVARIANT: no model request carries the labelled file's value");
});

test("gated (no guard): the same load_skill result is masked whole, never raw (the arbiter maps load_skill only under the guard)", { skip: gooseSkip(GOOSE), timeout: 300_000 }, async () => {
  const home = skillHome("h-gated");
  stand.seen.length = 0;
  stand.call = { name: "load_skill", input: { name: "deploy/creds.env" } };
  const { code, lines } = await launchGoose(GOOSE!, stand, home, { GOOSE_DISABLE_KEYRING: "1" }, { kernel: false });
  assert.equal(code, 0, lines.join("\n"));
  assert.ok(stand.seen.length >= 2, `the turns reached the upstream (${stand.seen.length})`);
  for (const q of stand.seen) assert.ok(!q.body.includes(CANARY), "INVARIANT: no model request carries the labelled file's value");
  const result = stand.seen.at(-1)!.body;
  assert.match(result, /tool_result/);
  assert.ok(!result.includes("Loaded: deploy/creds.env"), "nothing of the result rides in clear");
  assert.match(result, /without Mandu's file guard/, "the note says why it is hidden");
});
