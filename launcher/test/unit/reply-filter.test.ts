/**
 * reply-filter.test — the launch-composition of the user-reply egress filter
 * (packaging.md §5): default-on wrapper prepended to the launch prefix, degrading
 * to no wrapper (utility-only) when its runtime is missing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { applyReplyFilter, launcherReplyOutputFormat, REPLY_WRAP_RULE_ENV, replyWrapRuleEnv } from "../../src/reply-filter.js";
import { Layout } from "../../src/services/layout.js";
import { emptyMutation } from "../../src/backend/types.js";
import type { LaunchPlan } from "../../src/types.js";

const plan = (replyFilter: boolean): LaunchPlan => ({ replyFilter, argv: ["claude", "-p", "hello"] } as unknown as LaunchPlan);
const always = (): boolean => true;
const never = (): boolean => false;

test("default-on (dev): prepends the tsx reply-filter wrapper + `--` to the launch prefix", () => {
  const mut = emptyMutation();
  mut.launchPrefix = ["EXISTING"]; // an earlier prefix must be preserved AFTER the wrapper
  applyReplyFilter(plan(true), Layout.dev("/repo"), mut, always, () => {});
  assert.deepEqual(mut.launchPrefix, [
    "node", "--import", "file:///repo/interceptors/reply-filter/node_modules/tsx/dist/esm/index.mjs",
    "/repo/interceptors/reply-filter/src/run.ts",
    "--mandu-output-format=text",
    "--",
    "EXISTING",
  ]);
  assert.deepEqual(mut.env, {}); // no client-module env in dev
});

test("installed: prepends `node dist/reply-filter.mjs` + the arbiter client module env", () => {
  const mut = emptyMutation();
  applyReplyFilter(plan(true), Layout.installed("/opt/mandu"), mut, always, () => {});
  assert.deepEqual(mut.launchPrefix, [
    "node",
    "--no-warnings=ExperimentalWarning",
    "/opt/mandu/dist/reply-filter.mjs",
    "--mandu-output-format=text",
    "--",
  ]);
  assert.equal(mut.env["MANDU_ARBITER_CLIENT_MODULE"], "/opt/mandu/dist/arbiter-client.mjs");
});

test("--no-reply-filter / MANDU_REPLY_FILTER=0: no wrapper, launch prefix untouched", () => {
  const mut = emptyMutation();
  mut.launchPrefix = ["EXISTING"];
  applyReplyFilter(plan(false), Layout.dev("/repo"), mut, always, () => {});
  assert.deepEqual(mut.launchPrefix, ["EXISTING"]);
});

test("runtime missing: degrade to NO wrapper + a warning (utility-only, never hard-fail)", () => {
  const mut = emptyMutation();
  let warned = "";
  applyReplyFilter(plan(true), Layout.dev("/repo"), mut, never, (m) => { warned = m; });
  assert.deepEqual(mut.launchPrefix, []);
  assert.match(warned, /reply-filter runtime unavailable/);
});

test("truth-in-labeling: a wired reply-filter announces LIVE; opted-out is silent", () => {
  const on: string[] = [];
  applyReplyFilter(plan(true), Layout.dev("/repo"), emptyMutation(), always, (m) => on.push(m));
  assert.ok(on.some((m) => /reply-filter LIVE/.test(m)), `expected a LIVE banner, got ${JSON.stringify(on)}`);
  const off: string[] = [];
  applyReplyFilter(plan(false), Layout.dev("/repo"), emptyMutation(), always, (m) => off.push(m));
  assert.ok(!off.some((m) => /reply-filter LIVE/.test(m)), "opted-out reply-filter must not claim LIVE");
});


test("structured format comes from original agent argv while security prefixes remain intact", () => {
  const mut = emptyMutation();
  const prefixes = ["secret-twins", "--", "net-guard", "--", "landlock-net", "--"];
  mut.launchPrefix = [...prefixes];
  mut.argvPrefix = ["--settings", "{}"];
  applyReplyFilter({ ...plan(true), argv: ["claude", "--resume", "--output-format", "stream-json", "-p", "hello"] }, Layout.dev("/repo"), mut, always, () => {});
  assert.deepEqual(mut.launchPrefix.slice(4), ["--mandu-output-format=stream-json", "--", ...prefixes]); // 4 wrapper tokens: node --import <tsx esm> run.ts
  assert.deepEqual(mut.argvPrefix, ["--settings", "{}"]);
  assert.deepEqual(mut.env, {});
});

test("launcher detector stays aligned with standalone reply-filter detector", async () => {
  const path = "../../../interceptors/reply-filter/src/output-format.ts";
  const { replyOutputFormat } = await import(path) as { replyOutputFormat: (argv: string[]) => string };
  const cases = [
    ["claude"], ["supervisor", "--", "claude", "--output-format", "json"],
    ["claude", "--output-format", "yaml"], ["claude", "--", "--output-format", "json"],
    ["claude", "--system-prompt", "--output-format", "json"],
    ["claude", "--output-format", "json", "--output-format", "text"],
  ];
  for (const flag of ["--resume", "-r", "--debug", "-d", "--cloud", "--from-pr", "--prompt-suggestions", "--remote-control", "--teleport", "--worktree", "-w"]) {
    cases.push(["claude", flag, "--output-format", "stream-json"], ["claude", flag, "value", "--output-format=json"]);
  }
  for (const argv of cases) assert.equal(launcherReplyOutputFormat(argv), replyOutputFormat(argv), JSON.stringify(argv));
});

test("wrap rule (reply-row-reservation.md §17, differential-interactive.md §35): Goose's filter gets MANDU_REPLY_WRAP_RULE=terminal, OpenCode's none, every other target nothing", async () => {
  const goose = { replyFilter: true, target: "goose", argv: ["goose", "session"], arbiterHumanSock: "/run/h.sock" } as unknown as LaunchPlan;
  // Serial form: in mut.env (the filter strips it from its child, childEnv).
  const mut = emptyMutation();
  const w = applyReplyFilter(goose, Layout.dev("/repo"), mut, always, () => {});
  assert.equal(w?.filterEnv[REPLY_WRAP_RULE_ENV], "terminal");
  assert.equal(mut.env[REPLY_WRAP_RULE_ENV], "terminal");
  // Hand-off form: in the filter's own env only.
  const handed = emptyMutation();
  const h = applyReplyFilter(goose, Layout.dev("/repo"), handed, always, () => {}, { handOff: true });
  assert.equal(h?.filterEnv[REPLY_WRAP_RULE_ENV], "terminal");
  assert.equal(handed.env[REPLY_WRAP_RULE_ENV], undefined);
  // OpenCode: its wrap is unmodelled, so the filter asks for v1 heads only.
  assert.deepEqual(replyWrapRuleEnv("opencode"), { [REPLY_WRAP_RULE_ENV]: "none" });
  const oc = emptyMutation();
  const o = applyReplyFilter({ ...goose, target: "opencode", argv: ["opencode"] } as LaunchPlan, Layout.dev("/repo"), oc, always, () => {});
  assert.equal(o?.filterEnv[REPLY_WRAP_RULE_ENV], "none");
  assert.equal(oc.env[REPLY_WRAP_RULE_ENV], "none");
  for (const target of ["claude", "codex", "openclaw", "shell"] as const) {
    assert.deepEqual(replyWrapRuleEnv(target), {}, target);
    const m = emptyMutation();
    const r = applyReplyFilter({ ...goose, target } as LaunchPlan, Layout.dev("/repo"), m, always, () => {});
    assert.equal(r?.filterEnv[REPLY_WRAP_RULE_ENV], undefined, target);
  }
  // The name is the filter's (interceptors/reply-filter/src/reserve-block.ts).
  const path = "../../../interceptors/reply-filter/src/reserve-block.ts";
  const { WRAP_RULE_ENV } = await import(path) as { WRAP_RULE_ENV: string };
  assert.equal(REPLY_WRAP_RULE_ENV, WRAP_RULE_ENV);
});
