/**
 * openclaw-argv — the allowlist of OpenClaw launch shapes (src/openclaw-argv.ts).
 * Only shapes whose agent loop runs inside the wrap and reads Mandu's routing
 * launch; a Gateway client, the Gateway service, `crestodian`, `--container`
 * and every other subcommand are refused. Bare `mandu openclaw` maps to `chat`
 * (openclawDefaultArgv), so onboarding / Crestodian never starts under Mandu. Facts probed on OpenClaw 2026.6.35 (2026-09-27).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { openclawDefaultArgv, openclawGatewayClientNotice, openclawLaunchRefusal, openclawRunsGateway, openclawRunsLocally, readOpenclawArgv } from "../../src/openclaw-argv.js";
import { parse } from "../../src/parse.js";
import { testRuntimeDir } from "../lib/test-runtime.js";

const ENV = { HOME: "/home/u", XDG_RUNTIME_DIR: testRuntimeDir() }; // a private dir, never another account's /run/user/<uid> (test-organization.md §8.7)
const OPT_IN = { MANDU_OPENCLAW_GATEWAY_CLIENT: "1" };

test("readOpenclawArgv: npm bin, source checkout, npx, global flags (with values), bare, wrapper scripts", () => {
  assert.deepEqual(readOpenclawArgv(["openclaw", "tui", "--session", "s"]), { sub: "tui", rest: ["--session", "s"], globals: [] });
  assert.deepEqual(readOpenclawArgv(["/usr/bin/openclaw", "--profile", "work", "--dev", "chat"]), { sub: "chat", rest: [], globals: ["--profile", "--dev"] });
  assert.deepEqual(readOpenclawArgv(["openclaw", "--log-level=debug", "chat"]), { sub: "chat", rest: [], globals: ["--log-level"] });
  assert.deepEqual(readOpenclawArgv(["node", "/src/openclaw/openclaw.mjs", "agent", "--local"]), { sub: "agent", rest: ["--local"], globals: [] });
  assert.deepEqual(readOpenclawArgv(["npx", "openclaw", "chat"]), { sub: "chat", rest: [], globals: [] });
  assert.deepEqual(readOpenclawArgv(["openclaw"]), { sub: "", rest: [], globals: [] });
  assert.deepEqual(readOpenclawArgv(["openclaw", "--no-color"]), { sub: "", rest: [], globals: ["--no-color"] });
  assert.equal(readOpenclawArgv(["./my-openclaw-wrapper.sh", "tui"]), null, "a wrapper hides the shape: --target vouches for it");
});

test("allowed: the confined shapes (embedded runtime, the Gateway itself under the wrap) and help/version", () => {
  for (const argv of [
    ["openclaw", "chat"], ["openclaw", "terminal"], ["openclaw", "--profile", "w", "chat", "--session", "x"],
    ["openclaw", "tui", "--local"], ["openclaw", "tui", "--session", "x", "--local"],
    ["openclaw", "agent", "--local", "-m", "hi"], ["node", "/x/openclaw.mjs", "agent", "--local", "--json"],
    ["openclaw", "gateway"], ["openclaw", "gateway", "--port", "1", "--auth", "none"], ["openclaw", "gateway", "run", "--force"],
    ["openclaw", "--version"], ["openclaw", "-V"], ["openclaw", "--help"], ["openclaw", "help"], ["openclaw", "acp", "--help"],
  ]) {
    assert.equal(openclawLaunchRefusal(argv, {}), null, `${argv.join(" ")} must launch`);
  }
});

test("refused: Gateway clients (tui / agent without --local, acp, acp client), opt-in opens exactly these", () => {
  for (const argv of [["openclaw", "tui"], ["openclaw", "tui", "--session", "x"], ["openclaw", "agent", "-m", "hi"], ["node", "/x/openclaw.mjs", "tui"], ["openclaw", "acp"], ["openclaw", "acp", "client"]]) {
    const why = openclawLaunchRefusal(argv, {});
    assert.ok(why && /drives an OpenClaw Gateway/.test(why) && /OUTSIDE this confinement/.test(why), `${argv.join(" ")} must be refused`);
    assert.match(why!, /MANDU_OPENCLAW_GATEWAY_CLIENT=1/, "the refusal names the opt-in");
    assert.equal(openclawLaunchRefusal(argv, OPT_IN), null, `${argv.join(" ")} opens with the opt-in`);
  }
  assert.match(openclawLaunchRefusal(["openclaw", "tui"], {})!, /mandu openclaw chat/, "the refusal names the confined alternative");
  assert.notEqual(openclawLaunchRefusal(["openclaw", "tui"], { MANDU_OPENCLAW_GATEWAY_CLIENT: "0" }), null);
});

test("refused even with the opt-in: bare openclaw (onboarding / Crestodian), crestodian, the Gateway service, --container, anything else", () => {
  const cases: Array<[string[], Record<string, string>, RegExp]> = [
    [["openclaw"], {}, /bare `openclaw` starts onboarding or Crestodian/],
    [["openclaw", "--dev"], {}, /bare `openclaw`/],
    [["openclaw", "crestodian", "--message", "status"], {}, /Crestodian is the setup and repair assistant/],
    [["openclaw", "gateway", "start"], {}, /manages the Gateway SERVICE/],
    [["openclaw", "gateway", "--port", "1", "restart"], {}, /gateway restart/],
    [["openclaw", "gateway", "call", "agent"], {}, /gateway call/],
    [["openclaw", "--container", "box", "chat"], {}, /inside a container/],
    [["openclaw", "chat"], { OPENCLAW_CONTAINER: "box" }, /inside a container/],
    [["openclaw", "infer", "model", "run", "--local"], {}, /not an agent shape Mandu confines/],
    [["openclaw", "configure"], {}, /not an agent shape/],
    [["openclaw", "message", "send"], {}, /not an agent shape/],
  ];
  for (const [argv, env, re] of cases) {
    const why = openclawLaunchRefusal(argv, { ...OPT_IN, ...env });
    assert.ok(why, `${argv.join(" ")} must be refused`);
    assert.match(why!, re);
  }
  assert.match(openclawLaunchRefusal(["openclaw"], {})!, /mandu openclaw chat/, "bare `mandu openclaw` points at chat");
});

test("the Gateway service stays refused; the advice names the plugin (mandu openclaw install) and says when it is already attached", () => {
  const argv = ["openclaw", "gateway", "start"];
  const notAttached = openclawLaunchRefusal(argv, {}, { attached: () => false })!;
  assert.match(notAttached, /manages the Gateway SERVICE/);
  assert.match(notAttached, /mandu serve start`, then `mandu openclaw install/);
  assert.equal(openclawLaunchRefusal(argv, {})!, notAttached, "no probe: the not-installed advice");
  const attached = openclawLaunchRefusal(argv, {}, { attached: () => true })!;
  assert.match(attached, /refusing `openclaw gateway`/, "still refused: this launch would protect nothing");
  assert.match(attached, /already attached to Mandu through its plugin/);
  assert.match(attached, /Run `openclaw gateway start` without `mandu`/);
  const broken = openclawLaunchRefusal(argv, {}, { attached: () => { throw new Error("unreadable"); } })!;
  assert.equal(broken, notAttached, "a probe that fails is 'not attached'");
  // The probe is asked only for a Gateway-service shape.
  let asked = 0;
  assert.equal(openclawLaunchRefusal(["openclaw", "chat"], {}, { attached: () => { asked++; return true; } }), null);
  assert.equal(openclawLaunchRefusal(["openclaw", "gateway"], {}, { attached: () => { asked++; return true; } }), null);
  assert.equal(asked, 0);
});

test("parse: a refused shape throws before anything launches; confined shapes and non-openclaw targets parse", () => {
  assert.throws(() => parse(["openclaw", "tui"], ENV), /refusing `openclaw tui`/);
  assert.throws(() => parse(["--target", "openclaw", "--", "openclaw", "agent", "-m", "x"], ENV), /refusing `openclaw agent`/);
  assert.throws(() => parse(["openclaw", "gateway", "start"], ENV), /Gateway SERVICE/);
  assert.equal(parse(["openclaw", "chat"], ENV).target, "openclaw");
  assert.equal(parse(["openclaw", "tui", "--local", "--session", "s"], ENV).target, "openclaw");
  assert.equal(parse(["openclaw", "tui"], { ...ENV, ...OPT_IN }).target, "openclaw");
  assert.equal(parse(["--target", "openclaw", "--", "./wrap.sh"], ENV).target, "openclaw", "a wrapper is the user's --target call");
  assert.equal(parse(["claude"], ENV).target, "claude");
});

test("openclawRunsLocally: the shapes whose agent loop runs in this launch's child, and no other", () => {
  for (const argv of [["openclaw", "chat"], ["openclaw", "terminal"], ["openclaw", "tui", "--local"],
    ["openclaw", "agent", "--local", "-m", "hi"], ["openclaw", "--profile", "work", "chat"], ["node", "/src/openclaw.mjs", "chat"]]) {
    assert.equal(openclawRunsLocally(argv), true, argv.join(" "));
  }
  for (const argv of [["openclaw"], ["openclaw", "tui"], ["openclaw", "agent", "-m", "hi"], ["openclaw", "gateway"],
    ["openclaw", "gateway", "run"], ["openclaw", "--help"], ["./my-openclaw-wrapper.sh", "chat"], []]) {
    assert.equal(openclawRunsLocally(argv), false, argv.join(" ") || "(empty)");
  }
});

test("bare `mandu openclaw` runs `openclaw chat`; help, version, subcommands and wrappers pass unchanged", () => {
  assert.deepEqual(openclawDefaultArgv(["openclaw"]), ["openclaw", "chat"]);
  assert.deepEqual(openclawDefaultArgv(["openclaw", "--profile", "w", "--dev"]), ["openclaw", "--profile", "w", "--dev", "chat"], "global flags stay before the subcommand");
  assert.deepEqual(openclawDefaultArgv(["node", "/x/openclaw.mjs"]), ["node", "/x/openclaw.mjs", "chat"]);
  for (const argv of [["openclaw", "--help"], ["openclaw", "-V"], ["openclaw", "tui"], ["openclaw", "crestodian"], ["./wrap.sh"], []]) {
    assert.deepEqual(openclawDefaultArgv(argv), argv, `${argv.join(" ")} is unchanged`);
  }
  // Through parse: the plan runs chat, which is a confined, locally-run shape.
  const plan = parse(["openclaw"], ENV);
  assert.equal(plan.target, "openclaw");
  assert.deepEqual(plan.argv, ["openclaw", "chat"]);
  assert.equal(openclawRunsLocally(plan.argv), true, "so the workspace fence applies");
  assert.deepEqual(parse(["openclaw", "--dev"], ENV).argv, ["openclaw", "--dev", "chat"]);
  assert.deepEqual(parse(["--target", "openclaw", "--", "openclaw"], ENV).argv, ["openclaw", "chat"]);
  // A caller that skips the mapping still meets the refusal (Crestodian is not routed).
  assert.match(openclawLaunchRefusal(["openclaw"], {})!, /bare `openclaw` starts onboarding or Crestodian/);
  assert.throws(() => parse(["openclaw", "crestodian"], ENV), /Crestodian/);
});

test("a Gateway run under Mandu says which clients it protects: OpenClaw's own clients run a failed turn themselves on the user's unrouted config", () => {
  for (const argv of [["openclaw", "gateway"], ["openclaw", "gateway", "run"], ["openclaw", "gateway", "--port", "18789", "run"], ["openclaw", "--profile", "w", "gateway", "--bind", "loopback"]]) {
    assert.ok(openclawRunsGateway(argv), argv.join(" "));
    const note = openclawGatewayClientNotice(argv);
    assert.match(note ?? "", /runs under Mandu/, argv.join(" "));
    assert.match(note!, /`mandu openclaw agent`/);
    assert.match(note!, /MANDU_OPENCLAW_GATEWAY_CLIENT=1/);
    assert.match(note!, /plain `openclaw agent` or `openclaw tui` .* runs a turn itself .* goes around Mandu/);
    assert.match(note!, /a client outside Mandu \(a plain `openclaw agent`, a remote app\) cannot connect to this Gateway with your Gateway token/);
  }
  for (const argv of [["openclaw", "chat"], ["openclaw", "agent", "--local", "-m", "x"], ["openclaw", "tui"], ["openclaw", "gateway", "status"], ["/opt/wrapper.sh"]]) {
    assert.equal(openclawGatewayClientNotice(argv), null, argv.join(" "));
  }
});
