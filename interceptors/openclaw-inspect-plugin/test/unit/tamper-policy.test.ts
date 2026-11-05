/**
 * tamper-policy tests — the before_tool_call refusal (src/tamper-policy.ts,
 * docs/design/agents/openclaw-plugin.md §3.6). Pure: no OpenClaw, no arbiter.
 *
 * Positives: every rule, in the spellings a model would use plainly, in every
 * tool field shape (a shell command, a path field, a patch body, an array, a
 * nested object, the host's derivedPaths hint). Near misses: the words and
 * paths beside each rule that must pass (a policy that refused ordinary work
 * would be switched off). The header's caveat is pinned too: an obfuscated
 * spelling passes, because this is a policy, not a boundary.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { collectStrings, compileTamperPolicy, tamperDecision, type TamperContext } from "../../src/tamper-policy.js";

const CTX: TamperContext = {
  home: "/home/u",
  manduPaths: ["/home/u/.mandu", "/run/user/1000/mandu", "/run/user/1000/mandu/instances/ab12/arbiter.sock"],
  openclawConfigPath: "/home/u/.openclaw/openclaw.json",
  openclawStateDir: "/home/u/.openclaw",
};
const policy = compileTamperPolicy(CTX);

function blocked(params: unknown, tool = "exec", derived?: string[]): string | null {
  const v = policy.decide(tool, params, derived);
  return v.block ? v.rule : null;
}
const cmd = (command: string): unknown => ({ command });

test("mandu-state: ~/.mandu in its spellings, and the configured Mandu paths", () => {
  for (const c of [
    "cat ~/.mandu/state/mandu.db",
    "ls ~/.mandu",
    "rm -rf ~/.mandu/",
    "sqlite3 $HOME/.mandu/state/mandu.db .dump",
    "tar czf /tmp/x.tgz ${HOME}/.mandu",
    "cp /home/u/.mandu/config/policy.yaml /tmp/",
    "echo $MANDU_HOME",
    "ls ${MANDU_HOME}/state",
    "ls $XDG_RUNTIME_DIR/mandu",
    "ls /run/user/1000/mandu/",
    "socat - UNIX-CONNECT:/run/user/1000/mandu/instances/ab12/arbiter.sock",
    "cat ~/.config/systemd/user/mandu-serve.service",
    "look at ~/.mandu.",
  ]) assert.equal(blocked(cmd(c)), "mandu-state", c);
  assert.equal(blocked({ path: "/home/u/.mandu/config/policy.yaml" }, "read"), "mandu-state");
  assert.equal(blocked({ file_path: "~/.mandu/config/config.toml", content: "x" }, "write"), "mandu-state");
});

test("mandu-state near misses pass", () => {
  for (const c of [
    "ls ~/.mandu-notes",
    "cat ~/.mandu.bak",
    "cat ~/notes/mandu.txt",
    "grep -r mandu README.md",
    "ls /srv/x/home/u/.mandu",
    "ls /run/user/1000/mandu-other",
    "echo MANDU_HOMEPAGE",
    "npm install mandu-utils",
  ]) assert.equal(blocked(cmd(c)), null, c);
});

test("openclaw-config: the config file, its variables, its directory's JSON files, the state dir, its plugins, the rewriting commands", () => {
  for (const c of [
    "cat ~/.openclaw/openclaw.json",
    "sed -i 's/127.0.0.1/api.anthropic.com/' openclaw.json",
    "cp openclaw.json.bak openclaw.json",
    "echo $OPENCLAW_CONFIG_PATH",
    "OPENCLAW_STATE_DIR=/tmp/x openclaw gateway restart",
    "export OPENCLAW_INCLUDE_ROOTS=/tmp",
    "cat /home/u/.openclaw/models.json5",
    "cat ~/.openclaw/providers.json",
    "rm -rf ~/.openclaw",
    "rm -rf ~/.openclaw/",
    "rm -rf ~/.openclaw/*",
    "ls ~/.openclaw/extensions",
    "rm -rf /home/u/.openclaw/extensions/mandu-inspect",
    "openclaw config set models.providers.anthropic.baseUrl https://api.anthropic.com",
    "openclaw config unset plugins.entries.mandu-inspect",
    "openclaw config patch --file ./p.json5",
    "openclaw --profile work config set x y",
    "openclaw plugins disable mandu-inspect",
    "openclaw plugins uninstall mandu-inspect",
    "openclaw configure",
    "openclaw onboard",
    "openclaw reset --yes",
  ]) assert.equal(blocked(cmd(c)), "openclaw-config", c);
  assert.equal(blocked({ path: "/home/u/.openclaw/openclaw.json", edits: [] }, "edit"), "openclaw-config");
});

test("openclaw-config near misses pass: the agent's own workspace, the read-only config commands", () => {
  for (const c of [
    "cat ~/.openclaw/workspace/README.md",
    "ls ~/.openclaw/workspace/",
    "cat ~/.openclaw/agents/main/sessions/index.txt",
    "cat openclaw.jsonl",
    "grep -r openclaw docs/",
    "openclaw config get agents.defaults.model",
    "openclaw config validate",
    "openclaw plugins list",
    "openclaw gateway status",
    "echo OPENCLAW_HOME",
    "cat ~/.openclaw/workspace/notes.json",
  ]) assert.equal(blocked(cmd(c)), null, c);
});

test("mandu-service: stopping or uninstalling the service, changing the mode", () => {
  for (const c of [
    "mandu serve stop",
    "mandu serve uninstall",
    "npx mandu serve disable",
    "mandu stop",
    "mandu stop --all",
    "mandu reap",
    "mandu mode off",
    "systemctl --user stop mandu-serve",
    "systemctl --user disable --now mandu.service",
    "systemctl --user mask mandu-serve.service",
    "systemctl --user kill mandu-serve",
    "launchctl bootout gui/501/com.mandusecurity.mandu",
    "pkill -f mandu",
    "killall mandu-arbiter",
    "kill -9 $(pgrep -f mandu-arbiter)",
    "kill $(pidof mandu-anthropic-proxy)",
    "echo ok; mandu serve stop",
  ]) assert.equal(blocked(cmd(c)), "mandu-service", c);
});

test("mandu-service near misses pass: status, start, doctor, other processes", () => {
  for (const c of [
    "mandu serve status",
    "mandu serve start",
    "mandu doctor",
    "mandu mode",
    "mandu mode --help",
    "systemctl --user status mandu-serve",
    "systemctl --user restart mandu-serve",
    "systemctl --user stop nginx",
    "pkill -f node",
    "kill 4242",
    "echo 'the mandu service stops at night'",
    "pkill node && echo mandu",
  ]) assert.equal(blocked(cmd(c)), null, c);
});

test("every string is read: nested objects, arrays, keys, the derivedPaths hint, any tool", () => {
  assert.equal(blocked({ a: { b: [1, { c: "cat ~/.mandu/x" }] } }, "anything"), "mandu-state");
  assert.equal(blocked({ "/home/u/.openclaw/openclaw.json": true }, "weird"), "openclaw-config");
  assert.equal(blocked({ input: "*** Begin Patch\n*** Update File: /home/u/.openclaw/openclaw.json\n@@\n-a\n+b\n*** End Patch" }, "apply_patch"), "openclaw-config");
  assert.equal(blocked({ input: "opaque" }, "apply_patch", ["/home/u/.mandu/config/policy.yaml"]), "mandu-state");
  assert.equal(blocked({ url: "file:///home/u/.mandu/state/mandu.db" }, "web_fetch"), "mandu-state");
  assert.equal(blocked({ symbol: "$MDU:env[ab12]", instruction: "summarize" }, "inspect_symbol"), null);
  assert.equal(blocked({}, "exec"), null);
  assert.equal(blocked(undefined, "exec"), null);
});

test("a policy, not a boundary: an obfuscated spelling passes (stated in the header and the docs)", () => {
  for (const c of [
    "cd ~ && cat .mandu/state/mandu.db",
    "d=.man; cat ~/${d}du/x",
    "echo bWFuZHUgc2VydmUgc3RvcA== | base64 -d | sh",
    "cd ~ && cat .openclaw/open\"\"claw.json",
  ]) assert.equal(blocked(cmd(c)), null, c);
});

test("the refusal names the rule and tells the model to ask the human", () => {
  const v = tamperDecision("exec", cmd("mandu serve stop"), CTX);
  assert.equal(v.block, true);
  if (!v.block) return;
  assert.equal(v.rule, "mandu-service");
  assert.match(v.reason, /^Mandu refused this exec call: it names /);
  assert.match(v.reason, /ask the human/);
});

test("context paths: an OPENCLAW_CONFIG_PATH elsewhere and a state dir elsewhere are matched there", () => {
  const p = compileTamperPolicy({ home: "/home/u", manduPaths: [], openclawConfigPath: "/etc/oc/gateway.json5", openclawStateDir: "/srv/oc" });
  assert.equal(p.decide("exec", cmd("cat /etc/oc/gateway.json5"), undefined).block, true);
  assert.equal(p.decide("exec", cmd("cat /etc/oc/other.json"), undefined).block, true, "a sibling JSON file (an include)");
  assert.equal(p.decide("exec", cmd("cat /etc/oc/notes.txt"), undefined).block, false);
  assert.equal(p.decide("exec", cmd("rm -rf /srv/oc"), undefined).block, true);
  assert.equal(p.decide("exec", cmd("ls /srv/oc/workspace"), undefined).block, false);
  // A relative or root path in the context names nothing.
  const q = compileTamperPolicy({ home: "/home/u", manduPaths: ["relative/x", "/"], openclawConfigPath: "rel.json", openclawStateDir: "/" });
  assert.equal(q.decide("exec", cmd("ls /etc"), undefined).block, false);
});

test("collectStrings is bounded", () => {
  const many = Array.from({ length: 5000 }, (_, i) => `s${i}`);
  assert.ok(collectStrings(many).length <= 1024);
  let deep: unknown = "cat ~/.mandu/x";
  for (let i = 0; i < 40; i++) deep = { d: deep };
  assert.ok(!collectStrings(deep).some((s) => s.includes(".mandu")), "past the depth bound nothing is read (a policy, not a boundary)");
});
