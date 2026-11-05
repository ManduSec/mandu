/**
 * doctor-openclaw-attach — the `mandu doctor` rows for an OpenClaw service
 * Gateway attached with `mandu openclaw install` (src/doctor.ts
 * openclawAttachRows; docs/design/agents/openclaw-plugin.md §8). Pure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { openclawAttachRows, renderDoctor, type DoctorFacts } from "../../src/doctor.js";
import type { OpenclawAttachFacts } from "../../src/openclaw-install-command.js";
import type { AttachState } from "../../src/openclaw-attach.js";

const BASE: DoctorFacts = {
  node: { version: "22.22.1", ok: true },
  git: "2.50.1",
  agents: { claude: true, codex: false },
  layout: { mode: "installed", root: "/opt/mandu" },
  arbiter: { sock: "/run/mandu/arbiter.sock", reachable: true },
  kernel: { "net-supervisor": false, "fs-supervisor": false, "exec-supervisor": false },
  confinement: { posture: "confined" },
  claudeSandbox: null,
};

const GOOD: AttachState = {
  plugin: "enabled", attachment: true, loadPath: true, route: "service",
  routeUrl: "http://127.0.0.1:41234", routeSession: "openclaw:main", modelsAround: [], conversationAccess: false,
};
const facts = (state: Partial<AttachState>, service: OpenclawAttachFacts["service"] = { ok: true, port: 41234, url: "http://127.0.0.1:41234", arbiterSock: "/a.sock" }): OpenclawAttachFacts => ({
  configPath: "/home/u/.openclaw/openclaw.json", session: "openclaw:main", state: { ...GOOD, ...state }, service,
});

test("no attachment: no rows, no section", () => {
  assert.deepEqual(openclawAttachRows(null), []);
  assert.deepEqual(openclawAttachRows(undefined), []);
  assert.doesNotMatch(renderDoctor(BASE), /OpenClaw service Gateway/);
  assert.doesNotMatch(renderDoctor({ ...BASE, openclawAttach: null }), /OpenClaw service Gateway/);
});

test("a healthy attachment: plugin enabled, route on the service proxy, the policy caveat", () => {
  const rows = openclawAttachRows(facts({})).join("\n");
  assert.match(rows, /✓ the Mandu plugin is enabled in \/home\/u\/\.openclaw\/openclaw\.json \(session openclaw:main\)/);
  assert.match(rows, /✓ Anthropic calls go to Mandu's service proxy \(http:\/\/127\.0\.0\.1:41234\)/);
  assert.match(rows, /a policy, not a boundary/);
  // The caveat is one sentence over two rows: it says what the programs can
  // do (it read "… run as you and can (a policy, not a boundary)", the verb
  // missing; found building the fresh-openclaw-plugin VM leg).
  assert.match(rows, /the agent's programs run as you and can\n\s+still change it \(a policy, not a boundary\)/);
  assert.doesNotMatch(rows, /✗/);
  assert.match(renderDoctor({ ...BASE, openclawAttach: facts({}) }), /OpenClaw service Gateway \(mandu openclaw install\)/);
});

test("the route points elsewhere, or nowhere: ✗ with the fix", () => {
  const other = openclawAttachRows(facts({ route: "other", routeUrl: "https://api.anthropic.com" })).join("\n");
  assert.match(other, /✗ Anthropic calls go to https:\/\/api\.anthropic\.com, not Mandu's service proxy \(http:\/\/127\.0\.0\.1:41234\): tool results reach the model unmasked/);
  assert.match(other, /fix: mandu openclaw install/);
  const none = openclawAttachRows(facts({ route: "none", routeUrl: undefined })).join("\n");
  assert.match(none, /✗ Anthropic calls go to Anthropic directly/);
});

test("Route 1: every routed provider is named; one ✗ per provider that lost its route or was added since; the unprotected ones are a ✗", () => {
  const routes = { checkAnthropic: true, unrouted: [] as string[], providerRoutes: [
    { id: "openai", wire: "openai-responses" as const, route: "service" as const, routeUrl: "http://127.0.0.1:41234/_mandu/openai/openai" },
    { id: "openrouter", wire: "openai-completions" as const, route: "service" as const, routeUrl: "http://127.0.0.1:41234/_mandu/openai/openrouter" },
  ] };
  const ok = openclawAttachRows({ ...facts(routes), unprotected: ["vertex"] }).join("\n");
  assert.match(ok, /✓ Anthropic, openai, openrouter calls go to Mandu's service proxy \(http:\/\/127\.0\.0\.1:41234\), each on to its provider's own address/);
  assert.match(ok, /✗ left unprotected by your choice \(mandu openclaw install --leave-unprotected\): vertex; their models read tool results unmasked/);
  const lost = openclawAttachRows(facts({
    ...routes, unrouted: ["groq"],
    providerRoutes: [routes.providerRoutes[0]!, { ...routes.providerRoutes[1]!, route: "other", routeUrl: "https://openrouter.ai/api/v1" }],
  })).join("\n");
  assert.match(lost, /✗ calls of provider openrouter go to https:\/\/openrouter\.ai, not Mandu's service proxy/);
  assert.match(lost, /✗ provider groq is not routed through Mandu \(added after the install\)/);
  assert.match(lost, /fix: mandu openclaw install, then openclaw gateway restart/);
});

test("the service is down: ✗ with `mandu serve start`", () => {
  const rows = openclawAttachRows(facts({ route: "other" }, { ok: false, why: "no service proxy for openclaw:main" })).join("\n");
  assert.match(rows, /✗ Mandu's service proxy for openclaw:main is not running \(no service proxy for openclaw:main\)/);
  assert.match(rows, /fix: mandu serve start/);
});

test("the plugin off, a model around the proxy, conversation access granted", () => {
  const rows = openclawAttachRows(facts({ plugin: "disabled", modelsAround: ["claude-x.baseUrl"], conversationAccess: true })).join("\n");
  assert.match(rows, /✗ the Mandu plugin is disabled/);
  assert.match(rows, /✗ model entries with their own endpoint go around the proxy: claude-x\.baseUrl/);
  assert.match(rows, /granted conversation access; it needs none/);
  assert.match(openclawAttachRows(facts({ plugin: "absent" })).join("\n"), /✗ the Mandu plugin is not in the config/);
  assert.match(openclawAttachRows(facts({ attachment: false })).join("\n"), /not in attachment mode/);
});

test("an unreadable config that names the plugin: one ✗ row", () => {
  const rows = openclawAttachRows({ configPath: "/x/openclaw.json", unreadable: "could not read /x/openclaw.json: bad" });
  assert.equal(rows.length, 1);
  assert.match(rows[0]!, /✗ could not read/);
});
