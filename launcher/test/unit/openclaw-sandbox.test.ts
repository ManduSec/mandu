/**
 * The confined-commands tier's decisions (docs/design/agents/openclaw-plugin.md
 * §10): what `mandu openclaw install --sandbox` writes and uninstall puts
 * back (openclaw-sandbox.ts), what the declaration records, and what the
 * doctor, the install's post-check and the service's route check say
 * (attachment-contract.ts sandboxTierProblems, the plugin's status, the pool
 * record). Pure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  declareAttachment, parseDeclared, parseDeclaredSandbox, parseSandboxRecord, parseSandboxStatus, renderDeclared,
  sandboxLostLines, sandboxRecordOf, sandboxStatusFile, sandboxTierProblems, SANDBOX_STATUS_FRESH_MS, withDeclaredSandbox,
  type SandboxStatusRecord,
} from "../../src/attachment-contract.js";
import { applySandboxInstall, applySandboxUninstall, hasSandboxBlock, sandboxOriginal, sandboxTierRefusal, sandboxWriteProtect } from "../../src/openclaw-sandbox.js";
import { sandboxRows } from "../../src/openclaw-install-command.js";

type Json = Record<string, unknown>;
const INPUT = { launcher: ["/opt/mandu/launcher/mandu-run.sh"], writeProtect: ["/h/.openclaw/openclaw.json"], statusFile: "/run/mandu/attachments/openclaw:main/openclaw-sandbox.json" };
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

function userConfig(): Json {
  return {
    agents: { defaults: { model: { primary: "anthropic/claude" }, sandbox: { mode: "non-main", scope: "session", docker: { image: "my:img" } } } },
    tools: { profile: "coding", exec: { host: "gateway", security: "full" }, elevated: { enabled: true, allowFrom: { telegram: ["42"] } }, sandbox: { tools: { alsoAllow: ["memory_search"] } } },
    plugins: { entries: { "mandu-inspect": { enabled: true, config: { attachment: true } } } },
  };
}

test("install writes the tier: mode all, backend mandu, rw, the tool gate, elevated off, no gateway exec host, the plugin block", () => {
  const doc = userConfig();
  const pluginCfg = ((doc["plugins"] as Json)["entries"] as Json)["mandu-inspect"] as Json;
  const changes = applySandboxInstall(doc, pluginCfg["config"] as Json, INPUT);
  const sb = ((doc["agents"] as Json)["defaults"] as Json)["sandbox"] as Json;
  assert.deepEqual(sb, { mode: "all", scope: "agent", docker: { image: "my:img" }, backend: "mandu", workspaceAccess: "rw" }, "the user's Docker settings stay for uninstall");
  const tools = doc["tools"] as Json;
  assert.deepEqual(((tools["sandbox"] as Json)["tools"] as Json)["alsoAllow"], ["memory_search", "message", "group:web", "group:plugins"]);
  assert.deepEqual(tools["elevated"], { enabled: false, allowFrom: { telegram: ["42"] } });
  assert.deepEqual(tools["exec"], { security: "full" }, "the gateway exec host is an escape: removed");
  assert.deepEqual((pluginCfg["config"] as Json)["sandbox"], INPUT);
  assert.equal(changes.length, 5);
  assert.deepEqual(sandboxTierProblems(doc, "main", null), [], "the post-check holds over what install writes");
  // A second install changes nothing.
  const again = clone(doc);
  assert.deepEqual(applySandboxInstall(again, (((again["plugins"] as Json)["entries"] as Json)["mandu-inspect"] as Json)["config"] as Json, INPUT), []);
  assert.deepEqual(again, doc);
});

test("install then uninstall gives the config back key for key (the user's Docker sandbox, elevated, exec host, tool gate)", () => {
  const before = userConfig();
  const doc = clone(before);
  const original = sandboxOriginal(doc);
  const cfg = (((doc["plugins"] as Json)["entries"] as Json)["mandu-inspect"] as Json)["config"] as Json;
  applySandboxInstall(doc, cfg, INPUT);
  const changes = applySandboxUninstall(doc, cfg, original);
  assert.ok(changes.length >= 4, JSON.stringify(changes));
  assert.deepEqual(doc, before);
});

test("install over a config with no sandbox at all, then uninstall, leaves no sandbox keys", () => {
  const before: Json = { agents: { defaults: { model: { primary: "anthropic/claude" } } }, plugins: { entries: { "mandu-inspect": { enabled: true, config: {} } } } };
  const doc = clone(before);
  const original = sandboxOriginal(doc);
  assert.deepEqual(original, { sandbox: null, alsoAllow: null, elevated: null, execHost: null });
  const cfg = (((doc["plugins"] as Json)["entries"] as Json)["mandu-inspect"] as Json)["config"] as Json;
  applySandboxInstall(doc, cfg, INPUT);
  assert.equal(hasSandboxBlock(cfg), true);
  applySandboxUninstall(doc, cfg, original);
  assert.deepEqual(doc, before);
});

test("uninstall without a record removes only Mandu's values; a backend the user changed since is theirs", () => {
  const doc: Json = { agents: { defaults: { sandbox: { mode: "all", backend: "mandu", scope: "agent", workspaceAccess: "rw", docker: { image: "x" } } } }, tools: { elevated: { enabled: false }, sandbox: { tools: { alsoAllow: ["message", "group:web", "group:plugins", "mine"] } } } };
  applySandboxUninstall(doc, null, null);
  assert.deepEqual(doc, { agents: { defaults: { sandbox: { docker: { image: "x" } } } }, tools: { elevated: { enabled: false }, sandbox: { tools: { alsoAllow: ["mine"] } } } }, "elevated stays off without a record (the safe side)");
  const moved: Json = { agents: { defaults: { sandbox: { mode: "all", backend: "docker" } } } };
  assert.deepEqual(applySandboxUninstall(moved, null, null), []);
  assert.deepEqual(moved, { agents: { defaults: { sandbox: { mode: "all", backend: "docker" } } } });
});

test("each way the tier is lost, for the attached agent, in both roster forms", () => {
  const good: Json = {
    agents: { defaults: { sandbox: { mode: "all", backend: "mandu", workspaceAccess: "rw" } } },
    tools: { elevated: { enabled: false }, sandbox: { tools: { alsoAllow: ["message", "group:web", "group:plugins"] } } },
  };
  assert.deepEqual(sandboxTierProblems(good, "main", null), []);
  const kinds = (d: Json, agent = "main", st: SandboxStatusRecord | null = null): string[] => sandboxTierProblems(d, agent, st).map((p) => p.kind);
  const mode = clone(good);
  (((mode["agents"] as Json)["defaults"] as Json)["sandbox"] as Json)["mode"] = "non-main";
  assert.deepEqual(kinds(mode), ["sandbox-mode"]);
  const listOverride = clone(good);
  (listOverride["agents"] as Json)["list"] = [{ id: "Main", sandbox: { backend: "docker" } }, { id: "work", sandbox: { mode: "off" } }];
  assert.deepEqual(kinds(listOverride), ["sandbox-backend"], "the agent's own entry wins over the defaults");
  assert.deepEqual(kinds(listOverride, "work"), ["sandbox-mode"]);
  const entriesOverride = clone(good);
  (entriesOverride["agents"] as Json)["entries"] = { main: { tools: { exec: { host: "node" } } } };
  assert.deepEqual(kinds(entriesOverride), ["exec-host"]);
  const host = clone(good);
  (host["tools"] as Json)["exec"] = { host: "gateway" };
  assert.deepEqual(kinds(host), ["exec-host"]);
  const elevated = clone(good);
  delete (elevated["tools"] as Json)["elevated"];
  assert.deepEqual(kinds(elevated), ["elevated"], "elevated not switched off is an escape");
  const ro = clone(good);
  (((ro["agents"] as Json)["defaults"] as Json)["sandbox"] as Json)["workspaceAccess"] = "ro";
  assert.deepEqual(sandboxTierProblems(ro, "main", null).map((p) => [p.kind, p.severity]), [["workspace-access", "utility"]]);
  const gate = clone(good);
  delete ((gate["tools"] as Json)["sandbox"] as Json)["tools"];
  assert.deepEqual(sandboxTierProblems(gate, "main", null).map((p) => [p.kind, p.severity]), [["tools-blocked", "utility"]]);
  const st = (o: Partial<SandboxStatusRecord>): SandboxStatusRecord => ({ checkedAt: "x", sdk: true, registered: true, ours: true, ...o });
  assert.deepEqual(kinds(good, "main", st({ ours: false })), ["backend-replaced"], "last writer wins: another plugin took mandu");
  assert.deepEqual(kinds(good, "main", st({ registered: false, sdk: false, ours: null, error: "no seam" })), ["backend-missing"]);
  assert.deepEqual(kinds(good, "main", st({})), []);
});

test("the plugin's status counts only fresh, parsed, from a live writer", () => {
  const now = Date.parse("2026-10-26T12:00:00Z");
  const rec = (o: Json): string => JSON.stringify({ version: 1, pid: 42, checkedAt: "2026-10-26T11:59:30Z", sdk: true, registered: true, ours: false, ...o });
  assert.deepEqual(parseSandboxStatus(rec({}), now, () => true), { pid: 42, checkedAt: "2026-10-26T11:59:30Z", sdk: true, registered: true, ours: false });
  assert.equal(parseSandboxStatus(rec({}), now, () => false), null, "its Gateway is gone");
  assert.equal(parseSandboxStatus(rec({ checkedAt: new Date(now - SANDBOX_STATUS_FRESH_MS - 1).toISOString() }), now, () => true), null, "too old");
  assert.equal(parseSandboxStatus("{not json", now, () => true), null);
  assert.equal(parseSandboxStatus(rec({ version: 2 }), now, () => true), null);
  assert.equal(parseSandboxStatus(null, now, () => true), null);
  assert.equal(parseSandboxStatus(rec({ ours: "yes" }), now, () => true)?.ours, null);
  assert.equal(sandboxStatusFile("/run/mandu", "openclaw:main"), "/run/mandu/attachments/openclaw:main/openclaw-sandbox.json");
});

test("the declaration records the tier's originals; parse and render keep them; a bad record is named and dropped", () => {
  const { list } = declareAttachment([], "main", 4100);
  const original = { sandbox: { mode: "non-main", docker: { image: "x" } }, alsoAllow: null, elevated: { enabled: true }, execHost: "gateway" };
  const w = withDeclaredSandbox(list, "openclaw:main", { original });
  assert.equal(w.changed, true);
  const back = parseDeclared(renderDeclared(w.list));
  assert.deepEqual(back.problems, []);
  assert.deepEqual(back.attachments[0]!.sandbox, { original });
  assert.equal(withDeclaredSandbox(w.list, "openclaw:main", { original }).changed, false);
  assert.equal(withDeclaredSandbox(w.list, "openclaw:main", null).list[0]!.sandbox, undefined);
  assert.equal(withDeclaredSandbox(w.list, "openclaw:other", null).changed, false);
  // A later declaration (new routes) keeps the record.
  const again = declareAttachment(w.list, "main", null, "/h/.openclaw/openclaw.json", { providers: [], unprotected: [] });
  assert.deepEqual(again.entry.sandbox, { original });
  const bad = parseDeclared(JSON.stringify({ version: 2, attachments: [{ kind: "openclaw-plugin", agent: "main", session: "openclaw:main", port: null, sandbox: { original: { sandbox: 3 } } }] }));
  assert.equal(bad.attachments[0]!.sandbox, undefined);
  assert.match(bad.problems.join(), /sandbox/);
  assert.equal(typeof parseDeclaredSandbox({}), "string");
});

test("the pool record's tier check, said in serve status and the doctor", () => {
  const lostCfg: Json = { agents: { defaults: { sandbox: { mode: "off" } } }, tools: { elevated: { enabled: false } } };
  const rec = sandboxRecordOf(lostCfg, "main", null, "2026-10-26T12:00:00Z");
  assert.equal(rec.state, "lost");
  const parsed = parseSandboxRecord(JSON.stringify({ pid: 1, sandbox: rec }));
  assert.deepEqual(parsed, rec);
  const lines = sandboxLostLines("openclaw:main", parsed);
  assert.match(lines[0]!, /outside Mandu's box.*not "all"/);
  assert.match(lines[1]!, /mandu openclaw install --sandbox/);
  assert.deepEqual(sandboxLostLines("openclaw:main", { ...rec, state: "held" }), []);
  assert.equal(parseSandboxRecord("{}"), null);
  const rows = sandboxRows({ problems: rec.problems, status: null }, { ok: "OK", no: "NO", dot: "." });
  assert.ok(rows.some((r) => r.startsWith("  NO confined commands")));
  assert.ok(rows.some((r) => /fix: mandu openclaw install --sandbox/.test(r)));
  assert.ok(rows.some((r) => /has not reported/.test(r)), "no fresh status is said, not assumed fine");
  const okRows = sandboxRows({ problems: [], status: { checkedAt: "t", sdk: true, registered: true, ours: true } }, { ok: "OK", no: "NO", dot: "." });
  assert.ok(okRows[0]!.startsWith("  OK confined commands"));
  assert.ok(okRows.some((r) => /is Mandu's/.test(r)));
});

test("the tier is refused off Linux and without user namespaces (fail closed); the box's read-only paths", () => {
  assert.match(sandboxTierRefusal("darwin", true, "") ?? "", /Linux only.*macOS/);
  assert.match(sandboxTierRefusal("linux", false, "kernel.unprivileged_userns_clone=0") ?? "", /user namespaces.*unprivileged_userns_clone/);
  assert.equal(sandboxTierRefusal("linux", true, ""), null);
  assert.deepEqual(sandboxWriteProtect({ configPath: "/h/.openclaw/openclaw.json", configTarget: "/h/.openclaw/openclaw.json", includes: ["/h/.openclaw/models.json"], stateDir: "/h/.openclaw", pluginDir: "/src/plugin" }),
    ["/h/.openclaw/openclaw.json", "/h/.openclaw/models.json", "/h/.openclaw/extensions", "/src/plugin"]);
});
