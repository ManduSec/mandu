/**
 * scan-kept — the last `mandu scan`, kept for the dashboard and doctor
 * (confidentiality-plan-17-past-sessions-scan.md §3 items 12 and 13):
 *
 *   - `keepScan` copies only the fields it names, each checked: a field the
 *     answer carries beyond them is not written, examples are cut to 10 and
 *     a command to its length, control characters dropped; part B's and D's
 *     optional fields are kept when present and absent when not;
 *   - the file is written whole, mode 0600, and read back the same; a file
 *     that is not a record reads as none;
 *   - doctor's line with no scan, none reached, some reached (a session
 *     known to be under Mandu does not count), and rules waiting; and the
 *     row in `renderDoctor`;
 *   - the files named to the running Mandu: home-relative paths made
 *     absolute, "your environment" and the other tiers left out, names
 *     grouped per file; `keepLastScan` with no Mandu running, with one, with
 *     one that fails, and a write that fails;
 *   - no 8-character run of a planted value in what is kept.
 * Axes: none stated by the code under test (it reads a finished answer);
 * stated as secrets, the axis the scan runs on.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  KEPT_COMMAND_MAX, KEPT_EXAMPLES_MAX, KEPT_SEND_URL_MAX, KEPT_SEND_URLS_MAX, keepLastScan, keepScan, lastScanLine, lastScanPath, readLastScan, secretsBeforeMandu, suggestFilesOf, suggestionsLine, writeLastScan, type LastScan,
} from "../../src/scan-kept.js";
import { renderDoctor, type DoctorFacts } from "../../src/doctor.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;

/** A scan answer as the op gives it, with a field the record must not keep. */
function answer(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    axis: true,
    sessions: { "claude-code": 3, codex: 1 },
    duringMandu: 1,
    from: "2026-09-29T10:00:00Z",
    to: "2026-10-19T10:00:00Z",
    known: 4,
    findings: [
      {
        kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 2, agents: ["claude-code"],
        first: "2026-10-01T10:00:00Z", last: "2026-10-19T10:00:00Z", how: { "command-output": 2 }, projects: ["~/shop"], duringMandu: 0,
        secretFlag: "not kept",
        examples: Array.from({ length: 14 }, (_, i) => ({ at: `2026-10-${String(19 - i).padStart(2, "0")}T10:00:00Z`, agent: "claude-code", how: "command-output", command: `cat .env\u001b[2J # ${i}`, project: "~/shop", mandu: "without", extra: 1 })),
      },
      { kind: "known", preview: "token in ~/.config/cli/config.yml", source: { path: "~/.config/cli/config.yml", name: "token" }, sessions: 1, agents: ["codex"], last: "2026-10-05T10:00:00Z", how: { "read-file": 1 }, projects: [], duringMandu: 1, sessionsUnderMandu: 1, sessionsByTime: 0 },
      { kind: "known", preview: "GITHUB_TOKEN in your environment", source: { path: "your environment", name: "GITHUB_TOKEN" }, sessions: 1, agents: ["codex"], how: { "your-message": 1 }, projects: [], duringMandu: 0 },
      { kind: "github-token", preview: "ghp_…", sessions: 1, agents: ["codex"], how: { "your-message": 1 }, projects: [], duringMandu: 0 },
    ],
    dropped: 0,
    bytes: 1234,
    capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 1 },
    ms: 12,
    risk: { skippedPrompts: 2, skippedWithSecret: 1, envDumps: 1 },
    sends: [{ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, to: "other-host", host: "hooks.vendor.dev", sessions: 1, ran: 0, stoppedByMandu: 0, via: ["curl"], by: ["variable"], agents: ["claude-code"], last: "2026-10-19T10:00:00Z", duringMandu: 0 }],
    sendsDropped: 0,
    ...extra,
  };
}

test("keepScan: OpenCode's, Goose's and OpenClaw's sessions, findings, examples and sends are kept like the others", () => {
  const ex = { at: "2026-10-04T08:00:01Z", agent: "openclaw", how: "ai-wrote", tool: "web_fetch", project: "~/shop", mandu: "without", provider: "anthropic" };
  const rec = keepScan(answer({
    sessions: { "claude-code": 3, codex: 1, opencode: 2, goose: 1, openclaw: 1 },
    findings: [{ kind: "known", preview: "OPENAI_API_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "OPENAI_API_KEY" }, sessions: 2, agents: ["openclaw", "opencode"], how: { "ai-wrote": 1, "command-output": 1 }, projects: ["~/shop"], duringMandu: 0, examples: [ex, { ...ex, agent: "opencode", how: "command-output", command: "grep OPENAI .env", tool: "shell", provider: "other" }] }],
    sends: [{ kind: "known", preview: "OPENAI_API_KEY in ~/shop/.env", to: "other-host", host: "hooks.vendor.dev", sessions: 1, ran: 1, stoppedByMandu: 0, via: ["web_fetch"], by: ["value"], agents: ["openclaw"], duringMandu: 0 }],
  }), { ranAt: Date.parse("2026-10-21T09:00:00Z") })!;
  assert.deepEqual(rec.sessions, { "claude-code": 3, codex: 1, opencode: 2, goose: 1, openclaw: 1 });
  assert.deepEqual(rec.findings[0]!.agents, ["openclaw", "opencode"]);
  assert.deepEqual(rec.findings[0]!.examples!.map((e) => [e.agent, e.provider, e.command ?? null]), [["openclaw", "anthropic", null], ["opencode", "other", "grep OPENAI .env"]]);
  assert.deepEqual(rec.sends?.[0]?.agents, ["openclaw"]);
});

test("keepScan: only the named fields, checked and cut; the optional ones kept when present", () => {
  const rec = keepScan(answer({ newerField: STRIPE }), { ranAt: Date.parse("2026-10-21T09:00:00Z"), since: Date.parse("2026-09-01T00:00:00Z") })!;
  assert.equal(rec.version, 1);
  assert.equal(rec.ranAt, "2026-10-21T09:00:00.000Z");
  assert.equal(rec.since, "2026-09-01T00:00:00.000Z");
  assert.equal(rec.suggestions, null);
  assert.ok(!("newerField" in rec) && !("bytes" in rec) && !("ms" in rec));
  const f = rec.findings[0]!;
  assert.ok(!("secretFlag" in f));
  assert.equal(f.examples!.length, KEPT_EXAMPLES_MAX);
  assert.equal(f.examples![0]!.command, "cat .env [2J # 0", "a control character is dropped");
  assert.ok(!("extra" in f.examples![0]!));
  assert.equal(f.sessionsUnderMandu, undefined, "part B's field is absent when the answer has none");
  assert.equal(rec.findings[1]!.sessionsUnderMandu, 1);
  assert.equal(rec.sends![0]!.host, "hooks.vendor.dev");
  assert.deepEqual(rec.risk, { skippedPrompts: 2, skippedWithSecret: 1, envDumps: 1 });
  assert.equal(keepScan({ axis: false, findings: [] }, { ranAt: 1 }), null, "an axis-OFF answer is not kept");
  assert.equal(keepScan("nonsense", { ranAt: 1 }), null);
});

test("writeLastScan / readLastScan: written whole at 0600, read back the same; anything else reads as none", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-kept-"));
  try {
    const env = { MANDU_HOME: join(dir, ".mandu") };
    const path = lastScanPath(env, dir);
    assert.equal(path, join(dir, ".mandu", "state", "last-scan.json"));
    const rec = keepScan(answer(), { ranAt: Date.parse("2026-10-21T09:00:00Z") })!;
    rec.suggestions = { pending: 1, filed: 1, covered: 0 };
    writeLastScan(path, rec);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, ".mandu", "state")).mode & 0o777, 0o700);
    assert.deepEqual(readLastScan(path), rec);
    writeFileSync(path, "{\"version\": 9}");
    assert.equal(readLastScan(path), null);
    assert.equal(readLastScan(join(dir, "none.json")), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("lastScanLine: none, some reached before Mandu, none reached, rules waiting; and doctor's row", () => {
  assert.equal(lastScanLine(null), "No scan of your agents' past sessions yet: mandu scan shows which of your secrets they already sent to the AI");
  const rec = keepScan(answer(), { ranAt: Date.parse("2026-10-19T09:00:00Z") })!;
  // The config's one session ran under Mandu: it does not count.
  assert.deepEqual(secretsBeforeMandu(rec).map((f) => f.preview), ["STRIPE_KEY in ~/shop/.env", "GITHUB_TOKEN in your environment"]);
  assert.equal(lastScanLine(rec), "Last scan (19 Oct): 2 of your secrets reached the AI in sessions without Mandu (mandu scan to check again)");
  assert.equal(lastScanLine({ ...rec, suggestions: { pending: 1, filed: 1, covered: 0 } }), "Last scan (19 Oct): 2 of your secrets reached the AI in sessions without Mandu; 1 rule waits for you in the dashboard (mandu scan to check again)");
  assert.equal(lastScanLine({ ...rec, findings: [] }), "Last scan (19 Oct): none of your secrets reached the AI in sessions without Mandu (mandu scan to check again)");
  const facts: DoctorFacts = {
    node: { version: "22.22.1", ok: true }, git: "2.50.1", agents: { claude: true, codex: false },
    layout: { mode: "installed", root: "/opt/mandu" }, arbiter: { sock: "/run/mandu/arbiter.sock", reachable: false },
    kernel: { "net-supervisor": false, "fs-supervisor": false, "exec-supervisor": false }, confinement: { posture: "confined" }, claudeSandbox: null,
  };
  assert.match(renderDoctor({ ...facts, lastScan: rec }), /\n {2}✗ Last scan \(19 Oct\): 2 of your secrets reached the AI in sessions without Mandu/);
  assert.match(renderDoctor({ ...facts, lastScan: null }), /\n {2}· No scan of your agents' past sessions yet: mandu scan/);
  assert.doesNotMatch(renderDoctor(facts), /Last scan|No scan of/, "no row when doctor read none");
});

test("suggestFilesOf: your secrets' files, absolute, names grouped; the environment and the other tiers left out", () => {
  const rec = keepScan(answer(), { ranAt: 1 })!;
  rec.findings.push({ ...rec.findings[0]!, preview: "OTHER in ~/shop/.env", source: { path: "~/shop/.env", name: "OTHER" }, sessions: 5, last: "2026-10-20T00:00:00.000Z" });
  assert.deepEqual(suggestFilesOf(rec, "/home/u/"), [
    { path: "/home/u/shop/.env", names: ["STRIPE_KEY", "OTHER"], sessions: 5, last: "2026-10-20T00:00:00.000Z" },
    { path: "/home/u/.config/cli/config.yml", names: ["token"], sessions: 1, last: "2026-10-05T10:00:00.000Z" },
  ]);
});

test("keepLastScan: kept with no Mandu running, with the running one's answer, through its failure; a failed write is a note", async () => {
  const written: LastScan[] = [];
  const base = { write: (_p: string, r: LastScan) => { written.push(r); } };
  const ctx = { env: { MANDU_HOME: "/nowhere/.mandu" }, home: "/home/u", ranAt: Date.parse("2026-10-21T00:00:00Z") };
  const none = await keepLastScan(answer(), ctx, { ...base, resident: async () => null, suggest: async () => { throw new Error("not called"); } });
  assert.equal(none.rec!.suggestions, null);
  assert.equal(suggestionsLine(none.rec), null);
  const asked: unknown[] = [];
  const one = await keepLastScan(answer(), ctx, {
    ...base, resident: async () => "/run/a.sock",
    suggest: async (sock, home, files) => { asked.push([sock, home, files]); return { filed: ["pp-000001"], covered: 1, suggestions: [{ status: "pending" }] }; },
  });
  assert.deepEqual(one.rec!.suggestions, { pending: 1, filed: 1, covered: 1 });
  assert.deepEqual((asked[0] as unknown[]).slice(0, 2), ["/run/a.sock", "/home/u"]);
  assert.equal(suggestionsLine(one.rec), "1 file that holds them has no rule yet: Mandu suggests one for each in the dashboard (Rules, Files and folders, Suggested). Nothing changes until you save it.");
  const failed = await keepLastScan(answer(), ctx, { ...base, resident: async () => "/run/a.sock", suggest: async () => { throw new Error("busy"); } });
  assert.equal(failed.rec!.suggestions, null);
  assert.equal(failed.error, undefined);
  const noWrite = await keepLastScan(answer(), ctx, { resident: async () => null, suggest: async () => ({}), write: () => { throw new Error("read-only"); } });
  assert.match(noWrite.error ?? "", /could not keep the result for the dashboard: read-only/);
  assert.equal(written.length, 3);
  for (const r of written) assert.ok(!JSON.stringify(r).includes(STRIPE.slice(8, 16)));
});

test("keepScan: the examples by way (10 each) and the hosts it was sent to are kept; the totals' Mandu split too", () => {
  const a = answer({ sessionsUnderMandu: 2, sessionsByTime: 1 });
  const f = (a["findings"] as Array<Record<string, unknown>>)[0]!;
  f["examplesByHow"] = { "command-output": Array.from({ length: 12 }, () => ({ agent: "claude-code", how: "command-output", command: "cat .env", provider: "anthropic" })), bogus: "x" };
  f["sentToHosts"] = ["hooks.vendor.dev", 7];
  const rec = keepScan(a, { ranAt: 1 })!;
  assert.equal(rec.findings[0]!.examplesByHow!["command-output"]!.length, KEPT_EXAMPLES_MAX);
  assert.equal(rec.findings[0]!.examplesByHow!["command-output"]![0]!.provider, "anthropic");
  assert.ok(!("bogus" in rec.findings[0]!.examplesByHow!));
  assert.deepEqual(rec.findings[0]!.sentToHosts, ["hooks.vendor.dev"]);
  assert.deepEqual([rec.sessionsUnderMandu, rec.sessionsByTime], [2, 1]);
});

test("keepScan: a send's URLs are kept as the arbiter masked them, five at most, each cut, a non-string dropped", () => {
  const a = answer();
  const s = (a["sends"] as Array<Record<string, unknown>>)[0]!;
  s["urls"] = ["https://hooks.vendor.dev/in?k=…", 7, `https://hooks.vendor.dev/${"a".repeat(400)}\u0007`, ...["p1", "p2", "p3", "p4"].map((p) => `https://hooks.vendor.dev/${p}`)];
  const rec = keepScan(a, { ranAt: 1 })!;
  const urls = rec.sends![0]!.urls!;
  assert.equal(urls.length, KEPT_SEND_URLS_MAX);
  assert.equal(urls[0], "https://hooks.vendor.dev/in?k=…");
  assert.equal(urls[1]!.length, KEPT_SEND_URL_MAX + 1, "cut");
  assert.ok(!urls[1]!.includes("\u0007"));
  assert.equal(keepScan(answer(), { ranAt: 1 })!.sends![0]!.urls, undefined, "an older arbiter's send has none");
  s["urls"] = [];
  assert.equal(keepScan(a, { ranAt: 1 })!.sends![0]!.urls, undefined, "an empty list is not kept");
});

test("keepScan: a web fetch's URL is kept as the arbiter masked it, cut like a command, its control characters dropped", () => {
  const url = "https://hooks.vendor.dev/in?key=…&page=2";
  const base = (answer()["findings"] as Array<Record<string, unknown>>)[0]!;
  const rec = keepScan(answer({ findings: [{ ...base, how: { "tool-result": 1 }, examples: [
    { at: "2026-10-19T10:00:00Z", agent: "claude-code", how: "tool-result", tool: "WebFetch", url, mandu: "without", provider: "anthropic" },
    { at: "2026-10-18T10:00:00Z", agent: "openclaw", how: "ai-wrote", tool: "web_fetch", url: `https://x.dev/${"a".repeat(400)}\u0007`, mandu: "without" },
    { at: "2026-10-17T10:00:00Z", agent: "claude-code", how: "tool-result", tool: "WebFetch", url: 42 },
  ] }] }), { ranAt: 1 })!;
  const kept = rec.findings[0]!.examples!;
  assert.equal(kept[0]!.url, url);
  assert.equal(kept[1]!.url!.length, KEPT_COMMAND_MAX + 1, "cut like a command");
  assert.ok(!kept[1]!.url!.includes("\u0007"));
  assert.equal(kept[2]!.url, undefined, "not a string: not kept");
});

test("what is kept holds no 8-character run of a planted value, even when the answer carried one in a field it does not keep", () => {
  const rec = keepScan(answer({ leaked: STRIPE, findings: [{ ...(answer()["findings"] as Array<Record<string, unknown>>)[0]!, raw: STRIPE }] }), { ranAt: 1 })!;
  const text = JSON.stringify(rec);
  for (let i = 0; i + 8 <= STRIPE.length; i++) {
    const piece = STRIPE.slice(i, i + 8);
    if (piece === "sk_live_") continue;
    assert.ok(!text.includes(piece), `kept "${piece}"`);
  }
});

test("keepScan: the agents Mandu does not run (plan 17 §4 phase 3) are kept like the others, and the chats it only counted", () => {
  const ex = { at: "2026-10-04T08:00:01Z", agent: "gemini", how: "command-output", command: "cat .env", tool: "run_shell_command", project: "~/shop", mandu: "without", provider: "google" };
  const rec = keepScan(answer({
    sessions: { "claude-code": 3, gemini: 2, copilot: 1 },
    findings: [{ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", source: { path: "~/shop/.env", name: "STRIPE_KEY" }, sessions: 2, agents: ["copilot", "gemini"], how: { "command-output": 2 }, projects: ["~/shop"], duringMandu: 0, examples: [ex, { ...ex, agent: "copilot", tool: "bash", provider: "github" }] }],
    notRead: { cursor: 4, bogus: -1, [`x${"y".repeat(80)}`]: 2 },
  }), { ranAt: Date.parse("2026-10-21T09:00:00Z") })!;
  assert.deepEqual(rec.sessions, { "claude-code": 3, gemini: 2, copilot: 1 });
  assert.deepEqual(rec.findings[0]!.examples!.map((e) => [e.agent, e.provider]), [["gemini", "google"], ["copilot", "github"]]);
  assert.equal(rec.notRead?.["cursor"], 4);
  assert.equal(rec.notRead?.["bogus"], undefined, "a count that is not one is dropped");
  assert.ok(Object.keys(rec.notRead ?? {}).every((k) => k.length <= 64), "a key is cut");
  assert.equal(keepScan(answer(), { ranAt: Date.parse("2026-10-21T09:00:00Z") })!.notRead, undefined, "absent when the answer has none");
});

test("keepScan: a send's channel and the test-value mark are kept; an unknown channel and a mark on one of your secrets are not", () => {
  const a = answer();
  const sends = a["sends"] as Array<Record<string, unknown>>;
  sends.push({ ...sends[0]!, host: "mcp__notes__save", channel: "mcp", via: ["MCP"] });
  sends.push({ ...sends[0]!, host: "prod", channel: "carrier-pigeon" });
  sends.push({ ...sends[0]!, kind: "openai-key", preview: "sk-…", source: undefined, host: "api.openai.com", channel: "http", looksLikeTest: true });
  sends[0]!["looksLikeTest"] = true;
  const findings = a["findings"] as Array<Record<string, unknown>>;
  findings[0]!["looksLikeTest"] = true;
  findings[3]!["looksLikeTest"] = true;
  const rec = keepScan(a, { ranAt: 1 })!;
  assert.deepEqual(rec.sends!.map((s) => [s.host, s.channel, s.looksLikeTest]), [
    ["hooks.vendor.dev", undefined, undefined], ["mcp__notes__save", "mcp", undefined], ["prod", undefined, undefined], ["api.openai.com", "http", true],
  ], "an older send has no channel (HTTP); a known secret is never marked");
  assert.deepEqual(rec.findings.map((f) => f.looksLikeTest), [undefined, undefined, undefined, true]);
  assert.equal(keepScan(answer(), { ranAt: 1 })!.findings[3]!.looksLikeTest, undefined, "absent from an older arbiter");
});
