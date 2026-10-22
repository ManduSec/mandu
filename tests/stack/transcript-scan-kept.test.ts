/**
 * transcript-scan-kept e2e — `mandu scan` keeps its last report, and the
 * product shows it (confidentiality-plan-17-past-sessions-scan.md §3 items
 * 12 and 13; dashboard.md §4.25ai). The PRODUCTION path end to end:
 *
 *   1. the launcher's `runScan` with the real `realScanDeps` (the op call,
 *      `suggestFromScan` over ndjson, the file write), the scan in one REAL
 *      ArbiterServer (the throwaway's role) and the suggestions filed in a
 *      SECOND one (the running Mandu's), over a fixture home where a Claude
 *      Code session read a project `.env` (the catalog protects it) and a
 *      command printed a CLI's token from `~/.config/some-cli/config.yml`
 *      (nothing protects it);
 *   2. the report says a rule waits; the kept file is at the path table's
 *      `last-scan`, mode 0600;
 *   3. doctor's line reads it (`realDoctorDeps.lastScan`);
 *   4. a REAL DashboardServer reads it: /api/home's card leads with the two
 *      secrets that left, /api/scan tells both stories, and /api/suggestions
 *      (signed in) lists the CLI's config as a past-sessions row, which Save
 *      applies on the admin channel into policy.yaml;
 *   4b. each finding names its file for *Change it in Rules* (`file`,
 *      Home's `ruleFile`), and on the served Scan page (jsdom) following
 *      the link opens Rules with Add a rule's file browser at the `.env`,
 *      its row opened, the address back at `/rules` (§4.25ai);
 *   5. the oracle: no 8-character run of either planted value in the
 *      report, the kept file, doctor's line, any dashboard body or drawn
 *      page, either arbiter's log, the running one's database or
 *      policy.yaml.
 * Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { realScanDeps, runScan } from "../../launcher/src/scan-command.js";
import { lastScanPath } from "../../launcher/src/scan-kept.js";
import { realDoctorDeps } from "../../launcher/src/doctor.js";
import { lastScanLine } from "../../launcher/src/scan-kept.js";
import type { Layout } from "../../launcher/src/services/layout.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import type { EventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
const TOKEN = `${"gh" + "o_"}Zt4Qm8Lp2Xw7Rk9Vb3Nc6Hj1Df5Gs0Ae2Yu8T`;
const PLANTED = [STRIPE, TOKEN];

function assertNoValue(where: string, text: string): void {
  for (const v of PLANTED) {
    for (let i = 0; i + 8 <= v.length; i++) {
      const piece = v.slice(i, i + 8);
      if (piece === "sk_live_") continue; // the format's public prefix, shown on purpose
      assert.ok(!text.includes(piece), `${where} holds "${piece}" of a planted value`);
    }
  }
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function fixtureHome(dir: string): string {
  const home = join(dir, "home");
  const proj = join(home, "shop");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, ".env"), `STRIPE_KEY=${STRIPE}\n`);
  const cli = join(home, ".config", "some-cli");
  mkdirSync(cli, { recursive: true });
  writeFileSync(join(cli, "config.yml"), `user: someone\ntoken: ${TOKEN}\n`);
  const cc = join(home, ".claude", "projects", "-home-shop");
  mkdirSync(cc, { recursive: true });
  const line = (o: unknown): string => JSON.stringify(o);
  writeFileSync(join(cc, "s1.jsonl"), [
    line({ type: "assistant", timestamp: "2026-10-01T10:00:00Z", cwd: proj, message: { content: [{ type: "tool_use", id: "t1", name: "Read", input: { file_path: join(proj, ".env") } }] } }),
    line({ type: "user", timestamp: "2026-10-01T10:00:01Z", cwd: proj, message: { content: [{ type: "tool_result", tool_use_id: "t1", content: `STRIPE_KEY=${STRIPE}` }] } }),
    line({ type: "assistant", timestamp: "2026-10-01T10:00:02Z", cwd: proj, message: { content: [{ type: "tool_use", id: "t2", name: "Bash", input: { command: "cat ~/.config/some-cli/config.yml" } }] } }),
    line({ type: "user", timestamp: "2026-10-01T10:00:03Z", cwd: proj, message: { content: [{ type: "tool_result", tool_use_id: "t2", content: `user: someone\ntoken: ${TOKEN}` }] } }),
  ].join("\n") + "\n");
  return home;
}

const noSessions: EventSource = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
} as unknown as EventSource;

test("mandu scan keeps its report; doctor, Home, the Scan page and a past-sessions suggestion show it with no value", { timeout: 120_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-scan-kept-"));
  dirs.push(dir);
  const home = fixtureHome(dir);
  const env = { HOME: home, MANDU_HOME: join(home, ".mandu"), PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  const logs: string[] = [];
  // The throwaway's role: the scan runs here.
  const scanSock = join(dir, "scan.sock");
  const scanArb = new ArbiterServer({
    socketPath: scanSock, dbPath: join(dir, "scan.sqlite"), eventDir: join(dir, "scan-events"),
    log: (m) => logs.push(m), confidentiality: true, integrity: false, policyPollMs: 0,
  });
  // The running Mandu's: its own store and law, with an admin channel.
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const stack = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 0, log: (m) => logs.push(m), confidentiality: true, integrity: false,
  });
  await scanArb.listen();
  await stack.listen();
  const deps = {
    ...realScanDeps,
    arbiter: async () => ({ sock: scanSock, kind: "throwaway" as const, axisOn: true, stop: async () => {} }),
    keep: { ...realScanDeps.keep!, resident: async () => dataSock },
  };
  let dash: DashboardServer | null = null;
  try {
    // ── 1, 2: the scan, its report and the kept file ──
    const out: string[] = [];
    const err: string[] = [];
    const code = await runScan([], env, {} as Layout, deps, { out: (s) => out.push(s), err: (s) => err.push(s) });
    const report = out.join("");
    assert.equal(code, 0, err.join(""));
    assert.match(report, /\n✗ 2 of your secrets leaked to the AI\n/);
    assert.match(report, /\n {2}\d {2}token {3}~\/\.config\/some-cli\/config\.yml\n/);
    assert.match(report, /\n1 file that holds them has no rule yet: Mandu suggests one for each in the dashboard/);
    const kept = lastScanPath(env, home);
    assert.equal(kept, join(home, ".mandu", "state", "last-scan.json"));
    assert.equal(statSync(kept).mode & 0o777, 0o600);
    const keptText = readFileSync(kept, "utf8");
    const rec = JSON.parse(keptText) as { findings: Array<{ kind: string; preview: string }>; suggestions: unknown };
    assert.deepEqual(rec.findings.filter((f) => f.kind === "known").map((f) => f.preview).sort(), ["STRIPE_KEY in ~/shop/.env", "token in ~/.config/some-cli/config.yml"]);
    assert.deepEqual(rec.suggestions, { pending: 1, filed: 1, covered: 1 }, "the .env is the catalog's; the config is suggested");

    // ── 3: doctor ──
    const line = lastScanLine(realDoctorDeps.lastScan!(env));
    assert.match(line, /^Last scan \(\d{1,2} [A-Z][a-z]{2}\): 2 of your secrets reached the AI in sessions without Mandu; 1 rule waits for you in the dashboard \(mandu scan to check again\)$/);

    // ── 4: the dashboard over the kept file and the running arbiter ──
    const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
    assert.ok(wired?.policyDoc);
    dash = new DashboardServer({ source: noSessions, policyDocArbiter: wired.policyDoc, fileBrowserHome: home, configEnv: env, log: () => {}, ...ADMIN_OPTS });
    const base = `http://127.0.0.1:${await dash.listen(0)}`;
    const bodies: string[] = [];
    const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
      const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
      const text = await r.text();
      bodies.push(text);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return { status: r.status, body: JSON.parse(text) as any };
    };
    const homeVm = await call("GET", "/api/home");
    assert.equal(homeVm.status, 200);
    assert.equal(homeVm.body.scan.ran, true);
    assert.equal(homeVm.body.scan.headline, "2 of your secrets left this computer in your agents' requests");
    assert.deepEqual(homeVm.body.scan.top.map((t: { name: string; file: string }) => [t.name, t.file]).sort(), [["STRIPE_KEY", "~/shop/.env"], ["token", "~/.config/some-cli/config.yml"]]);
    assert.match(homeVm.body.scan.suggested, /^1 file that holds them has no rule yet/);
    const page = await call("GET", "/api/scan");
    assert.equal(page.status, 200);
    const yours = page.body.scan.sections.find((s: { id: string }) => s.id === "yours");
    const cfg = yours.items.find((i: { title: string }) => i.title === "token in ~/.config/some-cli/config.yml");
    // With part D's examples the command is named; without, the counts tell it.
    const told = cfg.story.map((s: { text: string }) => s.text);
    assert.equal(told[0], "It lives in ~/.config/some-cli/config.yml as token.");
    assert.match(told[1], /^1 Oct · ~\/shop · Claude Code$/);
    assert.match(told[2], /^(A command printed it\.|The agent ran: cat ~\/\.config\/some-cli\/config\.yml)$/);
    assert.equal(told[3], "The output, with the secret in it, went to the AI: it left this computer in Claude Code's next request to Anthropic.");
    assert.equal(cfg.footnote, "1 session without Mandu.");

    // ── 4b: Change it in Rules, from the finding to its file's row ──
    assert.equal(cfg.file, "~/.config/some-cli/config.yml");
    const stripe = yours.items.find((i: { title: string }) => i.title === "STRIPE_KEY in ~/shop/.env");
    assert.equal(stripe.file, "~/shop/.env");
    assert.deepEqual(homeVm.body.scan.top.map((t: { ruleFile: string | null }) => t.ruleFile).sort(), ["~/.config/some-cli/config.yml", "~/shop/.env"]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stripeLink = (doc: any) => doc.querySelector('[data-section="yours"] a.secret-rule-link[data-file="~/shop/.env"]');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const openRow = (doc: any) => doc.querySelector("#files-list .row.file.open");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(base, "/scan", (doc: any) => !!stripeLink(doc), async (doc: any) => {
      const w = doc.defaultView;
      const link = stripeLink(doc);
      assert.equal(link.textContent, "Change it in Rules");
      assert.equal(link.getAttribute("aria-label"), "Change the rule for ~/shop/.env in Rules");
      assert.equal(link.getAttribute("href"), "/rules?file=~/shop/.env");
      bodies.push(doc.body.textContent ?? "");
      link.click();
      await waitWhile(() => !openRow(doc), 20_000);
      assert.equal(w.location.pathname + w.location.search, "/rules", "the address drops ?file= once used");
      assert.equal(doc.getElementById("page-rules").hidden, false);
      assert.equal(doc.getElementById("lock-form").hidden, false, "Add a rule's browser is open");
      assert.equal(openRow(doc).getAttribute("data-path"), join(home, "shop", ".env"), "the file's row is opened");
      bodies.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    const listed = await call("GET", "/api/suggestions");
    assert.equal(listed.status, 200, JSON.stringify(listed.body));
    const row = listed.body.suggestions.find((s: { source: string }) => s.source === "past-sessions");
    assert.ok(row, JSON.stringify(listed.body.suggestions));
    assert.equal(row.path, join(home, ".config", "some-cli", "config.yml"));
    assert.equal(row.by, "Suggested by mandu scan");
    assert.deepEqual(row.found, [{ words: "Reached the AI in a past session", mask: "token" }]);
    const save = await call("POST", "/api/suggestions/apply", { ids: [row.id] });
    assert.equal(save.status, 200, JSON.stringify(save.body));
    assert.match(readFileSync(policy, "utf8"), /some-cli\/config\.yml\n\s+level: no-model/, "the person's Save wrote the lock");

    // ── 5: the oracle ──
    assertNoValue("the report", report + err.join(""));
    assertNoValue("the kept file", keptText);
    assertNoValue("doctor's line", line);
    for (const b of bodies) assertNoValue("a dashboard body", b);
    assertNoValue("the arbiters' logs", logs.join("\n"));
    assertNoValue("the running arbiter's database", readFileSync(join(dir, "mandu.db")).toString("latin1"));
    assertNoValue("policy.yaml", readFileSync(policy, "utf8"));
  } finally {
    if (dash) await dash.close();
    await scanArb.close();
    await stack.close();
  }
});
