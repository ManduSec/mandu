/**
 * scan-dashboard-link e2e — `mandu scan` points at the dashboard, and the
 * dashboard opens where Mandu never ran, saying protection is off
 * (confidentiality-plan-17-past-sessions-scan.md §3 item 12; dashboard.md
 * §4.25 *Protection is off when nothing runs*, §4.25ai). Mandu-new.
 *
 * The REAL launcher (`tsx launcher/src/run.ts`, its own process each time)
 * in a throwaway home and runtime dir where no Mandu ever ran (no arbiter,
 * no session, no dashboard), over a Claude Code record of a session that
 * read a project `.env`:
 *
 *   S1  `mandu scan`, run as npx runs it (npm exec's own variables): the
 *       report ends with the command that opens the dashboard in its npx
 *       form, and the report is kept; piped, it has no colour, and with
 *       FORCE_COLOR=1 it has (the same text, no value either way);
 *   S2  `mandu dashboard` with no arbiter: it starts one anyway (before
 *       2026-10-22 it refused: "start a session first"), starts nothing of
 *       Mandu's, and says protection is off;
 *   S3  no dashboard account yet (dashboard.md §6.z): the dashboard serves
 *       nothing (401, "no account yet"), its registry entry says
 *       `no-account`, and `mandu scan` names the Scan page's URL with "no
 *       account yet; set one: mandu dashboard --set-password";
 *   S4  the account made while it runs (`--set-password`'s writer): the
 *       entry says `account`, and that REAL dashboard, with its
 *       credentials: /api/home's hero says protection is off (never
 *       "Not connected.", never protected), the top bar's protection is
 *       "not running", the scan card says the secret left in a session
 *       without Mandu; /api/scan holds the report; /scan serves the page;
 *       `mandu scan --all` then says to sign in with the account;
 *   S5  the oracle: no 8-character run of the planted value in any output
 *       or served body.
 *
 * The dashboard is stopped (SIGTERM to its registered pid) at the end; it
 * also dies with this test process (test-owner.ts).
 * Axes: secrets (stated; the scan's throwaway arbiter is the launcher's own,
 * whose confidentiality is the built-in default). No kernel layer.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runChildToExit } from "../lib/child-run.js";
import { accountPath, makeAccount, writeAccount } from "../../launcher/src/dashboard-account.js";
import { LAUNCHER_MAIN, LAUNCHER_TSX, REPO_ROOT } from "../lib/launcher-live.js";
import { INSTALLED_MARKER, MissingStackPackagesError } from "../lib/stack-preflight.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8NbLink`;

function assertNoValue(where: string, text: string): void {
  for (let i = 0; i + 8 <= STRIPE.length; i++) {
    const piece = STRIPE.slice(i, i + 8);
    if (piece === "sk_live_") continue; // the format's public prefix, shown on purpose
    assert.ok(!text.includes(piece), `${where} holds "${piece}" of the planted value`);
  }
}

let tmp = "";
const dashPids: number[] = [];
after(async () => {
  for (const pid of dashPids) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
  // Wait for each to exit before the directory goes: a dashboard still
  // running writes under it (its home, its registry), and the removal raced
  // that (ENOTEMPTY, pipeline 12829).
  const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
  for (let i = 0; i < 100 && dashPids.some(alive); i++) await new Promise((r) => setTimeout(r, 50));
  for (const pid of dashPids) { if (alive(pid)) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } } }
  if (tmp) rmSync(tmp, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
});

test("mandu scan points at the dashboard; mandu dashboard opens with Mandu never run and says protection is off", { timeout: 300_000 }, async () => {
  // The packages these commands run: the launcher, the scan's throwaway
  // arbiter and the dashboard (no agent runs, so no interceptor).
  const missing = ["launcher", "arbiter", "dashboard"].filter((p) => !existsSync(join(REPO_ROOT, p, INSTALLED_MARKER)));
  if (missing.length > 0) throw new MissingStackPackagesError(missing, "scan-dashboard-link", REPO_ROOT);
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-scanlink-")));
  const home = join(tmp, "home");
  const proj = join(home, "shop");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, ".env"), `STRIPE_KEY=${STRIPE}\n`);
  const cc = join(home, ".claude", "projects", "-home-shop");
  mkdirSync(cc, { recursive: true });
  const line = (o: unknown): string => JSON.stringify(o);
  writeFileSync(join(cc, "s1.jsonl"), [
    line({ type: "assistant", timestamp: "2026-10-01T10:00:00Z", cwd: proj, message: { content: [{ type: "tool_use", id: "t1", name: "Read", input: { file_path: join(proj, ".env") } }] } }),
    line({ type: "user", timestamp: "2026-10-01T10:00:01Z", cwd: proj, message: { content: [{ type: "tool_result", tool_use_id: "t1", content: `STRIPE_KEY=${STRIPE}` }] } }),
  ].join("\n") + "\n");
  const xdg = join(tmp, "xdg");
  mkdirSync(xdg, { mode: 0o700 });
  // The person's environment: their home, their runtime dir, nothing of
  // Mandu's pinned (no MANDU_HOME, no arbiter socket).
  const env = { HOME: home, PATH: process.env["PATH"], XDG_RUNTIME_DIR: xdg, TMPDIR: tmp };
  const npx = { ...env, npm_command: "exec", npm_lifecycle_event: "npx", npm_lifecycle_script: "mandu" };
  const mandu = (args: string[], e: Record<string, string | undefined>) =>
    runChildToExit(LAUNCHER_TSX, [LAUNCHER_MAIN, ...args], { cwd: home, env: e, timeoutMs: 240_000, label: `mandu ${args[0]}` });
  const lastLine = (s: string): string => s.trimEnd().split("\n").pop() ?? "";
  const seen: [string, string][] = [];

  // ── S1: the scan, run as npx runs it ──
  const first = await mandu(["scan"], npx);
  seen.push(["the first scan", first.stdout + first.stderr]);
  assert.equal(first.code, 0, first.stderr);
  assert.match(first.stdout, /\n✗ 1 of your secrets leaked to the AI\n\n {2}1 {2}STRIPE_KEY {3}~\/shop\/\.env\n/);
  assert.doesNotMatch(first.stdout, /\x1b\[/, "piped: no colour");
  assert.equal(lastLine(first.stdout), "  Dashboard:            run npx @mandusec/mandu dashboard and open Scan");
  // FORCE_COLOR=1 (piped all the same): the SGR codes, around the same text.
  const colored = await mandu(["scan"], { ...npx, FORCE_COLOR: "1" });
  seen.push(["the coloured scan", colored.stdout + colored.stderr]);
  assert.equal(colored.code, 0, colored.stderr);
  assert.ok(colored.stdout.includes("\x1b[1m\x1b[31m✗ 1 of your secrets leaked to the AI\x1b[39m\x1b[22m"), colored.stdout);
  assert.ok(colored.stdout.includes("  \x1b[31m1\x1b[39m  STRIPE_KEY   \x1b[2m~/shop/.env\x1b[22m"), colored.stdout);
  // eslint-disable-next-line no-control-regex
  assert.equal(colored.stdout.replace(/\x1b\[[0-9;]*m/g, ""), first.stdout, "the colours add nothing but colour");
  const kept = readFileSync(join(home, ".mandu", "state", "last-scan.json"), "utf8");
  seen.push(["the kept report", kept]);

  // ── S2: the dashboard, with no arbiter anywhere ──
  const dash = await mandu(["dashboard"], env);
  seen.push(["mandu dashboard", dash.stdout + dash.stderr]);
  assert.equal(dash.code, 0, dash.stderr);
  const up = /^dashboard up — (http:\/\/127\.0\.0\.1:\d+\/)$/m.exec(dash.stdout);
  assert.ok(up, dash.stdout);
  const base = up[1]!;
  const entries = (): { pid: number; signInMode?: string }[] =>
    readdirSync(join(xdg, "mandu", "dashboards")).filter((n) => n.endsWith(".json"))
      .map((name) => JSON.parse(readFileSync(join(xdg, "mandu", "dashboards", name), "utf8")) as { pid: number; signInMode?: string });
  for (const m of entries()) {
    dashPids.push(m.pid);
    // How it signs people in rides its entry: no account yet (dashboard.md §6.z).
    assert.equal(m.signInMode, "no-account");
  }
  assert.ok(dashPids.length > 0, "the dashboard registered itself");
  assert.match(dash.stdout, /\nMandu is not running, so it protects no agent now: start yours with mandu claude \(or mandu codex\)\. The dashboard shows your last scan under Scan\.\n/);
  // It started nothing of Mandu's: no arbiter instance, no `current`.
  assert.deepEqual(readdirSync(join(xdg, "mandu")).filter((n) => n === "instances" || n === "current"), []);

  // ── S3: no account yet: nothing served, and the scan says to set one ──
  let headers: Record<string, string> = {};
  const get = async (path: string): Promise<{ status: number; body: string }> => {
    const r = await fetch(base + path, { headers });
    const body = await r.text();
    seen.push([`GET /${path}`, body]);
    return { status: r.status, body };
  };
  const closed = await get("api/home");
  assert.equal(closed.status, 401, closed.body);
  assert.match(closed.body, /no account yet; run `mandu dashboard --set-password`/);
  const second = await mandu(["scan"], env);
  seen.push(["the second scan", second.stdout + second.stderr]);
  assert.equal(second.code, 0, second.stderr);
  assert.equal(lastLine(second.stdout), `  Dashboard:            ${base}scan (no account yet; set one: mandu dashboard --set-password)`);

  // ── S4: the account, made while it runs; then Home, Scan and its API ──
  const PASSWORD = "the person's own password";
  writeAccount(accountPath({ HOME: home }), await makeAccount("me", PASSWORD));
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline && !entries().every((m) => m.signInMode === "account")) await new Promise((r) => setTimeout(r, 200));
  assert.deepEqual(entries().map((m) => m.signInMode), entries().map(() => "account"), "the entry says the new way in");
  headers = { Authorization: `Basic ${Buffer.from(`me:${PASSWORD}`).toString("base64")}` };
  const homeRes = await get("api/home");
  assert.equal(homeRes.status, 200, homeRes.body);
  const vm = JSON.parse(homeRes.body) as { verdict: string; headline: string; sentence: string; protection: Record<string, unknown>; scan?: { headline: string; sentence: string }; firstRun: unknown };
  assert.equal(vm.verdict, "off");
  assert.equal(vm.headline, "Protection is off: no agent runs with Mandu.");
  assert.equal(vm.sentence, "Your agents send what they read to the AI as it is, secrets included. To protect one, start it with mandu claude (or mandu codex).");
  assert.equal(vm.protection["notRunning"], true);
  assert.equal(vm.protection["connected"], false);
  assert.doesNotMatch(homeRes.body, /Not connected|You are protected|Your secrets are guarded/);
  assert.ok(vm.firstRun, "Mandu never ran: the setup card");
  assert.equal(vm.scan?.headline, "1 of your secrets left this computer in your agents' requests");
  assert.match(vm.scan?.sentence ?? "", /in a session without Mandu/);
  const scanRes = await get("api/scan");
  assert.equal(scanRes.status, 200);
  const page = (JSON.parse(scanRes.body) as { scan: { ran: boolean; sections: { id: string; items: { title: string; footnote: string | null }[] }[] } }).scan;
  assert.equal(page.ran, true);
  const yours = page.sections.find((s) => s.id === "yours")!;
  assert.deepEqual(yours.items.map((i) => i.title), ["STRIPE_KEY in ~/shop/.env"]);
  const html = await get("scan");
  assert.equal(html.status, 200);
  assert.match(html.body, /<meta name="mandu-app" content="home">/);

  // The scan again, with the account: its Scan page's URL and how to sign in.
  const all = await mandu(["scan", "--all"], env);
  seen.push(["the scan --all", all.stdout + all.stderr]);
  assert.equal(lastLine(all.stdout), `This report is in your dashboard too: ${base}scan (sign in with your Mandu dashboard account)`);

  // ── S5: the oracle ──
  for (const [where, text] of seen) {
    assertNoValue(where, text);
    assert.ok(!text.includes(PASSWORD), `${where} holds the account's password`);
  }
});
