/**
 * settings-not-running e2e — Settings › Protection says once that Mandu is
 * not running, with its start commands as code with Copy, on the REAL
 * dashboard where Mandu never ran (dashboard.md §4.25 *Protection is off
 * when nothing runs*, *Said once*). Mandu-new.
 *
 * Until 2026-11-02 the row said it twice there: "Saved as on. Mandu is not
 * running now, so no agent is protected. It starts with your first agent:
 * mandu claude (or mandu codex)." in plain words, and under it "Stopped. It
 * starts again by itself when you next start an agent with mandu. [Start]".
 * Here the REAL launcher (`tsx launcher/src/run.ts`) runs `mandu scan` and
 * then `mandu dashboard` in a throwaway home and runtime dir where no Mandu
 * ever ran (no arbiter, no session), as not-running-lines.test.ts does, with
 * an account made first. The served Settings page (its own index.html and
 * home.js in jsdom, fetching from that dashboard with the account, with a
 * clipboard):
 *
 *   S1  the Protection sentence names the command as code, with its Copy;
 *   S2  the service line under it, from the dashboard's own supervisor, is
 *       "Stopped." and Start: no "It starts again by itself";
 *   S3  the oracle: no 8-character run of the planted value in any output,
 *       answer or drawn page.
 *
 * The dashboard is stopped (SIGTERM to its registered pid) at the end.
 * Axes: secrets (stated; nothing of Mandu's runs, and the scan's throwaway
 * arbiter is the launcher's own at the built-in default). No kernel layer.
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
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6YvSaidOnce`;

function assertNoValue(where: string, text: string): void {
  for (let i = 0; i + 8 <= STRIPE.length; i++) {
    const piece = STRIPE.slice(i, i + 8);
    if (piece === "sk_live_") continue; // the format's public prefix, shown on purpose
    assert.ok(!text.includes(piece), `${where} holds "${piece}" of the planted value`);
  }
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

let tmp = "";
const dashPids: number[] = [];
after(async () => {
  for (const pid of dashPids) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
  const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
  for (let i = 0; i < 100 && dashPids.some(alive); i++) await sleep(50);
  for (const pid of dashPids) { if (alive(pid)) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } } }
  // A child of the launcher's can still be writing tsx's cache under the
  // TMPDIR it was given (`tsx-<uid>`) once the dashboard is gone (ENOTEMPTY,
  // pipeline 14099): the removal is tried again until those writes end, up
  // to 10 s; a tree still growing then is a leak, and fails.
  for (let i = 0; tmp; i++) {
    try { rmSync(tmp, { recursive: true, force: true }); break; } catch (e) {
      if (i >= 50 || (e as NodeJS.ErrnoException).code !== "ENOTEMPTY") throw e;
      await sleep(200);
    }
  }
});

test("where Mandu never ran, Settings › Protection says once that it is not running, the command as code with Copy, and the service line only Stopped with Start", { timeout: 300_000 }, async () => {
  const missing = ["launcher", "arbiter", "dashboard"].filter((p) => !existsSync(join(REPO_ROOT, p, INSTALLED_MARKER)));
  if (missing.length > 0) throw new MissingStackPackagesError(missing, "settings-not-running", REPO_ROOT);
  // A short name: `mandu scan` puts a throwaway arbiter's sockets under this
  // TMPDIR (`mdu-dr-*/human/…`), and a socket path must fit sun_path (107
  // bytes). Under test-all.sh's own TMPDIR the longer "mdu-settings-notrunning-"
  // made it 111 (the ubuntu-2604 matrix, 0.2.0-beta.9's tag run).
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-snr-")));
  const home = join(tmp, "home");
  const proj = join(home, "shop");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, ".env"), `STRIPE_KEY=${STRIPE}\n`);
  // A Claude Code record of a session that read the file, for the scan:
  // the command the page names is that agent's.
  const cc = join(home, ".claude", "projects", "-home-shop");
  mkdirSync(cc, { recursive: true });
  const line = (o: unknown): string => JSON.stringify(o);
  writeFileSync(join(cc, "s1.jsonl"), [
    line({ type: "assistant", timestamp: "2026-10-01T10:00:00Z", cwd: proj, message: { content: [{ type: "tool_use", id: "t1", name: "Read", input: { file_path: join(proj, ".env") } }] } }),
    line({ type: "user", timestamp: "2026-10-01T10:00:01Z", cwd: proj, message: { content: [{ type: "tool_result", tool_use_id: "t1", content: `STRIPE_KEY=${STRIPE}` }] } }),
  ].join("\n") + "\n");
  const xdg = join(tmp, "xdg");
  mkdirSync(xdg, { mode: 0o700 });
  const env = { HOME: home, PATH: process.env["PATH"], XDG_RUNTIME_DIR: xdg, TMPDIR: tmp };
  const mandu = (args: string[]) =>
    runChildToExit(LAUNCHER_TSX, [LAUNCHER_MAIN, ...args], { cwd: home, env, timeoutMs: 240_000, label: `mandu ${args[0]}` });
  const seen: [string, string][] = [];

  const scan = await mandu(["scan"]);
  seen.push(["mandu scan", scan.stdout + scan.stderr]);
  assert.equal(scan.code, 0, scan.stderr);
  const PASSWORD = "the person's own password";
  writeAccount(accountPath({ HOME: home }), await makeAccount("me", PASSWORD));
  const dash = await mandu(["dashboard"]);
  seen.push(["mandu dashboard", dash.stdout + dash.stderr]);
  assert.equal(dash.code, 0, dash.stderr);
  const up = /^dashboard up — (http:\/\/127\.0\.0\.1:\d+)\/$/m.exec(dash.stdout);
  assert.ok(up, dash.stdout);
  const base = up[1]!;
  for (const name of readdirSync(join(xdg, "mandu", "dashboards")).filter((n) => n.endsWith(".json"))) {
    dashPids.push((JSON.parse(readFileSync(join(xdg, "mandu", "dashboards", name), "utf8")) as { pid: number }).pid);
  }
  assert.ok(dashPids.length > 0, "the dashboard registered itself");
  const headers = { Authorization: `Basic ${Buffer.from(`me:${PASSWORD}`).toString("base64")}` };

  // The state, as the server says it: not running, never ran here; and the
  // dashboard's own supervisor holds the service, stopped.
  const homeRes = await pageFetch(`${base}/api/home`, { headers });
  const homeBody = await homeRes.text();
  seen.push(["GET /api/home", homeBody]);
  assert.equal(homeRes.status, 200, homeBody);
  const vm = JSON.parse(homeBody) as { protection: { notRunning?: boolean; connected: boolean } };
  assert.equal(vm.protection.notRunning, true);
  assert.equal(vm.protection.connected, false);
  const sumRes = await pageFetch(`${base}/api/control/summary`, { headers });
  const sumBody = await sumRes.text();
  seen.push(["GET /api/control/summary", sumBody]);
  const sum = (JSON.parse(sumBody) as { summary: { available: boolean; state: string; sentence: string } }).summary;
  assert.equal(sum.available, true, sumBody);
  assert.equal(sum.state, "stopped", sumBody);
  assert.match(sum.sentence, /It starts again by itself/, "the server still words the stopped line; the page says it once");

  const sentence = (doc: any) => doc.getElementById("settings-protect-text"); // eslint-disable-line @typescript-eslint/no-explicit-any
  const service = (doc: any) => doc.getElementById("settings-service-main"); // eslint-disable-line @typescript-eslint/no-explicit-any
  const wrote: string[] = [];
  await servedProductPage(base, "/settings",
    (doc) => sentence(doc)?.querySelector("code") !== null && service(doc)?.textContent === "Stopped. Start",
    async (doc) => {
      // S1: the one sentence, the command as code with its Copy.
      const copies = [...sentence(doc).querySelectorAll(".run-code > button.code-copy")] as any[]; // eslint-disable-line @typescript-eslint/no-explicit-any
      const read = sentence(doc).cloneNode(true);
      for (const b of read.querySelectorAll("button.code-copy, .code-copy-said")) b.remove();
      assert.equal(read.textContent, "Saved as on. Mandu is not running now, so no agent is protected. It starts with your first agent: mandu claude.");
      assert.deepEqual([...sentence(doc).querySelectorAll("code")].map((c: any) => c.textContent), ["mandu claude"]); // eslint-disable-line @typescript-eslint/no-explicit-any
      assert.deepEqual(copies.map((b) => b.getAttribute("aria-label")), ["Copy mandu claude"]);
      copies[0].click();
      await sleep(20);
      assert.deepEqual(wrote, ["mandu claude"], "S1: Copy writes exactly the command");
      // S2: the service line says only Stopped, with Start.
      assert.equal(service(doc).querySelector("button").textContent, "Start");
      assert.doesNotMatch(doc.getElementById("settings-protection-block").textContent, /It starts again by itself/);
      seen.push(["the drawn /settings", doc.body.textContent as string]);
    }, { headers, beforeScripts: (w) => {
      Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => (wrote.push(t), w.Promise.resolve()) } });
    } });

  // S3: the oracle.
  for (const [where, body] of seen) {
    assertNoValue(where, body);
    assert.ok(!body.includes(PASSWORD), `${where} holds the account's password`);
  }
});
