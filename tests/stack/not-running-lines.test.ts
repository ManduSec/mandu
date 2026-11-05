/**
 * not-running-lines e2e — before Mandu first runs, every page of the
 * dashboard says Mandu is not running yet, never a fault (dashboard.md §4.25
 * *Protection is off when nothing runs*, *Rule changes says when it could
 * not be read*). Mandu-new.
 *
 * Until 2026-10-31 the hero, the top bar and Settings › Protection said so,
 * and every line that could not read something read the same state as a
 * fault: "may be unreachable", "not connected", and Rule changes "The
 * dashboard server answered with an error (404). Refresh in a moment.".
 * Here the REAL launcher (`tsx launcher/src/run.ts`) runs `mandu scan` and
 * then `mandu dashboard` in a throwaway home and runtime dir where no Mandu
 * ever ran (no arbiter, no session), as scan-dashboard-link.test.ts S2
 * does, with an account made first. Each served page (its own index.html
 * and home.js in jsdom, fetching from that dashboard with the account):
 *
 *   N1  Home: the waiting card says none waits and how Mandu starts;
 *   N2  Approvals: Waiting, Answered earlier and Rule changes say Mandu is
 *       not running, with the start command as code, and no "(404)";
 *   N3  Rules: Your rules and Built-in protections say so ("not running");
 *       Add a rule's file browser note and Keys Mandu found (opened with
 *       Review) say so too, the command as code (since 2026-11-03);
 *   N4  Settings: Models, Sensitivity labels and Prompt filters say so;
 *   N5  History: the empty record's line, its Find box hidden;
 *   N6  on every page, none of the fault words; and the oracle: no
 *       8-character run of the planted value in any output, answer or
 *       drawn page.
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
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6YvQxPvZk9Lw`;

function assertNoValue(where: string, text: string): void {
  for (let i = 0; i + 8 <= STRIPE.length; i++) {
    const piece = STRIPE.slice(i, i + 8);
    if (piece === "sk_live_") continue; // the format's public prefix, shown on purpose
    assert.ok(!text.includes(piece), `${where} holds "${piece}" of the planted value`);
  }
}

/** The words of a fault, which this state never is. */
const FAULT = /may be unreachable|not connected|not reachable|error \(|\(404\)|Refresh in a moment|try again in a moment|Could not|could not be read/i;
const START = "Mandu is not running now; ";
/** The text under `node` outside every element marked hidden. */
function shownText(node: any): string { // eslint-disable-line @typescript-eslint/no-explicit-any
  if (node.nodeType === 3) return node.textContent as string;
  if (node.nodeType !== 1 || node.hidden) return "";
  return [...node.childNodes].map(shownText).join("");
}
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
/** Wait until `cond` holds (a served page reads its routes on its own time). */
async function until(cond: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 200 && !cond(); i++) await sleep(50);
  assert.ok(cond(), `${what} was never drawn`);
}

let tmp = "";
const dashPids: number[] = [];
after(async () => {
  for (const pid of dashPids) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
  const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
  for (let i = 0; i < 100 && dashPids.some(alive); i++) await sleep(50);
  for (const pid of dashPids) { if (alive(pid)) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } } }
  // A child of the launcher's can still be writing tsx's cache under the
  // TMPDIR it was given (`tsx-<uid>`) once the dashboard is gone (ENOTEMPTY;
  // settings-not-running.test.ts met it first): the removal is tried again
  // until those writes end, up to 10 s; a tree still growing then is a leak.
  for (let i = 0; tmp; i++) {
    try { rmSync(tmp, { recursive: true, force: true }); break; } catch (e) {
      if (i >= 50 || (e as NodeJS.ErrnoException).code !== "ENOTEMPTY") throw e;
      await sleep(200);
    }
  }
});

test("before Mandu first runs, Home, Approvals, Rules, Settings and History say it is not running, never a fault, with no value on the way", { timeout: 300_000 }, async () => {
  const missing = ["launcher", "arbiter", "dashboard"].filter((p) => !existsSync(join(REPO_ROOT, p, INSTALLED_MARKER)));
  if (missing.length > 0) throw new MissingStackPackagesError(missing, "not-running-lines", REPO_ROOT);
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-notrunning-")));
  const home = join(tmp, "home");
  const proj = join(home, "shop");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, ".env"), `STRIPE_KEY=${STRIPE}\n`);
  // A Claude Code record of a session that read the file, for the scan.
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

  // The state, as the server says it: not running, never ran here.
  const homeRes = await pageFetch(`${base}/api/home`, { headers });
  const homeBody = await homeRes.text();
  seen.push(["GET /api/home", homeBody]);
  assert.equal(homeRes.status, 200, homeBody);
  const vm = JSON.parse(homeBody) as { protection: { notRunning?: boolean; connected: boolean }; firstRun: unknown; builtIn: { note: string; items: string[] } };
  assert.equal(vm.protection.notRunning, true);
  assert.equal(vm.protection.connected, false);
  assert.ok(vm.firstRun, "Mandu never ran here");
  assert.equal(vm.builtIn.note, "not running", "N3: the server's Built-in protections");
  // The read Rule changes makes: the route's own refusal, which the page
  // must not show as its status.
  const changes = await pageFetch(`${base}/api/policy/changes?limit=21`, { headers });
  seen.push(["GET /api/policy/changes", await changes.text()]);

  /** The served `path` once `ready` holds: `check`, then no fault word on the page shown. */
  const page = async (path: string, ready: (doc: any) => boolean, check: (doc: any) => void | Promise<void>): Promise<void> => { // eslint-disable-line @typescript-eslint/no-explicit-any
    await servedProductPage(`${base}`, path, ready, async (doc) => {
      await check(doc);
      // What the page shown shows: the other pages, and a closed view
      // (Keys Mandu found until Review), are hidden in the same document.
      const main = shownText(doc.getElementById("page-" + (path.slice(1) || "home")));
      seen.push([`the drawn ${path}`, doc.body.textContent as string]);
      const fault = FAULT.exec(main);
      assert.equal(fault, null, `N6: ${path} says "${fault?.[0]}": ${main.slice(Math.max(0, (fault?.index ?? 0) - 120), (fault?.index ?? 0) + 120)}`);
    }, { headers });
  };
  const text = (doc: any, id: string): string => (doc.getElementById(id)?.textContent ?? "") as string; // eslint-disable-line @typescript-eslint/no-explicit-any
  const codes = (doc: any, id: string): string[] => [...doc.getElementById(id).querySelectorAll("code")].map((c: any) => c.textContent); // eslint-disable-line @typescript-eslint/no-explicit-any

  // N1: Home.
  await page("/", (doc) => /none is waiting/.test(text(doc, "home-waiting")), (doc) => {
    assert.equal(text(doc, "home-waiting"), "No agent runs with Mandu now, so none is waiting for your answer. Mandu starts with your first agent: mandu claude.");
    assert.deepEqual(codes(doc, "home-waiting"), ["mandu claude"], "N1: the command as code");
  });

  // N2: Approvals.
  await page("/approvals", (doc) => /none is waiting/.test(text(doc, "approvals-waiting")) && text(doc, "approvals-answered").startsWith(START)
    && text(doc, "approvals-rule-history").startsWith(START), (doc) => {
    assert.equal(text(doc, "approvals-answered"), START + "your earlier answers show here once it starts with your first agent: mandu claude.");
    assert.equal(text(doc, "approvals-rule-history"), START + "your rule changes show here once it starts with your first agent: mandu claude.");
    assert.deepEqual(codes(doc, "approvals-rule-history"), ["mandu claude"]);
    assert.doesNotMatch(doc.body.textContent, /\(404\)/, "N2: no status");
  });

  // N3: Rules.
  await page("/rules", (doc) => text(doc, "files-tree").startsWith(START) && text(doc, "builtin-note") === "not running", async (doc) => {
    assert.match(text(doc, "files-tree"), /^Mandu is not running now; your rules show here once it starts with your first agent: mandu claude\. You can still add a rule\.$/);
    assert.equal(text(doc, "builtin-list"), "Mandu is not running now, so none of these is on. They turn on with your first agent.");
    // Add a rule: the file browser lists the folder; the note over it says
    // where the levels show, not that the labels could not be read.
    doc.getElementById("rules-add").click();
    await until(() => text(doc, "files-note").startsWith(START), "the file browser's note");
    assert.equal(text(doc, "files-note"), START + "the levels of your files show here once it starts with your first agent: mandu claude. You can still choose rules.");
    assert.deepEqual(codes(doc, "files-note"), ["mandu claude"], "N3: the command as code");
    assert.equal(doc.getElementById("files-note").hidden, false);
    // Keys Mandu found, opened with Review: where its error was.
    doc.getElementById("suggest-open").click();
    await until(() => text(doc, "suggest-error").startsWith(START), "Keys Mandu found's line");
    assert.equal(text(doc, "suggest-error"), START + "the keys it finds show here once it starts with your first agent: mandu claude.");
    assert.deepEqual(codes(doc, "suggest-error"), ["mandu claude"]);
    assert.equal(doc.getElementById("files-suggested-view").hidden, false, "N3: Review opened it");
  });

  // N4: Settings.
  await page("/settings", (doc) => ["settings-models", "settings-labels", "settings-prompt-kinds"].every((id) => text(doc, id).startsWith(START)), (doc) => {
    assert.equal(text(doc, "settings-models"), START + "the model list shows here once it starts with your first agent: mandu claude.");
    assert.equal(text(doc, "settings-labels"), START + "your sensitivity labels show here once it starts with your first agent: mandu claude.");
    assert.equal(text(doc, "settings-prompt-kinds"), START + "your prompt filter settings show here once it starts with your first agent: mandu claude.");
    for (const id of ["settings-models", "settings-labels", "settings-prompt-kinds"]) assert.deepEqual(codes(doc, id), ["mandu claude"], id);
  });

  // N5: History.
  await page("/history", (doc) => /No session has been recorded yet/.test(text(doc, "history-list")), (doc) => {
    assert.equal(text(doc, "history-list"), "No session has been recorded yet. Start your agent through Mandu, mandu claude, and it shows up here.");
    assert.equal(doc.getElementById("history-search").hidden, true, "N5: no box over an empty record");
  });

  // N6: the oracle.
  for (const [where, body] of seen) {
    assertNoValue(where, body);
    assert.ok(!body.includes(PASSWORD), `${where} holds the account's password`);
  }
});
