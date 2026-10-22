/**
 * scan-open e2e — `mandu scan --open`: after the report, this user's
 * dashboard, started if none runs, and its Scan page opened in the browser
 * (confidentiality-plan-17-past-sessions-scan.md §3 item 12, the maintainer
 * 2026-10-22). Mandu-new.
 *
 * The REAL launcher (`tsx launcher/src/run.ts`, its own process each time)
 * in a throwaway home and runtime dir where no Mandu ever ran, over a Claude
 * Code record of a session that read a project `.env`, with `BROWSER` set to
 * a recorder script (the browser convention the launcher honours first):
 *
 *   O1  `mandu scan --open` with no dashboard: the report, then one started
 *       (registered, its pid alive, answering) and "Started the dashboard
 *       and opened its Scan page: <url> (no account yet; set one: mandu
 *       dashboard --set-password)"; the recorder was started with exactly
 *       that URL as its one argument (no query, no sign-in link or
 *       credential: an argument sits in `ps`); with no account the page
 *       there is the sign-in gate's (dashboard.md §6.z);
 *   O2  the account made, `mandu scan --open` again: the same dashboard
 *       reused (no second registry entry), "Opened the dashboard's Scan
 *       page: <same url> (sign in with your Mandu dashboard account)", the
 *       recorder started once more with the same URL, and the page answers
 *       there with the account's credentials;
 *   O3  `--open --json` and `--open --share`: exit 2, nothing started;
 *   O4  the oracle: no 8-character run of the planted value in any output,
 *       the recorder's arguments or the page served.
 *
 * The dashboard is stopped (SIGTERM to its registered pid) at the end.
 * Axes: secrets (stated; the scan's throwaway arbiter is the launcher's own,
 * whose confidentiality is the built-in default). No kernel layer.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runChildToExit } from "../lib/child-run.js";
import { accountPath, makeAccount, writeAccount } from "../../launcher/src/dashboard-account.js";
import { LAUNCHER_MAIN, LAUNCHER_TSX, REPO_ROOT } from "../lib/launcher-live.js";
import { INSTALLED_MARKER, MissingStackPackagesError } from "../lib/stack-preflight.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

// Assembled at run time: this file holds no credential-shaped literal.
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8NbOpen`;

function assertNoValue(where: string, text: string): void {
  for (let i = 0; i + 8 <= STRIPE.length; i++) {
    const piece = STRIPE.slice(i, i + 8);
    if (piece === "sk_live_") continue; // the format's public prefix, shown on purpose
    assert.ok(!text.includes(piece), `${where} holds "${piece}" of the planted value`);
  }
}

let tmp = "";
const dashPids = new Set<number>();
after(async () => {
  for (const pid of dashPids) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
  // Wait for each to exit before the directory goes: a dashboard still
  // running writes under it (its home, its registry), and the removal raced
  // that (ENOTEMPTY, pipeline 12829).
  const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
  for (let i = 0; i < 100 && [...dashPids].some(alive); i++) await new Promise((r) => setTimeout(r, 50));
  for (const pid of dashPids) { if (alive(pid)) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } } }
  if (tmp) rmSync(tmp, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
});

test("mandu scan --open starts the dashboard when none runs, opens its plain Scan URL, and reuses it the next time", { timeout: 300_000 }, async () => {
  const missing = ["launcher", "arbiter", "dashboard"].filter((p) => !existsSync(join(REPO_ROOT, p, INSTALLED_MARKER)));
  if (missing.length > 0) throw new MissingStackPackagesError(missing, "scan-open", REPO_ROOT);
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-scanopen-")));
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
  // The browser: a recorder of each start's arguments, one file per start.
  const rec = join(tmp, "browser-starts");
  mkdirSync(rec);
  const browser = join(tmp, "browser.sh");
  writeFileSync(browser, `#!/bin/sh\nf="${rec}/$$"\nprintf '%s\\n' "$#" "$@" > "$f.tmp" && mv "$f.tmp" "$f.txt"\n`);
  chmodSync(browser, 0o755);
  const starts = (): string[] => readdirSync(rec).filter((n) => n.endsWith(".txt")).map((n) => readFileSync(join(rec, n), "utf8"));
  const waitStarts = async (n: number): Promise<string[]> => {
    for (let i = 0; i < 200 && starts().length < n; i++) await new Promise((r) => setTimeout(r, 25));
    return starts();
  };
  // The person's environment: their home, their runtime dir, no display,
  // nothing of Mandu's pinned (no MANDU_HOME, no arbiter socket).
  const env = { HOME: home, PATH: process.env["PATH"], XDG_RUNTIME_DIR: xdg, TMPDIR: tmp, BROWSER: browser };
  const mandu = (args: string[]) =>
    runChildToExit(LAUNCHER_TSX, [LAUNCHER_MAIN, ...args], { cwd: home, env, timeoutMs: 240_000, label: `mandu ${args.join(" ")}` });
  const lastLine = (s: string): string => s.trimEnd().split("\n").pop() ?? "";
  const entries = (): { pid: number; port: number }[] => {
    const dir = join(xdg, "mandu", "dashboards");
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter((n) => n.endsWith(".json")).map((n) => JSON.parse(readFileSync(join(dir, n), "utf8")) as { pid: number; port: number });
  };
  const seen: [string, string][] = [];

  // ── O1: no dashboard: one started, its Scan page opened ──
  assert.deepEqual(entries(), []);
  const first = await mandu(["scan", "--open"]);
  for (const e of entries()) dashPids.add(e.pid);
  seen.push(["the first scan --open", first.stdout + first.stderr]);
  assert.equal(first.code, 0, first.stderr);
  assert.match(first.stdout, /\n✗ 1 of your secrets leaked to the AI\n/);
  const opened = /^Started the dashboard and opened its Scan page: (http:\/\/127\.0\.0\.1:(\d+)\/scan) \(no account yet; set one: mandu dashboard --set-password\)$/.exec(lastLine(first.stdout));
  assert.ok(opened, first.stdout);
  const url = opened[1]!;
  const reg = entries();
  assert.equal(reg.length, 1, "the dashboard registered itself");
  assert.equal(reg[0]!.port, Number(opened[2]));
  assert.doesNotThrow(() => process.kill(reg[0]!.pid, 0), "it runs on after the scan exited");
  const one = await waitStarts(1);
  assert.deepEqual(one, [`1\n${url}\n`], "the browser got exactly the Scan URL, as its one argument");
  assert.doesNotMatch(one[0]!, /[?#]|ticket|token|password/i, "no sign-in link or credential in argv");
  const gate = await fetch(url, { headers: { Accept: "text/html" } });
  const gateBody = await gate.text();
  seen.push(["GET /scan with no account", gateBody]);
  assert.equal(gate.status, 401, "no account yet: the sign-in gate's page");
  assert.match(gateBody, /No account yet/);

  // ── O2: the account made; again: the same dashboard, opened again ──
  const PASSWORD = "the person's own password";
  writeAccount(accountPath({ HOME: home }), await makeAccount("me", PASSWORD));
  const modes = (): unknown[] => {
    const dir = join(xdg, "mandu", "dashboards");
    return readdirSync(dir).filter((n) => n.endsWith(".json")).map((n) => (JSON.parse(readFileSync(join(dir, n), "utf8")) as { signInMode?: string }).signInMode);
  };
  for (let i = 0; i < 150 && !modes().every((m) => m === "account"); i++) await new Promise((r) => setTimeout(r, 200));
  assert.deepEqual(modes(), ["account"], "the running dashboard's entry says the new way in");
  const page = await fetch(url, { headers: { Authorization: `Basic ${Buffer.from(`me:${PASSWORD}`).toString("base64")}` } });
  const body = await page.text();
  seen.push(["GET /scan", body]);
  assert.equal(page.status, 200);
  assert.match(body, /<meta name="mandu-app" content="home">/);
  const second = await mandu(["scan", "--open"]);
  seen.push(["the second scan --open", second.stdout + second.stderr]);
  assert.equal(second.code, 0, second.stderr);
  assert.equal(lastLine(second.stdout), `Opened the dashboard's Scan page: ${url} (sign in with your Mandu dashboard account)`);
  assert.equal(entries().length, 1, "no second dashboard");
  const two = await waitStarts(2);
  assert.deepEqual(two, [`1\n${url}\n`, `1\n${url}\n`]);

  // ── O3: not with the outputs for a program or for pasting ──
  for (const flag of ["--json", "--share"]) {
    const r = await mandu(["scan", "--open", flag]);
    seen.push([`scan --open ${flag}`, r.stdout + r.stderr]);
    assert.equal(r.code, 2, r.stderr);
    assert.match(r.stderr, new RegExp(`--open opens the dashboard for you to read: it does not go with ${flag}`));
    assert.equal(r.stdout, "");
  }
  assert.equal(starts().length, 2, "nothing opened by a refused line");

  // ── O4: the oracle ──
  for (const [i, s] of starts().entries()) seen.push([`browser start ${i + 1}`, s]);
  for (const [where, text] of seen) {
    assertNoValue(where, text);
    assert.ok(!text.includes(PASSWORD), `${where} holds the account's password`);
  }
});
