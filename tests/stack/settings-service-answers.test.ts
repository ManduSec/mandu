/**
 * settings-service-answers — the product page's Settings › Protection
 * service row answers its button, across the REAL server, supervisor and
 * served home.js (dashboard.md §4.25 Settings and *Refusals*). Mandu-new.
 *
 * Until 2026-10-10 the row's Start or Restart threw the answer away and drew
 * the row again: signed out (every control POST needs the admin session,
 * while the row itself is an open read) a Start changed nothing on the page,
 * and a Restart's question vanished as if it had restarted. A service this
 * dashboard adopted (already running when it started) offered a Restart the
 * supervisor refuses every time, just as silently.
 *
 *   a real Supervisor over stand-in services, a real DashboardServer with an
 *   admin token, and the served Settings page (its own index.html and
 *   home.js in jsdom, its fetch bridged to the real server):
 *
 *   S1  signed out, the real start route refuses (403, the server's `admin
 *       session required`); on the page Start says "Sign in first: …" on
 *       its row, the command as code, and nothing starts;
 *   S2  signed in (the session cookie), the same Start starts the service,
 *       the row reads Running with Restart, and says no line;
 *   S3  signed out, Restart and then Restart now: the question goes, the row
 *       says "Sign in first: …", and the service keeps its pid;
 *   S4  adopted: a service already listening when the supervisor starts is
 *       adopted; the real restart route refuses it even signed in (503), and
 *       the page says why with no button and no start time;
 *   S5  the oracle: neither the admin token nor the session secret is on any
 *       page or answer this test read.
 *
 * Axes: `secrets` stated. No arbiter, policy or symbol table is involved: the
 * services are stand-ins, and the guards are the dashboard's admin gate and
 * the supervisor's refusal to stop what it did not start.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { connect } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Supervisor } from "../../dashboard/src/supervisor/supervisor.js";
import type { ServiceDefinition } from "../../dashboard/src/supervisor/supervisor-defs.js";
import { ADMIN_SESSION_REQUIRED, DashboardServer } from "../../dashboard/src/server.js";
import { FileEventSource } from "../../dashboard/src/event-source.js";
import { ADOPTED_SENTENCE } from "../../dashboard/src/view-model/service-summary.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { tmpDir, removeTmp } from "../lib/tmp-dir.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets");

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ADMIN_TOKEN = `settings-service-admin-${process.pid}`;
const SESSION_SECRET = `settings-service-secret-${process.pid}`;
const SIGN_IN = "Sign in first: in your own terminal, run mandu dashboard and open the sign-in link it prints (each link works once), or sign in with the dashboard's password if it has one.";
const text = (el: any): string => String(el?.textContent ?? "").replace(/\s+/g, " ").trim();
const row = (doc: any): any => doc.getElementById("settings-service-main");
const line = (doc: any): any => doc.querySelector("#settings-service-main .ask-error");

/** A node one-liner listening on `sock`, answering every request line with
 *  an error so the supervisor's probes settle. */
const LISTEN = "try { require('fs').unlinkSync(process.argv[1]); } catch {} require('net').createServer((s) => s.on('data', () => s.write(JSON.stringify({ ok: false, error: 'fake' }) + '\\n'))).listen(process.argv[1]); setInterval(() => {}, 1e9);";
function fake(label: string, sock: string): ServiceDefinition {
  return { label, command: process.execPath, args: ["-e", LISTEN, sock], cwd: dirname(sock), env: {}, ready: { kind: "socket", path: sock }, endpoint: sock, requires: [] };
}

/** Every service a stand-in, the main one at `run/arbiter.sock`. */
function stack(run: string): Record<string, ServiceDefinition> {
  mkdirSync(join(run, "test"), { recursive: true });
  return {
    arbiter: fake("Arbiter", join(run, "arbiter.sock")),
    "anthropic-proxy": fake("Anthropic proxy (Claude)", join(run, "a.sock")),
    "openai-proxy": fake("OpenAI proxy (Codex)", join(run, "o.sock")),
    "net-proxy": fake("Net proxy (network egress)", join(run, "n.sock")),
    "test-arbiter": fake("Test arbiter (test tenant)", join(run, "test", "arbiter.sock")),
  };
}

test("Settings › Protection service over the real admin gate and supervisor: signed out, Start and Restart say how to sign in and move nothing; signed in, Start starts; an adopted service offers no Restart and says why (secrets axes)", { timeout: 120_000 }, async () => {
  const dir = tmpDir("mdu-settings-service-");
  const run = join(dir, "run");
  mkdirSync(join(dir, "events"), { recursive: true });
  const sock = join(run, "arbiter.sock");
  const supervisor = new Supervisor({ repoRoot: REPO, arbiterSock: sock, autoStartArbiter: false, startTimeoutMs: 60_000, log: () => {}, definitions: stack(run) });
  const server = new DashboardServer({
    source: new FileEventSource(join(dir, "events")), supervisor,
    adminToken: ADMIN_TOKEN, sessionSecret: SESSION_SECRET, log: () => {},
  });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const signedIn = { headers: { Cookie: server.adminCookie() } };
  const main = () => supervisor.status().find((s) => s.id === "arbiter")!;
  const read: string[] = [];
  try {
    // ── S1: signed out, Start ──
    const refused = await pageFetch(base + "/api/control/arbiter/start", { method: "POST", headers: { "X-Mandu-Control": "1", "X-Mandu-Front": "product" } });
    const refusedBody = await refused.text();
    read.push(refusedBody);
    assert.equal(refused.status, 403, refusedBody);
    assert.equal(JSON.parse(refusedBody).error, ADMIN_SESSION_REQUIRED, "the gate's own words, which the page rewrites");
    assert.equal(main().state, "stopped");
    await servedProductPage(base, "/settings", (doc) => text(row(doc)?.querySelector(".service-state")) === "Stopped", async (doc) => {
      assert.equal(line(doc), null, "no line before a click");
      row(doc).querySelector("button").click();
      await waitWhile(() => line(doc) === null, 20_000);
      assert.equal(text(line(doc)), SIGN_IN, "the click is answered on the row");
      assert.equal(line(doc).querySelector("code")?.textContent, "mandu dashboard", "the command reads as code");
      assert.doesNotMatch(text(doc.getElementById("settings-services")), /admin session|DASHBOARD_PASSWORD|arbiter/i, "never the server's developer text");
      assert.equal(text(row(doc).querySelector(".service-state")), "Stopped", "the row still reads stopped");
      read.push(doc.documentElement.outerHTML);
    });
    assert.equal(main().state, "stopped", "signed out, nothing started");

    // ── S2: signed in, the same Start starts it ──
    await servedProductPage(base, "/settings", (doc) => text(row(doc)?.querySelector(".service-state")) === "Stopped", async (doc) => {
      row(doc).querySelector("button").click();
      await waitWhile(() => text(row(doc)?.querySelector(".service-state")) !== "Running", 30_000);
      assert.equal(text(row(doc).querySelector(".service-state")), "Running", "signed in, Start starts it");
      assert.equal(text(row(doc).querySelector("button")), "Restart");
      assert.equal(line(doc), null, "no line");
      read.push(doc.documentElement.outerHTML);
    }, signedIn);
    assert.equal(main().state, "running");
    assert.equal(main().adopted, false, "spawned here, so this dashboard may restart it");
    const pid = main().pid;
    assert.ok(pid, "the stand-in runs");

    // ── S3: signed out, Restart now ──
    await servedProductPage(base, "/settings", (doc) => text(row(doc)?.querySelector(".service-state")) === "Running", async (doc) => {
      row(doc).querySelector("button").click();
      await waitWhile(() => doc.getElementById("settings-service-confirm") === null, 5_000);
      doc.querySelector("#settings-service-confirm button.primary").click();
      await waitWhile(() => line(doc) === null, 20_000);
      assert.equal(doc.getElementById("settings-service-confirm"), null, "the question is gone");
      assert.equal(text(line(doc)), SIGN_IN, "the row says why nothing restarted");
      assert.equal(text(row(doc).querySelector("button")), "Restart");
      read.push(doc.documentElement.outerHTML);
    });
    assert.equal(main().pid, pid, "signed out, nothing restarted");
  } finally {
    await server.close();
    await supervisor.shutdownAll();
  }

  // ── S4: adopted ──
  const run2 = join(dir, "run2");
  const defs = stack(run2);
  const sock2 = join(run2, "arbiter.sock");
  const outside = spawn(process.execPath, ["-e", LISTEN, sock2], { stdio: "ignore" });
  const adoptive = new Supervisor({ repoRoot: REPO, arbiterSock: sock2, autoStartArbiter: false, startTimeoutMs: 60_000, log: () => {}, definitions: defs });
  const server2 = new DashboardServer({
    source: new FileEventSource(join(dir, "events")), supervisor: adoptive,
    adminToken: ADMIN_TOKEN, sessionSecret: SESSION_SECRET, log: () => {},
  });
  const base2 = `http://127.0.0.1:${await server2.listen(0)}`;
  try {
    // The outside listener answers first; then the supervisor finds it.
    const listening = (): Promise<boolean> => new Promise((r) => {
      const c = connect(sock2, () => { c.destroy(); r(true); });
      c.on("error", () => r(false));
    });
    const deadline = Date.now() + 20_000;
    while (!(await listening()) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    await adoptive.start("arbiter");
    const adopted = adoptive.status().find((s) => s.id === "arbiter")!;
    assert.equal(adopted.adopted, true, "already listening, so adopted");
    const restart = await pageFetch(base2 + "/api/control/arbiter/restart", { method: "POST", headers: { "X-Mandu-Control": "1", Cookie: server2.adminCookie() } });
    const restartBody = await restart.text();
    read.push(restartBody);
    assert.equal(restart.status, 503, "even signed in, the supervisor will not stop what it did not start");
    await servedProductPage(base2, "/settings", (doc) => text(row(doc)?.querySelector(".service-state")) === "Running", (doc) => {
      assert.equal(text(row(doc)), `Running. ${ADOPTED_SENTENCE}`, "says why, with no start time");
      assert.equal(row(doc).querySelector("button"), null, "no Restart that would always be refused");
      read.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: server2.adminCookie() } });
  } finally {
    await server2.close();
    await adoptive.shutdownAll();
    outside.kill("SIGKILL");
  }

  // ── S5: the oracle ──
  try {
    assert.equal(read.length, 6, "every page and answer was read");
    for (const body of read) {
      assert.equal(body.includes(ADMIN_TOKEN), false, "the admin token is never served");
      assert.equal(body.includes(SESSION_SECRET), false, "the session secret is never served");
    }
  } finally {
    removeTmp(dir);
  }
});
