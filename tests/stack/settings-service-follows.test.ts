/**
 * settings-service-follows — the product page's Settings › Protection
 * service row follows the service while the page is open, across the REAL
 * supervisor, server and served home.js (dashboard.md §4.25 *The service row
 * follows the service*). Mandu-new.
 *
 * Until 2026-10-10 the row was read once, when Settings opened. The
 * supervisor's state changes on its own (a crash; a start by the inspector,
 * another tab or the dashboard's own boot), so after a crash the row still said
 * "Running … Started …" with Restart while the same page's top bar said "Not
 * connected", and a row drawn while starting said "Starting" (with a Start
 * that only waited for that start) until you left Settings.
 *
 *   a real Supervisor over stand-in services (the main one listens only once
 *   a gate file exists, so its start can be held), a real DashboardServer
 *   with an admin token, and the served Settings page (its own index.html
 *   and home.js in jsdom, its fetch bridged to the real server) held open,
 *   signed out; its poll is run as a return to the tab runs it:
 *
 *   F1  the running service is killed: the next poll reads "Stopped
 *       unexpectedly" with Start and a red dot, no click;
 *   F2  signed out, Start says "Sign in first: …" on the row; a poll that
 *       finds the same service draws nothing, so the answer and the row stay;
 *   F3  started elsewhere (the supervisor's own start, as the inspector's
 *       Start or the dashboard's boot calls it), held at its gate: the poll
 *       reads "Starting" with no button and the old answer gone; released,
 *       the poll reads "Running" with Restart;
 *   F4  the oracle: neither the admin token nor the session secret is on any
 *       page this test read.
 *
 * Axes: `secrets` stated. No arbiter, policy or symbol table is involved: the
 * services are stand-ins; what is proved is the page's honesty about the
 * service that enforces them.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Supervisor } from "../../dashboard/src/supervisor/supervisor.js";
import type { ServiceDefinition } from "../../dashboard/src/supervisor/supervisor-defs.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { FileEventSource } from "../../dashboard/src/event-source.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { tmpDir, removeTmp } from "../lib/tmp-dir.js";

stateAxes("secrets");

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ADMIN_TOKEN = `settings-follows-admin-${process.pid}`;
const SESSION_SECRET = `settings-follows-secret-${process.pid}`;
const SIGN_IN = "Sign in first: reload this page and sign in with your dashboard account (if there isn't one yet, run mandu dashboard --set-password in your own terminal).";
const text = (el: any): string => String(el?.textContent ?? "").replace(/\s+/g, " ").trim();
const row = (doc: any): any => doc.getElementById("settings-service-main");
const name = (doc: any): string => text(row(doc)?.querySelector(".service-state"));
const button = (doc: any): string | null => row(doc)?.querySelector("button")?.textContent ?? null;
const line = (doc: any): any => doc.querySelector("#settings-service-main .ask-error");

/** A node one-liner that listens on `sock` once `gate` exists, answering
 *  every request line with an error so the supervisor's probes settle. */
const GATED = "const fs = require('fs'); const [sock, gate] = process.argv.slice(1); const go = () => { if (!fs.existsSync(gate)) return setTimeout(go, 20); try { fs.unlinkSync(sock); } catch {} require('net').createServer((s) => s.on('data', () => s.write(JSON.stringify({ ok: false, error: 'fake' }) + '\\n'))).listen(sock); }; go(); setInterval(() => {}, 1e9);";
function fake(label: string, sock: string, gate: string): ServiceDefinition {
  return { label, command: process.execPath, args: ["-e", GATED, sock, gate], cwd: dirname(sock), env: {}, ready: { kind: "socket", path: sock }, endpoint: sock, requires: [] };
}

/** The page's poll as a return to the tab runs it (the served page's
 *  setInterval is stubbed), waited until its read of the service row was
 *  answered and drawn: the read is counted when its body is parsed, and the
 *  draw follows within the same turn, before the next timer. */
function pollOn(doc: any): () => Promise<void> {
  const w = doc.defaultView;
  const reads = { done: 0 };
  const inner = w.fetch;
  w.fetch = (url: string, init?: unknown) => {
    const p = inner(url, init);
    if (!String(url).endsWith("/api/control/summary")) return p;
    return p.then((res: any) => ({ ...res, json: () => res.json().then((v: unknown) => { reads.done++; return v; }) }));
  };
  return async () => {
    const before = reads.done;
    doc.dispatchEvent(new w.Event("visibilitychange"));
    await waitWhile(() => reads.done === before, 20_000);
    assert.ok(reads.done > before, "the poll read the service row");
    await new Promise((r) => setTimeout(r, 50));
  };
}

test("Settings › Protection's service row follows the real supervisor while the page is open: a crash, a start held at its gate, a start that finished; an unchanged poll keeps the row's answer (secrets axes)", { timeout: 120_000 }, async () => {
  const dir = tmpDir("mdu-settings-follows-");
  const run = join(dir, "run");
  mkdirSync(join(run, "test"), { recursive: true });
  mkdirSync(join(dir, "events"), { recursive: true });
  const gate = join(run, "gate");
  const sock = join(run, "arbiter.sock");
  const definitions: Record<string, ServiceDefinition> = {
    arbiter: fake("Arbiter", sock, gate),
    "anthropic-proxy": fake("Anthropic proxy (Claude)", join(run, "a.sock"), gate),
    "openai-proxy": fake("OpenAI proxy (Codex)", join(run, "o.sock"), gate),
    "net-proxy": fake("Net proxy (network egress)", join(run, "n.sock"), gate),
    "test-arbiter": fake("Test arbiter (test tenant)", join(run, "test", "arbiter.sock"), gate),
  };
  const supervisor = new Supervisor({ repoRoot: REPO, arbiterSock: sock, autoStartArbiter: false, startTimeoutMs: 60_000, log: () => {}, definitions });
  const server = new DashboardServer({
    source: new FileEventSource(join(dir, "events")), supervisor,
    adminToken: ADMIN_TOKEN, sessionSecret: SESSION_SECRET, log: () => {},
  });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const main = () => supervisor.status().find((s) => s.id === "arbiter")!;
  const read: string[] = [];
  try {
    writeFileSync(gate, "");
    await supervisor.start("arbiter");
    assert.equal(main().state, "running");
    assert.equal(main().adopted, false, "spawned by this supervisor");

    await servedProductPage(base, "/settings", (doc) => name(doc) === "Running", async (doc) => {
      const poll = pollOn(doc);
      assert.equal(button(doc), "Restart");
      read.push(doc.documentElement.outerHTML);

      // ── F1: the service is killed under the open page ──
      process.kill(main().pid!, "SIGKILL");
      await waitWhile(() => main().state !== "crashed", 20_000);
      assert.equal(main().state, "crashed", "the supervisor saw it go");
      await poll();
      assert.equal(name(doc), "Stopped unexpectedly", "the row follows a crash with no click (it used to keep saying Running)");
      assert.equal(button(doc), "Start");
      assert.ok(doc.querySelector("#settings-protect-row .name .dot.bad"), "red dot, the Protection row's one dot");
      assert.doesNotMatch(text(row(doc)), /Started/, "no start time for a service that is not running");
      read.push(doc.documentElement.outerHTML);

      // ── F2: signed out, Start answers on the row; an unchanged poll keeps it ──
      row(doc).querySelector("button").click();
      await waitWhile(() => line(doc) === null, 20_000);
      assert.equal(text(line(doc)), SIGN_IN);
      const drawn = row(doc);
      await poll();
      await poll();
      assert.equal(row(doc), drawn, "the same row: a poll that finds the same service draws nothing");
      assert.equal(text(line(doc)), SIGN_IN, "so the answer stays");
      assert.equal(main().state, "crashed", "signed out, nothing started");

      // ── F3: started elsewhere, held at its gate, then released ──
      rmSync(gate, { force: true });
      const started = supervisor.start("arbiter");
      await waitWhile(() => main().state !== "starting", 20_000);
      assert.equal(main().state, "starting");
      await poll();
      assert.equal(name(doc), "Starting", "a start made elsewhere shows while it is under way");
      assert.equal(button(doc), null, "no Start on a start under way");
      assert.equal(text(row(doc)), "Starting.");
      assert.equal(line(doc), null, "the answer to the Start of a stopped service went with that row");
      read.push(doc.documentElement.outerHTML);
      writeFileSync(gate, "");
      await started;
      assert.equal(main().state, "running");
      await poll();
      assert.equal(name(doc), "Running", "running once it is up");
      assert.equal(button(doc), "Restart");
      assert.match(text(row(doc)), /^Running\. Started /);
      assert.equal(doc.querySelectorAll("#settings-protection-block .row").length, 1, "one row throughout: the on/off and the service");
      read.push(doc.documentElement.outerHTML);
    });
  } finally {
    await server.close();
    await supervisor.shutdownAll();
  }

  // ── F4: the oracle ──
  try {
    assert.equal(read.length, 4, "every page state was read");
    for (const body of read) {
      assert.equal(body.includes(ADMIN_TOKEN), false, "the admin token is never served");
      assert.equal(body.includes(SESSION_SECRET), false, "the session secret is never served");
    }
  } finally {
    removeTmp(dir);
  }
});
