/**
 * settings-service-focus — the product page's Settings › Protection service
 * line keeps the keyboard focus through its Start, its Restart and that
 * question, its answers and the poll, across the REAL server, supervisor and
 * served home.js (dashboard.md §4.25 *The service row keeps the focus*).
 * Mandu-new.
 *
 * Until 2026-10-13 every press there turned its button off and drew the line
 * again with the focus on <body> (a browser drops the focus of a button
 * turned off), Restart's question opened with no focus in it, and the poll
 * that follows the service dropped a focused Restart.
 *
 *   a real Supervisor over stand-in services, a real DashboardServer with an
 *   admin token, and the served Settings page (its own index.html and
 *   home.js in jsdom, its fetch bridged to the real server; its buttons drop
 *   their focus when turned off, as Chromium's do):
 *
 *   K1  signed out, Start with the focus: the real route refuses (403);
 *       Start, on again, has the focus, described by "Sign in first: …";
 *       nothing started;
 *   K2  signed in, Start: the service starts and the line, which says so,
 *       has the focus;
 *   K3  Restart: its question has the focus; Escape closes it with the
 *       focus back on Restart and nothing restarted; Restart now: the
 *       service restarts (a new pid) and the line has the focus;
 *   K4  the service is killed under the open page with the focus on
 *       Restart: the poll draws Start, and the focus is on the card's
 *       heading, never on Start;
 *   K5  the oracle: neither the admin token nor the session secret is on any
 *       page this test read.
 *
 * Axes: `secrets` stated. No arbiter, policy or symbol table is involved: the
 * services are stand-ins, and the guards are the dashboard's admin gate and
 * the supervisor.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
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
const ADMIN_TOKEN = `settings-focus-admin-${process.pid}`;
const SESSION_SECRET = `settings-focus-secret-${process.pid}`;
const SIGN_IN = "Sign in first: in your own terminal, run mandu dashboard and open the sign-in link it prints (each link works once), or sign in with the dashboard's password if it has one.";
const text = (el: any): string => String(el?.textContent ?? "").replace(/\s+/g, " ").trim();
const row = (doc: any): any => doc.getElementById("settings-service-main");
const name = (doc: any): string => text(row(doc)?.querySelector(".service-state"));
const button = (doc: any): any => row(doc)?.querySelector("button") ?? null;
const said = (doc: any): any => doc.querySelector("#settings-service-main .ask-error");
const question = (doc: any): any => doc.getElementById("settings-service-confirm");
const restartNow = (doc: any): any => doc.querySelector("#settings-service-confirm button.primary");

/** A node one-liner listening on `sock`, answering every request line with
 *  an error so the supervisor's probes settle. */
const LISTEN = "try { require('fs').unlinkSync(process.argv[1]); } catch {} require('net').createServer((s) => s.on('data', () => s.write(JSON.stringify({ ok: false, error: 'fake' }) + '\\n'))).listen(process.argv[1]); setInterval(() => {}, 1e9);";
function fake(label: string, sock: string): ServiceDefinition {
  return { label, command: process.execPath, args: ["-e", LISTEN, sock], cwd: dirname(sock), env: {}, ready: { kind: "socket", path: sock }, endpoint: sock, requires: [] };
}

/** Chromium drops the focus of a button turned off to <body>; jsdom keeps
 *  it, so the served page's buttons are made to (blur first: jsdom's blur()
 *  ignores a button already off). */
function dropOnDisable(doc: any): void {
  const proto = doc.defaultView.HTMLButtonElement.prototype;
  const desc = Object.getOwnPropertyDescriptor(proto, "disabled")!;
  Object.defineProperty(proto, "disabled", {
    configurable: true,
    get() { return desc.get!.call(this); },
    set(v: boolean) { if (v && this.ownerDocument.activeElement === this) this.blur(); desc.set!.call(this, v); },
  });
}
/** Enter on `b`: it has the focus, then the click. */
function press(b: any): void {
  b.focus();
  assert.equal(b.ownerDocument.activeElement, b);
  b.click();
}

/** The page's poll as a return to the tab runs it (the served page's
 *  setInterval is stubbed), waited until its read of the service row was
 *  answered and drawn. */
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

test("Settings › Protection's service line keeps the keyboard focus over the real admin gate and supervisor: a refused Start, a Start, Restart's question, Restart now and a crash the poll draws (secrets axes)", { timeout: 120_000 }, async () => {
  const dir = tmpDir("mdu-settings-focus-");
  const run = join(dir, "run");
  mkdirSync(join(run, "test"), { recursive: true });
  mkdirSync(join(dir, "events"), { recursive: true });
  const sock = join(run, "arbiter.sock");
  const definitions: Record<string, ServiceDefinition> = {
    arbiter: fake("Arbiter", sock),
    "anthropic-proxy": fake("Anthropic proxy (Claude)", join(run, "a.sock")),
    "openai-proxy": fake("OpenAI proxy (Codex)", join(run, "o.sock")),
    "net-proxy": fake("Net proxy (network egress)", join(run, "n.sock")),
    "test-arbiter": fake("Test arbiter (test tenant)", join(run, "test", "arbiter.sock")),
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
    // ── K1: signed out, a refused Start keeps its focus ──
    assert.equal(main().state, "stopped");
    await servedProductPage(base, "/settings", (doc) => name(doc) === "Stopped", async (doc) => {
      dropOnDisable(doc);
      press(button(doc));
      await waitWhile(() => said(doc) === null, 20_000);
      assert.equal(text(said(doc)), SIGN_IN, "the real gate's refusal, in the page's words");
      const start = button(doc);
      assert.equal(text(start), "Start");
      assert.equal(doc.activeElement, start, "Start, on again, has the focus (it fell to <body> before)");
      assert.equal(start.getAttribute("aria-describedby"), said(doc).id, "described by the refusal's words");
      read.push(doc.documentElement.outerHTML);
    });
    assert.equal(main().state, "stopped", "signed out, nothing started");

    await servedProductPage(base, "/settings", (doc) => name(doc) === "Stopped", async (doc) => {
      dropOnDisable(doc);
      const poll = pollOn(doc);

      // ── K2: signed in, Start ──
      press(button(doc));
      await waitWhile(() => doc.activeElement !== row(doc), 30_000);
      assert.equal(doc.activeElement, row(doc), "the line has the focus");
      if (name(doc) !== "Running") await poll(); // a start still under way reads Starting
      assert.equal(main().state, "running", "signed in, Start starts it");
      assert.equal(name(doc), "Running");
      assert.equal(doc.activeElement, row(doc), "the line keeps the focus, and says the service runs");
      assert.match(text(doc.activeElement), /^Running\. Started .*\. Restart$/);
      read.push(doc.documentElement.outerHTML);
      const pid = main().pid;
      assert.ok(pid);

      // ── K3: Restart, its question, Escape, Restart now ──
      press(button(doc));
      assert.ok(question(doc), "Restart asks first");
      assert.equal(doc.activeElement, question(doc).querySelector("p"), "the question's words have the focus");
      doc.activeElement.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
      assert.equal(question(doc), null, "Escape is Cancel");
      assert.equal(doc.activeElement, button(doc), "Restart has the focus back");
      assert.equal(main().pid, pid, "nothing restarted");

      press(button(doc));
      press(restartNow(doc));
      await waitWhile(() => question(doc) !== null || doc.activeElement !== row(doc), 30_000);
      assert.equal(question(doc), null, "the question is gone");
      assert.equal(doc.activeElement, row(doc), "the line has the focus");
      assert.equal(said(doc), null, "no refusal");
      assert.equal(main().state, "running");
      assert.notEqual(main().pid, pid, "the service restarted");
      read.push(doc.documentElement.outerHTML);

      // ── K4: killed under the open page, the focus on Restart ──
      button(doc).focus();
      process.kill(main().pid!, "SIGKILL");
      await waitWhile(() => main().state !== "crashed", 20_000);
      await poll();
      assert.equal(name(doc), "Stopped unexpectedly");
      assert.equal(text(button(doc)), "Start");
      assert.equal(doc.activeElement, doc.getElementById("settings-protection-title"), "the card's heading, never Start");
      read.push(doc.documentElement.outerHTML);
    }, { headers: { Cookie: server.adminCookie() } });
  } finally {
    await server.close();
    await supervisor.shutdownAll();
  }

  // ── K5: the oracle ──
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
