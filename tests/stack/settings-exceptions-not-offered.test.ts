/**
 * settings-exceptions-not-offered.test — Settings › Prompt filters ›
 * Exceptions says why no exception can be added, instead of how to write
 * one, across the REAL components (dashboard.md §4.25y *An exception that
 * cannot be added says why*). Mandu-new.
 *
 * A default install turns on only the registered-value check
 * (arbiter/prompt-filter/policy.ts DEFAULT_ON), so the one kind it lists is
 * a secret Mandu already knows, which the add form never names. Until
 * 2026-10-16 the page drew no form there but kept "Use a * for any text, as
 * in *@example.com" over the list: a pattern taught for a form that was not
 * there.
 *
 * Each case is a real ArbiterServer (secrets) with a registered key and a
 * real DashboardServer over the production adapter (`makeApprovalsArbiter`),
 * signed in; the served Settings page (its own index.html and home.js in
 * jsdom):
 *
 *   E1  defaults: no form, no pattern taught, and the reason "Exceptions are
 *       not offered for a secret Mandu already knows: …"; under it the empty
 *       list says only "No exceptions." (the reason already says what
 *       happens; 2026-10-16, nightly run 1130);
 *   E2  `key-shapes: on` in policy.yaml: the form names the key-shape kind,
 *       the note says how to write one and gives no reason, and the empty
 *       list says what happens; the arbiter asks before such an exception
 *       (it is not applied here);
 *   E3  the same with the administrator's lock on that kind: no form, and
 *       the reason names the lock, over "No exceptions."; the arbiter
 *       refuses such an exception, naming the administrator's file, so the
 *       page says what it enforces;
 *   E4  the oracle: no answer or rendered page carries the registered key or
 *       a token, and policy.yaml is as written.
 *
 * Axes: secrets (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const KEY = "sk_" + "live_settingsExceptionsNotOfferedCanary01";
const LOCK_FILE = "10-org.yaml";
const ABOUT = "What matches an exception goes to the AI as you wrote it.";
const REGISTERED = "Exceptions are not offered for a secret Mandu already knows: the choice above decides what happens to it.";
const REGISTERED_LOCKED = "Exceptions are not offered for a secret Mandu already knows, and your administrator locked the other kinds.";
const HOW = "Use a * for any text, as in *@example.com.";
/** The empty list with no reason over it, and under one. */
const FULL_EMPTY = "No exceptions. Everything Mandu finds gets the choice above.";
const SHORT_EMPTY = "No exceptions.";

/** What a reader sees of an element: its text without the hidden parts. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const shownText = (node: any): string => {
  const copy = node.cloneNode(true);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const h of [...copy.querySelectorAll("[hidden]")] as any[]) h.remove();
  return copy.textContent.replace(/\s+/g, " ").trim();
};

interface Seen { bodies: string[]; pages: string[] }

/** One real arbiter + dashboard over `policy` (and the administrator's
 *  `admin` file when given), signed in; `fn` gets the base URL and a JSON
 *  caller. Every answer and page lands in `seen` for the oracle; policy.yaml
 *  must be as written when it ends. */
async function withStack(
  policy: string,
  admin: string | null,
  seen: Seen,
  fn: (base: string, call: (method: "GET" | "POST", path: string, body?: unknown) => Promise<{ status: number; body: Record<string, any> }>) => Promise<void>, // eslint-disable-line @typescript-eslint/no-explicit-any
): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-exceptions-not-offered-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, policy);
  let adminDir: string | null = null;
  if (admin !== null) {
    adminDir = join(tmp, "policy.d");
    mkdirSync(adminDir);
    writeFileSync(join(adminDir, LOCK_FILE), admin);
  }
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: adminDir, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(`${base}/api/${path}`, { method, headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    seen.bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  try {
    // A registered key, for the oracle: nothing below may carry it.
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    await fn(base, call);
    assert.equal(readFileSync(policyPath, "utf8"), policy, "policy.yaml is as written: nothing was applied");
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** The served Settings page, signed in, once the kinds are drawn. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const settingsPage = (base: string, seen: Seen, fn: (doc: any) => void) =>
  servedProductPage(base, "/settings", (doc) => doc.querySelector("#settings-prompt-kinds .prompt-kind") != null, (doc) => {
    fn(doc);
    seen.pages.push(doc.body.textContent ?? "");
  }, { headers: { Cookie: ADMIN_COOKIE } });

test("Settings › Prompt filters › Exceptions over the real arbiter: no form says why, never how to write a pattern; the form says how; the reason matches what the arbiter refuses; no value on the page", { timeout: 120_000 }, async () => {
  const seen: Seen = { bodies: [], pages: [] };

  // E1: a default install.
  await withStack("version: 1\n", null, seen, async (base, call) => {
    const read = await call("GET", "policy/prompt-filters");
    assert.equal(read.status, 200, JSON.stringify(read.body));
    const vm = read.body.settings;
    assert.deepEqual(vm.kinds.map((k: { category: string }) => k.category), ["secret.registered"], "a default install finds only the secrets it knows");
    assert.deepEqual(vm.exceptionKinds, []);
    assert.equal(vm.exceptionNotOffered, REGISTERED);
    await settingsPage(base, seen, (doc) => {
      assert.equal(doc.getElementById("prompt-exception-form").hidden, true, "no form");
      assert.equal(doc.getElementById("settings-prompt-exceptions-head").hidden, false);
      assert.equal(shownText(doc.getElementById("settings-prompt-exceptions-about")), `${ABOUT} ${REGISTERED}`);
      assert.doesNotMatch(shownText(doc.getElementById("settings-prompt-block")), /for any text|\*@example\.com/, "no pattern taught for a form that is not there");
      assert.equal(shownText(doc.getElementById("settings-prompt-exceptions")), SHORT_EMPTY, "the reason is not said again");
    });
  });

  // E2: the key-shape check on: a kind an exception may name.
  await withStack("version: 1\nprompt_filters:\n  filters:\n    key-shapes: on\n", null, seen, async (base, call) => {
    const vm = (await call("GET", "policy/prompt-filters")).body.settings;
    assert.deepEqual(vm.exceptionKinds.map((k: { category: string }) => k.category), ["secret.shape"]);
    assert.equal(vm.exceptionNotOffered, null);
    await settingsPage(base, seen, (doc) => {
      assert.equal(doc.getElementById("prompt-exception-form").hidden, false, "the form");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      assert.deepEqual([...doc.querySelectorAll("#prompt-exception-kind option")].map((o: any) => o.value), ["secret.shape"]);
      assert.equal(shownText(doc.getElementById("settings-prompt-exceptions-about")), `${ABOUT} ${HOW}`);
      assert.equal(doc.getElementById("settings-prompt-exceptions-why").hidden, true);
      assert.equal(shownText(doc.getElementById("settings-prompt-exceptions")), FULL_EMPTY, "no reason: the empty list says what happens");
    });
    // What the form would send is taken: asked first, as every let-through.
    const asked = await call("POST", "policy/prompt-filters/change", { edit: { op: "add-prompt-exception", category: "secret.shape", match: "AKIAEXAMPLE*" } });
    assert.equal(asked.status, 200, JSON.stringify(asked.body));
    assert.equal(asked.body["confirm"], true, "asked before it applies");
  });

  // E3: the same kind locked by the administrator.
  await withStack("version: 1\nprompt_filters:\n  filters:\n    key-shapes: on\n", "prompt_filters:\n  actions:\n    secret.shape: { action: redact, locked: true }\n", seen, async (base, call) => {
    const vm = (await call("GET", "policy/prompt-filters")).body.settings;
    assert.ok(vm.kinds.some((k: { category: string; locked: boolean }) => k.category === "secret.shape" && k.locked), "the lock is read");
    assert.deepEqual(vm.exceptionKinds, []);
    assert.equal(vm.exceptionNotOffered, REGISTERED_LOCKED);
    await settingsPage(base, seen, (doc) => {
      assert.equal(doc.getElementById("prompt-exception-form").hidden, true, "no form");
      assert.equal(shownText(doc.getElementById("settings-prompt-exceptions-about")), `${ABOUT} ${REGISTERED_LOCKED}`);
      assert.equal(shownText(doc.getElementById("settings-prompt-exceptions")), SHORT_EMPTY);
    });
    // The arbiter refuses what the page does not offer, naming the file.
    const refused = await call("POST", "policy/prompt-filters/change", { edit: { op: "add-prompt-exception", category: "secret.shape", match: "AKIAEXAMPLE*" } });
    assert.notEqual(refused.body["applied"], true, JSON.stringify(refused.body));
    assert.notEqual(refused.body["confirm"], true, "refused, not asked");
    assert.match(JSON.stringify(refused.body), new RegExp(`set by your administrator \\([^)]*${LOCK_FILE.replace(".", "\\.")}\\)`));
  });

  // E4: the oracle.
  assert.equal(seen.pages.length, 3, "every page was read");
  for (const b of [...seen.bodies, ...seen.pages]) assert.ok(!b.includes(KEY), "no answer or page carries the registered key");
  for (const p of seen.pages) assert.doesNotMatch(p, /\$MDU/, "no page carries a token");
});
