/**
 * Stack e2e — the human plane's exposure, made visible
 * (arbiter-human-plane.md §10.1.1; P0 (E) decision 3, 2026-10-03) over the
 * PRODUCTION wiring: the launcher's own wall reading (`humanPlaneWalled`),
 * launch record (`beginLaunchRecord` / `endLaunchRecord` over `ndjsonCall`)
 * and human-plane watch (`humanPlaneWatch`, what run.ts starts for a walled
 * launch), the dashboard's real `ArbiterEventSource` (it finds the human
 * socket through `hello`, as in production) feeding `loadPolicyPanel` and the
 * product home (`buildHome`), all against a REAL ArbiterServer.
 *
 *   - a confined launch runs; an unwalled launch (`--mode off`, no guard,
 *     no wrap) starts beside it: the confined launcher's watch prints the
 *     WARNING naming the unwalled launch's pid and session and the fix; the
 *     inspector's Policy panel has `human plane exposed` with the same pid
 *     and session; the product page has the notice; the arbiter's audit
 *     stream has one `exposed` event;
 *   - the masking stays: the confined launch's guard report on the human
 *     socket is a claim (`twin`), as before this change;
 *   - when the unwalled launch ends (`endLaunch`, and in the second test its
 *     launcher dies), all three clear (the watch prints the "believed
 *     again" line, the chip reads walled, the notice goes), the report is
 *     believed again (`raw`), and the recap after the agent names the
 *     period;
 *   - when the unwalled launch's session is on record (the launcher's own
 *     posture event, sent as run.ts sends it, after the launch record: a
 *     claim by then), the notice names its agent as its Home row does, a
 *     link to its page, over the real dashboard server; the served product
 *     page draws the link and opens that agent's page in place (§4.25x);
 *   - the served product page, open with notifications granted while the
 *     plane is walled, raises one notification when the unwalled launch
 *     starts, in fixed words that hold neither its pid nor its session id
 *     (dashboard.md §4.25 *Notifications*), and none on the next poll.
 *
 * Axes: secrets (stated below).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ADMIN_SESSION_ID, ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { humanPlaneWalled } from "../../launcher/src/human-plane.js";
import { beginLaunchRecord, endLaunchRecord, type CacheEpochDeps, type LaunchClaim } from "../../launcher/src/cache-epoch.js";
import { humanPlaneWatch, watchesHumanPlane, WATCH_CALL_TIMEOUT_MS } from "../../launcher/src/human-plane-watch.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { loadPolicyPanel } from "../../dashboard/src/server/api-routes.js";
import { buildHome, HomeFacts } from "../../dashboard/src/server/home-routes.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { emitLauncherEvent, launchPostureEvent } from "../../launcher/src/services/observe.js";
import { stateAxes } from "../lib/axes.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-hp-notice-"));
  const secret = join(dir, "x.txt");
  writeFileSync(secret, "token=HP_NOTICE_STACK_CANARY\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  mkdirSync(dirname(humanSock), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false, packDir: null,
  });
  await server.listen();
  // The confined session's guard, reporting on the human socket.
  const guard = new ArbiterClient(humanSock);
  await guard.connect();
  const deps: CacheEpochDeps = { call: (s, op, a) => ndjsonCall(s, op, a, 5000), log: () => {}, purge: () => {} };
  const source = new ArbiterEventSource({ socketPath: sock });
  const facts = new HomeFacts(source);
  const homeOf = () => buildHome({ source, facts, approvals: undefined, testRuns: [], watchRuns: [], env: { MANDU_HOME: join(dir, "home") } });
  return {
    dir, secret, sock, humanSock, guard, deps, source, homeOf,
    close: async () => { guard.close(); source.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}
type Rig = Awaited<ReturnType<typeof rig>>;

function claim(r: Rig, over: Partial<LaunchClaim> & { guardDeny?: boolean }): LaunchClaim {
  const { guardDeny = false, ...rest } = over;
  return {
    pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false,
    humanPlaneWalled: humanPlaneWalled({ dirs: [dirname(r.humanSock)], guardDeny, launchPrefix: [], platform: "linux" }),
    ...rest,
  };
}

const guardOpen = (r: Rig, n: number) =>
  r.guard.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", sha256: "d".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: `conf-${n}`, session: "confined-sess" });

async function hpEvents(r: Rig): Promise<Array<{ state: string; launches: Array<{ pid: number; session?: string }> }>> {
  const evs = (await r.guard.events(ADMIN_SESSION_ID)) as unknown as Array<{ humanPlane?: { state: string; launches: Array<{ pid: number; session?: string }> } }>;
  return evs.flatMap((e) => (e.humanPlane ? [e.humanPlane] : []));
}

async function startConfined(r: Rig) {
  const conf = claim(r, { posture: "confined", writeProtect: true, guardDeny: true, sessionId: "confined-sess" });
  assert.equal(conf.humanPlaneWalled, true, "the guard's deny entry walls it");
  assert.equal(watchesHumanPlane(conf, r.humanSock), true, "run.ts starts the watch for it");
  const rec = await beginLaunchRecord(r.humanSock, conf, r.deps);
  assert.equal(rec.confined, true);
  const printed: string[] = [];
  const watch = humanPlaneWatch(r.humanSock, { call: (s, op, a) => ndjsonCall(s, op, a, WATCH_CALL_TIMEOUT_MS), print: (l) => printed.push(l), intervalMs: 100 });
  await watch.checkNow();
  assert.deepEqual(printed, [], "walled: nothing to tell");
  watch.start();
  return { rec, watch, printed: printed as string[] };
}

async function until(cond: () => boolean | Promise<boolean>, what: string): Promise<void> {
  for (let i = 0; i < 60; i++) {
    if (await cond()) return;
    await new Promise((ok) => setTimeout(ok, 100));
  }
  assert.fail(`timed out waiting for: ${what}`);
}

test("e2e: an unwalled launch beside a confined one: the confined launcher warns (pid, session, fix), the inspector and the product page show it, the masking stays; its end clears all three", async () => {
  const r = await rig();
  try {
    const conf = await startConfined(r);
    const panel0 = await loadPolicyPanel(r.source, undefined);
    assert.equal(panel0.humanPlane?.state, "walled");
    assert.equal((await guardOpen(r, 0)).verdict, "raw", "walled: the confined guard is believed");

    const off = claim(r, { mode: "off", posture: "off", sessionId: "claude-off-1" });
    assert.equal(off.humanPlaneWalled, false, "--mode off, no guard, no wrap: unwalled");
    const offRec = await beginLaunchRecord(r.humanSock, off, r.deps);
    assert.ok(offRec.token !== null);

    // The confined launcher's warning (the watch's next tick).
    await until(() => conf.printed.length > 0, "the WARNING");
    const warning = conf.printed.join("\n");
    assert.match(warning, /^WARNING: mandu: this session's file guard is not believed/);
    assert.match(warning, new RegExp(`pid ${process.pid} \\(session claude-off-1, mode off\\)`));
    assert.match(warning, /every secret file opens as its placeholder/);
    assert.match(warning, /To fix it: stop that launch, or start it again with its file guard on/);

    // The masking stays: the confined guard's report is a claim.
    assert.equal((await guardOpen(r, 1)).verdict, "twin");

    // The inspector's Policy panel and the product page.
    const panel = await loadPolicyPanel(r.source, undefined);
    assert.equal(panel.humanPlane?.state, "exposed");
    assert.deepEqual(panel.humanPlane?.launches.map((l) => [l.pid, l.session, l.mode]), [[process.pid, "claude-off-1", "off"]]);
    const home = await r.homeOf();
    assert.ok(home.exposure, "the product notice");
    assert.equal(home.exposure!.causes[0]!.words, `process ${process.pid}, session claude-off-1, protection off, no file guard`);
    // The fix, and the same words as parts with the launch flags as code
    // (dashboard.md §4.25x), as the product page draws them.
    assert.match(home.exposure!.fix, /^Stop that agent, or start it again with the file guard on \(without --mode off or --no-net-guard\)\./);
    assert.equal(home.exposure!.fixParts.map((p) => p.text).join(""), home.exposure!.fix);
    assert.deepEqual(home.exposure!.fixParts.filter((p) => p.kind === "code").map((p) => p.text), ["--mode off", "--no-net-guard"]);
    assert.deepEqual((await hpEvents(r)).map((e) => e.state), ["exposed"]);

    // Its end clears all three; the report is believed again.
    const before = conf.printed.length;
    await endLaunchRecord(r.humanSock, offRec, r.deps);
    await until(() => conf.printed.length > before, "the 'believed again' line");
    assert.match(conf.printed.at(-1)!, /^mandu: this session's file guard is believed again: the launch .*session claude-off-1.* ended\.$/);
    assert.equal(conf.printed.filter((l) => l.startsWith("WARNING")).length, 1, "told once, not per tick");
    assert.equal((await loadPolicyPanel(r.source, undefined)).humanPlane?.state, "walled");
    assert.equal((await r.homeOf()).exposure, null);
    assert.deepEqual((await hpEvents(r)).map((e) => e.state), ["exposed", "walled"]);
    assert.equal((await guardOpen(r, 2)).verdict, "raw", "believed again");

    conf.watch.stop();
    const recap = conf.watch.recap();
    assert.match(recap[0]!, /during this session its file guard was not believed .*session claude-off-1/);
    await endLaunchRecord(r.humanSock, conf.rec, r.deps);
  } finally { await r.close(); }
});

test("e2e: the unwalled launch's launcher dies: the arbiter sees it within a second and the confined launcher says it is believed again", async () => {
  const r = await rig();
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  try {
    const conf = await startConfined(r);
    const nog = claim(r, { pid: child.pid!, sessionId: "codex-noguard-2" });
    assert.equal(nog.humanPlaneWalled, false, "gated with no guard and no wrap: unwalled");
    await beginLaunchRecord(r.humanSock, nog, r.deps);
    await until(() => conf.printed.some((l) => l.includes(`pid ${child.pid} (session codex-noguard-2, mode secrets)`)), "the WARNING naming the child");
    assert.equal((await guardOpen(r, 3)).verdict, "twin", "the masking stays");
    const exited = new Promise((ok) => child.once("exit", ok));
    child.kill("SIGKILL");
    await exited;
    await until(async () => (await hpEvents(r)).at(-1)?.state === "walled", "the arbiter's own 'walled' event");
    await until(() => /believed again/.test(conf.printed.at(-1) ?? ""), "the 'believed again' line");
    assert.equal((await loadPolicyPanel(r.source, undefined)).humanPlane?.state, "walled");
    assert.equal((await guardOpen(r, 4)).verdict, "raw");
    conf.watch.stop();
    await endLaunchRecord(r.humanSock, conf.rec, r.deps);
  } finally { child.kill("SIGKILL"); await r.close(); }
});

test("e2e: the unwalled launch's session is on record: the notice names its agent as its Home row does, a link to its page; the served Home opens that page", async () => {
  const r = await rig();
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: r.sock }), configEnv: { MANDU_HOME: join(r.dir, "home") }, log: () => {} });
  try {
    const conf = await startConfined(r);
    const SESSION = "claude-off-3";
    // run.ts's order: the launch record, then the launcher's posture event,
    // which the exposed plane stores as a claim. The session is listed all
    // the same, and named from its events, as Home's row names it.
    const off = claim(r, { mode: "off", posture: "off", sessionId: SESSION });
    const offRec = await beginLaunchRecord(r.humanSock, off, r.deps);
    await until(() => conf.printed.length > 0, "the WARNING");
    const posture = launchPostureEvent({ scopeId: SESSION, target: "claude", argv0: "claude", notes: [], protection: { mode: "off", integrity: false, confidentiality: false, reported: true } });
    assert.equal(await emitLauncherEvent(r.sock, posture, r.humanSock), true);

    // GET /api/home, through the real server and event source.
    const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
    const home = (await (await pageFetch(`${base}/api/home`)).json()) as HomeVM;
    const row = home.agents.find((a) => a.id === SESSION);
    assert.ok(row, `Home lists the session: ${JSON.stringify(home.agents.map((a) => a.id))}`);
    assert.equal(row!.agent, "Claude Code");
    assert.ok(home.exposure, "the notice");
    const cause = home.exposure!.causes[0]!;
    // MASTER: "process <pid>, session claude-off-3, protection off, no file guard", no link
    assert.equal(cause.words, `Claude Code, process ${process.pid}, protection off, no file guard`);
    assert.deepEqual(cause.parts, [
      { kind: "link", text: "Claude Code", to: "agent", session: SESSION },
      { kind: "text", text: `, process ${process.pid}, protection off, no file guard` },
    ]);
    // The route's projection and buildHome's agree.
    assert.deepEqual((await r.homeOf()).exposure!.causes, home.exposure!.causes);

    // The served product page: the agent's name is a link; a click opens its page in place.
    await servedProductPage(base, "/", (doc) => !doc.getElementById("home-exposure").hidden && !!doc.querySelector("#exposure-causes li"), async (doc) => {
      const li = doc.querySelector("#exposure-causes li");
      assert.equal(li.textContent, cause.words);
      assert.equal(li.dataset.pid, String(process.pid));
      const links = [...li.querySelectorAll("a")] as Array<{ textContent: string; getAttribute(n: string): string | null; dataset: Record<string, string>; dispatchEvent(e: unknown): boolean }>;
      assert.equal(links.length, 1);
      assert.equal(links[0]!.textContent, "Claude Code");
      assert.equal(links[0]!.getAttribute("href"), `/agents/${SESSION}`);
      assert.equal(links[0]!.dataset.pageLink, "agent");
      links[0]!.dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true }));
      await until(() => !doc.getElementById("page-agent").hidden && /^Claude Code/.test(doc.getElementById("agent-name").textContent), "its agent page");
      assert.equal(doc.defaultView.location.pathname, `/agents/${SESSION}`);
      assert.equal(doc.getElementById("page-home").hidden, true);
    });

    await endLaunchRecord(r.humanSock, offRec, r.deps);
    conf.watch.stop();
    await endLaunchRecord(r.humanSock, conf.rec, r.deps);
  } finally { await dashboard.close(); await r.close(); }
});

/** The recording Notification stub, as page script (proposal-notifies). */
const NOTE_STUB = `(() => {
  const notes = [];
  function N(title, o) { notes.push({ title, body: (o && o.body) || "", tag: (o && o.tag) || "" }); this.close = () => {}; }
  N.permission = "granted";
  N.requestPermission = () => Promise.resolve("granted");
  Object.defineProperty(window, "Notification", { value: N, configurable: true, writable: true });
  window.__notes = notes;
})();`;

test("e2e: an unwalled launch starts while the served Home is open with notifications on: one notification, naming neither its pid nor its session", async () => {
  const r = await rig();
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: r.sock }), configEnv: { MANDU_HOME: join(r.dir, "home") }, log: () => {} });
  try {
    const conf = await startConfined(r);
    const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
    const SESSION = "claude-off-4";
    const seen = (doc: any): string[] | null => JSON.parse(doc.defaultView.localStorage.getItem("mandu.home.seenExposure") ?? "null");
    // The first poll, walled, primes this browser with nothing exposed.
    await servedProductPage(base, "/", (doc) => seen(doc) !== null, async (doc) => {
      const w = doc.defaultView;
      const notes = w.__notes as Array<{ title: string; body: string; tag: string }>;
      assert.deepEqual(seen(doc), [], "walled: primed with nothing");
      const off = claim(r, { mode: "off", posture: "off", sessionId: SESSION });
      const offRec = await beginLaunchRecord(r.humanSock, off, r.deps);
      await until(() => conf.printed.length > 0, "the WARNING");
      const poll = () => {
        Object.defineProperty(doc, "visibilityState", { value: "visible", configurable: true });
        doc.dispatchEvent(new w.Event("visibilitychange"));
      };
      poll();
      await until(() => notes.length > 0, "the exposure notification");
      // The poll notifies before it loads the suggestions and draws the
      // sections (home.js), so on a loaded machine the card comes a little
      // after the notification (CI pipelines 12729, 12730).
      await until(() => doc.getElementById("home-exposure").hidden === false, "the card is drawn too");
      // Plain copies: the page's objects belong to its own realm.
      const shown = Array.from(notes, (n) => ({ title: n.title, body: n.body, tag: n.tag }));
      assert.equal(shown.length, 1, JSON.stringify(shown));
      assert.equal(shown[0]!.title, "Mandu: another agent can reach Mandu's controls");
      assert.equal(shown[0]!.body, "Your other agents get masked copies of secret files and masked output until it stops. Open Home to see which agent.");
      assert.match(shown[0]!.tag, /^mandu-exposure-\d+$/, "keyed by when the arbiter first saw it");
      for (const words of [shown[0]!.title, shown[0]!.body]) {
        assert.ok(!words.includes(String(process.pid)), `the notification names the launch's pid: ${words}`);
        assert.ok(!words.includes(SESSION), `the notification names the launch's session: ${words}`);
        assert.ok(!words.includes("HP_NOTICE_STACK_CANARY") && !words.includes(r.secret), `CONFIDENTIALITY VIOLATION: ${words}`);
      }
      // The next poll, the same exposure: told once.
      const before = seen(doc);
      poll();
      await new Promise((ok) => setTimeout(ok, 500)); // its answer
      assert.deepEqual(seen(doc), before);
      assert.equal(notes.length, 1, "the same exposure is not told again");
      await endLaunchRecord(r.humanSock, offRec, r.deps);
    }, { beforeScripts: (w) => w.eval(NOTE_STUB) });
    conf.watch.stop();
    await endLaunchRecord(r.humanSock, conf.rec, r.deps);
  } finally { await dashboard.close(); await r.close(); }
});
