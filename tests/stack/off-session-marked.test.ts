/**
 * off-session-marked.test — a session that ran with protection off says so
 * on History, Home and its own page, across the REAL components
 * (dashboard.md §4.25 *A session that ran with protection off says so*,
 * §4.25ae, §4.25b). Mandu-new.
 *
 * Until this change a session that ran while protection was off had the
 * green dot of a protected one under Running now, the grey one under
 * Earlier and History, an empty counts line, and its page said so only in
 * the grey line at the end of Your secrets. Here a real ArbiterServer runs
 * at the `off` axes; the launcher's real `launch_posture` records the
 * protection that arbiter reports (`readArbiterAxes`, `modeOf`, as run.ts
 * builds it); the real anthropic-proxy on its production wiring
 * (`new ArbiterClientAdapter(new ArbiterClient(sock), …)`) carries session
 * OFF's turn, and its launcher records its exit. The arbiter is then
 * started again at the `secrets` axes on the same store; session SEC reads
 * a labelled `.env` through the proxy. A product-only DashboardServer over
 * a real ArbiterEventSource serves each phase:
 *
 *   M1  protection off now: OFF's page (its own index.html and home.js in
 *       jsdom) says at its top that protection was off, with the link to
 *       Settings › Protection;
 *   M2  protection on again: `/api/home/history` gives OFF `protectionOff`
 *       and SEC not, signed in and out; the served History and Home draw
 *       OFF with the amber dot and "protection was off" first, SEC without;
 *   M2c History's switch, *Only sessions where Mandu stepped in*
 *       (`?only=stepped-in`), keeps OFF (`historyFlagged`), though
 *       `steppedIn` of its row is false (Home's last-stepped-in line never
 *       names it), and keeps exactly the rows `historyFlagged` keeps; the
 *       served History with the switch on draws OFF with its amber dot;
 *       and it keeps LESS, a session at `secrets` whose launcher recorded
 *       a protection that did not start (its row's `lessProtection`, the
 *       amber "less protection than usual"; Shoemaker #267), whose
 *       `steppedIn` is false too;
 *   M2b protection on again, before SEC runs (OFF is the window's only
 *       session): `/api/home` counts it (`window.off`, its owner OFF) and
 *       names no `lastSteppedIn`; the served Home says "1 session ran with
 *       protection off", amber, linking OFF's page, not "Nothing to count";
 *       with SEC in the window too, it still leads the counts;
 *   M3  OFF's page keeps its line (the session's record, never today's
 *       setting), now without the link; SEC's page has none;
 *   M4  the oracle: the model never got the labelled value in SEC, and
 *       SEC's rows and page, as answered and as drawn, signed in and
 *       signed out, carry neither it nor a token.
 *
 * Axes: `off` for OFF's arbiter, then `secrets` for SEC's (stated, and each
 * server's pair explicit).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, launchPostureEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { readArbiterAxes } from "../../launcher/src/axis-preflight.js";
import { modeOf } from "../../launcher/src/mode.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { historyFlagged, steppedIn, type HistoryVM, type HomeVM } from "../../dashboard/src/view-model/home.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { stateAxes, type ProtectionMode } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("off"); // OFF's arbiter; SEC's is pinned to `secrets` below

const CANARY = `OFF_MARKED_STACK_CANARY_${process.pid}_7c1e`;
const OFF_WORDS = "Protection was off in this session: Mandu only watched. Your secrets were not guarded and nothing was masked.";
// The launcher's own line for a protection that did not start.
const DROP_LINE = "mandu: service 'net-proxy' is on by default but failed to start: 127.0.0.1:8790 is occupied — proceeding WITHOUT it (opt out explicitly with --no-net-proxy to silence this)";
const TOOLS = [{ name: "Read", description: "read", input_schema: { type: "object" } }];

test("a session that ran with protection off is marked on History, Home and its page, by its own record; a protected one is not, and shows no value (off, then secrets axes)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-off-marked-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const secret = join(ws, ".env");
  writeFileSync(secret, `API_TOKEN=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n`);
  const manduHome = join(tmp, "mandu-home");
  mkdirSync(manduHome, { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const stamp = Math.floor(Date.now() / 1000);
  const OFF = `${stamp}-${process.pid}-off`;
  const SEC = `${stamp + 1}-${process.pid}-sec`;
  const LESS = `${stamp + 2}-${process.pid}-less`;
  const toModel: string[] = [];
  const close: (() => Promise<void> | void)[] = [];

  /** One phase's stack: the arbiter at `mode`'s axes, the proxy, the dashboard. */
  const phase = async (mode: ProtectionMode) => {
    stateAxes(mode);
    writeFileSync(join(manduHome, "config.toml"), `mode = "${mode}"\n`);
    const arbiter = new ArbiterServer({
      socketPath, humanSocketPath: humanPath, adminSocketPath: join(tmp, "admin.sock"),
      dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {},
      confidentiality: mode === "secrets", integrity: false, // the axes, stated
    });
    await arbiter.listen();
    const clients: ArbiterClient[] = [];
    const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
    let up = new MockUpstream({ sse: buildTextSse("ok") });
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(socketPath), await open(humanPath)), upstream: (a) => up.fetcher(a), log: () => {} });
    const proxyPort = await proxy.listen(0);
    const dashboard = new DashboardServer({
      source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
      fileBrowserHome: tmp,
      configEnv: { MANDU_HOME: manduHome },
      log: () => {}, ...ADMIN_OPTS,
    });
    const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
    const stop = async () => {
      await proxy.close();
      await dashboard.close();
      for (const c of clients) c.close();
      await arbiter.close();
    };
    close.push(stop);
    /** The launcher's posture, with the protection the arbiter itself reports (run.ts). */
    const launch = async (scopeId: string, notes: string[] = []) => {
      const axes = await readArbiterAxes(socketPath, 1000, { helloOnly: true });
      assert.equal(typeof axes.confidentiality, "boolean", "the arbiter reports its axes");
      const effective = { integrity: axes.integrity === true, confidentiality: axes.confidentiality === true };
      assert.equal(modeOf(effective), mode);
      assert.ok(await emitLauncherEvent(socketPath, launchPostureEvent({
        scopeId, target: "claude", argv0: "/usr/local/bin/claude", notes,
        protection: { mode: modeOf(effective), ...effective, reported: true },
      }), humanPath));
    };
    const turn = async (session: string, messages: unknown[], sse: string) => {
      up = new MockUpstream({ sse });
      const res = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": session, "user-agent": "claude-cli/2.1.289 (external, cli)" },
        body: JSON.stringify({ model: "claude-opus-4", stream: true, system: "You are Claude Code.", tools: TOOLS, messages }),
      });
      assert.equal(res.status, 200, await res.text());
      toModel.push(...up.requests.map((r) => r.bodyText));
    };
    const settle = async (id: string, needle: string) => {
      const file = join(tmp, "events", `${id}.ndjson`);
      for (let i = 0; i < 200; i++) {
        let text = "";
        try { text = readFileSync(file, "utf8"); } catch { /* not yet */ }
        if (text.includes(needle)) return;
        await new Promise((r) => setTimeout(r, 30));
      }
      assert.fail(`${id}: no ${needle} recorded`);
    };
    return { base, stop, launch, turn, settle };
  };

  const read = async (base: string, path: string, signedIn: boolean) => {
    const res = await pageFetch(`${base}${path}`, signedIn ? { headers: { Cookie: ADMIN_COOKIE } } : {});
    assert.equal(res.status, 200, path);
    return res.text();
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(CANARY), `CONFIDENTIALITY VIOLATION: ${where} carries the labelled secret`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rowIn = (doc: any, host: string, id: string) => doc.querySelector(`#${host} .row.agent[data-session="${id}"]`) as any;

  try {
    // ── Protection off: session OFF, which ends. ──
    const off = await phase("off");
    await off.launch(OFF);
    await off.turn(OFF, [{ role: "user", content: "Tidy the README." }], buildTextSse("Done."));
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: OFF, code: 0, durationMs: 3_000 }), humanPath));
    await off.settle(OFF, "session_exit");
    await off.settle(OFF, "tllm_call");

    // M1: protection is off now: OFF's page says so at its top, with the link.
    const offPage = JSON.parse(await read(off.base, `/api/home/agent?session=${encodeURIComponent(OFF)}`, false)) as AgentPageVM;
    assert.equal(offPage.protectionOff, true, "the recorded mode is off");
    await servedProductPage(off.base, `/agents/${encodeURIComponent(OFF)}`, (doc) => doc.querySelector("#agent-off a") !== null, (doc) => {
      const line = doc.getElementById("agent-off");
      assert.equal(line.hidden, false);
      assert.equal(line.textContent, `${OFF_WORDS} Protection is in Settings.`);
      assert.equal(line.querySelector("a").getAttribute("href"), "/settings#protection");
      assert.equal(line.nextElementSibling.id, "agent-posture", "just above the posture line");
    });
    await off.stop();
    close.pop();

    // ── Protection on again (the arbiter restarted at `secrets`): session SEC. ──
    const sec = await phase("secrets");

    // M2b: OFF is the window's only session: not a quiet day.
    const quiet = JSON.parse(await read(sec.base, "/api/home", false)) as HomeVM;
    assert.equal(quiet.protection.level, "secrets", "protection is on now");
    assert.deepEqual([quiet.window.sessions, quiet.window.off, quiet.window.only.off], [1, 1, OFF], "the window counts OFF");
    assert.equal("lastSteppedIn" in quiet, false);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const offFact = (doc: any) => [...doc.querySelectorAll("#hero-facts a")].find((a: any) => /ran with protection off/.test(a.textContent)) as any;
    await servedProductPage(sec.base, "/", (doc) => offFact(doc) !== undefined, (doc) => {
      const facts = doc.getElementById("hero-facts");
      assert.equal(offFact(doc).textContent, "1 session ran with protection off");
      assert.equal(offFact(doc).getAttribute("href"), `/agents/${encodeURIComponent(OFF)}`, "it opens OFF's page");
      assert.ok(offFact(doc).querySelector("strong.warn"), "amber");
      assert.doesNotMatch(facts.textContent, /Nothing to count|Mandu last stepped in/);
    });

    await sec.launch(SEC);
    const ask = { role: "user", content: "Read the env." };
    const use = { role: "assistant", content: [{ type: "tool_use", id: "toolu_om_1", name: "Read", input: { file_path: secret } }] };
    const result = { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_om_1", content: `API_TOKEN=${CANARY}\n` }] };
    await sec.turn(SEC, [ask], buildToolUseSse({ id: "toolu_om_1", name: "Read", input: { file_path: secret } }));
    await sec.turn(SEC, [ask, use, result], buildTextSse("It holds one token."));
    await sec.settle(SEC, "\"tool_result\"");

    // M2: the server's History, signed in and out.
    for (const signedIn of [false, true]) {
      const who = signedIn ? "signed in" : "signed out";
      let text = "";
      let h: HistoryVM = { total: 0, rows: [], next: null };
      for (let i = 0; i < 200; i++) {
        text = await read(sec.base, "/api/home/history", signedIn);
        h = JSON.parse(text) as HistoryVM;
        if (h.rows.some((r) => r.id === OFF) && h.rows.some((r) => r.id === SEC)) break;
        await new Promise((r) => setTimeout(r, 30));
      }
      const r = (id: string) => h.rows.find((x) => x.id === id)!;
      assert.ok(r(OFF) && r(SEC), `${who}: History lists both: ${text.slice(0, 400)}`);
      assert.equal(r(OFF).protectionOff, true, `${who}: OFF ran with protection off`);
      assert.equal(r(SEC).protectionOff, false, `${who}: SEC did not`);
      // M4 on SEC's row (OFF read no secret; the whole answer is checked).
      noValue(text, `${who} /api/home/history`);
      const homeText = await read(sec.base, "/api/home", signedIn);
      const homeVm = JSON.parse(homeText) as HomeVM;
      assert.equal(homeVm.protection.level, "secrets", "protection is on now");
      assert.equal(homeVm.agents.find((a) => a.id === OFF)?.protectionOff, true, `${who}: Home's row of OFF`);
      assert.equal(homeVm.agents.find((a) => a.id === SEC)?.protectionOff, false, `${who}: Home's row of SEC`);
      noValue(homeText, `${who} /api/home`);
      const secText = await read(sec.base, `/api/home/agent?session=${encodeURIComponent(SEC)}`, signedIn);
      assert.equal((JSON.parse(secText) as AgentPageVM).protectionOff, false);
      assert.ok(!secText.includes(CANARY), `CONFIDENTIALITY VIOLATION: ${who}, SEC's page answer carries the labelled secret`);
    }

    for (const headers of [{}, { Cookie: ADMIN_COOKIE }] as Record<string, string>[]) {
      const who = "Cookie" in headers ? "signed in" : "signed out";
      // M2: the drawn History and Home.
      await servedProductPage(sec.base, "/history", (doc) => rowIn(doc, "history-list", OFF) !== null && rowIn(doc, "history-list", SEC) !== null, (doc) => {
        const o = rowIn(doc, "history-list", OFF);
        const s = rowIn(doc, "history-list", SEC);
        assert.equal(o.querySelector(".dot").className, "dot warn", `${who}: OFF's amber dot`);
        assert.match(o.querySelector(".agent-counts").textContent, /^protection was off/, `${who}: said first`);
        assert.notEqual(s.querySelector(".dot").className, "dot warn", `${who}: SEC is not marked`);
        assert.doesNotMatch(s.textContent, /protection was off/);
        noValue(doc.body.textContent, `${who}: the drawn History`);
      }, { headers });
      await servedProductPage(sec.base, "/", (doc) => rowIn(doc, "home-earlier", OFF) !== null && rowIn(doc, "home-agents", SEC) !== null, (doc) => {
        const o = rowIn(doc, "home-earlier", OFF);
        assert.equal(o.querySelector(".dot").className, "dot warn", `${who}: Earlier's row of OFF`);
        assert.match(o.querySelector(".agent-counts").textContent, /^protection was off/);
        const s = rowIn(doc, "home-agents", SEC);
        assert.equal(s.querySelector(".dot").className, "dot ok", `${who}: Running now's row of SEC is green`);
        assert.doesNotMatch(s.textContent, /protection was off/);
        // M2b: OFF still leads the window's counts, before SEC's masked secret.
        const lead = doc.querySelector("#hero-facts a");
        assert.equal(lead.textContent, "1 session ran with protection off", `${who}: first among the counts`);
        assert.equal(lead.getAttribute("href"), `/agents/${encodeURIComponent(OFF)}`);
        assert.doesNotMatch(doc.getElementById("hero-facts").textContent, /Nothing to count/);
        noValue(doc.body.textContent, `${who}: the drawn Home`);
      }, { headers });
      // M3: OFF's page keeps its line, without the link; SEC's has none.
      await servedProductPage(sec.base, `/agents/${encodeURIComponent(OFF)}`, (doc) => doc.getElementById("agent-off").hidden === false, (doc) => {
        const line = doc.getElementById("agent-off");
        assert.equal(line.textContent, OFF_WORDS, `${who}: the session's own record, never today's setting`);
        assert.equal(line.querySelector("a"), null, `${who}: protection is on now: nothing to turn on`);
      }, { headers });
      await servedProductPage(sec.base, `/agents/${encodeURIComponent(SEC)}`, (doc) => doc.getElementById("agent-name").textContent === "Claude Code", (doc) => {
        assert.equal(doc.getElementById("agent-off").hidden, true, `${who}: SEC's page has no such line`);
        assert.ok(!doc.body.textContent.includes(CANARY), `CONFIDENTIALITY VIOLATION: ${who}, SEC's drawn page carries the labelled secret`);
      }, { headers });
    }

    // LESS: protection on, but the network proxy did not start (the
    // launcher's own line, as run.ts records it); nothing else happens.
    await sec.launch(LESS, [DROP_LINE]);
    await sec.turn(LESS, [{ role: "user", content: "Fix the changelog typo." }], buildTextSse("Done."));
    assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: LESS, code: 0, durationMs: 2_000 }), humanPath));
    await sec.settle(LESS, "session_exit");
    await sec.settle(LESS, "tllm_call");

    // M2c: History's switch keeps OFF and LESS, signed in and out.
    for (const signedIn of [false, true]) {
      const who = signedIn ? "signed in" : "signed out";
      const every = JSON.parse(await read(sec.base, "/api/home/history?limit=100", signedIn)) as HistoryVM;
      const text = await read(sec.base, "/api/home/history?only=stepped-in&limit=100", signedIn);
      const h = JSON.parse(text) as HistoryVM;
      const o = h.rows.find((r) => r.id === OFF);
      assert.ok(o, `${who}: the switch keeps OFF: ${text.slice(0, 400)}`);
      assert.equal(o.protectionOff, true, `${who}: kept as the session that ran with protection off`);
      assert.equal(steppedIn(o), false, `${who}: Mandu did not step in on OFF`);
      const l = h.rows.find((r) => r.id === LESS);
      assert.ok(l, `${who}: the switch keeps LESS: ${text.slice(0, 400)}`);
      assert.equal(l.lessProtection, true, `${who}: kept as the session that ran with less protection than usual`);
      assert.equal(l.protectionOff, false, `${who}: protection was on in LESS`);
      assert.equal(steppedIn(l), false, `${who}: Mandu did not step in on LESS`);
      assert.doesNotMatch(text, /net-proxy|8790|WITHOUT/, `${who}: a mark, never the launch line`);
      assert.deepEqual(h.rows.map((r) => r.id), every.rows.filter(historyFlagged).map((r) => r.id), `${who}: exactly the rows historyFlagged keeps, in order`);
      noValue(text, `${who} /api/home/history?only=stepped-in`);
    }
    for (const headers of [{}, { Cookie: ADMIN_COOKIE }] as Record<string, string>[]) {
      const who = "Cookie" in headers ? "signed in" : "signed out";
      await servedProductPage(sec.base, "/history?only=stepped-in", (doc) => rowIn(doc, "history-list", OFF) !== null && rowIn(doc, "history-list", LESS) !== null, (doc) => {
        assert.equal(doc.getElementById("history-only").getAttribute("aria-checked"), "true", `${who}: the switch is on`);
        const o = rowIn(doc, "history-list", OFF);
        assert.equal(o.querySelector(".dot").className, "dot warn", `${who}: OFF's amber dot`);
        assert.match(o.querySelector(".agent-counts").textContent, /^protection was off/, `${who}: said first`);
        const l = rowIn(doc, "history-list", LESS);
        assert.equal(l.querySelector(".dot").className, "dot warn", `${who}: LESS's amber dot`);
        assert.match(l.querySelector(".agent-counts").textContent, /less protection than usual/, `${who}: its row says why it is listed`);
        assert.doesNotMatch(doc.body.textContent, /Mandu has not stepped in in any session on record/, `${who}: not the empty words`);
        noValue(doc.body.textContent, `${who}: the drawn History with the switch on`);
      }, { headers });
    }

    // M4: the model never got the value in SEC.
    const secRequests = toModel.filter((b) => b.includes("Read the env."));
    assert.ok(secRequests.length >= 2, "SEC's requests reached the model");
    for (const b of secRequests) assert.ok(!b.includes(CANARY), "CONFIDENTIALITY VIOLATION: the model got the labelled secret");
  } finally {
    for (const c of close.reverse()) await c();
    rmSync(tmp, { recursive: true, force: true });
  }
});
