/**
 * home-failed-sessions.test — when protection failed in several sessions,
 * Home's hero names each one and links its page, and Earlier never hides
 * one, across the REAL components (dashboard.md §4.25, *Protection failed
 * in several sessions*; §4.25ad). Mandu-new.
 *
 * Until 2026-10-25 the product build's hero said only "Each agent where it
 * happened says "protection failed" below", and Earlier drew its first ten
 * ended sessions: a failed one behind ten newer was on no row in sight.
 * Here a real ArbiterServer runs at the `secrets` axes; thirteen REAL
 * anthropic-proxy sessions on the production client each carry one turn
 * whose system prompt names its folder (Claude Code's " - Primary working
 * directory: …"), and each launcher records its REAL `session_exit`. The two
 * oldest, in ~/projects/shop and ~/projects/api, also carry a record the
 * leak check counts (`violatedInvariant` over the arbiter's IPC, as
 * product-history-trace.test.ts T4 records one); the eleven newer are clean.
 * A real DashboardServer with no extensions (the product page only) reads
 * it over a real ArbiterEventSource, signed out:
 *
 *   H1  `/api/home`: verdict `failed`; the sentence names both, newest
 *       first, each an `agent` link to its session;
 *   H2  the served Home (its own index.html and home.js in jsdom): the
 *       hero's two links, the folder as code, each opening that session's
 *       page; Earlier draws both failed rows, the twelfth and thirteenth,
 *       without Show them, which counts the one clean row left; the top
 *       bar's Protection failed opens Home (2026-11-03, #305), on Home and
 *       on a failed session's page, never one session alone;
 *   H3  the oracle: no answer, hero text, title or href carries the
 *       secret's value or a token, and the model never got the value.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const VALUE = `sk_live_homeFailedSessionsCanary_${process.pid}_0000`;
const FAILED = [
  { session: `hf-${process.pid}-api`, folder: "api" },
  { session: `hf-${process.pid}-shop`, folder: "shop" },
] as const;
const CLEAN = Array.from({ length: 11 }, (_, i) => ({ session: `hf-${process.pid}-clean-${String(i).padStart(2, "0")}`, folder: `clean-${i}` }));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("protection failed in two sessions: Home's hero names each and links its page, and Earlier draws both past its first ten; no value anywhere (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-home-failed-"));
  const home = join(tmp, "home");
  for (const a of [...FAILED, ...CLEAN]) mkdirSync(join(home, "projects", a.folder), { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const humanClient = new ArbiterClient(human); await humanClient.connect();
  // No `extensions`: the product page only, as the shipped package.
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: human }), fileBrowserHome: home, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(buildTextSse("Done.", { deltas: 1 }), "utf8")]) };
  };
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  const bodies: string[] = [];
  try {
    // Oldest first: the two failed sessions, then the eleven clean ones.
    for (const a of [...FAILED, ...CLEAN]) {
      const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(gate, humanClient), upstream, sessionKey: a.session, log: () => {} });
      try {
        const port = await proxy.listen(0);
        const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-mandu-session-id": a.session, "anthropic-version": "2023-06-01" },
          body: JSON.stringify({
            model: "claude-opus-4", stream: true, max_tokens: 256,
            system: [{ type: "text", text: `You are Claude Code.\n\n# Environment\n - Primary working directory: ${join(home, "projects", a.folder)}\n - Platform: linux` }],
            messages: [{ role: "user", content: "Deploy the site." }],
          }),
        });
        assert.equal(res.status, 200, await res.text());
      } finally {
        await proxy.close();
      }
      if (FAILED.some((f) => f.session === a.session)) {
        // The leak check's record, as product-history-trace.test.ts T4 records one.
        await gate.emit({
          id: `leak-${a.session}`, sessionId: a.session, turn: 1, ts: new Date().toISOString(), seq: 0, callId: `toolu_${a.folder}`, parentId: null,
          kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
          input: null, output: null, invariant: { violatedInvariant: true, detail: `un-symbolized span survived: STRIPE_KEY=${VALUE}` },
        } as never);
      }
      await new Promise((r) => setTimeout(r, 5));
      assert.ok(await emitLauncherEvent(sock, sessionExitEvent({ scopeId: a.session, code: 0, durationMs: 1_000 }), human), `${a.session}: its exit lands`);
      await new Promise((r) => setTimeout(r, 5));
    }
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the value");

    // ── H1: /api/home ──
    let vm: HomeVM | null = null;
    let text = "";
    const done = (x: HomeVM) => x.verdict === "failed" && x.agents.length === 13 && x.agents.every((a) => a.state === "idle" && a.cwd)
      && x.sentenceParts.filter((p) => p.kind === "link").length === 2;
    for (let i = 0; i < 400; i++) {
      text = await (await pageFetch(`${base}/api/home`)).text();
      vm = JSON.parse(text) as HomeVM;
      if (done(vm)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(vm && done(vm), text.slice(0, 600));
    bodies.push(text);
    assert.equal(vm.headline, "Protection failed.");
    assert.equal(vm.sentence, "2 items reached the AI unmasked in the last 24 hours, in Claude Code in ~/projects/shop and Claude Code in ~/projects/api. Open each to see which.");
    assert.deepEqual(vm.sentenceParts.flatMap((p) => (p.kind === "link" && p.to === "agent" ? [p.session] : [])), [FAILED[1].session, FAILED[0].session], "newest first");
    assert.deepEqual(vm.agents.filter((a) => !a.holds).map((a) => a.id), [FAILED[1].session, FAILED[0].session]);
    assert.deepEqual([FAILED[1], FAILED[0]].map((f) => vm!.agents.findIndex((a) => a.id === f.session)), [11, 12], "both failed sessions are past Earlier's first ten");

    // ── H2: the served Home ──
    await servedProductPage(base, "/", (doc: Doc) => doc.querySelectorAll('#hero-sentence a[data-page-link="agent"]').length === 2 && doc.querySelector("#home-earlier .row.agent") !== null, async (doc: Doc) => {
      assert.equal(doc.getElementById("hero").dataset.verdict, "failed");
      const links = [...doc.querySelectorAll('#hero-sentence a[data-page-link="agent"]')] as Doc[];
      assert.deepEqual(links.map((l) => l.textContent), ["Claude Code in ~/projects/shop", "Claude Code in ~/projects/api"]);
      assert.deepEqual(links.map((l) => l.querySelector("code").textContent), ["~/projects/shop", "~/projects/api"], "each folder a name, as the rows write it");
      assert.deepEqual(links.map((l) => l.dataset.session), [FAILED[1].session, FAILED[0].session]);
      for (const l of links) assert.ok(l.getAttribute("href").includes(encodeURIComponent(l.dataset.session)), l.getAttribute("href"));
      const hero = doc.getElementById("hero");
      noValue(hero.textContent, "the hero's text");
      for (const e of [...hero.querySelectorAll("[title], a")] as Doc[]) {
        noValue(e.getAttribute("title") ?? "", "a hero title");
        noValue(e.getAttribute("href") ?? "", "a hero href");
      }
      // Earlier: both failed rows drawn without Show them, which counts the clean rest.
      const rows = () => ([...doc.querySelectorAll("#home-earlier .row.agent")] as Doc[]).map((r) => r.dataset.session);
      assert.equal(rows().length, 12, "the ten newest, and both failed rows behind them");
      assert.ok(rows().includes(FAILED[0].session), "the older failed session is on Home without Show them");
      assert.ok(rows().includes(FAILED[1].session));
      assert.match(doc.getElementById("home-earlier").querySelector(".row.agent[data-session=\"" + FAILED[0].session + "\"]").textContent, /protection failed/);
      assert.match(doc.querySelector("#home-earlier > .row.dim").textContent, /^1 more session in the last 24 hours\. Show it$/);
      // The top bar's Protection failed opens Home, which names both, not
      // the newest one alone (§4.25 *It says when protection failed*).
      const topBar = () => {
        const a = doc.querySelectorAll("#top-status a") as Doc[];
        assert.equal(a.length, 1, "one link in the top bar");
        assert.equal(doc.getElementById("top-status").textContent, "Protection failed");
        assert.equal(doc.querySelector("#top-status > .dot").className, "dot bad");
        return a[0];
      };
      const atHome = (where: string) => {
        const a = topBar();
        assert.equal(new URL(a.getAttribute("href"), base).pathname, "/", `${where}: the top bar opens Home`);
        assert.equal(a.getAttribute("aria-label"), "Protection failed: open Home", where);
        assert.equal(a.dataset.session, undefined, where);
        for (const f of FAILED) assert.ok(!a.getAttribute("href").includes(f.session), `${where}: not one session's page`);
        noValue(a.getAttribute("href"), "the top bar's href");
        noValue(a.getAttribute("aria-label"), "the top bar's name");
      };
      atHome("on Home");
      // Each link opens that session's page.
      links[1].click();
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(doc.defaultView.location.pathname, `/agents/${encodeURIComponent(FAILED[0].session)}`);
      atHome("on a failed session's page");
      // A plain click on it opens Home in place.
      topBar().click();
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(doc.defaultView.location.pathname, "/");
      assert.equal(doc.getElementById("page-home").hidden, false, "Home is open");
      noValue(doc.body.textContent, "the rendered page");
    });

    // ── H3: the oracle over each answer read ──
    for (const a of FAILED) {
      const r = await pageFetch(`${base}/api/home/agent?session=${encodeURIComponent(a.session)}`);
      assert.equal(r.status, 200);
      bodies.push(await r.text());
    }
    for (const b of bodies) noValue(b, "an answer");
  } finally {
    await dashboard.close();
    gate.close();
    humanClient.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
