/**
 * plugins-page — the product's Plugins page (dashboard.md §4.25aj) over the
 * REAL components, laid out as `mandu serve`'s pool lays out one attachment
 * session (attachment-pool.ts; the contract in attachment-contract.ts):
 *
 *   - a real ArbiterServer on the `secrets` axes with its data and human
 *     sockets; a `.env` registered over the human socket (the pool's secret
 *     registration), then the attachment (`beginAttachment`, kind
 *     `openclaw-plugin`, the launcher's coverage row);
 *   - the real anthropic-proxy in its production wiring for `openclaw:main`,
 *     answering `/_mandu/identity` as the session's; its port file 0600 in a
 *     0700 directory, the pool's records (the running pool, this process;
 *     the session's secret counts), and the declared file, as the pool and
 *     `mandu openclaw install` write them;
 *   - a real DashboardServer over the production ArbiterEventSource reading
 *     those (as a dashboard that is not the service's own reads them).
 *
 * The oracle:
 *   P0  before anything is declared or the pool runs, the service's line is
 *       a plain fact (no agent depends on it): no colour, no command;
 *   P1  `/api/plugins` reports the card: attached, the agent and session,
 *       the proxy answering, registered with when it began, the secret
 *       files, the posture the protection service decided with the shared
 *       sentence (the launcher's copy), the cost notice, the session page;
 *   P2  the served page in jsdom draws that card, its posture line saying
 *       the AI sees your secrets "masked" with no retired word
 *       (dashboard.md §4.25u), and its session link opens the session page
 *       of `openclaw:main`;
 *   P3  the attachment ended (its proxy still up): lapsed; the proxy gone:
 *       not answering; the pool's record gone: the service is not running,
 *       amber now that an agent is declared;
 *   P5  the route check's word (§3.6): a lost route recorded on the exposed
 *       human socket is a claim and leaves the card attached; recorded on
 *       the admin channel (believed) it turns the card red with what changed
 *       (no proxy address) and the re-attach commands, and Home's lost-route
 *       card says the AI reads your secrets "as they are, not masked";
 *       restored, attached;
 *   P6  the commands the page asks you to run carry the `run` mark (its
 *       Copy, dashboard.md §4.25b) on exactly those parts, in
 *       `/api/plugins` (the stopped service line's two, the cost notice's
 *       and a lost route's fix) and `/api/home` (the exposure card's and
 *       the lost-route card's fix); the agent and session names never;
 *   P4  no answer or drawn page carries the secret's value, a token, the
 *       proxy's port or a path.
 * Axes stated: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ATTACHMENT_COVERAGE, attachmentCoverage, postureSentence, resolvePosture } from "../../launcher/src/confinement-posture.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { PluginsVM } from "../../dashboard/src/view-model/plugins.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { RETIRED } from "../../dashboard/test/unit/view-model/retired-words.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const SESSION = "openclaw:main";
const VALUE = `pluginsPageDbPass_${process.pid}_0001`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

test("the Plugins page reports an attachment over the real arbiter, proxy and dashboard: attached, then lapsed, down, and the service stopped; no value, token, port or path (secrets axes, explicit)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-plugins-page-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "shop-app"), { recursive: true });
  const env = join(home, "shop-app", ".env");
  writeFileSync(env, `DB_PASSWORD=${VALUE}\n`);
  const runtime = join(tmp, "run");
  const sessionDir = join(runtime, "attachments", SESSION);
  mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  const declaredFile = join(tmp, "mandu-home", "state", "serve-attachments.json");
  mkdirSync(join(tmp, "mandu-home", "state"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null, confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const service = new ArbiterClient(humanPath);
  await service.connect();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const human = new ArbiterClient(humanPath);
  // The service's own dashboard's admin channel: where the route check records its word, believed.
  const admin = new ArbiterClient(join(tmp, "admin.sock"));
  await human.connect();
  await admin.connect();
  let proxy: AnthropicProxy | null = null;
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    plugins: { runtimeBase: runtime, declaredFile },
    configEnv: { MANDU_HOME: join(tmp, "mandu-home"), HOME: home },
    log: () => {},
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const seen: string[] = [];
  const answers: string[] = [];
  const plugins = async (): Promise<PluginsVM> => {
    const r = await pageFetch(`${base}/api/plugins`);
    const text = await r.text();
    assert.equal(r.status, 200, text);
    answers.push(text);
    return (JSON.parse(text) as { plugins: PluginsVM }).plugins;
  };
  const homeAnswer = async (): Promise<HomeVM> => {
    const r = await pageFetch(`${base}/api/home`);
    const text = await r.text();
    assert.equal(r.status, 200, text);
    // P4's value, token and path checks (Home's route card names the
    // problem as the route check found it, an address too: not a Plugins answer).
    seen.push(text);
    return JSON.parse(text) as HomeVM;
  };
  /** The text of each part marked `run` (P6). */
  const runs = (parts: ReadonlyArray<{ kind: string; text: string; run?: true }>): string[] => parts.filter((p) => p.kind === "code" && p.run === true).map((p) => p.text);
  /** Every part of a card that is not its fix's (the state's words, the facts). */
  const unmarked = (card: PluginsVM["hosts"][number]["cards"][number]) => [...card.facts.flatMap((f) => f.parts)].filter((p) => "run" in p);
  const EXPOSURE_FIX = ["mandu openclaw gateway", "mandu serve stop", "mandu openclaw uninstall"];
  const REATTACH = ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"];
  let port = 0;
  try {
    // ── P0: nothing declared, no pool record ──
    const fresh = await plugins();
    assert.deepEqual([fresh.service.running, fresh.service.tone, fresh.service.headline], [false, "plain", "The Mandu service is not running."]);
    assert.deepEqual(fresh.service.parts, [{ kind: "text", text: "You need it only to attach Mandu to an agent as a plugin; the steps are below." }], "no colour, no command: nothing depends on it");
    assert.equal(fresh.hosts[0]!.setup!.commands[0], "mandu serve install", "the set-up below starts with the service's own");

    // The pool's order: the secret file, the attachment, then the proxy.
    const reg = await service.registerSecret({ path: env, home });
    assert.ok(reg.symbol, reg.reason);
    const before = Date.now();
    const att = await service.beginAttachment({ sessionId: SESSION, kind: "openclaw-plugin", coverage: ATTACHMENT_COVERAGE["openclaw-plugin"] });
    assert.equal(att.posture, "gated");
    proxy = new AnthropicProxy({
      arbiter: new ArbiterClientAdapter(data, human), upstream: new MockUpstream({ sse: buildTextSse("ok") }).fetcher, sessionKey: SESSION, log: () => {},
      identity: { service: "anthropic-proxy", sessionKey: SESSION, arbiterSock: socketPath },
    });
    port = await proxy.listen(0);
    // What the pool and `mandu openclaw install` leave on disk.
    writeFileSync(join(sessionDir, "anthropic-proxy.port"), `${port}\n`, { mode: 0o600 });
    writeFileSync(join(sessionDir, "pool.json"), JSON.stringify({ pid: process.pid, proxyPid: process.pid, session: SESSION, startedAt: new Date().toISOString(), secrets: { found: 1, registered: 1, at: new Date().toISOString() } }), { mode: 0o600 });
    writeFileSync(join(runtime, "attachments", "pool.json"), JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }), { mode: 0o600 });
    writeFileSync(declaredFile, JSON.stringify({ version: 1, attachments: [{ kind: "openclaw-plugin", agent: "main", session: SESSION, port }] }), { mode: 0o600 });

    // ── P1: the answer ──
    const vm = await plugins();
    assert.equal(vm.service.running, true);
    assert.equal(vm.service.headline, "The Mandu service is running.");
    const host = vm.hosts.find((h) => h.kind === "openclaw-plugin")!;
    assert.equal(host.title, "Mandu in OpenClaw");
    assert.equal(host.setup, null);
    const card = host.cards[0]!;
    assert.equal(host.cards.length, 1);
    assert.deepEqual([card.state, card.tone, card.headline, card.session, card.agent], ["attached", "ok", "Attached", SESSION, "main"]);
    assert.deepEqual(card.facts.map((f) => [f.label, f.parts.map((p) => p.text).join("")]), [
      ["Agent", "OpenClaw's agent main, session openclaw:main"],
      ["AI requests", "Mandu's proxy answers."],
      ["Registered", "Yes, Mandu holds it."],
      ["Secret files", "1 secret file registered."],
    ]);
    assert.ok(card.since !== null && card.since >= before - 1000 && card.since <= Date.now(), `since when the protection service first held it: ${card.since}`);
    const decided = resolvePosture(ATTACHMENT_COVERAGE["openclaw-plugin"]);
    assert.deepEqual(card.posture, { name: decided.posture, sentence: postureSentence(decided) }, "the protection service's decision, the launcher's sentence");
    assert.ok(card.notice, "the cost while it runs");
    assert.deepEqual(card.links, { session: SESSION, historyQuery: "OpenClaw" }, "the arbiter's registration record gives the session a page");
    // P6: the cost's fix is marked to run; the agent and session are not.
    assert.deepEqual(runs(card.notice!.parts), EXPOSURE_FIX);
    assert.deepEqual(runs(card.parts), []);
    assert.deepEqual(unmarked(card), [], "the agent and session names carry no mark");
    assert.deepEqual(runs(vm.service.parts), [], "running: no command");
    const homeNow = await homeAnswer();
    assert.ok(homeNow.exposure, "the attachment holds the human plane exposed: Home's notice");
    assert.deepEqual(runs(homeNow.exposure!.fixParts), EXPOSURE_FIX, "Home's exposure fix, marked to run");

    // ── P2: the served page ──
    await servedProductPage(base, "/plugins", (doc: Doc) => !!doc.querySelector(".plugin-card"), async (doc: Doc) => {
      const c = doc.querySelector(".plugin-card");
      assert.equal(c.dataset.state, "attached");
      assert.equal(c.querySelector(".plugin-state").textContent.trim(), "Attached");
      const postureLine = c.querySelector(".plugin-posture").textContent as string;
      assert.match(postureLine, /^Protection here: gated\. The AI sees your secrets masked, /, "the product's word for what the AI gets");
      assert.doesNotMatch(postureLine, RETIRED, "no retired word (dashboard.md §4.25u)");
      assert.equal(doc.querySelector('#nav a[aria-current="page"]').getAttribute("data-page-link"), "plugins");
      seen.push(doc.documentElement.outerHTML);
      c.querySelector('.plugin-links a[data-page-link="agent"]').click();
      await waitWhile(() => doc.getElementById("page-agent").hidden);
      assert.equal(doc.getElementById("page-agent").hidden, false, "its session link opens the session page");
      assert.equal(doc.defaultView.location.pathname, "/agents/openclaw%3Amain");
      seen.push(doc.documentElement.outerHTML);
    });

    // ── P5: the route check's word (openclaw-plugin.md §3.6) ──
    const LOST_COVERAGE = attachmentCoverage("openclaw-plugin", { modelContext: true, policy: true });
    const lostRoute = {
      state: "lost",
      problems: [
        { code: "plugin-disabled", detail: "the Mandu plugin is disabled (its entry, plugins.enabled, plugins.deny or plugins.allow)" },
        { code: "route-elsewhere", detail: `Anthropic calls go to api.anthropic.com, not Mandu's service proxy (http://127.0.0.1:${port})` },
      ],
      config: join(home, ".openclaw", "openclaw.json"),
    };
    // A claim (the exposed human socket, where a program in the Gateway could
    // write): stored, never what the page shows.
    const claimed = await human.updateAttachment({ token: att.token, coverage: LOST_COVERAGE, route: lostRoute }) as { believed: boolean };
    assert.equal(claimed.believed, false, "the exposed human socket's word is a claim");
    assert.equal((await plugins()).hosts[0]!.cards[0]!.state, "attached", "a claimed record does not turn the card");
    // The service's own dashboard, on the admin channel: believed.
    const believed = await admin.updateAttachment({ token: att.token, coverage: LOST_COVERAGE, route: lostRoute }) as { believed: boolean; gap: string };
    assert.deepEqual([believed.believed, believed.gap], [true, "model-route-lost"]);
    const lost = (await plugins()).hosts[0]!.cards[0]!;
    assert.deepEqual([lost.state, lost.tone, lost.headline], ["route-lost", "bad", "Not going through Mandu"]);
    const lostWords = lost.parts.map((p) => p.text).join("");
    assert.match(lostWords, /the Mandu plugin is disabled .*; Anthropic calls go to api\.anthropic\.com, not Mandu's service proxy\. /);
    assert.deepEqual(lost.parts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"], "the re-attach commands");
    assert.deepEqual(lost.posture, { name: "gated", sentence: postureSentence({ posture: "gated", gap: "model-route-lost" }) });
    assert.deepEqual(runs(lost.parts), REATTACH, "P6: the re-attach commands, marked to run; the problem's words not");
    assert.deepEqual(unmarked(lost), []);
    const homeLost = await homeAnswer();
    assert.ok(homeLost.routeLost, "Home's lost-route card");
    assert.match(homeLost.routeLost!.sentence, /the AI can read your secrets as they are, not masked\./);
    assert.doesNotMatch(homeLost.routeLost!.sentence, RETIRED);
    assert.deepEqual(runs(homeLost.routeLost!.fixParts), REATTACH, "Home's lost-route fix, marked to run");
    assert.deepEqual(homeLost.routeLost!.items.flatMap((it) => it.parts).filter((p) => "run" in p), [], "the session and its config are no command");
    await servedProductPage(base, "/plugins", (doc: Doc) => doc.querySelector(".plugin-card")?.dataset.state === "route-lost", (doc: Doc) => {
      const c = doc.querySelector(".plugin-card");
      assert.equal(c.dataset.tone, "bad");
      assert.deepEqual([...c.querySelectorAll(".plugin-sentence code")].map((x: Doc) => x.textContent), ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"]);
      seen.push(doc.documentElement.outerHTML);
    });
    // Restored: the route check sends the kind's full coverage again.
    await admin.updateAttachment({ token: att.token, coverage: ATTACHMENT_COVERAGE["openclaw-plugin"], route: { state: "routed", problems: [] } });
    const back = (await plugins()).hosts[0]!.cards[0]!;
    assert.deepEqual([back.state, back.tone], ["attached", "ok"], "restored: attached again");
    assert.equal(back.posture.sentence, postureSentence(decided));

    // ── P3: lapsed, down, stopped ──
    assert.equal((await service.endAttachment(att.token)).ended, true);
    const lapsed = (await plugins()).hosts[0]!.cards[0]!;
    assert.deepEqual([lapsed.state, lapsed.tone], ["lapsed", "bad"], "the proxy answers, the protection service holds it no more");
    assert.equal(lapsed.notice, null);
    await proxy.close();
    proxy = null;
    rmSync(join(sessionDir, "anthropic-proxy.port"));
    const down = (await plugins()).hosts[0]!.cards[0]!;
    assert.deepEqual([down.state, down.tone], ["down", "bad"]);
    rmSync(join(runtime, "attachments", "pool.json"));
    const stopped = await plugins();
    assert.equal(stopped.service.running, false);
    assert.equal(stopped.service.tone, "warn", "an agent depends on it: amber");
    assert.deepEqual(stopped.service.parts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu serve start", "mandu serve install"]);
    assert.deepEqual(runs(stopped.service.parts), ["mandu serve start", "mandu serve install"], "P6: both marked to run");
    assert.equal(stopped.hosts[0]!.cards[0]!.state, "stopped", "still set up: its AI requests fail until the service runs");

    // ── P4: the oracle ──
    for (const s of [...seen, ...answers]) {
      assert.ok(!s.includes(VALUE), "CONFIDENTIALITY VIOLATION: the secret's value in an answer or a drawn page");
      assert.doesNotMatch(s, /\$MDU/, "nor a token");
      assert.ok(!s.includes(runtime) && !s.includes(declaredFile), "nor a path");
    }
    for (const s of answers) {
      assert.doesNotMatch(s, new RegExp(`(?<![0-9])${port}(?![0-9])`), "no answer names the proxy's port");
      assert.doesNotMatch(s, /"port"/);
    }
  } finally {
    await proxy?.close();
    await dashboard.close();
    service.close();
    data.close();
    human.close();
    admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
