/**
 * plugins.test — the Plugins page's projection (dashboard.md §4.25aj,
 * view-model/plugins.ts). Mandu-new.
 *
 *   - nothing attached, the service running: OpenClaw's card group says it
 *     is not attached and how to attach it (two commands);
 *   - the service not running with nothing attached: a plain fact (no
 *     colour, no command), and the set-up starts with `mandu serve
 *     install`; with a declared agent: amber, with how to start it;
 *   - one live attachment: attached, its agent and session, the proxy
 *     answering, registered, its secret files, since when, the posture name
 *     and the sentence from the shared copy (confinement-posture.ts), the
 *     cost while it runs with Home's fix, and its links;
 *   - one lapsed (the proxy answers, the protection service holds it no
 *     more), one down, one starting, one unknown, one detached, one with the
 *     service stopped, and a lost route (the arbiter's believed record:
 *     red, the problems named without the proxy's address, Home's fix) and
 *     one restored;
 *   - the words: product vocabulary only, never a port, a path or a token;
 *   - the hosts: OpenClaw only (OpenShell is not shown until it exists).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { pluginsPage, routeProblemWords, PLUGIN_HOSTS, type PluginFacts, type PluginRoute, type PluginSessionFacts } from "../../../src/view-model/plugins.js";
import { ROUTE_FIX_PARTS } from "../../../src/view-model/attachment-route.js";
import { fenceHoleWords, type FenceHole } from "../../../src/attachment-contract.js";
import { RETIRED, THIS_MACHINE } from "./retired-words.js";
import { ATTACHMENT_COVERAGE, postureSentence, resolvePosture } from "../../../src/confinement-posture.js";
import { PLUGIN_EXPOSURE_FIX, homeExposure, toHumanPlaneVM } from "../../../src/view-model/human-plane.js";


const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|attestation|attachment|claim)\w*|\$MDU:|\bpool\b|\bproxy pool\b/i;

const SESSION = "openclaw:main";
const BEGUN = Date.parse("2026-10-25T09:00:00.000Z");
/** The route check's word as the arbiter recorded it (attachment-contract.ts routeVerdict's sentences). */
const LOST: PluginRoute = { state: "lost", since: BEGUN, problems: ["the Mandu plugin is disabled (its entry)", "Anthropic calls go to api.anthropic.com, not Mandu's service proxy (http://127.0.0.1:41000)"] };

function session(over: Partial<PluginSessionFacts> = {}): PluginSessionFacts {
  return {
    session: SESSION, kind: "openclaw-plugin", agent: "main", declared: true, answering: true, poolState: null,
    secrets: { found: 3, registered: 2, at: "2026-10-25T09:00:01.000Z" }, route: null, ...over,
  };
}

function facts(over: Partial<PluginFacts> = {}): PluginFacts {
  return { serviceRunning: true, sessions: [session()], live: new Map([[SESSION, BEGUN]]), known: new Set([SESSION]), ...over };
}

/** Every word of the page as one string. */
function allWords(vm: ReturnType<typeof pluginsPage>): string {
  const parts = (p: Array<{ text: string }>) => p.map((x) => x.text).join("");
  const out = [vm.intro, vm.service.headline, parts(vm.service.parts)];
  for (const h of vm.hosts) {
    out.push(h.title, parts(h.covers));
    if (h.setup) out.push(h.setup.sentence, ...h.setup.commands);
    for (const c of h.cards) {
      out.push(c.headline, parts(c.parts), c.posture.sentence, ...c.facts.flatMap((f) => [f.label, parts(f.parts)]));
      if (c.notice) out.push(c.notice.headline, parts(c.notice.parts));
    }
  }
  return out.join("\n");
}

test("nothing attached, the service running: OpenClaw is not attached, with its two commands", () => {
  const vm = pluginsPage(facts({ sessions: [], live: new Map(), known: new Set() }));
  assert.equal(vm.service.running, true);
  assert.equal(vm.service.tone, "ok");
  assert.equal(vm.service.headline, "The Mandu service is running.");
  assert.match(vm.service.parts.map((p) => p.text).join(""), /Nothing is attached/);
  assert.equal(vm.hosts.length, 1);
  const oc = vm.hosts[0]!;
  assert.equal(oc.title, "Mandu in OpenClaw");
  assert.deepEqual(oc.cards, []);
  assert.deepEqual(oc.setup, { sentence: "Not attached. To attach OpenClaw, run:", commands: ["mandu openclaw install", "openclaw gateway restart"] });
  assert.equal(oc.covers.map((p) => p.text).join(""),
    "Mandu in OpenClaw keeps your secrets out of what the AI sees. Files, programs and their network are not covered here; for that, run mandu openclaw gateway.");
  assert.deepEqual(oc.covers.filter((p) => p.kind === "code").map((p) => p.text), ["mandu openclaw gateway"]);
});

test("the service not running, nothing attached: a plain fact, no command; the set-up starts with the service's own", () => {
  // Until 2026-10-26 this line was amber with the start commands: a warning
  // about nothing, since no agent depends on the service (§4.25aj).
  const vm = pluginsPage(facts({ serviceRunning: false, sessions: [], live: null, known: new Set() }));
  assert.equal(vm.service.running, false);
  assert.equal(vm.service.tone, "plain");
  assert.equal(vm.service.headline, "The Mandu service is not running.");
  assert.deepEqual(vm.service.parts, [{ kind: "text", text: "You need it only to attach Mandu to an agent as a plugin; the steps are below." }]);
  assert.deepEqual(vm.hosts[0]!.setup!.commands, ["mandu serve install", "mandu openclaw install", "openclaw gateway restart"]);
  assert.match(vm.hosts[0]!.setup!.sentence, /set up the Mandu service, then attach it/);
});

test("the service not running with an agent declared: amber, and how to start it", () => {
  const vm = pluginsPage(facts({ serviceRunning: false, sessions: [session({ answering: false })], live: null }));
  assert.equal(vm.service.running, false);
  assert.equal(vm.service.tone, "warn");
  assert.equal(vm.service.headline, "The Mandu service is not running.");
  assert.match(vm.service.parts.map((p) => p.text).join(""), /^Plugins need it: /);
  assert.deepEqual(vm.service.parts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu serve start", "mandu serve install"]);
  // Both are commands to run: the page gives each a Copy (dashboard.md §4.25b).
  assert.deepEqual(vm.service.parts.filter((p) => p.kind === "code" && p.run === true).map((p) => p.text), ["mandu serve start", "mandu serve install"]);
  assert.equal(vm.hosts[0]!.cards[0]!.state, "stopped");
  // A card the protection service still holds without a declaration counts too.
  const held = pluginsPage(facts({ serviceRunning: false, sessions: [session({ declared: false, answering: false })], live: null }));
  assert.equal(held.service.tone, "warn");
});

test("one live attachment: attached, its facts, since when, the posture from the shared copy, the cost with Home's fix, its links", () => {
  const vm = pluginsPage(facts());
  assert.match(vm.service.parts.map((p) => p.text).join(""), /attached to 1 agent below/);
  const [card] = vm.hosts[0]!.cards;
  assert.ok(card);
  assert.equal(card.state, "attached");
  assert.equal(card.tone, "ok");
  assert.equal(card.headline, "Attached");
  assert.equal(card.session, SESSION);
  assert.equal(card.agent, "main");
  assert.equal(card.since, BEGUN);
  assert.deepEqual(card.facts.map((f) => [f.label, f.parts.map((p) => p.text).join(""), f.tone]), [
    ["Agent", "OpenClaw's agent main, session openclaw:main", "plain"],
    ["AI requests", "Mandu's proxy answers.", "ok"],
    ["Registered", "Yes, Mandu holds it.", "ok"],
    ["Secret files", "2 secret files registered of 3 found.", "plain"],
  ]);
  // The posture: the protection service's decision over the kind's coverage,
  // its name, and the gap's own sentence (no egress promise it does not keep).
  const decided = resolvePosture(ATTACHMENT_COVERAGE["openclaw-plugin"]);
  assert.deepEqual(decided, { posture: "gated", gap: "openclaw-plugin" });
  assert.deepEqual(card.posture, { name: "gated", sentence: postureSentence(decided) });
  assert.doesNotMatch(card.posture.sentence, /sent out only where/);
  // The cost while it runs: the confined agents' guard is not trusted; the fix is Home's.
  assert.ok(card.notice);
  assert.match(card.notice.parts.map((p) => p.text).join(""), /does not trust the file guard of the agents you start with it/);
  assert.deepEqual(card.notice.parts.slice(-PLUGIN_EXPOSURE_FIX.length), [...PLUGIN_EXPOSURE_FIX]);
  assert.deepEqual(card.notice.parts.filter((p) => p.kind === "code" && p.run === true).map((p) => p.text), ["mandu openclaw gateway", "mandu serve stop", "mandu openclaw uninstall"], "the fix's commands, marked to run");
  // The agent and the session are names, not commands: plain code.
  assert.deepEqual(card.facts.flatMap((f) => f.parts).filter((p) => p.kind === "code").map((p) => [p.text, "run" in p]), [["main", false], [SESSION, false]]);
  const home = homeExposure(toHumanPlaneVM({ exposed: true, since: BEGUN, launches: [{ pid: 0, mode: "secrets", posture: "gated", session: SESSION, attachment: "openclaw-plugin" }] }));
  assert.ok(home);
  assert.ok(home.fix.endsWith(PLUGIN_EXPOSURE_FIX.map((p) => p.text).join("")), "Home's notice ends with the same fix");
  assert.deepEqual(card.links, { session: SESSION, historyQuery: "OpenClaw" });
});

test("one lapsed: the proxy answers but the protection service holds it no more; no cost notice", () => {
  const card = pluginsPage(facts({ live: new Map() })).hosts[0]!.cards[0]!;
  assert.equal(card.state, "lapsed");
  assert.equal(card.tone, "bad");
  assert.equal(card.headline, "Not registered");
  assert.match(card.parts.map((p) => p.text).join(""), /registration of it lapsed.*fail rather than go out unmasked/);
  assert.deepEqual(card.facts.find((f) => f.label === "Registered")!.parts.map((p) => p.text), ["No."]);
  assert.equal(card.since, null);
  assert.equal(card.notice, null);
});

test("the other states: down, starting, unknown, detached, the service stopped", () => {
  const down = pluginsPage(facts({ sessions: [session({ answering: false })] })).hosts[0]!.cards[0]!;
  assert.deepEqual([down.state, down.tone, down.headline], ["down", "bad", "Not answering"]);
  assert.match(down.parts.map((p) => p.text).join(""), /never go out unmasked/);
  assert.deepEqual(down.parts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu serve status"]);
  assert.ok(down.notice, "still held: the cost is still real");

  const starting = pluginsPage(facts({ sessions: [session({ answering: false, poolState: "starting", secrets: null })], live: new Map() })).hosts[0]!.cards[0]!;
  assert.deepEqual([starting.state, starting.tone, starting.headline], ["starting", "warn", "Starting"]);
  assert.deepEqual(starting.facts.find((f) => f.label === "Secret files")!.parts.map((p) => p.text), ["Not registered yet."]);

  const unknown = pluginsPage(facts({ live: null })).hosts[0]!.cards[0]!;
  assert.deepEqual([unknown.state, unknown.tone], ["unknown", "warn"]);
  assert.match(unknown.facts.find((f) => f.label === "Registered")!.parts[0]!.text, /Not known/);
  assert.equal(unknown.notice, null);

  const detached = pluginsPage(facts({ sessions: [session({ declared: false, answering: false })] }));
  assert.deepEqual([detached.hosts[0]!.cards[0]!.state, detached.hosts[0]!.cards[0]!.headline], ["detaching", "Detached"]);
  assert.match(detached.service.parts[0]!.text, /Nothing is attached/, "a detached one is not counted as attached");
  assert.equal(detached.hosts[0]!.setup, null, "a card is drawn, so no set-up beside it");

  const stopped = pluginsPage(facts({ serviceRunning: false, sessions: [session({ answering: false })], live: null }));
  const s = stopped.hosts[0]!.cards[0]!;
  assert.deepEqual([s.state, s.tone, s.headline], ["stopped", "bad", "Not running"]);
  assert.match(s.parts.map((p) => p.text).join(""), /OpenClaw's agent main is set up to send its AI requests through Mandu, and they fail until the Mandu service runs again/);
  assert.equal(stopped.service.headline, "The Mandu service is not running.");
});

test("a lost route (the arbiter's believed record) turns the card red with the problems named and Home's fix; restored, it is attached again", () => {
  const lost = pluginsPage(facts({ sessions: [session({ route: LOST, recorded: { posture: "gated", gap: "model-route-lost" } })] })).hosts[0]!.cards[0]!;
  assert.deepEqual([lost.state, lost.tone, lost.headline], ["route-lost", "bad", "Not going through Mandu"]);
  const words = lost.parts.map((p) => p.text).join("");
  assert.match(words, /^OpenClaw's config was changed: the Mandu plugin is disabled \(its entry\); Anthropic calls go to api\.anthropic\.com, not Mandu's service proxy\. /);
  assert.ok(!words.includes("127.0.0.1") && !words.includes("41000"), "the service proxy's address is not named");
  assert.deepEqual(lost.parts.slice(-ROUTE_FIX_PARTS.length), [...ROUTE_FIX_PARTS], "Home's route fix, word for word");
  assert.deepEqual(lost.parts.filter((p) => p.kind === "code" && p.run === true).map((p) => p.text), ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"], "the fix's commands, marked to run; the problem's words are not");
  assert.deepEqual(lost.parts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"]);
  // The posture the record decided: the lost model route's own sentence.
  assert.deepEqual(lost.posture, { name: "gated", sentence: postureSentence({ posture: "gated", gap: "model-route-lost" }) });
  assert.ok(lost.notice, "still held: the cost is still real");
  const back = pluginsPage(facts({ sessions: [session({ route: { state: "ok" } })] })).hosts[0]!.cards[0]!;
  assert.deepEqual([back.state, back.tone], ["attached", "ok"]);
  assert.equal(back.posture.sentence, postureSentence({ posture: "gated", gap: "openclaw-plugin" }));
});

test("routeProblemWords: no loopback address, a file by its name only", () => {
  assert.equal(routeProblemWords("Anthropic calls go to example.com, not Mandu's service proxy (http://127.0.0.1:41234)"), "Anthropic calls go to example.com, not Mandu's service proxy");
  assert.equal(routeProblemWords("cannot read /home/u/.openclaw/openclaw.json: ENOENT"), "cannot read openclaw.json: ENOENT");
  assert.equal(routeProblemWords("the Mandu plugin is not in the config"), "the Mandu plugin is not in the config");
  assert.equal(routeProblemWords("cannot read '/home/u/.openclaw/x.json5' (~/.openclaw/inc/a.json)"), "cannot read 'x.json5' (a.json)");
});

test("routeProblemWords: the model fence's words keep their model references whole, and show no path or port (openclaw-plugin.md §3.6)", () => {
  const holes: FenceHole[] = [
    { kind: "fence-gone", names: ["anthropic/*", "openrouter/deepseek/x"] },
    { kind: "fence-unrouted", names: ["mistral/*"] },
    { kind: "openrouter-wildcard", names: ["openrouter/*"] },
    { kind: "openrouter-unlisted", names: ["qwen/qwen3", "openrouter/auto"] },
  ];
  for (const h of holes) {
    const detail = fenceHoleWords(h);
    assert.equal(routeProblemWords(detail), detail, `${h.kind}: nothing to strip, nothing mangled`);
    assert.doesNotMatch(detail, /127\.0\.0\.1|:\d{2,5}\b|\/home\//, h.kind);
  }
  assert.match(routeProblemWords(fenceHoleWords(holes[3]!)), /qwen\/qwen3, openrouter\/auto are named by the config/);
  // On the page: the card names the hole.
  const vm = pluginsPage(facts({ sessions: [session({ route: { state: "lost", problems: holes.map(fenceHoleWords), since: BEGUN } })] }));
  const words = allWords(vm);
  assert.match(words, /names openrouter\/\*, which OpenClaw before 2026\.3\.22 reads as the model/);
  assert.doesNotMatch(words, FORBIDDEN);
});

test("a session with no record gets no session link; its History search stays", () => {
  const card = pluginsPage(facts({ known: new Set() })).hosts[0]!.cards[0]!;
  assert.deepEqual(card.links, { session: null, historyQuery: "OpenClaw" });
});

test("the words: product vocabulary only, never a port, a path or a token, in every state", () => {
  const all = [
    facts(), facts({ sessions: [], live: new Map() }), facts({ serviceRunning: false, sessions: [], live: null }),
    facts({ live: new Map() }), facts({ sessions: [session({ answering: false })] }), facts({ live: null }),
    facts({ sessions: [session({ route: LOST, recorded: { posture: "gated", gap: "model-route-lost" } })] }), facts({ sessions: [session({ declared: false })] }),
    facts({ serviceRunning: false }), facts({ sessions: [session({ answering: false, poolState: "registering" })], live: new Map() }),
  ].map((f) => allWords(pluginsPage(f))).join("\n");
  assert.doesNotMatch(all, FORBIDDEN);
  assert.doesNotMatch(all, /127\.0\.0\.1|:\d{4,5}\b|\/run\/|\.port\b|serve-attachments|\/home\//, "no port, address or path");
  assert.doesNotMatch(JSON.stringify(pluginsPage(facts())), /"port"/, "no port field");
  // The page's own words keep the product's (§4.25u: "masked", "this
  // computer"); the posture sentence is the shared copy's, quoted as the
  // launcher and the doctor say it.
  const sentences = new Set([postureSentence({ posture: "gated", gap: "openclaw-plugin" }), postureSentence({ posture: "gated", gap: "model-route-lost" })]);
  const own = all.split("\n").filter((l) => !sentences.has(l)).join("\n");
  assert.doesNotMatch(own, RETIRED, own.match(RETIRED)?.[0]);
  assert.doesNotMatch(own, THIS_MACHINE);
});

test("the hosts the product knows: OpenClaw only, so no set-up is offered for a host that does not exist yet", () => {
  assert.deepEqual(PLUGIN_HOSTS.map((h) => h.kind), ["openclaw-plugin"]);
  assert.ok(!JSON.stringify(pluginsPage(facts())).includes("OpenShell"));
});

test("the run mark (a Copy on the page, dashboard.md §4.25b): only the stopped service's line, the cost notice's fix and a lost route's fix, never a name or a problem's words", () => {
  /** Every code part of the page, each with its place and whether it is marked. */
  const marked = (vm: ReturnType<typeof pluginsPage>): string[] => {
    const out: string[] = [];
    const sweep = (where: string, parts: readonly { kind: string; text: string; run?: true }[]) => {
      for (const p of parts) if ("run" in p) out.push(`${where}: ${p.text}`);
    };
    sweep("service", vm.service.parts);
    for (const h of vm.hosts) {
      sweep("covers", h.covers);
      for (const c of h.cards) {
        sweep(`card ${c.state}`, c.parts);
        for (const f of c.facts) sweep(`fact ${f.label}`, f.parts);
        if (c.notice) sweep("notice", c.notice.parts);
      }
    }
    return out;
  };
  const NOTICE = ["notice: mandu openclaw gateway", "notice: mandu serve stop", "notice: mandu openclaw uninstall"];
  assert.deepEqual(marked(pluginsPage(facts())), NOTICE, "attached: the cost's fix only");
  assert.deepEqual(marked(pluginsPage(facts({ sessions: [] }))), [], "nothing attached: the set-up's steps are commands of their own (setup.commands)");
  assert.deepEqual(marked(pluginsPage(facts({ sessions: [session({ answering: false })] }))), NOTICE, "down: its mandu serve status stays plain");
  assert.deepEqual(marked(pluginsPage(facts({ serviceRunning: false, sessions: [session({ answering: false })], live: null }))),
    ["service: mandu serve start", "service: mandu serve install"], "stopped: the line's two; the card's own start stays plain");
  assert.deepEqual(marked(pluginsPage(facts({ sessions: [session({ route: LOST, recorded: { posture: "gated", gap: "model-route-lost" } })] }))),
    ["card route-lost: mandu openclaw install", "card route-lost: openclaw gateway restart", "card route-lost: mandu openclaw uninstall", ...NOTICE]);
});
