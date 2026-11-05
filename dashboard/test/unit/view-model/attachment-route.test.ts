/**
 * attachment-route — Home's loud notice when an attached OpenClaw Gateway's
 * config no longer routes through Mandu (src/view-model/attachment-route.ts;
 * docs/design/agents/openclaw-plugin.md §3.6, dashboard.md §4.25 *Home
 * notices*), from the session health the arbiter's posture records give
 * (session-health.ts): the NEWEST believed attachment record stands (a route
 * lost, then back), a claim never moves it, and the card names the session,
 * what changed and the fix, only while the attachment is live, in product
 * words. Axes: secrets (display only; nothing here reads an axis).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveHealth } from "../../../src/session-health.js";
import { homeRouteLost } from "../../../src/view-model/attachment-route.js";
import { toHumanPlaneVM } from "../../../src/view-model/human-plane.js";
import { buildHomeViewModel } from "../../../src/view-model/home.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { ManduEvent } from "../../../src/event-model.js";

const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:/i;
const SESSION = "openclaw:main";
const FULL = { modelContext: "proxy", files: { by: "none", why: "openclaw-plugin" }, exec: "policy", egress: "none", replies: "chat", ownState: "readable" };

let n = 0;
/** A posture record as the arbiter writes it (emitter arbiter, `attachment`). */
function posture(o: { gap?: string; coverage?: Record<string, unknown>; route?: Record<string, unknown>; claimed?: boolean } = {}): ManduEvent {
  n++;
  return {
    id: `e${n}`, sessionId: SESSION, turn: 0, ts: new Date(1_761_000_000_000 + n * 1000).toISOString(), seq: n,
    callId: null, parentId: null, kind: "launch_posture", view: "HumanView", boundary: "model_context",
    emitter: "arbiter", input: null, output: null, invariant: { violatedInvariant: false },
    target: "openclaw", argv0: "openclaw-plugin", live: [], dropped: [],
    secrets: { posture: "gated", gap: o.gap ?? "openclaw-plugin" }, humanPlaneWalled: false,
    attachment: { kind: "openclaw-plugin", coverage: o.coverage ?? FULL },
    ...(o.route ? { attachmentRoute: o.route } : {}),
    ...(o.claimed ? { claimed: true } : {}),
  } as unknown as ManduEvent;
}

const LOST_ROUTE = {
  state: "lost",
  problems: [{ code: "route-elsewhere", detail: "Anthropic calls go to https://evil.example, not Mandu's service proxy (http://127.0.0.1:41234)" }],
  config: "/home/u/.openclaw/openclaw.json",
};
const lost = () => posture({ gap: "model-route-lost", coverage: { ...FULL, modelContext: "none" }, route: LOST_ROUTE });
const back = () => posture({ route: { state: "routed", problems: [], config: LOST_ROUTE.config } });

const LIVE = toHumanPlaneVM({ exposed: true, since: 1, launches: [{ pid: 0, mode: "secrets", posture: "gated", session: SESSION, begunAt: 1, attachment: "openclaw-plugin" }] });

test("session health: the newest believed attachment record stands; its lost route is carried; a claim never moves it", () => {
  const registered = deriveHealth([posture({ route: { state: "routed", problems: [], config: LOST_ROUTE.config } })])!;
  assert.equal(registered.secrets?.gap, "openclaw-plugin");
  assert.equal(registered.attachmentRoute, undefined);

  const h = deriveHealth([posture(), lost()])!;
  assert.equal(h.secrets?.gap, "model-route-lost", "the session page no longer claims the model context is covered");
  assert.match(h.secrets!.sentence, /no longer sends every model call through Mandu/);
  assert.deepEqual(h.attachmentRoute?.problems, LOST_ROUTE.problems);
  assert.equal(h.attachmentRoute?.config, LOST_ROUTE.config);
  assert.ok(typeof h.attachmentRoute?.since === "number");
  assert.equal(h.verdict, "degraded");
  assert.ok(h.reasons.some((r) => /no longer routes this session through Mandu: Anthropic calls go to https:\/\/evil\.example.*mandu openclaw install`, then `openclaw gateway restart/.test(r)));

  // Back: the newer record clears it.
  const b = deriveHealth([posture(), lost(), back()])!;
  assert.equal(b.secrets?.gap, "openclaw-plugin");
  assert.equal(b.attachmentRoute, undefined);

  // A claim (the exposed human socket, the data socket) never clears a believed lost route ...
  const forgedBack = { ...back(), claimed: true } as ManduEvent;
  const c = deriveHealth([posture(), lost(), forgedBack])!;
  assert.equal(c.secrets?.gap, "model-route-lost");
  assert.ok(c.attachmentRoute);
  // ... nor raises one.
  const forgedLost = { ...lost(), claimed: true } as ManduEvent;
  assert.equal(deriveHealth([posture(), forgedLost])!.attachmentRoute, undefined);
});

test("homeRouteLost: one card naming each live session, what changed and the fix; none while routed or ended; product words", () => {
  const session = (events: ManduEvent[]) => ({ id: SESSION, health: deriveHealth(events)! });
  assert.equal(homeRouteLost([session([posture()])], LIVE), null, "routed: no card");
  assert.equal(homeRouteLost([], LIVE), null);
  const card = homeRouteLost([session([posture(), lost()])], LIVE)!;
  assert.equal(card.headline, "Your OpenClaw Gateway's config no longer goes through Mandu.");
  assert.match(card.sentence, /keeps the config it loaded until it restarts/);
  assert.match(card.sentence, /read your secrets as they are/);
  assert.equal(card.items.length, 1);
  const it = card.items[0]!;
  assert.equal(it.session, SESSION);
  assert.deepEqual(it.parts[0], { kind: "code", text: SESSION });
  assert.match(it.words, /^openclaw:main: Anthropic calls go to https:\/\/evil\.example, not Mandu's service proxy \(http:\/\/127\.0\.0\.1:41234\) \(in \/home\/u\/\.openclaw\/openclaw\.json\)$/);
  assert.ok(typeof it.since === "number");
  assert.match(card.fix, /^Run mandu openclaw install in a terminal to write Mandu's route back, then openclaw gateway restart so the Gateway reads it\. Mandu never changes your config by itself\./);
  assert.deepEqual(card.fixParts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"]);
  // Each command is marked to run (the page's Copy, dashboard.md §4.25b); the session and its config file are not.
  assert.deepEqual(card.fixParts.filter((p) => p.kind === "code" && p.run === true).map((p) => p.text), ["mandu openclaw install", "openclaw gateway restart", "mandu openclaw uninstall"]);
  assert.ok(card.fixParts.every((p) => p.kind === "code" || !("run" in p)), "no text part carries the mark");
  assert.deepEqual(it.parts.filter((p) => "run" in p), [], "a session id or a config path is no command");
  for (const copy of [card.headline, card.sentence, card.fix, it.words]) assert.doesNotMatch(copy, FORBIDDEN, copy);

  // Back: gone.
  assert.equal(homeRouteLost([session([posture(), lost(), back()])], LIVE), null);
  // The attachment ended (the human plane lists it no more): its last record says nothing about now.
  assert.equal(homeRouteLost([session([posture(), lost()])], toHumanPlaneVM({ exposed: false, since: null, launches: [] })), null);
  // The human plane unknown: loud anyway (the card does not wait on an answer the page did not get).
  assert.ok(homeRouteLost([session([posture(), lost()])], toHumanPlaneVM(null)));
  assert.ok(homeRouteLost([session([posture(), lost()])]));
});

test("buildHomeViewModel carries the card over every live session, beside the exposure notice", () => {
  const now = Date.parse("2026-10-25T12:00:00Z");
  const s = {
    id: SESSION, label: "", eventCount: 2, agent: "openclaw", status: "running" as const, violated: false,
    // Outside the 24-hour window: a route lost days ago and not fixed is still lost.
    firstTs: new Date(now - 72 * 3_600_000).toISOString(), lastTs: new Date(now - 48 * 3_600_000).toISOString(),
    health: deriveHealth([posture(), lost()])!,
  };
  const snap = { specId: "x", origins: [], tools: [], posture: { integrity: false, confidentiality: true }, verdicts: [] } as never;
  const panel = { ...toPolicyPanelViewModel(snap), humanPlane: LIVE };
  const vm = buildHomeViewModel({ sessions: [s], facts: new Map(), panel, configuredMode: "secrets", nowMs: now, windowHours: 24, historyTotal: 1 } as never);
  assert.ok(vm.routeLost, "the card");
  assert.equal(vm.routeLost!.items[0]!.session, SESSION);
  assert.ok(vm.exposure, "the plugin's exposure notice stays beside it");
  const routed = buildHomeViewModel({ sessions: [{ ...s, health: deriveHealth([posture(), lost(), back()])! }], facts: new Map(), panel, configuredMode: "secrets", nowMs: now, windowHours: 24, historyTotal: 1 } as never);
  assert.equal(routed.routeLost, null);
});
