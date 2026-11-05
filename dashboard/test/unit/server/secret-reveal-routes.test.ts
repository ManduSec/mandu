/**
 * secret-reveal-routes.test — POST /api/home/reveal, the product page's
 * "Show the real value" (src/server/secret-reveal-routes.ts; dashboard.md
 * §4.25b "Showing a real value").
 *
 * A real DashboardServer on an ephemeral port over a fake source whose
 * session recorded a secret twin, an ordinary masked item and (claimed, on
 * the agent's channel) another secret. Pins:
 *   - the gate: no CSRF header → 403; the header without the admin session
 *     (what any same-host process can send) → 403 ADMIN_SESSION_REQUIRED;
 *   - signed in, the ref of a secret the session recorded → its value only;
 *   - never a general desymbolize: an ordinary item's ref, another
 *     session's ref, a claimed event's token, an unknown or malformed ref
 *     resolve nothing, and the source is asked for no other token;
 *   - no source to ask → 501; the source not holding it → 404;
 *   - an attachment session (§4.25aj): its own proxy's claimed record of a
 *     masked read is revealable once the arbiter's believed registration
 *     says it is one; a forged registration widens nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer, ADMIN_SESSION_REQUIRED } from "../../../src/server.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import { isAttachmentSession, revealScopeEvents, type ManduEvent } from "../../../src/event-model.js";
import { secretRef } from "../../../src/view-model/secret-ref.js";
import { revealableSecrets } from "../../../src/view-model/agent-page.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../admin-session.js";

const SESSION = "1791200000-1";
const TWIN = "$MDU:nomodel_Read[3fa9].PASTE_KEY";
const PLAIN = "$MDU:Read[d4d4]";
const CLAIMED = "$MDU:nomodel_Read[7777].OTHER";
const VALUES: Record<string, string> = { [TWIN]: "pk-live-123", [PLAIN]: "hello", [CLAIMED]: "claimed-secret" };

function ev(id: string, seq: number, symbols: string[], over: Partial<ManduEvent> = {}): ManduEvent {
  return {
    id, sessionId: SESSION, turn: 1, ts: `2026-10-05T10:00:0${seq}.000Z`, seq, callId: "c1", parentId: null,
    kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", input: null,
    output: { symbolized: symbols.join(" "), original: null, differs: true, symbols: symbols.map((name) => ({ name, tool: "Read", field: null, origin: "/w/.env", value: null })) },
    invariant: { violatedInvariant: false }, ...over,
  } as ManduEvent;
}

const EVENTS: ManduEvent[] = [
  ev("e1", 1, [TWIN, PLAIN]),
  ev("e2", 2, [CLAIMED], { claimed: true }),
];

function fakeSource(withDesymbolize = true): { source: EventSource; asked: string[] } {
  const asked: string[] = [];
  const source: EventSource = {
    async listSessions(): Promise<SessionRef[]> { return []; },
    async readEvents(id: string): Promise<ManduEvent[]> { return id === SESSION ? EVENTS : []; },
    subscribe(): () => void { return () => {}; },
    close(): void {},
    ...(withDesymbolize ? { async desymbolize(text: string): Promise<string> { asked.push(text); return VALUES[text] ?? text; } } : {}),
  };
  return { source, asked };
}

async function start(withDesymbolize = true) {
  const f = fakeSource(withDesymbolize);
  const server = new DashboardServer({ source: f.source, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const post = (body: unknown, headers: Record<string, string> = CSRF_ADMIN) =>
    fetch(`http://127.0.0.1:${port}/api/home/reveal`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { ...f, post, close: () => server.close() };
}

test("revealableSecrets: the session's recorded secret tokens only (twins, not an ordinary item)", () => {
  const names = revealableSecrets(toSessionViewModel(SESSION, [EVENTS[0]!]));
  assert.deepEqual([...names], [TWIN]);
  assert.match(secretRef(SESSION, TWIN), /^[0-9a-f]{24}$/);
  assert.notEqual(secretRef(SESSION, TWIN), secretRef("other", TWIN), "a ref is per session");
});

test("the gate: no CSRF header, or the header without the admin session, is refused", async () => {
  const h = await start();
  try {
    const ref = secretRef(SESSION, TWIN);
    assert.equal((await h.post({ session: SESSION, ref }, {})).status, 403);
    const noSession = await h.post({ session: SESSION, ref }, { "X-Mandu-Control": "1" });
    assert.equal(noSession.status, 403);
    assert.equal(((await noSession.json()) as { error: string }).error, ADMIN_SESSION_REQUIRED);
    assert.deepEqual(h.asked, [], "the source was never asked");
  } finally {
    await h.close();
  }
});

test("signed in: a recorded secret's ref shows its value, and only that token is asked", async () => {
  const h = await start();
  try {
    const res = await h.post({ session: SESSION, ref: secretRef(SESSION, TWIN) });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { value: "pk-live-123" });
    assert.deepEqual(h.asked, [TWIN]);
  } finally {
    await h.close();
  }
});

test("never a general desymbolize: an ordinary item, another session, a claimed token, unknown or malformed refs", async () => {
  const h = await start();
  try {
    for (const body of [
      { session: SESSION, ref: secretRef(SESSION, PLAIN) },
      { session: SESSION, ref: secretRef("another-session", TWIN) },
      { session: "another-session", ref: secretRef("another-session", TWIN) },
      { session: SESSION, ref: secretRef(SESSION, CLAIMED) },
      { session: SESSION, ref: "0".repeat(24) },
    ]) {
      const res = await h.post(body);
      assert.equal(res.status, 404, JSON.stringify(body));
    }
    for (const body of [{ session: SESSION }, { session: SESSION, ref: TWIN }, { ref: secretRef(SESSION, TWIN) }, { session: SESSION, ref: "ABC" }]) {
      assert.equal((await h.post(body)).status, 400, JSON.stringify(body));
    }
    assert.deepEqual(h.asked, [], "no token was ever sent to the source");
  } finally {
    await h.close();
  }
});

test("no source to ask → 501", async () => {
  const h = await start(false);
  try {
    assert.equal((await h.post({ session: SESSION, ref: secretRef(SESSION, TWIN) })).status, 501);
  } finally {
    await h.close();
  }
});

// ── An attachment session (dashboard.md §4.25aj, event-model.ts revealScopeEvents) ──

const PLUGIN = "openclaw:main";
/** The arbiter's own record of the registration (openclaw-plugin.md §3.3). */
const registration = (over: Record<string, unknown> = {}): ManduEvent => ({
  id: "ev-att", sessionId: PLUGIN, turn: 0, ts: "2026-10-25T09:00:00.000Z", seq: 0, callId: null, parentId: null,
  kind: "launch_posture", view: "HumanView", boundary: "shell", emitter: "arbiter", input: null, output: null,
  invariant: { violatedInvariant: false }, target: "openclaw", secrets: { posture: "gated", gap: "openclaw-plugin" }, humanPlaneWalled: false,
  attachment: { kind: "openclaw-plugin", coverage: {} }, ...over,
} as unknown as ManduEvent);
/** Its proxy's record of a masked read: a claim, as every one is while the attachment holds the plane exposed. */
const pluginRead = ev("p1", 1, [TWIN], { sessionId: PLUGIN, claimed: true });

async function startWith(events: ManduEvent[]) {
  const asked: string[] = [];
  const source: EventSource = {
    async listSessions(): Promise<SessionRef[]> { return []; },
    async readEvents(id: string): Promise<ManduEvent[]> { return id === PLUGIN ? events : []; },
    subscribe(): () => void { return () => {}; },
    close(): void {},
    async desymbolize(text: string): Promise<string> { asked.push(text); return VALUES[text] ?? text; },
  };
  const server = new DashboardServer({ source, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const post = (body: unknown) => fetch(`http://127.0.0.1:${port}/api/home/reveal`, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { asked, post, close: () => server.close() };
}

test("an attachment session: its own proxy's claimed record of a masked read is revealable, signed in (the arbiter's believed registration says what the session is)", async () => {
  assert.equal(isAttachmentSession([registration(), pluginRead]), true);
  assert.deepEqual(revealScopeEvents([registration(), pluginRead]).map((e) => e.id), ["ev-att", "p1"]);
  const h = await startWith([registration(), pluginRead]);
  try {
    const res = await h.post({ session: PLUGIN, ref: secretRef(PLUGIN, TWIN) });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { value: "pk-live-123" });
    assert.deepEqual(h.asked, [TWIN], "that one token only");
    // Still never a general desymbolize: an ordinary item, another session's ref.
    assert.equal((await h.post({ session: PLUGIN, ref: secretRef(PLUGIN, PLAIN) })).status, 404);
    assert.equal((await h.post({ session: PLUGIN, ref: secretRef(SESSION, TWIN) })).status, 404);
  } finally {
    await h.close();
  }
});

test("not an attachment session: a registration record that is a claim, or not the arbiter's, or names no attachment, widens nothing", async () => {
  for (const forged of [registration({ claimed: true }), registration({ emitter: "launcher" }), registration({ attachment: undefined })]) {
    assert.equal(isAttachmentSession([forged, pluginRead]), false);
    assert.deepEqual(revealScopeEvents([forged, pluginRead]).map((e) => e.id), forged.claimed ? [] : ["ev-att"]);
    const h = await startWith([forged, pluginRead]);
    try {
      assert.equal((await h.post({ session: PLUGIN, ref: secretRef(PLUGIN, TWIN) })).status, 404, JSON.stringify({ emitter: forged.emitter, claimed: forged.claimed }));
      assert.deepEqual(h.asked, []);
    } finally {
      await h.close();
    }
  }
});
