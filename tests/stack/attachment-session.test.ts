/**
 * Stack e2e — an ATTACHMENT session (docs/design/agents/openclaw-plugin.md
 * §3.3, §3.4) over the PRODUCTION wiring: a REAL ArbiterServer with its data
 * and human sockets, the arbiter's own client on each (the registering
 * service on the human socket, the OpenClaw plugin on the data socket), the
 * launcher's coverage row for the plugin (confinement-posture.ts, the
 * producer side), and the dashboard's real event source reading the session
 * back as the session list does (`ArbiterEventSource.listSessions` →
 * `deriveHealth`).
 *
 *   - the plugin (data socket) cannot register an attachment, nor forge the
 *     session's posture record (a forgery written before the registration
 *     stays a claim, and the believed record the arbiter writes wins);
 *   - the service (human socket) registers one: the arbiter decides `gated`
 *     with the gap `openclaw-plugin`, exactly the launcher's
 *     `resolvePosture` over the same coverage, and the session's health shows
 *     that posture with the plugin's own sentence;
 *   - while it is live the human plane is exposed (the dashboard's status
 *     names the attachment) and the seals are void; renewed it stays; ended,
 *     the human socket is believed again.
 *
 * No secret crosses here (the attachment carries none); the invariant this
 * guards is that the posture the user is shown is the arbiter's own and
 * never claims more than the attachment covers. Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ATTACHMENT_COVERAGE, attachmentSessionId, postureSentence, resolvePosture } from "../../launcher/src/confinement-posture.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source/arbiter-source.js";
import { toHumanPlaneVM } from "../../dashboard/src/view-model/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const COVERAGE = ATTACHMENT_COVERAGE["openclaw-plugin"];

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-attach-stack-"));
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, packDir: null,
  });
  await server.listen();
  const service = new ArbiterClient(humanSock); await service.connect();
  const plugin = new ArbiterClient(sock); await plugin.connect();
  const source = new ArbiterEventSource({ socketPath: sock, humanSocketPath: humanSock });
  return {
    service, plugin, source,
    done: async () => { service.close(); plugin.close(); source.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

/** A posture record as a forger would write it: `confined`, no gap. */
function forgedPosture(sessionId: string): Record<string, unknown> {
  return {
    id: `ev_forged_${Math.random().toString(36).slice(2)}`, sessionId, turn: 0, ts: new Date().toISOString(), callId: null, parentId: null,
    kind: "launch_posture", view: "HumanView", boundary: "shell", emitter: "launcher", invariant: { violatedInvariant: false },
    target: "openclaw", argv0: "openclaw", live: ["net-guard"], dropped: [], secrets: { posture: "confined" }, humanPlaneWalled: true,
    input: null, output: null,
  };
}

test("an attachment registered on the human socket reaches the session health as the arbiter decided it; the data socket can neither register one nor forge its posture", async () => {
  const r = await rig();
  try {
    const sid = attachmentSessionId("openclaw-plugin", "main");
    assert.equal(sid, "openclaw:main");

    // The plugin, on the data socket: no registration, and a forged posture
    // written first is only a claim.
    await assert.rejects(r.plugin.beginAttachment({ sessionId: sid, kind: "openclaw-plugin", coverage: COVERAGE }), /human-plane: 'beginAttachment'/);
    await r.plugin.emit(forgedPosture(sid) as never);
    let ref = (await r.source.listSessions()).find((s) => s.id === sid)!;
    assert.equal(ref.health?.secrets?.posture, "confined", "before the registration only the claim exists (and is shown as before)");

    // The service, on the human socket: registered, gated, the launcher's own decision.
    const want = resolvePosture(COVERAGE);
    assert.deepEqual(want, { posture: "gated", gap: "openclaw-plugin" });
    const reg = await r.service.beginAttachment({ sessionId: sid, kind: "openclaw-plugin", coverage: COVERAGE });
    assert.equal(reg.posture, want.posture);
    assert.equal(reg.gap, want.gap);
    assert.equal(reg.believed, true);

    // After it, a forged posture is refused on the data socket and on the
    // (now exposed) human socket.
    await assert.rejects(r.plugin.emit(forgedPosture(sid) as never), /is an attachment session/);
    await assert.rejects(r.service.emit(forgedPosture(sid) as never), /is an attachment session/);

    // The session list's health: the arbiter's believed record wins over the claim.
    ref = (await r.source.listSessions()).find((s) => s.id === sid)!;
    assert.ok(ref.health, "the session is graded");
    assert.equal(ref.health!.verdict, "degraded", "gated is amber");
    assert.deepEqual(ref.health!.secrets, { posture: "gated", gap: "openclaw-plugin", sentence: postureSentence(want) });
    assert.doesNotMatch(ref.health!.secrets!.sentence, /sent out only where/, "no egress promise the plugin does not keep");
    assert.equal(ref.agent, "openclaw");
    const events = await r.source.readEvents(sid);
    const postures = events.filter((e) => e.kind === "launch_posture");
    assert.deepEqual(postures.map((e) => [e.emitter, e.claimed === true]), [["launcher", true], ["arbiter", false]]);

    // While it is live: the human plane is exposed, named as the attachment;
    // the seals are void.
    const st = await r.source.humanPlaneStatus();
    assert.equal(st.exposed, true);
    assert.deepEqual(st.launches.map((l) => [l.pid, l.session, l.attachment]), [[0, sid, "openclaw-plugin"]]);
    assert.match(JSON.stringify(toHumanPlaneVM(st).detail), /Mandu's plugin in an OpenClaw Gateway, session openclaw:main/);
    assert.equal((await r.service.cacheSeals("object-twin", [])).honoured, false);

    // The plugin cannot end it or keep it alive.
    await assert.rejects(r.plugin.endAttachment(reg.token), /human-plane: 'endAttachment'/);
    await assert.rejects(r.plugin.renewAttachment(reg.token), /human-plane: 'renewAttachment'/);
    assert.equal((await r.service.renewAttachment(reg.token)).renewed, true);

    // Ended by the service: walled again, believed again.
    assert.equal((await r.service.endAttachment(reg.token)).ended, true);
    const after = await r.source.humanPlaneStatus();
    assert.equal(after.exposed, false);
    assert.equal((await r.service.cacheSeals("object-twin", [])).honoured, true);
  } finally {
    await r.done();
  }
});
