/**
 * secrets-posture.test — the secret-confinement posture, end to end through
 * the dashboard (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md §3.4;
 * dashboard.md §4.23): a session log whose launcher recorded `gated` reaches
 * /api/sessions as an AMBER health verdict carrying the posture, the one
 * honest sentence, and the upgrade command. The event is built by the
 * LAUNCHER's own `launchPostureEvent`, so the wire shape cannot drift from
 * what a real launch emits. The product page (§4.23 *Product page*): the
 * newest launch's `gated` posture reaches `/api/home` as `secretsPosture`
 * (the card under Home's headline) and a session's own reaches
 * `/api/home/agent`, both with the fix, signed in and signed out; a
 * `confined` launch carries none.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";

let dir: string;
let server: DashboardServer;
let baseUrl: string;
/** Home's newest launch: gated (`gatedHome`), then confined (`confinedHome`). */
let gatedHome: { dir: string; server: DashboardServer; base: string };
let confinedHome: { dir: string; server: DashboardServer; base: string };

const NOTICE = [
  "mandu: secrets are GATED, not confined, on this host.",
  "  Ubuntu restricts unprivileged user namespaces (AppArmor).",
  "  Programs the agent runs can still read your credential files.",
  "  One-time upgrade:  mandu setup   (asks for sudo once)",
  "  Details:           mandu doctor",
].join("\n");

before(async () => {
  dir = tmpDir("mdu-secrets-posture-");
  // Loaded by URL: the launcher is a separate package outside this tsconfig's rootDir.
  const src = new URL("../../../launcher/src/services/observe.ts", import.meta.url).href;
  const { launchPostureEvent } = (await import(src)) as {
    launchPostureEvent: (i: Record<string, unknown>) => Record<string, unknown>;
  };
  // `minutesAgo` moves the launch back in time (the event as written, its ts only).
  const mk = (scopeId: string, notes: string[], secrets: Record<string, string>, minutesAgo = 0): string => {
    const e = launchPostureEvent({ scopeId, tenant: "live", target: "claude", argv0: "claude", notes, secrets });
    if (minutesAgo) e["ts"] = new Date(Date.now() - minutesAgo * 60_000).toISOString();
    return JSON.stringify(e) + "\n";
  };
  writeFileSync(join(dir, "sess-gated.ndjson"),
    mk("sess-gated", ["mandu: fs rung ACTIVE: cooperative", NOTICE], { posture: "gated", gap: "apparmor-userns" }));
  writeFileSync(join(dir, "sess-confined.ndjson"),
    mk("sess-confined", ["mandu: fs rung ACTIVE: cooperative"], { posture: "confined" }));
  server = new DashboardServer({ ...ADMIN_OPTS, source: new FileEventSource(dir), log: () => {}, extensions: [] });
  baseUrl = `http://127.0.0.1:${await server.listen(0)}`;
  const serve = async (files: Record<string, string>): Promise<{ dir: string; server: DashboardServer; base: string }> => {
    const d = tmpDir("mdu-secrets-posture-home-");
    for (const [id, body] of Object.entries(files)) writeFileSync(join(d, `${id}.ndjson`), body);
    const srv = new DashboardServer({ ...ADMIN_OPTS, source: new FileEventSource(d), log: () => {}, extensions: [] });
    return { dir: d, server: srv, base: `http://127.0.0.1:${await srv.listen(0)}` };
  };
  gatedHome = await serve({
    "sess-confined-before": mk("sess-confined-before", ["mandu: fs rung ACTIVE: cooperative"], { posture: "confined" }, 90),
    "sess-gated-now": mk("sess-gated-now", ["mandu: fs rung ACTIVE: cooperative", NOTICE], { posture: "gated", gap: "apparmor-userns" }, 5),
  });
  confinedHome = await serve({
    "sess-gated-before": mk("sess-gated-before", ["mandu: fs rung ACTIVE: cooperative", NOTICE], { posture: "gated", gap: "apparmor-userns" }, 90),
    "sess-confined-now": mk("sess-confined-now", ["mandu: fs rung ACTIVE: cooperative"], { posture: "confined" }, 5),
  });
});

after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
  for (const h of [gatedHome, confinedHome]) {
    await h.server.close();
    rmSync(h.dir, { recursive: true, force: true });
  }
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function read(base: string, path: string, admin: boolean): Promise<any> {
  const r = await fetch(`${base}${path}`, admin ? { headers: CSRF_ADMIN } : {});
  assert.equal(r.status, 200, `${path} (${admin ? "signed in" : "signed out"})`);
  return r.json();
}

/** The card and the line carry the launcher's words and a command: no path,
 *  no credential file, no value. */
function namesNothing(posture: unknown): void {
  assert.doesNotMatch(JSON.stringify(posture), /\/|\.aws|credentials\b|sk_|AKIA/);
}

interface Ref { id: string; health?: { verdict: string; reasons: string[]; secrets?: { posture: string; gap?: string; fix?: string; sentence: string } } }

test("a gated launch reaches /api/sessions as AMBER with the posture, the honest sentence and the upgrade command", async () => {
  const body = (await (await fetch(`${baseUrl}/api/sessions`)).json()) as { sessions: Ref[] };
  const gated = body.sessions.find((s) => s.id === "sess-gated")!;
  assert.ok(gated?.health, "the launcher session is graded");
  assert.equal(gated.health!.verdict, "degraded", "a known host condition is amber, never the red 'broken'");
  assert.equal(gated.health!.secrets?.posture, "gated");
  assert.equal(gated.health!.secrets?.gap, "apparmor-userns");
  assert.equal(gated.health!.secrets?.fix, "mandu setup");
  assert.match(gated.health!.secrets!.sentence, /can still read your credential files/);
  // dashboard.md §4.25d: a rule sends a secret with no question asked.
  assert.match(gated.health!.secrets!.sentence, /a secret is sent out only where a rule or your OK allows/);
  assert.doesNotMatch(gated.health!.secrets!.sentence, /without your OK/);
  assert.doesNotMatch(gated.health!.secrets!.sentence, /absent from the agent's world/, "gated never borrows the confined claim");
  assert.equal(gated.health!.reasons.length, 1, "one plain reason, not the raw multi-line banner as well");

  const confined = body.sessions.find((s) => s.id === "sess-confined")!;
  assert.equal(confined.health!.verdict, "ok");
  assert.equal(confined.health!.secrets?.posture, "confined");
  assert.equal(confined.health!.secrets?.fix, undefined);
});

test("Home: a gated newest launch reaches /api/home as the card's posture with `mandu setup`, signed in and signed out; a newer confined launch, none (§4.23 *Product page*)", async () => {
  for (const admin of [true, false]) {
    const home = await read(gatedHome.base, "/api/home", admin);
    const p = home.secretsPosture;
    assert.ok(p, `the card (${admin ? "signed in" : "signed out"})`);
    assert.equal(p.session, "sess-gated-now", "the newest launch decides");
    assert.equal(p.gap, "apparmor-userns");
    assert.equal(p.headline, "Programs your agent runs can still read your credential files.");
    assert.match(p.sentence, /programs the AI runs can still read your credential files/);
    assert.doesNotMatch(p.sentence, /absent from the agent's world|placeholder copy of each credential file/, "never the confined claim");
    assert.equal(p.fix, "mandu setup");
    assert.deepEqual(p.fixParts.filter((x: { kind: string }) => x.kind === "code").map((x: { text: string }) => x.text), ["mandu setup"]);
    assert.equal(p.note, null);
    namesNothing(p);
    const after = await read(confinedHome.base, "/api/home", admin);
    assert.equal(after.secretsPosture, null, "a confined newest launch: no card");
    assert.equal(home.headline, after.headline, "the headline is the same either way");
  }
});

test("a session's page: a gated launch's own posture with the fix reaches /api/home/agent, signed in and signed out; a confined one's, none (§4.23 *Product page*)", async () => {
  for (const admin of [true, false]) {
    const gated = await read(baseUrl, "/api/home/agent?session=sess-gated", admin);
    assert.equal(gated.found, true);
    assert.equal(gated.secretsPosture?.headline, "Programs this agent ran could read your credential files.");
    assert.equal(gated.secretsPosture?.fix, "mandu setup");
    assert.match(gated.secretsPosture?.sentence, /can still read your credential files/);
    namesNothing(gated.secretsPosture);
    const confined = await read(baseUrl, "/api/home/agent?session=sess-confined", admin);
    assert.equal(confined.found, true);
    assert.equal(confined.secretsPosture, null);
    // An old gated session keeps saying what it ran with after a confined launch.
    const old = await read(confinedHome.base, "/api/home/agent?session=sess-gated-before", admin);
    assert.equal(old.secretsPosture?.gap, "apparmor-userns");
  }
});
