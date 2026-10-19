/**
 * secrets-posture.test — the secret-confinement posture, end to end through
 * the dashboard (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md §3.4;
 * dashboard.md §4.23): a session log whose launcher recorded `gated` reaches
 * /api/sessions as an AMBER health verdict carrying the posture, the one
 * honest sentence, and the upgrade command. The event is built by the
 * LAUNCHER's own `launchPostureEvent`, so the wire shape cannot drift from
 * what a real launch emits.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { tmpDir } from "../unit/tmp-dir.js";

let dir: string;
let server: DashboardServer;
let baseUrl: string;

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
  const mk = (scopeId: string, notes: string[], secrets: Record<string, string>): string =>
    JSON.stringify(launchPostureEvent({ scopeId, tenant: "live", target: "claude", argv0: "claude", notes, secrets })) + "\n";
  writeFileSync(join(dir, "sess-gated.ndjson"),
    mk("sess-gated", ["mandu: fs rung ACTIVE: cooperative", NOTICE], { posture: "gated", gap: "apparmor-userns" }));
  writeFileSync(join(dir, "sess-confined.ndjson"),
    mk("sess-confined", ["mandu: fs rung ACTIVE: cooperative"], { posture: "confined" }));
  server = new DashboardServer({ source: new FileEventSource(dir), log: () => {} });
  baseUrl = `http://127.0.0.1:${await server.listen(0)}`;
});

after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

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
