/**
 * config-axes-routes.test — offline unit tests for GET|POST /api/config/axes
 * (the Protection drawer's durable axis setup, dashboard.md §4.19 ②), thin
 * over src/config-axes.ts.
 *
 * Mandu-new test (NO reference origin). A real DashboardServer on an
 * ephemeral port with its `configEnv` TEST SEAM pinning MANDU_HOME at a
 * per-test temp path (no process.env mutation), driven with `fetch` (mirrors
 * egress-approvals-routes.test.ts). No arbiter surface at all — the config
 * routes must work exactly when the arbiter is down for the restart the edit
 * is about.
 *
 * It pins:
 *   - GET serves the §4.19 frozen shape on a missing file (exists:false, all
 *     nulls, effective = arbiter defaults) and after writes;
 *   - POST without X-Mandu-Control → 403, no file appears;
 *   - POST rejects non-boolean values and an empty act with 400 (no coercion);
 *   - POST creates file+dir, edits surgically (unrelated bytes verbatim),
 *     answers with the GET shape;
 *   - an unresolvable config path → 500, never a lying 200;
 *   - the §4.19 config_change AUDIT TRAIL over an in-process fake
 *     ConfigAuditArbiter: one event per FLIPPED effective value (arbiter-admin
 *     stream, top-level axis/from/to/requestedBy scalars), an explicit-default
 *     write emits nothing (applied-only discipline), an emit/events failure
 *     never fails the route, and GET/POST answers carry the latest-per-axis
 *     `audit` attribution;
 *   - THE INTEGRITY FREEZE (docs/design/architecture/protection-modes.md §10): without
 *     MANDU_EXPERIMENTAL_INTEGRITY in the dashboard's env, a write whose
 *     resulting pair leaves integrity ON (mode injection/full, integrity:true,
 *     or a confidentiality flip while integrity is on) → 403 {frozen:true},
 *     nothing written, nothing emitted; turning it off is always allowed; the
 *     GET carries `integrityAllowed`. Suites that exercise the frozen modes
 *     pass the opt-in by name (OPT_IN).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  DashboardServer,
  type ConfigAuditArbiter,
  type DashboardServerOptions,
  type AxesStateWithAudit,
} from "../../../src/server.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../admin-session.js";
import {
  AXIS_DEFAULTS,
  DEFAULT_MODE,
  MODES,
  MODE_AXES,
  MODE_PROVENANCE_COMMENT,
  PRODUCT_MODES,
  PROVENANCE_COMMENT,
  INTEGRITY_OPT_IN_ENV,
  modeOf,
  type AxesState,
  type Mode,
} from "../../../src/config-axes.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { tmpDir } from "../tmp-dir.js";

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> {
    return [];
  },
  async readEvents(): Promise<ManduEvent[]> {
    return [];
  },
  subscribe(): () => void {
    return () => {};
  },
  close(): void {},
};

interface Harness {
  baseUrl: string;
  dir: string;
  configPath: string;
  close(): Promise<void>;
}

/** The dashboard env that opts into the FROZEN integrity axis. */
const OPT_IN = { [INTEGRITY_OPT_IN_ENV]: "1" };

async function startServer(
  extra: Partial<DashboardServerOptions> = {},
  env: Record<string, string> = {},
): Promise<Harness> {
  const dir = tmpDir("mandu-axes-routes-");
  const configPath = join(dir, "mandu", "config.toml");
  const server = new DashboardServer({
    source: fakeSource,
    configEnv: { MANDU_HOME: join(dir, "mandu"), ...env },
    log: () => {},
    ...ADMIN_OPTS,
    ...extra,
  });
  const port = await server.listen(0);
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    dir,
    configPath,
    close: async () => {
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

const CSRF = { "X-Mandu-Control": "1", "Content-Type": "application/json", Cookie: ADMIN_COOKIE };

/** In-memory ConfigAuditArbiter fake: `store` is the arbiter-admin stream (the
 *  emitted events, in order); the fail flags simulate a dying connection on
 *  either op independently. */
function fakeAudit(): {
  store: Record<string, unknown>[];
  surface: ConfigAuditArbiter;
  fail: { emit: boolean; events: boolean };
} {
  const store: Record<string, unknown>[] = [];
  const fail = { emit: false, events: false };
  return {
    store,
    fail,
    surface: {
      async emit(event) {
        if (fail.emit) throw new Error("emit down");
        store.push(event);
        return store.length;
      },
      async events(sessionId) {
        if (fail.events) throw new Error("events down");
        return sessionId === "arbiter-admin" ? [...store] : [];
      },
    },
  };
}

// ── tests ─────────────────────────────────────────────────────────────────────

test("GET /api/config/axes on a missing file → the frozen shape with arbiter defaults", async () => {
  const h = await startServer();
  try {
    const res = await fetch(`${h.baseUrl}/api/config/axes`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as AxesState;
    assert.deepEqual(body, {
      ok: true,
      path: h.configPath,
      exists: false,
      configured: { integrity: null, confidentiality: null },
      defaults: { ...AXIS_DEFAULTS },
      effective: { ...AXIS_DEFAULTS },
      // The additive mode fields (protection-modes.md §3.3): no `mode` key in
      // a missing file, no badMode, and the default named by the SERVER.
      mode: null,
      effectiveMode: DEFAULT_MODE,
      defaultMode: DEFAULT_MODE,
      // The frozen integrity axis: no opt-in in this dashboard's env.
      integrityAllowed: false,
    });
  } finally {
    await h.close();
  }
});

test("POST without X-Mandu-Control → 403 and NO file is created", async () => {
  const h = await startServer();
  try {
    const res = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confidentiality: true }),
    });
    assert.equal(res.status, 403);
    assert.match(((await res.json()) as { error: string }).error, /X-Mandu-Control/);
    assert.equal(existsSync(h.configPath), false, "the config was never written");
  } finally {
    await h.close();
  }
});

test("POST rejects non-boolean values and an empty act with 400 (a value is never coerced)", async () => {
  const h = await startServer();
  try {
    for (const bad of [{ integrity: "true" }, { confidentiality: 1 }, { integrity: null }]) {
      const res = await fetch(`${h.baseUrl}/api/config/axes`, {
        method: "POST",
        headers: CSRF,
        body: JSON.stringify(bad),
      });
      assert.equal(res.status, 400, `${JSON.stringify(bad)} must be rejected`);
      assert.match(((await res.json()) as { error: string }).error, /must be a boolean/);
    }
    // Neither key present is not a configuration act.
    const empty = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST",
      headers: CSRF,
      body: JSON.stringify({ "reply-filter": false }),
    });
    assert.equal(empty.status, 400);
    assert.match(((await empty.json()) as { error: string }).error, /at least one of/);
    // Unparseable JSON body.
    const unparseable = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST",
      headers: CSRF,
      body: "{nope",
    });
    assert.equal(unparseable.status, 400);
    assert.equal(existsSync(h.configPath), false, "nothing was written by any rejected act");
  } finally {
    await h.close();
  }
});

test("POST creates file+parent dir, appends under the provenance comment, answers the GET shape", async () => {
  const h = await startServer();
  try {
    const res = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST",
      headers: CSRF,
      body: JSON.stringify({ confidentiality: true }),
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as AxesState;
    assert.equal(body.ok, true);
    assert.equal(body.exists, true);
    assert.deepEqual(body.configured, { integrity: null, confidentiality: true });
    // The unconfigured axis falls to the built-in default (derived, never
    // hardcoded here: the default moved to `secrets` on 2026-09-21).
    assert.deepEqual(body.effective, { integrity: AXIS_DEFAULTS.integrity, confidentiality: true });
    assert.equal(
      readFileSync(h.configPath, "utf8"),
      `${PROVENANCE_COMMENT}\nconfidentiality = true\n`,
      "bare TOML boolean under the one provenance comment line",
    );

    // A fresh GET agrees with the POST's answer.
    const again = (await (await fetch(`${h.baseUrl}/api/config/axes`)).json()) as AxesState;
    assert.deepEqual(again, body);
  } finally {
    await h.close();
  }
});

test("POST edits an existing hand-written file SURGICALLY — every other byte verbatim", async () => {
  const h = await startServer();
  try {
    // Seed a hand-written file at the pinned path.
    const hand = "# hand-written\nnet-guard = true\nintegrity = true # keep on\n# tail\n";
    mkdirSync(join(h.dir, "mandu"), { recursive: true });
    writeFileSync(h.configPath, hand);

    const res = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST",
      headers: CSRF,
      body: JSON.stringify({ integrity: false }),
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as AxesState;
    assert.equal(body.configured.integrity, false);
    assert.equal(body.effective.integrity, false);
    assert.equal(
      readFileSync(h.configPath, "utf8"),
      "# hand-written\nnet-guard = true\nintegrity = false  # keep on\n# tail\n",
      "only the managed line changed (inline comment kept); every other byte identical",
    );
  } finally {
    await h.close();
  }
});

// ── the §4.19 config_change audit trail ──────────────────────────────────────

test("POST with a connected arbiter emits one config_change per FLIPPED axis and answers the attribution", async () => {
  const audit = fakeAudit();
  const h = await startServer({ auditArbiter: audit.surface });
  try {
    // Pin the prior state explicitly (independent of which mode is the
    // built-in default): integrity on, confidentiality off. The act flips BOTH.
    mkdirSync(join(h.dir, "mandu"), { recursive: true });
    writeFileSync(h.configPath, "integrity = true\nconfidentiality = false\n");
    const res = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST",
      headers: CSRF,
      body: JSON.stringify({ integrity: false, confidentiality: true }),
    });
    assert.equal(res.status, 200);

    assert.equal(audit.store.length, 2, "one event per flipped axis");
    for (const ev of audit.store) {
      assert.equal(ev["kind"], "config_change");
      assert.equal(ev["sessionId"], "arbiter-admin", "the reserved arbiter-global audit stream");
      assert.equal(ev["emitter"], "dashboard");
      assert.equal(ev["requestedBy"], "dashboard");
      assert.equal(ev["view"], "HumanView");
      const input = ev["input"] as Record<string, unknown>;
      assert.equal(input["original"], null, "a config act carries no raw value to redact");
    }
    const byAxis = new Map(audit.store.map((ev) => [ev["axis"], ev]));
    assert.deepEqual(
      { from: byAxis.get("integrity")?.["from"], to: byAxis.get("integrity")?.["to"] },
      { from: true, to: false },
      "integrity flipped off — the top-level SIEM scalars say so",
    );
    assert.deepEqual(
      { from: byAxis.get("confidentiality")?.["from"], to: byAxis.get("confidentiality")?.["to"] },
      { from: false, to: true },
    );

    // The answer already carries the who/when attribution per axis.
    const body = (await res.json()) as AxesStateWithAudit;
    assert.equal(body.audit?.integrity?.to, false);
    assert.equal(body.audit?.integrity?.requestedBy, "dashboard");
    assert.equal(body.audit?.confidentiality?.to, true);
    assert.equal(typeof body.audit?.integrity?.ts, "string");
  } finally {
    await h.close();
  }
});

test("a write that does NOT flip the effective value emits NOTHING (applied-only discipline)", async () => {
  const audit = fakeAudit();
  const h = await startServer({ auditArbiter: audit.surface });
  try {
    // The key is absent → the default rules. Making that default explicit is
    // a config act but not an applied change.
    const res = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST",
      headers: CSRF,
      body: JSON.stringify({ confidentiality: AXIS_DEFAULTS.confidentiality }),
    });
    assert.equal(res.status, 200);
    assert.equal(audit.store.length, 0, "no effective flip → no audit event");
    const body = (await res.json()) as AxesStateWithAudit;
    assert.equal(body.configured.confidentiality, AXIS_DEFAULTS.confidentiality, "the file write itself still happened");
    assert.equal(body.audit, undefined, "an empty stream never invents an attribution");
  } finally {
    await h.close();
  }
});

test("an emit failure is audit-only — the POST still answers 200 with the applied state", async () => {
  const audit = fakeAudit();
  audit.fail.emit = true;
  const h = await startServer({ auditArbiter: audit.surface });
  try {
    const res = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST",
      headers: CSRF,
      body: JSON.stringify({ integrity: false }),
    });
    assert.equal(res.status, 200, "the config write is the act; the event is only its record");
    const body = (await res.json()) as AxesStateWithAudit;
    assert.equal(body.effective.integrity, false);
    assert.equal(audit.store.length, 0);
  } finally {
    await h.close();
  }
});

test("GET carries the LATEST attribution per axis; an events failure yields the plain shape", async () => {
  const audit = fakeAudit();
  // Turning integrity back ON is the frozen act: this dashboard opted in.
  const h = await startServer({ auditArbiter: audit.surface }, OPT_IN);
  try {
    // Two acts on integrity: off, then back on — the newer one wins.
    for (const to of [false, true]) {
      const res = await fetch(`${h.baseUrl}/api/config/axes`, {
        method: "POST",
        headers: CSRF,
        body: JSON.stringify({ integrity: to }),
      });
      assert.equal(res.status, 200);
    }
    const get = (await (await fetch(`${h.baseUrl}/api/config/axes`)).json()) as AxesStateWithAudit;
    assert.deepEqual(
      { from: get.audit?.integrity?.from, to: get.audit?.integrity?.to },
      { from: false, to: true },
      "the LATEST config_change attributes the axis",
    );
    assert.equal(get.audit?.confidentiality, undefined, "an axis with no act carries no claim");

    audit.fail.events = true;
    const plain = (await (await fetch(`${h.baseUrl}/api/config/axes`)).json()) as AxesStateWithAudit;
    assert.equal(plain.ok, true, "the axes facts are the point; the attribution is garnish");
    assert.equal(plain.audit, undefined);
  } finally {
    await h.close();
  }
});

test("an unresolvable config path (neither MANDU_HOME nor HOME) → GET serves nulls, POST → 500", async () => {
  const server = new DashboardServer({ source: fakeSource, configEnv: {}, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  try {
    const get = await fetch(`${base}/api/config/axes`);
    assert.equal(get.status, 200);
    const body = (await get.json()) as AxesState;
    assert.equal(body.path, null);
    assert.equal(body.exists, false);

    const post = await fetch(`${base}/api/config/axes`, {
      method: "POST",
      headers: CSRF,
      body: JSON.stringify({ integrity: false }),
    });
    assert.equal(post.status, 500);
    assert.match(((await post.json()) as { error: string }).error, /cannot resolve the config path/);
  } finally {
    await server.close();
  }
});

// ── the four MODES over the same route (protection-modes.md §3.3) ────────────

async function postAxes(h: Harness, body: unknown): Promise<Response> {
  return fetch(`${h.baseUrl}/api/config/axes`, { method: "POST", headers: CSRF, body: JSON.stringify(body) });
}

test("POST {mode} validates: unknown / non-string / case-variant names → 400, a mode mixed with axis keys → 400; nothing is written", async () => {
  const h = await startServer();
  try {
    for (const bad of [
      { mode: "paranoid" }, { mode: "Full" }, { mode: "" }, { mode: true }, { mode: null }, { mode: ["full"] },
      { mode: "full", integrity: true }, { mode: "secrets", confidentiality: false },
    ]) {
      const res = await postAxes(h, bad);
      assert.equal(res.status, 400, JSON.stringify(bad));
      assert.equal(typeof ((await res.json()) as { error: string }).error, "string");
    }
    assert.equal(existsSync(h.configPath), false, "a refused act writes nothing");
  } finally {
    await h.close();
  }
});

test("POST {mode} without the CSRF header → 403, no file", async () => {
  const h = await startServer();
  try {
    const res = await fetch(`${h.baseUrl}/api/config/axes`, {
      method: "POST", headers: { "Content-Type": "application/json", Cookie: ADMIN_COOKIE },
      body: JSON.stringify({ mode: "off" }),
    });
    assert.equal(res.status, 403);
    assert.equal(existsSync(h.configPath), false);
  } finally {
    await h.close();
  }
});

test("POST {mode} writes through applyModeEdit and answers the GET shape, for all four modes (opted in)", async () => {
  const h = await startServer({}, OPT_IN);
  try {
    for (const m of MODES) {
      const res = await postAxes(h, { mode: m });
      assert.equal(res.status, 200);
      const body = (await res.json()) as AxesState;
      assert.equal(body.mode, m);
      assert.equal(body.effectiveMode, m);
      assert.equal(body.defaultMode, DEFAULT_MODE);
      assert.deepEqual(body.effective, MODE_AXES[m]);
      assert.deepEqual(body.configured, { integrity: null, confidentiality: null },
        "a mode write never APPENDS axis lines");
      const got = (await (await fetch(`${h.baseUrl}/api/config/axes`)).json()) as AxesState;
      assert.deepEqual(got, body, "GET agrees with the POST echo");
    }
    assert.equal(readFileSync(h.configPath, "utf8"), `${MODE_PROVENANCE_COMMENT}\nmode = "off"\n`,
      "one comment, one mode line, replaced in place across the four writes");
  } finally {
    await h.close();
  }
});

test("POST {mode} re-aligns EXISTING axis lines and keeps every other byte", async () => {
  const h = await startServer();
  try {
    mkdirSync(join(h.dir, "mandu"), { recursive: true });
    writeFileSync(h.configPath, "# mine\nproxy-port = 0\nintegrity = true  # paper\n");
    const res = await postAxes(h, { mode: "secrets" });
    assert.equal(res.status, 200);
    assert.equal(readFileSync(h.configPath, "utf8"),
      `# mine\nproxy-port = 0\nintegrity = false  # paper\n\n${MODE_PROVENANCE_COMMENT}\nmode = "secrets"\n`);
    const body = (await res.json()) as AxesState;
    assert.deepEqual(body.configured, { integrity: false, confidentiality: null });
    assert.equal(body.effectiveMode, "secrets");
  } finally {
    await h.close();
  }
});

test("a mode write emits one config_change per FLIPPED axis (effective before vs after), none for an unflipped one", async () => {
  const audit = fakeAudit();
  const h = await startServer({ auditArbiter: audit.surface }, OPT_IN);
  try {
    mkdirSync(join(h.dir, "mandu"), { recursive: true });
    writeFileSync(h.configPath, 'mode = "full"\n');
    // full → secrets flips integrity ONLY.
    assert.equal((await postAxes(h, { mode: "secrets" })).status, 200);
    assert.deepEqual(audit.store.map((e) => [e["axis"], e["from"], e["to"]]), [["integrity", true, false]]);
    // secrets → injection flips BOTH.
    assert.equal((await postAxes(h, { mode: "injection" })).status, 200);
    assert.deepEqual(audit.store.slice(1).map((e) => [e["axis"], e["from"], e["to"]]),
      [["integrity", false, true], ["confidentiality", true, false]]);
    // The same mode again: no flip, no event.
    const res = await postAxes(h, { mode: "injection" });
    assert.equal(audit.store.length, 3);
    for (const ev of audit.store) {
      assert.equal(ev["kind"], "config_change");
      assert.equal(ev["sessionId"], "arbiter-admin");
      assert.equal(ev["requestedBy"], "dashboard");
    }
    const body = (await res.json()) as AxesStateWithAudit;
    assert.equal(body.audit?.confidentiality?.to, false, "the answer attributes the latest act per axis");
  } finally {
    await h.close();
  }
});

test("a mode write that only makes the running default explicit emits NOTHING", async () => {
  const audit = fakeAudit();
  const h = await startServer({ auditArbiter: audit.surface });
  try {
    assert.equal((await postAxes(h, { mode: DEFAULT_MODE })).status, 200);
    assert.equal(audit.store.length, 0);
  } finally {
    await h.close();
  }
});

test("a single-axis write on a file WITH a mode line rewrites that line to the resulting pair (one event, the named axis)", async () => {
  const audit = fakeAudit();
  const h = await startServer({ auditArbiter: audit.surface });
  try {
    mkdirSync(join(h.dir, "mandu"), { recursive: true });
    writeFileSync(h.configPath, 'mode = "full"  # picked\n');
    const res = await postAxes(h, { integrity: false });
    assert.equal(res.status, 200);
    const body = (await res.json()) as AxesState;
    assert.equal(body.mode, "secrets", "the mode line now names the pair that runs");
    assert.equal(body.effectiveMode, "secrets");
    assert.equal(body.mode, modeOf(body.effective) as Mode, "the file never contradicts itself");
    const text = readFileSync(h.configPath, "utf8");
    assert.match(text, /^mode = "secrets" {2}# picked$/m);
    assert.match(text, /^integrity = false$/m);
    assert.deepEqual(audit.store.map((e) => [e["axis"], e["from"], e["to"]]), [["integrity", true, false]]);
  } finally {
    await h.close();
  }
});

test("GET reports an invalid file mode as badMode and ignores it; a mode + axis conflict resolves per axis", async () => {
  const h = await startServer();
  try {
    mkdirSync(join(h.dir, "mandu"), { recursive: true });
    writeFileSync(h.configPath, 'mode = "paranoid"\n');
    let body = (await (await fetch(`${h.baseUrl}/api/config/axes`)).json()) as AxesState;
    assert.equal(body.mode, null);
    assert.equal(body.badMode, "paranoid");
    assert.equal(body.effectiveMode, DEFAULT_MODE);

    writeFileSync(h.configPath, 'mode = "full"\nconfidentiality = false\n');
    body = (await (await fetch(`${h.baseUrl}/api/config/axes`)).json()) as AxesState;
    assert.equal(body.mode, "full");
    assert.equal(body.badMode, undefined);
    assert.deepEqual(body.effective, { integrity: true, confidentiality: false });
    assert.equal(body.effectiveMode, "injection");
  } finally {
    await h.close();
  }
});

// ── the integrity freeze (docs/design/architecture/protection-modes.md §10) ───────────────────

test("freeze: without the opt-in, every write that leaves integrity ON → 403 {frozen}; nothing written, nothing emitted", async () => {
  const audit = fakeAudit();
  const h = await startServer({ auditArbiter: audit.surface });
  try {
    for (const body of [{ mode: "injection" }, { mode: "full" }, { integrity: true }, { integrity: true, confidentiality: false }]) {
      const res = await postAxes(h, body);
      assert.equal(res.status, 403, JSON.stringify(body));
      const answer = (await res.json()) as { error: string; frozen: boolean };
      assert.equal(answer.frozen, true);
      assert.match(answer.error, new RegExp(`frozen.*${INTEGRITY_OPT_IN_ENV}=1`));
    }
    assert.equal(existsSync(h.configPath), false, "a refused act writes nothing");
    assert.equal(audit.store.length, 0, "a refused act emits nothing");

    // With integrity already ON in the file, a confidentiality flip would
    // save a pair that still has it on: refused too, the file byte-identical.
    mkdirSync(join(h.dir, "mandu"), { recursive: true });
    const hand = 'mode = "injection"  # old\n';
    writeFileSync(h.configPath, hand);
    for (const body of [{ confidentiality: true }, { confidentiality: false }, { mode: "full" }]) {
      const res = await postAxes(h, body);
      assert.equal(res.status, 403, JSON.stringify(body));
      assert.equal(((await res.json()) as { frozen: boolean }).frozen, true);
    }
    assert.equal(readFileSync(h.configPath, "utf8"), hand);
    assert.equal(audit.store.length, 0);
  } finally {
    await h.close();
  }
});

test("freeze: turning integrity OFF is always allowed without the opt-in (integrity:false, mode secrets/off)", async () => {
  const audit = fakeAudit();
  const h = await startServer({ auditArbiter: audit.surface });
  try {
    mkdirSync(join(h.dir, "mandu"), { recursive: true });
    writeFileSync(h.configPath, 'mode = "full"\n');
    const off = await postAxes(h, { integrity: false });
    assert.equal(off.status, 200);
    const body = (await off.json()) as AxesStateWithAudit;
    assert.equal(body.effective.integrity, false);
    assert.equal(body.effectiveMode, "secrets");
    assert.equal(body.integrityAllowed, false);
    assert.deepEqual(audit.store.map((e) => [e["axis"], e["from"], e["to"]]), [["integrity", true, false]]);
    // Writing false again (a no-flip) is still allowed.
    assert.equal((await postAxes(h, { integrity: false })).status, 200);
    // The product modes are always allowed, from a frozen mode too.
    for (const start of ['mode = "injection"\n', 'mode = "full"\n', ""]) {
      for (const m of PRODUCT_MODES) {
        writeFileSync(h.configPath, start);
        const res = await postAxes(h, { mode: m });
        assert.equal(res.status, 200, `${JSON.stringify(start)} → ${m}`);
        assert.deepEqual(((await res.json()) as AxesState).effective, MODE_AXES[m]);
      }
    }
    // With integrity OFF, a confidentiality flip is an ordinary write.
    writeFileSync(h.configPath, 'mode = "secrets"\n');
    assert.equal((await postAxes(h, { confidentiality: false })).status, 200);
  } finally {
    await h.close();
  }
});

test("freeze: with the opt-in in the dashboard's env the frozen modes save; the GET says integrityAllowed", async () => {
  for (const v of ["1", "true", "ON", " yes "]) {
    const h = await startServer({}, { [INTEGRITY_OPT_IN_ENV]: v });
    try {
      const get = (await (await fetch(`${h.baseUrl}/api/config/axes`)).json()) as AxesState;
      assert.equal(get.integrityAllowed, true, `opt-in ${JSON.stringify(v)}`);
      for (const body of [{ mode: "injection" }, { mode: "full" }, { integrity: true }, { confidentiality: false }]) {
        const res = await postAxes(h, body);
        assert.equal(res.status, 200, `${JSON.stringify(v)} ${JSON.stringify(body)}`);
        assert.equal(((await res.json()) as AxesState).integrityAllowed, true);
      }
      assert.match(readFileSync(h.configPath, "utf8"), /^mode = "injection"$/m, "the last write: integrity on, confidentiality off");
    } finally {
      await h.close();
    }
  }
});

test("freeze: a value that is not an explicit yes does not opt in (GET integrityAllowed false, POST still 403)", async () => {
  for (const v of ["", "0", "false", "off", "no", "yes please", "2"]) {
    const h = await startServer({}, { [INTEGRITY_OPT_IN_ENV]: v });
    try {
      const get = (await (await fetch(`${h.baseUrl}/api/config/axes`)).json()) as AxesState;
      assert.equal(get.integrityAllowed, false, JSON.stringify(v));
      assert.equal((await postAxes(h, { mode: "full" })).status, 403, JSON.stringify(v));
    } finally {
      await h.close();
    }
  }
});
