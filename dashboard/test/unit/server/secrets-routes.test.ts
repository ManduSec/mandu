/**
 * /api/secrets — the confidentiality standing-release surface (confidentiality.md
 * §6; plans 5 + 6). Every registered secret and every binding is a STANDING
 * release rule, so the human must be able to see the whole surface. The panel
 * shows what is confined and where it may go — NEVER what is inside.
 *
 * Plan 6 adds THE LABELING ACT to the same module (`POST|DELETE
 * /api/secrets/label`) — the only producer of `any-model` in the system.
 * These are the HANDLER-level tests (the route functions in isolation); the
 * CSRF gate lives in server.ts and is pinned end-to-end over a real server in
 * secrets-label-routes.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  getSecrets,
  setSecretLabel,
  removeSecretLabel,
  type ConfidentialityState,
  type PathLabelResult,
  type SecretsArbiter,
  type SecretsResponse,
} from "../../../src/server/secrets-routes.js";

/** Minimal ServerResponse stand-in capturing status + body (json() calls
 *  writeHead then end). */
function fakeRes(): {
  res: { writeHead: (s: number) => void; end: (b?: string) => void };
  captured: { status: number; body: unknown };
} {
  const captured = { status: 0, body: undefined as unknown };
  const res = {
    writeHead: (s: number) => {
      captured.status = s;
    },
    end: (b?: string) => {
      captured.body = b ? JSON.parse(b) : undefined;
    },
  };
  return { res, captured };
}

/** Minimal IncomingMessage stand-in: readJson() only consumes data/end events. */
function fakeReq(body: unknown): { on: (ev: string, cb: (c?: unknown) => void) => void } {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  return {
    on(ev: string, cb: (c?: unknown) => void) {
      if (ev === "data") cb(Buffer.from(raw));
      if (ev === "end") cb();
    },
  };
}

/** A SecretsArbiter fake: `confidentialityState` returns `state`; the label ops
 *  record their calls (and can be made to throw). */
function fakeArbiter(
  state: ConfidentialityState | (() => Promise<ConfidentialityState>),
  label?: Partial<SecretsArbiter>,
): SecretsArbiter & { calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    calls,
    confidentialityState: typeof state === "function" ? state : async () => state,
    async setPathLabel(args): Promise<PathLabelResult> {
      calls.push(args);
      if (label?.setPathLabel) return label.setPathLabel(args);
      return {
        path: args.path,
        level: args.confidentiality,
        bindings: args.bindings ?? [],
        recursive: args.recursive ?? true,
        declassifies: false,
      };
    },
    async removePathLabel(path): Promise<boolean> {
      calls.push({ remove: path });
      if (label?.removePathLabel) return label.removePathLabel(path);
      return true;
    },
  };
}

const STATE: ConfidentialityState = {
  enabled: true,
  secrets: [
    {
      path: "/home/u/.aws/credentials",
      symbol: "$MDU:nomodel_Read[3fa9]",
      level: "no-model",
      bindings: ["amazonaws.com"],
    },
    {
      path: "/work/app/.env",
      symbol: "$MDU:nomodel_Read[7b21]",
      level: "no-model",
      bindings: [],
    },
  ],
  labels: [
    {
      path: "/work/app/test/fixtures/.env",
      level: "public",
      bindings: [],
      recursive: true,
      source: "user",
      updatedAt: 1_700_000_000_000,
      declassifies: true,
    },
  ],
};

// ── GET /api/secrets ──────────────────────────────────────────────────────────

test("returns the axis state and the standing release surface", async () => {
  const arbiter = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await getSecrets(arbiter, res as any);

  assert.equal(captured.status, 200);
  const body = captured.body as SecretsResponse;
  assert.equal(body.enabled, true);
  assert.equal(body.panel.secrets.length, 2);
  // The BINDING is the standing rule — it must be visible (§6).
  assert.deepEqual(body.panel.secrets[0]!.bindings, ["amazonaws.com"]);
  assert.equal(body.panel.secrets[0]!.level, "no-model");
  // The USER LABELS are part of the same surface (plan 6).
  assert.equal(body.panel.labels.length, 1);
  assert.equal(body.panel.labels[0]!.declassifies, true);
});

test("each secret goes out ONCE: the panel, not the raw state beside it (dashboard.md §4.30)", async () => {
  // Until 2026-10-03 the body was `{ ...state, panel }`: every secret, label,
  // derived record and tainted program twice, and any field the arbiter added
  // to its state passed straight through to the browser.
  const arbiter = fakeArbiter({ ...STATE, extra: "an arbiter field the panel does not show" } as unknown as ConfidentialityState);
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await getSecrets(arbiter, res as any);
  assert.deepEqual(Object.keys(captured.body as object).sort(), ["enabled", "panel"]);
  const raw = JSON.stringify(captured.body);
  for (const s of STATE.secrets) {
    assert.equal(raw.split(JSON.stringify(s.symbol)).length - 1, 1, `${s.symbol} appears once`);
  }
  assert.ok(!raw.includes("an arbiter field"), "an unshown arbiter field does not reach the browser");
});

test("the GET ships the PROJECTED panel (the pure view-model)", async () => {
  // The render logic is unit-tested TS; the browser shell only paints it.
  const arbiter = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await getSecrets(arbiter, res as any);
  const body = captured.body as { panel: { status: string; summary: { declassifications: number } } };
  assert.equal(body.panel.status, "active");
  assert.equal(body.panel.summary.declassifications, 1);
});

test("the response NEVER carries a secret's contents", async () => {
  // The arbiter op is shaped so there is no value field at all; this pins that
  // neither the route NOR the panel projection reintroduces one (a key viewer is
  // not the panel's job).
  const arbiter = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await getSecrets(arbiter, res as any);
  const raw = JSON.stringify(captured.body);
  assert.ok(!raw.includes("value"));
  for (const s of (captured.body as SecretsResponse).panel.secrets) {
    assert.deepEqual(Object.keys(s).sort(), [
      "bindings", "bindingsText", "fields", "level", "levelClass", "levelLabel", "modelOk", "others", "path",
      "readers", "readersListed", "readersText", "symbol",
    ]);
  }
});

test("axis OFF renders as disabled — as OFF, not as 'nothing confined'", async () => {
  const arbiter = fakeArbiter({ enabled: false, secrets: [] });
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await getSecrets(arbiter, res as any);
  assert.equal(captured.status, 200);
  const body = captured.body as SecretsResponse;
  assert.equal(body.enabled, false);
  assert.deepEqual(body.panel.secrets, []);
  assert.equal(body.panel.status, "off");
  assert.match(body.panel.statusText, /OFF/);
});

test("an arbiter error is a 502 — NOT a green 'no secrets confined'", async () => {
  // The failure mode that matters: an unreachable arbiter must never render as
  // a reassuring empty list, which reads as "nothing to worry about".
  const arbiter = fakeArbiter(async () => {
    throw new Error("connection closed");
  });
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await getSecrets(arbiter, res as any);
  assert.equal(captured.status, 502);
  assert.match((captured.body as { error: string }).error, /connection closed/);
});

// ── POST /api/secrets/label — the labeling act ────────────────────────────────

test("a valid label is passed to the arbiter and echoed back", async () => {
  const arbiter = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  await setSecretLabel(
    arbiter,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fakeReq({ path: "~/models/local", confidentiality: "any-model", recursive: false }) as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    res as any,
  );
  assert.equal(captured.status, 200);
  const { label } = captured.body as { label: PathLabelResult };
  assert.equal(label.level, "any-model");
  assert.equal(label.recursive, false);
  assert.deepEqual(arbiter.calls[0], {
    path: "~/models/local",
    confidentiality: "any-model",
    bindings: [],
    recursive: false,
  });
});

test("plan 11 D1: a local-model label is accepted and passed through verbatim (never coerced to no-model)", async () => {
  const arbiter = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await setSecretLabel(arbiter, fakeReq({ path: "/home/u/contracts", confidentiality: "local-model" }) as any, res as any);
  assert.equal(captured.status, 200);
  assert.equal((arbiter.calls[0] as { confidentiality: string }).confidentiality, "local-model");
});

test("a bad level's 400 names all four levels", async () => {
  const arbiter = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await setSecretLabel(arbiter, fakeReq({ path: "/w/x", confidentiality: "secret-local" }) as any, res as any);
  assert.equal(captured.status, 400);
  assert.match((captured.body as { error: string }).error, /public \| any-model \| local-model \| no-model/);
});

test("recursive DEFAULTS to true (a directory label covers its subtree, §6)", async () => {
  const arbiter = fakeArbiter(STATE);
  const { res } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await setSecretLabel(arbiter, fakeReq({ path: "/w/docs", confidentiality: "public" }) as any, res as any);
  assert.equal((arbiter.calls[0] as { recursive: boolean }).recursive, true);
});

test("a BAD LEVEL is rejected with 400 — never coerced", async () => {
  // The whole point: coercing up is a silent lockout, coercing down is a silent
  // release. A labeling act is explicit or it is not an act.
  for (const bad of ["modelok", "SECRET-STRICT", "secret", "", 3, null, undefined]) {
    const arbiter = fakeArbiter(STATE);
    const { res, captured } = fakeRes();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await setSecretLabel(arbiter, fakeReq({ path: "/w/x", confidentiality: bad }) as any, res as any);
    assert.equal(captured.status, 400, `level ${JSON.stringify(bad)} must be rejected`);
    assert.match((captured.body as { error: string }).error, /confidentiality level/);
    // and the arbiter was NEVER called — nothing was stored, at any level.
    assert.equal(arbiter.calls.length, 0);
  }
});

test("a relative path is rejected with 400 (a relative label would apply to nothing)", async () => {
  const arbiter = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  await setSecretLabel(
    arbiter,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fakeReq({ path: "app/.env", confidentiality: "public" }) as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    res as any,
  );
  assert.equal(captured.status, 400);
  assert.match((captured.body as { error: string }).error, /absolute/);
  assert.equal(arbiter.calls.length, 0);
});

test("a missing path, a bad bindings type, and a bad recursive type are all 400", async () => {
  const cases: unknown[] = [
    { confidentiality: "public" },
    { path: "/w/x", confidentiality: "public", bindings: "evil.example" },
    { path: "/w/x", confidentiality: "public", bindings: [1, 2] },
    { path: "/w/x", confidentiality: "public", recursive: "yes" },
  ];
  for (const body of cases) {
    const arbiter = fakeArbiter(STATE);
    const { res, captured } = fakeRes();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await setSecretLabel(arbiter, fakeReq(body) as any, res as any);
    assert.equal(captured.status, 400, `${JSON.stringify(body)} must be rejected`);
    assert.equal(arbiter.calls.length, 0);
  }
});

test("an arbiter that rejects the label is a 502 — never a 200 for a label never stored", async () => {
  const arbiter = fakeArbiter(STATE, {
    setPathLabel: async () => {
      throw new Error("arbiter: db is read-only");
    },
  });
  const { res, captured } = fakeRes();
  await setSecretLabel(
    arbiter,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fakeReq({ path: "/w/x", confidentiality: "public" }) as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    res as any,
  );
  assert.equal(captured.status, 502);
  assert.match((captured.body as { error: string }).error, /read-only/);
});

test("a DECLASSIFYING label round-trips its declassifies flag (the loud path)", async () => {
  const arbiter = fakeArbiter(STATE, {
    setPathLabel: async (args) => ({
      path: args.path,
      level: args.confidentiality,
      bindings: [],
      recursive: true,
      declassifies: true,
    }),
  });
  const { res, captured } = fakeRes();
  await setSecretLabel(
    arbiter,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fakeReq({ path: "/w/app/.env", confidentiality: "public" }) as any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    res as any,
  );
  assert.equal(captured.status, 200);
  assert.equal((captured.body as { label: PathLabelResult }).label.declassifies, true);
});

// ── DELETE /api/secrets/label ─────────────────────────────────────────────────

test("removing a label reports removed:true; an unknown path reports removed:false", async () => {
  const hit = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await removeSecretLabel(hit, fakeReq({ path: "/w/app/.env" }) as any, res as any);
  assert.equal(captured.status, 200);
  assert.deepEqual(captured.body, { removed: true, path: "/w/app/.env" });

  const miss = fakeArbiter(STATE, { removePathLabel: async () => false });
  const r2 = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await removeSecretLabel(miss, fakeReq({ path: "/w/nope" }) as any, r2.res as any);
  assert.equal(r2.captured.status, 200);
  assert.deepEqual(r2.captured.body, { removed: false, path: "/w/nope" });
});

test("DELETE with no path → 400; an arbiter failure → 502", async () => {
  const arbiter = fakeArbiter(STATE);
  const { res, captured } = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await removeSecretLabel(arbiter, fakeReq({}) as any, res as any);
  assert.equal(captured.status, 400);

  const broken = fakeArbiter(STATE, {
    removePathLabel: async () => {
      throw new Error("connection closed");
    },
  });
  const r2 = fakeRes();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await removeSecretLabel(broken, fakeReq({ path: "/w/x" }) as any, r2.res as any);
  assert.equal(r2.captured.status, 502);
});
