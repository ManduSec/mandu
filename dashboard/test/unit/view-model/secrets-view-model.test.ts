/**
 * view-model/secrets — the pure Secrets-panel projection (confidentiality.md §6,
 * plan 6 Task 4). This is the oracle for the three things the panel exists to
 * say, and it is testable precisely because the render LOGIC is pure TS and the
 * browser file is a dumb shell:
 *
 *   1. it NEVER renders a secret's value (not even if the arbiter grew one);
 *   2. axis OFF renders as OFF — never as a green "nothing confined";
 *   3. a declassification (a label WEAKER than the catalog's verdict) is loud,
 *      and the `model-ok` surface is enumerated explicitly (both are standing
 *      release rules, and §6 requires the surface be visible).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CONFIDENTIALITY_LEVELS,
  isConfidentialityLevel,
  readersTextOf,
  toSecretsPanel,
  type ConfidentialityStateWire,
} from "../../../src/view-model/secrets.js";

const STATE: ConfidentialityStateWire = {
  enabled: true,
  secrets: [
    {
      path: "/home/u/.aws/credentials",
      symbol: "$MDU:nomodel_Read[3fa9]",
      level: "no-model",
      bindings: ["amazonaws.com"],
    },
    {
      path: "/home/u/notes/journal.md",
      symbol: "$MDU:anymodel_Read[9c02]",
      level: "any-model",
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
      declassifies: true, // the catalog calls it a credential; the human says fixture
    },
    {
      path: "/home/u/notes",
      level: "any-model",
      bindings: ["api.anthropic.com"],
      recursive: true,
      source: "user",
      updatedAt: 1_700_000_001_000,
      declassifies: false,
    },
  ],
};

test("every registered secret renders path, symbol, level and bindings", () => {
  const panel = toSecretsPanel(STATE);
  assert.equal(panel.status, "active");
  assert.equal(panel.secrets.length, 2);

  const aws = panel.secrets[0]!;
  assert.equal(aws.path, "/home/u/.aws/credentials");
  assert.equal(aws.symbol, "$MDU:nomodel_Read[3fa9]");
  assert.equal(aws.level, "no-model");
  assert.equal(aws.levelClass, "strict");
  assert.equal(aws.modelOk, false);
  // The BINDING is the standing release rule — it must be on the surface (§6).
  assert.deepEqual(aws.bindings, ["amazonaws.com"]);
  assert.equal(aws.bindingsText, "amazonaws.com");

  // Unbound = bound NOWHERE. It must never read as "anywhere".
  assert.equal(panel.secrets[1]!.bindingsText, "—");
});

test("the panel NEVER carries a value — not even one the arbiter invented", () => {
  // Defense in depth: the arbiter op returns no values by construction. This
  // pins that the projection copies fields EXPLICITLY, so a future arbiter that
  // started leaking a `value` (or any extra field) could not paint it into the
  // privileged dashboard DOM.
  const leaky = {
    enabled: true,
    secrets: [
      {
        path: "/home/u/.aws/credentials",
        symbol: "$MDU:nomodel_Read[3fa9]",
        level: "no-model",
        bindings: [],
        // an arbiter regression:
        value: "AKIA-SUPER-SECRET-KEY",
      },
    ],
  } as unknown as ConfidentialityStateWire;

  const panel = toSecretsPanel(leaky);
  const raw = JSON.stringify(panel);
  assert.ok(!raw.includes("AKIA-SUPER-SECRET-KEY"), "a secret's contents reached the panel");
  assert.ok(!raw.includes("value"), "the panel grew a value-shaped field");
  assert.deepEqual(Object.keys(panel.secrets[0]!).sort(), ["bindings", "bindingsText", "fields", "level", "levelClass", "levelLabel", "modelOk", "others", "path", "readers", "readersListed", "readersText", "symbol"]);
});

test("a declassification is flagged and carries a rendered note", () => {
  const panel = toSecretsPanel(STATE);
  const fixture = panel.labels.find((l) => l.path.endsWith("fixtures/.env"))!;
  assert.equal(fixture.declassifies, true);
  assert.equal(fixture.level, "public");
  assert.match(String(fixture.note), /DECLASSIFIED/);

  const notes = panel.labels.find((l) => l.path === "/home/u/notes")!;
  assert.equal(notes.declassifies, false);
  assert.equal(notes.note, null);

  assert.equal(panel.summary.declassifications, 1);
});

test("a PATTERN label (policy.yaml gitignore-style paths:) projects as one: marked, and its public release worded as covering every match", () => {
  const panel = toSecretsPanel({
    ...STATE,
    labels: [
      { path: "**/ws-*/contracts/**", level: "any-model", bindings: [], recursive: true, glob: true, source: "policy-file", updatedAt: 1, declassifies: false },
      { path: "**/test/fixtures/.env", level: "public", bindings: [], recursive: false, glob: true, source: "policy-file", updatedAt: 1, declassifies: true },
      { path: "/home/u/notes", level: "any-model", bindings: [], recursive: true, source: "user", updatedAt: 1, declassifies: false },
    ],
  });
  const by = new Map(panel.labels.map((l) => [l.path, l]));
  assert.equal(by.get("**/ws-*/contracts/**")!.pattern, true);
  assert.equal(by.get("/home/u/notes")!.pattern, false, "a label without the flag (every older arbiter) is a plain path");
  assert.match(String(by.get("**/test/fixtures/.env")!.note), /public pattern: every file it matches/);
});

test("the model-ok surface is listed EXPLICITLY (§6) — secrets and labels alike", () => {
  const panel = toSecretsPanel(STATE);
  // Each model-ok path is a standing grant of MODEL readability. §6 requires the
  // dashboard enumerate them, precisely because nothing may ever infer the level.
  assert.deepEqual(panel.summary.modelOkPaths.sort(), [
    "/home/u/notes",
    "/home/u/notes/journal.md",
  ]);
  assert.equal(panel.summary.modelOk, 2);
  assert.equal(panel.secrets[1]!.modelOk, true);
  assert.equal(panel.labels[1]!.modelOk, true);
});

test("the coverage line counts what is confined, model-ok, declassified and bound", () => {
  const panel = toSecretsPanel(STATE);
  assert.equal(panel.summary.confined, 2);
  assert.equal(panel.summary.strict, 1);
  assert.equal(panel.summary.labels, 2);
  // Standing bindings: amazonaws.com (secret) + api.anthropic.com (label).
  assert.equal(panel.summary.bindings, 2);
  assert.match(panel.summary.text, /2 secrets confined/);
  assert.match(panel.summary.text, /2 model-ok grants/);
  assert.match(panel.summary.text, /1 declassification/);
  assert.match(panel.summary.text, /2 standing bindings/);
});

test("axis OFF renders as OFF — the distinct state, not an empty green list", () => {
  const panel = toSecretsPanel({ enabled: false, secrets: [] });
  assert.equal(panel.status, "off");
  assert.equal(panel.enabled, false);
  assert.match(panel.statusText, /OFF/);
  // And it says WHY the surface is empty: nothing is confined, no label consulted.
  assert.match(panel.statusText, /never consulted|no label is consulted/i);
  assert.notEqual(panel.status, "empty");
});

test("axis OFF with STORED labels still says OFF (labels are retained, not consulted, §11)", () => {
  const panel = toSecretsPanel({ ...STATE, enabled: false });
  assert.equal(panel.status, "off");
  // The labels remain visible (they exist), but the panel must not imply they bite.
  assert.equal(panel.labels.length, 2);
  assert.match(panel.summary.text, /OFF/);
});

test("axis ON with nothing confined is 'empty' — a different statement from OFF", () => {
  const panel = toSecretsPanel({ enabled: true, secrets: [], labels: [] });
  assert.equal(panel.status, "empty");
  assert.match(panel.statusText, /axis ON/);
});

test("an arbiter with no labels field (a pre-plan-6 build) renders as no labels", () => {
  const panel = toSecretsPanel({ enabled: true, secrets: STATE.secrets });
  assert.deepEqual(panel.labels, []);
  assert.equal(panel.summary.declassifications, 0);
  assert.equal(panel.status, "active");
});

test("an UNKNOWN level renders verbatim and counts as neither model-ok nor public", () => {
  const panel = toSecretsPanel({
    enabled: true,
    secrets: [{ path: "/x", symbol: "$MDU:nomodel_Read[0001]", level: "secret-ish", bindings: [] }],
  });
  const row = panel.secrets[0]!;
  assert.equal(row.level, "secret-ish");
  assert.equal(row.levelClass, "unknown");
  assert.equal(row.levelLabel, "secret-ish");
  assert.equal(row.modelOk, false);
  assert.equal(panel.summary.modelOk, 0);
});

test("recursive:false is an EXACT-path label; the default is the subtree", () => {
  const panel = toSecretsPanel({
    enabled: true,
    secrets: [],
    labels: [
      {
        path: "/w/one.txt",
        level: "no-model",
        bindings: [],
        recursive: false,
        source: "user",
        updatedAt: 1,
        declassifies: false,
      },
    ],
  });
  assert.equal(panel.labels[0]!.scope, "exact");
  assert.equal(panel.labels[0]!.recursive, false);
});

test("dashboard.md §4.25f a rule on a file reads as a file: a subtree label whose path is a file is marked pathIsFile, and keeps its scope", () => {
  const label = (path: string, more: { recursive?: boolean; glob?: boolean } = {}) => ({ path, level: "no-model", bindings: [], recursive: true, source: "user", updatedAt: 1, declassifies: false, ...more });
  const state = {
    enabled: true,
    secrets: [],
    labels: [label("/w/deploy.token"), label("/w/secrets"), label("/w/one.txt", { recursive: false }), label("/w/*.key", { glob: true })],
  };
  // What server/path-kinds.ts found on disk (it never looks a pattern up).
  const rows = toSecretsPanel(state, new Set(["/w/deploy.token", "/w/one.txt", "/w/*.key"])).labels;
  assert.deepEqual(rows.map((r) => [r.path, r.scope, r.pathIsFile ?? null]), [
    ["/w/deploy.token", "subtree", true],
    ["/w/secrets", "subtree", null],
    ["/w/one.txt", "exact", null],
    ["/w/*.key", "subtree", null],
  ]);
  assert.equal(toSecretsPanel(state).labels[0]!.pathIsFile, undefined, "not looked at: as before");
});

test("isConfidentialityLevel accepts exactly the four levels", () => {
  assert.equal(isConfidentialityLevel("public"), true);
  assert.equal(isConfidentialityLevel("any-model"), true);
  assert.equal(isConfidentialityLevel("local-model"), true);
  assert.equal(isConfidentialityLevel("no-model"), true);
  assert.deepEqual([...CONFIDENTIALITY_LEVELS], ["public", "any-model", "local-model", "no-model"], "plan 11 D1: the total order, least to most restrictive");
  for (const bad of ["", "PUBLIC", "modelok", "secret", "localmodel", "local", "secret-local", 1, null, undefined, {}]) {
    assert.equal(isConfidentialityLevel(bad), false, `${JSON.stringify(bad)} is not a level`);
  }
});

// ── plan 9: the DERIVED surface (the watermark, persisted) ────────────────────

const DERIVED_ROW = {
  path: "/w/notes/summary.md",
  level: "any-model",
  bindings: ["acme.example.com"],
  sessionKey: "sess-A",
  tool: "Write",
  updatedAt: 7,
  effective: "any-model",
  overridden: false,
};

test("a derived row projects with its provenance — §8's release UI needs to know what fed it", () => {
  const panel = toSecretsPanel({ enabled: true, secrets: [], derived: [DERIVED_ROW] });
  assert.equal(panel.derived.length, 1);
  const d = panel.derived[0]!;
  assert.equal(d.path, "/w/notes/summary.md");
  assert.equal(d.levelClass, "model-ok");
  assert.equal(d.effectiveClass, "model-ok");
  assert.equal(d.sessionKey, "sess-A");
  assert.equal(d.tool, "Write");
  assert.equal(d.overridden, false);
  assert.match(d.note, /written by Write in session sess-A/);
  assert.equal(panel.summary.derivedFiles, 1);
});

test("a derived MODEL-OK file is enumerated as a standing model-read grant (§6)", () => {
  // A future session may read it into context. §6 requires every model-ok path be
  // listed, and "a machine put it there" is not an exemption.
  const panel = toSecretsPanel({ enabled: true, secrets: [], derived: [DERIVED_ROW] });
  assert.deepEqual(panel.summary.modelOkPaths, ["/w/notes/summary.md"]);
  assert.equal(panel.summary.modelOk, 1);
});

test("an OVERRIDDEN derived row says so — and is NOT counted as a model-read grant", () => {
  // The human labeled the artifact public: the release took effect, and a release
  // the human cannot see they made is not a release, it is a surprise.
  const panel = toSecretsPanel({
    enabled: true,
    secrets: [],
    derived: [{ ...DERIVED_ROW, effective: "public", overridden: true }],
  });
  const d = panel.derived[0]!;
  assert.equal(d.overridden, true);
  assert.equal(d.effectiveClass, "public");
  assert.match(d.note, /RELEASED/);
  assert.deepEqual(panel.summary.modelOkPaths, []);
});

test("derived rows keep the panel ACTIVE — a tainted file is a surface, not an empty one", () => {
  const panel = toSecretsPanel({ enabled: true, secrets: [], labels: [], derived: [DERIVED_ROW] });
  assert.equal(panel.status, "active");
});

test("an arbiter predating plan 9 (no `derived` field) projects an empty list, not a crash", () => {
  const panel = toSecretsPanel({ enabled: true, secrets: [] });
  assert.deepEqual(panel.derived, []);
  assert.equal(panel.summary.derivedFiles, 0);
});

test("plan 13 D8 (2026-10-03): the reader marks are the ARBITER's (a pin's hash, a script pin); the names judge only when it sent none", () => {
  const row = (readersAdmitNothing?: boolean[]) => toSecretsPanel({ ...STATE, secrets: [
    { path: "/ws/.env", symbol: "$MDU:nomodel_Read[9bbd]", level: "no-model", bindings: [], readers: ["mytool", "python3", "ssh-add"], ...(readersAdmitNothing ? { readersAdmitNothing } : {}), others: "deny" },
  ] }).secrets[0]!;
  // mytool is a pinned renamed copy of python (its hash); python3 pins a script
  assert.deepEqual(row([true, false, false]).readers, ["mytool (admits nothing)", "python3", "ssh-add"]);
  // an older arbiter: the names alone (the code before, for both entries)
  assert.deepEqual(row().readers, ["mytool", "python3 (admits nothing)", "ssh-add"]);
});

test("plan 10: a structured twin's field count and the reader list ride the row; NO list reads as the twin for every program, an EMPTY list as every program refused (§3.3), `others: twin` as the twin for the rest", () => {
  const panel = toSecretsPanel({
    ...STATE,
    secrets: [
      { path: "/ws/.env", symbol: "$MDU:nomodel_Read[9bbd]", level: "no-model", bindings: ["api.stripe.com"], fields: 3, readers: ["bash", "node"], others: "deny" },
      { path: "/home/u/.ssh/id_ed25519", symbol: "$MDU:nomodel_Read[1111]", level: "no-model", bindings: [] },
      // an empty list EXISTS: before 2026-09-24 this rendered "twin for every program", the opposite of the law
      { path: "/home/u/.pgpass", symbol: "$MDU:nomodel_Read[2222]", level: "no-model", bindings: [], readers: [] },
      { path: "/home/u/.npmrc", symbol: "$MDU:nomodel_Read[3333]", level: "no-model", bindings: [], readers: ["npm"], others: "twin" },
      // an older arbiter sends no `others`: a list without it is the §3.3 default, deny
      { path: "/home/u/.netrc", symbol: "$MDU:nomodel_Read[4444]", level: "no-model", bindings: [], readers: [] },
    ],
  });
  const env = panel.secrets[0]!;
  assert.equal(env.fields, 3);
  // plan 13 §8 decision (b): a bare shell or interpreter admits nothing
  assert.deepEqual(env.readers, ["bash (admits nothing)", "node (admits nothing)"]);
  assert.equal(env.readersListed, true);
  assert.equal(env.readersText, "bash (admits nothing), node (admits nothing); every other program is refused");
  // plan 13 D8 (2026-10-03): a printer admits nothing too
  const printed = toSecretsPanel({ ...STATE, secrets: [{ path: "/ws/.env", symbol: "$MDU:nomodel_Read[9bbd]", level: "no-model", bindings: [], readers: ["cat", "ssh-add"], others: "twin" }] }).secrets[0]!;
  assert.deepEqual(printed.readers, ["cat (admits nothing)", "ssh-add"]);
  const key = panel.secrets[1]!;
  assert.equal(key.fields, 0);
  assert.deepEqual(key.readers, []);
  assert.equal(key.readersListed, false);
  assert.equal(key.readersText, "twin for every program");
  const pg = panel.secrets[2]!;
  assert.equal(pg.readersListed, true);
  assert.equal(pg.others, "deny");
  assert.equal(pg.readersText, "none: every program is refused (the reader list is empty)");
  const npm = panel.secrets[3]!;
  assert.equal(npm.others, "twin");
  // npm runs the package's scripts: on the code-running list since 2026-10-04
  // (plan 13 D8 (10)), so the entry admits nothing (npm reads .npmrc as the
  // wire release's twin, as node does)
  assert.equal(npm.readersText, "npm (admits nothing); every other program gets the twin");
  assert.equal(panel.secrets[4]!.readersText, "none: every program is refused (the reader list is empty)");
  assert.equal(readersTextOf(true, [], "twin"), "none listed: every program gets the twin");
});

test("plan 10 §11.9: the programs holding a secret are rows with the program, file, level and time; absent on an older arbiter", () => {
  const panel = toSecretsPanel({ ...STATE, taintedProcesses: [{ procKey: "4242-77", app: "ssh-add", path: "/home/u/.pgpass", level: "no-model", session: "s1", since: 1_790_000_000_000 }] });
  assert.equal(panel.tainted.length, 1);
  assert.equal(panel.tainted[0]!.app, "ssh-add");
  assert.equal(panel.tainted[0]!.levelLabel, "strict");
  assert.match(panel.tainted[0]!.since, /^2026-/);
  assert.deepEqual(toSecretsPanel(STATE).tainted, []);
});


// ── plan 11 D1: local-model, readable only by a declared local model ─────────

test("local-model: its own class, NOT a model-ok grant (an outside model may not read it)", () => {
  const panel = toSecretsPanel({
    enabled: true,
    secrets: [{ path: "/home/u/contract.md", symbol: "$MDU:localmodel_Read[77aa]", level: "local-model", bindings: [] }],
    labels: [{ path: "/home/u/contracts", level: "local-model", bindings: ["api.example.com"], recursive: true, source: "user", updatedAt: 1, declassifies: false }],
    derived: [{ path: "/w/summary.md", level: "local-model", bindings: [], sessionKey: "s1", tool: "Write", updatedAt: 2, effective: "local-model", overridden: false }],
  });
  const [secret] = panel.secrets;
  const [label] = panel.labels;
  const [derived] = panel.derived;
  for (const row of [secret!, label!, derived!]) {
    assert.equal(row.levelClass, "local-only");
    assert.equal(row.levelLabel, "local-only");
    assert.equal(row.modelOk, false);
  }
  assert.equal(derived!.effectiveClass, "local-only");
  assert.equal(panel.summary.modelOk, 0, "not enumerated with the any-model grants");
  assert.deepEqual(panel.summary.modelOkPaths, []);
  assert.match(derived!.note!, /held local-only content/);
});
