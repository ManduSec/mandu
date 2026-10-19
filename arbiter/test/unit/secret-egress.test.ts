/**
 * Plan-2 egress enforcement (docs/design/confidentiality/confidentiality.md):
 * the decideDesymbolization secret branches + bindings (Task 1), the U-LLM
 * deep-resolve exclusion (Task 2), and the HumanShell exec withholding
 * (Task 3) — each with its OFF-dual (§12 matrix fold 2).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  decideDesymbolization,
  destinationMatchesBindings,
  type DesymSymbolEntry,
  type SymbolLookup,
} from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

function entry(over: Partial<DesymSymbolEntry> = {}): DesymSymbolEntry {
  return { value: "raw", origin: null, obsoleted_at: null, ...over };
}

function lookupOf(map: Record<string, DesymSymbolEntry>): SymbolLookup {
  return (s) => map[s];
}

const TRUSTED_HOST = "good.example";
const isDestTrusted = (d: string) => d === TRUSTED_HOST;

const STRICT = "$MDU:nomodel_Read[ab12]";
const MODEL_OK = "$MDU:anymodel_Read[cd34]";
const PUBLIC = "$MDU:web_fetch[ef56]";

const LOOKUP = lookupOf({
  [STRICT]: entry({ confidentiality: "no-model", bindings: ["example.com"] }),
  [MODEL_OK]: entry({ confidentiality: "any-model" }),
  [PUBLIC]: entry(),
});

const ON = { confidentiality: true };

// ── Task 1: the gate ─────────────────────────────────────────────────────────

test("gate ON: strict at a TRUSTED destination no longer auto-releases", () => {
  const d = decideDesymbolization(
    { symbol: STRICT, boundary: "network", destination: TRUSTED_HOST },
    LOOKUP, isDestTrusted, ON,
  );
  assert.equal(d.allow, false);
  assert.equal(d.allow === false && d.requiresApproval, true);
});

test("gate ON: strict at a BOUND destination → one-time approval (§9b), distinct reason", () => {
  const d = decideDesymbolization(
    { symbol: STRICT, boundary: "network", destination: "api.example.com" },
    LOOKUP, isDestTrusted, ON,
  );
  assert.equal(d.allow, false);
  assert.equal(d.allow === false && d.requiresApproval, true);
  assert.match(d.reason, /BOUND destination/);
});

test("gate ON: strict + BOUND destination + TRUSTED integrity → allow (§3.2 carve-out)", () => {
  const trustedLookup = lookupOf({
    [STRICT]: entry({
      confidentiality: "no-model",
      bindings: ["example.com"],
      integrity: "trusted",
    }),
  });
  const bound = decideDesymbolization(
    { symbol: STRICT, boundary: "network", destination: "api.example.com" },
    trustedLookup, isDestTrusted, ON,
  );
  assert.equal(bound.allow, true);
  assert.match(bound.reason, /BOUND destination/);
  // ...but only at the bound destination: unbound stays declassification.
  const unbound = decideDesymbolization(
    { symbol: STRICT, boundary: "network", destination: "attacker.test" },
    trustedLookup, isDestTrusted, ON,
  );
  assert.equal(unbound.allow, false);
  // ...and model context stays a hard deny regardless of integrity.
  const model = decideDesymbolization(
    { symbol: STRICT, boundary: "model_context" },
    trustedLookup, isDestTrusted, ON,
  );
  assert.equal(model.allow, false);
  assert.equal(model.allow === false && model.requiresApproval, false);
  // ...and junk integrity values never grant the release (fail-closed parse).
  const junkLookup = lookupOf({
    [STRICT]: entry({
      confidentiality: "no-model", bindings: ["example.com"], integrity: "TRUSTED-ish",
    }),
  });
  const junk = decideDesymbolization(
    { symbol: STRICT, boundary: "network", destination: "api.example.com" },
    junkLookup, isDestTrusted, ON,
  );
  assert.equal(junk.allow, false);
});

test("gate ON: strict at an unbound destination → declassification approval", () => {
  const d = decideDesymbolization(
    { symbol: STRICT, boundary: "network", destination: "attacker.test" },
    LOOKUP, isDestTrusted, ON,
  );
  assert.equal(d.allow, false);
  assert.equal(d.allow === false && d.requiresApproval, true);
  assert.match(d.reason, /declassification/);
});

test("binding matching: exact, dot-suffix, port, case; no substring tricks", () => {
  assert.equal(destinationMatchesBindings("example.com", ["example.com"]), true);
  assert.equal(destinationMatchesBindings("api.example.com", ["example.com"]), true);
  assert.equal(destinationMatchesBindings("API.Example.COM:443", ["example.com"]), true);
  assert.equal(destinationMatchesBindings("evil-example.com", ["example.com"]), false);
  assert.equal(destinationMatchesBindings("example.com.evil.test", ["example.com"]), false);
  assert.equal(destinationMatchesBindings("anything", []), false);
  assert.equal(destinationMatchesBindings("anything", null), false);
});

test("gate ON: strict in model context is a HARD deny — no approval override", () => {
  const d = decideDesymbolization(
    { symbol: STRICT, boundary: "model_context" },
    LOOKUP, isDestTrusted, ON,
  );
  assert.equal(d.allow, false);
  assert.equal(d.allow === false && d.requiresApproval, false);
});

test("gate ON: strict to the filesystem (HumanView) stays allow", () => {
  const d = decideDesymbolization(
    { symbol: STRICT, boundary: "filesystem" },
    LOOKUP, isDestTrusted, ON,
  );
  assert.equal(d.allow, true);
});

test("gate ON: any-model behaves like strict on network egress", () => {
  const d = decideDesymbolization(
    { symbol: MODEL_OK, boundary: "network", destination: TRUSTED_HOST },
    LOOKUP, isDestTrusted, ON,
  );
  assert.equal(d.allow, false);
});

test("gate ON: public symbol keeps the integrity path (trusted destination allows)", () => {
  const d = decideDesymbolization(
    { symbol: PUBLIC, boundary: "network", destination: TRUSTED_HOST },
    LOOKUP, isDestTrusted, ON,
  );
  assert.equal(d.allow, true);
});

test("gate ON: strict asCommand still hits the untrusted-command approval", () => {
  const d = decideDesymbolization(
    { symbol: STRICT, boundary: "network", destination: "api.example.com", asCommand: true },
    LOOKUP, isDestTrusted, ON,
  );
  assert.equal(d.allow, false);
  assert.equal(d.allow === false && d.requiresApproval, true);
});

test("gate OFF-dual (fold 2): strict entries decide byte-identically to today", () => {
  for (const opts of [undefined, { confidentiality: false }]) {
    const trusted = decideDesymbolization(
      { symbol: STRICT, boundary: "network", destination: TRUSTED_HOST },
      LOOKUP, isDestTrusted, opts,
    );
    assert.equal(trusted.allow, true, "trusted destination allows (integrity path)");
    const model = decideDesymbolization(
      { symbol: STRICT, boundary: "model_context" },
      LOOKUP, isDestTrusted, opts,
    );
    assert.equal(model.allow, true, "model_context allows (pre-axis behavior)");
  }
});

test("gate OFF-dual: pre-axis entries (no label fields) are inert even ON", () => {
  const legacy = lookupOf({ [PUBLIC]: entry() });
  const d = decideDesymbolization(
    { symbol: PUBLIC, boundary: "network", destination: TRUSTED_HOST },
    legacy, isDestTrusted, ON,
  );
  assert.equal(d.allow, true); // absent level parses to public → integrity path
});

// ── Task 2: the U-LLM exclusion (dispatch-level) ─────────────────────────────

import { ArbiterServer } from "../../ipc/server.js";
import { loadSymbolMap, allocateSymbol } from "../../symbol-table/symbol-table.js";

function tmpServer(confidentiality: boolean): {
  server: ArbiterServer;
  dbPath: string;
  cleanup: () => void;
} {
  const dir = mkdtempSync(join(tmpdir(), "mandu-segress-"));
  const dbPath = join(dir, "symbols.db");
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    dbPath,
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality,
  });
  return { server, dbPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function dispatchResolve(server: ArbiterServer, symbol: string): string | null {
  const resp = server.dispatch({ id: "t", op: "resolve", symbol, deep: true }) as {
    ok: boolean; result: { value: string | null }; error?: string;
  };
  assert.equal(resp.ok, true, resp.error);
  return resp.result.value;
}

test("resolve(deep) ON: top-level secret refused; nested secret stays opaque; HumanView desymbolize unrestricted", () => {
  const { server, dbPath, cleanup } = tmpServer(true);
  try {
    const map = loadSymbolMap(dbPath);
    const secret = allocateSymbol(map, {
      tool: "Read", value: "AKIA-SECRET-KEY", origin: "~/.aws/credentials",
      confidentiality: "no-model",
    }, dbPath);
    const wrapper = allocateSymbol(map, {
      tool: "Bash", value: `line1 ${secret} line3`,
    }, dbPath);
    // The server hydrated its own map at construction — re-dispatch through a
    // fresh server so it sees the rows written above.
    void server.close();
    const { server: s2, cleanup: c2 } = (() => {
      const srv = new ArbiterServer({
        socketPath: join(dbPath, "..", "arbiter2.sock"),
        dbPath, eventDir: join(dbPath, "..", "events"), log: () => {}, confidentiality: true,
      });
      return { server: srv, cleanup: () => void srv.close() };
    })();
    try {
      // 1. top-level secret → refused (null): the U-LLM quarantine is an
      //    egress to the provider (§3.2).
      assert.equal(dispatchResolve(s2, secret), null);
      // 2. nested secret stays opaque inside a public expansion.
      const v = dispatchResolve(s2, wrapper);
      assert.ok(v !== null && v.includes(secret), v ?? "null");
      assert.ok(v !== null && !v.includes("AKIA-SECRET-KEY"));
      // 3. HumanView deep desymbolize reveals everything — the human owns
      //    their secrets.
      const d = s2.dispatch({ id: "t", op: "desymbolize", text: `see ${wrapper}` }) as {
        ok: boolean; result: { text: string };
      };
      assert.equal(d.ok, true);
      assert.ok(d.result.text.includes("AKIA-SECRET-KEY"), d.result.text);
    } finally {
      c2();
    }
  } finally {
    cleanup();
  }
});

// ── Task 3: exec — HumanShell withholds secret symbols ───────────────────────

import { resolveExecArgv } from "../../policy/exec-classify.js";
import type { SymbolMap, SymbolEntry } from "../../symbol-table/index.js";

function mapOf(entries: Record<string, Partial<SymbolEntry> & { value: string }>): SymbolMap {
  const symbols = new Map<string, SymbolEntry>();
  for (const [name, e] of Object.entries(entries)) {
    symbols.set(name, {
      tool: "Read", field: null, origin: null, session_key: null, call_id: null,
      created_at: 1, obsoleted_at: null, obsoleted_by: null,
      derived_from: null, line_range: null,
      confidentiality: "public", bindings: null, integrity: "untrusted",
      ...e,
    });
  }
  return { symbols };
}

const EXEC_MAP = mapOf({
  "$MDU:nomodel_Read[ab12]": { value: "AKIA-SECRET", confidentiality: "no-model" },
  "$MDU:Read[cd34]": { value: "hello-data" },
});

test("exec ON: HumanShell leaves a secret data-position symbol as its placeholder and runs (§7.1: the value goes in at the network chokepoint, never the argv)", () => {
  const r = resolveExecArgv(
    { argv: ["echo", "$MDU:nomodel_Read[ab12]"], shell: "HumanShell" },
    EXEC_MAP,
    { confidentiality: true },
  );
  assert.deepEqual(r.argv, ["echo", "$MDU:nomodel_Read[ab12]"]); // unchanged: the placeholder, never the value
  assert.ok(!r.argv.join(" ").includes("AKIA-SECRET"));
  assert.deepEqual(r.approvals, [], "nothing withheld: the command runs with the placeholder");
  assert.match(r.reason, /placeholder.*network egress gate/);
});

// The 2026-10-05 tutorial case: `. ./.env; curl -u "$STRIPE_KEY:"` and the
// §7.1 example `curl -H "Authorization: Bearer $KEY"`. Before: rc 77
// (`secret_symbol`, the whole command withheld).
const ENV_MAP = mapOf({
  "$MDU:nomodel_Read[de31].STRIPE_KEY": { value: "sk_live_fake_123456", confidentiality: "no-model" },
  "$MDU:Read[cd34]": { value: "hello-data" },
});

test("exec ON: curl with a secret placeholder runs with the argv exactly as given (a header holding spaces, a -w format, Basic's user:)", () => {
  const cases: string[][] = [
    ["curl", "-sS", "https://api.stripe.com/v1/customers", "-u", "$MDU:nomodel_Read[de31].STRIPE_KEY:", "-d", "limit=100", "-G"],
    ["curl", "-H", "Authorization: Bearer $MDU:nomodel_Read[de31].STRIPE_KEY", "https://api.stripe.com/v1/customers"],
    // `{`, `?` and `|` would be an unsupported shape for a resolved value;
    // nothing is resolved here, and the argv is exec'd as an array.
    ["curl", "-s", "-w", "%{http_code}", "-H", "X-Key: $MDU:nomodel_Read[de31].STRIPE_KEY", "https://api.stripe.com/v1/customers?limit=1|x"],
    ["wget", "-q", "-O-", "--header=Authorization: Bearer $MDU:nomodel_Read[de31].STRIPE_KEY", "https://api.stripe.com/"],
  ];
  for (const argv of cases) {
    const r = resolveExecArgv({ argv, shell: "HumanShell" }, ENV_MAP, { confidentiality: true });
    assert.deepEqual(r.argv, argv, `argv preserved byte for byte: ${JSON.stringify(argv)}`);
    assert.deepEqual(r.approvals, [], `runs: ${JSON.stringify(argv)} (${r.reason})`);
    assert.ok(!JSON.stringify(r.argv).includes("sk_live_fake_123456"), "THE INVARIANT: the real value never enters the argv");
  }
});

test("exec ON: a secret placeholder next to a public symbol: the public one resolves in its slot, the secret stays a placeholder", () => {
  const r = resolveExecArgv(
    { argv: ["curl", "-d", "note=$MDU:Read[cd34]", "-u", "$MDU:nomodel_Read[de31].STRIPE_KEY:", "https://api.stripe.com/v1/customers"], shell: "HumanShell" },
    ENV_MAP,
    { confidentiality: true },
  );
  assert.deepEqual(r.approvals, []);
  assert.deepEqual(r.argv, ["curl", "-d", "note=hello-data", "-u", "$MDU:nomodel_Read[de31].STRIPE_KEY:", "https://api.stripe.com/v1/customers"]);
  assert.ok(!JSON.stringify(r.argv).includes("sk_live_fake_123456"));
});

test("exec ON: a secret placeholder next to a public symbol in an unsupported shape is still refused (a resolved value could become syntax)", () => {
  const r = resolveExecArgv(
    { argv: ["curl", "-d", "note=$MDU:Read[cd34]", "-w", "%{http_code}", "-u", "$MDU:nomodel_Read[de31].STRIPE_KEY:", "https://x.test/"], shell: "HumanShell" },
    ENV_MAP,
    { confidentiality: true },
  );
  assert.equal(r.approvals[0]?.kind, "unsupported_command");
  assert.ok(!JSON.stringify(r.argv).includes("sk_live_fake_123456"));
  assert.ok(!JSON.stringify(r.argv).includes("hello-data"), "nothing resolved");
});

test("exec ON: a secret placeholder where code runs is still refused (symbol_as_command), and never resolved", () => {
  const r = resolveExecArgv(
    { argv: ["sh", "-c", "$MDU:nomodel_Read[de31].STRIPE_KEY"], shell: "HumanShell" },
    ENV_MAP,
    { confidentiality: true },
  );
  assert.equal(r.approvals[0]?.kind, "symbol_as_command");
  assert.ok(!JSON.stringify(r.argv).includes("sk_live_fake_123456"));
});

test("exec ON: the field symbol's BASE row is secret too: an alias lookup never resolves it into the argv", () => {
  // The stranded base of a field symbol (`…[de31]`) has no row of its own;
  // the candidate walk aliases it to its one field row, which is secret.
  const r = resolveExecArgv(
    { argv: ["curl", "-u", "$MDU:nomodel_Read[de31]:", "https://x.test/"], shell: "HumanShell" },
    ENV_MAP,
    { confidentiality: true },
  );
  assert.ok(!JSON.stringify(r.argv).includes("sk_live_fake_123456"));
  assert.deepEqual(r.argv, ["curl", "-u", "$MDU:nomodel_Read[de31]:", "https://x.test/"]);
});

test("exec ON: public data-position symbols still resolve in-slot", () => {
  const r = resolveExecArgv(
    { argv: ["echo", "$MDU:Read[cd34]"], shell: "HumanShell" },
    EXEC_MAP,
    { confidentiality: true },
  );
  assert.deepEqual(r.argv, ["echo", "hello-data"]);
  assert.equal(r.approvals.length, 0);
});

test("exec ON: AgentShell keeps symbols symbolic, no approvals (unchanged)", () => {
  const r = resolveExecArgv(
    { argv: ["echo", "$MDU:nomodel_Read[ab12]"], shell: "AgentShell" },
    EXEC_MAP,
    { confidentiality: true },
  );
  assert.deepEqual(r.argv, ["echo", "$MDU:nomodel_Read[ab12]"]);
  assert.equal(r.approvals.length, 0);
});

test("exec OFF-dual: a secret-labelled row is STILL never resolved into the argv (the op answers on the data socket; arbiter-human-plane.md §4), a public one resolves", () => {
  for (const opts of [undefined, { confidentiality: false }]) {
    const r = resolveExecArgv(
      { argv: ["echo", "$MDU:nomodel_Read[ab12]"], shell: "HumanShell" },
      EXEC_MAP,
      opts,
    );
    assert.deepEqual(r.argv, ["echo", "$MDU:nomodel_Read[ab12]"]);
    assert.ok(!r.argv.join(" ").includes("AKIA-SECRET"));
    assert.deepEqual(r.approvals, []);
    const pub = resolveExecArgv(
      { argv: ["echo", "$MDU:Read[cd34]"], shell: "HumanShell" },
      EXEC_MAP,
      opts,
    );
    assert.deepEqual(pub.argv, ["echo", "hello-data"]);
    assert.equal(pub.approvals.length, 0);
  }
});

test("resolve(deep) OFF-dual: a no-model row is STILL refused (the level gate holds whatever the axis); an unlabelled row resolves", () => {
  const { server, dbPath, cleanup } = tmpServer(false);
  try {
    void server.close();
    const map = loadSymbolMap(dbPath);
    const secret = allocateSymbol(map, {
      tool: "Read", value: "AKIA-SECRET-KEY", origin: "~/.aws/credentials",
      confidentiality: "no-model", // label present (e.g. minted while ON)
    }, dbPath);
    const s2 = new ArbiterServer({
      socketPath: join(dbPath, "..", "arbiter2.sock"),
      dbPath, eventDir: join(dbPath, "..", "events"), log: () => {}, confidentiality: false,
    });
    // arbiter-human-plane.md §4: deep resolve is the data-plane U-LLM read,
    // reachable from the agent world, so a no-model row minted while the axis
    // was ON is refused after a restart with it OFF — and a nested one inside
    // a public value stays a token. An unlabelled (public) row still resolves.
    const plain = allocateSymbol(map, { tool: "Read", value: "plain notes", origin: "/ws/notes.md" }, dbPath);
    const wrapper = allocateSymbol(map, { tool: "Read", value: `see ${secret}` }, dbPath);
    const s3 = new ArbiterServer({
      socketPath: join(dbPath, "..", "arbiter3.sock"),
      dbPath, eventDir: join(dbPath, "..", "events"), log: () => {}, confidentiality: false,
    });
    try {
      assert.equal(dispatchResolve(s3, secret), null, "no-model refused with the axis OFF");
      assert.equal(dispatchResolve(s3, plain), "plain notes", "public still resolves");
      const expanded = dispatchResolve(s3, wrapper);
      assert.equal(expanded, `see ${secret}`, "a nested no-model stays a token");
      assert.ok(!expanded!.includes("AKIA-SECRET-KEY"));
      // The HumanView surfaces are not level-gated (human plane only).
      const d = s3.dispatch({ id: "t", op: "desymbolize", text: `x ${secret}` }, { channel: "human" }) as { ok: boolean; result: { text: string } };
      assert.equal(d.result.text, "x AKIA-SECRET-KEY");
    } finally {
      void s3.close();
      void s2.close();
    }
  } finally {
    cleanup();
  }
});
