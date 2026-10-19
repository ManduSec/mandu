/**
 * relative-read-bindings.test — a RELATIVE typed-path read is stored where the
 * agent read it, so its row carries the label's BINDINGS, and a declassify of
 * it leaves the session bound to exactly them (2026-10-10, confidentiality.md
 * §6).
 *
 * The live drill conf-declassify-confines-session (policy: the workspace's
 * `memo/` labelled `any-model` with bindings [example.com]) passed on OpenCode
 * and over-blocked on OpenClaw: after the declassify, a `web_fetch` of
 * https://example.com, the memo's own bound host, was held as
 * `session:high-unbound`. OpenCode reads `{filePath: "/abs/…/memo/brief.md"}`;
 * OpenClaw reads `{path: "memo/brief.md"}`, relative to its workspace. The
 * classify read that relative path in the launch directory (2026-10-09,
 * `relativeBase`), so the row was `any-model`; the symbolize re-derived the
 * BINDINGS from the relative origin, which no label matches, so the row was
 * bound nowhere. The declassify raised the session with that row (bindings
 * none) and the registered file's row it opened (example.com): the
 * intersection was empty, and every host asked.
 *
 * Now the symbolize applies the same `relativeBase` the classify does, under
 * the same rule (the session's own gate surface says `launch` and lists the
 * tool, the value is one the tool reads as `<base>/<value>`), and STORES the
 * row at the resolved path. The bindings are then that file's label's, at
 * mint and at every later bindings sync (which reads the stored origin).
 *
 * The invariant's side, pinned: an UNBOUND host still asks; a base the
 * session's surface does not vouch for, a value that may name another file,
 * and no base at all keep the relative origin (bound nowhere: fail-closed);
 * the axis OFF stores the origin as sent.
 *
 * Run: npx tsx --test test/unit/relative-read-bindings.test.ts
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import type { ArbiterRequest } from "../../ipc/protocol.js";
import { resolveTypedPathOrigin } from "../../policy/secret-catalog.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis is the code under test

const BRIEF = "Deal brief. Reference code: REL_BIND_CANARY_2718. Keep internal.\n";

interface Fixture {
  server: ArbiterServer;
  ws: string;
  ask(req: Record<string, unknown>): Record<string, unknown>;
  close(): void;
}

function fixture(confidentiality = true): Fixture {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rel-bind-"));
  // The drill's shape: a per-session workspace `ws-<hash>`, its memo/ labelled.
  const ws = join(tmp, "ws-df5643da29");
  mkdirSync(join(ws, "memo"), { recursive: true });
  writeFileSync(join(ws, "memo", "brief.md"), BRIEF);
  const server = new ArbiterServer({
    socketPath: join(tmp, "arbiter.sock"),
    dbPath: join(tmp, "symbols.db"),
    eventDir: join(tmp, "events"),
    log: () => {},
    confidentiality,
    integrity: false,
    policyDocument: { version: 1, paths: [{ path: "**/ws-*/memo/**", level: "any-model", bindings: ["example.com"] }] } as never,
  });
  let n = 0;
  return {
    server, ws,
    ask(req) {
      const r = server.dispatch({ id: `t${n++}`, ...req } as unknown as ArbiterRequest) as { ok: boolean; result?: Record<string, unknown>; error?: string };
      assert.equal(r.ok, true, r.error);
      return r.result ?? {};
    },
    close() { rmSync(tmp, { recursive: true, force: true }); },
  };
}

/** The proxy's symbolize of a `read` result, as rewrite-request sends it. */
function readResult(f: Fixture, session: string, path: string, extra: Record<string, unknown> = {}): { symbol: string; origin: string | null; bindings: string[] | null } {
  const r = f.ask({
    op: "symbolize", tool: "read", value: BRIEF, origin: path, sessionKey: session, callId: `toolu_${session}_${path}`,
    confidentiality: "any-model", integrity: "trusted", ...extra,
  });
  const symbol = r["symbol"] as string;
  const row = (f.server as unknown as { symbolMap: { symbols: Map<string, { origin: string | null; bindings: string[] | null }> } }).symbolMap.symbols.get(symbol)!;
  return { symbol, origin: row.origin, bindings: row.bindings };
}

function egress(f: Fixture, session: string, destination: string): { allow: boolean; requiresApproval: boolean; ruleRef?: { id?: string } } {
  return f.ask({ op: "sessionEgressDecision", sessionKey: session, boundary: "network", destination }) as never;
}

test("resolveTypedPathOrigin: a relative value the tool reads in the base resolves there; anything else does not", () => {
  assert.equal(resolveTypedPathOrigin("memo/brief.md", "/w/ws"), "/w/ws/memo/brief.md");
  assert.equal(resolveTypedPathOrigin("./memo/brief.md", "/w/ws"), "/w/ws/memo/brief.md");
  for (const v of ["/abs/brief.md", "~/brief.md", "@memo/brief.md", "memo/*.md", "$HOME/x", "https://example.com/x", "mémo/brief.md", ""]) {
    assert.equal(resolveTypedPathOrigin(v, "/w/ws"), undefined, `kept as written: ${v}`);
  }
  assert.equal(resolveTypedPathOrigin("memo/brief.md", "w/ws"), undefined, "a relative base is no base");
  assert.equal(resolveTypedPathOrigin("memo/brief.md", "/w/../ws"), undefined, "a base with `..` is no base");
});

test("OpenClaw: a relative `read` is stored at the launch directory's file and carries its label's bindings; declassify leaves the session bound to exactly them", () => {
  const f = fixture();
  try {
    const S = "oc-rel-bind";
    f.ask({ op: "setSessionSpec", sessionKey: S, spec: "openclaw-agent", requestedBy: "relative-read-bindings unit" });
    const r = readResult(f, S, "memo/brief.md", { relativeBase: f.ws });
    assert.equal(r.origin, join(f.ws, "memo", "brief.md"), "stored where the agent read it");
    assert.deepEqual(r.bindings, ["example.com"], "the label's bindings, not none");
    assert.match(r.symbol, /^\$MDU:anymodel_read\[/);

    const d = f.ask({ op: "declassifySymbol", symbol: r.symbol, sessionKey: S });
    assert.equal(d["allowed"], true, String(d["reason"]));
    const st = f.ask({ op: "sessionState", sessionKey: S });
    assert.deepEqual([st["confidentiality"], st["bindings"]], ["any-model", ["example.com"]]);

    const bound = egress(f, S, "example.com");
    assert.equal(bound.allow, true, "the memo's own bound host is released (the over-block this fixes)");
    assert.equal(bound.ruleRef?.id, "session:high-bound-release");
    const away = egress(f, S, "httpbin.org");
    assert.equal(away.allow, false, "CONFIDENTIALITY: an unbound host still asks");
    assert.equal(away.requiresApproval, true);
    assert.equal(away.ruleRef?.id, "session:high-unbound");
    assert.equal(egress(f, S, "evil-example.com").allow, false, "label-boundary host match");

    // A later bindings sync (any label act) reads the STORED origin: the
    // row and the session keep the binding instead of being narrowed away.
    f.ask({ op: "setPathLabel", path: join(f.ws, "unrelated.txt"), confidentiality: "no-model" });
    const again = readResult(f, S, "memo/brief.md", { relativeBase: f.ws });
    assert.equal(again.symbol, r.symbol, "the re-sent result reuses its row");
    assert.deepEqual(again.bindings, ["example.com"], "the sync keeps the label's binding");
    assert.equal(egress(f, S, "example.com").allow, true, "and the session keeps its release");
  } finally {
    f.close();
  }
});

test("fail-closed: no base, a base the session's surface does not vouch for, or a value the tool may read elsewhere keeps the relative origin, bound nowhere", () => {
  const f = fixture();
  try {
    // No base (a proxy the launcher named no directory).
    f.ask({ op: "setSessionSpec", sessionKey: "oc-nobase", spec: "openclaw-agent", requestedBy: "unit" });
    const none = readResult(f, "oc-nobase", "memo/brief.md");
    assert.deepEqual([none.origin, none.bindings], ["memo/brief.md", null]);
    // Declassifying it leaves the session bound nowhere: every host asks.
    const d = f.ask({ op: "declassifySymbol", symbol: none.symbol, sessionKey: "oc-nobase" });
    assert.equal(d["allowed"], true, String(d["reason"]));
    assert.equal(egress(f, "oc-nobase", "example.com").allow, false, "no binding is invented");
    // Claude Code's surface names no launch base (its relative paths follow `cd`).
    f.ask({ op: "setSessionSpec", sessionKey: "cc", spec: "claude-code", requestedBy: "unit" });
    const cc = readResult(f, "cc", "memo/brief.md", { relativeBase: f.ws });
    assert.deepEqual([cc.origin, cc.bindings], ["memo/brief.md", null]);
    // A tool the surface does not list under `paths` (its untrusted result
    // taints the session, which is why the declassify above came first).
    const other = f.ask({ op: "symbolize", tool: "web_fetch", value: BRIEF, origin: "memo/brief.md", relativeBase: f.ws, sessionKey: "oc-nobase", callId: "toolu_wf", confidentiality: "any-model" });
    const otherRow = (f.server as unknown as { symbolMap: { symbols: Map<string, { origin: string | null }> } }).symbolMap.symbols.get(other["symbol"] as string)!;
    assert.equal(otherRow.origin, "memo/brief.md");
    // A leading `@` (OpenClaw strips it): may name another file.
    const at = readResult(f, "oc-nobase", "@memo/brief.md", { relativeBase: f.ws });
    assert.equal(at.origin, "@memo/brief.md");
    // A view-map translated origin is not the relative value.
    const human = readResult(f, "oc-nobase", "memo/brief.md", { relativeBase: f.ws, originHuman: "/elsewhere/memo/brief.md" });
    assert.equal(human.origin, "memo/brief.md");

  } finally {
    f.close();
  }
});

test("axis OFF: the origin is stored as sent (secrets-axis behavior only)", () => {
  const f = fixture(false);
  try {
    f.ask({ op: "setSessionSpec", sessionKey: "oc-off", spec: "openclaw-agent", requestedBy: "unit" });
    const r = f.ask({ op: "symbolize", tool: "read", value: BRIEF, origin: "memo/brief.md", relativeBase: f.ws, sessionKey: "oc-off", callId: "toolu_off" });
    const row = (f.server as unknown as { symbolMap: { symbols: Map<string, { origin: string | null }> } }).symbolMap.symbols.get(r["symbol"] as string)!;
    assert.equal(row.origin, "memo/brief.md");
  } finally {
    f.close();
  }
});
