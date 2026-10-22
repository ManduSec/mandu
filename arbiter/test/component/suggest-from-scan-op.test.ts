/**
 * suggest-from-scan-op — the arbiter's `suggestFromScan` op over its socket
 * (confidentiality-plan-17-past-sessions-scan.md §3 item 13; server.ts
 * `suggestFromScanOp`, transcript-suggestions.ts): the files `mandu scan`'s
 * "your secrets" came from, named by path and key name, become plan 14
 * suggestions (source `past-sessions`) only after the arbiter has read each
 * file itself.
 *
 *   - a CLI's config holding a token under the named key: filed, once (a
 *     second call finds it pending), applied on the data socket like any
 *     scan suggestion, and covered once applied;
 *   - a project `.env` the catalog protects: covered, not filed;
 *   - an agent's own login, a file in Mandu's home, a link to the token's
 *     file, a path outside HOME, a file with no credential under the named
 *     key: refused, each with its reason;
 *   - bad arguments are refused; with the confidentiality axis OFF nothing
 *     is filed;
 *   - the oracle: no 8-character run of a planted value in any reply, the
 *     arbiter's log, its event files or its database.
 *
 * Axes stated: secrets (the axis-OFF answer is asserted explicitly).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

// Built at run time: no credential-shaped literal in this file.
const TOKEN = `${"gh" + "o_"}Zt4Qm8Lp2Xw7Rk9Vb3Nc6Hj1Df5Gs0Ae2Yu8T`;
const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
const CODEX = `${"ey" + "J"}hbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMzQ1Njc4In0.c2lnbmF0dXJlLWZvci10ZXN0cw`;
const PLANTED = [TOKEN, STRIPE, CODEX];

function assertNoValue(where: string, text: string): void {
  for (const v of PLANTED) {
    for (let i = 0; i + 8 <= v.length; i++) {
      const piece = v.slice(i, i + 8);
      if (piece === "sk_live_") continue;
      assert.ok(!text.includes(piece), `${where} holds "${piece}" of a planted value`);
    }
  }
}

function call(sock: string, req: Record<string, unknown>): Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }> {
  return new Promise((resolve, reject) => {
    const c = net.createConnection(sock);
    let buf = "";
    c.on("data", (d) => {
      buf += d.toString();
      const nl = buf.indexOf("\n");
      if (nl >= 0) { c.end(); resolve(JSON.parse(buf.slice(0, nl))); }
    });
    c.on("error", reject);
    c.write(`${JSON.stringify({ id: 1, ...req })}\n`);
  });
}

interface Fixture { dir: string; home: string; sock: string; logs: string[] }

async function withServer(confidentiality: boolean, fn: (f: Fixture) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-sfs-"));
  const home = join(dir, "home");
  mkdirSync(join(home, ".config", "some-cli"), { recursive: true });
  writeFileSync(join(home, ".config", "some-cli", "config.yml"), `user: someone\ntoken: ${TOKEN}\n`);
  mkdirSync(join(home, "shop"), { recursive: true });
  writeFileSync(join(home, "shop", ".env"), `STRIPE_KEY=${STRIPE}\n`);
  mkdirSync(join(home, ".codex"), { recursive: true });
  writeFileSync(join(home, ".codex", "auth.json"), JSON.stringify({ tokens: { access_token: CODEX } }));
  mkdirSync(join(home, ".mandu", "state"), { recursive: true });
  writeFileSync(join(home, ".mandu", "state", "notes.yml"), `token: ${TOKEN}\n`);
  symlinkSync(join(home, ".config", "some-cli", "config.yml"), join(home, "link.yml"));
  writeFileSync(join(home, "plain.yml"), "colour: blue\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  const sock = join(dir, "a.sock");
  const logs: string[] = [];
  const server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "s.sqlite"), eventDir: join(dir, "ev"), log: (m) => logs.push(m), policyPath: policy,
    confidentiality, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  try { await fn({ dir, home, sock, logs }); } finally { await server.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("suggestFromScan: a file no rule covers becomes one past-sessions suggestion; the rest are covered or refused; no value anywhere", async () => {
  await withServer(true, async ({ dir, home, sock, logs }) => {
    const cfg = join(home, ".config", "some-cli", "config.yml");
    const files = [
      { path: cfg, names: ["token"], sessions: 3, last: "2026-10-19T08:00:00Z" },
      { path: join(home, "shop", ".env"), names: ["STRIPE_KEY"], sessions: 1 },
      { path: join(home, ".codex", "auth.json"), names: ["tokens.access_token"], sessions: 1 },
      { path: join(home, ".mandu", "state", "notes.yml"), names: ["token"], sessions: 1 },
      { path: join(home, "link.yml"), names: ["token"], sessions: 1 },
      { path: join(dir, "elsewhere.yml"), names: ["token"], sessions: 1 },
      { path: join(home, "plain.yml"), names: ["colour"], sessions: 1 },
    ];
    const r = await call(sock, { op: "suggestFromScan", home, files });
    assert.equal(r.ok, true, r.error);
    const res = r.result as { axis: boolean; filed: string[]; covered: number; refused: Array<{ path: string; why: string }>; suggestions: Array<Record<string, unknown>> };
    assert.equal(res.axis, true);
    assert.equal(res.filed.length, 1, "the CLI's config is filed");
    assert.equal(res.covered, 1, "the catalog protects the .env");
    assert.deepEqual(res.refused.map((x) => [x.path.slice(home.length), x.why]).sort(), [
      ["/.codex/auth.json", "agent-own"],
      ["/.mandu/state/notes.yml", "mandu-state"],
      ["/link.yml", "not-a-file"],
      ["/plain.yml", "no-credential"],
      [join(dir, "elsewhere.yml").slice(home.length), "not-under-home"],
    ].sort());
    const s = res.suggestions;
    assert.equal(s.length, 1);
    assert.equal(s[0]!["source"], "past-sessions");
    assert.equal(s[0]!["requestedBy"], "mandu:scan");
    assert.equal(s[0]!["rotate"], true, "the key did leave the machine");
    assert.deepEqual(s[0]!["edits"], [{ op: "lock-path", path: cfg, level: "no-model" }]);
    assert.deepEqual((s[0]!["evidence"] as { pastSessions: unknown }).pastSessions, { names: ["token"], sessions: 3, last: "2026-10-19T08:00:00.000Z" });
    assert.equal(s[0]!["repoRoot"], join(home, ".config", "some-cli"), "a file outside any project groups by its folder, never by HOME");

    // A second scan files nothing new: it is pending already.
    const again = await call(sock, { op: "suggestFromScan", home, files: files.slice(0, 1) });
    assert.deepEqual((again.result as { filed: string[]; alreadyPending: number }).filed, []);
    assert.equal((again.result as { alreadyPending: number }).alreadyPending, 1);

    // The person applies it (the terminal's data-socket apply), and the file is covered.
    const applied = await call(sock, { op: "applySuggestion", suggestionId: s[0]!["id"] });
    assert.equal(applied.ok, true, applied.error);
    const after = await call(sock, { op: "suggestFromScan", home, files: files.slice(0, 1) });
    assert.deepEqual([(after.result as { filed: string[] }).filed, (after.result as { covered: number }).covered], [[], 1]);

    for (const x of [r, again, applied, after]) assertNoValue("a reply", JSON.stringify(x));
    assertNoValue("the arbiter's log", logs.join("\n"));
    const ev = join(dir, "ev");
    for (const f of readdirSync(ev, { recursive: true }) as string[]) {
      try { assertNoValue(`event file ${f}`, readFileSync(join(ev, f), "utf8")); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "EISDIR") throw e; }
    }
    assertNoValue("the database", readFileSync(join(dir, "s.sqlite")).toString("latin1"));
    assertNoValue("policy.yaml", readFileSync(join(dir, "policy.yaml"), "utf8"));
    assert.match(readFileSync(join(dir, "policy.yaml"), "utf8"), /some-cli\/config\.yml/, "the applied rule names the file");
  });
});

test("suggestFromScan: bad arguments are refused", async () => {
  await withServer(true, async ({ home, sock }) => {
    assert.match((await call(sock, { op: "suggestFromScan", home: "rel", files: [] })).error ?? "", /home must be an absolute path/);
    assert.match((await call(sock, { op: "suggestFromScan", home, files: "x" })).error ?? "", /files must be a list/);
    assert.match((await call(sock, { op: "suggestFromScan", home, files: [{ path: "rel", names: ["a"] }] })).error ?? "", /absolute path/);
    assert.match((await call(sock, { op: "suggestFromScan", home, files: [{ path: "/a", names: [] }] })).error ?? "", /names/);
    assert.match((await call(sock, { op: "suggestFromScan", home, files: [{ path: "/a", names: ["a"], last: "yesterday" }] })).error ?? "", /last must be a time/);
    assert.match((await call(sock, { op: "suggestFromScan", home, files: Array.from({ length: 65 }, () => ({ path: "/a", names: ["a"] })) })).error ?? "", /at most 64/);
  });
});

test("suggestFromScan: with the confidentiality axis OFF it files nothing", async () => {
  await withServer(false, async ({ home, sock }) => {
    const r = await call(sock, { op: "suggestFromScan", home, files: [{ path: join(home, ".config", "some-cli", "config.yml"), names: ["token"] }] });
    assert.equal(r.ok, true, r.error);
    assert.deepEqual([(r.result as { axis: boolean }).axis, (r.result as { filed: string[] }).filed], [false, []]);
  });
});
