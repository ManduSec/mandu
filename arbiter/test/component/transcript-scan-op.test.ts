/**
 * transcript-scan-op — the arbiter's `scanAgentTranscripts` op over its
 * socket (confidentiality-plan-17-past-sessions-scan.md; arbiter/ipc/server.ts
 * `scanAgentTranscriptsOp`): the values it looks for come from its own
 * discovery of the home and never from the caller (a caller's `known` would
 * make it an oracle for "was this ever sent"), a bad `eventsDir` or `since`
 * is refused, and with the confidentiality axis OFF it scans nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the op's axis-OFF answer is asserted explicitly below

const STRIPE = `${"sk" + "_live_"}51Qz7Kp2Lm9Xw3Rt6Yv8Nb4C`;
const GUESS = "Correct-Horse-Battery-Staple-42";

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

async function withServer(confidentiality: boolean, fn: (sock: string, home: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-tsop-"));
  const home = join(dir, "home");
  mkdirSync(join(home, "shop"), { recursive: true });
  writeFileSync(join(home, "shop", ".env"), `STRIPE_KEY=${STRIPE}\n`);
  const cc = join(home, ".claude", "projects", "p");
  mkdirSync(cc, { recursive: true });
  writeFileSync(join(cc, "s.jsonl"), [
    JSON.stringify({ type: "user", timestamp: "2026-10-01T00:00:00Z", message: { content: `STRIPE_KEY=${STRIPE}` } }),
    JSON.stringify({ type: "user", timestamp: "2026-10-01T00:00:01Z", message: { content: `password ${GUESS}` } }),
  ].join("\n") + "\n");
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({ socketPath: sock, dbPath: join(dir, "s.sqlite"), eventDir: join(dir, "ev"), log: () => {}, confidentiality, integrity: false, policyPollMs: 0 });
  await server.listen();
  try { await fn(sock, home); } finally { await server.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("scanAgentTranscripts: finds the home's own secret; a value the caller passes is never looked for", async () => {
  await withServer(true, async (sock, home) => {
    const r = await call(sock, { op: "scanAgentTranscripts", home, known: [{ value: GUESS, path: "guess", name: "PASSWORD" }] });
    assert.equal(r.ok, true, r.error);
    const findings = (r.result!["findings"] as Array<{ kind: string; preview: string }>);
    assert.deepEqual(findings.filter((f) => f.kind === "known").map((f) => f.preview), ["STRIPE_KEY in ~/shop/.env"]);
    assert.ok(!JSON.stringify(r).includes("guess"), "the caller's value was not looked for");
    assert.ok(!JSON.stringify(r).includes(STRIPE.slice(8, 16)));
  });
});

test("scanAgentTranscripts: a relative eventsDir or a bad since is refused", async () => {
  await withServer(true, async (sock, home) => {
    assert.match((await call(sock, { op: "scanAgentTranscripts", home, eventsDir: "rel/events" })).error ?? "", /eventsDir must be an absolute path/);
    assert.match((await call(sock, { op: "scanAgentTranscripts", home, since: "yesterday" })).error ?? "", /since must be a time in ms/);
  });
});

test("scanAgentTranscripts: the agents' directory variables are this HOME's; another home's stores are read at their defaults", async () => {
  const elsewhere = mkdtempSync(join(tmpdir(), "mdu-tsop-xdg-"));
  const saved = process.env["XDG_DATA_HOME"];
  try {
    // An OpenCode store where this process's XDG_DATA_HOME points: not the fixture home's.
    mkdirSync(join(elsewhere, "opencode"), { recursive: true });
    writeFileSync(join(elsewhere, "opencode", "opencode.db"), "not a database: opening it would count as unreadable");
    process.env["XDG_DATA_HOME"] = elsewhere;
    await withServer(true, async (sock, home) => {
      const r = await call(sock, { op: "scanAgentTranscripts", home });
      assert.equal(r.ok, true, r.error);
      assert.deepEqual(r.result!["sessions"], { "claude-code": 1 }, "only the fixture home's stores");
      assert.equal((r.result!["capped"] as { readFailed: number }).readFailed, 0, "the other store was never opened");
    });
  } finally {
    if (saved === undefined) delete process.env["XDG_DATA_HOME"]; else process.env["XDG_DATA_HOME"] = saved;
    rmSync(elsewhere, { recursive: true, force: true });
  }
});

test("scanAgentTranscripts: a CLI's token is known when the launch walk's caps left its store out (2026-10-22)", async () => {
  // A launch's walk stops at MAX_FILES (here inside ~/.aws, which sorts
  // before ~/.config and the project) and keeps MAX_SKIP_RECORDS records,
  // the agents' logins last (here after 210 folders below the depth cap):
  // the GitHub CLI's and glab's tokens, Claude Code's login and the
  // project's key were each reported by its shape ("not in your files
  // now"), not as the person's.
  const gho = `${"gh" + "o_"}Qm7Lz2Xw4Rt9Yv6Nb1Cs5Hf0Gp2Ae7WqK3Jd`;
  const glpat = `${"gl" + "pat-"}Zy9Xw8Vu7Ts6Rq5Po4Nm`;
  const oat = `${"sk-ant-" + "oat01-"}Qm7Lz2Xw4Rt9Yv6Nb1Cs5Hf0Gp2Ae7WqK3Jd8`;
  await withServer(true, async (sock, home) => {
    const cache = join(home, ".aws", "cli", "cache");
    mkdirSync(cache, { recursive: true });
    for (let i = 0; i < 480; i++) writeFileSync(join(cache, `c${String(i).padStart(3, "0")}.json`), "{}");
    for (let i = 0; i < 210; i++) mkdirSync(join(home, "deep", "a", "b", "c", `d${i}`), { recursive: true });
    mkdirSync(join(home, ".config", "gh"), { recursive: true });
    writeFileSync(join(home, ".config", "gh", "hosts.yml"), `github.com:\n    users:\n        alice:\n            oauth_token: ${gho}\n    oauth_token: ${gho}\n    user: alice\n`);
    mkdirSync(join(home, ".config", "glab-cli"), { recursive: true });
    writeFileSync(join(home, ".config", "glab-cli", "config.yml"), `hosts:\n    gitlab.com:\n        token:\n    gitlab.corp.example:\n        token: ${glpat}\n`);
    writeFileSync(join(home, ".claude", ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: oat } }));
    writeFileSync(join(home, ".claude", "projects", "p", "t.jsonl"), JSON.stringify({ type: "user", timestamp: "2026-10-02T00:00:00Z", message: { content: `gh auth token: ${gho}\nglab: ${glpat}\nlogin: ${oat}` } }) + "\n");
    const r = await call(sock, { op: "scanAgentTranscripts", home });
    assert.equal(r.ok, true, r.error);
    const findings = r.result!["findings"] as Array<{ kind: string; preview: string; sessions: number }>;
    assert.deepEqual(findings.filter((f) => f.kind === "known").map((f) => f.preview).sort(), [
      "STRIPE_KEY in ~/shop/.env",
      "accessToken in ~/.claude/.credentials.json",
      "github.com.users.alice.oauth_token in ~/.config/gh/hosts.yml",
      "hosts.gitlab.corp.example.token in ~/.config/glab-cli/config.yml",
    ]);
    assert.deepEqual(findings.filter((f) => f.kind !== "known").map((f) => f.kind), [], "none of them again by its shape");
    for (const v of [gho, glpat, oat]) assert.ok(!JSON.stringify(r).includes(v.slice(8, 16)), "no value in the answer");
  });
});

test("scanAgentTranscripts: with the confidentiality axis OFF it scans nothing", async () => {
  await withServer(false, async (sock, home) => {
    const r = await call(sock, { op: "scanAgentTranscripts", home });
    assert.equal(r.ok, true);
    assert.equal(r.result!["axis"], false);
    assert.deepEqual(r.result!["findings"], []);
    assert.deepEqual(r.result!["sessions"], {});
  });
});
