/**
 * key-shapes-misses e2e — the detection misses closed 2026-10-02
 * (secret-discovery.md §3.2 item 5; confidentiality-plan-15-prompt-filter.md
 * §4.1, the `key-shapes` filter) through the production path: a listening
 * ArbiterServer whose policy FILE turns `key-shapes` on, the production
 * `ArbiterClient` on its data socket, `filterPrompt` as the model proxies
 * call it. Each value below reached the model raw before the change:
 *
 *   (a) a real-format key whose random body holds `xxxx` / `dummy` by
 *       chance (an Anthropic key, an AWS secret key, a fine-grained GitHub
 *       token): the stand-in word filter dropped it;
 *   (b) `DB_PASSWORD=` with a letters-only password: the assignment rule
 *       demanded a digit;
 *   (c) `github_pat_` has no published checksum: it takes (a)'s rule.
 *
 * And a person's placeholders (`sk-ant-…-PLACEHOLDER-…`, AWS's documented
 * example key, `DB_PASSWORD=your_password_here`) still pass untouched.
 * Oracle: no value byte in the answer; each is redacted by its kind.
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

// Assembled at run time: this file holds no key-shaped literal.
const R1 = "Q7wX2mZ9pL4kV8rT";
const R2 = "Hn3bR6tY9cJ2wE5q";
const ANTHROPIC = "sk-" + "ant-" + "api03-" + R1 + "xxxx" + R2;
const AWS_SECRET = "Q7wX2m" + "Z9/pL4kV8rTa" + "dummy" + "Hn3bR6tY9cJ2wE5q+";
const LETTERS_PW = "hJkqWz" + "PmvXrTbnLs";
const PAT = "github" + "_pat_" + "11ABCDEFG0" + R1.slice(0, 12) + "_" + R1 + R2 + "xxxx" + R1 + R2.slice(0, 7);
const STAND_INS = [
  "sk-" + "ant-oat01-" + "PLACEHOLDER-not-a-real-token",
  "aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
  "DB_PASSWORD=" + "your_password_here_123",
  "token = floatToFixedToStr(token)",
];

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-key-shapes-misses-"));
  dirs.push(dir);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\nprompt_filters:\n  filters:\n    key-shapes: on\n");
  const sock = join(dir, "a.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0, packDir: null,
    promptPackDir: join(dir, "packs"), adminPromptPackDir: join(dir, "admin-packs"), adminPolicyDir: null, packKeysDir: join(dir, "keys"),
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  return { data, close: async () => { data.close(); await server.close(); } };
}

test("the values the detector missed are redacted by kind in the human's prompt; a person's placeholders pass", async () => {
  const r = await rig();
  try {
    const text = [
      `(a) the key is ${ANTHROPIC}`,
      `(a) aws_secret_access_key = ${AWS_SECRET}`,
      `(b) DB_PASSWORD=${LETTERS_PW}`,
      `(c) GH_TOKEN=${PAT}`,
    ].join("\n");
    const out = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: "h", origin: "human", text }] });
    const [h] = out.segments;
    assert.equal(h!.action, "rewrite");
    assert.equal(h!.text, [
      "(a) the key is [redacted: secret.shape.anthropic-key]",
      "(a) aws_secret_access_key = [redacted: secret.shape.aws-secret-key]",
      "(b) DB_PASSWORD=[redacted: secret.shape.credential-assignment]",
      "(c) GH_TOKEN=[redacted: secret.shape.github-token]",
    ].join("\n"));
    const answer = JSON.stringify(out);
    for (const v of [ANTHROPIC, AWS_SECRET, LETTERS_PW, PAT, R1, R2]) assert.ok(!answer.includes(v), "no value byte in the answer");

    const plain = STAND_INS.join("\n");
    const ok = await r.data.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: "p", origin: "human", text: plain }] });
    assert.equal(ok.segments[0]!.text ?? plain, plain, "a person's placeholders and code are not redacted");
    assert.notEqual(ok.segments[0]!.action, "rewrite");
  } finally {
    await r.close();
  }
});
