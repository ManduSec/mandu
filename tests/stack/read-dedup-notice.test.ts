/**
 * read-dedup-notice — confidentiality.md §7.1, "The Read dedup notice" (tour
 * item 5), across the REAL components: a real ArbiterServer in `secrets` with
 * a policy file that labels deploy/staging.conf `no-model`, the real
 * anthropic-proxy in its production wiring (`new ArbiterClientAdapter(data,
 * human)`) with a mock model behind it, and the reply filter's production
 * adapter (`new ReplyArbiterAdapter(new ArbiterClient(humanSock))`).
 *
 * The bug: Claude Code answers a re-Read of an unchanged file with its own
 * sentence ("Wasted call — file unchanged since your last Read…") instead of
 * the file. The arbiter masked that sentence at the file's path-derived
 * level, so the model got a symbol standing for the harness's words, quoted
 * it as the file, and the reply filter showed the user the notice as the
 * file's content. Now:
 *
 *   1. the first Read of the secret file is one symbol, which the reply
 *      filter resolves to the file (no change);
 *   2. a re-Read whose result is EXACTLY a dedup notice (both sentences, and
 *      the seeded form naming the call's own path) reaches the model as the
 *      notice itself, in clear: no symbol stands for it;
 *   3. NEGATIVE: the notice with file text appended or prepended, a
 *      lookalike (a hyphen for the em dash, a value tacked on), a file whose
 *      content IS the notice (behind the gutter), the seeded form naming
 *      another path, the empty-file warning, and the same sentence as a
 *      Bash result naming the file all stay masked, as before;
 *   4. THE ORACLE: no byte of the file anywhere in what the model received,
 *      and no symbol in it resolves to the bare notice.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { ArbiterClientAdapter as ReplyArbiterAdapter } from "../../interceptors/reply-filter/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const TOKEN = "ghp_FakeDedupNotice8Hq3Zr5Lw2Kt9Xc4";
const FILE = `[staging]\nhost = "staging.dedup.example"\ntoken = "${TOKEN}"\n`;
const FILE_PIECES = [TOKEN, "ghp_FakeDedup", "staging.dedup.example", "[staging]"];
/** Claude Code's Read rendering of FILE. */
const READ_RENDER = FILE.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
const WASTED = "Wasted call — file unchanged since your last Read. Refer to that earlier tool_result instead.";
const UNCHANGED =
  "File unchanged since last read. The content from the earlier Read tool_result in this conversation is still current — refer to that instead of re-reading.";
const seeded = (p: string) =>
  `<system-reminder>This file is already in your context (see "Contents of ${p}" above) and has not changed on disk. Use that content instead of re-reading.</system-reminder>`;
const EMPTY_FILE = "<system-reminder>Warning: the file exists but the contents are empty.</system-reminder>";
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]$/;
const TOKEN_RE = /\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\](?:\.[A-Za-z0-9_]+)*/g;

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("a re-Read of a secret file answered by Claude Code's dedup notice reaches the model as the notice, never a symbol the reply filter would show as the file; any result with a file byte or a lookalike stays masked (secrets axes, explicit)", async () => {
  const session = `read-dedup-notice-${process.pid}`;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-read-dedup-"));
  dirs.push(tmp);
  const ws = join(tmp, "mandu-try");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const path = join(ws, "deploy", "staging.conf");
  writeFileSync(path, FILE);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${path}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const upstream = new MockUpstream({ sse: buildTextSse("ok", { deltas: 1 }) });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream: upstream.fetcher, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const reply = new ReplyArbiterAdapter(await open(humanSock));

  type Msg = { role: string; content: unknown };
  const read = (id: string, content: string, file_path = path): Msg[] => [
    { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
  ];
  // The clear cases: exactly a dedup notice, nothing else.
  const clear: Array<[string, string]> = [
    ["toolu_wasted", WASTED],
    ["toolu_unchanged", UNCHANGED],
    ["toolu_wasted_ws", `${WASTED}\n`],
    ["toolu_seeded", seeded(path)],
  ];
  // The masked cases: a file byte, a lookalike, or not the dedup shape.
  const masked: Array<[string, string, string?]> = [
    ["toolu_appended", `${WASTED}\n${READ_RENDER}`],
    ["toolu_prepended", `${READ_RENDER}${WASTED}`],
    ["toolu_tacked", `${WASTED} ${TOKEN}`],
    ["toolu_hyphen", WASTED.replace("—", "-")],
    ["toolu_gutter", `     1\t${WASTED}\n`],
    ["toolu_seeded_other", seeded(join(ws, "deploy", "other.conf"))],
    ["toolu_empty", EMPTY_FILE],
  ];
  const messages: Msg[] = [
    { role: "user", content: "What is in deploy/staging.conf? Read it a few times." },
    ...read("toolu_first", READ_RENDER),
    ...clear.flatMap(([id, v]) => read(id, v)),
    ...masked.flatMap(([id, v]) => read(id, v)),
    // the same sentence from a tool that is not Claude Code's Read
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_bash", name: "Bash", input: { command: `cat ${path}` } }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_bash", content: WASTED }] },
  ];

  try {
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 256, tools: [{ name: "Read", input_schema: { type: "object" } }, { name: "Bash", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    const sent = upstream.requests.at(-1)!;
    const json = sent.json() as { messages: Msg[] };
    const resultOf = (id: string): string => {
      for (const m of json.messages) {
        if (!Array.isArray(m.content)) continue;
        for (const b of m.content as Array<{ type: string; tool_use_id?: string; content?: unknown }>) {
          if (b.type === "tool_result" && b.tool_use_id === id) return typeof b.content === "string" ? b.content : (b.content as Array<{ text: string }>).map((x) => x.text).join("");
        }
      }
      throw new Error(`no tool_result ${id}`);
    };

    // 1. the file's own Read: one symbol, which the reply filter resolves to the file
    const first = resultOf("toolu_first");
    assert.match(first, SYM_RE, `the secret file's Read is masked: ${first}`);
    assert.ok((await reply.desymbolize(first)).includes(TOKEN), "the reply filter shows the human the file for its symbol");

    // 2. the dedup notice: in clear, exactly as the harness wrote it
    for (const [id, v] of clear) {
      assert.equal(resultOf(id), v, `${id}: the dedup notice reaches the model as itself`);
    }

    // 3. everything else stays masked, as before
    for (const [id, v] of masked) {
      const got = resultOf(id);
      assert.notEqual(got, v, `${id}: masked`);
      assert.match(got, /\$MDU:/, `${id}: a symbol in its place: ${got}`);
      assert.ok(!got.includes("unchanged since") && !got.includes("Wasted call"), `${id}: no notice text in clear: ${got}`);
    }
    const bash = resultOf("toolu_bash");
    assert.match(bash, /\$MDU:/, `a Bash result naming the secret file stays masked whatever it says: ${bash}`);

    // 4. THE ORACLE: no byte of the file in what the model received, and no
    // symbol in a Read result that the reply filter would turn into the bare
    // notice (the Bash one above does, on purpose: its tool is not the Read
    // whose notice this rule knows, so its mask stands)
    for (const piece of FILE_PIECES) assert.ok(!sent.bodyText.includes(piece), `the model got file byte(s): ${piece}`);
    const readText = ["toolu_first", ...clear.map(([id]) => id), ...masked.map(([id]) => id)].map(resultOf).join("\n");
    const tokens = [...new Set(readText.match(TOKEN_RE) ?? [])];
    assert.ok(tokens.length >= masked.length, `the masked results carry symbols: ${tokens.join(", ")}`);
    for (const t of tokens) {
      const shown = await reply.desymbolize(t);
      assert.notEqual(shown, t, `the reply filter resolves ${t}`);
      for (const n of [WASTED, UNCHANGED, seeded(path)]) assert.notEqual(shown.trim(), n, `${t} stands for the bare notice`);
    }
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
  }
});
