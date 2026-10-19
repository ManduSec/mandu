/**
 * goose-auth-substitution.test — Goose's own key file twinned, its key put
 * back in the auth header by the model proxy (agent-sign-in.md §3): the REAL
 * goose binary, the REAL launcher (`main()`), the real arbiter and
 * anthropic-proxy, and a scripted upstream on loopback (TLS) that records
 * `x-api-key` and `authorization`. Made-up keys only; no network. No guard
 * here (MANDU_NO_KERNEL=1, the twin bind); the guarded half is
 * test/kernel/goose-keyring.test.ts. Self-SKIPs without a goose binary.
 *
 *   anthropic  secrets.yaml holds ANTHROPIC_API_KEY: the launch grants it
 *              the upstream's host and twins the file. The upstream receives
 *              the REAL key in `x-api-key` on every turn; a shell in the
 *              agent's world that base64-dumps every file under
 *              ~/.config (no word of the path, so only the file's own bytes
 *              decide what the model sees) shows the model the TWIN, the
 *              placeholder where the key was; and no model request carries
 *              the key or a piece of it;
 *   openai     secrets.yaml holds OPENAI_API_KEY and the launch routes Goose's
 *              openai provider: the upstream receives `Bearer <the real
 *              key>`, never the placeholder;
 *   opt-out    MANDU_AUTH_SUBSTITUTION=0: no grant, the file is Goose's own
 *              key file again (supported-agents.md §5.6.1), and the key still
 *              reaches the upstream.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { stateAxes } from "../axes.js";
import { FAKE_KEY, findGoose, gooseHome, gooseSkip, launchGoose, startStand, type Stand } from "../lib/goose-login-stand.js";

stateAxes("secrets"); // the shipped default: the key file is a catalog secret only with confidentiality on

const GOOSE = findGoose();
const SKIP = gooseSkip(GOOSE);
/** A made-up OpenAI-shaped key, never a real one. */
const FAKE_OPENAI_KEY = "sk-proj-MANDUFAKEgooseOPENAIkey0123456789abcdefABCDEFghij";

let stand: Stand;
before(async () => { if (!SKIP) stand = await startStand("mdu-goose-auth-"); });
after(async () => { await stand?.close(); });

/** Every base64 run of `text` (as JSON escaped it), decoded. */
function decodedRuns(text: string): string[] {
  return [...text.matchAll(/[A-Za-z0-9+/]{40,}={0,2}/g)].map((m) => Buffer.from(m[0], "base64").toString("utf8"));
}

test("anthropic: the upstream gets the real key in x-api-key, the agent's world reads the twin, and no model request carries the key", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home, secrets } = gooseHome(stand, "h-anth", `ANTHROPIC_API_KEY: ${FAKE_KEY}\n`);
  stand.seen.length = 0;
  stand.command = "for f in ~/.config/*/*; do base64 -w0 \"$f\"; echo; done";
  const { code, lines } = await launchGoose(GOOSE!, stand, home, { GOOSE_DISABLE_KEYRING: "1" }, { kernel: false });
  assert.equal(code, 0, `goose under Mandu exited 0:\n${lines.join("\n")}`);
  assert.ok(stand.seen.length >= 2, `the turns reached the upstream (${stand.seen.length})`);
  for (const q of stand.seen) {
    assert.equal(q.key, FAKE_KEY, `x-api-key is the REAL key, put back by the proxy (${q.key?.slice(0, 24)}…)`);
    assert.ok(!q.body.includes(FAKE_KEY), "INVARIANT: no model request carries the key");
    assert.ok(!q.body.includes("MANDUFAKEgoose"), "INVARIANT: not even a piece of it");
    for (const d of decodedRuns(q.body)) assert.ok(!d.includes("MANDUFAKEgoose"), "INVARIANT: nor an encoding of it");
  }
  const last = stand.seen.at(-1)!.body;
  assert.match(last, /tool_result/, "the shell's result went back to the model");
  const twin = decodedRuns(last).find((d) => d.includes("ANTHROPIC_API_KEY:"));
  assert.ok(twin, `the shell dumped secrets.yaml: ${last.slice(last.indexOf("tool_result"), last.indexOf("tool_result") + 600)}`);
  assert.match(twin!, /^ANTHROPIC_API_KEY: \$MDU:nomodel_Read\[[0-9a-f]+\]\.ANTHROPIC_API_KEY\s*$/, "the agent's world holds the placeholder, not the key");
  assert.ok(lines.some((l) => l.includes(secrets) && /placeholder in Goose's world/.test(l) && l.includes("127.0.0.1")), `the launch said so:\n${lines.join("\n")}`);
  assert.ok(!lines.some((l) => /agent's own key file/.test(l)), "the file is not left readable");
  assert.ok(!lines.some((l) => /no Goose login found/.test(l)), "no login warning: the file is a login");
});

test("openai: the upstream gets `Bearer <the real key>` for Goose's openai provider", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home } = gooseHome(stand, "h-oai", `OPENAI_API_KEY: ${FAKE_OPENAI_KEY}\n`);
  stand.seen.length = 0;
  stand.command = null;
  const { code, lines } = await launchGoose(GOOSE!, stand, home, {
    GOOSE_DISABLE_KEYRING: "1", GOOSE_PROVIDER: "openai", OPENAI_HOST: stand.upstreamOrigin, GOOSE_MODEL: "gpt-4o",
  }, { kernel: false });
  assert.equal(code, 0, `goose under Mandu exited 0:\n${lines.join("\n")}`);
  const chat = stand.seen.filter((q) => /chat\/completions/.test(q.path));
  assert.ok(chat.length >= 1, `the turns reached the upstream: ${stand.seen.map((q) => q.path).join(", ")}`);
  for (const q of chat) {
    assert.equal(q.auth, `Bearer ${FAKE_OPENAI_KEY}`, `the REAL key, put back by the proxy (${q.auth?.slice(0, 30)}…)`);
    assert.ok(!q.body.includes(FAKE_OPENAI_KEY) && !q.body.includes("MANDUFAKEgooseOPENAI"), "INVARIANT: no model request carries the key");
  }
  assert.ok(lines.some((l) => /placeholder in Goose's world/.test(l)), lines.join("\n"));
});

test("opt-out (MANDU_AUTH_SUBSTITUTION=0): the file is Goose's own key file again, and the key reaches the upstream", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home, secrets } = gooseHome(stand, "h-opt", `ANTHROPIC_API_KEY: ${FAKE_KEY}\n`);
  stand.seen.length = 0;
  stand.command = null;
  const { code, lines } = await launchGoose(GOOSE!, stand, home, { GOOSE_DISABLE_KEYRING: "1", MANDU_AUTH_SUBSTITUTION: "0" }, { kernel: false });
  assert.equal(code, 0, lines.join("\n"));
  assert.ok(stand.seen.length >= 1 && stand.seen.every((q) => q.key === FAKE_KEY), "Goose sent the key it read raw");
  assert.ok(lines.some((l) => l.includes(secrets) && /agent's own key file/.test(l)), lines.join("\n"));
  assert.ok(!lines.some((l) => /placeholder in Goose's world/.test(l)));
});

// ── Goose's Chat Completions providers and key variables (§3.10) ─────────────

/** A made-up OpenRouter-shaped key, never a real one. */
const FAKE_OR_KEY = "sk-or-v1-MANDUFAKEgooseOPENROUTERkey0123456789abcdefABCDEF";

test("openrouter (secrets.yaml): the upstream gets `Bearer <the real key>`, the file is twinned", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home, secrets } = gooseHome(stand, "h-or", `OPENROUTER_API_KEY: ${FAKE_OR_KEY}\n`);
  stand.seen.length = 0;
  stand.command = null;
  const { code, lines } = await launchGoose(GOOSE!, stand, home, {
    GOOSE_DISABLE_KEYRING: "1", GOOSE_PROVIDER: "openrouter", OPENROUTER_HOST: stand.upstreamOrigin, GOOSE_MODEL: "openai/gpt-4o",
  }, { kernel: false });
  assert.equal(code, 0, `goose under Mandu exited 0:\n${lines.join("\n")}`);
  const chat = stand.seen.filter((q) => /chat\/completions/.test(q.path));
  assert.ok(chat.length >= 1, `the turns reached the upstream: ${stand.seen.map((q) => q.path).join(", ")}`);
  for (const q of chat) assert.equal(q.auth, `Bearer ${FAKE_OR_KEY}`, `the REAL key, put back by the proxy (${q.auth?.slice(0, 30)}…)`);
  for (const q of stand.seen) assert.ok(!q.body.includes(FAKE_OR_KEY) && !q.body.includes("MANDUFAKEgooseOPENROUTER"), "INVARIANT: no model request carries the key");
  assert.ok(lines.some((l) => l.includes(secrets) && /placeholder in Goose's world/.test(l)), lines.join("\n"));
});

test("key variables (§3.10): OPENROUTER_API_KEY and ANTHROPIC_API_KEY in Goose's environment are placeholders; the upstream gets the real keys; a shell reads only placeholders", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home } = gooseHome(stand, "h-env");
  stand.seen.length = 0;
  stand.command = "printf 'OR=%s AN=%s\\n' \"$OPENROUTER_API_KEY\" \"$ANTHROPIC_API_KEY\" | base64 -w0; echo";
  const { code, lines } = await launchGoose(GOOSE!, stand, home, {
    GOOSE_DISABLE_KEYRING: "1", ANTHROPIC_API_KEY: FAKE_KEY, OPENROUTER_API_KEY: FAKE_OR_KEY,
  }, { kernel: false });
  assert.equal(code, 0, `goose under Mandu exited 0:\n${lines.join("\n")}`);
  const turns = stand.seen.filter((q) => /\/v1\/messages/.test(q.path));
  assert.ok(turns.length >= 2, `the turns reached the upstream (${turns.length})`);
  for (const q of turns) assert.equal(q.key, FAKE_KEY, "x-api-key is the REAL key, put back by the proxy");
  for (const q of stand.seen) {
    for (const v of [FAKE_KEY, FAKE_OR_KEY]) assert.ok(!q.body.includes(v), "INVARIANT: no model request carries a key");
    for (const d of decodedRuns(q.body)) assert.ok(!d.includes("MANDUFAKEgoose"), "INVARIANT: nor an encoding of one");
  }
  const shown = stand.seen.flatMap((q) => decodedRuns(q.body)).find((d) => d.startsWith("OR="));
  assert.ok(shown, "the shell's output went back to the model");
  assert.match(shown!, /^OR=\$MDU:nomodel_Env\[[0-9a-f]+\]\.OPENROUTER_API_KEY AN=\$MDU:nomodel_Env\[[0-9a-f]+\]\.ANTHROPIC_API_KEY\s*$/, "the agent's environment holds placeholders");
  assert.ok(lines.some((l) => /ANTHROPIC_API_KEY is a placeholder in Goose's environment/.test(l)), lines.join("\n"));
});

test("openrouter (its key variable, the routed provider): masked in Goose's environment, put back as Bearer", { skip: SKIP, timeout: 300_000 }, async () => {
  const { home } = gooseHome(stand, "h-or-env");
  stand.seen.length = 0;
  stand.command = null;
  const { code, lines } = await launchGoose(GOOSE!, stand, home, {
    GOOSE_DISABLE_KEYRING: "1", GOOSE_PROVIDER: "openrouter", OPENROUTER_HOST: stand.upstreamOrigin, GOOSE_MODEL: "openai/gpt-4o",
    OPENROUTER_API_KEY: FAKE_OR_KEY,
  }, { kernel: false });
  assert.equal(code, 0, `goose under Mandu exited 0:\n${lines.join("\n")}`);
  const chat = stand.seen.filter((q) => /chat\/completions/.test(q.path));
  assert.ok(chat.length >= 1, `the turns reached the upstream: ${stand.seen.map((q) => q.path).join(", ")}`);
  for (const q of chat) assert.equal(q.auth, `Bearer ${FAKE_OR_KEY}`, `the REAL key, put back by the proxy (${q.auth?.slice(0, 30)}…)`);
  for (const q of stand.seen) assert.ok(!q.body.includes(FAKE_OR_KEY), "INVARIANT: no model request carries the key");
  assert.ok(lines.some((l) => /OPENROUTER_API_KEY is a placeholder in Goose's environment/.test(l)), lines.join("\n"));
});
