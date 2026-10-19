#!/usr/bin/env node
/**
 * set-api-key — put a vendor API key into the developer's Mandu secrets file,
 * interactively: run it, paste the key at the prompt (no echo), done.
 *
 *   node scripts/set-api-key.mjs                 asks which provider, then the key
 *   node scripts/set-api-key.mjs anthropic       an Anthropic Console key (sk-ant-api…)
 *   node scripts/set-api-key.mjs openai          an OpenAI key (sk-…, sk-proj-…)
 *   --dest FILE     another file (default: the Mandu home's secrets.json,
 *                   $MANDU_HOME/secrets.json else ~/.mandu/secrets.json,
 *                   which every checkout and worktree finds)
 *   --no-verify     skip the check against the vendor
 *
 * The file is the one scripts/secrets-to-env.mjs loads (`source
 * scripts/mandu-env.sh`, and the `mandu` shim): the key lands in its
 * `anthropic_api_key` / `openai_api_key` field, every other field kept,
 * written mode 0600 through a temp file and a rename. The key's shape is
 * checked first (an OAuth token or an admin key is refused, the rule of the
 * CI lane's `credential.mjs install api`). Unless --no-verify, one GET of the
 * vendor's model list checks the key before anything is written (no tokens
 * spent); a rejected key changes nothing, an unreachable vendor still saves. Nothing prints the key; the confirmation shows its kind and length.
 *
 * API keys serve runs on a developer's machine only, never CI, and those runs
 * are kept rare (docs/design/testing/continuous-integration.md §13.4).
 *
 * Env (tests): MANDU_SET_KEY_VERIFY_BASE  the vendor base URL to verify against.
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync, readSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

import { refusedKey, readSecretLine, PROVIDERS } from "./ci/credential.mjs";
import { resolvePath } from "./paths/mandu-paths.mjs";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIELD = { anthropic: "anthropic_api_key", openai: "openai_api_key" };
const LABEL = { anthropic: "Anthropic Console API key (sk-ant-api…)", openai: "OpenAI API key (sk-…)" };
const VERIFY = {
  anthropic: { base: "https://api.anthropic.com", headers: (k) => ({ "x-api-key": k, "anthropic-version": "2023-06-01" }) },
  openai: { base: "https://api.openai.com", headers: (k) => ({ authorization: `Bearer ${k}` }) },
};

const say = (m) => process.stderr.write(`set-api-key: ${m}\n`);

/** The key's kind and length, never its tail (secrets-to-env.mjs `mask`). */
export function masked(key) {
  return `${key.slice(0, 3)}… (${key.length} chars)`;
}

/** The secrets file's text with `provider`'s key set, every other field kept;
 *  or a refusal. */
export function mergeKey(existingText, provider, key) {
  const why = refusedKey(provider, key);
  if (why) return { ok: false, reason: why };
  let obj = {};
  if (existingText != null && existingText.trim() !== "") {
    try { obj = JSON.parse(existingText); } catch { return { ok: false, reason: "the existing file is not JSON; fix or move it first" }; }
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return { ok: false, reason: "the existing file is not a JSON object" };
  }
  obj[FIELD[provider]] = key;
  return { ok: true, text: JSON.stringify(obj, null, 2) + "\n" };
}

/** One GET of the model list (no tokens): accepted, rejected, or unreachable. */
export async function verifyKey(provider, key, base = process.env.MANDU_SET_KEY_VERIFY_BASE || VERIFY[provider].base) {
  try {
    const r = await fetch(`${base.replace(/\/$/, "")}/v1/models`, { headers: VERIFY[provider].headers(key), signal: AbortSignal.timeout(15000) });
    if (r.ok) return { state: "usable", line: "usable (the vendor accepted it; no tokens spent)" };
    return { state: "rejected", line: `rejected (HTTP ${r.status}): check the key and its workspace` };
  } catch (e) {
    return { state: "unreachable", line: `not verified, the vendor was unreachable (${e.cause?.code ?? e.name}); the key is saved` };
  }
}

/** A visible one-line answer from the terminal. */
function promptLine(prompt) {
  process.stderr.write(prompt);
  const buf = Buffer.alloc(256);
  let text = "";
  for (;;) {
    let n;
    try { n = readSync(0, buf, 0, buf.length, null); } catch (e) { if (e.code === "EAGAIN") continue; throw e; }
    if (n <= 0) break;
    text += buf.subarray(0, n).toString("utf8");
    if (text.includes("\n")) break;
  }
  return text.split("\n")[0];
}

async function main(argv) {
  const opt = (k) => { const i = argv.indexOf(k); if (i < 0) return undefined; const v = argv[i + 1]; argv.splice(i, 2); return v; };
  const flag = (k) => { const i = argv.indexOf(k); if (i < 0) return false; argv.splice(i, 1); return true; };
  if (flag("-h") || flag("--help")) {
    const doc = readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(2, 27);
    process.stderr.write(doc.map((l) => l.replace(/^ \* ?/, "")).join("\n") + "\n");
    return 0;
  }
  const dest = opt("--dest") ?? resolvePath("secrets-json", process.env, homedir());
  const noVerify = flag("--no-verify");
  let provider = argv.shift();
  if (provider === undefined) {
    if (!process.stdin.isTTY) { say("name the provider: set-api-key.mjs anthropic|openai"); return 2; }
    const pick = promptLine("Which key? 1) Anthropic Console API key  2) OpenAI API key  [1]: ").trim();
    provider = pick === "2" ? "openai" : "anthropic";
  }
  if (!PROVIDERS.includes(provider)) { say(`unknown provider '${provider}' (known: ${PROVIDERS.join(", ")})`); return 2; }

  const key = readSecretLine(`Paste your ${LABEL[provider]} (hidden), then Enter: `).trim();
  if (!key) { say("no key read; nothing changed"); return 1; }
  const existing = existsSync(dest) ? readFileSync(dest, "utf8") : null;
  const r = mergeKey(existing, provider, key);
  if (!r.ok) { say(`${r.reason}; nothing changed`); return 1; }

  if (!noVerify) {
    const v = await verifyKey(provider, key);
    say(`check: ${v.line}`);
    if (v.state === "rejected") { say("nothing changed"); return 1; }
  }

  mkdirSync(dirname(dest), { recursive: true, mode: 0o700 });
  const tmp = `${dest}.tmp-${process.pid}`;
  writeFileSync(tmp, r.text, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, dest);
  say(`saved ${FIELD[provider]} = ${masked(key)} in ${dest} (mode 0600)`);

  const shadow = join(REPO_ROOT, "secrets.local.json");
  if (existsSync(shadow) && shadow !== dest) say(`NOTE: ${shadow} exists and is read first, so this checkout uses it, not ${dest}`);
  say("load it in a shell with `source scripts/mandu-env.sh` (the mandu shim loads it on its own)");
  say("API keys serve rare, hand-started runs on this machine only, never CI (continuous-integration.md §13.4)");
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { say(String(e?.message ?? e)); process.exit(1); });
}
