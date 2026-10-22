#!/usr/bin/env node
// reduce-codex-auth — prepare the REDUCED Codex sign-in an npm-release guest
// may hold (docs/design/testing/os-test-matrix.md §10.18), the Codex twin of
// reduce-credential.mjs.
//
// A ChatGPT sign-in (`codex login`) keeps an OAuth refresh token in
// ~/.codex/auth.json, and those ROTATE: a second holder that refreshes would
// log the host out. So the guest gets the access token ONLY, with
// `last_refresh` set to now so Codex does not try to refresh it during the
// run. It can never refresh, and what it holds dies when the token expires.
// A saved API key (`codex login --with-api-key`) is copied as the key alone.
//
//   reduce-codex-auth.mjs <src auth.json> <out-dir> <min-seconds-left>
//
// Exit 0 = wrote <out-dir>/codex-auth.json (0600). Exit 3 = cannot (reason on
// stderr): missing/unparsable source, no access token or key, or too little
// lifetime left. NEVER prints a token. Refuses an <out-dir> that does not
// already exist (the caller owns the per-run directory and its cleanup).
import { readFileSync, writeFileSync, statSync, chmodSync } from "node:fs";
import { join } from "node:path";

/** The `exp` claim of a JWT, in ms, or undefined. */
function jwtExpMs(token) {
  try {
    const c = JSON.parse(Buffer.from(String(token).split(".")[1], "base64url").toString("utf8"));
    return typeof c.exp === "number" ? c.exp * 1000 : undefined;
  } catch { return undefined; }
}

export function reduce(raw, nowMs, minSecondsLeft) {
  let auth;
  try { auth = JSON.parse(raw); } catch { return { ok: false, reason: "auth file is not JSON" }; }
  if (typeof auth?.OPENAI_API_KEY === "string" && auth.OPENAI_API_KEY) {
    return { ok: true, json: JSON.stringify({ OPENAI_API_KEY: auth.OPENAI_API_KEY }), kind: "key" };
  }
  const t = auth?.tokens;
  if (!t || typeof t.access_token !== "string" || !t.access_token) return { ok: false, reason: "no tokens.access_token and no OPENAI_API_KEY (not signed in?)" };
  const exp = jwtExpMs(t.access_token);
  if (exp === undefined) return { ok: false, reason: "the access token has no exp claim; cannot tell whether it outlives the run" };
  const left = Math.floor((exp - nowMs) / 1000);
  if (left < minSecondsLeft) return { ok: false, reason: `access token has ${left}s left, need ${minSecondsLeft}s; run any \`codex exec\` on the host first`, stale: true };
  // Allow-list, not a delete: a future field that carries refresh capability
  // must not ride along by default.
  const reduced = {
    auth_mode: auth.auth_mode, OPENAI_API_KEY: null,
    tokens: { id_token: t.id_token, access_token: t.access_token, refresh_token: "", account_id: t.account_id },
    last_refresh: new Date(nowMs).toISOString(),
  };
  return { ok: true, json: JSON.stringify(reduced), kind: "sign-in", secondsLeft: left };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [src, outDir, min] = process.argv.slice(2);
  const bail = (m) => { console.error(`reduce-codex-auth: ${m}`); process.exit(3); };
  if (!src || !outDir || !/^\d+$/.test(min ?? "")) bail("usage: reduce-codex-auth.mjs <src> <out-dir> <min-seconds-left>");
  try { if (!statSync(outDir).isDirectory()) bail("out-dir is not a directory"); } catch { bail("out-dir does not exist"); }
  let raw; try { raw = readFileSync(src, "utf8"); } catch { bail(`no auth file at ${src}`); }
  const r = reduce(raw, Date.now(), Number(min));
  if (!r.ok) bail(r.reason);
  const out = join(outDir, "codex-auth.json");
  writeFileSync(out, r.json, { mode: 0o600 }); chmodSync(out, 0o600);
  console.error(`reduce-codex-auth: wrote ${r.kind === "key" ? "key-only" : `access-token-only (${r.secondsLeft}s left)`} Codex auth`);
}
