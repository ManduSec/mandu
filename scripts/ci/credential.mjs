#!/usr/bin/env node
// credential.mjs — the credentials a CI guest may hold (one lane's kinds per
// run), and the canary that proves they came back out nowhere
// (docs/design/testing/continuous-integration.md §9, §9.8).
//
// Only the nightly holds a credential, and each lane holds only its own kinds
// (§9.8):
//   claude  the subscription lane: a scoped agent credential (an access
//           token only, no refresh token);
//   codex   the subscription lane: a REDUCED Codex sign-in (access and id
//           token, no refresh token) cut from a DEDICATED CI account's full
//           sign-in, which stays on the runner host and is refreshed there
//           before each run (`refresh codex`, §9.8 "The Codex sign-in");
//   api     the API lane: vendor API keys, Anthropic and/or OpenAI;
//   docker, gitguardian
//           TOOL credentials, not model credentials (§9.8 "Tool
//           credentials"): a Docker personal access token (with the
//           account's username, which is not secret) for Docker Sandboxes'
//           sign-in, and a GitGuardian API token for ggshield. A
//           subscription-lane run carries them beside its subscription kinds
//           (`claude,docker,gitguardian`); an API-lane run may carry `docker`
//           beside `api` (`api,docker`), never `gitguardian`.
// A run takes subscription and tool kinds in any combination (`claude`,
// `codex`, `claude,codex`, `claude,docker,gitguardian`, …), or `api` alone or
// with `docker`, never `api` with a subscription kind (parseKinds). A human
// places each on the runner host, outside the repository, mode 0600, owned by
// the runner's account; nothing in the repository or in the CI variables
// holds them. The job reads them from there.
//
//   credential.mjs path claude|codex|api|docker|gitguardian
//       the host file ($MANDU_CI_CLAUDE_CREDENTIAL, $MANDU_CI_CODEX_CREDENTIAL,
//       $MANDU_CI_API_CREDENTIAL, $MANDU_CI_DOCKER_CREDENTIAL or
//       $MANDU_CI_GITGUARDIAN_CREDENTIAL override the default)
//   credential.mjs install claude --subscription max|pro [--dest FILE] [--valid-days N]
//       the human's step: read ONE token from stdin (no echo on a terminal)
//       and write the file, mode 0600, in the agent's own credential shape
//       (the allow-listed fields only). Refuses anything but an access token.
//   credential.mjs install api --provider anthropic|openai [--dest FILE]
//       the API lane's step: read ONE key from stdin (no echo on a terminal)
//       and set it in the file, mode 0600 (the other provider's key, when
//       present, is kept). Refuses an OAuth token, an admin key and anything
//       not shaped like the provider's inference key
//   credential.mjs install docker|gitguardian [--dest FILE]
//   credential.mjs install api --provider docker|gitguardian [--dest FILE]
//       a tool credential (the two forms are one command): read ONE token
//       from stdin (no echo on a terminal) and write it to its own file,
//       mode 0600, the bare token with no newline; never into the API lane's
//       file. Refuses a token not shaped like the tool's. Docker also needs
//       the account's username (not secret): $MANDU_CI_DOCKER_USER, else the
//       file `docker-user` beside the token; when that file is absent,
//       install writes it, from $MANDU_CI_DOCKER_USER or else asked for
//       (echoed) on the next line of stdin. `install docker-user [--dest
//       TOKEN_FILE]` writes the username alone, for a token already in place
//   credential.mjs install codex --from FILE [--dest FILE]
//       the subscription lane's Codex step: copy a DEDICATED CI account's
//       full sign-in to the host file, mode 0600. Refuses the invoking
//       account's own sign-in (every refresh here would rotate it and log
//       that Codex out), a saved API key and a sign-in without a refresh token
//   credential.mjs refresh codex [--min-seconds N]
//       the host's refresh (§9.8): under flock(1) on FILE.lock, refresh the
//       sign-in as Codex itself does (MANDU_CI_CODEX_REFRESH_URL for a test,
//       https or literal loopback only) and write the rotated tokens back
//       (tmp + rename, 0600). With --min-seconds, only when the access token
//       has less than N seconds left or the last refresh is old. A failed
//       refresh leaves the file as it was
//   credential.mjs check K[,K] [--src FILE] [--min-seconds N]
//       exit 0 when the file is usable; exit 3 with the reason (and, when it is
//       absent, the setup steps) otherwise. An API key has no expiry: api
//       ignores --min-seconds. --src only with one kind
//   credential.mjs prepare K[,K] [--src FILE] --out TAR [--min-seconds N]
//       write the guest's credential disk: a tar holding, per kind, the
//       reduced, allow-listed credential (for codex, without its refresh
//       token)
//   credential.mjs scan [K[,K]] [--src FILE] PATH...
//       the canary: exit 1 (naming the file, never the bytes) when a token or
//       key, or any 19 consecutive characters of its secret part (a JWT's:
//       its signature), is in a file under PATH (directories walked, symlinks
//       not followed; all-zero stretches of a sparse raw disk skipped); 0
//       clean; 2 usage. The kind defaults to claude. For codex every token of
//       the HOST file is looked for, the refresh token the guest never had too
//
// What the host file may hold: an access token with no refresh token, in
// the `install` shape, as a reduced credentials JSON (reduce-credential.mjs's
// output), or bare on one line. A refresh token is refused: the guest must
// never be able to rotate a login, and the runner host keeps no agent
// refresh token either (the one refresh token a host keeps is the DEDICATED
// Codex CI account's, §9.8). An API key is refused: the API lane has its own
// file.
//
// What the api file may hold: a JSON object with `anthropic` and/or `openai`
// inference keys, nothing else. An admin key and an OAuth token are refused:
// the lane only calls models. It takes keys of its own, each with a limit on
// the vendor's side (§9.8).
//
// What the codex file may hold: Codex's own sign-in file. The guest's copy
// keeps the id and access token and the account id and no refresh token, so
// a guest can never rotate the sign-in.
//
// NEVER prints a token. The tar lives on the host only as an unlinked file
// that qemu holds open (vm-run.sh), so it is gone with the guest.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

export const KINDS = ["claude", "codex", "api", "docker", "gitguardian"];
/** The subscription lane's kinds; a run may combine these, never with `api`. */
export const SUBSCRIPTION_KINDS = ["claude", "codex"];
/** Tool credentials (a third-party tool's own account, not a model's): they
 *  ride beside the subscription kinds; API_TOOL_KINDS beside `api` too. */
export const TOOL_KINDS = ["docker", "gitguardian"];
/** The tool kinds an API-lane run may carry beside `api` (2026-10-19): Docker
 *  Sandboxes' sign-in, whose local sandboxes Docker's FAQ calls free "including
 *  for commercial and professional work". Not `gitguardian`: GitGuardian's
 *  free-plan terms bar commercial use, and ggshield is out of the battery. A
 *  tool token is never a model key (each in its own file and shape), so the
 *  API lane's guest still holds no subscription credential. */
export const API_TOOL_KINDS = ["docker"];
export const PROVIDERS = ["anthropic", "openai"];
const MAX_FILE = 64 * 1024;
const PIECE = 16, STRIDE = 4;
const BARE_HOURS = 24; // expiresAt given to a bare token, which carries none
const TOKEN_RE = /^sk-ant-oat\d*-[A-Za-z0-9_-]{16,}$/;
const FILE_NAME = { claude: "claude-credential.json", codex: "codex-auth.json", api: "api-keys.json",
  docker: "docker-token", gitguardian: "gitguardian-token" };
const PATH_ENV = { claude: "MANDU_CI_CLAUDE_CREDENTIAL", codex: "MANDU_CI_CODEX_CREDENTIAL", api: "MANDU_CI_API_CREDENTIAL",
  docker: "MANDU_CI_DOCKER_CREDENTIAL", gitguardian: "MANDU_CI_GITGUARDIAN_CREDENTIAL" };

export function defaultPath(kind, env = process.env) {
  if (!KINDS.includes(kind)) return null;
  const over = env[PATH_ENV[kind]];
  if (over) return over;
  let home;
  try { home = os.userInfo().homedir; } catch { home = os.homedir(); }
  return path.join(home, ".config", "mandu-ci", FILE_NAME[kind]);
}

/**
 * A run's credential kinds: the subscription kinds (`claude`, `codex`) and
 * the tool kinds (`docker`, `gitguardian`) combine; `api` stands alone or
 * with API_TOOL_KINDS (`api,docker`), never with a subscription kind (§9.8:
 * one lane's credentials per guest).
 * @returns {{ok: true, kinds: string[]} | {ok: false, reason: string}}
 */
export function parseKinds(spec) {
  const kinds = String(spec ?? "").split(",").map((s) => s.trim());
  if (!kinds.length || kinds.some((k) => !k)) return { ok: false, reason: "no credential kind" };
  const unknown = kinds.filter((k) => !KINDS.includes(k));
  if (unknown.length) return { ok: false, reason: `unknown credential kind '${unknown[0]}' (known: ${KINDS.join(", ")})` };
  if (new Set(kinds).size !== kinds.length) return { ok: false, reason: "a credential kind is named twice" };
  if (kinds.includes("api") && kinds.some((k) => k !== "api" && !API_TOOL_KINDS.includes(k)))
    return { ok: false, reason: `api does not combine with ${kinds.filter((k) => k !== "api" && !API_TOOL_KINDS.includes(k)).join(", ")} (only with ${API_TOOL_KINDS.join(", ")}): one lane's credentials per run` };
  return { ok: true, kinds };
}

export const SETUP_STEPS = (file, kind = "claude") => kind === "codex" ? [
  "the nightly subscription lane's Codex sign-in is placed once, by a human (continuous-integration.md §9.8):",
  "  1. a DEDICATED ChatGPT account for CI (never a personal one: this host refreshes it)",
  "  2. on any machine: CODEX_HOME=$(mktemp -d) codex login   (sign in as that account)",
  "  3. copy that directory's auth.json to this runner host, then, as this account, in a checkout:",
  `     node scripts/ci/credential.mjs install codex --from <that auth.json>${file === defaultPath("codex", {}) ? "" : ` --dest "${file}"`}`,
  "     and delete the copy; it writes the file mode 0600:",
  `     ${file}`,
  "  the nightly refreshes it before each run; if a refresh ever fails, repeat 2 and 3",
] : kind === "docker" ? [
  "the Docker sign-in (the Docker Sandboxes baseline, continuous-integration.md §9.8 \"Tool credentials\") is placed once, by a human:",
  "  1. on Docker Hub, for an account whose plan includes Docker Sandboxes:",
  "     Account settings > Personal access tokens > a new token (dckr_pat_…)",
  "  2. on this runner host, as this account, in a checkout of the repository:",
  `     node scripts/ci/credential.mjs install docker${file === defaultPath("docker", {}) ? "" : ` --dest "${file}"`}`,
  "     and paste the token (no echo), then the account's username (echoed); it writes, mode 0600:",
  `     ${file}`,
  `     ${dockerUserFile(file)}   (or set MANDU_CI_DOCKER_USER)`,
] : kind === "gitguardian" ? [
  "the GitGuardian token (the ggshield baseline, continuous-integration.md §9.8 \"Tool credentials\") is placed once, by a human:",
  "  1. on the GitGuardian dashboard: API > Personal access tokens > a new token with the scan scope",
  "  2. on this runner host, as this account, in a checkout of the repository:",
  `     node scripts/ci/credential.mjs install gitguardian${file === defaultPath("gitguardian", {}) ? "" : ` --dest "${file}"`}`,
  "     and paste the token (no echo); it writes the file mode 0600:",
  `     ${file}`,
] : kind === "api" ? [
  "the API lane's keys (the weekly `nightly-api-key` job reads them) are placed once, by a human (continuous-integration.md §9.8):",
  "  1. create keys for CI only, each with a spend limit on the vendor's side:",
  "     an Anthropic API key (a Console workspace with a spend limit)",
  "     and/or an OpenAI project key (a project with a budget)",
  "  2. on this runner host, as this account, in a checkout of the repository, once per key:",
  `     node scripts/ci/credential.mjs install api --provider anthropic${file === defaultPath("api", {}) ? "" : ` --dest "${file}"`}`,
  `     node scripts/ci/credential.mjs install api --provider openai${file === defaultPath("api", {}) ? "" : ` --dest "${file}"`}`,
  "     and paste the key (no echo); it writes the file mode 0600:",
  `     ${file}`,
] : [
  "the nightly's Claude credential is placed once, by a human (continuous-integration.md §9):",
  "  1. on a machine logged in to the subscription: `claude setup-token`",
  "     (it prints a long-lived, inference-only OAuth token with no refresh token)",
  "  2. on this runner host, as this account, in a checkout of the repository:",
  `     node scripts/ci/credential.mjs install claude --subscription max${file === defaultPath("claude", {}) ? "" : ` --dest "${file}"`}`,
  "     and paste the token (no echo); it writes the file mode 0600:",
  `     ${file}`,
];

/** A refresh token or a key is refused whatever the form. */
function refused(t) {
  if (/sk-ant-ort\d*-/.test(t)) return "the credential holds a REFRESH token (sk-ant-ort…); place only an access token (`claude setup-token`)";
  if (/^sk-ant-(?:api|usr)\d*-/.test(t)) return "the credential holds an API key; the nightly uses the subscription (`claude setup-token`)";
  return null;
}

/**
 * Parse the host file's text into the reduced credential, or refuse.
 * @returns {{ok: true, token: string, json: string, secondsLeft: number|null, form: string} | {ok: false, reason: string}}
 */
export function parseClaude(text, nowMs, minSecondsLeft = 0) {
  const t = String(text ?? "").trim();
  if (!t) return { ok: false, reason: "the credential file is empty" };
  const bad = refused(t);
  if (bad) return { ok: false, reason: bad };
  if (t.startsWith("{")) {
    let cred;
    try { cred = JSON.parse(t); } catch { return { ok: false, reason: "the credential file is neither a token nor JSON" }; }
    const o = cred?.claudeAiOauth;
    if (!o || typeof o !== "object") return { ok: false, reason: "the credential JSON has no claudeAiOauth object" };
    if (Object.keys(o).some((k) => /refresh/i.test(k)))
      return { ok: false, reason: "the credential JSON carries a refresh token; place a reduced one (`credential.mjs install`)" };
    if (typeof o.accessToken !== "string" || !TOKEN_RE.test(o.accessToken))
      return { ok: false, reason: "the credential JSON has no OAuth access token (sk-ant-oat…)" };
    if (typeof o.expiresAt !== "number") return { ok: false, reason: "the credential JSON has no expiresAt" };
    const left = Math.floor((o.expiresAt - nowMs) / 1000);
    if (left < minSecondsLeft) return { ok: false, reason: `the access token has ${left}s left, the run needs ${minSecondsLeft}s (renew it: \`claude setup-token\`, then \`credential.mjs install\`)` };
    // Allow-list: a future field that carries refresh capability must not ride along.
    const reduced = { claudeAiOauth: { accessToken: o.accessToken, expiresAt: o.expiresAt,
      scopes: Array.isArray(o.scopes) ? o.scopes.filter((s) => typeof s === "string") : ["user:inference"],
      ...(typeof o.subscriptionType === "string" ? { subscriptionType: o.subscriptionType } : {}),
      ...(typeof o.rateLimitTier === "string" ? { rateLimitTier: o.rateLimitTier } : {}) } };
    return { ok: true, token: o.accessToken, json: JSON.stringify(reduced), secondsLeft: left, form: "reduced credentials JSON" };
  }
  if (/\s/.test(t)) return { ok: false, reason: "the credential file must hold one token on one line, or the JSON form" };
  if (!TOKEN_RE.test(t)) return { ok: false, reason: "the credential file does not hold an OAuth access token (sk-ant-oat…, from `claude setup-token`)" };
  const reduced = { claudeAiOauth: { accessToken: t, expiresAt: nowMs + BARE_HOURS * 3600_000, scopes: ["user:inference"] } };
  return { ok: true, token: t, json: JSON.stringify(reduced), secondsLeft: null, form: "bare token" };
}

/** What `install` writes for an access token. */
export function installShape(token, { nowMs = Date.now(), validDays = 365, subscription = null } = {}) {
  const t = String(token ?? "").trim();
  const bad = refused(t);
  if (bad) return { ok: false, reason: bad };
  if (!TOKEN_RE.test(t)) return { ok: false, reason: "that is not an OAuth access token (sk-ant-oat…, from `claude setup-token`)" };
  if (subscription !== null && !["max", "pro"].includes(subscription)) return { ok: false, reason: "--subscription is max or pro" };
  const o = { accessToken: t, expiresAt: nowMs + validDays * 86400_000, scopes: ["user:inference"], ...(subscription ? { subscriptionType: subscription } : {}) };
  return { ok: true, json: JSON.stringify({ claudeAiOauth: o }) + "\n" };
}

// ── the api kind (the API lane, §9.8) ──────────────────────────────────────
const KEY_RE = {
  // `sk-ant-api…` and the Console's newer `sk-ant-usr…` (seen 2026-10-05,
  // accepted by /v1/models and /v1/messages/count_tokens).
  anthropic: /^sk-ant-(?:api|usr)\d*-[A-Za-z0-9_-]{16,}$/,
  openai: /^sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}$/,
};

/** Why `key` cannot be the API lane's `provider` key, or null. */
export function refusedKey(provider, key) {
  const k = String(key ?? "");
  if (!PROVIDERS.includes(provider)) return `unknown provider '${provider}' (known: ${PROVIDERS.join(", ")})`;
  if (/^sk-ant-(oat|ort)\d*-/.test(k)) return "that is a Claude OAuth token; it belongs to the subscription lane (`credential.mjs install claude`)";
  if (/^sk-ant-admin\d*-/.test(k) || /^sk-admin-/.test(k)) return "that is an admin key; the lane only calls models (give it an inference key)";
  if (provider === "openai" && /^sk-ant-/.test(k)) return "that is an Anthropic key, not an OpenAI one";
  if (!KEY_RE[provider].test(k)) return provider === "anthropic"
    ? "that is not an Anthropic API key (sk-ant-api… or sk-ant-usr…)"
    : "that is not an OpenAI API key (sk-…, sk-proj-…)";
  return null;
}

/**
 * Parse the api file into the allow-listed keys, or refuse.
 * @returns {{ok: true, tokens: string[], json: string, secondsLeft: null, form: string, providers: string[]} | {ok: false, reason: string}}
 */
export function parseApi(text) {
  const t = String(text ?? "").trim();
  if (!t) return { ok: false, reason: "the credential file is empty" };
  let o;
  try { o = JSON.parse(t); } catch { return { ok: false, reason: 'the api credential file is not JSON ({"anthropic": …, "openai": …})' }; }
  if (!o || typeof o !== "object" || Array.isArray(o)) return { ok: false, reason: "the api credential file is not a JSON object" };
  const extra = Object.keys(o).filter((k) => !PROVIDERS.includes(k));
  if (extra.length) return { ok: false, reason: `the api credential file has fields other than ${PROVIDERS.join(" and ")}: ${extra.join(", ")}` };
  const keys = {};
  for (const p of PROVIDERS) {
    if (o[p] === undefined) continue;
    const v = typeof o[p] === "string" ? o[p].trim() : "";
    const bad = refusedKey(p, v);
    if (bad) return { ok: false, reason: `${p}: ${bad}` };
    keys[p] = v;
  }
  const providers = Object.keys(keys);
  if (!providers.length) return { ok: false, reason: "the api credential file holds no key (`credential.mjs install api --provider …`)" };
  return { ok: true, tokens: Object.values(keys), json: JSON.stringify(keys), secondsLeft: null, form: `API keys (${providers.join(", ")})`, providers };
}

/** What `install api` writes: the file's current keys with `provider`'s set to `key`. */
export function installApi(existingText, provider, key) {
  const k = String(key ?? "").trim();
  const bad = refusedKey(provider, k);
  if (bad) return { ok: false, reason: bad };
  let cur = {};
  if (String(existingText ?? "").trim()) {
    const r = parseApi(existingText);
    if (!r.ok) return { ok: false, reason: `the existing file is not usable (${r.reason}); remove it first` };
    cur = JSON.parse(r.json);
  }
  return { ok: true, json: JSON.stringify({ ...cur, [provider]: k }) + "\n" };
}

// ── the tool kinds (§9.8 "Tool credentials") ───────────────────────────────
// Docker documents its personal access tokens as `dckr_pat_…` (base64url
// after the prefix). GitGuardian documents no token format; its tokens are
// one word of letters and digits, so the shape is a 32-128 character word
// carrying no other vendor's known prefix.
const TOOL_RE = {
  docker: /^dckr_pat_[A-Za-z0-9_-]{20,}$/,
  gitguardian: /^[A-Za-z0-9_-]{32,128}$/,
};
const OTHER_VENDOR_RE = /^(?:dckr_|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|AKIA|ASIA|AIza)/;
const DOCKER_USER_RE = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$/;

/** Why `token` cannot be the `kind` tool's token, or null. Never quotes it. */
export function refusedTool(kind, token) {
  const t = String(token ?? "");
  if (!TOOL_KINDS.includes(kind)) return `unknown tool credential '${kind}' (known: ${TOOL_KINDS.join(", ")})`;
  if (!t) return "the token is empty";
  if (/\s/.test(t)) return "the token must be one word on one line (no spaces or line breaks inside)";
  if (/^sk-/.test(t)) return "that is a model credential (sk-…); model keys go to `install api --provider anthropic|openai` or `install claude`";
  if (kind === "docker") {
    if (/^dckr_(?!pat_)/.test(t)) return "that is a Docker token but not a personal access token (dckr_pat_…)";
    if (!TOOL_RE.docker.test(t)) return "that is not a Docker personal access token (dckr_pat_…)";
    return null;
  }
  if (/^ggtt-/.test(t)) return "that is a GitGuardian test token (ggtt-…), not an API token";
  if (OTHER_VENDOR_RE.test(t)) return "that is another vendor's token, not a GitGuardian API token";
  if (!TOOL_RE.gitguardian.test(t)) return "that is not a GitGuardian API token (one word of 32-128 letters, digits, _ or -)";
  return null;
}

/** Why `user` cannot be a Docker username, or null. */
export function refusedDockerUser(user) {
  const u = String(user ?? "");
  if (!u) return "no Docker username (MANDU_CI_DOCKER_USER, or the docker-user file `credential.mjs install docker` writes)";
  if (u.startsWith("dckr_")) return "the Docker username looks like a token (dckr_…): the username goes in docker-user, the token in docker-token";
  // Docker Hub's own login takes the email too, but `sbx login` refuses it
  // ("docker token username does not match requested username", 2026-10-17)
  if (u.includes("@")) return "that is the account's email; sbx login takes the Docker ID (the account handle, shown on hub.docker.com), not the email";
  if (!DOCKER_USER_RE.test(u)) return "the Docker username is not one word of letters, digits and . _ - @ +";
  return null;
}

/** The username file beside a Docker token file. */
export function dockerUserFile(tokenFile) {
  return path.join(path.dirname(tokenFile), "docker-user");
}

/**
 * The Docker username: $MANDU_CI_DOCKER_USER, else the `docker-user` file
 * beside the token (a regular file of at most 1 KiB; not secret).
 * @returns {{ok: true, user: string, from: string} | {ok: false, reason: string, absent?: boolean}}
 */
export function dockerUser(tokenFile, env = process.env) {
  if (env.MANDU_CI_DOCKER_USER) {
    const u = env.MANDU_CI_DOCKER_USER.trim();
    const bad = refusedDockerUser(u);
    return bad ? { ok: false, reason: `MANDU_CI_DOCKER_USER: ${bad}` } : { ok: true, user: u, from: "MANDU_CI_DOCKER_USER" };
  }
  const f = dockerUserFile(tokenFile);
  let st;
  try { st = fs.lstatSync(f); } catch { return { ok: false, reason: `no Docker username: MANDU_CI_DOCKER_USER is unset and there is no ${f}`, absent: true }; }
  if (!st.isFile() || st.size > 1024) return { ok: false, reason: `${f} is not a small regular file` };
  const u = fs.readFileSync(f, "utf8").trim();
  const bad = refusedDockerUser(u);
  return bad ? { ok: false, reason: `${f}: ${bad}` } : { ok: true, user: u, from: f };
}

/**
 * A tool's host file (the bare token) as the guest's JSON, or a refusal.
 * Docker's JSON carries the username; `user === null` (the canary's read)
 * checks the token only.
 * @returns {{ok: true, tokens: string[], json: string, secondsLeft: null, form: string} | {ok: false, reason: string}}
 */
export function parseTool(kind, text, user = null) {
  const t = String(text ?? "").trim();
  if (!t) return { ok: false, reason: "the credential file is empty" };
  const bad = refusedTool(kind, t);
  if (bad) return { ok: false, reason: bad };
  if (kind === "gitguardian") return { ok: true, tokens: [t], json: JSON.stringify({ token: t }), secondsLeft: null, form: "GitGuardian API token" };
  if (user === null) return { ok: true, tokens: [t], json: "", secondsLeft: null, form: "Docker personal access token" };
  const ub = refusedDockerUser(user);
  if (ub) return { ok: false, reason: ub };
  return { ok: true, tokens: [t], json: JSON.stringify({ username: user, token: t }), secondsLeft: null, form: `Docker personal access token (user ${user})` };
}

// ── the codex kind (the subscription lane, §9.8 "The Codex sign-in") ──────
// Codex's own refresh, read from openai/codex codex-rs/login (2026-09-30:
// auth/manager.rs, oauth/client.rs) and the 0.159.1 binary's strings: a JSON
// POST of {client_id, grant_type: "refresh_token", refresh_token} to the token
// endpoint, answered by {id_token?, access_token?, refresh_token?}; a field
// the answer leaves out keeps its old value.
export const CODEX_REFRESH_URL = "https://auth.openai.com/oauth/token";
export const CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const JWT_RE = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
const CODEX_REFRESH_DAYS = 7; // under Codex's own 8, so a hand run never refreshes in a guest

/** The `exp` claim (seconds) of a JWT, or null. */
export function jwtExp(t) {
  try {
    const c = JSON.parse(Buffer.from(String(t).split(".")[1], "base64url").toString("utf8"));
    return typeof c?.exp === "number" ? c.exp : null;
  } catch { return null; }
}

/**
 * Parse the host file: a full Codex ChatGPT sign-in, refresh token included.
 * @returns {{ok: true, auth: object, tokens: string[], exp: number} | {ok: false, reason: string}}
 */
export function parseCodex(text) {
  const t = String(text ?? "").trim();
  if (!t) return { ok: false, reason: "the credential file is empty" };
  let o;
  try { o = JSON.parse(t); } catch { return { ok: false, reason: "the codex credential file is not JSON (Codex's auth.json)" }; }
  if (!o || typeof o !== "object" || Array.isArray(o)) return { ok: false, reason: "the codex credential file is not a JSON object" };
  if (o.OPENAI_API_KEY !== undefined && o.OPENAI_API_KEY !== null)
    return { ok: false, reason: "the sign-in holds a saved API key (OPENAI_API_KEY); the subscription lane takes a ChatGPT sign-in (`codex login`), the API lane has its own file" };
  const k = o.tokens;
  if (!k || typeof k !== "object") return { ok: false, reason: "the codex credential has no tokens object (a ChatGPT sign-in: `codex login`)" };
  for (const f of ["access_token", "id_token"]) {
    if (typeof k[f] !== "string" || !JWT_RE.test(k[f])) return { ok: false, reason: `the codex credential's ${f} is not a JWT` };
  }
  if (typeof k.refresh_token !== "string" || !k.refresh_token.trim())
    return { ok: false, reason: "the codex credential has no refresh token: the host keeps the full sign-in of the CI account and refreshes it (`credential.mjs install codex`)" };
  if (/\s/.test(k.refresh_token)) return { ok: false, reason: "the codex credential's refresh token is malformed" };
  if (k.account_id !== undefined && k.account_id !== null && typeof k.account_id !== "string")
    return { ok: false, reason: "the codex credential's account_id is not a string" };
  const exp = jwtExp(k.access_token);
  if (exp === null) return { ok: false, reason: "the codex credential's access token carries no expiry (exp)" };
  const tokens = { id_token: k.id_token, access_token: k.access_token, refresh_token: k.refresh_token,
    ...(typeof k.account_id === "string" ? { account_id: k.account_id } : {}) };
  return { ok: true, auth: { ...o, OPENAI_API_KEY: null, tokens }, tokens: [k.access_token, k.id_token, k.refresh_token], exp };
}

/**
 * The guest's copy: id and access token and the account id, no refresh
 * token, last_refresh now (Codex's own refresh never comes due in a run).
 * Allow-listed: nothing else rides along.
 */
export function reduceCodex(parsed, nowMs, minSecondsLeft = 0) {
  const left = Math.floor(parsed.exp - nowMs / 1000);
  if (left < minSecondsLeft)
    return { ok: false, reason: `the codex access token has ${left}s left, the run needs ${minSecondsLeft}s (\`credential.mjs refresh codex\`)` };
  const k = parsed.auth.tokens;
  const reduced = { OPENAI_API_KEY: null,
    tokens: { id_token: k.id_token, access_token: k.access_token, refresh_token: "", ...(k.account_id ? { account_id: k.account_id } : {}) },
    last_refresh: new Date(nowMs).toISOString() };
  return { ok: true, json: JSON.stringify(reduced), secondsLeft: left, form: "Codex ChatGPT sign-in (reduced: no refresh token)" };
}

/** The sign-ins `install codex` refuses as personal: the invoking account's own. */
export function ownCodexSignIns(env = process.env) {
  let home;
  try { home = os.userInfo().homedir; } catch { home = os.homedir(); }
  const out = [path.join(home, ".codex", "auth.json")];
  if (env.HOME) out.push(path.join(env.HOME, ".codex", "auth.json"));
  if (env.CODEX_HOME) out.push(path.join(env.CODEX_HOME, "auth.json"));
  return out;
}

/** The token endpoint: the real one, or a test's (https, or http to a literal loopback address). */
export function codexRefreshUrl(env = process.env) {
  const raw = env.MANDU_CI_CODEX_REFRESH_URL || CODEX_REFRESH_URL;
  let u;
  try { u = new URL(raw); } catch { return { ok: false, reason: "MANDU_CI_CODEX_REFRESH_URL is not a URL" }; }
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (u.protocol === "https:") return { ok: true, url: u.href };
  if (u.protocol === "http:" && (host === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host))) return { ok: true, url: u.href };
  return { ok: false, reason: "MANDU_CI_CODEX_REFRESH_URL must be https, or http to a literal loopback address" };
}

/** Whether `refresh --min-seconds N` has anything to do. */
export function codexNeedsRefresh(parsed, nowMs, minSeconds) {
  if (minSeconds === undefined) return true;
  if (parsed.exp - nowMs / 1000 < minSeconds) return true;
  const last = Date.parse(parsed.auth.last_refresh ?? "");
  return !Number.isFinite(last) || nowMs - last > CODEX_REFRESH_DAYS * 86400_000;
}

const REFRESH_ERRORS = {
  refresh_token_expired: "the refresh token has expired",
  refresh_token_reused: "the refresh token was already used (another copy of this sign-in refreshed it)",
  refresh_token_invalidated: "the refresh token was revoked",
};

/** Write `text` to `file` atomically, mode 0600. */
function writeAtomic(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.tmp-${process.pid}`;
  const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try { fs.writeSync(fd, text); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}

/**
 * Refresh the host's Codex sign-in (the caller holds the lock). Never throws,
 * never returns a token. A failure leaves the file as it was.
 * @returns {Promise<{ok: true, refreshed: boolean, secondsLeft: number} | {ok: false, reason: string}>}
 */
export async function refreshCodex(file, { env = process.env, nowMs = Date.now(), minSeconds, fetchImpl = fetch, uid } = {}) {
  const f = checkFile(file, uid === undefined ? {} : { uid });
  if (!f.ok) return f;
  const cur = parseCodex(fs.readFileSync(file, "utf8"));
  if (!cur.ok) return cur;
  if (!codexNeedsRefresh(cur, nowMs, minSeconds)) return { ok: true, refreshed: false, secondsLeft: Math.floor(cur.exp - nowMs / 1000) };
  const u = codexRefreshUrl(env);
  if (!u.ok) return u;
  let res, body;
  try {
    res = await fetchImpl(u.url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ client_id: CODEX_CLIENT_ID, grant_type: "refresh_token", refresh_token: cur.auth.tokens.refresh_token }),
      signal: AbortSignal.timeout(60_000),
    });
    body = await res.text();
  } catch (e) {
    return { ok: false, reason: `the refresh request failed (${e?.name === "TimeoutError" ? "timeout" : "network"}); the sign-in is unchanged` };
  }
  let j = null;
  try { j = JSON.parse(body); } catch { /* reported below */ }
  if (!res.ok) {
    // Only the error CODE is reported: an error body is the vendor's text.
    const code = typeof j?.error === "string" ? j.error : typeof j?.error?.code === "string" ? j.error.code : typeof j?.code === "string" ? j.code : null;
    const why = code && REFRESH_ERRORS[code] ? REFRESH_ERRORS[code] : `HTTP ${res.status}${code && /^[a-z_]{1,64}$/.test(code) ? ` (${code})` : ""}`;
    return { ok: false, reason: `the refresh was refused: ${why}; place a new sign-in of the CI account (credential.mjs install codex)` };
  }
  if (!j || typeof j !== "object") return { ok: false, reason: "the refresh answer is not JSON; the sign-in is unchanged" };
  const next = { ...cur.auth.tokens };
  for (const f of ["id_token", "access_token", "refresh_token"]) {
    if (j[f] === undefined || j[f] === null) continue;
    if (typeof j[f] !== "string" || !j[f]) return { ok: false, reason: `the refresh answer's ${f} is not a string; the sign-in is unchanged` };
    next[f] = j[f];
  }
  const text = JSON.stringify({ ...cur.auth, tokens: next, last_refresh: new Date(nowMs).toISOString() }, null, 2) + "\n";
  const check = parseCodex(text);
  if (!check.ok) return { ok: false, reason: `the refreshed sign-in is not usable (${check.reason}); the file is unchanged` };
  if (check.exp - nowMs / 1000 <= 0) return { ok: false, reason: "the refreshed access token is already expired; the file is unchanged" };
  try { writeAtomic(file, text); } catch (e) {
    return { ok: false, reason: `the refresh succeeded but writing ${file} failed (${e.code ?? "error"}): the old refresh token may be spent; place a new sign-in (credential.mjs install codex)` };
  }
  return { ok: true, refreshed: true, secondsLeft: Math.floor(check.exp - nowMs / 1000) };
}

/** The host file must be a regular file of this account, closed to everyone else. */
export function checkFile(file, { uid = process.getuid?.() } = {}) {
  let st;
  try { st = fs.lstatSync(file); } catch { return { ok: false, reason: `no credential file at ${file}`, absent: true }; }
  if (!st.isFile()) return { ok: false, reason: `${file} is not a regular file (a symlink is refused)` };
  if (uid !== undefined && st.uid !== uid) return { ok: false, reason: `${file} is not owned by this account (uid ${uid})` };
  if (st.mode & 0o077) return { ok: false, reason: `${file} is readable or writable by others (mode ${(st.mode & 0o777).toString(8)}); chmod 600 it` };
  if (st.size > MAX_FILE) return { ok: false, reason: `${file} is larger than ${MAX_FILE} bytes` };
  return { ok: true };
}

export function load(kind, file, { nowMs = Date.now(), minSecondsLeft = 0, uid, env = process.env, tokenOnly = false } = {}) {
  if (!KINDS.includes(kind)) return { ok: false, reason: `unknown credential kind '${kind}' (known: ${KINDS.join(", ")})` };
  const f = checkFile(file, uid === undefined ? {} : { uid });
  if (!f.ok) return f;
  const text = fs.readFileSync(file, "utf8");
  if (kind === "gitguardian") return parseTool(kind, text);
  if (kind === "docker") {
    const tk = parseTool(kind, text, null);
    if (!tk.ok || tokenOnly) return tk;
    const u = dockerUser(file, env);
    return u.ok ? parseTool(kind, text, u.user) : { ok: false, reason: u.reason, ...(u.absent ? { absentUser: true } : {}) };
  }
  if (kind === "api") return parseApi(text);
  if (kind === "codex") {
    const p = parseCodex(text);
    if (!p.ok) return p;
    const r = reduceCodex(p, nowMs, minSecondsLeft);
    return r.ok ? { ...r, tokens: p.tokens } : r;
  }
  const r = parseClaude(text, nowMs, minSecondsLeft);
  return r.ok ? { ...r, tokens: [r.token] } : r;
}

// ── the credential disk: a ustar archive, one directory and one file ──────
function header(name, { size = 0, mode = 0o600, type = "0", mtime = Math.floor(Date.now() / 1000) } = {}) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write(mode.toString(8).padStart(7, "0") + "\0", 100);
  h.write("0000000\0", 108); h.write("0000000\0", 116);          // uid, gid 0
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write(mtime.toString(8).padStart(11, "0") + "\0", 136);
  h.write("        ", 148);                                         // checksum placeholder
  h.write(type, 156);
  h.write("ustar\0", 257); h.write("00", 263);
  let sum = 0; for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}

/** The directory and file each kind's disk holds (the guest's boot.sh reads them). */
export const TAR_PATH = {
  claude: ["claude/", "claude/.credentials.json"],
  codex: ["codex/", "codex/auth.json"],
  api: ["api/", "api/keys.json"],
  docker: ["docker/", "docker/auth.json"],
  gitguardian: ["gitguardian/", "gitguardian/key.json"],
};

/** One disk for the run: `credentialTar(json, kind)`, or `credentialTar([{kind, json}, …])`. */
export function credentialTar(json, kind = "claude") {
  const entries = Array.isArray(json) ? json : [{ kind, json }];
  const parts = [];
  for (const e of entries) {
    const [dir, name] = TAR_PATH[e.kind];
    const body = Buffer.from(e.json, "utf8");
    parts.push(header(dir, { mode: 0o700, type: "5" }), header(name, { size: body.length }), body,
      Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  const tar = Buffer.concat([...parts, Buffer.alloc(1024)]);
  const rec = 10240;
  return Buffer.concat([tar, Buffer.alloc((rec - (tar.length % rec)) % rec)]);
}

// ── the canary ─────────────────────────────────────────────────────────────
/**
 * What must never come back: the whole token, and the 16-character pieces of
 * its secret part at every STRIDE-th offset, so any run of
 * PIECE + STRIDE - 1 = 19 consecutive characters of it is found (a truncated
 * or re-wrapped leak too, not only the whole token). A JWT's secret part is
 * its signature: its header and claims are shared with every token of the
 * kind and name no one, so a piece of them would flag harmless output.
 */
export function needles(token) {
  const secret = JWT_RE.test(token)
    ? token.slice(token.lastIndexOf(".") + 1)
    : token.replace(/^(?:sk-(?:ant-[a-z]+\d*-|proj-|svcacct-)?|dckr_pat_)/, "");
  const out = new Set([token]);
  for (let i = 0; i + PIECE <= secret.length; i += STRIDE) out.add(secret.slice(i, i + PIECE));
  if (secret.length >= PIECE) out.add(secret.slice(-PIECE));
  return [...out].map((s) => Buffer.from(s, "utf8"));
}

function scanFile(file, ns) {
  const maxLen = Math.max(...ns.map((n) => n.length));
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const chunk = Buffer.alloc(4 * 1024 * 1024);
    const zero = Buffer.alloc(chunk.length);
    let carry = Buffer.alloc(0);
    for (;;) {
      const n = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (n <= 0) return false;
      // A raw results disk is 2 GiB, almost all of it a hole: a chunk of
      // zeros holds no needle and ends no straddling one.
      if (n === chunk.length && chunk.equals(zero)) { carry = Buffer.alloc(0); continue; }
      const buf = carry.length ? Buffer.concat([carry, chunk.subarray(0, n)]) : chunk.subarray(0, n);
      if (ns.some((x) => buf.indexOf(x) !== -1)) return true;
      carry = Buffer.from(buf.subarray(Math.max(0, buf.length - (maxLen - 1))));
    }
  } finally { fs.closeSync(fd); }
}

/** `tokens`: one token, or every key of the api kind. @returns {{found: string[], files: number, bytes: number}} */
export function scan(tokens, paths) {
  const ns = [].concat(tokens).flatMap((t) => needles(t));
  const found = []; let files = 0, bytes = 0;
  const visit = (p) => {
    let st; try { st = fs.lstatSync(p); } catch { return; }
    if (st.isSymbolicLink()) return;
    if (st.isDirectory()) { for (const e of fs.readdirSync(p)) visit(path.join(p, e)); return; }
    if (!st.isFile()) return;
    files++; bytes += st.size;
    if (scanFile(p, ns)) found.push(p);
  };
  for (const p of paths) visit(p);
  return { found, files, bytes };
}

/**
 * One line of stdin: on a terminal after `prompt`, with echo off unless
 * `echo` (stty, so it works the same under any login shell; no shell `read`).
 * Read a byte at a time, so a second call gets the next line of a pipe.
 */
export function readSecretLine(prompt = "paste the token from `claude setup-token`, then Enter: ", { echo = false } = {}) {
  const tty = process.stdin.isTTY;
  if (tty) {
    process.stderr.write(prompt);
    if (!echo) { try { execFileSync("stty", ["-echo"], { stdio: ["inherit", "ignore", "ignore"] }); } catch { /* no stty */ } }
  }
  const bytes = [];
  try {
    const buf = Buffer.alloc(1);
    for (;;) {
      let n;
      try { n = fs.readSync(0, buf, 0, 1, null); } catch (e) { if (e.code === "EAGAIN") continue; if (e.code === "EOF") break; throw e; }
      if (n <= 0) break;
      if (buf[0] === 0x0a) break;
      bytes.push(buf[0]);
      if (bytes.length > MAX_FILE) break;
    }
  } finally {
    if (tty && !echo) { try { execFileSync("stty", ["echo"], { stdio: ["inherit", "ignore", "ignore"] }); } catch { /* no stty */ } process.stderr.write("\n"); }
  }
  return Buffer.from(bytes).toString("utf8").replace(/\r$/, "");
}

/** `install docker|gitguardian` (also `install api --provider docker|gitguardian`):
 *  the token to its own file, bare, 0600; Docker's username beside it. */
function installTool(kind, dest, say) {
  const file = dest ?? defaultPath(kind);
  if (fs.existsSync(file)) {
    const f = checkFile(file);
    if (!f.ok) { say(`not installed: ${f.reason}`); process.exit(3); }
  }
  const what = kind === "docker" ? "Docker personal access token (dckr_pat_…)" : "GitGuardian API token";
  const token = readSecretLine(`paste the ${what}, then Enter: `).trim();
  const bad = refusedTool(kind, token);
  if (bad) { say(`not installed: ${bad}`); process.exit(3); }
  let userNote = "";
  if (kind === "docker") {
    const uf = dockerUserFile(file);
    if (fs.existsSync(uf)) {
      const u = dockerUser(file, {});
      if (!u.ok) { say(`not installed: ${u.reason} (fix or remove it)`); process.exit(3); }
      userNote = `; username ${u.user} from ${uf}`;
    } else {
      const fromEnv = (process.env.MANDU_CI_DOCKER_USER ?? "").trim();
      const user = fromEnv || readSecretLine("the Docker account's username, then Enter: ", { echo: true }).trim();
      const ub = refusedDockerUser(user);
      if (ub) { say(`not installed: ${ub}`); process.exit(3); }
      writeAtomic(uf, user);
      userNote = `; username ${user} written to ${uf}`;
    }
  }
  writeAtomic(file, token);
  say(`installed the ${what} in ${file} (mode 0600, the bare token${userNote}); never in api-keys.json`);
}

// ── CLI ────────────────────────────────────────────────────────────────────
if (import.meta.url === `file://${process.argv[1]}`) {
  const argv = process.argv.slice(2);
  const say = (m) => console.error(`credential: ${m}`);
  const opt = (k) => { const i = argv.indexOf(k); if (i < 0) return undefined; const v = argv[i + 1]; argv.splice(i, 2); return v; };
  const cmd = argv.shift();
  const src = opt("--src"), out = opt("--out"), min = opt("--min-seconds"), dest = opt("--dest");
  const subscription = opt("--subscription") ?? null, validDays = Number(opt("--valid-days") ?? 365);
  const provider = opt("--provider"), from = opt("--from");
  const minSecondsLeft = min === undefined ? 0 : Number(min);
  if (!Number.isInteger(minSecondsLeft) || minSecondsLeft < 0) { say("--min-seconds must be a number"); process.exit(2); }
  const kindOk = (k) => { if (!KINDS.includes(k)) { say(`unknown credential kind '${k}' (known: ${KINDS.join(", ")})`); process.exit(2); } };
  const kindsOk = (spec) => {
    const r = parseKinds(spec);
    if (!r.ok) { say(r.reason); process.exit(2); }
    if (src !== undefined && r.kinds.length > 1) { say("--src names one kind's file; with several kinds each is read from its own path"); process.exit(2); }
    return r.kinds;
  };
  const fileOf = (kind) => src ?? defaultPath(kind);
  if (cmd === "path") {
    kindOk(argv[0]);
    console.log(defaultPath(argv[0]));
  } else if (cmd === "install" && argv[0] === "codex") {
    if (!from) { say("install codex needs --from <the CI account's auth.json> (made with CODEX_HOME=$(mktemp -d) codex login)"); process.exit(2); }
    const real = (p) => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };
    if (ownCodexSignIns().some((p) => real(p) === real(from))) {
      say("not installed: that is this account's own Codex sign-in; the host refreshes the CI sign-in, which would rotate yours and log that Codex out. " +
        "Sign in a DEDICATED CI account in a throwaway directory (CODEX_HOME=$(mktemp -d) codex login) and install that auth.json");
      process.exit(3);
    }
    let text;
    try { text = fs.readFileSync(from, "utf8"); } catch (e) { say(`not installed: cannot read ${from} (${e.code})`); process.exit(3); }
    const r = parseCodex(text);
    if (!r.ok) { say(`not installed: ${r.reason}`); process.exit(3); }
    const file = dest ?? defaultPath("codex");
    writeAtomic(file, JSON.stringify(r.auth, null, 2) + "\n");
    const days = Math.floor((r.exp - Date.now() / 1000) / 86400);
    say(`installed ${file} (mode 0600; the access token has ${days} days left; the nightly refreshes it). Delete ${from} now`);
  } else if (cmd === "refresh") {
    if (argv[0] !== "codex") { say("usage: credential.mjs refresh codex [--min-seconds N]"); process.exit(2); }
    const file = dest ?? defaultPath("codex");
    if (!process.env.MANDU_CI_CODEX_LOCKED) {
      // flock(1): two refreshes of one sign-in must never race (the first
      // rotates the refresh token, the second would present a spent one).
      const lock = `${file}.lock`;
      fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      fs.closeSync(fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT, 0o600));
      let rc = 0;
      try {
        execFileSync("flock", ["-w", "600", lock, process.execPath, process.argv[1], ...process.argv.slice(2)],
          { stdio: "inherit", env: { ...process.env, MANDU_CI_CODEX_LOCKED: "1" } });
      } catch (e) { rc = typeof e.status === "number" ? e.status : 3; }
      process.exit(rc);
    }
    const r = await refreshCodex(file, { minSeconds: min === undefined ? undefined : minSecondsLeft });
    if (!r.ok) {
      say(`codex: not refreshed: ${r.reason}`);
      if (r.absent) for (const l of SETUP_STEPS(file, "codex")) console.error(l);
      process.exit(3);
    }
    say(`codex: ${r.refreshed ? "refreshed" : "fresh enough, not refreshed"}; the access token has ${Math.floor(r.secondsLeft / 3600)} h left`);
  } else if (cmd === "install" && argv[0] === "docker-user") {
    // The username alone, for a token already in place (not secret: echoed).
    const uf = dockerUserFile(dest ?? defaultPath("docker"));
    const user = readSecretLine("the Docker account's username, then Enter: ", { echo: true }).trim();
    const ub = refusedDockerUser(user);
    if (ub) { say(`not installed: ${ub}`); process.exit(3); }
    writeAtomic(uf, user);
    say(`wrote the Docker username ${user} to ${uf}`);
  } else if (cmd === "install" && (TOOL_KINDS.includes(argv[0]) || (argv[0] === "api" && TOOL_KINDS.includes(provider ?? "")))) {
    // A tool's token: its own file, never api-keys.json (`install api
    // --provider docker` is the same command as `install docker`).
    installTool(TOOL_KINDS.includes(argv[0]) ? argv[0] : provider, dest, say);
  } else if (cmd === "install" && argv[0] === "api") {
    if (!PROVIDERS.includes(provider ?? "")) {
      say(`install api needs --provider ${PROVIDERS.join("|")} (model keys, into api-keys.json) or ${TOOL_KINDS.join("|")} (tool tokens, each into its own file)`);
      process.exit(2);
    }
    const file = dest ?? defaultPath("api");
    let existing = "";
    if (fs.existsSync(file)) {
      const f = checkFile(file);
      if (!f.ok) { say(`not installed: ${f.reason}`); process.exit(3); }
      existing = fs.readFileSync(file, "utf8");
    }
    const r = installApi(existing, provider, readSecretLine(`paste the ${provider} API key, then Enter: `));
    if (!r.ok) { say(`not installed: ${r.reason}`); process.exit(3); }
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = `${file}.tmp-${process.pid}`;
    const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    fs.writeSync(fd, r.json); fs.closeSync(fd); fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
    say(`installed the ${provider} key in ${file} (mode 0600; keys: ${Object.keys(JSON.parse(r.json)).join(", ")})`);
  } else if (cmd === "install") {
    kindOk(argv[0]);
    if (!Number.isInteger(validDays) || validDays < 1) { say("--valid-days must be a positive number"); process.exit(2); }
    // The eval runners (and the agent's own auth status, which reads it from
    // this file only) need the plan in the file; the token carries none.
    if (!["max", "pro"].includes(subscription ?? "")) { say("install needs --subscription max|pro (the plan of the login the token came from)"); process.exit(2); }
    const file = dest ?? defaultPath(argv[0]);
    const r = installShape(readSecretLine(), { validDays, subscription });
    if (!r.ok) { say(`not installed: ${r.reason}`); process.exit(3); }
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = `${file}.tmp-${process.pid}`;
    const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    fs.writeSync(fd, r.json); fs.closeSync(fd); fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
    say(`installed ${file} (mode 0600; valid for ${validDays} days${subscription ? `, subscription ${subscription}` : ""})`);
  } else if (cmd === "check" || cmd === "prepare") {
    const kinds = kindsOk(argv[0]);
    const loaded = [];
    for (const kind of kinds) {
      const file = fileOf(kind);
      const r = load(kind, file, { minSecondsLeft });
      if (!r.ok) {
        say(`not usable: ${kinds.length > 1 ? `${kind}: ` : ""}${r.reason}`);
        if (r.absentUser) console.error(`the token is in place; add the username: node scripts/ci/credential.mjs install docker-user${src ? ` --dest "${file}"` : ""}   (or set MANDU_CI_DOCKER_USER)`);
        else if (r.absent) for (const l of SETUP_STEPS(file, kind)) console.error(l);
        process.exit(3);
      }
      loaded.push({ kind, ...r });
    }
    if (cmd === "prepare") {
      if (!out) { say("prepare needs --out TAR"); process.exit(2); }
      const fd = fs.openSync(out, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
      fs.writeSync(fd, credentialTar(loaded.map((r) => ({ kind: r.kind, json: r.json })))); fs.closeSync(fd);
    }
    for (const r of loaded) {
      const left = r.secondsLeft === null ? "" : r.secondsLeft >= 172800 ? `, ${Math.floor(r.secondsLeft / 86400)} days left` : `, ${Math.floor(r.secondsLeft / 3600)} h left`;
      say(`${r.kind}: ${r.form}${left}; ${cmd === "prepare" ? "on the credential disk" : "usable"}`);
    }
  } else if (cmd === "scan") {
    const kinds = /^[a-z,]+$/.test(argv[0] ?? "") && argv[0].split(",").every((k) => KINDS.includes(k)) ? kindsOk(argv.shift()) : ["claude"];
    if (!argv.length) { say("usage: credential.mjs scan [K[,K]] [--src FILE] PATH... (--src with one kind; else each kind's own path)"); process.exit(2); }
    const tokens = [];
    for (const kind of kinds) {
      // Any age: an expired token that leaks is still a leak.
      const r = load(kind, fileOf(kind), { minSecondsLeft: -Infinity, tokenOnly: true });
      if (!r.ok) { say(`scan: cannot read the ${kind} credential: ${r.reason}`); process.exit(2); }
      tokens.push(...r.tokens);
    }
    const s = scan(tokens, argv);
    if (s.found.length) { for (const f of s.found) say(`CANARY: the credential is in ${f}`); process.exit(1); }
    say(`canary: clean (${s.files} files, ${s.bytes} bytes)`);
  } else {
    say("usage: credential.mjs path|install|refresh|check|prepare|scan …"); process.exit(2);
  }
}
