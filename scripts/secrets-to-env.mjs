#!/usr/bin/env node
/**
 * secrets-to-env — read the (gitignored) Mandu secrets JSON and emit shell
 * `export VAR=…` lines mapping it to the env vars the stack already reads.
 *
 * This is the CENTRAL place API keys are specified: one JSON file, mapped here to
 * the scattered env vars (ANTHROPIC_API_KEY / OPENAI_API_KEY / MANDU_ULLM_*)
 * that launcher/parse.ts, the proxies, inspect-mcp, and the eval backends consume.
 * See docs/design/testing/continuous-integration.md §13.
 *
 * Usage (via scripts/mandu-env.sh):  eval "$(node scripts/secrets-to-env.mjs)"
 *
 * IN PROCESS (2026-10-16, packaging.md §5.1): a checkout's `mandu` launch no
 * longer runs this as a CLI. launcher/mandu-run.sh execs the launcher's own
 * node, whose checkout prelude (launcher/scripts/checkout-launch.mjs) imports
 * `applySecretsEnv` and applies the same exports to its process.env before
 * the launcher reads it: one node start fewer per launch. `secretsEnv` is the
 * one computation both use, so the CLI's export lines and the in-process
 * assignments carry the same names and values, with the same precedence.
 *
 * OUTPUT FORMATS:
 *   (default)          `export VAR='…'` lines, to be eval'd into a shell. Vars
 *                      already set in the environment are NOT emitted — the shell
 *                      already has them, and re-exporting would clobber an
 *                      explicit override.
 *   --format=env-file  bare `VAR=…` lines for `docker run --env-file`, carrying
 *                      the EFFECTIVE value of each key: the environment wins where
 *                      it is set (so a masked GitLab CI variable overrides the
 *                      file), the file fills the rest. Unlike the default format
 *                      this MUST materialize already-set vars too — the container
 *                      does not inherit the caller's environment, so a var omitted
 *                      here simply would not exist inside it. Used by
 *                      scripts/ci/docker-run.sh --with-secrets, which is the only
 *                      path by which a key ever enters a CI container.
 *
 * DISCOVERY (first that exists wins):
 *   <repo>/secrets.local.json             repo-root, gitignored (convenient)
 *   <home>/secrets.json                   the Mandu home's (the path table's
 *                                         `secrets-json`): $MANDU_HOME/secrets.json,
 *                                         else ~/.mandu/secrets.json
 *
 * SAFETY:
 *   - Prints ONLY to stdout the `export` lines (so it can be eval'd); all
 *     diagnostics go to stderr, masked (never the raw key).
 *   - Never OVERRIDES an env var already set+non-empty — an explicit `export` in
 *     your shell / CI wins over the file (principle of least surprise).
 *   - A missing file, unreadable file, or JSON parse error is NON-FATAL: it emits
 *     nothing and exits 0, so `source`-ing it never breaks your shell.
 *   - Warns (stderr) if the file is group/other-readable.
 *
 * OFF (MANDU_SECRETS_FILE=0): the file is not read at all, as if none
 * existed; the environment alone counts (in env-file format it is still
 * materialized). For a launch that must ride a subscription sign-in and
 * never a key from the file: the hand-run Claude Code live drill, whose
 * launcher shim would otherwise load ANTHROPIC_API_KEY (and with it the
 * U-LLM's api mode). continuous-integration.md §13.2.
 *
 * QUIET (MANDU_SECRETS_QUIET=1 for the CLI; the launcher's in-process load
 * passes `quiet` itself, true unless the launch is verbose): the
 * informational lines (no file found, what was loaded) are dropped so `mandu
 * claude` opens with the launcher's own banner only (packaging.md §5 "Launch
 * display policy"); warnings and errors still print.
 */

import { readFileSync, realpathSync, statSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { resolvePath } from "./paths/mandu-paths.mjs";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** JSON key → target env var. `ullm_api_key` has a fallback (see below). */
const MAP = {
  anthropic_api_key: "ANTHROPIC_API_KEY",
  openai_api_key: "OPENAI_API_KEY",
  openai_base_url: "OPENAI_BASE_URL",
  ullm_api_key: "MANDU_ULLM_API_KEY",
  ullm_base_url: "MANDU_ULLM_BASE_URL",
  ullm_model: "MANDU_ULLM_MODEL",
  // Model services a program in the session calls itself (jev-ultrafast's
  // TypeSafe model and its OpenRouter text helper): the launch masks each and
  // binds it to its own API host (launcher agent-key-grant.ts
  // PROVIDER_KEY_HOSTS, agent-sign-in.md §3.12).
  typesafe_api_key: "TYPESAFE_API_KEY",
  openrouter_api_key: "OPENROUTER_API_KEY",
};

/** A diagnostic line on stderr (the default `log`). */
const stderrLine = (msg) => process.stderr.write(`[mandu-secrets] ${msg}\n`);

function discover(env, home, off) {
  if (off) return null;
  const candidates = [
    join(REPO_ROOT, "secrets.local.json"),
    // The path table's `secrets-json` (docs/design/architecture/on-disk-layout.md §5).
    resolvePath("secrets-json", env, home),
  ];
  for (const p of candidates) {
    try {
      if (statSync(p).isFile()) return p;
    } catch {
      /* not there */
    }
  }
  return null;
}

/** What the load line shows for a value: its kind prefix and length, never
 *  its tail. The line lands in terminal recordings (the watch runner's .cast
 *  files are replayed and shared), so a `sk-pro…PoIA` preview there was a
 *  fingerprint of the real key (2026-09-27). */
function mask(v) {
  if (typeof v !== "string" || v.length === 0) return "(empty)";
  if (v.length <= 12) return `(set, ${v.length} chars)`;
  return `${v.slice(0, 3)}… (${v.length} chars)`;
}

function shQuote(v) {
  // POSIX single-quote escaping: close, insert an escaped quote, reopen.
  return `'${String(v).replace(/'/g, "'\\''")}'`;
}

function nonEmpty(v) {
  return typeof v === "string" && v.trim().length > 0;
}

/**
 * The variables the secrets file contributes, as `[name, value]` pairs in the
 * order the CLI prints them:
 *
 *   format "export"   (the default): only the variables `env` does not already
 *                     hold non-empty (an explicit export wins over the file);
 *   format "env-file": the EFFECTIVE value of every key (the environment
 *                     first, the file fills the gap); a value with a newline
 *                     is skipped.
 *
 * `env` is the environment judged (and read for MANDU_HOME,
 * MANDU_SECRETS_FILE); `quiet` drops the informational lines; `log` receives
 * each stderr line without its `[mandu-secrets] ` prefix. A missing,
 * unreadable or malformed file contributes nothing (and says so).
 */
export function secretsEnv({
  env = process.env,
  format = "export",
  quiet = env.MANDU_SECRETS_QUIET === "1",
  home = homedir(),
  log = stderrLine,
} = {}) {
  const warn = (msg) => log(msg);
  /** An informational line: dropped when quiet. */
  const info = (msg) => { if (!quiet) warn(msg); };
  /** MANDU_SECRETS_FILE=0: read no secrets file (the header's OFF). */
  const off = env.MANDU_SECRETS_FILE === "0";
  const out = [];

  const file = discover(env, home, off);
  let data = {};

  if (!file) {
    info(off
      ? "MANDU_SECRETS_FILE=0: the secrets file is not read"
      : "no secrets file found (looked for <repo>/secrets.local.json, then the Mandu home's secrets.json)");
    // env-file mode still has work: the environment itself (a masked GitLab
    // variable, say) may carry the keys, and the container — which inherits
    // nothing — needs them materialized. Shell mode has nothing left to do.
    if (format !== "env-file") return out;
  } else {
    // Perms hygiene: warn if others can read the key file.
    try {
      const mode = statSync(file).mode & 0o077;
      if (mode !== 0) warn(`WARNING: ${file} is group/other-readable (mode …${(statSync(file).mode & 0o777).toString(8)}); consider 'chmod 600'`);
    } catch {
      /* ignore */
    }

    try {
      data = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      warn(`could not parse ${file}: ${e.message} — file ignored`);
      data = {};
    }
    if (typeof data !== "object" || data === null) {
      warn(`${file} is not a JSON object — file ignored`);
      data = {};
    }
  }

  // ullm_api_key falls back to anthropic_api_key (the common single-key case).
  if (!nonEmpty(data.ullm_api_key) && nonEmpty(data.anthropic_api_key)) {
    data = { ...data, ullm_api_key: data.anthropic_api_key };
  }

  const loaded = [];
  const skipped = [];

  const emit = (envVar, value) => {
    const fromEnv = nonEmpty(env[envVar]);

    if (format === "env-file") {
      // Effective value: env wins (a CI variable overrides the file), file fills
      // the gap. Both are emitted — see the format note in the header.
      const effective = fromEnv ? env[envVar] : value;
      if (!nonEmpty(effective)) return;
      if (/[\r\n]/.test(effective)) {
        warn(`skipping ${envVar}: value contains a newline, which docker --env-file cannot represent`);
        return;
      }
      out.push([envVar, effective]);
      loaded.push(`${envVar}=${mask(effective)} (from ${fromEnv ? "env" : "file"})`);
      return;
    }

    if (!nonEmpty(value)) return;
    if (fromEnv) {
      skipped.push(envVar);
      return;
    }
    out.push([envVar, value]);
    loaded.push(`${envVar}=${mask(value)}`);
  };

  for (const [jsonKey, envVar] of Object.entries(MAP)) emit(envVar, data[jsonKey]);

  // Arbitrary passthrough for anything not first-classed above.
  if (data.env && typeof data.env === "object") {
    for (const [k, v] of Object.entries(data.env)) emit(k, v);
  }

  info(file ? `loaded ${file}` : "no secrets file — environment only");
  for (const l of loaded) info(`  set  ${l}`);
  for (const s of skipped) info(`  kept existing ${s} (env wins)`);
  if (loaded.length === 0 && skipped.length === 0) info("  (no recognized keys set)");
  return out;
}

/** A name `export NAME=…` accepts (bash rejects any other and sets nothing). */
const SHELL_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * The launcher's in-process load (packaging.md §5.1): what `source
 * scripts/mandu-env.sh` did to the shell that then exec'd the launcher,
 * applied to `env` (the launcher's process.env) directly. The same variables
 * with the same values, since it is `secretsEnv` in its export format: an
 * already-set variable is never overridden. Where the shell's `eval` would
 * have done otherwise it is followed: a name bash's `export` rejects is
 * skipped (with a line saying so), and a NUL byte, which command substitution
 * drops, is dropped. Best effort: an error is one warning line, never a
 * throw. Returns the names it set.
 */
export function applySecretsEnv(env = process.env, opts = {}) {
  const log = opts.log ?? stderrLine;
  const set = [];
  try {
    for (const [name, value] of secretsEnv({ ...opts, env, format: "export", log })) {
      if (!SHELL_NAME.test(name)) {
        log(`skipping ${JSON.stringify(name)}: not a valid environment variable name`);
        continue;
      }
      env[name] = String(value).replace(/\0/g, "");
      set.push(name);
    }
  } catch (e) {
    log(`could not load the secrets file: ${e instanceof Error ? e.message : String(e)} — nothing loaded`);
  }
  return set;
}

/** The CLI: "export" lines (eval into a shell) or "env-file" lines (docker
 *  run --env-file). */
function cli() {
  const format = process.argv.includes("--format=env-file") ? "env-file" : "export";
  for (const [name, value] of secretsEnv({ format })) {
    // env-file syntax is bare KEY=VALUE — no quoting, no escaping: docker takes
    // the rest of the line verbatim. shQuote there would embed literal quotes.
    process.stdout.write(format === "env-file" ? `${name}=${value}\n` : `export ${name}=${shQuote(value)}\n`);
  }
}

/** Run as a script (not imported)? Compared by real path: node resolves
 *  import.meta.url through symlinks while argv[1] keeps the typed spelling
 *  (a checkout reached through a symlinked directory). */
function isMain() {
  if (!process.argv[1]) return false;
  const real = (p) => { try { return realpathSync(p); } catch { return resolve(p); } };
  return real(process.argv[1]) === real(fileURLToPath(import.meta.url));
}

if (isMain()) cli();
