// @ts-check
/**
 * inputs — the Mandu GitHub Action's inputs, read and checked (pure).
 *
 * The composite step hands every input over as an environment variable
 * `MANDU_ACTION_<NAME>` (action.yml: composite actions get no INPUT_*
 * variables of their own). This module turns them into one checked config,
 * or a list of problems the run prints before anything starts: an input the
 * action cannot read is a refusal, never a guess.
 *
 * Design: docs/design/distribution/github-action.md §4.
 * Mandu-new (no reference origin).
 */

/** The agents the action runs, and the headless form of each. */
export const AGENTS = /** @type {const} */ (["claude", "codex"]);

/** The variable name every binding and extra mask names. */
export const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** A binding host, as policy.yaml's validator takes it
 *  (arbiter/policy/policy-file-validate.ts BINDING_HOST_RE). */
export const BINDING_HOST_RE = /^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d+)?$/;

/**
 * @typedef {object} ActionConfig
 * @property {"claude" | "codex"} agent
 * @property {string} prompt
 * @property {string[]} agentArgs
 * @property {string} workingDirectory
 * @property {string} policyFile          workspace-relative; "" = none
 * @property {boolean} policyFileExplicit the user named it (a missing file is then a refusal)
 * @property {string} policyInline        inline policy.yaml text; "" = none
 * @property {Array<{ name: string, hosts: string[] }>} bindings
 * @property {string[]} maskEnv
 * @property {boolean} requireConfinement
 * @property {boolean} failOnBlocked
 * @property {boolean} trustWorkspacePolicy
 * @property {boolean} allowPersistedCredentials
 * @property {"auto" | "true" | "false"} setup
 * @property {boolean} summary
 * @property {boolean} verbose
 */

/** The default policy file, used only when it exists. */
export const DEFAULT_POLICY_FILE = ".github/mandu/policy.yaml";

/** `true` / `false` (and the usual spellings); anything else is a problem. */
export function parseBool(raw, name, dflt, problems) {
  const v = String(raw ?? "").trim().toLowerCase();
  if (v === "") return dflt;
  if (["true", "1", "yes", "on"].includes(v)) return true;
  if (["false", "0", "no", "off"].includes(v)) return false;
  problems.push(`${name}: must be true or false (got ${JSON.stringify(raw)})`);
  return dflt;
}

/**
 * Split an argument string the way a POSIX shell splits words, without
 * running anything: single quotes keep everything, double quotes keep
 * everything but `\"` and `\\`, a backslash outside quotes escapes the next
 * character. No expansion of any kind ($VAR, globs, ~). A JSON array
 * (`["--a", "b c"]`) is taken as is. Returns null on an unclosed quote.
 * @param {string} raw
 * @returns {string[] | null}
 */
export function splitArgs(raw) {
  const s = String(raw ?? "").trim();
  if (s === "") return [];
  if (s.startsWith("[")) {
    try {
      const v = JSON.parse(s);
      if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v;
    } catch { /* not JSON: fall through to a parse error */ }
    return null;
  }
  /** @type {string[]} */
  const out = [];
  let cur = "";
  let inWord = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) return null;
      cur += s.slice(i + 1, end);
      i = end;
      inWord = true;
    } else if (c === '"') {
      let j = i + 1;
      for (; j < s.length && s[j] !== '"'; j++) {
        if (s[j] === "\\" && (s[j + 1] === '"' || s[j + 1] === "\\")) { cur += s[j + 1]; j++; } else cur += s[j];
      }
      if (j >= s.length) return null;
      i = j;
      inWord = true;
    } else if (c === "\\") {
      if (i + 1 < s.length) { cur += s[i + 1]; i++; }
      inWord = true;
    } else if (/\s/.test(c)) {
      if (inWord) { out.push(cur); cur = ""; inWord = false; }
    } else {
      cur += c;
      inWord = true;
    }
  }
  if (inWord) out.push(cur);
  return out;
}

/**
 * The `bindings` input: one variable per line, `NAME: host, host` (also
 * `NAME=host host`). Blank lines and `#` comments are skipped. Each name is
 * a variable of the job's environment whose real value may go to those
 * hosts, and nowhere else.
 * @param {string} raw
 * @param {string[]} problems
 */
export function parseBindings(raw, problems) {
  /** @type {Map<string, string[]>} */
  const byName = new Map();
  String(raw ?? "").split(/\r?\n/).forEach((line, i) => {
    const t = line.replace(/(^|\s)#.*$/, "").trim();
    if (t === "") return;
    const m = /^([^:=\s]+)\s*[:=]\s*(.*)$/.exec(t);
    if (!m) { problems.push(`bindings line ${i + 1}: write NAME: host, host`); return; }
    const name = m[1];
    if (!ENV_NAME_RE.test(name)) { problems.push(`bindings line ${i + 1}: ${JSON.stringify(name)} is not a variable name`); return; }
    const hosts = m[2].split(/[\s,]+/).filter(Boolean);
    if (hosts.length === 0) { problems.push(`bindings line ${i + 1}: ${name} names no host`); return; }
    const bad = hosts.filter((h) => !BINDING_HOST_RE.test(h));
    if (bad.length) { problems.push(`bindings line ${i + 1}: not a host name: ${bad.map((h) => JSON.stringify(h)).join(", ")}`); return; }
    if (byName.has(name)) { problems.push(`bindings line ${i + 1}: ${name} is bound twice; put its hosts on one line`); return; }
    byName.set(name, hosts);
  });
  return [...byName].map(([name, hosts]) => ({ name, hosts }));
}

/** A list input: names separated by commas, spaces or newlines. */
export function parseNameList(raw, what, problems) {
  const names = String(raw ?? "").split(/[\s,]+/).filter(Boolean);
  for (const n of names) if (!ENV_NAME_RE.test(n)) problems.push(`${what}: ${JSON.stringify(n)} is not a variable name`);
  return [...new Set(names.filter((n) => ENV_NAME_RE.test(n)))];
}

/**
 * Read the action's inputs from its environment.
 * @param {Record<string, string | undefined>} env
 * @param {(path: string) => string | null} readFile  for prompt-file; null when unreadable
 * @returns {{ config: ActionConfig, problems: string[] }}
 */
export function parseInputs(env, readFile) {
  /** @type {string[]} */
  const problems = [];
  const get = (/** @type {string} */ k) => env[`MANDU_ACTION_${k}`] ?? "";

  const agentRaw = get("AGENT").trim() || "claude";
  const agent = /** @type {"claude" | "codex"} */ (AGENTS.includes(/** @type {any} */ (agentRaw)) ? agentRaw : "claude");
  if (!AGENTS.includes(/** @type {any} */ (agentRaw))) problems.push(`agent: must be claude or codex (got ${JSON.stringify(agentRaw)})`);

  let prompt = get("PROMPT");
  const promptFile = get("PROMPT_FILE").trim();
  if (prompt.trim() && promptFile) problems.push("prompt and prompt-file: give one, not both");
  else if (promptFile) {
    const text = readFile(promptFile);
    if (text === null) problems.push(`prompt-file: cannot read ${promptFile}`);
    else prompt = text;
  }
  if (!prompt.trim()) problems.push("prompt: required (or prompt-file)");

  const agentArgs = splitArgs(get("AGENT_ARGS"));
  if (agentArgs === null) problems.push("agent-args: an unclosed quote (or a JSON array that is not a list of strings)");

  const policyInline = get("POLICY");
  const policyFileRaw = get("POLICY_FILE").trim();
  if (policyInline.trim() && policyFileRaw) problems.push("policy and policy-file: give one, not both");

  const setupRaw = get("SETUP").trim().toLowerCase() || "auto";
  if (!["auto", "true", "false"].includes(setupRaw)) problems.push(`setup: must be auto, true or false (got ${JSON.stringify(setupRaw)})`);

  const config = {
    agent,
    prompt,
    agentArgs: agentArgs ?? [],
    workingDirectory: get("WORKING_DIRECTORY").trim() || ".",
    policyFile: policyInline.trim() ? "" : (policyFileRaw || DEFAULT_POLICY_FILE),
    policyFileExplicit: policyFileRaw !== "",
    policyInline: policyInline.trim() ? policyInline : "",
    bindings: parseBindings(get("BINDINGS"), problems),
    maskEnv: parseNameList(get("MASK_ENV"), "mask-env", problems),
    requireConfinement: parseBool(get("REQUIRE_CONFINEMENT"), "require-confinement", true, problems),
    failOnBlocked: parseBool(get("FAIL_ON_BLOCKED"), "fail-on-blocked", true, problems),
    trustWorkspacePolicy: parseBool(get("TRUST_WORKSPACE_POLICY"), "trust-workspace-policy", false, problems),
    allowPersistedCredentials: parseBool(get("ALLOW_PERSISTED_CREDENTIALS"), "allow-persisted-credentials", false, problems),
    setup: /** @type {"auto" | "true" | "false"} */ (["auto", "true", "false"].includes(setupRaw) ? setupRaw : "auto"),
    summary: parseBool(get("SUMMARY"), "summary", true, problems),
    verbose: parseBool(get("VERBOSE"), "verbose", false, problems),
  };
  return { config, problems };
}
