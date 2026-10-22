// @ts-check
/**
 * policy — the policy.yaml a CI run of Mandu enforces (pure).
 *
 * Two questions, each answered fail-closed:
 *
 *   1. Which policy text may this run trust (`policySource`)? A policy file
 *      in the workspace is only as trustworthy as the commit it came from. On
 *      the events whose workflow runs from the base branch while the
 *      workspace may hold someone else's code (`pull_request_target`, a
 *      comment trigger that checks out the pull request's head), a file read
 *      from that checkout could bind a secret to any host. So the file is
 *      read from the commit the workflow runs for (GITHUB_SHA): from the
 *      workspace when HEAD is that commit, else from git's copy of that
 *      commit, else not at all unless `trust-workspace-policy` says so.
 *
 *   2. What does the run enforce (`assemblePolicy`)? The trusted text, plus
 *      the action's `bindings` and `mask-env` inputs as an `env:` section:
 *      each binding is an `env.sources` entry that reads the job's own value
 *      (`cmd:printenv NAME`), so the arbiter registers it as a secret with
 *      exactly those hosts (launcher/src/env-sources.ts), and each extra
 *      mask is an `env.secrets` name. The text is never parsed as YAML here
 *      (the action ships no YAML library): the section is appended when the
 *      file has no top-level `env:` of its own, and a file that has one gets
 *      a refusal that says where its bindings go instead.
 *
 * Design: docs/design/distribution/github-action.md §5.
 * Mandu-new (no reference origin).
 */

/**
 * @typedef {{ ok: true, text: string, from: string } | { ok: false, problem: string }} SourceDecision
 */

/**
 * Decide where the run's policy text comes from.
 * @param {{
 *   inline: string,
 *   file: string,
 *   fileExplicit: boolean,
 *   trustWorkspace: boolean,
 *   githubSha: string,
 *   headSha: string | null,
 *   readWorkspace: (rel: string) => string | null,
 *   readAtCommit: (sha: string, rel: string) => string | null,
 * }} o
 * @returns {SourceDecision}
 */
export function policySource(o) {
  if (o.inline.trim()) return { ok: true, text: o.inline, from: "the policy input" };
  if (!o.file) return { ok: true, text: "", from: "none" };
  const atHead = o.readWorkspace(o.file);
  const sameCommit = !o.githubSha || (o.headSha !== null && o.headSha === o.githubSha);
  if (sameCommit || o.trustWorkspace) {
    if (atHead === null) {
      return o.fileExplicit
        ? { ok: false, problem: `policy-file: ${o.file} does not exist in the workspace` }
        : { ok: true, text: "", from: "none" };
    }
    return { ok: true, text: atHead, from: sameCommit ? o.file : `${o.file} (the workspace's copy, trust-workspace-policy)` };
  }
  // The workspace is another commit than the one the workflow runs for.
  const atCommit = o.readAtCommit(o.githubSha, o.file);
  if (atCommit !== null) return { ok: true, text: atCommit, from: `${o.file} at ${o.githubSha.slice(0, 12)}` };
  if (atHead === null && !o.fileExplicit) return { ok: true, text: "", from: "none" };
  return {
    ok: false,
    problem: `policy-file: the workspace is not the commit this workflow runs for (HEAD ${o.headSha?.slice(0, 12) ?? "unknown"}, GITHUB_SHA ${o.githubSha.slice(0, 12)}), ` +
      `and ${o.file} at ${o.githubSha.slice(0, 12)} is not in the clone, so a policy file from this checkout could bind your secrets to any host. ` +
      "Give the rules in the `policy` input (the workflow file is the base branch's), fetch that commit, or set trust-workspace-policy: true if this checkout is yours.",
  };
}

/** Does the YAML text have a top-level key `key:`? A plain line scan: a key
 *  at column 0, outside a block scalar is what YAML means; a flow-style
 *  document (`{ ... }`) is reported as unreadable. */
export function topLevelKeys(text) {
  const keys = new Set();
  let flow = false;
  for (const line of String(text).split(/\r?\n/)) {
    if (/^\s*(#|$)/.test(line) || /^(---|\.\.\.)\s*$/.test(line)) continue;
    if (/^[{[]/.test(line)) { flow = true; continue; }
    const m = /^([A-Za-z_][A-Za-z0-9_-]*|"[^"]+"|'[^']+')\s*:(\s|$)/.exec(line);
    if (m) keys.add(m[1].replace(/^["']|["']$/g, ""));
  }
  return { keys, flow };
}

/**
 * The policy text the run enforces.
 * @param {string} base           the trusted text ("" = none)
 * @param {Array<{ name: string, hosts: string[] }>} bindings
 * @param {string[]} maskEnv
 * @returns {{ ok: true, text: string } | { ok: false, problem: string }}
 */
export function assemblePolicy(base, bindings, maskEnv) {
  const text = String(base ?? "");
  const extra = bindings.length > 0 || maskEnv.length > 0;
  const { keys, flow } = topLevelKeys(text);
  if (!extra) return { ok: true, text: text.trim() ? text : "version: 1\n" };
  if (flow) return { ok: false, problem: "bindings / mask-env: the policy file is a flow-style YAML document; write it in block style, or put the bindings in its own env: section" };
  if (keys.has("env")) {
    return {
      ok: false,
      problem: "bindings / mask-env: the policy file has its own env: section; put the bindings there (env.sources, with source: \"cmd:printenv NAME\") and the extra names under env.secrets, or drop these inputs",
    };
  }
  const lines = ["", "# Added by the Mandu GitHub Action (its bindings and mask-env inputs).", "env:"];
  if (maskEnv.length) lines.push(`  secrets: [${maskEnv.map((n) => JSON.stringify(n)).join(", ")}]`);
  if (bindings.length) {
    lines.push("  sources:");
    for (const b of bindings) {
      lines.push(`    - name: ${JSON.stringify(b.name)}`);
      lines.push(`      source: ${JSON.stringify(`cmd:printenv ${b.name}`)}`);
      lines.push(`      bindings: [${b.hosts.map((h) => JSON.stringify(h)).join(", ")}]`);
    }
  }
  const head = text.trim() ? (text.endsWith("\n") ? text : `${text}\n`) : "version: 1\n";
  return { ok: true, text: `${head}${lines.join("\n")}\n` };
}
