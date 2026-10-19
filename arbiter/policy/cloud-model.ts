/**
 * cloud-model — is a model NAME one that a "local" server runs on someone
 * else's machine? (model-endpoints.md §1.8 item 3)
 *
 * Ollama serves cloud-backed models (`gpt-oss:120b-cloud`,
 * `qwen3-coder:480b-cloud`, `glm-4.6:cloud`, …) through the SAME loopback API
 * as the models it runs itself: the request goes to 127.0.0.1:11434 and the
 * prompt goes on to ollama.com. So a correctly declared `local: true`
 * endpoint can still send `local-model` bytes off the machine. D2 already
 * says an ADDRESS is not local by itself; this is the same rule for the
 * model name.
 *
 * The rule (case-insensitive, surrounding whitespace ignored, a trailing
 * `@<digest>` ignored):
 *   - the TAG (the part after the last `:`, when that part holds no `/`, so
 *     `registry:5000/model` has no tag) has `cloud` as one of its
 *     `-` / `_` / `.` separated words: `:cloud`, `:120b-cloud`,
 *     `:480b-cloud-q4`;
 *   - or the model's own name (the last `/` segment before the tag) ENDS in
 *     the word `cloud`: `deepseek-v3.1-cloud`, `foo_cloud:latest`, `cloud`.
 * Words, not substrings: `wordcloud`, `soundcloud-embed` and `cloudy` are
 * not cloud-backed. A name that merely starts with `cloud-` is not refused
 * (no server convention says it runs remotely).
 *
 * What this does NOT prove: that a name without the word runs locally. A
 * server can alias any name to a remote model (`ollama cp` of a cloud tag, a
 * LiteLLM route), and the name predicate cannot see that; `local: true`
 * stays the operator's claim about the server (D2, guarantees.md). The
 * predicate closes the one case the server's own naming makes visible.
 *
 * MIRRORED (the packages ship standalone and never import each other):
 *   launcher/src/model-endpoints.ts         `isCloudBackedModel`
 *   interceptors/anthropic-proxy/src/cloud-model.ts
 *   interceptors/openai-proxy/src/cloud-model.ts
 *   dashboard/src/model-probe.ts              `isCloudBackedModel`
 * tests/stack/cloud-model-parity.test.ts runs all five over
 * one table; change them together.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */

/** True when the model name says the server runs it remotely (see above). Pure. */
export function isCloudBackedModel(name: string): boolean {
  let s = name.trim().toLowerCase();
  const at = s.indexOf("@");
  if (at >= 0) s = s.slice(0, at);
  if (s === "") return false;
  const colon = s.lastIndexOf(":");
  const hasTag = colon >= 0 && !s.slice(colon + 1).includes("/");
  const tag = hasTag ? s.slice(colon + 1) : "";
  const base = hasTag ? s.slice(0, colon) : s;
  if (tag.split(/[-_.]/).includes("cloud")) return true;
  const own = base.slice(base.lastIndexOf("/") + 1);
  const words = own.split(/[-_.]/);
  return words[words.length - 1] === "cloud";
}
