/**
 * cloud-model — is a model NAME one the server runs on someone else's
 * machine? (model-endpoints.md §1.8 item 3)
 *
 * Ollama serves cloud-backed models (`gpt-oss:120b-cloud`, `glm-4.6:cloud`, …)
 * through the same loopback API as its own models, so a main model the
 * operator declared `local: true` at http://127.0.0.1:11434 still relays the
 * conversation to the vendor when the agent asks for such a name. The proxy
 * refuses those requests when its upstream is a declared local model
 * (`ProxyOptions.upstreamLocal`, env `MANDU_UPSTREAM_LOCAL=1`, set by the
 * launcher).
 *
 * The rule: case-insensitive, whitespace and a trailing `@<digest>` ignored;
 * true when the tag (after the last `:`, when that part holds no `/`) has
 * `cloud` as a `-` / `_` / `.` separated word, or the model's own name (last
 * `/` segment before the tag) ends in that word. Words, not substrings
 * (`wordcloud` is not). A name without the word is not proven local: a
 * server can alias any name to a remote model.
 *
 * MIRROR of arbiter/policy/cloud-model.ts (this package never imports the
 * arbiter's policy code) and of `isCloudBackedModel` in
 * launcher/src/model-endpoints.ts and interceptors/openai-proxy/src/cloud-model.ts; the four
 * are pinned to one table by
 * tests/stack/cloud-model-parity.test.ts. Change them together.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */

/** True when the model name says the server runs it remotely. Pure. */
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
