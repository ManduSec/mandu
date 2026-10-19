/**
 * codex-auth — how a real-model Codex suite authenticates
 * (docs/design/agents/agent-sign-in.md §2.7; continuous-integration.md §9.8).
 *
 * Two modes, picked by MANDU_CODEX_AUTH:
 *   - `key` (default): an OpenAI API key in OPENAI_API_KEY, the launcher's
 *     `env_key` provider, the API upstream. The nightly's API lane.
 *   - `chatgpt`: a ChatGPT sign-in, the launcher's sign-in provider
 *     (`requires_openai_auth`, no `env_key`), and the openai-proxy relaying
 *     each turn to the ChatGPT backend. The nightly's subscription lane.
 *     The sign-in is read from MANDU_CI_CODEX_AUTH (the guest's reduced copy;
 *     by hand, any Codex sign-in file) and written to the suite's own
 *     CODEX_HOME as a REDUCED copy without its refresh token: Codex may write
 *     its own file, so it never gets the source file, and with no
 *     refresh token it can neither refresh nor rotate the source sign-in
 *     (a rotation would sign the source out). No OPENAI_API_KEY reaches Codex.
 *
 * The suites stay identical otherwise: the same scenarios, the same oracles,
 * the same proxy; only the credential, the provider and the upstream differ.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { join } from "node:path";
import type { Readable } from "node:stream";

import { codexProviderToml } from "../../launcher/src/env-compose.js";
import {
  CHATGPT_UPSTREAM_BASE, upstreamRequestPath, type UpstreamFetcher,
} from "../../interceptors/openai-proxy/src/proxy.js";

export type CodexAuthMode = "key" | "chatgpt";

/** The suite's mode (MANDU_CODEX_AUTH; anything but `chatgpt` is `key`). */
export function codexAuthMode(env: NodeJS.ProcessEnv = process.env): CodexAuthMode {
  return env["MANDU_CODEX_AUTH"] === "chatgpt" ? "chatgpt" : "key";
}

/** Why this mode cannot run here, or false. */
export function codexAuthSkip(mode: CodexAuthMode, env: NodeJS.ProcessEnv = process.env): string | false {
  if (mode === "key") {
    return env["OPENAI_API_KEY"]
      ? false
      : "no OPENAI_API_KEY: this suite drives a real OpenAI model (the API lane holds the key, run by hand, " +
        "continuous-integration.md §9.8); by hand, `source scripts/mandu-env.sh` exports it from secrets.local.json";
  }
  const src = env["MANDU_CI_CODEX_AUTH"];
  if (!src) {
    return "no MANDU_CI_CODEX_AUTH: the ChatGPT form needs a Codex sign-in (the nightly's subscription lane " +
      "holds a reduced one, continuous-integration.md §9.8); by hand, MANDU_CI_CODEX_AUTH=~/.codex/auth.json";
  }
  if (!existsSync(src)) return `MANDU_CI_CODEX_AUTH names a file that does not exist: ${src}`;
  return false;
}

/**
 * Write the reduced sign-in into `codexHome/auth.json` (chatgpt mode only):
 * the source's tokens with `refresh_token: ""` (codex-cli 0.159.1 requires
 * the field), `last_refresh` now (no proactive refresh), no API key. Throws
 * on a source that is not a ChatGPT sign-in; never prints a value.
 */
export function writeReducedSignIn(codexHome: string, env: NodeJS.ProcessEnv = process.env): void {
  const src = env["MANDU_CI_CODEX_AUTH"]!;
  let doc: { tokens?: Record<string, unknown> };
  try {
    doc = JSON.parse(readFileSync(src, "utf8")) as typeof doc;
  } catch {
    throw new Error(`MANDU_CI_CODEX_AUTH (${src}) is not JSON`);
  }
  const t = doc.tokens ?? {};
  for (const k of ["id_token", "access_token", "account_id"]) {
    if (typeof t[k] !== "string" || t[k] === "") throw new Error(`MANDU_CI_CODEX_AUTH (${src}) has no tokens.${k}: not a ChatGPT sign-in`);
  }
  const reduced = {
    OPENAI_API_KEY: null,
    tokens: { id_token: t["id_token"], access_token: t["access_token"], refresh_token: "", account_id: t["account_id"] },
    last_refresh: new Date().toISOString(),
  };
  writeFileSync(join(codexHome, "auth.json"), JSON.stringify(reduced, null, 2), { mode: 0o600 });
}

/** The launcher's own provider TOML for this mode, at the proxy's port. */
export function codexProvider(mode: CodexAuthMode, port: number): string {
  return codexProviderToml({
    openaiProviderName: "mandu",
    openaiProxy: { host: "127.0.0.1", port },
    codexAuth: mode === "chatgpt" ? "sign-in" : "key",
  });
}

/** The credential part of Codex's environment: the key, or nothing. */
export function codexCredentialEnv(mode: CodexAuthMode, env: NodeJS.ProcessEnv = process.env): Record<string, string | undefined> {
  return mode === "key" ? { OPENAI_API_KEY: env["OPENAI_API_KEY"] } : {};
}

/** The `-c model=…` for this mode: the key mode's pinned model; on a
 *  ChatGPT sign-in the backend's own default unless MANDU_CODEX_MODEL names
 *  one (a ChatGPT plan lists its own models). */
export function codexModelArgs(mode: CodexAuthMode, keyDefault: string, env: NodeJS.ProcessEnv = process.env): string[] {
  const chosen = env["MANDU_CODEX_MODEL"] || (mode === "key" ? keyDefault : "");
  return chosen ? ["-c", `model=${chosen}`] : [];
}

/**
 * A real HTTPS transport for one fixed upstream, optionally recording each
 * forwarded body (what T-LLM saw). `base` is an origin (the API) or a base URL
 * (the ChatGPT backend, whose path replaces the proxy's `/v1`), mapped the way
 * the proxy's own default fetcher maps it (upstreamRequestPath).
 */
export function httpsForwarder(base: string, isBaseUrl: boolean, bodies?: string[]): UpstreamFetcher {
  const url = new URL(base);
  return async ({ method, path, headers, body }) => {
    bodies?.push(Buffer.from(body).toString("utf8"));
    return new Promise((resolve, reject) => {
      const r = request(
        { protocol: url.protocol, hostname: url.hostname, port: 443, method, path: upstreamRequestPath(path, url, isBaseUrl), headers: { ...headers, host: url.host } },
        (up) => resolve({ status: up.statusCode ?? 502, headers: up.headers, body: up as unknown as Readable }),
      );
      r.on("error", reject);
      r.end(body);
    });
  };
}

/** The proxy's two transports: the API origin and the ChatGPT backend, both
 *  real and both recording into `bodies` when given. */
export function codexUpstreams(apiOrigin: string, bodies?: string[]): { upstream: UpstreamFetcher; chatgptUpstream: UpstreamFetcher } {
  return {
    upstream: httpsForwarder(apiOrigin, false, bodies),
    chatgptUpstream: httpsForwarder(CHATGPT_UPSTREAM_BASE, true, bodies),
  };
}
