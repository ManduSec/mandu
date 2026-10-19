/**
 * env-sources — fill environment variables from a keystore or a command at
 * launch (policy.yaml `env.sources`, comparisons.md §3.4). The launcher
 * resolves each source here, OUTSIDE the agent's world and with the user's
 * terminal (a 1Password or keyring unlock can prompt), and hands the value to
 * the arbiter's registerEnvSecrets, which mints its placeholder with the
 * entry's bindings. The agent's environment only ever gets the placeholder:
 * a source that fails, or a value the arbiter will not register, leaves the
 * variable UNSET, never raw.
 *
 *   cmd:<shell command>              stdout, one trailing newline dropped
 *   keyring:<service>/<account>      secret-tool (Linux) / security (macOS)
 *   op://<vault>/<item>/<field>      the 1Password CLI, `op read`
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";

export interface EnvSource {
  name: string;
  source: string;
  bindings: string[];
}

/** The argv that reads a source, or null for an unknown scheme. Pure. */
export function envSourceCommand(source: string, platform: NodeJS.Platform = process.platform): string[] | null {
  if (source.startsWith("cmd:")) return ["sh", "-c", source.slice(4)];
  if (source.startsWith("op://")) return ["op", "read", source];
  const kr = /^keyring:([^/]+)\/(.+)$/.exec(source);
  if (kr) {
    return platform === "darwin"
      ? ["security", "find-generic-password", "-s", kr[1]!, "-a", kr[2]!, "-w"]
      : ["secret-tool", "lookup", "service", kr[1]!, "account", kr[2]!];
  }
  return null;
}

export type SourceResolver = (source: string) => { value: string } | { error: string };

/** Run a source's command: stdin and stderr stay on the user's terminal (an
 *  unlock prompt must reach them), stdout is the value. 60 s bound. */
export const resolveEnvSource: SourceResolver = (source) => {
  const argv = envSourceCommand(source);
  if (!argv) return { error: "unknown source scheme" };
  const r = spawnSync(argv[0]!, argv.slice(1), { encoding: "utf8", stdio: ["inherit", "pipe", "inherit"], timeout: 60_000 });
  if (r.error) return { error: (r.error as NodeJS.ErrnoException).code === "ENOENT" ? `${argv[0]} is not installed` : r.error.message };
  if (r.status !== 0) return { error: `${argv[0]} exited ${r.status}` };
  const value = (r.stdout ?? "").replace(/\r?\n$/, "");
  if (value === "") return { error: "the source printed nothing" };
  return { value };
};
