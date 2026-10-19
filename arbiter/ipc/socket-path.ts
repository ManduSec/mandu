/**
 * socket-path — refuse a Unix socket path the kernel would silently truncate
 * (docs/design/architecture/runtime-instances.md §3a).
 *
 * `sockaddr_un.sun_path` holds 108 bytes on Linux and 104 on macOS / the
 * BSDs, the trailing NUL included. bind(2) and connect(2) do not fail on a
 * longer path: they use its first 107 (103) bytes, so an arbiter binds a name
 * nobody looks for and a client dials whatever sits at the shortened name.
 * The launcher already refused an over-long MANDU_ARBITER_SOCK
 * (launcher/src/arbiter.ts assertSockPathFits); the arbiter's own bind and its
 * client now refuse too, so every way of starting or reaching an arbiter
 * (scripts/dev-arbiter.sh, the dashboard supervisor, tests) gets the same
 * refusal instead of an arbiter that "never comes up".
 *
 * The limit is on the string handed to the kernel, so a relative path is
 * measured as given. Byte length, not character length.
 *
 * Mandu-new (no reference origin).
 */

import { sunPathMaxFor } from "./runtime-base.js";

/** `sun_path` capacity, NUL included (runtime-base.ts sunPathMaxFor: 104 on
 *  macOS and the BSDs, 108 elsewhere). The default runtime base is chosen so
 *  an instance socket always fits (runtime-instances.md §3b); this check is
 *  what catches an explicit path that does not. */
export const SUN_PATH_MAX = sunPathMaxFor(process.platform);

/** Why `path` cannot be a Unix socket address, or null when it fits. Pure. */
export function socketPathProblem(path: string, max: number = SUN_PATH_MAX): string | null {
  const bytes = Buffer.byteLength(path, "utf8");
  if (bytes < max) return null;
  return (
    `the socket path is ${bytes} bytes, over the ${max - 1}-byte limit for a Unix socket (sun_path): ` +
    `the kernel would silently shorten it to ${JSON.stringify(Buffer.from(path, "utf8").subarray(0, max - 1).toString("utf8"))}. ` +
    `Use a shorter path (MANDU_ARBITER_SOCK or MANDU_RUNTIME_DIR). Path was: ${path}`
  );
}

/** Throw when `path` would be truncated. `what` names the socket in the message. */
export function assertSocketPathFits(path: string, what: string): void {
  const problem = socketPathProblem(path);
  if (problem !== null) throw new Error(`${what}: ${problem}`);
}
