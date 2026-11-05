// policy.mjs — the box's pure decisions (docs/design/agents/openclaw-plugin.md
// §10): what environment a command gets inside the box, the argv it runs
// under, whether a path lies inside a root, and whether the facts the box
// host reports at start show a confined world. PURE, no I/O.
//
// Mandu-new (no reference origin). Plain JavaScript for the same reason as
// frames.mjs: the box host runs it on a bare node inside the launch.

/**
 * Variables a command's request may never replace when the box's own
 * environment sets them: the launch composed them (the egress proxy and its
 * CA, the SDK route, Mandu's own settings, the model routes). Replacing
 * them would not leak anything (the network guard still allows only the
 * proxy, and the box holds only placeholders), but it would make a
 * command's egress fail in confusing ways and take it off the paths Mandu
 * reports on, so the launch's values win.
 *
 * HOME too: OpenClaw gives a sandboxed command its workspace as HOME (a
 * container has no home of the user's), but Mandu's box runs on the user's
 * own files, where a program finds its config in the real HOME and a
 * credential file there reads as its placeholder copy.
 */
export const PROTECTED_ENV = new Set([
  "HOME",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
  "NODE_USE_ENV_PROXY", "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "JAVA_TOOL_OPTIONS", "PYTHONPATH",
  "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "KUBECONFIG",
]);

/** A variable name a shell can export. */
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Is `v` one of Mandu's placeholders (a variable the launch masked)? */
function isPlaceholder(v) {
  return typeof v === "string" && v.includes("$MDU:");
}

/**
 * The environment a command runs with inside the box: the box's own (the
 * launch's, with secret-shaped variables already masked to placeholders),
 * then what OpenClaw asked for on top, except
 *   - a name that is not a shell name;
 *   - a protected name the box sets (PROTECTED_ENV, or any MANDU_* name);
 *   - a name whose box value is a placeholder (the launch masked it: the
 *     request must not put a raw value back);
 * PATH is the box's, with the request's directories it lacks appended (the
 * launch's own directories, its shims, stay first). Every value is a string.
 * @param {Record<string, string | undefined>} base
 * @param {Record<string, unknown> | undefined} requested
 * @returns {Record<string, string>}
 */
export function mergeCommandEnv(base, requested) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const [k, v] of Object.entries(base)) if (typeof v === "string") out[k] = v;
  for (const [k, v] of Object.entries(requested ?? {})) {
    if (typeof v !== "string" || !NAME_RE.test(k) || k === "PATH") continue;
    const own = out[k];
    if (own !== undefined && (PROTECTED_ENV.has(k) || k.startsWith("MANDU_") || isPlaceholder(own))) continue;
    if (own === undefined && k.startsWith("MANDU_")) continue;
    out[k] = v;
  }
  const basePath = (out["PATH"] ?? "").split(":").filter(Boolean);
  const reqPath = typeof requested?.["PATH"] === "string" ? String(requested["PATH"]).split(":").filter(Boolean) : [];
  const merged = [...basePath];
  for (const d of reqPath) if (!merged.includes(d)) merged.push(d);
  if (merged.length > 0) out["PATH"] = merged.join(":");
  return out;
}

/**
 * The argv a command runs under: `/bin/sh -c <command>`, or, when OpenClaw
 * asked for a terminal and `script` (util-linux) is there, the same command
 * under `script` so the program sees a terminal.
 * @param {string} command
 * @param {boolean} pty
 * @param {string | null} scriptBin
 * @returns {string[]}
 */
export function commandArgv(command, pty, scriptBin) {
  if (pty && scriptBin) return [scriptBin, "-qfec", command, "/dev/null"];
  return ["/bin/sh", "-c", command];
}

/**
 * Is the absolute path `p` at or under `root` (both already canonical)?
 * @param {string} root
 * @param {string} p
 */
export function isInside(root, p) {
  const r = root.endsWith("/") && root !== "/" ? root.slice(0, -1) : root;
  return p === r || p.startsWith(r === "/" ? "/" : `${r}/`);
}

/**
 * What the box host checks about its own world at start, and reports:
 *   seccomp       the `Seccomp:` mode of /proc/self/status ("2": a filter,
 *                 the network guard's);
 *   manduHome     "hidden" (unreadable), "absent" or "visible";
 *   egressProxy   whether the launch gave it an egress proxy (HTTPS_PROXY);
 *   guardPorts    whether the network guard names the proxy's port
 *                 (MANDU_NET_GUARD_PROXY_PORTS).
 * The plugin accepts the box only when every fact holds: a box that does not
 * confine is refused, never used (fail closed). Returns the reasons it falls
 * short (empty: confined).
 * @param {{seccomp?: string, manduHome?: string, egressProxy?: boolean, guardPorts?: boolean} | null | undefined} f
 * @returns {string[]}
 */
export function boxFactsProblems(f) {
  if (!f || typeof f !== "object") return ["the box reported nothing about its own world"];
  const out = [];
  if (f.seccomp !== "2") out.push("no network guard (no seccomp filter) on the box");
  if (f.manduHome === "visible") out.push("Mandu's own folder is readable inside the box");
  if (f.egressProxy !== true) out.push("the box has no egress proxy");
  if (f.guardPorts !== true) out.push("the network guard does not name the egress proxy");
  return out;
}
