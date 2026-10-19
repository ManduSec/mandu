/**
 * unix-policy — the Unix socket allow-list for the agent's process tree
 * (sandbox-security-review-2026-09-28 finding 1). Mandu-new.
 *
 * With the confidentiality axis on, the whole-agent guard refuses a Unix
 * socket connect unless the socket is on this list or its listener is a
 * process of the agent's own tree (the guard reads the listener's pid with a
 * probe connection, `SO_PEERCRED`). Host services that run code on request
 * listen on Unix sockets: the systemd user manager (`systemd-run --user`),
 * the D-Bus session bus, docker, a tmux or editor server. What they run is
 * outside every Mandu confinement and reads the real secret files, so the
 * list names only sockets that do not run code for the caller:
 *
 *   - Mandu: the arbiter's socket and the session's run directory;
 *   - name service and logging: nscd, sssd, systemd-resolved and userdb,
 *     avahi (.local names), the journal, syslog's /dev/log;
 *   - the user's choices (2026-09-28): the ssh-agent, the gpg-agent (not
 *     dirmngr, which fetches from the network outside the guard), the
 *     Wayland display, and the X11 display. X11 lets any client type into
 *     other windows (a host terminal included); docs/guarantees.md says so.
 *
 * Extras: policy.yaml `unix_sockets.allow` (the human's law, read from the
 * arbiter at launch; arbiter/policy/guard-settings.ts) and `MANDU_UNIX_ALLOW`
 * (colon-separated), unioned. Each entry is a socket file or a directory of
 * sockets (absolute or `~/`), or `@name` for an abstract socket (a trailing
 * `*` makes it a prefix).
 *
 * The arbiter's HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md) is never on
 * this list: an entry (built-in, policy.yaml, MANDU_UNIX_ALLOW, the arbiter or
 * scope-dir entry) that equals, contains or lies in a human-plane directory
 * is dropped and reported, and the guard's separate always-deny list
 * (human-plane.ts `applyHumanPlaneDeny`) refuses it even with this list off.
 *
 * macOS (`platform: "darwin"`; exec-routing.md §4.3 "macOS"): the same list,
 * enforced by the whole-agent Seatbelt profile (seatbelt-profile.ts
 * component 5), with the macOS spellings: Mandu's whole runtime directory
 * (the `current` instance changes on promotion), mDNSResponder (every name
 * lookup goes through it) and syslog, the ssh and gpg agents, X11. Seatbelt
 * cannot ask who listens, so "sockets the tree opens itself" becomes
 * "sockets under the workspace"; the known host services that run code
 * (`darwinUnixRefuse`) stay refused even there. No abstract sockets exist.
 * Pure except `applyUnixPolicy`.
 */
import { dirname, join } from "node:path";
import { expandHome, mergeGuardPolicy, type GuardPolicyDeps } from "./guard-policy-file.js";
import { touchesHumanPlane } from "./human-plane.js";

export interface UnixAllow {
  path: string;
  label: string;
}

export interface UnixPolicy {
  allow: UnixAllow[];
  abstractAllow: string[];
}

/** The labels of the human's own additions (policy.yaml, the env): on macOS
 *  they win over the host-service refusals (seatbelt-profile.ts). */
export const UNIX_EXTRA_LABELS: readonly string[] = ["policy.yaml unix_sockets", "MANDU_UNIX_ALLOW"];

const GPG_SOCKETS = ["S.gpg-agent", "S.gpg-agent.ssh", "S.gpg-agent.extra", "S.gpg-agent.browser", "S.keyboxd"];

export interface UnixPolicyOpts {
  arbiterSock?: string;
  scopeRunDir?: string;
  /** policy.yaml `unix_sockets.allow`, as written. */
  extra?: readonly string[];
  /** "darwin": the macOS list (above). Default: the Linux guard's. */
  platform?: "linux" | "darwin" | "win32";
  /** macOS: Mandu's runtime directory (arbiter-sock.ts `runtimeBase`), whose
   *  `instances/` holds every arbiter's data socket. */
  runtimeBase?: string;
  /** macOS: the workspace, whose sockets the agent's programs open. */
  cwd?: string;
  /** The human-plane directories (human-plane.ts `humanPlaneDirs`): no
   *  entry may equal, contain or lie in one. */
  humanDirs?: readonly string[];
  /** Told of each entry dropped for touching the human plane. */
  onRefused?: (path: string, label: string) => void;
}

/** The Unix socket allow-list for a launch (module header). */
export function unixPolicy(env: Record<string, string | undefined>, opts: UnixPolicyOpts = {}): UnixPolicy {
  if (opts.platform === "darwin") return darwinUnixPolicy(env, opts);
  const allow: UnixAllow[] = [];
  const abstractAllow: string[] = ["/tmp/.X11-unix/X*"];
  const humanDirs = opts.humanDirs ?? [];
  const add = (path: string | undefined, label: string) => {
    if (!path || !path.startsWith("/") || allow.some((a) => a.path === path)) return;
    if (touchesHumanPlane(path, humanDirs)) {
      opts.onRefused?.(path, label);
      return;
    }
    allow.push({ path, label });
  };
  /** One extra: a path (`~` expanded), or `@name` (abstract). `@` alone and
   *  `@*` would name every abstract socket and are ignored (the arbiter's
   *  validator refuses them in policy.yaml). */
  const addExtra = (raw: string, label: string) => {
    const v = raw.trim();
    if (v.startsWith("@")) {
      const name = v.slice(1);
      if (name !== "" && name !== "*" && !abstractAllow.includes(name)) abstractAllow.push(name);
      return;
    }
    const p = expandHome(v, env["HOME"]);
    if (p && p !== "/") add(p.length > 1 ? p.replace(/\/+$/, "") : p, label);
  };
  add(opts.arbiterSock, "Mandu's arbiter");
  add(opts.scopeRunDir, "this session's Mandu sockets");
  for (const p of ["/run/nscd/socket", "/var/run/nscd/socket"]) add(p, "name service (nscd)");
  add("/var/lib/sss/pipes/nss", "name service (sssd)");
  add("/run/systemd/resolve/io.systemd.Resolve", "name service (systemd-resolved)");
  add("/run/systemd/userdb", "name service (systemd userdb)");
  add("/run/avahi-daemon/socket", "name service (avahi)");
  add("/run/systemd/journal", "logging (journald)");
  add("/dev/log", "logging (syslog)");
  add(env["SSH_AUTH_SOCK"], "ssh-agent");
  const runtime = env["XDG_RUNTIME_DIR"];
  const home = env["HOME"];
  for (const dir of [runtime ? join(runtime, "gnupg") : undefined, home ? join(home, ".gnupg") : undefined]) {
    if (dir) for (const s of GPG_SOCKETS) add(join(dir, s), "gpg-agent");
  }
  const wayland = env["WAYLAND_DISPLAY"];
  if (wayland) add(wayland.startsWith("/") ? wayland : runtime ? join(runtime, wayland) : undefined, "Wayland display");
  add("/tmp/.X11-unix", "X11 display");
  for (const extra of opts.extra ?? []) addExtra(extra, "policy.yaml unix_sockets");
  for (const extra of (env["MANDU_UNIX_ALLOW"] ?? "").split(":")) if (extra.trim()) addExtra(extra, "MANDU_UNIX_ALLOW");
  return { allow, abstractAllow };
}

/** The macOS list (module header). Pure. */
function darwinUnixPolicy(env: Record<string, string | undefined>, opts: UnixPolicyOpts): UnixPolicy {
  const allow: UnixAllow[] = [];
  const humanDirs = opts.humanDirs ?? [];
  const add = (path: string | undefined, label: string) => {
    if (!path || !path.startsWith("/")) return;
    const p = path.length > 1 ? path.replace(/\/+$/, "") : path;
    if (p === "/" || allow.some((a) => a.path === p)) return;
    if (touchesHumanPlane(p, humanDirs)) {
      opts.onRefused?.(p, label);
      return;
    }
    allow.push({ path: p, label });
  };
  const home = env["HOME"];
  // The arbiter instances, not the whole runtime directory: `current` moves
  // on promotion (Seatbelt matches the resolved path, instances/<id>/), and
  // the directory's other entries (the human plane, other sessions' scope
  // dirs) are none of the agent's business.
  if (opts.runtimeBase) add(join(opts.runtimeBase, "instances"), "Mandu's arbiter instances");
  add(opts.arbiterSock, "Mandu's arbiter");
  add(opts.scopeRunDir, "this session's Mandu sockets");
  add("/private/var/run/mDNSResponder", "name service (mDNSResponder)");
  add("/private/var/run/syslog", "logging (syslog)");
  add(env["SSH_AUTH_SOCK"], "ssh-agent");
  if (home) for (const s of GPG_SOCKETS) add(join(home, ".gnupg", s), "gpg-agent");
  add("/private/tmp/.X11-unix", "X11 display");
  // XQuartz names its display socket in DISPLAY (a launchd-made path).
  const display = env["DISPLAY"];
  if (display && display.startsWith("/")) add(display, "X11 display");
  add(opts.cwd, "the workspace (sockets the agent's programs open there)");
  for (const [list, label] of [[opts.extra ?? [], "policy.yaml unix_sockets"], [(env["MANDU_UNIX_ALLOW"] ?? "").split(":"), "MANDU_UNIX_ALLOW"]] as const) {
    for (const raw of list) {
      const v = raw.trim();
      if (v === "" || v.startsWith("@")) continue; // macOS has no abstract sockets
      const p = expandHome(v, home);
      if (p && p !== "/") add(p, label);
    }
  }
  return { allow, abstractAllow: [] };
}

/** HOME-relative directories of macOS host services that run code on
 *  request over a Unix socket (`darwinUnixRefuse`): docker and its kin, then
 *  the terminals and editors whose control socket types into a window or
 *  evaluates code outside the profile. */
export const DARWIN_REFUSE_HOME_DIRS: readonly string[] = [
  // Docker Desktop, colima, OrbStack, Rancher Desktop, lima, podman.
  ".docker", ".colima", ".orbstack", ".rd", ".lima", join(".local", "share", "containers"),
  // WezTerm's GUI and mux sockets (`wezterm cli send-text`, `spawn`).
  join(".local", "share", "wezterm"),
  // iTerm2's Python API socket (`…/iTerm2/private/socket`): sends text to a
  // session and runs scripts.
  join("Library", "Application Support", "iTerm2"),
  // An Emacs server whose socket dir is set under ~/.emacs.d (`emacsclient
  // --eval`); the default dir is $TMPDIR/emacs<uid> (below).
  join(".emacs.d", "server"),
];

/** macOS host services that run code on request and listen on a Unix
 *  socket: refused even inside an allowed directory (the workspace, a HOME
 *  launch), unless the human lists them (policy.yaml `unix_sockets.allow`,
 *  MANDU_UNIX_ALLOW). Docker and its kin (Docker Desktop, colima, OrbStack,
 *  Rancher Desktop, lima, podman), a host tmux server, and the control
 *  sockets of WezTerm, iTerm2, kitty (when `KITTY_LISTEN_ON` names one) and
 *  an Emacs server. A list of what is known, not a proof: a launch from HOME
 *  (or a folder above many projects) admits every other socket under it
 *  (docs/guarantees.md §3). Pure. */
export function darwinUnixRefuse(env: Record<string, string | undefined>, uid?: number): string[] {
  const out = ["/private/var/run/docker.sock", "/var/run/docker.sock"];
  const home = env["HOME"];
  if (home) for (const d of DARWIN_REFUSE_HOME_DIRS) out.push(join(home, d));
  if (uid !== undefined) out.push(`/private/tmp/tmux-${uid}`);
  const tmux = env["TMUX"];
  if (tmux && tmux.startsWith("/")) out.push(dirname(tmux.split(",")[0]!));
  // The socket a running WezTerm names for its panes.
  const wez = env["WEZTERM_UNIX_SOCKET"];
  if (wez && wez.startsWith("/")) out.push(dirname(wez));
  // kitty's remote control (`kitty @ send-text`, `launch`) when it listens on
  // a Unix socket: `unix:/path` (an `@name` is abstract, which macOS lacks).
  const kitty = env["KITTY_LISTEN_ON"];
  if (kitty && kitty.startsWith("unix:/")) out.push(kitty.slice("unix:".length));
  // Emacs's default server socket dir: $XDG_RUNTIME_DIR/emacs when that is
  // set, else $TMPDIR/emacs<uid>, else /tmp's.
  const xdg = env["XDG_RUNTIME_DIR"];
  if (xdg && xdg.startsWith("/")) out.push(join(xdg, "emacs"));
  if (uid !== undefined) {
    const tmpdir = env["TMPDIR"];
    if (tmpdir && tmpdir.startsWith("/")) out.push(join(tmpdir, `emacs${uid}`));
    out.push(`/private/tmp/emacs${uid}`);
  }
  return [...new Set(out)];
}

/** Hand the allow-list to the guard (only with the confidentiality axis on and
 *  a running guard; the caller decides both). */
export function applyUnixPolicy(policy: UnixPolicy, mutEnv: Record<string, string>, deps: GuardPolicyDeps & { log: (m: string) => void }): void {
  mergeGuardPolicy(mutEnv, deps, { unixPolicy: policy });
  deps.log(
    `mandu: unix sockets — the agent's programs reach only Mandu, name service, logging, the ssh and gpg agents and the display, ` +
      "plus sockets they open themselves (host services such as systemd --user, D-Bus and docker are refused)",
  );
}
