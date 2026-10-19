/**
 * unix-policy.test — the Unix socket allow-list the launcher hands the guard
 * (sandbox-security-review-2026-09-28 finding 1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyUnixPolicy, darwinUnixRefuse, unixPolicy, UNIX_EXTRA_LABELS } from "../../src/unix-policy.js";

const ENV = { HOME: "/h", XDG_RUNTIME_DIR: "/run/user/7", SSH_AUTH_SOCK: "/tmp/ssh-x/agent.1", WAYLAND_DISPLAY: "wayland-0" };

test("the list: Mandu, name service, logging, the ssh and gpg agents, the displays; never the host services that run code", () => {
  const p = unixPolicy(ENV, { arbiterSock: "/run/user/7/mandu/current/arbiter.sock", scopeRunDir: "/run/user/7/mandu/s1" });
  const paths = p.allow.map((a) => a.path);
  for (const want of [
    "/run/user/7/mandu/current/arbiter.sock", "/run/user/7/mandu/s1",
    "/run/nscd/socket", "/var/lib/sss/pipes/nss", "/run/systemd/resolve/io.systemd.Resolve", "/run/systemd/userdb",
    "/run/systemd/journal", "/dev/log",
    "/tmp/ssh-x/agent.1",
    "/run/user/7/gnupg/S.gpg-agent", "/h/.gnupg/S.gpg-agent.ssh",
    "/run/user/7/wayland-0", "/tmp/.X11-unix",
  ]) assert.ok(paths.includes(want), want);
  for (const never of [
    "/run/user/7/bus", "/run/user/7/systemd", "/run/user/7/systemd/private", "/var/run/docker.sock", "/run/docker.sock",
    "/run/user/7/gnupg/S.dirmngr", "/run/dbus/system_bus_socket", "/run/user/7/pulse", "/run/user/7",
  ]) assert.ok(!paths.some((p2) => p2 === never || never.startsWith(`${p2}/`)), `${never} must not be reachable`);
  assert.deepEqual(p.abstractAllow, ["/tmp/.X11-unix/X*"]);
});

test("absent variables add nothing; relative spellings are ignored; MANDU_UNIX_ALLOW adds extras", () => {
  const bare = unixPolicy({}, {}).allow.map((a) => a.path);
  assert.ok(!bare.some((p) => p.includes("undefined")));
  assert.ok(!bare.some((p) => p.includes("gnupg")), "no HOME, no runtime dir: no gpg entries");
  const extra = unixPolicy({ MANDU_UNIX_ALLOW: "/srv/app.sock: relative.sock :/run/pg" }, {}).allow;
  assert.ok(extra.some((a) => a.path === "/srv/app.sock" && a.label === "MANDU_UNIX_ALLOW"));
  assert.ok(extra.some((a) => a.path === "/run/pg"));
  assert.ok(!extra.some((a) => a.path === "relative.sock"));
  // An absolute WAYLAND_DISPLAY is taken as is.
  assert.ok(unixPolicy({ WAYLAND_DISPLAY: "/tmp/w.sock" }, {}).allow.some((a) => a.path === "/tmp/w.sock"));
});

test("applyUnixPolicy writes the list into the guard's policy file", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-unixpol-"));
  try {
    const env: Record<string, string> = {};
    const logs: string[] = [];
    applyUnixPolicy(unixPolicy(ENV), env, { log: (m) => logs.push(m), scopeRunDir: dir, agentExe: "/bin/claude", session: "s" });
    const f = JSON.parse(readFileSync(env["MANDU_NET_GUARD_SECRETS"]!, "utf8"));
    assert.ok(Array.isArray(f.unixPolicy.allow) && f.unixPolicy.allow.length > 5);
    assert.deepEqual(f.secrets, []);
    assert.match(logs.join("\n"), /unix sockets/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("macOS (platform darwin): the arbiter instances, mDNSResponder and syslog, the ssh and gpg agents, X11, the workspace and the extras; no Linux paths, no abstract names", () => {
  const env = { HOME: "/Users/u", SSH_AUTH_SOCK: "/private/tmp/com.apple.launchd.x/Listeners", DISPLAY: "/private/tmp/com.apple.launchd.y/org.xquartz:0", MANDU_UNIX_ALLOW: "~/own.sock:@abstract" };
  const p = unixPolicy(env, { platform: "darwin", arbiterSock: "/rt/current/arbiter.sock", scopeRunDir: "/rt/sid", runtimeBase: "/rt", cwd: "/Users/u/proj", extra: ["~/.docker/run/docker.sock"] });
  assert.deepEqual(p.abstractAllow, [], "macOS has no abstract sockets");
  const byPath = new Map(p.allow.map((a) => [a.path, a.label]));
  assert.equal(byPath.get("/rt/instances"), "Mandu's arbiter instances", "every instance: promotion moves `current`");
  assert.ok(!byPath.has("/rt"), "never the whole runtime dir: it holds the human plane and other sessions' dirs");
  for (const want of [
    "/rt/current/arbiter.sock", "/rt/sid", "/private/var/run/mDNSResponder", "/private/var/run/syslog",
    "/private/tmp/com.apple.launchd.x/Listeners", "/Users/u/.gnupg/S.gpg-agent", "/private/tmp/.X11-unix",
    "/private/tmp/com.apple.launchd.y/org.xquartz:0", "/Users/u/proj",
  ]) assert.ok(byPath.has(want), want);
  assert.equal(byPath.get("/Users/u/.docker/run/docker.sock"), "policy.yaml unix_sockets");
  assert.equal(byPath.get("/Users/u/own.sock"), "MANDU_UNIX_ALLOW");
  assert.ok(!p.allow.some((a) => a.path.startsWith("/run/") || a.path === "/dev/log"), "no Linux paths");
  for (const l of UNIX_EXTRA_LABELS) assert.ok([...byPath.values()].includes(l), l);
});

test("macOS host services refused even inside an allowed directory: docker and its kin, a host tmux server", () => {
  const r = darwinUnixRefuse({ HOME: "/Users/u", TMUX: "/private/tmp/tmux-501/default,123,0" }, 501);
  for (const want of [
    "/private/var/run/docker.sock", "/var/run/docker.sock", "/Users/u/.docker", "/Users/u/.colima", "/Users/u/.orbstack",
    "/Users/u/.rd", "/Users/u/.lima", "/Users/u/.local/share/containers", "/private/tmp/tmux-501",
  ]) assert.ok(r.includes(want), want);
  assert.deepEqual(darwinUnixRefuse({}), ["/private/var/run/docker.sock", "/var/run/docker.sock"]);
});

test("macOS: the control sockets of terminals and editors under HOME are refused too (a launch from HOME admits every other socket under it)", () => {
  // Review 2026-09-29 (seatbelt-7): the workspace allow is a subpath, so a
  // launch from HOME reaches every socket under HOME but these.
  const r = darwinUnixRefuse({ HOME: "/Users/u", TMPDIR: "/var/folders/xy/T/" }, 501);
  for (const want of [
    "/Users/u/.local/share/wezterm", // WezTerm: `wezterm cli send-text` types into a pane
    "/Users/u/Library/Application Support/iTerm2", // iTerm2's Python API socket (…/private/socket)
    "/Users/u/.emacs.d/server", // an Emacs server whose socket dir is set there
    "/var/folders/xy/T/emacs501", // Emacs's default socket dir: $TMPDIR/emacs<uid>
    "/private/tmp/emacs501", // …or /tmp's when TMPDIR is unset
  ]) assert.ok(r.includes(want), want);
  // The sockets a running terminal names in the environment.
  const named = darwinUnixRefuse({
    HOME: "/Users/u",
    WEZTERM_UNIX_SOCKET: "/Users/u/.local/share/wezterm/gui-sock-4242",
    KITTY_LISTEN_ON: "unix:/tmp/kitty-4242",
    XDG_RUNTIME_DIR: "/Users/u/.run",
  });
  assert.ok(named.includes("/tmp/kitty-4242"), "kitty's remote control socket (KITTY_LISTEN_ON)");
  assert.ok(named.includes("/Users/u/.run/emacs"), "Emacs under XDG_RUNTIME_DIR");
  assert.ok(named.includes("/Users/u/.local/share/wezterm"));
  // An abstract or TCP kitty socket and a relative value name nothing.
  const none = darwinUnixRefuse({ KITTY_LISTEN_ON: "tcp:localhost:5000", WEZTERM_UNIX_SOCKET: "rel/sock", TMPDIR: "rel" });
  assert.deepEqual(none, ["/private/var/run/docker.sock", "/var/run/docker.sock"]);
  // No duplicates.
  assert.equal(new Set(r).size, r.length);
});

test("macOS: an entry that equals, contains or lies in a human-plane dir is dropped and reported, as on Linux", () => {
  const refused: string[] = [];
  const p = unixPolicy({ HOME: "/Users/u", MANDU_UNIX_ALLOW: "/rt/human/x.sock:/rt:/elsewhere.sock" }, {
    platform: "darwin", arbiterSock: "/rt/current/arbiter.sock", scopeRunDir: "/rt/sid", runtimeBase: "/rt", cwd: "/Users/u/proj",
    humanDirs: ["/rt/human"], onRefused: (path, label) => refused.push(`${path} (${label})`),
  });
  const paths = p.allow.map((a) => a.path);
  assert.ok(paths.includes("/rt/instances") && paths.includes("/elsewhere.sock"), paths.join(" "));
  assert.ok(!paths.includes("/rt/human/x.sock") && !paths.includes("/rt"), paths.join(" "));
  assert.deepEqual(refused, ["/rt/human/x.sock (MANDU_UNIX_ALLOW)", "/rt (MANDU_UNIX_ALLOW)"]);
});
