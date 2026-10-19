/**
 * seatbelt-profile.test — the ONE whole-agent Seatbelt profile of a macOS
 * launch (seatbelt-profile.ts; confidentiality.md §7.3), pinned per component
 * and per flag. Pure: no sandbox-exec here (the darwin live test,
 * test/darwin/seatbelt-live.test.ts, runs the rendered rules for real).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ancestorsOf,
  canonicalPath,
  HOST_SERVICE_PROGRAMS,
  normalizeAbs,
  renderSeatbeltProfile,
  SANDBOX_EXEC,
  sandboxExecAvailable,
  sbplQuote,
  seatbeltWrapArgv,
  seatbeltWrapArgvInline,
} from "../../src/seatbelt-profile.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // no arbiter here; the profile is the secrets-mode enactment on macOS

/** A macOS-shaped resolver: /tmp and /var are links into /private, and a
 *  path resolves only when it "exists" (listed, or under a listed dir). */
function macRealpath(existing: string[]): (p: string) => string | null {
  return (p) => {
    const mapped = p === "/tmp" || p.startsWith("/tmp/") ? `/private${p}` : p === "/var" || p.startsWith("/var/") ? `/private${p}` : p;
    if (mapped === "/" || existing.some((e) => mapped === e || e.startsWith(`${mapped}/`))) return mapped;
    return null;
  };
}

test("nothing to say ⇒ null (never wrap for nothing); the wrap argv", () => {
  assert.equal(renderSeatbeltProfile({}), null);
  assert.equal(renderSeatbeltProfile({ secrets: [], writeProtect: [], net: null, unix: null, hostServices: false }), null);
  assert.deepEqual(seatbeltWrapArgv("/p/agent.sb"), ["/usr/bin/sandbox-exec", "-f", "/p/agent.sb"]);
  // The launch passes the TEXT, so nothing is read back by path (seatbelt-setup.ts).
  assert.deepEqual(seatbeltWrapArgvInline("(version 1)\n(allow default)\n"), ["/usr/bin/sandbox-exec", "-p", "(version 1)\n(allow default)\n"]);
});

test("sandbox-exec is named and checked by absolute path, never looked up on PATH (review 2026-09-29, docs-tests-11)", () => {
  assert.equal(SANDBOX_EXEC, "/usr/bin/sandbox-exec");
  assert.equal(seatbeltWrapArgv("/p.sb")[0], SANDBOX_EXEC);
  assert.equal(seatbeltWrapArgvInline("(version 1)")[0], SANDBOX_EXEC);
  // An injected command check is asked for that path and nothing else.
  const asked: string[] = [];
  assert.equal(sandboxExecAvailable((p) => { asked.push(p); return p === "sandbox-exec"; }), false, "a bare name on PATH does not count");
  assert.deepEqual(asked, [SANDBOX_EXEC]);
  assert.equal(sandboxExecAvailable((p) => p === SANDBOX_EXEC), true);
});

test("paths: normalized, relative and root refused; canonical spelling of a not-yet-existing file", () => {
  assert.equal(normalizeAbs("/a//b/./c/../d/"), "/a/b/d");
  assert.equal(normalizeAbs("rel/x"), null);
  const real = macRealpath(["/private/tmp/h"]);
  assert.equal(canonicalPath("/tmp/h/.zshrc", real), "/private/tmp/h/.zshrc", "the file need not exist: the longest existing prefix resolves");
  assert.equal(canonicalPath("/tmp/h", real), "/private/tmp/h");
  assert.equal(canonicalPath("/Users/u/x", () => null), "/Users/u/x", "nothing resolves ⇒ the path as given");
  assert.deepEqual(ancestorsOf("/Users/u/.aws/credentials"), ["/Users/u/.aws", "/Users/u", "/Users"]);
  assert.deepEqual(ancestorsOf("/x"), []);
  assert.equal(sbplQuote('/a/we"ird\\x'), '"/a/we\\"ird\\\\x"');
});

test("1. credential files: read AND write denied in both spellings; every folder above them unrenameable (the rename bypass)", () => {
  const prof = renderSeatbeltProfile({
    secrets: ["/tmp/h/.aws/credentials"],
    canonical: (p) => canonicalPath(p, macRealpath(["/private/tmp/h/.aws/credentials"])),
  })!;
  const allowAt = prof.indexOf("(allow default)");
  const denyAt = prof.indexOf("(deny file-read* file-write*");
  assert.ok(allowAt >= 0 && denyAt > allowAt, "a deny placed BEFORE the allow would be overridden (SBPL is last-match-wins)");
  assert.ok(prof.includes('(deny file-read* file-write*\n  (literal "/private/tmp/h/.aws/credentials")\n  (literal "/tmp/h/.aws/credentials"))'), prof);
  // The file's own rename is covered by file-write*; a PARENT's needs its own
  // literal file-write-unlink (verified: mv ~/.aws ~/.a2 && cat ~/.a2/credentials).
  for (const d of ["/private/tmp/h/.aws", "/private/tmp/h", "/private/tmp", "/private", "/tmp/h/.aws", "/tmp/h", "/tmp"]) {
    assert.ok(prof.includes(`  (literal "${d}")`), `ancestor ${d}`);
  }
  assert.ok(/\(deny file-write-unlink\n/.test(prof));
  assert.ok(!prof.includes('(literal "/")'), "the root is never listed");
  assert.ok(!prof.includes("subpath"), "literal only: the folders' own contents stay writable");
});

test("determinism: input order and duplicates do not change the profile", () => {
  const a = renderSeatbeltProfile({ secrets: ["/h/.ssh/id_rsa", "/h/.aws/credentials", "/h/.aws/credentials"], writeProtect: ["/h/.zshrc", "/h/.bashrc"] });
  const b = renderSeatbeltProfile({ secrets: ["/h/.aws/credentials", "/h/.ssh/id_rsa"], writeProtect: ["/h/.bashrc", "/h/.zshrc", "/h/.zshrc"] });
  assert.equal(a, b);
});

test("2. Mandu's state: subpaths unreadable+unwritable, files literal, config write-only; no ancestor rule inside a sealed dir", () => {
  const prof = renderSeatbeltProfile({
    stateDirs: ["/h/.mandu", "/h/.local/state/mandu"],
    stateFiles: ["/db/sym.db"],
    stateWriteOnly: ["/h/.config/mandu"],
  })!;
  assert.ok(prof.includes('(deny file-read* file-write*\n  (subpath "/h/.local/state/mandu")\n  (subpath "/h/.mandu")\n  (literal "/db/sym.db"))'), prof);
  assert.ok(prof.includes('(deny file-write*\n  (subpath "/h/.config/mandu"))'), prof);
  assert.ok(prof.includes('  (literal "/h/.local/state")'), "a rename of ~/.local/state would move the event store out");
  assert.ok(!prof.includes('(literal "/h/.mandu")'), "the sealed dir itself is covered by its subpath rule");
});

test("3. write-protect: every entry refused as a subpath; a link entry is literal with only its parent resolved (never /tmp → all of /private/tmp)", () => {
  const prof = renderSeatbeltProfile({
    writeProtect: ["/tmp/h/.zshrc", "/tmp/h/Library/LaunchAgents"],
    writeProtectLinks: ["/tmp", "/tmp/rt/current", "/tmp/rt/current/arbiter.sock"],
    canonical: (p) => (p === "/tmp/rt/current" ? "/private/tmp/rt/instances/i1" : canonicalPath(p, macRealpath(["/private/tmp/h", "/private/tmp/rt/instances/i1/arbiter.sock"]))),
  })!;
  for (const want of [
    '(subpath "/private/tmp/h/.zshrc")', '(subpath "/tmp/h/.zshrc")',
    '(subpath "/private/tmp/h/Library/LaunchAgents")', '(subpath "/tmp/h/Library/LaunchAgents")',
    '(literal "/tmp")', '(literal "/private/tmp/rt/current")', '(literal "/tmp/rt/current")',
    '(literal "/private/tmp/rt/instances/i1/arbiter.sock")', '(literal "/tmp/rt/current/arbiter.sock")',
  ]) assert.ok(prof.includes(want), want);
  assert.ok(!prof.includes('(subpath "/private/tmp")') && !prof.includes('(subpath "/tmp")'), "a link entry never seals its target directory");
  assert.ok(prof.includes('  (literal "/private/tmp/h/Library")'), "renaming ~/Library would move LaunchAgents out from under the rule");
});

test("2. the home's carve-outs: allowed back (read + write) right after the state denies; never without a state deny", () => {
  const av = "/h/.mandu/state/workspaces/w/agentview";
  const prof = renderSeatbeltProfile({ stateDirs: ["/h/.mandu"], stateCarveOuts: [av, av] })!;
  const deny = prof.indexOf('(deny file-read* file-write*\n  (subpath "/h/.mandu"))');
  const allow = prof.indexOf(`(allow file-read* file-write*\n  (subpath "${av}"))`);
  assert.ok(deny >= 0 && allow > deny, prof);
  assert.equal(prof.split(`"${av}"`).length - 1, 1, "deduplicated");
  assert.equal(renderSeatbeltProfile({ stateCarveOuts: [av] }), null, "a carve-out with nothing to carve from makes no profile");
  assert.ok(!renderSeatbeltProfile({ secrets: ["/h/.env"], stateCarveOuts: [av] })!.includes("(allow file-read* file-write*"));
});

test("3. write-protect exceptions: a carve-out strictly below a protected entry stays writable, allowed after the deny; one elsewhere is dropped", () => {
  const av = "/h/.mandu/state/workspaces/w/agentview";
  const prof = renderSeatbeltProfile({ writeProtect: ["/h/.mandu", "/h/.zshrc"], writeProtectExcept: [av, "/h/elsewhere", "/h/.mandu"] })!;
  const deny = prof.indexOf("(deny file-write*\n");
  const allow = prof.indexOf(`(allow file-write*\n  (subpath "${av}"))`);
  assert.ok(deny >= 0 && allow > deny, prof);
  assert.ok(!prof.includes('(subpath "/h/elsewhere")'), "not below a protected entry: nothing to except");
  assert.equal(prof.split('(subpath "/h/.mandu")').length - 1, 1, "the entry itself is never excepted");
});

test("the human plane: no connect, no read or write under each dir (both spellings), after every file and socket allow, before the TCP rules; no rename above it", () => {
  const prof = renderSeatbeltProfile({
    stateDirs: ["/h/.mandu"],
    stateCarveOuts: ["/h/.mandu/state/workspaces/w/agentview"],
    unix: { allow: ["/tmp/rt/instances", "/tmp/rt"], refuse: [], extra: ["/tmp/rt/human"] },
    net: { connect: [{ host: "localhost", port: 8788 }], bind: [] },
    humanDirs: ["/tmp/rt/human"],
    canonical: (p) => canonicalPath(p, macRealpath(["/private/tmp/rt/human"])),
  })!;
  const lines = prof.split("\n");
  const at = lines.indexOf(";; The arbiter's human plane (arbiter-human-plane.md §5): no connect, no read or write.");
  assert.ok(at > 0, prof);
  assert.deepEqual(lines.slice(at + 1, at + 7), [
    "(deny file-read* file-write*",
    '  (subpath "/private/tmp/rt/human")',
    '  (subpath "/tmp/rt/human"))',
    "(deny network-outbound",
    '  (remote unix-socket (subpath "/private/tmp/rt/human"))',
    '  (remote unix-socket (subpath "/tmp/rt/human")))',
  ]);
  const lastUnixAllow = lines.map((l, i) => (l.includes("(remote unix-socket") && lines.slice(0, i).reverse().find((h) => !h.startsWith("  "))?.startsWith("(allow") ? i : -1)).reduce((a, b) => Math.max(a, b), -1);
  assert.ok(lastUnixAllow > 0 && lastUnixAllow < at, "after the socket allow list and the extras (last match wins)");
  assert.ok(lines.indexOf("(allow file-read* file-write*") < at, "after the carve-outs");
  assert.ok(lines.indexOf("(deny network-outbound (remote tcp))") > at, "before the TCP rules (the unix/TCP ordering quirk)");
  assert.ok(!lines.some((l, i) => i > at && (l.startsWith("(allow file") || (l.startsWith("(allow network-outbound") && lines[i + 1]?.includes("unix-socket")))), "no file or socket allow after it");
  // Renaming the runtime base would move the socket out from under the rule
  // (verified on macOS 26.5, 2026-09-30): the dirs above it are unrenameable.
  assert.ok(prof.includes('  (literal "/private/tmp/rt")') && prof.includes('  (literal "/tmp/rt")'), prof);
  // Alone it still makes a profile: the wall never depends on another component.
  assert.ok(renderSeatbeltProfile({ humanDirs: ["/rt/human"] })!.includes('(remote unix-socket (subpath "/rt/human"))'));
});

test("the runtime registries: one write deny (subpath dirs, literal names, prefix temp names; both spellings, a name's parent only), after every file allow; the folders above unrenameable", () => {
  const runtime = {
    dirs: ["/tmp/rt/instances", "/tmp/rt/dashboards", "/tmp/rt/instances"],
    names: ["/tmp/rt/current", "/tmp/rt/arbiter.sock", "/tmp/rt/dashboard.log"],
    prefixes: ["/tmp/rt/.current.tmp-", "/tmp/rt/dashboard-"],
  };
  const canonical = (p: string): string =>
    p === "/tmp/rt/current" ? "/private/tmp/rt/instances/i1" : canonicalPath(p, macRealpath(["/private/tmp/rt/instances/i1", "/private/tmp/rt/dashboards"]));
  const prof = renderSeatbeltProfile({
    stateDirs: ["/h/.mandu"],
    stateCarveOuts: ["/h/.mandu/state/workspaces/w/agentview"],
    writeProtect: ["/h/.mandu"],
    writeProtectLinks: ["/tmp/rt/instances/i1/arbiter.sock"],
    writeProtectExcept: ["/h/.mandu/state/workspaces/w/agentview"],
    runtime,
    canonical,
  })!;
  const lines = prof.split("\n");
  const at = lines.indexOf(";; Mandu's runtime registries (runtime-instances.md §2): never written from here; sockets stay reachable.");
  assert.ok(at > 0, prof);
  assert.deepEqual(lines.slice(at + 1, at + 16), [
    "(deny file-write*",
    '  (subpath "/private/tmp/rt/dashboards")',
    '  (subpath "/private/tmp/rt/instances")',
    '  (subpath "/tmp/rt/dashboards")',
    '  (subpath "/tmp/rt/instances")',
    '  (literal "/private/tmp/rt/arbiter.sock")',
    '  (literal "/private/tmp/rt/current")',
    '  (literal "/private/tmp/rt/dashboard.log")',
    '  (literal "/tmp/rt/arbiter.sock")',
    '  (literal "/tmp/rt/current")',
    '  (literal "/tmp/rt/dashboard.log")',
    '  (prefix "/private/tmp/rt/.current.tmp-")',
    '  (prefix "/private/tmp/rt/dashboard-")',
    '  (prefix "/tmp/rt/.current.tmp-")',
    '  (prefix "/tmp/rt/dashboard-"))',
  ]);
  assert.ok(!prof.includes('"/private/tmp/rt/instances/i1"'), "`current` is the link itself, never its target");
  const lastFileAllow = lines.reduce((a, l, i) => (l.startsWith("(allow file") ? i : a), -1);
  assert.ok(lastFileAllow > 0 && lastFileAllow < at, "after the carve-outs and the write-protect exceptions (last match wins)");
  assert.ok(!prof.includes('(subpath "/tmp/rt")') && !prof.includes('(subpath "/private/tmp/rt")'), "the base itself stays writable");
  for (const d of ["/private/tmp/rt", "/tmp/rt", "/private/tmp", "/tmp"]) assert.ok(prof.includes(`  (literal "${d}")`), `no rename above: ${d}`);
  for (const d of ["/tmp/rt/instances", "/tmp/rt/instances/i1", "/private/tmp/rt/instances", "/private/tmp/rt/instances/i1"]) {
    assert.ok(!prof.includes(`  (literal "${d}")`), `inside a denied subpath, no separate rename rule: ${d}`);
  }
  // Alone it still makes a profile; empty, it adds nothing.
  assert.ok(renderSeatbeltProfile({ runtime: { dirs: ["/rt/instances"], names: [], prefixes: [] } })!.includes('(subpath "/rt/instances")'));
  assert.equal(renderSeatbeltProfile({ runtime: { dirs: [], names: [], prefixes: [] } }), null);
  assert.equal(renderSeatbeltProfile({ runtime: null }), null);
});

test("policy.yaml protect: no delete or rename under it (file-write-unlink subpath), and none of the folders above", () => {
  const prof = renderSeatbeltProfile({ noDelete: ["/h/work/keep"] })!;
  assert.ok(prof.includes('(deny file-write-unlink\n  (subpath "/h/work/keep"))'), prof);
  assert.ok(prof.includes('  (literal "/h/work")'));
});

test("4. network: TCP connect only to the listed ports, bind only to the bind ports; UDP binds left alone", () => {
  const prof = renderSeatbeltProfile({
    net: { connect: [{ host: "*", port: 443 }, { host: "localhost", port: 40001 }, { host: "*", port: 22 }, { host: "*", port: 443 }, { host: "*", port: 0 }, { host: "*", port: 70000 }], bind: [3000] },
  })!;
  assert.ok(prof.includes(
    "(deny network-outbound (remote tcp))\n" +
    "(allow network-outbound\n" +
    '  (remote tcp "*:22")\n' +
    '  (remote tcp "*:443")\n' +
    '  (remote tcp "*:3000")\n' +
    '  (remote tcp "localhost:40001"))\n' +
    "(deny network-bind (local ip))\n" +
    "(allow network-bind (local udp))\n" +
    "(allow network-bind\n" +
    '  (local ip "*:3000"))\n',
  ), prof);
  assert.ok(!prof.includes(":0\"") && !prof.includes("70000"), "an invalid port is dropped");
  assert.ok(!prof.includes("unix-socket"), "the network component leaves Unix sockets alone");
});

test("4. network: an empty set is a whole-agent TCP deny-all (an explicit --landlock-net= with no port)", () => {
  const prof = renderSeatbeltProfile({ net: { connect: [], bind: [] } })!;
  assert.ok(prof.includes("(deny network-outbound (remote tcp))\n(deny network-bind (local ip))\n(allow network-bind (local udp))\n"), prof);
  assert.ok(!prof.includes("(allow network-outbound"));
});

test("5. Unix sockets: deny all, allow the list, refuse host services over it, the human's extras over that", () => {
  const prof = renderSeatbeltProfile({
    unix: { allow: ["/tmp/rt", "/Users/u"], refuse: ["/Users/u/.docker"], extra: ["/Users/u/.docker/run/docker.sock"] },
    canonical: (p) => canonicalPath(p, macRealpath(["/private/tmp/rt", "/Users/u/.docker/run/docker.sock"])),
  })!;
  const deny = prof.indexOf("(deny network-outbound (remote unix-socket))");
  const allow = prof.indexOf('(remote unix-socket (subpath "/private/tmp/rt"))');
  const refuse = prof.indexOf('(remote unix-socket (subpath "/Users/u/.docker"))');
  const extra = prof.indexOf('(remote unix-socket (subpath "/Users/u/.docker/run/docker.sock"))');
  assert.ok(deny >= 0 && deny < allow && allow < refuse && refuse < extra, `order deny < allow < refuse < extra:\n${prof}`);
  assert.ok(prof.includes('(remote unix-socket (subpath "/tmp/rt"))'), "both spellings");
});

test("the Unix-socket rules precede the TCP rules (after them the bare unix-socket deny misfires on some TCP ports, macOS 26.5)", () => {
  const prof = renderSeatbeltProfile({ net: { connect: [{ host: "localhost", port: 50011 }], bind: [] }, unix: { allow: ["/rt"], refuse: [], extra: ["/x"] } })!;
  const lastUnix = prof.lastIndexOf("(remote unix-socket");
  const firstTcp = prof.indexOf("(deny network-outbound (remote tcp))");
  assert.ok(lastUnix > 0 && firstTcp > lastUnix, prof);
});

test("6. host services: no exec of open, osascript, launchctl, crontab, at, batch; no Apple Events", () => {
  const prof = renderSeatbeltProfile({ hostServices: true })!;
  assert.ok(prof.includes(
    "(deny process-exec\n" + [...HOST_SERVICE_PROGRAMS].sort().map((p, i, a) => `  (literal "${p}")${i === a.length - 1 ? ")" : ""}`).join("\n") + "\n(deny appleevent-send)\n",
  ), prof);
  for (const p of ["/usr/bin/open", "/usr/bin/osascript", "/bin/launchctl", "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/batch"]) {
    assert.ok(HOST_SERVICE_PROGRAMS.includes(p), p);
  }
  assert.ok(!prof.includes("/usr/bin/security"), "the Keychain CLI stays (Claude Code keeps its login there)");
});

test("the whole profile, pinned byte for byte (every component, a macOS HOME)", () => {
  const prof = renderSeatbeltProfile({
    secrets: ["/Users/u/.aws/credentials"],
    stateDirs: ["/Users/u/.mandu"],
    stateWriteOnly: ["/Users/u/.config/mandu"],
    writeProtect: ["/Users/u/.zshrc"],
    net: { connect: [{ host: "localhost", port: 8788 }, { host: "*", port: 443 }], bind: [] },
    unix: { allow: ["/private/var/run/mDNSResponder"], refuse: ["/Users/u/.docker"], extra: [] },
    hostServices: true,
  });
  assert.equal(prof, [
    "(version 1)",
    ";; Mandu — the whole-agent Seatbelt profile (confidentiality.md §7.3).",
    ";; The macOS enactment of the Linux guard and landlock-net: last match wins,",
    ";; so each component's denies follow the default allow and its own",
    ";; exceptions follow its denies.",
    "(allow default)",
    ";; 1. Credential files: a read fails; no write, rename or delete.",
    "(deny file-read* file-write*",
    '  (literal "/Users/u/.aws/credentials"))',
    ";; 2. Mandu's own state: the symbol DB, the event store, the shadow repositories.",
    "(deny file-read* file-write*",
    '  (subpath "/Users/u/.mandu"))',
    "(deny file-write*",
    '  (subpath "/Users/u/.config/mandu"))',
    ";; 3. Write-protect: Mandu's own files and the files that run later (refused, not asked).",
    "(deny file-write*",
    '  (subpath "/Users/u/.zshrc"))',
    ";; The directories above them: no rename, no delete (their contents stay writable).",
    "(deny file-write-unlink",
    '  (literal "/Users")',
    '  (literal "/Users/u")',
    '  (literal "/Users/u/.aws")',
    '  (literal "/Users/u/.config"))',
    ";; 5. Unix sockets (unix-policy): only the listed ones; host services that run code are refused.",
    ";;    (Before the TCP rules: after them, the bare unix-socket deny misfires on some TCP ports.)",
    "(deny network-outbound (remote unix-socket))",
    "(allow network-outbound",
    '  (remote unix-socket (subpath "/private/var/run/mDNSResponder")))',
    "(deny network-outbound",
    '  (remote unix-socket (subpath "/Users/u/.docker")))',
    ";; 4. Network (landlock-net): TCP connect and bind only to the listed ports; UDP untouched.",
    "(deny network-outbound (remote tcp))",
    "(allow network-outbound",
    '  (remote tcp "*:443")',
    '  (remote tcp "localhost:8788"))',
    "(deny network-bind (local ip))",
    "(allow network-bind (local udp))",
    ";; 6. Host services that run code outside this profile: launchd, LaunchServices, Apple Events.",
    "(deny process-exec",
    '  (literal "/bin/launchctl")',
    '  (literal "/usr/bin/at")',
    '  (literal "/usr/bin/batch")',
    '  (literal "/usr/bin/crontab")',
    '  (literal "/usr/bin/open")',
    '  (literal "/usr/bin/osascript"))',
    "(deny appleevent-send)",
    "",
  ].join("\n"));
});

test("an embedded quote or backslash cannot break out of a literal", () => {
  const prof = renderSeatbeltProfile({ secrets: ['/h/we"ird/.env', "/h/back\\slash/.env"] })!;
  assert.ok(prof.includes('(literal "/h/we\\"ird/.env")'));
  assert.ok(prof.includes('(literal "/h/back\\\\slash/.env")'));
});
