import { test } from "node:test";
import assert from "node:assert/strict";
import {
  NESTED_SANDBOX_PROBE,
  nestedSandboxProbeArgv,
  planSecretTwins,
  TWIN_WRAP_HARDENING,
  seatbeltSecretProfile,
  bareTwinWrap,
  homeMaskOps,
  seatbeltWrapArgv,
  wholeFileTwinText,
  type SecretTwin,
} from "../../src/secret-twins.js";

const SECRETS: SecretTwin[] = [
  { path: "/home/u/.ssh/id_rsa", symbol: "$MDU:nomodel_Read[bbbb]" },
  { path: "/home/u/.aws/credentials", symbol: "$MDU:nomodel_Read[aaaa]" },
];

test("planSecretTwins: twin content is exactly the symbol; binds land after the root bind", () => {
  const plan = planSecretTwins(SECRETS, "/run/mandu/twins");

  // Deterministic (sorted by target path) — the argv must not depend on
  // registry iteration order.
  assert.deepEqual(
    plan.files.map((f) => f.targetPath),
    ["/home/u/.aws/credentials", "/home/u/.ssh/id_rsa"],
  );
  assert.equal(plan.files[0]!.content, "$MDU:nomodel_Read[aaaa]\n");
  assert.ok(plan.files[0]!.twinPath.startsWith("/run/mandu/twins/"));

  const argv = plan.wrapArgv;
  assert.equal(argv[0], "bwrap");
  // The root bind must come FIRST so the per-secret binds override it.
  const rootAt = argv.indexOf("--dev-bind");
  const firstBindAt = argv.indexOf("--bind");
  assert.ok(rootAt >= 0 && firstBindAt > rootAt, "secret binds come after --dev-bind / /");
  assert.ok(argv.includes("--die-with-parent"), "a killed launcher must not orphan the agent");
  assert.equal(argv.at(-1), "--", "the agent argv follows the separator");

  // The added hardening flags: drop every in-userns capability, isolate
  // SysV IPC + the hostname, and give the tree its own pid namespace with a
  // fresh /proc (sandbox review finding 3: it cannot signal the arbiter or
  // the proxies). They sit AFTER --die-with-parent and BEFORE the first
  // per-secret bind, in this exact order.
  const dieAt = argv.indexOf("--die-with-parent");
  const capAt = argv.indexOf("--cap-drop");
  assert.ok(capAt > 0, "--cap-drop is emitted");
  assert.equal(argv[capAt + 1], "ALL", "--cap-drop takes its ALL argument");
  const ipcAt = argv.indexOf("--unshare-ipc");
  const utsAt = argv.indexOf("--unshare-uts");
  const pidAt = argv.indexOf("--unshare-pid");
  const procAt = argv.indexOf("--proc");
  assert.ok(
    dieAt < capAt && capAt < ipcAt && ipcAt < utsAt && utsAt < pidAt && pidAt < procAt && procAt < firstBindAt,
    "hardening flags come after --die-with-parent, before the binds, in order",
  );
  assert.equal(argv[procAt + 1], "/proc", "a fresh procfs of the new pid namespace, over the root bind's");

  // The flags we DELIBERATELY do NOT add would each break the live agent:
  //   --unshare-net    severs the 127.0.0.1 anthropic-proxy
  //   --unshare-all    implies the above
  //   --new-session    detaches the controlling TTY (kills interactivity)
  //   --clearenv       wipes ANTHROPIC_BASE_URL / proxy / arbiter env
  //   --disable-userns blocks the agent's own nested AgentShell sandboxes
  // None may appear — this is a MASK around a live, networked, supervised
  // agent, not an isolated jail.
  for (const forbidden of [
    "--unshare-net",
    "--unshare-all",
    "--new-session",
    "--clearenv",
    "--disable-userns",
  ]) {
    assert.ok(!argv.includes(forbidden), `${forbidden} must NOT be added — it breaks the live agent`);
  }

  // Each secret is bound twin→real.
  for (const f of plan.files) {
    const i = argv.indexOf(f.twinPath);
    assert.ok(i > 0, `twin ${f.twinPath} is bound`);
    assert.equal(argv[i - 1], "--bind");
    assert.equal(argv[i + 1], f.targetPath);
  }
});

test("planSecretTwins: NO wrapper when there is nothing to mask", () => {
  const plan = planSecretTwins([], "/run/mandu/twins");
  assert.deepEqual(plan.files, []);
  assert.deepEqual(plan.wrapArgv, [], "never pay for a sandbox we do not need");
});

test("planSecretTwins: same-named secrets in different dirs do not collide", () => {
  const plan = planSecretTwins(
    [
      { path: "/home/u/.aws/credentials", symbol: "$MDU:nomodel_Read[1111]" },
      { path: "/home/u/.config/gcloud/credentials", symbol: "$MDU:nomodel_Read[2222]" },
    ],
    "/twins",
  );
  const names = plan.files.map((f) => f.twinPath);
  assert.equal(new Set(names).size, 2, "distinct twin files");
});

test("seatbeltSecretProfile: denies come AFTER the allow (SBPL is last-match-wins)", () => {
  const prof = seatbeltSecretProfile(SECRETS)!;
  assert.ok(prof.includes("(allow default)"));
  const allowAt = prof.indexOf("(allow default)");
  const denyAt = prof.indexOf("(deny file-read*");
  assert.ok(denyAt > allowAt, "a deny placed BEFORE the allow would be overridden — the whole bug");

  // Read AND write, and no rename of a folder above (seatbelt-profile.ts;
  // the rename-then-read bypass of the old read-only deny, 2026-09-29).
  assert.ok(prof.includes('(deny file-read* file-write*\n  (literal "/home/u/.aws/credentials")\n  (literal "/home/u/.ssh/id_rsa"))'), prof);
  assert.ok(prof.includes('(deny file-write-unlink\n  (literal "/home")\n  (literal "/home/u")\n  (literal "/home/u/.aws")\n  (literal "/home/u/.ssh"))'), prof);
  assert.deepEqual(seatbeltWrapArgv("/tmp/p.sb"), ["/usr/bin/sandbox-exec", "-f", "/tmp/p.sb"]);
});

test("seatbeltSecretProfile: Mandu's own stores alone still make a profile, denied by subpath for read and write", () => {
  const prof = seatbeltSecretProfile([], ["/Users/u/.mandu", "/Users/u/.local/state/mandu/events", "/Users/u/.mandu"])!;
  const allow = prof.indexOf("(allow default)");
  // The whole-agent renderer's state component (seatbelt-profile.ts): read and
  // write denied by subpath, after the default allow (last match wins).
  const deny = prof.indexOf("(deny file-read* file-write*");
  assert.ok(allow >= 0 && deny > allow, prof);
  assert.equal(prof.split('(subpath "/Users/u/.mandu")').length - 1, 1, "deduplicated");
  assert.ok(prof.includes('(subpath "/Users/u/.local/state/mandu/events")'));
});

test("seatbeltSecretProfile: the home denied whole, its carve-outs allowed AFTER the deny (last match wins), never alone", () => {
  const av = "/Users/u/.mandu/state/workspaces/w/agentview";
  const prof = seatbeltSecretProfile([], ["/Users/u/.mandu"], [av, av])!;
  const lines = prof.split("\n");
  const deny = lines.indexOf('  (subpath "/Users/u/.mandu"))');
  const allow = lines.indexOf(`  (subpath "${av}"))`);
  assert.equal(lines[deny - 1], "(deny file-read* file-write*", prof);
  assert.equal(lines[allow - 1], "(allow file-read* file-write*", prof);
  assert.ok(deny >= 0 && allow > deny, prof);
  assert.equal(prof.split(`"${av}"`).length - 1, 1, "deduplicated");
  assert.equal(seatbeltSecretProfile([], [], [av]), null, "a carve-out with nothing to carve from makes no profile");
  const secretsOnly = seatbeltSecretProfile(SECRETS, [], [av])!;
  assert.ok(!secretsOnly.includes("(allow file-read* file-write*"), "no allow without a deny of the home");
});

test("homeMaskOps: a tmpfs over each mask, then each carve-out bound back at its own path", () => {
  const av = "/h/.mandu/state/workspaces/w/agentview";
  const repo = "/h/.mandu/state/workspaces/w/repo.git";
  assert.deepEqual(homeMaskOps(["/run/s/events", "/h/.mandu"], [repo, av]), [
    "--tmpfs", "/h/.mandu", "--tmpfs", "/run/s/events",
    "--bind", av, av, "--bind", repo, repo,
  ]);
  assert.deepEqual(homeMaskOps([], []), []);
  // As extra flags, the ops sit BEFORE every secret-twin bind: a twin whose
  // file lies in the carve-out lands on it, not under the tmpfs.
  const ops = homeMaskOps(["/h/.mandu"], [av]);
  const plan = planSecretTwins([{ path: `${av}/.env`, symbol: "$MDU:nomodel_Read[aaaa]" }], "/run/t", "bwrap", { extraFlags: ops });
  const tmpfs = plan.wrapArgv.indexOf("--tmpfs");
  const carve = plan.wrapArgv.indexOf(av);
  const twin = plan.wrapArgv.indexOf(`${av}/.env`);
  assert.ok(tmpfs >= 0 && carve > tmpfs && twin > carve, plan.wrapArgv.join(" "));
});

test("bareTwinWrap: the twin wrap with no bind of its own; planSecretTwins builds on it", () => {
  const bare = bareTwinWrap("bwrap", ["--x"]);
  assert.deepEqual(bare.slice(0, 4), ["bwrap", "--dev-bind", "/", "/"]);
  assert.equal(bare.at(-1), "--");
  assert.equal(bare.at(-2), "--x");
  const planned = planSecretTwins(SECRETS, "/run/t", "bwrap", { extraFlags: ["--x"] }).wrapArgv;
  assert.deepEqual(planned.slice(0, bare.length - 1), bare.slice(0, -1));
});

test("seatbeltSecretProfile: null when there is nothing to deny; quotes are escaped", () => {
  assert.equal(seatbeltSecretProfile([]), null);
  assert.equal(seatbeltSecretProfile([], []), null);
  const prof = seatbeltSecretProfile([
    { path: '/home/u/we"ird/.env', symbol: "$MDU:nomodel_Read[3333]" },
  ])!;
  assert.ok(prof.includes('we\\"ird'), "an embedded quote cannot break out of the literal");
});

test("planSecretTwins: binds land on the RESOLVED target; two spellings of one file bind once; a vanished file is skipped, loudly", () => {
  // The 2026-09-05 bricked launch: the registry held a spelling through a
  // symlinked parent (`~/tools/linux/…` → `/mnt/…`). bwrap cannot mkdir a
  // mount point through a symlinked parent, so the bind must land on the
  // real path — and the same file registered under two spellings must not
  // race for one mount point.
  const real = "/mnt/hda1/u/linux/Documentation/security/credentials.rst";
  const plan = planSecretTwins(
    [
      { path: "/home/u/tools/linux/Documentation/security/credentials.rst", symbol: "$MDU:nomodel_Read[1111]" },
      { path: "/home/u/project/linux-link/Documentation/security/credentials.rst", symbol: "$MDU:nomodel_Read[2222]" },
      { path: "/home/u/.aws/credentials", symbol: "$MDU:nomodel_Read[3333]" },
      { path: "/home/u/.ssh/gone", symbol: "$MDU:nomodel_Read[4444]" },
    ],
    "/twins",
    "bwrap",
    {
      resolveTarget: (p) => {
        if (p.includes("/linux")) return real;      // both spellings → one real file
        if (p.endsWith("/gone")) return null;        // vanished since discovery
        return p;
      },
    },
  );
  assert.deepEqual(
    plan.files.map((f) => f.targetPath),
    ["/home/u/.aws/credentials", real],
    "one bind per REAL file, on the resolved path",
  );
  const bindTargets = plan.wrapArgv.filter((_, i, a) => a[i - 2] === "--bind");
  assert.deepEqual(bindTargets, ["/home/u/.aws/credentials", real]);
  assert.ok(!plan.wrapArgv.some((a) => a.includes("/home/u/tools/")), "no bind through the symlinked spelling");
  assert.deepEqual(
    plan.skipped.map((s) => s.path),
    ["/home/u/.ssh/gone", "/home/u/tools/linux/Documentation/security/credentials.rst"],
    "the vanished file and the duplicate spelling are reported, not silently dropped",
  );
  assert.match(plan.skipped[0]!.reason, /no longer exists/);
  assert.match(plan.skipped[1]!.reason, /same file as .*project\/linux-link/);
});

test("planSecretTwins: all secrets vanished → no wrapper, every one reported", () => {
  const plan = planSecretTwins(SECRETS, "/twins", "bwrap", { resolveTarget: () => null });
  assert.deepEqual(plan.files, []);
  assert.deepEqual(plan.wrapArgv, [], "never pay for a sandbox with nothing to mask");
  assert.equal(plan.skipped.length, SECRETS.length);
});

test("planSecretTwins: a STRUCTURED twin (plan 10 §2.4) is written verbatim; a whole-file twin stays the symbol", () => {
  const twin = "PORT=3000\nSTRIPE_KEY=$MDU:nomodel_Read[cccc].STRIPE_KEY\n";
  const plan = planSecretTwins(
    [
      { path: "/ws/.env", symbol: "$MDU:nomodel_Read[cccc]", twin },
      { path: "/home/u/.ssh/id_rsa", symbol: "$MDU:nomodel_Read[bbbb]" },
    ],
    "/run/mandu/twins",
  );
  const byTarget = new Map(plan.files.map((f) => [f.targetPath, f.content]));
  assert.equal(byTarget.get("/ws/.env"), twin);
  assert.equal(byTarget.get("/home/u/.ssh/id_rsa"), "$MDU:nomodel_Read[bbbb]\n");
});

test("planSecretTwins: the whole-file twin ends as the original does (the arbiter's `terminator`); the length is never the original's", () => {
  const plan = planSecretTwins(
    [
      { path: "/ws/notes.md", symbol: "$MDU:nomodel_Read[dddd]", terminator: "" },
      { path: "/ws/crlf.txt", symbol: "$MDU:nomodel_Read[eeee]", terminator: "\r\n" },
      { path: "/ws/lf.txt", symbol: "$MDU:nomodel_Read[ffff]", terminator: "\n" },
      { path: "/ws/old.txt", symbol: "$MDU:nomodel_Read[0000]" },
      { path: "/ws/odd.txt", symbol: "$MDU:nomodel_Read[1111]", terminator: "\n\n" },
      { path: "/ws/.env", symbol: "$MDU:nomodel_Read[2222]", twin: "A=1", terminator: "\n" },
    ],
    "/run/mandu/twins",
  );
  const byTarget = new Map(plan.files.map((f) => [f.targetPath, f.content]));
  assert.equal(byTarget.get("/ws/notes.md"), "$MDU:nomodel_Read[dddd]", "no trailing newline: Codex's cat shows no extra row");
  assert.equal(byTarget.get("/ws/crlf.txt"), "$MDU:nomodel_Read[eeee]\r\n");
  assert.equal(byTarget.get("/ws/lf.txt"), "$MDU:nomodel_Read[ffff]\n");
  assert.equal(byTarget.get("/ws/old.txt"), "$MDU:nomodel_Read[0000]\n", "an older arbiter sends no terminator: the old newline");
  assert.equal(byTarget.get("/ws/odd.txt"), "$MDU:nomodel_Read[1111]\n", "only the three line endings are honoured");
  assert.equal(byTarget.get("/ws/.env"), "A=1", "a structured twin is written verbatim");
  assert.equal(wholeFileTwinText("$MDU:x[1]", ""), "$MDU:x[1]");
});

test("nestedSandboxProbeArgv: the twin wrap as the launch runs it, around a nested bubblewrap as the agent's tools start one", () => {
  const argv = nestedSandboxProbeArgv("bwrap", ["--tmpfs", "/run/WSL"]);
  const sep = argv.indexOf("--");
  // outer: the same root bind + hardening + extra flags as planSecretTwins
  assert.deepEqual(argv.slice(0, sep), ["bwrap", "--dev-bind", "/", "/", ...TWIN_WRAP_HARDENING, "--tmpfs", "/run/WSL"]);
  // inner: its own user, pid and net namespaces (Codex's shell sandbox, Mandu's exec box)
  assert.deepEqual(argv.slice(sep + 1), ["bwrap", ...NESTED_SANDBOX_PROBE]);
  for (const ns of ["--unshare-user", "--unshare-pid", "--unshare-net"]) assert.ok(NESTED_SANDBOX_PROBE.includes(ns), ns);
  // the planner and the probe share the hardening, so the probe tests the real wrap
  const plan = planSecretTwins([{ path: "/home/u/.aws/credentials", symbol: "$MDU:nomodel_Read[aaaa]" }], "/run/t");
  assert.deepEqual(plan.wrapArgv.slice(4, 4 + TWIN_WRAP_HARDENING.length), [...TWIN_WRAP_HARDENING]);
});
