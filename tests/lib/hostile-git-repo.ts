/**
 * hostile-git-repo — a git repository an agent booby-trapped, for the
 * git-hardening oracle (docs/design/architecture/write-protection.md §8.7).
 *
 * Every repository config key and attribute git knows that starts a program
 * names a MARKER program: a shell script that appends a line to
 * `<markers>/<name>` and exits. A hardened git call over the repository must
 * leave the markers directory empty; `fired()` lists what ran.
 *
 * The history is real (a secret-shaped token committed, a deploy key
 * committed then deleted, a signed commit, a CRLF file), so every Mandu call
 * path has something to walk, scan, resolve and hash. The traps go in LAST,
 * after every commit (the fixture's own git would otherwise spring them),
 * and the working files are then touched so an index read sees them
 * stat-dirty (a `git status` would re-hash them through the clean filter).
 *
 * With `packed`, the history is repacked into one pack before the traps go
 * in (a stock `git repack`, nothing to spring yet): what the arbiter's
 * prepared copies (plan 14 §11.1 R3) rebuild is packs.
 *
 * With `promisor`, the repository is also a partial clone whose promisor
 * remote is an ssh URL (the transport runs `core.sshCommand`, a marker) and
 * one blob of the history is removed from the object store: whatever reads
 * it lazily fetches unless the fetch is refused.
 */
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface HostileRepo {
  /** The fixture's own directory (removed by `cleanup`). */
  dir: string;
  /** The work tree. */
  root: string;
  /** Where the markers write. */
  markers: string;
  /** A tracked file holding a secret-shaped token (working copy present). */
  secretRel: string;
  /** A path committed and then deleted (a human label's target). */
  goneRel: string;
  /** The blob id of `goneRel`'s committed version (what a label on it locks). */
  goneBlob: string;
  /** The CRLF file (`text eol=lf`). */
  crlfRel: string;
  /** The marker programs that ran, by name, sorted. */
  fired(): string[];
  /** Forget what ran so far. */
  clear(): void;
  cleanup(): void;
}

/** The hook names a hooks directory is filled with. Each is also a
 *  config-based hook (git 2.54 and later: `hook.<name>.command` run on
 *  `hook.<name>.event`, no file in any hooks directory), `trap-<event>`, whose
 *  marker is `cfghook-<event>`; one more, `trap-included` on `pre-commit`
 *  (marker `cfghook-included`), sits in the included config file. */
export const HOOK_NAMES = [
  "pre-commit", "prepare-commit-msg", "commit-msg", "post-commit", "post-checkout", "post-merge", "pre-rebase",
  "post-rewrite", "post-index-change", "reference-transaction", "pre-auto-gc", "pre-push", "fsmonitor-watchman",
] as const;

/** The running git's version (`git --version`), as [major, minor]; [0, 0]
 *  when it cannot be read. */
export function gitVersion(): [number, number] {
  try {
    const m = /(\d+)\.(\d+)/.exec(execFileSync("git", ["--version"], { encoding: "utf8" }));
    return m ? [Number(m[1]), Number(m[2])] : [0, 0];
  } catch { return [0, 0]; }
}

/** Does the running git run config-based hooks (git 2.54 and later)? The
 *  control: a stock git then springs the `cfghook-*` traps. */
export function gitRunsConfigHooks(): boolean {
  const [maj, min] = gitVersion();
  return maj > 2 || (maj === 2 && min >= 54);
}

/** git 2.54 runs config-based hooks but has no switch for them by event
 *  (`hook.<event>.enabled` came in 2.55), so a command of Mandu's that runs
 *  hooks (fs-sync's commit, frozen axis) still runs them there:
 *  write-protection.md §8.6. True on exactly that git. */
export function gitConfigHooksUnswitchable(): boolean {
  const [maj, min] = gitVersion();
  return maj === 2 && min === 54;
}

// The secret-shaped token (a GitHub classic PAT shape, built so this source
// never holds one whole).
const TOKEN = "gh" + "p_" + "Q9x2Lm7Vt4Rb8Kd1Wn6Ys3Ha5Ju0Pe2Fc7Gz";
const PEM = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n";

export function hostileRepo(opts: { promisor?: boolean; settled?: boolean; packed?: boolean } = {}): HostileRepo {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-hostile-git-")));
  const root = join(dir, "repo");
  const markers = join(dir, "markers");
  const bin = join(dir, "bin");
  mkdirSync(root, { recursive: true });
  mkdirSync(markers);
  mkdirSync(bin);
  const env = {
    PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: dir, LC_ALL: "C",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const prog = (name: string): string => {
    const p = join(bin, name);
    writeFileSync(p, `#!/bin/sh\necho "$0 $*" >> '${join(markers, name)}'\nexit 0\n`);
    chmodSync(p, 0o755);
    return p;
  };

  // Every work file an hour old before it is added: no index entry is racily
  // clean (as new as the index), so only a stat change makes git re-read one.
  const past = new Date(Date.now() - 3_600_000);
  const settle = (): void => {
    for (const f of ["config.env", "crlf.txt", "README.md", "old.txt", "deploy/id_rsa"]) {
      try { utimesSync(join(root, f), past, past); } catch { /* not there (yet) */ }
    }
  };

  // ── The history ──
  git("init", "-q", "-b", "main");
  mkdirSync(join(root, "deploy"));
  writeFileSync(join(root, "deploy", "id_rsa"), PEM);
  writeFileSync(join(root, "config.env"), `GITHUB_TOKEN=${TOKEN}\n`);
  writeFileSync(join(root, "crlf.txt"), "one\r\ntwo\r\n");
  writeFileSync(join(root, "README.md"), "# hostile\n");
  settle();
  git("add", "-A");
  git("commit", "-qm", "init");
  // A signed commit: a stand-in signer that emits a well-formed signature.
  const signer = join(bin, "signer");
  writeFileSync(signer, "#!/bin/sh\ncat >/dev/null\necho '[GNUPG:] SIG_CREATED ' >&2\nprintf -- '-----BEGIN PGP SIGNATURE-----\\n\\nx\\n-----END PGP SIGNATURE-----\\n'\n");
  chmodSync(signer, 0o755);
  git("-c", `gpg.program=${signer}`, "commit", "-q", "--allow-empty", "-S", "-m", "signed");
  const goneBlob = git("rev-parse", "HEAD:deploy/id_rsa").trim();
  git("rm", "-q", "deploy/id_rsa");
  writeFileSync(join(root, "config.env"), `GITHUB_TOKEN=${TOKEN}\nMORE=1\n`);
  settle();
  git("add", "-A");
  git("commit", "-qm", "rotate");
  if (opts.packed) git("repack", "-adq");
  let missing = "";
  if (opts.promisor) {
    // A blob only the history holds, stored loose, then removed.
    writeFileSync(join(root, "old.txt"), "an old version only the history holds\n");
    settle();
    git("add", "old.txt");
    git("commit", "-qm", "old");
    missing = git("rev-parse", "HEAD:old.txt").trim();
    git("rm", "-q", "old.txt");
    git("commit", "-qm", "drop old");
    rmSync(join(root, ".git", "objects", missing.slice(0, 2), missing.slice(2)));
  }

  // ── The traps (last: the fixture's own git above must not spring them) ──
  const hooksDir = join(dir, "hooks");
  mkdirSync(hooksDir);
  for (const h of HOOK_NAMES) {
    const body = `#!/bin/sh\necho "$0 $*" >> '${join(markers, `hook-${h}`)}'\nexit 0\n`;
    for (const d of [hooksDir, join(root, ".git", "hooks")]) {
      writeFileSync(join(d, h), body);
      chmodSync(join(d, h), 0o755);
    }
  }
  const included = join(dir, "included.cfg");
  writeFileSync(included, `[core]\n\tfsmonitor = ${prog("fsmonitor-included")}\n[diff]\n\texternal = ${prog("extdiff-included")}\n` +
    `[hook "trap-included"]\n\tcommand = ${prog("cfghook-included")}\n\tevent = pre-commit\n`);
  const cfg: Array<[string, string]> = [
    ["core.fsmonitor", prog("fsmonitor")],
    ["core." + "hooksPath", hooksDir],
    ["log.showSignature", "true"],
    ["gpg.program", prog("gpg")],
    ["gpg.ssh.program", prog("gpg-ssh")],
    ["gpg.x509.program", prog("gpg-x509")],
    ["commit.gpgSign", "true"],
    ["merge.verifySignatures", "true"],
    ["filter.evil.clean", prog("filter-clean")],
    ["filter.evil.smudge", prog("filter-smudge")],
    ["filter.evil.required", "true"],
    ["filter.proc.process", prog("filter-process")],
    ["diff.evil.textconv", prog("textconv")],
    ["diff.evil.command", prog("diff-driver")],
    ["diff.external", prog("extdiff")],
    ["merge.evil.driver", prog("merge-driver")],
    ["core.pager", prog("pager")],
    ["pager.log", prog("pager-log")],
    ["core.editor", prog("editor")],
    ["sequence.editor", prog("sequence-editor")],
    ["core.askPass", prog("askpass")],
    ["credential.helper", `!${prog("credential")}`],
    ["core.sshCommand", prog("ssh")],
    ["core.alternateRefsCommand", prog("alternate-refs")],
    ["uploadpack.packObjectsHook", prog("pack-objects-hook")],
    ["gc.auto", "1"],
    ["gc.autoPackLimit", "1"],
    ["maintenance.auto", "true"],
    ["submodule.recurse", "true"],
    ["remote.origin.url", "ssh://mandu-test.invalid/hostile.git"],
    ["include.path", included],
    // Config-based hooks (git 2.54+): `core.hooksPath` does not cover them.
    ...HOOK_NAMES.flatMap((h): Array<[string, string]> => [[`hook.trap-${h}.command`, prog(`cfghook-${h}`)], [`hook.trap-${h}.event`, h]]),
  ];
  if (opts.promisor) {
    cfg.push(["core.repositoryformatversion", "1"], ["extensions.partialClone", "origin"], ["remote.origin.promisor", "true"]);
  }
  for (const [k, v] of cfg) git("config", k, v);
  writeFileSync(join(root, ".gitattributes"), "* filter=evil diff=evil merge=evil\ncrlf.txt text eol=lf filter=evil diff=evil\n");
  writeFileSync(join(root, ".git", "info", "attributes"), "config.env filter=proc\n");
  // Stat-dirty working copies: an index read must decide by content (unless
  // `settled`: then only what does not compare the work tree is exercised,
  // e.g. a commit's hooks, signing and auto gc).
  if (!opts.settled) {
    const later = new Date(Date.now() + 120_000);
    for (const f of ["config.env", "crlf.txt", "README.md"]) utimesSync(join(root, f), later, later);
  }

  const fired = (): string[] => readdirSync(markers).sort();
  const clear = (): void => { for (const f of readdirSync(markers)) rmSync(join(markers, f), { force: true }); };
  clear();
  return {
    dir, root, markers, secretRel: "config.env", goneRel: "deploy/id_rsa", goneBlob, crlfRel: "crlf.txt",
    fired, clear, cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** Does the fixture's git (a stock git, none of Mandu's hardening) spring
 *  the traps? The oracle's control: a hostile repository that springs
 *  nothing would prove nothing. */
export function unhardenedFires(repo: HostileRepo, args: readonly string[], input = ""): string[] {
  repo.clear();
  try {
    execFileSync("git", [...args], {
      cwd: repo.root, input, stdio: ["pipe", "ignore", "ignore"], timeout: 20_000,
      env: {
        PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: repo.dir, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
        GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
      },
    });
  } catch { /* a trap that fails its command still ran */ }
  const got = repo.fired();
  repo.clear();
  return got;
}
