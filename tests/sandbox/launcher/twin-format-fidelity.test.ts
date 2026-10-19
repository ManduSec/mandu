/**
 * twin-format-fidelity.test.ts — the programs that read a configuration file
 * still parse it under the REAL launcher's secret twins (plan 10 §11.13,
 * 2026-10-02; the "Measured utility breakages" of plan 10 §11.12).
 *
 * Measured before: in `secrets` with the real launcher, the guard and a
 * developer-shaped HOME, `~/.ssh/config` became a whole-file placeholder and
 * ssh refused it ("bad configuration options"), so git over ssh failed; a
 * `pip.conf` with no credential got the same copy; git's `store` credential
 * helper could not read `~/.git-credentials`.
 *
 * This suite builds that HOME in withStack's throwaway HOME, runs the
 * private arbiter in `secrets` and the real launcher (all hardening on: the
 * twin binds, the guard) around a shell agent, and asserts:
 *   F1 ssh parses `~/.ssh/config` and its `Include`d `config.d/plain`
 *      (`ssh -G` exit 0, the resolved host names), the `SetEnv` token reads
 *      back as a symbol, and a connect fails at the network (port 1), never
 *      on the configuration;
 *   F2 `~/.ssh/known_hosts` is the real file (public material, not
 *      twinned): `ssh-keygen -F` finds the host;
 *   F3 pip's parser (RawConfigParser, and pip itself where installed) reads
 *      both pip.conf files: the plain one as written, the credentialed one
 *      with the password a symbol;
 *   F4 git's `store` helper parses the store's twin and hands git the
 *      password's placeholder: git is the store's known consumer but, since
 *      2026-10-04, a printer (plan 13 §4.9 option (a): `git diff
 *      --no-index` prints any file), so without the wire release (this run
 *      has no TLS inspection) it gets what `cat` gets, the twin; under the
 *      wire release the session proxy puts the password back at its host
 *      (wire-release-live). Until then git read the real store here;
 *   F5 THE LEAK ORACLE: no canary appears anywhere in the agent's output,
 *      the values no rule names included (§11.13.2: a password in a
 *      `ProxyCommand` off the relay grammar, a token in an index URL's
 *      path, a token written as the store's user); the masked
 *      `ProxyCommand` still parses (`ssh -G`) and its host fails with
 *      Mandu's notice (§11.13.3: which line of which file was withheld, why,
 *      the way out; no word of the command), a vetted one reads as written.
 * The model-boundary half of the oracle (twins released with symbols only,
 * raw text and git's output as one symbol) is tests/stack/config-twin-fidelity.
 *
 *   F6 a reader that sizes its read by a stat of the path reads every twin
 *      WHOLE, in both postures (confidentiality.md §7.2a "The size a reader
 *      sees", 2026-10-04): `git diff --no-index /dev/null` and `git grep
 *      --no-index` (lstat, open, read st_size bytes) print the store twin's
 *      lines as `cat` does, and Python's lstat-then-read gets exactly
 *      st_size bytes. Red before in the guard-only posture
 *      (`--no-secret-bind`): the twin cut at the real file's size (`git
 *      diff` printed "\ No newline at end of file" mid-placeholder).
 *
 * `--no-reply-filter` keeps stdout as the AGENT sees it. GATED on Linux +
 * bwrap + an unprivileged userns + the built guard; zero API budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withStack, runLauncher, probeKernelTier } from "../../lib/launcher-live.js";
import { installExitGuard } from "../../lib/exit-guard.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";

installExitGuard("twin-format-fidelity");

// This suite STATES its axes (protection-modes.md §4): `secrets`. withStack
// brings its private arbiter up in the same mode.
stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const GUARD = pickGuard(resolve(HERE, "..", "..", "..", "interceptors", "target"));
const probe = process.platform === "linux" ? probeKernelTier() : null;
const GATE = process.platform !== "linux"
  ? "Linux only (bwrap secret twins)"
  : !probe!.bwrap
    ? "`bwrap` not installed"
    : !probe!.userns
      ? "unprivileged user namespaces unavailable"
      : !GUARD.path
        ? "mandu-net-guard is not built (scripts/build-native.sh)"
        : false;

const SSH_TOKEN = "sshenvCANARY4c1e88a0d7";
const PIP_PW = "pippwCANARY93b07de215";
const GIT_PW = "gitpwCANARY51fa0c6e39";
// Plan 10 §11.13.2 (fail closed): values no rule classified as secret,
// which the own-text twin once carried raw.
const SSH_PROXY_PW = "proxypwCANARY2b8e5d0c73";
const PIP_PATH_TOKEN = "pathtokCANARY9e1c4a7b20";
const GIT_TOKEN_USER = "tokuserCANARY3f6d0a9e84";
const CANARIES = [SSH_TOKEN, PIP_PW, GIT_PW, SSH_PROXY_PW, PIP_PATH_TOKEN, GIT_TOKEN_USER];

const FILES: Record<string, string> = {
  ".ssh/config": [
    // Absolute: ssh resolves a relative Include against the password
    // database's home, not the throwaway one.
    "Include __HOME__/.ssh/config.d/*",
    "Host ci",
    "  HostName 127.0.0.1",
    "  Port 1",
    "  User builder",
    `  SetEnv CI_TOKEN=${SSH_TOKEN}`,
    "  StrictHostKeyChecking yes",
    "Host masked",
    "  HostName 127.0.0.1",
    `  ProxyCommand mysql -p${SSH_PROXY_PW} -h %h`,
    "Host jump",
    "  ProxyCommand ssh -W %h:%p bastion",
    "",
  ].join("\n"),
  ".ssh/config.d/plain": "Host bastion\n  HostName 10.9.8.7\n  User deploy\n",
  ".ssh/known_hosts": "known.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVf0Q3m3yq1wQh8d2Wk0bqv6c2b3y2m8x9Q1n3yW4Zt\n",
  ".config/pip/pip.conf": `[global]\nindex-url = https://__token__:${PIP_PW}@pypi.corp.example/simple\nextra-index-url = https://pypi.fury.io/${PIP_PATH_TOKEN}/acme/\n`,
  ".pip/pip.conf": "[global]\ntimeout = 60\ntrusted-host = pypi.corp.example\n",
  ".git-credentials": `https://builder:${GIT_PW}@git.example.com\nhttps://${GIT_TOKEN_USER}:x-oauth-basic@github.com\n`,
};

/** The agent's work, in bash (a child of the agent `/bin/sh`, so not the
 *  agent's own executable). Every line it prints is tagged. Tools by
 *  absolute path: the launcher's exec-box shims `cat`, `grep`, `sed` … on
 *  PATH into a box whose /tmp is its own, and withStack's HOME lives under
 *  /tmp (a real HOME does not). ssh and ssh-keygen find `~` through the
 *  password database, not $HOME, so the throwaway HOME's files are named
 *  (`-F`, `-f`): the same paths, so the same twin bind and guard decision. */
const AGENT_SCRIPT = String.raw`
set -u
T="$(/usr/bin/mktemp -d)"
tag() { /usr/bin/sed "s/^/$1 /"; }
if command -v ssh >/dev/null 2>&1; then
  ssh -F "$HOME/.ssh/config" -G ci > "$T/g" 2>&1; echo "SSH_G_EXIT $?"
  /usr/bin/grep -E '^(hostname|user|port|setenv) ' "$T/g" | tag SSH_G
  ssh -F "$HOME/.ssh/config" -G bastion 2>&1 | /usr/bin/grep -E '^(hostname|user) ' | tag SSH_GB
  ssh -F "$HOME/.ssh/config" -G masked 2>&1 | /usr/bin/grep -E '^proxycommand ' | tag SSH_GM
  ssh -F "$HOME/.ssh/config" -G jump 2>&1 | /usr/bin/grep -E '^proxycommand ' | tag SSH_GJ
  ssh -F "$HOME/.ssh/config" -o BatchMode=yes -o ConnectTimeout=5 masked true > "$T/m" 2>&1
  echo "SSH_MASKED_EXIT $?"
  tag SSH_MASKED < "$T/m"
  ssh -F "$HOME/.ssh/config" -o UserKnownHostsFile="$HOME/.ssh/known_hosts" -o BatchMode=yes -o ConnectTimeout=5 ci true > "$T/c" 2>&1
  echo "SSH_CONNECT_EXIT $?"
  tag SSH_CONNECT < "$T/c"
  ssh-keygen -F known.example -f "$HOME/.ssh/known_hosts" > "$T/k" 2>&1; echo "KNOWN_EXIT $?"
  /usr/bin/grep -c '^known.example ' "$T/k" | tag KNOWN_COUNT
else
  echo "SSH_ABSENT"
fi
/bin/cat "$HOME/.ssh/config" | tag CAT_SSH
python3 - <<'PY' 2>&1 | tag PIP_CP
import configparser, os
for f in (os.path.expanduser("~/.config/pip/pip.conf"), os.path.expanduser("~/.pip/pip.conf")):
    c = configparser.RawConfigParser()
    c.read(f)
    for s in c.sections():
        for k, v in c.items(s):
            print(f"{os.path.basename(os.path.dirname(f))}:{s}.{k}={v}")
PY
if python3 -m pip --version >/dev/null 2>&1; then
  python3 -m pip config list 2>&1 | tag PIP_LIST
else
  echo "PIP_ABSENT"
fi
printf 'protocol=https\nhost=git.example.com\n\n' \
  | GIT_TERMINAL_PROMPT=0 git -c credential.helper=store credential fill 2>"$T/ge" \
  | /usr/bin/sed -n 's/^password=//p' | tag GIT_PW_OUT
printf 'protocol=https\nhost=git.example.com\n\n' \
  | GIT_TERMINAL_PROMPT=0 git -c credential.helper=store credential fill 2>/dev/null | /usr/bin/grep '^username=' | tag GIT_USER
tag GIT_ERR < "$T/ge"
/bin/cat "$HOME/.git-credentials" | tag CAT_GIT
/usr/bin/rm -rf "$T"
echo "AGENT_DONE"
`;

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test(
  "LIVE: under the real launcher's twins ssh parses its config, known_hosts is real, pip parses pip.conf, git's store helper parses the store's twin (git is a printer), and no canary reaches the agent's output",
  { skip: GATE, timeout: 300_000 },
  async () => {
    await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
      for (const [rel, content] of Object.entries(FILES)) {
        mkdirSync(dirname(join(home, rel)), { recursive: true, mode: 0o700 });
        writeFileSync(join(home, rel), content.replace("__HOME__", home), { mode: 0o600 });
      }
      const script = join(tmp, "agent.sh");
      writeFileSync(script, `exec bash ${join(tmp, "work.sh")}\n`);
      writeFileSync(join(tmp, "work.sh"), AGENT_SCRIPT);
      const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home };
      const r = await runLauncher(
        ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude", "--", "/bin/sh", script],
        env, workspace, 240_000,
      );
      const out = r.out;
      const diag = `\n--- launch output (tail) ---\n${out.slice(-6000)}`;
      const tagged = (t: string): string[] => out.split("\n").filter((l) => l.startsWith(`${t} `)).map((l) => l.slice(t.length + 1));

      assert.equal(r.code, 0, `the launch failed${diag}`);
      assert.ok(out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
      assert.ok(/confidentiality — \d+ secret\(s\) confined/.test(out), `the twins engaged${diag}`);
      assert.ok(/net-guard LIVE/.test(out), `the guard engaged${diag}`);

      // F5 — THE LEAK ORACLE first: no canary in anything the agent saw.
      for (const c of CANARIES) assert.ok(!out.includes(c), `${c} reached the agent's world${diag}`);

      // F1 — ssh parses its config (and the Include) from the twins.
      if (!out.includes("SSH_ABSENT")) {
        assert.deepEqual(tagged("SSH_G_EXIT"), ["0"], `ssh -G refused the configuration${diag}`);
        const g = tagged("SSH_G");
        assert.ok(g.includes("hostname 127.0.0.1") && g.includes("user builder") && g.includes("port 1"), `ssh -G ci: ${g.join(" | ")}${diag}`);
        assert.ok(g.some((l) => /^setenv CI_TOKEN=\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.ci\.CI_TOKEN$/.test(l)), `the SetEnv token is a symbol: ${g.join(" | ")}${diag}`);
        assert.deepEqual([...tagged("SSH_GB")].sort(), ["hostname 10.9.8.7", "user deploy"], `the Included config.d/plain is read as written${diag}`);
        // §11.13.2/§11.13.3: a ProxyCommand off the relay grammar is
        // withheld: ssh still parses the file, and that host fails loudly
        // with Mandu's notice (the line, the keyword, why, the way out),
        // never silently and never with the command's text; a vetted jump
        // command reads as written.
        assert.ok(/^proxycommand \/bin\/sh -c '[^']*' '\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.masked\.ProxyCommand' 'mandu: /.test(tagged("SSH_GM")[0] ?? ""), `ssh -G masked: ${tagged("SSH_GM").join(" | ")}${diag}`);
        assert.deepEqual(tagged("SSH_GJ"), ["proxycommand ssh -W %h:%p bastion"], `ssh -G jump${diag}`);
        assert.notEqual(tagged("SSH_MASKED_EXIT")[0], "0");
        const masked = tagged("SSH_MASKED").join("\n");
        assert.match(masked, /^mandu: ~\/\.ssh\/config line 10: ProxyCommand withheld from the programs the agent runs/m, `the withheld ProxyCommand names its line${diag}`);
        assert.match(masked, /^mandu: why: .*would run code holding one/m, `the notice says why${diag}`);
        assert.match(masked, /^mandu: way out: use ProxyJump .*script Mandu can pin.*run this ssh outside the agent/m, `the notice says the way out${diag}`);
        assert.doesNotMatch(masked, /mysql|\$MDU/, `the notice prints no word of the command${diag}`);
        const connect = tagged("SSH_CONNECT").join("\n");
        assert.notEqual(tagged("SSH_CONNECT_EXIT")[0], "0");
        assert.ok(!/bad configuration option|Bad configuration|terminating, \d+ bad/i.test(connect), `ssh refused its configuration: ${connect}${diag}`);
        assert.match(connect, /Connection refused|connect to host 127\.0\.0\.1 port 1/, `the connect fails at the network: ${connect}${diag}`);
        // F2 — known_hosts is the real file.
        assert.deepEqual(tagged("KNOWN_EXIT"), ["0"], `ssh-keygen -F did not find the host${diag}`);
        assert.deepEqual(tagged("KNOWN_COUNT"), ["1"]);
      } else {
        console.error("twin-format-fidelity: no ssh client on this host; F1/F2 not exercised");
      }
      assert.ok(tagged("CAT_SSH").some((l) => /CI_TOKEN=\$MDU:nomodel_Read\[/.test(l)), `cat shows the ssh config twin${diag}`);
      assert.ok(tagged("CAT_SSH").includes("  HostName 127.0.0.1"), "the rest of the config reads as written");

      // F3 — pip's parser reads both files.
      const cp = tagged("PIP_CP");
      // `<dir>:` is the file's directory: `.pip` (~/.pip/pip.conf) or `pip` (~/.config/pip/pip.conf).
      assert.ok(cp.includes(".pip:global.timeout=60") && cp.includes(".pip:global.trusted-host=pypi.corp.example"), `the plain pip.conf: ${cp.join(" | ")}${diag}`);
      // The URL password's token is percent-encoded (pip decodes it back into
      // the token; a raw token's brackets break Python's URL parser, plan 10
      // §11.13.1).
      assert.ok(cp.some((l) => /^pip:global\.index-url=https:\/\/__token__:%24MDU%3Anomodel_Read%5B[0-9a-f]{4,8}%5D\.global\.pypi\.corp\.example\.password@pypi\.corp\.example\/simple$/.test(l)),
        `the credentialed pip.conf: ${cp.join(" | ")}${diag}`);
      if (!out.includes("PIP_ABSENT")) {
        const list = tagged("PIP_LIST").join("\n");
        assert.match(list, /global\.timeout='60'/, `pip config list: ${list}${diag}`);
        assert.match(list, /global\.index-url='https:\/\/__token__:%24MDU%3Anomodel_Read%5B/, `pip config list: ${list}${diag}`);
      } else {
        console.error("twin-format-fidelity: pip is not installed; RawConfigParser (pip's parser) stands for it");
      }

      // F4 — git's store helper parses the twin (git is a printer since
      // 2026-10-04): the password git gets is its placeholder; cat gets the
      // same twin.
      assert.ok(tagged("GIT_PW_OUT").length === 1 && /^\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.git\.git\.example\.com\.password$/.test(tagged("GIT_PW_OUT")[0]!),
        `git credential fill returned the twin's placeholder: ${tagged("GIT_PW_OUT").join(" | ")} (stderr: ${tagged("GIT_ERR").join(" | ")})${diag}`);
      assert.deepEqual(tagged("GIT_USER"), ["username=builder"]);
      assert.ok(tagged("CAT_GIT").some((l) => /^https:\/\/builder:\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.git\.git\.example\.com\.password@git\.example\.com$/.test(l)),
        `cat shows the store's twin: ${tagged("CAT_GIT").join(" | ")}${diag}`);

      console.error(`twin-format-fidelity: ssh -G ${JSON.stringify(tagged("SSH_G"))}; pip ${JSON.stringify(cp)}; git store helper got the placeholder; no canary in ${out.length} bytes of agent output`);
    }, { mode: "secrets" });
  },
);

/** F6: the readers that size their read by a stat of the path. Run from the
 *  throwaway HOME (git diff and grep name the file relatively, as an agent
 *  does). The ssh config twin is LONGER than its file (a placeholder is
 *  longer than the token), the store's twin longer too. */
const SIZED_SCRIPT = String.raw`
set -u
cd "$HOME"
for f in .git-credentials .ssh/config; do
  t=$(echo "$f" | /usr/bin/tr -c 'a-z\n' '_')
  git diff --no-index /dev/null "$f" 2>&1 | tag "DIFF$t"
  git grep --no-index -h -e '' "$f" 2>&1 | tag "GREP$t"
  /bin/cat "$f" | tag "CAT$t"
  python3 -c 'import os,sys; p=sys.argv[1]; n=os.lstat(p).st_size; f=open(p,"rb",buffering=0); b=f.read(n); print(n, len(b), len(f.read()), os.stat(p).st_size, os.fstat(f.fileno()).st_size)' "$f" 2>&1 | tag "PY$t"
done
echo "AGENT_DONE"
`;

for (const posture of ["bind", "guard-only"] as const) {
  test(
    `LIVE (${posture}): a reader that sizes its read by a stat of the path (git diff/grep --no-index, Python lstat + read) reads every twin whole`,
    { skip: GATE, timeout: 300_000 },
    async () => {
      await withStack(async ({ tmp, workspace, home, launcherEnv }) => {
        for (const [rel, content] of Object.entries(FILES)) {
          mkdirSync(dirname(join(home, rel)), { recursive: true, mode: 0o700 });
          writeFileSync(join(home, rel), content.replace("__HOME__", home), { mode: 0o600 });
        }
        const script = join(tmp, "agent.sh");
        writeFileSync(script, `exec bash ${join(tmp, "sized.sh")}\n`);
        writeFileSync(join(tmp, "sized.sh"), `tag() { /usr/bin/sed "s/^/$1 /"; }\n${SIZED_SCRIPT}`);
        const env = { ...launcherEnv("https://127.0.0.1:1", 0), HOME: home };
        const args = ["--no-scope", "--no-mcp", "--no-reply-filter", "--target", "claude"];
        if (posture === "guard-only") args.push("--no-secret-bind");
        const r = await runLauncher([...args, "--", "/bin/sh", script], env, workspace, 240_000);
        const out = r.out;
        const diag = `\n--- launch output (tail) ---\n${out.slice(-6000)}`;
        const tagged = (t: string): string[] => out.split("\n").filter((l) => l.startsWith(`${t} `)).map((l) => l.slice(t.length + 1));

        assert.equal(r.code, 0, `the launch failed${diag}`);
        assert.ok(out.includes("AGENT_DONE"), `the agent's script did not finish${diag}`);
        assert.ok(/confidentiality — \d+ secret\(s\) confined/.test(out), `the twins engaged${diag}`);
        assert.ok(/net-guard LIVE/.test(out), `the guard engaged${diag}`);
        if (posture === "guard-only") assert.ok(/bind mount SKIPPED \(--no-secret-bind\)/.test(out), `the guard-only posture${diag}`);
        // THE LEAK ORACLE first.
        for (const c of CANARIES) assert.ok(!out.includes(c), `${c} reached the agent's world${diag}`);

        for (const t of ["_git_credentials", "_ssh_config"]) {
          const cat = tagged(`CAT${t}`);
          assert.ok(cat.length > 0 && cat.some((l) => l.includes("$MDU:")), `cat printed the twin of ${t}: ${cat.join(" | ")}${diag}`);
          // git diff: every line of the twin, whole, and no line cut short.
          const diff = tagged(`DIFF${t}`);
          const added = diff.filter((l) => l.startsWith("+") && !l.startsWith("+++")).map((l) => l.slice(1));
          assert.deepEqual(added, cat, `git diff --no-index printed the twin of ${t} whole: ${diff.join(" | ")}${diag}`);
          assert.ok(!diff.some((l) => l.includes("No newline at end of file")), `git diff saw no cut twin (${t}): ${diff.join(" | ")}${diag}`);
          assert.deepEqual(tagged(`GREP${t}`), cat, `git grep --no-index printed the twin of ${t} whole${diag}`);
          // Python: lstat size == the bytes read == stat == fstat; nothing past it.
          const py = (tagged(`PY${t}`)[0] ?? "").split(" ").map(Number);
          assert.equal(py.length, 5, `python ran: ${tagged(`PY${t}`).join(" | ")}${diag}`);
          const [lsize, got, rest, ssize, fsize] = py as [number, number, number, number, number];
          assert.equal(got, lsize, `read(lstat size) returned exactly lstat's size (${t}): ${py}${diag}`);
          assert.equal(rest, 0, `nothing past lstat's size (${t}): ${py}${diag}`);
          assert.equal(ssize, lsize, `stat and lstat of the path agree (${t}): ${py}${diag}`);
          assert.equal(fsize, lsize, `the path's size is the descriptor's (${t}): ${py}${diag}`);
          assert.equal(lsize, Buffer.byteLength(cat.join("\n") + "\n"), `the size is the twin's (${t}): ${py}${diag}`);
        }
        console.error(`twin-format-fidelity (${posture}): git diff/grep --no-index and python lstat+read read both twins whole`);
      }, { mode: "secrets" });
    },
  );
}
