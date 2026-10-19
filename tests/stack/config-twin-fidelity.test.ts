/**
 * config-twin-fidelity — the leak oracle for the configuration twins of
 * plan 10 §11.13 (2026-10-02), over the REAL arbiter and the anthropic-proxy
 * through its production adapter (`new ArbiterClientAdapter(new
 * ArbiterClient(sock))`).
 *
 * A developer-shaped HOME: an `~/.ssh/config` with a `SetEnv` token and a
 * `ProxyCommand` holding a password no rule names (§11.13.2: masked whole;
 * a vetted jump command stays), an `Include`d `~/.ssh/config.d/plain` with
 * no secret, a `~/.ssh/known_hosts`, a `pip.conf` whose index URL carries a
 * password and whose extra index carries a token in its PATH, a plain
 * `pip.conf`, and a `~/.git-credentials` (with a token written as the user
 * beside a dummy password, and a note line). The twins are format-preserving (ssh and pip parse
 * them; the sandbox suite twin-format-fidelity runs the programs), git's
 * `store` helper, its known consumer and a printer since 2026-10-04 (plan
 * 13 §4.9), reads the twin like any other program, and:
 *   - no twin carries a secret byte, and a twin printed by a program the
 *     guard served it to reaches the model with only symbols where the
 *     secrets were;
 *   - the raw text of any of these files reaches the model as one symbol;
 *   - git's output carrying the store's raw text (as if it had read the
 *     real store) reaches the model as one symbol, however twin-like it
 *     looks;
 *   - an exhaustive file with no secret reaches the model as its text
 *     through a `cat` (plan 10 §11.13, 2026-10-17; it was one handle);
 *   - `known_hosts` is public material: not registered, read raw;
 *   - a withheld ssh command (§11.13.3) is Mandu's refusal in the twin: run
 *     the way ssh runs a `ProxyCommand` (real ssh when installed), it prints
 *     which line of which file was withheld, why and the way out, and that
 *     output reaches the model as printed, with no canary and no word of the
 *     withheld command;
 *   - an `~/.npmrc` whose `_password` twin holds its token ENCODED (base64,
 *     plan 10 §11.13.1) printed by `cat` is recognized as the twin and
 *     released as it is, with no form of the password in it.
 * Axes stated: `secrets` (confidentiality ON, integrity OFF), pinned on the
 * server too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { rewriteRequest } from "../../interceptors/anthropic-proxy/src/rewrite-request.js";
import type { MessagesRequest } from "../../interceptors/anthropic-proxy/src/messages-types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const SSH_TOKEN = "sshenv_CANARY_7f3e9a1c55";
const PIP_PW = "pippw_CANARY_0b2d4e6f88";
const GIT_PW = "gitpw_CANARY_93ac1e7b20";
// Plan 10 §11.13.2 (fail closed): values the extractor once left raw because
// no rule classified them as secret.
const SSH_PROXY_PW = "proxypwCANARY5e0b7c2d19";
const PIP_PATH_TOKEN = "pathtokCANARY4a9c1e6f02";
const GIT_TOKEN_USER = "tokuserCANARY7d2e9f04ab";
const GIT_NOTE = "notepwCANARY0f3a8b6c71";
// Plan 10 §11.13.1 (2026-10-03): npm's `_password` (base64 in the file and,
// of its symbol, in the twin). The file's other line is shorter than the
// value backstop's line fingerprint (24), so only the twin rule decides.
const NPM_PW = "npmpwCANARY2c7e1a9f3b";
const CANARIES = [SSH_TOKEN, PIP_PW, GIT_PW, SSH_PROXY_PW, PIP_PATH_TOKEN, GIT_TOKEN_USER, GIT_NOTE, NPM_PW, Buffer.from(NPM_PW).toString("base64")];

const FILES: Record<string, string> = {
  ".ssh/config": `Include config.d/*\nHost ci\n  HostName 127.0.0.1\n  User builder\n  SetEnv CI_TOKEN=${SSH_TOKEN}\nHost db\n  ProxyCommand mysql -p${SSH_PROXY_PW} -h %h\nHost jump\n  ProxyCommand ssh -W %h:%p bastion\n`,
  ".ssh/config.d/plain": "Host bastion\n  HostName 10.9.8.7\n  User deploy\n",
  ".ssh/known_hosts": "known.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnownHostPublicKeyMaterial0000000000\n",
  ".config/pip/pip.conf": `[global]\nindex-url = https://__token__:${PIP_PW}@pypi.corp.example/simple\nextra-index-url = https://pypi.fury.io/${PIP_PATH_TOKEN}/acme/\n`,
  ".pip/pip.conf": "[global]\ntimeout = 60\n",
  ".git-credentials": `https://builder:${GIT_PW}@git.example.com\nhttps://${GIT_TOKEN_USER}:x-oauth-basic@github.com\n# ${GIT_NOTE}\n`,
  ".npmrc": `//r.ex/:username=me\n//r.ex/:_password=${Buffer.from(NPM_PW).toString("base64")}\n`,
};

function bash(command: string, content: string, id: string): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "check my configuration" },
      { role: "assistant", content: [{ type: "tool_use", id, name: "Bash", input: { command } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] },
    ],
  };
}
const forwarded = (r: MessagesRequest): string => ((r.messages[2]!.content as any[])[0].content as string);

/** One symbol, and at most the path-derived note the proxy writes from the
 *  command (confidentiality.md §7.1, 2026-10-05): never an output byte. */
const ONE_SYMBOL = /^\$MDU:nomodel_Bash\[[0-9a-f]{4,8}\](?:\n\n\[mandu:secret\] masked: (?:the command names|this output contains the value of a registered secret)[^\n]*)?$/;

test("configuration twins: none holds a secret, a served twin reaches the model with symbols only, raw text and a reader's output are one symbol, known_hosts is public (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-config-twin-"));
  const home = join(tmp, "home");
  for (const [rel, content] of Object.entries(FILES)) {
    mkdirSync(dirname(join(home, rel)), { recursive: true });
    writeFileSync(join(home, rel), content);
  }
  const p = (rel: string): string => join(home, rel);
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: join(tmp, "human", "h.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const guard = new ArbiterClient(join(tmp, "human", "h.sock")); await guard.connect(); // the guard reports on the human socket (plan 13 D9)
  const realHuman = new ArbiterClient(join(tmp, "human", "h.sock")); await realHuman.connect(); // the proxies' second client (server-main)
  const real: RealArbiterClient = new ArbiterClient(socketPath); await real.connect();
  const claude = new ArbiterClientAdapter(real, realHuman);
  const session = "s-config-twin";
  try {
    // ── registration: the launcher's call, with the session's HOME ──────────
    const reg: Record<string, Awaited<ReturnType<ArbiterClient["registerSecret"]>>> = {};
    for (const rel of Object.keys(FILES)) reg[rel] = await guard.registerSecret({ path: p(rel), home, sessionKey: session });
    assert.equal(reg[".ssh/known_hosts"]!.symbol, null, "known_hosts holds public material: not registered");
    for (const rel of [".ssh/config", ".ssh/config.d/plain", ".config/pip/pip.conf", ".pip/pip.conf", ".git-credentials"]) {
      assert.ok(reg[rel]!.symbol, `${rel} registers: ${reg[rel]!.reason}`);
      assert.equal(typeof reg[rel]!.twin, "string", `${rel} has a format-preserving twin: ${reg[rel]!.reason}`);
    }
    assert.equal(reg[".ssh/config.d/plain"]!.twin, FILES[".ssh/config.d/plain"], "an ssh config with no secret is its own twin");
    assert.equal(reg[".pip/pip.conf"]!.twin, FILES[".pip/pip.conf"], "a pip.conf with no credential is its own twin");
    assert.match(reg[".ssh/config"]!.twin!, /SetEnv CI_TOKEN=\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.ci\.CI_TOKEN\n/);
    // A URL's password is percent-encoded in a pip.conf twin (pip decodes it;
    // plan 10 §11.13.1).
    assert.match(reg[".config/pip/pip.conf"]!.twin!, /https:\/\/__token__:%24MDU%3Anomodel_Read%5B[0-9a-f]{4,8}%5D\.global\.pypi\.corp\.example\.password@pypi\.corp\.example/);
    assert.match(reg[".git-credentials"]!.twin!, /^https:\/\/builder:\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.git\.git\.example\.com\.password@git\.example\.com\n/);
    // §11.13.2: what no rule vouches for is a symbol, and the rest stays.
    // §11.13.3: a ProxyCommand off the relay grammar is withheld: Mandu's
    // refusal command in its place, the field symbol riding along unused.
    assert.match(reg[".ssh/config"]!.twin!, /\n  ProxyCommand \/bin\/sh -c '[^']*' '\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.db\.ProxyCommand' 'mandu: ~\/\.ssh\/config line 7: ProxyCommand withheld [^'\n]*'( '[^'\n]*')*\n/, "a ProxyCommand off the relay grammar is withheld with a refusal");
    assert.ok(!reg[".ssh/config"]!.twin!.includes("mysql"), "no word of the withheld command");
    assert.ok(reg[".ssh/config"]!.twin!.includes("  ProxyCommand ssh -W %h:%p bastion\n"), "a vetted ProxyCommand stays");
    assert.match(reg[".config/pip/pip.conf"]!.twin!, /https:\/\/pypi\.fury\.io\/\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.global\.pypi\.fury\.io\.path\/acme\//, "a token in an index URL's path is a symbol");
    assert.match(reg[".git-credentials"]!.twin!, /\nhttps:\/\/\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.git\.github\.com\.user:\$MDU:nomodel_Read\[[0-9a-f]{4,8}\]\.git\.github\.com\.password@github\.com\n\$MDU:/, "a token user is a symbol, and a note (no URL) is masked whole");
    // THE ORACLE, part 1: no twin carries a secret byte.
    for (const [rel, r] of Object.entries(reg)) {
      for (const c of CANARIES) assert.ok(!(r.twin ?? "").includes(c), `${rel}: the twin carries ${c}`);
    }

    // ── the guard's opens (decideSecretOpen) ────────────────────────────────
    const gitOpen = await guard.decideSecretOpen({ path: p(".git-credentials"), exe: "/usr/bin/git", isAgent: false, exeSystem: true, openerEnv: [], procKey: "git-1", session, ask: "known" });
    // Plan 13 §4.9 option (a) (2026-10-04): git is a printer, so its store
    // helper reads the twin too (no wire release here; with it, the session
    // proxy puts the password back at its host).
    assert.equal(gitOpen.verdict, "twin", `git's store helper reads the twin: ${gitOpen.reason}`);
    assert.match(String(gitOpen.reason), /prints or copies/);
    const catOpen = await guard.decideSecretOpen({ path: p(".git-credentials"), exe: "/usr/bin/cat", isAgent: false, exeSystem: true, openerEnv: [], procKey: "cat-1", session, ask: "known" });
    assert.equal(catOpen.verdict, "twin", catOpen.reason);
    const agentOpen = await guard.decideSecretOpen({ path: p(".git-credentials"), exe: "/usr/bin/git", isAgent: true, exeSystem: true, openerEnv: [], procKey: "agent-1", session, ask: "known" });
    assert.equal(agentOpen.verdict, "twin", "the agent's own process never reads raw");

    // ── the model boundary ──────────────────────────────────────────────────
    // A twin with symbols, printed by `cat` (served the twin, no taint):
    // released with its symbols, no canary. Each Bash call runs in a shell
    // of the agent's own, as the guard reports it (the call-root recorder,
    // plan 13 D7), with the program under it.
    let roots = 0;
    // Plan 13 D9 follow-up: first the proxy's record of the call's delivered
    // command (its response side), which the call is bound by.
    const shellFor = async (command: string, child: string, callId: string): Promise<void> => {
      const root = `sh-${++roots}`;
      await claude.recordCallCommand!({ callId, command, sessionKey: session });
      await guard.recordExecRoot({ procKey: root, ancestors: ["agent-0"], argv: ["/bin/bash", "-c", command], session, callRoot: true });
      await guard.processLineage({ childKey: child, parentKey: root, session });
    };
    let n = 0;
    for (const rel of [".ssh/config", ".config/pip/pip.conf", ".git-credentials"]) {
      const id = `toolu_twin_${++n}`;
      await shellFor(`cat ${p(rel)}`, "cat-1", id);
      const r = await rewriteRequest(bash(`cat ${p(rel)}`, reg[rel]!.twin!, id), { arbiter: claude, sessionKey: session });
      const f = forwarded(r.request);
      for (const c of CANARIES) assert.ok(!f.includes(c), `${rel}: the model got ${c}`);
      assert.match(f, /\$MDU:nomodel_/, `${rel}: the model sees a symbol where the secret was`);
    }
    // The raw text (a program the guard did not serve): one symbol, no canary.
    for (const rel of [".ssh/config", ".config/pip/pip.conf", ".git-credentials"]) {
      const id = `toolu_raw_${++n}`;
      await shellFor(`cat ${p(rel)}`, "cat-1", id);
      const r = await rewriteRequest(bash(`cat ${p(rel)}`, FILES[rel]!, id), { arbiter: claude, sessionKey: session });
      assert.equal(r.rewrites[0]!.symbolized, true, `${rel}: ${r.rewrites[0]!.reason}`);
      assert.match(forwarded(r.request), ONE_SYMBOL, rel);
    }
    // git's output carrying the raw store (it reads the twin since
    // 2026-10-04; the raw form here is the worst case): one symbol, whatever
    // it looks like.
    const fillCmd = "printf 'protocol=https\\nhost=git.example.com\\n\\n' | git credential fill";
    await shellFor(fillCmd, "git-1", "toolu_git_fill");
    const fill = await rewriteRequest(
      bash(fillCmd, `protocol=https\nhost=git.example.com\nusername=builder\npassword=${GIT_PW}\n`, "toolu_git_fill"),
      { arbiter: claude, sessionKey: session },
    );
    assert.equal(fill.rewrites[0]!.symbolized, true, fill.rewrites[0]!.reason);
    assert.ok(!forwarded(fill.request).includes(GIT_PW), "the reader's output never reaches the model raw");
    // Plan 10 §11.13.1: a twin whose token is ENCODED (npm's `_password` as
    // the base64 of its symbol) printed by `cat` is still recognized as the
    // file's twin and released as it is; no form of the password is in it.
    const npmId = "toolu_twin_npmrc";
    await shellFor(`cat ${p(".npmrc")}`, "cat-1", npmId);
    const npm = await rewriteRequest(bash(`cat ${p(".npmrc")}`, reg[".npmrc"]!.twin!, npmId), { arbiter: claude, sessionKey: session });
    const npmOut = forwarded(npm.request);
    assert.equal(npmOut, reg[".npmrc"]!.twin!, `the npmrc twin (base64 token) reaches the model as the twin: ${JSON.stringify(npm.rewrites)}`);
    for (const f of [NPM_PW, Buffer.from(NPM_PW).toString("base64")]) assert.ok(!npmOut.includes(f), "no form of the npm password");
    // Its raw text is one symbol, as for every other file here.
    await shellFor(`cat ${p(".npmrc")}`, "cat-1", "toolu_raw_npmrc");
    const npmRaw = await rewriteRequest(bash(`cat ${p(".npmrc")}`, FILES[".npmrc"]!, "toolu_raw_npmrc"), { arbiter: claude, sessionKey: session });
    assert.match(forwarded(npmRaw.request), ONE_SYMBOL);
    // An exhaustive file with no secret (plan 10 §11.13, 2026-10-17): its
    // twin is its own text, and the model reads it too, with the twin line
    // (it used to get one handle). tests/stack/own-text-config-twin.test.ts
    // holds the negatives.
    await shellFor(`cat ${p(".pip/pip.conf")}`, "cat-1", "toolu_plain");
    const plain = await rewriteRequest(bash(`cat ${p(".pip/pip.conf")}`, FILES[".pip/pip.conf"]!, "toolu_plain"), { arbiter: claude, sessionKey: session });
    assert.equal(plain.rewrites[0]!.symbolized, false, `a no-secret config reaches the model as its text: ${plain.rewrites[0]!.reason}`);
    assert.ok(forwarded(plain.request).startsWith(FILES[".pip/pip.conf"]!), forwarded(plain.request));
    // A withheld command (§11.13.3), run as ssh runs a ProxyCommand: real
    // ssh over the twin when installed (the refusal fails before any
    // connect), else `sh -c "exec <command>"`, which is what ssh does.
    const twinFile = join(tmp, "ssh-config-twin");
    writeFileSync(twinFile, reg[".ssh/config"]!.twin!.replace(/^Include .*\n/, ""));
    const hasSsh = spawnSync("ssh", ["-V"], { encoding: "utf8" }).error === undefined;
    const sshRun = hasSsh
      ? spawnSync("ssh", ["-F", twinFile, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "db", "true"], { encoding: "utf8", timeout: 30_000 })
      : spawnSync("/bin/sh", ["-c", `exec ${/\n  ProxyCommand (.*)\n/.exec(reg[".ssh/config"]!.twin!)![1]!}`], { encoding: "utf8", timeout: 30_000 });
    const sshOut = `${sshRun.stdout}${sshRun.stderr}`;
    assert.notEqual(sshRun.status, 0, "the withheld host fails");
    assert.match(sshOut, /^mandu: ~\/\.ssh\/config line 7: ProxyCommand withheld from the programs the agent runs, so ssh cannot reach this host from inside the agent\.$/m, sshOut);
    assert.match(sshOut, /^mandu: why: .*would run code holding one/m, sshOut);
    assert.match(sshOut, /^mandu: way out: use ProxyJump .*script Mandu can pin.*run this ssh outside the agent\.$/m, sshOut);
    assert.doesNotMatch(sshOut, /\$MDU|mysql/, "neither the symbol nor the command is printed");
    await shellFor("ssh db true", "ssh-1", "toolu_ssh_withheld");
    const sshRes = await rewriteRequest(bash("ssh db true", sshOut, "toolu_ssh_withheld"), { arbiter: claude, sessionKey: session });
    const sshSeen = forwarded(sshRes.request);
    for (const c of CANARIES) assert.ok(!sshSeen.includes(c), `the model got ${c}`);
    assert.match(sshSeen, /mandu: ~\/\.ssh\/config line 7: ProxyCommand withheld/, `the model reads the notice and can relay it: ${sshSeen}`);
    assert.match(sshSeen, /mandu: way out:/);
    // known_hosts: public, read raw.
    await shellFor(`cat ${p(".ssh/known_hosts")}`, "cat-1", "toolu_known");
    const known = await rewriteRequest(bash(`cat ${p(".ssh/known_hosts")}`, FILES[".ssh/known_hosts"]!, "toolu_known"), { arbiter: claude, sessionKey: session });
    assert.equal(forwarded(known.request), FILES[".ssh/known_hosts"], "known_hosts reaches the model as it is");
  } finally {
    guard.close(); realHuman.close(); real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
