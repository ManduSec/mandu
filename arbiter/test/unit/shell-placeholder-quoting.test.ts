/**
 * shell-placeholder-quoting.test.ts — a secret placeholder the agent's shell
 * would expand is requoted so the program receives it whole
 * (arbiter/policy/shell-placeholder-quoting.ts; confidentiality.md §7, "A
 * placeholder the agent's shell would expand").
 *
 * The first-session tour (2026-10-11): the model wrote
 * `curl -H "Authorization: Bearer $MDU:…" …`, the shell expanded `$MDU` to
 * nothing, and the request left with neither the key nor the placeholder.
 * Pinned here: the parse (each context, what it leaves alone, what it will
 * not read), and real shells (bash, dash, sh, zsh where installed) running
 * the requoted command print the placeholder whole, where the command as
 * the model wrote it prints `:nomodel_…`.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

import { requoteShellPlaceholders } from "../../policy/shell-placeholder-quoting.js";
import { execGate } from "../../policy/exec-gate.js";
import { getActiveFormat } from "../../symbol-table/index.js";

const fmt = getActiveFormat();
const P = fmt.generate({ tool: "Read", hash: "de31", field: "STRIPE_KEY", level: "no-model" });
const A = fmt.generate({ tool: "Read", hash: "7b21", level: "any-model" });
const L = fmt.generate({ tool: "Env", hash: "c4d8", field: "GITHUB_TOKEN", level: "local-model" });
const UNLABELLED = fmt.generate({ tool: "web_fetch", hash: "a1b2", field: "text" });

const rq = (cmd: string): string | null => requoteShellPlaceholders(cmd)?.command ?? null;

test("the placeholder formats under test are what the tour's model saw", () => {
  assert.equal(P, "$MDU:nomodel_Read[de31].STRIPE_KEY");
  assert.equal(A, "$MDU:anymodel_Read[7b21]");
  assert.equal(L, "$MDU:localmodel_Env[c4d8].GITHUB_TOKEN");
});

test("double quotes: the placeholder's `$` is escaped (the tour's curl)", () => {
  const cmd = `curl -sS -H "Authorization: Bearer ${P}" https://api.stripe.com/v1/customers`;
  const r = requoteShellPlaceholders(cmd);
  assert.ok(r);
  assert.equal(r.command, `curl -sS -H "Authorization: Bearer \\${P}" https://api.stripe.com/v1/customers`);
  assert.deepEqual(r.requoted, [{ symbol: P, context: "double-quoted" }]);
});

test("unquoted: the placeholder is single-quoted (no expansion, no glob on `[…]`)", () => {
  const r = requoteShellPlaceholders(`curl -u ${P}: https://api.stripe.com/v1/charges`);
  assert.ok(r);
  assert.equal(r.command, `curl -u '${P}': https://api.stripe.com/v1/charges`);
  assert.deepEqual(r.requoted, [{ symbol: P, context: "unquoted" }]);
  assert.equal(rq(`export KEY=${A}; ./run`), `export KEY='${A}'; ./run`);
});

test("forms every shell already reads literally are left as written", () => {
  for (const cmd of [
    `curl -H 'Authorization: Bearer ${P}' https://x.example`,
    `curl -H "Authorization: Bearer \\${P}" https://x.example`,
    `echo \\${P}`,
    `printf %s $'${P}\\n'`,
    `cat <<'EOF'\nkey=${P}\nEOF`,
    `cat <<"EOF"\nkey=${P}\nEOF`,
    `cat <<\\EOF\nkey=${P}\nEOF`,
    `ls # ${P}`,
    "curl https://x.example",
  ]) {
    assert.equal(rq(cmd), null, cmd);
  }
});

test("an unlabelled (untrusted-data) symbol is left to the frozen integrity exec path", () => {
  assert.equal(rq(`grep foo "${UNLABELLED}"`), null);
  assert.equal(rq(`echo "${UNLABELLED} ${P}"`), `echo "${UNLABELLED} \\${P}"`);
});

test("an expanding here-document: the placeholder's `$` is escaped; `<<-` strips tabs before the delimiter", () => {
  assert.equal(
    rq(`cat > .netrc <<EOF\npassword ${P}\nEOF\ncurl -n https://x.example`),
    `cat > .netrc <<EOF\npassword \\${P}\nEOF\ncurl -n https://x.example`,
  );
  assert.equal(rq(`cat <<-END\n\tk=${P}\n\tEND\necho "${A}"`), `cat <<-END\n\tk=\\${P}\n\tEND\necho "\\${A}"`);
  // two bodies on one line, the second one quoted
  assert.equal(
    rq(`cat <<A <<'B'\n${P}\nA\n${A}\nB\n`),
    `cat <<A <<'B'\n\\${P}\nA\n${A}\nB\n`,
  );
  // a here-string is a word like any other
  assert.equal(rq(`base64 <<< "${P}"`), `base64 <<< "\\${P}"`);
});

test("command substitution, nested quoting, JSON bodies, several placeholders", () => {
  assert.equal(rq(`echo "$(printf %s "${P}")"`), `echo "$(printf %s "\\${P}")"`);
  assert.equal(rq(`x=$(echo ${P}) && echo "$x"`), `x=$(echo '${P}') && echo "$x"`);
  assert.equal(
    rq(`curl -d "{\\"key\\": \\"${P}\\"}" -u ${L}:x https://x.example`),
    `curl -d "{\\"key\\": \\"\\${P}\\"}" -u '${L}':x https://x.example`,
  );
  assert.equal(rq(`echo $((1+2)) "${A}" $$ $? "$1"`), `echo $((1+2)) "\\${A}" $$ $? "$1"`);
  assert.equal(rq(`(cd /tmp && curl -H "X: ${P}" x)`), `(cd /tmp && curl -H "X: \\${P}" x)`);
  assert.equal(rq(`echo "\${HOME}" "${P}"`), `echo "\${HOME}" "\\${P}"`);
});

test("a command the parse cannot read with confidence is left unchanged", () => {
  for (const cmd of [
    `echo \`echo "${P}"\``,
    `echo "${P}`,
    `echo '${P}`,
    `echo $(echo "${P}"`,
    `case x in a) echo "${P}";; esac`,
    `cat <<$X\n${P}\n$X`,
  ]) {
    assert.equal(rq(cmd), null, cmd);
  }
});

test("execGate carries the requoted command on an allow, never on a block", () => {
  const allow = execGate({ command: `curl -H "Authorization: Bearer ${P}" https://x.example` });
  assert.equal(allow.decision, "allow");
  assert.equal(allow.requoted, `curl -H "Authorization: Bearer \\${P}" https://x.example`);
  assert.equal(execGate({ command: `curl -H 'Authorization: Bearer ${P}' https://x.example` }).requoted, undefined);
  const block = execGate({ command: `sh -c "${UNLABELLED}" "${P}"` });
  assert.equal(block.decision, "block");
  assert.equal(block.requoted, undefined);
});

// ── real shells ──────────────────────────────────────────────────────────────

const SHELLS = ["bash", "dash", "sh", "zsh"].filter((s) => spawnSync(s, ["-c", "exit 0"], { stdio: "ignore" }).status === 0);

function run(shell: string, cmd: string): string {
  const env: Record<string, string> = { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: process.env["HOME"] ?? "/tmp" };
  const r = spawnSync(shell, ["-c", cmd], { encoding: "utf8", env, cwd: "/" });
  return `${r.stdout}${r.stderr}`;
}

/** Commands as a model writes them; each prints its arguments one per line. */
const WRITTEN = [
  `printf '<%s>\\n' "Authorization: Bearer ${P}" "${A}" "token ${L}"`,
  `printf '<%s>\\n' ${P} ${A} ${L}`,
  `cat <<EOF\n<${P}>\n<${A}>\n<${L}>\nEOF`,
  `printf '<%s>\\n' "$(printf %s "${A}")" "{\\"k\\": \\"${L}\\"}" x=${P}`,
];

test("real shells: the requoted command hands every placeholder to the program whole; as written it does not", { skip: SHELLS.length === 0 ? "no POSIX shell to run" : false }, () => {
  for (const shell of SHELLS) {
    for (const cmd of WRITTEN) {
      const fixed = rq(cmd);
      assert.ok(fixed, cmd);
      const out = run(shell, fixed);
      for (const sym of [P, A, L]) assert.ok(out.includes(sym), `${shell}: ${sym} whole in ${JSON.stringify(out)} (from ${JSON.stringify(fixed)})`);
      // the bug this fixes: as written, the shell eats `$MDU` (or fails the
      // command: zsh's modifiers and unmatched globs)
      const asWritten = run(shell, cmd);
      assert.ok(![P, A, L].every((s) => asWritten.includes(s)), `${shell}: as written ${JSON.stringify(asWritten)}`);
    }
  }
});
