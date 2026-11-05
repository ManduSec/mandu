/**
 * twin-write-targets.test.ts — the files a shell command WRITES, read off the
 * model's own command (twin-write-targets.ts; plan 10 §4.1, "The model is told
 * at the call", 2026-10-27): every write shape the live drill used (a heredoc
 * redirect, `sed -i`, `cp` onto the file), the other writers, and what is no
 * write (a read, a heredoc body's `>`, a descriptor, `/dev/null`, `cp -t`).
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { TWIN_WRITE_TARGETS_MAX, shellWriteTargets, withoutHeredocBodies } from "../../policy/twin-write-targets.js";

test("the drill's three writes of orders-app/.env (demo-orders-sync-debug, 2026-10-27)", () => {
  assert.deepEqual(shellWriteTargets("cat > orders-app/.env << 'EOF'\nORDERHUB_URL=https://api.orderhub.test\nORDERHUB_PASSWORD='$MDU:nomodel_Read[a169].ORDERHUB_PASSPHRASE'\nEOF\n"), ["orders-app/.env"]);
  // sed's script is an operand too; the server keeps only a registered file
  assert.deepEqual(shellWriteTargets("sed -i 's/ORDERHUB_PASSPHRASE/ORDERHUB_PASSWORD/' orders-app/.env"), ["s/ORDERHUB_PASSPHRASE/ORDERHUB_PASSWORD/", "orders-app/.env"]);
  assert.deepEqual(shellWriteTargets("cat orders-app/.env | sed 's/A/B/' > /tmp/.env.new && cp /tmp/.env.new orders-app/.env && rm /tmp/.env.new"), ["/tmp/.env.new", "orders-app/.env"]);
});

test("the other writers: append, tee, a quoted name, dd of=, perl -pi, truncate, mv / install / ln destinations, <>", () => {
  assert.deepEqual(shellWriteTargets("echo FEATURE=1 >> .env 2>&1"), [".env"]);
  assert.deepEqual(shellWriteTargets("printf 'x' | sudo tee -a conf/.env >/dev/null"), ["conf/.env"]);
  assert.deepEqual(shellWriteTargets("cd app && echo x >\"my .env\""), ["my .env"]);
  assert.deepEqual(shellWriteTargets("dd if=/dev/zero of=.env bs=1 count=0"), [".env"]);
  assert.deepEqual(shellWriteTargets("perl -pi -e 's/a/b/' .env"), ["s/a/b/", ".env"]);
  assert.deepEqual(shellWriteTargets("truncate -s 0 .env"), [".env"]);
  assert.deepEqual(shellWriteTargets("mv .env.new .env; install -m 600 x .env2; ln -sf a .env3"), [".env", ".env2", ".env3"]);
  assert.deepEqual(shellWriteTargets("exec 3<> .env"), [".env"]);
  assert.deepEqual(shellWriteTargets("FOO=1 env BAR=2 tee .env < in.txt"), [".env"]);
  assert.deepEqual(shellWriteTargets("echo x >| .env; echo y &> .env.log"), [".env", ".env.log"]);
});

test("no write: a read, an input redirect, a heredoc body's >, a descriptor, /dev/null, cp -t, a here-string, sed without -i", () => {
  assert.deepEqual(shellWriteTargets("cat .env"), []);
  assert.deepEqual(shellWriteTargets("grep KEY < .env"), []);
  assert.deepEqual(shellWriteTargets("cat <<EOF\nKEY=1 > .env\nEOF"), []);
  assert.deepEqual(shellWriteTargets("ls 2>&1 >&2; echo x > /dev/null"), []);
  assert.deepEqual(shellWriteTargets("cp -t dir .env"), []);
  assert.deepEqual(shellWriteTargets("cat <<< '.env'"), []);
  assert.deepEqual(shellWriteTargets("sed 's/a/b/' .env"), []);
  assert.deepEqual(shellWriteTargets("cp .env"), [], "one operand: no destination");
  assert.deepEqual(shellWriteTargets(""), []);
});

test("heredocs: quoted, unquoted and <<- bodies are dropped up to their delimiter; the commands after them are read", () => {
  assert.equal(withoutHeredocBodies("cat > a << 'EOF'\nx > b\nEOF\necho y > c"), "cat > a  \necho y > c");
  assert.deepEqual(shellWriteTargets("cat <<-EOF > x.env\n\tA=1 > y\n\tEOF\necho done > z"), ["x.env", "z"]);
  assert.deepEqual(shellWriteTargets('cat > a <<"END"\n> b\nEND'), ["a"]);
  // an unterminated heredoc swallows the rest: nothing after it is read
  assert.deepEqual(shellWriteTargets("cat > a << EOF\n> b\n> c"), ["a"]);
});

test("bounds: each target once, at most TWIN_WRITE_TARGETS_MAX", () => {
  assert.deepEqual(shellWriteTargets("echo a > x; echo b > x"), ["x"]);
  const many = Array.from({ length: 20 }, (_v, i) => `echo ${i} > f${i}`).join("; ");
  assert.equal(shellWriteTargets(many).length, TWIN_WRITE_TARGETS_MAX);
});
