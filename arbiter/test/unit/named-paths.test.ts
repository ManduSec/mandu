/**
 * named-paths.test — the classify verdict's `namedPaths` (confidentiality.md
 * §7.1, "the path-derived note", 2026-10-05): when a call's own input names a
 * secret path, the tokens that did so, as written there, so the model proxy
 * can name them in the note on a result masked whole by that path alone.
 * Only secret tokens, only when the level is secret, absent otherwise; the
 * proxy keeps only those its model's own command holds verbatim.
 *
 * Run: npx tsx --test test/unit/named-paths.test.ts
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { labelForClassify, type LabelLookup } from "../../policy/secret-catalog.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { CODEX_WORKDIR_TOOLS } from "../../policy/tool-gate-surface.js";
import { ArbiterServer } from "../../ipc/server.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality derivation is the code under test

const HOME = "/home/u";
const TOUR = 'set -a && . ./.env && set +a && curl -sS https://api.stripe.com/v1/customers -u "$STRIPE_KEY:"';
const bash = (command: string, callStartDir?: string) =>
  ({ tool: "Bash", origin: command, params: { command }, ...(callStartDir !== undefined ? { callStartDir } : {}) });

function lookupOver(...rows: Array<Partial<PathLabel> & { path: string }>): LabelLookup {
  const m = new Map<string, PathLabel>();
  for (const r of rows) {
    m.set(r.path, { path: r.path, confidentiality: r.confidentiality ?? "no-model", bindings: [], recursive: r.recursive ?? true, source: "user", updatedAt: 1 });
  }
  return (p) => resolvePathLabel(p, m, HOME);
}

test("the tour's command: ./.env, as the command wrote it", () => {
  const l = labelForClassify(bash(TOUR), HOME);
  assert.equal(l.level, "no-model");
  assert.deepEqual(l.paths, ["./.env"]);
});

test("every secret token, once, in order; a public token and a plain word are not named", () => {
  assert.deepEqual(labelForClassify(bash("cat .env ~/.aws/credentials notes.md .env"), HOME).paths, [".env", "~/.aws/credentials"]);
  const lk = lookupOver({ path: "/home/u/proj/test/fixtures/.env", confidentiality: "public", recursive: false });
  const mixed = labelForClassify(bash("cat test/fixtures/.env .env", "/home/u/proj"), HOME, lk);
  assert.equal(mixed.level, "no-model");
  assert.deepEqual(mixed.paths, [".env"], "the human's public fixture is not named");
});

test("a bare word read under a labelled directory sets the level but is not named; a path-shaped token is", () => {
  const lk = lookupOver({ path: "/home/u/proj", confidentiality: "no-model" });
  const l = labelForClassify({ tool: "exec_command", origin: "cat notes.md", params: { cmd: "cat notes.md", workdir: "/home/u/proj" }, workdirTools: CODEX_WORKDIR_TOOLS }, HOME, lk);
  assert.equal(l.level, "no-model");
  assert.deepEqual(l.paths, ["notes.md"], "`cat` is not a file the command names");
  assert.deepEqual(labelForClassify({ tool: "exec_command", origin: "ls -la", params: { cmd: "ls -la", workdir: "/home/u/proj" }, workdirTools: CODEX_WORKDIR_TOOLS }, HOME, lk).paths, []);
});

test("a public verdict names nothing; a shell call's command given only as its origin (Codex's `cmd`) is read too", () => {
  assert.deepEqual(labelForClassify(bash("ls -la"), HOME).paths, []);
  const lk = lookupOver({ path: "/home/u/proj/test/fixtures/.env", confidentiality: "public", recursive: false });
  assert.deepEqual(labelForClassify(bash("cat test/fixtures/.env", "/home/u/proj"), HOME, lk).paths, []);
  const codex = labelForClassify({ tool: "exec_command", origin: TOUR, params: { cmd: TOUR } }, HOME);
  assert.equal(codex.level, "no-model");
  assert.deepEqual(codex.paths, ["./.env"]);
});

test("the classify op carries namedPaths only with a secret level, and not at all with the axis off", async () => {
  for (const confidentiality of [true, false]) {
    const dir = mkdtempSync(join(tmpdir(), "mandu-named-paths-"));
    const server = new ArbiterServer({ socketPath: join(dir, "a.sock"), dbPath: join(dir, "s.db"), eventDir: join(dir, "ev"), log: () => {}, confidentiality });
    try {
      const classify = (command: string) => (server.dispatch({
        id: "t", op: "classify",
        request: { tool: "Bash", value: "out", boundary: "model_context", origin: command, params: { command } },
      }) as { ok: boolean; result: { confidentiality?: string; namedPaths?: string[] } }).result;
      const tour = classify(TOUR);
      const plain = classify("ls -la");
      if (confidentiality) {
        assert.equal(tour.confidentiality, "no-model");
        assert.deepEqual(tour.namedPaths, ["./.env"]);
      } else {
        assert.equal(tour.namedPaths, undefined, "axis off: no confidentiality field and no namedPaths");
      }
      assert.equal(plain.namedPaths, undefined);
    } finally {
      await server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
