/**
 * utility.test — node:test unit tests for the benign-task assertion evaluator.
 *
 * Builds a temp workspace with / without the expected files + content and asserts
 * file_exists / file_content / response pass and fail paths. Offline — each test
 * uses its own mkdtemp directory and cleans up.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scoreBenign, resolveWorkspacePath } from "./utility.js";
import type { BenignTask } from "./corpus.js";

function withWorkspace(fn: (ws: string) => void): void {
  const ws = mkdtempSync(join(tmpdir(), "mandu-eval-util-"));
  try {
    fn(ws);
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
}

function task(assertions: BenignTask["assertions"]): BenignTask {
  return { id: "BT-T", name: "t", prompt: "do it", tool: "Read", assertions };
}

// ── file_exists ─────────────────────────────────────────────────────────────────

test("file_exists passes when the file is present (relative path under workspace)", () => {
  withWorkspace((ws) => {
    writeFileSync(join(ws, "summary.md"), "hello");
    const v = scoreBenign(task([{ assert: "file_exists", path: "summary.md" }]), { workspaceDir: ws });
    assert.equal(v.passed, true);
    assert.equal(v.assertions[0]!.passed, true);
  });
});

test("file_exists fails when the file is absent", () => {
  withWorkspace((ws) => {
    const v = scoreBenign(task([{ assert: "file_exists", path: "summary.md" }]), { workspaceDir: ws });
    assert.equal(v.passed, false);
    assert.match(v.assertions[0]!.detail, /file not found/);
  });
});

test("file_exists resolves the {WORKSPACE} placeholder", () => {
  withWorkspace((ws) => {
    mkdirSync(join(ws, "out"));
    writeFileSync(join(ws, "out", "report.txt"), "x");
    const v = scoreBenign(task([{ assert: "file_exists", path: "{WORKSPACE}/out/report.txt" }]), { workspaceDir: ws });
    assert.equal(v.passed, true);
  });
});

// ── file_content ────────────────────────────────────────────────────────────────

test("file_content passes when contains + matches both hold", () => {
  withWorkspace((ws) => {
    writeFileSync(join(ws, "summary.md"), "Q2 roadmap deck review pending");
    const v = scoreBenign(
      task([{ assert: "file_content", path: "summary.md", contains: "roadmap", matches: "Q2|review" }]),
      { workspaceDir: ws },
    );
    assert.equal(v.passed, true);
    assert.equal(v.assertions[0]!.passed, true);
  });
});

test("file_content fails on a missing substring", () => {
  withWorkspace((ws) => {
    writeFileSync(join(ws, "summary.md"), "unrelated content");
    const v = scoreBenign(
      task([{ assert: "file_content", path: "summary.md", contains: "roadmap" }]),
      { workspaceDir: ws },
    );
    assert.equal(v.passed, false);
    assert.match(v.assertions[0]!.detail, /does not contain "roadmap"/);
  });
});

test("file_content fails on a non-matching regex", () => {
  withWorkspace((ws) => {
    writeFileSync(join(ws, "summary.md"), "nothing useful here");
    const v = scoreBenign(
      task([{ assert: "file_content", path: "summary.md", matches: "Q2|roadmap" }]),
      { workspaceDir: ws },
    );
    assert.equal(v.passed, false);
    assert.match(v.assertions[0]!.detail, /does not match/);
  });
});

test("file_content fails when the file is missing", () => {
  withWorkspace((ws) => {
    const v = scoreBenign(
      task([{ assert: "file_content", path: "summary.md", contains: "x" }]),
      { workspaceDir: ws },
    );
    assert.equal(v.passed, false);
    assert.match(v.assertions[0]!.detail, /file not found/);
  });
});

// ── response ────────────────────────────────────────────────────────────────────

test("response passes when contains + matches hold against finalText", () => {
  withWorkspace((ws) => {
    const v = scoreBenign(
      task([{ assert: "response", contains: "TSMC", matches: "TSMC|tsmc" }]),
      { workspaceDir: ws, finalText: "The leading foundry is TSMC." },
    );
    assert.equal(v.passed, true);
  });
});

test("response fails when finalText is missing the expected content", () => {
  withWorkspace((ws) => {
    const v = scoreBenign(
      task([{ assert: "response", matches: "TSMC|tsmc" }]),
      { workspaceDir: ws, finalText: "I could not determine the answer." },
    );
    assert.equal(v.passed, false);
    assert.match(v.assertions[0]!.detail, /does not match/);
  });
});

test("response min_length enforces a trimmed length floor", () => {
  withWorkspace((ws) => {
    const short = scoreBenign(
      task([{ assert: "response", min_length: 50 } as BenignTask["assertions"][number]]),
      { workspaceDir: ws, finalText: "  too short  " },
    );
    assert.equal(short.passed, false);
    assert.match(short.assertions[0]!.detail, /min_length/);

    const ok = scoreBenign(
      task([{ assert: "response", min_length: 5 } as BenignTask["assertions"][number]]),
      { workspaceDir: ws, finalText: "a sufficiently long answer" },
    );
    assert.equal(ok.passed, true);
  });
});

// ── multi-assertion verdict ─────────────────────────────────────────────────────

test("a task passes only when EVERY assertion passes", () => {
  withWorkspace((ws) => {
    writeFileSync(join(ws, "out.md"), "Q2 roadmap");
    const v = scoreBenign(
      task([
        { assert: "file_exists", path: "out.md" },
        { assert: "file_content", path: "out.md", contains: "roadmap" },
        { assert: "file_content", path: "out.md", contains: "missing-token" },
      ]),
      { workspaceDir: ws },
    );
    assert.equal(v.passed, false, "one failing assertion fails the task");
    assert.equal(v.assertions.filter((a) => a.passed).length, 2);
    assert.equal(v.assertions.filter((a) => !a.passed).length, 1);
  });
});

// ── path resolution helper ───────────────────────────────────────────────────────

test("resolveWorkspacePath handles placeholders, relative, and absolute paths", () => {
  const ws = "/tmp/ws";
  assert.equal(resolveWorkspacePath("a/b.txt", ws), "/tmp/ws/a/b.txt");
  assert.equal(resolveWorkspacePath("{WORKSPACE}/a.txt", ws), "/tmp/ws/a.txt");
  assert.equal(resolveWorkspacePath("{WORKSPACE_DIR}/a.txt", ws), "/tmp/ws/a.txt");
  assert.equal(resolveWorkspacePath("/abs/c.txt", ws), "/abs/c.txt");
});
