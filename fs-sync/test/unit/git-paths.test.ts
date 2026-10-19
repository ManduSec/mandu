import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { getChangedFiles, getTrackedFiles } from "../../src/git.js";
import { makeTempRepo, gitIn } from "../helpers/temp-repo.js";

test("Git path enumeration preserves Unicode, whitespace, quotes and line breaks", () => {
  const paths = ["남쪽 stock.json", " leading and trailing ", "quote\"name", "line\nbreak", "tab\tname"];
  const repo = makeTempRepo(Object.fromEntries(paths.map((path) => [path, "original\n"])));
  try {
    assert.deepEqual(getTrackedFiles({ cwd: repo.workspacePath }).sort(), [...paths].sort());
    for (const path of paths) writeFileSync(join(repo.workspacePath, path), "changed\n");
    assert.deepEqual(getChangedFiles({ cwd: repo.workspacePath }).map((file) => file.path).sort(), [...paths].sort());
  } finally { repo.cleanup(); }
});

test("Git status consumes the source record of a rename without inventing another changed path", () => {
  const repo = makeTempRepo({ "old name": "unchanged\n" });
  try {
    gitIn(repo.workspacePath, ["mv", "old name", "새 이름"]);
    assert.deepEqual(getChangedFiles({ cwd: repo.workspacePath }), [{ status: "R", path: "새 이름" }]);
  } finally { repo.cleanup(); }
});
