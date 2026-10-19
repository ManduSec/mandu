/**
 * tool-family — every supported agent's tool names by what they do, and the
 * fields they name a file in (dashboard.md §4.25b, *Every agent's steps read
 * in words*). The stack test `dashboard-agent-tool-words` checks this table
 * against each agent's gate surface; this file pins the table itself.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PATH_FIELDS, pathArg, toolFamily, type ToolFamily } from "../../../src/view-model/tool-family.js";

test("each supported agent's tools have a family", () => {
  const agents: Record<string, Record<string, ToolFamily>> = {
    "Claude Code": {
      Read: "read", Write: "write", Edit: "edit", MultiEdit: "edit", NotebookEdit: "edit", Bash: "exec", Monitor: "exec",
      WebFetch: "fetch", WebSearch: "web-search", Grep: "file-search", Glob: "file-search", LS: "list",
    },
    Codex: {
      exec_command: "exec", shell: "exec", shell_command: "exec", local_shell: "exec", read_file: "read",
      list_dir: "list", grep_files: "file-search", web_search: "web-search", apply_patch: "edit",
    },
    OpenCode: {
      read: "read", write: "write", edit: "edit", bash: "exec", shell: "exec", glob: "file-search", grep: "file-search",
      webfetch: "fetch", websearch: "web-search",
    },
    OpenClaw: { exec: "exec", read: "read", write: "write", edit: "edit", web_fetch: "fetch", web_search: "web-search", ls: "list" },
    Goose: { shell: "exec", write: "write", edit: "edit", tree: "list" },
  };
  for (const [agent, tools] of Object.entries(agents)) {
    for (const [tool, family] of Object.entries(tools)) assert.equal(toolFamily(tool), family, `${agent} ${tool}`);
  }
});

test("a name matches whatever its case; an editor's str_replace tools edit; anything else has no family", () => {
  assert.equal(toolFamily("READ"), "read");
  assert.equal(toolFamily("WEB_FETCH"), "fetch");
  assert.equal(toolFamily("str_replace_based_edit_tool"), "edit");
  assert.equal(toolFamily("str_replace_editor"), "edit");
  // The agent's own word, never a guess: an MCP tool, a lookalike, a tool no
  // family covers.
  for (const tool of ["mcp__fs__read", "reader", "read_image", "process", "analyze", "todowrite", "subagent", "update_plan", "inspect_symbol", ""]) {
    assert.equal(toolFamily(tool), null, tool);
  }
});

test("pathArg reads each agent's path field, in order", () => {
  assert.deepEqual([...PATH_FIELDS], ["file_path", "filePath", "path", "notebook_path", "dir_path"]);
  assert.equal(pathArg({ file_path: "/a" }), "/a");
  assert.equal(pathArg({ filePath: "/b" }), "/b", "OpenCode 1");
  assert.equal(pathArg({ path: "/c" }), "/c", "OpenCode 2, OpenClaw, Goose");
  assert.equal(pathArg({ notebook_path: "/d.ipynb" }), "/d.ipynb");
  assert.equal(pathArg({ dir_path: "/e" }), "/e", "Codex list_dir");
  assert.equal(pathArg({ path: "/c", file_path: "/a" }), "/a", "file_path first");
  assert.equal(pathArg({ file_path: "  ", path: "/c" }), "/c", "a blank field is skipped");
  assert.equal(pathArg({ file_path: 7, paths: ["/x"] }), null, "no string path field");
  assert.equal(pathArg({}), null);
});
