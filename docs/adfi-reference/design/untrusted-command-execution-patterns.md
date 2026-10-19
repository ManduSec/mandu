# Untrusted Command Execution Patterns

## Goal

Detect `exec.command` shapes where a Mandu symbol is positioned as command or
code text. This is narrower than a generic executable-field policy: `exec.command`
is always executable, but a symbol inside it is not always an untrusted-command
execution attempt.

For symbol-bearing `exec` calls, this check runs after Mandu lowers the command
template to its argv execution plan. The detector inspects the template argv
plan, where symbol positions are still explicit, rather than the final raw argv
values. That keeps the audit aligned with what will actually execute while
avoiding a second shell parse of resolved untrusted text.

## In Scope

The first implementation keeps these as table-driven pattern definitions in
`plugin/adfi/policy/untrusted-command-execution.ts`. Pattern entries declare
runner matchers and evidence sources (`whole_command_symbol`, `flag_argument`,
or `heredoc_body`); the detector applies those token matchers without
pattern-specific Python/Bash branches. It audits:

- `command_is_symbol`: the whole command is a single Mandu symbol.
- `shell_c_contains_symbol`: `sh -c`, `bash -c`, or `zsh -c` receives inline
  command text containing a symbol.
- `interpreter_inline_code_contains_symbol`: `python -c`, `python3 -c`, or
  `node -e` receives inline source code containing a symbol.
- `stdin_code_contains_symbol`: shell or Python source code is supplied through
  heredoc/stdin and that source contains a symbol.

Examples that should be audited:

```sh
$MDU:exec[05fa].comment_command
bash -c "$MDU:exec[05fa].comment_command"
python -c "print(\"$MDU:web_fetch[a1b2].text\")"
python - <<'PY'
print("$MDU:web_fetch[a1b2].text")
PY
```

Examples that should not be audited by this policy:

```sh
grep -R "$MDU:web_fetch[a1b2].text" docs
python script.py "$MDU:web_fetch[a1b2].text"
```

Those may still matter for outbound resolution or leakage analysis, but they are
symbol-as-data arguments rather than command-execution patterns.

## Argv Lowering Semantics

When `exec.command` contains a Mandu symbol, Mandu executes a shell-free argv
plan. A bare whole-command symbol is the only case where the resolved symbol
value is tokenized into argv words:

```sh
$MDU:web_fetch[05fa].text
```

If approved by this audit path, a resolved value such as `ls docs plugin`
becomes:

```ts
spawn("ls", ["docs", "plugin"], { shell: false })
```

Symbols embedded in a larger command template remain a single argv element at
their original position:

```sh
gh issue comment 1 --body $MDU:web_fetch[a1b2].text
```

becomes:

```ts
spawn("gh", ["issue", "comment", "1", "--body", resolvedText], { shell: false })
```

Shell metacharacters that come from `resolvedText` are data for `gh`; they are
not shell syntax.

## Script File Expansion

Unrestricted `exec` calls can also execute code that is not visible in
`exec.command` itself, such as:

```sh
python fix_script.py
bash fix.sh
./fix.sh
```

When file tracking has an Agent File System copy for the target script, Mandu performs
an analysis-only expansion before the human-view command runs:

1. Match a table-driven script execution rule (`python_script_file`,
   `shell_script_file`, `node_script_file`, or `direct_script_file`).
2. Resolve the script path against the command workdir.
3. Read the Agent File System copy of the script.
4. Build a synthetic inline command, for example
   `python -c '<trusted script content>'` or
   `bash -c '<trusted script content>'`.
5. Run the same untrusted-command-execution detector on the synthetic command.

The synthetic command is never executed and never replaces the real tool call.
The actual `exec.command` remains unchanged; only the audit decision uses the
expanded command. Restricted symbolic exec is skipped because it already runs
against the symbolized trusted view.

## Non-Goals

- Full POSIX shell parsing.
- Output classification downgrade for resolved-symbol laundering; that is
  tracked separately by #180.

## Audit

Matches emit `taintAction: "untrusted_command_execution_pattern"` from
`before_tool_call`, with pattern IDs, symbol tokens, unknown symbol tokens, and
short evidence snippets. This policy is currently audit-only: it does not ask
for interactive human approval or block the call. Audit records include
`userApproval.status: "human_approved"` and `userApproval.interactive: false` to
make that benchmark/eval approval assumption explicit. The full audit JSON body
is also emitted through the plugin logger with an `[Mandu-audit-json]` prefix, and
the dashboard renders the raw audit JSON in each audit event's expanded details.
