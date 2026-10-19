# Exec With Symbols

## Goal

Reduce unnecessary symbolizations for `exec` when the command does not require
raw untrusted data or network access. In this mode, `exec` runs with symbolized
inputs and the agent view, so its output can be treated as trusted.

## Design

### Problem

Currently, `exec` is classified as `UNTRUSTED` by default. Mandu cannot inspect
the internal behavior of arbitrary commands, and a command may read raw
untrusted data written in files, or fetch untrusted data from the network. Any
of those paths can introduce malicious input into the agent context, so the
`exec` result must be treated as untrusted conservatively.

This creates unnecessary friction for simple local FS commands such as `ls`,
`git status`, `grep`, or syntax-preserving transformations that do not require
raw values of untrusted data. For instance, `ls` in the agent view shows
filenames and metadata where untrusted values are already symbolized. `grep`
over the agent view returns lines containing `$MDU:` symbols rather than
raw untrusted text. In both cases the output cannot carry raw untrusted data.
These commands can operate on trusted data plus symbols, but default `exec`
resolves all symbols and treats the entire output as untrusted.


### Proposed Mode

Add an opt-in `RESTRICTED` mode controlled by the tool parameter
`env.RESTRICTED=1`. When present, the request means, "run this command against
symbolized data, not raw data."

In this mode Mandu changes execution semantics in `before_tool_call`:

1. Symbols in `exec` parameters are **not resolved** before execution. Symbols
   remain in command arguments, stdin, and environment values.
2. Filesystem access uses the **Agent File System** rather than the Human File
   System with raw data. The Agent File System is the canonical `agentview`
   directory for the workspace.
3. Network access is disabled via `unshare -nc` (new network + cgroup
   namespace), preventing the command from fetching untrusted data from the
   network.

### Trust Model

`exec` remains `UNTRUSTED` by default. The new mode creates a restricted
execution environment in which `exec` output is treated as trusted by Mandu.

- the command sees only trusted data, where external data is symbolized,
  not raw text
- the command has the agent view in the file system, not the human view
- the command cannot fetch additional network data

Under those constraints, the output may still be wrong, incomplete, or fail to
parse, but it is free from raw untrusted content.

### Exec Selection Policy

The T-LLM should decide whether to set `RESTRICTED=1` based on task context.
Good candidates include commands that:

- can operate correctly on symbols instead of original values
- only need local filesystem or process state
- do not require network access

Examples:

- directory listing, file discovery, and metadata inspection
- `grep`, `find`, `wc`, and similar structure-oriented commands over the agent view
- local builds or checks whose outcome does not depend on resolved content

Poor candidates include commands that:

- must validate, parse, or transform the original raw content
- need to contact remote services, package registries, or APIs
- produce useful output only if symbols are first resolved

### Retry Behavior

Symbols can change lexical structure. A command that succeeds on raw input may
fail on symbolized input due to validation, syntax, encoding, or schema checks.
If an `exec` call with `RESTRICTED=1` fails for that reason, the T-LLM should
retry without `RESTRICTED`, where the result is symbolized for security.

This keeps the secure fast path available without turning symbolic execution into a
hard blocker for legitimate tasks.

## Interface

### Symbolized Default Exec

When `exec.command` contains a Mandu symbol, Mandu switches the command to argv
execution before the tool runs. The command template is tokenized first, then
symbols are resolved inside the existing argv slots. Resolved symbol values are
never tokenized again unless the command is exactly one symbol.

For example:

```bash
gh issue comment 1 --body $MDU:exec[abcd].body
```

becomes equivalent to:

```ts
spawn("gh", ["issue", "comment", "1", "--body", resolvedBody], { shell: false })
```

If `resolvedBody` contains text such as `"ok" && other-command`, that text
remains the value of the `--body` argument. It cannot become shell syntax or
extra argv entries.

For symbol-bearing commands, Mandu recognizes only literal `&&` and `||` as
control operators in the original command template. The runner implements those
operators itself from subprocess exit codes; it does not delegate them to a
shell. Other shell features such as `cd`, pipes, redirects, command
substitution, and globbing are rejected instead of interpreted.

The exception is a bare whole-command symbol:

```bash
$MDU:web_fetch[abcd].text
```

If that shape is approved by the untrusted-command-execution audit path, Mandu
resolves the symbol and tokenizes the approved command text into argv form
without invoking a shell. A fixture value such as `printf 'OK\n'` becomes:

```ts
spawn("printf", ["OK\\n"], { shell: false })
```

This preserves the existing "command came from a symbol" workflow while still
preventing shell-only syntax from being interpreted by `sh` or `bash`.

The untrusted-command-execution detector runs over this argv plan. For example,
the bare whole-command symbol is audited as `command_is_symbol`, while
`gh issue comment 1 --body $MDU:...` is treated as fixed executable
structure plus a data argument.

### Tool Contract

The control surface is the `env` parameter on the `exec` tool call.

```json
{
  "toolName": "exec",
  "params": {
    "command": "grep -R TODO src",
    "env": {
      "RESTRICTED": "1"
    }
  }
}
```

### Hook Behavior

In `before_tool_call`, if `toolName === "exec"` and `params.env.RESTRICTED ===
"1"`:

- skip normal symbol resolution for this `exec` invocation
- run through the Mandu shell wrapper, which creates a new network namespace
- bind-mount active `agentview` roots over their Human File System paths for
  the subprocess

The hook must look at the structured `env` parameter. Setting `RESTRICTED=1`
inside the shell command string does **not** activate this mode, because the plugin
must know about the request before execution starts. For example, this does not
work:

```bash
RESTRICTED=1 grep -R TODO src
```

That syntax only changes the subprocess environment. It does not request symbolic
execution from the hook layer.

### Compatibility With Existing Mandu Modes

This mode composes naturally with worktree-based isolation.

- `write`/`edit` use `agentview`, and policy-untrusted `read` paths are
  redirected there when the Agent File System file exists
- restricted `exec` bind-mounts active `agentview` roots over their Human File
  System paths in a private mount namespace

Outside worktree mode, the same concept still applies. `RESTRICTED=1` means the
plugin should expose the agent view, not the human view.

## Open Questions

1. What is the fail-closed behavior on hosts where `unshare -nc` is unavailable
   (e.g., unprivileged containers without `CAP_SYS_ADMIN`)?
2. Which additional tools should gain the same symbolic, network-isolated execution
   mode, especially third-party tools that spawn subprocesses internally?

## Status

Implemented for network isolation and DualView filesystem isolation. The
custom shell wrapper (`plugin/adfi/shell`) uses `unshare -nc` for network
isolation with an `ADFI_SHELL` re-entry guard. Filesystem isolation wraps the
command with `unshare -Umr` and bind-mounts `agentview` over the Human File
System for the subprocess. Audit logs distinguish symbolic exec as `exec_sym`.
