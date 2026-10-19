# The reply-filter PTY relay

Decision note, BUILT (2026-09-29): the macOS companion of the relay. Code:
`interceptors/reply-filter/src/pty-relay.ts` (backends and probes),
`src/bsd-relay.ts` (the macOS companion), `src/run.ts` (the wiring).

The reply filter is a HumanView utility surface: it resolves `$MDU:*` symbols
in what the human's terminal shows, while AgentView (repo: Agent File System /
agent-view) and the privileged T-LLM (repo: privileged LLM) transcript keep the
symbols. Nothing here gates. Every failure degrades toward an opaque symbol on
screen or toward the pre-relay passthrough, and neither can leak.

## 1. What the relay is

`src/print-mode.ts` picks one of three modes per launch, keyed on whether
**stdout** is a TTY and on the agent's argv: `pipe` (the child's stdout is a pipe
through the filter), `pty` (interactive TUIs on a TTY) or `passthrough`. In
`pty` mode the child runs under the platform's `script(1)`. The child gets a
real pseudo-terminal, and script relays the session to its own stdout, which
the wrapper filters on its way to the human's terminal (`mandu.md` §4, the
user-reply egress row). The launcher runs the chain detached, so it sends the
terminal's SIGWINCH to the chain's whole process group
(`launcher/src/spawn.ts`), and the reply-filter gets it there.

## 2. The two backends

| | util-linux `script -qefc '<cmd>' /dev/null` (Linux) | BSD `/usr/bin/script -q /dev/null <cmd…>` (macOS) |
|---|---|---|
| command | one `sh -c` string (POSIX-quoted) | exec'd directly, no shell |
| pty, raw mode on the human's terminal | yes | yes |
| initial size | copied from its stdin | copied from its stdin; 0x0 when stdin is not a TTY |
| terminal resize | re-copies the size on SIGWINCH | **ignored**: the companion re-sizes (§3) |
| INT/TERM/HUP sent to script | handled by script (not re-measured here) | **kill script itself**: the companion sends them to the child (§3) |
| exit status | the child's; 128+n on a signal death (`-e`) | the child's; the **bare** n on a signal death |
| stdin it starts on | any | a TTY, /dev/null, an anonymous pipe, a regular file; **not** a socket or a named FIFO |

The macOS column was measured on macOS 26.5.1 (arm64) (§3.1). The Linux column
is util-linux's documented behavior, as the relay has used it since 2026-09.
It was not re-measured for this note. `differential-interactive.md` §18
measured the resize.

## 3. macOS: BSD script and the companion

### 3.1 Measurements (2026-09-29, macOS 26.5.1, arm64)

- **Exit status.** `script -q /dev/null sh -c '<c>' </dev/null` exits 9 for
  `exit 9`, 0, 130 and 200 for those codes, and **15, 9, 2, 11, 1** for a death
  by SIGTERM, SIGKILL, SIGINT, SIGSEGV and SIGHUP. The man page says `-e` is
  accepted for util-linux compatibility and changes nothing.
- **Resize.** An outer pty stood in for the human's terminal. It ran BSD script
  around a child that traps SIGWINCH and prints `stty size`. Re-sizing the
  outer terminal and sending SIGWINCH to script left the child at 24x80.
  `stty -f /dev/ttysNNN rows 40 cols 120` on the child's own pty, run from
  outside, reached it at once ("WINCH 40 120"). The kernel sent the SIGWINCH to
  the pty's foreground group itself. The same size again sent no signal.
- **Signals.** SIGTERM to script killed script (shell status 143). The child
  got SIGHUP, not SIGTERM, because the master closed. The terminal stayed raw
  (`-icanon -isig -echo`). SIGTERM to the child instead: the child got SIGTERM,
  script exited with the child's status, and the terminal was back in cooked
  mode. Under the reply-filter, node restores stdio's terminal mode when it
  exits, so there the raw terminal was not visible. What stayed visible was
  the SIGHUP and the lost shutdown output: a line the child prints on its way
  out never arrives, because the master is gone.
- **Stdin.** BSD script calls tcgetattr on its stdin and tolerates only
  ENOTTY. `/dev/null`, a pipe(2) and a regular file work. At EOF, BSD script
  writes VEOF into a canonical-mode child, which shows as `^D`. A named FIFO
  (fifofs is built on sockets) and node's `"pipe"` stdio (a socketpair) make it
  exit 1 before the child runs: `script: tcgetattr/ioctl: Operation not
  supported on socket`. node's fstat tells them apart: a pipe(2) is a FIFO on
  device 0 with no links, and a named FIFO has a device and a link.
- **Cost.** `ps -A -o pid=,ppid=,tty=` took about 11 ms with 711 processes,
  `ps -o tty= -p` about 3 ms, and `stty -f` about 3 ms.

### 3.2 The companion (`src/bsd-relay.ts`)

It runs only for the BSD flavor in `pty` mode, starts when script is spawned,
and stops on script's exit.

1. **Locate.** script forks one child, which calls `login_tty()` on the pty
   slave and execs the command (`sandbox-exec … claude` keeps that pid). The
   companion polls a `ps` snapshot at 0, 10, 20, … 1280 ms (about 2.5 s in all)
   until it sees script's child with a tty that is a pty slave name and not
   script's own tty. Until `login_tty()`, the forked child still shows
   script's terminal, which is the human's and never the one to resize. The pid
   alone, seen earlier, is enough for signals.
2. **Resize.** When stdout emits `'resize'`, the companion runs
   `/bin/stty -f /dev/ttysNNN rows R cols C`. The kernel raises SIGWINCH for
   the TUI. Requests coalesce: one stty runs at a time, and the latest size
   wins. A request that arrives before the child is located waits for it. The
   screen model (`screen-reconcile.ts`) resizes in stream order when the event
   fires, as on Linux, so the TUI's repaint at the new size lands on a model
   of that size. Once located, the companion also applies stdout's size one
   time. This fixes the 0x0 pty of a non-TTY stdin, and a resize that landed
   before the child was located. Same size means no change.
3. **Signals.** SIGINT/SIGTERM/SIGHUP go to the child's pid, the way pipe mode
   forwards them to the agent. The companion falls back to script only while
   the child is not yet known (its first milliseconds). SIGWINCH is still
   forwarded to script, which ignores it.
4. **Exit status.** When script's code equals the number of a signal the
   companion delivered, the wrapper exits 128+n. A normal exit code passes
   through unchanged. Mapping every small code was rejected: it would turn a
   real `exit 1` into 129 and the relay's own `exit 9` test into 137.

Why `ps` and `stty` rather than owning the pty master: the repo ships no native
Node addons, and node has no TIOCSWINSZ. A helper in another runtime is no
option either: `/usr/bin/python3` on a stock Mac is a stub that offers to
install the Command Line Tools. `/bin/ps` and `/bin/stty` are part of the base
system, and they are named by path so that a PATH entry cannot stand in for
them. The reply-filter runs outside the Seatbelt wrap (`sandbox-exec` sits
between script and the agent), and the slave is a device the same user owns.

The same rule covers the rest of the chain on macOS (review 2026-09-29):
script itself is `/usr/bin/script` (`BSD_SCRIPT`, `ptyScriptPath`), its
probe runs `/usr/bin/script -q /dev/null /usr/bin/true`, and the wrap
between script and the agent is `/usr/bin/sandbox-exec`
(launcher/src/seatbelt-profile.ts `SANDBOX_EXEC`). Each runs outside the
profile with the agent's PATH, whose user folders (`~/.local/bin`,
`/opt/homebrew/bin`) come before `/usr/bin` and are not write-protected, so
a bare name would let a program the agent planted in one session run in
the next session's relay or in place of the profile. `mandu doctor --live`
(launcher/src/doctor-live.ts L3) spawns and checks the same path. Linux
keeps util-linux `script` found on PATH, as before.

Races. A resize before the child is located waits for it, and the initial sync
covers a resize that came earlier. A signal in the first milliseconds goes to
script, which is the old behavior. After script exits, nothing touches the tty
name or the pid again, because either may be reused. The window between the
child's reaping and script's exit is microseconds, and macOS hands out pids
in sequence.

### 3.3 Residuals

- A death by a signal the relay did not deliver (a crash, `kill -9` of the
  agent) reads as the bare signal number. BSD script cannot tell it apart
  from `exit n`, and a status-preserving shell between script and the agent
  was rejected: it would change the agent's session and signal semantics.
- If the inner resize fails (ps or stty unavailable, the child gone), the TUI
  keeps its size while the screen model resizes. That was the behavior before
  2026-09-29, and it only affects repaint geometry, never what resolves.
- With a non-TTY stdin, BSD script types VEOF into a canonical-mode child at
  EOF. A raw-mode TUI such as Claude Code is unaffected.

## 4. Stdin and the mode decision (open)

The mode decision is keyed on stdout (`print-mode.ts`, rules 3–5) and is not
changed here. With a TTY stdout but a piped stdin (`echo … | mandu claude`),
both backends give the child a TTY stdin and copy the piped bytes into it as
typed input, while the agent run bare would see a pipe. Choosing `pipe` mode
when stdin is not a TTY would match the bare run more closely. It is a mode
change on both platforms, so it is left for a decision. What this change does
enforce is the §3.1 fact that BSD script cannot start on a socket or a named
FIFO: `ptyStdinProblem()` treats the relay as unavailable for that run, and
the wrapper degrades to passthrough, the existing rule for a missing backend,
instead of exiting 1 before the agent starts.

## 5. Tests

- `test/unit/pty-relay.test.ts` covers the flavor map, the argv per flavor
  (BSD by absolute path), the probe (a `script` and a `true` planted first on
  PATH never run), and the BSD stdin check against the §3.1 fstat shapes.
- `test/unit/bsd-relay.test.ts` covers the snapshot parser (script's own tty
  is never chosen, only pty slave names become paths), the stty argv, the
  exit mapping, and the companion's schedule over injected steps: polling,
  coalescing, signals, dispose.
- `test/component/run.test.ts` runs cases (e)–(j) on every host with a backend,
  macOS included (they were Linux-only until 2026-09-29). Case (m) shows a
  child's signal death re-raised through the wrapper. Before, the wrapper's
  own SIGTERM forwarder swallowed the re-raise, and the wrapper exited 0.
  Case (n) runs only on macOS: a socket stdin degrades to passthrough.
- `test/component/bsd-relay.test.ts` runs only on macOS, with a real outer terminal.
  Case (k): 24x80 → 40x120 reaches the child behind the inner script, and the
  reply still resolves. Case (l): SIGTERM reaches the child as SIGTERM, its
  shutdown output arrives, the terminal mode is restored, and the exit is 143.
  With the companion disabled, (k) times out and (l) sees no GOT-TERM.
- By hand on macOS 26.5.1, the full launcher ran in a pty:
  `mandu --target shell -- bash <child>`, then a resize. The child saw 24x80,
  then 40x120 (`WINCH 40 120`), behind `script` → `mandu-reply-filter` →
  `mandu`, and the exit code 7 came back.
