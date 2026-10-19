# Drill results

> Generated 2026-10-19 by the maintainers' drill tooling, at each release; do not edit.

Besides the public suites, the maintainers run **agent drills**: the real
agent CLIs, launched by the real `mandu`, doing everyday work around real
secrets. A scripted model replays them on every push; a real model runs
them before each release. The drills are the maintainers' evidence
tooling and are not published ([licensing.md §6](../design/distribution/licensing.md)); this
table is what they show. Each claim in [guarantees.md](../guarantees.md)
also names the public test that asserts it, which you can run yourself.

One row per property the drills check. *Every push* names the agents a
scripted model replays at least one of its drills on. *Real model* counts
the drills whose last real-model run passed on every agent it ran on, out
of the drills checking that property that a real model can run (a few are
replayed only). *Not passing* sorts the drills a real model ran whose last
run did not pass, each by its worst result on any agent:

- **failed a security check**: a check that the secret stayed masked, or
  that the protected path the drill exercises ran, failed. This is what a
  leak looks like, and the row counts it until a later run passes.
- **did not finish**: the run timed out, the model's own safeguards
  paused it, or the launch failed, so its checks were not all graded. No
  security check of it failed.
- **left the task undone**: every security check held, but the agent did
  not finish the task, or the protection blocked a step it should have
  allowed.
- **warned**: nothing failed, but a check could not be completed, most
  often because the model never reached the step it guards.

A real model is not deterministic, so a drill can pass on one run and
not finish on the next; the same drills replay on every push with a
scripted model. *Agents* names the agents a real model passed one of the
drills on, and *Last pass* the date and model of the latest real-model
pass.

| Property | Every push | Real model | Not passing | Agents | Last pass |
|---|---|---|---|---|---|
| A secret in a file the agent reads reaches the model only as a placeholder | Claude Code, Codex, OpenClaw, OpenCode, Goose | 12 of 20 passing | 3 failed a security check, 2 did not finish, 1 left the task undone, 2 warned | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-19, sonnet |
| A secret in a command's output reaches the model only as a placeholder | Claude Code, Codex, OpenClaw, OpenCode, Goose | 3 of 5 passing | 1 did not finish, 1 warned | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-19, sonnet |
| Web content the agent fetches is read through the quarantined helper model | Claude Code, Codex, OpenClaw, OpenCode, Goose | 0 of 1 passing | 1 warned | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-15, claude-haiku-4-5 |
| A secret in git output reaches the model only as a placeholder | Claude Code, Codex | 0 of 1 passing | 1 left the task undone | Claude Code | 2026-10-19, sonnet |
| A key pasted into the prompt is masked, held for the human or blocked, as the policy says | Claude Code, Codex, OpenClaw, OpenCode, Goose | 0 of 5 passing | 5 did not finish | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-15, claude-haiku-4-5 |
| The human sees the real values in the terminal | Claude Code, Codex, OpenClaw, OpenCode, Goose | 3 of 4 passing | 1 failed a security check | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-19, sonnet |
| A secret leaves the machine only to a host it is bound to | Claude Code, Codex, OpenClaw, OpenCode, Goose | 14 of 22 passing | 2 did not finish, 1 left the task undone, 5 warned | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-19, sonnet |
| A program's open of a secret file the policy holds waits for the human's answer | Claude Code, Codex, Goose | 2 of 2 passing | — | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-18, claude-haiku-4-5 |
| A program the agent runs reads a secret file's placeholder copy | Claude Code, Codex, OpenClaw, OpenCode, Goose | 3 of 4 passing | 1 did not finish | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-18, claude-haiku-4-5 |
| The quarantined helper model gets a secret only where its level admits it | Claude Code, Codex, OpenClaw, OpenCode, Goose | 1 of 3 passing | 2 failed a security check | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-19, sonnet |
| A file labeled for your own model reaches only that model | Claude Code, Codex, OpenClaw, OpenCode, Goose | 0 of 1 passing | 1 failed a security check | Claude Code, OpenClaw, Goose | 2026-10-19, sonnet |
| The policy tools never loosen a label | Claude Code, Codex, OpenCode, Goose | 0 of 2 passing | 2 did not finish | Claude Code, Codex, OpenCode, Goose | 2026-10-15, claude-haiku-4-5 |
| The policy tools suggest protection and the human decides | Claude Code, Codex, OpenCode, Goose | 0 of 1 passing | 1 did not finish | Claude Code, Codex, Goose | 2026-10-08, haiku |
| The agent still finishes the task | Claude Code, Codex, OpenClaw, OpenCode, Goose | 19 of 29 passing | 1 failed a security check, 2 did not finish, 5 left the task undone, 2 warned | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-19, sonnet |
| Mandu does not block safe work | Claude Code, Codex, OpenClaw, OpenCode, Goose | 6 of 12 passing | 2 did not finish, 2 left the task undone, 2 warned | Claude Code, Codex, OpenClaw, OpenCode, Goose | 2026-10-19, sonnet |

A property without a passing real-model run says so; it is not left out.
Researchers who need the drills themselves can ask at hello@mandusecurity.com.
