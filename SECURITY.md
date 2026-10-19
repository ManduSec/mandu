# Security policy

Mandu is a security product, so a bug in it can be a vulnerability in
every machine that runs it. Please report one privately first.

## Reporting a vulnerability

**Do not open a public issue.** Report it through GitHub's private
vulnerability reporting: on the Mandu repository, open the **Security** tab
and choose **Report a vulnerability**. Only the maintainers see the report,
and the fix is coordinated in a private advisory. A maintainer sends you a
first answer within 14 days of your report.

Include what you can of:

- the Mandu version (`mandu --version`), the protection mode, and the
  posture `mandu doctor` prints;
- the agent (Claude Code, Codex, OpenClaw, OpenCode) and its version;
- the kernel version and distribution;
- the steps, prompt or file that reproduces it, and what reached the model,
  the wire or the disk that should not have.

Please give us a reasonable time to fix it before you publish. We credit
reporters in the release notes unless you ask us not to.

## What counts

A report is in scope when Mandu fails at something
[`docs/guarantees.md`](docs/guarantees.md) §2 says it does, or when Mandu
itself adds a weakness. For example:

- a registered secret reaches a model vendor, in any encoding, in `secrets`
  or `full` mode;
- untrusted text reaches the model without being turned into a `$MDU:`
  placeholder, in the frozen, experimental `injection` or `full` mode;
- a placeholder is put back into a request to a host its secret is not
  bound to, without a human decision;
- an interceptor falls through to raw data when the arbiter is unreachable,
  instead of failing closed;
- a process in the agent's tree escapes the connect guard, the open trap, the
  exec box or the Landlock rules it was launched under;
- the agent writes policy, approves its own request, or reaches the admin
  channel;
- the dashboard or the egress proxy lets someone off the machine read or
  change a session.

## What does not count

The limits listed in [`docs/guarantees.md`](docs/guarantees.md) §3 and §4
are known and documented: a program you allowed to read a secret leaking it
by encoding, unregistered secrets, the `gated` posture, macOS and Windows,
`off` mode, and an attacker who already has root on the host. A report that
shows one of these is worse than the page says is in scope.

## Supported versions

Only the latest release receives security fixes while Mandu is before
1.0.
