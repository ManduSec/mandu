# Contributing to Mandu

Thank you for considering a contribution. This file covers the legal terms,
the rules every change follows (the invariant, the tests, the design-doc
update, the code conventions) and how a pull request is checked. Coding agents
working on this repository follow the same rules.

## License and contributor agreement

Mandu is licensed under the **Apache License, Version 2.0** (`LICENSE`); the
attributions are in `NOTICE`. **Every contribution is made under the
[Mandu Individual Contributor License Agreement](CLA.md)** (the CLA), so that
the company behind Mandu can also use it in its commercial offerings. In
short:

- You keep the copyright in your work. You grant Mandu Security a broad
  copyright and patent license to it, including the right to license it
  **under any terms**, commercial ones among them (CLA §2, §3).
- You confirm the work is yours to give. If an employer, a university or a
  grant has rights in what you write, get their permission first, or ask for
  a corporate agreement at hello@mandusecurity.com (CLA §4).

What to do, once and then on every commit (CLA §6):

1. Before your first pull request is merged, post this comment on it:
   `I have read the Mandu Individual Contributor License Agreement 1.0 and I agree to it.`
2. Sign off every commit (`git commit -s`, which adds
   `Signed-off-by: Your Name <your@email>`). The sign-off certifies the
   [Developer Certificate of Origin 1.1](https://developercertificate.org/)
   for that commit. A pull request whose commits lack it is not merged; fix
   it with `git rebase --signoff <the commit you branched from>` and a
   force-push.

A typo fix is a contribution too, and goes through the same two steps.

## The rules every change follows

These hold for every change, whoever or whatever writes it (people and coding
agents alike). Start with [`docs/design/architecture/mandu.md`](docs/design/architecture/mandu.md) for
the architecture and [Developing Mandu](docs/development.md) for the build,
the package map and the tests.

### The one invariant everything serves

> A secret (a registered credential, or a file or git object labelled above
> `public`) reaches a model **only as an opaque symbol** (`$MDU:*`) unless its
> level admits that model, and never leaves the machine unless a binding or
> the human allows it. Any change that could let un-symbolized secret data
> into a model context it is not cleared for, or out to the network, is a
> security regression: say so explicitly in the pull request.

Labelling, classification and the egress gate are **fail-closed** (secret,
untrusted or require-approval unless an explicit rule says otherwise). When
the arbiter is unreachable, every interceptor fails closed (block, or keep the
value symbolic); it never falls through to the raw value. The reply filter is
the one exception: it only turns placeholders back into originals for the
human, so on failure it passes the placeholders through. Interactive terminals use the PTY
relay (util-linux on Linux, BSD with a resize/signal companion on macOS;
[relay design](docs/design/agents/pty-relay.md)).

**Protection modes** (`docs/design/architecture/protection-modes.md`): `secrets` is the
default (confidentiality on, integrity off), `off` only observes. **`secrets`
mode does not mask untrusted text**, and user-facing copy must say so. The
integrity modes `injection` and `full` are frozen and run only behind
`MANDU_EXPERIMENTAL_INTEGRITY=1` (`docs/design/architecture/protection-modes.md §10`): keep the
frozen code working, but do not build new integrity features.

### No root, and every unprivileged hardening on

Mandu attaches every OS security primitive it can **without host root**
(user, mount, network, PID, IPC, UTS and cgroup namespaces; seccomp
interception and deny filters; Landlock; dropped capabilities;
`no_new_privs`) and turns each on by default where the kernel supports it,
probe-gated, skipping where absent. An unprivileged hardening left unused is a
gap to close. Mechanisms that need host root or change global host state are
out of scope by decision (`docs/design/architecture/privilege-model.md` §0).

### What a change must include

- **Tests, both kinds.** Every code change adds or updates unit tests **and**
  end-to-end tests. The end-to-end suite is the invariant oracle
  (`docs/design/architecture/implementation-plan.md` §9): a new ingress or egress path comes
  with a test asserting that no un-symbolized secret reaches a model it is not
  cleared for, or the network. **Every test states its protection axes**
  (`stateAxes("secrets")`, explicit options, or env; `npm test` sets
  `MANDU_AXES_STRICT=1`, which makes an unstated axis an error): a suite that
  passes because its axis went quiet is the regression to fear.
- **The suite manifest.** A new test file or `test*` npm script is listed in
  `tests/suites.mjs` with its kind and axis; `node scripts/suites.mjs check`
  fails on a file no entry claims.
- **The design doc, in the same change.** A change to behavior, architecture,
  the threat model or the build plan updates the matching `docs/design/` doc
  (index: [`docs/design/README.md`](docs/design/README.md)). Design decisions
  go there, not in code comments alone.
- **Type checks.** Run `npm run typecheck` in each TypeScript package you
  touched: `npm test` runs through `tsx`, which transpiles file by file and
  hides type errors.
- **Lints.** Rust changes pass `cargo clippy --workspace --all-targets --
  -D warnings` in `interceptors/`, at default features and with `--features
  kernel` (the `rust.clippy` suite; the lint policy is
  `[workspace.lints.clippy]` in `interceptors/Cargo.toml`). A new `#[allow]`
  says why on the line above it.
- **Dependencies.** A change to a lockfile passes the dependency audit
  (`node scripts/dep-audit.mjs npm` and `... cargo`): fix an advisory by
  updating the dependency; an advisory with no fix goes in
  `scripts/dep-audit-allow.json` with its reason and an expiry
  ([`continuous-integration.md`](docs/design/testing/continuous-integration.md) §14).
- **Commit messages:** `<type>(<scope>): <description>` (feat, fix, refactor,
  docs, test, chore), with a `Signed-off-by` trailer (above, and CLA §6).

### Conventions in the code

- **The arbiter is the hub.** It owns the symbol table, both policies and the
  event store; interceptors never open its database and call it over the
  Unix-socket IPC. A TypeScript package that calls the arbiter defines a
  *narrow* `Arbiter` interface, an adapter over `arbiter/ipc/client.ts` and an
  in-test mock (see `interceptors/anthropic-proxy/src/arbiter-client.ts`), and
  ships a parity test that builds the production wiring over a real
  `ArbiterServer`: the mock proves the package, only the parity test proves
  the wiring.
- **Kernel-gated Rust.** `cargo build` and `cargo test` in `interceptors/`
  must pass with no root. Kernel attachment lives behind each crate's `kernel`
  cargo feature and `#[ignore]`d tests (`scripts/kernel-tests.sh` runs them in
  unprivileged user namespaces); security decisions stay in privilege-free,
  unit-tested modules.
- **Reuse policy.** Much of the symbol table, policy engine, view sync and
  exec classification is lifted from DualView
  ([compsec-snu/dualview](https://github.com/compsec-snu/dualview)). A file
  copied or adapted from it carries a `PROVENANCE` header naming its origin
  path and purpose, with the OpenClaw runtime coupling stripped, and is listed
  in `NOTICE` (a test fails until it is). New Mandu code says so in the same
  header ("NEW Mandu code").
- **Vocabulary.** The paper and the DualView code use different words for the
  same things; pair them (e.g. *AgentView (repo: Agent File System /
  agent-view)*). The mapping is at the end of `docs/design/architecture/mandu.md` and in
  `docs/adfi-reference/terminology.md`.
- There is no root package.json: each TypeScript package installs and tests
  on its own, and the Rust crates share `interceptors/Cargo.toml`
  ([Developing Mandu](docs/development.md) §3).

## How a pull request is checked

Every suite is listed in `tests/suites.mjs` by what it needs
(`docs/design/testing/test-organization.md`). Pull requests run the public CI
(`.github/workflows/ci.yml`, `docs/design/testing/continuous-integration.md §12`), which covers the
`offline` tier; a pull request that changes documentation only skips it. No
CI runs on macOS: a maintainer runs the darwin entries on a Mac when a change
touches the macOS code (`docs/development.md`, "Developing and testing on
macOS"). Before an outside change ships, a maintainer also runs the
maintainers' pipeline on it, which adds the kernel tier in a throwaway VM and
the maintainers' agent drills (the real agent CLIs against a scripted model).
You can run the kernel tier yourself with `scripts/ci/vm-run.sh` (needs
`/dev/kvm`), or the quick local loop with `scripts/test-all.sh`. The drills
are the maintainers' evidence tooling and are not in this repository
(`docs/design/distribution/licensing.md` §6): a change to how Mandu wraps an
agent is checked against them by a maintainer, who tells you what failed.
What they show is in `docs/testing/drill-results.md`; for access to the
drills themselves, write to hello@mandusecurity.com.

## Enterprise components

The SIEM integration (a Wazuh rig and a redacting event exporter) is on the
enterprise side of the open-core line (`docs/design/distribution/licensing.md` §6). It is not
part of this repository and is not open for outside contribution.

## Code of conduct

Everyone taking part in the project is expected to follow the
[Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Report a breach of it to
hello@mandusecurity.com.

## Security issues

Do not open a public issue for a vulnerability. Report it privately through
GitHub's private vulnerability reporting, as `SECURITY.md` describes.
