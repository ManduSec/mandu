# Supported agents

> **Status: BUILT (2026-09-27).** The tested version ranges, the launch
> warning, OpenCode 2 (§2.3: refused, then built behind an opt-in, and
> supported by default since 2026-10-05 after a live check, with its own
> tested range), the `mandu doctor` row, the dashboard's health reason and the
> product page's notice (§1 to §4). §5 is the defendability study: which
> agents Mandu can defend, per enforcement layer, and which come next. §6 is
> the Codex script-cell wire the openai-proxy reads since codex-cli 0.154
> (BUILT 2026-09-24). How each agent's own sign-in passes through Mandu is
> [`agent-sign-in.md`](./agent-sign-in.md). §2.0: the support status, with
> Goose and OpenCode 2 a **preview** (BUILT 2026-10-07), and OpenCode 1 too
> (2026-10-09).
> §5.7: the agent registry, the one list of agents the test tooling and
> the product packages read, and the standing rule for adding an agent
> (BUILT 2026-10-18).

## 1. Why

Mandu attaches to the agent through its model-API traffic. The
anthropic-proxy and the openai-proxy read each tool's result off the wire and
the arbiter classifies it by the tool's **name**
(`arbiter/policy/claude-code-inbound.ts` for Claude Code). Agents ship often. A
new release can advertise a tool the inbound spec has never seen, or change the
request format, and the user must be told when the installed agent is outside
what Mandu was tested with.

What an unknown tool actually does (checked, not assumed): the inbound spec is
**fail-closed**. A tool name the spec does not list classifies UNTRUSTED
(`policy-interface.ts`, "fail-closed" in the reason), so with the integrity
axis on (`injection`, `full`) its whole result reaches the model only as a
`$MDU:` symbol. An unknown tool costs usefulness (the agent sees a placeholder
where a harmless ack would have been), not safety. This holds for what the
model READS. The wire gates on what the agent DOES (exec, net, path) key on
the tool names in `tool-gate-surface.ts`, so an unknown tool that runs a
command or reaches the network is not gated on the wire; the OS layer still
applies (§2.1 has the OpenClaw case).
`tests/stack/agent-version-drift.test.ts` proves this across
the real arbiter and proxy for a tool called `FutureNotebookSync` carrying an
injection. In `secrets` mode untrusted text is not masked for any tool, known
or not; secret values are still masked. The warning copy says exactly this
and never claims the agent runs "unprotected".

The second risk is a changed request format. The proxies fail closed on a
shape they cannot read (a Codex exec cell the gate cannot parse is refused,
§6), which can stop a session. The copy says that too.

## 2. The tested ranges

### 2.0 Support status: supported or preview (2026-10-07)

Every tested line (an agent, or a generation such as OpenCode 2) carries a
status next to its range (`status` in `agent-versions.ts`, mirrored in the
dashboard's table; `SupportStatus`). The maintainer's decision for 0.2.0:
Claude Code and Codex are fully supported; Goose and OpenCode 2, new in
0.2.0-beta.3, are a **preview**: each launches with every protection, but
was tested less (the first-session tour never ran on them live, and they
have no live battery, only a short live drill leg each, §2). OpenClaw kept
the status it had.

**OpenCode 1 joins the previews (2026-10-09).** OpenCode 1 had kept its
pre-0.2.0 status, but its evidence is as thin as a preview's: one
multi-agent e2e lane, no drill, no per-push replay, no tour. The
maintainer's decision marks it a preview the same way: the same launch line
("OpenCode support is a preview: …"), the doctor word and the dashboard tag,
under its README name "OpenCode". OpenCode 1 and 2 share the agent id
`opencode` and are told apart by the probed major (`testedRangeOf`), so the
status lives on each line, not on the id: the 1.x line
(`TESTED_AGENT_VERSIONS.opencode`) and the 2.x generation each carry their
own, and each would keep it if the other changed.

| Agent | Why | Status |
|---|---|---|
| Claude Code | live batteries, the differential lane, the first-session tour | supported |
| Codex | the agent-fake suites, live on the ChatGPT backend, the first-session tour | supported |
| OpenClaw | multi-agent e2e lanes and fresh-agents legs through `mandu` | supported |
| OpenCode | the multi-agent e2e lane only; no drill, no per-push replay, no live tour (a preview since 2026-10-09) | preview |
| OpenCode 2 | replay and real-binary suites; one live drill leg; no live battery, no live tour | preview |
| Goose | replay and real-binary suites; one live drill leg; no live battery, no live tour | preview |

What a preview gets, and what it does not:

- **A launch notice**, one line (`launchPreviewNotice` → `previewNotice`;
  already short, so `compactNotice` knows it): since 2026-10-18 the
  default display counts it on the launch's banner line and the launch's log
  (`mandu log`) holds it, `--verbose` prints it (packaging.md §5), always
  before the agent starts and so never inside its TUI:
  `mandu: ! Goose support is a preview: tested less than Claude Code and
  Codex; report problems at https://github.com/mandusec/mandu/issues`.
  It is keyed on the target (a Goose run through a wrapper script is still
  Goose) and, for OpenCode, on the generation the launch settled
  (`opencodeGeneration`: `opencode2` or a probed 2.x is OpenCode 2, a
  probed 1.x OpenCode 1). An OpenCode whose generation is not known (a
  wrapper script started as `--target opencode`) gets the line only when
  every OpenCode line has the same status, as both are previews now, named
  plain "OpenCode". None for a `--version` launch. `MANDU_PREVIEW_NOTICE=0` (config `preview-notice =
  false`) hides it. It is kept with the other notes (the launch's log,
  `launch.log`, the `launch_posture` event).
- **A word on the doctor row**: the agent's version row (§3) ends with
  "a preview: tested less than Claude Code and Codex", in every verdict.
- **A tag on the dashboard** (2026-10-09; dashboard.md §4.21 *A preview
  agent*): a **Preview** tag by the agent's name on its Home row and its
  agent page, opening "Goose support is a preview: Mandu was tested less
  with it than with Claude Code and Codex." and a link to report a
  problem; in the inspector, "(preview)" beside the version in the session
  header and a note (never a downgrade) in the health chip. Judged on the
  dashboard's own table from the session's version check
  (`supportStatusOf`, mirrored), so `MANDU_PREVIEW_NOTICE=0`, which hides
  the launch line, leaves the tag. The product page names an OpenCode 2
  session "OpenCode 2" (its Home row, its agent page, the asks it raised),
  the tag's own label; OpenCode 1 stays "OpenCode", the label of its tag.
- **Never a refusal**, and no protection is turned off: the status is about
  how much testing stands behind the agent, not about what Mandu enforces.

`tests/stack/agent-versions-parity.test.ts` holds the README's table (range
and status per row), this table's statuses and the user guide's preview
paragraph to the code; `agent-versions.test.ts`, `launch-banner.test.ts` and
`doctor-versions.test.ts` are the unit tests, and
`launcher/test/component/agent-preview.test.ts` launches stand-in `goose`,
`opencode` (1.x) and `opencode2` binaries through `main()` (the notice once,
under the mode line, the agent still starts, hidden by the switch; none for
Claude Code).
`tests/stack/agent-preview-dashboard.test.ts` carries those launches'
records to a real dashboard (the tag on Home, the agent page and the
inspector; none for Claude Code; the tag kept under the switch; a Goose
newer than tested gets the tag and the version's warning on both; the
OpenCode 2 session and its ask are named "OpenCode 2", an OpenCode 1 one
"OpenCode" with its own tag).

Much of the evidence below comes from the agent drills (the replay,
differential and live drill suites, the `integration.replay*`,
`integration.differential*` and `integration.*-e2e` entries), which run in
the maintainers' source repository and are not published. Their latest
results are in
[drill-results.md](../../testing/drill-results.md); to get access to them,
for research for example, write to hello@mandusecurity.com.

| Agent | Tested versions | Evidence |
|---|---|---|
| Claude Code | 2.1.273 to 2.1.295 | CI guest image pin (`scripts/ci/pins.env`; the `replay-drill` kind runs every push against it): 2.1.273 until 2026-10-09, 2.1.295 since; live batteries on 2.1.273 (160 recorded sessions) and 2.1.281 (92), `tool_surface` "all known to the inbound spec"; 2.1.285 (32 sessions, 38 tools, all known) and 2.1.287 (every advertised tool known): the claude differential lane 70/70 in the CI guest with the secret bind on. 2.1.292 (2026-10-07, below): every advertised tool known once DesignSync and PushNotification were mapped; the claude differential lane, the per-push replay drills and the agent-SDK suite on the host. 2.1.294 (2026-10-09, below): the live drills on haiku (the 2026-10-08/09 pre-release run and its reruns, `tool_surface` all known), the interactive surface (31 tools, `Artifact`, `ArtifactComments`, `ArtifactData`, `EndConversation` and `SendFeedback` newly mapped, the Artifact uploads gated) and the headless 23 all mapped. 2.1.295 (2026-10-09, below): every advertised tool mapped (the headless 23, the interactive 31), the claude differential lane 70/70 on the host (the 65 CI shards), the per-push replay drills (7), the agent-SDK suite (9), the fresh-agents VM legs on Ubuntu 24.04 and 26.04 75/75, and a live leg (haiku, mode `secrets`: `conf-read-exfil` and `util-quote-line` pass); the CI guest's pin since 2026-10-09: the per-push `replay-drill` kind in the guest (52 entries, the claude differential shards among them) green. 2.1.258 failed CI twice, so it is below the floor. |
| Codex | 0.136.0 to 0.162.0 | openai-proxy wire verified on 0.136 (Responses API) and 0.154 (script-cell exec, MCP; §6). 0.159.1: the agent-fake Codex suites (`integration.codex`, `integration.codex-view-map`, `integration.codex-chatgpt`) green, and live on the ChatGPT backend: a plain and a tool turn, `codex-e2e` (`reasoning`, `benign-exec`), and a session that compacted (`agent-sign-in.md` §2.8). 0.160.0 (2026-10-07, below): the agent-fake Codex suites with `integration.codex-policy-tools`, the per-push replay drills, the agent-SDK suite, every tool both wires advertise mapped; live on the ChatGPT backend (gpt-5.6-luna, 2026-10-07): `codex-e2e` `reasoning` and `benign-exec`, `codex-mcp` CMCP-1. 0.162.0 (2026-10-09, below and §6.4): the same suites, the codex differential lane 7/7, every tool both wires advertise mapped (the same tools as 0.160; the classic wire's prompt is now a developer message, pinned); live on the ChatGPT backend (`conf-read-exfil`, 2026-10-09). The CI guest's pin since 2026-10-09 (0.144.1 before): the per-push `replay-drill` kind, the codex sandbox entries and the codex differential lane 7/7 in the guest (`fidelity-permission-prompt` on the `on-request` posture, no fold; `differential-interactive.md` §34.1) |
| OpenClaw | 2026.3.12 to 2026.9.9 | multi-agent e2e lanes (`agent-e2e-harness.md`); fresh-agents legs through `mandu` on 2026.3.12, 2026.6.35, 2026.7.1 and 2026.9.6 (Node 24), both modes (`os-test-matrix.md §10` §14). Every tool 2026.7.1 advertises under `tools.profile: "coding"` is mapped in `openclaw-inbound.ts`; every tool 2026.9.6 advertises in each Tool Search mode is mapped, refused on the wire, or a dispatcher gated as the tool it runs (§2.1; unit tests hold both captured surfaces to the spec and the gate table). §2.1 also covers what the other profiles add. 2026.9.9 (2026-10-09, §2.1 "OpenClaw 2026.9.9 and Code Mode"): fresh-agents legs through `mandu` (Node 24, Ubuntu 24.04 and 26.04, scripted model, `secrets`; 75/75 with every agent at its latest); `integration.openclaw-e2e` 8/8 (`inspect_symbol` called directly past 9.x's Tool Search; the replay engine reads 9.x's internal-context block, SQLite transcript and masked stored replies); every tool it advertises in each Tool Search mode (default, `tools`, `directory`, off) mapped, refused on the wire, or a dispatcher gated as the tool it runs; Code Mode (`exec{code}`, `wait`) refused on the wire and off in the run config; a live leg (haiku, mode `secrets`: `conf-read-exfil`, `conf-public-label-wins`, `util-write-file` and `util-shell-echo` pass). |
| OpenCode | 1.18.13 to 1.18.35 | multi-agent e2e lane on 1.18.13. 1.18.35 (2026-10-09): the multi-agent e2e lane and the scripted-model replay catalog (`integration.opencode-e2e`, `opencode-hermetic`, `replay.opencode` util/conf/policy, `opencode-project-plugins`; the real-binary launcher component tests); the tool surface unchanged from 1.18.13, all known to the inbound spec; a live leg with the maintainers' live drill runner (haiku, mode `secrets`: `conf-read-exfil` and `conf-read-control`, no leak) |
| OpenCode 2 | 2.0.23 to 2.0.26 | npm `@opencode/cli`, judged on its own range (below). The 2.x e2e and replay suites on 2.0.23 (`integration.replay-opencode2`, the CI guest's pin, blocking per push; the `tests/stack/opencode2-*` suites); the real-binary launcher component tests (`opencode-v2-standalone`, `opencode-v2-refusal`, `opencode-v2-config`) and sandbox tests (`integration.opencode2-own-server`, `-agent-identity`, `-shell-output`); a live check with the maintainers' live drill runner on `opencode2` (2026-10-05, run `watch-20261005T135829`, haiku, mode `secrets`: `conf-read-exfil`, `conf-net-exfil-blocked` and `conf-read-control` pass, 12 exchanges, hermetic). 2.0.26 (2026-10-09): the same e2e and replay suites (`integration.replay-opencode2`, `opencode2-e2e`, `replay.opencode2` util/conf/policy), the real-binary launcher component and sandbox tests (with `opencode-project-plugins`); the tool surface identical to 2.0.23 (every tool mapped but `execute`, which the proxy refuses); a live leg (haiku, mode `secrets`: `conf-read-exfil` and `conf-read-control` pass). §2.3 |
| Goose | 1.53.0 to 1.54.0 | The CI guest's pin (`scripts/ci/pins.env`, the release tarball, sha256-checked). The replay suites on 1.53.0 (`integration.goose-e2e`, `integration.replay-push.goose` per push, `integration.replay.goose` nightly over 41 catalog scripts); the real-binary launcher component tests (`goose-real`, `goose-delivery`); every tool 1.53.0 advertises mapped, gated, refused on the wire or masked whole (`load` / `load_skill` mapped only under the guard; the `tool_surface` unknown list empty since 2026-10-09; §5.6); a live leg with the maintainers' live drill runner on `goose` (2026-10-05, run `watch-20261005T135717`, haiku, mode `secrets`: `conf-read-exfil` and `conf-read-control` pass, no leak, hermetic; on `conf-net-exfil-blocked` the model declined before reading, twice, so that drill's gate is covered by the replay lane); the differential interactive lane 13/13 (`integration.differential-goose`, nightly). 1.54.0 (2026-10-09): the replay suites (`integration.goose-e2e` 20/20, `replay-push.goose` 2/2, the `replay.goose` catalog 36 pass and 2 kernel-lane skips), the real-binary launcher component tests (`goose-real`, `goose-delivery` and the other `goose-*` files, 40/40), the same tool surface as 1.53.0, every tool mapped, gated, refused or masked whole; a live leg (haiku, mode `secrets`: `conf-read-exfil`, `conf-read-control` and `conf-public-label-wins` pass). §5.6 |

Codex on a ChatGPT sign-in (the openai-proxy's relay to the ChatGPT backend,
`agent-sign-in.md` §2.4) is verified on codex-cli 0.159.1 (live on the real
backend and the `integration.codex-chatgpt` agent-fake suite) and on 0.144.1,
the CI guest's pin until 2026-10-09 (the agent-fake suite; 0.162.0 since).

**Codex 0.160.0 and Claude Code 2.1.292 (2026-10-07).** Both warned at
every launch. Each was re-tested keyless, against scripted models, on the
host, with nothing billed:

- *Codex 0.160.0.* The policy tools did not work under it (a first-session
  tour: "the tool-discovery result was hidden from me"). 0.160 leaves
  deferred MCP tools out of the code-mode `exec` description and tells the
  model to filter `ALL_TOOLS`; that search cell was masked in any session
  with a raw read. Fixed by the filtered listing (confidentiality-plan-10
  §11.13), pinned by `integration.codex-policy-tools` with the real codex.
  0.160's tool surface, read off both wires against a scripted Responses
  server: the classic wire adds `get_goal`, `create_goal`, `update_goal`; the
  code-mode wire adds `request_user_input_async` and the `clock` (`sleep`) and
  `collaboration` (the sub-agent tools) namespaces, which were masked whole as
  unmapped; all are now on `CODEX_MAPPED_TOOLS` (§6.4). Then green on 0.160.0:
  `integration.codex` (5), `integration.codex-view-map` (1),
  `integration.codex-chatgpt` (2), `integration.codex-policy-tools` (3),
  `integration.agent-sdk` (9, both SDKs), `integration.replay-push.codex` (4),
  the codex legs of `integration.replay-engine` and the codex differential
  lane (`integration.differential-agents`, `MANDU_DIFF_AGENT=codex`, 7/7).
  **Live on the ChatGPT backend (2026-10-07, gpt-5.6-luna, a ChatGPT
  sign-in):** `codex-e2e` `reasoning` (a plain turn, 7/7 checks) and
  `benign-exec` (a tool turn, 6/6), and `codex-mcp` CMCP-1 (11 requests;
  tightenings applied, loosenings pending). The first `codex-e2e` attempt
  failed every turn with the proxy's 502 "arbiter filterPrompt failed —
  refusing to forward the prompt unfiltered": the suite wired the proxy
  through a test bridge that lacked `filterPrompt` (the prompt filter,
  confidentiality-plan-15 §3.2), so it failed closed as designed. The suite
  now builds the production wiring (the data client and the human plane's),
  and the bridge forwards the op for the frozen suites that still use it.
- *Claude Code 2.1.292.* Its headless tool surface (23 tools, captured
  against a stub that errors every request) named two tools no spec knew:
  `PushNotification` (a desktop or phone notification of the model's own
  line; the result is a sent / not sent ack: TRUSTED) and `DesignSync` (the
  user's claude.ai/design projects: `get_file` returns files other org
  members wrote: UNTRUSTED, RemoteTrigger's class). Both are mapped in
  `claude-code-inbound.ts`. DesignSync's `write_files` uploads local files
  by `localPath` to claude.ai, their bytes never entering the model
  context, so no symbol is ever minted for them; until 2026-10-07 the wire
  did not gate it and only the OS layer (the secret twins, the macOS read
  block) kept a secret file home. **Closed (2026-10-07): the upload gate.**
  The tool's input schema, captured from the same stub run
  (`arbiter/test/fixtures/claude-design-sync-tool-2026-10-07.json`): one
  tool on `method`; `finalize_plan{projectId, writes, deletes, localDir}`
  names the directory uploads read from (the working directory when
  absent), `write_files{projectId, planId, files: [{path, localPath | data,
  encoding, mimeType}]}` uploads (each `localPath` relative to that
  `localDir`, confined to it by the tool), and every other method
  (`list_projects`, `get_project`, `list_files`, `get_file`,
  `create_project`, `delete_files`, `register_assets`, `unregister_assets`,
  `report_validate`) sends only model-written text. Claude Code's gate
  surface has a new `upload` table (`tool-gate-surface.ts` `UploadKind`,
  `DesignSync: "claude-design-sync"`; the union carries it, so an arbiter
  that cannot say still gates it), which the proxy's `upload-gate.ts`
  applies before every other gate:
  1. *The net legs over every string the call sends* (net-gate.ts, reused
     at `claude.ai`): the session watermark (a high session's DesignSync
     call needs a binding or approval) and the per-symbol leg (a `$MDU:*`
     token in inline `data`, a name or a path is judged by
     `desymbolizationDecision` at `claude.ai`; allowed or not, it cannot be
     put back inside the tool's own HTTPS request without the egress
     proxy's TLS inspection, so the call is refused).
  2. *A plan must name an absolute `localDir`.* The working directory
     follows the shell's `cd` and is not known to the proxy (Claude Code
     has no `relativeBase`), so a plan without one, or with a relative one,
     is refused with a notice saying how to call it. An allowed plan's
     directory is remembered for the session (in memory).
  3. *Every `localPath` is placed and judged.* An absolute one as written;
     a relative one against every directory a plan of the session named
     (over-gating a wrong base is safe); `~/` also as the home. Each
     spelling goes to the arbiter's new `fileUploadDecision` op on the
     human plane (`arbiter/policy/file-upload.ts`): a built-in sensitive
     path, a label above `public` (human, catalog, derived or session
     label, or a registered secret file) not bound to `claude.ai`, a file
     the arbiter could not read whole (missing, not a regular file, over 8
     MiB), or bytes holding a registered secret value not bound there, each
     deny with approval (`fs:upload-*` rules); a symlink is judged by its
     real path too. Each held file is an Approvals row `fs:DesignSync:upload`
     × path, so *Allow once* and *Always* work as for the sensitive-path
     gate. From the data socket the op reads nothing and refuses
     (`fs:upload-unattested`).
  Any block, a relative path no plan places (a restarted proxy), an input
  the gate cannot read, or an arbiter that lacks the op, throws or does not
  answer refuses the WHOLE call: its input becomes `{action:
  "mandu-refused: …"}`, which the schema rejects (`method` is required,
  unknown keys are not allowed), so nothing is uploaded; the model reads the
  gate's notice in place of the validation error, and its own call back in
  its history. Proof: `arbiter/test/unit/file-upload.test.ts` (each rule;
  a registered `.env`, a copy of its key, a symlink, a missing and an
  oversize file over the real server; the data socket),
  `arbiter/test/unit/tool-gate-surface.test.ts` (the fields on the captured
  wire), `interceptors/anthropic-proxy/test/unit/upload-gate.test.ts`,
  `test/component/design-sync-upload.test.ts` (the real proxy, a recorded
  plan and upload, the notice next turn, a control with no table) and
  `tests/stack/design-sync-upload.test.ts` (the oracle: the real arbiter
  and the production adapter, no byte of the key in what DesignSync would
  upload; ordinary files go; a human *Allow once* lets the `.env` go once;
  a gone arbiter sends nothing). *Residue (as shipped; narrowed
  2026-10-17, "The upload residuals" below):* the gate judges the file when
  the call is gated, not when the tool reads it (a file changed in between
  is the OS layer's); a tool outside every gate table that uploads a local
  path (an MCP server's upload tool, a built-in a release adds before it is
  mapped) is not gated on the wire: its result is masked whole while
  unmapped, but its upload is the OS layer's alone (under the `gated`
  posture the agent can read the file, and no check knows the call uploads
  it; `docs/guarantees.md` §3). A generic leg (every bare path in an
  unknown tool's input put to `fileUploadDecision`) was weighed and left
  out: it would hold every MCP read of a labelled file for approval, which
  the inbound masking already makes safe for the model (2026-10-17: built,
  with the local-server exemption that answers that objection). Then green on
  2.1.292: the claude differential lane on the host (the 65 CI shards
  `integration.differential.*`, and the full local lane, 70/70),
  `integration.replay-push.claude` (7), `integration.agent-sdk` (9),
  `integration.claude-code` (5), `integration.launcher-golden-path` (2),
  `integration.launcher-gated-posture` (2) and
  `integration.claude-settings-route` (4). The CI image then still pinned
  2.1.273 (2.1.295 since 2026-10-09); the guest lane on npm latest (`ci.claude-latest`) was not run for this
  bump.

**Claude Code 2.1.295: the interactive Artifact tools (2026-10-09).** The
headless surface of 2.1.295 is 2.1.292's (the same 23 tools, byte-identical
definitions to 2.1.294's). The *interactive* surface was never captured
before: the TUI (`claude 'hi'` under `script(1)`, API-key auth, against the
same stub upstream) advertises 31 tools, identical in 2.1.290, 2.1.292,
2.1.294 and 2.1.295, and five of them no spec knew: `Artifact`,
`ArtifactComments`, `ArtifactData`, `EndConversation` and `SendFeedback`
(their definitions:
`arbiter/test/fixtures/claude-artifact-tools-2026-10-09.json`). The live
batteries' subscription sessions advertise none of the five (their
`tool_surface` read "all known"), so whether a session gets them depends on
the account or a server-side flag; a session that did read DEGRADED, and
its Artifact uploads had no wire gate. Mapped in `claude-code-inbound.ts`:
`Artifact` (a published page someone else owns, other people's titles),
`ArtifactComments` (comment text viewers wrote) and `ArtifactData` (rows
the page's viewers wrote) UNTRUSTED, DesignSync's class; `EndConversation`
(no input) and `SendFeedback` (a draft queued locally, sent only on the
user's approval) TRUSTED acks. Three of them send to claude.ai, so Claude
Code's `upload` table names them (`tool-gate-surface.ts` `UploadKind`; the
union carries them) and `upload-gate.ts` gates each before every other
gate, the net legs over every string the call sends first, as for
DesignSync:
- *`Artifact` (`claude-artifact`).* A `publish` (the default `action`)
  reads the page `file_path`, every `files` source (a list of `{path}`, or
  a map of published path to a source path or `{from}`; a `{artifact,
  path}` entry is a server-side copy and reads nothing local), relative to
  `root` or the working directory, and `file_paths` (a later release's
  asset upload). Each is placed absolute only: as written, or a `files`
  source against an absolute `root`; `~/` as the home. The working
  directory follows the shell's `cd` and is not known to the proxy, so a
  path relative to it, or a relative `root`, refuses the call with a notice
  that says to call again with absolute paths (`proxy:upload-relative-path`).
  Each placed file goes to `fileUploadDecision` (an Approvals row
  `fs:Artifact:upload` × path). `list`, `read`, `delete`, `pin` and `unpin`
  send only text (`read` with `out_dir` / `path` saves a published file
  here, which is a download, not an upload).
- *`ArtifactData` (`claude-artifact-data`).* `set` / `update` take a
  local JSON file by `file_path` whose object is sent as the document, and
  `batch` one per `writes[].file_path`: placed and judged the same way,
  whatever the action.
- *`ArtifactComments` (`claude-artifact-comments`).* No local file; its
  `reply` text goes through the net legs.
Every one takes `action` from an enum, so the refusal `{action:
"mandu-refused: …"}` fails its schema and nothing is sent; the model reads
the gate's notice next turn. Proof: `arbiter` `claude-code-policy` (the 31
names known, each verdict), `tool-surface` (unit and component),
`tool-gate-surface` (the fields on the captured wire, the refusal fails each
schema); `anthropic-proxy` `upload-gate` (unit) and `design-sync-upload`
(component: the real proxy, a held supporting file, the notice next turn,
a relative page path, an ArtifactData batch, a control); and the oracle
`tests/stack/artifact-upload.test.ts` (the real arbiter and the production
adapter: no byte of a registered key in what Artifact or ArtifactData
would send, by a supporting file, a copy of the key or a symlink; the
key's symbol in a comment reply or inline data refused; ordinary pages go;
*Allow once* lets the `.env` go once; a gone arbiter sends nothing).
*Residue:* `Artifact` `read` and `ArtifactData` `out_dir` write remote
content into local files without passing the model context (an integrity
matter, frozen with its axis); the residue of the 2.1.292 entry holds for
these tools too, as narrowed below.

**The upload residuals (2026-10-17).** The two entries above left three
residues (`docs/guarantees.md` §3): an upload tool no table maps was gated
only by the confinement; the file was judged when the call was gated, not
when the tool read it; and the upload host was assumed to be `claude.ai`.
Each was taken up without a live model run (item 4 ports the leg to
Codex).

1. *The host, observed.* The strings of the Claude Code 2.1.302 binary
   (excerpts pinned in
   `arbiter/test/fixtures/claude-upload-hosts-2026-10-17.json`) show
   DesignSync posting every MCP call, `write_files` with its file bytes
   included, to `${BASE_API_URL}/v1/design/mcp` ("Claude Design is only
   reachable from api.anthropic.com"), and the Artifact tools' file inputs
   hashing each file, then re-reading it, refusing a changed hash, and
   PUTting the bytes to an upload URL whose origin must be the OAuth API
   host's (`api.anthropic.com`; `api-staging.anthropic.com` when the
   service hands it out). So the bytes go to a MODEL API host, which the
   egress proxy did not carry until 2026-10-18 (`MODEL_HOST_SUFFIXES`, the
   launch's `NO_PROXY`): no network layer saw these uploads, and the
   model-wire gate was the only check they met. Under the model-host deny
   (agent-sdks.md §4, whenever the confidentiality axis is on and the
   egress proxy runs) they ride the egress proxy's TLS-inspected leg: their
   paths (`/v1/design/mcp`, `/api/artifacts/mcp`, the Artifact pages
   service's `/api/frame/…`) are on `api.anthropic.com`'s list, and each
   request meets the inspected leg's gate and verbatim tripwire too; the
   model-wire gate stays the decision. The guard's connect records and the
   egress proxy's connection attribution cannot observe them either (the
   agent's own process connects to a host both admit), and an observation
   would come after the bytes left in any case. The gate now names every
   host (`upload-gate.ts` `UPLOAD_HOSTS`: `claude.ai`, the service the
   tools present as, and `api.anthropic.com`, where the bytes go): the net
   legs ask about each (strictest first block), and `fileUploadDecision`
   takes `destinations`, a label or a registered value counting as bound
   only where its bindings name every host (`file-upload.ts`
   DESTINATIONS). A file bound to `claude.ai` alone, which the shipped
   gate released while its bytes went to `api.anthropic.com`, is now held;
   a binding to the API host alone (the agent key's own) releases nothing
   either. The per-symbol leg no longer takes the TLS-inspection release
   for an upload (`tlsInspected` is ignored): with the egress proxy never
   on the path, an allowed placeholder would have gone out as its literal
   token, so the call is refused instead (`proxy:symbol-in-tls-tunnel`).
   A unit test pins every host the fixture names into `UPLOAD_HOSTS`; a
   new release's capture adds to the fixture.
2. *The window.* The gate cannot bind its check to the bytes the tool
   reads: the tool reads in the agent's own process and sends to a host no
   Mandu layer sees, the digest the 2.1.302 Artifact client checks is its
   own (`requiredDigest` comes from files the person attached, never from
   the model's input), and DesignSync confines `localPath` to the plan's
   folder, so a frozen copy elsewhere cannot be substituted. What the proxy
   can close is the deterministic case: the agent runs one turn's calls in
   order, so `[Bash "cp ~/notes.txt site/a.html", Artifact a.html]` in one
   message has the gate judge the clean file and the tool read the copy.
   The proxy now keeps the calls of each response (one model turn) and
   refuses an upload of a local file after an earlier call of the same
   turn that may write files (`unmapped-upload.ts` `possibleWriter`: a
   shell, a write or patch tool, a dispatcher, a subagent, any unmapped
   tool; not a read-only path tool, a fetch, or bookkeeping such as
   `TodoWrite`): the mapped leg refuses the whole call before asking
   anything, the unmapped leg withholds each path it judged by its bytes
   (`proxy:upload-after-write`), and the notice says to call it again on
   its own. *Left:* a program already running (a shell started earlier
   with `&`, a `Monitor`, a background subagent) can change the file
   between the check and the read; under `confined` the guard's placeholder
   copies cover a registered or labelled secret file and any file a reader
   writes, not a file that merely holds a copy of a registered value. An
   agent that runs a turn's calls at once (not Claude Code) races a writer
   that comes later in the same turn. Closing the rest needs an
   enforcement point when the tool reads: the file guard denying writes to
   a leased file between the check and the upload, or the model API host
   routed through the egress proxy with its TLS inspection and the raw
   value check (a maintainer decision: the model host was excluded from the
   egress proxy on purpose; since 2026-10-18 the model-host deny routes the
   tree's direct calls there through the inspected leg, agent-sdks.md §4,
   so the verbatim tripwire now sees these uploads' bytes, though not the
   file the tool reads at the moment it reads it).
3. *The unmapped upload leg* (`interceptors/anthropic-proxy/src/unmapped-upload.ts`;
   `file-upload.ts` rules 0, 4a, 5a). For every tool no table of the
   session's surface names (an MCP server's tool, a claude.ai connector's
   attachment such as 2.1.302's Chrome `file_upload{paths}` or a managed
   agent's `start_task` files, a built-in a release adds), every string of
   its input that names a local path (absolute, `~/`, a `file://` URL; a
   relative one only under a key such as `path`, `file`, `src`, placed
   against the launch directory) goes to `fileUploadDecision` with
   `unmapped: true` and no host. The arbiter reads the session's mapping
   first and opens no file for a tool that keeps its own legs (spec,
   harness, surface, Mandu's own: `fs:upload-mapped-tool`) or for a tool of
   an MCP server the launcher registered as a local process in a session
   the file guard confines (`fs:upload-confined-server`): that server is a
   program the guard and the egress proxy confine like any the agent runs,
   so a local filesystem server reading a labelled file keeps working under
   `confined`, which answers the objection that kept the generic leg out
   in 2.1.292. Otherwise the file is judged as a mapped upload's, with no
   host, so no binding releases it: a sensitive path, a secret label, a
   registered value in the bytes, a file of a process (`/proc`, `/sys`,
   `/dev/fd`: `fs:upload-process-file`, both forms), or bytes the arbiter
   could not read are held for approval (an Approvals row `fs:<tool>:upload`
   × path); nothing at the path (a remote API's `/v1/items`) or a device
   passes (`fs:upload-no-file`), and a folder passes on its own label and
   the sensitive paths alone (`fs:upload-folder`). A held path's string
   becomes `/mandu/denied/upload/<path>`, which names no file, so the tool
   cannot read it whatever its schema accepts, and the rest of the call is
   the model's; the model reads why in place of the result, and its own
   call back. An arbiter without the op, one that throws or hangs, or more
   than 256 path-like strings withhold every path, and a value nested more
   than 32 levels deep is withheld whole. *Utility:* a call names
   a secret path rarely; the cost falls on an unmapped tool that reads a
   secret file under `gated` (or from a server Mandu did not register),
   which now asks once per path, and on an unmapped call that follows a
   shell in the same turn, which is made again on its own. *Left:* a path
   Mandu cannot recognize as one (a relative path under another key, a
   path inside prose or a JSON string), the files inside a folder an
   unmapped tool names, and a path that names nothing when the call is
   relayed and is created later by a program already running.
4. *The same leg for Codex* (2026-10-17;
   `interceptors/openai-proxy/src/unmapped-upload.ts`). Until then the
   openai-proxy had no such leg: a Codex MCP call
   `{namespace: "mcp__drive", name: "upload_file", arguments: {path:
   ".../.env"}}` reached Codex unchanged, its result masked whole while
   unmapped, and the file it sent kept home only by the confinement. The
   pure core (finding the paths, the arbiter asks, the withheld spelling,
   the notices) is one text in both proxies
   (`interceptors/{anthropic,openai}-proxy/src/unmapped-upload-core.ts`,
   byte-equal below a marker line; the openai-proxy's unit test pins the
   two, the repository's copy-and-pin convention for code the proxies share,
   as `auth-substitution.ts`), and the arbiter side is unchanged: the same
   `fileUploadDecision` op in its unmapped form, asked on the human plane
   (the openai-proxy's adapter gained the op, routed as the
   anthropic-proxy's; `tests/stack/codex-unmapped-upload.test.ts` pins the
   production wiring). What is Codex's:
   - *Which tools.* Every tool but Codex's own: its shells and
     `CODEX_MAPPED_TOOLS` (`apply_patch`, `view_image`, the file, goal,
     timer and sub-agent tools, the cells) keep their own legs and are
     never asked about. A namespaced call goes by `<namespace>__<name>`
     (the request side's spelling, now one helper, `codexToolName`), so an
     MCP server the launcher registered meets rule 0 exactly as on Claude
     Code. A relative path under a path-like key is placed in the session's
     directory as Codex's own `<environment_context>` names it (the
     request side's `codexSessionCwd`, HumanView); with none named, a
     relative path is not read as one. The leg runs first in the arguments
     transform (it judges the HumanView path the model wrote), then the
     exec gate, then the forward view map, on the stream and the buffered
     answer alike (and on the Chat Completions route, whose tool names are
     not Codex's: there every tool is asked and the arbiter's rule 0 exempts
     what the session's spec maps). The exec-gate switch (`execGate:
     false`, a test affordance) turns it off with the other response-side
     gates.
   - *A withheld function_call.* The path becomes `/mandu/denied/upload<path>`
     and the rest of the call is the model's; the call's output in the next
     request is replaced by the notice (`UploadNotices`, after the value
     backstop finds no registered value in it, the anthropic-proxy's
     ResultNotices), and the model reads back its own call (exec-history.ts).
     Each withheld path is an `fs_action` event (`makeFsGate`, the
     anthropic-proxy's shape).
   - *Code mode.* On codex's code-mode wire every MCP call rides inside an
     `exec` JavaScript cell. A cell the allow-list grammar identifies call by
     call (`mcp-cell.ts` `parseCell`, the request declaring each cell a fresh
     isolate) has each non-Codex call judged on its literal arguments, in
     order, an earlier call of the cell that may write counting as a writer.
     Any other cell has every string its text spells (`cellStringLiterals`:
     quoted strings and template pieces, escapes decoded, read by a scanner
     and by a plain pattern) judged under each non-Codex tool its text names
     (`writtenToolNames`; a tool it does not name is switched off by the
     cell guard), an exec or another tool named in it counting as a writer.
     A hold replaces the WHOLE cell by the exec gate's sentinel cell, which
     prints the notice (a `plainBlockWords` branch says a call in the cell
     would send a held file); its output reaches the model as that notice
     through the exec gate's whole-cell notice path, and the model reads
     back its own cell. A cell is code, so a held cell is not run half.
   - *The window.* Codex runs its tool calls under a lock: a tool that
     supports parallel calls takes it shared, one that does not takes it
     exclusive (codex-rs `core/src/tools/parallel.rs`; an MCP server is not
     parallel unless its config sets `supports_parallel_tool_calls = true`,
     a key present in the 0.162.0 binary). So an MCP upload starts only
     after every call the response named before it has finished, and the
     anthropic-proxy's rule holds: a path judged by its bytes in a call
     after a possible writer of the same response is withheld
     (`proxy:upload-after-write`). The calls are tracked per response in
     stream order (`UploadTurn`, by item id, recorded as each item is
     first seen); a writer is anything but Codex's bookkeeping
     (`CODEX_NON_WRITING_TOOLS`: the plan, the questions, the goal, the
     timer, the file readers, the image viewer, the tool search, the
     sub-agent tools that only look).
   *Left:* a server configured with `supports_parallel_tool_calls = true`
   runs its calls beside the turn's other parallel-capable calls
   (`exec_command` among them), so a writer LATER in the same response can
   change the file while it is read; a path a cell computes at run time
   (`[dir, name].join("/")`) is not read, nor a cell's call reached through
   a value an earlier cell stored when cells are not fresh isolates (older
   codex); the rest as item 3. *Utility:* as item 3; on Codex a cell that
   calls an unmapped tool with a path-like string after its own
   `exec_command` call is held whole, and the model is told to make the
   call on its own.

Proof: `arbiter` `file-upload` (unit: the destinations, the process files,
each rule of the unmapped form, the op over the real server with a
registered `.env`, a copy of its key, a symlink, a missing path, a folder,
a spec-mapped built-in and an unguarded registered server);
`anthropic-proxy` `upload-gate` (unit: `UPLOAD_HOSTS` pinned to the
fixture, `destinations` on every ask, the net legs at each host, no TLS
release, the window), `unmapped-upload` (unit) and `design-sync-upload`
(component: the surface without the upload table, before 2026-10-17 an
unchanged upload, now the secret path withheld; a Bash then an Artifact in
one turn); and the oracle `tests/stack/unmapped-upload.test.ts` (the real
arbiter and the production adapter: no byte of a registered key in what an
unmapped MCP upload or a Chrome attachment would send, by the file, a copy
or a symlink; a clean file and a remote path unchanged; a Bash copying the
key then the upload in one turn sends nothing of it after the copy runs; a
page bound to `claude.ai` alone held from Artifact, bound to both hosts
sent; a gone arbiter withholds every path). For Codex: `openai-proxy`
`unmapped-upload` (unit: the core equal to the anthropic-proxy's, which
tools and which writers, the cell's strings, a namespaced MCP upload
withheld and its output replaced by the notice next request, the window,
an identified and an unidentified cell held whole, the buffered answer,
fail-closed) and the oracle `tests/stack/codex-unmapped-upload.test.ts`
(the real arbiter and the production adapter: no byte of a registered key
in what a namespaced MCP upload would send, by the file, a copy or a
symlink; a clean file and a remote path unchanged; an `exec_command`
copying the key then the upload in one response sends nothing of it after
the copy runs; an MCP call in a code cell, identified or not, calls no
upload tool; the notice next request; the adapter asks on the human
socket). Red on the code before it: the key's path reached Codex
unchanged, and the adapter had no op.

**Claude Code's permission mode under Mandu: its default, unless the user
chose one (measured and decided 2026-10-09).** With
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, which the launch sets
(exec-routing.md §7.4), Claude Code 2.1.290 through 2.1.295 fetch no feature
flags and start in permission mode `auto` unless the user picks one; the
flags served without the variable keep it `default`. Measured on 2.1.295
against a stand-in model, in a fresh home: `-p` and the TUI both record
`"permissionMode":"auto"` in the transcript with the variable and no
choice. In `auto` a Bash command (even one `--allowedTools` names) first
goes to Claude Code's classifier, a non-streaming Messages request through
the context proxy (os-test-matrix.md §10.14.1 item 9), and Claude Code asks
the user less than the same Claude Code without Mandu. Mandu's gates do not
depend on the mode, but a user should get the agent they know.

*The decision.* The launch keeps the variable and passes
`--permission-mode default` to a Claude Code session unless the user
already chose a mode. The rule has one copy,
`launcher/src/claude-permission-rule.cjs`, which the launch
(`claude-permission-mode.ts`), the SDK route's preload and the `claude`
PATH shim all apply. A choice is any of:
- `--permission-mode <any value>` on the command line (either spelling);
- `--dangerously-skip-permissions`;
- `--inherit-permission-mode <any value>` (either spelling; 2.1.302's help:
  "Permission mode carried from a parent session, used only when nothing
  else configures one"), so a parent session's mode handed to its child is
  never overridden;
- `permissions.defaultMode` (any non-empty string) in a settings source
  Claude Code reads for this launch: the run's own last `--settings`
  (inline or a file) and any `--managed-settings`, the managed sources (the
  managed file and its drop-ins, the server-managed cache, macOS MDM; one
  Mandu cannot read counts), and the user, project and local files
  (claude-sandbox.ts `claudeSettingsFiles`, the same set §2.5 reads) unless
  `--setting-sources` leaves them out or `--restricted` drops them.

A command-line flag outranks every settings source in Claude Code
(measured: `defaultMode: "acceptEdits"` in the user file plus
`--permission-mode default` started in `default`), so the settings check is
what keeps the flag from overriding a choice made there. Not a choice:
`--allow-dangerously-skip-permissions` only makes bypass selectable (alone
it still started in `auto`; with the flag in `default`, bypass one
Shift+Tab away, as without Mandu). Re-read in 2.1.302's bundle
(2026-10-18): its start-mode resolver takes the mode from
`--permission-mode`, `--inherit-permission-mode`,
`--dangerously-skip-permissions`, an agent's frontmatter and the settings'
`defaultMode`; `--allow-dangerously-skip-permissions` sets no mode, it
only makes bypass available and lets a settings
`defaultMode: "bypassPermissions"` take effect, which the settings check
already counts. Also not a choice: a `defaultMode` that is not a string
(Claude Code ignores it). An unknown mode name is counted, so a newer mode
is never overridden. `default` is what 2.1.295's help now calls `manual`;
both are accepted and both record `default`. Only a session gets the flag:
`claude mcp …`, `config`, `doctor`, `update`, `--version`, `--help` and the
other subcommands that run no model do not (claude-sandbox.ts
`claudeRunsSession`), nor `agents`, `remote-control` / `rc` and `daemon`
(2.1.302 recognises `claude daemon` only as the first argument after the
skip-permissions flags, so a flag ahead of it would make it a prompt). The flag goes ahead of the user's arguments, so
`--resume` and `--continue` get it like a new session.

The SDK route (agent-sdks.md) does the same for every `claude` a Node host
program starts: the preload adds the flag unless the child's own arguments
choose a mode (the SDK's `permissionMode` becomes `--permission-mode`), or
a settings scope it reads sets one; the launch computes which scopes set
one for its folder and user config dir, and a child started in another
folder (project or local files Mandu did not read) or with another
`CLAUDE_CONFIG_DIR` is left alone.

*A `claude` the session starts by name (2026-10-18).* Mandu never sees the
command line of a `claude` started from inside a session: from the shell
of `mandu -- bash`, from a script, from the agent's own Bash tool. It
carried the launch's `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, so it
started in `auto`. Every claude or shell launch the SDK route does not
serve now writes a `claude` PATH shim, `<scope run dir>/sdk-shims/claude`
(sdk-route.ts `writeClaudeShim`; its folder is write-protected for
the agent, agent-sdks.md §3.6), and puts its folder first on the agent's PATH. The shim
runs the preload's `--claude` entry with the launcher's Node: it finds
the real `claude` further down PATH, applies the rule above to its
arguments with the launch's answer for the settings scopes (baked into the
shim, as the SDK route carries it), routes it as `mandu claude` is routed
(§2.5, agent-sdks.md §3.5), and `execve`s it in place. As for the
SDK route, a `claude` started in another folder than the launch folder, or
with another `CLAUDE_CONFIG_DIR`, is left alone: Mandu has not read that
folder's project and local settings (it still gets the flag when its
`--setting-sources` reads none of the unread files). The shim is written
only when a real `claude` is on PATH, so `command -v claude` stays honest
for a shell user without Claude Code. `mandu claude` itself starts the real
`claude` by path (the launch resolves a bare `claude` past the shim and
applies the rule to its own command line), so the agent has no extra Node
in front of it and the flag is added once; a nested `claude` the agent
runs meets the shim. A launch the SDK route serves already has the full
`claude` and `codex` shims (agent-sdks.md §3.3), which apply the same rule.
A `claude` started by its full path is not covered (it keeps its own start
mode; its model calls are refused at the transport since 2026-10-18,
agent-sdks.md §4, "The model-host deny").

The drills and the e2e harnesses pass an explicit mode
(`--permission-mode acceptEdits` / `bypassPermissions`,
`--dangerously-skip-permissions`), so nothing changes for them. Proof:
`launcher` unit `claude-permission-mode` (every choice, the non-choices,
the subcommands, the launch's wrappers and the preload over the one rule,
the PATH lookup) and component `claude-permission-mode` (a stand-in
`claude` launched by `main()`: no choice gets the flag, each kind of
choice is kept, `mcp list` gets nothing, and the SDK route's child
likewise; since 2026-10-18 `mandu -- sh -c 'claude …'` through the shim:
the flag for no choice and for the SDKs' stream-json line, each choice
kept, `--allow-dangerously-skip-permissions` not one, `mcp list`, `daemon`
and `agents` untouched, `--version` answered, user and launch-folder
settings kept, another folder left alone; `mandu claude` by name with
the flag once and the agent's nested `claude` given it; no shim without a
real `claude`). Checked by hand with the real 2.1.295
under this checkout's `mandu claude` (mode `secrets`, a stand-in model, a
fresh home): `-p` and the TUI record `default`; `--permission-mode auto`
records `auto`; `defaultMode: "acceptEdits"` in the user file records
`acceptEdits`, and with `--setting-sources project` (the user file unread)
`default`.

OpenClaw, OpenCode and Goose are not installed on the host that ran this,
so their ranges are unchanged.

**The 2026-10-09 qualification.** The ranges were raised to Claude Code
2.1.294 (then 2.1.295, below), Codex 0.162.0, OpenCode 1.18.35, OpenCode 2 2.0.26 and Goose
1.54.0, each after its batteries ran green on that version and its
advertised tool surface read fully mapped (the evidence is in the table
above and in each version's `evidence` string in `agent-versions.ts`):
Claude Code 2.1.294 once the interactive Artifact tools were mapped and
their uploads gated (above); Codex 0.162.0 with the same tools as 0.160
and its classic wire's prompt moved into a developer message (§6.4);
OpenCode 1.18.35 and 2.0.26 with tool surfaces unchanged from 1.18.13 and
2.0.23; Goose 1.54.0 with 1.53.0's surface (§5.6). Each also had a live
leg on haiku in mode `secrets` with no leak. The two OpenCode lines and
Goose keep their lowest tested version as `min`, so their rows now read as
ranges. Claude Code 2.1.295 followed the same day: the headless and the
interactive surfaces unchanged from 2.1.294 (all mapped), the claude
differential lane 70/70 on the host, the per-push replay drills, the
agent-SDK suite, the fresh-agents VM legs on Ubuntu 24.04 and 26.04 75/75
(a Bash leg's first failure was the scripted model answering Claude Code's
auto-mode classifier with no verdict, a harness fault, not 2.1.295's) and a
live leg on haiku in mode `secrets` (`conf-read-exfil`, `util-quote-line`).
OpenClaw 2026.9.9 was qualified too, the same day: its surfaces in every
Tool Search mode mapped, refused on the wire or gated through the
dispatcher, Code Mode refused on the wire and turned off in the run config
(§2.1, "OpenClaw 2026.9.9 and Code Mode"), the fresh-agents legs 75/75,
`integration.openclaw-e2e` 8/8, and a live leg on haiku in mode `secrets`
(`conf-read-exfil`, `conf-public-label-wins`, `util-write-file`,
`util-shell-echo`).

**OpenCode plugins and custom tools** (2026-10-06, 2026-10-07). A plugin
runs inside OpenCode and writes the model request past every check
(measured: a project plugin put a pinned reader's raw output into the
system prompt). With confidentiality ON none runs, whoever brought it: a
project's (§2.3 item 11) or the user's own, the global config directory's
and the npm plugins a global `opencode.json` names (§2.3 item 12). OpenCode
2 starts without them; OpenCode 1 runs with its own `OPENCODE_PURE=1`
switch (no external plugin), and is refused only where a custom tool
(which that switch does not skip) would load. The launch names what it left
out. `MANDU_OPENCODE_PROJECT_PLUGINS=1` / `MANDU_OPENCODE_GLOBAL_PLUGINS=1`
run them, with a warning. A change the agent makes to the user's OpenCode
settings files or plugin folders waits in Approvals.

**Claude Code: harness causes, not drift.** Two red results on the way to
2.1.287 were the harness, not the agent: a wrapped workspace seeded unlike
the vanilla one (`differential-interactive.md` §19), and a private arbiter
whose tenant did not match its launch (§24 there). One divergence is real
and declared: in the guard-only posture (no secret bind, for example a host
whose bubblewrap profile forbids nesting) Claude Code's permission dialog
names `<scope>/secret-twins` where vanilla names the cwd, on every version
(`differential-interactive.md` §20). On 2.1.302 the lane went red on one
footer row, `· ← for agents` shown on one side only. That was a timer in
Claude Code, not Mandu: 2.1.302 hides the hint 10 s after the prompt
appears, with or without Mandu (2.1.295 shows it for good). So a checkpoint
near that mark shows it on whichever side got there sooner. Mandu changes
none of the hint's other inputs: the agents-view env var and setting,
session persistence, a remote workspace, the `leftArrowOpensAgents`
setting. The wrapped side shows the hint before the 10 s mark, like
vanilla does (one red cell had it on the wrapped side only). The lane
masks the hint (2026-10-18, `differential-interactive.md` §37). The CI image then pinned 2.1.273, the
floor of the range (2.1.295, its top, since 2026-10-09). The tool surface Claude Code 2.1.287 advertises headless
with no MCP server (20 tools: Agent, Bash, CronCreate, CronDelete, CronList,
Edit, EnterWorktree, ExitWorktree, ListAgents, NotebookEdit, Read,
ReportFindings, ScheduleWakeup, SendMessage, Skill, TaskStop, WebFetch,
WebSearch, Workflow, Write) is all known to the inbound spec.

The table is `TESTED_AGENT_VERSIONS` in `launcher/src/agent-versions.ts`,
mirrored in `dashboard/src/agent-versions.ts` because the two packages ship
standalone. `tests/stack/agent-versions-parity.test.ts` holds the
two tables equal, the two checks answering alike, and the README's "Supported
agents" table in step.

**Generations (2026-10-05).** OpenCode 2 is a rewrite, not a later 1.x, so
it has a tested range of its own: `TESTED_AGENT_GENERATIONS` (beside the
table, mirrored the same way) holds a range per major, and `testedRangeOf`
judges a version against its major's range when there is one, else the
agent's. So 2.0.23 to 2.0.26 are `tested` (2.0.23 read "newer than tested"
against 1.18.13 before), 2.0.27 is `newer than tested (2.0.23 to 2.0.26)`,
and 1.18.36 stays newer than 1.x's range. A generation keeps the agent's
name, so the warning reads "OpenCode 2.0.27 is newer than tested (Mandu was
tested with OpenCode 2.0.23 to 2.0.26)"; its README row is `<name> <major>` ("OpenCode 2"). A major with no
range of its own (the `0.0.0-*` prereleases, 3.x) falls back to the agent's
and is refused at launch anyway (§2.3). The launch warning, `mandu doctor`
and the dashboard's health chip and product notice all go through the same
check, so each judges 2.x against 2.x. The parity test samples 2.0.22,
2.0.23, 2.0.24, 2.0.26, 2.0.27, `opencode v2.0.23` and `0.0.0-beta-1`.

`mandu doctor` reads each installed agent's version with `<bin> --version`
and must only look. Codex sets up its helper links under
`$CODEX_HOME/tmp/arg0` at every start, `--version` included (codex-cli
0.155.1, measured 2026-10-01), so the doctor's codex probe gets a throwaway
`CODEX_HOME` that is removed afterwards (`probeAgentVersionLooking`); the
user's `~/.codex` is not touched. OpenCode makes its XDG folders and a log
on `--version`, and Goose 1.53.0 writes a log under
`$XDG_STATE_HOME/goose/logs` (measured 2026-10-06; nothing under HOME once the
XDG folders are set), so both get throwaway XDG folders the same way. The
launch-time check probes as before: the launch runs the agent next anyway.

### 2.1 OpenClaw 2026.9.x: the tool surface and its gates

Three things had to be handled before 2026.9.6 joined the range. The
surfaces were captured from real requests with no Mandu in the path
(`arbiter/test/fixtures/openclaw-tool-surface-2026-09-27.json`).

1. **The Tool Search dispatcher is on by default.** With `tools.toolSearch`
   unset, 2026.9.6 advertises only `read`, `write`, `edit`, `apply_patch`,
   `exec`, `process`, `ls`, `view_image`, `sessions_yield` and the dispatcher
   `tool_search` / `tool_describe` / `tool_call`. Everything else (`web_fetch`,
   `web_search`, `memory_search`, `cron`, the session tools) is reachable only
   as `tool_call{id, args}`. The dispatcher's results classify UNTRUSTED, so
   the integrity invariant holds without more. The wire gates need more: the
   exec, net and path gates and the exec-output legs (callTaint, the value
   backstop) keyed on the outer tool name, so a `tool_call` to `exec` or
   `web_fetch` would pass them unseen, and in the default `secrets` mode a
   dispatched `cat .env` result would reach the model raw. The same holds on
   2026.6.35 and 2026.7.1 when a user turns `tools.toolSearch` on.
   `tools.toolSearch: {mode: "code"}` swaps the dispatcher for
   `tool_search_code`, which runs JavaScript that calls tools.

   **The gates see through the dispatcher.** The gate surface has a
   `dispatch` table (`tool-gate-surface.ts`; OpenClaw: `tool_call` →
   `openclaw-tool-call`, `tool_search_code` → `refuse`), and the proxy's
   `dispatch.ts` reads a `tool_call` as the tool it runs:
   - the inner tool's name is the id's last `:` segment (`exec`,
     `openclaw:core:exec`, `openclaw:memory-core:memory_search`); its input
     is `args` (or `input`), else the keys beside the id (2026.9.x's
     flattened form);
   - every response-side gate (net, exec, sensitive path, derived label, the
     view map) runs on the inner tool, and a rewrite is put back into the
     same envelope;
   - on the result, the path-derived level (origin and params) and callTaint
     read the inner tool; trust stays the dispatcher's own UNTRUSTED, because
     a bare name may resolve to a plugin or MCP tool that shares a core
     tool's name;
   - a shape whose meaning differs between versions (two selector keys,
     dotted `args.<key>` keys, `args` beside loose keys, a non-object `args`)
     or a dispatcher named inside the dispatcher is REFUSED: the agent
     receives `{id: "mandu-refused: <why>"}`, OpenClaw answers "Unknown tool
     id: mandu-refused: <why>", nothing runs;
   - `tool_search_code` is refused on every call: its code becomes a `throw`.
     The code calls tools through `openclaw.tools.call(id, args)` inside a
     Node child, which no wire gate can read (the openai-proxy refuses an
     unparseable Codex JS cell for the same reason, §6.2).

   An arbiter that predates the table answers none, and the proxy then
   applies the union's dispatchers (over-gating a name is safe). Pinned by
   `interceptors/anthropic-proxy/test/{unit/dispatch,component/openclaw-dispatch}.test.ts`
   (each gate with a control on a surface without the entry) and
   `tests/stack/openclaw-dispatch.test.ts` over the real
   arbiter and the production adapter (fails on both counts with the entry
   removed).
2. **With `tools.toolSearch: false` the surface grows by 17 tools** (plus
   `tool_search` / `tool_describe`, which the default mode shows), and
   several act outside every Mandu chokepoint. 2026.6.35 and 2026.7.1 accept
   the key (their dispatcher is off by default); 2026.3.12 rejects it
   ("Unrecognized key"). Every tool on the three captured surfaces is
   handled, read from its source in the 2026.9.6 package (a unit test holds
   each surface to the spec, the refuse table and the dispatch table):

   | Tool | Handling | Why |
   |---|---|---|
   | `terminal` | refused on the wire | types into a shell the operator opened in the gateway's Control UI: the gateway runs it, outside Mandu's sandbox, so no gate confines it |
   | `automations` (alias `cron`) | refused | schedules agent runs that fire later in the gateway, outside the session; `gatewayUrl` / `gatewayToken` name any endpoint |
   | `gateway` | refused | reads the gateway config and runs OpenClaw's self-update |
   | `plugins` | refused | installs, enables and reloads executable plugins |
   | `secrets` | refused | asks the human for a credential and binds it to hosts the agent names, for substitution outside Mandu's registry |
   | `portal` | refused | exposes a local port through a gateway route |
   | `nodes` (`full` profile) | refused | runs commands on paired devices |
   | `conversations_send`, `conversations_turn` | net gate on `message`, no checkable destination; UNTRUSTED | send to an external channel through the gateway: blocked in a high session and on any symbol, the block's added key fails their `additionalProperties: false` schema so nothing is delivered |
   | `conversations_list` | UNTRUSTED | channel metadata |
   | `agents_wait` | UNTRUSTED | subagent results (Task's class) |
   | `ask_user` | UNTRUSTED | the answer may come over a message channel from whoever answers there, unlike AskUserQuestion's terminal user |
   | `sessions`, `sessions_search` | UNTRUSTED | other sessions' titles and transcript text |
   | `intent` | UNTRUSTED | standing-intent descriptions earlier sessions wrote |
   | `dashboard`, `theme` | UNTRUSTED | plugin widget props and plugin theme text |
   | `tool_search`, `tool_describe` | UNTRUSTED | catalog entries with plugin-authored descriptions |
   | `progress_card` | TRUSTED | answers only the card's revision and step counts |

   **A refused tool** (the gate surface's `refuse` table, arbiter
   `tool-gate-surface.ts`, mirrored in the proxy) reaches the agent as
   `{action: "mandu-refused: <why>"}`. Every refused tool takes a required
   `action` enum and OpenClaw validates each call against the tool's schema
   before it runs (`validateToolArguments`, 2026.7.1 and 2026.9.6), so the
   call fails with the reason in its error and nothing runs. A `tool_call` to
   a refused tool is refused the dispatcher's way (`{id: "mandu-refused: …"}`).
   Refusing `cron` changes 2026.7.1 too: its scheduled runs fire in the
   gateway, outside Mandu. The session-health surface counts a dispatcher or
   a refused tool as handled, not unknown, so a 2026.9.6 session reads "all
   known" in every Tool Search mode
   (`arbiter/test/component/tool-surface.test.ts`). Pinned on the wire by
   `interceptors/anthropic-proxy/test/component/openclaw-dispatch.test.ts` (with
   controls) and `tests/stack/openclaw-refused-tools.test.ts`
   over the real arbiter and the production adapter.
3. **It needs Node ≥ 24.16** (`engines`). The fresh-agents suite picks the
   guest's Node major from the chosen OpenClaw's `engines`.

**The result:** a fresh-agents run through `mandu` on OpenClaw 2026.9.6
(Node 24, with Claude Code 2.1.281, Codex 0.154.0 and OpenCode 1.18.13)
passed 105 / 0 on both `ubuntu-2404` and `ubuntu-2604`, the OpenClaw legs
green in both modes (a secret read reached the model as
`$MDU:nomodel_read[…]` with read evidence; the poisoned note as
`$MDU:read[…]`).

**Beyond the `coding` profile.** The range was first claimed for
`tools.profile: "coding"`, the profile the suite and the captures use. Four
gaps sat outside it (on 2026.7.1 too); each is closed on the wire, read from
the tool's source in the 2026.7.1 and 2026.9.6 packages (the tools the
captures lack are listed, with their schema fields, under "2026.9.6 full
profile (package schemas)" in the fixture; that entry is read from the
package, not captured):

- **`exec{host: "node"}`** runs the command on a paired device through the
  gateway. The gate surface has a `refuseArgs` table (a tool refused in one
  FORM): `exec`'s `host` must be absent, empty, `auto`, `sandbox` or
  `gateway` (compared trimmed and lowercased, OpenClaw's own normalization;
  `auto` resolves to the sandbox or the gateway host, and under `mandu
  openclaw` the agent loop is this process). Any other value reaches the
  agent as `host: "mandu-refused: <why>"`, which the host enum rejects and
  OpenClaw's own host check throws on, and the command becomes the exec
  gate's exit-77 sentinel. `browser{target: "node"}` is refused the same way.
  Through `tool_call` the dispatcher call is refused. A host CONFIGURED as
  `node` (`tools.exec.host`, globally or per agent) applies to a call that
  names none, which the wire cannot see, so the launcher's run config drops
  it (`agent-config.ts` `fenceOpenclawExecHost`): every `tools.exec.host` in
  the merged `openclaw.json` that is not `auto`, `sandbox` or `gateway` is
  removed, with a WARNING naming it, and OpenClaw's default (`auto`) applies.
  Read from 2026.9.6 `exec-defaults.ts`: a call's own host, else the
  session's stored one, else the agent's, else the global one, else `auto`.
  The session's stored host (a user's `/exec host=node` in chat) is not in
  the file (§4).
- **`process{write, paste, send-keys}`** types into a background exec
  session's stdin, unseen by the exec gate, though the session is often a
  shell. The `stdin` table names `process`, and the proxy's `stdin-gate.ts`
  puts every typed stream through the arbiter's `execGate`, as a command:
  `data`, `text`, and `literal` + `hex` bytes + encoded `keys` as one stream
  (OpenClaw's encodeKeySequence order, so a symbol spelled across the three
  is still one token). An untrusted symbol in command position blocks it,
  and so does ANY typing in a high session (the net-capability leg that
  already blocks every shell command there: `y` + Enter into a prompt is
  refused too, the cost of a gate that cannot prove the process is
  net-less). A block, a non-text field, an unreachable arbiter or more than
  1 MiB of typed text refuses the whole call as `{action: "mandu-refused:
  <why>"}` (2026.9.6's action enum rejects it; 2026.7.1 answers "Unknown
  action"), so nothing is typed. The stdin text carries no callId, so it
  never becomes an exec supervisor correlation.
- **`sessions_send` / `sessions_spawn`** hand the work to whichever gateway
  serves the call: the in-process one only when the agent runs inside
  `openclaw gateway`; under `mandu openclaw chat` / `agent --local` OpenClaw
  falls back to the configured gateway (a daemon, or a remote one) outside
  Mandu, and `runtime: "acp"` starts an agent on the host. The proxy cannot
  tell the launch shapes apart, so both are refused on every shape (their
  schemas require `message` / `task`, so `{action: …}` fails validation).
- **`full`-profile and provider tools** all have a gate:

  | Tool | Handling | Why |
  |---|---|---|
  | `computer`, `mobile_ui`, `canvas` | refused | control the gateway's desktop, a paired computer, a paired Android app, a paired macOS widget panel (each takes an `action` enum) |
  | `openclaw` | refused | delegates setup and repair to a separate model turn that changes gateway config, plugins and credentials (requires `message`) |
  | `github_publish` | refused | the gateway pushes the session's workspace with credentials Mandu never sees; `git push` / `gh` through `exec` is checked instead (rejects unknown keys) |
  | `message` | net gate on `message`, path gate on `media`, upload gate on every media source (below, "Tools that send a local file") | a chat channel send |
  | `browser` | net gate on `targetUrl` and its `url` fallback, write path gate on `path` and the upload `paths`, `target: "node"` refused | navigates, types, uploads, runs page JavaScript |
  | `show_widget` | net gate on `widget_code` | CDN scripts, pinned widgets fetch declared origins |
  | `x_search`, `code_execution` | net gate on `query` / `task` | xAI |
  | `image_generate`, `music_generate`, `video_generate`, `tts`, `pdf` | net gate on `prompt` (`tts`: `text`) and the hosts of reference URLs, read path gates on the reference fields and their arrays (media references) | the configured media provider |

  None names a destination the gate can check, so a high session blocks
  each, and so does an untrusted symbol in its payload field. A block
  refuses the WHOLE input (`block: "refuse"` on the net entry, so the
  `message` attachment, the browser's typing or a generator's reference
  upload cannot act on a block), with the reason in `{action:
  "mandu-refused: <why>"}` (each schema rejects it: an `action` enum, a
  required field, or an `action` the generators refuse). `x_search`,
  `code_execution` and `show_widget` are mapped UNTRUSTED in the inbound
  spec; `pdf` and the three generators stay unmapped on purpose: they read
  local files named in arrays (`pdfs`, `images`, `videos`, `audioRefs`),
  and only an unmapped tool gets the input scan that raises the result's
  level for every labeled path it names (`confidentiality-plan-10`
  §11.11). The sensitive-path gate reads those arrays too (below), but only
  paths it can place and only with the view map, so the scan stays.

  Pinned by `arbiter/test/unit/tool-gate-surface.test.ts` (each refused
  tool with the field that makes its refusal fail the schema),
  `interceptors/anthropic-proxy/test/{unit/stdin-gate,unit/dispatch,unit/net-gate,component/openclaw-full-profile}.test.ts`
  (each gate with a control on a surface without the entry) and
  `tests/stack/openclaw-full-profile.test.ts` over the real
  arbiter and the production adapter.

**The gate-surface residue (closed 2026-09-29).** Four inputs of the
`coding` profile named a path or a destination no gate read (§5.5 item 4).
Each is read from the 2026.6.35 dist:

- **`apply_patch{input}`** names its target paths in the file headers of
  one text (`*** Add File:`, `*** Delete File:`, `*** Update File:`,
  `*** Move to:`). The gate surface has a `patch` table (`apply_patch` →
  `{field: "input", format: "apply-patch"}`), and the proxy parses the
  headers with a port of OpenClaw's own parser (`apply-patch.ts`: the same
  whole-input trim, `<<EOF` heredoc wrapper and hunk consumption, so both
  read the same headers). Every header path goes to the sensitive-path gate
  as a write, and every path the patch writes (an add, an update, a move's
  destination; not a delete) to the derived label, through the same code a
  typed path field takes. A patch that does not parse, or that touches a
  path either leg denies, is refused whole as `{action: "mandu-refused:
  <why>"}` (the schema requires `input`), so nothing is applied. OpenClaw
  parses before it applies, so the refusal of an unparseable patch costs
  nothing. The view map moves header paths between the views and never a
  content line.
- **`exec.workdir`** (and OpenCode's `bash.workdir`) is a path read. A
  denied one also turns the command into the exec gate's exit-77 sentinel:
  OpenClaw falls back to its own cwd, or the home directory, when the
  workdir does not exist (`resolveWorkdir`), so the denied-path sentinel
  alone would still run the command.
- **`image{image, images}`** (2026.6.35, 2026.7.1) and **`view_image{path,
  paths}`** (2026.9.x) load each reference (an http(s) URL is fetched) and
  send the image to an image model. Net entry: no destination names the
  provider (as `pdf`), and the references are further destinations
  (`alsoDestinations`): every host is checked by the session leg, every
  string scanned by the symbol leg, a block refuses the whole input. Path
  entry: the references are media references (`refs: "media"`: a leading
  `@` and a `MEDIA:` prefix dropped, a `file:` URL decoded to its path, an
  http(s), `data:` or `media://` reference skipped), so `@~/.ssh/id_rsa`
  and `file:///…/%2Essh/…` are gated like the plain path.
- **`browser`** reads `url` when `targetUrl` is absent
  (`readTargetUrlParam`), a further destination, and `upload` sends
  the local files in `paths`, a path field.

Path fields may hold an array: every string element is gated, a denied one
becomes the sentinel in a copy of the array (`browser.paths`,
`image.images`, `view_image.paths`, and the media providers' reference
arrays: `pdf.pdfs`, `image_generate` / `music_generate.images`,
`video_generate.images` / `videos` / `audioRefs`, each also read as media
references and its URLs checked as further destinations, as for `image`).
The derived label still reads string fields only; no tool writes through an
array. A further destination the gate cannot read (neither a string nor an
array) blocks the call, and so does a call naming more than 20 hosts. Pinned
by `arbiter/test/unit/tool-gate-surface.test.ts`,
`interceptors/anthropic-proxy/test/unit/{apply-patch,net-gate,fs-gate,view-map,gate-surface}.test.ts`,
`interceptors/anthropic-proxy/test/component/openclaw-gate-residue.test.ts` and
`tests/stack/openclaw-gate-residue.test.ts` (secrets mode,
the real arbiter, the production adapter, and the arbiter unreachable).

**Tools that send a local file (2026-10-17).** Some OpenClaw tools read a
file in OpenClaw's own process and send its bytes on, so the bytes never
reach a tool result the proxy masks and only the path is on the wire. Until
2026-10-17 `message.media` was only a read path (the sensitive-path gate,
which runs with the view map only, so not in `secrets` mode) and
`message.attachments` was read by nothing: a registered `.env` attached to a
chat send left the machine (`tests/stack/openclaw-local-file-senders.test.ts`
is red on that code). Read statically from the openclaw 2026.7.1 and
2026.9.9 dist (`arbiter/test/fixtures/openclaw-local-file-senders-2026-10-17.json`),
each now has an upload kind in the gate surface (`upload`, as Claude Code's
DesignSync and Artifact tools; the proxy's `upload-gate.ts`):

| Tool | Kind | What is read | Where the bytes go |
|---|---|---|---|
| `message` (every action) | `openclaw-message` | `media`, `path`, `filePath`, `mediaUrl`, `fileUrl`, `image` and their snake_case spellings, the `mediaUrls` list, each `attachments[]` entry's `media`, `mediaUrl`, `path`, `filePath`, `fileUrl` or `url`, and any other param whose name looks like a path (a channel plugin's own, as Matrix `avatarPath`) when its value names a local file | the chat channel |
| `view_image` (2026.9.x), `image` (2026.6.35, 2026.7.1), `pdf`, `image_generate`, `music_generate`, `video_generate` | `openclaw-media` | the reference fields of the tool's path entry (`refs: "media"`) | a model |
| `browser{action: "upload"}` | `openclaw-browser-upload` | `paths` | the page |

Each reference is read the way OpenClaw's media loader reads it (a leading
`@` and a `MEDIA:` prefix dropped, `file:` decoded, `~` as the home); a
local file goes to the arbiter's `fileUploadDecision` (its label, its
registration, the registered secret values in its bytes, the sensitive
places), and one held file refuses the WHOLE call (`{action:
"mandu-refused: …"}`: `message` and `browser` take an `action` enum, and a
media tool left with no reference loads nothing). An http(s) source of a
`message` is a URL OpenClaw fetches: the net legs judge its host and its
symbols (the media tools' URLs are their net entries' further destinations
already); a `data:` source is the model's own bytes.

- **The destination (a decision, 2026-10-17).** A `message` goes to a chat
  channel, delivered from OpenClaw's process or through a gateway (which
  `gatewayUrl` can name anywhere) to a channel API whose root is
  configurable (Telegram's `apiRoot`) or a plugin's own transport (Matrix,
  Slack, Discord). No host string can be vouched for, so the file is asked
  about with NO host: a binding never releases a secret file to a chat
  channel, and the person's OK on the Approvals page (`fs:message:upload` ×
  the path) is the only release. A browser upload's page is unknown the same
  way. A channel-to-host table read from each channel plugin's source is the
  way to let bindings name a channel, if that is wanted later.
- **To a model (`toModel`).** `view_image` returns the image as its result
  to the session's own model when that model has vision, and otherwise sends
  it to an image model OpenClaw resolves (`agents.defaults.imageModel`, the
  primary provider's vision model, the auto media providers); 2026.7.1's
  `image` always takes the second route, and `pdf` and the generators send
  their references to their provider's model. The proxy cannot tell the
  routes apart, so these are judged as an upload to a model: a file at
  `any-model` goes (the level admits every model), a `local-model` or
  `no-model` one is held. Before, `view_image` was gated by analogy with
  `image` only (no 2026.9.x source had been read), and its `paths` array
  was not read by the result's path-derived level (`labelForClassify` reads
  string params only), so on the native route a labelled image in `paths`
  reached the model as an image under `gated`.
- **Relative paths.** OpenClaw reads a relative media reference in its
  workspace, which the launcher pins to the launch directory for the local
  shapes (`relativeBase: "launch"`), so the proxy places it there; without a
  known base it is refused with how to call it, and always for `browser`,
  which reads a relative path in its own uploads directory. A `media://`
  reference names OpenClaw's own media store (files that came in from a
  chat), which the proxy cannot place: refused the same way.
- **Residue.** A file over 256 MiB (the arbiter's scan bound,
  `FILE_UPLOAD_MAX_BYTES`), or one whose scan does not finish in 45 s,
  cannot be checked and is held. Until 2026-10-17 the bound was 8 MiB, read
  whole, so every larger image, video or PDF asked; now the path is judged
  first (a secret label or path holds with no byte read) and the bytes are
  scanned in chunks for registered values, never held whole
  (confidentiality.md §7, "Path first, bytes streamed"; about 6 s for
  256 MiB of binary on the development host). The window
  rule holds (an upload after a possible writer of the same turn is
  refused). A file named by a `MEDIA:` line of the reply itself is the next
  paragraph's.

Pinned by `arbiter/test/unit/{tool-gate-surface,file-upload}.test.ts`,
`interceptors/anthropic-proxy/test/unit/{openclaw-upload,upload-gate,gate-surface}.test.ts`
and `tests/stack/openclaw-local-file-senders.test.ts` (secrets mode, the
real arbiter over the production adapter, directly and through Tool Search,
and the arbiter gone).

**Files named in the reply (2026-10-17).** OpenClaw also attaches the files
a `MEDIA:` line of the model's own REPLY TEXT names, when it delivers the
reply to a channel: the gateway's auto-reply to a channel message, `openclaw
agent --deliver`, heartbeat and cron runs, block streaming (each block as it
completes), a sub-agent's completion. Its system prompt teaches the
directive ("Media attachment: own line `MEDIA:<path-or-url>` per item").
No tool call carries the path, so no gate above read it: the model could
write `MEDIA: /home/u/.env` and OpenClaw uploaded the key to the chat
(`tests/stack/openclaw-media-lines.test.ts` is red on that code). Read
statically from the 2026.7.1 and 2026.9.9 dist
(`arbiter/test/fixtures/openclaw-media-lines-2026-10-17.json`; the cases
evaluated with the dists' own pure parser and sanitizer functions, no agent
or model):

- **The grammar.** A line is a directive when its first non-blank
  characters are `MEDIA:` in any case (2026.9.9 upper-cases the first six,
  2026.7.1 the whole line); the payload is the rest of the line. One
  quoted payload is one reference (spaces allowed); otherwise it is cut at
  blanks (2026.9.9 re-joins a path with spaces), each part cleaned of
  quotes, backticks and brackets, and every valid part is attached, several
  per line and several lines per reply. A local reference is absolute,
  `~/`, `./`, a relative path with a `/`, a `file:` URL, or a bare
  `name.ext` as the fallback; `..` is refused by OpenClaw itself. An https
  URL is fetched; 2026.9.9 also takes `media://inbound/<id>`, its own store
  of files that came in from a chat. A line inside a code fence is skipped
  by OpenClaw. A tool result's text is never read for directives (tool
  media come from the structured `details.media` of OpenClaw's own tools),
  and a Markdown image is attached only for an https URL or media the run's
  own tools produced.
- **Where OpenClaw reads it from.** OpenClaw reads the reply from the API
  response this proxy relays; the reply filter sits on the terminal, after
  OpenClaw, and never feeds it. So the model-API proxy is the chokepoint,
  and what it relays is exactly what OpenClaw parses (a symbol stays a
  symbol: nothing desymbolizes reply text on the way to OpenClaw).
- **The markup trap.** OpenClaw strips markup from the reply BEFORE it
  looks for directives (model special tokens, `<think>` and `<final>` tags,
  tool-call XML, `[Tool Call: …]` blocks, plain-text tool-call lines), so
  `ME<think>\n</think>DIA: /x`, `<final>MEDIA: /x</final>` or
  `[Tool Call: f]\nArguments: {}MEDIA: /x` attach `/x` though no raw line
  starts with `MEDIA:` (the fixture's `formsAfterSanitizing` cases). Every
  span those strippers delete inside a line starts with `<`, `[` or `]`.
- **The gate (`replyMedia: "openclaw-media-lines"` in the gate surface;
  the proxy's `reply-media.ts`).** Over the whole text of a response (its
  text blocks joined by a newline, as OpenClaw joins them; Messages,
  Chat Completions and Responses, streamed or buffered): a CANONICAL line
  (raw `MEDIA:` start, no `<`, `[` or `]`, no second directive) is read
  with both builds' grammars (ported; every reading the remote-URL check
  could choose) and each reference judged: a local file by
  `fileUploadDecision` with NO host, as tool `MEDIA` (a chat channel is no
  host a binding can name, so a secret file is held for the person's OK,
  `fs:MEDIA:upload` × the path), an https URL by the net legs, the media
  store and a relative path without a known base held. One held reference
  replaces the whole line with a notice (`[mandu] attachment not sent,
  nothing was uploaded: … (rule: …)`): OpenClaw finds no directive, the
  person in the chat reads why, and the model reads it in its own turn on
  the next request. Every OTHER place a directive could form after
  OpenClaw's strippers (a colon that `MEDIA` precedes with gaps that each
  start with `<`, `[` or `]`) gets its colon replaced by U+A789, which looks
  the same and which no stripper deletes or folds. Fences are read too: a
  fence the proxy misread would be a bypass.
- **The window.** OpenClaw reads the files at delivery, after the run. A
  response that also carries a tool call is not the last one, and that
  call runs before the read: every local reference of such a response is
  held before anything is asked (`proxy:reply-media-with-call`), and the
  notice says to name the file in the final reply.
- **Streaming.** Text streams as it comes, except a line start that may
  still become a directive (blanks, `M`, `ME`, …), held until the next
  delta decides it, so a `MEDIA:` split across deltas is never half out.
  From the first possible directive on, the rest of the response is held
  and relayed, rewritten, when it ends (directives sit at the end of a
  reply, so most replies are not held at all). A reply with none is
  relayed byte for byte.
- **Fail-closed.** An arbiter that throws, does not answer in time or
  lacks the op holds the reference; a gate surface the arbiter cannot give
  is the union, which reads every reply; a line past the grammar's bound is
  held whole.
- **Why not refuse `--deliver` instead (a decision, 2026-10-17).** The
  gateway's auto-reply delivers every reply without that flag, and so do
  heartbeat and cron runs; refusing the flag would close one path of
  several. The scan reads the bytes OpenClaw parses, so it is the
  chokepoint.
- **Utility.** A clean file is attached as before; a reply that names a
  file and also calls a tool loses the attachment (the model is told why);
  `media://` references (re-sending a file that came in from the chat) are
  neutralized; a colon after "media" in prose ("social media: …") or after
  "MEDIA" behind markup reads as a lookalike colon; a held line in a code
  block is replaced by the notice. A missing file is held, as for
  `message` (unread bytes are unchecked bytes).

Pinned by `interceptors/anthropic-proxy/test/unit/reply-media.test.ts`
(the fixture's cases, the grammar, the plan, the judgment, the stream on
all three wires), `interceptors/anthropic-proxy/test/component/reply-media-route.test.ts`
(every response route of the real proxy), `arbiter/test/unit/tool-gate-surface.test.ts`
and `tests/stack/openclaw-media-lines.test.ts` (secrets mode, the real
arbiter over the production adapter, a registered `.env` and a labelled
file by every spelling and split one character per delta, the markup
forms, a reply with a tool call, a clean file, the buffered answer, the
arbiter gone; a Claude Code session as the control).

**The workspace (`agent-config.ts` `fenceOpenclawWorkspace`).**
OpenClaw's workspace is the default cwd of its file tools and the folder
whose AGENTS.md, SOUL.md, USER.md, MEMORY.md and memory files it loads into
the model's context every session. Unset, it is `~/.openclaw/workspace`,
outside the project. Under the shapes whose agent loop runs in the launch
(`chat`, `terminal`, `tui --local`, `agent --local`) the run config pins
`agents.defaults.workspace`, and any `agents.list[].workspace`, to the
agent's working directory. That is the launch directory, or its AgentView
twin under the frozen integrity axis. A note names any workspace of the
user's that this replaces; their file is not touched. The pin also sets
`skipBootstrap: true`, because OpenClaw 2026.6.35 (`ensureAgentWorkspace`)
otherwise writes its seven starter files and a state file into a workspace
that lacks them, which would put them in the user's project. The project's
own AGENTS.md is still read.
- *Why it holds under the secret-twins wrap.* The wrap is a mask over the
  same paths, so the path is the same inside it. A labelled file OpenClaw
  loads from the workspace reaches it as its twin, the same ingress as Claude
  Code's CLAUDE.md.
- *Where it does not apply.* The Gateway and a wrapper script keep the
  user's setting.
- *Tests.* Unit: `launcher/test/unit/agent-config.test.ts`,
  `openclaw-argv.test.ts`. E2E: `launcher/test/component/openclaw-memory-fence.test.ts`.
  Under the real wrap: `launcher/test/kernel/openclaw-workspace-twin.test.ts`,
  where a labelled `USER.md` in the workspace reads as its twin.

**Relative paths** (fs-sync.md §1.4.1). OpenClaw resolves a relative
path in `read` / `write` / `edit` / `apply_patch` / `exec.workdir` against
its workspace, which the pin above makes the launch directory for the local
shapes. Its gate surface says so (`relativeBase: "launch"`), and the
launcher names the directory (`MANDU_AGENT_CWD`) only when the pin applies
and the argv names no `--agent` (a non-default agent without a workspace of
its own works in `<launch dir>/<id>`). There the sensitive-path gate and the
derived label place a relative path and judge it like an absolute one. Any
other shape (the Gateway, a wrapper, `--agent`) names no base: a relative
path that escapes the working directory with `..` (a typed field, or an
`apply_patch` header) is denied, and one under it is left to the guard's open
trap, the secret twins and the context backstop. OpenCode joins every
relative path to its launch directory and is placed the same way.

**OpenClaw 2026.9.9 and Code Mode (2026-10-09).** The 2026.9.9 surfaces
were captured the same way (Node 24, a routing override of the anthropic
provider like the launcher's; the fixture's `2026.9.9*` entries). The default
and `tools.toolSearch: {mode: "tools"}` send what 2026.9.6 sent;
`{mode: "directory"}` (2026.9.9's other mode) sends the same tools, and
`{mode: "code"}` is retired (the config is rejected). With
`tools.toolSearch: false` one tool is new: **`presence`** (read-only:
who and which devices are connected to the gateway, with display names,
activity, IP addresses and approximate locations those clients report),
mapped UNTRUSTED. `sessions`, `subagents` and `theme` gained fields no gate
reads.

The capture also showed what the 2026.9.6 check had missed: **Code Mode**
(`tools.codeMode`, in every release from 2026.5.18). Engaged, it replaces
the model's tools with `exec{code}` and `wait{runId}` (2026.9.x
`exec{title, code, restartSafe}`; 2026.5.18 to 2026.7.x
`exec{code, command, language}`, `command` an alias for the code), and the
model's JavaScript calls the tools inside OpenClaw: on 2026.9.9,
`exec{code: "await write({path, content})"}` wrote the file and no write
call ever crossed the wire. No wire gate reads which tool gets which input,
the case §5.3.4 decides against for every agent (`tool_search_code`, Goose's
and OpenCode 2's code mode). It is opt-in before 2026.9.x; from 2026.9.x an
absent `tools.codeMode` means "auto", which engages it for models the
provider catalog flags preferred (Claude Opus 5, Sonnet 5, GPT-5.5 and
others; under the launcher's routing override the captured `claude-opus-5`
and `claude-sonnet-5-5` turns still got the normal tools, but a user's own
model entry can carry the flag). Two layers close it:

- **The launcher turns it off** (`agent-config.ts`
  `fenceOpenclawCodeMode`): on the merged run config every `codeMode` the
  user set (`tools.codeMode`, `agents.list[].tools.codeMode`, and the
  per-model `agents.defaults.models.<ref>.codeMode` and
  `agents.list[].models.<ref>.codeMode`, read from 2026.9.9
  `readCodeModeRawConfig`) becomes `false`, with a WARNING naming each that
  turned it on, and `tools.codeMode: false` is written where the release
  accepts the key (2026.5.18 and later, read from the published packages:
  2026.5.12 has no key, 2026.3.12 rejects it).
- **The proxy refuses it on the wire** (`tool-gate-surface.ts`): `wait` is
  in the `refuse` table (its schema requires `runId`: "must have required
  properties runId"), and `exec` carrying `code` or `language`, any value,
  is refused by form (`refuseArgs`, an empty `allow`; the shell `exec` has
  neither field). The code becomes "mandu-refused: <why>", which is not
  JavaScript (2026.9.9: "SyntaxError … No tools were dispatched"), a
  `command` beside it the block sentinel ("code and command must match"),
  and a `language` a value 2026.7.1's enum rejects; the result reaches the
  model as the refusal notice. Through `tool_call` both are refused the
  dispatcher's way. A Code Mode `exec{command}` alone (2026.7.x's alias,
  with no `language`) reads as a shell command on the wire; on 2026.9.x the
  schema requires `code`, and before 2026.9.x Code Mode is on only where a
  user setting the launcher overrides turned it on.

Observed on the real binaries (2026.7.1, 2026.9.6, 2026.9.9) with a
scripted model; pinned by `arbiter/test/unit/tool-gate-surface.test.ts`
(every tool of each 2026.9.9 surface and each Code Mode surface has a rule,
a refusal or a dispatcher; the refused fields are on the Code Mode captures
and never on the shell `exec`), `arbiter/test/component/tool-surface.test.ts`
(those surfaces read all known), `interceptors/anthropic-proxy/test/unit/dispatch.test.ts`,
`tests/stack/openclaw-code-mode.test.ts` over the real arbiter and the
production adapter (with a Claude Code control), and the launcher's
`test/unit/agent-config.test.ts` and `test/component/openclaw-memory-fence.test.ts`.

Still outside the claim: `exec{host: "sandbox"}` runs in OpenClaw's Docker
sandbox, which the Docker daemon runs outside Mandu's box (the wrapper's
socket allow-list decides whether the agent reaches the daemon at all); a
browser PROFILE that attaches to a browser running outside Mandu (the
`existing-session` and extension-relay drivers, a remote CDP URL) is
reached over a socket the box's network policy decides, since the wire
does not say which profile a name means; and the tools a provider plugin
or an MCP server adds under names Mandu has not read stay UNTRUSTED with
their whole input scanned for labeled paths.

**OpenClaw's own web requests and the egress proxy (2026-10-09).** OpenClaw
fetches over its own SSRF guard (`fetch-guard.ts`), which resolves the host
itself and connects DIRECTLY in its default "strict" mode: it ignores
`HTTPS_PROXY`. So under Mandu, `web_fetch` and the URL references the media
tools load (`image`, `view_image`, `pdf`, the media-understanding fetches)
left around the net-proxy, through the kernel rungs' default any-host :443:
the egress gate, the TLS inspection and the verbatim-secret tripwire never
saw them, and only the model-context gate judged their URLs
(`tool-gate-surface.ts` `net`). Measured with a scripted model and a logging
forward proxy, no Mandu: 2026.7.1-2 and 2026.9.9 send `web_fetch` straight
to the destination. What reads the environment already was not affected:
`web_search`'s provider endpoints (`withTrustedWebToolsEndpoint`), MCP HTTP
servers (`useEnvProxyForEligibleUrls`), and Node's own fetch in a plugin or
a program the agent runs (`NODE_USE_ENV_PROXY`, `env-compose.ts`).

The launcher now routes them (`agent-config.ts` `fenceOpenclawWebEgress`,
with a net-proxy; the release boundaries read from the published packages):

- **2026.9.6 and later**: OpenClaw's managed proxy
  (`proxy: {enabled: true, proxyUrl: <the net-proxy>, loopbackMode:
  "gateway-only"}`) sends every strict fetch of the process through the
  net-proxy and keeps loopback (the model call to the context proxy) direct
  (`managedLoopbackBypassPolicy`, first in 2026.9.6), and
  `tools.web.fetch.useTrustedEnvProxy: true` as well. The managed proxy also
  sets `NO_PROXY` to the loopback names in OpenClaw's environment, so a
  program the agent runs sends a model vendor's host through the net-proxy
  too (with the confidentiality axis on, the model-host deny judges each
  request there by its path, agent-sdks.md §4; otherwise the net-proxy
  blind-tunnels a model host).
- **2026.5.3 to 2026.9.5**: `tools.web.fetch.useTrustedEnvProxy: true`
  (first in 2026.5.3), so `web_fetch` rides the net-proxy. The managed proxy
  is NOT used there: before 2026.9.6 it sends the loopback model call
  through the forward proxy too (2026.7.1-2: a `CONNECT 127.0.0.1:<port>`),
  which would break every turn. The media tools' URL references still
  connect direct on these releases; the model-context gate judges each URL
  (`alsoDestinations`), the net-proxy does not see them.
- **Before 2026.5.3, or a version the launch cannot read**: nothing routes
  `web_fetch`, so it is denied (`tools.deny`, added to the user's list) and
  the launch says so; `curl` through the shell goes through the net-proxy.

The user's own `proxy` and `useTrustedEnvProxy` are replaced for the run,
each named. An `http://` URL is tunneled (`CONNECT host:80`): the net-proxy,
with TLS inspection on, reads the tunnel's first byte and serves plain HTTP
with its plaintext leg under the same gate (`proxy.ts` `sniffTunnel`; before
this, inspection failed on it).

The kernel rungs keep allowing any host on :443 by default (the honest
trade-off `landlock-net` and `net-guard` print): OpenClaw's own requests now
ride the net-proxy, so what the fallback still serves is the programs the
agent runs that ignore the proxy variables, the same as for every other
agent; `--landlock-net-strict` (or `--net-allow`) drops it, at that cost.

Pinned by the launcher's `test/unit/agent-config.test.ts` (each release
tier, the user's settings, no net-proxy), net-proxy
`test/component/plain-http-tunnel.test.ts` (plain HTTP in a tunnel: a page
forwarded, a raw secret and an untrusted symbol refused; TLS still
inspected), and `tests/stack/openclaw-web-egress.test.ts` (the real launcher
and a real `openclaw agent --local` with a scripted model: an https and an
http `web_fetch` to a name no DNS knows reach the sink only through the
net-proxy's route, a registered secret's raw value in the URL is refused by
the tripwire and never reaches the sink; green on 2026.7.1-2 and 2026.9.9,
red with the fence off: `getaddrinfo ENOTFOUND`).

**Raising a range.** Raise `max` only after a battery ran green on the new
version AND its `tool_surface` event reads "all known to the inbound spec"
(map any new tool in the inbound spec first). Change both mirrors and the
README row in one commit.

### 2.2 Mandu's own tools on each agent

Mandu mounts its quarantine tools on every supported agent, under the name
each runtime gives them; the arbiter recognizes each spelling
(`arbiter/policy/inspect-tool.ts`) and maps it the same way on every agent,
so none shows as an unknown tool:

| Agent | `inspect_symbol` (rung 2) | `declassify_symbol` (rung 3) |
|---|---|---|
| Claude Code | `mcp__mandu-inspect__inspect_symbol` | `mcp__mandu-inspect__declassify_symbol` |
| Codex | `mcp__mandu_inspect__inspect_symbol` | `mcp__mandu_inspect__declassify_symbol` |
| OpenCode | `mandu-inspect_inspect_symbol` | `mandu-inspect_declassify_symbol` |
| Goose (§5.6; launcher mount pending) | `mandu-inspect__inspect_symbol` | `mandu-inspect__declassify_symbol` |
| OpenClaw | `inspect_symbol` (plugin tool) | `declassify_symbol` (plugin tool) |

**How long `inspect_symbol` may run** (2026-10-17,
[model-endpoints.md](../confidentiality/model-endpoints.md) §1.9). Each
agent bounds an MCP call by its own limit: Claude Code moves one past 120 s
to the background, Codex cuts it at `tool_timeout_sec` (60 s by default),
OpenCode at the server's `timeout` (the launcher's 30 s). With a
`local: true` model declared (or the user's own
`MANDU_ULLM_ENDPOINT_TIMEOUT_MS`) the launcher writes the U-LLM timeout into
the `mandu-inspect` entry and raises each limit for that server alone to the
longest call (twice the timeout plus 60 s): Claude Code's
`CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS`, Codex's
`mcp_servers.mandu-inspect.tool_timeout_sec`, OpenCode's `timeout` (V1) or
`timeout.execution` (V2). Goose gets the entry's env; its own extension
limit is not set. The other MCP servers keep their limits.

On Codex the quarantined model behind `inspect_symbol` is a `codex exec`
child cut down to a tool-less model call
([agent-sign-in.md](./agent-sign-in.md) §2.11; before 2026-10-04 it refused
to start outside a repository).

`declassify_symbol` on OpenCode and OpenClaw (`agent-e2e-harness.md` §8.5)
has Claude Code's approval and policy semantics: the arbiter decides and
queues the human's approval. It is covered by e2e tests through a real
arbiter, but no live model run has graded it on either agent yet, so it adds
nothing to the tested ranges above.

### 2.3 OpenCode 2: supported by default

**Status: SUPPORTED BY DEFAULT (2026-10-05).** OpenCode 2 launches with no
opt-in, as `opencode` or `opencode2`, with its argv rewritten (§2.3.1:
`--standalone`, a private server; the shapes that join or drive another
server refused), and in mode `secrets` only while its guards are in force
(§2.3.1, "Confidentiality ON: allowed under three conditions"). Its tested
range is its own, 2.0.23 to 2.0.26 (§2). The history, kept below as built: first a
refusal (the decision below), then parts 1 to 4 and items 5 to 10 behind
the experimental opt-in `MANDU_EXPERIMENTAL_OPENCODE2=1`, proved by the
catalog's confidentiality drills on the real 2.0.23 through the real
launcher (`integration.replay-opencode2`, item 5); the opt-in went after a
live check on a real model (the maintainers' live drill runner on
`opencode2`, 2026-10-05,
haiku, mode `secrets`: the confidentiality trio passed, §2).

- **The switch off.** `MANDU_OPENCODE2=0` (also `false`, `off`, `no`)
  refuses every 2.x launch with one line naming the variable ("refusing to
  launch OpenCode 2.0.23: MANDU_OPENCODE2=0 turns OpenCode 2 off. Unset
  MANDU_OPENCODE2 to run it, or use OpenCode 1 …"); `opencode2` is then
  refused by name and never run, not even for `--version`. Any other value,
  or none, leaves 2.x on (`opencode2Enabled`).
- **The old opt-in.** `MANDU_EXPERIMENTAL_OPENCODE2` is no longer read: a
  no-op either way, accepted silently (an environment or a drill profile
  that still sets it changes nothing; `0` there does not turn 2.x off).
- **What stays refused** (`opencodeLaunchRefusal`): a version Mandu cannot
  read (the probe is what tells the generations apart, and only a 2.x
  launch gets the argv rule), OpenCode 2's `0.0.0-*` prereleases, every
  major other than 1 and 2, and an `opencode2` that does not report major
  2. The message names both supported lines and how to install each.

OpenCode 2 went GA on 2026-09-11 as npm **`@opencode/cli`** (2.0.22, published
2026-10-02, was the latest on 2026-10-05; `npm view @opencode/cli`). OpenCode 1
stays on npm `opencode-ai` (1.18.34 on 2026-09-30). Both install the command
**`opencode`**; `@opencode/cli` also installs **`opencode2`**, and its
prereleases are published as `0.0.0-beta-…` and `0.0.0-dev-…`. What changed,
from the migration guide (opencode.ai/v2/docs/migrate-v1/) and from 2.0.22
itself (probed 2026-10-05 against two scripted local Anthropic upstreams, one
standing in for the proxy and one for the vendor, with hermetic XDG dirs):

- **Configuration.** Same files (`~/.config/opencode/opencode.json(c)`,
  `<project>/opencode.json(c)`, `<project>/.opencode/opencode.json(c)`), still
  read through `OPENCODE_CONFIG` and `OPENCODE_CONFIG_CONTENT`. The keys moved:
  `provider` → `providers`, `options.baseURL` → `settings.baseURL`, `options`
  split into `settings`, `headers`, `body`, `npm` → `package: "aisdk:…"`, MCP
  servers under `mcp.servers` (`enabled` → `disabled`, `timeout` an object),
  `permission` → an ordered `permissions` array, `agent` → `agents`. V1 keys
  are **normalized, not rejected**: `opencode debug config` shows Mandu's
  V1-shaped routing as `providers.anthropic.settings.baseURL` plus headers,
  `enabled_providers` as `experimental.policies` (deny `provider.use *`, allow
  `anthropic`), and the V1 `mcp.<name>` entry as `mcp.servers.<name>`. The
  inline `OPENCODE_CONFIG_CONTENT` still outranks a project config's provider
  settings, in either spelling, but not its provider RULES, and a model's own
  endpoint beats them both (part 4 below). `OPENCODE_PERMISSION` is gone from
  the binary (`--auto` remains).
- **Process model: the background service.** `opencode` and `opencode run`
  connect to a background server (`opencode service start|status|stop`, a
  localhost HTTP port recorded in `$XDG_STATE_HOME/opencode/service.json`)
  unless given `--standalone` or `--server <url>`. The service runs the model
  calls **and the tools**, with the configuration and environment it was
  started with. With a private (`--standalone`) server, Mandu's routing works
  unchanged: both requests of a turn reached the proxy with the session
  header, and a project or global config re-pointing the anthropic provider
  in V2 spelling did not move them. With a service the user started outside
  Mandu, the same wrapped run sent **both requests to the service's own
  endpoint, without the session header; none reached the proxy.** The
  service is also a daemon: one started from inside a session outlives it.
- **The tool surface** (2.0.22, read off the wire): `edit` `glob` `grep`
  `question` `read` `shell` `skill` `subagent` `webfetch` `websearch` `write`
  `execute`. `bash` is now `shell`; `read`, `edit` and `write` take `path`
  (not `filePath`); `task` is `subagent` (it takes a `model`); `execute` runs
  model-written code that calls tools in process (the code mode of §5.3.4).
  Until part 2 below, none of the renamed tools was in OpenCode's gate-surface
  table or inbound spec, so the exec and path gates would not have fired for
  them. The user agent is `opencode/latest/2.0.22/cli`. 2.0.23 advertises the
  same twelve tools (captured with each tool's result in
  `arbiter/test/fixtures/opencode2-tool-surface-2026-10-05.json`).

**The first decision (2026-10-05, superseded the same day by the support
above; the probe-and-refuse machinery it built is what the support keeps).**
A service that reaches the model around the proxy breaks
the confidentiality invariant (tool results, secrets included, unmasked at
the vendor), and Mandu cannot see from outside which service a run will
join. So `mandu opencode` launched only OpenCode 1. `opencodeLaunchRefusal`
(`launcher/src/agent-versions.ts`, called in `run.ts` before the model check
and before anything starts) refused:

- `opencode2`, by name (it is inferred as the `opencode` target, so the
  refusal says why rather than "cannot infer");
- an `opencode` whose major version is not 1: OpenCode 2 and later, and the
  `0.0.0-*` prereleases (OpenCode 1's own `0.0.0-snapshot-*` builds are
  refused too, as is OpenCode 0.x of 2025);
- an `opencode` whose `--version` cannot be read: the probe is the only thing
  that tells the two generations apart, so an unreadable one fails closed.

Today only the last two remain (with major 2 admitted beside 1, and
`opencode2` probed like `opencode`); the first two apply under
`MANDU_OPENCODE2=0`. The message names the supported lines and how to
install each at its tested maximum (`npm i -g opencode-ai@1.18.35`, `npm i -g
@opencode/cli@2.0.26`). A wrapper script under `--target opencode` is not
run with `--version` (§3) and is not refused; what it starts is the user's
choice, as for every target. Tests: `launcher/test/unit/agent-versions.test.ts`
(the rule, both states of `MANDU_OPENCODE2`, the old opt-in a no-op),
`launcher/test/component/opencode-v2-refusal.test.ts` (through `main()`
with stand-ins named `opencode` and `opencode2`: refused launches never run
the agent and the upstream sees nothing; OpenCode 1 still launches routed;
`opencode2` launches with `--standalone`), and, against the real 2.x binary
(`MANDU_OPENCODE_V2_BIN`, or `opencode2` on `PATH`; a SKIP with the reason
otherwise), the `MANDU_OPENCODE2=0` refusal from its own `--version` and the
service bypass above.

**What full OpenCode 2 support needs** (all built 2026-10-05, part 1 first
behind the opt-in, §2.3.1; what the 2.0.23 capture found is after the
list):

1. **Keep every model call in the wrapped process.** BUILT (§2.3.1),
   first behind the opt-in, now for every 2.x launch: `--standalone` on the TUI,
   `run` and `mini`; `--server`, `serve`, `service`, `pair`, `api`, `acp`
   and the management subcommands refused the way OpenClaw's Gateway shapes
   are (agent-e2e-harness.md §9.0); proved on the real 2.0.23 binary with a
   user service running; and under the default kernel layer since the
   guard's private-server allowance (§2.3.1, "Under the kernel layer").
2. **Map the 2.x tool surface. BUILT (2026-10-05).** One `opencode` table
   and inbound spec serve both generations (a name only one sends never
   appears on the other's wire): `shell{command}` is an exec and exec-output
   tool and its `workdir` a path read (a denied one blocks the command);
   `read` / `write` / `edit` gate `path` beside 1.x's `filePath`;
   `subagent` and `shell` take 1.x's `task` and `bash` postures (UNTRUSTED);
   `question` (TRUSTED, the user's answer), `skill` (UNTRUSTED), `webfetch`
   and `websearch` keep theirs. Each field is pinned against the capture
   (`arbiter/test/unit/tool-gate-surface.test.ts`,
   `opencode2-inbound.test.ts`). Three forms are refused, each verified on
   2.0.23 to fail the call before anything runs:
   - `shell{background: true}` and `subagent{background: true}`: the
     output (or the child's answer) comes back later as a USER TEXT
     (`<shell id=… state="completed" command=…>output</shell>`,
     `<subagent sessionID=… state="completed">answer</subagent>`), not a
     tool_result, so callTaint, the value backstop and the inbound spec never
     read it. The field becomes `"mandu-refused: <why>"` ("background:
     Expected boolean") and the shell's command the block sentinel;
     `background: false` passes (a refused-form rule now compares a boolean
     as "true" / "false").
   - `subagent{model}`: the child runs on the model it names. The provider
     fence refuses an unrouted provider ("Model openai/gpt-5 is not
     available", probed with the V1 `enabled_providers`), but the agent's
     pick is not a model the launcher checked; refused ("Invalid model"),
     with no child session started. Without it the child runs on the
     session's model through the proxy under the same session header (probed).
   2.x's `read` frames a text file as `Read file <the path as called>, lines
   A-B` then `n: <line>`, with no trailer; a cut read ends `[Output
   truncated. Continue reading with offset: N]`. The proxy's
   `unrenderOpencodeReadResult` and the arbiter's
   `opencodeReadRenderingText` read both frames (the symbol's value is the
   file's text, not the header, which would otherwise be registered as a
   secret line, the 1.x trailer bug of !730; the read-twin rule takes
   `read{path}`), pinned to one answer by `tests/stack/opencode-read-value.test.ts`.
   E2E: `tests/stack/opencode2-gate-surface.test.ts` (`secrets` mode: a
   labelled file read through `read{path}` and a `shell` result carrying it
   reach the model only as symbols, a symbol in a `shell` command to an
   unbound host stays a symbol, an unreachable arbiter fails closed) and
   `interceptors/anthropic-proxy/test/component/opencode2-gates.test.ts`.
3. **Refuse `execute`** (code mode), as §5.3.4 decides for every agent,
   unless a gate reads the code it runs. **BUILT (2026-10-05).** On 2.x code
   mode is ON by default: `execute{code}` runs model-written JavaScript with
   `fetch` and a `tools` catalog reachable only there (`opencode.models`,
   `session_move`, `session_rename`, `list_mcp_resources`,
   `read_mcp_resource`, an empty `browser` namespace). It is a refusing
   dispatcher (`dispatch: {execute: "refuse"}`): the input becomes `{code:
   "throw new Error(\"mandu: …\")"}`, which 2.0.23 runs and answers `Error:
   mandu: …` with no tool call made. Refusing it also removes
   `session_move`, which would move the directory relative paths resolve
   against.
4. **Read the 2.x config spelling. BUILT (2026-10-05).**
   `launcher/src/opencode-config.ts` reads a config document the way 2.0.23
   normalizes it (probed with `opencode debug config`, which on 2.0.23 lists
   every source normalized; it joins the background service, so each probe
   needs its own state dir and port): `providers.<id>` with `package` (V1
   `npm` becomes `aisdk:<npm>`) and `settings.baseURL` (a V1 `api` wins over
   `options.baseURL`); in ONE document a `providers.<id>` entry replaces the
   `provider.<id>` entry whole; `agents.<name>.model` with a `#variant`, or
   as `{providerID, model, variant}` (V1 `agent`, `mode`, and `small_model`
   as `agents.title`); `commands.<name>.model` (V1 `command`). OpenCode 2
   reads every layer, lowest first: the global config dir
   (`$OPENCODE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/opencode`:
   `opencode.json`, `opencode.jsonc`), the `OPENCODE_CONFIG` file, the
   project files of the start directory AND EVERY ANCESTOR up to `/`
   (`opencode.json(c)` outermost first, then `.opencode/opencode.json(c)`;
   none with `OPENCODE_DISABLE_PROJECT_CONFIG`), then
   `OPENCODE_CONFIG_CONTENT`. For a 2.x launch (`opencodeGeneration`:
   `opencode2`, or a probed major other than 1) `run.ts` hands the model
   check every layer (`readOpencodeConfigLayers`, for the cwd and an
   `opencode <dir>` argument) and `opencodeV2ModelPlan` refuses, before
   anything starts:
   - a layer it cannot parse;
   - a model on a provider Mandu does not route: the main model or `-m`,
     each agent's and each command's model, from the highest layer that sets
     it, with the 1.x messages in 2.x spelling. `openai` and a provider with
     the `aisdk:@ai-sdk/openai` or `aisdk:@ai-sdk/openai-compatible`
     package and a `settings.baseURL` are routed, as on 1.x. A
     `subagent{model}` is refused on the wire (part 2); a subagent started
     by agent name runs on that agent's configured model, which this covers;
   - a model of a routed provider with its own endpoint, in any layer: V2
     `models.<m>.settings.baseURL`, `models.<m>.package`,
     `models.<m>.variants[].settings.baseURL`; V1 `options.baseURL`,
     `provider.api`, `provider.npm`, `variants.<v>.baseURL`; and a
     `package` or `canonical` on the anthropic provider (another SDK may
     take its endpoint from other settings).

   The routing Mandu writes for a 2.x launch adds the fence in 2.x spelling,
   `experimental.policies` (deny `provider.use *`, allow each routed
   provider), which replaces a user's array merged into the same document
   (it would come after the `enabled_providers` rules there and win), and,
   where the user's document spells a routed provider in V2, the routing in
   V2 too (`withOpencodeV2Routing`): otherwise their `providers.anthropic`
   drops Mandu's `provider.anthropic` from that layer, and a user
   `OPENCODE_CONFIG_CONTENT` of `{"providers":{"anthropic":{"settings":
   {"baseURL":…}}}}` sent every turn to that URL (measured). It also turns
   code mode off as defense in depth beside part 3's wire refusal: a
   `permissions` rule `{action: "execute", resource: "*", effect: "deny"}`,
   appended after the user's own rules in the same document, with which
   2.0.23 offers neither the `execute` tool nor its catalog (`Tool.snapshot`).
   Permission rules keep the NORMAL precedence, unlike provider rules: a
   project or global `permissions` allow for `execute` did not bring it back
   (measured), but an agent's own `agents.<name>.permissions` allow does, so
   the wire refusal stays the guarantee. The 1.x shape is unchanged: 1.18.13
   rejects `providers` ("Unrecognized key").

   **SECURITY: the merge order of `experimental.policies`.** OpenCode 2
   evaluates provider rules over the layers REVERSED and takes the last
   match (`opencode.config.policy`: `entries.toReversed().flatMap(policies)
   …findLast`), so the rule of the LOWEST layer that names a provider wins,
   against the precedence every other key follows. Measured on 2.0.23 with
   Mandu's routing (run file and inline content) and `-m openai/gpt-5`: a
   PROJECT config's `experimental.policies` allow (or V1
   `enabled_providers`) for `openai` did NOT re-admit it ("Model
   unavailable"), because the run file Mandu passes as `OPENCODE_CONFIG`
   sits below every project layer and its `deny *` is the lowest match; the
   same allow in the GLOBAL config DID, and the turn went to that provider's
   own endpoint without the session header. Part 4 first refused such a
   global admission at launch; the lockdown of item 8 made that unneeded
   (OpenCode 2 no longer reads the global document itself: it is merged into
   the run file, under the fence), so it was dropped.
   The second hole is a model's own endpoint: from a project config,
   `providers.anthropic.models.<m>.settings.baseURL` (or the V1
   `options.baseURL` / `provider.api`, or a variant's) took the turn to that
   URL around the proxy while the provider's base URL pointed at it; 1.18.13
   keeps the provider's base URL there (measured). A provider-level re-point
   in either spelling and any layer stays overridden by the inline routing
   (measured). Tests: `launcher/test/unit/opencode-v2-config.test.ts`, and
   against the real binary `launcher/test/component/opencode-v2-config.test.ts`
   (SKIP without `MANDU_OPENCODE_V2_BIN` or `opencode2`), which pins each of
   these facts, so a version that changes them fails there.
5. **Re-verify the MCP mount** (`mcp.servers`, the tool name OpenCode 2 gives
   `mandu-inspect`'s tools), the drill profile (the TUI changed) and the
   `opencode-e2e` suite on a pinned 2.x, then raise the tested range. The
   mount, the replay drill profile and the confidentiality e2e are BUILT
   (below); the tested range waits for a live check.
   **The mount: BUILT (2026-10-05).** Read from the 2.0.23 source
   (`packages/core/src/mcp/index.ts`, `tool/mcp.ts`, tag `v2.0.23`) and
   measured on the binary:
   - **Code mode by default.** A 2.x MCP server's tools are offered only
     inside `execute` unless the server sets `codemode: false`, and Mandu
     denies and refuses `execute` (part 3), so the inspect channel would be
     unreachable. The V1 spelling (`mcp.<name>`) has no `codemode` field
     (2.0.23 drops it when normalizing), so a 2.x launch writes the mount in
     V2 spelling: `mcp.servers.<name>` with `codemode: false`, `environment`,
     and `timeout: {startup, catalog, execution}` (the V1 `timeout`
     normalizes to `{catalog, execution}`; `startup` covers the same cold
     start). The model then sees `mandu-inspect_inspect_symbol`, the
     spelling `inspect-tool.ts` already recognizes. The 1.x mount is
     unchanged (1.18.13 rejects `servers`).
   - **Never on the first step.** MCP servers connect in the background
     when the first session uses the directory, `MCP.tools()` reports only
     what is connected, and the tool registry is rebuilt on
     `mcp.tools.changed` after a 100 ms debounce. So the tool is offered from
     the second step on, and a scripted upstream that answers in
     milliseconds never sees it (what hid it in the first probes). Utility
     only: the first step carries only the user's prompt, with nothing yet
     to inspect.
   - **A layer can redefine the server.** `mcp.servers` merges by name
     across layers, the later layer winning, so a project config can replace
     `mandu-inspect`. Not a leak: the name unlocks only the pure-symbolic
     shape check on the result (`inspect-tool.ts`), so a stand-in's prose
     falls to the fail-closed default; the same holds for 1.x today.
   Tests: `launcher/test/unit/opencode-v2-config.test.ts` (the 2.x and 1.x
   mounts) and, against the real binary,
   `launcher/test/component/opencode-v2-config.test.ts` (Mandu's own entry,
   only its program swapped for a stub: the tool offered from step 2 on and
   its call answered; without `codemode: false` the same run offers no
   inspect tool).
   **The confidentiality e2e: BUILT (2026-10-05).** The catalog replay
   (`drill-replay.test.ts`, differential-interactive.md
   §28) drives the REAL OpenCode 2 TUI twice per drill, plain and through the
   REAL launcher (`mandu opencode`, then under the opt-in, the drill's own mode
   `secrets`, the default kernel layer: the guard with the private-server
   allowance, write-protect, the config lockdown), with
   `MANDU_REPLAY_OPENCODE=2`. Nothing is re-recorded: a script's intents are
   agent-neutral, and the scripted model spells them in 2.x's tools when the
   request advertises `shell` and no `bash` (`replay-engine.ts`
   `OPENCODE2_SPELLING`: `read{path}`, `shell{command}`, `write{path,
   content}`, `edit{path, oldString, newString}`, `webfetch{url}`, the MCP
   tools as `<server>_<tool>`), and reads 2.x's `Read file …, lines A-B`
   framing back. The profile (`differential-profiles.ts`
   `OPENCODE2_PROFILE`) is 1.x's TUI facts, which 2.0.23 kept (composer,
   `esc interrupt`, one Ctrl-C quits, measured), with `--standalone --auto`
   and no `--port` on both sides, and 2.x's transcript (`session_message`
   in the same `opencode.db`). Per push, blocking
   (`integration.replay-opencode2`, the CI guest pins `opencode2`, maxSkip
   0): `conf-read-exfil` (a `no-model` file read and posted to the sink: the
   model and the sink get one symbol, the token never), `conf-net-exfil-blocked`
   (posted to an unbound host: blocked, nothing forwarded; a hand script,
   since no live model would carry the send out), `conf-read-control` (the
   same file unlabelled: raw, the control that the oracles can fire),
   `util-reasoning`, `util-plain-read-verbatim`,
   `conf-quarantine-any-model` (the inspect channel over MCP: the answer
   returns as a symbol, the file's values never on the T-LLM wire) and
   `util-unicode-value` (a multi-byte reply, `pass:さくら-7741`, through the
   reply filter's PTY relay; added 2026-10-06). All seven
   pass on 2.0.23 and on 1.18.13 (the conf pair's and the hand script's
   OpenCode skips are lifted for both). Since 2026-10-11 also
   `conf-prompt-registered-value` and `conf-prompt-policy` (a registered key
   and a `key-shapes` token in the human's prompt: the model gets the
   symbol or the redaction, never the value), and the same eight drills less
   `util-unicode-value` run per push on 1.18.13 (`integration.replay-opencode`)
   and on OpenClaw (`integration.replay-openclaw`), blocking; after a week
   of it the legacy headless `opencode-e2e` / `openclaw-e2e` per-push
   entries retired on 2026-10-18 (test-reorganization.md §9.1). `util-unicode-value` timed out on
   both generations until 2026-10-06: the profiles read `opencode.db` + WAL
   as latin1 for the turn sentinel, so a multi-byte reply never matched;
   both now decode it as UTF-8, as Goose's does
   (`differential-profiles.ts` `sqliteRawText`). The watch runner has its own 2.x
   profile (`drill-target-opencode.ts` `OPENCODE2_WATCH_PROFILE`, no `-m`:
   the model rides the inline config). The rest of the drill tooling
   (2026-10-06): the nightly replays the whole catalog on 2.x as on 1.x
   (`integration.replay.opencode2`, the same area shards; its records under
   the lane `v2` so they never share a session key with 1.x's); the drill recorder reads
   a 2.x session's calls (`shell`, `read{path}`, …) in the spelling its
   requests advertised, back to the same intents as 1.x's
   (`integration.drill-record-opencode`, nightly, both generations); and the
   `opencode-e2e` harness, which runs `opencode run` against its own
   in-process stack rather than the launcher, ran on 2.x per push until
   2026-10-18, when its drills' replay took its place
   (`integration.opencode2-e2e`: `opencode2 run --standalone`, the private
   `OPENCODE_TEST_HOME`, the inspect server in 2.x's spelling with code mode
   off and `execute` denied; seven of eight scenarios, the quarantined read
   left out because a one-shot `run` does not wait for its MCP servers,
   docs/design/testing/agent-e2e-harness.md §2.2.1).
6. **A background move the user makes** (found 2026-10-05). The 2.x TUI can
   move a running foreground command or subagent to the background ("User
   requested that active blocking work be moved to the background", in the
   binary); its output then returns as the same `<shell …>` / `<subagent …>`
   user text, which no tool_result leg reads, whatever the call's input was.
   Refusing the `background` field closes only the model's own request.
   **BUILT (2026-10-05): the proxy reads the notices as tool output.**
   - *The move, on 2.0.23.* `opencode serve` driven through its own API
     with a scripted upstream: while the model's foreground `shell` (or
     `subagent`) ran, `POST /api/session/:id/background` (what the TUI's
     ctrl+b calls) moved it. The call's tool_result became `Command moved
     to the background (shell ID: sh_…).` / `The subagent is working in the
     background (sessionID: ses_…).`, a synthetic user text said the user
     moved it, and the output came back later as a user message of its own,
     `<shell id="sh_…" state="completed" command="<command>">\n<output>\n</shell>`
     or `<subagent sessionID="ses_…" state="completed" description="…">\n<answer>\n</subagent>`.
     A moved `cat` of a file reached the model in clear. OpenCode re-sends
     the same text in every later request (only its `cache_control` moves to
     the newest block) and escapes nothing in it: a command's quotes and a
     `</shell>` in the output appear as they are. The transcripts are in the
     fixture's `__background_move__`.
   - *The fix* (`interceptors/anthropic-proxy/src/opencode-background.ts`,
     applied by `rewriteRequest` in an `opencode` session and in one with no
     table of its own). Every user text that starts `<shell id="` or
     `<subagent sessionID="` becomes, for the rewrite, a stand-in
     tool_result with a stable id (`mandu-bg:<kind>:<id>`). It is tied to
     the call that started the work: exactly one tool_result must open with
     that call's "moved" line, the call must be a shell tool (or
     `subagent`), and the notice's header must equal the header rebuilt
     from that call's own command (or description), whole, the body running
     to the last closing tag. Then the body is classified and symbolized as
     that tool's result, with callTaint and the agent-receipt check asked
     under the real call's id, the value backstop and the inbound spec as
     for any result. A notice that does not parse that way (no or several
     claiming calls, another header, no closing tag) is masked whole at
     `no-model`, with a note saying why. The rewritten body goes back
     between the original header and closing tag, in the same block object
     and position, so the request keeps OpenCode's shape, a re-sent notice
     forwards byte for byte the same, and the OpenAI-wire shadow writes it
     back as user text. The prompt filter and the trusted-context haystack
     no longer see the notice (it is the tool's output, not the human's),
     and the §9 oracle reads it as tool output. Tests:
     `interceptors/anthropic-proxy/test/unit/opencode-background.test.ts`
     and `tests/stack/opencode2-background-notice.test.ts` (`secrets` mode,
     the real arbiter: a moved `cat` of a labelled file, the captured 2.0.23
     transcript replayed verbatim, a moved subagent's answer carrying a
     registered value, the re-sent notice, an unclaimed notice, an
     unreachable arbiter).
   - *A launcher switch, partial.* The move is bound to the TUI key
     `session_background` (default `ctrl+b`; `none` unbinds it) in 2.x's CLI
     config, which 2.x migrates from the old `tui.json`. The
     `session.background` route stays callable by any client of the
     session's server and by `tui.command.execute`, so a key binding cannot
     close the path; the proxy fix is what does.
7. **The background output file** (found 2026-10-05). The "moved"
   result names the file the output streams to
   (`$XDG_DATA_HOME/opencode/shell/<hash>/sh_<id>.out`) and invites a read
   of the current output. A `read` or `cat` of that file while the work
   runs was an ordinary read of an unlabelled file the agent itself wrote,
   so neither the path label nor callTaint (whose tree read only that file)
   masked it, and the value backstop knew the secret only once a masked
   copy was registered. **BUILT (2026-10-05): a session label.** When the
   proxy forwards a shell result that opens with the "moved" line, it reads
   the file's path off the result's first text block and registers it
   (and its HumanView spelling) as a SESSION label, `no-model`
   ([confidentiality.md](../confidentiality/confidentiality.md) §8,
   `arbiter/policy/session-path-labels.ts`, op `sessionPathLabel`), before
   the model can read the name. Nothing the human sees or keeps changes: it
   is in memory, raise-only, and `clearSessionPathLabels` (human plane)
   drops a session's rows. Covered: a `read{path}` of the file (the
   path-derived label), a shell command that names the file (`cat`,
   `tail`, any spelling the classify path parser resolves), and callTaint's
   file levels for a recorded tree. Not the kernel guard's open index
   (`derivedLabelsSince` does not list session labels, since 2026-10-05):
   it would hand OpenCode a twin of its own file. Not labelled (an arbiter
   without the op, a throw, a result that names no absolute path): the
   result is masked whole instead, so the model never learns where the
   unprotected output is. Since item 10 the file's directory is a
   persistent catalog location, so the session label is a second layer for
   a path the catalog does not know (a future layout); the launcher does
   not clear session labels at the session's end (item 10). Tests:
   `arbiter/test/unit/session-path-labels.test.ts`, the proxy's
   `test/unit/opencode-background.test.ts`, and
   `tests/stack/opencode2-usershell-outfile.test.ts` (`secrets` mode: before
   the moved result is forwarded a read of the file goes out raw, after it
   a `read{path}` and a shell `cat` of the file reach the model only as
   symbols).
8. **A config written mid-session. BUILT (2026-10-05): the config
   lockdown.** Found by part 4. Measured with scripted local upstreams:
   - *OpenCode 2 (2.0.23) reloads.* Its file watcher applied a project
     `opencode.json`, a `.opencode/opencode.json` (a new one too), an
     ancestor's (a file that did not exist at launch) and the global one,
     written while a `run --standalone` turn waited on a tool call, to the
     next model request; a model endpoint written there took that request,
     tool result included, around the proxy. The private server also takes
     `POST /api/location/reload` ("rebuild every loaded location"), and any
     process of the user can call it: the server listens on 127.0.0.1, its
     password sits in its `/proc/<pid>/environ`. A shell the model runs is
     such a process.
   - *OpenCode 1 (1.18.13) does not.* Neither a benign marker header nor a
     model endpoint written mid-turn to the project or the global config
     reached a later request of the same `run`, while the same marker
     written before the launch did. Its model-level endpoints do not
     re-point a request either (part 4). So the shipped product had no live
     hole here; `opencode-v2-config.test.ts` pins it on the real 1.x binary
     (`MANDU_OPENCODE_V1_BIN` or OpenCode 1 on `PATH`).
   - *Other reloaded sources.* An agent's markdown (`.opencode/agents/*.md`,
     either spelling's `request.settings.baseURL` or `options.baseURL` in its
     frontmatter) and an agent's `request.settings.baseURL` in a config did
     not move a request; their `model` is fenced like any model. A plugin is
     code run inside OpenCode, not a config value; it is out of this item's
     reach (items 11 and 12: neither a project's nor the user's own runs with
     confidentiality ON).

   *The fix* (`agent-config.ts` `opencodeLockdownEnv`, for a 2.x launch
   only): OpenCode 2 reads no configuration file the session can change.
   - `OPENCODE_DISABLE_FILEWATCHER=1` (and its alias): no reload on a write
     (measured alone: none of the four writes moved a request);
   - `OPENCODE_DISABLE_PROJECT_CONFIG=1` (and its alias): no project layer
     at all, at launch or on a reload;
   - `OPENCODE_CONFIG_DIR` at a directory the launcher writes in the scope
     run dir, and `OPENCODE_CONFIG` at a run file in it: every layer OpenCode
     2 would have read (the user's global documents, their `OPENCODE_CONFIG`,
     every ancestor's project documents) is merged there, lowest first, under
     the routing and the fence (`opencodeV2UserDoc`), after the launch-time
     check of part 4 read the same layers. The inline content stays in
     `OPENCODE_CONFIG_CONTENT`, fixed for the process;
   - the whole-agent guard refuses the agent's tree a write into that
     directory (a deny entry, `opencodeWriteProtect`, in `run.ts`'s
     write-protect list). It is the one layer left on disk: a test pins that
     a write there plus the reload API would move a request, which is the
     guard's job. Where the guard does not run (no seccomp user
     notification, `MANDU_WRITE_PROTECT=0`, mode `off`), that write stays
     possible, and it takes the server's password and a reload call besides;
     so with confidentiality ON the launch requires the guard (§2.3.1,
     "Confidentiality ON: allowed under three conditions"), and mode `off`
     keeps nothing from the model.

   Measured with the fix: none of the four writes moved a request, with or
   without the reload API called (it answered 204 and rebuilt the location).
   *Why this fix, and what it costs.* Write-protecting the config paths
   themselves would keep the project layers, but every ancestor up to `/`
   can hold one, a new file must be covered too, and renaming a prepared
   directory onto an ancestor would slip past an entry for its files; the
   reload API would still read whatever is there. The proxy cannot help:
   a request sent around it never arrives. The lockdown needs no agent
   cooperation and keeps most of the utility. The launcher's directory links
   in the user's global configuration directory and every project
   `.opencode` (agents, commands, skills, themes; a project's plugins and
   tools only with its opt-out, item 11, the user's own only with theirs,
   item 12;
   a project entry replaces a global one of the same name; measured: a
   linked project agent loads and runs), and composes one `AGENTS.md` from the global one and the
   project's (repository root down to the cwd), because OpenCode 2 reads no
   project `AGENTS.md` with project config off (the `instructions` key did
   not bring it back; measured). Lost: skills in a project's `.claude` or
   `.agents` directory (the home ones stay), and a config edit applying
   before the next launch. All of it is a snapshot taken at launch.
   Tests: `launcher/test/unit/opencode-v2-config.test.ts` (the env, the
   merged run file, the linked directory, the guard entry) and
   `launcher/test/component/opencode-v2-config.test.ts` (the real 2.x
   binary: each write, with and without the reload API; the guard's
   directory; the real 1.x binary: no reload).
9. **The user's own shell** (2026-10-05). The server's
   `POST /api/session/:id/shell` (the TUI's `!cmd`) runs a command and puts
   its output in the next request as a user message of its own:
   `The following shell command was executed by the user:\n<shell
   id="sh_…" state="completed" command="<command>">\n<output>\n</shell>`
   (captured on 2.0.23 through the server API; unescaped, like the
   background notice; re-sent unchanged in later requests; fixture
   `__user_shell__`). **BUILT: read as a shell result.** It is program
   output, not the human's typed text, so the proxy reads it as the
   background notices are read (item 6), under a stand-in call
   `shell{command}`: the classify verdict's path-derived label on the
   command, callTaint by the command's exec signature (no model call
   started it), the value backstop and the inbound spec. The command is
   read off the header up to the first `">` and newline (a command holding
   that sequence is cut early, and the rest is read as output, never
   forwarded raw as "the command"). Anything that opens with that line and
   does not parse is masked whole. Claude Code's own bash mode (`!cmd`) is
   read the same way since 2026-10-05 (§2.4). Stopping an agent's own
   commands from reaching the server's route is the kernel guard's
   (separate work).
10. **OpenCode's own stores, kept on disk** (found 2026-10-05). OpenCode 2
    writes EVERY shell command's output, a foreground one's too, to
    `$XDG_DATA_HOME/opencode/shell/<40 hex>/sh_<id>.out` and keeps the files
    after the run; its server keeps the session, tool outputs included, in
    `$XDG_DATA_HOME/opencode/opencode.db`, as OpenCode 1.18.13 does (it
    writes no `.out` files: probed, its tool output is in `opencode.db`'s
    WAL); `auth.json` there holds the provider keys. So a result Mandu
    masked left its raw output on disk, and a later session (or this one
    after an arbiter restart, which forgets session labels) could `read` or
    `cat` it raw: the value backstop knows only registered values.
    **BUILT: the same posture as Claude Code's and Codex's own stores.**
    What covers each agent's store:

    | Store | What Mandu does |
    |---|---|
    | Claude Code `~/.claude` (`projects/*.jsonl` transcripts, settings) | fs-outbound `SENSITIVE_PATHS`: a tool's read or write asks (denied on the wire unless approved); the catalog labels it `no-model` (a read or a shell command naming it is masked); discovery never twins it (`AGENT_STORES`), so the agent reads and writes it raw. Its login (`.credentials.json`, and `~/.claude.json`) is keyed per launch since 2026-10-09: raw only where Claude Code runs, twinned elsewhere (secret-discovery.md §1.10) |
    | Codex `~/.codex` (`sessions/` rollouts; its login `auth.json` keyed per launch, as above) | the same three |
    | OpenCode 1 and 2 `~/.local/share/opencode` (`opencode.db`, `auth.json`, 2.x `shell/<hash>/sh_<id>.out`) | the same three, since this change |
    | OpenCode under another `XDG_DATA_HOME` | the catalog's `OPENCODE_DATA_SHAPE_RE` (`…/opencode/shell/<40 hex>/…`, `…/share/opencode/shell`, `…/opencode/opencode.db*`) labels it `no-model` and discovery skips it; the path gate's prefix list does not reach it |

    Classification only, never a twin or an open gate: OpenCode keeps
    reading and writing its own files raw (it builds the background notice
    from the `.out` file). Proved on the real 2.0.23 binary under the real
    launcher stack (`tests/sandbox/guard/opencode2-shell-output.test.ts`,
    mode `secrets` with the test-named private-server allowance): run 1's
    `shell` wrote its `.out`; run 2, on a fresh arbiter, had the model `read`
    that file and `cat` it, and neither result carried the output (it went
    out raw without the change); run 2's own shell worked and wrote its own
    file. Residue: a command that names the file only through a variable or
    expansion (`cat $XDG_DATA_HOME/…`, `find … -exec cat`) is classified on
    what it names (the shape needs the 40-hex directory or `share/opencode/
    shell`), and no open gate catches it; the value backstop then applies.
    The session labels of item 7 stay as a second layer for a path no
    catalog rule knows, and the launcher does not clear them at the
    session's end: they are memory-only and raise-only, and clearing one
    would lower the protection of a file that is still on disk.
11. **A repository's plugins and custom tools, OpenCode 1 and 2**
    (found 2026-10-06). OpenCode imports JavaScript and TypeScript modules
    into its own process: plugins (`.opencode/plugin/*.{ts,js}`,
    `.opencode/plugins/`, on 2.x also a package directory there, and the
    packages a config document names under `plugin` / `plugins`), on 1.x
    custom tools (`.opencode/tool/`, `.opencode/tools/`), and on 1.x the
    plugins a `tui.json` names. A plugin's hooks edit the model request
    itself: the system prompt (1.x `experimental.chat.system.transform`, 2.x
    the session `context` hook), a tool's output after it ran (1.x
    `tool.execute.after`, 2.x `execute.after`), on 2.x the endpoint and the
    headers (`model.request`, `http.request`).
    - *Measured* (1.18.13 and 2.0.23 under the real launcher, `mandu opencode`
      / `mandu opencode2`, mode `secrets`, the guard on, a scripted model; a
      project plugin and a `no-model` file with a pinned reader):
      (a) a project `.opencode/plugin/probe.js` loaded on both: 1.x reads
      its project directories itself, and 2.x, though Mandu sets
      `OPENCODE_DISABLE_PROJECT_CONFIG`, loaded it through the launcher's own
      config directory, which linked every project `.opencode` entry in
      (item 8). (b) In the plugin, a read of the labelled file got the
      placeholder (the twin, as every program of the agent's tree does), and
      a connect to a loopback listener was refused (the guard); but the
      agent process holds what the proxy masks only on its way out: the
      reader's raw output (its tool_result is masked from the call's tree;
      OpenCode saw the bytes) and the credential stores the runtime reads
      raw (`~/.codex/auth.json`, then never twinned for any agent: the
      global exclusion before 2026-10-09; since secret-discovery.md §1.10
      Codex's login is a twin under `mandu opencode`, registered, so this
      file's key reaches the plugin only as a placeholder; OpenCode's own
      `auth.json` stays raw to it, as it must, and so do Claude Code's
      `~/.claude/.credentials.json` and `~/.claude.json` while Mandu's AI
      helper runs `claude -p` in OpenCode's world: neither
      `ANTHROPIC_API_KEY` nor `MANDU_ULLM_API_KEY` set, and no `--no-mcp`). The
      plugin put both into the SYSTEM PROMPT, which no check reads (the
      prompt filter reads user text; the tool_result legs read tool
      results), and the scripted model received the registered secret and
      the store's key raw, on both generations. (c) A rewrite of a tool's
      output did not evade the tool_result legs for a registered value (the
      value backstop masked the whole result), but a custom tool the
      project defined (1.x `.opencode/tool/leaktool.js`) returned the store
      file's key raw: a tool no spec maps is masked by what its input names
      and by the session's raw reads (guarantees.md, "A tool no Mandu spec
      knows"), not whole, and a clean session's tool that reads a file
      in-process names none. (d) The agent can write such a file: the
      workspace is writable, and no write-protect entry covered `.opencode`
      or the global config directory, so a plugin planted in one session
      ran in the next.
    - *Why not "the class of the agent's shell"* (item 8 said so): a shell's
      output reaches the model only as a tool result the proxy reads; a
      plugin writes the request. The proxy can check what OpenCode reports;
      it cannot check code that builds the report.
    - **BUILT (2026-10-06): a project's code does not run, by default,
      with confidentiality ON** (`launcher/src/opencode-project-code.ts`).
      A file the repository brings is text an injected agent or the
      repository's author controls, so it is held to the invariant:
      - *OpenCode 2*: the launcher leaves each project `.opencode`'s
        `plugin`, `plugins`, `tool` and `tools` out of the directory it
        links (`buildOpencodeConfigDir`) and drops `plugin` / `plugins` from
        each project document it merges into the run file
        (`opencodeV2UserDoc`), and says what it left out ("OpenCode — this
        project's plugins and custom tools are left out …"). The rest of
        the project's `.opencode` (agents, commands, skills, themes) is
        linked as before.
      - *OpenCode 1* reads its project directories itself (from the start
        directory up to the repository root, `/` outside one), so Mandu
        cannot leave a part out without dropping the whole project
        configuration. Until 2026-10-07 every such launch was refused. Now
        (item 12) a 1.x launch with neither opt-in runs with OpenCode's own
        `OPENCODE_PURE=1` (`--pure`, "run without external plugins"), which
        skips every plugin that is not built in, a project's plugin modules
        and the plugins its `opencode.json(c)` / `tui.json(c)` name included
        (measured on 1.18.13: the probe below never loads); the launch says
        so ("OpenCode — this project's plugins are left out …"). The switch
        does not skip custom tools (`{tool,tools}/*.{js,ts}` of every config
        directory), so a launch in a project that brings a custom tool
        module is REFUSED before anything starts (`run.ts`), naming each
        file and the ways out (remove it, OpenCode 2, or the opt-out); with
        the user's own opted in (the switch then off) a project's plugins
        refuse as well. A document Mandu cannot parse counts. A wrapper under
        `--target opencode`, whose generation the launcher does not probe,
        gets this rule. The user's own `OPENCODE_DISABLE_PROJECT_CONFIG=1`
        (OpenCode 1 then reads no project directory) leaves nothing to
        refuse.
      - *The user's own* plugins and tools (the global config directory,
        `$OPENCODE_CONFIG_DIR` or `~/.config/opencode`, and `~/.opencode`)
        were left running here as the user's choice; since 2026-10-07 they
        do not run either (item 12).
      - *The opt-out*: `MANDU_OPENCODE_PROJECT_PLUGINS=1` (also `true`,
        `yes`, `on`) runs a project's as before, with a warning line ("what
        they put into a model request is not checked"). Mode `off` keeps
        nothing from the model, so the rule does not apply there.
      - *Written mid-session* ((d)): the guard holds a change to the user's
        and the project's plugin and tool directories (the four names under
        the global config directory, `~/.opencode`, and each `.opencode`
        from the cwd up to the repository root, the cwd's alone outside one)
        for the human's answer, as it holds a repository's git hooks: they
        run in the next OpenCode session, outside Mandu too
        (write-protection.md §1, label "an OpenCode plugin or tool").
    - *Left as is, and why.* A config document can name an npm plugin
      (`"plugin": ["pkg"]`); the user's global `opencode.json` was not held
      here, because OpenCode writes it itself; item 12 holds it now and
      makes OpenCode 1's own `$schema` edit before the launch. A project's
      `opencode.json` is not held: the agent edits the workspace in ordinary
      work, and a plugin it names does not run under Mandu. A tool Mandu has no
      mapping for (no spec entry, no gate-table entry) is masked whole on
      every agent since 2026-10-07 (the maintainer's decision;
      confidentiality plan 10 §11.18), whatever the session read, unless
      the person lists it under policy.yaml `mapped_tools:`; with a
      project's tools off, what remains is the user's own, and those are
      masked until listed. A 1.x project `.opencode/package.json`
      still gets OpenCode's dependency install (lifecycle scripts run as a
      program of the agent's tree, the shell's class: their output reaches
      no request).
    - Tests: `launcher/test/unit/opencode-project-code.test.ts` (which files
      count per generation, the user's own never; the linked directory and
      the run file without them, with the opt-out, through
      `writeAgentConfig` with the axis on, unknown and off; the
      write-protect entries), `launcher/test/component/opencode-project-plugins.test.ts`
      (through `main()` with an OpenCode 1 stand-in: a plugin, a tool and a
      plugin-naming config each refused before the agent runs; the opt-out
      and mode `off` not), and against the real binaries
      `tests/sandbox/guard/opencode-project-plugins.test.ts` (the measured
      plugin: both generations leave it out and no request carries either
      value, 1.x through `OPENCODE_PURE`; the control, the opt-out, loads it
      and the model receives the secret raw in the system prompt).
12. **The user's own plugins and custom tools, OpenCode 1 and 2**
    (maintainer decision 2026-10-07, "Off + Approvals";
    `launcher/src/opencode-global-code.ts`). Item 11 left the user's own
    running as their choice. They are the same code in another folder: the
    modules in the global config directory's `plugin`, `plugins`, `tool` and
    `tools` (`$XDG_CONFIG_HOME/opencode`, `$OPENCODE_CONFIG_DIR`,
    `~/.opencode`) and the packages a global document names under `plugin`
    / `plugins` (npm plugins such as oh-my-opencode, which OpenCode
    installs into its cache and imports into its own process). Each can do
    what item 11's probe did, and on 2.x more: a plugin runs inside the
    private server, which the guard treats as the agent itself (§2.3.1,
    "the server is never made a holder"), so a plugin holding raw bytes
    (a pinned reader's output, a credential store) could send them out on
    443. And with the global `opencode.json` writable, an injected agent
    could add a plugin there for every later session.
    - **BUILT (2026-10-07): with confidentiality ON the user's own do not
      run either, by default.**
      - *OpenCode 2*: the launcher already builds the configuration (item
        8). It leaves the global directory's and `~/.opencode`'s `plugin`,
        `plugins`, `tool` and `tools` out of the directory it links
        (`buildOpencodeConfigDir`, `globalCode`), and drops `plugin` /
        `plugins` from the user's documents it merges: the global ones,
        `OPENCODE_CONFIG`, `~/.opencode/opencode.json(c)`
        (`opencodeV2UserDoc`), and the inline `OPENCODE_CONFIG_CONTENT`
        (`opencodeRoutingContent`).
      - *OpenCode 1* reads its global directory itself; redirecting it
        would take `XDG_CONFIG_HOME`, which every program the agent starts
        inherits. But OpenCode 1 has a switch for exactly this:
        `OPENCODE_PURE=1` (the `--pure` flag) loads no external plugin,
        whatever named it (a file in a plugin folder, a global, project or
        inline `plugin` list, a TUI plugin), and keeps OpenCode's built-in
        auth plugins, so sign-in still works. The launcher sets it whenever
        neither opt-in is given (`opencodeV1Pure`; the agent-config env,
        which overrides the user's own value), and also drops the user's
        plugin list from the run file and the inline content. The switch
        does not skip custom tools: a 1.x launch whose user directories hold
        one is REFUSED, naming the files (`opencodeGlobalToolsRefusal`: move
        it out, OpenCode 2, or the opt-in). Custom tools in the global
        directory are rare; plugins (the common case, oh-my-opencode
        included) no longer stop a launch.
      - *What the user sees*: one launch line naming what was left out,
        "OpenCode — your own OpenCode plugins and custom tools are left out
        of this session (they would run inside OpenCode, where what they
        put into a model request is not checked): <files>.
        MANDU_OPENCODE_GLOBAL_PLUGINS=1 runs them unchecked." OpenCode
        itself runs as usual without them. The default (compact) display
        shows each of these left-out lines, for a project's code too, as one
        short `mandu: ! … do not run under Mandu: <files>; <opt-in>=1 runs
        them unchecked` line (packaging.md §5, `compactNotice`); until
        2026-10-11 it dropped them and only `--verbose` named the files.
      - *The opt-in*: `MANDU_OPENCODE_GLOBAL_PLUGINS=1` (also `true`,
        `yes`, `on`) runs them as before, with a warning line naming them.
        On OpenCode 1 the switch is all or none, so the project opt-in alone
        cannot run a project's plugins while leaving the user's out: such a
        launch is refused when the user has plugins, naming them
        (`opencodeV1PluginSplitRefusal`); both opt-ins run both. Mode `off`
        keeps nothing from the model, so the rule does not apply there.
    - **The settings files wait in Approvals.** The user's OpenCode
      settings documents that can name a plugin join the write-protect list
      (`ask`, label "an OpenCode setting", write-protection.md §1):
      `opencode.json`, `opencode.jsonc`, `config.json` (1.x's legacy name),
      `tui.json` and `tui.jsonc` in the XDG global directory,
      `$OPENCODE_CONFIG_DIR` and `~/.opencode`, and the user's
      `OPENCODE_CONFIG` file. The code folders were already on it (item 11;
      now under both the XDG directory and `$OPENCODE_CONFIG_DIR` when that
      is set). For every agent, not only OpenCode: any agent could plant a
      plugin for the next OpenCode session. OpenCode writes some of these
      itself:
      - 1.x adds a `$schema` key to each config document it loads that
        lacks one, at every start until the key is there. Held, that would
        stop OpenCode's start for the hold's ceiling. So the launcher makes
        the same edit first (`addOpencodeSchema`: the same text OpenCode
        inserts, only to an existing document that parses and has no key;
        never creates a file), outside the guard, and says so on its log
        line.
      - 1.x saves the user's global settings through its API
        (`Config.updateGlobal`, from a client's settings action), adds or
        removes a TUI plugin from its plugin manager, and migrates `theme`
        / `keybinds` out of `opencode.json` into `tui.json` once. Under Mandu
        each waits in Approvals ("The program …/opencode wants to change a
        file that runs later: ~/.config/opencode/opencode.json"); the human
        answers. *Allow once* is the right answer for OpenCode's own change:
        *Always* would also admit the agent's own `write` / `edit` tool,
        which runs in the same OpenCode process, writing that file later.
        No answer within the hold's ceiling (60 s) is a refusal, and
        OpenCode carries on without the change.
      - 2.x under Mandu never writes the user's documents: its global
        directory is the launcher's (item 8), and a write there is refused.
      - Mandu's own launches are not affected: the launcher runs outside
        the guard, and writes none of these files but the `$schema` edit.
      `~/.claude/settings.json` (Claude Code's own settings, which can name
      a hook) stays OFF the list by the user's decision of 2026-09-28
      (write-protection.md §3): Claude Code writes it in ordinary use.
    - *What the opt-in leaves* (guarantees.md §3): the user's plugins run
      inside OpenCode unchecked, as before this item: what they put into a
      model request is not read, and on 2.x a plugin in the server process
      can send what the process holds out on 443 (the server is the agent's
      own process to the guard). With the default, both are closed: no such
      code runs. Also left: an npm plugin's package in OpenCode's cache
      (`~/.cache/opencode`) and the global directory's own `package.json` /
      `node_modules`, which OpenCode itself installs into, are not held; a
      change there matters only to a plugin that runs, which is the
      opt-in's (or a session outside Mandu).
    - Tests: `launcher/test/unit/opencode-global-code.test.ts` (which files
      count per generation; the launch decision for both origins, both
      generations and both opt-ins; `OPENCODE_PURE` and the run file through
      `writeAgentConfig` (1.x), the linked directory and run file (2.x),
      with the axis on, unknown and off; the inline content; the settings
      files on the write-protect list; the `$schema` edit),
      `launcher/test/component/opencode-project-plugins.test.ts` (through
      `main()`: the user's custom tool refused, their plugins not, the
      opt-ins), and against the real binaries
      `tests/sandbox/guard/opencode-project-plugins.test.ts` (a plugin in
      the global plugin folder and (1.x) one the global `opencode.json` names:
      left out on both generations, no request carries either value; the
      control, the opt-in, loads it and the model receives the secret raw;
      an agent's shell write to the global `opencode.json` waits in
      Approvals and, unanswered, is refused, while OpenCode's own start is
      not held).

#### 2.3.1 Part 1: every model call in the wrapped process

**Status: BUILT (2026-10-05)**, first behind the opt-in, on for every 2.x
launch since OpenCode 2 became a default-supported agent (§2.3). Read from OpenCode 2.0.23
(npm `@opencode/cli`, published after 2.0.22): its `--help` per
subcommand, its bundled code, and probes with hermetic XDG dirs and two
scripted local Anthropic upstreams (no key, no network).

**How OpenCode 2 reaches a server.** Every model-running shape is a client
of an OpenCode server, chosen in `cli.server-connection.resolve`:
`--server <url>` joins that server; `--standalone`, or `disabled: true` in
the service configuration file `$XDG_CONFIG_HOME/opencode/service.json`
(`opencode service set disabled true`), spawns a PRIVATE server as a child
(`opencode serve --stdio --port 0`, password from the environment, stopped
with SIGTERM when the client exits, no registration written); otherwise the
client joins the background service registered in
`$XDG_STATE_HOME/opencode/service.json` (default port 49374, the "latest"
channel), starting `opencode serve --service`, a daemon, when none answers.
The private server inherits the client's environment, so Mandu's routing
(`OPENCODE_CONFIG`, `OPENCODE_CONFIG_CONTENT`) and the wrap reach it.

**Admission.** `opencodeLaunchRefusal` admits major 2 as well as 1, as
`opencode` or `opencode2` (`opencode2` is probed with `--version` like
`opencode`, and must report major 2); an unreadable version, the `0.0.0-*`
prereleases and every other major stay refused, and `MANDU_OPENCODE2=0`
refuses major 2 (§2.3). Until 2026-10-05 this took the experimental opt-in
`MANDU_EXPERIMENTAL_OPENCODE2=1` (only an explicit yes, as
`MANDU_EXPERIMENTAL_INTEGRITY`), which is no longer read. With
confidentiality ON it admits OpenCode 2 only while its guards are in force
(see "Confidentiality ON: allowed under three conditions" below).

**The argv rule** (`launcher/src/opencode-argv.ts`, an allowlist; applied in
`run.ts` right after the version check, since the parse step does not know
the version; OpenCode 1's rule is after this list):

- allowed: the TUI (`opencode [dir]`), `run`, `mini`; each gets
  `--standalone`, after `opencode` for the TUI and after the subcommand for
  `run` / `mini` (OpenCode reads a flag only there: a flag put before a
  subcommand is a usage error, so that shape is refused too); an argv that
  already says `--standalone` is left alone;
- refused with what to do instead: `--server` (any spelling), `serve`,
  `service`, `pair`, `api`, `acp`, the management subcommands (`session`,
  `auth`, `mcp`, `plugin`, `models`, `stats`, `reload`, `debug`, `upgrade` /
  `update`, `uninstall`: run them without `mandu`), `--wizard` (it builds a
  command Mandu never sees), any flag 2.0.23 does not list for the shape, and
  a switch given a value (`--standalone=false`);
- `--help` / `--version` pass unchanged (for a refused subcommand only right
  after it, where no unknown value flag can hide them); `--` ends the flags
  (2.0.23 takes what follows as the message).

**OpenCode 1's rule** (`opencode1LaunchArgv`, 2026-10-11). Until then
OpenCode 1's argv was untouched, so a live walk of the first-session tour
ran `mandu opencode serve` inside the session (where it failed) and
`mandu opencode auth list` (which ran): commands that are not the agent,
and a server other clients would drive outside the launch. OpenCode 1 now
gets the same refusal, with the same message (the command named, what to
do instead), over its own command list, read from 1.18.13's
`opencode --help`:

- allowed, argv unchanged (1.x has no background service, so no
  `--standalone`; its flags are not allowlisted): the TUI
  (`opencode [project]`) and `run`;
- refused: `serve`, `web` (a server a browser drives), `attach` and
  `run --attach` (join a running server), `acp`, `pr` (checks out a branch,
  then starts OpenCode: not a checked shape; check the branch out first),
  `github`, and the management commands `providers` / `auth`, `mcp`,
  `agent`, `session`, `export`, `import`, `db`, `models`, `stats`,
  `plugin` / `plug`, `debug`, `upgrade`, `uninstall`, `completion` (run them
  without `mandu`);
- OpenCode 1 parses with yargs and reads a subcommand after its flags, so a
  TUI positional that names a subcommand is that subcommand
  (`opencode --print-logs serve` is refused as `serve`), skipping the
  values of the TUI's value flags (`--prompt serve` is a prompt), and also
  after `--` (fail closed); `run` with flags before it is refused with how
  to write it;
- `--help` / `--version` pass as for OpenCode 2.

**The listen flags (2026-10-11).** 1.18.13's TUI talks to its built-in
server IN-PROCESS (`http://opencode.internal`, an RPC to its worker, no
socket) unless `--port` or `--hostname` is in the argv before `--`, or
`--mdns` turns mDNS on (which also defaults the hostname to `0.0.0.0`);
then the worker listens on that address, and any client that reaches it (a
browser, `opencode attach`, another program) could drive the agent outside
the launch's checks. Read from the bundled TUI handler and
`resolveNetworkOptions`. So `--port`, `--hostname` and `--mdns`, in every
spelling (`--port 4096`, `--port=4096`, `--mdns`, `--mdns=true`), are
refused on the TUI, with the flag named and "leave it out". `--mdns-domain`
and `--cors` only shape a listener those start, and `--no-mdns` keeps it
off: allowed. Where else they could come from:

- *configuration*: OpenCode's `server` block (`port`, `hostname`, `mdns`,
  `mdnsDomain`, `cors`) is read only by `resolveNetworkOptions`, which only
  `serve`, `web` and `acp` call (all refused), and from the GLOBAL file
  only; the TUI resolves its listener from its argv alone, so a project's
  or the user's configuration cannot make a `mandu opencode` TUI listen.
  Nothing to neutralise;
- *environment*: no variable sets them (the CLI has no environment
  prefix; `OPENCODE_SERVER_PASSWORD` / `_USERNAME` only authenticate);
- `run --port`: declared ("port for the local server") but never read in
  1.18.13; `run` talks to its server in-process too, so it passes.

OpenCode 2 has no such TUI flag: `--port` / `--hostname` / `--cors` are
`serve`'s (refused), and the allowlist refuses them on the TUI, `run` and
`mini` as unknown flags. The private server `--standalone` spawns is
`opencode serve --stdio --port 0`; 2.0.23's `serve` takes its hostname from
`--hostname`, else the service configuration only in `--service` mode, else
`127.0.0.1`, so it binds an ephemeral loopback port whatever the
configuration says (and the guard admits only its own client to it,
§2.3.1).

Evidence: `launcher/test/unit/opencode-argv.test.ts` (each spelling, both
generations) and the OpenCode 1 stand-in in
`launcher/test/component/opencode-v2-standalone.test.ts` (`--port 4096`,
`--hostname=0.0.0.0`, `. --mdns` never run the agent).

**Evidence.** `launcher/test/unit/opencode-argv.test.ts` (the rule),
`launcher/test/unit/agent-versions.test.ts` (`MANDU_OPENCODE2`, both states), and
`launcher/test/component/opencode-v2-standalone.test.ts` through the real
CLI entry: stand-ins for every allowed and refused shape (refused ones never
run the agent), and, against the real binary (`MANDU_OPENCODE_V2_BIN` or
`opencode2` on `PATH`, else a SKIP with the reason), a launch with no
service running (the turn reaches the routing with the session header, no
`service.json` is written), then a user service started outside Mandu on a
reserved port and pointed at a "vendor" upstream: a plain `opencode run`
outside Mandu joins it (control), while the same run through `mandu` sends
every request to the routing with the session header and none to the
service's endpoint, leaves the service's registration untouched, and
leaves no process behind; the refused shapes (`service stop|restart`,
`serve --service`, `run --server <the service>`, `api`) never reach the
binary. OpenCode 1's rule: the same unit file, and an OpenCode 1.18.13
stand-in in the same component file (the TUI and `run` reach it unchanged
and routed; `serve`, `web`, `attach`, `run --attach`, `auth`, `providers`,
`acp`, `export`, `db` and `--print-logs serve` never run it).

**Nested invocations (a SECURITY finding).** The argv rule covers the
launch, not an `opencode run` the agent starts in its own shell. Measured
on 2.0.23 with a user service started outside Mandu, through the launcher in
mode `secrets`:

- with the kernel layer on (Linux: landlock-net and the net guard, both on
  by default), the nested run cannot reach the service: both admit only
  Mandu's own loopback ports, so its connect to the service port is refused
  in-kernel; it then tries to start a service of its own and its bind is
  refused too. Nothing reached the service's endpoint. (The service's
  persistent terminals also have a Unix socket, `opencode-pty`; a connect
  to it meets the Unix socket allow-list, which refuses a socket that is
  not on the list and whose listener is not the agent's tree. Read from the
  binary and the allow-list's rule, not measured.)
- with the kernel layer off (`MANDU_NO_KERNEL=1`, `--no-net-guard` with
  `--no-landlock-net`, or a host where both degrade), the nested run JOINS
  the user's service: both of its requests went to the service's endpoint
  without the session header, and the service runs its tools outside every
  confinement, on the real files. That is a model call around the proxy and
  a path around the secret twins, open to any agent Mandu runs, not only to
  OpenCode 2. It is the same class as the host services on Unix sockets
  (systemd, D-Bus, docker) the allow-list refuses, reached over loopback TCP.
- No environment variable forces `--standalone` in 2.0.23 (every
  `OPENCODE_*` name in the binary was read): the only switches are the flag,
  `--server`, and `disabled` in the service configuration file under
  `$XDG_CONFIG_HOME`. Pointing the agent's `XDG_STATE_HOME` at a private
  folder would hide the user's registration but make a nested run start
  its own service daemon, and it moves every program's state folder;
  pointing `XDG_CONFIG_HOME` at one with `disabled: true` hides the user's
  whole configuration. Neither is cheap and safe, so neither is built: with
  the kernel layer off, the residual stands (noted for guarantees).

**Under the kernel layer: BUILT (2026-10-05).** Before, OpenCode 2 could
not run under the default Linux kernel layer at all: landlock-net refused
the private server's bind of `127.0.0.1:0`, and with the net guard alone
the client's connect to its server's ephemeral port was refused (measured
in a real `secrets` session and under `mandu-net-guard` directly). The
port is hard-coded (`--port 0`), so no `--landlock-net-bind` /
`--net-allow` pair can name it in advance, unlike OpenCode 1's TUI
(differential-interactive.md §13.2), and a rule admitting every process of
the tree would hand the server's API to the agent's commands (below). Now
the guard does both legs itself, for the client only (exec-routing.md §7.5
"The agent's own private server"; net-supervisor `own_server.rs`): an
OpenCode 2 launch names its executable (`MANDU_NET_GUARD_OWN_SERVER`, set
by `run.ts` / `net-guard-setup.ts`); the guard performs the server's
ephemeral loopback bind (the server: a direct child of the client on the
same executable) outside the port wrap, and admits a TCP connect to that
port only from the client (the first-started process of the executable)
and only while every holder of the listener is that server. No process
but the client may trace it or touch its memory, and `pidfd_getfd` is
refused for the whole tree. landlock-net itself is not widened. Proved
with the real 2.0.23 binary under the real guard and landlock-net wrap
(`tests/sandbox/guard/opencode2-own-server.test.ts`, kind `sandbox`; it SKIPs
without the binary): `mandu opencode` in mode `off` (the product path) and
a `secrets` session (a `--target shell` session whose agent runs OpenCode
2, the allowance named by the test; the product path in `secrets` is
`integration.replay-opencode2`, item 5) each run a model turn and a `shell` tool call through the
routing, while that tool's command finds the server's port and is refused
a connect to it (EACCES), and to a listener outside the tree standing in
for the user's service; a nested `opencode run --standalone` (its server
cannot bind) and `opencode run --server <that service>` fail with no model
request, and nothing outlives the launch. Without the allowance the
private server cannot start (the control). Kernel test:
`interceptors/net-supervisor/tests/own_server_integration.rs`. The
launcher component test (`opencode-v2-standalone.test.ts`) still runs with
the kernel layer off, since it pins the argv and the routing.

**The agent is the server (2026-10-05).** Under OpenCode 2 the process that
holds every tool call's output, makes the model calls and spawns each
`shell` call's command is the private server, not the first-started
client, while the guard's agent identity (confidentiality-plan-13 D2: never
made a holder by what reaches it; D7: an exec by the agent's own child is a
tool call's root; §4.5.1: the agent's own receipts are agent flows) keyed on
the client. Measured on 2.0.23 in a `secrets` session (the real launcher,
guard and model proxy; a `shell` call running a pinned reader of a labelled
file, whose output is secret):

- no secret reached the model: the result came back as a symbol. Nothing
  found lets a secret reach the model unmasked or leave the machine: an
  unbound call is masked at the session's level (plan 13 D7's fail-closed
  fallback), and a server made a holder loses its new connections;
- utility: the call was NOT bound (the shell's parent is the server, so no
  call root): "Mandu could not tie this shell call to the processes that ran
  it", every later `shell` result masked whole while the session holds any
  raw read; and the reader's output made the SERVER a secret holder (a
  socket pair flow), so once its keep-alive to the model proxy lapsed its
  next model connection was refused and the turn stopped (a 7 s pause in
  the call: no follow-up request). The same would follow from the server's
  own connection to a holder (`webfetch` of a local server that read a
  secret).

Now, when the launch names the private server (the same executable as the
agent's), the guard's agent is the client AND its own server
(`own_server::agent_with_own_servers`, looked up live as the client's
child; `guard_flow::agent_keys`): the server's `shell` children are call
roots, the server is never made a holder by a pipe or socket pair, and its
own receipts are agent flows, exactly D2's terms for Claude Code's single
process. Its own opens already counted as the agent's (by executable: the
twin, never raw). After the change, the same session: the call is bound
(masked from the call's own tree, "mdu-holder read …"), no request carries
the canary, and the follow-up after the 7 s pause goes through. Like Claude
Code's transcripts, the server keeps the raw tool output in its own session
store (`$XDG_DATA_HOME/opencode`); a program that reads it back meets the
value backstop of the model exit, as for any agent. Tests:
`own_server.rs` units (`agent_with_own_servers`), the kernel test
`own_server_integration.rs` (a server's child's exec is a call root, a
grandchild's is not, a pipe from a holder does not taint the server; the
allowance off, the opposite), and
`tests/sandbox/guard/opencode2-agent-identity.test.ts` (the session above).

**Confidentiality ON: allowed under three conditions (2026-10-05).** The
SECURITY finding that first refused it: measured
on 2.0.23 (kernel layer off, scripted upstream, no Mandu): the agent's
`shell` tool runs as a child of the private server, a loopback HTTP server
whose password is in that server's environment, readable by its children
through `/proc`, and the session id is in the tool's own environment
(`OPENCODE_SESSION_ID`). A command can therefore call the server's
`POST /api/session/<id>/shell` (also `/synthetic`, `/prompt`, `/api/shell`):
a `cat` of a file there reached the next model request as a USER text
block, "The following shell command was executed by the user: `<shell
id=… command=…>`…`</shell>`", with no tool_result carrying it, so no
tool-result check (path labels, callTaint, the inbound spec) reads it.
Second, a command moved to the background streams its output to
`$XDG_DATA_HOME/opencode/shell/<40-hex hash>/sh_<id>.out` (verified on
2.0.23), and the "moved" tool_result names that path and invites the model
to read it: an agent-written file no label covers. The first is closed
by the kernel layer since the allowance above: the agent's commands cannot
connect to the server's port (measured, both modes). It stayed open where
the kernel layer is off (`--no-kernel`, or a host where the guard
degrades), until the proxy read those `<shell …>` user texts as the
tool's output. The second needed a `no-model` label on that folder, which
no arbiter operation offered then (`setPathLabel` is the human's
persistent act and the launcher must not write it). Both are closed now:
the first by the guard's allowance (above) and by the proxy reading those user texts as tool output (item 9), the second by
OpenCode's data directory being a persistent `no-model` location (the
secret catalog; item 7's session label stays as a second layer). What is
left depends on mechanisms a launch can lack, so `run.ts` allows a
confidentiality-ON launch (`secrets`, and the frozen modes) only while all
three are in force (`launcher/src/opencode2-confidentiality.ts`):

1. **The kernel-layer connect guard with the private-server allowance**
   (seccomp user notification, Linux only): refused when the launch turned
   it off (`--no-net-guard`, `--no-kernel`, `--portable`,
   `MANDU_NO_KERNEL`), when `mandu-net-guard` is not built, when the
   launcher cannot name the executable for the allowance, or when this
   kernel gives the guard no listener (`probeGuardNotify` runs the guard
   bin around `true` without `--skip-unsupported`: a few ms). The guard's
   wrap then runs WITHOUT `--skip-unsupported` (`plan.netGuardRequired`,
   `net-guard.ts` `planNetGuard`), so a guard that cannot start on the day
   fails the launch (exit 71) rather than running the agent unguarded.
2. **The whole-agent write-protect guard**, which keeps the agent out of
   the launcher's OpenCode config directory (item 8's residual):
   `MANDU_WRITE_PROTECT=0` is refused.
3. **The config lockdown** (item 8): `OPENCODE_CONFIG_DIR` at the
   launcher's directory, no project layer, no file watcher, in the
   environment the agent starts with.

Two checks, both before the agent exists, both one plain line naming each
missing protection and its fix, with the ways out (`--mode off`, or OpenCode
1): `opencode2ConfidentialityMissing` right after the effective axes are
known, before any service or event, from the flags, the platform, the guard
bin and the probe; and `opencode2ConfidentialityUnenforced` on the composed
launch (the guard wrap without the degrade, the allowance naming the
executable, the config directory a `deny` entry in the guard's
write-protect list, the lockdown keys in the agent's environment), which
catches a step that degraded on the way. These three conditions, checked
live on a real model (§2), are what let OpenCode 2 become a default-supported
agent (2026-10-05): where one is missing the launch is refused, never run
unguarded. Tests: `launcher/test/unit/opencode2-confidentiality.test.ts` (the
rule, the enactment check, the message, the probe),
`launcher/test/unit/net-guard.test.ts` (the required wrap), the stand-in
case in `launcher/test/component/opencode-v2-standalone.test.ts` (through
`main()`: each missing protection refused by name, the agent never run; a
stand-in guard bin for the probe), and the e2e of item 5
(`integration.replay-opencode2`).

**Also built:** a `mandu doctor` row for OpenCode (`opencode`, else
`opencode2`): OpenCode 1 and 2 read like every agent's version row, each
against its own tested range (§2), and OpenCode 2's adds what its launches
get (a private server; `secrets` only with the guards); OpenCode 2 under
`MANDU_OPENCODE2=0`, an unreadable version or another major says that
`mandu opencode` refuses it. The doctor's probe gives
OpenCode throwaway XDG folders, since even `--version` makes its folders
and a log (`probeAgentVersionLooking`). Tests:
`launcher/test/unit/doctor-versions.test.ts`.

### 2.4 Claude Code's bash mode: program output, not the human's text

**Status: BUILT (2026-10-05).** In Claude Code's TUI the human can run a
command with `!cmd`. Claude Code runs it with its own Bash tool and, unless
`respondToBashCommands` is off, sends the next request with two text blocks
in the user message (captured on 2.1.289 by driving the real TUI in a PTY
against a scripted upstream, no API spend;
`tests/fixtures/claude-bashmode-2026-10-05.json`):

    <bash-input>{the command, unescaped}</bash-input>\n
    <bash-stdout>{stdout}</bash-stdout><bash-stderr>{stderr}</bash-stderr>

The output is escaped (`&`, `<`, `>`; quotes are not), the final newline is
trimmed, and the Bash tool folds stderr into stdout; a failure is
`<bash-stderr>Command failed: …</bash-stderr>` alone, and a large output is
a raw `<persisted-output>` preview inside `<bash-stdout>` (read from the
binary). Every later request re-sends both blocks unchanged; only
`cache_control` moves to the newest block.

Until this change the prompt filter tagged both blocks harness, and only
the registered-value filter and the pattern packs read them: no path label
from the command, no callTaint. So a `!cat` of a labelled file whose values
Mandu had never registered (nothing had read it) reached the model raw.

**The fix** (`interceptors/anthropic-proxy/src/opencode-background.ts`, kind
`bashmode`, applied by `rewriteRequest` in a Claude Code session and in one
with no table of its own). The output block is PROGRAM OUTPUT. It becomes,
for the rewrite, a stand-in `Bash` result of the command in the
`<bash-input>` block right before it, on the UNESCAPED text:

- the classify verdict's path label from the command;
- callTaint by the command's exec signature (no model call started it);
- the value backstop and the inbound spec.

A masked output goes back as `<bash-stdout>{the symbol and its note,
escaped}</bash-stdout><bash-stderr></bash-stderr>`. An output forwarded
unchanged goes back byte for byte, and a masked one is the same in every
later request, so the prompt cache holds. Masked whole: an output block
with no `<bash-input>` block right before it, a persisted-output preview,
escaping that does not round-trip, any other form. The `<bash-input>` block
(the human's own command) and the human's typed prompt stay the prompt
filter's, as before.

The human still sees the real output: Claude Code renders it in the
terminal from its own run, before any model request, and the reply filter
only turns a symbol the model quotes back into the original.

Tests: `interceptors/anthropic-proxy/test/unit/claude-bashmode.test.ts`
(parsing, round trips, the unparsed forms, the rewrite) and
`tests/stack/claude-bashmode-output.test.ts` (`secrets` mode, the real
arbiter: a `!cat` of a labelled, never-registered file reaches the model
only as a symbol; an unlabelled file's output goes out byte for byte; a
masked block re-sent forwards the same; the captured request replayed; an
unreachable arbiter fails closed).

**Codex's user shell, the same class (BUILT 2026-10-05).** In Codex's TUI
`!cmd` runs a command too; it makes no request of its own and rides with
the next prompt as a user message item of its own (captured on codex-cli
0.160.0: the real TUI driven in a PTY with `--no-daemon`, a hermetic
CODEX_HOME whose custom provider points at a scripted Responses upstream, no
API spend; `tests/fixtures/codex-user-shell-2026-10-05.json`):

    <user_shell_command>\n<command>\n{command}\n</command>\n<result>\n
    Exit code: N\nDuration: S seconds\nOutput:\n{output}\n</result>\n</user_shell_command>

Nothing is escaped (a `</user_shell_command>` in the output appears as it
is), and every later request re-sends the item unchanged. Until this change
it was a harness segment of the prompt filter (plan 15 §3.1), read by the
registered-value filter only. Now the openai-proxy
(`interceptors/openai-proxy/src/user-shell.ts`, for a Codex request) reads
each record as a stand-in `function_call_output` of `exec_command{cmd}`,
inserted before its message for the rewrite while the record's own text
part is emptied (the prompt filter still reads the message's other parts):
the path label from the command, callTaint by the command's exec signature,
the value backstop and the inbound spec. The command runs to the first
`\n</command>\n<result>\n`, which the strict `Exit code` / `Duration` /
`Output:` head must follow (a command holding that sequence is cut early,
and the rest is read as output). The output goes back between the record's
own head and tail: byte for byte when unchanged, the symbol and its note
when masked, the same in every later request. A record that does not parse
is masked whole. The Chat Completions route writes the record back by its
part index, which the rewrite keeps. Tests:
`interceptors/openai-proxy/test/unit/user-shell.test.ts` and
`tests/stack/codex-user-shell-output.test.ts` (`secrets` mode, the real
arbiter: a labelled, never-registered file masked; an unlabelled one byte
for byte; a masked record re-sent the same; the capture replayed; an
unreachable arbiter fails closed).

### 2.5 Claude Code's settings files cannot re-point its model traffic (2026-10-07)

Mandu routes Claude Code by its environment (`ANTHROPIC_BASE_URL` at the
model proxy, the session header, the egress proxy variables). Claude Code
applies the `env` block of every settings source OVER that environment,
and applies it again when a settings file changes during the session.
Measured on Claude Code 2.1.290 against two local stand-in models: each of
these sent the turn to the other model, around the proxy, so tool results
reached it unmasked:

- `env.ANTHROPIC_BASE_URL` in `~/.claude/settings.json` (or the
  `CLAUDE_CONFIG_DIR` one), `.claude/settings.json`,
  `.claude/settings.local.json`, the global `~/.claude.json`, or a
  `--settings` file;
- the same written into `.claude/settings.local.json` by the agent's own
  Bash in the middle of a session: the next request, the one carrying that
  command's result, went to the new URL;
- `env.CLAUDE_CODE_USE_BEDROCK` (and the other cloud provider switches)
  with its base URL: the prompt went to the "Bedrock" endpoint;
- `env.HTTP_PROXY`, `http_proxy` or `ALL_PROXY` with `NO_PROXY` cleared:
  the request to the model proxy itself went through another proxy, raw.

A `remote-settings.json` the account is not entitled to was ignored,
`--managed-settings` did not apply `env` at all, and Claude Code never
takes `ANTHROPIC_UNIX_SOCKET` from a settings file.

**The fix** (`launcher/src/claude-route.ts`). Settings sources merge in a
fixed order, user < project < local < `--settings` < managed, and Claude
Code reads only the last `--settings` on its command line. The launch puts
its routing in that last `--settings` (merged into the run's own inline
one, never a second one): every routing variable (`ANTHROPIC_BASE_URL`,
`ANTHROPIC_CUSTOM_HEADERS`, `CLAUDE_CODE_API_BASE_URL`, the six
`HTTP(S)_PROXY` / `NO_PROXY` spellings, `ALL_PROXY` / `all_proxy`) with
the value the agent is launched with, or empty where it has none, and every
cloud provider switch set to `0`. Every lower source is then overridden,
at launch and at every re-apply: the agent's mid-session write stayed on
the proxy (measured, and the e2e below). What that `--settings` cannot
outrank is refused before the agent starts, naming the cause:

- a managed source (the managed file and its drop-ins, the server-managed
  cache, macOS MDM) that sets a routing variable to another value, or one
  Mandu cannot read;
- the run's own `--settings` given as a FILE: Claude Code would read it
  instead of Mandu's, and Mandu does not copy a settings file onto the
  command line, where every program the agent runs can read it. Pass the
  settings inline or put them in `.claude/settings.local.json`;
- a `--managed-settings` that sets a routing variable (not applied by
  2.1.290; a later version might);
- a cloud provider switch (`CLAUDE_CODE_USE_BEDROCK`, `_VERTEX`,
  `_FOUNDRY`, `_ANTHROPIC_AWS`, `_ANTHROPIC_GOOGLE_CLOUD`, `_MANTLE`) or
  `ANTHROPIC_UNIX_SOCKET` in the launch environment: Claude Code would talk
  to that provider or socket directly, on a wire the model proxy does not
  read. Before this change such a launch ran with no masking at all.

A user, project, local or global file that sets one of the variables gets
one launch line naming it: under Mandu it no longer applies. A user who
wants their own model endpoint sets `ANTHROPIC_BASE_URL` in the
environment and declares it under `models:`, as before (guarantees.md, "A
main model you point the AI at yourself").

`apiKeyHelper` and the other credential helpers change the key Claude Code
sends, never where it sends it: the request still goes to the proxy, so
they are left alone. An `ANTHROPIC_API_KEY` in the launch environment is
masked in Claude Code's environment since 2026-10-11 and put back in
`x-api-key` by the proxy, when the launch can bind it to the anthropic
upstream ([`agent-sign-in.md`](./agent-sign-in.md) §3.8). The SDK route's preload applies the same overlay to
every `claude` a host program starts, the SDK's own `settings` option
included, built from the launch's values alone (never from the
environment the host hands the child, 2026-10-18), and refuses a
`settings` given as a file path (agent-sdks.md §3, §4).

*A `claude` started inside the session (2026-10-18; a leak until then).*
The overlay above rode only the command line of the `claude` Mandu
launches. A `claude` started by name from inside a session (the shell of
`mandu -- bash`, a script, the agent's own Bash tool under `mandu claude`)
got the launch's environment and nothing else, so a user `settings.json`
naming a gateway, a `.claude/settings.local.json` the agent wrote, or an
`ANTHROPIC_BASE_URL=…` on its command line sent its requests around the
proxy, with what it read (still so on 2.1.302: Claude Code assigns each
settings source's `env` to its process environment and reads the base URL
from there; project settings may set it). No outer layer stopped that dial
(until 2026-10-18): the connect guard admitted the model host on :443 for
the whole agent tree, and the egress proxy passed a model host through,
judging only the sender's taint. Measured with the real 2.1.302 against a scripted model:
an unlabelled log holding a registered value reached the model raw. Every
claude or shell launch the SDK route does not serve now puts a `claude`
shim first on the agent's PATH (agent-sdks.md §3.5) that applies this
section to that `claude`: the launch's routing variables put back in its
environment and imposed in its last `--settings`, a `--settings` file, a
cloud provider switch or `ANTHROPIC_UNIX_SOCKET` refused, and the
permission-mode rule (§2.0's "A `claude` the session starts by name").

A `claude` the session starts by its full path, or with a PATH that skips
the shim, keeps only its environment's routing, which its caller can
change (agent-sdks.md §3.5); since 2026-10-18 the transport refuses its
model calls (the model-host deny, agent-sdks.md §4: a 403 at the egress
proxy, a refused connect at the guard; where it does not hold, the posture
matrix there says). Not covered: a server-managed
`remote-settings.json` that an entitled organization's account would honor,
written by the agent during the session (Mandu reads it at launch only).

Tests: `launcher/test/unit/claude-route.test.ts` (the overlay, its place
on the command line, the refusals, the layers read),
`launcher/test/unit/sdk-route.test.ts` (the preload's copy and its parity),
`claude-settings-route.test.ts`
(`integration.claude-settings-route`: the real launcher and `claude -p`
against a scripted model whose port the user allowed, so a direct dial
would reach it; a user settings file and a mid-session
`.claude/settings.local.json` keep a labelled file a symbol, a nested
`claude -p` the agent's Bash starts under the same user settings keeps a
registered value in an unlabelled log a symbol, the Bedrock and
`--settings` file launches are refused with no model request, and a
no-Mandu control hands the model the raw bytes), the settings-bypass
scenario of `agent-sdk.test.ts`, and `tests/stack/nested-claude-route.test.ts`
(a stand-in `claude` that resolves its base URL as Claude Code does, under
`mandu -- sh` and nested under `mandu claude`, through the real model proxy:
a user settings file, a `.claude/settings.local.json` the agent writes, an
`ANTHROPIC_BASE_URL=…` with `NO_PROXY` emptied and another
`CLAUDE_CONFIG_DIR` all stay on the proxy with the labelled `.env` and the
log's registered value symbols; a `--settings` file and a Bedrock switch
refused; red before the shim routed).

## 3. The check

- **Parsing** (`parseAgentVersion`): the first `X.Y.Z` in the `--version`
  output (`2.1.281 (Claude Code)`, `codex-cli 0.154.0`,
  `OpenClaw 2026.3.12 (a712433)`). A numeric-only suffix (`2026.7.1-2`) is a
  packaging revision and ignored; a suffix with a letter is a prerelease and
  sorts below its release. Anything else is "unknown".
- **Verdicts**: `tested` (inside, inclusive), `newer`, `older`, `unknown`.
- **Launch** (`run.ts` → `launchVersionCheck`): runs `<agent> --version` with a
  10-second budget stretched by the load per CPU, at most 60 s
  (`versionProbeTimeoutMs`; it was 3 s until 2026-10-07, which a loaded CI
  guest's OpenCode 1 missed, and the OpenCode refusal now says why the probe
  gave nothing: `timed out after … ms`, `exit <n>: …`), only when argv[0] really is the target's binary (a wrapper
  launched with `--target claude` is not run with a flag it may not know;
  agent-login.ts uses the same rule) and not for a `--version` launch. Outside
  the range: ONE `mandu: WARNING — …` line, a notice the default display
  counts on its banner line (`compactNotice` knows it; the launch's log and
  `--verbose` carry it in full, packaging.md §5). **A warning, never a refusal**: the fail-closed spec
  still holds and a probe can be wrong. The one exception is OpenCode (§2.3):
  a major version other than 1 and 2, an `opencode2` that is not major 2,
  an unreadable version, and major 2 under `MANDU_OPENCODE2=0` are refused,
  because there the version decides whether the model traffic goes through
  the proxy at all (major 2 launches only with its argv rewritten, §2.3.1).
  For OpenCode the probe runs before the model check, so a refused launch
  starts nothing. A version is judged against its generation's range (§2,
  `testedRangeOf`). The check rides on the `launch_posture` event as
  `agentVersion`.
- **Doctor**: one row per installed agent: ✓ tested, ✗ newer / older with what
  it costs, · when the version could not be read. OpenCode's row (2026-10-05)
  also says whether `mandu opencode` refuses it, and for OpenCode 2 what its
  launches get or that `MANDU_OPENCODE2=0` turned it off (§2.3.1). Goose's
  row (2026-10-06) is a plain version row: its routing is decided by its
  provider check (§5.6), not by its version. A preview agent's row (Goose,
  OpenCode 1 and 2) ends with "a preview" (§2.0).
- **Dashboard** (`session-health.ts`): the version is the proxy's `client_info`
  (Claude Code's user-agent: what the agent said on the wire) when present,
  else the launcher's probe (Codex, OpenClaw, OpenCode, Goose have no `client_info`).
  The verdict is re-derived from the dashboard's own table, never trusted off
  the event. Newer / older degrades the health chip with a reason; unknown is
  a note only.
- **Product page** (`view-model/home.ts` `agentNotice`; a preview agent's
  tag is `agentPreview`, §2.0): one plain sentence
  when the version is outside the range, or, in range, when the agent
  advertised tools Mandu does not know. Worded for the running level: "their
  output is masked in full" only when untrusted content is masked
  (`injection`, `full`). The row shows only a warning mark by the agent's name
  (`home.js` `agentNoticeMark`, the "?" help's button and note) and the
  sentence opens under the mark on a click or Enter, so the row stays one
  line (2026-10-05). The agent's page draws the same mark by its name, after
  a preview tag, with the same sentence (`AgentPageVM.notice`, 2026-10-09;
  until then only the row did, dashboard.md §4.21).

## 4. Not done

- No `--require-tested-agent` refusal flag. The fail-closed spec makes a
  refusal a utility choice, not a safety one (an unreadable or unknown
  OpenCode major, §2.3, is refused because its routing cannot be chosen, not
  because it is untested).
- OpenCode 2 (§2.3) is supported by default, in `secrets` only with its
  guards in force (§2.3.1); the live check, the tested range and the watch
  runner's OpenCode 2 profile (`OPENCODE2_WATCH_PROFILE`)
  are done, and since 2026-10-06 so are the drill tooling's: the recorder
  reads 2.x's tool spelling (`integration.drill-record-opencode`, nightly),
  the whole catalog replays on 2.x nightly (`integration.replay.opencode2`),
  and the `opencode-e2e` harness ran on 2.x per push
  (`integration.opencode2-e2e`, §2.3.1) until its drills' per-push replay
  (`integration.replay-opencode2`) took its place on 2026-10-18. Left: a one-shot `opencode2 run`
  sends its first requests before its MCP servers have started (2.0.23), so
  the inspect tool is offered only seconds into a run; the TUI, which waits
  for a typed prompt, is not affected.
- Codex (0.162) builds a turn's tool catalog after a shared 1 s grace for
  optional MCP servers (`mcp_optional_startup_grace_ms`) and leaves out a
  server still starting, so a `codex exec` whose Mandu server starts later
  than that runs its first turn without the policy or inspect tools. The
  launcher's bundled servers start well within the grace (24 of 24 runs on
  two loaded CPUs, 2026-10-11), and the launcher does not mark them
  `required`: that would make Codex refuse to start when one fails. The
  servers run from source through tsx (the replay suites) took longer on a
  loaded CI guest, so `integration.codex-policy-tools` marks mandu-policy
  `required` with a 120 s startup timeout.
- The ranges are hand-maintained. The live `tool_surface` event is the signal
  that a new release needs mapping; nothing raises a range automatically.
- OpenClaw's per-SESSION exec host: a user's `/exec host=node` directive is
  stored in OpenClaw's session store and outranks the configured host, so a
  session resumed under Mandu after such a directive sends each `exec` that
  names no host to the paired device. The launcher fences the configured
  host (§2.1) but does not rewrite OpenClaw's session store. Closing it needs
  either a read of the store at launch or a refusal of `node` targets at the
  gateway boundary.
- Non-Anthropic models: OpenClaw's built-in `openai` provider, an OpenClaw
  `models.providers.<id>` with `api: "openai-completions"` or
  `"openai-responses"` and a `baseUrl`, OpenCode's built-in `openai` and an
  OpenCode provider on `@ai-sdk/openai` or `@ai-sdk/openai-compatible` with
  a base URL, and Goose's built-in `openai` provider (§5.6, "The openai
  provider") are ROUTED through the model proxy (agent-e2e-harness.md §9,
  "Other providers through the model proxy"), with the same gates and the
  same text-delta token repacking as the Messages wire (a `$MDU:` token
  split across two deltas reaches the agent whole). Every other provider
  (Google, Bedrock, Mistral's own SDK, a catalog provider the user has not
  declared, OpenAI through a ChatGPT sign-in) is refused at launch; each
  needs its own wire reader in the proxy. Separately, the Codex openai-proxy
  reads Chat Completions too (its `/chat/completions` route), for agents not
  yet supported (Kimi Code, the OpenHands CLI; §5.5). OpenClaw and OpenCode
  stay on the model-proxy route above, where their gate-surface tables live.

## 5. Agent reach: which agents Mandu can defend

Which agents Mandu can defend, per enforcement layer, and which to support
next. Companion to
[`architecture-map.md §9`](../architecture/architecture-map.md)
(whose "use-case space" this expands) and
[`architecture-map.md`](../architecture/architecture-map.md) (the grid the
layers come from). Per-agent facts were read from each agent's source or
docs (July 2026); the OpenClaw and OpenCode facts were re-established by
driving each agent at a local endpoint and reading the captured request
([`agent-e2e-harness.md`](../testing/agent-e2e-harness.md) §2).

### 5.1 The defendability test

An agent is defendable exactly to the degree these four hold. (a) to (c)
decide the **context** chokepoint (the decisive axis); (d) decides how much
of the **action** side (fs · exec · net) the cooperative wrapper can see:

| # | Question | Why it matters |
|---|---|---|
| a | Is the LLM call made **locally** (a process on the user's machine)? | if server-side, the context layer never sees it: the invariant is unenforceable at any layer |
| b | Is the model endpoint **overridable** (base-URL env or config)? | env override = zero-touch; config override = a config splice (the Codex pattern); neither = MITM territory |
| c | Is the **wire format parseable** with an adapter we have? | Anthropic Messages, OpenAI Responses and OpenAI Chat Completions are read (the last by the openai-proxy's `/chat/completions` route); Google GenAI would be a build; LiteLLM-mediated agents emit one of the above |
| d | Do **tools execute as host subprocesses** (inherit env/PATH/CWD)? | subprocesses ⇒ shims + proxy env + CWD-scoping work; in-process tool calls ⇒ only the kernel layer sees them; agent-managed containers ⇒ inject into the container or gate its boundary |

### 5.2 Per-agent studies

OpenClaw and OpenCode are defended and tested: both have live e2e suites
(`openclaw-e2e`, `opencode-e2e`) proving the
[implementation-plan.md](../architecture/implementation-plan.md) §9
invariant end to end, and both speak genuine Anthropic Messages, so both
reuse the existing anthropic-proxy with no new wire adapter.

#### 5.2.1 OpenClaw: the reference host, as an OS target

Node gateway daemon (multi-channel: Telegram / WhatsApp / Discord / Slack /
Signal / iMessage…), agent loop embedded in-process (`pi-embedded-runner` over
`@mariozechner/pi-ai`, which wraps the official Anthropic/OpenAI/Google/Mistral/
Bedrock SDKs).

- **(a) local**: model calls happen inside the gateway process. There is a
  one-shot mode: `openclaw agent --local --agent main --session-id <id> -m
  '<prompt>' --json` runs a single embedded turn. `--local` is mandatory
  (without it the CLI tries the gateway first and only *falls back* to
  embedded, nondeterministic for a harness). This makes OpenClaw testable
  like `claude -p`.
- **(b) config, effectively env-drivable**: the SDK `baseURL` comes from
  provider `baseUrl` in `openclaw.json` (`models.providers.<id>.baseUrl`),
  projected into `<stateDir>/agents/<id>/agent/models.json`. There is no
  `ANTHROPIC_BASE_URL`-style env path, so it is a **config splice** (the
  Codex pattern), but `${VAR}` substitution applies to every string value
  at config load, and `OPENCLAW_HOME` / `OPENCLAW_STATE_DIR` /
  `OPENCLAW_CONFIG_PATH` redirect the whole state dir. Arbitrary custom
  **headers** also work (`models.providers.<id>.headers`; values need
  `${VAR}`, not a bare env-var name). The SDKs honor `HTTPS_PROXY` (global
  undici `EnvHttpProxyAgent`, installed at agent-run bootstrap), so the
  net-proxy also sees model traffic if ever needed.
- **No MCP client** (the ACP bridge explicitly rejects `mcpServers`), so the
  U-LLM `inspect_symbol` channel ships as a plugin-registered tool
  (`interceptors/openclaw-inspect-plugin/`). This is the one capability gap
  versus every other supported agent.
- **(c) reuse**: vendor-SDK wire = Anthropic Messages / OpenAI → existing
  proxies.
- **(d) split**: `exec` spawns real subprocesses that inherit the gateway's
  `process.env`/`PATH` (shims apply; PTY mode via node-pty). `exec` defaults
  to `host: "sandbox"` + `security: "deny"`, so a host-side harness must set
  `host: "gateway"` + `security: "full"` or the shell tool silently never
  runs. File tools are **direct in-process `fs` calls**. The one-shot path
  has a CWD lever: the embedded runner does `process.chdir(effectiveWorkspace)`
  per run, from `agents.defaults.workspace` (§2.1 "The workspace"). The
  long-lived *daemon* serving many sessions has none; the kernel layer
  (`fs-supervisor` traps the gateway's own `openat`) covers it. Web/fetch
  honors proxy env only in `TRUSTED_ENV_PROXY` mode, and a DNS-pinning SSRF
  guard resists transparent MITM: use the env-proxy path.
- **Unique: the in-process (layer-1) chokepoint is native.** The DualView
  reference plugin (`plugin/dualview/` in the DualView repository) hooks
  `transform_tool_result` (the sole symbolization point, before the result
  enters the LLM context), `before_tool_call` (symbol resolution + exec
  enforcement), `message_sending` (egress), `transform_webhook_content`
  (channel ingress), gated on `plugins.allowResultModification: true`.
  OpenClaw is therefore the one agent where the context chokepoint can sit
  *inside* the process, with Mandu adding the OS action layers around it, or
  the OS proxy can replace the plugin for a cooperation-free setup.
- **Posture.** Wrapper: context 🟢 (config splice or native plugin), exec 🟢
  (shims), net 🟢 (env proxy), fs 🟡 (in-process file tools; the context
  backstop and the kernel layer cover it). MicroVM: viable but the gateway
  is a human-facing daemon, so usually the *trusted-agent* columns apply.
  Extra surface to model: multi-channel **message ingress** is untrusted
  input (the plugin's webhook hook is the existing answer).

#### 5.2.2 Hermes (Nous Research): architecturally a Claude Code twin

Python agent; TUI (`hermes`) + messaging gateway (`hermes gateway`) + ACP
entry, all instantiating the agent loop in the local process.

- **(a) local**: no vendor-hosted control plane.
- **(b) env and config**: `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`,
  `OPENROUTER_BASE_URL`, … plus `model.base_url` in `~/.hermes/config.yaml`;
  `HTTP(S)_PROXY`/`NO_PROXY` respected. A later source read found the
  config outranks the env, so routing is a config splice, and its Anthropic
  base URL must end in `/anthropic`.
- **(c) reuse**: three native API modes (`anthropic`, `chat_compl.`,
  `codex_resp.`) = Anthropic Messages + OpenAI Chat Completions + OpenAI
  Responses.
- **(d) host subprocesses by default**: 70+ tools dispatch in-process, but the
  terminal tool's default backend is `local` (direct host execution; Docker/
  SSH/Modal optional) → PATH shims + proxy env + CWD apply. `HERMES_WRITE_SAFE_ROOT`
  already scopes file writes, a natural AgentView mount point.
- **Posture.** Wrapper: 🟢 full, essentially the Claude Code recipe (base-URL
  routing + env proxy + shims). Kernel/microVM: standard. Like OpenClaw,
  gateway mode adds untrusted **channel ingress** to model.

#### 5.2.3 OpenHands: two agents in one product

The conversation loop runs either fully in a host process or fully inside an
agent-server container.

- **CLI / headless** (`openhands`, no Docker): LLM calls (a: local) go through
  LiteLLM: `[llm] base_url` in `config.toml` or `LLM_BASE_URL` env (b: yes);
  wire is LiteLLM-emitted OpenAI Chat Completions / Responses or Anthropic
  Messages (c: reuse). Tools run as host subprocesses + direct file edits
  (d: yes). **Wrapper-defendable like Aider**: point `base_url` at the proxy,
  shims/CWD/net-proxy apply. The CLI is no longer maintained upstream.
- **GUI** (`openhands serve`, Docker): the app spawns an agent-server container
  and the **LLM call + all tool execution happen inside it**. The `base_url`
  still reaches the container (LLM settings are serialized into the
  conversation config), so the context proxy works if it is reachable from
  in-container (bind on the docker bridge / `host.docker.internal`). Action
  chokepoints: the container *is* the action boundary; treat it like a
  guest: gate its network at the container boundary (the microVM pattern,
  minus the VM), or inject env (`OH_AGENT_SERVER_ENV`, `LLM_*` auto-forward,
  unverified). `HTTP_PROXY` is *not* known to be forwarded.
- **Posture.** CLI: wrapper 🟢 (config/env splice + validation). GUI: 🟡 a
  container-boundary integration: context via in-container base_url,
  actions via container net gating; conceptually a dry run for the microVM
  layer.

#### 5.2.4 Kimi Code CLI / Kimi Work (Moonshot)

- One TS substrate behind three fronts: the **CLI** TUI (macOS/Linux/Windows,
  MIT, github.com/MoonshotAI/kimi-code), a **local daemon/web UI**
  (`daemon.lock` port discovery), and the **Kimi Work** Electron desktop,
  a thin client that attaches to any running daemon, including
  independently started CLI instances. Its features (cron-driven
  unattended runs, 128-subagent swarms, autonomous browsing) are guarded
  only by action-approval prompts with an off switch: maximal IPI exposure.
- (a) local: **yes**. (b) override: `config.toml` per-provider `base_url`
  (redirectable dir via `KIMI_CODE_HOME`), and `KIMI_CODE_BASE_URL` for the
  OAuth-subscription path; a later source read found the current Kimi Code
  no longer reads `KIMI_BASE_URL` from the shell. (c) wire: native =
  **OpenAI Chat Completions** (the `openai` npm client +
  `reasoning_content`), which the openai-proxy reads; config can switch the
  provider to **Anthropic Messages**, and Moonshot serves an Anthropic-compat
  upstream (`api.moonshot.ai/anthropic`, platform-key only). (d) tools:
  **host subprocesses**, plain spawn, no built-in sandbox.
- Symmetry with Claude Code: `KIMI_CODE_CUSTOM_HEADERS` mirrors
  `ANTHROPIC_CUSTOM_HEADERS` (session-id stamping ports as-is); `kimi
  --prompt` mirrors `claude -p` (subscription U-LLM); MCP config is the
  standard `mcpServers` shape via `--mcp-config-file`; tool names are
  Claude-Code-shaped (`Read`/`Bash`/`WebSearch`/`Grep`…), so the inbound spec
  is a fork, not a rewrite.
- **Posture: 🟢 fully defendable, cooperative, zero MITM.** The desktop
  daemon is the last part to wrap.

### 5.3 The wider landscape

A survey of agent CLIs (July 2026) ranked the next candidates by how cheaply
each can be defended; §5.3.4 is its October 2026 refresh, which supersedes
the §5.3.2 order.

#### 5.3.1 Landscape shifts

Gemini CLI is being replaced by Google's Antigravity CLI, whose
defendability is unassessed. Warp keeps its AI loop server-side. A family of
local messaging assistants grew around OpenClaw (zeroclaw, nanoclaw,
picoclaw, HKUDS/nanobot), all OpenClaw-shaped: local process, direct
provider calls, documented base-URL override, host-side tools.

#### 5.3.2 Support-next shortlist

| # | Agent | Why it is cheap | Adapter |
|---|---|---|---|
| 1 | **OpenCode** (SST): SUPPORTED | `opencode.json` `provider.*.options.baseURL`; with `npm: "@ai-sdk/anthropic"` the wire is genuine Anthropic Messages | `opencode-e2e` |
| 2 | **Copilot CLI** (GitHub) | BYOK env (`COPILOT_PROVIDER_BASE_URL/_TYPE/_API_KEY`), localhost documented | reuse, **BYOK sessions only** |
| 3 | **Goose** (Block → Linux Foundation) | cleanest env surface: `ANTHROPIC_HOST` / `OPENAI_HOST` (1.53.0 reads `OPENAI_BASE_URL` too, below an env `OPENAI_HOST`; §5.6) | reuse both |
| 4 | **nanobot** (HKUDS) | messaging ingress (Telegram/Discord/Slack/email), the highest IPI exposure on the list; `providers.*.apiBase`; a shell-less agent | reuse both |
| 5 | **Kilo Code** | custom-provider selector is our three wire formats; the extension runs on the **OpenCode server**, so #1 covers much of it | reuse both |
| 6 | **Pi** (earendil-works) | BYOK-local by design; the exact base-URL knob needs a config-read pass | reuse (confirm) |
| 7 | **browser-use** | the canonical injection surface; zero-code interception via SDK env fallbacks (`OPENAI_BASE_URL`/`ANTHROPIC_BASE_URL`), but a library inside other programs, not one wrappable process | reuse both |
| 8 | **Droid** (Factory) | BYOK `customModels` `baseUrl`; wire = our three formats | reuse, BYOK only |

Kimi Code (§5.2.4) was surveyed after this table was ranked and went
straight to a planned target.

**Batch tier** (same config-file provisioning pattern): Crush (Charm), Qwen
Code (key mode), Mistral Vibe, Zed (settings `api_url`; its ACP external
agents are already-defended CLIs), zeroclaw / picoclaw / nanoclaw (nanoclaw
= `ANTHROPIC_BASE_URL` into a Docker container, the same
container-reachability wrinkle as OpenHands GUI), CodeWhale, UI-TARS/Agent
TARS.

**Undefendable** (server-side loop or no override): Warp (localhost endpoints
explicitly rejected), Devin CLI, Augment/Auggie, Trae IDE, AWS Kiro (proprietary
Smithy stream), Jules / ChatGPT agent / Mariner / Claude Code on the web
(cloud-VM loops).

#### 5.3.3 Conclusion

No new wire-format adapter is required for the shortlist: Anthropic
Messages + OpenAI (Chat Completions and Responses) cover every primary wire;
Google GenAI and Bedrock appear only on optional or unreachable paths. The
binding constraint is **per-agent provisioning** (pointing each agent's
config or env at the proxy, plus its inbound spec and gate-surface table),
which argues for supporting many agents cheaply over a few deeply.

**Watch items:** Antigravity CLI (defendability unassessed) · Grok Build's
default wire (closed binary) · Copilot CLI default-path interception
(HTTPS_PROXY + NODE_EXTRA_CA_CERTS untested).

#### 5.3.4 The October 2026 refresh

A second survey (2026-10-05) re-read each candidate's repository, docs or
binary help, and supersedes §5.3.2's order (§5.5 has the new one). What
changed:

- **The agent SDKs start the real CLI, but were not covered by
  construction** (corrected the same day, [agent-sdks.md](agent-sdks.md)).
  The Claude Agent SDK starts its bundled Claude Code binary with the
  host's `process.env`; the Codex SDK starts `codex exec --experimental-json`
  (TypeScript) or `codex app-server` (Python). Both TypeScript SDKs' `env`
  option replaces `process.env` rather than extending it, and Codex takes
  its provider only from the command line the SDK builds, so a Codex SDK
  host was not routed at all. The launcher's SDK route (a Node preload in
  the host) now keeps the routing on every CLI a Node host starts; the
  Python Codex SDK is not routed yet.
- **OpenCode V2** (`@opencode/cli` 2.0, GA 2026-09-11) moved the base URL to
  `settings.baseURL` and MCP servers to `mcp.servers`; the tested range
  (§2) is 1.x. Verified on 2.0.22 (§2.3): the V1 keys Mandu writes are still
  normalized and honored (the provider fence needs 2.x's own rules,
  §2.3 part 4), but by default a run joins a background service
  that keeps its own configuration, and one started outside Mandu sent the
  turn around the proxy. `mandu opencode` refused OpenCode 2 from
  2026-10-05; the same day §2.3's full support was built, checked live, and
  OpenCode 2 became a default-supported agent with its own tested range.
- **Copilot CLI** routes through `COPILOT_PROVIDER_BASE_URL` (BYOK, with
  `_TYPE` and `_WIRE_API` choosing Anthropic Messages, Chat Completions or
  Responses). A subscription-keeping route exists: GitHub's own
  gh-aw-firewall runs the CLI offline and BYOK against a local sidecar that
  forwards to the Copilot API with the real token.
- **New green rows:** Kilo CLI (an OpenCode fork), Pi 1.0 (`models.json`
  `baseUrl`; OpenClaw's engine), Qwen Code, Mistral Vibe, Cline CLI, Crush,
  Grok Build, nanobot, the OpenHands SDK (LiteLLM `base_url`; Agent Canvas
  now lives in the main OpenHands repository). Factory Droid is BYOK-only
  and closed source. Antigravity CLI reaches only a Gemini-compatible
  endpoint, so it and the Gemini CLI need a Google GenAI adapter.
- **New red rows:** Cursor CLI (its server builds the prompt and calls the
  model), Amp (the Amp server runs the loop; BYOK removed), Kiro CLI (no
  base URL). Aider is dormant (last release 2026-02-12) and Roo Code is
  archived. The Python Kimi CLI was archived; Kimi Code is the TypeScript
  `kimi-code`.
- **Four patterns bind every new build:**
  1. *Transcript and trace uploads.* The agent process holds original tool
     output, so its own session or trace upload (Kilo's session ingest and
     the OpenAI Agents SDK's tracing are on by default; Grok's trace upload
     and Copilot's `--remote-export` are opt-in) would carry secrets off the
     machine past the model proxy. Each build forces the off switch, denies
     the upload host at the network layer, and ships an e2e test. The deny
     is built (2026-10-05): a build adds its target's row to
     `launcher/src/upload-deny.ts` (fixed hosts, and env keys whose URL
     names a user-configured collector), and the launcher hands the list to
     the connect guard (`mandu-net-guard --deny`, checked before every
     allow) and to the net-proxy (`MANDU_NET_PROXY_DENY_HOSTS`, 403 before
     any dial); exec-routing.md §7.5, "Deny rules". A host that answers on
     the same CDN addresses as one the agent needs is listed `proxyOnly`:
     the net-proxy refuses it by name and the connect guard, which matches
     resolved addresses, leaves it alone (Codex's `ab.chatgpt.com` shares
     `chatgpt.com`'s Cloudflare addresses). Rows: Goose (§5.6), Codex
     (§6.6, with the review of every host Codex reaches).
  2. *Code mode.* Pi and Kilo can run a model-written script that calls
     tools in process; the wire gates would see one script. Refused in the
     first cut.
  3. *Always-on and messaging modes* (gateway, daemon, cron, chat-channel
     ingress) are now common (Hermes, Cline, Qwen Code, Copilot CLI, Droid,
     nanobot, OpenClaw). The first builds refuse them, as for OpenClaw's
     Gateway; one design across agents comes first.
  4. *Vendor sandboxes nest inside Mandu's* (Copilot CLI, Qwen Code and
     Antigravity bring their own, built on user namespaces): each build turns
     the vendor sandbox off under Mandu or tests the nesting.

### 5.4 Summary: the agent axis

| Agent | (a) local call | (b) override | (c) wire | (d) tools | Wrapper verdict |
|---|---|---|---|---|---|
| Claude Code | ✓ | env | Anthropic | host subprocess | 🟢 supported |
| Codex CLI | ✓ | config splice | OpenAI Responses | host subprocess | 🟢 supported |
| **OpenClaw** | ✓ | config splice + `${VAR}` / `OPENCLAW_*` dirs | Anthropic Messages | host subprocess (`exec`), in-process fs | 🟢 supported (`openclaw-e2e`); U-LLM as a plugin tool |
| **OpenCode** | ✓ | config file + `{env:VAR}` / XDG dirs | Anthropic Messages (via `@ai-sdk/anthropic`) | host subprocess (`bash`) | 🟢 supported (`opencode-e2e`); speaks MCP |
| **Claude Agent SDK** (TS, Python) | ✓ (bundled Claude Code) | env + `--settings`, kept on the child by the SDK route (Node preload, Python hook) | Anthropic Messages | host subprocess | 🟢 supported, `--target claude -- node app.js` / `-- python3 app.py` (`agent-sdk`); [agent-sdks.md](agent-sdks.md) |
| **Codex SDK** (TS) | ✓ (bundled `codex exec`) | provider splice into the child's argv by the SDK route | OpenAI Responses | host subprocess | 🟢 supported, `--target codex -- node app.js` (`agent-sdk`) |
| Codex SDK (Python) | ✓ (bundled `codex app-server`) | config (`--config`) and the app-server protocol, neither held by Mandu yet | OpenAI Responses | host subprocess | 🔴 refused: its `app-server` does not start under Mandu ([agent-sdks.md](agent-sdks.md) §5) |
| **Kimi Code CLI / Kimi Work** | ✓ | config.toml / `KIMI_CODE_BASE_URL` | OpenAI Chat Completions (native) · Anthropic (switchable) | host subprocess | 🟢 planned (§5.5) |
| Aider | ✓ | env (LiteLLM) | OpenAI-compat | host subprocess | 🟡 needs an ingress study (§5.5) |
| **Hermes** | ✓ | config (outranks env) | Anthropic + OpenAI (3 modes) | host subprocess (default `local`) | 🟢 reuse + validation |
| **OpenHands CLI** | ✓ | config/env (LiteLLM) | OpenAI-compat | host subprocess | 🟢 reuse |
| **OpenHands GUI** | in-container | conversation config | LiteLLM | in-container | 🟡 container-boundary work |
| Gemini CLI | ✓ | env | Google GenAI | host subprocess | 🟡 needs a Google GenAI adapter |
| Continue · Cline | ✓ | env/config | OpenAI-compat | in-IDE | 🟡 partial |
| Cursor · Copilot · Amazon Q · Windsurf | ✗ server-side | — | — | — | 🔴 unreachable |

Two standing patterns: **a config splice is as good as env** (OpenClaw
joins Codex), and **agent-managed containers are a fifth (d)-shape**: not
host subprocesses, but a boundary we can gate like a small guest (OpenHands
GUI; also OpenClaw's opt-in Docker sandbox and Hermes's optional Docker
terminal backend).

### 5.5 Status and next steps

OpenCode and OpenClaw are built and in the tested ranges (§2):

- The maintainers' recorded drill runner drives both TUIs (target
  `opencode` or `openclaw`), and the dashboard's Watch picker offers all four
  agents.
- The launcher accepts only confined OpenClaw launch shapes: a Gateway
  client (`tui`, `agent`, `acp` without `--local`) would leave the agent loop
  in a Gateway outside the confinement
  ([agent-e2e-harness.md](../testing/agent-e2e-harness.md) §9.0). Each
  agent's session binds its own reviewed trust spec.
- The model-context gates (exec, net + session watermark, sensitive path,
  callTaint, the twin note) are keyed per agent through the arbiter's
  gate-surface tables, verified against captured `tools[]`, so they fire for
  OpenCode's `bash` / `webfetch` and OpenClaw's `exec` / `web_fetch`, not
  only for Claude Code's names
  ([exec-routing.md](../integrity/exec-routing.md) §3.2).

The items, open and closed:

1. **Open:** a graded live drill battery on a real Anthropic model for each
   agent (the drills have run only against a scripted upstream).
2. **Open:** re-grade the scenarios marked unsupported because a gate did
   not fire (the sensitive-path and WebFetch URL gates now do), and run the
   `inspect_symbol` scenarios live on both agents.
3. **Closed:** `declassify_symbol` is mounted for both
   ([agent-e2e-harness.md](../testing/agent-e2e-harness.md) §8.5): OpenCode
   reaches it over the existing MCP server as
   `mandu-inspect_declassify_symbol`, OpenClaw as the plugin tool
   `declassify_symbol`; one relay, the arbiter's decision and approval queue
   unchanged, e2e-tested per agent through a real arbiter and the model
   proxy (§2.2). The drills C6, C7 and C12 run on both agents but are not
   yet graded live (they join item 1's battery).
4. **Closed:** the OpenClaw gate-surface residue (`apply_patch` paths,
   `exec.workdir`, the `image` / `browser` destinations); §2.1 "The
   gate-surface residue".
5. **Closed:** OpenClaw's workspace under `mandu openclaw chat` is pinned to
   the launch directory (§2.1 "The workspace"; `agent-config.ts`
   `fenceOpenclawWorkspace`), and the kernel-layer test shows it holds under
   the secret-twins wrap. Wrapper scripts under `--target openclaw` stay
   allowed. Bare `mandu openclaw` runs `openclaw chat` (`openclaw-argv.ts`
   `openclawDefaultArgv`).

**Next agents, in order** (decided 2026-10-05 from §5.3.4, weighing each
agent's reach against how cheaply it can be defended). The design pass over
Hermes, Goose, Kimi Code and the OpenHands CLI, read from each project's
source and docs, corrected the assumptions noted in §5.2. Its decisions:
Chat Completions agents go through the anthropic-proxy's
`/_mandu/openai/<id>` route, where the gate-surface tables live, rather
than through the openai-proxy; Hermes on a borrowed Claude sign-in is
refused; code-mode tools are refused; the agents that keep their state in
one home directory (Hermes, and the U-LLM mount on Kimi Code) get a per-run
overlay of it.

1. **OpenCode V2**: keep a supported agent supported (§5.3.4). DONE
   (2026-10-05): supported by default, tested on 2.0.23 (§2, §2.3), after a
   day refused and then built behind an opt-in; `MANDU_OPENCODE2=0` turns
   it off.
2. **The Claude Agent SDK and the Codex SDK**: built 2026-10-05
   ([agent-sdks.md](agent-sdks.md)): the SDK route keeps a Node host's CLI
   routed (the Codex SDK was not routed before), the `agent-sdk` suite
   proves it on the pinned SDKs, and the user guide has the section. Open:
   the Python Codex SDK (refused since 2026-10-17, agent-sdks.md §5).
3. **Goose** and **Hermes**: both reach the existing Anthropic proxy
   (Goose by `ANTHROPIC_HOST`; Hermes by a config splice whose base URL ends
   in `/anthropic`), tools run as host subprocesses. Each needs a
   provisioning recipe, a launcher target, a gate-surface table and inbound
   spec, a drill profile and a live e2e, the OpenCode pattern. Goose is
   supported (§5.6, in the tested ranges since 2026-10-06).
4. **Copilot CLI**: BYOK sessions first; then the subscription-keeping
   upstream (§5.3.4).
5. **Kilo CLI** and **Pi**: near reuse of the OpenCode and OpenClaw work.
6. **The OpenHands SDK** (a study; the OpenHands CLI is unmaintained
   upstream and deferred) and **Factory Droid** (BYOK sessions only).
7. **Qwen Code** and **Mistral Vibe**, then Cline CLI, Crush, Grok Build,
   nanobot, DeepSeek Harness (not yet assessed) and **Kimi Code**. Kimi
   Code needs an inbound spec, a launcher target and config splice pointing
   it at the proxy's Chat Completions route with the upstream at Moonshot,
   the U-LLM, the reply filter, tests, and a gate-surface table for its
   Claude-Code-shaped tool names. The Chat Completions route is built:
   `POST …/chat/completions` is masked like the Responses route (tool
   messages symbolized through the same rewrite, the handling prompt in the
   system message, the answer's tool calls through the exec gate and path
   map, every call a `tool_use` event, text repacked, fail-closed 400 /
   502; `interceptors/openai-proxy/README.md`, "The Chat Completions
   route"). Refused with a 400 today: a tool message carrying an image (the
   mask reads text only, so the image would pass it), the legacy
   `functions` / `function` role, and provider-side tools. Local models
   (Ollama, vLLM): the existing `MANDU_UPSTREAM` / `upstreamIsBaseUrl` /
   `upstreamLocal` settings apply to the Chat route unchanged, including
   the cloud-model refusal.
8. **Antigravity CLI and the Gemini CLI**: one Google GenAI adapter serves
   both.

Not planned: Cursor CLI, Amp and Kiro CLI (no reachable model call),
Devin and Jules (cloud loops), Aider (dormant; it puts file contents in
user messages, which the route does not mask), Roo Code (archived).
The always-on and messaging modes get one design across agents before any
agent's mode is built.

### 5.6 Goose: the build (supported, 2026-10-06)

Goose (`aaif-goose/goose`, formerly `block/goose`) is one Rust binary that
reaches the anthropic-proxy by env alone (`GOOSE_PROVIDER=anthropic`,
`ANTHROPIC_HOST` at the proxy; an env var named as an uppercase config key
outranks `config.yaml`); its `openai` provider is routed the same way
since 2026-10-06 ("The openai provider" below), and its `litellm`,
`openrouter`, `ollama`, `xai` and `tetrate` providers since 2026-10-07
(§5.6.4). The CI guest image pins goose 1.53.0
(`scripts/ci/pins.env`, the release tarball, sha256-checked). Goose entered
the tested ranges (§2) on 2026-10-06, after its live leg on a real model.

**The capture.** Every table below is pinned to the `tools[]` of real goose
1.53.0 requests at a scripted local `/v1/messages`, with a throwaway home and
only loopback (`arbiter/test/fixtures/goose-tool-surface-2026-10-05.json`).
What the wire showed:

- `run` and `session` send only `POST /v1/messages` (`stream: true`); no
  `GET /v1/models` at start. Goose's own session header is
  `agent-session-id: <yyyymmdd>_<N>`; a `delegate` subagent gets its own.
  Mandu keys the session by the per-launch proxy's session key, as for Codex.
- Every tool result is a plain string. `shell` answers stderr, then stdout,
  then `Command exited with code N` when non-zero. It runs `bash -c` in the
  launch directory with stdin `/dev/null`; `write` and `edit` resolve a
  relative path there.
- The default surface (17 tools): `shell`, `write`, `edit`, `tree`,
  `analyze`, `read_image`, `delegate`, `load`, `load_skill`, four `apps__*`
  and four `extensionmanager__*`. There is no file-read tool: Goose reads a
  file through `shell`. Opt-in builtins add `todo__todo_write`,
  `chatrecall__chatrecall`, `summarize__summarize`, `memory__*`,
  `orchestrator__*`, `computercontroller__{pdf,docx,xlsx}_tool` (and
  `computer_control` on macOS), `tutorial__*` and `autovisualiser__*`.
- Code mode (`code_execution`) is `execute_typescript{code, tool_graph}`,
  `list_functions`, `get_function_details`; with it on, every non-developer
  tool moves inside `execute_typescript`.
- An MCP server mounted with `--with-extension '<name>:<command>'`
  advertises `<name>__<tool>`: Mandu's tools appear as
  `mandu-inspect__inspect_symbol`, `mandu-inspect__declassify_symbol` and
  `mandu-policy__<tool>`. Goose 1.53.0 opens with the MCP `server/discover`
  request and falls back to `initialize` on a JSON-RPC error.
- `delegate{provider}` makes the subagent build that provider in process and
  dial it, so a model could reach a provider Mandu does not route. Goose
  picks the subagent's provider from a recipe's settings, then env
  `GOOSE_SUBAGENT_PROVIDER`, then the call's `provider`, then the config.

**The model-context layer (built).** `arbiter/policy/goose-inbound.ts` (the
`goose` inbound spec: `shell`, `delegate`, `load`, `load_skill`,
`apps__list_apps` and `extensionmanager__search_available_extensions`
UNTRUSTED (the last four since 2026-10-09, `load` and `load_skill` only in a
session the guard confines: "The tool_surface unknown list" below); `write`, `edit`,
`tree` and the todo list TRUSTED; the in-process file readers `analyze`,
`read_image`, the document tools and `summarize` left unmapped so the
unmapped-input scan labels their results; everything else UNTRUSTED by
omission) and `GOOSE_GATE_SURFACE` (`tool-gate-surface.ts`, mirrored in the
proxy's union):

| Gate | Goose's entry |
|---|---|
| exec, exec output | `shell.command` |
| net | `read_image.source` (an http(s) URL is fetched) |
| paths | `write.path`, `edit.path` (writes); `tree.path`, `analyze.path`, `read_image.source` (a media path), `delegate.working_dir`; the document tools' `path`, `summarize.paths` |
| dispatch | `execute_typescript` refused (code mode, decision D4): its input becomes a stub that throws |
| refuse | enabling an extension, creating, iterating or deleting a Goose app, the scheduler, the orchestrator's agent control, `computer_control` |
| refused forms | `delegate` with a `provider` or a `source` (a recipe can pin a provider, and the agent can write the recipe itself) |
| relative base | the launch directory |
| workdir | none: `shell{command, timeout_secs}` has no `workdir`, and a `workdir` the model writes into a call is ignored (the call is read where the kernel says its shell started; 2026-10-11) |

The `workdir` row is the gate surface's `workdir` table (GateSurface
`workdir`): the tools whose `workdir` an agent acts on, which the
confidentiality derivation reads a shell call's relative path tokens in
([confidentiality.md](../confidentiality/confidentiality.md) §6, "A forged
`workdir`"). Goose's `shell` shares the name of Codex's classic tool, so the
arbiter used to take a Goose call's `workdir` the way it takes Codex's. The
tables now say it per agent: Codex's `exec_command` and argv `shell` (in
Claude Code's table, the one a Codex session resolves to), OpenCode's `bash`
and `shell`, none for Goose or OpenClaw (its `exec` falls back to the
workspace when the directory is missing). Tests:
`arbiter/test/unit/workdir-per-agent.test.ts` (each table held to the
captured wires: Goose's `shell` has no `workdir`) and the forged-`workdir`
case of `tests/stack/relative-read-public-label.test.ts`.

Each refusal input was run against goose 1.53.0 and fails the tool's own
parameter check before anything runs. With confidentiality ON a tool neither
the spec nor this table names (an extension's `<key>__<tool>`, the unmapped
built-in extensions `memory__*`, `chatrecall__*`, …) is masked whole unless
policy.yaml `mapped_tools:` lists it (confidentiality plan 10 §11.18); so are
`extensionmanager__list_resources` / `read_resource`, by decision (below);
code mode's `list_functions` /
`get_function_details` return the tool catalog and are mapped. Tests: `arbiter/test/unit/goose-inbound.test.ts`,
the Goose cases in `arbiter/test/unit/tool-gate-surface.test.ts` (every table
field held to the capture), `interceptors/anthropic-proxy/test/component/goose-gates.test.ts`
(each gate with a control on a table without Goose's entry) and
`tests/stack/goose-gate-surface.test.ts` (the real arbiter, the production
adapter, `secrets` mode, and the arbiter gone mid-turn: every gate blocks,
denies or refuses, and a shell result carrying a labelled secret never
reaches the model raw).

**The tool_surface unknown list (2026-10-09).** The 2026-10-08 live drills
on goose 1.53.0 recorded a `tool_surface` event naming nine of the 22
advertised tools UNKNOWN: `analyze`, `read_image`, `load`, `load_skill`,
`apps__list_apps`, `apps__delete_app`, `extensionmanager__list_resources`,
`extensionmanager__read_resource`,
`extensionmanager__search_available_extensions`. None was a leak path:

- `analyze` and `read_image` were already mapped by the gate surface (their
  path field gated, `read_image.source` a net destination too), left out of
  the spec only so the unmapped-input scan labels their result by the paths
  their input names. The `toolSurface` op excused a dispatcher or a refused
  tool but not a gated one, so it reported them: a reporting gap.
- The other seven had no mapping at all, so with confidentiality ON every
  result of theirs was masked whole (§11.18): fail-closed, a utility cost.
  `load` of a background task (`delegate{async: true}`) and every skill
  came back as a placeholder.

The fix: `apps__list_apps` and
`extensionmanager__search_available_extensions` are mapped UNTRUSTED (the
listings carry whatever wrote each entry's description); `load` and
`load_skill` are mapped UNTRUSTED only under the guard (a recipe, agent or
skill body is a workspace file, a background task's result a subagent's
answer; the posture rule is below). `apps__delete_app` is refused with the other app
tools (it deletes a file of the desktop's app store that no gated field
names; probed on 1.53.0 and 1.54.0: the refusal input fails with "Missing
or invalid 'name'" and the app stays). `extensionmanager__list_resources`
and `read_resource` stay masked whole, by decision
(`mapped-tools.ts MASKED_BY_DECISION`): they read the resources of the
extension the model names, a server whose own tools are masked until the
person maps it (`mapped_tools: [extensionmanager__read_resource]` lifts
it). `toolSurface` now excuses every tool the gate surface names and every
tool masked by decision; a tool nobody looked at is still reported.

`load` and `load_skill` read a file the model names by a NAME (a recipe,
an agent, a skill, or a skill's supporting file as `load_skill{name:
"<skill>/<file>"}`; probed: a supporting `creds.env` comes back verbatim),
in Goose's own process. No input field holds the path, so no model-context
gate can tell which file it is; what keeps a labelled file's bytes from the
model is the guard, which hands Goose's open the twin
(rootless-confinement-ubuntu-2404.md §0.1). So the two are mapped ONLY in a
session the guard confines (`mapped-tools.ts GUARD_MAPPED_TOOLS`): the
launcher's launch record (`beginLaunch`, on the human plane before Goose
starts) claims posture `confined` for the session's key, on an attested
channel, no other launch of the session claimed otherwise, and no unwalled
launch exposes the human plane now. Anywhere else (posture `gated` or
`read-blocked`, no record so the posture is unknown, an arbiter restarted
since the launch, the human plane exposed) their results are masked whole
with a note naming the missing guard, and policy.yaml `mapped_tools:` does
not lift that: fail-closed. A first version of this change (2026-10-09,
before review) mapped them everywhere, which in the `gated` posture would
have sent a labelled file's bytes read through them to the model raw where
the §11.18 mask had hidden them; the review caught it before it landed.

goose 1.54.0 (2026-10-08) advertises the same tools with the same input
fields, on the default surface and with each opt-in builtin
(captured 2026-10-09 the same way as the 1.53.0 fixture); it joined the
tested range on 2026-10-09 (§2).

Tests: `arbiter/test/component/goose-tool-surface.test.ts` (the real IPC:
the captured surface and the mounts read fully known, drift still
reported, the §11.18 answer per tool, and the posture rule: `load` /
`load_skill` forwarded only after a `confined` launch record, masked with
no record, a `gated` or `read-blocked` one, a mixed session, an ended
launch or an exposed human plane), the Goose cases in
`arbiter/test/unit/mapped-tools.test.ts` and `goose-inbound.test.ts`,
`tests/stack/goose-gate-surface.test.ts` (the nine through the production
proxy in `secrets` mode: `analyze` / `read_image` naming the labelled file
only as a symbol, image bytes included; the resource tools masked whole;
`load_skill` / `load` returning a labelled file's bytes masked whole with
no launch record and in a `gated` session, forwarded in a `confined` one
with the two listings; `delete_app` refused; all nine with the arbiter gone
never raw) and `launcher/test/kernel/goose-readers.test.ts` (the real goose:
under the guard `load_skill` of a labelled supporting file reaches the
model as its twin; without it, the result is masked whole; the control
without Mandu sends the value).

**The launcher target (built).** `mandu goose` (target `goose`, inferred
from the binary's name):

- **Launch shapes** (`launcher/src/goose-argv.ts`, an allowlist): bare
  `mandu goose` runs `goose session` (bare Goose falls back to the
  interactive `configure` without a config); `session`, `run` (with
  `--recipe`, read at launch), `review` and `acp` (through the launcher's
  ACP relay) launch (the recipes, review and ACP paragraph below).
  Refused: `serve` (the desktop backend and its scheduler), `gateway`
  (chat-platform ingress), `schedule`, `acp --enable-scheduler`, `roam`,
  `--container`, `--sub-recipe`, `--with-builtin code_execution` (decision
  D4), `session export|import|list|…` (`export --nostr` publishes a session
  to public relays), `recipe …` and every management command.
- **Routing and the provider check** (`launcher/src/goose-route.ts`):
  `ANTHROPIC_HOST` at the session's anthropic-proxy, `OPENAI_HOST` at its
  `/_mandu/openai/openai` route, and `GOOSE_PROVIDER` and
  `GOOSE_SUBAGENT_PROVIDER` pinned to the routed provider the launch
  resolved: `anthropic`, `openai` ("The openai provider" below) or one of
  the Chat Completions providers at their own routes (§5.6.4),
  `anthropic` when none is named (the env outranks the config and a
  `delegate` call's `provider`). A launch whose `--provider`, env or
  `config.yaml` names any other provider, for the session or its
  subagents, an endpoint the proxy cannot reach, or a declarative
  provider named like a provider it routes, is refused before anything
  starts; the refusal names the setting and the routed providers (the
  config's provider is read in Goose's order, `active_provider` before
  `GOOSE_PROVIDER`). Every other provider's endpoint keys and hosts are
  fenced, so a `/model --provider` switch mid-session sends nothing (§5.6.3).
  Goose's own `ANTHROPIC_HOST` is the
  base-URL override (claude's `ANTHROPIC_BASE_URL` semantics); a claude
  `ANTHROPIC_BASE_URL` in the env no longer skips Goose's proxy. The proxy
  binds the session to the `goose` spec (`context-proxy.ts`).
- **Resumed sessions.** `-r` / `--resume` gets `--provider <routed>`
  pinned, since a saved session's provider outranks the env ("Resumed
  sessions" below).
- **Uploads (§5.3.4 rule 1).** The launch env turns off PostHog
  (`GOOSE_TELEMETRY_OFF=1`, `GOOSE_TELEMETRY_ENABLED=false`), Langfuse (all
  four key variables set empty: Goose reads the second form only when the
  first is unset), OTLP (`OTEL_SDK_DISABLED=true`), the prompt and command
  classifiers and the toolshim. `upload-deny.ts` denies `us.i.posthog.com`,
  the four default Nostr relays and every Langfuse, OTLP or classifier
  endpoint named in the user's env or `config.yaml`, at the connect guard
  and the net-proxy.
- **The U-LLM mount.** Mandu's MCP servers ride `--with-extension
  '<name>:ENV=… command args'` right after `session` / `run`, each token
  quoted the way Goose's parser reads it back, only into the real `goose`
  binary (a wrapper under `--target goose` gets no splice). The tools appear
  as `mandu-inspect__inspect_symbol` and `mandu-policy__<tool>`; the
  inspect server's model channel is the real endpoint or the U-LLM
  forwarder, never the proxy, although the child inherits Goose's env.
- **The reply filter** is the launcher's default for every target; Goose's
  TUI is line-based (rustyline, the main screen). The differential
  interactive run (`integration.differential-goose`, nightly;
  differential-interactive.md §32): 13/13 on goose 1.53.0, vanilla against
  `mandu goose` over the scripted model, each side on its own HOME and
  `GOOSE_PATH_ROOT`. Its first run found two relay bugs, both fixed: a
  reserve head that Goose's Markdown streamer restyles at the `_` left
  `/1:N:W:F` on the screen, and the pad of Goose's live tool row, pushed
  past the edge by a wider value, left every spinner frame behind as a
  row. Goose prints its reply raw at column 0 and leaves the wrap to the
  terminal, so the launcher selects the reply filter's `terminal` wrap rule
  for it (`MANDU_REPLY_WRAP_RULE=terminal`, reply-row-reservation.md §17):
  a reserved value wider than the row now breaks where vanilla's does. Two
  differences stay: the shell's own output shows a labelled file's value as
  one row (the twin token outside the model's reply), and after a resize
  the terminal re-wraps vanilla's long line but keeps a reserved row's break
  (§17.6 there). `goose acp` runs without
  it (its stdout is a JSON-RPC stream): the ACP relay's own JSON-aware pass
  shows the editor originals instead (the ACP paragraph below).

Tests: `launcher/test/unit/goose-argv.test.ts` (the shapes, the splice,
the quoting round trip through a port of Goose's parser),
`launcher/test/unit/goose-route.test.ts` (the forced env, the provider
check over argv, env and config, the openai endpoint resolution, the deny
row), the Goose cases in
`env-compose.test.ts` and `spawn.test.ts`,
`launcher/test/component/goose-delivery.test.ts` (the real `main()` with a
stand-in `goose`: the routing env and the mounts delivered, every refused
shape and provider never starting the stand-in, a counting upstream seeing
nothing) and `launcher/test/component/goose-real.test.ts` (the REAL goose
under `main()`, the real arbiter and proxy, a scripted upstream: the turns
go through the proxy, `mandu-inspect__inspect_symbol` is advertised, and with
the user's env pointing OTLP and Langfuse at a counting collector, nothing
reaches it; the control run without Mandu does upload its traces; skipped
with its reason where no goose binary is installed). The control leaves out
the Langfuse keys: Goose 1.53.0's Langfuse layer aborted Goose in one CI run
in seven (its `on_close` calls `tokio::spawn` on a sqlx worker thread, "there
is no reactor running"), and the control never checked its 5 s batches
(test-organization.md §8.8).

**Recipes, review and ACP (built, 2026-10-06).** Read from goose 1.53.0's source
(`goose-cli/src/session/builder.rs`, `recipe/`, `commands/review/`,
`checks/mod.rs`, `agents/platform_extensions/summon.rs`):

- *`run --recipe` (supported).* A recipe is a Jinja template (`--params`,
  `{% include %}` from its own directory) whose `settings.goose_provider`
  OUTRANKS env GOOSE_PROVIDER (the order is `--provider`, a resumed
  session's saved provider, the recipe's, the env, the config), so the env
  routing alone does not hold. `launcher/src/goose-recipe.ts`: (1) resolves
  `--recipe <name>` the way goose does (a `.yaml` / `.json` path, else the
  local recipe directories in goose's component-sorted order) and hands
  goose the ABSOLUTE path it read; a name only GOOSE_RECIPE_GITHUB_REPO
  would supply (a `gh` fetch) is refused; (2) reads the file and the
  templates it includes without rendering them and refuses a
  `goose_provider` that names another provider or is itself a template,
  `sub_recipes`, and a `code_execution` extension; (3) pins `--provider
  <routed>` (the provider goose-route.ts resolved for the launch, `anthropic`
  or `openai`) right after `run` when the user gave none (a `--provider` the
  user gave is checked by goose-route.ts). A recipe naming the other routed
  provider is refused too: the pin would silently switch it. The pin, not the scan, is what
  holds the routing whatever the template renders to; the scan makes the
  refusal honest instead of silently switching the user's provider. What
  else a recipe carries stays inside the launch: stdio `extensions` are
  goose's subprocesses inside the wrap (as a `--with-extension`),
  streamable-HTTP ones are `--with-streamable-http-extension`'s case,
  `retry.checks` / `on_failure` are shell commands goose runs inside the
  wrap whose output is not sent to the model, and a `file` parameter is
  read inside the wrap into the prompt (a USER turn: the prompt filter's
  registered-value floor masks a labelled file's value there).
- *`--sub-recipe` and a recipe's `sub_recipes` (refused).* A sub-recipe runs
  only as `delegate{source}`, which the wire refuses (`GOOSE_GATE_SURFACE`:
  a sub-recipe's settings name its subagent's provider above
  GOOSE_SUBAGENT_PROVIDER), so it could never run; refused at launch with
  that reason.
- *`goose recipe …` (refused).* `validate`, `list`, `deeplink` run no agent;
  `open` hands the recipe to Goose Desktop, outside the launch. Run them
  without `mandu`.
- *`review` (supported).* The orchestrator runs every check
  (`**/.agents/checks/*.md`, the global `~/.config/{goose,agents}/checks`)
  and the main pass (one per touched file) as `goose run --no-session
  --quiet --no-profile -i -` children of the same binary
  (`std::env::current_exe`), with the parent's env (GOOSE_PROVIDER,
  ANTHROPIC_HOST, the forced-off uploads) and its `--provider` /
  `--model`; `--no-orchestrate` builds the agent in process. Every model
  call is therefore the env-routed provider, and the children run inside
  the wrap. A check's frontmatter names `model:` only (`CheckFrontmatter`:
  name, description, model, turn-limit, tools, severity-default; any other
  key is ignored), and a model id selects no endpoint, so the one provider
  knob is `review --provider`, checked with the others by goose-route.ts
  (with review's own value flags: `-s` is `--check-scope <DIR>` there but
  `run`'s value-less `--interactive`). `review` takes no
  `--with-extension`, so the U-LLM is not mounted (the children run
  `--no-profile`, without extensions); `--no-orchestrate` delegates each
  check as `delegate{source}`, which the wire refuses. The diff and every
  untracked file are inlined into the children's USER turns, not tool
  results: inside the wrap a labelled file reads as its twin, and the
  prompt filter's registered-value floor masks its value either way.
- *`acp` (supported, through a relay).* `goose acp` serves the editor's
  ACP over stdio; the editor is the human view (Goose's stdout reaches it),
  and it holds powers the env routing does not cover (`acp/`, captured
  against a scripted editor):
  (a) when the editor's `initialize` offers `clientCapabilities.fs` /
  `terminal`, Goose runs `shell` through the editor's `terminal/create`
  and its file tools through `fs/*` (and advertises an extra `read` tool):
  in the editor's process, outside the wrap and the twins;
  (b) the provider is the editor's to pick: `session/set_config_option
  {configId: "provider"}` rebuilds it (an editor shows it as a picker),
  `session/new`'s `_meta.provider` picks one and a recipe in its `_meta`
  (`recipeId`, `recipeDeeplink`) outranks that, and `session/load` /
  `fork` restore the saved session's provider;
  (c) the same stream answers the desktop's `_goose/*` methods: provider and
  custom-provider setup with their own endpoints, config writes,
  extensions, schedules, dictation, local models;
  (d) `--enable-scheduler` fires scheduled recipes inside the server.
  `launcher/src/goose-acp-relay.ts` sits between the editor (the
  launcher's stdin / stdout) and Goose (runAgent's `stdioRelay`: the chain
  gets piped stdin / stdout, stderr stays the launcher's): it offers Goose
  neither capability (every tool runs in Goose, inside the wrap, on the
  captured 17-tool surface) and answers a `fs/*` / `terminal/*` request
  from Goose with an error instead of forwarding it; passes only the
  standard ACP session methods (`initialize`, `authenticate`,
  `session/new|load|fork|list|close|delete|prompt|set_mode|set_config_option`,
  the `session/cancel` notification) and answers anything else with
  `-32601`; refuses a provider other than the ones this launch routes
  (`GooseRouting`: the session's and the subagents', `anthropic` or
  `openai`) or `goose` (the default, the env-pinned session provider) in
  `_meta.provider` and in a
  provider switch, and refuses `_meta` recipes and `enabledExtensions`;
  tracks each session's provider from Goose's own answers (`configOptions`,
  `config_option_update`) and refuses `session/prompt` on a session it has
  not seen on the routed provider (a loaded session saved under another
  provider, or one whose answer names none); mounts Mandu's MCP servers
  into every `session/new|load|fork`'s `mcpServers` (the tools appear as
  `mandu-inspect__inspect_symbol`). The byte-stream reply filter is off for
  this shape (parse.ts: its line rewriting would break the JSON-RPC
  framing); in its place the relay desymbolizes Goose's editor-bound
  messages itself (`launcher/src/goose-acp-display.ts`, built 2026-10-07;
  reply-row-reservation.md §15.4): each line is parsed into a span tree and
  only the human-display strings are resolved over the arbiter's human
  plane and re-escaped in place: the reply and thought text
  (`agent_message_chunk` / `agent_thought_chunk`), a tool call's title,
  content (text, a diff's old and new text), `rawInput` / `rawOutput` and
  Goose's live output, plan entries, session titles (`session_info_update`,
  the answer to `session/list`) and a `session/request_permission`'s tool
  call. Ids, methods, paths, keys and every other byte stay as Goose wrote
  them, and the human's own turns (`user_message_chunk`, replayed by a
  load) keep their symbols. Nothing the relay writes toward Goose is
  desymbolized. Any failure (no human-plane socket, the arbiter refusing,
  unreachable or past a two-second deadline, a line that does not parse)
  forwards the line unchanged, so the editor shows the symbol, which leaks
  nothing; `--no-reply-filter` / `MANDU_REPLY_FILTER=0` turn the pass off.
  *Flow-back:* an original the editor shows reaches Goose only if the human
  or the editor puts it into a new prompt: ACP answers to Goose's requests
  carry an option id (`fs/*` and `terminal/*` never reach the editor), an
  ACP client sends only the new prompt (the conversation lives in Goose,
  built from what the model wrote), and the turn an editor re-sends is the
  human's own, which is not desymbolized. A quoted original is a `human`
  prompt segment, where the prompt filter's registered-value filter masks a
  secret's value back to its symbol (confidentiality-plan-15-prompt-filter.md
  §4.1; the component test echoes one and the model reads the symbol); a
  value under that plan's prompt floor (12 characters, entropy 3.0) reaches
  the model as typed, the same residual as the human retyping what the
  terminal reply filter shows (reply-row-reservation.md §15.4).
  The launcher's notices go to stderr; `acp --enable-scheduler` and
  `--with-builtin code_execution` are refused at launch.

Tests: `launcher/test/unit/goose-recipe.test.ts` (the findings, the
include walk, goose's lookup order, the argv plan),
`goose-argv.test.ts` and `goose-route.test.ts` (the shapes; review's value
flags and `--provider`), `goose-delivery.test.ts` (a stand-in goose: the
pinned `--provider` and the absolute recipe path delivered, every refused
recipe never starting it; review's routing env), and
`launcher/test/component/goose-shapes-real.test.ts` (the REAL goose under
`main()`, the real arbiter in `secrets` mode with a `no-model` file, a
scripted upstream: a recipe's turns and every review child go through the
proxy, the labelled file the recipe's shell reads and the one in the
reviewed diff reach the model only as a symbol; a recipe naming `openai`
in an anthropic launch and `review --provider google` start nothing);
`tests/stack/goose-gate-surface.test.ts` holds the prompt path over the
production wiring (a review child's tool-less prompt and a recipe turn
carrying the labelled value: a symbol; the arbiter gone: never raw). ACP:
`launcher/test/unit/goose-acp-relay.test.ts` (the capability strip, the
allowlist, the provider checks and tracking, the mount, Goose's
`fs/*` / `terminal/*` answered, the stream wiring) and
`launcher/test/component/goose-acp-real.test.ts` (the launcher as its own
process with the REAL goose behind it and a scripted ACP client that
offers its fs and terminal: every line the editor reads parses, no
`fs/*` / `terminal/*` request reaches it, the turn goes through the proxy
on the captured surface plus `mandu-inspect__inspect_symbol`, the labelled
file reaches the model only as a symbol, a switch to `openai` and a
`_goose/*` method are refused, a loaded session prompts again; the CONTROL
without Mandu shows bare goose asking the editor's terminal; `acp
--enable-scheduler` starts nothing; "display": the scripted model quotes the
symbol it read, the editor reads the original, no request to the model
holds the value, the editor's echo of it in the next prompt reaches the
model as the symbol, a load replays originals, and `--no-reply-filter`
keeps the symbol). The display pass:
`launcher/test/unit/goose-acp-display.test.ts` (the fields, escapes and
unicode, failures as passthrough, order and back-off, nothing toward Goose
desymbolized) and `tests/stack/goose-acp-display.test.ts` (the production
resolver over a real arbiter's human plane; the data socket resolves
nothing; the arbiter gone is a passthrough in order).

**Resumed sessions (fixed, 2026-10-06).** A saved session remembers its
provider, and resuming it brings that provider back above the env routing
(goose 1.53.0 `goose-cli/src/session/builder.rs`
`resolve_provider_and_model`: `--provider`, then the provider SAVED with
the session, then a recipe's, then env `GOOSE_PROVIDER` and the config).
The shapes that load a saved session are `session` and `run` with `-r` /
`--resume` (with `--name`, `--session-id` or `--path`, or none for the most
recent session; `--fork`, `--edit` and `--history` require it); `--name`
without `--resume` starts a new session, and there is no in-session
command that loads another. Captured on the pinned goose against loopback
upstreams: a session created outside Mandu on a declarative provider
(`custom_providers/custom_leak.json`, its base URL a counting upstream
standing in for a provider Mandu does not route) and resumed with env
`GOOSE_PROVIDER=anthropic` dialed the counting upstream; so did `mandu goose
run --resume --name …` before the fix (`POST /v1/chat/completions`, the
saved history with the raw output of a labelled file's `cat` in it).

The fix (`gooseResumes`, `gooseResumePin` in `launcher/src/goose-route.ts`):
every resume shape the user gave no `--provider` gets `--provider
<routed>` right after the subcommand (the session's routed provider,
`anthropic` or `openai`), which outranks the saved one; a `--provider` the
user gave is checked like any other. `-r` inside a short-flag cluster
counts; a flag's value never does. Pinning holds on every shape, so none
is refused. The model then comes from `GOOSE_MODEL`, the config, or the
routed provider's default: the saved model is kept only when the saved
provider is the routed one (a model of another provider then fails at the
routed one; nothing leaves around the proxy). Tests:
`launcher/test/unit/goose-route.test.ts` (the shapes read, the pin),
`goose-delivery.test.ts` (`session -r` and `run --resume` deliver the pin,
openai's too; a new session gets none) and
`launcher/test/component/goose-resume-real.test.ts` (the REAL goose: the
CONTROL above, then `mandu goose run --resume --name …` and `-r -n …` on
that session: the counting upstream sees nothing, the turn goes through
the proxy, and the saved history's file content reaches the model only as
a symbol).

ACP: the relay already covers `session/load` and `session/fork`. They
restore the saved provider, the relay reads it from Goose's answer
(`configOptions`) and refuses `session/prompt` on a session it has not
seen on a routed provider, and a load makes no model request of its own
(`acp/server/load_session.rs`; the provider's `resume` hook is a no-op for
HTTP providers). One exception, closed by the launch env: with the
experimental state-machine loop on (`GOOSE_STATE_MACHINE=1`, read from the
env only), a load of a session with a pending tool confirmation starts a
turn ON LOAD, on the saved provider, before any `session/prompt`. The
launch sets `GOOSE_STATE_MACHINE=false` for every Goose shape (the gates
were captured on the default loop as well).

**The drills (built).** `gooseProvisioner` (`tests/lib/agent-provision.ts`)
and the replay suite `goose-e2e.test.ts`
(`integration.goose-e2e`, kind `replay-drill`, axis `secrets`): the real
goose 1.53.0 against a scripted upstream through the real proxy and
arbiter, the seven `confScenarios` (reasoning, benign-read,
secret-read-exfil, secret-net-exfil-blocked, secret-read-control,
prompt-secret, inspect-extract); `goose-uploads.test.ts` beside it holds
rule 1 at the provisioner. The catalog replays Goose like the other agents:
the replay engine spells a read as `cat` through `shell` (Goose has no read
tool), the driver profile is `GOOSE_PROFILE`
(`differential-profiles.ts`), the watch runner's is
`drill-target-goose.ts` (`--target goose`, the dashboard's Watch and Replay
pickers), and the recorder un-spells Goose's calls. 41 catalog scripts
replay on Goose (`integration.replay.goose`, nightly, every area); the conf
trio also runs per push (`integration.replay-push.goose`). Skipped on Goose,
with the reason in the catalog: conf-declassify-confines-session (its
script fetches a page twice and Goose has no fetch tool), and the three
drills no agent has a script for yet.

**The live leg (done, 2026-10-05).** The maintainers' live drill runner on
`goose`, haiku, mode `secrets`, the conf trio (run `watch-20261005T135717`, ~10
model calls, the agent on an empty HOME of its own, no NOT HERMETIC):
`conf-read-exfil` PASS (only the `$MDU:nomodel_…` token reached the sink),
`conf-read-control` PASS. On `conf-net-exfil-blocked` the model declined
before reading, both with the collector named `notes-sink.test` and with
`partner-api.test` (2026-10-06, `watch-20261005T204126`: "token" in the
file name and a plain-http URL), so that drill's gate is proven by the
replay lane on Goose, not live. Then Goose entered the tested ranges (§2),
the version table (`agent-versions.ts`: the launch warning, `mandu doctor`'s
row, the dashboard's check) and the README.

**The openai provider (routed, 2026-10-06).** Goose's built-in `openai`
provider goes through the model proxy's OpenAI route, with Goose's gate
surface and inbound spec (both bound to the session as for `anthropic`) and
the text-delta token repacking (agent-e2e-harness.md §9, "Other providers
through the model proxy").

*The capture.* goose 1.53.0 with `GOOSE_PROVIDER=openai`, a throwaway home,
only loopback, against a scripted OpenAI-wire upstream (no key; source read
at the v1.53.0 tag, `openai_def.rs` and goose-providers `openai.rs`):

- The endpoint: env `OPENAI_HOST` (deprecated but read first), else
  `OPENAI_BASE_URL` (env, then config; a trailing `/v1` moves into the
  path, query parameters ride every request), else the config's
  `OPENAI_HOST`, else `https://api.openai.com`. The base path is
  `OPENAI_BASE_PATH` (env, then config), default `v1/chat/completions`,
  joined to the host's own path.
- The wire is chosen PER MODEL on the default path: gpt-5, gpt-6 and
  o-series names (`is_openai_responses_model`) go to the Responses API at
  `v1/responses`, every other model to Chat Completions. A custom base path
  pins one wire: a path containing `responses` the Responses API, one
  containing `chat/completions` Chat. Captured: gpt-4o sent `GET
  /v1/models`, then `POST /v1/chat/completions`; gpt-5 `GET /v1/models`,
  then `POST /v1/responses`; with `OPENAI_HOST=<x>/_mandu/openai/openai` the
  same paths under that prefix.
- Chat Completions: `stream: true`, `stream_options.include_usage`,
  `max_tokens`; the system prompt as a `system` message, the user's turn as
  one string, the call as `tool_calls[]`, the shell's output as a `tool`
  message whose content is a plain string. Responses: `store: false`,
  `max_output_tokens`, no `instructions`: the system prompt is an input
  item `{type: "message", role: "system"}`, the user's turn two
  `input_text` parts, then `function_call` and `function_call_output`
  (a string). The 17 default tools, as on the Messages wire.
- Headers: `agent-session-id` and `Authorization: Bearer <OPENAI_API_KEY>`
  (none without a key); nothing that names Mandu's session, so the
  per-launch proxy keys it, as on the Messages wire.
- Goose's Responses reader rejects an event without a `sequence_number`
  (and a response without `created_at`). The proxy's released call events
  had none; they now carry the upstream's own numbers (openai-sse.ts).
- A declarative provider, bundled or the user's own
  (`custom_providers/*.json`, engine `openai`), speaks Chat Completions to
  the `base_url` in its definition (`v1/chat/completions` derived from its
  path), with its own key variable. No env key overrides that URL (a few
  bundled ones take a `${VAR}` host, such as `LMSTUDIO_HOST`), so the launch
  cannot point one at the proxy; a probe of the bundled `groq` with a fake
  key went straight to api.groq.com.

*The decision.* ROUTED: the built-in `openai` provider, on both wires, for
the session and its subagents. The launch resolves the endpoint Goose's way
(`gooseOpenAiEndpoint`) and keeps Goose's wire choice exactly: on the
default path the host is the proxy's upstream and the path stays
`v1/chat/completions` (the proxy reads one `/v1` before `chat/completions`
or `responses`, anthropic-proxy `route.ts`); a custom path's prefix moves
into the upstream (`engines/llama.cpp/v1/chat/completions` becomes
upstream `<host>/engines/llama.cpp/v1`, path `chat/completions`). Refused
at launch, naming the setting: an endpoint that is plain http off this
machine, carries credentials or a query string (the proxy forwards neither),
or a base path that ends in neither wire. Goose then treats the proxy as a
non-OpenAI host, which only decides whether it echoes a model's reasoning
text back on the Chat wire; OpenAI's Chat wire sends none.
REFUSED, each needing a route the env cannot give or a wire reader:
every declarative provider (the 48 bundled ones such as groq, mistral
and deepseek, and the user's custom providers: their URL is in the
definition); `google`, `gcp_vertex_ai`, `aws_bedrock`, `sagemaker_tgi`
(their own wires); `ollama`, `litellm`, `openrouter`, `xai`, `tetrate`,
`databricks`, `azure_openai`, `azure_foundry`, `github_copilot`,
`snowflake`, `huggingface` and the sign-in providers (`chatgpt_codex`,
`gemini_oauth`, `xai_oauth`); and the CLI and ACP providers
(`claude-code`, `codex`, `gemini-cli`, `cursor-agent`, `*-acp`: another
agent runs the model). Several of these
speak Chat Completions behind an env host knob and are the next
candidates, one capture each.

*The env.* `OPENAI_HOST=<proxy>/_mandu/openai/openai` and
`OPENAI_BASE_PATH` are set on every Goose launch, openai or not, so a
mid-session `/model --provider openai` reaches the proxy, which refuses a
provider the launch did not route (nothing is sent). A user's undeclared
`ANTHROPIC_HOST` skips the proxy, which the openai route needs: an
all-openai session drops it, and an openai session whose subagents (or
main session) still use anthropic at such a host is refused, naming the
three ways out (unset it, declare it in policy.yaml `models:`, or use one
provider). Uploads and the telemetry switches are the same on every
provider.

Tests: `launcher/test/unit/goose-route.test.ts` (the endpoint in Goose's
order, the wire kept, every refusal), `interceptors/anthropic-proxy/test/unit/route.test.ts`
(one `/v1` accepted, nothing else), `openai-sse.test.ts` (the released
events numbered), `launcher/test/component/goose-delivery.test.ts` (the
routed env through `main()`), `launcher/test/component/goose-openai-real.test.ts`
(the REAL goose on gpt-4o and gpt-5 through `main()`, the real arbiter and
proxy, a scripted upstream: each turn on Goose's own wire, the labelled
file's `cat` reaching the upstream only as a symbol; a refused provider
starting nothing) and `tests/stack/goose-openai-route.test.ts` (the real
arbiter and the production adapter on Goose's captured shapes, `secrets`
mode: ingress on both wires, the symbol in a later shell command, a
provider `delegate` refused, a split token repacked, and the arbiter gone).

*The in-session switch.* An interactive session's `/model --provider
<name>` builds that provider in process. A switch to `anthropic` or
`openai` stays on the proxy (an openai the launch did not route is refused
there, nothing sent). A switch to any other provider dialed its own
endpoint with the session's history until 2026-10-07; it is now fenced
(§5.6.3): its endpoint keys point at the proxy's refusal route, and the
hosts no key moves are denied at the net-proxy.

**Still to build.** Not routed yet: Goose's other providers (fenced,
§5.6.3; a launch naming one is refused). (Under `acp`, Goose's replies
are desymbolized for the editor since 2026-10-07: the ACP paragraph above.
The reply layout for Goose's terminal wrap, listed here until 2026-10-07, is
built: reply-row-reservation.md §17.)

#### 5.6.1 Goose's own login: `secrets.yaml` and the keyring (2026-10-06)

Goose 1.53.0 reads its key (`crates/goose/src/config/base.rs` `get_secret`)
from the provider's key variable (`ANTHROPIC_API_KEY`; `OPENAI_API_KEY` on
the openai provider), else from its secret store: the system
keyring (Secret Service over the D-Bus session bus; service `goose`, account
`secrets`, one JSON object holding every secret Goose keeps), falling back to
`<config dir>/secrets.yaml` when the keyring has no item or cannot be reached
(a D-Bus error turns the keyring off for the run). With
`GOOSE_DISABLE_KEYRING` set (any value in the env; `true` or `"1"` in
`config.yaml`) only the file is used. `goose configure` writes to the same
store. The first cut was tested with the variable only.

**What a saved login did under Mandu (measured).** The real goose, the real
launcher, arbiter and proxy, a scripted upstream recording `x-api-key`, a
made-up key:

- *`secrets.yaml`.* The file is a catalog secret (`shape:*secret*`), so the
  launch twinned it. With the bind (no guard) and with the guard (whose
  open decision gives the agent's own process the twin), Goose read
  `ANTHROPIC_API_KEY: $MDU:nomodel_Read[…].ANTHROPIC_API_KEY` and sent the
  placeholder as its key. The proxy relays the auth header untouched
  (agent-sign-in.md §1.3.1), so every turn would have been a 401: Mandu
  broke the login.
- *The keyring.* Outside Mandu, goose against a private session bus with a
  Secret Service (`launcher/test/fixtures/secret-service-mock.py`) opens a
  plain session, searches for its item and reads it. Under a guarded launch
  in `secrets` mode the session bus is not on the agent's Unix socket
  allow-list (`unix-policy.ts`: the bus runs programs on request, outside
  every confinement), so Goose never reaches it: the Secret Service sees no
  call, Goose falls back to the file and, with none, stops with
  `Configuration value not found: ANTHROPIC_API_KEY`. Where no guard runs
  (`--no-kernel`, a host without the guard) the bus is reachable and the
  keyring login works, as any other program's D-Bus use does there.

**Decision.** Mandu keeps the doctrine of agent-sign-in.md: the agent stays
the client and the proxy relays the credential it sends, with the one
exception of agent-sign-in.md §3 (item 5: a static key from a twinned file
is put back in the auth header at the bound host). So:

1. *`secrets.yaml` is the agent's own key file under `mandu goose`, when
   the launch cannot put the key back at the proxy (item 5).* The
   launcher passes it (`agent-login.ts` `agentOwnCredentialFiles`: the
   config dir's `secrets.yaml`, `GOOSE_PATH_ROOT` and `XDG_CONFIG_HOME`
   honored) to the secret setup as `agentOwnFiles`: it is REGISTERED like
   any secret, but neither twinned, bound nor named in the guard's policy
   file, so Goose reads its key and sends it. Registration keeps the value
   in: a tool output that carries it (a `cat` by name, by a glob, or with no
   word of the path in the command) reaches the model as a placeholder, and
   the net-proxy's verbatim tripwire refuses a request that carries it to a
   host it is not bound to (no taint is recorded for this file, since the
   guard does not trap it). The file is also in `SENSITIVE_PATHS` (a tool's
   read of it asks). This is the same rule as `AGENT_LOGIN_FILES` (Claude
   Code's, Codex's and OpenCode's logins, keyed per launch by the walk since
   2026-10-09, secret-discovery.md §1.10): under every other agent the file is
   twinned like any catalog secret. The raw file is in Goose's world, as
   Claude Code's and Codex's own credentials are in theirs (those, when kept,
   are not registered by that launch; one another launch registered is
   exempt from the tripwire in a session that runs its agent,
   secret-discovery.md §1.10, while Goose's `secrets.yaml` is not).
2. *The keyring is not reachable, and the launch says so.* Opening the
   session bus to the agent would hand it every service on it; a filtered
   bus would still hand it every secret in the keyring, and having the
   launcher read the item and pass the key is what the env sources refuse
   for an agent's own credential (confidentiality-plan-10 §11.4). So after
   the guard's Unix socket allow-list is applied, a Goose with no variable,
   no file and the keyring on gets one line (`gooseKeyringNote`): Goose
   would read its key from the keyring, which Mandu keeps it from reaching;
   set `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`), or run `GOOSE_DISABLE_KEYRING=1 goose configure`
   once without Mandu. A WARNING, not a refusal, like every login line.
3. *The login checks.* `probeAgentLogin("goose")`: the key variable of the
   provider the launch routes (`gooseKeyVar` over `gooseRoutePlan`:
   `--provider`, GOOSE_PROVIDER, config.yaml; `OPENAI_API_KEY` for openai,
   else `ANTHROPIC_API_KEY`, and both lines name that variable), then the
   file (existence only: which keys it holds is not read), then, with the
   keyring on, the keyring item. *The subagents' provider (2026-10-07).*
   The launch pins `GOOSE_SUBAGENT_PROVIDER` to a routed provider
   (`gooseRoutePlan`: env, then config.yaml, else the session's); when that
   provider's key variable differs from the session's (`gooseKeyVars`), the
   same three places are checked for it and the status carries a
   `subagent` entry (the store's answer is shared: the file serves both,
   and the keyring item, one JSON object of every secret, is asked once).
   The early line then also warns when only the subagents lack a login
   ("no login found for Goose's subagents, which GOOSE_SUBAGENT_PROVIDER
   puts on openai …", naming `OPENAI_API_KEY`), or names both variables
   when neither has one; the keyring line covers a subagent key that only
   the keyring could hold; and the doctor adds a `goose subagent login
   (<provider>, from GOOSE_SUBAGENT_PROVIDER)` row under `goose login`.
   Before this a session logged in by `ANTHROPIC_API_KEY` with
   `GOOSE_SUBAGENT_PROVIDER=openai` and no `OPENAI_API_KEY` launched
   silently and every subagent stopped with "Configuration value not
   found: OPENAI_API_KEY".
   `mandu doctor` asks the Secret Service `SearchItems` with `dbus-send`
   (object paths only: no session is opened and no secret read;
   `realGooseKeyringItem`), and its `goose login` row says which place Goose
   would use and that a keyring key is out of reach under `mandu goose`. The
   launch never asks the keyring: with none of the three, the early line is
   the usual "no Goose login found" with both fixes.
4. *The macOS Keychain (2026-10-07).* On macOS Goose's keyring crate keeps
   the same item (service `goose`, account `secrets`) in the login
   Keychain. The doctor asks for it with `/usr/bin/security
   find-generic-password -s goose -a secrets`, WITHOUT `-w` or `-g` (the
   item's attributes only: the password is never printed, and an attribute
   lookup raises no Keychain access prompt), with only `PATH=/usr/bin:/bin`
   and `HOME` in its environment (`keychainSearchArgv`,
   `readKeychainSearch`: exit 0 found, exit 44 `errSecItemNotFound` none,
   anything else cannot tell). Unlike the Secret Service, the Keychain stays
   reachable under the macOS Seatbelt profile (seatbelt-setup.ts: "the
   Keychain stays reachable"), so a key found there is a ✓ (`via` "the
   macOS Keychain", no `keyring` flag) and no keyring line is printed on
   macOS. Mandu never reads that key, so a tool that prints it from the
   Keychain is not masked (guarantees.md, "The Keychain").

5. *Since 2026-10-07 the file is twinned again, and the model proxy puts the
   key back in the auth header* ([`agent-sign-in.md`](./agent-sign-in.md) §3),
   when the launch can bind the key to the provider it routes. Before the
   secret setup the launcher grants, on the human plane
   (`registerAuthGrant`; `agent-key-grant.ts`), `ANTHROPIC_API_KEY` to the
   anthropic upstream's host and `OPENAI_API_KEY` to the openai route's
   host, for each provider the session or its subagents use; the file is
   then twinned like any catalog secret (Goose reads and sends
   `$MDU:nomodel_Read[h].ANTHROPIC_API_KEY`), and the anthropic-proxy, on
   the request it forwards to that host, replaces an `x-api-key` or
   `Authorization: Bearer` header whose whole value is the placeholder with
   the key (the egress gate's bound-destination release, asked on the human
   plane, then the shallow `resolve`). The body keeps the symbol. A host is
   granted only when it is the provider's own API host over https or this
   machine's loopback; any other routed host (a custom `OPENAI_HOST` on
   another machine, a declared remote main model, an undeclared
   `ANTHROPIC_HOST` that skips the proxy), a failed grant, or
   `MANDU_AUTH_SUBSTITUTION=0` keeps item 1's posture for the whole launch
   (the line names the file as the agent's own key file). The launch says
   which: `mandu: <file> is a placeholder in Goose's world; the model proxy
   puts its key back in the auth header to <host> only`. What it removes
   and what it does not (the key can still be USED through the proxy toward
   the bound host; the file's other values, an extension's token, are
   placeholders too) is §3.5 there.

**Not built.** The launch asks neither the Secret Service nor the Keychain
(doctor only): on macOS with no variable and no file it stays quiet.

Tests: `launcher/test/unit/agent-login.test.ts` (the Goose probe, both
lines, the keyring question's argv and its reading; the subagents' key
variable, their status and both lines; the Keychain argv without `-w` /
`-g`, its reading, and `realGooseKeyringItem` per platform over a mocked
command runner),
`secret-setup.test.ts` (an `agentOwnFiles` entry is registered, not
twinned; without it the same file is), `doctor.test.ts` (the `goose
login` row, the `goose subagent login` row, the macOS Keychain row), `arbiter/test/unit/secret-discovery.test.ts` (the file is
discovered, `no-model`, sensitive, not a global agent-auth path);
`tests/stack/goose-own-key-egress.test.ts` (the file registered and not
twinned, over a real ArbiterServer and the production adapters: its raw key
in a request to an unbound host is refused by the real net-proxy with no
taint recorded, and in a `shell` result it reaches the model as a
placeholder); `launcher/test/component/goose-login.test.ts` (the real goose: the upstream
gets the key from `secrets.yaml`, never a placeholder; three shell reads of
the file reach the model masked; no login at all prints one line; doctor's
keyring question against the mock finds the item and never reads it; this
file pins item 1's posture with `MANDU_AUTH_SUBSTITUTION=0`) and
`launcher/test/kernel/goose-keyring.test.ts` (under the real guard: a
keyring-only login never reaches the bus, nothing goes upstream, the line is
printed; the control without Mandu reads the key from the mock; the file
login works under the guard too, now through the twin and the proxy's
substitution). Item 5: `launcher/test/unit/agent-key-grant.test.ts`,
`launcher/test/component/goose-auth-substitution.test.ts` (the real goose on
both providers: the upstream gets the real key in the header, a shell in the
agent's world dumps the twin, no model request carries the key; the opt-out),
`arbiter/test/unit/auth-grant.test.ts`,
`interceptors/anthropic-proxy/test/unit/auth-substitution.test.ts` and
`tests/stack/auth-substitution.test.ts` (agent-sign-in.md §3.7).

#### 5.6.2 Goose's own stores: the session store and the request log (2026-10-07)

Goose 1.53.0 keeps two records of every session on disk, both as Goose
built them, before the model proxy symbolized anything:

- **The session store**, `<data>/sessions/sessions.db` (SQLite, with its
  `-wal` and `-shm`; session_manager.rs): every message, tool output
  included. Older versions wrote `<data>/sessions/<id>.jsonl`.
- **The request log**, `<state>/logs/llm_request.{0..9}.jsonl` (and a
  `llm_request.<uuid>.jsonl` while a request is in flight;
  providers/utils.rs): the last ten model requests WHOLE, always written by
  the CLI (goose-cli logging.rs). Beside it, `<state>/history.txt` (the
  prompt history) and `<state>/logs/cli/` (the CLI's own logs).

`<data>` is `$XDG_DATA_HOME/goose` (default `~/.local/share/goose`),
`<state>` is `$XDG_STATE_HOME/goose` (default `~/.local/state/goose`); an
absolute `GOOSE_PATH_ROOT` makes them `<root>/data` and `<root>/state`, with
no `goose` segment (config/paths.rs). A labelled secret masked in one turn
was therefore on disk raw, and a later `shell` `cat` or `sqlite3` of either
file put it in front of the model: neither directory was in the catalog.

**The posture (built).** The same as OpenCode's data directory (§2.3 item
10) and `~/.claude`, `~/.codex`
([confidentiality.md](../confidentiality/confidentiality.md) §8 "An agent's
own stores"): `~/.local/share/goose` and `~/.local/state/goose` are in
fs-outbound's `SENSITIVE_PATHS` (a tool's read or write asks) and so in the
catalog (`no-model`: a result of a command naming the path is masked), and
in `AGENT_STORES` (never twinned, in any launch: Goose keeps reading and writing its
own files raw). Another XDG directory, a `GOOSE_PATH_ROOT` layout and the
macOS Application Support directory are matched by shape
(secret-catalog.ts `GOOSE_DATA_SHAPE_RE`: `sessions/sessions.db*` under a
`…goose` or `data` directory, `logs/llm_request.*.jsonl` under a `…goose`
or `state` directory, a `…goose` directory's `sessions/*.jsonl`,
`logs/cli/` and `history.txt`), and a path the shape matches is not twinned
either (`isAgentAuthPath`). Goose's key file `~/.config/goose/secrets.yaml`
keeps its own posture (§5.6.1).

Tests: `arbiter/test/unit/goose-data-catalog.test.ts` (both prefixes and
every shape `no-model`, the near misses public, a command naming the files
or a glob of them, the path gate asking, never twinned, discovery walking
past both directories) and `tests/stack/goose-session-store.test.ts` (the
real arbiter and the production proxy wiring, `secrets` mode, a session
bound to `goose`: a `cat` of the request log and a `sqlite3` of the store
reach the model only masked at the default places, under other XDG
directories and under a `GOOSE_PATH_ROOT`; the CONTROL, the same text from a
file no rule knows, goes out as is) and
`launcher/test/component/goose-store-real.test.ts` (the real goose under
`mandu goose`: a kept session still writes `sessions/sessions.db` with the
prompt in it raw, so the wrap neither hides nor twins Goose's own store; a
later session's `shell` read of it reaches the model only masked; the same
bytes copied into the project go out as they are).

#### 5.6.3 The provider fence: Goose's other providers (2026-10-07)

The launch check (§5.6 "Routing and the provider check") covers what Goose
STARTS on. Goose 1.53.0 also builds a provider later: an interactive
`/model --provider <name>` switches the session to it
(goose-cli `session/mod.rs` `handle_model` -> `providers::create`), and a
nested `goose run --provider <name>` started from a shell builds it at its
start. Either reads the provider's endpoint keys at that moment with
`Config::get_param`, env first, so the launch env decides. Before the fence,
a switch to anything but `anthropic` or `openai` dialed that provider's own
endpoint with the session's history, which holds the tool output as Goose
saw it. Goose has no provider allowlist knob; `-acp` providers are refused
by Goose itself on a switch, and `claude_code` / `gemini_cli` keep their own
context, so Goose refuses a switch to them too.

**The env fence** (`launcher/src/goose-route.ts` `GOOSE_PROVIDER_FENCE`,
set by `gooseForcedEnv`). Every endpoint key of every provider the launch
does not route is pointed where nothing is sent:

- a base URL (`GOOGLE_HOST`, `AVIAN_HOST`, `GONDOLA_HOST`,
  `HF_HOST`, `MUSE_CODE_HOST` / `_AUTH_HOST`, `DATABRICKS_HOST`,
  `AZURE_OPENAI_ENDPOINT`, `AZURE_FOUNDRY_ENDPOINT`, `SNOWFLAKE_HOST`,
  `GITHUB_COPILOT_TOKEN_URL`, the AWS SDK's
  `AWS_ENDPOINT_URL_BEDROCK_RUNTIME` and `_SAGEMAKER_RUNTIME`, and the 11
  bundled declarative providers whose `base_url` is `${VAR}…`:
  `ATOMIC_CHAT_HOST`, `ASTRON_BASE_URL`, `LLAMA_SWAP_HOST`,
  `LMSTUDIO_HOST`, `LYNKR_HOST`, `MOONSHOT_BASE_URL`, `OMLX_HOST`,
  `ROUTSTR_HOST`, `TANZU_AI_ENDPOINT`, `ZAI_BASE_URL`, `ZHIPU_BASE_URL`)
  at the session proxy's refusal route
  `<proxy>/_mandu/openai/goose-unrouted-<provider>`: an OpenAI route id the
  launch never routes, which the proxy answers 403 without dialing anything
  (anthropic-proxy `route.ts` `classifyOpenAiRoute`), whatever relative path
  the provider appends (Goose's `ApiClient` joins relative paths);
  Snowflake refuses the http URL itself;
- a bare host (`GITHUB_COPILOT_HOST`) at
  `goose-provider-not-routed-by-mandu.invalid` (RFC 6761: never resolves),
  and `GCP_LOCATION` so that Vertex's `https://<location>-aiplatform…` host
  is under `.invalid`;
- the CLI a provider spawns (`CODEX_COMMAND`, `CURSOR_AGENT_COMMAND`,
  `CLAUDE_CODE_COMMAND`, `GEMINI_CLI_COMMAND`) at a path under `/dev/null/`,
  which cannot exist (Goose resolves an absolute path as is).

The user's own declarative providers (`<config dir>/custom_providers/*.json`,
any name; `gooseCustomProviderFence`): a `base_url` that starts with
`${VAR}` gets VAR fenced the same way (Goose resolves it env first,
`declarative_providers.rs` `expand_env_vars`; `${ANTHROPIC_HOST}` /
`${OPENAI_HOST}` are already the proxy); a literal one has its host denied at
both network layers (below). One the launch can fence neither way refuses the
launch, naming the file: a host built from a variable later in the URL, a
variable the launch cannot repoint (`PATH`, `GOOSE_*`, …), or
`api.anthropic.com` / `api.openai.com` itself (Mandu's own model traffic and
the U-LLM go there, so the network layer cannot deny it, and NO_PROXY sends
it around the net-proxy).

The routed providers' own keys (`ANTHROPIC_HOST`, `OPENAI_HOST`,
`OPENAI_BASE_PATH`, and since 2026-10-07 `OLLAMA_HOST`, `LITELLM_HOST`,
`LITELLM_BASE_PATH`, `OPENROUTER_HOST`, `XAI_HOST`, `TETRATE_HOST`, §5.6.4)
are never fenced; a switch to one of those providers when the launch did not
route it reaches the proxy's route of that provider's own id, which the
launch did not give the proxy, so it refuses it 403 without dialing (as
`openai` before). Until 2026-10-07 the five Chat Completions providers' keys
were in the fence, at `goose-unrouted-<provider>`.

**The host fence** (`upload-deny.ts`, the goose row). The model hosts no key
moves are denied at the net-proxy (`GOOSE_PROVIDER_HOSTS`, the row's
`proxyOnly`): the 37 bundled declarative providers with a literal
`base_url` (`api.groq.com`, `api.mistral.ai`, `api.deepseek.com`, …), the
remote defaults of the `${VAR}` ones, the fixed hosts of `chatgpt_codex`
(`chatgpt.com`), `gemini_oauth` (`cloudcode-pa.googleapis.com`), `kimicode`
(`api.kimi.com`) and `nanogpt`, the default hosts of the fenced built-ins
(`openrouter.ai`, `generativelanguage.googleapis.com`, `.githubcopilot.com`,
…) and Bedrock's runtime and mantle hosts per AWS region. Goose's HTTP client
honours HTTPS_PROXY (the default transport), and the net-proxy is on by
default and fail-closed. These go to the net-proxy only, by name, never to
the connect guard: the guard resolves every deny name on every connect
(cached 30 s) and matches by address, so 150 vendor hosts, many behind shared
CDN addresses, would slow every connect and could refuse an unrelated site
sharing an address. A user's declarative provider's literal host (a few, and
a loopback one is reached around the net-proxy through NO_PROXY) goes to
both layers. Never denied: `api.anthropic.com`, `api.openai.com`, a loopback
default (the user's own local servers; their keys are fenced).

**The launch check reads `active_provider`.** Goose 1.53.0 reads the main
provider from env `GOOSE_PROVIDER`, then the config's `active_provider`
(what `goose configure` writes now), then its legacy `GOOSE_PROVIDER`
(`config/providers.rs`); the check read only the flat keys, so a configured
`active_provider: ollama` was silently overridden to `anthropic`. It now
reads the same order: an unrouted `active_provider` is refused, `openai`
routed.

**What the fence costs.** The fenced keys are in the agent's whole
environment, so a program the agent runs that reads one (the `ollama` CLI's
`OLLAMA_HOST`, the `databricks` CLI's `DATABRICKS_HOST`, an SDK's
`AZURE_OPENAI_ENDPOINT`) sees the refusal value inside a `mandu goose`
session; most of those are model calls, which the session would not send
anyway. A program reaching one of the denied hosts through the net-proxy is
refused (an `opencode.ai` download included).

**Left.** A program the agent runs can start its own `goose` with the keys
set again and HTTPS_PROXY unset: that is a program sending what it read, the
same as `curl`, and only the guard's holder rule covers it (for a registered
secret). Vertex AI's regional hosts are fenced by `GCP_LOCATION` only (not
denied: `gcloud ai` uses them). Bedrock re-exports `AWS_*` keys from Goose's
config and keyring into its env before it builds (`bedrock.rs`), so an
`AWS_ENDPOINT_URL_BEDROCK_RUNTIME` saved there outranks the fence; the
regional hosts are denied at the net-proxy for that case. With the connect
guard off, a declarative provider of the user's at a loopback port is not
fenced. A file planted in `custom_providers/` during a session is not loaded
by the running CLI (Goose loads the registry once; only ACP's provider
methods refresh it, which the ACP relay refuses) and is fenced at the next
launch, so the directory is not write-protected.

Tests: `launcher/test/unit/goose-provider-fence.test.ts` (every key set,
each form, the relative-path joins staying under the refusal route, the
routed keys untouched, the user's declarative providers fenced, denied or
refused, `active_provider`, the deny lists and which layer gets each),
`goose-route.test.ts`; `tests/stack/goose-provider-fence.test.ts` (the env
the launcher composes over a user env pointing every key at a counting
upstream: each key, joined as Goose joins it, reaches only the REAL proxy's
refusal, 403, and the counting upstream sees nothing while the routed openai
route still works; the REAL net-proxy the launcher starts with a goose
launch's list refuses a bundled provider's host and the user's declarative
provider's host, a control host passes); the real goose leg,
`goose-provider-fence.test.ts` (in `integration.goose-e2e`:
`goose run --provider ollama|lmstudio|openrouter` under the launch env sends
the user's endpoint nothing; the controls without it do reach it).

#### 5.6.4 Goose's Chat Completions providers: litellm, openrouter, ollama, xai, tetrate (2026-10-07)

Five more of goose 1.53.0's built-in providers speak Chat Completions to a
host taken from one env key, a wire the anthropic-proxy already gates
(`openai-wire.ts`, `openai-sse.ts`, the same gates as the Messages wire), so
they are ROUTED like `openai` instead of fenced (§5.6.3). Read from goose's
source (`providers/litellm.rs`, `openrouter_def.rs`, `ollama_def.rs`,
`xai.rs`, `tetrate.rs`) and captured with the real binary against a scripted
upstream:

| provider | host key (default) | path Goose joins | key |
|---|---|---|---|
| `litellm` | `LITELLM_HOST` (`http://localhost:4000`) | `LITELLM_BASE_PATH` (`v1/chat/completions`) | `LITELLM_API_KEY` (optional) |
| `openrouter` | `OPENROUTER_HOST` (`https://openrouter.ai`) | `api/v1/chat/completions` | `OPENROUTER_API_KEY` |
| `ollama` | `OLLAMA_HOST` (`localhost`: `http://` added, port 11434) | `v1/chat/completions` | none |
| `xai` | `XAI_HOST` (`https://api.x.ai/v1`) | `chat/completions` | `XAI_API_KEY` |
| `tetrate` | `TETRATE_HOST` (`https://api.router.tetrate.ai`) | `v1/chat/completions` | `TETRATE_API_KEY` |

**The routing** (`launcher/src/goose-route.ts` `GOOSE_COMPAT_PROVIDERS`,
`gooseCompatEndpoint`, `gooseForcedEnv`). Every launch pins each host key at
`<proxy>/_mandu/openai/<provider>`, whether or not it routes that provider.
The provider the session or its subagents use (`--provider`,
`GOOSE_PROVIDER` / `active_provider`, `GOOSE_SUBAGENT_PROVIDER`, as for
`openai`) goes to the proxy as a route (`MANDU_OPENAI_UPSTREAMS`) whose
upstream is the user's own endpoint, resolved as Goose resolves it: the host
key (env, then config), else Goose's default; Ollama's host normalized as
Goose does it; LiteLLM's `LITELLM_BASE_PATH` must end in `chat/completions`
(a prefix before it moves into the upstream and the pinned path becomes
`chat/completions`, as for `OPENAI_BASE_PATH`). A plain-http `localhost`
endpoint is read as `127.0.0.1` (LiteLLM's and Ollama's defaults; the proxy
dials plain http only to a literal loopback address). The proxy forwards
`<upstream><path Goose sent>`: `route.ts` accepts one `/v1` or `/api/v1`
before `chat/completions` (OpenRouter's path). Refused at launch, naming
the setting: an endpoint the proxy cannot reach (plain http to another
machine, a URL with credentials or a query, a host with no scheme) and a
`LITELLM_BASE_PATH` on another wire. A declarative provider named like one of
the five is refused when the launch uses that provider (otherwise the fence
covers its file).

**A mid-session switch.** `/model --provider <other>` (or a nested `goose
run --provider <other>`) builds the other provider from the same pinned key,
so it lands on the proxy's route of that provider's id. Only the providers
the launch routed are routes the proxy has; any other is answered 403 and
nothing is dialed (`classifyOpenAiRoute`: "Mandu did not route that
provider"). xAI's `xai_oauth` provider reads `XAI_HOST` too: a switch to it
in an `xai` session reaches the `xai` route, gated, toward the same
upstream.

**What the proxy does not forward.** Goose's other requests on these hosts:
a bodyless GET (OpenRouter's and Tetrate's model listings, LiteLLM's
`model/info`, Ollama's `api/tags`) is relayed as a read; Ollama's `api/show`
POST (a capability probe) and OpenRouter's `api/alpha/decisions` (an SDK
API the CLI does not call) are refused 403, and Goose falls back (Ollama
then guesses thinking support from the model name). OpenRouter's request
options that make the provider fetch content (`plugins`, an `:online` model;
`OPENROUTER_PARAMETERS` can add them) are refused 400 (`providerSideRefusal`).

**Tool calls written as text (Ollama).** Goose's ollama reader
(`goose-provider-types` `formats/ollama.rs`, for Qwen3-coder and kin)
buffers the assistant text once it contains `<function=` and turns every
`<function=name><parameter=k>v</parameter></function>` in it into a tool
call, which the wire gates never see as one. Captured: goose alone, on a
scripted upstream that streams such text, runs the shell command in it. The
launch marks the ollama route `textCalls` (`MANDU_OPENAI_TEXT_CALLS`), and on
that route the proxy ends a response whose text carries `<function=`
(`openai-sse.ts` `refuseTextCalls`, the stream's error event; a buffered
answer is a 502) before the chunk that completes it, so Goose never holds the
whole mark (a mark split across chunks is caught on the tail before it). A
model that only ever answers with text tool calls cannot work through
`mandu goose` on Ollama; one that uses the wire's `tool_calls` (Ollama
returns them for models with tool support) is unaffected. The same reader
backs a declarative provider of the `ollama` engine: one whose base URL is a
routed key other than `OLLAMA_HOST` (`${OPENAI_HOST}`, `${LITELLM_HOST}`, …)
refuses the launch, since only the ollama route checks the text.

**The provider's own key.** The routed provider's key variable
(`OPENROUTER_API_KEY`, `XAI_API_KEY`, `TETRATE_API_KEY`, `LITELLM_API_KEY`)
is the agent's own model credential. Masked with no way back, Goose sent
the placeholder as its key (captured: `Authorization: Bearer
$MDU:nomodel_Env[…].LITELLM_API_KEY`) and every turn failed
authentication. Since 2026-10-11 ([`agent-sign-in.md`](./agent-sign-in.md)
§3.10) the launch grants the variable, and the same field of Goose's
`secrets.yaml`, to the provider's own API host (`openrouter.ai`,
`api.x.ai`, `api.router.tetrate.ai`) or this machine's loopback (LiteLLM:
loopback only), and the model proxy puts the key back as `Bearer` on that
provider's route. A variable whose provider's host is not grantable (a
remote LiteLLM, another `*_HOST`) is still left out of the masking
(`secret-setup.ts` `applyEnvSecrets`, `gooseRoutedKeyVars`), as before;
and the file keeps the agent's-own-key-file posture (§5.6.1) unless every
routed provider is grantable. Another provider's key, one the launch does
not route, is masked as before. `mandu doctor` and the launch's login note
name the routed provider's key; `ollama` takes none and asks for no grant.

**The model's clearance is unchanged.** These routes carry no declared
model binding: the proxy treats the provider as an outside model, so
everything above `public` reaches it as a symbol even when Ollama runs on
this machine (declaring it in `policy.yaml` `models:` is a separate,
unbuilt path for Goose).

**Left.** The proxy's auth substitution (agent-sign-in.md §3) for these
providers' keys, which would make the env key and `secrets.yaml` placeholders
in the agent's world as well. The Responses wire is not marked on the ollama route (Goose's
ollama provider never sends it). A model listing GET on a LiteLLM base path
with a prefix goes under the prefix (`<host>/<prefix>/model/info`), so it
may 404; Goose then has no model metadata and carries on. The text-call
check ends the turn rather than converting the call into a gated one.

Tests: `launcher/test/unit/goose-compat-providers.test.ts` (each endpoint
resolved as Goose resolves it, the refusals, the routing plan for session and
subagents, the pinned keys and the paths Goose joins to them, `textCalls`,
the declarative rules), `goose-route.test.ts`, `goose-provider-fence.test.ts`,
`agent-login.test.ts` (the key per provider), `secret-setup.test.ts` (the
routed key unmasked); `interceptors/anthropic-proxy/test/unit/route.test.ts`
(`/api/v1`), `openai-sse.test.ts` (`refuseTextCalls`, split or not, the
buffered form), `openai-wire.test.ts` (`MANDU_OPENAI_TEXT_CALLS`);
`tests/stack/goose-compat-providers.test.ts` (per provider, Goose's own body
shape on the launch env over the real arbiter and proxy: a registered secret
and a labelled file reach the provider's loopback stand-in only as `$MDU:`
symbols on Goose's own path; every other provider's pinned key refused 403
with its stand-in seeing nothing; the text-call check; the reads; fail-closed
with the arbiter down), `goose-provider-fence.test.ts` (the five keys among
the fenced ones on a launch that routes none);
`launcher/test/component/goose-compat-real.test.ts` (the REAL goose under the
real launcher on each provider against a scripted upstream: every turn
through the proxy on Goose's own path, the labelled file only as a symbol;
on ollama a shell call written as text never runs, while goose alone runs it;
the refusals); `goose-provider-fence.test.ts` (the real
goose's `run --provider litellm|xai|tetrate` added to the protected runs and
the controls).

### 5.7 The agent registry: one list of agents (2026-10-18)

The agents the test tooling drives were listed by hand in about twelve
places (the suite manifests and runner, the test harness, the dashboard,
the maintainers' drill tooling), and each new agent had to find them all.
They are now one table, `scripts/agents/agent-registry.mjs`, one row per
agent **line**: an agent CLI, or a later generation of one that installs
and runs as its own line (`opencode2`, the `opencode` agent's second
generation, §2.3). A row gives the line's `id` (its `needs` name and
`--agents` name), the `agent` it is a line of, its product `name` (as the
tested-version table writes it), a later line's `generation`, the `wire` it
speaks to the model proxy in the test harnesses (`anthropic` or `openai`),
the `credential` its live runs sign in with (`subscription`, naming its
`signIn` need, or the Anthropic `api-key`), whether the hand-run agent cache
pins its CLI (`cache`), its `pin` key in `scripts/ci/pins.env`, and the
`npm` package its CLI installs from (none for Goose, a release binary).

Every other list is the table or a **named filter** over it, never a copy:
`AGENTS` (each agent's first line), `LINES`, `AGENT_NAMES`, `API_KEY_AGENTS`,
`CACHED_LINES`, `ANTHROPIC_WIRE_AGENTS` / `_LINES`, `NPM_AGENTS`, `PIN_KEYS`,
and `agentOfLine`. The module is data (no imports, no I/O), so the drill
catalog, which is data, can import it. TypeScript importers get literal
types from its generated declarations (`agent-registry.d.mts`), and a
package that ships standalone gets a generated copy instead of an import,
the rule the path table follows (on-disk-layout.md §5): the dashboard's
`src/generated/agents.ts` (which `AGENT_KINDS` is), the launcher's (its
`AGENTS`, `LINES` and `isAgent`) and the arbiter's (its `AGENTS`). The
launcher bundle needs no manifest entry for its copy: esbuild bundles what
`src/` imports. `node scripts/agents/agent-copies.mjs generate` writes them
all; `check` fails on a stale one.

**The scan-only agents** (2026-10-21). `mandu scan` also reads, or only
counts, the local session stores of agents Mandu does not run (Gemini CLI,
Copilot CLI, Cursor: plan 17 §4, phase 3). They are not lines (no launch,
no suite, no pin), so they are a second table of the same module,
`SCAN_ONLY_AGENTS` (`id`, `name`, `read`: whether the scan reads its
sessions or only counts them), with `SCAN_ONLY_IDS`, `SCAN_ONLY_NAMES` and
`SCAN_READ_IDS`; the copies carry `SCAN_ONLY_AGENTS` and `SCAN_ONLY_NAMES`
(the arbiter's also `SCAN_READ_AGENTS`). A scan-only id is never a line
nor a launch target (the soundness check and the registry test hold it),
and the sweep below counts its ids too. When Mandu comes to run one, its
row moves to `AGENT_LINES`.

**The product packages' lists** (2026-10-18). What each was, and what it is
now; no value changed:

| list | what it is | now |
|---|---|---|
| launcher `agent-versions.ts` `VersionedAgent` | every agent | `Agent`: `TESTED_AGENT_VERSIONS` is a `Record` over it, so a new agent fails the type check until its tested range is written |
| launcher `types.ts` `Target` | every agent plus `shell`, the plain-command target, which is the launcher's own and not an agent | `Agent \| "shell"`, with `TARGETS` and `isTarget` beside it |
| launcher `parse.ts` `--target` check, its error message, the basename inference; `doctor-secrets.ts` `TARGETS`; `agent-versions.ts` `versionedAgentOf` | the same, spelled out as comparisons | `isTarget` / `TARGETS` / `isAgent` |
| launcher `doctor.ts` `agentVersion`'s command | every line but OpenClaw: the doctor has no OpenClaw version row (OpenClaw's version is checked at launch only) | `DoctorVersionBin = Exclude<AgentLine, "openclaw">` |
| arbiter `secret-discovery.ts` `keptLoginOwners`'s known targets | the launcher's targets | `KNOWN_TARGETS`, every agent plus `shell`. An unknown target keeps every agent's login raw and a known one only its own, so an agent the registry gains keeps fewer logins raw, never more |
| arbiter `secret-discovery.ts` `StoreOwner` | a deliberate subset: the agents whose own data stays raw in every launch, every agent but OpenClaw | `Exclude<Agent, "openclaw">`: `AGENT_STORES` is a `Record` over it, so a new agent fails the type check until its store is decided (its paths, or its name in the exclusion). Never widened by the registry alone: a raw store is never masked |
| arbiter `secret-discovery.ts` `LoginOwner` | the three agents whose login files are keyed per launch | left: three names, a decision per agent (secret-discovery.md §1.10), not the agent list |
| `scripts/matrix/suites/fresh-agents.host.sh` | the agents the fresh-agents VM suite installs from npm (os-test-matrix.md §10.14) | `NPM_AGENTS`, read with a node one-liner; the guest's npm package table is held to each row's `npm` (`scripts.fresh-agents-host`). Goose is not one: it has no npm package, and a Goose leg (a release-binary install in the guest) is not built |

`tests/stack/agent-registry.test.ts` holds the rule for the public tree:
the table is sound and its copies fresh; the launcher's targets and the
arbiter's known targets are the registry's agents and `shell`, and the
arbiter's raw stores every agent but OpenClaw; the launcher's tested-version
table (§2) has a range for every agent and a generation for every later
line, under the registry's names; every line's pin is in `pins.env` and
every line and sign-in a `needs` word; and no script, test helper,
dashboard, launcher or arbiter source holds a hand-copied list (`tests/lib/agent-lists.ts`: four or more agent ids
in one quoted run, one array of `id:` rows, or one plain-JS keyed table; a
TypeScript table is typed `Record<Agent, …>`, so the type checker names it).
The drill suite holds its own tree, and the inspector's browser tables and
pickers (plain JS and HTML, which cannot import the table), to the same rule.

**Adding an agent** (the standing rule):

1. Add its row (and a row per later generation that runs as its own line),
   then run `node scripts/agents/agent-copies.mjs generate`.
2. `npm run typecheck` in `tests/`, `dashboard/`, `launcher/`, `arbiter/`
   and the other packages that import it: every `Record<Agent, …>` that
   lacks the agent fails, the drill catalog's per-drill `agents` marks, the
   launcher's tested ranges and the arbiter's raw stores among them.
3. `tests/stack/agent-registry.test.ts` (and the drill suite's own check)
   name what is left: the tested-version range (§2), the pin, the `needs`
   word, a plain-JS or HTML table that does not name it.

The launcher's copy makes the row a launch target: `--target <id>` and a
command named `<id>` are accepted once the copies are regenerated. So the
row lands with the launcher's support for the agent (its model routing, its
tested range), never before it: a target the launcher accepts but does not
route is the silent unprotected launch `types.ts` `Target` describes. The
type check holds the tested range to it; the routing is the agent's own
work (§5.6 is Goose's).

What stays in the packages: a word that is not an agent (the launcher's
`shell` target) and a subset that is a feature's decision (the arbiter's
`LoginOwner`, the `StoreOwner` exclusion) are written where the feature
is, over the registry's types where they name agents. A subset written for one suite or one drill
(the catalog's per-drill agents, a suite's `needs`) is data, not a copy;
the check looks for lists of four or more agents, so an old copy is still
found once a new agent joins.

## 6. Codex's script-cell wire (codex-cli ≥ 0.154)

**BUILT 2026-09-24.** On codex-cli 0.154 every shell result re-entered the
model **raw**, and the model's `workdir` sent commands into the user's real
tree instead of the AgentView twin, because the openai-proxy read only the
0.136 wire. Code: `interceptors/openai-proxy/src/script-cell.ts`,
`responses-types.ts`, `rewrite-request.ts`, `sse-rewrite.ts`, `view-map.ts`,
`proxy.ts`, `events.ts`; `arbiter/policy/claude-code-inbound.ts` (the
envelope grammar). Tests: `interceptors/openai-proxy/test/unit/script-cell.test.ts`,
`sse-rewrite-script-cell.test.ts`, `rewrite-request.test.ts` (the SCRIPT CELL
cases), `test/component/script-cell-wire.test.ts`;
`arbiter/test/integrity/codex-exec-envelope.test.ts`.

### 6.1 What changed on the wire

The openai-proxy ([`mandu.md`](../architecture/mandu.md) §4, the Codex
realization of the model-context chokepoint) was written against codex-cli
0.136: the model's shell call was a Responses `function_call` named
`exec_command` with a JSON `arguments` string, and the result came back as a
`function_call_output` whose `output` was a string beginning with a
`Chunk ID: … / Output:` header. Everything the proxy did keyed on those two
item types.

codex-cli 0.154 (the `code_mode_host` + `unified_exec` features, stable and on
by default; disabling them leaves the model emitting the same shape into a
host that answers "code-mode host is disabled") speaks a different wire,
captured against a scripted Responses fake:

| | 0.136 | 0.154 |
|---|---|---|
| the battery | `tools: [...]` at the top level | an `input[]` item `{type:"additional_tools", tools:[{type:"namespace", name:"functions", tools:[{type:"custom", name:"exec"}, {type:"function", name:"wait"}, …]}, …]}`; no `tools` key |
| the call | `{type:"function_call", name:"exec_command", arguments:'{"cmd":"…"}'}` | `{type:"custom_tool_call", name:"exec", input:'const r = await tools.exec_command({"cmd":"cat notes.md","workdir":"/…","yield_time_ms":10000,"max_output_tokens":2000});\ntext(r.output);\n'}` — a JavaScript **cell** the runtime evaluates; the command is a JSON object literal inside it |
| streamed as | `response.function_call_arguments.delta` / `.done` | `response.custom_tool_call_input.delta` / `.done` (plus the same `output_item.done` / `completed` snapshots) |
| the result | `{type:"function_call_output", output:"Chunk ID: …\nOutput:\n<bytes>"}` | `{type:"custom_tool_call_output", output:[{type:"input_text", text:"Script completed\nWall time 0.2 seconds\nOutput:\n"}, {type:"input_text", text:"<bytes>"}]}` — an **array** of text parts |

A proxy that walks only `function_call_output` items produces, on a 0.154
turn, no `symbolize`, no `tool_result`, no exec gate, no path map, and a
`tllm_call` with `toolCount: 0`: un-symbolized untrusted data reaching
T-LLM, the class the invariant forbids.

### 6.2 The decision

Support both wires in the same modules, by making the script cell look like
argument JSON at exactly one seam (`script-cell.ts`) and keeping every gate,
map and event keyed on argument JSON as before.

- **Request side** (`rewrite-request.ts`). The correlation map reads a
  `custom_tool_call`'s cell and takes the FIRST `tools.exec_command({…})`
  literal as the call's arguments; the call is named `exec_command` (the
  function the cell calls), so the arbiter's exec-output trust rungs, the
  plan-10 process taint and the symbol tag apply unchanged. A
  `custom_tool_call_output` array of `input_text` parts is joined **in order**
  into one value (envelope part, then output), classified and symbolized as
  one datum, and written back as **one** `input_text` part (the envelope +
  symbol, the symbol alone, or the released value; any other part shape is
  dropped with the original, as the string path drops a structured payload).
  A forged output with no originating cell, or a cell with no parseable
  literal, symbolizes fail-closed. `function_call_output` keeps its string
  write-back byte for byte. A cell with no exec literal that is nothing but
  one literal MCP call, under an `exec` tool that says each cell runs in a
  fresh isolate, is named as that tool with the literal's object as its
  arguments, as the namespaced `function_call` is (an `ALL_TOOLS` listing,
  bare or filtered by name and description as codex-cli 0.160 tells the
  model to search its deferred MCP tools, is `exec` with no input:
  confidentiality-plan-10 §11.13 "The filtered listing"); any other such cell is asked about as
  `unmappedTool: "exec"`. A cell named by its first exec literal whose calls
  the grammar cannot all identify as that one literal also folds in the
  session; on the response side such a cell is gated as a whole before its
  literals (confidentiality-plan-10 §11.13 (a)).
- **The envelope** (`arbiter/policy/claude-code-inbound.ts`
  `CODEX_EXEC_ENVELOPE_SRC`, mirrored in the proxy's split regex). The
  script-cell runtime writes `Script <status>\nWall time N seconds\nOutput:\n`;
  the grammar accepts a status word from a closed set (`completed`, `failed`,
  `running`, `yielded`, `timed out`, `interrupted`, `killed`), an optional
  `(exit code N)`, and the same digits-only lines as the `Chunk ID` form. Same
  channel width as before: a word from a list plus digits; anything else
  keeps the whole value symbolized.
- **Response side** (`sse-rewrite.ts`). `custom_tool_call_input.delta` is
  buffered per item like `function_call_arguments.delta`; at `.done` (and in
  the `output_item.done` / `completed` snapshots, and at a stream cut) the
  cell goes through `transformScriptCell`, which runs the SAME composed
  transform (exec gate → forward path-map) over every exec literal and
  splices the results back. A blocked command becomes the `exit 77` sentinel
  **inside** the model's own cell.
- **Fail-closed on the shape the gate cannot read.** A cell whose exec
  arguments are not one JSON object literal (a variable, a concatenation, an
  unquoted key: the shape that would carry a symbol past a literal-only
  gate) is replaced whole by a sentinel cell that runs the block sentinel
  through the same tool, while the exec gate is on. The observed cells are
  always `JSON.stringify`-shaped, so the honest cell pays nothing. With the
  gate off the path-map's rule 3 applies (never rewrite what cannot be
  parsed).
- **`workdir` is a path surface** (`view-map.ts` `CODEX_PATH_KEYS`). The model
  spells its working directory the way it sees the tree (HumanView), so the
  forward map rewrites `workdir`/`cwd` like a command string; the reverse map
  rewrites the echoed cell (free text) and every output part. Without this a
  0.154 command ran in the user's real tree next to the AgentView cwd.
- **`tool_use` is narrated.** The stream rewriter reports every assembled
  call once (`onCall`) and the proxy emits a `tool_use` event per
  `exec_command` literal / `function_call`, `<name>(<arguments JSON>)` with
  the symbols mined, exactly as the anthropic-proxy narrates a Bash call.
  Without it the drill oracles' sabotage and "gate exercised" checks (which
  key on `tool_use`) would pass vacuously for Codex.
- **A freeform patch is one call, and not code** (2026-10-09,
  `sse-rewrite.ts` `FREEFORM_INPUT_TOOLS`, `freeformCalls`). Codex's
  freeform `apply_patch` is a `custom_tool_call` whose input is the patch
  text. It is reported once as `apply_patch({"input": <patch>})`, the shape
  of its JSON form (Codex's function tool, OpenClaw's), as the model wrote it
  (its placeholders kept), so the dashboard reads every form's files alike
  (dashboard.md §4.25b "A patch names its files"). Before, it reported
  nothing, or a shell call for an exec literal its content held. Nothing in
  a patch runs, so neither the whole-cell gate nor the exec-literal rule
  reads it, as neither reads the JSON form: before, in a HIGH session (a
  secret's content shown to the model, where the gate blocks every
  command) the patch was replaced by the sentinel cell, which is no patch,
  and Codex's edit failed. A patch can only write
  files, and a placeholder it writes stays a placeholder. The code-mode
  `exec` cell and `js_repl` keep the cell rule. Tests:
  `sse-rewrite-freeform-patch.test.ts`, the stack test
  `dashboard-apply-patch-words`.
- **A patch in a code cell is a call too** (2026-10-17,
  `cell-patch-calls.ts`). A code-mode cell that runs `await
  tools.apply_patch("*** Begin Patch …")` reports, after its exec literals,
  each patch whose text is certain from the cell's source as
  `apply_patch({"input": <patch>})` under the cell's call id: a string or
  hole-free template literal, a one-field `{input: …}` object, or a name
  bound once by a top-level `const` and used nowhere else (the form a live
  model writes). A computed patch (a concatenation, a template hole, a
  call, a `let`) reports nothing, and a cell whose `/` the reader cannot
  place (after `)` or `}`) reports no patch at all. A record only: the
  gate, the cell guard (which keeps `apply_patch`, one of codex's own) and
  the delivered bytes are unchanged (dashboard.md §4.25b "A patch in a code
  cell"). Tests: `cell-patch-calls.test.ts`,
  `sse-rewrite-freeform-patch.test.ts`, the stack test
  `dashboard-cell-patch-words`.
- **The battery is counted from either place** (`responses-types.ts`
  `advertisedTools`): `tools`, or the `additional_tools` namespaces
  flattened. `tllm_call.callShape.toolCount` and the handling prompt's
  capability facts (`custom` `exec` ⇒ the exec capability) read it.

### 6.3 Alternatives considered

- *Pin codex to the old wire* (`-c features.code_mode_host=false`). Measured:
  the model still emits the cell and the host refuses it ("code-mode host is
  disabled"); the model then reports "RAN" over a failed tool. Not a wire
  selector, and not what users run.
- *Symbolize the whole `custom_tool_call_output` array as an opaque string.*
  Safe but loses the envelope dual (the header would ride inside every symbol
  again: random wall times minting a fresh symbol per run, junk on the human's
  screen) and would change the item's shape on the wire. Rejected; the
  one-part array keeps both.
- *Parse the cell as JavaScript.* A full parser would gate composed commands
  too, but a literal scanner plus a fail-closed answer to anything else is
  the same guarantee with none of the surface.

### 6.4 What is still open

- **The exec-wrap shim cannot reach the arbiter from inside codex's sandbox
  while that sandbox's network is off** (codex's default). Measured
  2026-10-04 on codex-cli 0.160.0 (`codex sandbox -c
  'sandbox_mode="workspace-write"'` and a real `codex exec` cell against a
  scripted Responses server). Each cell command runs under
  `codex-linux-sandbox`, which uses bubblewrap (a PID namespace), Landlock
  (read everywhere; write in the workspace, `/tmp` and `$TMPDIR`) and, when
  the network is off, a seccomp filter. That filter, not Landlock and not
  the socket's path (the path stays visible and `stat`-able, and the errno
  is `EPERM`, not Landlock's `EACCES`), is the blocker:

  | refused (`EPERM`) | allowed |
  |---|---|
  | `connect` (every family, Unix included), `bind`, `sendto` (even with no address), `socket` of any family but `AF_UNIX`, `getsockopt` | `socket(AF_UNIX)`, `socketpair`, `sendmsg` (with a path address and `SCM_RIGHTS` too), `read` / `write` / `recvfrom` |

  With `sandbox_workspace_write.network_access = true` the filter is not
  installed: the shim's `connect` to the arbiter succeeds and so does a
  command's `socket(AF_INET)`. (The earlier note that it failed "also with
  `network_access=true`" was measured with a bare `codex sandbox`, which
  runs read-only, where that key does nothing.) The other ways in fail too.
  A socket path the sandbox permits does not exist, because `connect` is
  refused whatever the path. A descriptor inherited from the launcher does
  not reach a cell either: codex closes everything above 2 in the commands
  it runs, and a node program could not use it anyway (libuv's handle probe
  calls the refused `getsockopt`; the same probe drops a node program's
  output when its stdout is a socket, which codex's real pipes avoid). What
  does get through is a socket pair end passed by `sendmsg(SCM_RIGHTS)` on
  an unconnected datagram socket to a relay's path. That needs native code
  on both sides, and it would still give the guarded command no network.

  **Decision (2026-10-04, revised 2026-10-05 in §6.5): the product keeps
  Codex's own sandbox as the user runs it.** Superseded: a `mandu codex`
  launch now opens the sandbox's network by default, out loud, where Mandu's
  guard stands in for it, and never over the user's own setting (§6.5).
  What follows still holds wherever the network stays off.
  With the network off a shadowed command (curl / wget / nc) still fails
  closed (exit 77), and it could not have reached the network anyway. The
  shim now says that instead of "the Mandu service is not answering": on
  `EPERM` the refusal names the sandbox that refused the dial and the
  setting that opens it (`interceptors/exec-wrap/src/gate.ts`
  `unreachableMessage`). Since 2026-10-09 (tour 8) it names Codex's
  sandbox outright when Codex says its network is off
  (`CODEX_SANDBOX_NETWORK_DISABLED=1`, set by Codex in every command it
  runs so, read on 0.162.0), says the command itself was not the problem,
  and gives both ways to run it: outside Codex's sandbox
  (`sandbox_permissions "require_escalated"`, which asks the user; the
  command then still runs under Mandu) or with the setting below. `EACCES`
  counts as a refusal too. That stderr is hidden with the rest of a
  masked result, so the model also gets a `blocked:` line, built by the
  arbiter from the guard's own record of Codex's sandbox helper
  (`codex-linux-sandbox … --permission-profile {…"network":"restricted"}`),
  never from the command's output: confidentiality plan 10 §11.8,
  "Blocked commands", the `codex_sandbox` kind. Pinned live by
  `tests/sandbox/launcher/codex-sandbox-refusal-note.test.ts` (the real
  launcher, the real `codex exec`, a scripted model).
  Found there too: a Codex call under its own sandbox is never bound by
  the call-root recorder (plan 13 D7). The agent's child is the helper's
  process, whose argv the guard cuts short inside Codex's shell-snapshot
  preamble, so it never carries the command; the command's shell is a
  grandchild under bwrap. Such a call is masked at session level while the
  session holds a raw read. The `blocked:` line finds the command's shell
  by its exact command instead, for that line only. With the network on, the shim reaches the arbiter,
  the egress gate decides, and a plain send goes through. A drill replay
  runs BOTH sides with `network_access = true` (`DiffSideCtx.shellNetwork`,
  test-reorganization.md §6.4), so the gate, not codex's wall, is what the
  oracles grade; live drill runs keep `--skip-permissions`. Pinned by
  `tests/sandbox/codex-sandbox-exec-wrap.test.ts`: real `codex sandbox`,
  real shim, real arbiter. Network off gives exit 77 with the sandbox
  reason. Network on, a no-model secret's curl runs with its placeholder
  left as written (confidentiality.md §7.1, 2026-10-05) and the sink gets
  the placeholder, never the value, and a plain curl reaches the sink. The
  launcher keeps the exec box off for codex for
  the sibling reason (a nested bwrap cannot make its net namespace there).
- The `wait` function tool (a yielded cell's continuation): each `wait` is
  tied to the cell whose `Script running with cell ID <id>` output named its
  `cell_id`, and takes that cell's process leg; an untied `wait` is asked as
  an unmapped tool (confidentiality-plan-10 §11.13 (b)). The wire was read
  against a recording server with a real codex 0.159.1 cell that yields; a
  long-running command through a live model has not been run.
- Other custom tools a future codex may add ride the same `custom_tool_call`
  path with an empty argument map (origin unknown ⇒ UNTRUSTED), which is the
  fail-closed default, not a mapping. With confidentiality ON, a Codex tool
  that is not one of its shells (EXEC_TOOL_NAMES) nor on the openai-proxy's
  `CODEX_MAPPED_TOOLS` list (`apply_patch`, `update_plan`, `view_image`,
  `wait`, `write_stdin`, the `exec` and `js_repl` cells, `tool_search`,
  `request_user_input`, `read_file`, `list_dir`, `grep_files`, the
  sub-agent tools; since codex-cli 0.160 also the goal tools `get_goal` /
  `create_goal` / `update_goal`, `request_user_input_async`, and the
  namespaced `clock__sleep` and `collaboration__*` sub-agent tools), nor an
  `mcp__` tool of a server the launcher registered,
  is masked whole unless policy.yaml `mapped_tools:` lists it
  (confidentiality plan 10 §11.18); the MCP resource tools are masked so.
  A codex release that adds a built-in needs it on that list. A
  `function_call` in a namespace is named `<namespace>__<name>`, except in
  codex's own default namespace `functions`, which codex runs as the bare
  tool (`{namespace: "functions", name: "wait"}` is `wait`, measured on
  0.160.0), so the proxy names it so too.
- codex-cli 0.161.0 and 0.162.0 (read off both wires 2026-10-09 against a
  scripted Responses server, no MCP server configured) advertise the same
  tools as 0.160.0: on the classic wire `exec_command`, `write_stdin`,
  `request_user_input`, `apply_patch`, `view_image`, the three goal tools,
  `tool_search` and the hosted `web_search` (run by the provider, so no
  result of it comes back as a tool output); on the code-mode wire `exec`,
  `wait`, the two user questions, `clock__sleep` and the six
  `collaboration__*` tools. Each is a shell, on `CODEX_MAPPED_TOOLS`, or
  hosted (pinned by the openai-proxy unit `codex-mcp.test.ts`). Two things
  moved in 0.162, neither a new tool. The classic wire sends no
  `instructions`: codex's own prompt is the first developer message, as on
  the code-mode wire since 0.154; the proxy's handling prompt becomes the
  request's `instructions` and the developer messages pass untouched
  (`tests/stack/codex-developer-prompt.test.ts`, the real arbiter and the
  production wiring: a secret a listed reader printed still reaches the
  model only as a symbol). And code mode's `exec` description now always
  carries the "Some deferred nested tools may be omitted … filter
  `ALL_TOOLS`" note (0.160 added it only with deferred MCP tools; the
  search cell it asks for is the filtered listing of
  confidentiality-plan-10 §11.13, `integration.codex-policy-tools` green
  on 0.162.0) and declares
  the three MCP resource tools as nested tools even with no MCP server
  configured. A direct call is masked whole (§11.18). A cell calling one
  took only the cell rules (an unmapped `exec` asked about the session,
  §11.13), so in a session that read nothing a resource reached the model
  raw through a cell, a registered secret among them when a server the
  guard does not run served it as a base64 `blob`; since 2026-10-11 the
  cell is also asked about each resource tool it may call, as the direct
  call is, and masked whole (confidentiality-plan-10 §11.18, "A cell's
  resource tools", `integration.codex-cell-resources` with the real
  0.162.0). The same day an unregistered server's `mcp__` tool in such a
  cell got the same treatment, and the proxy now delivers every cell the
  §11.13 grammar cannot identify with a run-time guard at its head that
  switches off each nested tool Mandu has no mapping for before the
  model's code runs (§11.18, "The cell guard",
  `integration.codex-cell-tools-guard`): read on 0.162.0, `tools` is an
  extensible object of configurable data properties, a tool function is
  bound to its tool, `ALL_TOOLS` carries names and descriptions only, and
  every `import` is refused. A codex release that changes any of these
  needs the guard re-measured (a non-configurable tool makes the guard
  stop the cell).
- The differential harness's codex lane still scripts the 0.136 `function_call` shape; both shapes are
  accepted, so it stays green, but it does not exercise the 0.154 shape.

### 6.5 Codex's command sandbox network: on by default, said at launch (2026-10-05)

**The problem.** §6.4's decision left Codex's sandbox as the user runs it.
In Codex's default workspace-write mode its network is off, and its seccomp
filter refuses every `connect`. In the kernel's filter stack that `ERRNO`
answer outranks the guard's user notification, so the guard never sees the
call, and the exec-wrap shim cannot ask the arbiter. The one request Mandu
exists to let through, a `curl` with a key bound to that host, could never
run under `mandu codex`, while the same request works under `mandu claude`
(whose Bash runs without a sandbox unless the user turns `/sandbox` on, and
then the arbiter socket rides `allowUnixSockets`, `launcher/src/claude-sandbox.ts`).
A user had to know to pass `-c sandbox_workspace_write.network_access=true`.

**Decision.** A `mandu codex` launch adds
`-c sandbox_workspace_write.network_access=true` (spliced at every Codex
command level, codex-argv.ts) and prints one line that says so, on every
launch:

```
mandu: ! Codex's commands may use the network (Mandu decides where they connect); --no-codex-shell-network keeps Codex's default
```

(`--verbose` prints the full form, `OPEN_NOTE` in
`launcher/src/codex-shell-network.ts`.) It does so only where Mandu's own
walls stand in for the one it opens, and never over a choice someone made:

| Condition | Result |
|---|---|
| `--no-codex-shell-network`, `MANDU_CODEX_SHELL_NETWORK=0`, `codex-shell-network = false` in `config.toml` | Codex's default, nothing said |
| The command line picks a sandbox where the key does nothing (`-s read-only`, `danger-full-access`, `--dangerously-bypass-approvals-and-sandbox`, `-c sandbox_mode=…`) | nothing spliced, nothing said |
| The command line sets the network or a permission profile (`-c …network_access…`, `-c sandbox_workspace_write=…`, `default_permissions`, `permissions.*`) | left as set; a line in `--verbose` |
| A config file Codex reads sets it: `$CODEX_HOME/config.toml`, the named profile's `<name>.config.toml`, each `.codex/config.toml` from the working directory up to `/`, `/etc/codex/config.toml` | left as set; a line in `--verbose` |
| `/etc/codex/managed_config.toml` or `requirements.toml` mentions the sandbox, the network or permissions | the administrator's setting decides |
| Not Linux | this Linux-only option makes no override or network claim; macOS uses the separate sandbox decision below |
| The `off` mode, or the connect guard did not come up | Codex's default; a line in `--verbose` says why |
| Otherwise | opened, and said |

**macOS.** This command-network option and its opt-out apply only on Linux.
When Mandu applies its whole-agent Seatbelt profile on macOS, the separate
`codex-sandbox.ts` decision normally turns Codex's own per-command sandbox
off because Seatbelt profiles cannot nest, and announces that choice.
`--no-codex-shell-network` does not restore that sandbox or deny command
networking; Mandu's applied Seatbelt network rules still govern the launch.
An explicit sandbox choice or an administrator/user policy that keeps the
sandbox remains governed by that existing decision. Without Mandu's
profile, Codex's own sandbox stays as configured. No Linux network notice
is printed on macOS.

The config scan reads text, not Codex's whole layering: a mention anywhere
except a whole-line comment counts. It over-detects on purpose, because a
false hit only leaves Codex at its own default, the safe direction.

**Why it is safe to open.** With the network on, Codex installs no network
filter, so every `connect` from a command reaches the guard: it decides by
destination (exec-routing.md §7.5), and with the confidentiality axis on
the Unix-socket allow-list refuses the host services that run programs on
request (the D-Bus session bus, docker, `systemd-run --user`; exec-routing.md
§4.3). A bare Codex with its network on and no managed proxy leaves those
reachable; under Mandu they are not. Secrets reach commands as placeholders
and leave only through the egress gate to bound hosts (confidentiality.md
§7.1). Residual: what Mandu does not label (ordinary source files) can now
leave over the guard's default `*:443` / `*:22` fallback, where Codex's
closed network stopped it; `--landlock-net-strict` or `--net-allow` narrow
that, and `--no-codex-shell-network` restores Codex's wall. The guard's
`--skip-unsupported` degrade (no seccomp user notification) is not visible
at launch time; on such a kernel the guard's own launch line already says so.

**Pinned by.** `launcher/test/unit/codex-shell-network.test.ts` (the table
above, the launch line's compact form, parse, `config.toml`, the splice at
every level, the config files read); `launcher/test/unit/env-compose.test.ts`
(only the Linux network and macOS sandbox adapters name their respective
Codex settings, with announced platform decisions); `tests/sandbox/launcher/codex-shell-network.test.ts` (the
real launcher in `secrets`, a stand-in `codex` running its work inside the
real `codex sandbox`: by default the override arrives, the line is printed,
the bound host gets the value from the proxy and the unbound host nothing;
opted out, the shim names Codex's sandbox, exit 77, and no host gets a
request).

### 6.6 Codex's own uploads: forced off, hosts denied (2026-10-07)

The agent-SDK runs (`integration.agent-sdk`) showed Codex sending GET and
POST requests to chatgpt.com, github.com and ab.chatgpt.com through the
egress proxy. Codex's process holds original tool output, so each such
call was reviewed under §5.3.4 rule 1 (transcript and trace uploads),
from the codex-cli 0.160.0 source and checked against 0.136.0, the oldest
tested release.

**Every host, what it carries, and the decision.**

| Host and path | Carries | Default | Under Mandu |
|---|---|---|---|
| `ab.chatgpt.com` `/otlp/v1/metrics` (Statsig metrics) | metric names and counts; tag values limited to `[A-Za-z0-9._/-]` | on | off (`analytics.enabled=false` also turns the metrics exporter off; `otel.metrics_exporter="none"`); host denied by name at the net-proxy |
| `chatgpt.com` `/backend-api/codex/analytics-events/events` | ids, model, tool, skill and plugin names, line counts, a repository hash | on | off (`analytics.enabled=false`) |
| a collector the user configures (`[otel] exporter` / `trace_exporter`, `OTEL_EXPORTER_OTLP_*`) | tool arguments and up to 2 KiB of each tool's output; prompts with `log_user_prompt` | off unless configured | off (`otel.exporter="none"`, `otel.trace_exporter="none"`); the configured hosts denied |
| `o33249.ingest.us.sentry.io` (the feedback report) | the session's rollout (raw tool output) and logs | on, sent when the user files feedback | off (`feedback.enabled=false`); host denied at both layers |
| `chatgpt.com` `/backend-api/ps/mcp` (0.160) or `/backend-api/wham/apps` (0.136), and `/backend-api/files` (ChatGPT apps) | an app's file parameter makes Codex read the named local file and upload its bytes | on with a ChatGPT sign-in | off (`features.apps=false`, and `features.connectors=false` when the user's config names that legacy alias); the launch says so |
| `github.com` `info/refs` and `git-upload-pack` of `openai/plugins.git`; `chatgpt.com` `plugins/export/curated` | the public plugin repository's fetch | on | left on: it downloads a public repository and sends nothing of the session |
| `api.github.com` releases (the update check) | bodyless GETs | TUI only | off (`check_for_update_on_startup=false`) |
| `chatgpt.com` `wham/usage`, `wham/accounts/check`, `wham/settings/user`, `wham/config/bundle`, `ps/plugins/*` | ids and account metadata | with a ChatGPT sign-in | left on: the sign-in needs them, and they carry no session content (the `codex-chatgpt` drill checks every one for the secret, the prompt and the workspace path) |
| `auth.openai.com` `/oauth/token` | the refresh token | as needed | left on: the sign-in must stay refreshable |
| Codex Cloud (`codex cloud`) | the prompt, as a task run on OpenAI's machines | when run | refused at launch |

The model turns themselves go to the openai-proxy: Mandu's provider has a
loopback `base_url`, so Codex's backend rerouting (which needs a base URL
ending in `/backend-api/codex`) does not apply. `chatgpt.com` itself cannot
be denied without breaking the sign-in, which is why the switches, not the
network, close the channels it hosts.

**The switches** (`launcher/src/codex-argv.ts` `CODEX_UPLOADS_OFF`) ride the
routing overrides at every command level, in the plain launch
(`env-compose.ts`) and in the SDK route's Codex splice
(`sdk-route-preload.cjs`, held equal by the parity test), routing first. A
`-c` outranks every config.toml layer (system, user, `--profile`, project),
so a user's config cannot turn them back on; a managed config
(`/etc/codex/managed_config.toml`, MDM) sits above the command line and can,
which Mandu does not override (an administrator's choice). Within one
command level the last `-c` for a key wins, so a user's own `-c` that sets
one of these keys otherwise, sets a key below one, or replaces its table
(`-c otel={…}`), and `--enable apps` / `--enable connectors`, are refused
at launch, fail-closed. Every key exists in 0.136.0, and the set starts
0.136.0, 0.144.1 and 0.160.0 with no warning (probed 2026-10-07; 0.160.0
names an unknown key in a startup warning, so a key Codex lacks would show,
not fail). The legacy alias `connectors` needs care: Codex applies feature
keys in name order, so a config with `connectors = true` turns apps back on
after `apps = false`; forcing `features.connectors=false` on every launch
would print Codex's "`[features].connectors` is deprecated" notice each
time, so the launcher adds it only when one of the user's config layers
names the key (`codexConfigNamesConnectors`, carried to the SDK route as
`connectorsOff`).

**The deny row** (`launcher/src/upload-deny.ts`, `codex`): the Sentry host
(both layers); `ab.chatgpt.com` in `proxyOnly`, by name at the net-proxy, because it
answers on `chatgpt.com`'s Cloudflare addresses and the connect guard,
which matches resolved addresses, would cut the sign-in off with it; the
hosts of `OTEL_EXPORTER_OTLP_ENDPOINT` and its per-signal variants; and,
from every config layer Codex may read (`codex-sandbox.ts`
`codexAllConfigLayers`: system, user, the run's profile, the project
layers, the managed config), the `[otel]` exporters' endpoints and the
realtime base URLs (`experimental_realtime_ws_base_url`,
`experimental_realtime_webrtc_call_base_url`), which would carry a voice
conversation past the model proxy. A realtime URL given on the command line
(`-c experimental_realtime_ws_base_url=…`) is not read.

**The launch line.** A Codex on a ChatGPT sign-in (the only kind with apps)
prints one plain line, `mandu: ChatGPT apps and connectors are off in Codex
under Mandu: …` (the default display counts it as a notice; the launch's
log and `--verbose` carry it, packaging.md §5): an app that asks
for a file makes Codex upload it, around the model proxy.

**Pinned by.** `launcher/test/unit/codex-argv.test.ts` (the switches, the
splice at every level, the conflict check and its refusals, `codex cloud`);
`env-compose.test.ts` (the composed prefix, wrappers, shells, the note);
`sdk-route.test.ts` (the preload's copy, its conflict check and refusals,
parity); `upload-deny.test.ts` (the row, the `proxyOnly` entry kept off the
guard, the config scan); `codex-sandbox.test.ts` (the layers read);
`launcher/test/component/codex-routing.test.ts` and `sdk-route.test.ts`
(through `main()` and the real preload, each switch at every level, the
refusals); `tests/stack/upload-deny.test.ts` (the real net-proxy refuses
Statsig, Sentry and the configured collectors, and reaches `chatgpt.com`);
`codex-chatgpt.test.ts` (a real Codex on a ChatGPT
sign-in with the launcher's argv makes no analytics post and never reaches
the apps MCP server; a control with the routing alone does both; run on
0.136.0, 0.144.1 and 0.160.0).
