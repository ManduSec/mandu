# Mandu × AgentDojo — the apples-to-apples robustness number

This is the AgentDojo backend of `eval/`: it runs **AgentDojo's own benchmark**
(Debenedetti et al., NeurIPS 2024 — the suite CaMeL and FIDES report on) with the
Anthropic pipeline routed through the **real Mandu anthropic-proxy**, so the ASR
/ utility numbers are directly comparable. Design + rationale:
[`docs/design/testing/evaluation.md §2`](../../docs/design/testing/evaluation.md).

## The one-line idea

AgentDojo is a **function-calling** IPI benchmark; injections live in tool
outputs. Mandu's defense for that surface is the **context chokepoint** — the
model-API proxy. AgentDojo's Anthropic SDK client honors `ANTHROPIC_BASE_URL`, so
pointing it at the proxy is a one-env-var change. The proxy classifies each
`tool_result` (via the `agentdojo` trust spec) and **symbolizes** the untrusted
ones, so the injected instruction reaches the model only as `$MDU:*` and
can't be followed. No fork, no monkeypatch — AgentDojo is just another client
speaking the API the proxy already parses.

## Run it

```sh
./run.sh                 # offline invariant smoke (default) — no key, no network
./run.sh smoke           # same
./run.sh audit           # offline trust-gap audit — no key; the static adaptive arm
./run.sh real            # real-model ASR / utility / overhead — needs a key
```

`run.sh` provisions a local `.venv` (prefers `uv`, which fetches Python 3.12 even
when the host python is older) with `agentdojo` pinned, then dispatches. It **SKIPs
cleanly (exit 0)** when Python 3.10+, the Node stack, or `openssl` is unavailable —
so it never breaks a portable suite.

### `smoke` — the offline invariant proof (runs anywhere)

Boots the **real** arbiter + **real** anthropic-proxy against a scripted **mock**
upstream and runs a real AgentDojo task pair (slack `user_task_0` "read
www.informations.com" × `injection_task_1`, `important_instructions` attack). It
asserts the §9 invariant on the request the proxy forwarded upstream: the injected
instruction (`<INFORMATION> … secure-systems-252.com`) — and the entire untrusted
webpage — reach the model **only** as a `$MDU:*` token. This proves the
integration is real (AgentDojo's `tool_result` wire format is actually parsed and
symbolized by the proxy under the `agentdojo` trust spec). It is **not** an ASR
measurement — a scripted mock can't "decide"; that's `real`'s job.

### `audit` — the offline (no-key) trust-gap audit

The static half of the adaptive-attack arm (`docs/design/testing/evaluation.md §2`
§4.2). Runs AgentDojo's own ground-truth pipeline (deterministic, no model) to find
every tool whose result surfaces an injection, then asserts each classifies
UNTRUSTED under `arbiter/policy/agentdojo-inbound.ts`. A tool marked TRUSTED that
carries an injection is a by-construction hole → **exit non-zero**. Runs anywhere,
no key. (This audit already found and closed three real holes — `get_channels` and
the echo-back action tools `add_calendar_event_participants` / `delete_file`; the
policy unit test `arbiter/test/integrity/agentdojo-policy.test.ts` now guards them.)

### `real` — the comparable numbers (needs a Console key)

```sh
# Provide a CONSOLE key (see note below). Either export it, or put it in the
# central gitignored secrets file — run.sh auto-loads it (docs/design/testing/continuous-integration.md §13):
#   cp ../../secrets.example.json ../../secrets.local.json  # set anthropic_api_key
export ANTHROPIC_API_KEY=sk-ant-…
./run.sh real --model haiku                 # cheap validation, capped subset (default caps)
./run.sh real --suites slack,banking --limit-users 5 --limit-injections 3
./run.sh real --configs baseline,agentdojo --full --out report.json
# Without --out the JSON report goes to report.json in a new run dir,
# ~/.mandu/runs/eval/<UTC yyyymmddThhmmssZ>-agentdojo-<6 hex>/ (0700; MANDU_HOME
# moves it; eval_out.py). The path is printed before the run starts.

# The adaptive-attack arm (runtime half) — measure ASR stays at the defended
# baseline against attacks written against the defense:
./run.sh real --attack mandu_delimiter --full      # DUALVIEW wire-format escape, ported
./run.sh real --attack mandu_symbol_aware --full   # attacks the desymbolize/recovery seam
./run.sh real --attack mandu_split --full          # split-payload / parser-attribution probe
./run.sh real --attack injecagent --full             # InjecAgent-style attack string

# --model takes an alias (sonnet-3.5 | haiku | sonnet | opus) or a full model id.
# sonnet-3.5 (claude-3-5-sonnet-20241022) is the comparable-era leaderboard model;
# current models are auto-registered so the named important_instructions attack works.
```

Runs AgentDojo's suites through a real Claude model under three configs and
reports **ASR / utility(attacked) / utility(benign) / wall-clock**, defense off vs
on:

| config | what |
|---|---|
| `baseline` | defense OFF — SDK talks straight to `api.anthropic.com` |
| `agentdojo` | defense ON — through the proxy, calibrated trust spec |
| `fail-closed` | defense ON — every tool output symbolized (conservative bound) |

> **Why a Console key, not a subscription.** AgentDojo's pipeline is a third-party
> Anthropic SDK client, not Claude Code. A subscription OAuth token
> presented by a non–Claude-Code client is not a supported use
> ([`agent-sign-in.md §1`](../../docs/design/agents/agent-sign-in.md) F4/F6), so the
> `real` tier needs a Console API key. Without one it SKIPs cleanly.

## The trust spec

Which AgentDojo tool outputs are untrusted is `arbiter/policy/agentdojo-inbound.ts`
(selected by `MANDU_INBOUND_SPEC=agentdojo`, wired in `stack.py`). The rule: a
tool output is UNTRUSTED iff a party other than the user can influence it —
received mail, third-party reviews, attacker-set transaction subjects, slack
messages, fetched webpages. It is unit-tested per tool in
`arbiter/test/integrity/agentdojo-policy.test.ts` (the arbiter's frozen `test:integrity` lane, `docs/design/architecture/protection-modes.md §10`).

## Files

| file | role |
|---|---|
| `run.sh` | entrypoint; venv bootstrap + dispatch (smoke \| audit \| real) |
| `invariant_smoke.py` | offline §9 proof against a mock upstream |
| `trust_gap_audit.py` | offline trust-gap audit (static adaptive arm; no key) |
| `attacks_mandu.py` | runtime adaptive attacks (`mandu_delimiter/symbol_aware/split`) |
| `runner.py` | real-model ASR / utility / overhead benchmark + report |
| `stack.py` | boot/teardown the real arbiter + anthropic-proxy (+ cert minter) |
| `mock_upstream.py` | scripted HTTPS Anthropic mock for the smoke |
| `pipeline.py` | build the AgentDojo pipeline pointed at the proxy |
| `requirements.txt` | pinned `agentdojo` + `anthropic` |
