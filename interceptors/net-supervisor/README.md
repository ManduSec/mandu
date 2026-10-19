# net-supervisor (Rust lib) — M3

Ingress symbolization + egress desymbolization for the agent's **non-model**
network traffic. Model-API traffic (api.anthropic.com / api.openai.com / a
configured inference host) is **excluded** — the TS `anthropic-proxy` owns it
(`transform::is_model_host`).

## Pure vs kernel-gated

| Module | Pure / gated | What |
|---|---|---|
| `transform` | **pure** | `ingress_transform` (classify + symbolize a response body before the agent sees it), `egress_transform` (desymbolize an outbound body, gated **per symbol** by `desymbolizationDecision`, withholding fail-closed), `is_model_host` (model-API exclusion). |
| `events` | **pure** | the `net_action` event builders (AgentView for symbolized ingress, HumanView for egress). |
| `kernel` | **`--features kernel`** | the nftables **TPROXY** redirection of the cgroup's non-model traffic + the accept loop that runs the pure transforms over each connection. Needs root + the `nft` binary. |

**Pure decision functions:** `transform::ingress_transform(...) -> IngressResult`
and `transform::egress_transform(...) -> EgressResult`.

**Behind `kernel`:** `kernel::render_tproxy_ruleset` + `kernel::run_proxy`.

## Security invariant (fail-closed)

- **Ingress** never lets un-symbolized untrusted bytes reach the agent: an
  UNTRUSTED body is replaced by an allocated symbol, and a **arbiter miss** serves
  a synthetic `$MDU_OPAQUE_INGRESS[...]` marker — **never the raw bytes**.
- **Egress** is fail-closed: a symbol is desymbolized **only** on a positive
  `desymbolizationDecision` (allow). A denied or unreachable gate leaves the
  symbol **symbolic on the wire** (withheld → needs approval), so a secret can
  never be exfiltrated to an untrusted destination.

## Running the kernel path (privileged host)

Requires root, the **`nft` binary** (absent on the dev host), kernel TPROXY
support, and the agent under the launcher's cgroup v2 scope.

```
cargo build -p net-supervisor --features kernel
sudo nft -f mandu-tproxy.nft                       # divert cgroup non-model traffic
sudo ./target/debug/net-supervisor ...                    # accept loop
cargo test  -p net-supervisor --features kernel -- --ignored
```

Default `cargo build` / `cargo test` need **no privileges** and skip the
`#[ignore]`d `tests/kernel_integration.rs`.
