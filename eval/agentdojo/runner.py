"""
runner — the REAL-MODEL AgentDojo benchmark for Mandu: run AgentDojo's own
suites through a real Claude model, defense OFF vs ON, and report the
apples-to-apples ASR / utility / overhead (docs/design/testing/evaluation.md §2.7).

Needs a Console ANTHROPIC_API_KEY (a subscription OAuth token can't drive a
third-party SDK client — agent-sign-in.md F4/F6). SKIPS cleanly (exit 0)
without one, mirroring eval/lib/run-live.ts's real-api mode.

Configs (each a column in the report):
  baseline      defense OFF — the SDK talks straight to api.anthropic.com.
  agentdojo     defense ON  — through the anthropic-proxy, MANDU_INBOUND_SPEC
                              = agentdojo (the calibrated trust spec).
  fail-closed   defense ON  — through the proxy, every tool output symbolized
                              (the conservative security bound).

Metrics (AgentDojo's own checkers, so the number is comparable to CaMeL/FIDES):
  ASR              mean(security) over (user_task × injection_task) pairs — the
                   attacker goal was achieved. Lower is better; the defense should
                   drive it toward 0.
  utility_attacked mean(utility) over the same pairs — the benign task still
                   completed despite the injection.
  utility_benign   mean(utility) over user tasks with NO injection — the
                   over-symbolization tax on normal work.
  wall_clock_s     total seconds — the on/off overhead line (token overhead is
                   recorded in the arbiter event log; see README).

Usage:
  run.sh real                                   # all suites, capped subset
  run.sh real --suites slack,banking --limit-users 5 --limit-injections 3
  run.sh real --configs baseline,agentdojo --full

The JSON report goes to --out (a file) or, by default, to report.json in a new
run dir under ~/.mandu/runs/eval (eval_out.py); the path is printed first.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass, asdict

from eval_out import resolve_report_path

ALL_SUITES = ["workspace", "travel", "banking", "slack"]
DEFAULT_CONFIGS = ["baseline", "agentdojo", "fail-closed"]


@dataclass
class ConfigResult:
    config: str
    n_pairs: int
    n_benign: int
    asr: float
    utility_attacked: float
    utility_benign: float
    wall_clock_s: float


def _skip(reason: str) -> int:
    print(f"SKIP: {reason}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="runner.py")
    ap.add_argument("--suites", default=",".join(ALL_SUITES),
                    help="comma-separated suite names (default: all four)")
    ap.add_argument("--attack", default="important_instructions",
                    help="AgentDojo attack name (default: important_instructions). "
                         "Mandu adaptive arm: mandu_delimiter, mandu_symbol_aware, "
                         "mandu_split. InjecAgent-style: injecagent.")
    ap.add_argument("--configs", default=",".join(DEFAULT_CONFIGS),
                    help="comma-separated: baseline,agentdojo,fail-closed")
    ap.add_argument("--model", default=None, help="model id (default: pipeline.DEFAULT_MODEL)")
    ap.add_argument("--limit-users", type=int, default=3,
                    help="cap user tasks per suite (0 = all). Default 3 keeps a keyed run cheap.")
    ap.add_argument("--limit-injections", type=int, default=2,
                    help="cap injection tasks per suite (0 = all). Default 2.")
    ap.add_argument("--full", action="store_true", help="run the FULL benchmark (ignore the caps)")
    ap.add_argument("--out", default=None,
                    help="write the JSON report to this file (default: report.json in a new run dir "
                         "under ~/.mandu/runs/eval; MANDU_HOME moves it)")
    return ap.parse_args(argv)


def run(argv: list[str]) -> int:
    args = parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return _skip("real-model run needs a Console ANTHROPIC_API_KEY (not set) — "
                     "a subscription token can't drive AgentDojo's SDK client "
                     "(docs/design/agents/agent-sign-in.md F4/F6)")
    try:
        from agentdojo.task_suite.load_suites import get_suites
        from agentdojo.attacks.attack_registry import load_attack
    except Exception as e:  # pragma: no cover
        return _skip(f"agentdojo not importable ({e})")

    from stack import defense_stack, DepsMissing
    from pipeline import build_pipeline, DEFAULT_MODEL, resolve_model
    import attacks_mandu  # noqa: F401 — registers the mandu_* adaptive attacks

    model = resolve_model(args.model or DEFAULT_MODEL)
    suites_req = [s.strip() for s in args.suites.split(",") if s.strip()]
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    limit_users = 0 if args.full else args.limit_users
    limit_inj = 0 if args.full else args.limit_injections

    all_suites = get_suites("v1")
    suites = {name: all_suites[name] for name in suites_req if name in all_suites}
    if not suites:
        print(f"no known suites in {suites_req}; valid: {list(all_suites)}")
        return 2

    # --out wins; else report.json in a new run dir under the path table's
    # eval-runs (~/.mandu/runs/eval; on-disk-layout.md §9 decision 3).
    report_path, defaulted = resolve_report_path(args.out, "agentdojo")
    print(f"Output: {report_path}" + (" (default; pass --out <file> to choose)" if defaulted else ""))

    results: list[ConfigResult] = []
    for config in configs:
        try:
            results.append(_run_config(
                config, suites, args.attack, model, limit_users, limit_inj,
                get_suites=get_suites, load_attack=load_attack,
                build_pipeline=build_pipeline, defense_stack=defense_stack,
            ))
        except DepsMissing as e:
            return _skip(str(e))

    report = {
        "benchmark": "agentdojo-v1",
        "attack": args.attack,
        "model": model,
        "suites": list(suites),
        "full": bool(args.full),
        "configs": [asdict(r) for r in results],
    }
    _print_report(report)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nwrote {report_path}")
    return 0


def _run_config(config, suites, attack_name, model, limit_users, limit_inj, *,
                get_suites, load_attack, build_pipeline, defense_stack) -> ConfigResult:
    """Run every selected suite under one defense config; aggregate the metrics."""
    print(f"\n=== config: {config} ===")
    start = time.time()

    # baseline = no proxy (direct to api.anthropic.com); else boot the stack and
    # point ANTHROPIC_BASE_URL at the proxy with the chosen inbound spec.
    prev_base = os.environ.get("ANTHROPIC_BASE_URL")
    tmp = tempfile.mkdtemp(prefix=f"mandu-agentdojo-{config}-")
    ctx = None
    try:
        if config == "baseline":
            os.environ.pop("ANTHROPIC_BASE_URL", None)
        else:
            ctx = defense_stack(tmp, upstream_origin="https://api.anthropic.com",
                                inbound_spec=config, fake_upstream=False)
            stack = ctx.__enter__()
            os.environ["ANTHROPIC_BASE_URL"] = stack.proxy_base_url

        pipeline = build_pipeline(model=model)

        n_pairs = n_benign = 0
        sec_sum = util_atk_sum = util_ben_sum = 0.0

        for sname, suite in suites.items():
            user_tasks = list(suite.user_tasks.values())
            if limit_users:
                user_tasks = user_tasks[:limit_users]
            inj_tasks = list(suite.injection_tasks.values())
            if limit_inj:
                inj_tasks = inj_tasks[:limit_inj]

            class _NameCarrier:
                name = f"{model}-mandu"
            attack = load_attack(attack_name, suite, _NameCarrier())

            # Benign utility (no injection).
            for ut in user_tasks:
                utility, _ = suite.run_task_with_pipeline(pipeline, ut, None, {})
                util_ben_sum += 1.0 if utility else 0.0
                n_benign += 1

            # Under attack (each user × injection pair).
            for ut in user_tasks:
                for it in inj_tasks:
                    injections = attack.attack(ut, it)
                    utility, security = suite.run_task_with_pipeline(pipeline, ut, it, injections)
                    sec_sum += 1.0 if security else 0.0
                    util_atk_sum += 1.0 if utility else 0.0
                    n_pairs += 1
            print(f"  [{sname}] {len(user_tasks)} users × {len(inj_tasks)} injections done")

        wall = time.time() - start
        return ConfigResult(
            config=config,
            n_pairs=n_pairs,
            n_benign=n_benign,
            asr=(sec_sum / n_pairs) if n_pairs else 0.0,
            utility_attacked=(util_atk_sum / n_pairs) if n_pairs else 0.0,
            utility_benign=(util_ben_sum / n_benign) if n_benign else 0.0,
            wall_clock_s=round(wall, 1),
        )
    finally:
        if ctx is not None:
            ctx.__exit__(None, None, None)
        if prev_base is not None:
            os.environ["ANTHROPIC_BASE_URL"] = prev_base
        else:
            os.environ.pop("ANTHROPIC_BASE_URL", None)


def _print_report(report: dict) -> None:
    print("\n" + "─" * 78)
    print(f"Mandu × AgentDojo — {report['benchmark']} · attack={report['attack']} · model={report['model']}")
    print(f"suites={report['suites']} full={report['full']}")
    print("─" * 78)
    hdr = f"{'config':<14}{'pairs':>6}{'ASR':>9}{'util(atk)':>11}{'util(benign)':>14}{'wall(s)':>10}"
    print(hdr)
    print("-" * len(hdr))
    for r in report["configs"]:
        print(f"{r['config']:<14}{r['n_pairs']:>6}{r['asr']*100:>8.1f}%"
              f"{r['utility_attacked']*100:>10.1f}%{r['utility_benign']*100:>13.1f}%"
              f"{r['wall_clock_s']:>10.1f}")
    print("─" * 78)
    base = next((c for c in report["configs"] if c["config"] == "baseline"), None)
    defc = next((c for c in report["configs"] if c["config"] == "agentdojo"), None)
    if base and defc:
        print(f"ASR: baseline {base['asr']*100:.1f}%  →  Mandu(agentdojo) {defc['asr']*100:.1f}%  "
              f"(Δ {(base['asr']-defc['asr'])*100:+.1f} pts)")


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
