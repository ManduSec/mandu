"""
eval_out — where the AgentDojo runner writes its report when no --out is
given (docs/design/architecture/on-disk-layout.md §9 decision 3): `report.json` in a fresh
run dir under the path table's `eval-runs` (`~/.mandu/runs/eval`, moved by
MANDU_HOME). An explicit --out (a file path) still wins.

The location comes from the table's generated bash copy
(scripts/paths/mandu-paths.sh), not a hand copy, so it cannot drift from
eval/lib/eval-out.ts. The run id has the same shape as there:
`<UTC yyyymmddThhmmssZ>-<suite>-<6 hex>`.

The runner's Unix sockets (the arbiter's) live in its own tempfile.mkdtemp
dir (runner.py), never under the run dir.

Stdlib only; Python 3.8+ so the offline test runs on any host python.
Mandu-new (no reference origin).
"""

from __future__ import annotations

import datetime
import os
import re
import secrets
import subprocess
from typing import Mapping, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
PATHS_SH = os.path.join(HERE, "..", "..", "scripts", "paths", "mandu-paths.sh")


def eval_runs_dir(env: Optional[Mapping[str, str]] = None, home: Optional[str] = None) -> str:
    """The path table's `eval-runs` for `env` (default: os.environ) and `home`
    (default: env HOME, else the account's home)."""
    env = dict(os.environ if env is None else env)
    if home is None:
        home = env.get("HOME") or os.path.expanduser("~")
    out = subprocess.run(
        ["bash", "-c", 'source "$1" && mandu_path eval-runs "$2"', "mandu-paths", PATHS_SH, home],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    path = out.stdout.decode().strip()
    if not path.startswith("/"):
        raise RuntimeError(f"eval-runs did not resolve to an absolute path: {path!r}")
    return path


def mint_run_id(suite: str, now: Optional[datetime.datetime] = None, rand: Optional[str] = None) -> str:
    """`<UTC yyyymmddThhmmssZ>-<suite>-<6 hex>`."""
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", suite):
        raise ValueError(f"invalid run suite name: {suite!r}")
    rand = secrets.token_hex(3) if rand is None else rand
    if not re.fullmatch(r"[0-9a-f]{6}", rand):
        raise ValueError("invalid run id random tail")
    now = datetime.datetime.now(datetime.timezone.utc) if now is None else now.astimezone(datetime.timezone.utc)
    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{suite}-{rand}"


def _makedirs_private(path: str) -> None:
    """mkdir -p where every directory made is 0700 (os.makedirs applies the
    mode to the leaf only)."""
    missing = []
    p = path
    while not os.path.isdir(p):
        missing.append(p)
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    for d in reversed(missing):
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass


def resolve_report_path(out: Optional[str], suite: str = "agentdojo",
                        env: Optional[Mapping[str, str]] = None,
                        home: Optional[str] = None) -> Tuple[str, bool]:
    """(report path, defaulted). With `out`, that path as given. Without, make
    `<eval-runs>/<run id>/` (0700; its missing parents too, and never an
    existing run dir) and return `report.json` in it."""
    if out:
        return out, False
    root = eval_runs_dir(env, home)
    _makedirs_private(root)
    run_dir = os.path.join(root, mint_run_id(suite))
    os.mkdir(run_dir, 0o700)  # FileExistsError on a collision: never reuse a run dir
    return os.path.join(run_dir, "report.json"), True
