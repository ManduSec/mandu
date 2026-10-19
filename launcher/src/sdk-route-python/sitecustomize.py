"""Mandu's SDK route for Python host programs (docs/design/agents/agent-sdks.md).

WHY. A product built on the Python Claude Agent SDK (`claude-agent-sdk`) or
the Python Codex SDK (`openai-codex`) runs as `mandu --target claude|codex --
python3 app.py`. The SDK starts the agent CLI as a child, and Python loads no
Node preload, so before this hook:
  - the Claude SDK's `env` option, merged over `os.environ`, could set its own
    ANTHROPIC_BASE_URL (or drop the proxy variables), and a settings source
    could re-point Claude Code: the CLI then called its vendor directly, and
    a labelled file it read reached the model raw;
  - the Codex SDK's `codex app-server` ran with no Mandu provider at all.
The launcher copies this file into its own `<scope run dir>/sdk-route/python/`
and puts that directory first on PYTHONPATH, so Python imports this file at
startup (the `site` module's `sitecustomize`). The launch's route (JSON,
launcher/src/sdk-route.ts) is read from `../route.json` beside this copy, a
folder on the whole-agent guard's (and the macOS profile's) write-protect
list, never from the environment: a MANDU_SDK_ROUTE there is ignored and
removed from every child, since a host the model steers could forge it
(agent-sdks.md §3.6). A copy in a `sdk-route/python/` folder whose route is
missing or unreadable refuses every child that may be an agent CLI. It hooks
`subprocess.Popen._execute_child`, the one place every Python start goes
through (`subprocess.*`, `asyncio` and `anyio` subprocesses, so both SDKs):
  - every child gets the launch's routing variables back (the Node preload's
    routeEnv, mirrored here and held equal by the parity test), the shims at
    the head of PATH, the Node preload in NODE_OPTIONS and this directory at
    the head of PYTHONPATH;
  - a child that is an agent CLI (by name, the script a JS runtime runs, or
    the SDKs' own command line) is decided by the Node preload itself
    (`node sdk-route-preload.cjs --decide`, the one copy of the decision): the
    provider splice for codex, the settings overlay and permission mode for
    claude (both from the launch's own values, the route's launchRouting,
    which this hook hands on unchanged: never from the child's `env`), and
    a refusal for what Mandu cannot route (the Python Codex SDK's
    `app-server`, an agent the launch does not route). A refusal raises
    ManduRouteRefused (a PermissionError) instead of starting the child, and
    so does a decision that cannot be made: fail-closed.

Not covered: `os.posix_spawn`, `os.exec*`, `os.spawn*` and `pty.spawn` called
directly (no SDK does), and a Python started with `-I`, `-E` or `-S`, which
does not import this file (the launch refuses that under `--target codex`).
An agent CLI found by name on PATH still meets the PATH shims.

A `sitecustomize` the environment already had (a distribution's, a virtual
environment's) is loaded after this one.

Mandu-new (no reference origin).
"""

import json
import os
import subprocess
import sys
import threading

# The variable that carried the route before 2026-10-18: ignored, removed.
ROUTE_ENV = "MANDU_SDK_ROUTE"
# The launch's folder of route copies and the route in it (sdk-route.ts
# SDK_ROUTE_DIR, SDK_ROUTE_FILE); this copy lives in its `python/`.
ROUTE_DIR = "sdk-route"
ROUTE_FILE = "route.json"
_AGENT_NAMES = ("claude", "codex")
_JS_RUNTIMES = ("node", "nodejs", "bun", "deno")


class ManduRouteRefused(PermissionError):
    """An agent CLI this launch cannot route: it is not started."""


def _parse_route(raw):
    if not isinstance(raw, str) or raw == "":
        return None
    try:
        r = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(r, dict) or r.get("v") != 1 or not isinstance(r.get("env"), dict):
        return None
    return r


def _own_route_dir():
    """The launch's route folder this copy lives in, or None (the bundle's
    copy, which has none)."""
    here = os.path.dirname(os.path.abspath(__file__))
    up = os.path.dirname(here)
    if os.path.basename(here) == "python" and os.path.basename(up) == ROUTE_DIR:
        return up
    return None


def _read_route_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return _parse_route(f.read())
    except (OSError, ValueError):
        return None


def effective_route(route, own_env):
    """The route as this process received it (the preload's effectiveRoute):
    a routing variable is forced only when this process carries it."""
    out = dict(route)
    out["env"] = {k: own_env[k] for k in route["env"] if isinstance(own_env.get(k), str)}
    return out


def _require_option(p):
    return '--require="%s"' % p if any(c.isspace() for c in p) else "--require=%s" % p


def route_env(route, env):
    """The child's environment with the launch's routing put back (the
    preload's routeEnv; the parity test holds the two equal)."""
    out = dict(env)
    for k, v in route["env"].items():
        out[k] = v
    # The route rides the launch's file, never the environment.
    out.pop(ROUTE_ENV, None)
    dirs = route.get("pathPrefix") if isinstance(route.get("pathPrefix"), list) else []
    have = out.get("PATH") if isinstance(out.get("PATH"), str) and out.get("PATH") != "" else (route.get("path") or "")
    rest = [d for d in have.split(os.pathsep) if d != "" and d not in dirs]
    out["PATH"] = os.pathsep.join(list(dirs) + rest)
    py = route.get("pythonPath")
    if isinstance(py, str) and py != "":
        cur = out.get("PYTHONPATH") if isinstance(out.get("PYTHONPATH"), str) and out.get("PYTHONPATH") != "" else ""
        parts = [d for d in cur.split(os.pathsep) if d != "" and d != py] if cur else []
        out["PYTHONPATH"] = os.pathsep.join([py] + parts)
    req = route.get("require")
    if isinstance(req, str) and req != "":
        opt = _require_option(req)
        cur = out.get("NODE_OPTIONS") if isinstance(out.get("NODE_OPTIONS"), str) else ""
        if opt not in cur.split():
            out["NODE_OPTIONS"] = opt if cur.strip() == "" else "%s %s" % (cur.strip(), opt)
    return out


def _bare(p):
    b = os.path.basename(p)
    for ext in (".exe", ".js", ".mjs", ".cjs"):
        if b.lower().endswith(ext):
            return b[: -len(ext)]
    return b


def _may_be_agent(file, args):
    """Whether the Node preload must decide this child: it names an agent, a JS
    runtime runs something, or the arguments carry an agent's name or the
    SDKs' command line. Anything else only gets its environment back."""
    if _bare(file) in _AGENT_NAMES or _bare(file) in _JS_RUNTIMES:
        return True
    for a in args:
        if _bare(a) in _AGENT_NAMES or a in ("stream-json", "--experimental-json", "app-server"):
            return True
    return False


_local = threading.local()
_ROUTE = None


def _decide(file, args, env, cwd):
    """The Node preload's routeSpawn for one child: (args, env), or raise."""
    node = _ROUTE.get("node")
    preload = _ROUTE.get("require")
    if not isinstance(node, str) or node == "" or not isinstance(preload, str) or preload == "":
        raise ManduRouteRefused("mandu: refusing to start %s: the route names no Node to decide it with" % file)
    # The decision reads the launch's route from beside the preload; this
    # process's own values only narrow it (the preload's decideMain).
    req = json.dumps({"own": _ROUTE["env"], "file": file, "args": args, "env": env, "cwd": cwd})
    _local.busy = True
    try:
        res = subprocess.run(
            [node, "--no-warnings", preload, "--decide"],
            input=req.encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, timeout=60,
        )
        answer = json.loads(res.stdout.decode("utf-8"))
    except Exception as e:  # noqa: BLE001 — any failure is a refusal (fail-closed)
        raise ManduRouteRefused("mandu: refusing to start %s: Mandu's route could not decide it (%s)" % (file, e))
    finally:
        _local.busy = False
    if not isinstance(answer, dict):
        raise ManduRouteRefused("mandu: refusing to start %s: Mandu's route gave no answer" % file)
    if "refusal" in answer:
        raise ManduRouteRefused(str(answer["refusal"]))
    out_args, out_env = answer.get("args"), answer.get("env")
    if not isinstance(out_args, list) or not isinstance(out_env, dict):
        raise ManduRouteRefused("mandu: refusing to start %s: Mandu's route gave no answer" % file)
    return [str(a) for a in out_args], {str(k): str(v) for k, v in out_env.items()}


def route_child(args, executable, cwd, env, shell):
    """(args, env) to start one Popen child with. `args` as Popen holds it."""
    base = dict(os.environ) if env is None else {os.fsdecode(k): os.fsdecode(v) for k, v in env.items()}
    if shell or isinstance(args, (str, bytes, os.PathLike)):
        argv = [os.fsdecode(args)] if not shell else None
    else:
        argv = [os.fsdecode(a) for a in args]
    if not argv:
        # A shell command string: its environment only (the PATH shims meet an
        # agent CLI it names).
        return args, (base if _ROUTE is None else route_env(_ROUTE, base))
    file = os.fsdecode(executable) if executable is not None else argv[0]
    rest = argv[1:]
    if _ROUTE is None:
        # The launch's route is missing or unreadable: nothing to put back,
        # and a child that may be an agent would run unrouted.
        if _may_be_agent(file, rest):
            raise ManduRouteRefused(
                "mandu: refusing to start %s: Mandu's route file is missing or unreadable, so it would run unrouted" % file)
        return args, base
    if not _may_be_agent(file, rest):
        return args, route_env(_ROUTE, base)
    here = os.fsdecode(cwd) if cwd is not None else os.getcwd()
    out_args, out_env = _decide(file, rest, base, here)
    return [argv[0]] + out_args, out_env


def _install():
    orig = subprocess.Popen._execute_child
    if getattr(orig, "_mandu_sdk_route", False):
        return

    def _execute_child(self, args, executable, preexec_fn, close_fds, pass_fds, cwd, env, startupinfo,
                       creationflags, shell, *rest, **kw):
        if not getattr(_local, "busy", False):
            args, env = route_child(args, executable, cwd, env, shell)
        return orig(self, args, executable, preexec_fn, close_fds, pass_fds, cwd, env, startupinfo,
                    creationflags, shell, *rest, **kw)

    _execute_child._mandu_sdk_route = True
    subprocess.Popen._execute_child = _execute_child


def _chain():
    """Load the `sitecustomize` this one shadows, if there is one."""
    import importlib.machinery
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    paths = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != here]
    spec = importlib.machinery.PathFinder.find_spec("sitecustomize", paths)
    if spec is None or spec.loader is None or spec.origin == os.path.abspath(__file__):
        return
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)


_route_dir = _own_route_dir()
if _route_dir is not None and os.name == "posix":
    _received = _read_route_file(os.path.join(_route_dir, ROUTE_FILE))
    # The decision needs the Node binary and the preload, which ride in the
    # route itself, not in the variables. No route: _ROUTE stays None and the
    # hook refuses every child that may be an agent (fail-closed).
    _ROUTE = effective_route(_received, os.environ) if _received is not None else None
    _install()
try:
    _chain()
except Exception:  # noqa: BLE001 — the shadowed one's own failure is not ours
    pass
