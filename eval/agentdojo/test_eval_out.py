"""
Offline unit test for eval_out.py (the AgentDojo runner's default report
location, on-disk-layout.md §9 decision 3). Stdlib only, Python 3.8+:

    python3 -m unittest discover -s eval/agentdojo -p 'test_*.py'

eval/lib/eval-out.test.ts runs it in the eval package's `npm test`.
Every case uses a temp MANDU_HOME / HOME; none touches a real ~/.mandu.
"""

import datetime
import os
import re
import shutil
import stat
import tempfile
import unittest

import eval_out


class EvalOutTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mdu-agentdojo-out-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, **extra):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        env.update(extra)
        return env

    def test_eval_runs_follows_mandu_home_then_home(self):
        mh = os.path.join(self.tmp, "mh")
        self.assertEqual(eval_out.eval_runs_dir(self.env(MANDU_HOME=mh), home="/nowhere"),
                         os.path.join(mh, "runs", "eval"))
        self.assertEqual(eval_out.eval_runs_dir(self.env(), home="/home/u"), "/home/u/.mandu/runs/eval")
        # An empty MANDU_HOME counts as unset (the table's rule).
        self.assertEqual(eval_out.eval_runs_dir(self.env(MANDU_HOME=""), home="/home/u"), "/home/u/.mandu/runs/eval")

    def test_run_id_shape(self):
        now = datetime.datetime(2026, 9, 29, 12, 3, 1, tzinfo=datetime.timezone.utc)
        self.assertEqual(eval_out.mint_run_id("agentdojo", now, "a1b2c3"), "20260929T120301Z-agentdojo-a1b2c3")
        self.assertRegex(eval_out.mint_run_id("agentdojo"), r"^\d{8}T\d{6}Z-agentdojo-[0-9a-f]{6}$")
        for bad in ("", "../x", "A", "a b"):
            with self.assertRaises(ValueError):
                eval_out.mint_run_id(bad)

    def test_default_is_a_new_private_run_dir_under_mandu_home(self):
        mh = os.path.join(self.tmp, "fresh", "mh")  # none of it exists yet
        path, defaulted = eval_out.resolve_report_path(None, "agentdojo", env=self.env(MANDU_HOME=mh))
        self.assertTrue(defaulted)
        run_dir = os.path.dirname(path)
        self.assertEqual(os.path.basename(path), "report.json")
        self.assertEqual(os.path.dirname(run_dir), os.path.join(mh, "runs", "eval"))
        self.assertRegex(os.path.basename(run_dir), r"^\d{8}T\d{6}Z-agentdojo-[0-9a-f]{6}$")
        for d in (mh, os.path.join(mh, "runs"), os.path.join(mh, "runs", "eval"), run_dir):
            self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700, d)
        # A second run gets its own dir.
        path2, _ = eval_out.resolve_report_path(None, "agentdojo", env=self.env(MANDU_HOME=mh))
        self.assertNotEqual(os.path.dirname(path2), run_dir)

    def test_out_wins_and_makes_nothing(self):
        mh = os.path.join(self.tmp, "mh")
        target = os.path.join(self.tmp, "mine.json")
        self.assertEqual(eval_out.resolve_report_path(target, "agentdojo", env=self.env(MANDU_HOME=mh)), (target, False))
        self.assertFalse(os.path.exists(mh))


if __name__ == "__main__":
    unittest.main()
