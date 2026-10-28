"""test_cli.py — argparse structure + CLI smoke (no network).

Verifies the unified CLI exposes all 6 modes, that guards are wired in, and
that `version` runs end-to-end without touching the network.
"""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib.util
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "php2shell_cli", os.path.join(ROOT, "php2shell.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.cli = _load_cli()
        self.parser = self.cli.build_parser()

    def test_six_subcommands(self):
        # parse_args with a subcommand should set .sub
        for mode in ("scan", "detect", "preflight", "exploit", "shell",
                     "version"):
            with self.subTest(mode=mode):
                ns = self.parser.parse_args([mode, "http://x/"]
                                            if mode in ("preflight", "exploit")
                                            else [mode] if mode in ("shell", "version")
                                            else [mode, "http://x/"])
                self.assertEqual(ns.sub, mode)

    def test_ja3_choices(self):
        ns = self.parser.parse_args(["detect", "http://x/", "--ja3", "safari"])
        self.assertEqual(ns.ja3, "safari")

    def test_wan_flag_parses(self):
        ns = self.parser.parse_args(["-u", "http://x/", "--wan"])
        self.assertTrue(ns.wan)
        ns = self.parser.parse_args(["exploit", "http://x/", "--wan"])
        self.assertTrue(ns.wan)
        ns = self.parser.parse_args(["-u", "http://x/"])
        self.assertFalse(ns.wan)

    def test_chain_choices(self):
        ns = self.parser.parse_args(["exploit", "http://x/", "--chain", "remote"])
        self.assertEqual(ns.chain, "remote")

    def test_exploit_profile_choices(self):
        ns = self.parser.parse_args(["exploit", "http://x/",
                                      "--exploit-profile", "lab"])
        self.assertEqual(ns.exploit_profile, "lab")

    def test_no_subcommand_prints_splash(self):
        # no sub -> func not set; main() prints splash
        ns = self.parser.parse_args([])
        self.assertFalse(getattr(ns, "sub", None))

    def test_version_runs(self):
        rc = self.cli.cmd_version(argparse_stub())
        self.assertEqual(rc, 0)


def argparse_stub():
    return type("NS", (), {})()


class SubprocessSmokeTests(unittest.TestCase):
    def test_cli_version_subprocess(self):
        # run the real file as a subprocess to catch import-time errors
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, "php2shell.py"), "version"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("php2shell 2.1.0", r.stdout)
        self.assertIn("CVE-2026-109619", r.stdout)

    def test_cli_no_args_shows_splash(self):
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, "php2shell.py")],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertIn("P H P 2 S H E L L", r.stdout)


if __name__ == "__main__":
    unittest.main()
