"""test_preflight.py — readiness scoring logic.

No network. Feeds synthetic Detection objects to preflight and checks the
score, blockers, and the READY decision.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import preflight as preflight_mod
from lib.detect import Detection


class PreflightTests(unittest.TestCase):
    def test_vulnerable_target_ready(self):
        d = Detection(url="http://t/", reachable=True, status=200,
                       verdict="vulnerable", php_version="8.4.26",
                       branch="8.4", fix_floor="8.4.27",
                       upload_progress="on", display_errors="on")
        p = preflight_mod.preflight(d)
        self.assertTrue(p.ready)
        self.assertEqual(p.score, p.max_score)
        self.assertEqual(p.support_level, "rce")

    def test_patched_target_blocked(self):
        d = Detection(url="http://t/", reachable=True, status=200,
                       verdict="patched", php_version="8.4.27",
                       branch="8.4", fix_floor="8.4.27",
                       upload_progress="on", display_errors="on")
        p = preflight_mod.preflight(d)
        self.assertFalse(p.ready)
        self.assertTrue(p.blockers)

    def test_eol_target_ready(self):
        d = Detection(url="http://t/", reachable=True, status=200,
                       verdict="eol", php_version="7.4.33",
                       branch="7.4", upload_progress="on",
                       display_errors="off")
        p = preflight_mod.preflight(d)
        self.assertTrue(p.ready)

    def test_unknown_version_not_blocked(self):
        d = Detection(url="http://t/", reachable=True, status=200,
                       verdict="unknown", upload_progress="unknown",
                       display_errors="unknown")
        p = preflight_mod.preflight(d)
        self.assertTrue(p.ready)
        self.assertEqual(p.support_level, "unknown")

    def test_unreachable_blocked(self):
        d = Detection(url="http://t/", reachable=False, status=0,
                       verdict="unknown")
        p = preflight_mod.preflight(d)
        self.assertFalse(p.ready)
        self.assertTrue(any("unreachable" in b for b in p.blockers))

    def test_display_errors_off_not_blocked(self):
        # leak comes via Set-Cookie, not error output — off is neutral
        d = Detection(url="http://t/", reachable=True, status=200,
                       verdict="vulnerable", php_version="8.4.26",
                       branch="8.4", fix_floor="8.4.27",
                       upload_progress="on", display_errors="off")
        p = preflight_mod.preflight(d)
        self.assertTrue(p.ready)
        self.assertGreaterEqual(p.score, 60)

    def test_verdict_line_format(self):
        d = Detection(url="http://t/", reachable=True, status=200,
                       verdict="vulnerable", php_version="8.4.26",
                       branch="8.4", fix_floor="8.4.27",
                       upload_progress="on", display_errors="on")
        p = preflight_mod.preflight(d)
        line = preflight_mod.verdict_line(d, p)
        self.assertIn("vulnerable", line)
        self.assertIn("READY", line)


if __name__ == "__main__":
    unittest.main()
