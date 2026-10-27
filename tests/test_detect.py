"""test_detect.py — version classification + detection dataclass.

No network. Verifies the fix-floor map and the verdict logic that decides
vulnerable / patched / eol.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import detect as detect_mod


class ClassifyTests(unittest.TestCase):
    def test_vulnerable_8_4(self):
        v, r, fix = detect_mod.classify("8.4.26", "8.4")
        self.assertEqual(v, "vulnerable")
        self.assertEqual(fix, "8.4.27")
        self.assertIn("8.4.26", r)

    def test_patched_8_4(self):
        v, r, fix = detect_mod.classify("8.4.27", "8.4")
        self.assertEqual(v, "patched")
        self.assertEqual(fix, "8.4.27")

    def test_eol_7_4(self):
        v, r, fix = detect_mod.classify("7.4.33", "7.4")
        self.assertEqual(v, "eol")
        self.assertIn("END-OF-LIFE", r)

    def test_unknown_branch(self):
        v, r, fix = detect_mod.classify("9.9.9", "9.9")
        self.assertEqual(v, "unknown")

    def test_fix_floor_map_complete(self):
        for b in ("8.2", "8.3", "8.4", "8.5"):
            with self.subTest(branch=b):
                self.assertIn(b, detect_mod.FIX_FLOOR)

    def test_last_vuln_map_complete(self):
        for b in ("8.2", "8.3", "8.4", "8.5"):
            with self.subTest(branch=b):
                self.assertIn(b, detect_mod.LAST_VULN)


class ParseVersionTests(unittest.TestCase):
    def test_parse_x_powered_by(self):
        v, b = detect_mod._parse_version("X-Powered-By: PHP/8.4.26")
        self.assertEqual(v, "8.4.26")
        self.assertEqual(b, "8.4")

    def test_parse_bare(self):
        v, b = detect_mod._parse_version("running PHP 8.3.35 here")
        self.assertEqual(v, "8.3.35")
        self.assertEqual(b, "8.3")

    def test_parse_none(self):
        self.assertIsNone(detect_mod._parse_version("nothing here"))


class DetectionDataclassTests(unittest.TestCase):
    def test_defaults(self):
        d = detect_mod.Detection(url="http://t/")
        self.assertEqual(d.verdict, "unknown")
        self.assertEqual(d.upload_progress, "unknown")
        self.assertEqual(d.display_errors, "unknown")
        self.assertFalse(d.patched_but_bypassable)

    def test_as_dict_keys(self):
        d = detect_mod.Detection(url="http://t/", verdict="vulnerable")
        dd = d.as_dict()
        for k in ("url", "verdict", "php_version", "branch", "fix_floor",
                  "upload_progress", "display_errors", "signals"):
            self.assertIn(k, dd)


if __name__ == "__main__":
    unittest.main()
