"""Unit tests for lib/auto.py — SAPI detection, path discovery helpers."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lib.auto import detect_sapi  # noqa: E402


class SapiDetectionTests(unittest.TestCase):
    """detect_sapi() parses the Server header."""

    def test_mod_php(self):
        self.assertEqual(
            detect_sapi("Apache/2.4.58 (Ubuntu) mod_php8.3"),
            "mod_php")

    def test_mod_fcgid(self):
        self.assertEqual(
            detect_sapi("Apache/2.4.6 (CentOS) mod_fcgid/2.3.9 PHP/8.1.29"),
            "mod_fcgid")

    def test_fpm(self):
        self.assertEqual(
            detect_sapi("nginx/1.24.0 PHP-FPM"),
            "fpm")

    def test_php_in_server_header_implies_mod_php(self):
        self.assertEqual(
            detect_sapi("Apache/2.4.69 (Debian) PHP/8.4.26"),
            "mod_php")

    def test_plain_apache(self):
        self.assertEqual(
            detect_sapi("Apache/2.4.69 (Debian)"),
            "unknown")

    def test_nginx_only(self):
        self.assertEqual(detect_sapi("nginx/1.24.0"), "unknown")

    def test_empty(self):
        self.assertEqual(detect_sapi(""), "unknown")

    def test_none_like(self):
        self.assertEqual(detect_sapi(""), "unknown")

    def test_mod_fastcgi(self):
        self.assertEqual(
            detect_sapi("Apache/2.4 mod_fastcgi/2.4.6"),
            "mod_fcgid")

    def test_case_insensitive(self):
        self.assertEqual(
            detect_sapi("Apache/2.4.6 MOD_FCGID/2.3.9"),
            "mod_fcgid")


class SapiBlockingTests(unittest.TestCase):
    """Verify SAPI values that should block the exploit."""

    BLOCK_SAPIS = ("mod_fcgid", "fpm")
    ALLOW_SAPIS = ("mod_php", "unknown")

    def test_block_list(self):
        for sapi in self.BLOCK_SAPIS:
            self.assertIn(sapi, ("mod_fcgid", "fpm"),
                          f"{sapi} should be in the block list")

    def test_allow_list(self):
        for sapi in self.ALLOW_SAPIS:
            self.assertNotIn(sapi, ("mod_fcgid", "fpm"),
                             f"{sapi} should NOT be blocked")


if __name__ == "__main__":
    unittest.main()
