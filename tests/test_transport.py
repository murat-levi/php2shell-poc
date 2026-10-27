"""test_transport.py — JA3 profiles, target loading, OOM classification.

No network. Verifies the browser profile registry, the target-list parser,
and the OOM response classifier (signals S1-S4).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import transport as transport_mod
from lib import oomprobe as oom_mod


class ProfileTests(unittest.TestCase):
    def test_all_profiles_have_required_keys(self):
        for name, p in transport_mod.PROFILES.items():
            with self.subTest(profile=name):
                self.assertIn("impersonate", p)
                self.assertIn("ua", p)
                self.assertIn("lang", p)
                self.assertTrue(p["ua"])
                self.assertTrue(p["impersonate"])

    def test_default_profile_exists(self):
        self.assertIn(transport_mod.DEFAULT_PROFILE, transport_mod.PROFILES)

    def test_chrome_safari_firefox_present(self):
        for name in ("chrome", "safari", "firefox", "edge", "android"):
            with self.subTest(profile=name):
                self.assertIn(name, transport_mod.PROFILES)

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            transport_mod.Transport(profile="netscape")


class ResponseTests(unittest.TestCase):
    def test_ok_property(self):
        r = transport_mod.Response(url="x", status=200)
        self.assertTrue(r.ok)
        r = transport_mod.Response(url="x", status=404)
        self.assertFalse(r.ok)
        r = transport_mod.Response(url="x", status=0, error="boom")
        self.assertFalse(r.ok)

    def test_header_case_insensitive(self):
        r = transport_mod.Response(url="x", status=200,
                                   headers={"Set-Cookie": "PHPSESSID=abc"})
        self.assertEqual(r.header("set-cookie"), "PHPSESSID=abc")
        self.assertEqual(r.header("SET-COOKIE"), "PHPSESSID=abc")
        self.assertEqual(r.header("missing"), "")


class LoadTargetsTests(unittest.TestCase):
    def test_parses_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                          delete=False) as f:
            f.write("# comment\n\nhttp://a/\nhttps://b\n  \nhttp://a/\n")
            path = f.name
        try:
            urls = transport_mod.load_targets(path)
            self.assertEqual(urls, ["http://a/", "https://b"])
        finally:
            os.unlink(path)

    def test_adds_scheme_if_missing(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                          delete=False) as f:
            f.write("example.com\n")
            path = f.name
        try:
            urls = transport_mod.load_targets(path)
            self.assertEqual(urls, ["https://example.com"])
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            transport_mod.load_targets("/no/such/file.txt")


class OOMClassifyTests(unittest.TestCase):
    def _resp(self, status, body=""):
        return transport_mod.Response(url="x", status=status, body=body)

    def test_s1_oom_in_parser(self):
        body = ("Fatal error: Allowed memory size of 8388608 bytes "
                "exhausted, tried to allocate ... in Unknown on line 0")
        v, s = oom_mod._classify_response(self._resp(500, body), 100)
        self.assertEqual(v, "vulnerable")
        self.assertEqual(s, "oom_in_parser")

    def test_postlen_rejected_not_vulnerable(self):
        body = ("Warning: POST Content-Length of 9999999 bytes exceeds "
                "the limit of 8388608 bytes in Unknown on line 0")
        v, s = oom_mod._classify_response(self._resp(500, body), 100)
        self.assertEqual(v, "inconclusive")
        self.assertEqual(s, "post_len_rejected")

    def test_s2_empty_500(self):
        v, s = oom_mod._classify_response(self._resp(500, ""), 100)
        self.assertEqual(v, "vulnerable")
        self.assertEqual(s, "empty_500")

    def test_blocked_on_waf_reject(self):
        for code in (400, 403, 413, 429):
            with self.subTest(status=code):
                v, s = oom_mod._classify_response(self._resp(code, ""), 100)
                self.assertEqual(v, "blocked")

    def test_s3_worker_abort_fpm(self):
        for code in (502, 503, 504):
            with self.subTest(status=code):
                v, s = oom_mod._classify_response(self._resp(code, ""), 100,
                                                   sapi="fpm")
                self.assertEqual(v, "vulnerable")
                self.assertEqual(s, "worker_abort")

    def test_s3_suppressed_mod_php(self):
        v, s = oom_mod._classify_response(self._resp(502, ""), 100,
                                           sapi="mod_php")
        self.assertNotEqual(v, "vulnerable")

    def test_s4_empty_200(self):
        v, s = oom_mod._classify_response(self._resp(200, ""), 100, sapi="fpm")
        self.assertEqual(v, "vulnerable")
        self.assertEqual(s, "empty_200")

    def test_nonempty_500_inconclusive(self):
        v, s = oom_mod._classify_response(self._resp(500, "app error"), 100)
        self.assertEqual(v, "inconclusive")

    def test_nested_name_depth(self):
        name = oom_mod._nested_name(62)
        # a[b][b]... 61 times after the leading a
        self.assertEqual(name.count("[b]"), 61)

    def test_build_payload_size(self):
        p = oom_mod._build_payload(1)
        self.assertEqual(len(p), 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
