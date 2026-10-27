"""test_reporter.py — JSON/CSV/table output formatting.

No network. Verifies the CSV column contract and the table/summary helpers.
"""
import csv
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import reporter


def _rec(verdict="vulnerable", php="8.4.26", ready=True, score=90):
    return {
        "url": "http://t/",
        "detect": {"url": "http://t/", "verdict": verdict,
                   "php_version": php, "branch": "8.4",
                   "upload_progress": "on", "display_errors": "on",
                   "status": 200, "reachable": True, "server": "Apache",
                   "fix_floor": "8.4.27", "reason": "x",
                   "patched_but_bypassable": False, "signals": [],
                   "error": ""},
        "preflight": {"score": score, "max_score": 90, "ready": ready,
                       "checks": {}, "blockers": [], "notes": [],
                       "support": {"level": "rce", "text": ""},
                       "body_cap": "unknown"},
    }


class CSVTests(unittest.TestCase):
    def test_columns_contract(self):
        self.assertEqual(reporter.CSV_COLUMNS[0], "url")
        self.assertIn("verdict", reporter.CSV_COLUMNS)
        self.assertIn("score", reporter.CSV_COLUMNS)
        self.assertIn("ready", reporter.CSV_COLUMNS)
        self.assertIn("exploited", reporter.CSV_COLUMNS)

    def test_write_csv_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.csv")
            reporter.write_csv(path, [_rec()])
            with open(path, encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["verdict"], "vulnerable")
            self.assertEqual(rows[0]["php_version"], "8.4.26")
            self.assertEqual(rows[0]["ready"], "True")


class JSONTests(unittest.TestCase):
    def test_write_json_structure(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            reporter.write_json(path, [_rec()], {"mode": "scan"})
            data = json.loads(open(path, encoding="utf-8").read())
            self.assertEqual(data["count"], 1)
            self.assertEqual(data["meta"]["mode"], "scan")
            self.assertEqual(data["results"][0]["detect"]["verdict"],
                             "vulnerable")


class TableTests(unittest.TestCase):
    def test_empty_table(self):
        self.assertIn("no targets", reporter.table([]))

    def test_table_has_rows(self):
        t = reporter.table([_rec(), _rec()])
        self.assertIn("verdict", t)
        self.assertIn("http://t/", t)

    def test_summary_counts(self):
        s = reporter.summary([_rec(verdict="vulnerable"),
                              _rec(verdict="patched", ready=False)])
        self.assertIn("total=2", s)
        self.assertIn("vulnerable=1", s)
        self.assertIn("patched=1", s)


if __name__ == "__main__":
    unittest.main()
