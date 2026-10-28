"""test_syntax.py — every .py file compiles and imports cleanly.

Catches the most common merge-time mistakes: a stray typo, a missing import,
a half-edited file. Runs without network or dependencies.
"""
import os
import py_compile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _py_files():
    out = []
    for dirpath, _, files in os.walk(ROOT):
        if "__pycache__" in dirpath or dirpath.endswith(".venv"):
            continue
        for f in files:
            if f.endswith(".py"):
                out.append(os.path.join(dirpath, f))
    return sorted(out)


class SyntaxTests(unittest.TestCase):
    def test_all_py_compile(self):
        files = _py_files()
        self.assertGreater(len(files), 10, "expected to find python files")
        for path in files:
            with self.subTest(path=path):
                py_compile.compile(path, doraise=True)

    def test_lib_modules_import(self):
        import importlib
        for name in ("transport", "detect", "preflight", "oomprobe",
                     "reporter", "banner", "chain", "exploit_runner"):
            with self.subTest(mod=name):
                importlib.import_module(f"lib.{name}")

    def test_main_cli_module_imports(self):
        # importing php2shell.py must not execute main()
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "php2shell_cli", os.path.join(ROOT, "php2shell.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.VERSION, "2.1.0")
        self.assertEqual(mod.CVE_IDS, "CVE-2026-109619")


if __name__ == "__main__":
    unittest.main()
