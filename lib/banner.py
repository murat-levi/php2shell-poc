"""banner.py — ASCII art + identity for the php2shell toolkit.

All text here is pure presentation. No network logic.
Color auto-disables when stdout is not a TTY or NO_COLOR is set.
"""

from __future__ import annotations

import os
import sys

CVE_IDS = "CVE-2026-109619"
CVE_FAMILY = "CVE-2026-109618/109619"

ART = r"""
 ____  _   _ ____ ____  ____  _   _ _____ _     _
|  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |
| |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |
|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
|_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|
"""

TAGLINE = (
    "  PHP session.upload_progress stale-state UAF  ->  unauthenticated RCE\n"
    "  tested here   : CVE-2026-109619 (full chain)\n"
    "  detected      : CVE-2026-109618 (version classify; DIFFERENT chain, not run)\n"
    "  same CVE family · CVSS 9.2 · PHP 5.4 - 8.x\n"
)

USAGE_HINT = (
    "  mode  : scan | detect | preflight | exploit | shell | version\n"
    "  quick : php2shell.py scan -l targets.txt\n"
    "  help  : php2shell.py --help\n"
)

FIX_FLOOR = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}
LAST_VULN = {
    "8.5": "8.5.11",
    "8.4": "8.4.26",
    "8.3": "8.3.35",
    "8.2": "8.2.34",
}

_WIDTH = 64


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return True


class C:
    """ANSI 256-color (brighter, high contrast on dark terminals)."""

    def __init__(self, on: bool):
        self.on = on

    def _w(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s

    def red(self, s):     return self._w("38;5;203", s)
    def green(self, s):   return self._w("38;5;48", s)
    def yellow(self, s):  return self._w("38;5;220", s)
    def blue(self, s):    return self._w("38;5;39", s)
    def magenta(self, s): return self._w("38;5;207", s)
    def cyan(self, s):    return self._w("38;5;51", s)
    def grey(self, s):    return self._w("38;5;245", s)
    def white(self, s):   return self._w("38;5;255", s)
    def bold(self, s):    return self._w("1", s)
    def dim(self, s):     return self._w("2", s)


def art(c: "C") -> str:
    if not c.on:
        return ART.strip("\n")
    lines = ART.strip("\n").splitlines()
    paints = (c.cyan, c.cyan, c.blue, c.blue, c.magenta)
    return "\n".join(paints[i % len(paints)](ln) for i, ln in enumerate(lines))


def render(mode: str = "", profile: str = "", delay: float = 0.0,
           stealth: bool = True, version: str | None = None) -> str:
    c = C(_use_color())
    if version is None:
        version = ""
        for name in ("php2shell", "__main__"):
            mod = sys.modules.get(name)
            v = getattr(mod, "VERSION", None) if mod else None
            if v:
                version = v
                break
    out = []
    out.append(art(c))
    out.append("  " + c.bold(c.white("P H P 2 S H E L L")) +
               c.dim(f"  v{version}" if version else "") +
               c.grey("  -  unified toolkit"))
    out.append(c.grey("  " + "-" * _WIDTH))
    out.append(c.yellow("  tested: ") + c.white("CVE-2026-109619") +
               c.grey(" (full chain)   ") +
               c.yellow("detect: ") + c.grey("CVE-2026-109618 (different chain, not run)"))
    out.append(c.white("  fix-floor: ") +
               c.green("8.2.35") + c.white(" / ") +
               c.green("8.3.36") + c.white(" / ") +
               c.green("8.4.27") + c.white(" / ") +
               c.green("8.5.12"))
    out.append(c.white("  last vulnerable: ") +
               c.red("8.2.34") + c.white(" / ") +
               c.red("8.3.35") + c.white(" / ") +
               c.red("8.4.26") + c.white(" / ") +
               c.red("8.5.11"))
    out.append(c.grey("  " + "-" * _WIDTH))

    if mode:
        out.append(c.white("  mode   : ") + c.bold(c.cyan(mode)))
    if profile:
        out.append(c.white("  ja3    : ") + c.cyan(profile))
    if delay:
        out.append(c.white("  delay  : ") + c.cyan(f"{delay}s") +
                   c.grey("  (+jitter)"))
    if stealth:
        out.append(c.white("  stealth: ") + c.green("curl_cffi JA3 impersonate"))
    else:
        out.append(c.white("  stealth: ") +
                   c.red("urllib fallback - EASILY DETECTED") +
                   c.grey(" (pip install curl_cffi)"))
    out.append(c.grey("  " + "-" * _WIDTH))
    return "\n".join(out)


def splash() -> str:
    c = C(_use_color())
    out = [render()]
    out.append("")
    out.append(c.cyan(USAGE_HINT.rstrip("\n")))
    out.append("")
    out.append(c.grey("  guards & warnings: php2shell.py --help  |  details: README.md"))
    return "\n".join(out)


GUARDS_TEXT = (
    "  Guards enforced in CODE, not text — cannot be disabled from the CLI:\n"
    "    - exploit only on READY targets + confirmation (--yes or answer y)\n"
    "    - proof commands: id / whoami / uname / hostname / pwd, max 14 bytes\n"
    "    - chaining ( ; | & $ ` > < ) REJECTED\n"
    "    - --revshell DOES NOT EXIST in the parser and is blocked at the runner\n"
    "    - chains run in-process from lib/chain.py; sha256 printed every run\n"
)
