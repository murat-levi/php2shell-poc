"""detect.py — non-destructive detection for CVE-2026-109618 / 109619.

THIS IS NOT AN EXPLOIT. It only reads HTTP responses and infers:
  - PHP version (if leaked)
  - patch status against the fix-floor per branch
  - whether the branch is EOL (will never be patched)
  - externally visible prerequisites (upload_progress, display_errors)

Every claim here must be reproducible by a triager with plain `curl -I`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .transport import Response, Transport

# Fix-floor for the CVE-2026-109618/109619 family (2026-10-21). Applies to BOTH.
FIX_FLOOR: dict[str, tuple[int, int]] = {
    "8.2": (8, 35),
    "8.3": (8, 36),
    "8.4": (8, 27),
    "8.5": (8, 12),
}

# Most recent version per branch that is still vulnerable (for reporting).
LAST_VULN: dict[str, str] = {
    "8.2": "8.2.34",
    "8.3": "8.3.35",
    "8.4": "8.4.26",
    "8.5": "8.5.11",
}

EOL_BRANCHES = {"5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4",
                "8.0", "8.1"}

PHP_VER_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
PHP_BARE_RE = re.compile(r"\bPHP\s+(\d+)\.(\d+)\.(\d+)\b", re.I)
PHP_GENERIC_RE = re.compile(r"\bPHP/(\d+)\.(\d+)", re.I)
POWERED_RE = re.compile(r"X-Powered-By:\s*PHP/(\d+)\.(\d+)\.(\d+)", re.I)
DISPLAY_ERR_RE = re.compile(
    r"(Warning|Notice|Fatal error|Parse error|Deprecated)\s*(?:</b>)?\s*:.*?"
    r"\s*in\s+<b>(.+?)</b>\s*on\s+line\s*<b>(\d+)</b>",
    re.I | re.S,
)
DISPLAY_ERR_LOOSE_RE = re.compile(
    r"(Warning|Notice|Fatal error|Parse error|Deprecated)\s*(?:</b>)?\s*:\s*\S+",
    re.I,
)


@dataclass
class Detection:
    url: str
    reachable: bool = False
    status: int = 0
    server: str = ""
    powered_by: str = ""
    php_version: str | None = None
    branch: str | None = None
    verdict: str = "unknown"   # vulnerable | patched | eol | unknown
    fix_floor: str | None = None
    reason: str = ""
    upload_progress: str = "unknown"   # on | off | unknown
    display_errors: str = "unknown"   # on | off | unknown
    patched_but_bypassable: bool = False
    signals: list[str] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "status": self.status,
            "server": self.server,
            "powered_by": self.powered_by,
            "php_version": self.php_version,
            "branch": self.branch,
            "verdict": self.verdict,
            "fix_floor": self.fix_floor,
            "reason": self.reason,
            "upload_progress": self.upload_progress,
            "display_errors": self.display_errors,
            "patched_but_bypassable": self.patched_but_bypassable,
            "signals": self.signals,
            "error": self.error,
        }


def _parse_version(text: str) -> tuple[str, str] | None:
    for rx in (PHP_VER_RE, PHP_BARE_RE):
        m = rx.search(text or "")
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}", \
                   f"{m.group(1)}.{m.group(2)}"
    return None


def classify(version: str, branch: str) -> tuple[str, str, str | None]:
    """Return (verdict, reason, fix_floor) for a visible version."""
    if branch in EOL_BRANCHES:
        return (
            "eol",
            f"PHP {version} is END-OF-LIFE — will never receive the "
            f"CVE-2026-109618/109619 patch",
            None,
        )
    floor = FIX_FLOOR.get(branch)
    if not floor:
        return ("unknown", f"branch {branch} not in fix-floor map", None)
    fmaj, fmin = floor
    fix = f"{fmaj}.{branch.split('.')[1]}.{fmin}"
    parts = version.split(".")
    try:
        maj, mnr, pat = int(parts[0]), int(parts[1]), int(parts[2])
    except (IndexError, ValueError):
        return ("unknown", f"unparseable version: {version}", fix)
    if (maj, mnr, pat) < (fmaj, int(branch.split(".")[1]), fmin):
        last = LAST_VULN.get(branch, "?")
        return (
            "vulnerable",
            f"PHP {version} < fix-floor {fix} (last vulnerable: {last})",
            fix,
        )
    return ("patched", f"PHP {version} >= fix-floor {fix}", fix)


def _probe_display_errors(t: Transport, url: str) -> tuple[str, list[str]]:
    """Detect display_errors from a deliberately error-triggering request.

    Non-destructive: asks for a non-existent path (404) and a PHP route with a
    parameter that usually triggers a notice. Runs no commands.
    """
    signals: list[str] = []
    base = url.rstrip("/")
    for probe in (f"{base}/__php2shell_probe_{'0'*8}.php",
                  f"{base}/?php2shell_probe=1"):
        r = t.get(probe)
        body = r.body or ""
        m = DISPLAY_ERR_RE.search(body)
        if m:
            signals.append(
                f"display_errors=On (error at {m.group(2)}:{m.group(3)})")
            return "on", signals
        if DISPLAY_ERR_LOOSE_RE.search(body):
            signals.append("display_errors=On (PHP error pattern without path)")
            return "on", signals
    return "off", signals


def _probe_upload_progress(t: Transport, url: str) -> tuple[str, list[str]]:
    """Check session.upload_progress from outside WITHOUT sending a file.

    Technique: POST a ~1 KB multipart containing PHP_SESSION_UPLOAD_PROGRESS
    and PHPSESSID. If `session.upload_progress.enabled=On`, PHP processes
    that field via the rfc1867 callback and replies with `Set-Cookie:
    PHPSESSID`. This is the only external signal available — not proof of
    exploitation.
    """
    signals: list[str] = []
    boundary = "----php2shellprobe"
    sid = "php2shellprobe0001"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"probe\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        f"{sid}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    r = t.post(
        url,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Site": "same-origin",
            "Origin": url.rstrip("/"),
            "Referer": url,
        },
    )
    sc = r.header("set-cookie")
    if sc and "PHPSESSID" in sc.upper():
        signals.append(
            "upload_progress=On (PHPSESSID emitted after 1 KB probe)")
        return "on", signals
    if r.status in (401, 403):
        signals.append(f"upload_progress not visible (HTTP {r.status} from edge/WAF)")
        return "unknown", signals
    if r.status >= 500:
        signals.append(f"upload_progress not visible (HTTP {r.status})")
        return "unknown", signals
    signals.append(f"upload_progress not visible (HTTP {r.status}, no Set-Cookie)")
    return "unknown", signals


def detect(
    url: str,
    transport: Transport | None = None,
    check_upload_progress: bool = True,
    check_display_errors: bool = True,
    check_oom: bool | None = None,
    sapi: str = "auto",
) -> Detection:
    """Detect php2shell posture for one URL.

    check_oom: None (default) = auto — only run if verdict is still
      "unknown" or "eol" after passive probes. True = always. False = never.
    sapi: "auto" | "fpm" | "mod_php" — forwarded to the OOM probe gating.
    """
    own = transport is None
    t = transport or Transport()
    d = Detection(url=url)
    try:
        r: Response = t.get(url)
        d.status = r.status
        d.reachable = r.ok and r.status != 0
        d.server = r.header("server")
        d.powered_by = r.header("x-powered-by")
        d.error = r.error
        blob = f"{d.powered_by}\n{d.server}\n{(r.body or '')[:200_000]}"
        vers = _parse_version(blob)
        gm = PHP_GENERIC_RE.search(blob) or POWERED_RE.search(blob)
        if vers:
            d.php_version, d.branch = vers
            d.verdict, d.reason, d.fix_floor = classify(*vers)
        elif gm:
            d.branch = f"{gm.group(1)}.{gm.group(2)}"
            d.verdict = "eol" if d.branch in EOL_BRANCHES else "unknown"
            d.reason = f"branch {d.branch} visible, patch-level not leaked"
            d.php_version = None
        else:
            d.verdict = "unknown"
            d.reason = "PHP version not leaked (clean headers / CDN-fronted)"

        if check_display_errors:
            d.display_errors, sig = _probe_display_errors(t, url)
            d.signals.extend(sig)
        if check_upload_progress:
            d.upload_progress, sig = _probe_upload_progress(t, url)
            d.signals.extend(sig)

        # patched-but-bypassable: version is patched but a second mitigation is absent
        if d.verdict == "patched" and (
            d.upload_progress == "on" or d.display_errors == "on"
        ):
            d.patched_but_bypassable = True
            d.signals.append(
                "patched_but_bypassable: version >= fix-floor but "
                f"upload_progress={d.upload_progress}, "
                f"display_errors={d.display_errors}")
        if d.verdict == "eol" and d.upload_progress == "on":
            d.reason += " · upload_progress=ON (worst-case combo)"

        # ---- active OOM detection (assetnote php2shell-scanner style) ----
        run_oom = check_oom if check_oom is not None else (
            d.verdict in ("unknown", "eol"))
        if run_oom:
            from .oomprobe import oom_detect  # local import: avoid cycle
            oom = oom_detect(url, transport=t, sapi=sapi)
            d.signals.append(
                f"oom: verdict={oom.verdict} signal={oom.signal} "
                f"probes={oom.probes_sent} ({oom.evidence})")
            if oom.verdict == "vulnerable":
                d.verdict = "vulnerable"
                d.reason = f"active OOM probe: {oom.signal} — {oom.evidence}"
                if not d.php_version:
                    d.branch = d.branch or "unknown-branch"
            elif oom.verdict == "not_vulnerable" and d.verdict == "unknown":
                d.verdict = "not_vulnerable"
                d.reason = (
                    "version not leaked, but active OOM probe returned a "
                    "normal response (no fatal-in-parser / empty-500 / "
                    "abort) — target does not respond to the php2shell path")
            elif oom.verdict == "inconclusive" and d.verdict == "unknown":
                d.reason += (
                    " · OOM probe inconclusive (target memory_limit may be "
                    "> 20 MiB; raise PROBES_MB in lib/oomprobe.py if "
                    "authorized, or verify via version/fix-floor)")
            elif oom.verdict == "blocked" and d.verdict == "unknown":
                d.reason += " · OOM probe blocked by WAF (verdict retained)"
            elif oom.verdict == "error" and d.verdict == "unknown":
                d.reason += f" · OOM probe error: {oom.error}"
    except Exception as exc:  # noqa: BLE001
        d.error = f"{type(exc).__name__}: {exc}"
    finally:
        if own:
            t.close()
    return d
