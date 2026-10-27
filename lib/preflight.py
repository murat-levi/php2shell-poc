"""preflight.py — exploit readiness score for one target (non-destructive).

Scores only what is externally visible + what is publicly known about the
upstream exploit. Goal: answer one question — "if I run the exploit here,
does it have a chance, or am I just wasting time / tripping an alarm?"

NOT an exploit. Does not send the 3 MB / 12 MB OOM payload.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detect import Detection


PREREQS = (
    ("display_errors", "display_errors=On (convenience; leak still works when off)"),
    ("upload_progress", "session.upload_progress.enabled=On (chain 109619 consumer)"),
    ("version", "version below fix-floor OR EOL"),
)


@dataclass
class Preflight:
    url: str
    score: int = 0            # 0..90
    max_score: int = 90
    ready: bool = False
    checks: dict[str, str] = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    support_level: str = "unknown"   # rce | leak | no | unknown
    support_text: str = ""
    body_cap: str = "unknown"

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "score": self.score,
            "max_score": self.max_score,
            "ready": self.ready,
            "support": {"level": self.support_level, "text": self.support_text},
            "body_cap": self.body_cap,
            "checks": self.checks,
            "blockers": self.blockers,
            "notes": self.notes,
        }


def _support_level(php_version: str | None) -> tuple[str, str]:
    """Coarse build-support hint. NOT a blocker — operator still decides."""
    if not php_version:
        return "unknown", "version not leaked; chain runs with default offsets"
    if php_version.startswith("8.4."):
        return "rce", f"PHP {php_version} bookworm build — full RCE proven"
    if php_version.startswith(("8.2.", "8.3.", "8.5.")):
        return "leak", f"PHP {php_version} — leak stage proven; RCE unverified"
    return "no", f"PHP {php_version} — no proven chain; supply manual offsets"


def preflight(d: Detection) -> Preflight:
    p = Preflight(url=d.url)
    pts = 0

    # PHILOSOPHY: detection = INFORMATION, not a GATE. Unknown version behind
    # a CDN is not a reason to hold the exploit — those are real-world cases.
    # Only two things hard-block:
    #   1. target UNREACHABLE (obvious waste of time), and
    #   2. version READABLE and already >= fix-floor (patched) — shooting a
    #      known-patched version is a pointless crash.

    # --- version (30) ---
    if d.verdict == "vulnerable":
        pts += 30
        p.checks["version"] = f"OK — {d.php_version or d.branch} below fix-floor"
    elif d.verdict == "eol":
        pts += 30
        p.checks["version"] = f"OK — {d.php_version or d.branch} EOL (never patched)"
    elif d.verdict == "patched":
        p.checks["version"] = f"BLOCK — {d.php_version} already >= {d.fix_floor}"
        p.blockers.append(
            f"version {d.php_version} is patched (fix {d.fix_floor}); "
            "CVE-2026-109619/109618 does not apply")
    else:
        pts += 15
        p.checks["version"] = (
            "UNKNOWN — version not leaked (CDN / clean headers); CHAIN STILL "
            "RUNS — default bookworm offsets, retry if build differs")
        p.notes.append(
            "version not detected: chain still executes (not a blocker). "
            "If stage leak fails, the build may differ from bookworm — "
            "supply --zif-offset / --dtor-offset measured from the target binary.")

    # --- upload_progress (30) ---
    if d.upload_progress == "on":
        pts += 30
        p.checks["upload_progress"] = "OK — 109619 chain consumer open"
    elif d.upload_progress == "off":
        p.checks["upload_progress"] = "BLOCK-ish — 109619 chain consumer closed"
        p.notes.append(
            "upload_progress appears off; the 109619 consumer path is likely "
            "closed, but this is NOT proof of safety (the 109618/109619 OOM "
            "producer remains — version patch is the only full mitigation)")
    else:
        p.checks["upload_progress"] = "UNKNOWN (edge/WAF hides the answer)"
        p.notes.append(
            "upload_progress not visible: could be WAF, could be config. "
            "Do not conclude safe.")

    # --- display_errors (30) ---
    # IMPORTANT: this toolkit's leak comes from the Set-Cookie header
    # (OOB read via PS(id)), NOT from error output. So display_errors=off
    # does NOT close the leak path. Off only lowers the comfort signal,
    # it is NOT a blocker.
    if d.display_errors == "on":
        pts += 30
        p.checks["display_errors"] = "OK — error output visible (convenience, not a requirement)"
    elif d.display_errors == "off":
        pts += 15
        p.checks["display_errors"] = "NEUTRAL — leak via Set-Cookie, not error output"
    else:
        p.checks["display_errors"] = "UNKNOWN"

    p.score = min(pts, p.max_score)

    # --- build support (RCE vs LEAK vs unproven) ---
    p.support_level, p.support_text = _support_level(d.php_version)
    if p.support_level == "leak":
        p.notes.append(
            "this build is only proven up to the leak stage — stage 3 (fake "
            "HashTable -> zif_system) is unverified. Commands will NOT run; "
            "stop after the address leak.")
    elif p.support_level == "no":
        p.notes.append(
            "this build has never been proven to chain at all. The chain "
            "will likely stop at stage 1-2; prepare manual offsets if you "
            "still want to try.")

    # --- body size cap (signal, not a blocker) ---
    if p.body_cap == "rejected":
        p.checks["body_cap"] = ("LIMITED — 16 MB body rejected/dropped; "
                                "target post_max_size smaller than stage-1 body")
        p.notes.append(
            "target post_max_size/upload_max_filesize likely < 16 MB. The "
            "stage-1 body is dropped by PHP before code runs, so the leak "
            "stage will fail regardless of offsets. Not proof of safety.")
    elif p.body_cap == "accepted":
        p.checks["body_cap"] = "OK — 16 MB body accepted by PHP"

    # READY rule: only hard blockers hold. Low score / "unknown" does NOT hold.
    p.ready = not p.blockers
    if not d.reachable:
        p.blockers.append(f"target unreachable (HTTP {d.status})")
        p.ready = False
    return p


def verdict_line(d: Detection, p: Preflight) -> str:
    """One line for the terminal table."""
    ver = d.php_version or (d.branch or "?")
    lvl = {"rce": "RCE", "leak": "LEAK", "no": "NO",
           "unknown": "?"}.get(p.support_level, "?")
    return (
        f"{d.verdict:<10} | {ver:<8} | {lvl:<4} | up={d.upload_progress:<7} | "
        f"disp={d.display_errors:<7} | score={p.score:>2}/{p.max_score} | "
        f"{'READY' if p.ready else 'NO'}"
    )
