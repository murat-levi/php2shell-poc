"""transport.py — HTTP with browser JA3/TLS fingerprint, rate limit, audit.

Why this exists: every phase of the toolkit (detect, preflight, exploit probe,
scan) talks to the target through ONE transport so a single target only ever
sees one consistent browser identity. Behind Cloudflare/Akamai a raw socket
with a Python TLS fingerprint and no User-Agent is flagged instantly.

`curl_cffi` is optional: when present it impersonates Chrome/Safari/Firefox/
Edge/Android down to the TLS ClientHello (JA3). When absent it degrades to
urllib with full browser headers (still detectable, but does not crash).
"""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# (impersonate, User-Agent, Accept-Language). Rotated per request optionally.
PROFILES: dict[str, dict[str, str]] = {
    "chrome": {
        "impersonate": "chrome124",
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
        "lang": "en-US,en;q=0.9",
    },
    "safari": {
        "impersonate": "safari17_0",
        "ua": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"),
        "lang": "en-GB,en;q=0.9",
    },
    "firefox": {
        "impersonate": "firefox133",
        "ua": ("Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 "
               "Firefox/133.0"),
        "lang": "en-US,en;q=0.5",
    },
    "android": {
        "impersonate": "chrome99_android",
        "ua": ("Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari/537.36"),
        "lang": "en-US,en;q=0.9",
    },
    "edge": {
        "impersonate": "edge101",
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 "
               "Edg/101.0.1210.53"),
        "lang": "en-US,en;q=0.9",
    },
}

DEFAULT_PROFILE = "chrome"
DEFAULT_DELAY = 1.0
DEFAULT_TIMEOUT = 15


def _have_curl_cffi() -> bool:
    try:
        import curl_cffi  # noqa: F401
        return True
    except Exception:
        return False


HAVE_CURL_CFFI = _have_curl_cffi()


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    def header(self, name: str) -> str:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return ""


class Transport:
    """Single HTTP client for every phase, with rate limit + JSONL audit."""

    def __init__(
        self,
        profile: str = DEFAULT_PROFILE,
        delay: float = DEFAULT_DELAY,
        timeout: int = DEFAULT_TIMEOUT,
        proxy: str | None = None,
        audit_log: str | Path | None = None,
        retries: int = 2,
        verbose: bool = False,
    ) -> None:
        if profile not in PROFILES:
            raise ValueError(
                f"unknown profile: {profile} (choices: {', '.join(PROFILES)})")
        self.profile_name = profile
        self.profile = PROFILES[profile]
        self.delay = max(0.0, float(delay))
        self.timeout = timeout
        self.proxy = proxy
        self.retries = max(0, retries)
        self.audit_path = Path(audit_log) if audit_log else None
        self.verbose = bool(verbose)
        self._last = 0.0
        self._session = None

    # ---------- internal ----------

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        gap = time.monotonic() - self._last
        jitter = self.delay * random.uniform(0.75, 1.35)
        if gap < jitter:
            time.sleep(jitter - gap)
        self._last = time.monotonic()

    def _audit(self, rec: dict[str, Any]) -> None:
        if not self.audit_path:
            return
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **rec}
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        h = {
            "User-Agent": self.profile["ua"],
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            "Accept-Language": self.profile["lang"],
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Connection": "keep-alive",
        }
        if extra:
            h.update(extra)
        return h

    # ---------- public ----------

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        return self.request("GET", url, headers=headers)

    def head(self, url: str, headers: dict[str, str] | None = None) -> Response:
        return self.request("HEAD", url, headers=headers)

    def post(
        self,
        url: str,
        data: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        return self.request("POST", url, data=data, headers=headers)

    def request(
        self,
        method: str,
        url: str,
        data: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        attempt = 0
        last: Response | None = None
        while attempt <= self.retries:
            self._throttle()
            start = time.monotonic()
            try:
                resp = self._do(method, url, data, headers)
            except Exception as exc:  # noqa: BLE001
                resp = Response(url=url, status=0,
                                error=f"{type(exc).__name__}: {exc}")
            resp.elapsed_ms = int((time.monotonic() - start) * 1000)
            if self.verbose:
                err = f" err={resp.error}" if resp.error else ""
                print(f"    [{method}] {resp.status} {resp.elapsed_ms}ms "
                      f"{len(data) if data else 0}B {url}{err}", flush=True)
            self._audit({
                "profile": self.profile_name,
                "method": method,
                "url": url,
                "status": resp.status,
                "ms": resp.elapsed_ms,
                "error": resp.error,
                "bytes": len(data) if data else 0,
            })
            last = resp
            # 5xx / dropped connection = retry. 4xx = final answer.
            if resp.status and resp.status < 500:
                return resp
            attempt += 1
            if attempt <= self.retries:
                time.sleep(min(2 ** attempt, 8))
        return last or Response(url=url, status=0, error="no attempt")

    def _do(
        self,
        method: str,
        url: str,
        data: bytes | str | None,
        headers: dict[str, str] | None,
    ) -> Response:
        hdrs = self._headers(headers)
        if HAVE_CURL_CFFI:
            from curl_cffi import requests as creq

            if self._session is None:
                self._session = creq.Session(
                    impersonate=self.profile["impersonate"])
            proxies = ({"http": self.proxy, "https": self.proxy}
                       if self.proxy else None)
            r = self._session.request(
                method, url, data=data, headers=hdrs, timeout=self.timeout,
                proxies=proxies, allow_redirects=True, verify=False,
            )
            return Response(
                url=str(r.url), status=r.status_code,
                headers=dict(r.headers),
                body=r.text if method != "HEAD" else "",
            )

        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        ctx = None
        if url.lower().startswith("https"):
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx)
            if ctx else urllib.request.HTTPSHandler())
        try:
            with opener.open(req, timeout=self.timeout) as r:
                raw = b"" if method == "HEAD" else r.read(2_000_000)
                return Response(
                    url=r.geturl(), status=r.status,
                    headers=dict(r.headers),
                    body=raw.decode("utf-8", "replace"),
                )
        except urllib.error.HTTPError as exc:
            raw = b"" if method == "HEAD" else exc.read(2_000_000)
            return Response(
                url=url, status=exc.code,
                headers=dict(exc.headers or {}),
                body=raw.decode("utf-8", "replace"),
            )

    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None


def load_targets(path: str | Path) -> list[str]:
    """Read a target list — one per line; '#' = comment; blank = skip."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"target file does not exist: {p}")
    out: list[str] = []
    seen: set[str] = set()
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "://" not in s:
            s = "https://" + s
        key = s.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out
