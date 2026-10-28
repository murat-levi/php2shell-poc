"""lib/auto.py — auto-detection helpers for simplified CLI.

Detects:
  - SAPI type (mod_php / mod_fcgid / fpm / unknown)
  - PHP endpoint path (tries common paths)
  - MaxRequestWorkers (concurrent-connection probe)
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from urllib.parse import urlsplit

SAPI_RE = re.compile(
    r"\b(mod_php\d?|mod_fcgid|mod_fastcgi|PHP-FPM)\b", re.I)

# Common PHP paths to probe, ordered by likelihood.
PHP_PATHS = (
    "/",
    "/index.php",
    "/index.html",
    "/info.php",
    "/test.php",
    "/phpinfo.php",
    "/wp-login.php",
    "/wp-admin/",
    "/administrator/",
    "/login.php",
    "/admin/",
    "/api/",
    "/default.php",
    "/home.php",
)


def detect_sapi(server_header: str) -> str:
    """Parse the Server header for the PHP SAPI.

    Returns "mod_php", "mod_fcgid", "fpm", or "unknown".
    """
    if not server_header:
        return "unknown"
    m = SAPI_RE.search(server_header)
    if not m:
        if re.search(r"\bPHP/", server_header):
            return "mod_php"
        return "unknown"
    val = m.group(1).lower()
    if "fcgid" in val or "fastcgi" in val:
        return "mod_fcgid"
    if "fpm" in val:
        return "fpm"
    if "mod_php" in val:
        return "mod_php"
    return "unknown"


def _simple_get(host: str, port: int, path: str, tls: bool,
                timeout: float = 8) -> tuple[int, dict[str, str], str]:
    """Minimal HTTP GET — returns (status, headers_dict, body[:2000])."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.settimeout(timeout)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "Connection: close\r\n\r\n").encode()
        s.sendall(req)
        buf = bytearray()
        while len(buf) < 65536:
            c = s.recv(8192)
            if not c:
                break
            buf += c
        s.close()
    except OSError:
        return 0, {}, ""
    raw = bytes(buf)
    if not raw.startswith(b"HTTP/"):
        return 0, {}, ""
    try:
        status = int(raw.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 0, {}, ""
    hdr_end = raw.find(b"\r\n\r\n")
    if hdr_end < 0:
        return status, {}, ""
    hdr_raw = raw[:hdr_end].decode("latin1", "replace")
    body = raw[hdr_end + 4:hdr_end + 4 + 2000].decode("utf-8", "replace")
    headers: dict[str, str] = {}
    for line in hdr_raw.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def _is_php_response(status: int, headers: dict[str, str],
                     body: str) -> bool:
    """Heuristic: did this response come from PHP?"""
    if status == 404:
        return False
    powered = headers.get("x-powered-by", "")
    if "PHP" in powered:
        return True
    sc = headers.get("set-cookie", "")
    if "PHPSESSID" in sc:
        return True
    ct = headers.get("content-type", "")
    if "text/html" in ct and status == 200:
        if re.search(r"<\?php|\.php[\"']", body, re.I):
            return True
        return True
    return False


def discover_php_path(url: str, log=None) -> str | None:
    """Try common paths against the target, return the first PHP-responsive one.

    Returns the path (e.g. "/index.php") or None.
    """
    u = urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    tls = u.scheme == "https"

    for path in PHP_PATHS:
        status, headers, body = _simple_get(host, port, path, tls)
        if log:
            log(f"  path probe {path} → {status}")
        if _is_php_response(status, headers, body):
            return path
    return None


def detect_workers(host: str, port: int, tls: bool = False,
                   max_probe: int = 200, timeout: float = 5,
                   log=None) -> int:
    """Estimate MaxRequestWorkers by holding connections.

    Opens partial POST requests one at a time. After each, tries a GET.
    When the GET times out, the number of held connections = MaxRequestWorkers - 1.

    Returns estimated MaxRequestWorkers (minimum 1).
    Stops probing at max_probe to avoid abuse.
    """
    holders: list[socket.socket] = []
    estimated = 1

    def _hold_one() -> bool:
        """Open one partial-POST holder. Returns True on success."""
        try:
            s = socket.create_connection((host, port), timeout=15)
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            req = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                   "Content-Type: application/x-www-form-urlencoded\r\n"
                   "Content-Length: 1048576\r\n\r\nx").encode()
            s.sendall(req)
            holders.append(s)
            return True
        except OSError:
            return False

    def _can_respond() -> bool:
        """Try a quick GET. Returns True if the server responds with data.

        Uses a very short timeout: once all workers are held, new requests
        sit in the kernel listen queue but never get processed.
        """
        try:
            s = socket.create_connection((host, port), timeout=5)
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.settimeout(5)
            s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                      "Connection: close\r\n\r\n".encode())
            data = s.recv(512)
            s.close()
            return data.startswith(b"HTTP/")
        except (OSError, socket.timeout):
            return False

    try:
        if log:
            log("  worker detection: probing MaxRequestWorkers...")
        batch = 10
        for i in range(1, max_probe + 1):
            if not _hold_one():
                break
            time.sleep(0.02)
            if i % batch == 0:
                time.sleep(0.5)
                ok = _can_respond()
                if log and i % 50 == 0:
                    log(f"  worker detection: {i} held, "
                        f"server {'responds' if ok else 'BLOCKED'}")
                if not ok:
                    time.sleep(1.0)
                    ok2 = _can_respond()
                    if not ok2:
                        estimated = i + 1
                        if log:
                            log(f"  worker detection: server stopped responding "
                                f"after {i} held connections → "
                                f"MaxRequestWorkers ≈ {estimated}")
                        break
                estimated = i + 2
        else:
            if log:
                log(f"  worker detection: reached probe limit ({max_probe}), "
                    f"using Apache default (150)")
            estimated = 150
    finally:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass
    return max(1, estimated)
