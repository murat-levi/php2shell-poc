# PHP2Shell

**CVE-2026-109618 / CVE-2026-109619 exploit toolkit — 5 chains + JA3/TLS stealth + mass scan + safe webshell. Authorized testing only.**

PHP2Shell is a PHP `session.upload_progress` stale-state use-after-free that yields unauthenticated remote code execution. This toolkit ports the public research into a single, guarded, scan-ready CLI: detect, score, exploit, and (optionally) drop a password-protected webshell — all behind one consistent browser fingerprint so a target only ever sees one identity.

> **Authorized testing only.** Every target must be yours or covered by written authorization (engagement, lab, bug-bounty scope). Running this against systems you do not own is a crime in most jurisdictions.

---

## What this is

| | |
|---|---|
| **CVE tested (full chain)** | CVE-2026-109619 — 2-request `session.upload_progress` UAF + ASLR bypass via heap/libphp leak + `pDestructor = zif_system` |
| **CVE detected (version only)** | CVE-2026-109618 — OOM corruption, single request. Different chain, **not** run by this toolkit. |
| **CVSS** | 9.2 (Critical) |
| **Affected** | PHP 5.4 – 8.x, fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (2026-10-21) |
| **Stealth** | `curl_cffi` JA3/TLS impersonation (Chrome / Safari / Firefox / Edge / Android) on every request |
| **Chains** | 5 — production (128M, `display_errors=Off`), 8M remote, local UAF, handler mismatch, session injection |
| **Tests** | 74 unit tests (syntax, guards, classification, OOM signals, CLI smoke) |

### Credit

CVE-2026-109618/109619 was first found by **Calif (Ryan A.)** on 1 Aug 2026 and reported to PHP on 11 Aug 2026. **Wiz Research** found it independently (19 Aug, reported 24 Aug) — [wiz.io/blog/php2shell-php-rce](https://wiz.io/blog/php2shell-php-rce). **OpenAI Codex Security** reported an additional vector on 18 Sep. All three are credited in the PHP advisory.

The chain technique in `exploit/` is a port of **9bie's** public research ([github.com/9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)). This is **not** our original work — it is an independent implementation of public research. See `CREDITS` below.

---

## Install

```bash
git clone https://github.com/eagleofanadolu/php2shell-poc.git
cd php2shell-poc
bash install.sh
# or, without the global symlink:
bash install.sh --no-bin
```

`install.sh` creates a `.venv`, installs `curl_cffi` + `bcrypt`, smoke-tests the CLI, and (optionally) symlinks `php2shell` into `~/.local/bin`. Docker is optional and only needed for the exploit lab.

Manual:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## Quick start

```bash
# toolkit info
php2shell.py version

# single-target detection (non-destructive)
php2shell.py detect -u http://target/

# mass scan from a list (one URL per line, # = comment)
php2shell.py scan -l targets.txt --json out/report.json --csv out/report.csv

# exploit readiness score for one target
php2shell.py preflight http://target/

# run a chain (READY + confirmation); default chain = pure (production)
php2shell.py exploit http://target/ --chain pure --cmd 'id>/out/p1'

# generate a password-protected webshell (add-on, not an uploader)
php2shell.py shell --out out --ttl 24
```

---

## Modes

| Mode | What it does | Destructive? |
|---|---|---|
| `scan` | `targets.txt` → detect → preflight → (optional `--exploit`) → JSON/CSV report | only if `--exploit` |
| `detect` | one or more URLs: version, patch state, `upload_progress`, `display_errors`, active OOM probe | non-destructive |
| `preflight` | one URL: 0–90 readiness score + blockers + build-support hint | non-destructive |
| `exploit` | one URL: detect → if READY + confirmed → run the chosen chain | **yes** |
| `shell` | generate a bcrypt+TTL webshell (whitelist-only, no eval/uploader/revshell) | generator only |
| `version` | print version, chain sha256, fix-floor map, stealth status | — |

---

## The 5 chains

All chains live in `exploit/` and run as subprocesses dispatched by `lib/chain.py`.

| Chain | File | Target profile |
|---|---|---|
| `pure` | `pure_off.py` | **Production** — `display_errors=Off`, `memory_limit=128M`, chunked-encoding bypass. The real-world chain. |
| `remote` | `remote_cve.py` | 8M `memory_limit`, `display_errors=On`, remote. Small memory, easier leak. |
| `local` | `auto_exp.py` + `var_destroy_uaf_rce.php` | Local `var_destroy` UAF — needs the PHP binary on the attacker host. |
| `mismatch` | `handler_mismatch.py` | `php_serialize` vs `php` session handler mismatch (per-directory `.user.ini`/`.htaccess`). |
| (utility) | `tunnel_proxy.py` | HTTP→HTTPS proxy bridge for running the raw-socket chains through a Cloudflare tunnel. |

Pick with `--chain {pure,remote,local,mismatch}`. Offsets default to the `bookworm` profile (`php:8.4.26-apache`, Debian 12); override with `--exploit-profile lab` or `--zif-offset` / `--dtor-offset` / `--htdata-offset`.

---

## Stealth (JA3/TLS fingerprint)

Every HTTP request — detect, preflight, OOM probe, scan — goes through one `Transport` (`lib/transport.py`) that impersonates a real browser down to the TLS ClientHello (JA3) via `curl_cffi`:

```
chrome   chrome124    Windows Chrome 124
safari   safari17_0   macOS Safari 17
firefox  firefox133   Linux Firefox 133
edge     edge101      Windows Edge 101
android  chrome99_android  Android Chrome 99
```

Pick with `--ja3 <profile>`. Without `curl_cffi` the toolkit degrades to `urllib` with full browser headers — still works, but **far** easier to fingerprint. Install it: `pip install curl_cffi`.

Rate limiting (`--delay` + jitter), a JSONL audit log (`--audit`), and a proxy (`--proxy`) are built in.

---

## Guards (enforced in code, not text)

These cannot be disabled from the CLI:

- **Exploit only on READY targets** + confirmation (`--yes` or answer `y`). A target that is unreachable or whose version reads as patched is hard-blocked.
- **Proof-of-access only.** Default command is `id` (or `whoami`). Max 14 bytes (the 167-byte carrier limit). Shell chaining (`; | & $ \` > <`) is rejected. `--revshell` **does not exist** in the parser and is blocked at the runner.
- **Whitelist is bounded.** `--allow-cmd` only accepts `uname, hostname, pwd, ls, cat, df, uptime, who, w, env`. `sh / bash / nc / curl / wget / chmod / rm` are permanently blocked.
- **In-process chain engine.** `lib/chain.py` dispatches the chains; its sha256 is printed every run so you always know exactly what executed.

---

## Lab

A Docker lab ships in `lab/` with two profiles:

| Profile | `memory_limit` | `display_errors` | Apache workers | Purpose |
|---|---|---|---|---|
| `lab` | 8M | On | 1 (single worker) | Easy mode — small memory, errors visible, deterministic worker |
| `production` | 128M | Off | 150 | Hard mode — real-world defaults, the `pure` chain target |

```bash
cd lab
docker compose up --build -d        # default = lab profile
docker compose --profile production up --build -d
```

See `lab/README.md` for the full setup, port map, and how to read the proof file.

---

## Output

`scan` / `detect` / `preflight` / `exploit` accept `--json` and `--csv`. The CSV column contract is stable across versions (it is what engagements use to dedupe in the ledger):

```
url, reachable, status, server, php_version, branch, verdict, fix_floor,
upload_progress, display_errors, patched_but_bypassable, score, ready,
exploited, proof, reason, error
```

---

## Project layout

```
php2shell/
├── php2shell.py              # unified CLI (scan/detect/preflight/exploit/shell/version)
├── lib/
│   ├── transport.py          # JA3/TLS stealth (curl_cffi)
│   ├── detect.py             # non-destructive detection
│   ├── preflight.py          # readiness scoring
│   ├── oomprobe.py           # active OOM detection (assetnote-style)
│   ├── reporter.py           # JSON/CSV/table output
│   ├── banner.py             # CLI banner
│   ├── chain.py              # chain registry + dispatch
│   └── exploit_runner.py     # guard enforcement + orchestration
├── exploit/
│   ├── pure_off.py           # production chain (128M, display_errors=Off)
│   ├── remote_cve.py        # 8M chain
│   ├── auto_exp.py          # local UAF driver
│   ├── handler_mismatch.py  # handler mismatch (FPM)
│   ├── var_destroy_uaf_rce.php  # local PHP RCE payload
│   └── tunnel_proxy.py      # HTTP→HTTPS tunnel bridge
├── shell/
│   ├── safe_shell.py         # bcrypt+TTL webshell generator (CLI variant)
│   ├── web_shell_gen.py     # webshell generator (cli/web/both variants)
│   └── README.md
├── lab/                      # Docker lab (lab + production profiles)
├── tests/                    # 74 unit tests
├── docs/TUTORIAL.md
├── install.sh
├── requirements.txt
└── README.md
```

---

## Credits

- **Calif (Ryan A.)** — original discovery of CVE-2026-109618/109619 (1 Aug 2026), reported to PHP 11 Aug 2026.
- **Wiz Research** — independent discovery (19 Aug 2026), reported 24 Aug 2026. [wiz.io/blog/php2shell-php-rce](https://wiz.io/blog/php2shell-php-rce).
- **OpenAI Codex Security** — additional vector (18 Sep 2026).
- **9bie (Qi Deng)** — the public ASLR-bypass chain technique this toolkit ports: [github.com/9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp).
- **ikow** — crash verifier for CVE-2026-109618 (`verify_oom_trigger.py`), referenced.
- The modular stealth/scan/preflight/OOM/webshell architecture is adapted from **aarsaputra/php2shell**.

The chain implementations in `exploit/` are independent ports of 9bie's public research, not our original work. The orchestration, guards, transport, and webshell generator are ours.

---

## License

MIT. See `LICENSE`. The ported chain technique remains the copyright of its respective authors; this repo claims no ownership over their work.

---

## Türkçe özet

**PHP2Shell**, PHP `session.upload_progress` stale-state use-after-free zafiyeti (CVE-2026-109618/109619) için birleşik bir exploit toolkit'idir. Tek bir CLI altında: tespit (detect), hazırlık skoru (preflight), exploit, ve opsiyonel bcrypt korumalı webshell üretimi. Tüm HTTP trafiği `curl_cffi` ile Chrome/Safari/Firefox/Edge/Android JA3 parmak izi taklidi yapar — hedef tek bir tarayıcı kimliği görür.

**5 exploit chain:** production (`display_errors=Off`, 128M, chunked bypass), 8M remote, local UAF, handler mismatch, session injection. Offsets `bookworm` profiline (`php:8.4.26-apache`, Debian 12) kalibre edilmiştir; `--exploit-profile lab` veya `--zif-offset`/`--dtor-offset` ile geçilebilir.

**Güvenlik pagaları (koddan, metinden değil):** exploit yalnızca READY hedeflerde + onayla çalışır; komutlar proof-of-access (id/whoami), maks 14 byte, chaining yasak; `--revshell` parser'da yok ve runner'da bloklu; whitelist sınırlı (sh/bash/nc/curl/wget/chmod/rm kalıcı engelli).

**Docker lab:** iki profil — `lab` (8M, `display_errors=On`, tek worker — kolay mod) ve `production` (128M, `display_errors=Off`, 150 worker — gerçek dünya). `lab/docker-compose.yml`.

**Kurulum:** `bash install.sh`. **Test:** 74 unit test, `python -m unittest discover -s tests`.

**Yalnızca yetkili test için.** Sahibi olmadığınız sistemlere karşı kullanmak çoğu yargıda suçtur.

**Katkı:** Calif (Ryan A.) orijinal keşif, Wiz Research bağımsız keşif, OpenAI Codex Security ek vektör, 9bie (Qi Deng) public ASLR-bypass chain tekniği (bu toolkit'in portladığı), ikow crash verifikatörü. Stealth/scan/preflight/OOM/webshell modüler mimarisi aarsaputra/php2shell'den uyarlanmıştır. `exploit/` içindeki chain'ler 9bie'nin public araştırmasının bağımsız portlarıdır, bizim özgün çalışmamız değildir.
