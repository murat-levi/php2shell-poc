# shell/ — webshell generator + up-shell tools (proof-of-concept, lab)

**Generator only — it does not upload anywhere.** The target must be yours /
written authorization; for bug bounty `--proof-file` (uid=) is enough.

## Folder contents

| File | Function |
|---|---|
| `safe_shell.py` | generator called by `php2shell.py shell` — CLI whitelist variant (Basic-Auth), bcrypt+TTL+audit, credentials -> `CREDENTIALS.txt` |
| `web_shell_gen.py` | 2-variant generator — `web` (browser login page + terminal + free mode) & `cli` (Basic-Auth + free); credentials -> `CREDENTIALS-<ts>.txt` |

## Usage (tested examples)

```bash
# CLI variant via the main CLI:
python3 php2shell.py shell --out shell/out --ttl 24
# -> shell/out/<32hex>.php + shell/out/CREDENTIALS.txt

# web + cli variants (browser login page, no popup):
python3 shell/web_shell_gen.py --out shell/out --ttl 24 --variant both
# -> 2 files <32hex>.php + shell/out/CREDENTIALS-<ts>.txt
```

The output folder `shell/out/` is **gitignored** — credentials are never committed.

## Principle

> "a safe shell is like an admin login page" — not a backdoor.
> There is no `--revshell` in this toolkit; it is blocked at the runner level.
