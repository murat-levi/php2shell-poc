#!/usr/bin/env bash
# install.sh — php2shell one-shot installer
#
# What it does:
#   1. check python3 >= 3.9 + docker (optional, for the lab)
#   2. create a .venv in the repo folder
#   3. install dependencies (curl_cffi, bcrypt) into the venv
#   4. smoke test: CLI banner shows, quick tests pass
#   5. (optional) symlink `php2shell` to ~/.local/bin for global use
#
# Usage:
#   bash install.sh            # full install
#   bash install.sh --no-bin   # without the global symlink
#
# Run WITHOUT root. If docker is missing it is skipped with a note
# (the lab still works once docker is ready — see lab/setup.sh).

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(pwd)"
NO_BIN=0
[ "${1:-}" = "--no-bin" ] && NO_BIN=1

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
warn()  { printf '  \033[33m[!!]\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m[x]\033[0m %s\n' "$*"; exit 1; }

echo
bold "== php2shell installer =="

# --- 1) prerequisites ------------------------------------------------------
command -v python3 >/dev/null 2>&1 || fail "python3 missing — install it first (apt install python3 python3-venv python3-pip)"
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYOK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,9) else 0)')
[ "$PYOK" = "1" ] || fail "python3 $PYVER < 3.9 — upgrade first"
ok "python3 $PYVER"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    ok "docker active (lab ready: bash lab/setup.sh)"
elif command -v docker >/dev/null 2>&1; then
    warn "docker installed but daemon not reachable for this user — run: sudo usermod -aG docker \$USER then logout/login"
else
    warn "docker missing — the exploit lab cannot run (detect/preflight still work). See lab/setup.sh"
fi

# --- 2) venv ---------------------------------------------------------------
if [ ! -d .venv ]; then
    echo "  * creating venv .venv ..."
    python3 -m venv .venv || fail "venv creation failed (needs python3-venv)"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
ok "venv .venv ready ($(python --version 2>&1))"

# --- 3) dependencies -------------------------------------------------------
echo "  * installing dependencies (curl_cffi, bcrypt) ..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt || fail "pip install failed"
ok "dependencies installed"

# --- 4) smoke test ---------------------------------------------------------
echo "  * smoke test ..."
python php2shell.py version >/dev/null 2>&1 || fail "CLI did not run"
ok "CLI runs"
python -c "import curl_cffi" 2>/dev/null && ok "curl_cffi impersonation active (stealth mode)" \
    || warn "curl_cffi import failed — tool runs in urllib mode (easier to detect)"
python -m unittest discover -s tests -t . 2>&1 | tail -1 | grep -q "^OK" \
    && ok "unit tests pass" \
    || warn "unit tests did not fully pass — check: python -m unittest discover -s tests -t ."

# --- 5) global symlink (optional) -----------------------------------------
if [ "$NO_BIN" = 0 ]; then
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/php2shell" <<EOF
#!/usr/bin/env bash
# php2shell wrapper (created by install.sh)
exec "$ROOT/.venv/bin/python" "$ROOT/php2shell.py" "\$@"
EOF
    chmod +x "$BIN_DIR/php2shell"
    ok "global symlink: $BIN_DIR/php2shell  (remove with: rm $BIN_DIR/php2shell)"
fi

echo
bold "done. quick start:"
echo "  php2shell.py version                       # toolkit info"
echo "  php2shell.py detect -u http://target/      # single-target detection"
echo "  php2shell.py scan -l targets.txt           # mass scan"
echo "  php2shell.py preflight http://target/      # readiness score"
echo "  php2shell.py exploit http://target/        # run a chain (READY + confirm)"
echo "  php2shell.py shell --out out --ttl 24     # generate a safe webshell"
echo
