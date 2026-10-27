#!/bin/bash
# PHP2Shell Lab — Remote Testing Setup
# Dışarıdan erişilebilir test ortamı kurar
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB_DIR"

echo "========================================"
echo "  PHP2SHELL LAB — REMOTE SETUP"
echo "========================================"
echo ""

# Docker kontrolü
if ! command -v docker &>/dev/null; then
    echo "[-] Docker kurulu değil!"
    echo "    macOS:  brew install --cask docker"
    echo "    Linux:  sudo apt install docker.io docker-compose"
    exit 1
fi

echo "[*] Docker: $(docker --version)"
echo ""

# Port seçimi
PORT_LAB="${LAB_PORT:-8088}"
PORT_PROD="${PROD_PORT:-8089}"

echo "[*] Lab port:      $PORT_LAB (display_errors=On, 8M)"
echo "[*] Production port: $PORT_PROD (display_errors=Off, 128M)"
echo ""

# Önceki container'ları temizle
echo "[*] Önceki container'lar temizleniyor..."
docker compose down 2>/dev/null || true
docker rm -f php2shell-lab php2shell-prod 2>/dev/null || true

# Lab profile (8M, display_errors=On)
echo ""
echo "[*] Lab container başlatılıyor (port $PORT_LAB)..."
docker compose up -d lab 2>&1
sleep 3

# Production profile (128M, display_errors=Off)
echo "[*] Production container başlatılıyor (port $PORT_PROD)..."
docker compose up -d production 2>&1
sleep 3

# IP adreslerini göster
echo ""
echo "========================================"
echo "  LAB HAZIR"
echo "========================================"
echo ""

# Yerel IP
LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
PUBLIC_IP=$(curl -s -m 5 https://ifconfig.me 2>/dev/null || echo "unknown")

echo "  Lab (8M):        http://$LOCAL_IP:$PORT_LAB/"
echo "  Production:      http://$LOCAL_IP:$PORT_PROD/"
echo ""
echo "  Public IP: $PUBLIC_IP"
if [ "$PUBLIC_IP" != "unknown" ]; then
    echo "  Remote Lab:       http://$PUBLIC_IP:$PORT_LAB/"
    echo "  Remote Production: http://$PUBLIC_IP:$PORT_PROD/"
fi

echo ""
echo "  PHP version:"
docker exec php2shell-lab php -r 'echo "    " . PHP_VERSION . " (" . php_sapi_name() . ")\n";' 2>/dev/null
docker exec php2shell-prod php -r 'echo "    " . PHP_VERSION . " (" . php_sapi_name() . ")\n";' 2>/dev/null

echo ""
echo "========================================"
echo "  EXPLOIT KOMUTLARI"
echo "========================================"
echo ""
echo "  # Lab (8M chain):"
echo "  python3 exploit/remote_cve.py -u http://$LOCAL_IP:$PORT_LAB/index.php --cmd 'id>/out/p1'"
echo ""
echo "  # Production (pure_off.py):"
echo "  python3 exploit/pure_off.py --host $LOCAL_IP --port $PORT_PROD --auto"
echo ""
echo "  # Uzaktan (public IP ile):"
if [ "$PUBLIC_IP" != "unknown" ]; then
    echo "  python3 exploit/pure_off.py --host $PUBLIC_IP --port $PORT_PROD --auto"
fi
echo ""
echo "  # Worker pinning ile production:"
echo "  python3 exploit/pure_off.py --host $LOCAL_IP --port $PORT_PROD --cmd 'id>/out/p1' --proof ./out/p1 --auto"
echo ""

# ngrok önerisi
if ! command -v ngrok &>/dev/null; then
    echo "========================================"
    echo "  NGROK ILE UZAKTAN PAYLASIM"
    echo "========================================"
    echo ""
    echo "  Public IP yoksa ngrok ile tunnel aç:"
    echo "    brew install ngrok"
    echo "    ngrok http $PORT_LAB"
    echo "    # veya"
    echo "    ngrok http $PORT_PROD"
    echo ""
    echo "  ngrok URL'sini arkadaşına gönder:"
    echo "    python3 exploit/pure_off.py --host 0.tcp.ngrok.io --port XXXXX --auto"
    echo ""
fi

echo "========================================"
echo "  DURDURMAK ICIN"
echo "========================================"
echo "  docker compose down"
echo "========================================"
